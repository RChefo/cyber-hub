// SPDX-License-Identifier: Apache-2.0
//! Application updates through the official Tauri updater plugin.
//!
//! The whole flow runs in the backend; the web view has no updater permission and only calls the
//! commands in `commands::updates`, which return the [`Status`] below and receive progress through
//! the `update-status` event.
//!
//! Security properties (see docs/UPDATER.md):
//! - every downloaded artifact is verified by the plugin against the public key compiled into the
//!   app (minisign) before it is kept, and the signature must carry the version announced by the
//!   feed (`requireSignedVersion`), so a tampered feed cannot pair a new version with an old build;
//! - the feed and the download must use HTTPS (only a test build that enables the plugin's
//!   `dangerousInsecureTransportProtocol` accepts plain HTTP, and the status says so); a build that
//!   accepts invalid certificates or host names refuses to check at all;
//! - only newer stable versions are offered (no downgrades, no pre-releases on the stable channel);
//! - nothing is installed without a native confirmation, and never while tool runs, OSINT
//!   collections, MCP approvals or uploads are in progress;
//! - the downloaded package stays in memory until installation; nothing is written next to the app.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio_util::sync::CancellationToken;

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const EVENT_STATUS: &str = "update-status";
pub const EVENT_NOTICE: &str = "update-notice";

const PREF_AUTO: &str = "updates.autoCheck";
const PREF_FREQ: &str = "updates.frequencyHours";
const PREF_LAST_CHECK: &str = "updates.lastCheck";
const PREF_LAST_RESULT: &str = "updates.lastResult";
const PREF_NOTIFIED: &str = "updates.notifiedVersion";

/// Allowed automatic check intervals, in hours.
pub const FREQUENCIES: [u32; 4] = [6, 12, 24, 168];
const DEFAULT_FREQUENCY: u32 = 24;
/// The first automatic check waits until the app has settled after startup.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(90);
/// How often the scheduler looks at whether a check is due (a check is not made every tick).
const TICK: Duration = Duration::from_secs(300);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Installers are a few tens of MB; anything far larger is refused before it fills memory.
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;
const MAX_NOTES: usize = 20_000;
const CHANNEL: &str = "stable";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Idle,
    Checking,
    UpToDate,
    Available,
    Downloading,
    Verifying,
    Ready,
    Installing,
    RestartRequired,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallKind {
    Nsis,
    Msi,
    Appimage,
    Deb,
    Rpm,
    /// development build, or an executable that was not installed by one of the installers
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub version: String,
    pub date: Option<String>,
    pub notes: String,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    /// network, tls, http, feed, manifest, signature, disk, install, auth, config, notConfigured,
    /// unsupported, other
    pub kind: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub phase: Phase,
    pub current_version: String,
    pub os: &'static str,
    pub arch: &'static str,
    pub install_kind: InstallKind,
    /// this copy can install updates itself
    pub supported: bool,
    pub support_note: Option<String>,
    pub channel: &'static str,
    /// an update feed is compiled into this build
    pub configured: bool,
    /// shown when the build's updater configuration is weaker than a release build's
    pub warning: Option<String>,
    pub last_check: Option<String>,
    pub last_result: Option<String>,
    pub next_check: Option<String>,
    pub available: Option<Release>,
    pub progress: Option<Progress>,
    pub error: Option<Failure>,
    pub auto_check: bool,
    pub frequency_hours: u32,
    /// work that must finish before installing (only filled when an update is ready)
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Settings {
    auto_check: bool,
    frequency_hours: u32,
    last_check: Option<String>,
    last_result: Option<String>,
    notified_version: Option<String>,
}

struct Inner {
    phase: Phase,
    settings: Settings,
    available: Option<Release>,
    progress: Option<Progress>,
    error: Option<Failure>,
    update: Option<Update>,
    bytes: Option<Arc<Vec<u8>>>,
    cancel: Option<CancellationToken>,
    /// consecutive failed automatic checks (backoff)
    failures: u32,
}

pub struct Updates {
    inner: Mutex<Inner>,
    /// held for the duration of a check, so checks never overlap
    checking: tokio::sync::Mutex<()>,
}

/* ───────────────────────── pure helpers (unit tested) ───────────────────────── */

/// Whether `candidate` is offered to a user on the stable channel running `current`:
/// strictly newer (no downgrades, no reinstall of the same version) and not a pre-release.
pub fn offered(current: &semver::Version, candidate: &semver::Version) -> bool {
    // precedence ignores build metadata (`1.0.0+5` is the same release as `1.0.0`)
    candidate.cmp_precedence(current) == std::cmp::Ordering::Greater && candidate.pre.is_empty()
}

pub fn install_kind() -> InstallKind {
    use tauri::utils::config::BundleType;
    match tauri::utils::platform::bundle_type() {
        Some(BundleType::Nsis) => InstallKind::Nsis,
        Some(BundleType::Msi) => InstallKind::Msi,
        Some(BundleType::AppImage) => InstallKind::Appimage,
        Some(BundleType::Deb) => InstallKind::Deb,
        Some(BundleType::Rpm) => InstallKind::Rpm,
        _ => InstallKind::Unknown,
    }
}

/// Whether this copy can update itself, with a note for the Update Center.
pub fn support(kind: InstallKind, appimage_path: Option<&str>) -> (bool, Option<String>) {
    match kind {
        InstallKind::Nsis => (true, None),
        InstallKind::Msi => (true, Some("Installed with the MSI package: Windows asks for administrator approval while the update installs.".into())),
        InstallKind::Appimage => match appimage_path {
            Some(_) => (true, Some("Running from an AppImage: the AppImage file is replaced in place, so its folder must be writable by you.".into())),
            None => (false, Some("This AppImage build cannot find its own file, so it cannot replace itself. Download the new AppImage from the release page instead.".into())),
        },
        InstallKind::Deb => (true, Some("Installed from the .deb package: installing an update asks for an administrator password (dpkg).".into())),
        InstallKind::Rpm => (true, Some("Installed from the .rpm package: installing an update asks for an administrator password (rpm).".into())),
        InstallKind::Unknown => (
            false,
            Some("This copy was not installed by an ExploitX installer (a development build or a copied executable), so it cannot update itself. Install ExploitX from the release installer to receive updates.".into()),
        ),
    }
}

/// Delay before the next automatic check after `failures` consecutive failures:
/// 15 min, 30 min, 1 h, 2 h … never longer than the configured interval.
pub fn retry_delay(failures: u32, frequency_hours: u32) -> chrono::Duration {
    let interval = chrono::Duration::hours(frequency_hours as i64);
    if failures == 0 {
        return interval;
    }
    let backoff = chrono::Duration::minutes(15 * (1i64 << (failures - 1).min(10)));
    backoff.min(interval)
}

/// One notification per version: only a version newer than every one announced before (a feed
/// that goes back to an older version, or flips between two, does not notify again).
pub fn should_notify(notified: Option<&str>, version: &str) -> bool {
    match (notified.and_then(|n| semver::Version::parse(n).ok()), semver::Version::parse(version)) {
        (Some(prev), Ok(new)) => new.cmp_precedence(&prev) == std::cmp::Ordering::Greater,
        _ => notified != Some(version),
    }
}

/// Whether a folder in the temporary directory is one the updater plugin left behind: on Windows it
/// writes the installer to `<product name>-<version>-updater-<random>` and keeps it, because the
/// installer still runs from there after ExploitX exits.
pub fn is_installer_leftover(dir_name: &str, product_name: &str) -> bool {
    dir_name
        .strip_prefix(product_name)
        .and_then(|rest| rest.strip_prefix('-'))
        .and_then(|rest| rest.split_once("-updater-"))
        .is_some_and(|(version, _)| semver::Version::parse(version).is_ok())
}

/// Removes installer folders left by earlier updates (best effort; a folder whose installer is
/// still running is skipped and removed at a later start).
fn clean_installer_leftovers(app: &AppHandle) {
    let product = app.package_info().name.clone();
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let old_enough = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(60));
        if entry.file_type().is_ok_and(|t| t.is_dir()) && old_enough && is_installer_leftover(&name, &product) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// When the next automatic check is due, if automatic checks are on.
fn next_due(s: &Settings, failures: u32) -> Option<DateTime<Utc>> {
    if !s.auto_check {
        return None;
    }
    let failures = if failures == 0 && s.last_result.as_deref() == Some("failed") { 1 } else { failures };
    match s.last_check.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
        Some(t) => Some(t.with_timezone(&Utc) + retry_delay(failures, s.frequency_hours)),
        None => Some(Utc::now()),
    }
}

/// Release notes are shown as plain text: control characters removed, length capped.
pub fn clean_notes(notes: Option<&str>) -> String {
    let s: String = notes
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    let s = s.replace("\r\n", "\n");
    if s.chars().count() > MAX_NOTES {
        let cut: String = s.chars().take(MAX_NOTES).collect();
        format!("{cut}\n…")
    } else {
        s.trim().to_string()
    }
}

/// Normalizes the feed's `pub_date` (RFC 3339) or drops it.
fn clean_date(raw: Option<&serde_json::Value>) -> Option<String> {
    let s = raw?.as_str()?;
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn failure(kind: &'static str, message: impl Into<String>) -> Failure {
    Failure { kind, message: message.into() }
}

/// Turns a plugin error into a message for the Update Center.
pub fn classify(e: &tauri_plugin_updater::Error) -> Failure {
    use tauri_plugin_updater::Error as E;
    match e {
        // the client could not be built, which on Linux means no CA certificates are installed (Mission 11)
        E::Reqwest(r) if r.is_builder() => failure("tls", crate::tls_trust::describe_build_error(r)),
        E::Reqwest(r) if is_certificate_error(r) => failure(
            "tls",
            "The update server's TLS certificate is not trusted, so the connection was refused. Updates are only accepted over a verified HTTPS connection.",
        ),
        E::Reqwest(r) if r.is_timeout() => failure("network", "The update server did not answer in time. Check the internet connection and try again."),
        E::Reqwest(r) if r.is_connect() => failure("network", "Could not connect to the update server. Check the internet connection and try again."),
        E::Reqwest(r) if r.is_decode() => failure("manifest", "The update information could not be read (it is not a valid update manifest)."),
        E::Reqwest(r) => match r.status() {
            Some(s) => failure("http", format!("The update server answered with HTTP {}.", s.as_u16())),
            None => failure("network", format!("The update request failed: {r}")),
        },
        E::ReleaseNotFound => failure("feed", "No update information is published at the update address (the server did not return a release manifest)."),
        E::Network(m) => failure("http", format!("The download failed: {}", m.trim_matches('`'))),
        E::Serialization(_) | E::Semver(_) | E::UrlParse(_) => failure("manifest", format!("The update manifest is invalid: {e}")),
        E::TargetNotFound(_) | E::TargetsNotFound(_) => failure("manifest", "The new release does not include an update for this platform and package type."),
        E::Minisign(_) | E::Base64(_) | E::SignatureUtf8(_) | E::SignedVersionMismatch { .. } | E::MissingSignedVersion => {
            failure("signature", format!("The downloaded update failed signature verification and was discarded. Nothing was installed. ({e})"))
        }
        E::InsecureTransportProtocol => failure("config", "The update address does not use HTTPS, so it was not contacted."),
        E::Io(err) => failure("disk", format!("Could not write the installer to the temporary folder: {err}")),
        E::AuthenticationFailed => failure("auth", "Installation was cancelled at the administrator password prompt. Nothing was changed."),
        E::DebInstallFailed | E::PackageInstallFailed => failure("install", "The package manager could not install the update. Nothing was removed; the current version stays installed."),
        E::InvalidUpdaterFormat | E::BinaryNotFoundInArchive => failure("install", "The downloaded file is not an installer for this system."),
        E::TempDirNotOnSameMountPoint | E::TempDirNotFound | E::FailedToDetermineExtractPath => failure("disk", format!("The update cannot be installed from this location: {e}")),
        E::UnsupportedOs | E::UnsupportedArch => failure("unsupported", e.to_string()),
        E::EmptyEndpoints => failure("notConfigured", "No update address is configured in this build."),
        _ => failure("other", e.to_string()),
    }
}

/// Whether a request failed because the server's certificate was rejected.
pub(crate) fn is_certificate_error(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        let text = format!("{err} {err:?}").to_ascii_lowercase();
        if text.contains("certificate") || text.contains("unknownissuer") || text.contains("invalid peer cert") {
            return true;
        }
        cur = err.source();
    }
    false
}

/* ───────────────────────── feed configuration ───────────────────────── */

struct Feed {
    endpoints: usize,
    insecure_transport: bool,
    insecure_tls: bool,
}

fn feed(app: &AppHandle) -> Feed {
    let cfg = app.config().plugins.0.get("updater");
    let flag = |k: &str| cfg.and_then(|c| c.get(k)).and_then(|v| v.as_bool()).unwrap_or(false);
    Feed {
        endpoints: cfg.and_then(|c| c.get("endpoints")).and_then(|v| v.as_array()).map_or(0, |a| a.len()),
        insecure_transport: flag("dangerousInsecureTransportProtocol"),
        insecure_tls: flag("dangerousAcceptInvalidCerts") || flag("dangerousAcceptInvalidHostnames"),
    }
}

/* ───────────────────────── service ───────────────────────── */

fn read_settings(db: &Db) -> Settings {
    let get = |c: &rusqlite::Connection, k: &str| -> Option<serde_json::Value> {
        c.query_row("SELECT value FROM user_preferences WHERE key = ?1", params![k], |r| r.get::<_, String>(0))
            .optional()
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
    };
    db.with(|c| {
        let freq = get(c, PREF_FREQ).and_then(|v| v.as_u64()).map(|v| v as u32).filter(|v| FREQUENCIES.contains(v));
        Ok(Settings {
            auto_check: get(c, PREF_AUTO).and_then(|v| v.as_bool()).unwrap_or(true),
            frequency_hours: freq.unwrap_or(DEFAULT_FREQUENCY),
            last_check: get(c, PREF_LAST_CHECK).and_then(|v| v.as_str().map(str::to_string)),
            last_result: get(c, PREF_LAST_RESULT).and_then(|v| v.as_str().map(str::to_string)),
            notified_version: get(c, PREF_NOTIFIED).and_then(|v| v.as_str().map(str::to_string)),
        })
    })
    .unwrap_or(Settings { auto_check: true, frequency_hours: DEFAULT_FREQUENCY, last_check: None, last_result: None, notified_version: None })
}

fn write_prefs(db: &Db, values: &[(&str, serde_json::Value)]) {
    let at = now();
    let _ = db.with(|c| {
        for (k, v) in values {
            c.execute(
                "INSERT INTO user_preferences (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![k, v.to_string(), at],
            )?;
        }
        Ok(())
    });
}

impl Updates {
    pub fn load(db: &Db) -> Self {
        Self {
            inner: Mutex::new(Inner {
                phase: Phase::Idle,
                settings: read_settings(db),
                available: None,
                progress: None,
                error: None,
                update: None,
                bytes: None,
                cancel: None,
                failures: 0,
            }),
            checking: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn status(&self, app: &AppHandle) -> Status {
        let kind = install_kind();
        let appimage = std::env::var("APPIMAGE").ok();
        let (supported, support_note) = support(kind, appimage.as_deref());
        let f = feed(app);
        let warning = if f.insecure_tls {
            Some("This build accepts invalid TLS certificates for updates, so update checks are disabled.".to_string())
        } else if f.insecure_transport {
            Some("Test build: this build accepts an update feed over plain HTTP. Release builds require HTTPS.".to_string())
        } else {
            None
        };
        let i = self.lock();
        let phase = i.phase;
        let blockers = if phase == Phase::Ready { blockers(app) } else { Vec::new() };
        Status {
            phase,
            current_version: app.package_info().version.to_string(),
            os: crate::util::current_os(),
            arch: std::env::consts::ARCH,
            install_kind: kind,
            supported,
            support_note,
            channel: CHANNEL,
            configured: f.endpoints > 0 && !f.insecure_tls,
            warning,
            last_check: i.settings.last_check.clone(),
            last_result: i.settings.last_result.clone(),
            next_check: if f.endpoints > 0 { next_due(&i.settings, i.failures).map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)) } else { None },
            available: i.available.clone(),
            progress: i.progress.clone(),
            error: i.error.clone(),
            auto_check: i.settings.auto_check,
            frequency_hours: i.settings.frequency_hours,
            blockers,
        }
    }

    fn emit(&self, app: &AppHandle) {
        let _ = app.emit(EVENT_STATUS, self.status(app));
    }

    pub fn set_settings(&self, app: &AppHandle, auto_check: bool, frequency_hours: u32) -> AppResult<Status> {
        if !FREQUENCIES.contains(&frequency_hours) {
            return Err(validation("The check frequency must be 6, 12, 24 or 168 hours"));
        }
        write_prefs(&app.state::<Db>(), &[(PREF_AUTO, auto_check.into()), (PREF_FREQ, frequency_hours.into())]);
        {
            let mut i = self.lock();
            i.settings.auto_check = auto_check;
            i.settings.frequency_hours = frequency_hours;
        }
        let s = self.status(app);
        let _ = app.emit(EVENT_STATUS, s.clone());
        Ok(s)
    }

    /// Whether the scheduler should check now.
    fn auto_due(&self, app: &AppHandle) -> bool {
        let f = feed(app);
        if f.endpoints == 0 || f.insecure_tls {
            return false;
        }
        let i = self.lock();
        if !matches!(i.phase, Phase::Idle | Phase::UpToDate | Phase::Failed | Phase::Cancelled | Phase::Available | Phase::Ready) {
            return false;
        }
        next_due(&i.settings, i.failures).is_some_and(|d| Utc::now() >= d)
    }
}

/* ───────────────────────── check ───────────────────────── */

/// Checks the feed. Concurrent calls do not start a second request: they get the current status.
/// A failed check is reported in the returned status (`phase: failed`), not as an error.
pub async fn check(app: &AppHandle, manual: bool) -> AppResult<Status> {
    let svc = app.state::<Arc<Updates>>().inner().clone();
    let Ok(_guard) = svc.checking.try_lock() else {
        return Ok(svc.status(app));
    };
    // a verified download is kept if the feed still announces the same package
    let ready: Option<(String, String)>;
    {
        let mut i = svc.lock();
        if matches!(i.phase, Phase::Downloading | Phase::Verifying | Phase::Installing | Phase::RestartRequired) {
            drop(i);
            if manual {
                return Err(validation("An update is already being downloaded or installed."));
            }
            return Ok(svc.status(app));
        }
        ready = match (i.phase, &i.update) {
            (Phase::Ready, Some(u)) => Some((u.version.clone(), u.signature.clone())),
            _ => None,
        };
        i.phase = Phase::Checking;
        i.error = None;
    }
    svc.emit(app);

    let result = run_check(app).await;
    let at = now();
    let db = app.state::<Db>();
    let mut notice: Option<String> = None;
    {
        let mut i = svc.lock();
        i.settings.last_check = Some(at.clone());
        match result {
            Ok(Some((update, _))) if ready.as_ref().is_some_and(|(v, sig)| *v == update.version && *sig == update.signature) => {
                i.failures = 0;
                i.phase = Phase::Ready;
                i.settings.last_result = Some("available".into());
            }
            Ok(Some((update, release))) => {
                i.failures = 0;
                i.phase = Phase::Available;
                i.settings.last_result = Some("available".into());
                if should_notify(i.settings.notified_version.as_deref(), &release.version) {
                    i.settings.notified_version = Some(release.version.clone());
                    notice = Some(release.version.clone());
                }
                i.available = Some(release);
                i.update = Some(update);
                i.bytes = None;
                i.progress = None;
            }
            Ok(None) => {
                i.failures = 0;
                i.phase = Phase::UpToDate;
                i.settings.last_result = Some("upToDate".into());
                i.available = None;
                i.update = None;
                i.bytes = None;
                i.progress = None;
            }
            Err(f) => {
                if !manual {
                    i.failures = i.failures.saturating_add(1);
                }
                // a failed check does not discard a verified download
                i.phase = if ready.is_some() { Phase::Ready } else { Phase::Failed };
                i.settings.last_result = Some("failed".into());
                i.error = Some(f);
            }
        }
        let s = &i.settings;
        let mut prefs: Vec<(&str, serde_json::Value)> =
            vec![(PREF_LAST_CHECK, at.clone().into()), (PREF_LAST_RESULT, s.last_result.clone().unwrap_or_default().into())];
        if let Some(v) = &notice {
            prefs.push((PREF_NOTIFIED, v.clone().into()));
        }
        drop(i);
        write_prefs(&db, &prefs);
    }
    if let Some(version) = notice {
        // one notification per version: a toast in the app and an entry in the activity list
        let _ = db.with(|c| crate::commands::activity::log(c, "update", &format!("ExploitX {version} is available"), "Open Settings → Updates to review and install it.", None, None, None));
        let _ = app.emit(EVENT_NOTICE, serde_json::json!({ "version": version }));
    }
    svc.emit(app);
    Ok(svc.status(app))
}

async fn run_check(app: &AppHandle) -> Result<Option<(Update, Release)>, Failure> {
    let f = feed(app);
    if f.endpoints == 0 {
        return Err(failure("notConfigured", "No update address is configured in this build (development and local builds do not check for updates)."));
    }
    if f.insecure_tls {
        return Err(failure("config", "This build accepts invalid TLS certificates for updates, so it does not check for updates."));
    }
    let https_only = !f.insecure_transport;
    let handle = app.clone();
    let updater = app
        .updater_builder()
        .version_comparator(|current, release| offered(&current, &release.version))
        .timeout(REQUEST_TIMEOUT)
        .configure_client(move |b| b.https_only(https_only))
        // Windows: runs right before the installer starts and ExploitX exits
        .on_before_exit(move || {
            crate::shutdown(&handle);
            handle.cleanup_before_exit();
        })
        .build()
        .map_err(|e| classify(&e))?;
    let Some(update) = updater.check().await.map_err(|e| classify(&e))? else {
        return Ok(None);
    };
    if https_only && update.download_url.scheme() != "https" {
        return Err(failure("manifest", "The update manifest points to a download that does not use HTTPS, so it was ignored."));
    }
    let size = download_size(&update, https_only).await;
    let release = Release {
        version: update.version.clone(),
        date: clean_date(update.raw_json.get("pub_date")),
        notes: clean_notes(update.body.as_deref()),
        size,
    };
    Ok(Some((update, release)))
}

/// Best-effort size of the package (HEAD request); unknown sizes are shown once downloading.
async fn download_size(update: &Update, https_only: bool) -> Option<u64> {
    let client = crate::tls_trust::build(reqwest::Client::builder().https_only(https_only).timeout(Duration::from_secs(15)).user_agent("CyberHub-Updater")).ok()?;
    let res = client.head(update.download_url.clone()).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    res.headers().get(reqwest::header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok().filter(|n| *n > 0)
}

/* ───────────────────────── download ───────────────────────── */

pub fn download(app: &AppHandle) -> AppResult<Status> {
    let svc = app.state::<Arc<Updates>>().inner().clone();
    let (supported, note) = support(install_kind(), std::env::var("APPIMAGE").ok().as_deref());
    if !supported {
        return Err(validation(note.unwrap_or_else(|| "This copy cannot install updates.".into())));
    }
    let (update, token) = {
        let mut i = svc.lock();
        if !matches!(i.phase, Phase::Available | Phase::Cancelled | Phase::Failed) || i.update.is_none() {
            return Err(validation("There is no update to download. Check for updates first."));
        }
        let token = CancellationToken::new();
        i.cancel = Some(token.clone());
        i.phase = Phase::Downloading;
        i.progress = Some(Progress { downloaded: 0, total: i.available.as_ref().and_then(|r| r.size) });
        i.error = None;
        i.bytes = None;
        (i.update.clone().expect("checked above"), token)
    };
    let started = svc.status(app);
    let _ = app.emit(EVENT_STATUS, started.clone());

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let too_large = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut downloaded: u64 = 0;
        let mut last = Instant::now();
        let (s1, a1, s2, a2, t1, big) = (svc.clone(), app.clone(), svc.clone(), app.clone(), token.clone(), too_large.clone());
        let on_chunk = move |len: usize, total: Option<u64>| {
            downloaded += len as u64;
            if downloaded > MAX_DOWNLOAD || total.is_some_and(|t| t > MAX_DOWNLOAD) {
                big.store(true, std::sync::atomic::Ordering::SeqCst);
                t1.cancel();
                return;
            }
            if last.elapsed() >= Duration::from_millis(150) || total == Some(downloaded) {
                last = Instant::now();
                s1.lock().progress = Some(Progress { downloaded, total });
                s1.emit(&a1);
            }
        };
        let on_finish = move || {
            let mut i = s2.lock();
            if let Some(p) = i.progress.as_mut() {
                p.total = p.total.or(Some(p.downloaded));
            }
            i.phase = Phase::Verifying;
            drop(i);
            s2.emit(&a2);
        };
        let result = tokio::select! {
            r = update.download(on_chunk, on_finish) => Some(r),
            _ = token.cancelled() => None,
        };
        {
            let mut i = svc.lock();
            i.cancel = None;
            match result {
                Some(Ok(bytes)) => {
                    let n = bytes.len() as u64;
                    i.progress = Some(Progress { downloaded: n, total: Some(n) });
                    i.bytes = Some(Arc::new(bytes));
                    i.phase = Phase::Ready;
                }
                Some(Err(e)) => {
                    let f = classify(&e);
                    if f.kind == "signature" {
                        // an artifact that failed verification is never offered again: check again
                        i.update = None;
                        i.available = None;
                    }
                    i.progress = None;
                    i.phase = Phase::Failed;
                    i.error = Some(f);
                }
                None if too_large.load(std::sync::atomic::Ordering::SeqCst) => {
                    i.progress = None;
                    i.phase = Phase::Failed;
                    i.error = Some(failure("http", format!("The download is larger than {} MB and was stopped.", MAX_DOWNLOAD / (1024 * 1024))));
                }
                None => {
                    i.progress = None;
                    i.phase = Phase::Cancelled;
                }
            }
        }
        svc.emit(&app);
    });
    Ok(started)
}

pub fn cancel(app: &AppHandle) -> AppResult<Status> {
    let svc = app.state::<Arc<Updates>>().inner().clone();
    let token = svc.lock().cancel.clone();
    match token {
        Some(t) => t.cancel(),
        None => return Err(validation("No download is in progress.")),
    }
    Ok(svc.status(app))
}

/* ───────────────────────── install ───────────────────────── */

/// Work that an installation would interrupt. Installing waits until the list is empty.
pub fn blockers(app: &AppHandle) -> Vec<String> {
    let mut out = Vec::new();
    let plural = |n: usize, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
    let runs = app.state::<crate::process::ProcessManager>().running_ids().len();
    if runs > 0 {
        out.push(format!("{} in progress (Runs page)", plural(runs, "tool run", "tool runs")));
    }
    let osint = app.state::<Arc<crate::osint::discovery::OsintState>>().running_count();
    if osint > 0 {
        out.push(format!("{} in progress (OSINT Workspace)", plural(osint, "OSINT collection", "OSINT collections")));
    }
    let bridge = app.state::<Arc<crate::mcp::bridge::Bridge>>();
    let pending = bridge.approvals.pending_count();
    if pending > 0 {
        out.push(format!("{} waiting for your decision (MCP)", plural(pending, "MCP request", "MCP requests")));
    }
    let uploads = app.state::<crate::commands::virustotal::VtState>().uploads_in_progress();
    if uploads > 0 {
        out.push(format!("{} in progress", plural(uploads, "VirusTotal upload", "VirusTotal uploads")));
    }
    #[cfg(windows)]
    {
        // a running cyberhub-mcp.exe (started by an MCP client) would stop the installer from
        // replacing it
        let n = running_mcp_servers();
        if n > 0 {
            out.push(format!(
                "{} running for an MCP client: close the MCP client (for example Claude Code or Claude Desktop) so the installer can replace it",
                plural(n, "ExploitX MCP server (cyberhub-mcp) is", "ExploitX MCP servers (cyberhub-mcp) are")
            ));
        }
    }
    out
}

#[cfg(windows)]
fn running_mcp_servers() -> usize {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let Some(path) = crate::commands::mcp::server_path() else { return 0 };
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::Always));
    sys.processes()
        .values()
        .filter(|p| p.exe().map(|e| std::fs::canonicalize(e).unwrap_or_else(|_| e.to_path_buf())) == Some(path.clone()))
        .count()
}

pub async fn install(app: &AppHandle) -> AppResult<Status> {
    let svc = app.state::<Arc<Updates>>().inner().clone();
    let version = {
        let i = svc.lock();
        if i.phase != Phase::Ready || i.bytes.is_none() || i.update.is_none() {
            return Err(validation("No verified update is ready to install. Download it first."));
        }
        i.available.as_ref().map(|r| r.version.clone()).unwrap_or_default()
    };
    let b = blockers(app);
    if !b.is_empty() {
        return Err(validation(format!("Finish or stop this work before installing: {}.", b.join("; "))));
    }
    let kind = install_kind();
    let message = match kind {
        InstallKind::Nsis | InstallKind::Msi => format!(
            "ExploitX closes, the installer updates it to version {version} and starts it again.\n\nProjects, OSINT investigations, settings, stored credentials and the MCP setup are kept. Connected MCP clients are disconnected."
        ),
        InstallKind::Appimage => format!(
            "The AppImage file is replaced with version {version}. ExploitX then asks you to restart.\n\nProjects, OSINT investigations, settings, stored credentials and the MCP setup are kept."
        ),
        _ => format!(
            "The package manager installs version {version} and asks for an administrator password. ExploitX then asks you to restart.\n\nProjects, OSINT investigations, settings, stored credentials and the MCP setup are kept."
        ),
    };
    if !crate::confirm::native(app, "Install update", message, "Install update").await {
        return Err(AppError::Cancelled("Installation cancelled".into()));
    }
    // work may have started while the dialog was open
    let b = blockers(app);
    if !b.is_empty() {
        return Err(validation(format!("Finish or stop this work before installing: {}.", b.join("; "))));
    }
    let (update, bytes) = {
        let mut i = svc.lock();
        if i.phase != Phase::Ready {
            return Err(validation("The update is no longer ready to install."));
        }
        i.phase = Phase::Installing;
        i.error = None;
        (i.update.clone().expect("checked"), i.bytes.clone().expect("checked"))
    };
    svc.emit(app);
    // Windows: on success this does not return (the installer starts and ExploitX exits)
    let result = tauri::async_runtime::spawn_blocking(move || update.install(bytes.as_slice()))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    {
        let mut i = svc.lock();
        match result {
            Ok(()) => {
                i.phase = Phase::RestartRequired;
                i.bytes = None;
            }
            Err(e) => {
                let f = classify(&e);
                // a cancelled password prompt leaves the verified package ready for another try
                i.phase = if f.kind == "auth" { Phase::Ready } else { Phase::Failed };
                i.error = Some(f);
            }
        }
    }
    #[cfg(windows)]
    restart_bridge_after_failed_install(app);
    svc.emit(app);
    Ok(svc.status(app))
}

/// On Windows the shutdown hook ran (MCP bridge stopped) before the installer failed to start.
#[cfg(windows)]
fn restart_bridge_after_failed_install(app: &AppHandle) {
    if crate::commands::mcp::enabled_pref(&app.state::<Db>()) && app.state::<Arc<crate::mcp::bridge::Bridge>>().info().is_none() {
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = crate::commands::mcp::start_bridge(&handle).await;
        });
    }
}

pub fn restart(app: &AppHandle) -> AppResult<()> {
    let svc = app.state::<Arc<Updates>>().inner().clone();
    if svc.lock().phase != Phase::RestartRequired {
        return Err(validation("No installed update is waiting for a restart."));
    }
    let b = blockers(app);
    if !b.is_empty() {
        return Err(validation(format!("Finish or stop this work before restarting: {}.", b.join("; "))));
    }
    // runs the normal exit path (tool processes stopped, MCP bridge closed), then starts again
    app.request_restart();
    Ok(())
}

/* ───────────────────────── scheduler ───────────────────────── */

/// Automatic checks: the first one a while after startup, then whenever one is due. Failed
/// automatic checks back off and are only shown in the Update Center, never as notifications.
pub fn start_scheduler(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_DELAY).await;
        clean_installer_leftovers(&app);
        loop {
            let due = app.try_state::<Arc<Updates>>().is_some_and(|s| s.auto_due(&app));
            if due {
                let _ = check(&app, false).await;
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn only_newer_stable_versions_are_offered() {
        assert!(offered(&v("0.1.0"), &v("0.1.1")));
        assert!(offered(&v("0.1.0"), &v("1.0.0")));
        assert!(!offered(&v("0.1.0"), &v("0.1.0")), "same version");
        assert!(!offered(&v("0.2.0"), &v("0.1.9")), "downgrade");
        assert!(!offered(&v("0.1.0"), &v("0.2.0-beta.1")), "pre-release on the stable channel");
        assert!(offered(&v("0.2.0-beta.1"), &v("0.2.0")), "a pre-release moves to its stable release");
        assert!(!offered(&v("1.0.0"), &v("1.0.0+build.5")), "build metadata is not a new version");
    }

    #[test]
    fn install_formats_and_support() {
        assert!(support(InstallKind::Nsis, None).0);
        assert!(support(InstallKind::Msi, None).0);
        assert!(support(InstallKind::Deb, None).0);
        assert!(support(InstallKind::Rpm, None).0);
        assert!(support(InstallKind::Appimage, Some("/home/u/Cyber Hub.AppImage")).0);
        assert!(!support(InstallKind::Appimage, None).0);
        let (ok, note) = support(InstallKind::Unknown, None);
        assert!(!ok && note.unwrap().contains("not installed by an ExploitX installer"));
        // `cargo test` binaries are not bundled
        assert_eq!(install_kind(), InstallKind::Unknown);
    }

    #[test]
    fn failed_checks_back_off_up_to_the_interval() {
        assert_eq!(retry_delay(0, 24), chrono::Duration::hours(24));
        assert_eq!(retry_delay(1, 24), chrono::Duration::minutes(15));
        assert_eq!(retry_delay(2, 24), chrono::Duration::minutes(30));
        assert_eq!(retry_delay(4, 24), chrono::Duration::hours(2));
        assert_eq!(retry_delay(9, 24), chrono::Duration::hours(24));
        assert_eq!(retry_delay(9, 6), chrono::Duration::hours(6));
        assert_eq!(retry_delay(u32::MAX, 168), chrono::Duration::hours(168));
    }

    #[test]
    fn next_check_follows_settings_and_last_result() {
        let mut s = Settings { auto_check: true, frequency_hours: 24, last_check: None, last_result: None, notified_version: None };
        assert!(next_due(&s, 0).unwrap() <= Utc::now(), "never checked: due now");
        s.last_check = Some("2026-11-05T10:00:00Z".into());
        s.last_result = Some("upToDate".into());
        assert_eq!(next_due(&s, 0).unwrap().to_rfc3339(), "2026-11-06T10:00:00+00:00");
        s.last_result = Some("failed".into());
        assert_eq!(next_due(&s, 0).unwrap().to_rfc3339(), "2026-11-05T10:15:00+00:00", "a failure from the last session retries soon");
        assert_eq!(next_due(&s, 3).unwrap().to_rfc3339(), "2026-11-05T11:00:00+00:00");
        s.auto_check = false;
        assert!(next_due(&s, 0).is_none());
    }

    #[test]
    fn each_new_version_is_announced_once() {
        assert!(should_notify(None, "0.2.0"));
        assert!(!should_notify(Some("0.2.0"), "0.2.0"));
        assert!(should_notify(Some("0.2.0"), "0.3.0"));
        // a feed that went to 0.3.0 and back to 0.2.0 does not announce 0.2.0 again
        assert!(!should_notify(Some("0.3.0"), "0.2.0"));
        assert!(should_notify(Some("garbage"), "0.2.0"));
    }

    #[test]
    fn only_the_updaters_own_temp_folders_are_cleaned() {
        let p = "Cyber Hub";
        assert!(is_installer_leftover("Cyber Hub-0.2.0-updater-lto92Q", p));
        assert!(is_installer_leftover("Cyber Hub-1.10.3-updater-AbC123", p));
        assert!(!is_installer_leftover("Cyber Hub Updater Test-0.2.0-updater-lto92Q", p), "another product");
        assert!(!is_installer_leftover("Cyber Hub-notes-updater-x", p), "not a version");
        assert!(!is_installer_leftover("Cyber Hub-0.2.0-installer", p));
        assert!(!is_installer_leftover("Other-0.2.0-updater-x", p));
        assert!(!is_installer_leftover("", p));
    }

    #[test]
    fn notes_are_plain_text() {
        assert_eq!(clean_notes(Some("  Fixes\r\n- a\u{1b}[31m\u{7}\n\tb  ")), "Fixes\n- a[31m\n\tb");
        assert_eq!(clean_notes(None), "");
        let long = "x".repeat(MAX_NOTES + 10);
        assert!(clean_notes(Some(&long)).ends_with('…'));
        assert_eq!(clean_date(Some(&serde_json::json!("2026-11-05T12:00:00+02:00"))).as_deref(), Some("2026-11-05T10:00:00Z"));
        assert_eq!(clean_date(Some(&serde_json::json!("yesterday"))), None);
        assert_eq!(clean_date(None), None);
    }

    #[test]
    fn plugin_errors_get_specific_messages() {
        use tauri_plugin_updater::Error as E;
        assert_eq!(classify(&E::ReleaseNotFound).kind, "feed");
        assert_eq!(classify(&E::TargetsNotFound(vec!["windows-x86_64-nsis".into()])).kind, "manifest");
        assert_eq!(classify(&E::MissingSignedVersion).kind, "signature");
        assert_eq!(classify(&E::SignedVersionMismatch { signed: "0.1.0".into(), announced: "0.2.0".into() }).kind, "signature");
        assert_eq!(classify(&E::InsecureTransportProtocol).kind, "config");
        assert_eq!(classify(&E::AuthenticationFailed).kind, "auth");
        assert_eq!(classify(&E::Network("Download request failed with status: 404 Not Found".into())).message, "The download failed: Download request failed with status: 404 Not Found");
        assert_eq!(classify(&E::Io(std::io::Error::other("disk full"))).kind, "disk");
        assert_eq!(classify(&E::EmptyEndpoints).kind, "notConfigured");
    }
}
