//! VirusTotal commands. All requests are made here, in Rust, with the API key read from
//! the OS credential store. The key is never returned, logged or stored in the database.
//!
//! File analysis: the web view never supplies a path. `vt_file_pick` opens the native file
//! picker in the backend, hashes the file locally and returns an opaque handle. Uploading
//! (`vt_file_upload`) requires a native OS confirmation for every file; see `vtfile.rs`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio_util::sync::CancellationToken;

use crate::commands::activity::log;
use crate::commands::system::read_secret;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::ti::http::ApiError;
use crate::ti::limit::RateLimiter;
use crate::ti::{KeyId, ProviderId};
use crate::util::now;
use crate::vt::{self, Indicator, Report};
use crate::vtfile::{self, Hashes, Phase, UploadError};

pub const KEY_NAME: &str = "virustotal_api_key";
const MAX_HANDLES: usize = 10;
const HANDLE_TTL: Duration = Duration::from_secs(3600);

struct PickedFile {
    path: PathBuf,
    name: String,
    hashes: Hashes,
    picked_at: Instant,
}

pub struct VtState {
    pub(crate) http: reqwest::Client,
    pub(crate) base: String,
    pub(crate) limiter: RateLimiter,
    files: Mutex<HashMap<String, PickedFile>>,
    uploads: Mutex<HashMap<String, CancellationToken>>,
}

impl VtState {
    /// File uploads that are sending or waiting for their confirmation.
    pub fn uploads_in_progress(&self) -> usize {
        self.uploads.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn new() -> AppResult<Self> {
        let (max, window) = ProviderId::Virustotal.rate();
        Ok(Self {
            http: crate::ti::http::client(Duration::from_secs(20)).map_err(AppError::Internal)?,
            base: ProviderId::Virustotal.base(),
            limiter: RateLimiter::new(max, window),
            files: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
        })
    }

    fn acquire(&self) -> AppResult<()> {
        self.limiter
            .try_acquire(Instant::now())
            .map_err(|wait| AppError::RateLimited(format!("The public VirusTotal API allows 4 requests per minute. Try again in {wait} s.")))
    }
}

pub fn api_error(e: ApiError) -> AppError {
    let msg = e.message(vt::NAME);
    match e {
        ApiError::Quota(_) => AppError::RateLimited(msg),
        ApiError::Network(_) | ApiError::Server(_) | ApiError::Unexpected(_) => AppError::Network(msg),
        _ => AppError::Validation(msg),
    }
}

fn key() -> AppResult<String> {
    read_secret(KEY_NAME).ok_or_else(|| validation(crate::commands::threat_intel::not_configured(ProviderId::Virustotal)))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupResult {
    pub kind: vt::Kind,
    pub indicator: String,
    pub hash_type: Option<&'static str>,
    /// None when VirusTotal has no record of the indicator
    pub report: Option<Report>,
    /// "live" (fetched now) or "cache"
    pub source: &'static str,
    pub fetched_at: String,
    pub fresh_until: String,
}

pub fn ttl_end(fetched_at: &str, ttl_secs: i64) -> String {
    chrono::DateTime::parse_from_rfc3339(fetched_at)
        .map(|t| (t + chrono::Duration::seconds(ttl_secs)).with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn ttl(not_found: bool) -> i64 {
    if not_found {
        vt::NOT_FOUND_TTL_SECS
    } else {
        vt::REPORT_TTL_SECS
    }
}

pub fn cached(db: &Db, ind: &Indicator) -> AppResult<Option<(Option<Report>, String, bool)>> {
    db.with(|c| {
        let row: Option<(Option<String>, bool, String)> = c
            .query_row("SELECT data, not_found, fetched_at FROM vt_cache WHERE id = ?1", params![ind.cache_key()], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?))
            })
            .optional()?;
        Ok(row.map(|(data, nf, at)| (data.and_then(|d| serde_json::from_str(&d).ok()), at, nf)))
    })
}

fn result(ind: &Indicator, report: Option<Report>, source: &'static str, fetched_at: String) -> LookupResult {
    let fresh_until = ttl_end(&fetched_at, ttl(report.is_none()));
    LookupResult { kind: ind.kind, indicator: ind.value.clone(), hash_type: ind.hash_label(), report, source, fetched_at, fresh_until }
}

/// Reputation lookup through the cache. Only GET requests for existing records.
/// `log_activity` is false when called as part of a multi-provider investigation.
pub async fn fetch(db: &Db, st: &VtState, ind: &Indicator, refresh: bool, log_activity: bool) -> AppResult<LookupResult> {
    if !refresh {
        if let Some((report, at, nf)) = cached(db, ind)? {
            if vt::is_fresh(&at, nf, chrono::Utc::now()) {
                return Ok(result(ind, report, "cache", at));
            }
        }
    }
    let key = key()?;
    st.acquire()?;
    let outcome = vt::get(&st.http, &st.base, &vt::path(ind), &key).await;
    drop(key);
    let report = match outcome {
        Ok(body) => Some(vt::parse_report(ind, &body).map_err(AppError::Network)?),
        Err(ApiError::NotFound) => None,
        Err(e) => return Err(api_error(e)),
    };

    let at = now();
    let data = report.as_ref().map(serde_json::to_string).transpose()?;
    let summary = match &report {
        Some(r) => format!("{} malicious, {} suspicious of {} engines", r.stats.malicious, r.stats.suspicious, r.engines_total),
        None => "no VirusTotal record".to_string(),
    };
    let shown: String = ind.value.chars().take(120).collect();
    db.with(|c| {
        c.execute(
            "INSERT INTO vt_cache (id, kind, indicator, data, not_found, fetched_at) VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET data=excluded.data, not_found=excluded.not_found, fetched_at=excluded.fetched_at",
            params![ind.cache_key(), ind.kind.as_str(), ind.value, data, report.is_none() as i64, at],
        )?;
        if log_activity {
            log(c, "vt_lookup", &format!("VirusTotal {} lookup: {shown}", ind.kind.noun()), &summary, Some("vt"), Some(&ind.cache_key()), None)?;
        }
        Ok(())
    })?;
    Ok(result(ind, report, "live", at))
}

/// Reputation lookup. Serves a fresh cached result unless `refresh` is set.
#[tauri::command]
pub async fn vt_lookup(db: State<'_, Db>, vtst: State<'_, VtState>, query: String, refresh: bool) -> AppResult<LookupResult> {
    let ind = vt::detect(&query).map_err(AppError::Validation)?;
    fetch(&db, &vtst, &ind, refresh, true).await
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentLookup {
    pub kind: String,
    pub indicator: String,
    pub malicious: Option<u32>,
    pub suspicious: Option<u32>,
    pub engines_total: Option<u32>,
    pub not_found: bool,
    pub fetched_at: String,
    pub fresh: bool,
}

#[tauri::command]
pub async fn vt_recent(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<RecentLookup>> {
    let limit = limit.unwrap_or(20).clamp(1, 200);
    let now_t = chrono::Utc::now();
    db.with(|c| {
        let mut stmt = c.prepare("SELECT kind, indicator, data, not_found, fetched_at FROM vt_cache ORDER BY fetched_at DESC LIMIT ?1")?;
        let rows = stmt
            .query_map(params![limit], |r| {
                let data: Option<String> = r.get(2)?;
                let nf = r.get::<_, i64>(3)? != 0;
                let at: String = r.get(4)?;
                let rep: Option<Report> = data.and_then(|d| serde_json::from_str(&d).ok());
                Ok(RecentLookup {
                    kind: r.get(0)?,
                    indicator: r.get(1)?,
                    malicious: rep.as_ref().map(|x| x.stats.malicious),
                    suspicious: rep.as_ref().map(|x| x.stats.suspicious),
                    engines_total: rep.as_ref().map(|x| x.engines_total),
                    not_found: nf,
                    fresh: vt::is_fresh(&at, nf, now_t),
                    fetched_at: at,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn vt_cache_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM vt_cache", [])?;
        Ok(())
    })
}

#[tauri::command]
pub async fn vt_key_status() -> AppResult<bool> {
    Ok(crate::commands::system::secret_configured(KeyId::Virustotal.secret_name()))
}

/* ─────────────── file analysis ─────────────── */

/// User-configured upload limit in bytes (preference `vt.uploadLimitMb`, 1–650, default 32).
pub fn upload_limit(db: &Db) -> u64 {
    let mb = db
        .with(|c| {
            Ok(c.query_row("SELECT value FROM user_preferences WHERE key = 'vt.uploadLimitMb'", [], |r| r.get::<_, String>(0)).optional()?)
        })
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_str::<f64>(&v).ok())
        .map(|v| v.round().clamp(1.0, 650.0) as u64)
        .unwrap_or(vtfile::DEFAULT_LIMIT_MB);
    mb * 1024 * 1024
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedInfo {
    pub handle: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    /// "direct" (≤ 32 MB) or "upload_url"
    pub upload_mode: &'static str,
    pub limit_bytes: u64,
    pub within_limit: bool,
}

async fn pick_file(app: &AppHandle) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Choose a file to analyse");
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.pick_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    rx.await.ok().flatten()
}

/// Open the native picker, hash the chosen file locally and return a handle. Nothing is sent.
#[tauri::command]
pub async fn vt_file_pick(app: AppHandle, db: State<'_, Db>, vtst: State<'_, VtState>) -> AppResult<Option<PickedInfo>> {
    let Some(path) = pick_file(&app).await else { return Ok(None) };
    let p2 = path.clone();
    let hashes = tokio::task::spawn_blocking(move || vtfile::hash_file(&p2)).await.map_err(|e| AppError::Internal(e.to_string()))?.map_err(AppError::Validation)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let limit = upload_limit(&db).min(vtfile::API_MAX);
    let handle = vtfile::token();
    let info = PickedInfo {
        handle: handle.clone(),
        name: name.clone(),
        size: hashes.size,
        sha256: hashes.sha256.clone(),
        sha1: hashes.sha1.clone(),
        md5: hashes.md5.clone(),
        upload_mode: if hashes.size <= vtfile::DIRECT_MAX { "direct" } else { "upload_url" },
        limit_bytes: limit,
        within_limit: hashes.size <= limit,
    };
    let mut files = vtst.files.lock().map_err(|_| AppError::Internal("lock".into()))?;
    files.retain(|_, f| f.picked_at.elapsed() < HANDLE_TTL);
    while files.len() >= MAX_HANDLES {
        let oldest = files.iter().min_by_key(|(_, f)| f.picked_at).map(|(k, _)| k.clone());
        match oldest {
            Some(k) => files.remove(&k),
            None => break,
        };
    }
    files.insert(handle, PickedFile { path, name, hashes, picked_at: Instant::now() });
    Ok(Some(info))
}

#[tauri::command]
pub async fn vt_file_forget(vtst: State<'_, VtState>, handle: String) -> AppResult<()> {
    vtst.files.lock().map_err(|_| AppError::Internal("lock".into()))?.remove(&handle);
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadEvent {
    pub phase: Phase,
    pub sent: u64,
    pub total: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResult {
    pub analysis_id: String,
    pub sha256: String,
}

/// Upload a picked file for a new public analysis. Requires an explicit native confirmation
/// every time; returns `cancelled` without sending anything if the user declines.
#[tauri::command]
pub async fn vt_file_upload(
    app: AppHandle,
    db: State<'_, Db>,
    vtst: State<'_, VtState>,
    handle: String,
    on_event: Channel<UploadEvent>,
) -> AppResult<UploadResult> {
    let (path, name, hashes) = {
        let files = vtst.files.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let f = files.get(&handle).filter(|f| f.picked_at.elapsed() < HANDLE_TTL).ok_or_else(|| validation("Select the file again."))?;
        (f.path.clone(), f.name.clone(), f.hashes.clone())
    };
    let key = key()?;
    let limit = upload_limit(&db);
    if hashes.size > limit.min(vtfile::API_MAX) {
        return Err(AppError::Validation(UploadError::TooLarge { size: hashes.size, limit: limit.min(vtfile::API_MAX) }.message()));
    }
    // The upload-URL flow makes two API requests. Check now without using quota, so the user is
    // not asked to confirm an upload that would be refused; take the slots only after approval.
    let requests = if hashes.size > vtfile::DIRECT_MAX { 2 } else { 1 };
    let busy = |wait: u64| format!("The public VirusTotal API allows 4 requests per minute. Try again in {wait} s.");
    vtst.limiter.check(Instant::now(), requests).map_err(|w| AppError::RateLimited(busy(w)))?;

    let cancel = CancellationToken::new();
    {
        let mut uploads = vtst.uploads.lock().map_err(|_| AppError::Internal("lock".into()))?;
        if uploads.contains_key(&handle) {
            return Err(validation("This file is already being uploaded."));
        }
        uploads.insert(handle.clone(), cancel.clone());
    }
    let admit = || vtst.limiter.try_acquire_n(Instant::now(), requests).map_err(busy);
    let work_dir = crate::util::data_dir(&app)?.join("runtime");
    let channel = on_event.clone();
    let app2 = app.clone();
    let outcome = vtfile::upload(
        vtfile::Plan {
            client: &vtst.http,
            base: &vtst.base,
            key: &key,
            source: &path,
            file_name: &name,
            hashes: &hashes,
            limit,
            direct_max: vtfile::DIRECT_MAX,
            work_dir: &work_dir,
            allow_loopback: crate::ti::mock_active(),
            admit: &admit,
        },
        |message| async move { crate::confirm::native(&app2, "Upload file to VirusTotal", message, "Upload publicly").await },
        move |phase, sent, total| {
            let _ = channel.send(UploadEvent { phase, sent, total });
        },
        cancel,
    )
    .await;
    drop(key);
    vtst.uploads.lock().map_err(|_| AppError::Internal("lock".into()))?.remove(&handle);

    let analysis_id = match outcome {
        Ok(id) => id,
        Err(UploadError::Cancelled) => return Err(AppError::Cancelled(UploadError::Cancelled.message())),
        Err(e @ UploadError::RateLimited(_)) => return Err(AppError::RateLimited(e.message())),
        Err(UploadError::Api(e)) => return Err(api_error(e)),
        Err(e @ UploadError::Io(_)) => return Err(AppError::Internal(e.message())),
        Err(e) => return Err(AppError::Validation(e.message())),
    };
    let shown: String = name.chars().take(120).collect();
    db.with(|c| {
        log(c, "vt_upload", &format!("VirusTotal file upload: {shown}"), &format!("SHA-256 {} · {} · analysis queued", hashes.sha256, vtfile::human_size(hashes.size)), Some("vt"), Some(&format!("file:{}", hashes.sha256)), None)
    })?;
    Ok(UploadResult { analysis_id, sha256: hashes.sha256 })
}

/// Cancel an upload in progress (no effect once VirusTotal has accepted the file).
#[tauri::command]
pub async fn vt_file_cancel(vtst: State<'_, VtState>, handle: String) -> AppResult<bool> {
    let token = vtst.uploads.lock().map_err(|_| AppError::Internal("lock".into()))?.get(&handle).cloned();
    Ok(token.map(|t| t.cancel()).is_some())
}

/// Status of an analysis started by an upload.
#[tauri::command]
pub async fn vt_analysis(vtst: State<'_, VtState>, analysis_id: String) -> AppResult<vtfile::AnalysisStatus> {
    if !vtfile::valid_analysis_id(&analysis_id) {
        return Err(validation("Invalid analysis id"));
    }
    let key = key()?;
    vtst.acquire()?;
    let body = vt::get(&vtst.http, &vtst.base, &vtfile::analysis_path(&analysis_id), &key).await.map_err(api_error)?;
    vtfile::parse_analysis(&body).map_err(api_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_end_adds_the_right_lifetime() {
        let at = "2026-01-01T00:00:00Z";
        assert_eq!(ttl_end(at, ttl(false)), "2026-01-02T00:00:00Z");
        assert_eq!(ttl_end(at, ttl(true)), "2026-01-01T01:00:00Z");
    }

    #[test]
    fn upload_limit_reads_and_clamps_the_preference() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(upload_limit(&db), 32 * 1024 * 1024);
        db.with(|c| Ok(c.execute("INSERT INTO user_preferences (key, value, updated_at) VALUES ('vt.uploadLimitMb', '5000', 'x')", [])?)).unwrap();
        assert_eq!(upload_limit(&db), 650 * 1024 * 1024);
    }
}
