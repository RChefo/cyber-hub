//! Threat-intelligence commands: provider status, multi-provider lookups, history, saved
//! indicators and report export.
//!
//! * Every provider runs independently and concurrently; one provider's failure, missing
//!   credential or rate limit never prevents the others from returning results.
//! * Credentials are provisioned by the application owner (developer-only `cyberhub-keys`
//!   tool, see docs/PROVISIONING.md) and only read here. No command can read, set, test or
//!   delete a credential; the UI only learns whether a provider is configured.
//! * Results are cached per provider (`ti_cache`; VirusTotal keeps using `vt_cache`).
//! * No command submits, reports or changes anything at a provider.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::commands::activity::log;
use crate::commands::system::{read_secret, secret_configured, NVD_KEY};
use crate::commands::virustotal::{self, ttl_end, VtState};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::ti::http::ApiError;
use crate::ti::indicator::{self, Indicator, Kind};
use crate::ti::lifecycle;
use crate::ti::limit::RateLimiter;
use crate::ti::model::{Level, Parsed, ProviderResult, Report, Status};
use crate::ti::{abusech, abuseipdb, otx, shodan, KeyId, ProviderId};
use crate::util::{clean, now};
use crate::vt;

/// Last observed outcome of a real lookup, per provider (since the app started). Messages are
/// the same sanitized texts shown on results; they never contain a credential.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    /// "ok" | "rate_limited" | "rejected" | "error"
    pub state: &'static str,
    pub message: Option<String>,
    pub at: String,
    pub quota: Option<String>,
}

/// What a lookup result says about the service, if anything (cache hits and skipped
/// providers say nothing new).
pub fn observed_state(r: &ProviderResult) -> Option<&'static str> {
    if r.source.as_deref() == Some("cache") {
        return None;
    }
    match r.status {
        Status::Found | Status::NotFound => Some("ok"),
        Status::RateLimited => Some("rate_limited"),
        Status::Error if r.message.as_deref().is_some_and(|m| m.contains("rejected the configured credentials")) => Some("rejected"),
        Status::Error => Some("error"),
        Status::Unsupported | Status::Disabled | Status::NoKey => None,
    }
}

pub struct TiState {
    http: reqwest::Client,
    limiters: HashMap<ProviderId, RateLimiter>,
    health: Mutex<HashMap<ProviderId, Health>>,
}

impl TiState {
    pub fn new() -> AppResult<Self> {
        let limiters = ProviderId::ALL
            .into_iter()
            .filter(|p| *p != ProviderId::Virustotal) // VirusTotal shares VtState's limiter
            .map(|p| {
                let (max, window) = p.rate();
                (p, RateLimiter::new(max, window))
            })
            .collect();
        Ok(Self {
            http: crate::ti::http::client(Duration::from_secs(20)).map_err(AppError::Internal)?,
            limiters,
            health: Mutex::new(HashMap::new()),
        })
    }

    fn record(&self, p: ProviderId, r: &ProviderResult) {
        let Some(state) = observed_state(r) else { return };
        if let Ok(mut h) = self.health.lock() {
            let quota = r.quota.clone().or_else(|| h.get(&p).and_then(|x| x.quota.clone()));
            h.insert(p, Health { state, message: if state == "ok" { None } else { r.message.clone() }, at: now(), quota });
        }
    }
}

fn provider(id: &str) -> AppResult<ProviderId> {
    ProviderId::parse(id).ok_or_else(|| validation("Unknown provider"))
}

fn enabled_map(db: &Db) -> AppResult<HashMap<String, bool>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT provider, enabled FROM ti_provider_settings")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?;
        Ok(rows.collect::<Result<HashMap<_, _>, _>>()?)
    })
}

/* ─────────────── provider status (read-only) ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub kinds: &'static [&'static str],
    /// credentials have been provisioned by the application owner (the value is never exposed)
    pub configured: bool,
    pub enabled: bool,
    pub service_note: &'static str,
    pub docs_url: &'static str,
    pub rate_limit: String,
    /// last observed outcome of a real lookup since the app started
    pub health: Option<Health>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersOverview {
    pub providers: Vec<ProviderStatus>,
    /// NVD works without a key at a lower rate; this only says whether the owner provisioned one
    pub nvd_configured: bool,
}

#[tauri::command]
pub async fn ti_providers(db: State<'_, Db>, tist: State<'_, TiState>) -> AppResult<ProvidersOverview> {
    let enabled = enabled_map(&db)?;
    let configured: HashMap<KeyId, bool> = KeyId::ALL.into_iter().map(|k| (k, secret_configured(k.secret_name()))).collect();
    let health = tist.health.lock().map(|h| h.clone()).unwrap_or_default();
    Ok(ProvidersOverview {
        providers: ProviderId::ALL
            .into_iter()
            .map(|p| {
                let (max, window) = p.rate();
                ProviderStatus {
                    id: p.as_str(),
                    name: p.name(),
                    description: p.description(),
                    kinds: p.kinds(),
                    configured: configured[&p.key()],
                    enabled: enabled.get(p.as_str()).copied().unwrap_or(true),
                    service_note: p.service_note(),
                    docs_url: p.docs_url(),
                    rate_limit: RateLimiter::new(max, window).describe(),
                    health: health.get(&p).cloned(),
                }
            })
            .collect(),
        nvd_configured: secret_configured(NVD_KEY),
    })
}

#[tauri::command]
pub async fn ti_provider_set_enabled(db: State<'_, Db>, provider_id: String, enabled: bool) -> AppResult<()> {
    let p = provider(&provider_id)?;
    db.with(|c| {
        c.execute(
            "INSERT INTO ti_provider_settings (provider, enabled, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(provider) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
            params![p.as_str(), enabled as i64, now()],
        )?;
        Ok(())
    })
}

/* ─────────────── lookups ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detected {
    pub kind: Kind,
    pub label: &'static str,
    pub value: String,
    pub hash_type: Option<&'static str>,
}

/// Classify an indicator (no network). Used for the live type hint in search boxes.
#[tauri::command]
pub async fn ti_detect(query: String) -> AppResult<Detected> {
    let i = indicator::detect(&query).map_err(AppError::Validation)?;
    Ok(Detected { kind: i.kind, label: i.kind.label(), value: i.value.clone(), hash_type: i.hash_label() })
}

fn base_result(p: ProviderId, status: Status, message: Option<String>) -> ProviderResult {
    ProviderResult {
        provider: p.as_str().into(),
        provider_name: p.name().into(),
        status,
        report: None,
        message,
        source: None,
        fetched_at: None,
        fresh_until: None,
        quota: None,
    }
}

fn unsupported_message(p: ProviderId, ind: &Indicator) -> String {
    match (ind.kind, ind.hash_label()) {
        (Kind::File, Some(h)) if p != ProviderId::Abuseipdb && p != ProviderId::Shodan => format!("{} does not accept {h} hashes.", p.name()),
        _ => format!("{} does not look up {}.", p.name(), ind.kind.plural()),
    }
}

/// (found, report, quota, fetched_at)
type CachedResult = (bool, Report, Option<String>, String);

fn cached_ti(db: &Db, p: ProviderId, ind: &Indicator) -> AppResult<Option<CachedResult>> {
    db.with(|c| {
        let row: Option<(i64, String, Option<String>, String)> = c
            .query_row(
                "SELECT found, data, quota, fetched_at FROM ti_cache WHERE provider = ?1 AND indicator_key = ?2",
                params![p.as_str(), ind.cache_key()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        Ok(row.and_then(|(f, d, q, at)| serde_json::from_str::<Report>(&d).ok().map(|rep| (f != 0, rep, q, at))))
    })
}

fn fresh(at: &str, ttl: i64) -> bool {
    chrono::DateTime::parse_from_rfc3339(at).map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds() < ttl).unwrap_or(false)
}

fn from_parts(p: ProviderId, found: bool, report: Report, quota: Option<String>, source: &str, at: String) -> ProviderResult {
    let mut r = base_result(p, if found { Status::Found } else { Status::NotFound }, None);
    if !found {
        r.message = Some(format!("{} has no record of this indicator.", p.name()));
    }
    let has_content = found || !report.facts.is_empty();
    r.report = has_content.then_some(report);
    r.fresh_until = Some(ttl_end(&at, p.ttl(found)));
    r.fetched_at = Some(at);
    r.source = Some(source.into());
    r.quota = quota;
    r
}

async fn call(p: ProviderId, tist: &TiState, key: &str, ind: &Indicator) -> Result<(Parsed, Option<String>), ApiError> {
    let base = p.base();
    let c = &tist.http;
    match p {
        ProviderId::Abuseipdb => abuseipdb::lookup(c, &base, key, ind).await,
        ProviderId::Otx => otx::lookup(c, &base, key, ind).await.map(|x| (x, None)),
        ProviderId::Urlhaus => abusech::urlhaus_lookup(c, &base, key, ind).await.map(|x| (x, None)),
        ProviderId::Malwarebazaar => abusech::bazaar_lookup(c, &base, key, ind).await.map(|x| (x, None)),
        ProviderId::Threatfox => abusech::threatfox_lookup(c, &base, key, ind).await.map(|x| (x, None)),
        ProviderId::Shodan => shodan::lookup(c, &base, key, ind).await.map(|x| (x, None)),
        ProviderId::Virustotal => Err(ApiError::Unexpected("handled separately".into())),
    }
}

pub fn not_configured(p: ProviderId) -> String {
    format!("{} is not configured: its credentials have not been provisioned by the application owner, so this service is unavailable.", p.name())
}

/// Run one provider and record the observed service state.
async fn run_one(db: &Db, vtst: &VtState, tist: &TiState, p: ProviderId, ind: &Indicator, refresh: bool, enabled: bool) -> ProviderResult {
    let r = run_provider(db, vtst, tist, p, ind, refresh, enabled).await;
    tist.record(p, &r);
    r
}

/// Run one provider. Never returns an error: every outcome is a status in the result.
async fn run_provider(db: &Db, vtst: &VtState, tist: &TiState, p: ProviderId, ind: &Indicator, refresh: bool, enabled: bool) -> ProviderResult {
    if !p.supports(ind) {
        return base_result(p, Status::Unsupported, Some(unsupported_message(p, ind)));
    }
    if !enabled {
        return base_result(p, Status::Disabled, Some(format!("{} is turned off in Settings.", p.name())));
    }
    let has_key = read_secret(p.key().secret_name()).is_some();

    if p == ProviderId::Virustotal {
        if !has_key && (refresh || virustotal::cached(db, ind).ok().flatten().is_none()) {
            return base_result(p, Status::NoKey, Some(not_configured(p)));
        }
        return match virustotal::fetch(db, vtst, ind, refresh, false).await {
            Ok(lr) => {
                let found = lr.report.is_some();
                let report = lr.report.as_ref().map(vt::to_ti).unwrap_or_default();
                from_parts(p, found, report, None, lr.source, lr.fetched_at)
            }
            Err(AppError::RateLimited(m)) => base_result(p, Status::RateLimited, Some(m)),
            Err(e) => base_result(p, Status::Error, Some(e.to_string())),
        };
    }

    if !refresh {
        if let Ok(Some((found, report, quota, at))) = cached_ti(db, p, ind) {
            if fresh(&at, p.ttl(found)) {
                return from_parts(p, found, report, quota, "cache", at);
            }
        }
    }
    let Some(key) = read_secret(p.key().secret_name()) else {
        return base_result(p, Status::NoKey, Some(not_configured(p)));
    };
    if let Err(wait) = tist.limiters[&p].try_acquire(Instant::now()) {
        return base_result(p, Status::RateLimited, Some(format!("Cyber Hub limits {} to {}. Try again in {wait} s.", p.name(), tist.limiters[&p].describe())));
    }
    let outcome = call(p, tist, &key, ind).await;
    drop(key);
    match outcome {
        Ok((parsed, quota)) => {
            let at = now();
            if let Ok(data) = serde_json::to_string(&parsed.report) {
                let _ = db.with(|c| {
                    c.execute(
                        "INSERT INTO ti_cache (provider, indicator_key, kind, indicator, found, data, quota, fetched_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                         ON CONFLICT(provider, indicator_key) DO UPDATE SET found=excluded.found, data=excluded.data, quota=excluded.quota, fetched_at=excluded.fetched_at",
                        params![p.as_str(), ind.cache_key(), ind.kind.as_str(), ind.value, parsed.found as i64, data, quota, at],
                    )?;
                    Ok(())
                });
            }
            from_parts(p, parsed.found, parsed.report, quota, "live", at)
        }
        Err(ApiError::NotFound) => {
            let at = now();
            let _ = db.with(|c| {
                c.execute(
                    "INSERT INTO ti_cache (provider, indicator_key, kind, indicator, found, data, quota, fetched_at) VALUES (?1,?2,?3,?4,0,'{}',NULL,?5)
                     ON CONFLICT(provider, indicator_key) DO UPDATE SET found=0, data='{}', quota=NULL, fetched_at=excluded.fetched_at",
                    params![p.as_str(), ind.cache_key(), ind.kind.as_str(), ind.value, at],
                )?;
                Ok(())
            });
            from_parts(p, false, Report::default(), None, "live", at)
        }
        Err(e @ ApiError::Quota(_)) => base_result(p, Status::RateLimited, Some(e.message(p.name()))),
        Err(e) => base_result(p, Status::Error, Some(e.message(p.name()))),
    }
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub malicious: Vec<String>,
    pub suspicious: Vec<String>,
    pub clean: Vec<String>,
    pub informational: Vec<String>,
    pub no_verdict: Vec<String>,
    pub no_record: Vec<String>,
    pub failed: Vec<String>,
    pub skipped: Vec<String>,
}

/// Counts providers per outcome. This is not a score: it only tells which sources said what.
pub fn summarize(results: &[ProviderResult]) -> Summary {
    let mut s = Summary::default();
    for r in results {
        let name = r.provider_name.clone();
        match r.status {
            Status::Found => match r.report.as_ref().and_then(|x| x.verdict.as_ref()).map(|v| v.level) {
                Some(Level::Malicious) => s.malicious.push(name),
                Some(Level::Suspicious) => s.suspicious.push(name),
                Some(Level::Clean) => s.clean.push(name),
                Some(Level::Info) => s.informational.push(name),
                _ => s.no_verdict.push(name),
            },
            Status::NotFound => s.no_record.push(name),
            Status::Error | Status::RateLimited => s.failed.push(name),
            Status::Unsupported | Status::Disabled | Status::NoKey => s.skipped.push(name),
        }
    }
    s
}

fn summary_line(s: &Summary) -> String {
    let mut parts = Vec::new();
    for (label, v) in [
        ("malicious", &s.malicious),
        ("suspicious", &s.suspicious),
        ("clean", &s.clean),
        ("info", &s.informational),
        ("no record", &s.no_record),
        ("failed", &s.failed),
    ] {
        if !v.is_empty() {
            parts.push(format!("{label}: {}", v.join(", ")));
        }
    }
    if parts.is_empty() {
        "no provider returned data".into()
    } else {
        parts.join(" · ")
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub kind: Kind,
    pub indicator: String,
    pub hash_type: Option<&'static str>,
    pub results: Vec<ProviderResult>,
    pub summary: Summary,
    pub searched_at: String,
    pub saved: bool,
}

pub(crate) async fn investigate(db: &Db, vtst: &VtState, tist: &TiState, ind: &Indicator, only: Option<&[ProviderId]>, refresh: bool) -> AppResult<Vec<ProviderResult>> {
    let enabled = enabled_map(db)?;
    let want = |p: ProviderId| only.is_none_or(|o| o.contains(&p));
    let on = |p: ProviderId| enabled.get(p.as_str()).copied().unwrap_or(true);
    macro_rules! one {
        ($p:expr) => {
            async {
                if want($p) {
                    Some(run_one(db, vtst, tist, $p, ind, refresh, on($p)).await)
                } else {
                    None
                }
            }
        };
    }
    let (a, b, c, d, e, f, g) = tokio::join!(
        one!(ProviderId::Virustotal),
        one!(ProviderId::Abuseipdb),
        one!(ProviderId::Otx),
        one!(ProviderId::Urlhaus),
        one!(ProviderId::Malwarebazaar),
        one!(ProviderId::Threatfox),
        one!(ProviderId::Shodan)
    );
    Ok([a, b, c, d, e, f, g].into_iter().flatten().collect())
}

/// Look an indicator up across the selected (default: all) providers.
#[tauri::command]
pub async fn ti_lookup(
    db: State<'_, Db>,
    vtst: State<'_, VtState>,
    tist: State<'_, TiState>,
    query: String,
    providers: Option<Vec<String>>,
    refresh: bool,
) -> AppResult<Investigation> {
    let ind = indicator::detect(&query).map_err(AppError::Validation)?;
    let only: Option<Vec<ProviderId>> = providers.map(|v| v.iter().map(|p| provider(p)).collect::<AppResult<Vec<_>>>()).transpose()?;
    let results = investigate(&db, &vtst, &tist, &ind, only.as_deref(), refresh).await?;
    let summary = summarize(&results);
    let at = now();
    let shown: String = ind.value.chars().take(120).collect();
    let saved = db.with(|c| {
        c.execute(
            "INSERT INTO ti_history (kind, indicator, summary, searched_at) VALUES (?1, ?2, ?3, ?4)",
            params![ind.kind.as_str(), ind.value, serde_json::to_string(&summary)?, at],
        )?;
        // keep history bounded
        c.execute("DELETE FROM ti_history WHERE id NOT IN (SELECT id FROM ti_history ORDER BY searched_at DESC LIMIT 500)", [])?;
        log(c, "ti_lookup", &format!("Threat intel lookup: {shown}"), &summary_line(&summary), Some("ti"), Some(&ind.cache_key()), None)?;
        Ok(c.query_row("SELECT COUNT(*) FROM ti_saved WHERE indicator = ?1", params![ind.value], |r| r.get::<_, i64>(0))? > 0)
    })?;
    Ok(Investigation { kind: ind.kind, indicator: ind.value.clone(), hash_type: ind.hash_label(), results, summary, searched_at: at, saved })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: i64,
    pub kind: String,
    pub indicator: String,
    pub summary: Summary,
    pub searched_at: String,
}

#[tauri::command]
pub async fn ti_history(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<HistoryEntry>> {
    let limit = limit.unwrap_or(30).clamp(1, 500);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, kind, indicator, summary, searched_at FROM ti_history WHERE id IN
             (SELECT MAX(id) FROM ti_history GROUP BY indicator) ORDER BY searched_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(HistoryEntry {
                id: r.get(0)?,
                kind: r.get(1)?,
                indicator: r.get(2)?,
                summary: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
                searched_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
}

#[tauri::command]
pub async fn ti_history_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM ti_history", [])?;
        Ok(())
    })
}

#[tauri::command]
pub async fn ti_cache_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM ti_cache", [])?;
        Ok(())
    })
}

/// Saved indicators with their source, reliability, confidence, status and validity.
#[tauri::command]
pub async fn ti_saved_list(db: State<'_, Db>) -> AppResult<Vec<lifecycle::Saved>> {
    db.with(lifecycle::list)
}

#[tauri::command]
pub async fn ti_saved_add(db: State<'_, Db>, query: String, note: String) -> AppResult<()> {
    let ind = indicator::detect(&query).map_err(AppError::Validation)?;
    let note = clean("Note", &note, 500, false)?;
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        let existed = lifecycle::find(&tx, &ind.value)?;
        let ts = now();
        tx.execute(
            "INSERT INTO ti_saved (kind, indicator, note, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(indicator) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at",
            params![ind.kind.as_str(), ind.value, note, ts],
        )?;
        match existed {
            None => lifecycle::record(&tx, tx.last_insert_rowid(), "saved", "")?,
            Some(s) if s.note != note => lifecycle::record(&tx, s.id, "updated", "note changed")?,
            Some(_) => {}
        }
        tx.commit()?;
        Ok(())
    })
}

/// Changes the source, reliability, confidence, status, validity or note of a saved indicator;
/// every change is recorded in its history.
#[tauri::command]
pub async fn ti_saved_update(db: State<'_, Db>, id: i64, changes: lifecycle::Changes) -> AppResult<lifecycle::Saved> {
    db.with(|c| lifecycle::update(c, id, &changes))
}

#[tauri::command]
pub async fn ti_saved_history(db: State<'_, Db>, id: i64) -> AppResult<Vec<lifecycle::Event>> {
    db.with(|c| lifecycle::history(c, id))
}

#[tauri::command]
pub async fn ti_saved_remove(db: State<'_, Db>, query: String) -> AppResult<()> {
    let ind = indicator::detect(&query).map_err(AppError::Validation)?;
    db.with(|c| {
        c.execute("DELETE FROM ti_saved WHERE indicator = ?1", params![ind.value])?;
        Ok(())
    })
}

/* ─────────────── export ─────────────── */

/// Latest stored results for every provider (no network).
pub(crate) fn stored_results(db: &Db, ind: &Indicator) -> AppResult<Vec<ProviderResult>> {
    let mut out = Vec::new();
    for p in ProviderId::ALL {
        if !p.supports(ind) {
            continue;
        }
        if p == ProviderId::Virustotal {
            if let Some((report, at, nf)) = virustotal::cached(db, ind)? {
                out.push(from_parts(p, !nf, report.as_ref().map(vt::to_ti).unwrap_or_default(), None, "cache", at));
            }
        } else if let Some((found, report, quota, at)) = cached_ti(db, p, ind)? {
            out.push(from_parts(p, found, report, quota, "cache", at));
        }
    }
    Ok(out)
}

/// Provider-supplied text is data: keep it on one line, inside tables, and inert in
/// Markdown viewers that render inline HTML.
fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' | '[' | ']' | '(' | ')' | '!' | '*' | '_' | '`' | '#' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' | '\n' | '\u{2028}' | '\u{2029}' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

pub fn markdown(ind: &Indicator, results: &[ProviderResult], generated: &str) -> String {
    let summary = summarize(results);
    let mut m = String::new();
    m.push_str(&format!("# Threat intelligence report: `{}`\n\n", ind.value.replace('`', "'")));
    m.push_str(&format!("- Type: {}{}\n- Generated: {generated} by Cyber Hub\n", ind.kind.label(), ind.hash_label().map(|h| format!(" ({h})")).unwrap_or_default()));
    m.push_str(&format!("- Summary: {}\n\n", summary_line(&summary)));
    m.push_str("> Each provider's verdict is reported in its own terms. Cyber Hub does not combine scores from different providers.\n\n");
    for r in results {
        m.push_str(&format!("## {}\n\n", r.provider_name));
        let status = match r.status {
            Status::Found => "has data",
            Status::NotFound => "no record",
            Status::Unsupported => "not applicable to this indicator type",
            Status::NoKey => "not run (no API key)",
            Status::Disabled => "not run (turned off)",
            Status::RateLimited => "rate limited",
            Status::Error => "failed",
        };
        m.push_str(&format!("- Status: {status}\n"));
        if let Some(at) = &r.fetched_at {
            m.push_str(&format!("- Retrieved: {at}\n"));
        }
        if let Some(msg) = &r.message {
            m.push_str(&format!("- Note: {}\n", md_escape(msg)));
        }
        if let Some(rep) = &r.report {
            if let Some(v) = &rep.verdict {
                m.push_str(&format!("- Verdict (provider's wording): {}\n", md_escape(&v.label)));
            }
            for s in &rep.scores {
                m.push_str(&format!("- {}: {}\n", md_escape(&s.label), md_escape(&s.display)));
            }
            for (label, list) in [("Categories", &rep.categories), ("Malware families", &rep.families), ("Tags", &rep.tags)] {
                if !list.is_empty() {
                    m.push_str(&format!("- {label}: {}\n", md_escape(&list.join(", "))));
                }
            }
            if let Some(f) = &rep.first_seen {
                m.push_str(&format!("- First seen: {}\n", md_escape(f)));
            }
            if let Some(l) = &rep.last_seen {
                m.push_str(&format!("- Last seen: {}\n", md_escape(l)));
            }
            for f in &rep.facts {
                m.push_str(&format!("- {}: {}\n", md_escape(&f.label), md_escape(&f.value)));
            }
            // the provider's link, only as a plain https URL (nothing in it can end the autolink)
            if let Some(link) = rep.permalink.as_deref().filter(|l| l.starts_with("https://") && !l.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '`' | '(' | ')'))) {
                m.push_str(&format!("- Source: <{link}>\n"));
            }
            for t in &rep.tables {
                m.push_str(&format!("\n### {}\n\n| {} |\n|{}|\n", md_escape(&t.title), t.columns.iter().map(|c| md_escape(c)).collect::<Vec<_>>().join(" | "), vec!["---"; t.columns.len()].join("|")));
                for row in &t.rows {
                    m.push_str(&format!("| {} |\n", row.iter().map(|c| md_escape(c)).collect::<Vec<_>>().join(" | ")));
                }
            }
            if !rep.related.is_empty() {
                m.push_str("\n### Related indicators\n\n");
                for x in &rep.related {
                    m.push_str(&format!("- `{}` ({}, {})\n", x.value.replace('`', "'"), x.kind.as_str(), md_escape(&x.relation)));
                }
            }
        }
        m.push('\n');
    }
    m
}

/// Export the stored results for an indicator through a native save dialog. Sends nothing.
#[tauri::command]
pub async fn ti_export(app: AppHandle, db: State<'_, Db>, query: String, format: String) -> AppResult<Option<String>> {
    let ind = indicator::detect(&query).map_err(AppError::Validation)?;
    let results = stored_results(&db, &ind)?;
    if results.is_empty() {
        return Err(validation("Run a lookup first; there are no stored results for this indicator."));
    }
    let generated = now();
    let (content, ext) = match format.as_str() {
        "md" => (markdown(&ind, &results, &generated), "md"),
        "json" => (
            serde_json::to_string_pretty(&serde_json::json!({
                "indicator": ind.value, "kind": ind.kind, "hashType": ind.hash_label(), "generatedAt": generated,
                "note": "Each provider's verdict is reported in its own terms; scores are not combined.",
                "summary": summarize(&results), "results": results,
            }))?,
            "json",
        ),
        _ => return Err(validation("Format must be md or json")),
    };
    let safe: String = ind.value.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Export threat intelligence report").set_file_name(format!("ti-{safe}.{ext}")).add_filter(ext.to_uppercase(), &[ext]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the report: {e}")))?;
    Ok(Some(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StixExport {
    pub file_name: String,
    pub exported: usize,
    /// saved values that cannot be expressed as a STIX pattern (for example a hash of unknown length)
    pub skipped: Vec<String>,
}

/// Saves the saved indicators as a STIX 2.1 bundle through a native save dialog. None when cancelled.
#[tauri::command]
pub async fn ti_saved_export_stix(app: AppHandle) -> AppResult<Option<StixExport>> {
    let mut rows: Vec<lifecycle::Saved> = app.state::<Db>().with(lifecycle::list)?;
    rows.reverse();
    if rows.is_empty() {
        return Err(validation("There are no saved indicators to export"));
    }
    let items: Vec<crate::ti::stix::Saved> = rows
        .iter()
        .map(|s| crate::ti::stix::Saved {
            kind: &s.kind,
            value: &s.indicator,
            note: &s.note,
            saved_at: &s.created_at,
            source: &s.source,
            reliability: &s.reliability,
            confidence: s.confidence,
            valid_until: s.valid_until.as_deref(),
            status: &s.status,
        })
        .collect();
    let (bundle, skipped) = crate::ti::stix::bundle(&items);
    let exported = items.len() - skipped.len();
    if exported == 0 {
        return Err(validation("None of the saved indicators can be written as a STIX pattern"));
    }
    let content = serde_json::to_string_pretty(&bundle)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Export saved indicators (STIX 2.1)").set_file_name("cyberhub-indicators.stix.json").add_filter("STIX 2.1 JSON", &["json"]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the bundle: {e}")))?;
    let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| log(c, "ti_export", &format!("Exported {exported} saved indicators as STIX 2.1"), &file_name, Some("ti"), None, None));
    Ok(Some(StixExport { file_name, exported, skipped }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::model::Verdict;

    fn res(p: ProviderId, status: Status, level: Option<Level>) -> ProviderResult {
        let mut r = base_result(p, status, None);
        r.report = level.map(|l| Report { verdict: Some(Verdict { level: l, label: "x".into() }), ..Default::default() });
        r
    }

    #[test]
    fn summary_keeps_each_provider_in_its_own_bucket() {
        let s = summarize(&[
            res(ProviderId::Virustotal, Status::Found, Some(Level::Malicious)),
            res(ProviderId::Abuseipdb, Status::Found, Some(Level::Suspicious)),
            res(ProviderId::Otx, Status::NotFound, None),
            res(ProviderId::Shodan, Status::Found, Some(Level::Info)),
            res(ProviderId::Urlhaus, Status::Error, None),
            res(ProviderId::Threatfox, Status::RateLimited, None),
            res(ProviderId::Malwarebazaar, Status::Unsupported, None),
        ]);
        assert_eq!(s.malicious, vec!["VirusTotal"]);
        assert_eq!(s.suspicious, vec!["AbuseIPDB"]);
        assert_eq!(s.no_record, vec!["AlienVault OTX"]);
        assert_eq!(s.informational, vec!["Shodan"]);
        assert_eq!(s.failed, vec!["URLhaus", "ThreatFox"]);
        assert_eq!(s.skipped, vec!["MalwareBazaar"]);
        assert_eq!(summary_line(&s), "malicious: VirusTotal · suspicious: AbuseIPDB · info: Shodan · no record: AlienVault OTX · failed: URLhaus, ThreatFox");
    }

    #[test]
    fn markdown_report_attributes_every_result() {
        let ind = indicator::detect("evil-domain.xyz").unwrap();
        let mut r = res(ProviderId::Urlhaus, Status::Found, Some(Level::Malicious));
        r.fetched_at = Some("2026-11-01T00:00:00Z".into());
        r.report.as_mut().unwrap().permalink = Some("https://urlhaus.abuse.ch/host/evil-domain.xyz/".into());
        let md = markdown(&ind, &[r, res(ProviderId::Otx, Status::NotFound, None)], "2026-11-02T00:00:00Z");
        assert!(md.contains("## URLhaus") && md.contains("Retrieved: 2026-11-01T00:00:00Z") && md.contains("Source: <https://urlhaus.abuse.ch/host/evil-domain.xyz/>"));
        assert!(md.contains("## AlienVault OTX") && md.contains("does not combine scores"));
        assert!(md.contains("- Status: has data") && md.contains("- Status: no record"));
        assert_eq!(md_escape("a|b\n<script>x</script>"), "a\\|b &lt;script&gt;x&lt;/script&gt;");
        // provider-written text cannot create links, images or headings
        assert_eq!(md_escape("![](https://x/b.png)\r## VirusTotal\u{2028}clean"), "\\!\\[\\]\\(https://x/b.png\\) \\#\\# VirusTotal clean");
    }

    #[test]
    fn availability_is_recorded_only_for_real_requests() {
        let mut live = res(ProviderId::Otx, Status::NotFound, None);
        live.source = Some("live".into());
        assert_eq!(observed_state(&live), Some("ok"));
        let mut cached = live.clone();
        cached.source = Some("cache".into());
        assert_eq!(observed_state(&cached), None);
        assert_eq!(observed_state(&res(ProviderId::Shodan, Status::NoKey, None)), None);
        let mut rejected = res(ProviderId::Abuseipdb, Status::Error, None);
        rejected.message = Some(ApiError::Unauthorized.message("AbuseIPDB"));
        assert_eq!(observed_state(&rejected), Some("rejected"));
        let msg = not_configured(ProviderId::Shodan);
        assert!(msg.contains("not been provisioned by the application owner") && !msg.contains("Settings") && !msg.contains("enter"));
    }

    #[test]
    fn unsupported_messages_are_specific() {
        let sha1 = indicator::detect(&"a".repeat(40)).unwrap();
        assert_eq!(unsupported_message(ProviderId::Urlhaus, &sha1), "URLhaus does not accept SHA-1 hashes.");
        let dom = indicator::detect("example.org").unwrap();
        assert_eq!(unsupported_message(ProviderId::Shodan, &dom), "Shodan does not look up domains.");
    }
}
