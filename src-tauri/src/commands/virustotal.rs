//! VirusTotal commands. All requests are made here, in Rust, with the API key read from
//! the OS credential store. The key is never accepted from the UI except when saving it,
//! never returned, logged or stored in the database.

use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::State;

use crate::commands::activity::log;
use crate::commands::system::{delete_secret, read_secret, store_secret};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;
use crate::vt::{self, Indicator, Report, VtError};

pub const KEY_NAME: &str = "virustotal_api_key";

pub struct VtState {
    client: vt::Client,
    limiter: vt::RateLimiter,
}

impl VtState {
    pub fn new() -> AppResult<Self> {
        Ok(Self {
            client: vt::Client::new(&api_base()).map_err(AppError::Internal)?,
            limiter: vt::RateLimiter::new(vt::PUBLIC_RATE_PER_MIN, Duration::from_secs(60)),
        })
    }
}

/// Production always uses the official API. Debug builds may point to a local mock server
/// (loopback only) via CYBERHUB_VT_BASE_URL so the UI can be exercised without real quota.
fn api_base() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(b) = std::env::var("CYBERHUB_VT_BASE_URL") {
            if b.starts_with("http://127.0.0.1:") || b.starts_with("http://localhost:") {
                return b;
            }
        }
    }
    vt::API_BASE.to_string()
}

fn vt_error(e: VtError) -> AppError {
    match e {
        VtError::Quota(_) => AppError::RateLimited(e.user_message()),
        VtError::Network(_) | VtError::Server(_) => AppError::Network(e.user_message()),
        _ => AppError::Validation(e.user_message()),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detected {
    pub kind: vt::Kind,
    pub label: &'static str,
    pub value: String,
    pub hash_type: Option<&'static str>,
}

/// Classify an indicator (no network). Used for the live type hint in the search box.
#[tauri::command]
pub async fn vt_detect(query: String) -> AppResult<Detected> {
    let i = vt::detect(&query).map_err(AppError::Validation)?;
    Ok(Detected { kind: i.kind, label: i.kind.label(), value: i.value, hash_type: i.hash_type })
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

fn ttl_end(fetched_at: &str, not_found: bool) -> String {
    let ttl = if not_found { vt::NOT_FOUND_TTL_SECS } else { vt::REPORT_TTL_SECS };
    chrono::DateTime::parse_from_rfc3339(fetched_at)
        .map(|t| (t + chrono::Duration::seconds(ttl)).with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn cached(db: &Db, ind: &Indicator) -> AppResult<Option<(Option<Report>, String, bool)>> {
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
    let fresh_until = ttl_end(&fetched_at, report.is_none());
    LookupResult { kind: ind.kind, indicator: ind.value.clone(), hash_type: ind.hash_type, report, source, fetched_at, fresh_until }
}

/// Reputation lookup. Serves a fresh cached result unless `refresh` is set. Never uploads
/// or submits anything: only GET requests for existing VirusTotal records.
#[tauri::command]
pub async fn vt_lookup(db: State<'_, Db>, vtst: State<'_, VtState>, query: String, refresh: bool) -> AppResult<LookupResult> {
    let ind = vt::detect(&query).map_err(AppError::Validation)?;

    if !refresh {
        if let Some((report, at, nf)) = cached(&db, &ind)? {
            if vt::is_fresh(&at, nf, chrono::Utc::now()) {
                return Ok(result(&ind, report, "cache", at));
            }
        }
    }

    let key = read_secret(KEY_NAME).ok_or_else(|| validation("Add a VirusTotal API key in Settings to run lookups."))?;
    vtst.limiter
        .try_acquire(Instant::now())
        .map_err(|wait| AppError::RateLimited(format!("The public VirusTotal API allows 4 lookups per minute. Try again in {wait} s.")))?;

    let outcome = vtst.client.get(&ind.path, &key).await;
    drop(key);
    let report = match outcome {
        Ok(body) => Some(vt::parse_report(&ind, &body).map_err(AppError::Network)?),
        Err(VtError::NotFound) => None,
        Err(e) => return Err(vt_error(e)),
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
        log(c, "vt_lookup", &format!("VirusTotal {} lookup: {shown}", ind.kind.noun()), &summary, Some("vt"), Some(&ind.cache_key()), None)
    })?;
    Ok(result(&ind, report, "live", at))
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

/* ─────────────── API key (write-only from the UI) ─────────────── */

#[tauri::command]
pub async fn vt_key_status() -> AppResult<bool> {
    Ok(read_secret(KEY_NAME).is_some())
}

/// Verify a key with one read-only lookup of a fixed public indicator, then store it in
/// the OS credential store. The key is never echoed back or written anywhere else.
#[tauri::command]
pub async fn vt_key_set(vtst: State<'_, VtState>, value: String) -> AppResult<()> {
    let key = value.trim().to_string();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(validation("A VirusTotal API key is 64 hexadecimal characters."));
    }
    vtst.limiter
        .try_acquire(Instant::now())
        .map_err(|wait| AppError::RateLimited(format!("Too many VirusTotal requests; try again in {wait} s.")))?;
    // 8.8.8.8 is a stable public indicator; the request only checks that the key is accepted
    match vtst.client.get("/ip_addresses/8.8.8.8", &key).await {
        Ok(_) | Err(VtError::NotFound) => {}
        Err(VtError::Quota(_)) => {} // key is valid but out of quota right now
        Err(e) => return Err(vt_error(e)),
    }
    store_secret(KEY_NAME, &key)
}

#[tauri::command]
pub async fn vt_key_delete() -> AppResult<()> {
    delete_secret(KEY_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_end_adds_the_right_lifetime() {
        let at = "2026-01-01T00:00:00Z";
        assert_eq!(ttl_end(at, false), "2026-01-02T00:00:00Z");
        assert_eq!(ttl_end(at, true), "2026-01-01T01:00:00Z");
    }

    #[test]
    fn debug_base_override_is_loopback_only() {
        std::env::set_var("CYBERHUB_VT_BASE_URL", "https://evil.example/api");
        assert_eq!(api_base(), vt::API_BASE);
        std::env::set_var("CYBERHUB_VT_BASE_URL", "http://127.0.0.1:9999");
        assert_eq!(api_base(), "http://127.0.0.1:9999");
        std::env::remove_var("CYBERHUB_VT_BASE_URL");
        assert_eq!(api_base(), vt::API_BASE);
    }
}
