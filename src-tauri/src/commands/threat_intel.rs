//! Threat-intelligence commands: provider status and keys, multi-provider lookups, history,
//! saved indicators and report export.
//!
//! * Every provider runs independently and concurrently; one provider's failure, missing key
//!   or rate limit never prevents the others from returning results.
//! * Keys live in the OS credential store and are only read here. `ti_key_set` verifies a
//!   key with one read-only request before storing it; keys are never returned.
//! * Results are cached per provider (`ti_cache`; VirusTotal keeps using `vt_cache`).
//! * No command submits, reports or changes anything at a provider.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::commands::activity::log;
use crate::commands::system::{delete_secret, read_secret, store_secret};
use crate::commands::virustotal::{self, ttl_end, VtState};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::ti::http::ApiError;
use crate::ti::indicator::{self, Indicator, Kind};
use crate::ti::limit::RateLimiter;
use crate::ti::model::{Level, Parsed, ProviderResult, Report, Status};
use crate::ti::{abusech, abuseipdb, otx, shodan, KeyId, ProviderId};
use crate::util::{clean, now};
use crate::vt;

pub struct TiState {
    http: reqwest::Client,
    limiters: HashMap<ProviderId, RateLimiter>,
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
        Ok(Self { http: crate::ti::http::client(Duration::from_secs(20)).map_err(AppError::Internal)?, limiters })
    }
}

fn provider(id: &str) -> AppResult<ProviderId> {
    ProviderId::parse(id).ok_or_else(|| validation("Unknown provider"))
}

fn parse_key(id: &str) -> AppResult<KeyId> {
    KeyId::parse(id).ok_or_else(|| validation("Unknown provider key"))
}

fn enabled_map(db: &Db) -> AppResult<HashMap<String, bool>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT provider, enabled FROM ti_provider_settings")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?;
        Ok(rows.collect::<Result<HashMap<_, _>, _>>()?)
    })
}

/* ─────────────── provider status and keys ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub kinds: &'static [&'static str],
    pub key_id: &'static str,
    pub key_stored: bool,
    pub enabled: bool,
    pub access_note: &'static str,
    pub docs_url: &'static str,
    pub rate_limit: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyStatus {
    pub id: &'static str,
    pub label: &'static str,
    pub stored: bool,
    pub providers: Vec<&'static str>,
    pub signup_url: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersOverview {
    pub providers: Vec<ProviderStatus>,
    pub keys: Vec<KeyStatus>,
}

#[tauri::command]
pub async fn ti_providers(db: State<'_, Db>) -> AppResult<ProvidersOverview> {
    let enabled = enabled_map(&db)?;
    let stored: HashMap<KeyId, bool> = KeyId::ALL.into_iter().map(|k| (k, read_secret(k.secret_name()).is_some())).collect();
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
                    key_id: p.key().as_str(),
                    key_stored: stored[&p.key()],
                    enabled: enabled.get(p.as_str()).copied().unwrap_or(true),
                    access_note: p.access_note(),
                    docs_url: p.docs_url(),
                    rate_limit: RateLimiter::new(max, window).describe(),
                }
            })
            .collect(),
        keys: KeyId::ALL
            .into_iter()
            .map(|k| KeyStatus { id: k.as_str(), label: k.label(), stored: stored[&k], providers: k.providers().into_iter().map(ProviderId::name).collect(), signup_url: k.signup_url() })
            .collect(),
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCheck {
    pub ok: bool,
    pub message: String,
    /// quota / plan information reported by the provider, if any
    pub quota: Option<String>,
}

/// One read-only request that proves the key works. Never sends user data.
async fn validate(k: KeyId, key: &str, vtst: &VtState, tist: &TiState) -> Result<Option<String>, ApiError> {
    match k {
        KeyId::Virustotal => match vt::get(&vtst.http, &vtst.base, "/ip_addresses/8.8.8.8", key).await {
            Ok(_) | Err(ApiError::NotFound) => Ok(None),
            Err(ApiError::Quota(_)) => Ok(Some("Key accepted; VirusTotal reports the quota is used up for now".into())),
            Err(e) => Err(e),
        },
        KeyId::Abuseipdb => abuseipdb::validate(&tist.http, &ProviderId::Abuseipdb.base(), key).await,
        KeyId::Otx => otx::validate(&tist.http, &ProviderId::Otx.base(), key).await,
        KeyId::Abusech => abusech::validate(&tist.http, &ProviderId::Malwarebazaar.base(), key).await,
        KeyId::Shodan => shodan::validate(&tist.http, &ProviderId::Shodan.base(), key).await,
    }
}

fn limiter_for(k: KeyId, vtst: &VtState, tist: &TiState) -> AppResult<()> {
    let p = match k {
        KeyId::Abusech => ProviderId::Malwarebazaar,
        _ => k.providers()[0],
    };
    let limiter = if p == ProviderId::Virustotal { &vtst.limiter } else { &tist.limiters[&p] };
    limiter.try_acquire(Instant::now()).map_err(|wait| AppError::RateLimited(format!("Too many {} requests; try again in {wait} s.", p.name())))
}

fn key_error(k: KeyId, e: ApiError) -> AppError {
    let name = match k {
        KeyId::Abusech => "abuse.ch",
        _ => k.providers()[0].name(),
    };
    let msg = e.message(name);
    match e {
        ApiError::Network(_) | ApiError::Server(_) | ApiError::Unexpected(_) => AppError::Network(msg),
        ApiError::Quota(_) => AppError::RateLimited(msg),
        _ => AppError::Validation(msg),
    }
}

/// Verify a key with one read-only request, then store it. The key is never echoed back.
#[tauri::command]
pub async fn ti_key_set(vtst: State<'_, VtState>, tist: State<'_, TiState>, key_id: String, value: String) -> AppResult<KeyCheck> {
    let k = parse_key(&key_id)?;
    let key = value.trim().to_string();
    k.check_format(&key).map_err(AppError::Validation)?;
    limiter_for(k, &vtst, &tist)?;
    let quota = validate(k, &key, &vtst, &tist).await.map_err(|e| key_error(k, e))?;
    store_secret(k.secret_name(), &key)?;
    Ok(KeyCheck { ok: true, message: format!("{} verified and saved to the system keychain.", k.label()), quota })
}

/// Re-check the stored key (connection status and quota).
#[tauri::command]
pub async fn ti_key_test(vtst: State<'_, VtState>, tist: State<'_, TiState>, key_id: String) -> AppResult<KeyCheck> {
    let k = parse_key(&key_id)?;
    let Some(key) = read_secret(k.secret_name()) else {
        return Ok(KeyCheck { ok: false, message: "No key stored.".into(), quota: None });
    };
    limiter_for(k, &vtst, &tist)?;
    Ok(match validate(k, &key, &vtst, &tist).await {
        Ok(quota) => KeyCheck { ok: true, message: "Connected; the key was accepted.".into(), quota },
        Err(e) => KeyCheck { ok: false, message: key_error(k, e).to_string(), quota: None },
    })
}

#[tauri::command]
pub async fn ti_key_delete(key_id: String) -> AppResult<()> {
    delete_secret(parse_key(&key_id)?.secret_name())
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

/// Run one provider. Never returns an error: every outcome is a status in the result.
async fn run_one(db: &Db, vtst: &VtState, tist: &TiState, p: ProviderId, ind: &Indicator, refresh: bool, enabled: bool) -> ProviderResult {
    if !p.supports(ind) {
        return base_result(p, Status::Unsupported, Some(unsupported_message(p, ind)));
    }
    if !enabled {
        return base_result(p, Status::Disabled, Some(format!("{} is turned off in Settings.", p.name())));
    }
    let has_key = read_secret(p.key().secret_name()).is_some();

    if p == ProviderId::Virustotal {
        if !has_key && (refresh || virustotal::cached(db, ind).ok().flatten().is_none()) {
            return base_result(p, Status::NoKey, Some("Add a VirusTotal API key in Settings.".into()));
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
        let what = if p.key() == KeyId::Abusech { "an abuse.ch Auth-Key" } else { "an API key" };
        return base_result(p, Status::NoKey, Some(format!("Add {what} for {} in Settings.", p.name())));
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

async fn investigate(db: &Db, vtst: &VtState, tist: &TiState, ind: &Indicator, only: Option<&[ProviderId]>, refresh: bool) -> AppResult<Vec<ProviderResult>> {
    let enabled = enabled_map(db)?;
    let want = |p: ProviderId| only.map_or(true, |o| o.contains(&p));
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedIndicator {
    pub id: i64,
    pub kind: String,
    pub indicator: String,
    pub note: String,
    pub created_at: String,
}

#[tauri::command]
pub async fn ti_saved_list(db: State<'_, Db>) -> AppResult<Vec<SavedIndicator>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT id, kind, indicator, note, created_at FROM ti_saved ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |r| Ok(SavedIndicator { id: r.get(0)?, kind: r.get(1)?, indicator: r.get(2)?, note: r.get(3)?, created_at: r.get(4)? }))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
}

#[tauri::command]
pub async fn ti_saved_add(db: State<'_, Db>, query: String, note: String) -> AppResult<()> {
    let ind = indicator::detect(&query).map_err(AppError::Validation)?;
    let note = clean("Note", &note, 500, false)?;
    db.with(|c| {
        c.execute(
            "INSERT INTO ti_saved (kind, indicator, note, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(indicator) DO UPDATE SET note = excluded.note",
            params![ind.kind.as_str(), ind.value, note, now()],
        )?;
        Ok(())
    })
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
fn stored_results(db: &Db, ind: &Indicator) -> AppResult<Vec<ProviderResult>> {
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
            if let Some(link) = &rep.permalink {
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
    fn unsupported_messages_are_specific() {
        let sha1 = indicator::detect(&"a".repeat(40)).unwrap();
        assert_eq!(unsupported_message(ProviderId::Urlhaus, &sha1), "URLhaus does not accept SHA-1 hashes.");
        let dom = indicator::detect("example.org").unwrap();
        assert_eq!(unsupported_message(ProviderId::Shodan, &dom), "Shodan does not look up domains.");
    }
}
