//! Vulnerability management: CVEs tracked per project (optionally per asset), a transparent
//! priority computed from stated factors, remediation and verification, and an append-only
//! history. EPSS (FIRST.org) is an optional input; priorities say whether it was available.

use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::intel::{CveRecord, CvssScore};
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const STATUSES: &[&str] = &["open", "triaged", "in_remediation", "mitigated", "resolved", "accepted_risk", "false_positive"];
/// Whether a vulnerability still needs work.
pub fn is_open(status: &str) -> bool {
    matches!(status, "open" | "triaged" | "in_remediation")
}
pub const EXPOSURES: &[&str] = &["internet", "internal", "unknown"];
pub const CRITICALITIES: &[&str] = &["low", "medium", "high"];

/* ───────────────────────── priority model ───────────────────────── */

/// Everything the priority is computed from. Nothing else is used.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Factors {
    pub cvss: Option<f64>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub kev: bool,
    pub exploit_known: bool,
    pub exposure: String,
    pub criticality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Reason {
    pub factor: String,
    /// contribution to the score
    pub effect: f64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Priority {
    pub level: &'static str,
    pub score: f64,
    pub reasons: Vec<Reason>,
}

fn reason(reasons: &mut Vec<Reason>, factor: &str, effect: f64, text: String) {
    reasons.push(Reason { factor: factor.into(), effect, text });
}

/// The priority model (documented in DATA_MODEL.md):
/// score = CVSS base score (5 when unknown)
///       + 2 if listed in CISA KEV, + 2 if the analyst knows of exploitation (not both: max 2)
///       + EPSS: +2 at ≥ 0.5, +1 at ≥ 0.1, +0.5 at ≥ 0.01
///       + exposure: internet +1, unknown +0.5, internal 0
///       + criticality: high +1, medium 0, low −1
/// P1 ≥ 11, P2 ≥ 8.5, P3 ≥ 6, otherwise P4.
pub fn prioritize(f: &Factors) -> Priority {
    let mut reasons = Vec::new();
    let mut score = match f.cvss {
        Some(s) => {
            reason(&mut reasons, "cvss", s, format!("CVSS base score {s:.1}"));
            s
        }
        None => {
            reason(&mut reasons, "cvss", 5.0, "No CVSS score is known; counted as 5.0".into());
            5.0
        }
    };
    if f.kev {
        reason(&mut reasons, "kev", 2.0, "Listed in CISA's Known Exploited Vulnerabilities catalog".into());
        score += 2.0;
    } else if f.exploit_known {
        reason(&mut reasons, "exploit", 2.0, "Exploitation is known (analyst's assessment)".into());
        score += 2.0;
    }
    match f.epss {
        Some(p) => {
            let pct = f.epss_percentile.map(|x| format!(", higher than {:.0}% of CVEs", x * 100.0)).unwrap_or_default();
            let effect = if p >= 0.5 {
                2.0
            } else if p >= 0.1 {
                1.0
            } else if p >= 0.01 {
                0.5
            } else {
                0.0
            };
            reason(&mut reasons, "epss", effect, format!("EPSS {:.1}% probability of exploitation in the next 30 days{pct}", p * 100.0));
            score += effect;
        }
        None => reason(&mut reasons, "epss", 0.0, "EPSS was not available; the priority was computed without it".into()),
    }
    let exposure = match f.exposure.as_str() {
        "internet" => (1.0, "Reachable from the internet"),
        "internal" => (0.0, "Internal only"),
        _ => (0.5, "Exposure unknown; counted as possibly reachable"),
    };
    reason(&mut reasons, "exposure", exposure.0, exposure.1.into());
    score += exposure.0;
    let crit = match f.criticality.as_str() {
        "high" => (1.0, "Asset criticality high"),
        "low" => (-1.0, "Asset criticality low"),
        _ => (0.0, "Asset criticality medium"),
    };
    reason(&mut reasons, "criticality", crit.0, crit.1.into());
    score += crit.0;
    let score = (score * 10.0).round() / 10.0;
    let level = if score >= 11.0 {
        "p1"
    } else if score >= 8.5 {
        "p2"
    } else if score >= 6.0 {
        "p3"
    } else {
        "p4"
    };
    Priority { level, score, reasons }
}

/// The CVSS score to use: the newest version available (4.0, then 3.1, 3.0, 2.0), NVD's own first.
pub fn best_cvss(scores: &[CvssScore]) -> Option<&CvssScore> {
    let rank = |v: &str| match v {
        "4.0" => 0,
        "3.1" => 1,
        "3.0" => 2,
        "2.0" => 3,
        _ => 4,
    };
    scores.iter().min_by_key(|s| (rank(&s.version), !s.source.contains("nvd@nist.gov") as u8))
}

pub fn severity_of(score: Option<f64>) -> &'static str {
    match score {
        Some(s) if s >= 9.0 => "critical",
        Some(s) if s >= 7.0 => "high",
        Some(s) if s >= 4.0 => "medium",
        Some(s) if s > 0.0 => "low",
        _ => "info",
    }
}

/* ───────────────────────── records ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub id: i64,
    pub project_id: i64,
    pub cve_id: String,
    pub asset_id: Option<i64>,
    /// the asset's value (None when there is no asset or it was deleted)
    pub asset: Option<String>,
    pub title: String,
    pub status: String,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub kev: bool,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub epss_date: Option<String>,
    pub exploit_known: bool,
    pub exposure: String,
    pub criticality: String,
    pub priority: String,
    pub priority_score: f64,
    pub priority_reasons: Vec<Reason>,
    pub remediation: String,
    pub remediation_owner: String,
    pub remediation_due: Option<String>,
    pub verified_at: Option<String>,
    pub verification_note: String,
    pub notes: String,
    pub source: String,
    pub created_at: String,
    pub updated_at: String,
}

const COLS: &str = "v.id, v.project_id, v.cve_id, v.asset_id, a.value, v.title, v.status, v.cvss_score, v.cvss_version, v.cvss_vector, v.kev,
    v.epss, v.epss_percentile, v.epss_date, v.exploit_known, v.exposure, v.criticality, v.priority, v.priority_score, v.priority_reasons,
    v.remediation, v.remediation_owner, v.remediation_due, v.verified_at, v.verification_note, v.notes, v.source, v.created_at, v.updated_at";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Vulnerability> {
    Ok(Vulnerability {
        id: r.get(0)?,
        project_id: r.get(1)?,
        cve_id: r.get(2)?,
        asset_id: r.get(3)?,
        asset: r.get(4)?,
        title: r.get(5)?,
        status: r.get(6)?,
        cvss_score: r.get(7)?,
        cvss_version: r.get(8)?,
        cvss_vector: r.get(9)?,
        kev: r.get::<_, i64>(10)? != 0,
        epss: r.get(11)?,
        epss_percentile: r.get(12)?,
        epss_date: r.get(13)?,
        exploit_known: r.get::<_, i64>(14)? != 0,
        exposure: r.get(15)?,
        criticality: r.get(16)?,
        priority: r.get(17)?,
        priority_score: r.get(18)?,
        priority_reasons: serde_json::from_str(&r.get::<_, String>(19)?).unwrap_or_default(),
        remediation: r.get(20)?,
        remediation_owner: r.get(21)?,
        remediation_due: r.get(22)?,
        verified_at: r.get(23)?,
        verification_note: r.get(24)?,
        notes: r.get(25)?,
        source: r.get(26)?,
        created_at: r.get(27)?,
        updated_at: r.get(28)?,
    })
}

pub fn get(c: &Connection, id: i64) -> AppResult<Vulnerability> {
    c.query_row(&format!("SELECT {COLS} FROM vulnerabilities v LEFT JOIN assets a ON a.id = v.asset_id WHERE v.id = ?1"), params![id], row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("vulnerability {id}")))
}

/// Highest priority first.
pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<Vulnerability>> {
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM vulnerabilities v LEFT JOIN assets a ON a.id = v.asset_id WHERE v.project_id = ?1 ORDER BY v.priority, v.priority_score DESC, v.cve_id"
    ))?;
    let rows = st.query_map(params![project_id], row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn factors(v: &Vulnerability) -> Factors {
    Factors { cvss: v.cvss_score, epss: v.epss, epss_percentile: v.epss_percentile, kev: v.kev, exploit_known: v.exploit_known, exposure: v.exposure.clone(), criticality: v.criticality.clone() }
}

/// Before an asset is removed: each vulnerability tracked on it is kept for the whole project, with
/// an event. When the same CVE is also tracked for the whole project, nothing changes and the
/// removal is refused: the two records cannot be merged without losing one history.
pub fn detach_asset(c: &Connection, asset_id: i64, asset_value: &str) -> AppResult<()> {
    let ids: Vec<i64> = c.prepare("SELECT id FROM vulnerabilities WHERE asset_id = ?1 ORDER BY id")?.query_map(params![asset_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut both: Vec<String> = Vec::new();
    for id in &ids {
        let v = get(c, *id)?;
        let wide: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM vulnerabilities WHERE project_id = ?1 AND cve_id = ?2 AND asset_id IS NULL)", params![v.project_id, v.cve_id], |r| r.get(0))?;
        if wide {
            both.push(v.cve_id);
        }
    }
    if !both.is_empty() {
        return Err(validation(format!(
            "{asset_value} cannot be removed: {} {} tracked on it and also for the whole project. Delete one of the two records first, or retire the asset instead, which keeps it",
            both.join(", "),
            if both.len() == 1 { "is" } else { "are" }
        )));
    }
    for id in ids {
        let v = get(c, id)?;
        c.execute("UPDATE vulnerabilities SET asset_id = NULL, updated_at = ?2 WHERE id = ?1", params![id, now()])?;
        let note = format!("The asset {asset_value} was removed; the vulnerability is now tracked for the whole project (its exposure, {}, was taken from the asset)", v.exposure);
        record_event(c, &v, "updated", (Some(asset_value), None), &note, "user")?;
    }
    Ok(())
}

pub fn record_event(c: &Connection, v: &Vulnerability, kind: &str, (from, to): (Option<&str>, Option<&str>), note: &str, source: &str) -> AppResult<()> {
    c.execute(
        "INSERT INTO vulnerability_events (vulnerability_id, project_id, kind, from_value, to_value, note, source, at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![v.id, v.project_id, kind, from, to, note.chars().take(4000).collect::<String>(), source, now()],
    )?;
    Ok(())
}

/// Recomputes and stores the priority; a changed level is recorded with its reasons.
fn reprioritize(c: &Connection, id: i64, source: &str) -> AppResult<Vulnerability> {
    let v = get(c, id)?;
    let p = prioritize(&factors(&v));
    c.execute(
        "UPDATE vulnerabilities SET priority = ?2, priority_score = ?3, priority_reasons = ?4, updated_at = ?5 WHERE id = ?1",
        params![id, p.level, p.score, serde_json::to_string(&p.reasons)?, now()],
    )?;
    if p.level != v.priority {
        let why = p.reasons.iter().filter(|r| r.effect != 0.0).map(|r| r.text.clone()).collect::<Vec<_>>().join("; ");
        record_event(c, &v, "priority", (Some(&v.priority), Some(p.level)), &why, source)?;
    }
    get(c, id)
}

/// What the asset says about exposure: private addresses are internal, public names and
/// addresses are internet-facing, anything else is unknown.
pub fn exposure_of_asset(c: &Connection, asset_id: i64) -> AppResult<&'static str> {
    let (kind, value, data): (String, String, String) = c.query_row("SELECT type, value, data FROM assets WHERE id = ?1", params![asset_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let data: Value = serde_json::from_str(&data).unwrap_or(Value::Null);
    let ip = match kind.as_str() {
        "ip" => Some(value),
        "service" => crate::workspace::discovery::service_host(&value),
        "domain" | "subdomain" | "http_service" | "endpoint" => return Ok(if data.get("nonPublic") == Some(&Value::Bool(true)) { "internal" } else { "internet" }),
        _ => None,
    };
    Ok(match ip.and_then(|i| i.parse::<std::net::IpAddr>().ok()) {
        Some(ip) if crate::ti::indicator::is_non_public(&ip) => "internal",
        Some(_) => "internet",
        None => "unknown",
    })
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VulnInput {
    pub project_id: i64,
    pub cve_id: String,
    #[serde(default)]
    pub asset_id: Option<i64>,
    #[serde(default)]
    pub exposure: Option<String>,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub exploit_known: bool,
    #[serde(default)]
    pub notes: String,
}

/// EPSS values for one CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct Epss {
    pub epss: f64,
    pub percentile: f64,
    pub date: String,
}

pub fn normalize_cve(id: &str) -> AppResult<String> {
    let id = id.trim().to_ascii_uppercase();
    let ok = id.strip_prefix("CVE-").is_some_and(|rest| {
        let mut p = rest.splitn(2, '-');
        let (y, n) = (p.next().unwrap_or(""), p.next().unwrap_or(""));
        y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()) && (4..=7).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit())
    });
    if !ok {
        return Err(validation("Use a CVE identifier such as CVE-2024-3094"));
    }
    Ok(id)
}

/// Tracks a CVE in a project. `record` is the NVD record when known, `epss` when available.
pub fn create(c: &Connection, input: &VulnInput, record: Option<&CveRecord>, epss: Option<&Epss>, source: &str) -> AppResult<Vulnerability> {
    let tx = c.unchecked_transaction()?;
    let v = create_in(&tx, input, record, epss, source)?;
    tx.commit()?;
    Ok(v)
}

/// The NVD record of a CVE from the local cache (no network).
pub fn cached_record(c: &Connection, cve: &str) -> AppResult<Option<CveRecord>> {
    let raw: Option<String> = c.query_row("SELECT data FROM cve_cache WHERE id = ?1", params![cve], |r| r.get(0)).optional()?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// [`create`] inside the caller's transaction or savepoint (imports).
pub fn create_in(c: &Connection, input: &VulnInput, record: Option<&CveRecord>, epss: Option<&Epss>, source: &str) -> AppResult<Vulnerability> {
    let cve = normalize_cve(&input.cve_id)?;
    let exists: i64 = c.query_row("SELECT COUNT(*) FROM projects WHERE id = ?1", params![input.project_id], |r| r.get(0))?;
    if exists == 0 {
        return Err(AppError::NotFound(format!("project {}", input.project_id)));
    }
    if let Some(a) = input.asset_id {
        let owner: Option<i64> = c.query_row("SELECT project_id FROM assets WHERE id = ?1", params![a], |r| r.get(0)).optional()?;
        if owner != Some(input.project_id) {
            return Err(validation("The asset belongs to another project"));
        }
    }
    let exposure = match input.exposure.as_deref() {
        Some(e) if EXPOSURES.contains(&e) => e.to_string(),
        Some(_) => return Err(validation("Exposure must be internet, internal or unknown")),
        None => match input.asset_id {
            Some(a) => exposure_of_asset(c, a)?.to_string(),
            None => "unknown".into(),
        },
    };
    let criticality = input.criticality.clone().unwrap_or_else(|| "medium".into());
    if !CRITICALITIES.contains(&criticality.as_str()) {
        return Err(validation("Criticality must be low, medium or high"));
    }
    let notes = crate::util::clean("Notes", &input.notes, 20_000, false)?;
    let cvss = record.and_then(|r| best_cvss(&r.cvss));
    let title = record.map(|r| r.description.split(". ").next().unwrap_or("").chars().take(300).collect::<String>()).unwrap_or_default();
    let f = Factors {
        cvss: cvss.map(|s| s.score),
        epss: epss.map(|e| e.epss),
        epss_percentile: epss.map(|e| e.percentile),
        kev: record.is_some_and(|r| r.kev),
        exploit_known: input.exploit_known,
        exposure: exposure.clone(),
        criticality: criticality.clone(),
    };
    let p = prioritize(&f);
    let ts = now();
    let tx = c;
    let dup: Option<i64> = tx
        .query_row("SELECT id FROM vulnerabilities WHERE project_id = ?1 AND cve_id = ?2 AND COALESCE(asset_id, 0) = COALESCE(?3, 0)", params![input.project_id, cve, input.asset_id], |r| r.get(0))
        .optional()?;
    if dup.is_some() {
        return Err(AppError::Conflict(format!("{cve} is already tracked for this {}", if input.asset_id.is_some() { "asset" } else { "project" })));
    }
    tx.execute(
        "INSERT INTO vulnerabilities (project_id, cve_id, asset_id, title, status, cvss_score, cvss_version, cvss_vector, kev, epss, epss_percentile, epss_date,
             exploit_known, exposure, criticality, priority, priority_score, priority_reasons, notes, source, created_at, updated_at)
         VALUES (?1,?2,?3,?4,'open',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?20)",
        params![
            input.project_id, cve, input.asset_id, title, f.cvss, cvss.map(|s| s.version.clone()), cvss.map(|s| s.vector.clone()), f.kev as i64,
            f.epss, f.epss_percentile, epss.map(|e| e.date.clone()), f.exploit_known as i64, exposure, criticality, p.level, p.score,
            serde_json::to_string(&p.reasons)?, notes, source, ts
        ],
    )?;
    let v = get(tx, tx.last_insert_rowid())?;
    record_event(tx, &v, "created", (None, Some(p.level)), if record.is_none() { "NVD record not available; CVSS unknown" } else { "" }, source)?;
    Ok(v)
}

/// Updates the analyst's context and recomputes the priority.
pub fn set_context(c: &Connection, id: i64, exposure: &str, criticality: &str, exploit_known: bool, source: &str) -> AppResult<Vulnerability> {
    if !EXPOSURES.contains(&exposure) || !CRITICALITIES.contains(&criticality) {
        return Err(validation("Exposure must be internet, internal or unknown; criticality low, medium or high"));
    }
    let tx = c.unchecked_transaction()?;
    let before = get(&tx, id)?;
    tx.execute("UPDATE vulnerabilities SET exposure = ?2, criticality = ?3, exploit_known = ?4 WHERE id = ?1", params![id, exposure, criticality, exploit_known as i64])?;
    let mut changed = Vec::new();
    if before.exposure != exposure {
        changed.push(format!("exposure {} → {exposure}", before.exposure));
    }
    if before.criticality != criticality {
        changed.push(format!("criticality {} → {criticality}", before.criticality));
    }
    if before.exploit_known != exploit_known {
        changed.push(format!("known exploitation {}", if exploit_known { "set" } else { "cleared" }));
    }
    if !changed.is_empty() {
        record_event(&tx, &before, "updated", (None, None), &changed.join(", "), source)?;
    }
    let v = reprioritize(&tx, id, source)?;
    tx.commit()?;
    Ok(v)
}

/// Stores new CVSS/KEV/EPSS values (a refresh) and recomputes the priority.
pub fn set_scores(c: &Connection, id: i64, record: Option<&CveRecord>, epss: Option<&Epss>, source: &str) -> AppResult<Vulnerability> {
    let tx = c.unchecked_transaction()?;
    if let Some(r) = record {
        let cvss = best_cvss(&r.cvss);
        tx.execute(
            "UPDATE vulnerabilities SET cvss_score = ?2, cvss_version = ?3, cvss_vector = ?4, kev = ?5, title = CASE WHEN title = '' THEN ?6 ELSE title END WHERE id = ?1",
            params![id, cvss.map(|s| s.score), cvss.map(|s| s.version.clone()), cvss.map(|s| s.vector.clone()), r.kev as i64, r.description.split(". ").next().unwrap_or("").chars().take(300).collect::<String>()],
        )?;
    }
    if let Some(e) = epss {
        tx.execute("UPDATE vulnerabilities SET epss = ?2, epss_percentile = ?3, epss_date = ?4 WHERE id = ?1", params![id, e.epss, e.percentile, e.date])?;
    }
    let v = reprioritize(&tx, id, source)?;
    tx.commit()?;
    Ok(v)
}

pub fn set_status(c: &Connection, id: i64, status: &str, note: &str, source: &str) -> AppResult<Vulnerability> {
    if !STATUSES.contains(&status) {
        return Err(validation(format!("Status must be one of: {}", STATUSES.join(", "))));
    }
    let tx = c.unchecked_transaction()?;
    let v = get(&tx, id)?;
    if v.status == status {
        return Err(validation("The vulnerability already has this status"));
    }
    if matches!(status, "accepted_risk" | "false_positive") && note.trim().is_empty() {
        return Err(validation("Say why: accepting a risk or dismissing a vulnerability needs a reason"));
    }
    tx.execute("UPDATE vulnerabilities SET status = ?2, updated_at = ?3 WHERE id = ?1", params![id, status, now()])?;
    // a vulnerability that comes back is no longer verified as fixed
    if !matches!(status, "resolved" | "mitigated") && v.verified_at.is_some() {
        tx.execute("UPDATE vulnerabilities SET verified_at = NULL WHERE id = ?1", params![id])?;
    }
    record_event(&tx, &v, "status", (Some(&v.status), Some(status)), note, source)?;
    let out = get(&tx, id)?;
    tx.commit()?;
    Ok(out)
}

pub fn set_remediation(c: &Connection, id: i64, plan: &str, owner: &str, due: Option<&str>, source: &str) -> AppResult<Vulnerability> {
    let plan = crate::util::clean("Remediation", plan, 20_000, false)?;
    let owner = crate::util::clean("Owner", owner, 100, false)?;
    let due = match due.map(str::trim).filter(|d| !d.is_empty()) {
        None => None,
        Some(d) => Some(chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| validation("The due date must be a date (YYYY-MM-DD)"))?.to_string()),
    };
    let tx = c.unchecked_transaction()?;
    let v = get(&tx, id)?;
    if v.remediation == plan && v.remediation_owner == owner && v.remediation_due == due {
        return Ok(v);
    }
    tx.execute("UPDATE vulnerabilities SET remediation = ?2, remediation_owner = ?3, remediation_due = ?4, updated_at = ?5 WHERE id = ?1", params![id, plan, owner, due, now()])?;
    let summary = [
        (!owner.is_empty()).then(|| format!("owner {owner}")),
        due.as_ref().map(|d| format!("due {d}")),
        (v.remediation != plan).then(|| "plan updated".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ");
    record_event(&tx, &v, "remediation", (None, None), &summary, source)?;
    let out = get(&tx, id)?;
    tx.commit()?;
    Ok(out)
}

/// Records that the fix was verified and closes the vulnerability as resolved.
pub fn verify(c: &Connection, id: i64, note: &str, source: &str) -> AppResult<Vulnerability> {
    let note = crate::util::clean("Verification", note, 4000, true)?;
    let tx = c.unchecked_transaction()?;
    let v = get(&tx, id)?;
    let ts = now();
    tx.execute("UPDATE vulnerabilities SET status = 'resolved', verified_at = ?2, verification_note = ?3, updated_at = ?2 WHERE id = ?1", params![id, ts, note])?;
    record_event(&tx, &v, "verification", (Some(&v.status), Some("resolved")), &note, source)?;
    let out = get(&tx, id)?;
    tx.commit()?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnEvent {
    pub id: i64,
    pub kind: String,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
    pub note: String,
    pub source: String,
    pub at: String,
}

pub fn history(c: &Connection, id: i64) -> AppResult<Vec<VulnEvent>> {
    get(c, id)?;
    let mut st = c.prepare("SELECT id, kind, from_value, to_value, note, source, at FROM vulnerability_events WHERE vulnerability_id = ?1 ORDER BY id")?;
    let rows = st
        .query_map(params![id], |r| Ok(VulnEvent { id: r.get(0)?, kind: r.get(1)?, from_value: r.get(2)?, to_value: r.get(3)?, note: r.get(4)?, source: r.get(5)?, at: r.get(6)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    let v = get(c, id)?;
    let tx = c.unchecked_transaction()?;
    crate::workspace::findings::forget_ref(&tx, "vulnerability", id)?;
    tx.execute("DELETE FROM vulnerabilities WHERE id = ?1", params![id])?;
    crate::workspace::timeline::record(&tx, v.project_id, "vulnerability", &format!("Vulnerability removed: {}", v.cve_id), &v.status, None, None)?;
    tx.commit()?;
    Ok(())
}

/* ───────────────────────── EPSS (FIRST.org) ───────────────────────── */

const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const EPSS_CACHE_HOURS: i64 = 24;

/// Reads FIRST's EPSS API response (`data: [{cve, epss, percentile, date}]`, numbers as strings).
pub fn parse_epss(body: &Value) -> Result<Vec<(String, Epss)>, String> {
    let rows = body.get("data").and_then(Value::as_array).ok_or("EPSS returned an unexpected document")?;
    let num = |v: Option<&Value>| v.and_then(|x| x.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| x.as_f64())).filter(|f| (0.0..=1.0).contains(f));
    Ok(rows
        .iter()
        .filter_map(|r| {
            let cve = normalize_cve(r.get("cve")?.as_str()?).ok()?;
            Some((cve, Epss { epss: num(r.get("epss"))?, percentile: num(r.get("percentile"))?, date: r.get("date").and_then(Value::as_str).unwrap_or("").chars().take(10).collect() }))
        })
        .collect())
}

pub fn epss_cached(c: &Connection, cve: &str) -> AppResult<Option<Epss>> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(EPSS_CACHE_HOURS)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Ok(c.query_row("SELECT epss, percentile, score_date FROM epss_cache WHERE cve_id = ?1 AND fetched_at >= ?2", params![cve, cutoff], |r| Ok(Epss { epss: r.get(0)?, percentile: r.get(1)?, date: r.get(2)? })).optional()?)
}

pub fn epss_store(c: &Connection, rows: &[(String, Epss)]) -> AppResult<()> {
    let ts = now();
    for (cve, e) in rows {
        c.execute(
            "INSERT INTO epss_cache (cve_id, epss, percentile, score_date, fetched_at) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(cve_id) DO UPDATE SET epss = excluded.epss, percentile = excluded.percentile, score_date = excluded.score_date, fetched_at = excluded.fetched_at",
            params![cve, e.epss, e.percentile, e.date, ts],
        )?;
    }
    Ok(())
}

/// Fetches EPSS scores for up to 100 CVE ids (only the ids are sent).
pub async fn epss_fetch(cves: &[String]) -> AppResult<Vec<(String, Epss)>> {
    if cves.is_empty() {
        return Ok(vec![]);
    }
    let list: Vec<String> = cves.iter().take(100).map(|c| normalize_cve(c)).collect::<Result<_, _>>()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client: {e}")))?;
    let resp = client.get(EPSS_URL).query(&[("cve", list.join(","))]).send().await.map_err(|e| AppError::Network(format!("EPSS (FIRST.org) is not reachable: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::Network(format!("EPSS (FIRST.org) returned HTTP {}", resp.status())));
    }
    let mut resp = resp;
    let mut raw = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| AppError::Network(e.to_string()))? {
        if raw.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err(AppError::Network("EPSS returned an unexpectedly large response".into()));
        }
        raw.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&raw)?;
    parse_epss(&body).map_err(AppError::Network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use serde_json::json;

    fn f(cvss: Option<f64>, epss: Option<f64>, kev: bool, exposure: &str, criticality: &str) -> Factors {
        Factors { cvss, epss, epss_percentile: None, kev, exploit_known: false, exposure: exposure.into(), criticality: criticality.into() }
    }

    #[test]
    fn the_priority_model_is_deterministic_and_explained() {
        // Log4Shell-like: critical, KEV, likely exploited, internet-facing, critical asset
        let p = prioritize(&f(Some(10.0), Some(0.97), true, "internet", "high"));
        assert_eq!((p.level, p.score), ("p1", 16.0));
        assert_eq!(p.reasons.iter().map(|r| r.factor.as_str()).collect::<Vec<_>>(), vec!["cvss", "kev", "epss", "exposure", "criticality"]);
        // same CVSS, internal, low criticality, unlikely exploitation
        assert_eq!(prioritize(&f(Some(9.8), Some(0.001), false, "internal", "low")).level, "p2");
        assert_eq!(prioritize(&f(Some(5.3), None, false, "internal", "medium")).level, "p4");
        assert_eq!(prioritize(&f(Some(5.3), Some(0.2), false, "internet", "medium")).level, "p3");
        // missing data is stated, not hidden
        let p = prioritize(&f(None, None, false, "unknown", "medium"));
        assert!(p.reasons.iter().any(|r| r.text.contains("No CVSS")));
        assert!(p.reasons.iter().any(|r| r.text.contains("EPSS was not available")));
        // KEV and analyst knowledge do not add up twice
        let both = prioritize(&Factors { exploit_known: true, ..f(Some(7.0), None, true, "internal", "medium") });
        assert_eq!(both.score, 9.0);
    }

    #[test]
    fn the_newest_cvss_version_is_used() {
        let s = |v: &str, score: f64, src: &str| CvssScore { version: v.into(), score, severity: String::new(), vector: String::new(), source: src.into() };
        let list = vec![s("2.0", 7.5, "nvd@nist.gov"), s("3.1", 9.1, "vendor@example.com"), s("3.1", 9.8, "nvd@nist.gov")];
        assert_eq!(best_cvss(&list).map(|x| x.score), Some(9.8));
        assert_eq!(severity_of(Some(9.8)), "critical");
        assert_eq!(severity_of(None), "info");
    }

    #[test]
    fn epss_responses_are_validated() {
        let body = json!({ "status": "OK", "data": [
            { "cve": "CVE-2021-44228", "epss": "0.944340000", "percentile": "0.999890000", "date": "2026-11-04" },
            { "cve": "not-a-cve", "epss": "0.5", "percentile": "0.5" },
            { "cve": "CVE-2020-0001", "epss": "1.7", "percentile": "0.5" }
        ]});
        let rows = parse_epss(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "CVE-2021-44228");
        assert!((rows[0].1.epss - 0.94434).abs() < 1e-9);
        assert!(parse_epss(&json!({ "error": 1 })).is_err());
        assert_eq!(normalize_cve(" cve-2024-3094 ").unwrap(), "CVE-2024-3094");
        for bad in ["CVE-24-1", "CVE-2024-12", "2024-3094", "CVE-2024-3094; DROP"] {
            assert!(normalize_cve(bad).is_err(), "{bad}");
        }
    }

    fn setup(db: &Db) -> (i64, i64) {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            c.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (?1,'service','10.0.0.5:443/tcp','10.0.0.5:443/tcp','nmap','t','t','t','t')", params![p])?;
            Ok((p, c.last_insert_rowid()))
        })
        .unwrap()
    }

    fn record(score: f64, kev: bool) -> CveRecord {
        CveRecord {
            id: "CVE-2024-3094".into(),
            published: String::new(),
            last_modified: String::new(),
            status: String::new(),
            description: "Malicious code was discovered in xz. More text.".into(),
            cvss: vec![CvssScore { version: "3.1".into(), score, severity: "CRITICAL".into(), vector: "CVSS:3.1/AV:N".into(), source: "nvd@nist.gov".into() }],
            cwes: vec![],
            products: vec![],
            references: vec![],
            kev,
        }
    }

    #[test]
    fn removing_an_asset_keeps_its_vulnerabilities_for_the_project() {
        let db = Db::open_in_memory().unwrap();
        let (p, asset) = setup(&db);
        db.with(|c| {
            let input = VulnInput { project_id: p, cve_id: "CVE-2024-3094".into(), asset_id: Some(asset), exposure: None, criticality: None, exploit_known: false, notes: String::new() };
            let v = create(c, &input, None, None, "user")?;
            detach_asset(c, asset, "10.0.0.5:443/tcp")?;
            let after = get(c, v.id)?;
            assert_eq!((after.asset_id, after.exposure.as_str()), (None, v.exposure.as_str()));
            let note: String = c.query_row("SELECT note FROM vulnerability_events WHERE vulnerability_id = ?1 AND kind = 'updated'", params![v.id], |r| r.get(0))?;
            assert!(note.contains("10.0.0.5:443/tcp was removed"), "{note}");
            // the same CVE on the asset and for the whole project: refused, nothing changes
            let on_asset = create(c, &input, None, None, "user")?;
            let err = detach_asset(c, asset, "10.0.0.5:443/tcp").unwrap_err().to_string();
            assert!(err.contains("CVE-2024-3094") && err.contains("retire the asset"), "{err}");
            assert_eq!(get(c, on_asset.id)?.asset_id, Some(asset));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn the_lifecycle_is_recorded_and_rules_are_enforced() {
        let db = Db::open_in_memory().unwrap();
        let (p, asset) = setup(&db);
        db.with(|c| {
            let input = VulnInput { project_id: p, cve_id: "cve-2024-3094".into(), asset_id: Some(asset), ..Default::default() };
            let v = create(c, &input, Some(&record(10.0, false)), None, "user")?;
            assert_eq!((v.cve_id.as_str(), v.exposure.as_str(), v.title.as_str()), ("CVE-2024-3094", "internal", "Malicious code was discovered in xz"), "a private service is internal");
            assert_eq!(v.priority, "p2");
            assert!(matches!(create(c, &input, None, None, "user"), Err(AppError::Conflict(_))), "one record per CVE and asset");
            // the same CVE without an asset is a separate record, also unique
            let general = create(c, &VulnInput { asset_id: None, ..input.clone() }, None, None, "user")?;
            assert_eq!(general.priority_reasons[0].text, "No CVSS score is known; counted as 5.0");
            assert!(create(c, &VulnInput { asset_id: None, ..input.clone() }, None, None, "user").is_err());

            let v = set_context(c, v.id, "internet", "high", true, "user")?;
            assert_eq!(v.priority, "p1");
            let v = set_scores(c, v.id, Some(&record(10.0, true)), Some(&Epss { epss: 0.9, percentile: 0.99, date: "2026-11-04".into() }), "user")?;
            assert!(v.kev && v.epss == Some(0.9));
            assert!(set_status(c, v.id, "accepted_risk", " ", "user").is_err(), "accepting a risk needs a reason");
            set_status(c, v.id, "in_remediation", "", "user")?;
            let v = set_remediation(c, v.id, "Downgrade xz to 5.4.6", "ops team", Some("2026-11-20"), "user")?;
            assert_eq!(v.remediation_due.as_deref(), Some("2026-11-20"));
            assert!(set_remediation(c, v.id, "", "", Some("soon"), "user").is_err());
            let v = verify(c, v.id, "Rescanned 2026-11-21: xz 5.4.6 installed", "user")?;
            assert_eq!(v.status, "resolved");
            assert!(v.verified_at.is_some());
            let v = set_status(c, v.id, "open", "Came back after the rollback", "user")?;
            assert!(v.verified_at.is_none(), "a reopened vulnerability is no longer verified");
            let kinds: Vec<String> = history(c, v.id)?.into_iter().map(|e| e.kind).collect();
            assert_eq!(kinds, vec!["created", "updated", "priority", "status", "remediation", "verification", "status"]);
            assert!(create(c, &VulnInput { project_id: p + 1, ..input.clone() }, None, None, "user").is_err());
            assert!(create(c, &VulnInput { cve_id: "log4shell".into(), ..input.clone() }, None, None, "user").is_err());
            delete(c, general.id)?;
            assert_eq!(list(c, p)?.len(), 1);
            Ok(())
        })
        .unwrap();
    }
}
