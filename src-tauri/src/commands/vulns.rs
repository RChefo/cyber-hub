//! Vulnerability management and bulk finding commands (see `workspace::vulns`).

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::State;

use crate::commands::intel::{cve_search, CveRecord};
use crate::commands::projects::{finding_get, finding_save, FindingInput};
use crate::db::Db;
use crate::error::{validation, AppResult};
use crate::workspace::findings as lifecycle;
use crate::workspace::vulns::{self, Epss, VulnInput, Vulnerability};

fn cached_record(db: &Db, cve: &str) -> AppResult<Option<CveRecord>> {
    db.with(|c| {
        let raw: Option<String> = c.query_row("SELECT data FROM cve_cache WHERE id = ?1", params![cve], |r| r.get(0)).optional()?;
        Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
    })
}

/// EPSS is on unless the user turned it off (Settings → stored as `epss.enabled`).
fn epss_enabled(db: &Db) -> bool {
    db.with(|c| Ok(c.query_row("SELECT value FROM user_preferences WHERE key = 'epss.enabled'", [], |r| r.get::<_, String>(0)).optional()?))
        .ok()
        .flatten()
        .map_or(true, |v| v.trim() != "false")
}

/// EPSS for these CVEs: cached values (24 h), the rest fetched in one request.
async fn epss_for(db: &Db, cves: &[String], warnings: &mut Vec<String>) -> Vec<(String, Epss)> {
    if !epss_enabled(db) {
        return vec![];
    }
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for cve in cves {
        match db.with(|c| vulns::epss_cached(c, cve)) {
            Ok(Some(e)) => out.push((cve.clone(), e)),
            _ => missing.push(cve.clone()),
        }
    }
    for chunk in missing.chunks(100) {
        match vulns::epss_fetch(chunk).await {
            Ok(rows) => {
                let _ = db.with(|c| vulns::epss_store(c, &rows));
                out.extend(rows);
            }
            Err(e) => {
                warnings.push(format!("EPSS: {e}"));
                break;
            }
        }
    }
    out
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnResult {
    pub vulnerability: Vulnerability,
    /// what could not be fetched (the priority states it too)
    pub warnings: Vec<String>,
}

#[tauri::command]
pub async fn vulns_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<Vulnerability>> {
    db.with(|c| vulns::list(c, project_id))
}

/// Tracks a CVE: the NVD record comes from the local cache or one NVD lookup, EPSS (when on)
/// from FIRST.org. Missing data does not block; it is stated in the priority's reasons.
#[tauri::command]
pub async fn vuln_add(db: State<'_, Db>, input: VulnInput) -> AppResult<VulnResult> {
    let cve = vulns::normalize_cve(&input.cve_id)?;
    let mut warnings = Vec::new();
    let record = match cached_record(&db, &cve)? {
        Some(r) => Some(r),
        None => match cve_search(db.clone(), cve.clone(), true).await {
            Ok(res) => res.records.into_iter().find(|r| r.id == cve),
            Err(e) => {
                warnings.push(format!("NVD: {e}"));
                None
            }
        },
    };
    if record.is_none() && warnings.is_empty() {
        warnings.push(format!("NVD has no record for {cve}"));
    }
    let epss = epss_for(&db, std::slice::from_ref(&cve), &mut warnings).await.into_iter().next().map(|(_, e)| e);
    let input = VulnInput { cve_id: cve, ..input };
    let vulnerability = db.with(|c| vulns::create(c, &input, record.as_ref(), epss.as_ref(), "user"))?;
    Ok(VulnResult { vulnerability, warnings })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResult {
    pub updated: usize,
    pub warnings: Vec<String>,
}

/// Re-reads CVSS/KEV from the local CVE cache (one NVD lookup each for at most 5 CVEs that have no
/// record yet) and EPSS for the project's open vulnerabilities, then recomputes priorities.
#[tauri::command]
pub async fn vulns_refresh(db: State<'_, Db>, project_id: i64) -> AppResult<RefreshResult> {
    let list: Vec<Vulnerability> = db.with(|c| vulns::list(c, project_id))?.into_iter().filter(|v| vulns::is_open(&v.status)).collect();
    let mut warnings = Vec::new();
    let mut cves: Vec<String> = list.iter().map(|v| v.cve_id.clone()).collect();
    cves.sort();
    cves.dedup();
    let mut lookups = 0;
    let mut records = std::collections::HashMap::new();
    for cve in &cves {
        let mut r = cached_record(&db, cve)?;
        if r.is_none() && lookups < 5 {
            lookups += 1;
            match cve_search(db.clone(), cve.clone(), true).await {
                Ok(res) => r = res.records.into_iter().find(|x| &x.id == cve),
                Err(e) => warnings.push(format!("NVD ({cve}): {e}")),
            }
        }
        if let Some(r) = r {
            records.insert(cve.clone(), r);
        }
    }
    let epss: std::collections::HashMap<String, Epss> = epss_for(&db, &cves, &mut warnings).await.into_iter().collect();
    let mut updated = 0;
    for v in &list {
        db.with(|c| vulns::set_scores(c, v.id, records.get(&v.cve_id), epss.get(&v.cve_id), "refresh"))?;
        updated += 1;
    }
    Ok(RefreshResult { updated, warnings })
}

#[tauri::command]
pub async fn vuln_set_context(db: State<'_, Db>, id: i64, exposure: String, criticality: String, exploit_known: bool) -> AppResult<Vulnerability> {
    db.with(|c| vulns::set_context(c, id, &exposure, &criticality, exploit_known, "user"))
}

#[tauri::command]
pub async fn vuln_set_status(db: State<'_, Db>, id: i64, status: String, note: Option<String>) -> AppResult<Vulnerability> {
    db.with(|c| vulns::set_status(c, id, &status, note.as_deref().unwrap_or(""), "user"))
}

#[tauri::command]
pub async fn vuln_set_remediation(db: State<'_, Db>, id: i64, plan: String, owner: String, due: Option<String>) -> AppResult<Vulnerability> {
    db.with(|c| vulns::set_remediation(c, id, &plan, &owner, due.as_deref(), "user"))
}

#[tauri::command]
pub async fn vuln_verify(db: State<'_, Db>, id: i64, note: String) -> AppResult<Vulnerability> {
    db.with(|c| vulns::verify(c, id, &note, "user"))
}

#[tauri::command]
pub async fn vuln_history(db: State<'_, Db>, id: i64) -> AppResult<Vec<vulns::VulnEvent>> {
    db.with(|c| vulns::history(c, id))
}

#[tauri::command]
pub async fn vuln_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| vulns::delete(c, id))
}

/// Creates a finding from a vulnerability (severity from CVSS, remediation copied) and links them.
#[tauri::command]
pub async fn vuln_create_finding(db: State<'_, Db>, id: i64) -> AppResult<i64> {
    db.with(|c| {
        let v = vulns::get(c, id)?;
        let existing: Option<i64> = c
            .query_row("SELECT finding_id FROM finding_links WHERE kind = 'vulnerability' AND ref_id = ?1 LIMIT 1", params![id], |r| r.get(0))
            .optional()?;
        if let Some(f) = existing {
            return Err(crate::error::AppError::Conflict(format!("Finding #{f} already covers this vulnerability")));
        }
        let title = if v.title.is_empty() { v.cve_id.clone() } else { format!("{}: {}", v.cve_id, v.title) };
        let input = FindingInput {
            project_id: v.project_id,
            title: title.chars().take(200).collect(),
            severity: vulns::severity_of(v.cvss_score).into(),
            status: "new".into(),
            cve: v.cve_id.clone(),
            affected_target: v.asset.clone().unwrap_or_default().chars().take(500).collect(),
            description: format!(
                "{}{}\n\nPriority {} ({}): {}",
                v.title,
                v.cvss_score.map(|s| format!(" CVSS {s:.1}.")).unwrap_or_default(),
                v.priority.to_uppercase(),
                v.priority_score,
                v.priority_reasons.iter().filter(|r| r.effect != 0.0).map(|r| r.text.clone()).collect::<Vec<_>>().join("; ")
            ),
            remediation: v.remediation.clone(),
            category: "Vulnerable software".into(),
            confidence: Some(if v.asset_id.is_some() { "medium" } else { "low" }.into()),
            ..Default::default()
        };
        let fid = finding_save(c, &input, "vulnerability")?;
        lifecycle::link(c, fid, "vulnerability", id, "vulnerability")?;
        if let Some(a) = v.asset_id {
            let _ = lifecycle::link(c, fid, "asset", a, "vulnerability");
        }
        Ok(fid)
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResult {
    pub changed: Vec<i64>,
    /// (finding id, reason) for findings that were left as they were
    pub skipped: Vec<(i64, String)>,
}

/// Changes the status of several findings; each change is validated and recorded on its own, and
/// findings that cannot change (same status, invalid step) are reported, not failed.
#[tauri::command]
pub async fn findings_bulk_status(db: State<'_, Db>, ids: Vec<i64>, status: String, note: Option<String>) -> AppResult<BulkResult> {
    if ids.is_empty() || ids.len() > 1000 {
        return Err(validation("Select 1 to 1000 findings"));
    }
    let note = note.unwrap_or_default();
    db.with(|c| bulk_status(c, &ids, &status, &note))
}

pub(crate) fn bulk_status(c: &rusqlite::Connection, ids: &[i64], status: &str, note: &str) -> AppResult<BulkResult> {
    let target = lifecycle::status_or_err(status)?;
    let tx = c.unchecked_transaction()?;
    let mut out = BulkResult { changed: vec![], skipped: vec![] };
    for &id in ids {
        match finding_get(&tx, id).map_err(|e| e.to_string()).and_then(|f| lifecycle::transition_ok(&f.status, target)) {
            Err(reason) => out.skipped.push((id, reason)),
            Ok(()) => {
                lifecycle::set_status(&tx, id, target, note, "user")?;
                out.changed.push(id);
            }
        }
    }
    tx.commit()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_status_changes_valid_findings_and_reports_the_rest() {
        let db = Db::open_in_memory().unwrap();
        let ids: Vec<i64> = db
            .with(|c| {
                c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
                let p = c.last_insert_rowid();
                let mut ids = vec![];
                for s in ["new", "resolved", "confirmed"] {
                    ids.push(finding_save(c, &FindingInput { project_id: p, title: format!("F {s}"), severity: "low".into(), status: s.into(), ..Default::default() }, "user")?);
                }
                Ok(ids)
            })
            .unwrap();
        let ids_and_missing: Vec<i64> = ids.iter().copied().chain([9999]).collect();
        let run = |status: &str| db.with(|c| bulk_status(c, &ids_and_missing, status, "bulk")).unwrap();
        let r = run("reopened");
        assert_eq!(r.changed, vec![ids[1]], "only the resolved finding can be reopened");
        assert_eq!(r.skipped.len(), 3);
        let r = run("in_remediation");
        assert_eq!(r.changed, ids);
        assert!(db.with(|c| bulk_status(c, &ids, "closed", "")).is_err(), "unknown statuses are refused");
        let r = run("open");
        assert_eq!(r.changed, ids, "legacy names are accepted");
    }
}
