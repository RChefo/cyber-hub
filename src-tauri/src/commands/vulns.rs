//! Vulnerability management and bulk finding commands (see `workspace::vulns`).

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::intel::{cve_search, CveRecord};
use crate::commands::projects::{finding_get, finding_write, FindingInput};
use crate::db::Db;
use crate::error::{validation, AppResult};
use crate::workspace::findings as lifecycle;
use crate::workspace::vulns::{self, Epss, VulnInput, Vulnerability};

fn cached_record(db: &Db, cve: &str) -> AppResult<Option<CveRecord>> {
    db.with(|c| vulns::cached_record(c, cve))
}

/// EPSS is on unless the user turned it off (Settings → stored as `epss.enabled`).
fn epss_enabled(db: &Db) -> bool {
    db.with(|c| Ok(c.query_row("SELECT value FROM user_preferences WHERE key = 'epss.enabled'", [], |r| r.get::<_, String>(0)).optional()?))
        .ok()
        .flatten()
        .is_none_or(|v| v.trim() != "false")
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
        // the finding is saved with its links, or not at all (a retry cannot duplicate it)
        let tx = c.unchecked_transaction()?;
        let fid = finding_write(&tx, &input, "vulnerability", true)?;
        lifecycle::link(&tx, fid, "vulnerability", id, "vulnerability")?;
        if let Some(a) = v.asset_id {
            lifecycle::link(&tx, fid, "asset", a, "vulnerability")?;
        }
        tx.commit()?;
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

/// Tags to add or remove and an optional new assignee for several findings.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkEdit {
    #[serde(default)]
    pub add_tags: Vec<String>,
    #[serde(default)]
    pub remove_tags: Vec<String>,
    /// None keeps each finding's assignee; an empty string clears it
    #[serde(default)]
    pub assignee: Option<String>,
}

/// Adds or removes tags and sets the assignee of several findings; each finding is saved on its
/// own (its history records what changed), and findings that would not change are reported.
#[tauri::command]
pub async fn findings_bulk_edit(db: State<'_, Db>, ids: Vec<i64>, edit: BulkEdit) -> AppResult<BulkResult> {
    if ids.is_empty() || ids.len() > 1000 {
        return Err(validation("Select 1 to 1000 findings"));
    }
    db.with(|c| bulk_edit(c, &ids, &edit))
}

fn clean_tags(list: &[String]) -> AppResult<Vec<String>> {
    if list.len() > 20 {
        return Err(validation("At most 20 tags at a time"));
    }
    let mut out = Vec::new();
    for t in list {
        let v = crate::util::clean("Tag", t, 40, false)?;
        if !v.is_empty() {
            out.push(v);
        }
    }
    Ok(out)
}

pub(crate) fn bulk_edit(c: &rusqlite::Connection, ids: &[i64], edit: &BulkEdit) -> AppResult<BulkResult> {
    let add = clean_tags(&edit.add_tags)?;
    let remove: Vec<String> = clean_tags(&edit.remove_tags)?.into_iter().map(|t| t.to_lowercase()).collect();
    let assignee = match edit.assignee.as_deref() {
        Some(a) => Some(crate::util::clean("Assignee", a, 100, false)?),
        None => None,
    };
    if add.is_empty() && remove.is_empty() && assignee.is_none() {
        return Err(validation("Choose tags to add or remove, or an assignee"));
    }
    let tx = c.unchecked_transaction()?;
    let mut out = BulkResult { changed: vec![], skipped: vec![] };
    for &id in ids {
        let f = match finding_get(&tx, id) {
            Ok(f) => f,
            Err(e) => {
                out.skipped.push((id, e.to_string()));
                continue;
            }
        };
        let mut tags: Vec<String> = f.tags.iter().filter(|t| !remove.contains(&t.to_lowercase())).cloned().collect();
        for t in &add {
            if !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                tags.push(t.clone());
            }
        }
        if tags.len() > 20 {
            out.skipped.push((id, "It would have more than 20 tags".into()));
            continue;
        }
        let new_assignee = assignee.clone().unwrap_or_else(|| f.assignee.clone());
        if tags == f.tags && new_assignee == f.assignee {
            out.skipped.push((id, "Nothing to change".into()));
            continue;
        }
        let input = FindingInput {
            id: Some(id),
            project_id: f.project_id,
            title: f.title,
            severity: f.severity,
            status: f.status,
            category: f.category,
            confidence: Some(f.confidence),
            description: f.description,
            affected_target: f.affected_target,
            cve: f.cve,
            evidence: f.evidence,
            reproduction: f.reproduction,
            technical_details: f.technical_details,
            remediation: f.remediation,
            tags,
            assignee: new_assignee,
            due_date: f.due_date,
            cvss_vector: f.cvss_vector,
        };
        finding_write(&tx, &input, "user", false)?;
        out.changed.push(id);
    }
    tx.commit()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::projects::finding_save;

    #[test]
    fn bulk_edit_adds_and_removes_tags_and_sets_assignees() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            let mk = |c: &rusqlite::Connection, tags: &[&str]| {
                finding_save(c, &FindingInput { project_id: p, title: "F".into(), severity: "low".into(), status: "new".into(), tags: tags.iter().map(|t| t.to_string()).collect(), ..Default::default() }, "user")
            };
            let a = mk(c, &["web", "old"])?;
            let b = mk(c, &["Web"])?;
            let r = bulk_edit(c, &[a, b, 9999], &BulkEdit { add_tags: vec!["retest".into(), " WEB ".into()], remove_tags: vec!["OLD".into()], assignee: Some("dana".into()) })?;
            assert_eq!(r.changed, vec![a, b]);
            assert_eq!(r.skipped.len(), 1, "a missing finding is reported");
            let fa = finding_get(c, a)?;
            assert_eq!((fa.tags.clone(), fa.assignee.as_str()), (vec!["web".to_string(), "retest".to_string()], "dana"), "case-insensitive add and remove");
            assert!(lifecycle::history(c, a)?.iter().any(|e| e.note.contains("tags") && e.note.contains("assignee")));
            let again = bulk_edit(c, &[a], &BulkEdit { add_tags: vec!["retest".into()], ..Default::default() })?;
            assert_eq!(again.skipped[0].1, "Nothing to change");
            bulk_edit(c, &[a], &BulkEdit { assignee: Some(String::new()), ..Default::default() })?;
            assert_eq!(finding_get(c, a)?.assignee, "");
            assert!(bulk_edit(c, &[a], &BulkEdit::default()).is_err(), "an empty edit is refused");
            Ok(())
        })
        .unwrap();
    }

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
