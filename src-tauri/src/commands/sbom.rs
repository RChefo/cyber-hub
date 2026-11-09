//! SBOM commands (`workspace/sbom.rs`): import an SBOM into a project, read it with its checks,
//! look its components up on OSV.dev when the analyst asks, and record findings.

use std::collections::BTreeMap;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::commands::activity;
use crate::commands::apisec::recorded_finding;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::workspace::evidence::{self, EvidenceStore};
use crate::workspace::sbom::{self, Issue, Sbom, SbomSummary, Vuln};
use crate::workspace::{findings, scan_import, timeline};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomView {
    pub summary: SbomSummary,
    pub sbom: Sbom,
    /// the file's own and the looked-up vulnerabilities, most severe first
    pub vulns: Vec<Vuln>,
    pub issues: Vec<Issue>,
    /// recorded findings: "vuln:<id>:<component>" or "issue:<id>" → finding id
    pub recorded: BTreeMap<String, i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomCheck {
    /// components looked up
    pub checked: usize,
    /// components without a package URL or a version, not sent
    pub skipped: usize,
    pub vulns: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomRecorded {
    pub created: usize,
    pub existing: usize,
}

fn inputs(summary: &SbomSummary, sbom: &Sbom, vulns: &[Vuln], issues: &[Issue]) -> Vec<(String, crate::commands::projects::FindingInput)> {
    let mut out = Vec::new();
    for v in vulns {
        for c in &v.components {
            if let Some(f) = sbom::vuln_finding(summary, sbom, v, *c) {
                out.push((format!("vuln:{}:{c}", v.id), f));
            }
        }
    }
    for i in issues {
        out.push((format!("issue:{}", i.id), sbom::issue_finding(summary, sbom, i)));
    }
    out
}

pub(crate) fn view(c: &Connection, id: i64) -> AppResult<SbomView> {
    let (summary, sbom, osv) = sbom::get(c, id)?;
    let vulns = sbom::merged(&sbom, &osv);
    let issues = sbom::audit(&sbom);
    let mut recorded = BTreeMap::new();
    for (key, input) in inputs(&summary, &sbom, &vulns, &issues) {
        if let Some(fid) = recorded_finding(c, &input)? {
            recorded.insert(key, fid);
        }
    }
    Ok(SbomView { summary, sbom, vulns, issues, recorded })
}

/// Records the chosen vulnerabilities and issues as findings, each once, linked to the SBOM file.
pub(crate) fn record(c: &Connection, id: i64, keys: &[String]) -> AppResult<SbomRecorded> {
    if keys.is_empty() || keys.len() > 2000 {
        return Err(validation("Choose between 1 and 2,000 entries to record"));
    }
    let (summary, sbom, osv) = sbom::get(c, id)?;
    let vulns = sbom::merged(&sbom, &osv);
    let issues = sbom::audit(&sbom);
    let all: BTreeMap<String, crate::commands::projects::FindingInput> = inputs(&summary, &sbom, &vulns, &issues).into_iter().collect();
    let tx = c.unchecked_transaction()?;
    let (mut created, mut existing) = (0, 0);
    for key in keys {
        let input = all.get(key).ok_or_else(|| AppError::NotFound(format!("SBOM entry {key}")))?;
        if recorded_finding(&tx, input)?.is_some() {
            existing += 1;
            continue;
        }
        let fid = crate::commands::projects::finding_write(&tx, input, "sbom", true)?;
        if let Some(ev) = summary.evidence_id {
            findings::link(&tx, fid, "evidence", ev, "sbom")?;
        }
        created += 1;
    }
    tx.commit()?;
    Ok(SbomRecorded { created, existing })
}

/// Choose an SBOM (native dialog) and add it to the project. The file is kept in the evidence
/// vault. None when the dialog is cancelled.
#[tauri::command]
pub async fn sbom_import(app: AppHandle, project_id: i64) -> AppResult<Option<SbomSummary>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    crate::commands::workspace::main_window_dialog(&app, "Import an SBOM or a lockfile")
        .add_filter("SBOM or lockfile", &["json", "xml", "spdx", "txt", "cdx", "lock", "yaml", "yml", "mod", "lockfile", "locked"])
        .add_filter("All files", &["*"])
        .pick_file(move |f| {
            let _ = tx.send(f.and_then(|f| f.into_path().ok()));
        });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Option<SbomSummary>> {
        let meta = std::fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(validation("Choose a file"));
        }
        if meta.len() as usize > sbom::MAX_FILE_BYTES {
            return Err(validation(format!("The file is larger than {} MB", sbom::MAX_FILE_BYTES / 1024 / 1024)));
        }
        let bytes = std::fs::read(&path)?;
        if bytes.len() > sbom::MAX_FILE_BYTES {
            return Err(validation("The file grew while it was read"));
        }
        let (text, _) = scan_import::decode_text(&bytes);
        let file_name: String = evidence::display_name(&path.to_string_lossy()).chars().take(200).collect();
        let parsed = sbom::parse_file(&file_name, &text).map_err(AppError::Validation)?;
        if parsed.components.is_empty() {
            return Err(validation("The file lists no components"));
        }
        let what_file = if parsed.format.starts_with("lockfile-") { "Lockfile" } else { "SBOM" };
        let sha256: String = {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
        };
        let db = handle.state::<Db>();
        let dup: Option<i64> = db.with(|c| Ok(c.query_row("SELECT id FROM sbom_docs WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?))?;
        if dup.is_some() {
            return Err(validation("This file is already in the project"));
        }
        let store = handle.state::<Arc<EvidenceStore>>();
        let existed: Option<i64> = db.with(|c| {
            Ok(c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?)
        })?;
        let rec = store.add_bytes(&db, project_id, &file_name, &bytes, (&format!("{what_file}: {file_name}"), &format!("Imported {} ({}). SHA-256 {sha256}", what_file.to_lowercase(), parsed.format)), "import")?;
        let stored = db.with(|c| {
            let tx = c.unchecked_transaction()?;
            let id = sbom::store(&tx, project_id, &file_name, &sha256, Some(rec.id), &parsed)?;
            let what = format!("{} components from {file_name}", parsed.components.len());
            timeline::record(&tx, project_id, "asset", &format!("{what_file}: {}", if parsed.subject.is_empty() { &file_name } else { &parsed.subject }), &what, Some("sbom"), Some(id))?;
            activity::log(&tx, "import", &format!("{what_file} imported"), &what, Some("project"), Some(&project_id.to_string()), Some(project_id))?;
            tx.commit()?;
            Ok(id)
        });
        let id = match stored {
            Ok(id) => id,
            Err(e) => {
                if existed.is_none() {
                    let _ = store.delete(&db, rec.id);
                }
                return Err(e);
            }
        };
        Ok(Some(db.with(|c| sbom::get(c, id))?.0))
    })
    .await
    .map_err(|e| AppError::Internal(format!("reading the SBOM failed: {e}")))?
}

#[tauri::command]
pub async fn sboms_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<SbomSummary>> {
    db.with(|c| sbom::list_docs(c, project_id))
}

#[tauri::command]
pub async fn sbom_get(db: State<'_, Db>, id: i64) -> AppResult<SbomView> {
    db.with(|c| view(c, id))
}

/// Looks the SBOM's components up on OSV.dev. Only package URLs with versions are sent.
#[tauri::command]
pub async fn sbom_check(db: State<'_, Db>, id: i64) -> AppResult<SbomCheck> {
    let (summary, parsed, _) = db.with(|c| sbom::get(c, id))?;
    // no database lock while the network is asked
    let found = sbom::osv_lookup(sbom::OSV_BASE, &parsed.components).await?;
    let check = SbomCheck { checked: found.checked, skipped: found.skipped, vulns: found.vulns.len() };
    db.with(|c| {
        sbom::save_lookup(c, id, &found.vulns)?;
        let what = format!("{} known vulnerabilities in {} checked components ({} not checked: no package URL or version)", check.vulns, check.checked, check.skipped);
        timeline::record(c, summary.project_id, "vulnerability", &format!("SBOM checked on OSV.dev: {}", summary.name), &what, Some("sbom"), Some(id))?;
        activity::log(c, "vuln_lookup", "SBOM checked on OSV.dev", &what, Some("project"), Some(&summary.project_id.to_string()), Some(summary.project_id))
    })?;
    Ok(check)
}

#[tauri::command]
pub async fn sbom_record(db: State<'_, Db>, id: i64, keys: Vec<String>) -> AppResult<SbomRecorded> {
    db.with(|c| record(c, id, &keys))
}

/// Removes an SBOM from the project. Its file stays in the evidence vault, and recorded findings
/// stay.
#[tauri::command]
pub async fn sbom_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        let (summary, _, _) = sbom::get(c, id)?;
        sbom::delete(c, id)?;
        activity::log(c, "import", "SBOM removed", &summary.name, Some("project"), Some(&summary.project_id.to_string()), Some(summary.project_id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_are_recorded_once_and_shown_as_recorded() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
            let pid = c.last_insert_rowid();
            let s = sbom::parse(r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"bom-ref":"a","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","licenses":[{"license":{"id":"AGPL-3.0-only"}}]}],
              "vulnerabilities":[{"id":"CVE-2021-23337","ratings":[{"score":7.2,"severity":"high"}],"affects":[{"ref":"a"}]}]}"#)
            .unwrap();
            let id = sbom::store(c, pid, "bom.json", "aa11", None, &s)?;
            let v = view(c, id)?;
            assert!(v.recorded.is_empty());
            let keys = vec!["vuln:CVE-2021-23337:0".to_string(), "issue:LIC-NETWORK-COPYLEFT".to_string()];
            let first = record(c, id, &keys)?;
            assert_eq!((first.created, first.existing), (2, 0));
            let again = record(c, id, &keys)?;
            assert_eq!((again.created, again.existing), (0, 2), "each entry once");
            let v = view(c, id)?;
            assert!(v.recorded.contains_key("vuln:CVE-2021-23337:0") && v.recorded.contains_key("issue:LIC-NETWORK-COPYLEFT"));
            assert!(record(c, id, &["vuln:nope:0".to_string()]).is_err());
            assert!(record(c, id, &[]).is_err());
            Ok(())
        })
        .unwrap();
    }
}
