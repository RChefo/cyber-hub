//! ATT&CK matrix commands (`workspace/attack_matrix.rs`): the bundled catalog, a project's
//! matrix, the analyst's assessments, imported Navigator layers and the layer export. Files are
//! chosen in native dialogs; nothing here contacts a network.

use std::sync::Arc;

use rusqlite::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};

use crate::commands::workspace::main_window_dialog;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::workspace::attack::{self, Tactic, Technique};
use crate::workspace::attack_matrix::{self as matrix, Assessment, LayerSummary, Matrix};
use crate::workspace::evidence::{self, EvidenceStore, Provenance};
use crate::workspace::{relations, timeline};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogView {
    pub domain: String,
    pub version: String,
    pub modified: String,
    pub retrieved: String,
    pub url: String,
    pub notice: String,
    pub tactics: Vec<Tactic>,
    pub techniques: Vec<Technique>,
}

fn domain_arg(domain: Option<String>) -> AppResult<&'static str> {
    match domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        None => Ok(attack::ENTERPRISE),
        Some(d) => attack::parse_domain(d).ok_or_else(|| validation("The ATT&CK domain is enterprise-attack, mobile-attack or ics-attack")),
    }
}

/// A bundled ATT&CK catalog (Enterprise by default, Mobile or ICS): tactics in matrix order and
/// every technique.
#[tauri::command]
pub async fn attack_catalog(domain: Option<String>) -> AppResult<CatalogView> {
    let d = domain_arg(domain)?;
    let c = attack::catalog_for(d).unwrap_or_else(attack::catalog);
    Ok(CatalogView { domain: d.into(), version: c.version.clone(), modified: c.modified.clone(), retrieved: c.retrieved.clone(), url: c.url.clone(), notice: c.notice.clone(), tactics: c.tactics.clone(), techniques: c.techniques.clone() })
}

/// Everything that happened about one technique in a project, oldest first.
#[tauri::command]
pub async fn attack_technique_history(db: State<'_, Db>, project_id: i64, technique: String) -> AppResult<Vec<crate::workspace::attack_history::HistoryEntry>> {
    db.with(|c| crate::workspace::attack_history::technique_history(c, project_id, &technique))
}

/// Two technique sets compared: observed, hypotheses, coverage, snapshot:<id>, layer:<id>.
#[tauri::command]
pub async fn attack_compare(db: State<'_, Db>, project_id: i64, a: String, b: String, domain: Option<String>) -> AppResult<crate::workspace::attack_history::Comparison> {
    let d = domain_arg(domain)?;
    db.with(|c| crate::workspace::attack_history::compare(c, project_id, d, &a, &b))
}

#[tauri::command]
pub async fn attack_snapshots(db: State<'_, Db>) -> AppResult<Vec<crate::workspace::attack_history::Snapshot>> {
    db.with(crate::workspace::attack_history::snapshots)
}

#[tauri::command]
pub async fn attack_snapshot_take(db: State<'_, Db>, label: String, domain: Option<String>) -> AppResult<i64> {
    let d = domain_arg(domain)?;
    db.with(|c| crate::workspace::attack_history::snapshot_take(c, &label, d))
}

#[tauri::command]
pub async fn attack_snapshot_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| crate::workspace::attack_history::snapshot_delete(c, id))
}

#[tauri::command]
pub async fn attack_matrix(db: State<'_, Db>, project_id: i64, domain: Option<String>) -> AppResult<Matrix> {
    let d = domain_arg(domain)?;
    db.with(|c| matrix::matrix_for(c, project_id, d))
}

/// Sets the analyst's assessment of a technique (confirmed, hypothesis, ruled_out), or removes it
/// when `status` is null.
#[tauri::command]
pub async fn attack_assess(db: State<'_, Db>, project_id: i64, technique: String, status: Option<String>, confidence: String, note: Option<String>) -> AppResult<Option<Assessment>> {
    db.with(|c| matrix::assess(c, project_id, &technique, status.as_deref(), &confidence, note.as_deref().unwrap_or(""), "user"))
}

/// Imports an ATT&CK Navigator layer chosen in a native dialog as an overlay of the project's
/// matrix; the file is kept in the evidence vault. None when cancelled.
#[tauri::command]
pub async fn attack_layer_import(app: AppHandle, project_id: i64) -> AppResult<Option<LayerSummary>> {
    app.state::<Db>().with(|c| relations::require_open(c, project_id))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Import an ATT&CK Navigator layer").add_filter("ATT&CK Navigator layer", &["json"]).add_filter("All files", &["*"]).pick_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Option<LayerSummary>> {
        if std::fs::metadata(&path)?.len() > matrix::MAX_LAYER_BYTES as u64 {
            return Err(validation("The layer is larger than 10 MB"));
        }
        let bytes = std::fs::read(&path)?;
        let parsed = matrix::parse_layer(&bytes).map_err(validation)?;
        let sha: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        let file_name = evidence::display_name(&path.to_string_lossy());
        let db = handle.state::<Db>();
        let store = handle.state::<Arc<EvidenceStore>>();
        if db.with(|c| Ok(c.query_row("SELECT 1 FROM attack_layers WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha], |_| Ok(())).ok()))?.is_some() {
            return Err(validation("This layer is already imported in the project"));
        }
        let before: i64 = db.with(|c| Ok(c.query_row("SELECT COALESCE(MAX(id), 0) FROM evidence", [], |r| r.get(0))?))?;
        let rec = store.add_bytes(&db, project_id, &file_name, &bytes, (&format!("ATT&CK layer: {}", parsed.name), &format!("Imported ATT&CK Navigator layer. SHA-256 {sha}")), "import")?;
        let stored = db.with(|c| {
            let tx = c.unchecked_transaction()?;
            let id = matrix::store_layer(&tx, project_id, &file_name, &sha, Some(rec.id), &parsed)?;
            let tool = if parsed.navigator_version.is_empty() { "ATT&CK Navigator".to_string() } else { format!("ATT&CK Navigator {}", parsed.navigator_version) };
            evidence::set_provenance(&tx, rec.id, &Provenance { source_module: "attack_layer".into(), source_ref: format!("attack_layer:{id}"), tool, tool_version: parsed.layer_version.clone(), ..Default::default() })?;
            let made_for = if parsed.attack_version.is_empty() { String::new() } else { format!(", made for ATT&CK v{}", parsed.attack_version) };
            let summary = format!("ATT&CK layer imported: {} ({} techniques{made_for})", parsed.name, parsed.techniques.len());
            tx.execute("INSERT INTO relation_events (project_id, relation_id, action, summary, note, actor, at) VALUES (?1, NULL, 'layer_imported', ?2, ?3, 'user', ?4)", params![project_id, summary, file_name, crate::util::now()])?;
            tx.commit()?;
            Ok(id)
        });
        let id = match stored {
            Ok(id) => id,
            Err(e) => {
                // nothing was recorded: a file this import added does not stay behind
                if rec.id > before {
                    let _ = store.delete(&db, rec.id);
                }
                return Err(e);
            }
        };
        db.with(|c| matrix::layers(c, project_id)).map(|ls| ls.into_iter().find(|l| l.id == id))
    })
    .await
    .map_err(|e| AppError::Internal(format!("the import failed: {e}")))?
}

/// Removes an imported layer; its file stays in the evidence vault.
#[tauri::command]
pub async fn attack_layer_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        let name: String = c.query_row("SELECT name FROM attack_layers WHERE id = ?1", params![id], |r| r.get(0)).unwrap_or_default();
        let project_id = matrix::delete_layer(c, id)?;
        c.execute("INSERT INTO relation_events (project_id, relation_id, action, summary, note, actor, at) VALUES (?1, NULL, 'layer_removed', ?2, '', 'user', ?3)", params![project_id, format!("ATT&CK layer removed: {name}"), crate::util::now()])?;
        Ok(())
    })
}

/// Saves the project's techniques (named by findings, and the analyst's assessments) as an
/// ATT&CK Navigator layer through a native dialog. Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn attack_layer_export(app: AppHandle, project_id: i64, domain: Option<String>) -> AppResult<Option<String>> {
    let d = domain_arg(domain)?;
    let (name, content) = app.state::<Db>().with(|c| {
        let name: String = c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?;
        let m = matrix::matrix_for(c, project_id, d)?;
        Ok((name.clone(), matrix::export_layer(&name, &crate::util::now(), &m).map_err(validation)?))
    })?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    // the file name says which matrix the layer belongs to
    let short = d.split('-').next().unwrap_or("enterprise");
    main_window_dialog(&app, "Export ATT&CK layer").set_file_name(format!("{safe}-attack-{short}-layer.json")).add_filter("ATT&CK Navigator layer", &["json"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the layer: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let what = format!("ATT&CK {} layer exported (findings and assessments)", attack::domain_label(d));
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", &what, &file, None, None));
    Ok(Some(file))
}
