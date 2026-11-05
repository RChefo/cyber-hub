//! OSINT workspace commands. Thin wrappers over `crate::osint`: validation and data rules live
//! there; this layer adds transactions, native file dialogs and change notifications.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::osint::analysis::{self, Graph};
use crate::osint::discovery::{self, DiscoverRequest, Operation, OperationDetail, Selection, EVENT_CHANGED};
use crate::osint::ingest::{self, ChangeSummary, Origin};
use crate::osint::io::{self, Document, ImportPreview};
use crate::osint::model::{self, EntityType, Verification};
use crate::osint::providers::{self, internal::ImportSource};
use crate::osint::report::{self, Suggestion};
use crate::osint::store::*;

fn tx<T>(db: &Db, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
    db.with(|c| {
        let t = c.unchecked_transaction()?;
        let r = f(&t)?;
        t.commit()?;
        Ok(r)
    })
}

fn count(n: i64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn changed(app: &AppHandle, inv: i64) {
    let _ = app.emit(EVENT_CHANGED, json!({ "investigationId": inv }));
}

fn safe_name(s: &str) -> String {
    let n: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).take(60).collect();
    if n.trim_matches('_').is_empty() {
        "osint".into()
    } else {
        n
    }
}

async fn save_dialog(app: &AppHandle, title: &str, file_name: &str, filter: &str, ext: &str) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title(title).set_file_name(file_name).add_filter(filter, &[ext]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    rx.await.ok().flatten()
}

fn write_file(path: &std::path::Path, bytes: &[u8]) -> AppResult<String> {
    std::fs::write(path, bytes).map_err(|e| AppError::Internal(format!("Could not write the file: {e}")))?;
    Ok(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
}

/* ───────────────────────── registry ───────────────────────── */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityTypeInfo {
    id: &'static str,
    label: &'static str,
    target: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    entity_types: Vec<EntityTypeInfo>,
    relationship_types: &'static [model::RelationshipType],
    providers: &'static [providers::ProviderInfo],
    event_kinds: &'static [&'static str],
    running: usize,
}

#[tauri::command]
pub async fn osint_registry(state: State<'_, std::sync::Arc<discovery::OsintState>>) -> AppResult<Registry> {
    Ok(Registry {
        entity_types: EntityType::ALL.iter().map(|t| EntityTypeInfo { id: t.as_str(), label: t.label(), target: t.is_target_type() }).collect(),
        relationship_types: model::RELATIONSHIP_TYPES,
        providers: providers::PROVIDERS,
        event_kinds: EVENT_KINDS,
        running: state.running_count(),
    })
}

/* ───────────────────────── investigations ───────────────────────── */

#[tauri::command]
pub async fn osint_investigations(db: State<'_, Db>, include_archived: bool) -> AppResult<Vec<Investigation>> {
    db.with(|c| Ok(investigation_list(c, include_archived)?))
}

#[tauri::command]
pub async fn osint_investigation_get(db: State<'_, Db>, id: i64, touch: Option<bool>) -> AppResult<Investigation> {
    db.with(|c| {
        if touch == Some(true) {
            investigation_touch(c, id)?;
        }
        investigation_get(c, id)
    })
}

#[tauri::command]
pub async fn osint_investigation_create(app: AppHandle, db: State<'_, Db>, input: InvestigationInput) -> AppResult<Investigation> {
    let i = tx(&db, |c| {
        let id = investigation_create(c, &input)?;
        let i = investigation_get(c, id)?;
        crate::commands::activity::log(c, "osint", &format!("Investigation created: {}", i.name), &format!("{} {}", i.target_type, i.target_value), Some("osint"), Some(&id.to_string()), i.project_id)?;
        Ok(i)
    })?;
    changed(&app, i.id);
    Ok(i)
}

#[tauri::command]
pub async fn osint_investigation_update(app: AppHandle, db: State<'_, Db>, id: i64, input: InvestigationInput) -> AppResult<Investigation> {
    let i = tx(&db, |c| {
        investigation_update(c, id, &input)?;
        investigation_get(c, id)
    })?;
    changed(&app, id);
    Ok(i)
}

#[tauri::command]
pub async fn osint_investigation_set_status(app: AppHandle, db: State<'_, Db>, id: i64, status: String) -> AppResult<()> {
    tx(&db, |c| investigation_set_status(c, id, &status))?;
    changed(&app, id);
    Ok(())
}

/// Delete an investigation with its entities, evidence, graphs and versions, after a native
/// confirmation. Running collections for it are cancelled first.
#[tauri::command]
pub async fn osint_investigation_delete(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<bool> {
    let i = db.with(|c| investigation_get(c, id))?;
    let msg = format!(
        "Delete the investigation \"{}\" with its {}, {}, {} and {}, including all versions? This cannot be undone. Export the graphs first if you may need them.",
        i.name,
        count(i.counts.entities, "entity", "entities"),
        count(i.counts.relationships, "relationship", "relationships"),
        count(i.counts.evidence, "evidence record", "evidence records"),
        count(i.counts.graphs, "saved graph", "saved graphs")
    );
    if !crate::confirm::native(&app, "Delete investigation", msg, "Delete").await {
        return Ok(false);
    }
    let running: Vec<i64> = db.with(|c| {
        let mut st = c.prepare("SELECT id FROM osint_operations WHERE investigation_id = ?1 AND status = 'running'")?;
        let v = st.query_map(params![id], |r| r.get(0))?.collect::<Result<Vec<i64>, _>>()?;
        Ok(v)
    })?;
    for op in running {
        discovery::cancel(&app, op);
    }
    db.with(|c| {
        c.execute("DELETE FROM osint_investigations WHERE id = ?1", params![id])?;
        crate::commands::activity::log(c, "osint", &format!("Investigation deleted: {}", i.name), "", Some("osint"), Some(&id.to_string()), None)?;
        Ok(())
    })?;
    changed(&app, id);
    Ok(true)
}

#[tauri::command]
pub async fn osint_compare(db: State<'_, Db>, a: i64, b: i64) -> AppResult<Vec<SharedEntity>> {
    db.with(|c| compare_investigations(c, a, b))
}

/* ───────────────────────── entities & relationships ───────────────────────── */

#[tauri::command]
pub async fn osint_entities(db: State<'_, Db>, investigation_id: i64, query: EntityQuery) -> AppResult<Page<EntityRow>> {
    db.with(|c| entity_list(c, investigation_id, &query))
}

#[tauri::command]
pub async fn osint_entity(db: State<'_, Db>, id: i64) -> AppResult<EntityDetail> {
    db.with(|c| entity_detail(c, id))
}

#[tauri::command]
pub async fn osint_relationship(db: State<'_, Db>, id: i64) -> AppResult<RelationshipDetail> {
    db.with(|c| relationship_detail(c, id))
}

fn inv_of(c: &Connection, kind: &str, id: i64) -> AppResult<i64> {
    match kind {
        "entity" => entity_investigation(c, id),
        "relationship" => relationship_investigation(c, id),
        _ => Err(validation("Unknown kind")),
    }
}

#[tauri::command]
pub async fn osint_set_verification(app: AppHandle, db: State<'_, Db>, kind: String, id: i64, verification: String, note: Option<String>) -> AppResult<()> {
    let v = Verification::parse(&verification).ok_or_else(|| validation("Unknown verification state"))?;
    let inv = tx(&db, |c| {
        let inv = inv_of(c, &kind, id)?;
        set_verification(c, &kind, id, v, note.as_deref())?;
        Ok(inv)
    })?;
    changed(&app, inv);
    Ok(())
}

#[tauri::command]
pub async fn osint_entity_update(app: AppHandle, db: State<'_, Db>, id: i64, display_name: Option<String>, notes: Option<String>) -> AppResult<()> {
    let inv = tx(&db, |c| {
        entity_update(c, id, display_name.as_deref(), notes.as_deref())?;
        entity_investigation(c, id)
    })?;
    changed(&app, inv);
    Ok(())
}

#[tauri::command]
pub async fn osint_entity_delete(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<()> {
    let inv = tx(&db, |c| {
        let inv = entity_investigation(c, id)?;
        entity_delete(c, id)?;
        Ok(inv)
    })?;
    changed(&app, inv);
    Ok(())
}

#[tauri::command]
pub async fn osint_relationship_delete(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<()> {
    let inv = tx(&db, |c| {
        let inv = relationship_investigation(c, id)?;
        relationship_delete(c, id)?;
        Ok(inv)
    })?;
    changed(&app, inv);
    Ok(())
}

#[tauri::command]
pub async fn osint_entity_merge(app: AppHandle, db: State<'_, Db>, keep: i64, merge: i64) -> AppResult<()> {
    let inv = tx(&db, |c| {
        entity_merge(c, keep, merge)?;
        entity_investigation(c, keep)
    })?;
    changed(&app, inv);
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManualEntityInput {
    investigation_id: i64,
    #[serde(rename = "type")]
    entity_type: String,
    value: String,
    #[serde(default)]
    note: String,
    /// link the new entity to an existing one
    #[serde(default)]
    link_to: Option<i64>,
    #[serde(default)]
    link_type: Option<String>,
    /// true: new entity → existing; false: existing → new entity
    #[serde(default)]
    link_outgoing: bool,
}

#[tauri::command]
pub async fn osint_entity_add(app: AppHandle, db: State<'_, Db>, input: ManualEntityInput) -> AppResult<ChangeSummary> {
    let t = EntityType::parse(&input.entity_type).ok_or_else(|| validation("Unknown entity type"))?;
    let link = match (input.link_to, input.link_type.as_deref()) {
        (Some(id), Some(rt)) => Some((id, rt, input.link_outgoing)),
        (None, None) => None,
        _ => return Err(validation("Choose both the entity to link and the relationship type")),
    };
    let s = tx(&db, |c| manual_entity(c, input.investigation_id, t, &input.value, &input.note, link))?;
    changed(&app, input.investigation_id);
    Ok(s)
}

#[tauri::command]
pub async fn osint_link(app: AppHandle, db: State<'_, Db>, source: i64, target: i64, rel_type: String, note: String) -> AppResult<i64> {
    let (id, inv) = tx(&db, |c| {
        let id = link_entities(c, source, target, &rel_type, Origin::Manual, &note, "analyst")?;
        Ok((id, entity_investigation(c, source)?))
    })?;
    changed(&app, inv);
    Ok(id)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighborhood {
    entities: Vec<EntityBrief>,
    relationships: Vec<RelationshipBrief>,
}

/// Entities linked to the given ones (graph expansion), bounded.
#[tauri::command]
pub async fn osint_neighbors(db: State<'_, Db>, investigation_id: i64, ids: Vec<i64>, include_rejected: bool, limit: Option<usize>) -> AppResult<Neighborhood> {
    if ids.len() > 500 {
        return Err(validation("Expand at most 500 entities at once"));
    }
    let (entities, relationships) = db.with(|c| neighbors(c, investigation_id, &ids, include_rejected, limit.unwrap_or(300).clamp(1, 2000)))?;
    Ok(Neighborhood { entities, relationships })
}

/// Look up entities by id (e.g. to add search results to a graph).
#[tauri::command]
pub async fn osint_entities_by_ids(db: State<'_, Db>, investigation_id: i64, ids: Vec<i64>) -> AppResult<Neighborhood> {
    if ids.len() > 5000 {
        return Err(validation("Too many entities"));
    }
    db.with(|c| {
        let entities: Vec<EntityBrief> = entities_by_ids(c, &ids)?.into_iter().collect();
        for e in &entities {
            if entity_investigation(c, e.id)? != investigation_id {
                return Err(validation("Entity belongs to another investigation"));
            }
        }
        let set: HashSet<i64> = entities.iter().map(|e| e.id).collect();
        let relationships = relationships_among(c, investigation_id, &set)?;
        Ok(Neighborhood { entities, relationships })
    })
}

#[tauri::command]
pub async fn osint_duplicates(db: State<'_, Db>, investigation_id: i64) -> AppResult<Vec<Vec<EntityBrief>>> {
    db.with(|c| {
        let groups = ingest::possible_duplicates(c, investigation_id)?;
        groups.into_iter().take(100).map(|g| entities_by_ids(c, &g)).collect()
    })
}

/// Create a finding in the linked project from an entity (its value becomes the affected target,
/// its evidence the finding's evidence references).
#[tauri::command]
pub async fn osint_finding_from_entity(app: AppHandle, db: State<'_, Db>, entity_id: i64, title: String, severity: String, description: String) -> AppResult<i64> {
    let (project_id, value, evidence) = db.with(|c| {
        let inv = entity_investigation(c, entity_id)?;
        let i = investigation_get(c, inv)?;
        let pid = i.project_id.ok_or_else(|| validation("Link the investigation to a project first"))?;
        let d = entity_detail(c, entity_id)?;
        let ev: Vec<crate::commands::projects::Evidence> = d
            .evidence
            .iter()
            .take(20)
            .map(|e| crate::commands::projects::Evidence { label: format!("OSINT {} ({})", e.source, e.collected_at.get(..10).unwrap_or("")), reference: e.reference.clone().unwrap_or_else(|| e.summary.chars().take(300).collect()) })
            .collect();
        Ok((pid, d.brief.value.clone(), ev))
    })?;
    let id = crate::commands::projects::finding_upsert(
        db.clone(),
        crate::commands::projects::FindingInput { id: None, project_id, title, severity, status: "open".into(), description, affected_target: value.chars().take(500).collect(), cve: String::new(), evidence },
    )
    .await?;
    let inv = db.with(|c| {
        let inv = entity_investigation(c, entity_id)?;
        ingest::event(c, inv, "annotation", &format!("Finding #{id} created in the linked project"), Some("analyst"), Some(entity_id), None, None, None, json!({ "findingId": id }))?;
        Ok(inv)
    })?;
    changed(&app, inv);
    Ok(id)
}

/* ───────────────────────── graphs ───────────────────────── */

#[tauri::command]
pub async fn osint_graphs(db: State<'_, Db>, investigation_id: Option<i64>) -> AppResult<Vec<GraphMeta>> {
    db.with(|c| graph_list(c, investigation_id))
}

#[tauri::command]
pub async fn osint_graph_create(app: AppHandle, db: State<'_, Db>, investigation_id: i64, name: String, description: String, follow_new: bool) -> AppResult<i64> {
    let id = tx(&db, |c| graph_create(c, investigation_id, &name, &description, follow_new))?;
    changed(&app, investigation_id);
    Ok(id)
}

#[tauri::command]
pub async fn osint_graph_load(db: State<'_, Db>, id: i64, touch: Option<bool>) -> AppResult<GraphData> {
    // refreshes of an open graph pass touch=false, so they do not write to the database
    db.with(|c| graph_load(c, id, touch.unwrap_or(true)))
}

#[tauri::command]
pub async fn osint_graph_save(app: AppHandle, db: State<'_, Db>, id: i64, save: GraphSave) -> AppResult<SaveResult> {
    let (r, inv) = tx(&db, |c| Ok((graph_save(c, id, &save)?, graph_meta(c, id)?.investigation_id)))?;
    changed(&app, inv);
    Ok(r)
}

#[tauri::command]
pub async fn osint_graph_save_as(app: AppHandle, db: State<'_, Db>, from: i64, name: String, nodes: Vec<GraphNodeState>, workspace: Value, follow_new: bool) -> AppResult<i64> {
    let (id, inv) = tx(&db, |c| Ok((graph_save_as(c, from, &name, &nodes, &workspace, follow_new)?, graph_meta(c, from)?.investigation_id)))?;
    changed(&app, inv);
    Ok(id)
}

#[tauri::command]
pub async fn osint_graph_duplicate(app: AppHandle, db: State<'_, Db>, from: i64, name: String) -> AppResult<i64> {
    let (id, inv) = tx(&db, |c| Ok((graph_duplicate(c, from, &name)?, graph_meta(c, from)?.investigation_id)))?;
    changed(&app, inv);
    Ok(id)
}

#[tauri::command]
pub async fn osint_graph_rename(app: AppHandle, db: State<'_, Db>, id: i64, name: String, description: Option<String>, follow_new: Option<bool>) -> AppResult<()> {
    let inv = tx(&db, |c| {
        graph_rename(c, id, &name, description.as_deref(), follow_new)?;
        Ok(graph_meta(c, id)?.investigation_id)
    })?;
    changed(&app, inv);
    Ok(())
}

/// Delete a saved graph and its versions after a native confirmation. The investigation's
/// entities and evidence are kept.
#[tauri::command]
pub async fn osint_graph_delete(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<bool> {
    let m = db.with(|c| graph_meta(c, id))?;
    let msg = format!("Delete the graph \"{}\" and its {}? The investigation's entities, relationships and evidence are kept.", m.name, count(m.version_count, "saved version", "saved versions"));
    if !crate::confirm::native(&app, "Delete graph", msg, "Delete").await {
        return Ok(false);
    }
    tx(&db, |c| graph_delete(c, id))?;
    changed(&app, m.investigation_id);
    Ok(true)
}

#[tauri::command]
pub async fn osint_versions(db: State<'_, Db>, graph_id: i64) -> AppResult<Vec<VersionRow>> {
    db.with(|c| versions(c, graph_id))
}

#[tauri::command]
pub async fn osint_version_create(app: AppHandle, db: State<'_, Db>, graph_id: i64, label: String) -> AppResult<Option<i64>> {
    let (v, inv) = tx(&db, |c| Ok((record_version(c, graph_id, "manual", &label, true)?, graph_meta(c, graph_id)?.investigation_id)))?;
    changed(&app, inv);
    Ok(v)
}

#[tauri::command]
pub async fn osint_version_compare(db: State<'_, Db>, a: i64, b: Option<i64>) -> AppResult<Diff> {
    db.with(|c| version_compare(c, a, b))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    version: i64,
    missing: usize,
}

#[tauri::command]
pub async fn osint_version_restore(app: AppHandle, db: State<'_, Db>, version_id: i64) -> AppResult<RestoreResult> {
    let (version, missing, inv) = tx(&db, |c| {
        let (v, missing) = version_restore(c, version_id)?;
        let g: i64 = c.query_row("SELECT graph_id FROM osint_graph_versions WHERE id = ?1", params![version_id], |r| r.get(0))?;
        Ok((v, missing, graph_meta(c, g)?.investigation_id))
    })?;
    changed(&app, inv);
    Ok(RestoreResult { version, missing })
}

/* ───────────────────────── timeline & analysis ───────────────────────── */

#[tauri::command]
pub async fn osint_timeline(db: State<'_, Db>, investigation_id: i64, query: TimelineQuery) -> AppResult<Page<TimelineEvent>> {
    db.with(|c| timeline(c, investigation_id, &query))
}

/// Analysis over the whole investigation, or over the members of one graph.
fn scoped(c: &Connection, inv: i64, graph: Option<i64>) -> AppResult<(Vec<EntityBrief>, Vec<RelationshipBrief>)> {
    let (ents, rels) = investigation_graph(c, inv, 20_000)?;
    match graph {
        None => Ok((ents, rels)),
        Some(g) => {
            if graph_meta(c, g)?.investigation_id != inv {
                return Err(validation("The graph belongs to another investigation"));
            }
            let mut st = c.prepare("SELECT entity_id FROM osint_graph_nodes WHERE graph_id = ?1")?;
            let members: HashSet<i64> = st.query_map(params![g], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok((ents.into_iter().filter(|e| members.contains(&e.id)).collect(), rels))
        }
    }
}

#[tauri::command]
pub async fn osint_analysis(db: State<'_, Db>, investigation_id: i64, graph_id: Option<i64>, include_inferred: bool) -> AppResult<analysis::Overview> {
    db.with(|c| {
        let (ents, rels) = scoped(c, investigation_id, graph_id)?;
        Ok(analysis::overview(&Graph::new(&ents, &rels, include_inferred)))
    })
}

#[tauri::command]
pub async fn osint_path(db: State<'_, Db>, investigation_id: i64, graph_id: Option<i64>, from: i64, to: i64, include_inferred: bool, max_depth: Option<usize>) -> AppResult<Option<analysis::Path>> {
    db.with(|c| {
        let (ents, rels) = scoped(c, investigation_id, graph_id)?;
        Ok(analysis::shortest_path(&Graph::new(&ents, &rels, include_inferred), from, to, max_depth.unwrap_or(8).clamp(1, 12)))
    })
}

#[tauri::command]
pub async fn osint_suggestions(db: State<'_, Db>, investigation_id: i64) -> AppResult<Vec<Suggestion>> {
    db.with(|c| report::suggestions(c, investigation_id))
}

/* ───────────────────────── discovery ───────────────────────── */

#[tauri::command]
pub async fn osint_discover(app: AppHandle, request: DiscoverRequest) -> AppResult<i64> {
    let inv = request.investigation_id;
    let id = discovery::start(&app, request, "analyst")?;
    changed(&app, inv);
    Ok(id)
}

#[tauri::command]
pub async fn osint_operations(db: State<'_, Db>, investigation_id: i64) -> AppResult<Vec<Operation>> {
    discovery::operations(&db, investigation_id, 200)
}

#[tauri::command]
pub async fn osint_operation(db: State<'_, Db>, id: i64) -> AppResult<OperationDetail> {
    discovery::operation_get(&db, id)
}

#[tauri::command]
pub async fn osint_operation_cancel(app: AppHandle, id: i64) -> AppResult<bool> {
    Ok(discovery::cancel(&app, id))
}

#[tauri::command]
pub async fn osint_operation_import(app: AppHandle, db: State<'_, Db>, id: i64, selection: Option<Selection>) -> AppResult<ChangeSummary> {
    let s = discovery::import(&db, id, selection.as_ref())?;
    let inv = db.with(|c| Ok(c.query_row("SELECT investigation_id FROM osint_operations WHERE id = ?1", params![id], |r| r.get::<_, i64>(0))?))?;
    changed(&app, inv);
    Ok(s)
}

#[tauri::command]
pub async fn osint_import_sources(db: State<'_, Db>, project_id: Option<i64>) -> AppResult<Vec<ImportSource>> {
    providers::internal::list_sources(&db, project_id)
}

#[tauri::command]
pub async fn osint_import_internal(app: AppHandle, db: State<'_, Db>, investigation_id: i64, kind: String, id: String) -> AppResult<ChangeSummary> {
    let s = discovery::import_internal(&db, investigation_id, &kind, &id)?;
    changed(&app, investigation_id);
    Ok(s)
}

/* ───────────────────────── export ───────────────────────── */

/// Export a graph through a native save dialog: json (native, re-importable), graphml,
/// csv-entities, csv-relationships. Returns the file name or None when cancelled.
#[tauri::command]
pub async fn osint_export(app: AppHandle, db: State<'_, Db>, graph_id: i64, format: String) -> AppResult<Option<String>> {
    let doc = db.with(|c| io::export_document(c, graph_id))?;
    let base = safe_name(&format!("{}-{}", doc.investigation.name, doc.graph.name));
    let (content, ext, filter, suffix) = match format.as_str() {
        "json" => (serde_json::to_string_pretty(&doc)?, "json", "Cyber Hub graph", ""),
        "graphml" => (io::export_graphml(&doc), "graphml", "GraphML", ""),
        "csv-entities" => (io::export_csv_entities(&doc), "csv", "CSV", "-entities"),
        "csv-relationships" => (io::export_csv_relationships(&doc), "csv", "CSV", "-relationships"),
        _ => return Err(validation("Unknown export format")),
    };
    let Some(path) = save_dialog(&app, "Export graph", &format!("{base}{suffix}.{ext}"), filter, ext).await else { return Ok(None) };
    let name = write_file(&path, content.as_bytes())?;
    let inv = db.with(|c| {
        let m = graph_meta(c, graph_id)?;
        ingest::event(c, m.investigation_id, "export", &format!("Graph \"{}\" exported as {format} ({} entities, {} relationships)", m.name, doc.entities.len(), doc.relationships.len()), Some("analyst"), None, None, None, Some(graph_id), json!({ "format": format }))?;
        Ok(m.investigation_id)
    })?;
    changed(&app, inv);
    Ok(Some(name))
}

fn b64_decode(s: &str) -> AppResult<Vec<u8>> {
    let s = s.split_once("base64,").map(|(_, d)| d).unwrap_or(s);
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c).ok_or_else(|| validation("Invalid image data"))? << (18 - 6 * i as u32);
        }
        let n = chunk.len();
        if n == 1 {
            return Err(validation("Invalid image data"));
        }
        out.push((acc >> 16) as u8);
        if n > 2 {
            out.push((acc >> 8) as u8);
        }
        if n > 3 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

/// Save a rendered image of the graph (PNG as base64, or SVG text) through a native dialog.
#[tauri::command]
pub async fn osint_export_image(app: AppHandle, db: State<'_, Db>, graph_id: i64, format: String, data: String) -> AppResult<Option<String>> {
    if data.len() > 80 * 1024 * 1024 {
        return Err(validation("The image is too large to export"));
    }
    let bytes = match format.as_str() {
        "png" => {
            let b = b64_decode(&data)?;
            if !b.starts_with(&[0x89, b'P', b'N', b'G']) {
                return Err(validation("Invalid PNG data"));
            }
            b
        }
        "svg" => {
            if !data.trim_start().starts_with("<svg") && !data.trim_start().starts_with("<?xml") {
                return Err(validation("Invalid SVG data"));
            }
            data.into_bytes()
        }
        _ => return Err(validation("Unknown image format")),
    };
    let m = db.with(|c| graph_meta(c, graph_id))?;
    let Some(path) = save_dialog(&app, "Export graph image", &format!("{}.{format}", safe_name(&format!("{}-{}", m.investigation_name, m.name))), &format.to_uppercase(), &format).await else { return Ok(None) };
    let name = write_file(&path, &bytes)?;
    db.with(|c| Ok(ingest::event(c, m.investigation_id, "export", &format!("Graph \"{}\" exported as {}", m.name, format.to_uppercase()), Some("analyst"), None, None, None, Some(graph_id), json!({ "format": format }))?))?;
    changed(&app, m.investigation_id);
    Ok(Some(name))
}

#[tauri::command]
pub async fn osint_report(db: State<'_, Db>, investigation_id: i64) -> AppResult<String> {
    db.with(|c| report::markdown(c, investigation_id, &chrono::Local::now().format("%Y-%m-%d").to_string()))
}

#[tauri::command]
pub async fn osint_report_export(app: AppHandle, db: State<'_, Db>, investigation_id: i64) -> AppResult<Option<String>> {
    let (name, md) = db.with(|c| Ok((investigation_get(c, investigation_id)?.name, report::markdown(c, investigation_id, &chrono::Local::now().format("%Y-%m-%d").to_string())?)))?;
    let Some(path) = save_dialog(&app, "Export investigation report", &format!("{}-osint-report.md", safe_name(&name)), "Markdown", "md").await else { return Ok(None) };
    let file = write_file(&path, md.as_bytes())?;
    db.with(|c| Ok(ingest::event(c, investigation_id, "export", "Investigation report exported (Markdown)", Some("analyst"), None, None, None, None, json!({ "format": "md" }))?))?;
    changed(&app, investigation_id);
    Ok(Some(file))
}

/* ───────────────────────── import ───────────────────────── */

/// Parsed files waiting for confirmation (token → document). Bounded; nothing is written until
/// the analyst confirms.
#[derive(Default)]
pub struct ImportState(Mutex<HashMap<String, (Document, String, String)>>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingImport {
    token: String,
    file_name: String,
    preview: ImportPreview,
}

fn token() -> String {
    let mut b = [0u8; 12];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Choose a graph file (native dialog), validate it and return a preview. Nothing is imported.
#[tauri::command]
pub async fn osint_import_pick(app: AppHandle, db: State<'_, Db>, imports: State<'_, ImportState>, investigation_id: Option<i64>) -> AppResult<Option<PendingImport>> {
    let (tx_, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Import graph").add_filter("Graph files", &["json", "graphml", "xml"]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.pick_file(move |f| {
        let _ = tx_.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let meta = std::fs::metadata(&path)?;
    if meta.len() as usize > io::MAX_IMPORT_BYTES {
        return Err(validation(format!("The file is larger than {} MB", io::MAX_IMPORT_BYTES / 1024 / 1024)));
    }
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let format = match ext.as_str() {
        "json" => "json",
        "graphml" | "xml" => "graphml",
        _ => return Err(validation("Choose a .json (Cyber Hub graph) or .graphml file")),
    };
    let bytes = std::fs::read(&path)?;
    let doc = io::parse(&bytes, format).map_err(AppError::Validation)?;
    let preview = db.with(|c| io::preview(c, &doc, format, investigation_id))?;
    let file_name: String = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default().chars().take(120).collect();
    let token = token();
    let mut m = imports.0.lock().map_err(|_| AppError::Internal("import state poisoned".into()))?;
    if m.len() >= 4 {
        m.clear();
    }
    m.insert(token.clone(), (doc, file_name.clone(), format.to_string()));
    Ok(Some(PendingImport { token, file_name, preview }))
}

/// Preview a pending import against an investigation (how many entities already exist there).
#[tauri::command]
pub async fn osint_import_preview(db: State<'_, Db>, imports: State<'_, ImportState>, token: String, investigation_id: Option<i64>) -> AppResult<ImportPreview> {
    let (doc, format) = {
        let m = imports.0.lock().map_err(|_| AppError::Internal("import state poisoned".into()))?;
        let (d, _, f) = m.get(&token).ok_or_else(|| validation("The import expired; choose the file again"))?;
        (d.clone(), f.clone())
    };
    db.with(|c| io::preview(c, &doc, &format, investigation_id))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    investigation_id: i64,
    graph_id: i64,
}

/// Apply a pending import: into an existing investigation (entities resolve against it) or a
/// new one. Always creates a new graph; nothing existing is overwritten.
#[tauri::command]
pub async fn osint_import_apply(app: AppHandle, db: State<'_, Db>, imports: State<'_, ImportState>, token: String, investigation_id: Option<i64>, graph_name: String) -> AppResult<ImportResult> {
    let (doc, file) = {
        let mut m = imports.0.lock().map_err(|_| AppError::Internal("import state poisoned".into()))?;
        let (d, f, _) = m.remove(&token).ok_or_else(|| validation("The import expired; choose the file again"))?;
        (d, f)
    };
    let (inv, graph) = tx(&db, |c| io::apply(c, &doc, investigation_id, &graph_name, &file))?;
    db.with(|c| crate::commands::activity::log(c, "osint", &format!("Graph imported from {file}"), "", Some("osint"), Some(&inv.to_string()), None))?;
    changed(&app, inv);
    Ok(ImportResult { investigation_id: inv, graph_id: graph })
}

#[tauri::command]
pub async fn osint_import_discard(imports: State<'_, ImportState>, token: String) -> AppResult<()> {
    if let Ok(mut m) = imports.0.lock() {
        m.remove(&token);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_png_data_urls() {
        assert_eq!(b64_decode("data:image/png;base64,iVBORw==").unwrap(), vec![0x89, b'P', b'N', b'G']);
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("aGk").unwrap(), b"hi");
        assert!(b64_decode("a$==").is_err());
    }

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(safe_name("Acme / ../x"), "Acme___.._x");
        assert_eq!(safe_name("///"), "osint");
    }
}
