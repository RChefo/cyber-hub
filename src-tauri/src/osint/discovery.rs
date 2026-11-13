// SPDX-License-Identifier: Apache-2.0
//! Discovery operations: run a provider in the background, keep its proposed observations for
//! review, import them (all or a selection) into the investigation, cancel running operations.
//!
//! Guards applied before anything is sent: the provider must support the entity type; private,
//! loopback, reserved addresses and internal names are never sent to external sources; the one
//! provider that contacts the target directly requires a linked, active project whose authorized
//! scope covers the target; per-provider rate limits apply.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;

use super::ingest::{self, ChangeSummary, Observation};
use super::model::EntityType;
use super::providers::{self, Error, Limits, Output};
use super::{normalize, store};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const EVENT_CHANGED: &str = "osint-changed";
/// Proposed results kept per operation (larger results are cut, and the operation says so).
const MAX_RESULTS_BYTES: usize = 6 * 1024 * 1024;
const MAX_CONCURRENT: usize = 6;

#[derive(Default)]
pub struct OsintState {
    running: Mutex<HashMap<i64, oneshot::Sender<()>>>,
    pub limits: Limits,
}

impl OsintState {
    pub fn running_count(&self) -> usize {
        self.running.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Refuse values that must not leave the computer (or reach a third party).
pub fn check_public(t: EntityType, value: &str) -> Result<(), String> {
    use crate::ti::indicator::{is_internal_domain, is_non_public};
    match t {
        EntityType::Ip => {
            let ip: std::net::IpAddr = value.parse().map_err(|_| "invalid address".to_string())?;
            if is_non_public(&ip) {
                return Err("Private, loopback, link-local and reserved addresses are not sent to external sources".into());
            }
        }
        EntityType::Domain => {
            if is_internal_domain(value) {
                return Err("Internal and reserved names are not sent to external sources".into());
            }
        }
        EntityType::Url => {
            let u = url::Url::parse(value).map_err(|_| "invalid URL".to_string())?;
            match u.host() {
                Some(url::Host::Domain(d)) if is_internal_domain(d) => return Err("URLs on internal names are not sent to external sources".into()),
                Some(url::Host::Ipv4(a)) if is_non_public(&std::net::IpAddr::V4(a)) => return Err("URLs on private addresses are not sent to external sources".into()),
                Some(url::Host::Ipv6(a)) if is_non_public(&std::net::IpAddr::V6(a)) => return Err("URLs on private addresses are not sent to external sources".into()),
                _ => {}
            }
        }
        EntityType::Email => {
            if let Some((_, d)) = value.rsplit_once('@') {
                if is_internal_domain(d) {
                    return Err("Addresses on internal domains are not sent to external sources".into());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// For providers that contact the target: the investigation's project must be active and its
/// authorized scope must cover the target (same engine as tool runs, exclusions included).
fn check_scope(db: &Db, inv: &store::Investigation, t: EntityType, value: &str) -> AppResult<()> {
    let project = inv.project_id.ok_or_else(|| AppError::Scope("This source contacts the target directly. Link the investigation to an active project whose scope covers the target.".into()))?;
    let (status, entries) = db.with(|c| {
        let status: String = c.query_row("SELECT status FROM projects WHERE id = ?1", params![project], |r| r.get(0))?;
        Ok((status, crate::commands::projects::scope_entries(c, project)?))
    })?;
    if status != "active" {
        return Err(AppError::Scope(format!("The linked project is '{status}'; set it to active to contact targets")));
    }
    // the value is requested exactly as stored: quotes or spaces around it would be checked away
    if value.trim() != value || value.contains(['"', '\'']) {
        return Err(AppError::Scope("The value has quotes or spaces around it; edit the entity before contacting it".into()));
    }
    // a URL is checked as the URL it is (path-level entries can authorize it); a domain is
    // contacted over HTTPS and HTTP at `/`, so the host itself must be authorized
    let target = match t {
        EntityType::Url => crate::scope::parse_target(value).filter(|x| matches!(x, crate::scope::Target::Url(_))),
        _ => crate::scope::parse_target(value).map(|x| x.host_level().clone()),
    }
    .ok_or_else(|| AppError::Scope(format!("{} is not a valid target", value.chars().take(200).collect::<String>())))?;
    crate::scope::check_target(&entries, &target).map_err(AppError::Scope)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoverRequest {
    pub investigation_id: i64,
    pub provider: String,
    /// an existing entity of the investigation…
    #[serde(default)]
    pub entity_id: Option<i64>,
    /// …or a value (it becomes an entity when results are imported)
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub auto_import: bool,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub id: i64,
    pub investigation_id: i64,
    pub provider: String,
    pub provider_name: String,
    pub input_type: String,
    pub input_value: String,
    pub input_entity_id: Option<i64>,
    pub status: String,
    pub requested_by: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub result_count: i64,
    pub message: Option<String>,
    pub imported_at: Option<String>,
    pub imported_count: i64,
}

const OP_COLS: &str = "id, investigation_id, provider, input_type, input_value, input_entity_id, status, requested_by, started_at, finished_at, result_count, message, imported_at, imported_count";

fn op_row(r: &rusqlite::Row) -> rusqlite::Result<Operation> {
    let provider: String = r.get(2)?;
    Ok(Operation {
        id: r.get(0)?,
        investigation_id: r.get(1)?,
        provider_name: providers::info(&provider).map(|p| p.name.to_string()).unwrap_or_else(|| provider.replace("import:", "Import: ")),
        provider,
        input_type: r.get(3)?,
        input_value: r.get(4)?,
        input_entity_id: r.get(5)?,
        status: r.get(6)?,
        requested_by: r.get(7)?,
        started_at: r.get(8)?,
        finished_at: r.get(9)?,
        result_count: r.get(10)?,
        message: r.get(11)?,
        imported_at: r.get(12)?,
        imported_count: r.get(13)?,
    })
}

pub fn operations(db: &Db, inv: i64, limit: i64) -> AppResult<Vec<Operation>> {
    db.with(|c| {
        let mut st = c.prepare(&format!("SELECT {OP_COLS} FROM osint_operations WHERE investigation_id = ?1 ORDER BY id DESC LIMIT ?2"))?;
        let v = st.query_map(params![inv, limit.clamp(1, 500)], op_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(v)
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationDetail {
    #[serde(flatten)]
    pub operation: Operation,
    pub results: Vec<Observation>,
    pub truncated: bool,
    pub rate_note: Option<String>,
}

pub fn operation_get(db: &Db, id: i64) -> AppResult<OperationDetail> {
    db.with(|c| {
        let (op, results): (Operation, Option<String>) = c
            .query_row(&format!("SELECT {OP_COLS}, results FROM osint_operations WHERE id = ?1"), params![id], |r| Ok((op_row(r)?, r.get(14)?)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("operation {id}")))?;
        let v: Value = results.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(json!({}));
        Ok(OperationDetail {
            operation: op,
            results: serde_json::from_value(v["observations"].clone()).unwrap_or_default(),
            truncated: v["truncated"].as_bool().unwrap_or(false),
            rate_note: v["rateNote"].as_str().map(String::from),
        })
    })
}

fn resolve_input(db: &Db, req: &DiscoverRequest) -> AppResult<(EntityType, String, Option<i64>)> {
    match req.entity_id {
        Some(id) => db.with(|c| {
            let (inv, t, v): (i64, String, String) = c
                .query_row("SELECT investigation_id, type, value FROM osint_entities WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("entity {id}")))?;
            if inv != req.investigation_id {
                return Err(validation("The entity belongs to another investigation"));
            }
            Ok((EntityType::parse(&t).unwrap_or(EntityType::Other), v, Some(id)))
        }),
        None => {
            let t = req.entity_type.as_deref().and_then(EntityType::parse).ok_or_else(|| validation("Choose an entity or a value with its type"))?;
            let n = normalize::normalize(t, req.value.as_deref().unwrap_or("")).map_err(validation)?;
            Ok((t, n.value, None))
        }
    }
}

async fn run_provider(app: &AppHandle, provider: &str, t: EntityType, value: &str, refresh: bool) -> Result<Output, Error> {
    let db = app.state::<Db>();
    match provider {
        "dns" => {
            let key = format!("{}:{value}", t.as_str());
            if !refresh {
                if let Some(answers) = providers::cache_get(&db, "dns", &key, 1).and_then(|v| serde_json::from_value::<providers::dns::Answers>(v).ok()) {
                    let mut out = providers::dns::domain_observation(value, t, &answers);
                    out.from_cache = true;
                    return Ok(out);
                }
            }
            let answers = if t == EntityType::Ip {
                let ip: std::net::IpAddr = value.parse().map_err(|_| Error::Invalid("invalid address".into()))?;
                providers::dns::query_ptr(&ip).await?
            } else {
                providers::dns::query_domain(value).await?
            };
            providers::cache_put(&db, "dns", &key, &json!(answers));
            Ok(providers::dns::domain_observation(value, t, &answers))
        }
        "asn" => {
            let ip: std::net::IpAddr = value.parse().map_err(|_| Error::Invalid("invalid address".into()))?;
            if !refresh {
                if let Some(v) = providers::cache_get(&db, "asn", value, 24) {
                    if let Ok(o) = serde_json::from_value::<providers::dns::Origin>(v) {
                        let mut out = providers::dns::asn_observation(value, &o);
                        out.from_cache = true;
                        return Ok(out);
                    }
                }
            }
            match providers::dns::query_asn(&ip).await? {
                Some(o) => {
                    providers::cache_put(&db, "asn", value, &serde_json::to_value(&o).unwrap_or_default());
                    Ok(providers::dns::asn_observation(value, &o))
                }
                None => Ok(Output { summary: format!("No origin AS is announced for {value}"), ..Default::default() }),
            }
        }
        "rdap" => providers::rdap::run(&db, t, value, refresh).await,
        "crtsh" => providers::crtsh::run(&db, value, refresh).await,
        "github" => providers::github::run(&db, t, value, refresh).await,
        "http" => providers::web::run(t, value).await,
        "threat_intel" => {
            let ind = providers::ti::indicator_for(t, value)?;
            let vt = app.state::<crate::commands::virustotal::VtState>();
            let tist = app.state::<crate::commands::threat_intel::TiState>();
            let results = crate::commands::threat_intel::investigate(&db, &vt, &tist, &ind, None, refresh).await.map_err(|e| Error::Unavailable(e.to_string()))?;
            Ok(providers::ti::map_results(providers::ti::entity_type_of(ind.kind), &ind.value, &results))
        }
        "nvd" => {
            let id = value.to_uppercase();
            if !id.starts_with("CVE-") {
                return Err(Error::Unsupported("NVD covers CVE identifiers".into()));
            }
            let cached = crate::commands::intel::cve_get_cached(db.clone(), id.clone()).await.map_err(|e| Error::Unavailable(e.to_string()))?;
            let (rec, source) = match cached {
                Some((rec, _)) if !refresh => (rec, "cache"),
                _ => {
                    crate::commands::intel::cve_search(db.clone(), id.clone(), true).await.map_err(|e| Error::Network(e.to_string()))?;
                    let rec = crate::commands::intel::cve_get_cached(db.clone(), id.clone()).await.map_err(|e| Error::Unavailable(e.to_string()))?.ok_or_else(|| Error::Invalid(format!("NVD has no record for {id}")))?.0;
                    (rec, "live")
                }
            };
            Ok(Output { observations: vec![providers::ti::map_cve(&rec, source)], summary: format!("NVD record {id} ({source})"), rate_note: None, from_cache: source == "cache" })
        }
        _ => Err(Error::Unsupported("Unknown source".into())),
    }
}

/// Validate and start a discovery operation; returns its id at once.
/// A request that passed every check (source, entity type, public value, scope).
pub struct Validated {
    pub info: &'static providers::ProviderInfo,
    pub entity_type: EntityType,
    pub value: String,
    pub entity_id: Option<i64>,
    pub investigation: store::Investigation,
}

/// All checks that happen before anything is sent; used by `start` and by the MCP approval
/// prompt (so invalid requests never reach the user).
pub fn validate(db: &Db, req: &DiscoverRequest) -> AppResult<Validated> {
    let inv = db.with(|c| store::investigation_get(c, req.investigation_id))?;
    if inv.status == "archived" {
        return Err(validation("Restore the investigation before collecting new data"));
    }
    let info = providers::info(&req.provider).ok_or_else(|| validation("Unknown source"))?;
    let (t, value, entity_id) = resolve_input(db, req)?;
    if !info.inputs.contains(&t) {
        return Err(validation(format!("{} does not support {} entities", info.name, t.label().to_lowercase())));
    }
    check_public(t, &value).map_err(AppError::Scope)?;
    if info.contacts_target {
        check_scope(db, &inv, t, &value)?;
    }
    Ok(Validated { info, entity_type: t, value, entity_id, investigation: inv })
}

pub fn start(app: &AppHandle, req: DiscoverRequest, requested_by: &str) -> AppResult<i64> {
    let db = app.state::<Db>();
    let Validated { info, entity_type: t, value, entity_id, .. } = validate(&db, &req)?;
    let state = app.state::<Arc<OsintState>>();
    if state.running_count() >= MAX_CONCURRENT {
        return Err(validation("Several collections are already running; wait for one to finish"));
    }
    state.limits.acquire(info.id).map_err(|e| AppError::Validation(e.message()))?;
    let op = db.with(|c| {
        c.execute(
            "INSERT INTO osint_operations (investigation_id, provider, input_type, input_value, input_entity_id, status, requested_by, started_at) VALUES (?1,?2,?3,?4,?5,'running',?6,?7)",
            params![req.investigation_id, info.id, t.as_str(), value, entity_id, requested_by, now()],
        )?;
        let id = c.last_insert_rowid();
        ingest::event(c, req.investigation_id, "discovery", &format!("{} started for {value}", info.name), Some(info.id), entity_id, None, Some(id), None, json!({ "requestedBy": requested_by }))?;
        Ok(id)
    })?;
    let (tx, rx) = oneshot::channel();
    if let Ok(mut m) = state.running.lock() {
        m.insert(op, tx);
    }
    let app2 = app.clone();
    let provider = info.id;
    let inv_id = req.investigation_id;
    tauri::async_runtime::spawn(async move {
        let result = tokio::select! {
            r = run_provider(&app2, provider, t, &value, req.refresh) => Some(r),
            _ = rx => None,
        };
        finish(&app2, inv_id, op, result, req.auto_import);
    });
    Ok(op)
}

fn finish(app: &AppHandle, inv: i64, op: i64, result: Option<Result<Output, Error>>, auto_import: bool) {
    let state = app.state::<Arc<OsintState>>();
    if let Ok(mut m) = state.running.lock() {
        m.remove(&op);
    }
    let db = app.state::<Db>();
    let _ = db.with(|c| {
        match &result {
            None => {
                c.execute("UPDATE osint_operations SET status = 'cancelled', finished_at = ?2, message = 'Cancelled by the analyst' WHERE id = ?1", params![op, now()])?;
                ingest::event(c, inv, "discovery", "Collection cancelled", None, None, None, Some(op), None, json!({}))?;
            }
            Some(Err(e)) => {
                c.execute("UPDATE osint_operations SET status = 'failed', finished_at = ?2, message = ?3 WHERE id = ?1", params![op, now(), e.message()])?;
                ingest::event(c, inv, "discovery", &format!("Collection failed: {}", e.message()), None, None, None, Some(op), None, json!({}))?;
            }
            Some(Ok(out)) => {
                let mut kept = out.observations.clone();
                let mut truncated = false;
                while serde_json::to_string(&kept).map(|s| s.len()).unwrap_or(0) > MAX_RESULTS_BYTES && !kept.is_empty() {
                    kept.pop();
                    truncated = true;
                }
                let count: usize = kept.iter().map(|o| o.entities.len()).sum();
                let msg = format!("{}{}{}", out.summary, if out.from_cache { " (from cache)" } else { "" }, if truncated { " — results were cut to stay within limits" } else { "" });
                let doc = json!({ "observations": kept, "truncated": truncated, "rateNote": out.rate_note });
                c.execute(
                    "UPDATE osint_operations SET status = 'completed', finished_at = ?2, message = ?3, results = ?4, result_count = ?5 WHERE id = ?1",
                    params![op, now(), msg, doc.to_string(), count as i64],
                )?;
                ingest::event(c, inv, "discovery", &format!("Collection completed: {msg}"), None, None, None, Some(op), None, json!({}))?;
            }
        }
        Ok(())
    });
    if auto_import && matches!(result, Some(Ok(_))) {
        let _ = import(&db, op, None);
    }
    let _ = app.emit(EVENT_CHANGED, json!({ "investigationId": inv, "operationId": op }));
}

pub fn cancel(app: &AppHandle, op: i64) -> bool {
    let state = app.state::<Arc<OsintState>>();
    let tx = state.running.lock().ok().and_then(|mut m| m.remove(&op));
    tx.map(|t| t.send(()).is_ok()).unwrap_or(false)
}

/// Mark operations left running by a previous session (the app exited) as failed.
pub fn recover_interrupted(db: &Db) {
    let _ = db.with(|c| {
        c.execute("UPDATE osint_operations SET status = 'failed', finished_at = ?1, message = 'Interrupted: ExploitX closed while the collection was running' WHERE status = 'running'", params![now()])?;
        Ok(())
    });
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    /// (observation index, entity index)
    pub entities: Vec<(usize, usize)>,
    /// (observation index, relationship index)
    pub relationships: Vec<(usize, usize)>,
}

/// Keep only the selected entities and the selected relationships between them.
pub fn select(results: &[Observation], sel: &Selection) -> Vec<Observation> {
    let mut out = vec![];
    for (oi, o) in results.iter().enumerate() {
        let mut map: HashMap<usize, usize> = HashMap::new();
        let mut entities = vec![];
        for (ei, e) in o.entities.iter().enumerate() {
            if sel.entities.contains(&(oi, ei)) {
                map.insert(ei, entities.len());
                entities.push(e.clone());
            }
        }
        if entities.is_empty() {
            continue;
        }
        let relationships = o
            .relationships
            .iter()
            .enumerate()
            .filter(|(ri, _)| sel.relationships.contains(&(oi, *ri)))
            .filter_map(|(_, r)| Some(ingest::RelationshipInput { source: *map.get(&r.source)?, target: *map.get(&r.target)?, ..r.clone() }))
            .collect();
        out.push(Observation { evidence: o.evidence.clone(), entities, relationships });
    }
    out
}

/// Import an operation's results (all, or a selection) through the mapping pipeline.
pub fn import(db: &Db, op: i64, selection: Option<&Selection>) -> AppResult<ChangeSummary> {
    let detail = operation_get(db, op)?;
    if detail.operation.status != "completed" {
        return Err(validation("Only completed collections can be imported"));
    }
    let chosen = match selection {
        Some(s) => select(&detail.results, s),
        None => detail.results.clone(),
    };
    if chosen.is_empty() {
        return Err(validation("Nothing selected to import"));
    }
    let inv = detail.operation.investigation_id;
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        let mut total = ChangeSummary::default();
        for mut o in chosen {
            o.evidence.operation_id = Some(op);
            let s = ingest::ingest(&tx, inv, &o)?;
            total.new_entities.extend(s.new_entities);
            total.updated_entities.extend(s.updated_entities);
            total.new_relationships.extend(s.new_relationships);
            total.updated_relationships.extend(s.updated_relationships);
            total.inferred_relationships.extend(s.inferred_relationships);
            total.rejected.extend(s.rejected);
        }
        for v in [&mut total.new_entities, &mut total.updated_entities, &mut total.new_relationships, &mut total.updated_relationships, &mut total.inferred_relationships] {
            v.sort();
            v.dedup();
        }
        // entities this operation added to the investigation; an entity is new only once, so
        // importing a selection and later the rest never counts anything twice
        tx.execute(
            "UPDATE osint_operations SET imported_at = ?2, imported_count = imported_count + ?3 WHERE id = ?1",
            params![op, now(), total.new_entities.len() as i64],
        )?;
        ingest::event(&tx, inv, "import", &format!("Imported results of {}: {}", detail.operation.provider_name, total.line()), Some(&detail.operation.provider), None, None, Some(op), None, json!({}))?;
        tx.commit()?;
        Ok(total)
    })
}

/// Import an internal source directly (the analyst chose the item explicitly).
pub fn import_internal(db: &Db, inv: i64, kind: &str, id: &str) -> AppResult<ChangeSummary> {
    let investigation = db.with(|c| store::investigation_get(c, inv))?;
    let out = providers::internal::import(db, kind, id, investigation.project_id).map_err(|e| AppError::Validation(e.message()))?;
    if out.observations.is_empty() {
        return Err(validation(format!("Nothing to import: {}", out.summary)));
    }
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        let at = now();
        let count: usize = out.observations.iter().map(|o| o.entities.len()).sum();
        tx.execute(
            "INSERT INTO osint_operations (investigation_id, provider, input_type, input_value, status, requested_by, started_at, finished_at, result_count, message, results, imported_at)
             VALUES (?1,?2,'source',?3,'completed','user',?4,?4,?5,?6,?7,?4)",
            params![inv, format!("import:{kind}"), id, at, count as i64, out.summary, json!({ "observations": out.observations }).to_string()],
        )?;
        let op = tx.last_insert_rowid();
        let mut total = ChangeSummary::default();
        for mut o in out.observations.clone() {
            o.evidence.operation_id = Some(op);
            let s = ingest::ingest(&tx, inv, &o)?;
            total.new_entities.extend(s.new_entities);
            total.updated_entities.extend(s.updated_entities);
            total.new_relationships.extend(s.new_relationships);
            total.updated_relationships.extend(s.updated_relationships);
            total.inferred_relationships.extend(s.inferred_relationships);
            total.rejected.extend(s.rejected);
        }
        tx.execute("UPDATE osint_operations SET imported_count = ?2 WHERE id = ?1", params![op, (total.new_entities.len() + total.updated_entities.len()) as i64])?;
        ingest::event(&tx, inv, "import", &format!("Imported {}: {}", out.summary, total.line()), Some(kind), None, None, Some(op), None, json!({}))?;
        tx.commit()?;
        Ok(total)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::ingest::tests::{ent, ev, rel};

    #[test]
    fn private_values_never_leave_and_selection_keeps_consistent_relationships() {
        for (t, v) in [(EntityType::Ip, "10.1.2.3"), (EntityType::Ip, "::1"), (EntityType::Domain, "server.local"), (EntityType::Url, "http://192.168.0.1/x"), (EntityType::Email, "a@corp.internal")] {
            assert!(check_public(t, v).is_err(), "{v}");
        }
        assert!(check_public(EntityType::Domain, "example.com").is_ok());
        let o = Observation { evidence: ev("dns", "x"), entities: vec![ent(EntityType::Domain, "a.example"), ent(EntityType::Ip, "192.0.2.1"), ent(EntityType::Ip, "192.0.2.2")], relationships: vec![rel(0, 1, "RESOLVES_TO"), rel(0, 2, "RESOLVES_TO")] };
        // entity 2 not selected: its relationship is dropped even if selected
        let s = select(&[o], &Selection { entities: vec![(0, 0), (0, 1)], relationships: vec![(0, 0), (0, 1)] });
        assert_eq!(s[0].entities.len(), 2);
        assert_eq!(s[0].relationships.len(), 1);
        assert_eq!((s[0].relationships[0].source, s[0].relationships[0].target), (0, 1));
    }

    #[test]
    fn imports_operations_and_internal_sources_with_provenance() {
        let db = Db::open_in_memory().unwrap();
        let inv = crate::osint::ingest::tests::inv(&db);
        let obs = Observation { evidence: ev("dns", "A for a.example"), entities: vec![ent(EntityType::Domain, "a.example"), ent(EntityType::Ip, "192.0.2.1")], relationships: vec![rel(0, 1, "RESOLVES_TO")] };
        let op = db
            .with(|c| {
                c.execute(
                    "INSERT INTO osint_operations (investigation_id, provider, input_type, input_value, status, started_at, results) VALUES (?1, 'dns', 'domain', 'a.example', 'completed', 'x', ?2)",
                    params![inv, json!({ "observations": [obs] }).to_string()],
                )?;
                Ok(c.last_insert_rowid())
            })
            .unwrap();
        let s = import(&db, op, None).unwrap();
        assert_eq!((s.new_entities.len(), s.new_relationships.len()), (2, 1));
        let linked: i64 = db.with(|c| Ok(c.query_row("SELECT operation_id FROM osint_evidence WHERE source = 'dns'", [], |r| r.get(0))?)).unwrap();
        assert_eq!(linked, op, "evidence keeps the discovery operation");
        assert!(import(&db, op, Some(&Selection::default())).is_err(), "empty selection");

        // a stored Nmap run imported as a source
        let run = db
            .with(|c| {
                c.execute(
                    "INSERT INTO executions (tool_id, kind, program, args, status, output, started_at) VALUES ('nmap','run','nmap','[\"-sT\"]','succeeded',?1,'2026-01-01T00:00:00Z')",
                    params!["Nmap scan report for a.example (192.0.2.1)\n80/tcp open http nginx 1.24.0\n"],
                )?;
                Ok(c.last_insert_rowid())
            })
            .unwrap();
        let s = import_internal(&db, inv, "run", &run.to_string()).unwrap();
        assert!(s.new_entities.len() >= 2, "{s:?}");
        let exec: i64 = db.with(|c| Ok(c.query_row("SELECT execution_id FROM osint_evidence WHERE kind = 'tool_run'", [], |r| r.get(0))?)).unwrap();
        assert_eq!(exec, run, "evidence keeps the tool run");
        assert!(import_internal(&db, inv, "finding", "1").is_err(), "findings need a linked project");
    }

    #[test]
    fn contacted_values_are_checked_exactly_as_they_are_requested() {
        let db = Db::open_in_memory().unwrap();
        let inv_id = crate::osint::ingest::tests::inv(&db);
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (5, 'P', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (5, 'https://app.example.com/api/', 'url', 1, 't')", [])?;
            c.execute("UPDATE osint_investigations SET project_id = 5 WHERE id = ?1", params![inv_id])?;
            Ok(())
        })
        .unwrap();
        let inv = db.with(|c| store::investigation_get(c, inv_id)).unwrap();
        assert!(check_scope(&db, &inv, EntityType::Url, "https://app.example.com/api/x").is_ok());
        for v in ["\"https://app.example.com/api/x\"", " https://app.example.com/api/x", "https://app.example.com/api/x'", "https://app.example.com/admin"] {
            assert!(check_scope(&db, &inv, EntityType::Url, v).is_err(), "{v}");
        }
        let err = check_scope(&db, &inv, EntityType::Domain, "app.example.com").unwrap_err().to_string();
        assert!(err.contains("specific URLs"), "a domain is contacted as a host: {err}");
    }
}
