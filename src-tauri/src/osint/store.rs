// SPDX-License-Identifier: Apache-2.0
//! Persistence for investigations, entities, relationships, evidence, graphs, versions and the
//! timeline. Intelligence data is relational and investigation-scoped; a saved graph stores its
//! own membership (which entities it shows, where, pinned/hidden/grouped) and a workspace
//! document (viewport, layout, filters, annotations). Changing a graph's layout or membership
//! never changes the intelligence; analyst decisions on entities and relationships do, for every
//! graph of the investigation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::ingest::{self, fingerprint, EntityInput, EvidenceInput, Observation, Origin, RelationshipInput};
use super::model::{self, EntityType, Strength, Verification};
use super::normalize;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const MAX_WORKSPACE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_GRAPH_NODES: usize = 20_000;
/// Large graphs get a warning in the workspace (rendering stays responsive well beyond this).
pub const LARGE_GRAPH_NODES: usize = 3_000;
const MAX_VERSIONS_KEPT: i64 = 60;

fn j<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/* ───────────────────────── investigations ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub target_type: String,
    pub target_value: String,
    pub status: String,
    pub tags: Vec<String>,
    pub notes: String,
    pub authorization: String,
    pub project_id: Option<i64>,
    pub project_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_opened_at: Option<String>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub entities: i64,
    pub relationships: i64,
    pub evidence: i64,
    pub graphs: i64,
    pub operations: i64,
    pub pending_review: i64,
    pub flagged: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvestigationInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub target_type: String,
    pub target_value: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub authorization: String,
    #[serde(default)]
    pub project_id: Option<i64>,
}

fn clean_text(label: &str, s: &str, max: usize, required: bool) -> AppResult<String> {
    let t = s.trim();
    if required && t.is_empty() {
        return Err(validation(format!("{label} is required")));
    }
    if t.chars().count() > max {
        return Err(validation(format!("{label} is longer than {max} characters")));
    }
    if t.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(validation(format!("{label} contains control characters")));
    }
    Ok(t.to_string())
}

fn clean_tags(tags: &[String]) -> AppResult<Vec<String>> {
    if tags.len() > 30 {
        return Err(validation("At most 30 tags"));
    }
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = clean_text("Tag", t, 40, false)?;
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

const INV_COLS: &str = "i.id, i.name, i.description, i.target_type, i.target_value, i.status, i.tags, i.notes, i.authorization, i.project_id, p.name, i.created_at, i.updated_at, i.last_opened_at";

fn inv_row(r: &rusqlite::Row) -> rusqlite::Result<Investigation> {
    Ok(Investigation {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        target_type: r.get(3)?,
        target_value: r.get(4)?,
        status: r.get(5)?,
        tags: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
        notes: r.get(7)?,
        authorization: r.get(8)?,
        project_id: r.get(9)?,
        project_name: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
        last_opened_at: r.get(13)?,
        counts: Counts::default(),
    })
}

pub fn counts(c: &Connection, id: i64) -> rusqlite::Result<Counts> {
    let one = |sql: &str| c.query_row(sql, params![id], |r| r.get::<_, i64>(0));
    Ok(Counts {
        entities: one("SELECT COUNT(*) FROM osint_entities WHERE investigation_id = ?1")?,
        relationships: one("SELECT COUNT(*) FROM osint_relationships WHERE investigation_id = ?1 AND verification != 'rejected'")?,
        evidence: one("SELECT COUNT(*) FROM osint_evidence WHERE investigation_id = ?1")?,
        graphs: one("SELECT COUNT(*) FROM osint_graphs WHERE investigation_id = ?1")?,
        operations: one("SELECT COUNT(*) FROM osint_operations WHERE investigation_id = ?1")?,
        pending_review: one("SELECT COUNT(*) FROM osint_relationships WHERE investigation_id = ?1 AND verification = 'inferred'")?,
        flagged: one("SELECT COUNT(*) FROM osint_entities WHERE investigation_id = ?1 AND flagged = 1")?,
    })
}

pub fn investigation_list(c: &Connection, include_archived: bool) -> rusqlite::Result<Vec<Investigation>> {
    let sql = format!(
        "SELECT {INV_COLS} FROM osint_investigations i LEFT JOIN projects p ON p.id = i.project_id {} ORDER BY COALESCE(i.last_opened_at, i.updated_at) DESC",
        if include_archived { "" } else { "WHERE i.status != 'archived'" }
    );
    let mut st = c.prepare(&sql)?;
    let mut v = st.query_map([], inv_row)?.collect::<Result<Vec<_>, _>>()?;
    for i in &mut v {
        i.counts = counts(c, i.id)?;
    }
    Ok(v)
}

pub fn investigation_get(c: &Connection, id: i64) -> AppResult<Investigation> {
    let mut inv = c
        .query_row(&format!("SELECT {INV_COLS} FROM osint_investigations i LEFT JOIN projects p ON p.id = i.project_id WHERE i.id = ?1"), params![id], inv_row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("investigation {id}")))?;
    inv.counts = counts(c, id)?;
    Ok(inv)
}

/// name, description, normalized target value, tags, notes, authorization, target type, raw target value
type ValidInput = (String, String, String, Vec<String>, String, String, EntityType, String);

fn validate_input(c: &Connection, input: &InvestigationInput) -> AppResult<ValidInput> {
    let name = clean_text("Name", &input.name, 120, true)?;
    let description = clean_text("Description", &input.description, 4000, false)?;
    let t = EntityType::parse(&input.target_type).filter(|t| t.is_target_type()).ok_or_else(|| validation("Unsupported target type"))?;
    let n = normalize::normalize(t, &input.target_value).map_err(|e| validation(format!("Primary target: {e}")))?;
    let tags = clean_tags(&input.tags)?;
    let notes = clean_text("Notes", &input.notes, 20_000, false)?;
    let authorization = clean_text("Scope and authorization", &input.authorization, 4000, false)?;
    if let Some(p) = input.project_id {
        let exists: bool = c.query_row("SELECT COUNT(*) FROM projects WHERE id = ?1", params![p], |r| r.get::<_, i64>(0))? > 0;
        if !exists {
            return Err(AppError::NotFound(format!("project {p}")));
        }
    }
    Ok((name, description, n.value, tags, notes, authorization, t, input.target_value.clone()))
}

/// Create an investigation, its main graph (which follows new data) and the target entity.
/// Record the primary target as an entity (with analyst evidence) of the investigation.
fn ingest_target(c: &Connection, id: i64, t: EntityType, raw: String) -> AppResult<()> {
    ingest::ingest(
        c,
        id,
        &Observation {
            evidence: EvidenceInput {
                kind: "manual".into(),
                source: "analyst".into(),
                reference: None,
                observed_at: None,
                summary: format!("Primary target of the investigation: {raw}"),
                data: json!({}),
                strength: Strength::Direct,
                operation_id: None,
                execution_id: None,
            },
            entities: vec![EntityInput { entity_type: t, value: raw, display_name: None, metadata: Map::from_iter([("primaryTarget".to_string(), json!(true))]), flagged: false }],
            relationships: vec![],
        },
    )?;
    Ok(())
}

pub fn investigation_create(c: &Connection, input: &InvestigationInput) -> AppResult<i64> {
    let (name, description, target, tags, notes, authorization, t, raw) = validate_input(c, input)?;
    let at = now();
    c.execute(
        "INSERT INTO osint_investigations (name, description, target_type, target_value, tags, notes, authorization, project_id, created_at, updated_at, last_opened_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?9)",
        params![name, description, t.as_str(), target, j(&tags), notes, authorization, input.project_id, at],
    )?;
    let id = c.last_insert_rowid();
    ingest_target(c, id, t, raw)?;
    // the main graph starts with the target and follows the investigation
    graph_create(c, id, "Main graph", "Follows the investigation: new entities are added automatically.", true)?;
    ingest::event(c, id, "investigation", &format!("Investigation created: {name}"), Some("analyst"), None, None, None, None, json!({}))?;
    Ok(id)
}

/// What a project holds that refers to an investigation: finding links to its entities, evidence
/// records of its evidence and assets observed from its entities.
pub fn project_references(c: &Connection, investigation_id: i64, project_id: i64) -> AppResult<(i64, i64, i64)> {
    let links: i64 = c.query_row(
        "SELECT COUNT(*) FROM finding_links l JOIN findings f ON f.id = l.finding_id
          WHERE l.kind = 'osint_entity' AND f.project_id = ?2 AND l.ref_id IN (SELECT id FROM osint_entities WHERE investigation_id = ?1)",
        params![investigation_id, project_id],
        |r| r.get(0),
    )?;
    let evidence: i64 = c.query_row(
        "SELECT COUNT(*) FROM evidence WHERE project_id = ?2 AND osint_evidence_id IN (SELECT id FROM osint_evidence WHERE investigation_id = ?1)",
        params![investigation_id, project_id],
        |r| r.get(0),
    )?;
    let assets: i64 = c.query_row(
        "SELECT COUNT(*) FROM assets WHERE project_id = ?2 AND osint_entity_id IN (SELECT id FROM osint_entities WHERE investigation_id = ?1)",
        params![investigation_id, project_id],
        |r| r.get(0),
    )?;
    Ok((links, evidence, assets))
}

pub fn investigation_update(c: &Connection, id: i64, input: &InvestigationInput) -> AppResult<()> {
    let before = investigation_get(c, id)?;
    let (name, description, target, tags, notes, authorization, t, raw) = validate_input(c, input)?;
    if let (Some(old), true) = (before.project_id, before.project_id != input.project_id) {
        // the old project's findings, evidence and assets would point into another engagement
        let (links, evidence, assets) = project_references(c, id, old)?;
        if links + evidence + assets > 0 {
            let mut parts = Vec::new();
            for (n, one, many) in [(links, "finding link", "finding links"), (evidence, "evidence record", "evidence records"), (assets, "asset", "assets")] {
                if n > 0 {
                    parts.push(format!("{n} {}", if n == 1 { one } else { many }));
                }
            }
            return Err(validation(format!(
                "The linked project refers to this investigation ({}). Remove those references in the project before linking the investigation elsewhere",
                parts.join(", ")
            )));
        }
    }
    if before.target_type != t.as_str() || before.target_value != target {
        // the previous target stays an entity with its evidence; it is no longer the primary one
        c.execute(
            "UPDATE osint_entities SET metadata = json_remove(metadata, '$.primaryTarget') WHERE investigation_id = ?1 AND json_extract(metadata, '$.primaryTarget') = 1",
            params![id],
        )?;
        ingest_target(c, id, t, raw)?;
        ingest::event(c, id, "investigation", &format!("Primary target changed from {} {} to {} {}", before.target_type, before.target_value, t.as_str(), target), Some("analyst"), None, None, None, None, json!({}))?;
    }
    c.execute(
        "UPDATE osint_investigations SET name=?2, description=?3, target_type=?4, target_value=?5, tags=?6, notes=?7, authorization=?8, project_id=?9, updated_at=?10 WHERE id=?1",
        params![id, name, description, t.as_str(), target, j(&tags), notes, authorization, input.project_id, now()],
    )?;
    if before.project_id != input.project_id {
        let name_of = |p: Option<i64>| -> AppResult<String> {
            Ok(match p {
                Some(p) => c.query_row("SELECT name FROM projects WHERE id = ?1", params![p], |r| r.get(0)).optional()?.unwrap_or_else(|| format!("#{p}")),
                None => "no project".into(),
            })
        };
        let what = format!("Linked project changed from {} to {}", name_of(before.project_id)?, name_of(input.project_id)?);
        ingest::event(c, id, "investigation", &what, Some("analyst"), None, None, None, None, json!({ "from": before.project_id, "to": input.project_id }))?;
        if let Some(old) = before.project_id {
            crate::workspace::timeline::record(c, old, "investigation", &format!("Investigation {} unlinked", before.name), &what, None, None)?;
        }
    }
    ingest::event(c, id, "investigation", "Investigation details updated", Some("analyst"), None, None, None, None, json!({}))?;
    Ok(())
}

/// Deletes an investigation with everything it holds. Finding links to its entities go with it,
/// and the linked project's timeline says that its events are gone.
pub fn investigation_delete(c: &Connection, i: &Investigation) -> AppResult<()> {
    crate::workspace::assets::with_savepoint(c, || {
        c.execute("DELETE FROM finding_links WHERE kind = 'osint_entity' AND ref_id IN (SELECT id FROM osint_entities WHERE investigation_id = ?1)", params![i.id])?;
        c.execute("DELETE FROM osint_investigations WHERE id = ?1", params![i.id])?;
        if let Some(p) = i.project_id {
            crate::workspace::timeline::record(c, p, "investigation", &format!("Investigation deleted: {}", i.name), "Its events are no longer part of this timeline", None, None)?;
        }
        crate::commands::activity::log(c, "osint", &format!("Investigation deleted: {}", i.name), "", Some("osint"), Some(&i.id.to_string()), i.project_id)
    })
}

pub fn investigation_set_status(c: &Connection, id: i64, status: &str) -> AppResult<()> {
    if !matches!(status, "active" | "archived" | "closed") {
        return Err(validation("Unknown status"));
    }
    investigation_get(c, id)?;
    c.execute("UPDATE osint_investigations SET status = ?2, updated_at = ?3 WHERE id = ?1", params![id, status, now()])?;
    ingest::event(c, id, "investigation", &format!("Status changed to {status}"), Some("analyst"), None, None, None, None, json!({}))?;
    Ok(())
}

pub fn investigation_touch(c: &Connection, id: i64) -> rusqlite::Result<()> {
    c.execute("UPDATE osint_investigations SET last_opened_at = ?2 WHERE id = ?1", params![id, now()])?;
    Ok(())
}

/* ───────────────────────── entities ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityBrief {
    pub id: i64,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: String,
    pub display_name: String,
    pub verification: String,
    pub confidence: String,
    pub flagged: bool,
}

const BRIEF_COLS: &str = "e.id, e.type, e.value, e.display_name, e.verification, e.confidence, e.flagged";

fn brief_row(r: &rusqlite::Row) -> rusqlite::Result<EntityBrief> {
    Ok(EntityBrief { id: r.get(0)?, entity_type: r.get(1)?, value: r.get(2)?, display_name: r.get(3)?, verification: r.get(4)?, confidence: r.get(5)?, flagged: r.get::<_, i64>(6)? != 0 })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityRow {
    #[serde(flatten)]
    pub brief: EntityBrief,
    pub first_seen: String,
    pub last_seen: String,
    pub relationships: i64,
    pub evidence: i64,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct EntityQuery {
    pub q: Option<String>,
    #[serde(rename = "type")]
    pub entity_type: Option<String>,
    pub verification: Option<String>,
    pub flagged: Option<bool>,
    pub offset: i64,
    pub limit: i64,
    /// "recent" (default), "value", "connections"
    pub sort: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub total: i64,
    pub offset: i64,
    pub items: Vec<T>,
}

pub fn entity_list(c: &Connection, inv: i64, q: &EntityQuery) -> AppResult<Page<EntityRow>> {
    let mut where_ = vec!["e.investigation_id = ?".to_string()];
    let mut args: Vec<SqlValue> = vec![SqlValue::Integer(inv)];
    if let Some(t) = q.entity_type.as_deref().filter(|t| !t.is_empty()) {
        EntityType::parse(t).ok_or_else(|| validation("Unknown entity type"))?;
        where_.push("e.type = ?".into());
        args.push(SqlValue::Text(t.into()));
    }
    if let Some(v) = q.verification.as_deref().filter(|v| !v.is_empty()) {
        Verification::parse(v).ok_or_else(|| validation("Unknown verification state"))?;
        where_.push("e.verification = ?".into());
        args.push(SqlValue::Text(v.into()));
    }
    if q.flagged == Some(true) {
        where_.push("e.flagged = 1".into());
    }
    if let Some(s) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let s = clean_text("Search", s, 200, false)?.to_lowercase().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        where_.push("(lower(e.value) LIKE ? ESCAPE '\\' OR lower(e.display_name) LIKE ? ESCAPE '\\' OR lower(e.aliases) LIKE ? ESCAPE '\\')".into());
        let pat = format!("%{s}%");
        args.extend([SqlValue::Text(pat.clone()), SqlValue::Text(pat.clone()), SqlValue::Text(pat)]);
    }
    let w = where_.join(" AND ");
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM osint_entities e WHERE {w}"), params_from_iter(args.iter()), |r| r.get(0))?;
    let order = match q.sort.as_deref() {
        Some("value") => "e.type, e.value",
        Some("connections") => "rels DESC, e.last_seen DESC",
        _ => "e.last_seen DESC, e.id DESC",
    };
    let limit = q.limit.clamp(1, 500);
    let offset = q.offset.max(0);
    let sql = format!(
        "SELECT {BRIEF_COLS}, e.first_seen, e.last_seen,
           (SELECT COUNT(*) FROM osint_relationships r WHERE (r.source_id = e.id OR r.target_id = e.id) AND r.verification != 'rejected') AS rels,
           (SELECT COUNT(*) FROM osint_entity_evidence x WHERE x.entity_id = e.id),
           (SELECT group_concat(DISTINCT ev.source) FROM osint_entity_evidence x JOIN osint_evidence ev ON ev.id = x.evidence_id WHERE x.entity_id = e.id)
         FROM osint_entities e WHERE {w} ORDER BY {order} LIMIT {limit} OFFSET {offset}"
    );
    let mut st = c.prepare(&sql)?;
    let items = st
        .query_map(params_from_iter(args.iter()), |r| {
            Ok(EntityRow {
                brief: brief_row(r)?,
                first_seen: r.get(7)?,
                last_seen: r.get(8)?,
                relationships: r.get(9)?,
                evidence: r.get(10)?,
                sources: r.get::<_, Option<String>>(11)?.map(|s| s.split(',').map(String::from).collect()).unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page { total, offset, items })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub id: i64,
    pub kind: String,
    pub source: String,
    pub reference: Option<String>,
    pub observed_at: String,
    pub collected_at: String,
    pub operation_id: Option<i64>,
    pub execution_id: Option<i64>,
    pub summary: String,
    pub data: Value,
    pub strength: String,
}

const EV_COLS: &str = "ev.id, ev.kind, ev.source, ev.reference, ev.observed_at, ev.collected_at, ev.operation_id, ev.execution_id, ev.summary, ev.data, ev.strength";

fn ev_row(r: &rusqlite::Row) -> rusqlite::Result<Evidence> {
    Ok(Evidence {
        id: r.get(0)?,
        kind: r.get(1)?,
        source: r.get(2)?,
        reference: r.get(3)?,
        observed_at: r.get(4)?,
        collected_at: r.get(5)?,
        operation_id: r.get(6)?,
        execution_id: r.get(7)?,
        summary: r.get(8)?,
        data: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or(Value::Null),
        strength: r.get(10)?,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipBrief {
    pub id: i64,
    pub source: i64,
    pub target: i64,
    #[serde(rename = "type")]
    pub rel_type: String,
    pub directed: bool,
    pub origin: String,
    pub verification: String,
    pub confidence: String,
}

const REL_COLS: &str = "r.id, r.source_id, r.target_id, r.type, r.directed, r.origin, r.verification, r.confidence";

fn rel_row(r: &rusqlite::Row) -> rusqlite::Result<RelationshipBrief> {
    Ok(RelationshipBrief { id: r.get(0)?, source: r.get(1)?, target: r.get(2)?, rel_type: r.get(3)?, directed: r.get::<_, i64>(4)? != 0, origin: r.get(5)?, verification: r.get(6)?, confidence: r.get(7)? })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedEntity {
    pub relationship: RelationshipBrief,
    pub other: EntityBrief,
    /// "out" when this entity is the source
    pub direction: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: i64,
    pub at: String,
    pub kind: String,
    pub summary: String,
    pub source: Option<String>,
    pub entity_id: Option<i64>,
    pub relationship_id: Option<i64>,
    pub operation_id: Option<i64>,
    pub graph_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityDetail {
    #[serde(flatten)]
    pub brief: EntityBrief,
    pub investigation_id: i64,
    pub aliases: Vec<String>,
    pub metadata: Value,
    pub notes: String,
    pub first_seen: String,
    pub last_seen: String,
    pub confidence_reason: String,
    pub related: Vec<RelatedEntity>,
    pub related_total: i64,
    pub evidence: Vec<Evidence>,
    pub events: Vec<TimelineEvent>,
    pub merged_from: Vec<Value>,
}

fn entity_brief(c: &Connection, id: i64) -> AppResult<EntityBrief> {
    c.query_row(&format!("SELECT {BRIEF_COLS} FROM osint_entities e WHERE e.id = ?1"), params![id], brief_row).optional()?.ok_or_else(|| AppError::NotFound(format!("entity {id}")))
}

pub fn entity_investigation(c: &Connection, id: i64) -> AppResult<i64> {
    c.query_row("SELECT investigation_id FROM osint_entities WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("entity {id}")))
}

pub fn entity_detail(c: &Connection, id: i64) -> AppResult<EntityDetail> {
    let brief = entity_brief(c, id)?;
    let (inv, aliases, metadata, notes, first, last): (i64, String, String, String, String, String) = c.query_row(
        "SELECT investigation_id, aliases, metadata, notes, first_seen, last_seen FROM osint_entities WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    let related_total: i64 = c.query_row("SELECT COUNT(*) FROM osint_relationships WHERE source_id = ?1 OR target_id = ?1", params![id], |r| r.get(0))?;
    let related = {
        let mut st = c.prepare(&format!(
            "SELECT {REL_COLS}, {BRIEF_COLS} FROM osint_relationships r JOIN osint_entities e ON e.id = CASE WHEN r.source_id = ?1 THEN r.target_id ELSE r.source_id END
             WHERE r.source_id = ?1 OR r.target_id = ?1 ORDER BY CASE r.verification WHEN 'rejected' THEN 1 ELSE 0 END, r.type, e.value LIMIT 300"
        ))?;
        let v = st
            .query_map(params![id], |r| {
                let rel = rel_row(r)?;
                let other = EntityBrief { id: r.get(8)?, entity_type: r.get(9)?, value: r.get(10)?, display_name: r.get(11)?, verification: r.get(12)?, confidence: r.get(13)?, flagged: r.get::<_, i64>(14)? != 0 };
                let direction = if rel.source == id { "out" } else { "in" }.to_string();
                Ok(RelatedEntity { relationship: rel, other, direction })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        v
    };
    let evidence = {
        let mut st = c.prepare(&format!("SELECT {EV_COLS} FROM osint_entity_evidence x JOIN osint_evidence ev ON ev.id = x.evidence_id WHERE x.entity_id = ?1 ORDER BY ev.collected_at DESC LIMIT 200"))?;
        let v = st.query_map(params![id], ev_row)?.collect::<Result<Vec<_>, _>>()?;
        v
    };
    let events = timeline(c, inv, &TimelineQuery { entity_id: Some(id), limit: 100, ..Default::default() })?.items;
    let merged_from = {
        let mut st = c.prepare("SELECT merged_type, merged_value, merged_at FROM osint_entity_merges WHERE kept_id = ?1 ORDER BY id")?;
        let v = st.query_map(params![id], |r| Ok(json!({ "type": r.get::<_, String>(0)?, "value": r.get::<_, String>(1)?, "at": r.get::<_, String>(2)? })))?.collect::<Result<Vec<_>, _>>()?;
        v
    };
    let ev_pairs: Vec<(String, Strength)> = evidence.iter().map(|e| (e.source.clone(), Strength::parse(&e.strength).unwrap_or(Strength::Weak))).collect();
    let (_, confidence_reason) = super::confidence::assess(Verification::parse(&brief.verification).unwrap_or(Verification::Observed), &ev_pairs);
    Ok(EntityDetail {
        brief,
        investigation_id: inv,
        aliases: serde_json::from_str(&aliases).unwrap_or_default(),
        metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
        notes,
        first_seen: first,
        last_seen: last,
        confidence_reason,
        related,
        related_total,
        evidence,
        events,
        merged_from,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipDetail {
    #[serde(flatten)]
    pub brief: RelationshipBrief,
    pub investigation_id: i64,
    pub label: String,
    pub category: String,
    pub description: String,
    pub source_entity: EntityBrief,
    pub target_entity: EntityBrief,
    pub confidence_reason: String,
    pub metadata: Value,
    pub first_seen: String,
    pub last_seen: String,
    pub evidence: Vec<Evidence>,
    pub events: Vec<TimelineEvent>,
}

pub fn relationship_investigation(c: &Connection, id: i64) -> AppResult<i64> {
    c.query_row("SELECT investigation_id FROM osint_relationships WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("relationship {id}")))
}

pub fn relationship_detail(c: &Connection, id: i64) -> AppResult<RelationshipDetail> {
    let (brief, inv, reason, meta, first, last): (RelationshipBrief, i64, String, String, String, String) = c
        .query_row(&format!("SELECT {REL_COLS}, r.investigation_id, r.confidence_reason, r.metadata, r.first_seen, r.last_seen FROM osint_relationships r WHERE r.id = ?1"), params![id], |r| {
            Ok((rel_row(r)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?))
        })
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("relationship {id}")))?;
    let evidence = {
        let mut st = c.prepare(&format!(
            "SELECT {EV_COLS}, re.strength FROM osint_relationship_evidence re JOIN osint_evidence ev ON ev.id = re.evidence_id WHERE re.relationship_id = ?1 ORDER BY ev.collected_at DESC LIMIT 200"
        ))?;
        let v = st
            .query_map(params![id], |r| {
                let mut e = ev_row(r)?;
                e.strength = r.get(11)?; // strength of this evidence for this relationship
                Ok(e)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        v
    };
    let known = model::relationship_type(&brief.rel_type);
    let events = timeline(c, inv, &TimelineQuery { relationship_id: Some(id), limit: 50, ..Default::default() })?.items;
    Ok(RelationshipDetail {
        label: known.map_or_else(|| brief.rel_type.to_lowercase().replace('_', " "), |k| k.label.to_string()),
        category: known.map_or("custom", |k| k.category).to_string(),
        description: known.map_or("Custom relationship type defined by the analyst.", |k| k.description).to_string(),
        source_entity: entity_brief(c, brief.source)?,
        target_entity: entity_brief(c, brief.target)?,
        brief,
        investigation_id: inv,
        confidence_reason: reason,
        metadata: serde_json::from_str(&meta).unwrap_or(Value::Null),
        first_seen: first,
        last_seen: last,
        evidence,
        events,
    })
}

/// Analyst decision on an entity or relationship.
pub fn set_verification(c: &Connection, kind: &str, id: i64, v: Verification, note: Option<&str>) -> AppResult<()> {
    if !v.is_analyst_decision() && v != Verification::Observed {
        return Err(validation("Choose verified, disputed, rejected or observed"));
    }
    let (inv, table) = match kind {
        "entity" => (entity_investigation(c, id)?, "osint_entities"),
        "relationship" => (relationship_investigation(c, id)?, "osint_relationships"),
        _ => return Err(validation("Unknown element")),
    };
    let before: String = c.query_row(&format!("SELECT verification FROM {table} WHERE id = ?1"), params![id], |r| r.get(0))?;
    c.execute(&format!("UPDATE {table} SET verification = ?2 WHERE id = ?1"), params![id, v.as_str()])?;
    if kind == "entity" {
        ingest::recompute_entity(c, id)?;
    } else {
        ingest::recompute_relationship(c, id)?;
    }
    let note = note.map(|n| clean_text("Note", n, 1000, false)).transpose()?.unwrap_or_default();
    let what = if kind == "entity" { label_entity(c, id)? } else { label_relationship(c, id)? };
    let text = format!("{} {what}: {before} → {}{}", if kind == "entity" { "Entity" } else { "Relationship" }, v.as_str(), if note.is_empty() { String::new() } else { format!(" ({note})") });
    let (e, r) = if kind == "entity" { (Some(id), None) } else { (None, Some(id)) };
    ingest::event(c, inv, "verification", &text, Some("analyst"), e, r, None, None, json!({ "from": before, "to": v.as_str() }))?;
    Ok(())
}

fn label_entity(c: &Connection, id: i64) -> rusqlite::Result<String> {
    c.query_row("SELECT value FROM osint_entities WHERE id = ?1", params![id], |r| r.get(0))
}

fn label_relationship(c: &Connection, id: i64) -> rusqlite::Result<String> {
    c.query_row(
        "SELECT s.value || ' ' || r.type || ' ' || t.value FROM osint_relationships r JOIN osint_entities s ON s.id = r.source_id JOIN osint_entities t ON t.id = r.target_id WHERE r.id = ?1",
        params![id],
        |r| r.get(0),
    )
}

pub fn entity_update(c: &Connection, id: i64, display_name: Option<&str>, notes: Option<&str>) -> AppResult<()> {
    let inv = entity_investigation(c, id)?;
    if let Some(d) = display_name {
        let d = clean_text("Display name", d, 200, true)?;
        c.execute("UPDATE osint_entities SET display_name = ?2 WHERE id = ?1", params![id, d])?;
    }
    if let Some(n) = notes {
        let n = clean_text("Notes", n, 20_000, false)?;
        c.execute("UPDATE osint_entities SET notes = ?2 WHERE id = ?1", params![id, n])?;
        ingest::event(c, inv, "annotation", &format!("Notes updated for {}", label_entity(c, id)?), Some("analyst"), Some(id), None, None, None, json!({}))?;
    }
    Ok(())
}

pub fn relationship_delete(c: &Connection, id: i64) -> AppResult<()> {
    let inv = relationship_investigation(c, id)?;
    let what = label_relationship(c, id)?;
    c.execute("DELETE FROM osint_relationships WHERE id = ?1", params![id])?;
    ingest::event(c, inv, "relationship_removed", &format!("Relationship removed: {what}"), Some("analyst"), None, None, None, None, json!({ "relationship": id }))?;
    Ok(())
}

pub fn entity_delete(c: &Connection, id: i64) -> AppResult<()> {
    let inv = entity_investigation(c, id)?;
    let what = label_entity(c, id)?;
    crate::workspace::findings::forget_ref(c, "osint_entity", id)?;
    c.execute("DELETE FROM osint_entities WHERE id = ?1", params![id])?;
    ingest::event(c, inv, "entity_removed", &format!("Entity removed: {what}"), Some("analyst"), None, None, None, None, json!({ "entity": id }))?;
    Ok(())
}

/// Merge `merge` into `keep` (same investigation and type): relationships, evidence and graph
/// placements move to `keep`, the merged value becomes an alias, and the merge is recorded.
pub fn entity_merge(c: &Connection, keep: i64, merge: i64) -> AppResult<()> {
    if keep == merge {
        return Err(validation("Choose two different entities"));
    }
    let (inv_k, type_k): (i64, String) = c.query_row("SELECT investigation_id, type FROM osint_entities WHERE id = ?1", params![keep], |r| Ok((r.get(0)?, r.get(1)?))).optional()?.ok_or_else(|| AppError::NotFound(format!("entity {keep}")))?;
    let (inv_m, type_m, value_m, aliases_m, notes_m, flagged_m): (i64, String, String, String, String, i64) = c
        .query_row("SELECT investigation_id, type, value, aliases, notes, flagged FROM osint_entities WHERE id = ?1", params![merge], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("entity {merge}")))?;
    if inv_k != inv_m {
        return Err(validation("Entities from different investigations cannot be merged"));
    }
    if type_k != type_m {
        return Err(validation("Only entities of the same type can be merged"));
    }
    // relationships: move each to `keep`, folding into an existing identical relationship
    let rels: Vec<(i64, i64, i64, String)> = {
        let mut st = c.prepare("SELECT id, source_id, target_id, type FROM osint_relationships WHERE source_id = ?1 OR target_id = ?1")?;
        let v = st.query_map(params![merge], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<Vec<_>, _>>()?;
        v
    };
    for (rid, s, t, ty) in rels {
        let (mut ns, mut nt) = (if s == merge { keep } else { s }, if t == merge { keep } else { t });
        if ns == nt {
            c.execute("DELETE FROM osint_relationships WHERE id = ?1", params![rid])?; // a self-loop after merging
            continue;
        }
        if !model::is_directed(&ty) && ns > nt {
            std::mem::swap(&mut ns, &mut nt);
        }
        let existing: Option<i64> = c.query_row("SELECT id FROM osint_relationships WHERE investigation_id = ?1 AND source_id = ?2 AND target_id = ?3 AND type = ?4 AND id != ?5", params![inv_k, ns, nt, ty, rid], |r| r.get(0)).optional()?;
        match existing {
            Some(other) => {
                c.execute("INSERT OR IGNORE INTO osint_relationship_evidence (relationship_id, evidence_id, strength) SELECT ?1, evidence_id, strength FROM osint_relationship_evidence WHERE relationship_id = ?2", params![other, rid])?;
                c.execute("DELETE FROM osint_relationships WHERE id = ?1", params![rid])?;
                ingest::recompute_relationship(c, other)?;
            }
            None => {
                c.execute("UPDATE osint_relationships SET source_id = ?2, target_id = ?3 WHERE id = ?1", params![rid, ns, nt])?;
            }
        }
    }
    c.execute("INSERT OR IGNORE INTO osint_entity_evidence (entity_id, evidence_id) SELECT ?1, evidence_id FROM osint_entity_evidence WHERE entity_id = ?2", params![keep, merge])?;
    c.execute("INSERT OR IGNORE INTO osint_graph_nodes (graph_id, entity_id, x, y, pinned, hidden, group_id) SELECT graph_id, ?1, x, y, pinned, hidden, group_id FROM osint_graph_nodes WHERE entity_id = ?2", params![keep, merge])?;
    let (aliases_k, notes_k): (String, String) = c.query_row("SELECT aliases, notes FROM osint_entities WHERE id = ?1", params![keep], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let mut aliases: Vec<String> = serde_json::from_str(&aliases_k).unwrap_or_default();
    for a in std::iter::once(value_m.clone()).chain(serde_json::from_str::<Vec<String>>(&aliases_m).unwrap_or_default()) {
        if !aliases.contains(&a) {
            aliases.push(a);
        }
    }
    let notes = match (notes_k.is_empty(), notes_m.is_empty()) {
        (_, true) => notes_k,
        (true, false) => notes_m,
        (false, false) => format!("{notes_k}\n\n[merged from {value_m}]\n{notes_m}"),
    };
    c.execute("UPDATE osint_entities SET aliases = ?2, notes = ?3, flagged = MAX(flagged, ?4), last_seen = ?5 WHERE id = ?1", params![keep, j(&aliases), notes, flagged_m, now()])?;
    c.execute(
        "INSERT INTO osint_entity_merges (investigation_id, kept_id, merged_id, merged_type, merged_value, merged_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![inv_k, keep, merge, type_m, value_m, now()],
    )?;
    // what refers to the merged entity refers to the kept one: finding links, assets, events
    c.execute("UPDATE OR IGNORE finding_links SET ref_id = ?1 WHERE kind = 'osint_entity' AND ref_id = ?2", params![keep, merge])?;
    crate::workspace::findings::forget_ref(c, "osint_entity", merge)?;
    crate::workspace::relations::repoint(c, "osint_entity", merge, keep)?;
    c.execute("UPDATE assets SET osint_entity_id = ?1 WHERE osint_entity_id = ?2", params![keep, merge])?;
    c.execute("UPDATE osint_events SET entity_id = ?1 WHERE entity_id = ?2", params![keep, merge])?;
    c.execute("DELETE FROM osint_entities WHERE id = ?1", params![merge])?;
    ingest::recompute_entity(c, keep)?;
    ingest::event(c, inv_k, "entity_merged", &format!("{value_m} merged into {}", label_entity(c, keep)?), Some("analyst"), Some(keep), None, None, None, json!({ "merged": merge }))?;
    Ok(())
}

/// Analyst-entered entity (and optionally a relationship to an existing entity).
pub fn manual_entity(c: &Connection, inv: i64, t: EntityType, value: &str, note: &str, link: Option<(i64, &str, bool)>) -> AppResult<ingest::ChangeSummary> {
    investigation_get(c, inv)?;
    let mut entities = vec![EntityInput { entity_type: t, value: value.into(), display_name: None, metadata: Map::new(), flagged: false }];
    let mut relationships = vec![];
    if let Some((other, rel_type, outgoing)) = link {
        if entity_investigation(c, other)? != inv {
            return Err(validation("The linked entity belongs to another investigation"));
        }
        if !model::is_valid_type(rel_type) {
            return Err(validation("Relationship types are UPPER_SNAKE_CASE, 3-40 characters"));
        }
        let (ot, ov): (String, String) = c.query_row("SELECT type, value FROM osint_entities WHERE id = ?1", params![other], |r| Ok((r.get(0)?, r.get(1)?)))?;
        entities.push(EntityInput { entity_type: EntityType::parse(&ot).unwrap_or(EntityType::Other), value: ov, display_name: None, metadata: Map::new(), flagged: false });
        let (s, t) = if outgoing { (0, 1) } else { (1, 0) };
        relationships.push(RelationshipInput { source: s, target: t, rel_type: rel_type.into(), strength: Strength::Direct, origin: Origin::Manual, metadata: Map::new() });
    }
    let note = clean_text("Note", note, 2000, false)?;
    let s = ingest::ingest(
        c,
        inv,
        &Observation {
            evidence: EvidenceInput {
                kind: "manual".into(),
                source: "analyst".into(),
                reference: None,
                observed_at: None,
                summary: if note.is_empty() { format!("Added by the analyst: {value}") } else { format!("Added by the analyst: {value} — {note}") },
                data: json!({}),
                strength: Strength::Direct,
                operation_id: None,
                execution_id: None,
            },
            entities,
            relationships,
        },
    )?;
    if !s.rejected.is_empty() {
        return Err(validation(s.rejected.join("; ")));
    }
    Ok(s)
}

/// Relationship between two existing entities, by the analyst (verified) or proposed by an
/// assistant (inferred, waits for review).
pub fn link_entities(c: &Connection, source: i64, target: i64, rel_type: &str, origin: Origin, note: &str, proposer: &str) -> AppResult<i64> {
    let inv = entity_investigation(c, source)?;
    if entity_investigation(c, target)? != inv {
        return Err(validation("Both entities must belong to the same investigation"));
    }
    if source == target {
        return Err(validation("Choose two different entities"));
    }
    if !model::is_valid_type(rel_type) {
        return Err(validation("Relationship types are UPPER_SNAKE_CASE, 3-40 characters"));
    }
    let note = clean_text("Reason", note, 2000, false)?;
    let get = |id: i64| c.query_row("SELECT type, value FROM osint_entities WHERE id = ?1", params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
    let ((st, sv), (tt, tv)) = (get(source)?, get(target)?);
    let strength = if origin == Origin::Manual { Strength::Direct } else { Strength::Weak };
    let summary = match origin {
        Origin::Manual => format!("Linked by the analyst: {sv} {rel_type} {tv}{}", if note.is_empty() { String::new() } else { format!(" — {note}") }),
        _ => format!("Suggested by {proposer} for review: {sv} {rel_type} {tv}{}", if note.is_empty() { String::new() } else { format!(" — {note}") }),
    };
    let s = ingest::ingest(
        c,
        inv,
        &Observation {
            evidence: EvidenceInput { kind: if origin == Origin::Manual { "manual" } else { "suggestion" }.into(), source: proposer.into(), reference: None, observed_at: None, summary, data: json!({}), strength, operation_id: None, execution_id: None },
            entities: vec![
                EntityInput { entity_type: EntityType::parse(&st).unwrap_or(EntityType::Other), value: sv, display_name: None, metadata: Map::new(), flagged: false },
                EntityInput { entity_type: EntityType::parse(&tt).unwrap_or(EntityType::Other), value: tv, display_name: None, metadata: Map::new(), flagged: false },
            ],
            relationships: vec![RelationshipInput { source: 0, target: 1, rel_type: rel_type.into(), strength, origin, metadata: Map::new() }],
        },
    )?;
    s.new_relationships.first().or(s.updated_relationships.first()).copied().ok_or_else(|| validation("The relationship could not be created"))
}

/// Entities linked to `ids` (one hop), for expanding a graph.
pub fn neighbors(c: &Connection, inv: i64, ids: &[i64], include_rejected: bool, limit: usize) -> AppResult<(Vec<EntityBrief>, Vec<RelationshipBrief>)> {
    if ids.is_empty() || ids.len() > 500 {
        return Err(validation("Choose 1 to 500 entities to expand"));
    }
    let marks = vec!["?"; ids.len()].join(",");
    let mut args: Vec<SqlValue> = vec![SqlValue::Integer(inv)];
    args.extend(ids.iter().map(|i| SqlValue::Integer(*i)));
    args.extend(ids.iter().map(|i| SqlValue::Integer(*i)));
    let rej = if include_rejected { "" } else { "AND r.verification != 'rejected'" };
    let sql = format!("SELECT {REL_COLS} FROM osint_relationships r WHERE r.investigation_id = ? AND (r.source_id IN ({marks}) OR r.target_id IN ({marks})) {rej} LIMIT {}", limit.min(5000));
    let mut st = c.prepare(&sql)?;
    let rels = st.query_map(params_from_iter(args.iter()), rel_row)?.collect::<Result<Vec<_>, _>>()?;
    let mut want: BTreeSet<i64> = BTreeSet::new();
    for r in &rels {
        want.insert(r.source);
        want.insert(r.target);
    }
    Ok((entities_by_ids(c, &want.into_iter().collect::<Vec<_>>())?, rels))
}

/// Every entity and relationship of an investigation (analysis and reports), bounded.
pub fn investigation_graph(c: &Connection, inv: i64, limit: usize) -> AppResult<(Vec<EntityBrief>, Vec<RelationshipBrief>)> {
    let mut st = c.prepare(&format!("SELECT {BRIEF_COLS} FROM osint_entities e WHERE e.investigation_id = ?1 ORDER BY e.id LIMIT ?2"))?;
    let ents = st.query_map(params![inv, limit as i64], brief_row)?.collect::<Result<Vec<_>, _>>()?;
    let mut st = c.prepare(&format!("SELECT {REL_COLS} FROM osint_relationships r WHERE r.investigation_id = ?1 ORDER BY r.id LIMIT ?2"))?;
    let rels = st.query_map(params![inv, (limit * 4) as i64], rel_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok((ents, rels))
}

/// Evidence records of an investigation, newest first.
pub fn evidence_list(c: &Connection, inv: i64, limit: usize) -> AppResult<Vec<Evidence>> {
    let mut st = c.prepare(&format!("SELECT {EV_COLS} FROM osint_evidence ev WHERE ev.investigation_id = ?1 ORDER BY ev.collected_at DESC, ev.id DESC LIMIT ?2"))?;
    let v = st.query_map(params![inv, limit as i64], ev_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn entities_by_ids(c: &Connection, ids: &[i64]) -> AppResult<Vec<EntityBrief>> {
    let mut out = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut st = c.prepare(&format!("SELECT {BRIEF_COLS} FROM osint_entities e WHERE e.id IN ({marks})"))?;
        out.extend(st.query_map(params_from_iter(chunk.iter()), brief_row)?.collect::<Result<Vec<_>, _>>()?);
    }
    Ok(out)
}

/// Relationships between the given entities.
pub fn relationships_among(c: &Connection, inv: i64, ids: &HashSet<i64>) -> AppResult<Vec<RelationshipBrief>> {
    let mut st = c.prepare(&format!("SELECT {REL_COLS} FROM osint_relationships r WHERE r.investigation_id = ?1"))?;
    let all = st.query_map(params![inv], rel_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(all.into_iter().filter(|r| ids.contains(&r.source) && ids.contains(&r.target)).collect())
}

/* ───────────────────────── graphs ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphMeta {
    pub id: i64,
    pub investigation_id: i64,
    pub investigation_name: String,
    pub primary_target: String,
    pub name: String,
    pub description: String,
    pub follow_new: bool,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
    pub last_opened_at: Option<String>,
    pub entity_count: i64,
    pub relationship_count: i64,
    pub version_count: i64,
    pub latest_version: Option<i64>,
    /// changes only when the saved presentation state is written (save, restore)
    pub state_revision: i64,
}

const GRAPH_COLS: &str = "g.id, g.investigation_id, i.name, i.target_value, g.name, g.description, g.follow_new, g.revision, g.created_at, g.updated_at, g.last_opened_at,
    (SELECT COUNT(*) FROM osint_graph_nodes n WHERE n.graph_id = g.id),
    (SELECT COUNT(*) FROM osint_relationships r
        JOIN osint_graph_nodes a ON a.graph_id = g.id AND a.entity_id = r.source_id
        JOIN osint_graph_nodes b ON b.graph_id = g.id AND b.entity_id = r.target_id
        WHERE r.investigation_id = g.investigation_id AND r.verification != 'rejected'),
    (SELECT COUNT(*) FROM osint_graph_versions v WHERE v.graph_id = g.id),
    (SELECT MAX(number) FROM osint_graph_versions v WHERE v.graph_id = g.id), g.state_revision";

fn graph_row(r: &rusqlite::Row) -> rusqlite::Result<GraphMeta> {
    Ok(GraphMeta {
        id: r.get(0)?,
        investigation_id: r.get(1)?,
        investigation_name: r.get(2)?,
        primary_target: r.get(3)?,
        name: r.get(4)?,
        description: r.get(5)?,
        follow_new: r.get::<_, i64>(6)? != 0,
        revision: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
        last_opened_at: r.get(10)?,
        entity_count: r.get(11)?,
        relationship_count: r.get(12)?,
        version_count: r.get(13)?,
        latest_version: r.get(14)?,
        state_revision: r.get(15)?,
    })
}

pub fn graph_meta(c: &Connection, id: i64) -> AppResult<GraphMeta> {
    c.query_row(&format!("SELECT {GRAPH_COLS} FROM osint_graphs g JOIN osint_investigations i ON i.id = g.investigation_id WHERE g.id = ?1"), params![id], graph_row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("graph {id}")))
}

pub fn graph_list(c: &Connection, inv: Option<i64>) -> AppResult<Vec<GraphMeta>> {
    let mut st = c.prepare(&format!(
        "SELECT {GRAPH_COLS} FROM osint_graphs g JOIN osint_investigations i ON i.id = g.investigation_id WHERE (?1 IS NULL OR g.investigation_id = ?1) ORDER BY COALESCE(g.last_opened_at, g.updated_at) DESC"
    ))?;
    let v = st.query_map(params![inv], graph_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

fn clean_graph_name(name: &str) -> AppResult<String> {
    clean_text("Graph name", name, 120, true)
}

pub fn graph_create(c: &Connection, inv: i64, name: &str, description: &str, follow_new: bool) -> AppResult<i64> {
    let name = clean_graph_name(name)?;
    let description = clean_text("Description", description, 2000, false)?;
    let at = now();
    c.execute(
        "INSERT INTO osint_graphs (investigation_id, name, description, follow_new, workspace, created_at, updated_at) VALUES (?1,?2,?3,?4,'{}',?5,?5)",
        params![inv, name, description, follow_new as i64, at],
    )?;
    let id = c.last_insert_rowid();
    if follow_new {
        c.execute("INSERT OR IGNORE INTO osint_graph_nodes (graph_id, entity_id) SELECT ?1, id FROM osint_entities WHERE investigation_id = ?2", params![id, inv])?;
    }
    record_version(c, id, "created", "Graph created", true)?;
    ingest::event(c, inv, "graph", &format!("Graph created: {name}"), Some("analyst"), None, None, None, Some(id), json!({}))?;
    Ok(id)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphNodeState {
    pub entity_id: i64,
    #[serde(default)]
    pub x: Option<f64>,
    #[serde(default)]
    pub y: Option<f64>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphData {
    pub graph: GraphMeta,
    pub workspace: Value,
    pub nodes: Vec<GraphNodeState>,
    pub entities: Vec<EntityBrief>,
    pub relationships: Vec<RelationshipBrief>,
    pub warning: Option<String>,
}

fn node_states(c: &Connection, graph: i64) -> rusqlite::Result<Vec<GraphNodeState>> {
    let mut st = c.prepare("SELECT entity_id, x, y, pinned, hidden, group_id FROM osint_graph_nodes WHERE graph_id = ?1 ORDER BY entity_id")?;
    let v = st
        .query_map(params![graph], |r| Ok(GraphNodeState { entity_id: r.get(0)?, x: r.get(1)?, y: r.get(2)?, pinned: r.get::<_, i64>(3)? != 0, hidden: r.get::<_, i64>(4)? != 0, group: r.get(5)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

pub fn graph_load(c: &Connection, id: i64, touch: bool) -> AppResult<GraphData> {
    let graph = graph_meta(c, id)?;
    if touch {
        c.execute("UPDATE osint_graphs SET last_opened_at = ?2 WHERE id = ?1", params![id, now()])?;
        investigation_touch(c, graph.investigation_id)?;
    }
    let workspace: String = c.query_row("SELECT workspace FROM osint_graphs WHERE id = ?1", params![id], |r| r.get(0))?;
    let nodes = node_states(c, id)?;
    let ids: HashSet<i64> = nodes.iter().map(|n| n.entity_id).collect();
    let entities = entities_by_ids(c, &ids.iter().copied().collect::<Vec<_>>())?;
    let relationships = relationships_among(c, graph.investigation_id, &ids)?;
    let warning = (nodes.len() > LARGE_GRAPH_NODES).then(|| format!("This graph has {} entities. Filters, hidden categories and focused graphs keep the workspace fast.", nodes.len()));
    Ok(GraphData { graph, workspace: serde_json::from_str(&workspace).unwrap_or(json!({})), nodes, entities, relationships, warning })
}

fn validate_workspace(w: &Value) -> AppResult<String> {
    if !w.is_object() {
        return Err(validation("The workspace state must be an object"));
    }
    let s = w.to_string();
    if s.len() > MAX_WORKSPACE_BYTES {
        return Err(validation("The workspace state is too large"));
    }
    Ok(s)
}

fn validate_nodes(c: &Connection, inv: i64, nodes: &[GraphNodeState]) -> AppResult<()> {
    if nodes.len() > MAX_GRAPH_NODES {
        return Err(validation(format!("A graph can hold at most {MAX_GRAPH_NODES} entities")));
    }
    let ids: Vec<i64> = nodes.iter().map(|n| n.entity_id).collect();
    let unique: HashSet<i64> = ids.iter().copied().collect();
    if unique.len() != ids.len() {
        return Err(validation("Duplicate entities in the graph state"));
    }
    for n in nodes {
        if [n.x, n.y].iter().flatten().any(|v| !v.is_finite() || v.abs() > 1e7) {
            return Err(validation("Invalid node position"));
        }
        if let Some(g) = &n.group {
            if g.len() > 64 {
                return Err(validation("Group ids are at most 64 characters"));
            }
        }
    }
    for chunk in ids.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut args: Vec<SqlValue> = vec![SqlValue::Integer(inv)];
        args.extend(chunk.iter().map(|i| SqlValue::Integer(*i)));
        let found: i64 = c.query_row(&format!("SELECT COUNT(*) FROM osint_entities WHERE investigation_id = ? AND id IN ({marks})"), params_from_iter(args.iter()), |r| r.get(0))?;
        if found as usize != chunk.len() {
            return Err(validation("The graph refers to entities that are not part of its investigation"));
        }
    }
    Ok(())
}

fn upsert_nodes(c: &Connection, graph: i64, nodes: &[GraphNodeState]) -> rusqlite::Result<()> {
    let mut st = c.prepare(
        "INSERT INTO osint_graph_nodes (graph_id, entity_id, x, y, pinned, hidden, group_id) VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(graph_id, entity_id) DO UPDATE SET x = excluded.x, y = excluded.y, pinned = excluded.pinned, hidden = excluded.hidden, group_id = excluded.group_id",
    )?;
    for n in nodes {
        st.execute(params![graph, n.entity_id, n.x, n.y, n.pinned as i64, n.hidden as i64, n.group])?;
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphSave {
    pub base_revision: i64,
    pub nodes: Vec<GraphNodeState>,
    /// entities the analyst removed from this graph since it was loaded
    #[serde(default)]
    pub removed: Vec<i64>,
    pub workspace: Value,
    #[serde(default)]
    pub version_label: Option<String>,
    /// record a named version even when nothing changed
    #[serde(default)]
    pub manual_version: bool,
    /// the `state_revision` the client loaded; a different stored value means the graph was
    /// saved or restored elsewhere and the save is refused with a conflict unless `force`
    #[serde(default)]
    pub base_state_revision: Option<i64>,
    /// overwrite a newer saved state (the analyst chose to keep their version)
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    pub revision: i64,
    pub version: Option<i64>,
    /// the graph changed in the meantime (new data); the saved state includes those entities
    pub merged_concurrent_changes: bool,
    pub state_revision: i64,
}

/// Save: upserts the client's node states, removes only the entities the analyst removed (so new
/// entities added by collection in the meantime survive), stores the workspace and records a
/// version when the content changed. Runs in the caller's transaction.
pub fn graph_save(c: &Connection, id: i64, s: &GraphSave) -> AppResult<SaveResult> {
    let meta = graph_meta(c, id)?;
    if let Some(base) = s.base_state_revision {
        if base != meta.state_revision && !s.force {
            return Err(AppError::Conflict(format!(
                "\"{}\" was saved or restored elsewhere after you opened it (latest version {}). Reload it, save your work as a new graph, or overwrite the newer state.",
                meta.name,
                meta.latest_version.map(|v| v.to_string()).unwrap_or_else(|| "none".into())
            )));
        }
    }
    validate_nodes(c, meta.investigation_id, &s.nodes)?;
    let ws = validate_workspace(&s.workspace)?;
    upsert_nodes(c, id, &s.nodes)?;
    for chunk in s.removed.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut args: Vec<SqlValue> = vec![SqlValue::Integer(id)];
        args.extend(chunk.iter().map(|i| SqlValue::Integer(*i)));
        c.execute(&format!("DELETE FROM osint_graph_nodes WHERE graph_id = ? AND entity_id IN ({marks})"), params_from_iter(args.iter()))?;
    }
    c.execute("UPDATE osint_graphs SET workspace = ?2, revision = revision + 1, state_revision = state_revision + 1, updated_at = ?3 WHERE id = ?1", params![id, ws, now()])?;
    let label = s.version_label.as_deref().map(|l| clean_text("Version label", l, 120, false)).transpose()?.unwrap_or_default();
    let version = record_version(c, id, if s.manual_version { "manual" } else { "save" }, &label, s.manual_version)?;
    let (revision, state_revision): (i64, i64) = c.query_row("SELECT revision, state_revision FROM osint_graphs WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    ingest::event(c, meta.investigation_id, "graph", &format!("Graph saved: {}{}", meta.name, version.map(|v| format!(" (version {v})")).unwrap_or_default()), Some("analyst"), None, None, None, Some(id), json!({}))?;
    Ok(SaveResult { revision, version, merged_concurrent_changes: meta.revision != s.base_revision, state_revision })
}

/// Save As: a new, independent graph with the given state.
pub fn graph_save_as(c: &Connection, from: i64, name: &str, nodes: &[GraphNodeState], workspace: &Value, follow_new: bool) -> AppResult<i64> {
    let meta = graph_meta(c, from)?;
    validate_nodes(c, meta.investigation_id, nodes)?;
    let ws = validate_workspace(workspace)?;
    let id = graph_create(c, meta.investigation_id, name, &format!("Saved from \"{}\"", meta.name), false)?;
    upsert_nodes(c, id, nodes)?;
    c.execute("UPDATE osint_graphs SET workspace = ?2, follow_new = ?3 WHERE id = ?1", params![id, ws, follow_new as i64])?;
    // the creation version should describe the saved content
    c.execute("DELETE FROM osint_graph_versions WHERE graph_id = ?1", params![id])?;
    record_version(c, id, "created", &format!("Saved as from \"{}\"", meta.name), true)?;
    Ok(id)
}

/// Duplicate: copy of the stored state of a graph.
pub fn graph_duplicate(c: &Connection, from: i64, name: &str) -> AppResult<i64> {
    let data = graph_load(c, from, false)?;
    let follow: bool = data.graph.follow_new;
    graph_save_as(c, from, name, &data.nodes, &data.workspace, follow)
}

pub fn graph_rename(c: &Connection, id: i64, name: &str, description: Option<&str>, follow_new: Option<bool>) -> AppResult<()> {
    let meta = graph_meta(c, id)?;
    let name = clean_graph_name(name)?;
    c.execute("UPDATE osint_graphs SET name = ?2, updated_at = ?3 WHERE id = ?1", params![id, name, now()])?;
    if let Some(d) = description {
        c.execute("UPDATE osint_graphs SET description = ?2 WHERE id = ?1", params![id, clean_text("Description", d, 2000, false)?])?;
    }
    if let Some(f) = follow_new {
        c.execute("UPDATE osint_graphs SET follow_new = ?2 WHERE id = ?1", params![id, f as i64])?;
    }
    if meta.name != name {
        ingest::event(c, meta.investigation_id, "graph", &format!("Graph renamed: {} → {name}", meta.name), Some("analyst"), None, None, None, Some(id), json!({}))?;
    }
    Ok(())
}

pub fn graph_delete(c: &Connection, id: i64) -> AppResult<()> {
    let meta = graph_meta(c, id)?;
    c.execute("DELETE FROM osint_graphs WHERE id = ?1", params![id])?;
    ingest::event(c, meta.investigation_id, "graph", &format!("Graph deleted: {}", meta.name), Some("analyst"), None, None, None, None, json!({ "graph": id }))?;
    Ok(())
}

/* ───────────────────────── versions ───────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Snapshot {
    pub format: u32,
    pub nodes: Vec<GraphNodeState>,
    pub workspace: Value,
    /// entity id → [type, value, verification, confidence, flagged]
    pub entities: BTreeMap<i64, (String, String, String, String, bool)>,
    /// relationship id → [source, target, type, verification, confidence, evidence count]
    pub relationships: BTreeMap<i64, (i64, i64, String, String, String, i64)>,
}

pub fn snapshot(c: &Connection, graph: i64) -> AppResult<Snapshot> {
    let data = graph_load(c, graph, false)?;
    let mut entities = BTreeMap::new();
    for e in &data.entities {
        entities.insert(e.id, (e.entity_type.clone(), e.value.clone(), e.verification.clone(), e.confidence.clone(), e.flagged));
    }
    let mut relationships = BTreeMap::new();
    for r in &data.relationships {
        let n: i64 = c.query_row("SELECT COUNT(*) FROM osint_relationship_evidence WHERE relationship_id = ?1", params![r.id], |x| x.get(0))?;
        relationships.insert(r.id, (r.source, r.target, r.rel_type.clone(), r.verification.clone(), r.confidence.clone(), n));
    }
    // positions rounded so a re-render does not count as a change
    let nodes = data.nodes.into_iter().map(|mut n| {
        n.x = n.x.map(|v| (v * 10.0).round() / 10.0);
        n.y = n.y.map(|v| (v * 10.0).round() / 10.0);
        n
    });
    Ok(Snapshot { format: 1, nodes: nodes.collect(), workspace: data.workspace, entities, relationships })
}

/// Record a version if the content differs from the latest one (or always when `force`).
/// Keeps the newest versions; manual and restore versions are never pruned.
pub fn record_version(c: &Connection, graph: i64, kind: &str, label: &str, force: bool) -> AppResult<Option<i64>> {
    let snap = snapshot(c, graph)?;
    let text = serde_json::to_string(&snap)?;
    let hash = fingerprint(&[&text]);
    let last: Option<(i64, String, String)> = c.query_row("SELECT number, content_hash, snapshot FROM osint_graph_versions WHERE graph_id = ?1 ORDER BY number DESC LIMIT 1", params![graph], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
    if !force && last.as_ref().is_some_and(|(_, h, _)| *h == hash) {
        return Ok(None);
    }
    let number = last.as_ref().map_or(1, |(n, _, _)| n + 1);
    let summary = match &last {
        Some((_, _, prev)) => serde_json::to_value(diff(&serde_json::from_str(prev).unwrap_or_default(), &snap))?,
        None => json!({ "entitiesAdded": snap.entities.len(), "relationshipsAdded": snap.relationships.len() }),
    };
    c.execute(
        "INSERT INTO osint_graph_versions (graph_id, number, created_at, kind, label, content_hash, snapshot, summary) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![graph, number, now(), kind, label, hash, text, summary.to_string()],
    )?;
    c.execute(
        "DELETE FROM osint_graph_versions WHERE graph_id = ?1 AND kind IN ('save','created','import') AND number NOT IN
           (SELECT number FROM osint_graph_versions WHERE graph_id = ?1 ORDER BY number DESC LIMIT ?2)",
        params![graph, MAX_VERSIONS_KEPT],
    )?;
    Ok(Some(number))
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Diff {
    pub entities_added: Vec<(i64, String, String)>,
    pub entities_removed: Vec<(i64, String, String)>,
    pub relationships_added: Vec<(i64, String)>,
    pub relationships_removed: Vec<(i64, String)>,
    /// (id, value, from, to)
    pub verification_changes: Vec<(i64, String, String, String)>,
    pub evidence_changes: Vec<(i64, String, i64, i64)>,
    pub nodes_moved: usize,
    pub workspace_changed: bool,
}

pub fn diff(a: &Snapshot, b: &Snapshot) -> Diff {
    let mut d = Diff::default();
    let name = |s: &Snapshot, id: i64| s.entities.get(&id).map(|e| e.1.clone()).unwrap_or_else(|| format!("#{id}"));
    for (id, e) in &b.entities {
        match a.entities.get(id) {
            None => d.entities_added.push((*id, e.0.clone(), e.1.clone())),
            Some(old) if old.2 != e.2 => d.verification_changes.push((*id, e.1.clone(), old.2.clone(), e.2.clone())),
            _ => {}
        }
    }
    for (id, e) in &a.entities {
        if !b.entities.contains_key(id) {
            d.entities_removed.push((*id, e.0.clone(), e.1.clone()));
        }
    }
    for (id, r) in &b.relationships {
        let label = format!("{} {} {}", name(b, r.0), r.2, name(b, r.1));
        match a.relationships.get(id) {
            None => d.relationships_added.push((*id, label)),
            Some(old) => {
                if old.3 != r.3 {
                    d.verification_changes.push((*id, label.clone(), old.3.clone(), r.3.clone()));
                }
                if old.5 != r.5 {
                    d.evidence_changes.push((*id, label, old.5, r.5));
                }
            }
        }
    }
    for (id, r) in &a.relationships {
        if !b.relationships.contains_key(id) {
            d.relationships_removed.push((*id, format!("{} {} {}", name(a, r.0), r.2, name(a, r.1))));
        }
    }
    let pos: HashMap<i64, (Option<f64>, Option<f64>)> = a.nodes.iter().map(|n| (n.entity_id, (n.x, n.y))).collect();
    d.nodes_moved = b.nodes.iter().filter(|n| pos.get(&n.entity_id).is_some_and(|p| *p != (n.x, n.y))).count();
    d.workspace_changed = a.workspace != b.workspace;
    d
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionRow {
    pub id: i64,
    pub number: i64,
    pub created_at: String,
    pub kind: String,
    pub label: String,
    pub summary: Value,
    pub entity_count: usize,
    pub relationship_count: usize,
}

pub fn versions(c: &Connection, graph: i64) -> AppResult<Vec<VersionRow>> {
    graph_meta(c, graph)?;
    let mut st = c.prepare("SELECT id, number, created_at, kind, label, summary, snapshot FROM osint_graph_versions WHERE graph_id = ?1 ORDER BY number DESC")?;
    let v = st
        .query_map(params![graph], |r| {
            let snap: Snapshot = serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default();
            Ok(VersionRow {
                id: r.get(0)?,
                number: r.get(1)?,
                created_at: r.get(2)?,
                kind: r.get(3)?,
                label: r.get(4)?,
                summary: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(Value::Null),
                entity_count: snap.entities.len(),
                relationship_count: snap.relationships.len(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

fn version_snapshot(c: &Connection, version: i64) -> AppResult<(i64, i64, Snapshot)> {
    let (graph, number, text): (i64, i64, String) = c
        .query_row("SELECT graph_id, number, snapshot FROM osint_graph_versions WHERE id = ?1", params![version], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("version {version}")))?;
    let snap: Snapshot = serde_json::from_str(&text).map_err(|_| AppError::Internal("This version is stored in an unreadable format".into()))?;
    if snap.format != 1 {
        return Err(validation("This version was saved by an incompatible ExploitX version"));
    }
    Ok((graph, number, snap))
}

/// Compare two versions of the same graph (or a version with the current state if `b` is None).
pub fn version_compare(c: &Connection, a: i64, b: Option<i64>) -> AppResult<Diff> {
    let (ga, _, sa) = version_snapshot(c, a)?;
    let sb = match b {
        Some(b) => {
            let (gb, _, sb) = version_snapshot(c, b)?;
            if ga != gb {
                return Err(validation("Versions belong to different graphs"));
            }
            sb
        }
        None => snapshot(c, ga)?,
    };
    Ok(diff(&sa, &sb))
}

/// Restore the membership, layout and workspace of a version. The current state is recorded
/// as a version first and the restore becomes a new version, so no history is lost.
/// Intelligence (verification, evidence) is investigation-wide and is not rewound.
pub fn version_restore(c: &Connection, version: i64) -> AppResult<(i64, usize)> {
    let (graph, number, snap) = version_snapshot(c, version)?;
    let meta = graph_meta(c, graph)?;
    record_version(c, graph, "save", "Before restoring an earlier version", false)?;
    let existing: HashSet<i64> = {
        let mut st = c.prepare("SELECT id FROM osint_entities WHERE investigation_id = ?1")?;
        let v = st.query_map(params![meta.investigation_id], |r| r.get(0))?.collect::<Result<HashSet<i64>, _>>()?;
        v
    };
    let keep: Vec<GraphNodeState> = snap.nodes.iter().filter(|n| existing.contains(&n.entity_id)).cloned().collect();
    let missing = snap.nodes.len() - keep.len();
    c.execute("DELETE FROM osint_graph_nodes WHERE graph_id = ?1", params![graph])?;
    upsert_nodes(c, graph, &keep)?;
    c.execute("UPDATE osint_graphs SET workspace = ?2, revision = revision + 1, state_revision = state_revision + 1, updated_at = ?3 WHERE id = ?1", params![graph, snap.workspace.to_string(), now()])?;
    let new = record_version(c, graph, "restore", &format!("Restored version {number}"), true)?.unwrap_or(number);
    ingest::event(c, meta.investigation_id, "graph", &format!("Graph \"{}\" restored to version {number}", meta.name), Some("analyst"), None, None, None, Some(graph), json!({ "missing": missing }))?;
    Ok((new, missing))
}

/* ───────────────────────── timeline ───────────────────────── */

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct TimelineQuery {
    pub kinds: Vec<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub entity_id: Option<i64>,
    pub relationship_id: Option<i64>,
    pub source: Option<String>,
    pub q: Option<String>,
    pub offset: i64,
    pub limit: i64,
}

pub const EVENT_KINDS: &[&str] = &[
    "investigation",
    "collection",
    "entity_discovered",
    "relationship_discovered",
    "relationship_inferred",
    "verification",
    "annotation",
    "entity_merged",
    "entity_removed",
    "relationship_removed",
    "graph",
    "discovery",
    "import",
    "export",
];

/// A timeline bound (RFC 3339 with an offset, e.g. a local midnight from the UI) converted to
/// the stored form (UTC, whole seconds, `Z`), so text comparison matches instants exactly.
pub fn utc_bound(s: &str) -> AppResult<String> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .map(|d| d.with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .map_err(|_| validation("Dates must be RFC 3339 timestamps with a time zone"))
}

pub fn timeline(c: &Connection, inv: i64, q: &TimelineQuery) -> AppResult<Page<TimelineEvent>> {
    let mut where_ = vec!["investigation_id = ?".to_string()];
    let mut args: Vec<SqlValue> = vec![SqlValue::Integer(inv)];
    if !q.kinds.is_empty() {
        if q.kinds.iter().any(|k| !EVENT_KINDS.contains(&k.as_str())) {
            return Err(validation("Unknown event type"));
        }
        where_.push(format!("kind IN ({})", vec!["?"; q.kinds.len()].join(",")));
        args.extend(q.kinds.iter().map(|k| SqlValue::Text(k.clone())));
    }
    if let Some(f) = q.from.as_deref().filter(|s| !s.is_empty()) {
        where_.push("at >= ?".into());
        args.push(SqlValue::Text(utc_bound(f)?));
    }
    if let Some(t) = q.to.as_deref().filter(|s| !s.is_empty()) {
        where_.push("at <= ?".into());
        args.push(SqlValue::Text(utc_bound(t)?));
    }
    if let Some(e) = q.entity_id {
        where_.push("(entity_id = ? OR relationship_id IN (SELECT id FROM osint_relationships WHERE source_id = ? OR target_id = ?))".into());
        args.extend([SqlValue::Integer(e), SqlValue::Integer(e), SqlValue::Integer(e)]);
    }
    if let Some(r) = q.relationship_id {
        where_.push("relationship_id = ?".into());
        args.push(SqlValue::Integer(r));
    }
    if let Some(s) = q.source.as_deref().filter(|s| !s.is_empty()) {
        where_.push("source = ?".into());
        args.push(SqlValue::Text(s.into()));
    }
    if let Some(s) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let s = clean_text("Search", s, 200, false)?.to_lowercase().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        where_.push("lower(summary) LIKE ? ESCAPE '\\'".into());
        args.push(SqlValue::Text(format!("%{s}%")));
    }
    let w = where_.join(" AND ");
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM osint_events WHERE {w}"), params_from_iter(args.iter()), |r| r.get(0))?;
    let limit = if q.limit <= 0 { 100 } else { q.limit.min(500) };
    let mut st = c.prepare(&format!("SELECT id, at, kind, summary, source, entity_id, relationship_id, operation_id, graph_id FROM osint_events WHERE {w} ORDER BY at DESC, id DESC LIMIT {limit} OFFSET {}", q.offset.max(0)))?;
    let items = st
        .query_map(params_from_iter(args.iter()), |r| {
            Ok(TimelineEvent { id: r.get(0)?, at: r.get(1)?, kind: r.get(2)?, summary: r.get(3)?, source: r.get(4)?, entity_id: r.get(5)?, relationship_id: r.get(6)?, operation_id: r.get(7)?, graph_id: r.get(8)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Page { total, offset: q.offset.max(0), items })
}

/* ───────────────────────── cross-investigation comparison ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedEntity {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: String,
    pub a_id: i64,
    pub b_id: i64,
    pub a_relationships: i64,
    pub b_relationships: i64,
}

/// Entities present in both investigations (same type and match key). Read-only: the
/// investigations stay separate.
pub fn compare_investigations(c: &Connection, a: i64, b: i64) -> AppResult<Vec<SharedEntity>> {
    if a == b {
        return Err(validation("Choose two different investigations"));
    }
    investigation_get(c, a)?;
    investigation_get(c, b)?;
    let mut st = c.prepare(
        "SELECT x.type, x.value, x.id, y.id,
           (SELECT COUNT(*) FROM osint_relationships r WHERE r.source_id = x.id OR r.target_id = x.id),
           (SELECT COUNT(*) FROM osint_relationships r WHERE r.source_id = y.id OR r.target_id = y.id)
         FROM osint_entities x JOIN osint_entities y ON y.type = x.type AND y.match_key = x.match_key
         WHERE x.investigation_id = ?1 AND y.investigation_id = ?2 ORDER BY x.type, x.value LIMIT 2000",
    )?;
    let v = st
        .query_map(params![a, b], |r| Ok(SharedEntity { entity_type: r.get(0)?, value: r.get(1)?, a_id: r.get(2)?, b_id: r.get(3)?, a_relationships: r.get(4)?, b_relationships: r.get(5)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::osint::ingest::tests::{ent, ev, rel, run};

    fn setup() -> (Db, i64) {
        let db = Db::open_in_memory().unwrap();
        let id = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let id = investigation_create(&tx, &InvestigationInput { name: "Acme".into(), description: String::new(), target_type: "domain".into(), target_value: "Example.com".into(), tags: vec!["a".into(), "a".into()], notes: String::new(), authorization: "Client engagement #12".into(), project_id: None })?;
                tx.commit()?;
                Ok(id)
            })
            .unwrap();
        (db, id)
    }

    fn main_graph(db: &Db, inv: i64) -> i64 {
        db.with(|c| Ok(graph_list(c, Some(inv))?[0].id)).unwrap()
    }

    /// A project with a finding, and an entity of the investigation linked to that finding.
    fn linked(c: &Connection, inv: i64, value: &str) -> AppResult<(i64, i64, i64)> {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P', 'active', 't', 't')", [])?;
        let p = c.last_insert_rowid();
        c.execute("UPDATE osint_investigations SET project_id = ?2 WHERE id = ?1", params![inv, p])?;
        c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1, 'domain', ?2, ?2, ?2, 't', 't')", params![inv, value])?;
        let e = c.last_insert_rowid();
        c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1, 'F', 'low', 'new', 't', 't')", params![p])?;
        let f = c.last_insert_rowid();
        crate::workspace::findings::link(c, f, "osint_entity", e, "user")?;
        Ok((p, e, f))
    }

    fn links(c: &Connection, f: i64) -> Vec<i64> {
        c.prepare("SELECT ref_id FROM finding_links WHERE finding_id = ?1 AND kind = 'osint_entity' ORDER BY ref_id").unwrap().query_map(params![f], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    }

    #[test]
    fn finding_links_follow_entities_that_are_merged_or_deleted() {
        let (db, inv) = setup();
        db.with(|c| {
            let (p, a, f) = linked(c, inv, "a.example.com")?;
            c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1, 'domain', 'b.example.com', 'b.example.com', 'b.example.com', 't', 't')", params![inv])?;
            let b = c.last_insert_rowid();
            c.execute("INSERT INTO assets (project_id, type, value, key, source, osint_entity_id, first_seen, last_seen, created_at, updated_at) VALUES (?1,'domain','a.example.com','a.example.com','osint',?2,'t','t','t','t')", params![p, a])?;
            entity_merge(c, b, a)?;
            assert_eq!(links(c, f), vec![b], "the link moves to the kept entity");
            let asset: Option<i64> = c.query_row("SELECT osint_entity_id FROM assets WHERE project_id = ?1", params![p], |r| r.get(0))?;
            assert_eq!(asset, Some(b), "and so does the asset's origin");
            // a link to both entities becomes one
            c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1, 'domain', 'c.example.com', 'c.example.com', 'c.example.com', 't', 't')", params![inv])?;
            let cc = c.last_insert_rowid();
            crate::workspace::findings::link(c, f, "osint_entity", cc, "user")?;
            entity_merge(c, b, cc)?;
            assert_eq!(links(c, f), vec![b]);
            entity_delete(c, b)?;
            assert!(links(c, f).is_empty(), "no link to a deleted entity");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn an_investigation_stays_with_the_project_that_refers_to_it() {
        let (db, inv) = setup();
        db.with(|c| {
            let (p, _, f) = linked(c, inv, "a.example.com")?;
            let input = |project_id: Option<i64>| InvestigationInput { name: "Acme".into(), description: String::new(), target_type: "domain".into(), target_value: "example.com".into(), tags: vec![], notes: String::new(), authorization: "Client engagement #12".into(), project_id };
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Q', 'active', 't', 't')", [])?;
            let q = c.last_insert_rowid();
            let err = investigation_update(c, inv, &input(Some(q))).unwrap_err().to_string();
            assert!(err.contains("1 finding link"), "{err}");
            let err = investigation_update(c, inv, &input(None)).unwrap_err().to_string();
            assert!(err.contains("refers to this investigation"), "unlinking is refused too: {err}");
            assert_eq!(investigation_get(c, inv)?.project_id, Some(p));
            // without references the link can change, and both sides record it
            c.execute("DELETE FROM finding_links WHERE finding_id = ?1", params![f])?;
            investigation_update(c, inv, &input(Some(q)))?;
            assert_eq!(investigation_get(c, inv)?.project_id, Some(q));
            let noted: i64 = c.query_row("SELECT COUNT(*) FROM timeline_events WHERE project_id = ?1 AND type = 'investigation' AND title LIKE 'Investigation Acme unlinked'", params![p], |r| r.get(0))?;
            assert_eq!(noted, 1);
            let event: i64 = c.query_row("SELECT COUNT(*) FROM osint_events WHERE investigation_id = ?1 AND summary LIKE 'Linked project changed from P to Q'", params![inv], |r| r.get(0))?;
            assert_eq!(event, 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn deleting_an_investigation_removes_links_to_its_entities_and_tells_the_project() {
        let (db, inv) = setup();
        db.with(|c| {
            let (p, _, f) = linked(c, inv, "a.example.com")?;
            let i = investigation_get(c, inv)?;
            investigation_delete(c, &i)?;
            assert!(links(c, f).is_empty());
            let noted: i64 = c.query_row("SELECT COUNT(*) FROM timeline_events WHERE project_id = ?1 AND title = 'Investigation deleted: Acme'", params![p], |r| r.get(0))?;
            assert_eq!(noted, 1);
            let logged: Option<i64> = c.query_row("SELECT project_id FROM activity_logs WHERE title = 'Investigation deleted: Acme'", [], |r| r.get(0))?;
            assert_eq!(logged, Some(p), "the activity entry names the project");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn creating_an_investigation_creates_its_target_and_main_graph() {
        let (db, inv) = setup();
        let i = db.with(|c| investigation_get(c, inv)).unwrap();
        assert_eq!((i.target_value.as_str(), i.tags.len(), i.counts.entities, i.counts.graphs), ("example.com", 1, 1, 1));
        let mg = main_graph(&db, inv);
        let g = db.with(|c| graph_load(c, mg, true)).unwrap();
        assert_eq!(g.nodes.len(), 1);
        assert!(db.with(|c| investigation_create(c, &InvestigationInput { name: " ".into(), description: String::new(), target_type: "domain".into(), target_value: "x.com".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })).is_err());
        assert!(db.with(|c| investigation_create(c, &InvestigationInput { name: "x".into(), description: String::new(), target_type: "service".into(), target_value: "1.2.3.4:80/tcp".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })).is_err(), "not a target type");
    }

    /// Regression guard for the graph metadata query, which was quadratic (correlated `IN`
    /// subqueries): 2,000 entities took over a second even in release builds. Now a few ms; the
    /// bounds are generous so slow CI machines do not fail spuriously.
    #[test]
    fn large_graph_load_and_save_stay_fast() {
        let (db, inv) = setup();
        let n = 2000;
        let mut ents = vec![];
        let mut rels = vec![];
        for i in 0..n {
            ents.push(ent(EntityType::Domain, &format!("h{i}.perf.example")));
            if i > 0 {
                rels.push(rel(i, (i * 7919) % i, "ASSOCIATED_WITH"));
                rels.push(rel(i, i / 2, "LINKS_TO"));
            }
        }
        run(&db, inv, &Observation { evidence: ev("dns", "bulk"), entities: ents, relationships: rels });
        let g = main_graph(&db, inv);
        let t = std::time::Instant::now();
        db.with(|c| graph_meta(c, g)).unwrap();
        let meta = t.elapsed();
        let t = std::time::Instant::now();
        let d = db.with(|c| graph_load(c, g, false)).unwrap();
        let load = t.elapsed();
        let t = std::time::Instant::now();
        let nodes: Vec<GraphNodeState> = d.nodes.iter().map(|x| GraphNodeState { x: Some(1.0), y: Some(2.0), ..x.clone() }).collect();
        db.with(|c| {
            let tx = c.unchecked_transaction()?;
            graph_save(&tx, g, &GraphSave { base_revision: d.graph.revision, nodes, removed: vec![], workspace: json!({}), version_label: None, manual_version: false, base_state_revision: None, force: false })?;
            tx.commit()?;
            Ok(())
        })
        .unwrap();
        let save = t.elapsed();
        println!("entities {} rels {} meta {:?} load {:?} save {:?}", d.entities.len(), d.relationships.len(), meta, load, save);
        assert_eq!((d.entities.len(), db.with(|c| graph_meta(c, g)).unwrap().relationship_count), (2001, 3998));
        assert!(meta < std::time::Duration::from_millis(500), "graph metadata took {meta:?}");
        assert!(load < std::time::Duration::from_secs(2), "graph load took {load:?}");
        assert!(save < std::time::Duration::from_secs(5), "graph save took {save:?}");
    }

    #[test]
    fn changing_the_target_adds_it_as_the_primary_entity() {
        let (db, inv) = setup();
        let i = db.with(|c| investigation_get(c, inv)).unwrap();
        let input = InvestigationInput { name: i.name.clone(), description: String::new(), target_type: "domain".into(), target_value: "www.example.org".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None };
        db.with(|c| investigation_update(c, inv, &input)).unwrap();
        let primary: Vec<String> = db
            .with(|c| {
                let mut st = c.prepare("SELECT value FROM osint_entities WHERE investigation_id = ?1 AND json_extract(metadata, '$.primaryTarget') = 1")?;
                let v = st.query_map(params![inv], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(primary, vec!["www.example.org".to_string()], "exactly one primary target, the new one");
        let g = main_graph(&db, inv);
        let data = db.with(|c| graph_load(c, g, false)).unwrap();
        assert!(data.entities.iter().any(|e| e.value == "www.example.org"), "the new target joins the graph that follows the investigation");
        assert!(data.entities.iter().any(|e| e.value == i.target_value), "the previous target is kept with its evidence");
        // saving unchanged details does not add anything
        let n = data.entities.len();
        db.with(|c| investigation_update(c, inv, &input)).unwrap();
        assert_eq!(db.with(|c| graph_load(c, g, false)).unwrap().entities.len(), n);
    }

    #[test]
    fn stale_saves_are_refused_unless_forced_and_collection_is_not_a_conflict() {
        let (db, inv) = setup();
        let g = main_graph(&db, inv);
        let a = db.with(|c| graph_load(c, g, false)).unwrap();
        let b = a.clone(); // a second editor of the same graph
        let save = |d: &GraphData, ws: Value, force: bool| {
            db.with(|c| graph_save(c, g, &GraphSave { base_revision: d.graph.revision, nodes: d.nodes.clone(), removed: vec![], workspace: ws, version_label: None, manual_version: false, base_state_revision: Some(d.graph.state_revision), force }))
        };
        // entities collected into a follow-new graph change `revision`, not the saved state
        run(&db, inv, &Observation { evidence: ev("dns", "A"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] });
        let first = save(&a, json!({ "layout": "radial" }), false).unwrap();
        assert!(first.merged_concurrent_changes, "collection while editing is merged, not refused");
        assert_eq!(first.state_revision, a.graph.state_revision + 1);
        // the other editor still holds the old state revision: refused, nothing written
        let err = save(&b, json!({ "layout": "circular" }), false).unwrap_err();
        assert_eq!(err.kind(), "conflict");
        assert_eq!(db.with(|c| graph_load(c, g, false)).unwrap().workspace["layout"], "radial");
        // explicit overwrite
        save(&b, json!({ "layout": "circular" }), true).unwrap();
        assert_eq!(db.with(|c| graph_load(c, g, false)).unwrap().workspace["layout"], "circular");
        // a restore also invalidates stale editors
        let fresh = db.with(|c| graph_load(c, g, false)).unwrap();
        let v = db.with(|c| versions(c, g)).unwrap().last().unwrap().id;
        db.with(|c| version_restore(c, v)).unwrap();
        assert_eq!(save(&fresh, json!({}), false).unwrap_err().kind(), "conflict");
    }

    #[test]
    fn timeline_bounds_are_compared_as_utc_instants() {
        assert_eq!(utc_bound("2026-11-05T00:00:00+02:00").unwrap(), "2026-11-04T22:00:00Z");
        assert_eq!(utc_bound("2026-11-05T23:59:59.999-05:00").unwrap(), "2026-11-06T04:59:59Z");
        assert!(utc_bound("2026-11-05T00:00:00").is_err(), "a bound without a zone is ambiguous");
        assert!(utc_bound("yesterday").is_err());
        let (db, inv) = setup();
        db.with(|c| {
            c.execute("UPDATE osint_events SET at = '2026-11-04T23:30:00Z' WHERE investigation_id = ?1", params![inv])?;
            Ok(())
        })
        .unwrap();
        let q = |from: &str, to: &str| db.with(|c| timeline(c, inv, &TimelineQuery { from: Some(from.into()), to: Some(to.into()), ..Default::default() })).unwrap().total;
        // 23:30 UTC on the 4th is the 5th in UTC+2: a local-day filter for the 5th includes it
        assert!(q("2026-11-05T00:00:00+02:00", "2026-11-05T23:59:59+02:00") > 0);
        assert_eq!(q("2026-11-05T00:00:00+00:00", "2026-11-05T23:59:59+00:00"), 0);
    }

    #[test]
    fn save_keeps_concurrent_additions_and_save_as_is_independent() {
        let (db, inv) = setup();
        let g = main_graph(&db, inv);
        let loaded = db.with(|c| graph_load(c, g, false)).unwrap();
        let target = loaded.nodes[0].entity_id;
        // new data arrives while the analyst has the graph open
        run(&db, inv, &Observation { evidence: ev("dns", "A"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] });
        let save = GraphSave { base_revision: loaded.graph.revision, nodes: vec![GraphNodeState { entity_id: target, x: Some(10.0), y: Some(20.0), pinned: true, hidden: false, group: Some("g1".into()) }], removed: vec![], workspace: json!({ "viewport": { "x": 1, "y": 2, "zoom": 1.5 }, "layout": "force" }), version_label: None, manual_version: false, base_state_revision: None, force: false };
        let r = db.with(|c| graph_save(c, g, &save)).unwrap();
        assert!(r.merged_concurrent_changes && r.version.is_some());
        let after = db.with(|c| graph_load(c, g, false)).unwrap();
        assert_eq!(after.nodes.len(), 2, "the concurrently added address is kept");
        assert_eq!(after.relationships.len(), 1);
        assert_eq!(after.workspace["viewport"]["zoom"], 1.5);
        let pinned = after.nodes.iter().find(|n| n.entity_id == target).unwrap();
        assert_eq!((pinned.x, pinned.pinned, pinned.group.as_deref()), (Some(10.0), true, Some("g1")));

        // Save As → independent graph
        let copy = db.with(|c| graph_save_as(c, g, "Copy", &after.nodes, &after.workspace, false)).unwrap();
        let mut moved = after.nodes.clone();
        moved[0].x = Some(999.0);
        db.with(|c| graph_save(c, copy, &GraphSave { base_revision: 0, nodes: moved, removed: vec![after.nodes[1].entity_id], workspace: json!({}), version_label: None, manual_version: false, base_state_revision: None, force: false })).unwrap();
        let orig = db.with(|c| graph_load(c, g, false)).unwrap();
        assert_eq!(orig.nodes.len(), 2);
        assert_eq!(orig.nodes.iter().find(|n| n.entity_id == target).unwrap().x, Some(10.0));
        assert_eq!(db.with(|c| graph_load(c, copy, false)).unwrap().nodes.len(), 1);
        // duplicate, rename, delete
        let dup = db.with(|c| graph_duplicate(c, copy, "Dup")).unwrap();
        db.with(|c| graph_rename(c, dup, "Renamed", None, None)).unwrap();
        assert_eq!(db.with(|c| graph_meta(c, dup)).unwrap().name, "Renamed");
        db.with(|c| graph_delete(c, dup)).unwrap();
        assert!(db.with(|c| graph_meta(c, dup)).is_err());
        assert_eq!(db.with(|c| graph_list(c, Some(inv))).unwrap().len(), 2);
    }

    #[test]
    fn invalid_graph_state_is_refused() {
        let (db, inv) = setup();
        let g = main_graph(&db, inv);
        let bad = |nodes: Vec<GraphNodeState>, ws: Value| db.with(|c| graph_save(c, g, &GraphSave { base_revision: 1, nodes, removed: vec![], workspace: ws, version_label: None, manual_version: false, base_state_revision: None, force: false }));
        let n = |id: i64, x: f64| GraphNodeState { entity_id: id, x: Some(x), y: Some(0.0), pinned: false, hidden: false, group: None };
        assert!(bad(vec![n(999_999, 0.0)], json!({})).is_err(), "unknown entity");
        assert!(bad(vec![n(1, f64::NAN)], json!({})).is_err(), "non-finite position");
        assert!(bad(vec![n(1, 0.0), n(1, 1.0)], json!({})).is_err(), "duplicate ids");
        assert!(bad(vec![n(1, 0.0)], json!([1, 2])).is_err(), "workspace must be an object");
        assert!(bad(vec![n(1, 0.0)], json!({ "big": "x".repeat(MAX_WORKSPACE_BYTES) })).is_err());
        // an entity of another investigation
        let (other_db_inv, other_entity) = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let o = investigation_create(&tx, &InvestigationInput { name: "Other".into(), description: String::new(), target_type: "ip".into(), target_value: "192.0.2.1".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })?;
                tx.commit()?;
                Ok((o, c.query_row("SELECT id FROM osint_entities WHERE investigation_id = ?1", params![o], |r| r.get::<_, i64>(0))?))
            })
            .unwrap();
        assert_ne!(other_db_inv, inv);
        assert!(bad(vec![n(other_entity, 0.0)], json!({})).is_err(), "entity from another investigation");
    }

    #[test]
    fn versions_record_changes_compare_and_restore_without_losing_history() {
        let (db, inv) = setup();
        let g = main_graph(&db, inv);
        let v1 = db.with(|c| versions(c, g)).unwrap();
        assert_eq!(v1.len(), 1);
        run(&db, inv, &Observation { evidence: ev("dns", "A"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] });
        let data = db.with(|c| graph_load(c, g, false)).unwrap();
        db.with(|c| graph_save(c, g, &GraphSave { base_revision: data.graph.revision, nodes: data.nodes.clone(), removed: vec![], workspace: json!({ "layout": "radial" }), version_label: None, manual_version: false, base_state_revision: None, force: false })).unwrap();
        // saving the same state again does not create a version
        let same = db.with(|c| graph_save(c, g, &GraphSave { base_revision: data.graph.revision, nodes: data.nodes.clone(), removed: vec![], workspace: json!({ "layout": "radial" }), version_label: None, manual_version: false, base_state_revision: None, force: false })).unwrap();
        assert!(same.version.is_none());
        let vs = db.with(|c| versions(c, g)).unwrap();
        assert_eq!(vs.len(), 2);
        let d = db.with(|c| version_compare(c, vs[1].id, Some(vs[0].id))).unwrap();
        assert_eq!((d.entities_added.len(), d.relationships_added.len()), (1, 1));
        assert!(d.workspace_changed);
        // a verification change shows up in the comparison with the current state
        let rid: i64 = db.with(|c| Ok(c.query_row("SELECT id FROM osint_relationships", [], |r| r.get(0))?)).unwrap();
        db.with(|c| set_verification(c, "relationship", rid, Verification::Verified, Some("checked"))).unwrap();
        let d2 = db.with(|c| version_compare(c, vs[0].id, None)).unwrap();
        assert_eq!(d2.verification_changes.len(), 1);
        // restore version 1: membership back to the target only, later versions kept
        let (new_number, missing) = db.with(|c| version_restore(c, vs[1].id)).unwrap();
        assert_eq!(missing, 0);
        assert_eq!(db.with(|c| graph_load(c, g, false)).unwrap().nodes.len(), 1);
        let after = db.with(|c| versions(c, g)).unwrap();
        assert!(after.len() >= 3 && after[0].number == new_number && after[0].kind == "restore");
        assert!(after.iter().any(|v| v.number == vs[0].number), "later versions are preserved");
    }

    #[test]
    fn merge_moves_relationships_evidence_and_records_history() {
        let (db, inv) = setup();
        run(&db, inv, &Observation {
            evidence: ev("a", "x"),
            entities: vec![ent(EntityType::Organization, "Example Corp"), ent(EntityType::Organization, "Example, Inc."), ent(EntityType::Domain, "example.com")],
            relationships: vec![rel(2, 0, "REGISTERED_TO"), rel(2, 1, "REGISTERED_TO")],
        });
        let (keep, merge): (i64, i64) = db.with(|c| Ok((c.query_row("SELECT id FROM osint_entities WHERE value = 'Example Corp'", [], |r| r.get(0))?, c.query_row("SELECT id FROM osint_entities WHERE value = 'Example, Inc.'", [], |r| r.get(0))?))).unwrap();
        db.with(|c| entity_merge(c, keep, merge)).unwrap();
        let d = db.with(|c| entity_detail(c, keep)).unwrap();
        assert!(d.aliases.contains(&"Example, Inc.".to_string()));
        assert_eq!(d.merged_from.len(), 1);
        assert_eq!(d.related.iter().filter(|r| r.relationship.rel_type == "REGISTERED_TO").count(), 1, "the duplicate relationship is folded");
        let domain: i64 = db.with(|c| Ok(c.query_row("SELECT id FROM osint_entities WHERE value = 'example.com'", [], |r| r.get(0))?)).unwrap();
        assert!(db.with(|c| entity_merge(c, keep, domain)).is_err(), "different types");
    }

    #[test]
    fn manual_links_are_verified_suggestions_wait_for_review_and_timeline_filters() {
        let (db, inv) = setup();
        run(&db, inv, &Observation { evidence: ev("a", "x"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Organization, "Acme")], relationships: vec![] });
        let (d, o): (i64, i64) = db.with(|c| Ok((c.query_row("SELECT id FROM osint_entities WHERE type='domain'", [], |r| r.get(0))?, c.query_row("SELECT id FROM osint_entities WHERE type='organization'", [], |r| r.get(0))?))).unwrap();
        let m = db.with(|c| link_entities(c, d, o, "REGISTERED_TO", Origin::Manual, "from the contract", "analyst")).unwrap();
        let s = db.with(|c| link_entities(c, o, d, "OWNS_BRAND", Origin::Suggested, "AI suggestion", "mcp:test-client")).unwrap();
        let get = |id: i64| db.with(|c| relationship_detail(c, id)).unwrap();
        assert_eq!(get(m).brief.verification, "verified");
        let sd = get(s);
        assert_eq!((sd.brief.verification.as_str(), sd.brief.confidence.as_str(), sd.category.as_str()), ("inferred", "low", "custom"));
        assert!(db.with(|c| link_entities(c, d, o, "bad type", Origin::Manual, "", "analyst")).is_err());
        let t = db.with(|c| timeline(c, inv, &TimelineQuery { kinds: vec!["relationship_inferred".into()], limit: 50, ..Default::default() })).unwrap();
        assert_eq!(t.total, 1);
        let by_entity = db.with(|c| timeline(c, inv, &TimelineQuery { entity_id: Some(o), limit: 50, ..Default::default() })).unwrap();
        assert!(by_entity.total >= 2);
        assert!(db.with(|c| timeline(c, inv, &TimelineQuery { kinds: vec!["drop table".into()], ..Default::default() })).is_err());
        // entity listing with search that contains LIKE wildcards
        let page = db.with(|c| entity_list(c, inv, &EntityQuery { q: Some("%".into()), limit: 50, ..Default::default() })).unwrap();
        assert_eq!(page.total, 0);
        let page = db.with(|c| entity_list(c, inv, &EntityQuery { q: Some("exam".into()), limit: 50, ..Default::default() })).unwrap();
        assert_eq!(page.total, 1);
    }

    #[test]
    fn compare_finds_shared_entities_without_mixing_investigations() {
        let (db, a) = setup();
        let b = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let b = investigation_create(&tx, &InvestigationInput { name: "B".into(), description: String::new(), target_type: "ip".into(), target_value: "93.184.216.34".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })?;
                tx.commit()?;
                Ok(b)
            })
            .unwrap();
        run(&db, a, &Observation { evidence: ev("dns", "A"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] });
        let shared = db.with(|c| compare_investigations(c, a, b)).unwrap();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].value, "93.184.216.34");
        let bi = db.with(|c| investigation_get(c, b)).unwrap();
        assert_eq!(bi.counts.entities, 1, "B is unchanged");
    }
}
