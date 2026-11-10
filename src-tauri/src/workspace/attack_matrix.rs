//! The ATT&CK matrix of a project (docs/DATA_MODEL.md#attck-matrix-schema-23).
//!
//! Three kinds of statement about a technique are kept apart, because they mean different things:
//! * **named by findings**: tools reported something that maps to the technique (a capability of a
//!   file, a log detection, a cloud check). These are leads, not confirmed adversary activity.
//! * **the analyst's assessment**: confirmed, hypothesis or ruled out, with a confidence and a
//!   note. Only an assessment says a technique was confirmed.
//! * **imported layers**: ATT&CK Navigator layers from elsewhere, typically detection coverage.
//!   They are an overlay and never count as observed.
//!
//! Layers are read as the Navigator's layer format specifies (4.x, and the older 2.x and 3.x
//! files), for the Enterprise domain only; technique IDs are checked against the bundled catalog,
//! revoked IDs are mapped to the technique that replaced them, and unknown IDs are counted, never
//! guessed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::attack::{self, IdState};
use super::attack_layer::techniques_of;
use super::relations;
use crate::error::{validation, AppResult};
use crate::util::now;

pub const STATUSES: &[&str] = &["confirmed", "hypothesis", "ruled_out"];
/// Navigator release the exported layer was checked with (layer format 4.5 needs 4.9.0 or later).
const NAVIGATOR: &str = "5.3.2";
/// A layer file read from disk.
pub const MAX_LAYER_BYTES: usize = 10 * 1024 * 1024;
const MAX_LAYER_TECHNIQUES: usize = 20_000;

static ID: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[Tt]\d{4}(\.\d{3})?$").expect("technique id"));
static COLOR: Lazy<Regex> = Lazy::new(|| Regex::new(r"^#[0-9a-fA-F]{3,8}$").expect("color"));

/// The catalog's version as the Navigator writes it in `versions.attack` (the major version).
/// The major ATT&CK version of a domain's catalog, as Navigator layers name it.
pub fn attack_major_of(domain: &str) -> String {
    attack::catalog_for(domain).unwrap_or_else(attack::catalog).version.split('.').next().unwrap_or_default().to_string()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Observed {
    pub finding_id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub confidence: String,
    /// evidence records linked to the finding
    pub evidence: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub status: String,
    pub confidence: String,
    pub note: String,
    /// the catalog version the analyst assessed against
    pub attack_version: String,
    pub created_by: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Mark {
    pub score: Option<f64>,
    pub color: String,
    pub comment: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LayerMark {
    pub layer_id: i64,
    #[serde(flatten)]
    pub mark: Mark,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Linked {
    pub relation_id: i64,
    /// the other record
    pub label: String,
    pub key: String,
    pub verification: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub tactics: Vec<String>,
    pub parent: Option<String>,
    pub state: IdState,
    pub observed: Vec<Observed>,
    pub linked: Vec<Linked>,
    pub assessment: Option<Assessment>,
    pub layers: Vec<LayerMark>,
    /// detection rules of the library mapped to the technique (coverage, not observation)
    pub rules: Vec<crate::workspace::detections::Coverage>,
    /// open detection matches in the project for rules mapped to the technique (leads)
    pub hits: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LayerSummary {
    pub id: i64,
    /// the layer's ATT&CK domain (`enterprise-attack`, `mobile-attack`, `ics-attack`)
    pub domain: String,
    pub name: String,
    pub description: String,
    pub file_name: String,
    pub evidence_id: Option<i64>,
    pub layer_version: String,
    pub attack_version: String,
    pub navigator_version: String,
    pub techniques: usize,
    pub unknown: Vec<String>,
    /// revoked IDs in the layer and the techniques they were mapped to
    pub remapped: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    pub imported_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// techniques named by at least one finding
    pub observed: usize,
    pub confirmed: usize,
    pub hypothesis: usize,
    pub ruled_out: usize,
    /// findings that name a technique (false positives left out)
    pub findings: usize,
    /// techniques with at least one enabled rule that can run
    pub covered: usize,
    /// techniques named by findings or assessed as confirmed or hypothesis without such a rule
    pub uncovered: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Matrix {
    /// the ATT&CK domain of this matrix (`enterprise-attack`, `mobile-attack`, `ics-attack`)
    pub domain: String,
    pub attack_version: String,
    pub attack_modified: String,
    pub attack_retrieved: String,
    pub entries: Vec<Entry>,
    pub layers: Vec<LayerSummary>,
    pub counts: Counts,
}

fn label(domain: &str, id: &str, state: &IdState) -> String {
    let name = |id: &str| attack::technique_in(domain, id).map(|t| t.name.clone());
    match state {
        IdState::Current => name(id).unwrap_or_default(),
        IdState::Revoked { by } => format!("revoked, now {by}{}", name(by).map(|n| format!(" {n}")).unwrap_or_default()),
        IdState::Deprecated => "deprecated".into(),
        IdState::Unknown => "not in ATT&CK".into(),
    }
}

fn entry<'a>(map: &'a mut BTreeMap<String, Entry>, domain: &str, id: &str) -> &'a mut Entry {
    let id = id.to_ascii_uppercase();
    map.entry(id.clone()).or_insert_with(|| {
        let state = attack::id_state_in(domain, &id);
        let t = attack::technique_in(domain, &id);
        Entry {
            name: label(domain, &id, &state),
            tactics: t.map(|t| t.tactics.clone()).unwrap_or_default(),
            parent: t.and_then(|t| t.parent.clone()),
            state,
            id,
            observed: Vec::new(),
            linked: Vec::new(),
            assessment: None,
            layers: Vec::new(),
            rules: Vec::new(),
            hits: 0,
        }
    })
}

/// Every Enterprise technique the project says something about, with what it says.
pub fn matrix(c: &Connection, project_id: i64) -> AppResult<Matrix> {
    matrix_for(c, project_id, attack::ENTERPRISE)
}

/// How many techniques of each ATT&CK domain have data in a project (named by findings, linked,
/// assessed or in a layer): the matrix switch shows them, so the analyst sees where data is before
/// switching (Mission 7, backlog #62).
pub fn domain_counts(c: &Connection, project_id: i64) -> AppResult<Vec<(String, usize)>> {
    [attack::ENTERPRISE, "mobile-attack", "ics-attack"].iter().map(|d| Ok((d.to_string(), matrix_for(c, project_id, d)?.entries.len()))).collect()
}

/// [`matrix`] for one ATT&CK domain: only the techniques of that domain (an ID no catalog knows is
/// shown with Enterprise), its assessments, layers, coverage and matches.
pub fn matrix_for(c: &Connection, project_id: i64, domain: &str) -> AppResult<Matrix> {
    let domain = attack::parse_domain(domain).ok_or_else(|| validation("The ATT&CK domain is enterprise-attack, mobile-attack or ics-attack"))?;
    let here = |id: &str| attack::in_domain(id, domain);
    relations::project_status(c, project_id)?;
    let mut map: BTreeMap<String, Entry> = BTreeMap::new();
    let mut counts = Counts::default();
    // named by findings (false positives are not named by anything)
    let evidence: HashMap<i64, i64> = c
        .prepare("SELECT l.finding_id, COUNT(*) FROM finding_links l JOIN findings f ON f.id = l.finding_id WHERE f.project_id = ?1 AND l.kind = 'evidence' GROUP BY l.finding_id")?
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for f in crate::commands::projects::findings_of(c, project_id)? {
        if f.status == "false_positive" {
            continue;
        }
        let ids: Vec<String> = techniques_of(&f).into_iter().filter(|id| here(id)).collect();
        if !ids.is_empty() {
            counts.findings += 1;
        }
        for id in ids {
            entry(&mut map, domain, &id).observed.push(Observed {
                finding_id: f.id,
                title: f.title.clone(),
                severity: f.severity.clone(),
                status: f.status.clone(),
                confidence: f.confidence.clone(),
                evidence: evidence.get(&f.id).copied().unwrap_or(0),
            });
        }
    }
    // records linked to a technique (not the rejected ones)
    let page = relations::list(c, project_id, &relations::Filter { kind: Some("technique".into()), limit: Some(500), ..Default::default() })?;
    for r in page.items.iter().filter(|r| r.verification != "rejected") {
        let (tech, other) = if r.a.r.kind == "technique" { (&r.a, &r.b) } else { (&r.b, &r.a) };
        if !here(&tech.r.sub) {
            continue;
        }
        entry(&mut map, domain, &tech.r.sub).linked.push(Linked { relation_id: r.id, label: other.label.clone(), key: other.key.clone(), verification: r.verification.clone(), origin: r.origin.clone() });
    }
    // the analyst's assessments
    let mut st = c.prepare("SELECT technique, status, confidence, note, attack_version, created_by, updated_at FROM attack_assessments WHERE project_id = ?1 AND domain = ?2")?;
    for row in st.query_map(params![project_id, domain], |r| {
        Ok((r.get::<_, String>(0)?, Assessment { status: r.get(1)?, confidence: r.get(2)?, note: r.get(3)?, attack_version: r.get(4)?, created_by: r.get(5)?, updated_at: r.get(6)? }))
    })? {
        let (id, a) = row?;
        match a.status.as_str() {
            "confirmed" => counts.confirmed += 1,
            "hypothesis" => counts.hypothesis += 1,
            _ => counts.ruled_out += 1,
        }
        entry(&mut map, domain, &id).assessment = Some(a);
    }
    // imported layers of this domain
    let layers: Vec<LayerSummary> = layers(c, project_id)?.into_iter().filter(|l| l.domain == domain).collect();
    for l in &layers {
        let marks: BTreeMap<String, Mark> = c.query_row("SELECT techniques FROM attack_layers WHERE id = ?1", params![l.id], |r| r.get::<_, String>(0)).map(|s| serde_json::from_str(&s).unwrap_or_default())?;
        for (id, mark) in marks {
            entry(&mut map, domain, &id).layers.push(LayerMark { layer_id: l.id, mark });
        }
    }
    // detection coverage of the library, and this project's detection matches
    for (t, rules) in crate::workspace::detections::coverage(c)? {
        if here(&t) {
            entry(&mut map, domain, &t).rules = rules;
        }
    }
    for (t, n) in crate::workspace::detections::hits_by_technique(c, project_id)? {
        if here(&t) {
            entry(&mut map, domain, &t).hits = n;
        }
    }
    counts.observed = map.values().filter(|e| !e.observed.is_empty()).count();
    counts.covered = map.values().filter(|e| e.rules.iter().any(|r| r.enabled && r.runnable)).count();
    counts.uncovered = map
        .values()
        .filter(|e| matches!(e.state, IdState::Current) && (!e.observed.is_empty() || e.assessment.as_ref().is_some_and(|a| a.status != "ruled_out")) && !e.rules.iter().any(|r| r.enabled && r.runnable))
        .count();
    let cat = attack::catalog_for(domain).unwrap_or_else(attack::catalog);
    Ok(Matrix { domain: domain.into(), attack_version: cat.version.clone(), attack_modified: cat.modified.clone(), attack_retrieved: cat.retrieved.clone(), entries: map.into_values().collect(), layers, counts })
}

/// Sets (or, with no status, removes) the analyst's assessment of a technique in a project.
pub fn assess(c: &Connection, project_id: i64, technique: &str, status: Option<&str>, confidence: &str, note: &str, actor: &str) -> AppResult<Option<Assessment>> {
    relations::require_open(c, project_id)?;
    let id = technique.trim().to_ascii_uppercase();
    let Some(domain) = attack::domain_of(&id) else {
        return Err(validation(format!("{id} is not an ATT&CK technique of the bundled Enterprise, Mobile or ICS catalogs (v{})", attack::catalog().version)));
    };
    let state = attack::id_state_in(domain, &id);
    if !["low", "medium", "high"].contains(&confidence) {
        return Err(validation("Confidence is low, medium or high"));
    }
    let note: String = note.trim().chars().take(5000).collect();
    let name = label(domain, &id, &state);
    let version = attack::catalog_for(domain).map(|c| c.version.clone()).unwrap_or_default();
    let tx = c.unchecked_transaction()?;
    let ts = now();
    let summary = match status {
        None => {
            if tx.execute("DELETE FROM attack_assessments WHERE project_id = ?1 AND technique = ?2", params![project_id, id])? == 0 {
                return Ok(None);
            }
            format!("Assessment removed: {id} {name}")
        }
        Some(s) => {
            if !STATUSES.contains(&s) {
                return Err(validation("An assessment is confirmed, hypothesis or ruled out"));
            }
            tx.execute(
                "INSERT INTO attack_assessments (project_id, technique, status, confidence, note, attack_version, created_by, created_at, updated_at, domain) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
                 ON CONFLICT (project_id, technique) DO UPDATE SET status = excluded.status, confidence = excluded.confidence, note = excluded.note, attack_version = excluded.attack_version, created_by = excluded.created_by, updated_at = excluded.updated_at, domain = excluded.domain",
                params![project_id, id, s, confidence, note, version, actor, ts, domain],
            )?;
            format!("ATT&CK {id} {name}: {} ({confidence} confidence)", s.replace('_', " "))
        }
    };
    tx.execute("INSERT INTO relation_events (project_id, relation_id, action, summary, note, actor, at) VALUES (?1, NULL, 'assessed', ?2, ?3, ?4, ?5)", params![project_id, summary, note, actor, ts])?;
    tx.commit()?;
    c.query_row("SELECT status, confidence, note, attack_version, created_by, updated_at FROM attack_assessments WHERE project_id = ?1 AND technique = ?2", params![project_id, id], |r| {
        Ok(Assessment { status: r.get(0)?, confidence: r.get(1)?, note: r.get(2)?, attack_version: r.get(3)?, created_by: r.get(4)?, updated_at: r.get(5)? })
    })
    .optional()
    .map_err(Into::into)
}

/* ───────────────────────── layers ───────────────────────── */

/// A Navigator layer as read, before it is stored.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ParsedLayer {
    /// the layer's ATT&CK domain
    pub domain: String,
    pub name: String,
    pub description: String,
    pub layer_version: String,
    pub attack_version: String,
    pub navigator_version: String,
    pub techniques: BTreeMap<String, Mark>,
    pub unknown: Vec<String>,
    pub remapped: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Reads an ATT&CK Navigator layer (format 4.x, or the older 2.x and 3.x) of the Enterprise domain.
pub fn parse_layer(bytes: &[u8]) -> Result<ParsedLayer, String> {
    if bytes.len() > MAX_LAYER_BYTES {
        return Err("The layer is larger than 10 MB".into());
    }
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("This is not a JSON file: {e}"))?;
    let obj = doc.as_object().ok_or("A layer is a JSON object")?;
    let techniques = obj.get("techniques").and_then(Value::as_array).ok_or("This is not an ATT&CK Navigator layer: it has no technique list")?;
    if techniques.len() > MAX_LAYER_TECHNIQUES {
        return Err(format!("The layer lists more than {MAX_LAYER_TECHNIQUES} techniques"));
    }
    let mut out = ParsedLayer::default();
    let named = text(obj.get("domain").unwrap_or(&Value::Null));
    let domain = if named.trim().is_empty() {
        out.warnings.push("The layer names no domain; it was read as ATT&CK Enterprise".into());
        attack::ENTERPRISE
    } else {
        attack::parse_domain(&named).ok_or_else(|| format!("Unknown layer domain '{}' (Cyber Hub reads enterprise-attack, mobile-attack and ics-attack)", cut(&named, 40)))?
    };
    out.domain = domain.into();
    let catalog = attack::catalog_for(domain).unwrap_or_else(attack::catalog);
    let versions = obj.get("versions").and_then(Value::as_object);
    out.layer_version = cut(&versions.map(|v| text(v.get("layer").unwrap_or(&Value::Null))).filter(|s| !s.is_empty()).unwrap_or_else(|| text(obj.get("version").unwrap_or(&Value::Null))), 20);
    out.attack_version = cut(&versions.map(|v| text(v.get("attack").unwrap_or(&Value::Null))).unwrap_or_default(), 20);
    out.navigator_version = cut(&versions.map(|v| text(v.get("navigator").unwrap_or(&Value::Null))).unwrap_or_default(), 20);
    let major: u32 = out.layer_version.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
    if major > 4 {
        out.warnings.push(format!("The layer format {} is newer than 4.5; it was read as 4.5", out.layer_version));
    } else if major == 0 {
        out.warnings.push("The layer names no format version; it was read as format 4.5".into());
    }
    let catalog_major = attack_major_of(domain);
    if !out.attack_version.is_empty() && out.attack_version.split('.').next() != Some(catalog_major.as_str()) {
        out.warnings.push(format!("The layer was made for ATT&CK v{}; Cyber Hub's {} catalog is v{}", out.attack_version, attack::domain_label(domain), catalog.version));
    }
    out.name = cut(&text(obj.get("name").unwrap_or(&Value::Null)), 200);
    out.description = cut(&text(obj.get("description").unwrap_or(&Value::Null)), 2000);
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    let mut deprecated: BTreeSet<String> = BTreeSet::new();
    for t in techniques {
        let raw = text(t.get("techniqueID").unwrap_or(&Value::Null));
        if !ID.is_match(&raw) {
            if !raw.is_empty() {
                unknown.insert(cut(&raw, 20));
            }
            continue;
        }
        let raw = raw.to_ascii_uppercase();
        let id = match attack::id_state_in(domain, &raw) {
            IdState::Current => raw.clone(),
            IdState::Revoked { by } => {
                out.remapped.insert(raw.clone(), by.clone());
                by
            }
            IdState::Deprecated => {
                deprecated.insert(raw.clone());
                raw.clone()
            }
            IdState::Unknown => {
                unknown.insert(raw);
                continue;
            }
        };
        // one entry per technique: a layer may list a technique once per tactic
        let score = t.get("score").and_then(Value::as_f64).filter(|s| s.is_finite());
        let color = text(t.get("color").unwrap_or(&Value::Null));
        let comment = cut(&text(t.get("comment").unwrap_or(&Value::Null)), 1000);
        let enabled = t.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        let m = out.techniques.entry(id).or_insert_with(|| Mark { enabled: false, ..Default::default() });
        m.score = match (m.score, score) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        if m.color.is_empty() && COLOR.is_match(&color) {
            m.color = color;
        }
        if !comment.is_empty() && !m.comment.contains(&comment) {
            m.comment = cut(&if m.comment.is_empty() { comment } else { format!("{} / {comment}", m.comment) }, 1000);
        }
        m.enabled |= enabled;
    }
    if !deprecated.is_empty() {
        out.warnings.push(format!("Deprecated techniques: {}", deprecated.into_iter().collect::<Vec<_>>().join(", ")));
    }
    out.unknown = unknown.into_iter().take(200).collect();
    if out.techniques.is_empty() {
        return Err(if out.unknown.is_empty() { "The layer lists no technique".into() } else { format!("None of the layer's techniques is in ATT&CK {} v{} ({} unknown)", attack::domain_label(domain), catalog.version, out.unknown.len()) });
    }
    if out.name.is_empty() {
        out.name = "Imported layer".into();
    }
    Ok(out)
}

/// Stores a parsed layer for a project. The same file twice in a project is refused.
pub fn store_layer(c: &Connection, project_id: i64, file_name: &str, sha256: &str, evidence_id: Option<i64>, l: &ParsedLayer) -> AppResult<i64> {
    relations::require_open(c, project_id)?;
    if c.query_row("SELECT 1 FROM attack_layers WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha256], |_| Ok(())).optional()?.is_some() {
        return Err(validation("This layer is already imported in the project"));
    }
    c.execute(
        "INSERT INTO attack_layers (project_id, name, description, file_name, sha256, evidence_id, layer_version, attack_version, navigator_version, techniques, unknown, remapped, warnings, imported_at, domain)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            project_id,
            l.name,
            l.description,
            cut(file_name, 200),
            sha256,
            evidence_id,
            l.layer_version,
            l.attack_version,
            l.navigator_version,
            serde_json::to_string(&l.techniques).unwrap_or_else(|_| "{}".into()),
            serde_json::to_string(&l.unknown).unwrap_or_else(|_| "[]".into()),
            serde_json::to_string(&l.remapped).unwrap_or_else(|_| "{}".into()),
            serde_json::to_string(&l.warnings).unwrap_or_else(|_| "[]".into()),
            now(),
            attack::parse_domain(&l.domain).unwrap_or(attack::ENTERPRISE)
        ],
    )?;
    Ok(c.last_insert_rowid())
}

pub fn layers(c: &Connection, project_id: i64) -> AppResult<Vec<LayerSummary>> {
    let mut st = c.prepare(
        "SELECT id, name, description, file_name, evidence_id, layer_version, attack_version, navigator_version, techniques, unknown, remapped, warnings, imported_at, domain FROM attack_layers WHERE project_id = ?1 ORDER BY id",
    )?;
    let rows = st.query_map(params![project_id], |r| {
        let marks: BTreeMap<String, Value> = serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default();
        Ok(LayerSummary {
            id: r.get(0)?,
            name: r.get(1)?,
            description: r.get(2)?,
            file_name: r.get(3)?,
            evidence_id: r.get(4)?,
            layer_version: r.get(5)?,
            attack_version: r.get(6)?,
            navigator_version: r.get(7)?,
            techniques: marks.len(),
            unknown: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
            remapped: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
            warnings: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or_default(),
            imported_at: r.get(12)?,
            domain: r.get(13)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Removes an imported layer (its file stays in the evidence vault). Returns its project.
pub fn delete_layer(c: &Connection, id: i64) -> AppResult<i64> {
    let project_id: i64 = c.query_row("SELECT project_id FROM attack_layers WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| crate::error::AppError::NotFound(format!("layer {id}")))?;
    relations::require_open(c, project_id)?;
    c.execute("DELETE FROM attack_layers WHERE id = ?1", params![id])?;
    Ok(project_id)
}

/* ───────────────────────── export ───────────────────────── */

const STATE_COLORS: &[(&str, &str, &str)] = &[
    ("confirmed", "Confirmed by the analyst", "#c62828"),
    ("observed", "Named by findings, not assessed", "#ef6c00"),
    ("hypothesis", "Hypothesis", "#f9a825"),
    ("ruled_out", "Ruled out", "#b0bec5"),
];

/// The project's techniques as an ATT&CK Navigator layer (format 4.5): what findings name and the
/// analyst's assessments, each technique colored by its state. Imported layers are not included.
/// The library's detection coverage as an ATT&CK Navigator layer (format 4.5): techniques with
/// enabled rules, scored with their number, green when every one of them passed its tests.
/// Coverage says what could be detected, not what happened.
pub fn export_coverage_layer(generated: &str, m: &Matrix) -> Result<String, String> {
    let mut techniques = Vec::new();
    let mut most = 1usize;
    for e in m.entries.iter().filter(|e| matches!(e.state, IdState::Current)) {
        let rules: Vec<&crate::workspace::detections::Coverage> = e.rules.iter().filter(|r| r.enabled && r.runnable).collect();
        if rules.is_empty() {
            continue;
        }
        most = most.max(rules.len());
        let tested = rules.iter().all(|r| r.tested);
        techniques.push(json!({
            "techniqueID": e.id,
            "score": rules.len(),
            "color": if tested { "#31a354" } else { "#c7e9c0" },
            "comment": format!("{} detection rule{}{}", rules.len(), if rules.len() == 1 { "" } else { "s" }, if tested { ", all tested" } else { ", not all tested" }),
            "enabled": true,
            "metadata": rules.iter().take(25).map(|r| json!({ "name": format!("Rule #{}", r.rule_id), "value": format!("{}{}", r.title, if r.tested { " (tested)" } else { "" }) })).collect::<Vec<_>>(),
            "showSubtechniques": false,
        }));
    }
    if techniques.is_empty() {
        return Err("No enabled detection rule maps to an ATT&CK technique".into());
    }
    let doc = json!({
        "name": "Cyber Hub detection coverage",
        "versions": { "attack": attack_major_of(&m.domain), "layer": "4.5", "navigator": NAVIGATOR },
        "domain": m.domain,
        "description": format!("Techniques with enabled Sigma rules in Cyber Hub's detection library, exported on {generated} with ATT&CK {} v{}. Score: number of rules; dark green: every rule passed its tests. Coverage says what could be detected, not what was observed.", attack::domain_label(&m.domain), m.attack_version),
        "sorting": 3,
        "layout": { "layout": "side", "showID": true, "showName": true, "expandedSubtechniques": "annotated" },
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": { "colors": ["#ffffff", "#31a354"], "minValue": 0, "maxValue": most },
        "legendItems": [{ "label": "All rules tested", "color": "#31a354" }, { "label": "Not all rules tested", "color": "#c7e9c0" }],
        "metadata": [{ "name": "Source", "value": "Cyber Hub detection library" }, { "name": "Exported", "value": generated }],
        "showTacticRowBackground": false,
        "selectTechniquesAcrossTactics": true,
        "selectSubtechniquesWithParent": false,
        "selectVisibleTechniques": false,
    });
    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

pub fn export_layer(project: &str, generated: &str, m: &Matrix) -> Result<String, String> {
    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut most = 1usize;
    let mut techniques: Vec<Value> = Vec::new();
    for e in m.entries.iter().filter(|e| matches!(e.state, IdState::Current | IdState::Deprecated) && (!e.observed.is_empty() || e.assessment.is_some())) {
        let state = e.assessment.as_ref().map(|a| a.status.as_str()).unwrap_or("observed");
        let si = STATE_COLORS.iter().position(|(s, _, _)| *s == state).unwrap_or(1);
        used.insert(si);
        most = most.max(e.observed.len());
        let mut comment = Vec::new();
        let mut metadata = Vec::new();
        if let Some(a) = &e.assessment {
            comment.push(format!("{} ({} confidence){}", STATE_COLORS[si].1, a.confidence, if a.note.is_empty() { String::new() } else { format!(": {}", a.note) }));
            metadata.push(json!({ "name": "Assessment", "value": format!("{} ({} confidence, ATT&CK v{})", a.status.replace('_', " "), a.confidence, a.attack_version) }));
        }
        if !e.observed.is_empty() {
            comment.push(format!("named by {} {} (leads, not confirmed activity)", e.observed.len(), if e.observed.len() == 1 { "finding" } else { "findings" }));
        }
        for o in e.observed.iter().take(25) {
            metadata.push(json!({ "name": format!("Finding #{}", o.finding_id), "value": format!("[{}, {}] {}", o.severity, o.status.replace('_', " "), o.title) }));
        }
        techniques.push(json!({
            "techniqueID": e.id,
            "score": e.observed.len(),
            "color": STATE_COLORS[si].2,
            "comment": comment.join("; "),
            "enabled": state != "ruled_out",
            "metadata": metadata,
            "showSubtechniques": false,
        }));
    }
    if techniques.is_empty() {
        return Err("No technique is named by a finding or assessed in this project".into());
    }
    let legend: Vec<Value> = used.iter().map(|i| json!({ "label": STATE_COLORS[*i].1, "color": STATE_COLORS[*i].2 })).collect();
    let doc = json!({
        "name": format!("{project}: ATT&CK {}", attack::domain_label(&m.domain)),
        "versions": { "attack": attack_major_of(&m.domain), "layer": "4.5", "navigator": NAVIGATOR },
        "domain": m.domain,
        "description": format!(
            "Techniques of {project}, exported by Cyber Hub on {generated} with ATT&CK {} v{}. Color: the analyst's assessment (confirmed, hypothesis, ruled out); techniques only named by findings are leads, not confirmed activity. Score: how many findings name a technique. Ruled-out techniques are disabled.",
            attack::domain_label(&m.domain),
            m.attack_version
        ),
        "sorting": 3,
        "layout": { "layout": "side", "showID": true, "showName": true, "expandedSubtechniques": "annotated" },
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": { "colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": most },
        "legendItems": legend,
        "metadata": [{ "name": "Project", "value": project }, { "name": "Exported", "value": generated }, { "name": "Source", "value": "Cyber Hub" }, { "name": "ATT&CK catalog", "value": format!("{} v{} ({})", attack::domain_label(&m.domain), m.attack_version, m.attack_modified) }],
        "showTacticRowBackground": false,
        "selectTechniquesAcrossTactics": true,
        "selectSubtechniquesWithParent": false,
        "selectVisibleTechniques": false,
    });
    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "attack_matrix_tests.rs"]
mod tests;
