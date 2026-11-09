//! Relationships between records of different modules (docs/DATA_MODEL.md#investigation-layer-schema-22).
//!
//! A relationship joins two references, each a record kind and its stable identifier (a finding, an
//! asset, a vulnerability, an evidence record, an OSINT entity, an endpoint of an API definition, a
//! component of an SBOM, an ATT&CK technique, a tool run). It keeps how it was established
//! (`origin`, the vocabulary of OSINT relationships plus `imported`), whether it is a fact
//! (`verification`) and whether the analyst has dealt with it (`review`). Correlation rules only
//! ever *suggest*: a suggestion stays inferred until the analyst accepts it, and nothing is merged.
//!
//! Finding links (`finding_links`) stay the confirmed links of findings that reports and the
//! evidence chain read; accepting a suggestion between a finding and an asset, vulnerability,
//! evidence record, OSINT entity or tool run creates that link (and undoing the decision removes
//! the link it created). Every decision is kept in `relation_events`, which the timeline shows.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const KINDS: &[&str] = &["finding", "asset", "vulnerability", "evidence", "osint_entity", "api_endpoint", "sbom_component", "technique", "execution"];
/// (type, directed, label)
pub const TYPES: &[(&str, bool, &str)] = &[
    ("affects", true, "affects"),
    ("corresponds_to", false, "corresponds to"),
    ("supported_by", true, "is supported by"),
    ("related_to", false, "is related to"),
    ("possible_duplicate", false, "may duplicate"),
    ("maps_to", true, "maps to"),
    ("associated_with", false, "is associated with"),
];
pub const ORIGINS: &[&str] = &["observed", "imported", "derived", "inferred", "manual", "suggested"];
pub const VERIFICATIONS: &[&str] = &["observed", "verified", "inferred", "disputed", "rejected"];
/// Suggestions kept in the queue per project; older rules' output beyond it is not stored.
pub const MAX_PENDING: usize = 5_000;

/// A record: its kind, its row id, and for records inside another one (an endpoint of an API
/// definition, a component of an SBOM) its index there; for techniques the technique ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    pub kind: String,
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub sub: String,
}

impl Ref {
    pub fn new(kind: &str, id: i64) -> Self {
        Ref { kind: kind.into(), id, sub: String::new() }
    }
    pub fn sub(kind: &str, id: i64, sub: impl Into<String>) -> Self {
        Ref { kind: kind.into(), id, sub: sub.into() }
    }
    pub fn technique(id: &str) -> Self {
        Ref { kind: "technique".into(), id: 0, sub: id.to_ascii_uppercase() }
    }
    /// The stored form: technique IDs in capitals without a row id.
    pub fn normalized(self) -> Self {
        if self.kind == "technique" {
            Ref::technique(self.sub.trim())
        } else {
            Ref { sub: self.sub.trim().to_string(), ..self }
        }
    }
    /// `finding:12`, `api_endpoint:3:5`, `technique:T1059.001`
    pub fn key(&self) -> String {
        match (self.kind.as_str(), self.sub.is_empty()) {
            ("technique", _) => format!("technique:{}", self.sub),
            (_, true) => format!("{}:{}", self.kind, self.id),
            (_, false) => format!("{}:{}:{}", self.kind, self.id, self.sub),
        }
    }
}

/// What a referenced record is, for lists and the graph.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    #[serde(rename = "ref")]
    pub r: Ref,
    pub key: String,
    pub label: String,
    /// "high · new", "subdomain", "file"…
    pub detail: String,
    pub severity: Option<String>,
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub field_a: String,
    pub value_a: String,
    pub field_b: String,
    pub value_b: String,
    /// exact, normalized or contained
    pub how: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Relation {
    pub id: i64,
    pub project_id: i64,
    pub a: Node,
    pub b: Node,
    #[serde(rename = "type")]
    pub rel_type: String,
    pub label: String,
    pub directed: bool,
    pub origin: String,
    pub verification: String,
    pub review: String,
    pub confidence: String,
    pub rules: Vec<String>,
    pub reason: String,
    pub matched: Vec<Match>,
    pub created_by: String,
    pub materialized: bool,
    pub note: String,
    pub created_at: String,
    pub updated_at: String,
    pub reviewed_at: Option<String>,
}

/// What a correlation rule found.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub a: Ref,
    pub b: Ref,
    pub rel_type: &'static str,
    pub rule: &'static str,
    pub reason: String,
    pub matched: Vec<Match>,
    pub confidence: &'static str,
    /// derived (the values are the same) or inferred (a judgement)
    pub origin: &'static str,
}

fn type_info(t: &str) -> AppResult<(bool, &'static str)> {
    TYPES.iter().find(|(n, _, _)| *n == t).map(|(_, d, l)| (*d, *l)).ok_or_else(|| validation(format!("Unknown relationship type '{t}'")))
}

/// Symmetric relationships keep their endpoints in one order, so a pair is stored once.
fn ordered(rel_type: &str, a: Ref, b: Ref) -> (Ref, Ref) {
    let directed = TYPES.iter().find(|(n, _, _)| *n == rel_type).is_some_and(|(_, d, _)| *d);
    if !directed && b < a {
        (b, a)
    } else {
        (a, b)
    }
}

fn rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

pub fn project_status(c: &Connection, project_id: i64) -> AppResult<String> {
    c.query_row("SELECT status FROM projects WHERE id = ?1", params![project_id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("project {project_id}")))
}

/// Changes to an archived project are refused: it is kept for reference.
pub fn require_open(c: &Connection, project_id: i64) -> AppResult<()> {
    if project_status(c, project_id)? == "archived" {
        return Err(validation("The project is archived (kept for reference); set another status to change its relationships"));
    }
    Ok(())
}

/* ───────────────────────── describing records ───────────────────────── */

/// What a lookup finds: the record's project (None for techniques), label, detail, severity,
/// flagged.
type Found = (Option<i64>, String, String, Option<String>, bool);

/// Describes references, checking they exist and belong to the project. Documents (API
/// definitions, SBOMs) are read once per call.
#[derive(Default)]
pub struct Describer {
    endpoints: HashMap<i64, Option<(i64, Vec<String>)>>,
    components: HashMap<i64, Option<(i64, Vec<String>)>>,
}

impl Describer {
    fn endpoint_labels(&mut self, c: &Connection, spec: i64) -> AppResult<Option<(i64, Vec<String>)>> {
        if let Some(v) = self.endpoints.get(&spec) {
            return Ok(v.clone());
        }
        let loaded = match crate::workspace::apisec::get(c, spec) {
            Ok((s, doc)) => Some((s.project_id, doc.endpoints.iter().map(|e| format!("{} {}", e.method, e.path)).collect())),
            Err(AppError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        self.endpoints.insert(spec, loaded.clone());
        Ok(loaded)
    }
    fn component_labels(&mut self, c: &Connection, doc: i64) -> AppResult<Option<(i64, Vec<String>)>> {
        if let Some(v) = self.components.get(&doc) {
            return Ok(v.clone());
        }
        let loaded = match crate::workspace::sbom::get(c, doc) {
            Ok((s, sbom, _)) => Some((s.project_id, sbom.components.iter().map(|x| x.label()).collect())),
            Err(AppError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        self.components.insert(doc, loaded.clone());
        Ok(loaded)
    }

    /// The record, or None when it does not exist (any more). The project is checked by
    /// [`Describer::node`].
    pub fn lookup(&mut self, c: &Connection, r: &Ref) -> AppResult<Option<(Option<i64>, Node)>> {
        let node = |label: String, detail: String, severity: Option<String>, flagged: bool| Node { r: r.clone(), key: r.key(), label, detail, severity, flagged };
        let one = |sql: &str| -> AppResult<Option<Found>> {
            Ok(c.query_row(sql, params![r.id], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get::<_, i64>(4)? != 0))).optional()?)
        };
        let found = match r.kind.as_str() {
            "finding" => one("SELECT project_id, title, severity || ' · ' || replace(status, '_', ' '), severity, 0 FROM findings WHERE id = ?1")?,
            "asset" => one("SELECT project_id, value, replace(type, '_', ' ') || CASE status WHEN 'active' THEN '' ELSE ' · ' || replace(status, '_', ' ') END, NULL, 0 FROM assets WHERE id = ?1")?,
            "vulnerability" => one("SELECT project_id, cve_id, upper(priority) || ' · ' || replace(status, '_', ' ') || CASE WHEN title <> '' THEN ' · ' || title ELSE '' END, NULL, kev FROM vulnerabilities WHERE id = ?1")?,
            "evidence" => one("SELECT project_id, title, kind || CASE WHEN source <> '' THEN ' · ' || source ELSE '' END, NULL, 0 FROM evidence WHERE id = ?1")?,
            "osint_entity" => one(
                "SELECT i.project_id, e.display_name, replace(e.type, '_', ' ') || ' · ' || i.name, NULL, e.flagged FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id WHERE e.id = ?1",
            )?,
            "execution" => one("SELECT project_id, tool_id || ' run #' || id, status, NULL, 0 FROM executions WHERE id = ?1")?,
            "api_endpoint" => {
                let idx: usize = r.sub.parse().map_err(|_| validation("An API endpoint reference needs the endpoint's index"))?;
                self.endpoint_labels(c, r.id)?.and_then(|(p, labels)| labels.get(idx).map(|l| (Some(p), l.clone(), format!("endpoint of API definition #{}", r.id), None, false)))
            }
            "sbom_component" => {
                let idx: usize = r.sub.parse().map_err(|_| validation("An SBOM component reference needs the component's index"))?;
                self.component_labels(c, r.id)?.and_then(|(p, labels)| labels.get(idx).map(|l| (Some(p), l.clone(), format!("component of SBOM #{}", r.id), None, false)))
            }
            "technique" => {
                use crate::workspace::attack::{id_state, technique_name, IdState};
                let id = r.sub.to_ascii_uppercase();
                if !regex_technique().is_match(&id) {
                    None
                } else {
                    let version = &crate::workspace::attack::catalog().version;
                    match id_state(&id) {
                        IdState::Current => Some((None, format!("{id} {}", technique_name(&id).unwrap_or_default()), format!("ATT&CK technique (v{version})"), None, false)),
                        IdState::Revoked { by } => Some((None, format!("{id} (revoked, now {by})"), format!("ATT&CK technique revoked before v{version}"), None, false)),
                        IdState::Deprecated => Some((None, format!("{id} (deprecated)"), format!("ATT&CK technique deprecated in v{version}"), None, false)),
                        IdState::Unknown => None,
                    }
                }
            }
            other => return Err(validation(format!("Unknown record kind '{other}'"))),
        };
        Ok(found.map(|(p, label, detail, sev, flagged)| (p, node(label, detail, sev, flagged))))
    }

    /// The record of the project, or an error naming what is wrong.
    pub fn node(&mut self, c: &Connection, project_id: i64, r: &Ref) -> AppResult<Node> {
        match self.lookup(c, r)? {
            None => Err(AppError::NotFound(format!("{} {}", r.kind.replace('_', " "), r.key()))),
            Some((Some(p), _)) if p != project_id => Err(validation(format!("{} belongs to another project", r.key()))),
            Some((_, n)) => Ok(n),
        }
    }

    /// The record as stored, or a placeholder when it was deleted since.
    fn node_or_gone(&mut self, c: &Connection, r: &Ref) -> AppResult<Node> {
        Ok(match self.lookup(c, r)? {
            Some((_, n)) => n,
            None => Node { r: r.clone(), key: r.key(), label: format!("{} (deleted)", r.key()), detail: String::new(), severity: None, flagged: false },
        })
    }
}

fn regex_technique() -> &'static regex::Regex {
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r"^T\d{4}(\.\d{3})?$").expect("technique"));
    &RE
}

/* ───────────────────────── storing ───────────────────────── */

const COLS: &str = "id, project_id, a_kind, a_id, a_sub, b_kind, b_id, b_sub, type, origin, verification, review, confidence, rules, reason, matched, created_by, materialized, note, created_at, updated_at, reviewed_at";

type Row = (i64, i64, Ref, Ref, String, String, String, String, String, String, String, String, String, bool, String, String, String, Option<String>);

fn read_row(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        Ref { kind: r.get(2)?, id: r.get(3)?, sub: r.get(4)? },
        Ref { kind: r.get(5)?, id: r.get(6)?, sub: r.get(7)? },
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
        r.get(16)?,
        r.get::<_, i64>(17)? != 0,
        r.get(18)?,
        r.get(19)?,
        r.get(20)?,
        r.get(21)?,
    ))
}

fn build(d: &mut Describer, c: &Connection, row: Row) -> AppResult<Relation> {
    let (id, project_id, a, b, rel_type, origin, verification, review, confidence, rules, reason, matched, created_by, materialized, note, created_at, updated_at, reviewed_at) = row;
    let (directed, label) = type_info(&rel_type).unwrap_or((false, "is related to"));
    Ok(Relation {
        id,
        project_id,
        a: d.node_or_gone(c, &a)?,
        b: d.node_or_gone(c, &b)?,
        rel_type,
        label: label.into(),
        directed,
        origin,
        verification,
        review,
        confidence,
        rules: serde_json::from_str(&rules).unwrap_or_default(),
        reason,
        matched: serde_json::from_str(&matched).unwrap_or_default(),
        created_by,
        materialized,
        note,
        created_at,
        updated_at,
        reviewed_at,
    })
}

pub fn get(c: &Connection, id: i64) -> AppResult<Relation> {
    let row = c.query_row(&format!("SELECT {COLS} FROM relations WHERE id = ?1"), params![id], read_row).optional()?.ok_or_else(|| AppError::NotFound(format!("relationship {id}")))?;
    build(&mut Describer::default(), c, row)
}

fn event(c: &Connection, project_id: i64, relation_id: Option<i64>, action: &str, summary: &str, note: &str, actor: &str) -> AppResult<()> {
    c.execute(
        "INSERT INTO relation_events (project_id, relation_id, action, summary, note, actor, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![project_id, relation_id, action, summary.chars().take(500).collect::<String>(), note.chars().take(2000).collect::<String>(), actor, now()],
    )?;
    Ok(())
}

fn sentence(r: &Relation) -> String {
    format!("{} {} {}", r.a.label, r.label, r.b.label)
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SuggestResult {
    pub new: usize,
    pub updated: usize,
    /// pairs the analyst already decided on: left as they are
    pub decided: usize,
    /// candidates for pairs that a finding link already joins
    pub linked: usize,
    pub truncated: bool,
}

fn finding_link_kind(a: &Ref, b: &Ref) -> Option<(i64, &'static str, i64)> {
    let link = |f: &Ref, o: &Ref| -> Option<(i64, &'static str, i64)> {
        let kind = match o.kind.as_str() {
            "asset" => "asset",
            "vulnerability" => "vulnerability",
            "evidence" => "evidence",
            "osint_entity" => "osint_entity",
            "execution" => "execution",
            _ => return None,
        };
        Some((f.id, kind, o.id))
    };
    match (a.kind.as_str(), b.kind.as_str()) {
        ("finding", _) => link(a, b),
        (_, "finding") => link(b, a),
        _ => None,
    }
}

fn already_linked(c: &Connection, a: &Ref, b: &Ref) -> AppResult<bool> {
    Ok(match finding_link_kind(a, b) {
        Some((f, kind, id)) => c.query_row("SELECT EXISTS (SELECT 1 FROM finding_links WHERE finding_id = ?1 AND kind = ?2 AND ref_id = ?3)", params![f, kind, id], |r| r.get(0))?,
        None => false,
    })
}

/// Stores what correlation rules found as suggestions. Pairs the analyst already decided on keep
/// their decision; suggestions still waiting get the latest explanation.
pub fn suggest(c: &Connection, project_id: i64, candidates: Vec<Candidate>, actor: &str) -> AppResult<SuggestResult> {
    require_open(c, project_id)?;
    let mut res = SuggestResult::default();
    // one candidate per pair and type: the strongest, with every rule and match
    let mut merged: BTreeMap<(String, Ref, Ref), Candidate> = BTreeMap::new();
    let mut rules: BTreeMap<(String, Ref, Ref), Vec<&'static str>> = BTreeMap::new();
    for cand in candidates {
        if cand.a == cand.b {
            continue;
        }
        let (a, b) = ordered(cand.rel_type, cand.a.clone(), cand.b.clone());
        let k = (cand.rel_type.to_string(), a.clone(), b.clone());
        let list = rules.entry(k.clone()).or_default();
        if !list.contains(&cand.rule) {
            list.push(cand.rule);
        }
        match merged.get_mut(&k) {
            Some(m) => {
                for x in cand.matched {
                    if !m.matched.contains(&x) && m.matched.len() < 10 {
                        m.matched.push(x);
                    }
                }
                if rank(cand.confidence) > rank(m.confidence) {
                    m.confidence = cand.confidence;
                    m.reason = cand.reason;
                }
            }
            None => {
                merged.insert(k, Candidate { a, b, ..cand });
            }
        }
    }
    let pending: i64 = c.query_row("SELECT COUNT(*) FROM relations WHERE project_id = ?1 AND review = 'pending'", params![project_id], |r| r.get(0))?;
    let mut room = MAX_PENDING.saturating_sub(pending as usize);
    let ts = now();
    for ((rel_type, a, b), cand) in merged {
        if already_linked(c, &a, &b)? {
            res.linked += 1;
            continue;
        }
        let existing: Option<(i64, String, String)> = c
            .query_row(
                "SELECT id, review, confidence FROM relations WHERE project_id = ?1 AND type = ?2 AND a_kind = ?3 AND a_id = ?4 AND a_sub = ?5 AND b_kind = ?6 AND b_id = ?7 AND b_sub = ?8",
                params![project_id, rel_type, a.kind, a.id, a.sub, b.kind, b.id, b.sub],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let rule_list = serde_json::to_string(&rules[&(rel_type.clone(), a.clone(), b.clone())]).unwrap_or_else(|_| "[]".into());
        let matched = serde_json::to_string(&cand.matched).unwrap_or_else(|_| "[]".into());
        match existing {
            Some((_, review, _)) if review != "pending" => res.decided += 1,
            Some((id, _, _)) => {
                c.execute("UPDATE relations SET rules = ?2, reason = ?3, matched = ?4, confidence = ?5, origin = ?6, updated_at = ?7 WHERE id = ?1", params![id, rule_list, cand.reason, matched, cand.confidence, cand.origin, ts])?;
                res.updated += 1;
            }
            None if room == 0 => res.truncated = true,
            None => {
                c.execute(
                    "INSERT INTO relations (project_id, a_kind, a_id, a_sub, b_kind, b_id, b_sub, type, origin, verification, review, confidence, rules, reason, matched, created_by, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'inferred', 'pending', ?10, ?11, ?12, ?13, ?14, ?15, ?15)",
                    params![project_id, a.kind, a.id, a.sub, b.kind, b.id, b.sub, rel_type, cand.origin, cand.confidence, rule_list, cand.reason, matched, actor, ts],
                )?;
                room -= 1;
                res.new += 1;
            }
        }
    }
    Ok(res)
}

/// Creates the finding link or the asset's OSINT entity a confirmed relationship stands for.
/// Returns whether something was created (and so may be removed again).
fn materialize(c: &Connection, r: &Relation) -> AppResult<bool> {
    if let Some((finding, kind, id)) = finding_link_kind(&r.a.r, &r.b.r) {
        return crate::workspace::findings::link(c, finding, kind, id, "correlation");
    }
    let pair = match (r.a.r.kind.as_str(), r.b.r.kind.as_str()) {
        ("asset", "osint_entity") => Some((r.a.r.id, r.b.r.id)),
        ("osint_entity", "asset") => Some((r.b.r.id, r.a.r.id)),
        _ => None,
    };
    if let Some((asset, entity)) = pair {
        return Ok(c.execute("UPDATE assets SET osint_entity_id = ?2, updated_at = ?3 WHERE id = ?1 AND osint_entity_id IS NULL", params![asset, entity, now()])? == 1);
    }
    Ok(false)
}

fn unmaterialize(c: &Connection, r: &Relation) -> AppResult<()> {
    if !r.materialized {
        return Ok(());
    }
    if let Some((finding, kind, id)) = finding_link_kind(&r.a.r, &r.b.r) {
        crate::workspace::findings::unlink(c, finding, kind, id, "correlation")?;
        return Ok(());
    }
    let pair = match (r.a.r.kind.as_str(), r.b.r.kind.as_str()) {
        ("asset", "osint_entity") => Some((r.a.r.id, r.b.r.id)),
        ("osint_entity", "asset") => Some((r.b.r.id, r.a.r.id)),
        _ => None,
    };
    if let Some((asset, entity)) = pair {
        c.execute("UPDATE assets SET osint_entity_id = NULL, updated_at = ?3 WHERE id = ?1 AND osint_entity_id = ?2", params![asset, entity, now()])?;
    }
    Ok(())
}

/// The analyst's decision on a relationship: accept, reject, dismiss, reviewed (looked at, left
/// unconfirmed) or restore (back into the queue).
pub fn review(c: &Connection, id: i64, action: &str, note: &str, actor: &str) -> AppResult<Relation> {
    let r = get(c, id)?;
    require_open(c, r.project_id)?;
    let note = note.trim();
    let tx = c.unchecked_transaction()?;
    let ts = now();
    match action {
        "accept" => {
            let made = materialize(&tx, &r)?;
            tx.execute("UPDATE relations SET verification = 'verified', review = 'done', reviewed_at = ?2, updated_at = ?2, materialized = materialized OR ?3, note = CASE WHEN ?4 = '' THEN note ELSE ?4 END WHERE id = ?1", params![id, ts, made, note])?;
        }
        "reject" => {
            unmaterialize(&tx, &r)?;
            tx.execute("UPDATE relations SET verification = 'rejected', review = 'done', reviewed_at = ?2, updated_at = ?2, materialized = 0, note = CASE WHEN ?3 = '' THEN note ELSE ?3 END WHERE id = ?1", params![id, ts, note])?;
        }
        "dismiss" => {
            tx.execute("UPDATE relations SET review = 'dismissed', reviewed_at = ?2, updated_at = ?2, note = CASE WHEN ?3 = '' THEN note ELSE ?3 END WHERE id = ?1", params![id, ts, note])?;
        }
        "reviewed" => {
            tx.execute("UPDATE relations SET review = 'done', reviewed_at = ?2, updated_at = ?2, note = CASE WHEN ?3 = '' THEN note ELSE ?3 END WHERE id = ?1", params![id, ts, note])?;
        }
        "restore" => {
            if r.origin == "manual" {
                return Err(validation("A link made by hand is not a suggestion; remove it instead"));
            }
            unmaterialize(&tx, &r)?;
            tx.execute("UPDATE relations SET verification = 'inferred', review = 'pending', reviewed_at = NULL, updated_at = ?2, materialized = 0 WHERE id = ?1", params![id, ts])?;
        }
        other => return Err(validation(format!("Unknown review action '{other}'"))),
    }
    let past = match action {
        "accept" => "Accepted",
        "reject" => "Rejected",
        "dismiss" => "Dismissed",
        "reviewed" => "Reviewed",
        _ => "Restored",
    };
    event(&tx, r.project_id, Some(id), action, &format!("{past}: {}", sentence(&r)), note, actor)?;
    tx.commit()?;
    get(c, id)
}

/// A relationship the analyst asserts (or, from an MCP client, proposes for review).
pub fn link(c: &Connection, project_id: i64, a: Ref, b: Ref, rel_type: &str, note: &str, actor: &str) -> AppResult<Relation> {
    require_open(c, project_id)?;
    type_info(rel_type)?;
    let (a, b) = (a.normalized(), b.normalized());
    if a == b {
        return Err(validation("A record cannot be related to itself"));
    }
    let mut d = Describer::default();
    d.node(c, project_id, &a)?;
    d.node(c, project_id, &b)?;
    let (a, b) = ordered(rel_type, a, b);
    let proposal = actor == "mcp";
    let (origin, verification, review) = if proposal { ("suggested", "inferred", "pending") } else { ("manual", "verified", "done") };
    let tx = c.unchecked_transaction()?;
    let ts = now();
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM relations WHERE project_id = ?1 AND type = ?2 AND a_kind = ?3 AND a_id = ?4 AND a_sub = ?5 AND b_kind = ?6 AND b_id = ?7 AND b_sub = ?8",
            params![project_id, rel_type, a.kind, a.id, a.sub, b.kind, b.id, b.sub],
            |r| r.get(0),
        )
        .optional()?;
    let id = match existing {
        Some(id) if proposal => id,
        Some(id) => {
            tx.execute("UPDATE relations SET verification = 'verified', review = 'done', reviewed_at = ?2, updated_at = ?2, note = CASE WHEN ?3 = '' THEN note ELSE ?3 END WHERE id = ?1", params![id, ts, note.trim()])?;
            id
        }
        None => {
            tx.execute(
                "INSERT INTO relations (project_id, a_kind, a_id, a_sub, b_kind, b_id, b_sub, type, origin, verification, review, confidence, reason, created_by, note, created_at, updated_at, reviewed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'high', ?12, ?13, ?14, ?15, ?15, CASE WHEN ?11 = 'done' THEN ?15 END)",
                params![project_id, a.kind, a.id, a.sub, b.kind, b.id, b.sub, rel_type, origin, verification, review, if proposal { "Proposed by an MCP client" } else { "Linked by the analyst" }, actor, note.trim(), ts],
            )?;
            tx.last_insert_rowid()
        }
    };
    let r = get(&tx, id)?;
    if !proposal && !r.materialized && r.verification == "verified" {
        let made = materialize(&tx, &r)?;
        if made {
            tx.execute("UPDATE relations SET materialized = 1 WHERE id = ?1", params![id])?;
        }
    }
    event(&tx, project_id, Some(id), if proposal { "proposed" } else { "linked" }, &format!("{}: {}", if proposal { "Proposed" } else { "Linked" }, sentence(&r)), note, actor)?;
    tx.commit()?;
    get(c, id)
}

/// Removes a relationship: one made by hand is deleted; one a rule found is kept as rejected, so
/// correlation does not suggest it again.
pub fn unlink(c: &Connection, id: i64, note: &str, actor: &str) -> AppResult<()> {
    let r = get(c, id)?;
    require_open(c, r.project_id)?;
    let tx = c.unchecked_transaction()?;
    unmaterialize(&tx, &r)?;
    if r.origin == "manual" {
        tx.execute("DELETE FROM relations WHERE id = ?1", params![id])?;
    } else {
        tx.execute("UPDATE relations SET verification = 'rejected', review = 'done', materialized = 0, reviewed_at = ?2, updated_at = ?2 WHERE id = ?1", params![id, now()])?;
    }
    event(&tx, r.project_id, if r.origin == "manual" { None } else { Some(id) }, "unlinked", &format!("Unlinked: {}", sentence(&r)), note, actor)?;
    tx.commit()?;
    Ok(())
}

/// Moves the relationships of a record that is merged into another (OSINT entities); a pair that
/// already exists for the kept record keeps the kept record's decision.
pub fn repoint(c: &Connection, kind: &str, from: i64, to: i64) -> AppResult<()> {
    c.execute("UPDATE OR IGNORE relations SET a_id = ?3 WHERE a_kind = ?1 AND a_id = ?2", params![kind, from, to])?;
    c.execute("UPDATE OR IGNORE relations SET b_id = ?3 WHERE b_kind = ?1 AND b_id = ?2", params![kind, from, to])?;
    c.execute("DELETE FROM relations WHERE (a_kind = ?1 AND a_id = ?2) OR (b_kind = ?1 AND b_id = ?2)", params![kind, from])?;
    // a relationship between the two merged records would now join the kept record to itself
    c.execute("DELETE FROM relations WHERE a_kind = ?1 AND b_kind = ?1 AND a_id = ?2 AND b_id = ?2 AND a_sub = b_sub", params![kind, to])?;
    // symmetric relationships keep their stored order; one that now exists both ways is kept once
    let moved: Vec<(i64, String, Ref, Ref)> = {
        let mut st = c.prepare("SELECT id, type, a_kind, a_id, a_sub, b_kind, b_id, b_sub FROM relations WHERE (a_kind = ?1 AND a_id = ?2) OR (b_kind = ?1 AND b_id = ?2)")?;
        let rows = st.query_map(params![kind, to], |r| Ok((r.get(0)?, r.get(1)?, Ref::sub(&r.get::<_, String>(2)?, r.get(3)?, r.get::<_, String>(4)?), Ref::sub(&r.get::<_, String>(5)?, r.get(6)?, r.get::<_, String>(7)?))))?;
        rows.collect::<Result<_, _>>()?
    };
    for (id, rel_type, a, b) in moved {
        let (oa, ob) = ordered(&rel_type, a.clone(), b);
        if oa != a {
            let changed = c.execute("UPDATE OR IGNORE relations SET a_kind = ?2, a_id = ?3, a_sub = ?4, b_kind = ?5, b_id = ?6, b_sub = ?7 WHERE id = ?1", params![id, oa.kind, oa.id, oa.sub, ob.kind, ob.id, ob.sub])?;
            if changed == 0 {
                c.execute("DELETE FROM relations WHERE id = ?1", params![id])?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// pending, done, dismissed; none: all
    #[serde(default)]
    pub review: Option<String>,
    #[serde(default)]
    pub verification: Option<String>,
    /// a record kind on either side
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub min_confidence: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub items: Vec<Relation>,
    pub total: i64,
    /// counts by review state: pending, done, dismissed
    pub pending: i64,
    pub done: i64,
    pub dismissed: i64,
}

fn check_filter(review: Option<&str>, verification: Option<&str>, kinds: &[&str], origins: &[String]) -> AppResult<()> {
    if review.is_some_and(|r| !["pending", "done", "dismissed"].contains(&r)) {
        return Err(validation("Unknown review state"));
    }
    if verification.is_some_and(|v| !VERIFICATIONS.contains(&v)) {
        return Err(validation("Unknown verification state"));
    }
    if let Some(k) = kinds.iter().find(|k| !KINDS.contains(k)) {
        return Err(validation(format!("Unknown record kind '{k}'")));
    }
    if let Some(o) = origins.iter().find(|o| !ORIGINS.contains(&o.as_str())) {
        return Err(validation(format!("Unknown origin '{o}'")));
    }
    Ok(())
}

pub fn list(c: &Connection, project_id: i64, f: &Filter) -> AppResult<Page> {
    project_status(c, project_id)?;
    check_filter(f.review.as_deref(), f.verification.as_deref(), &f.kind.as_deref().into_iter().collect::<Vec<_>>(), &[])?;
    let min = f.min_confidence.as_deref().map(rank).unwrap_or(1) as i64;
    let wheres = "project_id = ?1 AND (?2 IS NULL OR review = ?2) AND (?3 IS NULL OR verification = ?3) AND (?4 IS NULL OR a_kind = ?4 OR b_kind = ?4)
                  AND (CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) >= ?5 AND (?6 IS NULL OR rules LIKE '%\"' || ?6 || '\"%')";
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM relations WHERE {wheres}"), params![project_id, f.review, f.verification, f.kind, min, f.rule], |r| r.get(0))?;
    let limit = f.limit.unwrap_or(100).clamp(1, 500);
    let offset = f.offset.unwrap_or(0).max(0);
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM relations WHERE {wheres}
         ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, updated_at DESC, id DESC LIMIT ?7 OFFSET ?8"
    ))?;
    let rows = st.query_map(params![project_id, f.review, f.verification, f.kind, min, f.rule, limit, offset], read_row)?.collect::<Result<Vec<_>, _>>()?;
    let mut d = Describer::default();
    let items = rows.into_iter().map(|row| build(&mut d, c, row)).collect::<AppResult<Vec<_>>>()?;
    let count = |state: &str| -> AppResult<i64> { Ok(c.query_row("SELECT COUNT(*) FROM relations WHERE project_id = ?1 AND review = ?2", params![project_id, state], |r| r.get(0))?) };
    Ok(Page { items, total, pending: count("pending")?, done: count("done")?, dismissed: count("dismissed")? })
}

/* ───────────────────────── related records ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Related {
    pub node: Node,
    /// "affects", "finding link", "asset of the vulnerability"…
    pub via: String,
    pub origin: String,
    pub verification: String,
    pub relation_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RelatedView {
    pub node: Node,
    pub related: Vec<Related>,
    /// timeline events about the record
    pub events: Vec<crate::workspace::timeline::TimelineEvent>,
}

/// How a finding link was made, from the finding's history: import, the analyst, correlation.
fn link_origin(c: &Connection, finding: i64, kind: &str, id: i64) -> AppResult<&'static str> {
    let source: Option<String> = c
        .query_row("SELECT source FROM finding_events WHERE finding_id = ?1 AND kind = 'link' AND note = ?2 ORDER BY id DESC LIMIT 1", params![finding, format!("{kind} #{id}")], |r| r.get(0))
        .optional()?;
    Ok(match source.as_deref() {
        Some("user") => "manual",
        Some("import") | Some("sbom") | Some("api") => "imported",
        Some("correlation") => "derived",
        _ => "observed",
    })
}

/// Everything known to be related to a record: relationships (rejected ones only when asked),
/// finding links, and the structural links of the data (an asset's vulnerabilities, a
/// vulnerability's asset, an evidence record's source).
pub fn related(c: &Connection, project_id: i64, r: &Ref, include_rejected: bool) -> AppResult<RelatedView> {
    let normalized = r.clone().normalized();
    let r = &normalized;
    let mut d = Describer::default();
    let node = d.node(c, project_id, r)?;
    let mut out: Vec<Related> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut push = |out: &mut Vec<Related>, item: Related| {
        if seen.insert((item.node.key.clone(), item.via.clone())) {
            out.push(item);
        }
    };
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM relations WHERE id IN (SELECT id FROM relations WHERE a_kind = ?2 AND a_id = ?3 AND a_sub = ?4 AND project_id = ?1
                                                    UNION ALL SELECT id FROM relations WHERE b_kind = ?2 AND b_id = ?3 AND b_sub = ?4 AND project_id = ?1)
           AND (?5 OR verification <> 'rejected') AND review <> 'dismissed' ORDER BY id"
    ))?;
    let rows = st.query_map(params![project_id, r.kind, r.id, r.sub, include_rejected], read_row)?.collect::<Result<Vec<_>, _>>()?;
    // finding links a confirmed relationship stands for are shown once, as that relationship
    let mut covered: HashSet<Ref> = HashSet::new();
    for row in rows {
        let rel = build(&mut d, c, row)?;
        let (other, via) = if rel.a.r == *r { (rel.b.clone(), rel.label.clone()) } else { (rel.a.clone(), if rel.directed { format!("{} (from the other side)", rel.label) } else { rel.label.clone() }) };
        if rel.verification == "verified" && finding_link_kind(&rel.a.r, &rel.b.r).is_some() {
            covered.insert(other.r.clone());
        }
        push(&mut out, Related { node: other, via, origin: rel.origin.clone(), verification: rel.verification.clone(), relation_id: Some(rel.id) });
    }
    // finding links
    if r.kind == "finding" {
        let mut st = c.prepare("SELECT kind, ref_id FROM finding_links WHERE finding_id = ?1 ORDER BY id")?;
        for row in st.query_map(params![r.id], |x| Ok((x.get::<_, String>(0)?, x.get::<_, i64>(1)?)))?.collect::<Result<Vec<_>, _>>()? {
            let other = Ref::new(&row.0, row.1);
            if covered.contains(&other) {
                continue;
            }
            if let Some((_, n)) = d.lookup(c, &other)? {
                let origin = link_origin(c, r.id, &row.0, row.1)?;
                push(&mut out, Related { node: n, via: "finding link".into(), origin: origin.into(), verification: "verified".into(), relation_id: None });
            }
        }
    } else if matches!(r.kind.as_str(), "asset" | "vulnerability" | "evidence" | "osint_entity" | "execution") {
        let mut st = c.prepare("SELECT finding_id FROM finding_links WHERE kind = ?1 AND ref_id = ?2 ORDER BY id")?;
        for fid in st.query_map(params![r.kind, r.id], |x| x.get::<_, i64>(0))?.collect::<Result<Vec<_>, _>>()? {
            let other = Ref::new("finding", fid);
            if covered.contains(&other) {
                continue;
            }
            if let Some((Some(p), n)) = d.lookup(c, &other)? {
                if p == project_id {
                    let origin = link_origin(c, fid, &r.kind, r.id)?;
                    push(&mut out, Related { node: n, via: "linked to the finding".into(), origin: origin.into(), verification: "verified".into(), relation_id: None });
                }
            }
        }
    }
    // structural links
    let mut structural = |out: &mut Vec<Related>, d: &mut Describer, kind: &str, ids: Vec<i64>, via: &str| -> AppResult<()> {
        for id in ids {
            if let Some((_, n)) = d.lookup(c, &Ref::new(kind, id))? {
                push(out, Related { node: n, via: via.into(), origin: "observed".into(), verification: "observed".into(), relation_id: None });
            }
        }
        Ok(())
    };
    let ids = |sql: &str, id: i64| -> AppResult<Vec<i64>> { Ok(c.prepare(sql)?.query_map(params![id], |x| x.get::<_, i64>(0))?.collect::<Result<Vec<_>, _>>()?) };
    match r.kind.as_str() {
        "asset" => {
            structural(&mut out, &mut d, "vulnerability", ids("SELECT id FROM vulnerabilities WHERE asset_id = ?1", r.id)?, "vulnerability of the asset")?;
            structural(&mut out, &mut d, "osint_entity", ids("SELECT osint_entity_id FROM assets WHERE id = ?1 AND osint_entity_id IS NOT NULL", r.id)?, "OSINT entity of the asset")?;
        }
        "vulnerability" => structural(&mut out, &mut d, "asset", ids("SELECT asset_id FROM vulnerabilities WHERE id = ?1 AND asset_id IS NOT NULL", r.id)?, "asset of the vulnerability")?,
        "osint_entity" => structural(&mut out, &mut d, "asset", ids("SELECT id FROM assets WHERE osint_entity_id = ?1", r.id)?, "asset of the entity")?,
        "evidence" => {
            structural(&mut out, &mut d, "evidence", ids("SELECT derived_from FROM evidence WHERE id = ?1 AND derived_from IS NOT NULL", r.id)?, "derived from")?;
            structural(&mut out, &mut d, "evidence", ids("SELECT id FROM evidence WHERE derived_from = ?1", r.id)?, "analysis derived from it")?;
            structural(&mut out, &mut d, "execution", ids("SELECT execution_id FROM evidence WHERE id = ?1 AND execution_id IS NOT NULL", r.id)?, "tool run")?;
        }
        "sbom_component" => structural(&mut out, &mut d, "evidence", ids("SELECT evidence_id FROM sbom_docs WHERE id = ?1 AND evidence_id IS NOT NULL", r.id)?, "imported from")?,
        "api_endpoint" => structural(&mut out, &mut d, "evidence", ids("SELECT evidence_id FROM api_specs WHERE id = ?1 AND evidence_id IS NOT NULL", r.id)?, "imported from")?,
        _ => {}
    }
    let events = crate::workspace::timeline::events_about(c, project_id, r, 50)?;
    Ok(RelatedView { node, related: out, events })
}

/* ───────────────────────── graph ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub rel_type: String,
    pub label: String,
    pub directed: bool,
    pub origin: String,
    pub verification: String,
    pub confidence: String,
    pub relation_id: Option<i64>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<GraphEdge>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphFilter {
    /// include suggestions still waiting for review
    #[serde(default)]
    pub include_pending: bool,
    #[serde(default)]
    pub include_rejected: bool,
    #[serde(default)]
    pub min_confidence: Option<String>,
    /// origins to show; empty: all
    #[serde(default)]
    pub origins: Vec<String>,
    /// record kinds to show; empty: all
    #[serde(default)]
    pub kinds: Vec<String>,
    /// relationships changed at or after this time
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// only the records within `depth` steps of this one (a node key such as `asset:12`)
    #[serde(default)]
    pub focus: Option<String>,
    #[serde(default)]
    pub depth: Option<usize>,
}

/// The project's relationships and finding links as a graph, for the investigation view.
pub fn graph(c: &Connection, project_id: i64, f: &GraphFilter) -> AppResult<Graph> {
    project_status(c, project_id)?;
    check_filter(None, None, &f.kinds.iter().map(String::as_str).collect::<Vec<_>>(), &f.origins)?;
    let limit = f.limit.unwrap_or(1500).clamp(10, 5000);
    let min = f.min_confidence.as_deref().map(rank).unwrap_or(1) as i64;
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut refs: Vec<Ref> = Vec::new();
    let mut known: HashSet<Ref> = HashSet::new();
    let mut truncated = false;
    let wanted = |r: &Ref| f.kinds.is_empty() || f.kinds.contains(&r.kind);
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM relations WHERE project_id = ?1 AND review <> 'dismissed' AND (?2 OR review <> 'pending') AND (?3 OR verification <> 'rejected')
           AND (CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) >= ?4 AND (?5 IS NULL OR updated_at >= ?5) ORDER BY id"
    ))?;
    let rows = st.query_map(params![project_id, f.include_pending, f.include_rejected, min, f.since], read_row)?.collect::<Result<Vec<_>, _>>()?;
    // finding links a confirmed relationship stands for are drawn once, as that relationship
    let mut covered: HashSet<(i64, &'static str, i64)> = HashSet::new();
    for (id, _, a, b, rel_type, origin, verification, _, confidence, _, _, _, _, _, _, _, updated_at, _) in rows {
        if verification == "verified" {
            if let Some(pair) = finding_link_kind(&a, &b) {
                covered.insert(pair);
            }
        }
        if !f.origins.is_empty() && !f.origins.contains(&origin) || !wanted(&a) || !wanted(&b) {
            continue;
        }
        if edges.len() >= limit {
            truncated = true;
            break;
        }
        let (directed, label) = type_info(&rel_type).unwrap_or((false, "is related to"));
        for x in [&a, &b] {
            if known.insert(x.clone()) {
                refs.push(x.clone());
            }
        }
        edges.push(GraphEdge { id: format!("r{id}"), source: a.key(), target: b.key(), rel_type, label: label.into(), directed, origin, verification, confidence, relation_id: Some(id), updated_at });
    }
    // finding links of the project's findings
    if f.origins.is_empty() || f.origins.iter().any(|o| o == "observed" || o == "imported" || o == "manual" || o == "derived") {
        let mut st = c.prepare("SELECT l.id, l.finding_id, l.kind, l.ref_id, l.created_at FROM finding_links l JOIN findings x ON x.id = l.finding_id WHERE x.project_id = ?1 AND (?2 IS NULL OR l.created_at >= ?2) ORDER BY l.id")?;
        let rows = st.query_map(params![project_id, f.since], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, i64>(1)?, x.get::<_, String>(2)?, x.get::<_, i64>(3)?, x.get::<_, String>(4)?)))?.collect::<Result<Vec<_>, _>>()?;
        for (lid, fid, kind, rid, at) in rows {
            let (a, b) = (Ref::new("finding", fid), Ref::new(&kind, rid));
            if !wanted(&a) || !wanted(&b) || finding_link_kind(&a, &b).is_some_and(|p| covered.contains(&p)) {
                continue;
            }
            let origin = link_origin(c, fid, &kind, rid)?;
            if !f.origins.is_empty() && !f.origins.iter().any(|o| o == origin) {
                continue;
            }
            if edges.len() >= limit {
                truncated = true;
                break;
            }
            for x in [&a, &b] {
                if known.insert(x.clone()) {
                    refs.push(x.clone());
                }
            }
            edges.push(GraphEdge { id: format!("l{lid}"), source: a.key(), target: b.key(), rel_type: "linked".into(), label: "finding link".into(), directed: true, origin: origin.into(), verification: "verified".into(), confidence: "high".into(), relation_id: None, updated_at: at });
        }
    }
    let mut d = Describer::default();
    let mut nodes = Vec::with_capacity(refs.len());
    let mut gone: HashSet<String> = HashSet::new();
    for r in refs {
        match d.lookup(c, &r)? {
            Some((_, n)) => nodes.push(n),
            None => {
                gone.insert(r.key());
            }
        }
    }
    edges.retain(|e| !gone.contains(&e.source) && !gone.contains(&e.target));
    let mut g = Graph { nodes, edges, truncated };
    if let Some(focus) = f.focus.as_deref() {
        let keep = neighborhood(&g, focus, f.depth.unwrap_or(2).clamp(1, 6));
        g.nodes.retain(|n| keep.contains(&n.key));
        g.edges.retain(|e| keep.contains(&e.source) && keep.contains(&e.target));
    }
    Ok(g)
}

/// The records within `depth` steps of a record, and a shortest path between two, over a graph's
/// edges (rejected and pending relationships count only if they are in the graph).
pub fn neighborhood(g: &Graph, start: &str, depth: usize) -> HashSet<String> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &g.edges {
        adj.entry(e.source.as_str()).or_default().push(e.target.as_str());
        adj.entry(e.target.as_str()).or_default().push(e.source.as_str());
    }
    let mut seen: HashSet<String> = HashSet::from([start.to_string()]);
    let mut queue: VecDeque<(&str, usize)> = VecDeque::from([(start, 0)]);
    while let Some((n, d)) = queue.pop_front() {
        if d >= depth {
            continue;
        }
        for &m in adj.get(n).map(Vec::as_slice).unwrap_or(&[]) {
            if seen.insert(m.to_string()) {
                queue.push_back((m, d + 1));
            }
        }
    }
    seen
}

pub fn shortest_path(g: &Graph, from: &str, to: &str) -> Option<Vec<String>> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &g.edges {
        adj.entry(e.source.as_str()).or_default().push(e.target.as_str());
        adj.entry(e.target.as_str()).or_default().push(e.source.as_str());
    }
    let mut prev: HashMap<&str, &str> = HashMap::new();
    let mut queue: VecDeque<&str> = VecDeque::from([from]);
    let mut seen: HashSet<&str> = HashSet::from([from]);
    while let Some(n) = queue.pop_front() {
        if n == to {
            let mut path = vec![to.to_string()];
            let mut cur = to;
            while let Some(&p) = prev.get(cur) {
                path.push(p.to_string());
                cur = p;
            }
            path.reverse();
            return Some(path);
        }
        for &m in adj.get(n).map(Vec::as_slice).unwrap_or(&[]) {
            if seen.insert(m) {
                prev.insert(m, n);
                queue.push_back(m);
            }
        }
    }
    None
}

/// JSON of the graph for export: every node with its kind, every edge with its provenance.
pub fn export_json(project: &str, generated: &str, g: &Graph) -> String {
    let v = serde_json::json!({
        "format": "cyberhub-investigation-graph",
        "version": 1,
        "project": project,
        "exportedAt": generated,
        "nodes": g.nodes.iter().map(|n| serde_json::json!({ "id": n.key, "kind": n.r.kind, "label": n.label, "detail": n.detail })).collect::<Vec<Value>>(),
        "edges": g.edges.iter().map(|e| serde_json::json!({ "source": e.source, "target": e.target, "type": e.rel_type, "origin": e.origin, "verification": e.verification, "confidence": e.confidence })).collect::<Vec<Value>>(),
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

#[cfg(test)]
#[path = "relations_tests.rs"]
mod tests;
