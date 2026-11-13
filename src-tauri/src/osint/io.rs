//! Graph export (native JSON, GraphML, CSV) and import (native JSON, GraphML) with validation.
//!
//! Imports never overwrite anything: they create a new graph (and, if requested, a new
//! investigation) and feed every element through the normal mapping pipeline, so entities are
//! normalized and resolved like collected data. Analyst decisions found in a file are recorded
//! as metadata but not adopted: imported elements start as observed (or inferred).

use std::collections::{BTreeMap, HashMap, HashSet};

use quick_xml::events::Event;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::ingest::{self, EntityInput, EvidenceInput, Observation, Origin, RelationshipInput};
use super::model::{self, EntityType, Strength};
use super::store::{self, GraphNodeState};
use crate::error::AppResult;
use crate::util::now;

pub const FORMAT: &str = "cyberhub-osint-graph";
pub const FORMAT_VERSION: u32 = 1;
pub const MAX_IMPORT_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_IMPORT_ENTITIES: usize = 20_000;
pub const MAX_IMPORT_RELATIONSHIPS: usize = 60_000;
pub const MAX_IMPORT_EVIDENCE: usize = 60_000;

/* ───────────────────────── native JSON ───────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XEntity {
    pub id: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    #[serde(default)]
    pub verification: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub flagged: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XRelationship {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub rel_type: String,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub verification: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub confidence_reason: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    /// evidence id → strength
    #[serde(default)]
    pub evidence: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XEvidence {
    pub id: String,
    pub kind: String,
    pub source: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub observed_at: Option<String>,
    #[serde(default)]
    pub collected_at: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub strength: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XGraph {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub workspace: Value,
    /// entity id → node state (positions etc.)
    #[serde(default)]
    pub nodes: Vec<XNode>,
    #[serde(default)]
    pub latest_version: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XNode {
    pub entity: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XInvestigation {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub target_type: String,
    pub target_value: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub exported_at: Option<String>,
    pub investigation: XInvestigation,
    pub graph: XGraph,
    pub entities: Vec<XEntity>,
    #[serde(default)]
    pub relationships: Vec<XRelationship>,
    #[serde(default)]
    pub evidence: Vec<XEvidence>,
}

/// Native export of a graph: its entities, the relationships among them, their evidence and the
/// workspace. Original identifiers are kept as strings so the file can be re-imported.
pub fn export_document(c: &Connection, graph: i64) -> AppResult<Document> {
    let data = store::graph_load(c, graph, false)?;
    let inv = store::investigation_get(c, data.graph.investigation_id)?;
    let ids: Vec<i64> = data.nodes.iter().map(|n| n.entity_id).collect();
    let mut entities = vec![];
    let mut evidence_ids: HashSet<i64> = HashSet::new();
    for id in &ids {
        let (t, v, d, a, m, ver, conf, fl, notes, fs, ls): (String, String, String, String, String, String, String, i64, String, String, String) = c.query_row(
            "SELECT type, value, display_name, aliases, metadata, verification, confidence, flagged, notes, first_seen, last_seen FROM osint_entities WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?)),
        )?;
        let ev: Vec<i64> = {
            let mut st = c.prepare("SELECT evidence_id FROM osint_entity_evidence WHERE entity_id = ?1")?;
            let v = st.query_map(params![id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
            v
        };
        evidence_ids.extend(ev.iter().copied());
        entities.push(XEntity {
            id: id.to_string(),
            entity_type: t,
            value: v,
            display_name: Some(d),
            aliases: serde_json::from_str(&a).unwrap_or_default(),
            metadata: serde_json::from_str(&m).unwrap_or_default(),
            verification: Some(ver),
            confidence: Some(conf),
            flagged: fl != 0,
            notes: Some(notes),
            first_seen: Some(fs),
            last_seen: Some(ls),
            evidence: ev.iter().map(|e| e.to_string()).collect(),
        });
    }
    let mut relationships = vec![];
    for r in &data.relationships {
        let (reason, meta, fs, ls): (String, String, String, String) =
            c.query_row("SELECT confidence_reason, metadata, first_seen, last_seen FROM osint_relationships WHERE id = ?1", params![r.id], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)))?;
        let ev: Vec<(i64, String)> = {
            let mut st = c.prepare("SELECT evidence_id, strength FROM osint_relationship_evidence WHERE relationship_id = ?1")?;
            let v = st.query_map(params![r.id], |x| Ok((x.get(0)?, x.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
            v
        };
        evidence_ids.extend(ev.iter().map(|(e, _)| *e));
        relationships.push(XRelationship {
            id: r.id.to_string(),
            source: r.source.to_string(),
            target: r.target.to_string(),
            rel_type: r.rel_type.clone(),
            origin: Some(r.origin.clone()),
            verification: Some(r.verification.clone()),
            confidence: Some(r.confidence.clone()),
            confidence_reason: Some(reason),
            metadata: serde_json::from_str(&meta).unwrap_or_default(),
            first_seen: Some(fs),
            last_seen: Some(ls),
            evidence: ev.into_iter().map(|(e, s)| (e.to_string(), s)).collect(),
        });
    }
    let mut evidence = vec![];
    let mut ev_sorted: Vec<i64> = evidence_ids.into_iter().collect();
    ev_sorted.sort();
    for id in ev_sorted {
        let e: XEvidence = c.query_row(
            "SELECT kind, source, reference, observed_at, collected_at, summary, data, strength FROM osint_evidence WHERE id = ?1",
            params![id],
            |r| {
                Ok(XEvidence {
                    id: id.to_string(),
                    kind: r.get(0)?,
                    source: r.get(1)?,
                    reference: r.get(2)?,
                    observed_at: r.get(3)?,
                    collected_at: r.get(4)?,
                    summary: r.get(5)?,
                    data: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
                    strength: r.get(7)?,
                })
            },
        )?;
        evidence.push(e);
    }
    Ok(Document {
        format: FORMAT.into(),
        version: FORMAT_VERSION,
        exported_at: Some(now()),
        investigation: XInvestigation { name: inv.name, description: inv.description, target_type: inv.target_type, target_value: inv.target_value, tags: inv.tags },
        graph: XGraph {
            name: data.graph.name,
            description: data.graph.description,
            workspace: data.workspace,
            nodes: data.nodes.iter().map(|n| XNode { entity: n.entity_id.to_string(), x: n.x, y: n.y, pinned: n.pinned, hidden: n.hidden, group: n.group.clone() }).collect(),
            latest_version: data.graph.latest_version,
        },
        entities,
        relationships,
        evidence,
    })
}

/* ───────────────────────── GraphML ───────────────────────── */

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

const NODE_KEYS: &[&str] = &["type", "value", "label", "verification", "confidence", "flagged", "x", "y"];
const EDGE_KEYS: &[&str] = &["type", "verification", "confidence", "origin"];

pub fn export_graphml(doc: &Document) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    for k in NODE_KEYS {
        let ty = if matches!(*k, "x" | "y") { "double" } else if *k == "flagged" { "boolean" } else { "string" };
        s.push_str(&format!("  <key id=\"n_{k}\" for=\"node\" attr.name=\"{k}\" attr.type=\"{ty}\"/>\n"));
    }
    for k in EDGE_KEYS {
        s.push_str(&format!("  <key id=\"e_{k}\" for=\"edge\" attr.name=\"{k}\" attr.type=\"string\"/>\n"));
    }
    s.push_str(&format!("  <graph id=\"{}\" edgedefault=\"directed\">\n", xml_escape(&doc.graph.name)));
    let pos: HashMap<&str, &XNode> = doc.graph.nodes.iter().map(|n| (n.entity.as_str(), n)).collect();
    for e in &doc.entities {
        s.push_str(&format!("    <node id=\"n{}\">\n", xml_escape(&e.id)));
        let mut data = |k: &str, v: &str| s.push_str(&format!("      <data key=\"n_{k}\">{}</data>\n", xml_escape(v)));
        data("type", &e.entity_type);
        data("value", &e.value);
        data("label", e.display_name.as_deref().unwrap_or(&e.value));
        data("verification", e.verification.as_deref().unwrap_or("observed"));
        data("confidence", e.confidence.as_deref().unwrap_or(""));
        data("flagged", if e.flagged { "true" } else { "false" });
        if let Some(n) = pos.get(e.id.as_str()) {
            if let (Some(x), Some(y)) = (n.x, n.y) {
                data("x", &x.to_string());
                data("y", &y.to_string());
            }
        }
        s.push_str("    </node>\n");
    }
    for r in &doc.relationships {
        s.push_str(&format!("    <edge id=\"e{}\" source=\"n{}\" target=\"n{}\" directed=\"{}\">\n", xml_escape(&r.id), xml_escape(&r.source), xml_escape(&r.target), model::is_directed(&r.rel_type)));
        for (k, v) in [("type", Some(r.rel_type.as_str())), ("verification", r.verification.as_deref()), ("confidence", r.confidence.as_deref()), ("origin", r.origin.as_deref())] {
            s.push_str(&format!("      <data key=\"e_{k}\">{}</data>\n", xml_escape(v.unwrap_or(""))));
        }
        s.push_str("    </edge>\n");
    }
    s.push_str("  </graph>\n</graphml>\n");
    s
}

/// Parse GraphML into a native document. Attribute keys are matched by `attr.name`; nodes need
/// `type` and `value` (or at least a label, imported as type "other").
pub fn parse_graphml(text: &str) -> Result<Document, String> {
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut keys: HashMap<String, String> = HashMap::new(); // key id → attr.name
    let mut nodes: NodeAcc = vec![];
    let mut edges: EdgeAcc = vec![];
    let mut graph_name = String::from("Imported graph");
    let mut current: Option<(bool, usize)> = None; // (is_node, index)
    let mut data_key: Option<String> = None;
    let mut depth = 0usize;
    loop {
        let ev = reader.read_event().map_err(|e| format!("Invalid XML at byte {}: {e}", reader.buffer_position()))?;
        match ev {
            Event::Eof => break,
            Event::DocType(_) => return Err("GraphML files with a DOCTYPE are not accepted".into()),
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_empty = matches!(ev, Event::Empty(_));
                if !is_empty {
                    depth += 1;
                    if depth > 64 {
                        return Err("The document is nested too deeply".into());
                    }
                }
                let mut attrs: HashMap<String, String> = HashMap::new();
                for a in e.attributes() {
                    let a = a.map_err(|e| format!("Invalid attribute: {e}"))?;
                    let k = a.key.local_name().into_inner().to_string();
                    let v = a.normalized_value(quick_xml::XmlVersion::default()).map_err(|e| format!("Invalid attribute value: {e}"))?.to_string();
                    attrs.insert(k, v);
                }
                match e.local_name().into_inner() {
                    "key" => {
                        if let (Some(id), Some(name)) = (attrs.get("id"), attrs.get("attr.name").or(attrs.get("name"))) {
                            keys.insert(id.clone(), name.clone());
                        }
                    }
                    "graph" => {
                        if let Some(id) = attrs.get("id") {
                            graph_name = id.chars().take(120).collect();
                        }
                    }
                    "node" => {
                        let id = attrs.get("id").cloned().ok_or("A node has no id")?;
                        nodes.push((id, HashMap::new()));
                        current = (!is_empty).then_some((true, nodes.len() - 1));
                    }
                    "edge" => {
                        let (Some(s), Some(t)) = (attrs.get("source"), attrs.get("target")) else { return Err("An edge has no source or target".into()) };
                        let id = attrs.get("id").cloned().unwrap_or_else(|| format!("edge{}", edges.len()));
                        edges.push((id, s.clone(), t.clone(), HashMap::new()));
                        current = (!is_empty).then_some((false, edges.len() - 1));
                    }
                    "data" => data_key = attrs.get("key").map(|k| keys.get(k).cloned().unwrap_or_else(|| k.clone())),
                    _ => {}
                }
                if nodes.len() > MAX_IMPORT_ENTITIES || edges.len() > MAX_IMPORT_RELATIONSHIPS {
                    return Err("The file has more elements than can be imported".into());
                }
            }
            Event::Text(t) => push_text(&data_key, current, &mut nodes, &mut edges, &t.xml10_content()),
            Event::CData(t) => push_text(&data_key, current, &mut nodes, &mut edges, &t.xml10_content()),
            Event::GeneralRef(r) => {
                let ch = match r.resolve_char_ref().map_err(|e| format!("Invalid character reference: {e}"))? {
                    Some(c) => c.to_string(),
                    None => match r.xml10_content().as_ref() {
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "amp" => "&".into(),
                        "quot" => "\"".into(),
                        "apos" => "'".into(),
                        other => return Err(format!("Unknown entity &{};", other.chars().take(20).collect::<String>())),
                    },
                };
                push_text(&data_key, current, &mut nodes, &mut edges, &ch);
            }
            Event::End(ref e) => {
                depth = depth.saturating_sub(1);
                match e.local_name().into_inner() {
                    "data" => data_key = None,
                    "node" | "edge" => current = None,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let mut first_type = None;
    let entities: Vec<XEntity> = nodes
        .iter()
        .map(|(id, d)| {
            let (t, v) = match (d.get("type"), d.get("value")) {
                (Some(t), Some(v)) => (t.clone(), v.clone()),
                _ => ("other".into(), d.get("label").or(d.get("value")).cloned().unwrap_or_else(|| id.clone())),
            };
            first_type.get_or_insert((t.clone(), v.clone()));
            XEntity {
                id: id.clone(),
                entity_type: t,
                value: v,
                display_name: d.get("label").cloned(),
                aliases: vec![],
                metadata: Map::new(),
                verification: d.get("verification").cloned(),
                confidence: None,
                flagged: d.get("flagged").is_some_and(|f| f == "true"),
                notes: None,
                first_seen: None,
                last_seen: None,
                evidence: vec![],
            }
        })
        .collect();
    let graph_nodes = nodes
        .iter()
        .map(|(id, d)| XNode { entity: id.clone(), x: d.get("x").and_then(|v| v.parse().ok()), y: d.get("y").and_then(|v| v.parse().ok()), pinned: false, hidden: false, group: None })
        .collect();
    let relationships = edges
        .into_iter()
        .map(|(id, s, t, d)| XRelationship {
            id,
            source: s,
            target: t,
            rel_type: d.get("type").cloned().unwrap_or_else(|| "ASSOCIATED_WITH".into()),
            origin: None,
            verification: d.get("verification").cloned(),
            confidence: None,
            confidence_reason: None,
            metadata: Map::new(),
            first_seen: None,
            last_seen: None,
            evidence: vec![],
        })
        .collect();
    let (tt, tv) = first_type.unwrap_or(("other".into(), "imported".into()));
    Ok(Document {
        format: FORMAT.into(),
        version: FORMAT_VERSION,
        exported_at: None,
        investigation: XInvestigation { name: graph_name.clone(), description: "Imported from GraphML".into(), target_type: tt, target_value: tv, tags: vec![] },
        graph: XGraph { name: graph_name, description: String::new(), workspace: json!({}), nodes: graph_nodes, latest_version: None },
        entities,
        relationships,
        evidence: vec![],
    })
}

type NodeAcc = Vec<(String, HashMap<String, String>)>;
type EdgeAcc = Vec<(String, String, String, HashMap<String, String>)>;

/// Append character data to the current `<data>` value (text and entity references arrive as
/// separate events).
fn push_text(key: &Option<String>, current: Option<(bool, usize)>, nodes: &mut NodeAcc, edges: &mut EdgeAcc, text: &str) {
    if let (Some(k), Some((is_node, i))) = (key, current) {
        let map = if is_node { &mut nodes[i].1 } else { &mut edges[i].3 };
        let v = map.entry(k.clone()).or_default();
        if v.len() < 4096 {
            v.extend(text.chars().take(4096 - v.len().min(4096)));
        }
    }
}

/* ───────────────────────── CSV ───────────────────────── */

/// CSV cell: quoted, and neutralised when a spreadsheet would treat it as a formula.
pub fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// UTF-8 byte order mark: spreadsheet applications (Excel) otherwise read CSV in the local ANSI
/// code page and garble non-ASCII values.
const CSV_BOM: &str = "\u{feff}";

pub fn export_csv_entities(doc: &Document) -> String {
    let mut out = String::from(CSV_BOM);
    out.push_str("id,type,value,display_name,verification,confidence,flagged,first_seen,last_seen,aliases\n");
    for e in &doc.entities {
        let row = [
            e.id.clone(),
            e.entity_type.clone(),
            e.value.clone(),
            e.display_name.clone().unwrap_or_default(),
            e.verification.clone().unwrap_or_default(),
            e.confidence.clone().unwrap_or_default(),
            e.flagged.to_string(),
            e.first_seen.clone().unwrap_or_default(),
            e.last_seen.clone().unwrap_or_default(),
            e.aliases.join(" | "),
        ];
        out.push_str(&row.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

pub fn export_csv_relationships(doc: &Document) -> String {
    let values: HashMap<&str, &str> = doc.entities.iter().map(|e| (e.id.as_str(), e.value.as_str())).collect();
    let mut out = String::from(CSV_BOM);
    out.push_str("id,source_id,source,type,target_id,target,verification,confidence,origin,evidence_count,confidence_reason\n");
    for r in &doc.relationships {
        let row = [
            r.id.clone(),
            r.source.clone(),
            values.get(r.source.as_str()).unwrap_or(&"").to_string(),
            r.rel_type.clone(),
            r.target.clone(),
            values.get(r.target.as_str()).unwrap_or(&"").to_string(),
            r.verification.clone().unwrap_or_default(),
            r.confidence.clone().unwrap_or_default(),
            r.origin.clone().unwrap_or_default(),
            r.evidence.len().to_string(),
            r.confidence_reason.clone().unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/* ───────────────────────── import ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub format: String,
    pub graph_name: String,
    pub investigation_name: String,
    pub target: String,
    pub entities: usize,
    pub relationships: usize,
    pub evidence: usize,
    pub by_type: BTreeMap<String, usize>,
    /// problems that will skip individual elements
    pub warnings: Vec<String>,
    /// entities that already exist in the chosen investigation (when one was given)
    pub existing_matches: usize,
}

/// Parse bytes in the given format and validate structure. Fatal problems are errors.
pub fn parse(bytes: &[u8], format: &str) -> Result<Document, String> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(format!("The file is larger than {} MB", MAX_IMPORT_BYTES / 1024 / 1024));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "The file is not UTF-8 text".to_string())?;
    let doc = match format {
        "json" => {
            let doc: Document = serde_json::from_str(text).map_err(|e| format!("Not an ExploitX graph file: {e}"))?;
            if doc.format != FORMAT {
                return Err("Not an ExploitX graph file".into());
            }
            if doc.version > FORMAT_VERSION {
                return Err(format!("The file was written by a newer ExploitX (format {}); this version reads format {FORMAT_VERSION}", doc.version));
            }
            doc
        }
        "graphml" => parse_graphml(text)?,
        _ => return Err("Unsupported format".into()),
    };
    if doc.entities.is_empty() {
        return Err("The file contains no entities".into());
    }
    if doc.entities.len() > MAX_IMPORT_ENTITIES || doc.relationships.len() > MAX_IMPORT_RELATIONSHIPS || doc.evidence.len() > MAX_IMPORT_EVIDENCE {
        return Err("The file has more elements than can be imported".into());
    }
    let dup = |ids: Vec<&str>| {
        let mut seen = HashSet::new();
        ids.into_iter().find(|i| !seen.insert(*i)).map(String::from)
    };
    if let Some(d) = dup(doc.entities.iter().map(|e| e.id.as_str()).collect()) {
        return Err(format!("Duplicate entity id \"{}\"", d.chars().take(60).collect::<String>()));
    }
    if let Some(d) = dup(doc.relationships.iter().map(|r| r.id.as_str()).collect()) {
        return Err(format!("Duplicate relationship id \"{}\"", d.chars().take(60).collect::<String>()));
    }
    if let Some(d) = dup(doc.evidence.iter().map(|e| e.id.as_str()).collect()) {
        return Err(format!("Duplicate evidence id \"{}\"", d.chars().take(60).collect::<String>()));
    }
    Ok(doc)
}

pub fn preview(c: &Connection, doc: &Document, format: &str, investigation: Option<i64>) -> AppResult<ImportPreview> {
    let mut warnings = vec![];
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut existing = 0;
    let ids: HashSet<&str> = doc.entities.iter().map(|e| e.id.as_str()).collect();
    for e in &doc.entities {
        match EntityType::parse(&e.entity_type) {
            None => warnings.push(format!("Unknown entity type \"{}\" ({}) will be skipped", clip(&e.entity_type), clip(&e.value))),
            Some(t) => match super::normalize::normalize(t, &e.value) {
                Err(why) => warnings.push(format!("{} \"{}\" will be skipped: {why}", t.as_str(), clip(&e.value))),
                Ok(n) => {
                    *by_type.entry(t.as_str().to_string()).or_default() += 1;
                    if let Some(inv) = investigation {
                        let found: i64 = c.query_row("SELECT COUNT(*) FROM osint_entities WHERE investigation_id = ?1 AND type = ?2 AND match_key = ?3", params![inv, t.as_str(), n.key], |r| r.get(0))?;
                        existing += found as usize;
                    }
                }
            },
        }
    }
    for r in &doc.relationships {
        if !ids.contains(r.source.as_str()) || !ids.contains(r.target.as_str()) {
            warnings.push(format!("Relationship {} refers to a missing entity and will be skipped", clip(&r.id)));
        } else if !model::is_valid_type(&r.rel_type) {
            warnings.push(format!("Relationship type \"{}\" is not valid and will be skipped", clip(&r.rel_type)));
        }
    }
    if doc.relationships.iter().any(|r| r.verification.as_deref().is_some_and(|v| v == "verified" || v == "disputed" || v == "rejected")) {
        warnings.push("Analyst decisions in the file (verified, disputed, rejected) are kept as notes; imported elements start unverified.".into());
    }
    warnings.truncate(200);
    Ok(ImportPreview {
        format: format.into(),
        graph_name: doc.graph.name.clone(),
        investigation_name: doc.investigation.name.clone(),
        target: format!("{}: {}", doc.investigation.target_type, doc.investigation.target_value),
        entities: doc.entities.len(),
        relationships: doc.relationships.len(),
        evidence: doc.evidence.len(),
        by_type,
        warnings,
        existing_matches: existing,
    })
}

fn clip(s: &str) -> String {
    s.chars().take(80).collect()
}

/// Apply an import: into an existing investigation (entities resolve against it) or a new one.
/// Always creates a new graph. Returns (investigation id, graph id).
pub fn apply(c: &Connection, doc: &Document, into: Option<i64>, graph_name: &str, file_label: &str) -> AppResult<(i64, i64)> {
    let inv = match into {
        Some(id) => {
            store::investigation_get(c, id)?;
            id
        }
        None => {
            let t = EntityType::parse(&doc.investigation.target_type).filter(|t| t.is_target_type()).map(|t| t.as_str()).unwrap_or("other");
            let value = if super::normalize::normalize(EntityType::parse(t).unwrap_or(EntityType::Other), &doc.investigation.target_value).is_ok() { doc.investigation.target_value.clone() } else { "imported".into() };
            let id = store::investigation_create(
                c,
                &store::InvestigationInput {
                    // a distinct name: the original investigation usually still exists next to the copy
                    name: if doc.investigation.name.trim().is_empty() { "Imported investigation".into() } else { format!("{} (imported)", doc.investigation.name.trim().chars().take(105).collect::<String>()) },
                    description: format!("Imported from {file_label}. {}", doc.investigation.description.chars().take(3000).collect::<String>()),
                    target_type: t.into(),
                    target_value: value,
                    tags: doc.investigation.tags.iter().take(30).map(|t| t.chars().take(40).collect()).collect(),
                    notes: String::new(),
                    authorization: String::new(),
                    project_id: None,
                },
            )?;
            id
        }
    };
    // evidence groups: each evidence record becomes one observation with the entities and
    // relationships it supports; elements without evidence share one "import" evidence. An id
    // that names no record joins that group too: it was a group of its own with the same
    // synthetic evidence, one full ingest per listed id (Mission 6). Each element joins each
    // group once, however often the file lists the id.
    let entity_idx: HashMap<&str, &XEntity> = doc.entities.iter().map(|e| (e.id.as_str(), e)).collect();
    let evidence_idx: HashMap<&str, &XEvidence> = doc.evidence.iter().map(|e| (e.id.as_str(), e)).collect();
    type Group<'a> = (Vec<&'a XEntity>, Vec<(&'a XRelationship, Strength)>);
    let mut by_evidence: BTreeMap<String, Group> = BTreeMap::new();
    let import_key = "\u{0}import".to_string();
    let group_of = |id: &str| if evidence_idx.contains_key(id) { id.to_string() } else { import_key.clone() };
    for e in &doc.entities {
        let mut keys: HashSet<String> = HashSet::new();
        if e.evidence.is_empty() {
            keys.insert(import_key.clone());
        }
        for ev in &e.evidence {
            let k = group_of(ev);
            if keys.insert(k.clone()) {
                by_evidence.entry(k).or_default().0.push(e);
            }
        }
        if e.evidence.is_empty() {
            by_evidence.entry(import_key.clone()).or_default().0.push(e);
        }
    }
    for r in &doc.relationships {
        if r.evidence.is_empty() {
            by_evidence.entry(import_key.clone()).or_default().1.push((r, Strength::Corroborating));
        }
        let mut keys: HashSet<String> = HashSet::new();
        for (ev, st) in &r.evidence {
            let k = group_of(ev);
            if keys.insert(k.clone()) {
                by_evidence.entry(k).or_default().1.push((r, Strength::parse(st).unwrap_or(Strength::Corroborating)));
            }
        }
    }
    let mut new_ids: HashMap<String, i64> = HashMap::new();
    let mut deferred = ingest::Deferred::default();
    for (key, (ents, rels)) in by_evidence {
        let evidence = match evidence_idx.get(key.as_str()) {
            Some(e) => EvidenceInput {
                kind: e.kind.chars().take(40).collect(),
                source: e.source.chars().take(60).collect(),
                reference: e.reference.clone().map(|r| r.chars().take(2000).collect()),
                observed_at: e.observed_at.clone(),
                summary: format!("{} [imported from {file_label}]", e.summary),
                data: e.data.clone(),
                strength: e.strength.as_deref().and_then(Strength::parse).unwrap_or(Strength::Corroborating),
                operation_id: None,
                execution_id: None,
            },
            None => EvidenceInput { kind: "import".into(), source: "import".into(), reference: None, observed_at: None, summary: format!("Imported from {file_label} without recorded evidence"), data: json!({}), strength: Strength::Corroborating, operation_id: None, execution_id: None },
        };
        // entities of this group plus relationship endpoints (each once, found through a set)
        let mut local: Vec<&XEntity> = Vec::with_capacity(ents.len());
        let mut in_local: HashSet<&str> = HashSet::new();
        for e in ents.iter().copied() {
            if in_local.insert(e.id.as_str()) {
                local.push(e);
            }
        }
        for (r, _) in &rels {
            for id in [&r.source, &r.target] {
                if let Some(e) = entity_idx.get(id.as_str()) {
                    if in_local.insert(e.id.as_str()) {
                        local.push(e);
                    }
                }
            }
        }
        let mut inputs = vec![];
        let mut pos: HashMap<&str, usize> = HashMap::new();
        for e in &local {
            let Some(t) = EntityType::parse(&e.entity_type) else { continue };
            let mut metadata = e.metadata.clone();
            metadata.retain(|k, _| k.len() <= 64);
            if let Some(v) = e.verification.as_deref().filter(|v| *v != "observed") {
                metadata.insert("importedVerification".into(), json!(v));
            }
            pos.insert(e.id.as_str(), inputs.len());
            inputs.push(EntityInput { entity_type: t, value: e.value.clone(), display_name: e.display_name.clone(), metadata, flagged: e.flagged });
        }
        let relationships = rels
            .iter()
            .filter_map(|(r, st)| {
                let (s, t) = (*pos.get(r.source.as_str())?, *pos.get(r.target.as_str())?);
                // links the file marks as unreviewed, disputed or rejected come back as inferred
                // (they wait for review) instead of reappearing as plain observations
                let inferred = matches!(r.verification.as_deref(), Some("inferred" | "disputed" | "rejected")) || matches!(r.origin.as_deref(), Some("inferred" | "suggested"));
                let mut metadata = r.metadata.clone();
                if let Some(v) = r.verification.as_deref() {
                    metadata.insert("importedVerification".into(), json!(v));
                }
                Some(RelationshipInput { source: s, target: t, rel_type: r.rel_type.clone(), strength: *st, origin: if inferred { Origin::Inferred } else { Origin::Observed }, metadata })
            })
            .collect();
        let summary = ingest::ingest_deferred(c, inv, &Observation { evidence, entities: inputs, relationships }, &mut deferred)?;
        let _ = summary;
        // map file ids → database ids
        for e in &local {
            if let Some(t) = EntityType::parse(&e.entity_type) {
                if let Ok(n) = super::normalize::normalize(t, &e.value) {
                    if let Ok(id) = c.query_row("SELECT id FROM osint_entities WHERE investigation_id = ?1 AND type = ?2 AND match_key = ?3", params![inv, t.as_str(), n.key], |r| r.get::<_, i64>(0)) {
                        new_ids.insert(e.id.clone(), id);
                    }
                }
            }
        }
    }
    deferred.finish(c)?;
    let name = if graph_name.trim().is_empty() { doc.graph.name.clone() } else { graph_name.to_string() };
    let graph = store::graph_create(c, inv, &name.chars().take(120).collect::<String>(), &format!("Imported from {file_label}"), false)?;
    let nodes: Vec<GraphNodeState> = doc
        .graph
        .nodes
        .iter()
        .filter_map(|n| {
            let id = *new_ids.get(&n.entity)?;
            Some(GraphNodeState { entity_id: id, x: n.x.filter(|v| v.is_finite() && v.abs() < 1e7), y: n.y.filter(|v| v.is_finite() && v.abs() < 1e7), pinned: n.pinned, hidden: n.hidden, group: n.group.clone().map(|g| g.chars().take(64).collect()) })
        })
        .chain(new_ids.values().map(|id| GraphNodeState { entity_id: *id, x: None, y: None, pinned: false, hidden: false, group: None }))
        .fold((Vec::<GraphNodeState>::new(), HashSet::<i64>::new()), |(mut acc, mut seen), n| {
            if seen.insert(n.entity_id) {
                acc.push(n);
            }
            (acc, seen)
        })
        .0;
    let workspace = if doc.graph.workspace.is_object() && doc.graph.workspace.to_string().len() < store::MAX_WORKSPACE_BYTES { doc.graph.workspace.clone() } else { json!({}) };
    store::graph_save(c, graph, &store::GraphSave { base_revision: 0, nodes, removed: vec![], workspace, version_label: Some(format!("Imported from {file_label}")), manual_version: true, base_state_revision: None, force: false })?;
    ingest::event(c, inv, "import", &format!("Graph \"{name}\" imported from {file_label}: {} entities, {} relationships", new_ids.len(), doc.relationships.len()), Some("import"), None, None, None, Some(graph), json!({}))?;
    Ok((inv, graph))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::osint::ingest::tests::{ent, ev, rel, run};

    fn sample() -> (Db, i64, i64) {
        let db = Db::open_in_memory().unwrap();
        let (inv, g) = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let inv = store::investigation_create(&tx, &store::InvestigationInput { name: "Acme <x>".into(), description: String::new(), target_type: "domain".into(), target_value: "example.com".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })?;
                tx.commit()?;
                let g: i64 = c.query_row("SELECT id FROM osint_graphs WHERE investigation_id = ?1", params![inv], |r| r.get(0))?;
                Ok((inv, g))
            })
            .unwrap();
        run(&db, inv, &Observation { evidence: ev("dns", "A example.com"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34"), ent(EntityType::Organization, "=cmd|' /C calc'!A0")], relationships: vec![rel(0, 1, "RESOLVES_TO"), rel(0, 2, "REGISTERED_TO")] });
        db.with(|c| {
            let data = store::graph_load(c, g, false)?;
            let nodes: Vec<GraphNodeState> = data.nodes.iter().enumerate().map(|(i, n)| GraphNodeState { x: Some(i as f64 * 10.0), y: Some(5.0), ..n.clone() }).collect();
            store::graph_save(c, g, &store::GraphSave { base_revision: data.graph.revision, nodes, removed: vec![], workspace: json!({ "layout": "radial", "viewport": { "x": 0, "y": 0, "zoom": 1.2 } }), version_label: None, manual_version: false, base_state_revision: None, force: false })
        })
        .unwrap();
        (db, inv, g)
    }

    #[test]
    fn json_round_trip_restores_entities_relationships_evidence_and_layout() {
        let (db, _, g) = sample();
        let doc = db.with(|c| export_document(c, g)).unwrap();
        assert_eq!((doc.entities.len(), doc.relationships.len()), (3, 2));
        assert!(!doc.evidence.is_empty());
        let bytes = serde_json::to_vec(&doc).unwrap();
        let parsed = parse(&bytes, "json").unwrap();
        let (inv2, g2) = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let r = apply(&tx, &parsed, None, "", "test.json")?;
                tx.commit()?;
                Ok(r)
            })
            .unwrap();
        let data = db.with(|c| store::graph_load(c, g2, false)).unwrap();
        assert_eq!((data.entities.len(), data.relationships.len()), (3, 2));
        assert_eq!(data.workspace["layout"], "radial");
        assert_eq!(db.with(|c| store::investigation_get(c, inv2)).unwrap().name, "Acme <x> (imported)", "the copy is told apart from the original");
        assert!(data.nodes.iter().any(|n| n.x == Some(10.0)), "positions are restored");
        let refs: i64 = db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM osint_evidence WHERE investigation_id = ?1 AND source = 'dns'", params![inv2], |r| r.get(0))?)).unwrap();
        assert!(refs >= 1, "the original evidence source is kept");
        // importing the same file into the original investigation resolves to existing entities
        let (_, inv1_g) = (0, g);
        let before: i64 = db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM osint_graphs", [], |r| r.get(0))?)).unwrap();
        let orig_inv: i64 = db.with(|c| Ok(c.query_row("SELECT investigation_id FROM osint_graphs WHERE id = ?1", params![inv1_g], |r| r.get(0))?)).unwrap();
        let p = db.with(|c| preview(c, &parsed, "json", Some(orig_inv))).unwrap();
        assert_eq!(p.existing_matches, 3);
        db.with(|c| apply(c, &parsed, Some(orig_inv), "Copy", "test.json")).unwrap();
        assert_eq!(db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM osint_entities WHERE investigation_id = ?1", params![orig_inv], |r| r.get::<_, i64>(0))?)).unwrap(), 3, "no duplicates");
        assert_eq!(db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM osint_graphs", [], |r| r.get::<_, i64>(0))?)).unwrap(), before + 1, "a new graph, nothing overwritten");
    }

    #[test]
    fn graphml_and_csv_are_escaped_and_graphml_round_trips() {
        let (db, _, g) = sample();
        let doc = db.with(|c| export_document(c, g)).unwrap();
        let xml = export_graphml(&doc);
        assert!(xml.contains("Acme &lt;x&gt;") || !xml.contains("<x>"), "names are escaped");
        let back = parse(xml.as_bytes(), "graphml").unwrap();
        assert_eq!((back.entities.len(), back.relationships.len()), (3, 2));
        assert!(back.entities.iter().any(|e| e.entity_type == "ip" && e.value == "93.184.216.34"));
        assert!(back.graph.nodes.iter().any(|n| n.x.is_some()));
        let csv = export_csv_entities(&doc);
        assert!(csv.contains("\"'=cmd|' /C calc'!A0\""), "formulas are neutralised: {csv}");
        assert_eq!(export_csv_relationships(&doc).lines().count(), 3);
    }

    #[test]
    fn csv_is_marked_utf8_and_rejected_links_return_for_review() {
        let (db, _, g) = sample();
        let mut doc = db.with(|c| export_document(c, g)).unwrap();
        doc.entities[0].display_name = Some("Société Ünïcode 中文".into());
        let csv = export_csv_entities(&doc);
        assert!(csv.starts_with('\u{feff}'), "UTF-8 \u{feff} for spreadsheet applications");
        assert!(csv.contains("Société Ünïcode 中文"));
        assert!(export_csv_relationships(&doc).starts_with('\u{feff}'));
        // a relationship the file records as rejected comes back as inferred (needs review)
        doc.relationships[0].verification = Some("rejected".into());
        doc.relationships[1].verification = Some("verified".into());
        let parsed = parse(&serde_json::to_vec(&doc).unwrap(), "json").unwrap();
        let (_, g2) = db.with(|c| apply(c, &parsed, None, "", "t.json")).unwrap();
        let data = db.with(|c| store::graph_load(c, g2, false)).unwrap();
        let mut states: Vec<String> = data.relationships.iter().map(|r| r.verification.clone()).collect();
        states.sort();
        assert_eq!(states, vec!["inferred".to_string(), "observed".to_string()], "never verified, never silently observed when rejected");
    }

    #[test]
    fn invalid_imports_are_refused_or_reported() {
        assert!(parse(b"\xff\xfe", "json").is_err());
        assert!(parse(b"{\"format\":\"other\"}", "json").is_err());
        assert!(parse(br#"{"format":"cyberhub-osint-graph","version":99,"investigation":{"name":"x","targetType":"domain","targetValue":"a.com"},"graph":{"name":"g"},"entities":[{"id":"1","type":"domain","value":"a.com"}]}"#, "json").unwrap_err().contains("newer"));
        let dup = br#"{"format":"cyberhub-osint-graph","version":1,"investigation":{"name":"x","targetType":"domain","targetValue":"a.com"},"graph":{"name":"g"},"entities":[{"id":"1","type":"domain","value":"a.com"},{"id":"1","type":"ip","value":"192.0.2.1"}]}"#;
        assert!(parse(dup, "json").unwrap_err().contains("Duplicate entity id"));
        assert!(parse(&vec![b' '; MAX_IMPORT_BYTES + 1], "json").is_err());
        assert!(parse(b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><graphml/>", "graphml").is_err(), "no DTDs");
        assert!(parse(b"<graphml><graph><node></node></graph></graphml>", "graphml").is_err(), "node without id");
        let ok = br#"{"format":"cyberhub-osint-graph","version":1,"investigation":{"name":"x","targetType":"domain","targetValue":"a.com"},"graph":{"name":"g"},
            "entities":[{"id":"1","type":"domain","value":"a.com"},{"id":"2","type":"spaceship","value":"x"},{"id":"3","type":"ip","value":"not-an-ip"}],
            "relationships":[{"id":"r1","source":"1","target":"9","type":"RESOLVES_TO"},{"id":"r2","source":"1","target":"3","type":"bad type"},{"id":"r3","source":"1","target":"1","type":"ALIAS_OF","verification":"verified"}]}"#;
        let doc = parse(ok, "json").unwrap();
        let db = Db::open_in_memory().unwrap();
        let p = db.with(|c| preview(c, &doc, "json", None)).unwrap();
        assert_eq!(p.warnings.len(), 5, "{:?}", p.warnings);
        assert_eq!(p.by_type.get("domain"), Some(&1));
    }
}
