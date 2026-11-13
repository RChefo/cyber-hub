// SPDX-License-Identifier: Apache-2.0
//! The mapping pipeline. Every source (discovery providers, imported tool runs and lookups,
//! analyst edits, graph imports) hands an `Observation` to `ingest`, which:
//!
//! 1. stores the evidence once (deduplicated by fingerprint);
//! 2. normalizes every entity and resolves it against the investigation (exact match on the
//!    type-specific key; looser look-alikes are only reported as *possible* duplicates);
//! 3. creates missing entities and links them to the evidence;
//! 4. adds structural relationships that follow from the values themselves (URL → host,
//!    email → domain, service → host, subdomain → nearest known parent, address → network block);
//! 5. upserts the observed relationships without duplicating them;
//! 6. runs the correlation rules, which may only produce `inferred` relationships for review;
//! 7. recomputes confidence for everything it touched;
//! 8. records timeline events and adds new entities to graphs that follow the investigation.
//!
//! Nothing here ever promotes an element to `verified`; only analyst actions do.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::confidence;
use super::model::{self, EntityType, Strength, Verification};
use super::normalize::{self, normalize, Normalized};
use crate::util::now;

/// Correlation is skipped for infrastructure shared by more entities than this (CDNs, large
/// hosters, public name servers): it would connect everything and say nothing.
pub const SHARED_INFRA_FANOUT_LIMIT: usize = 25;
const MAX_EVIDENCE_SUMMARY: usize = 4000;
const MAX_EVIDENCE_DATA: usize = 64 * 1024;
const MAX_ALIASES: usize = 50;
const PER_ITEM_EVENT_LIMIT: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// reported by a source
    Observed,
    /// follows from the values themselves (subdomain, URL host)
    Derived,
    /// produced by a correlation rule
    Inferred,
    /// asserted by the analyst
    Manual,
    /// proposed by an automated assistant (e.g. an MCP client) for review
    Suggested,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Observed => "observed",
            Origin::Derived => "derived",
            Origin::Inferred => "inferred",
            Origin::Manual => "manual",
            Origin::Suggested => "suggested",
        }
    }
    fn initial_verification(self) -> Verification {
        match self {
            Origin::Observed | Origin::Derived => Verification::Observed,
            Origin::Manual => Verification::Verified,
            Origin::Inferred | Origin::Suggested => Verification::Inferred,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityInput {
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    pub value: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    /// a provider reports it as malicious or suspicious
    #[serde(default)]
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipInput {
    /// index into `Observation::entities`
    pub source: usize,
    pub target: usize,
    #[serde(rename = "type")]
    pub rel_type: String,
    pub strength: Strength,
    pub origin: Origin,
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceInput {
    /// provider_response, tool_run, lookup, manual, import, derived
    pub kind: String,
    /// provider or source id ("dns", "rdap", "crtsh", "nmap", "analyst", ...)
    pub source: String,
    /// original reference (URL of the record, run id...) when one exists; never invented
    #[serde(default)]
    pub reference: Option<String>,
    /// when the source observed the fact (defaults to collection time)
    #[serde(default)]
    pub observed_at: Option<String>,
    /// human-readable original observation
    pub summary: String,
    #[serde(default)]
    pub data: Value,
    /// default strength for entities taken from this evidence
    pub strength: Strength,
    #[serde(default)]
    pub operation_id: Option<i64>,
    #[serde(default)]
    pub execution_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub evidence: EvidenceInput,
    pub entities: Vec<EntityInput>,
    #[serde(default)]
    pub relationships: Vec<RelationshipInput>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSummary {
    pub evidence_id: Option<i64>,
    pub new_entities: Vec<i64>,
    pub updated_entities: Vec<i64>,
    pub new_relationships: Vec<i64>,
    pub updated_relationships: Vec<i64>,
    /// new relationships from correlation rules or suggestions, waiting for review
    pub inferred_relationships: Vec<i64>,
    /// values that could not be normalized (with the reason)
    pub rejected: Vec<String>,
}

impl ChangeSummary {
    pub fn is_empty(&self) -> bool {
        self.new_entities.is_empty() && self.updated_entities.is_empty() && self.new_relationships.is_empty() && self.updated_relationships.is_empty()
    }
    pub fn line(&self) -> String {
        format!(
            "{} new entit{}, {} updated; {} new relationship{} ({} inferred for review), {} updated",
            self.new_entities.len(),
            if self.new_entities.len() == 1 { "y" } else { "ies" },
            self.updated_entities.len(),
            self.new_relationships.len(),
            if self.new_relationships.len() == 1 { "" } else { "s" },
            self.inferred_relationships.len(),
            self.updated_relationships.len()
        )
    }
}

pub fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn bounded_json(v: &Value) -> String {
    let s = v.to_string();
    if s.len() <= MAX_EVIDENCE_DATA {
        s
    } else {
        json!({ "truncated": true, "bytes": s.len() }).to_string()
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Insert (or find) the evidence record.
pub fn store_evidence(c: &Connection, inv: i64, e: &EvidenceInput) -> rusqlite::Result<i64> {
    let data = bounded_json(&e.data);
    let summary = clip(&e.summary, MAX_EVIDENCE_SUMMARY);
    let fp = fingerprint(&[&e.kind, &e.source, e.reference.as_deref().unwrap_or(""), &summary, &data]);
    if let Some(id) = c.query_row("SELECT id FROM osint_evidence WHERE investigation_id = ?1 AND fingerprint = ?2", params![inv, fp], |r| r.get(0)).optional()? {
        return Ok(id);
    }
    let at = now();
    c.execute(
        "INSERT INTO osint_evidence (investigation_id, kind, source, reference, observed_at, collected_at, operation_id, execution_id, summary, data, strength, fingerprint)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![inv, e.kind, e.source, e.reference, e.observed_at.clone().unwrap_or_else(|| at.clone()), at, e.operation_id, e.execution_id, summary, data, e.strength.as_str(), fp],
    )?;
    Ok(c.last_insert_rowid())
}

struct Ctx<'a> {
    c: &'a Connection,
    inv: i64,
    at: String,
    summary: ChangeSummary,
    touched_entities: BTreeSet<i64>,
    touched_relationships: BTreeSet<i64>,
    new_entity_set: HashSet<i64>,
    /// entities whose structural relationships were already computed in this run
    structured: HashSet<i64>,
}

impl Ctx<'_> {
    /// Find or create an entity; returns its id.
    fn upsert_entity(&mut self, t: EntityType, n: &Normalized, raw: &str, input: Option<&EntityInput>, evidence: i64) -> rusqlite::Result<i64> {
        let existing: Option<(i64, String, String, i64)> = self
            .c
            .query_row(
                "SELECT id, aliases, metadata, flagged FROM osint_entities WHERE investigation_id = ?1 AND type = ?2 AND match_key = ?3",
                params![self.inv, t.as_str(), n.key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let flagged = input.is_some_and(|i| i.flagged);
        let id = match existing {
            Some((id, aliases, meta, was_flagged)) => {
                let mut aliases: Vec<String> = serde_json::from_str(&aliases).unwrap_or_default();
                let raw_t = raw.trim();
                if raw_t != n.value && !aliases.iter().any(|a| a == raw_t) && aliases.len() < MAX_ALIASES {
                    aliases.push(raw_t.to_string());
                }
                let mut meta: Map<String, Value> = serde_json::from_str(&meta).unwrap_or_default();
                // first observation wins for existing keys; the evidence keeps every original
                for (k, v) in n.metadata.iter().chain(input.map(|i| i.metadata.iter()).into_iter().flatten()) {
                    if !meta.contains_key(k) || meta[k].is_null() {
                        meta.insert(k.clone(), v.clone());
                    }
                }
                self.c.execute(
                    "UPDATE osint_entities SET last_seen = ?2, aliases = ?3, metadata = ?4, flagged = ?5 WHERE id = ?1",
                    params![id, self.at, serde_json::to_string(&aliases).unwrap_or_default(), Value::Object(meta).to_string(), (was_flagged != 0 || flagged) as i64],
                )?;
                if !self.new_entity_set.contains(&id) && !self.summary.updated_entities.contains(&id) {
                    self.summary.updated_entities.push(id);
                }
                id
            }
            None => {
                let mut meta = n.metadata.clone();
                if let Some(i) = input {
                    for (k, v) in &i.metadata {
                        meta.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                let display = input.and_then(|i| i.display_name.as_ref()).map(|d| clip(d.trim(), 200)).filter(|d| !d.is_empty()).unwrap_or_else(|| n.display.clone());
                let aliases: Vec<String> = if raw.trim() != n.value { vec![raw.trim().to_string()] } else { vec![] };
                self.c.execute(
                    "INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, aliases, metadata, verification, flagged, first_seen, last_seen)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,'observed',?8,?9,?9)",
                    params![self.inv, t.as_str(), n.value, n.key, display, serde_json::to_string(&aliases).unwrap_or_default(), Value::Object(meta).to_string(), flagged as i64, self.at],
                )?;
                let id = self.c.last_insert_rowid();
                self.summary.new_entities.push(id);
                self.new_entity_set.insert(id);
                id
            }
        };
        self.c.execute("INSERT OR IGNORE INTO osint_entity_evidence (entity_id, evidence_id) VALUES (?1, ?2)", params![id, evidence])?;
        self.touched_entities.insert(id);
        Ok(id)
    }

    /// Find or create a relationship and attach evidence. Analyst decisions are never overridden.
    #[allow(clippy::too_many_arguments)] // one argument per stored column
    fn upsert_relationship(&mut self, src: i64, tgt: i64, rel_type: &str, origin: Origin, strength: Strength, meta: &Map<String, Value>, evidence: i64) -> rusqlite::Result<Option<i64>> {
        if src == tgt || !model::is_valid_type(rel_type) {
            return Ok(None);
        }
        let directed = model::is_directed(rel_type);
        // undirected relationships are stored once, in a canonical order
        let (s, t) = if directed { (src, tgt) } else { (src.min(tgt), src.max(tgt)) };
        let existing: Option<(i64, String, String)> = self
            .c
            .query_row(
                "SELECT id, verification, origin FROM osint_relationships WHERE investigation_id = ?1 AND source_id = ?2 AND target_id = ?3 AND type = ?4",
                params![self.inv, s, t, rel_type],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let id = match existing {
            Some((id, ver, old_origin)) => {
                let ver = Verification::parse(&ver).unwrap_or(Verification::Observed);
                // an inferred link that a source now reports directly becomes observed;
                // verified / disputed / rejected are analyst decisions and stay
                let promote = ver == Verification::Inferred && matches!(origin, Origin::Observed | Origin::Derived) && strength != Strength::Weak;
                let new_origin = if promote { origin.as_str().to_string() } else { old_origin };
                let new_ver = if promote { Verification::Observed } else { ver };
                self.c.execute(
                    "UPDATE osint_relationships SET last_seen = ?2, verification = ?3, origin = ?4 WHERE id = ?1",
                    params![id, self.at, new_ver.as_str(), new_origin],
                )?;
                if !self.summary.new_relationships.contains(&id) && !self.summary.updated_relationships.contains(&id) {
                    self.summary.updated_relationships.push(id);
                }
                id
            }
            None => {
                let ver = if model::relationship_type(rel_type).is_some_and(|r| r.inferred) && origin != Origin::Manual { Verification::Inferred } else { origin.initial_verification() };
                self.c.execute(
                    "INSERT INTO osint_relationships (investigation_id, source_id, target_id, type, directed, origin, verification, metadata, first_seen, last_seen)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
                    params![self.inv, s, t, rel_type, directed as i64, origin.as_str(), ver.as_str(), Value::Object(meta.clone()).to_string(), self.at],
                )?;
                let id = self.c.last_insert_rowid();
                self.summary.new_relationships.push(id);
                if ver == Verification::Inferred {
                    self.summary.inferred_relationships.push(id);
                }
                id
            }
        };
        self.c.execute(
            "INSERT INTO osint_relationship_evidence (relationship_id, evidence_id, strength) VALUES (?1, ?2, ?3)
             ON CONFLICT(relationship_id, evidence_id) DO UPDATE SET strength = CASE WHEN excluded.strength = 'direct' OR osint_relationship_evidence.strength = 'direct' THEN 'direct'
                 WHEN excluded.strength = 'corroborating' OR osint_relationship_evidence.strength = 'corroborating' THEN 'corroborating' ELSE 'weak' END",
            params![id, evidence, strength.as_str()],
        )?;
        self.touched_relationships.insert(id);
        Ok(Some(id))
    }

    fn entity_by_key(&self, t: EntityType, key: &str) -> rusqlite::Result<Option<i64>> {
        self.c.query_row("SELECT id FROM osint_entities WHERE investigation_id = ?1 AND type = ?2 AND match_key = ?3", params![self.inv, t.as_str(), key], |r| r.get(0)).optional()
    }

    /// Evidence record for facts derived from values (one per investigation and rule).
    fn derived_evidence(&mut self, rule: &str, summary: &str) -> rusqlite::Result<i64> {
        store_evidence(
            self.c,
            self.inv,
            &EvidenceInput { kind: "derived".into(), source: "structure".into(), reference: None, observed_at: None, summary: summary.into(), data: json!({ "rule": rule }), strength: Strength::Direct, operation_id: None, execution_id: None },
        )
    }

    /// Structural relationships implied by the entity's own value.
    fn structural(&mut self, id: i64, t: EntityType, n: &Normalized) -> rusqlite::Result<()> {
        match t {
            EntityType::Url | EntityType::Profile => {
                if let Some(host) = n.metadata.get("host").and_then(Value::as_str) {
                    let host_t = if normalize::ip(host).is_ok() { EntityType::Ip } else { EntityType::Domain };
                    if let Ok(hn) = normalize(host_t, host) {
                        let ev = self.derived_evidence("url-host", &format!("The URL {} is served from {}.", n.value, hn.value))?;
                        let hid = self.upsert_entity(host_t, &hn, host, None, ev)?;
                        self.upsert_relationship(id, hid, "ON_HOST", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        self.structural_once(hid, host_t, &hn)?;
                    }
                }
            }
            EntityType::Email => {
                if let Some(d) = n.metadata.get("domain").and_then(Value::as_str) {
                    if let Ok(dn) = normalize(EntityType::Domain, d) {
                        let ev = self.derived_evidence("email-domain", &format!("The address {} is under the domain {}.", n.value, dn.value))?;
                        let did = self.upsert_entity(EntityType::Domain, &dn, d, None, ev)?;
                        self.upsert_relationship(id, did, "BELONGS_TO", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        self.structural_once(did, EntityType::Domain, &dn)?;
                    }
                }
            }
            EntityType::Service => {
                if let Some(host) = n.metadata.get("host").and_then(Value::as_str) {
                    let host_t = if normalize::ip(host).is_ok() { EntityType::Ip } else { EntityType::Domain };
                    if let Ok(hn) = normalize(host_t, host) {
                        let ev = self.derived_evidence("service-host", &format!("The service {} runs on {}.", n.value, hn.value))?;
                        let hid = self.upsert_entity(host_t, &hn, host, None, ev)?;
                        self.upsert_relationship(hid, id, "EXPOSES_SERVICE", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        self.structural_once(hid, host_t, &hn)?;
                    }
                }
            }
            EntityType::Domain => {
                // link to the nearest known ancestor; never invents parent domains (without the
                // public-suffix list, "co.uk" and "example.co.uk" cannot be told apart reliably)
                let mut p = normalize::parent_domain(&n.key);
                while let Some(parent) = p {
                    if let Some(pid) = self.entity_by_key(EntityType::Domain, parent)? {
                        let ev = self.derived_evidence("subdomain", &format!("{} is below {} in the DNS tree.", n.key, parent))?;
                        self.upsert_relationship(id, pid, "SUBDOMAIN_OF", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        break;
                    }
                    p = normalize::parent_domain(parent);
                }
                // known descendants whose nearest known ancestor is now this domain
                let children: Vec<(i64, String)> = {
                    let mut st = self.c.prepare(
                        "SELECT id, match_key FROM osint_entities WHERE investigation_id = ?1 AND type = 'domain' AND length(match_key) > length(?2) + 1
                           AND substr(match_key, -(length(?2) + 1)) = '.' || ?2",
                    )?;
                    let v = st.query_map(params![self.inv, n.key], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
                    v
                };
                for (cid, ckey) in children {
                    let mut q = normalize::parent_domain(&ckey);
                    let mut nearest = None;
                    while let Some(pk) = q {
                        if pk == n.key {
                            nearest = Some(id);
                            break;
                        }
                        if self.entity_by_key(EntityType::Domain, pk)?.is_some() {
                            break; // a closer ancestor exists
                        }
                        q = normalize::parent_domain(pk);
                    }
                    if nearest.is_some() {
                        // drop derived links to ancestors above this one: keep the tree tidy
                        self.c.execute(
                            "DELETE FROM osint_relationships WHERE investigation_id = ?1 AND source_id = ?2 AND type = 'SUBDOMAIN_OF' AND origin = 'derived' AND target_id IN
                               (SELECT id FROM osint_entities WHERE investigation_id = ?1 AND type = 'domain' AND length(match_key) < ?4 AND substr(?3, -(length(match_key) + 1)) = '.' || match_key)",
                            params![self.inv, cid, n.key, n.key.len() as i64],
                        )?;
                        let ev = self.derived_evidence("subdomain", &format!("{ckey} is below {} in the DNS tree.", n.key))?;
                        self.upsert_relationship(cid, id, "SUBDOMAIN_OF", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                    }
                }
            }
            EntityType::Ip => {
                if let Ok(addr) = n.key.parse::<std::net::IpAddr>() {
                    for (nid, net) in self.netblocks()? {
                        if net.contains(&addr) {
                            let ev = self.derived_evidence("address-in-block", &format!("{} lies inside {}.", n.key, net))?;
                            self.upsert_relationship(id, nid, "PART_OF", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        }
                    }
                }
            }
            EntityType::Netblock => {
                if let Ok(net) = n.key.parse::<ipnet::IpNet>() {
                    let ips: Vec<(i64, String)> = {
                        let mut st = self.c.prepare("SELECT id, match_key FROM osint_entities WHERE investigation_id = ?1 AND type = 'ip'")?;
                        let v = st.query_map(params![self.inv], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
                        v
                    };
                    for (iid, ip) in ips {
                        if ip.parse::<std::net::IpAddr>().is_ok_and(|a| net.contains(&a)) {
                            let ev = self.derived_evidence("address-in-block", &format!("{ip} lies inside {net}."))?;
                            self.upsert_relationship(iid, id, "PART_OF", Origin::Derived, Strength::Direct, &Map::new(), ev)?;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Structural links for a host created as a by-product (domain/IP rules only create links).
    fn structural_once(&mut self, id: i64, t: EntityType, n: &Normalized) -> rusqlite::Result<()> {
        if self.structured.insert(id) {
            self.structural(id, t, n)?;
        }
        Ok(())
    }

    fn netblocks(&self) -> rusqlite::Result<Vec<(i64, ipnet::IpNet)>> {
        let mut st = self.c.prepare("SELECT id, match_key FROM osint_entities WHERE investigation_id = ?1 AND type = 'netblock'")?;
        let v = st.query_map(params![self.inv], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
        Ok(v.into_iter().filter_map(|(id, k)| k.parse().ok().map(|n| (id, n))).collect())
    }

    /// Correlation: domains that share an address, name server or certificate get an inferred,
    /// weak SHARES_INFRASTRUCTURE link — never more than that, and not for heavily shared
    /// infrastructure.
    fn correlate(&mut self) -> rusqlite::Result<()> {
        let touched: Vec<i64> = self.touched_relationships.iter().copied().collect();
        let mut infra: BTreeSet<(i64, String)> = BTreeSet::new();
        for rid in touched {
            let row: Option<(i64, String, String)> = self
                .c
                .query_row("SELECT target_id, type, verification FROM osint_relationships WHERE id = ?1", params![rid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?;
            if let Some((target, ty, ver)) = row {
                if matches!(ty.as_str(), "RESOLVES_TO" | "USES_NAMESERVER" | "USES_CERTIFICATE") && ver != "rejected" {
                    infra.insert((target, ty));
                }
            }
        }
        for (target, ty) in infra {
            let domains: Vec<i64> = {
                let mut st = self.c.prepare(
                    "SELECT r.source_id FROM osint_relationships r JOIN osint_entities e ON e.id = r.source_id
                     WHERE r.investigation_id = ?1 AND r.target_id = ?2 AND r.type = ?3 AND r.verification != 'rejected' AND e.type = 'domain' ORDER BY r.source_id",
                )?;
                let v = st.query_map(params![self.inv, target, ty], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
                v
            };
            if domains.len() < 2 || domains.len() > SHARED_INFRA_FANOUT_LIMIT {
                continue;
            }
            let shared: String = self.c.query_row("SELECT value FROM osint_entities WHERE id = ?1", params![target], |r| r.get(0))?;
            let basis = match ty.as_str() {
                "RESOLVES_TO" => format!("both resolve to {shared}"),
                "USES_NAMESERVER" => format!("both use the name server {shared}"),
                _ => format!("both are named in certificate {shared}"),
            };
            for (i, a) in domains.iter().enumerate() {
                for b in &domains[i + 1..] {
                    let ev = store_evidence(
                        self.c,
                        self.inv,
                        &EvidenceInput {
                            kind: "derived".into(),
                            source: "correlation".into(),
                            reference: None,
                            observed_at: None,
                            summary: format!("Correlation rule: {basis}. Shared infrastructure is a weak signal and does not prove common ownership."),
                            data: json!({ "rule": "shared-infrastructure", "via": ty, "shared": shared, "pair": [a, b] }),
                            strength: Strength::Weak,
                            operation_id: None,
                            execution_id: None,
                        },
                    )?;
                    let mut meta = Map::new();
                    meta.insert("basis".into(), json!(basis));
                    self.upsert_relationship(*a, *b, "SHARES_INFRASTRUCTURE", Origin::Inferred, Strength::Weak, &meta, ev)?;
                }
            }
        }
        Ok(())
    }

    fn recompute_confidence(&self) -> rusqlite::Result<()> {
        for rid in &self.touched_relationships {
            recompute_relationship(self.c, *rid)?;
        }
        for eid in &self.touched_entities {
            recompute_entity(self.c, *eid)?;
        }
        Ok(())
    }
}

pub fn recompute_relationship(c: &Connection, rid: i64) -> rusqlite::Result<()> {
    let ver: Option<String> = c.query_row("SELECT verification FROM osint_relationships WHERE id = ?1", params![rid], |r| r.get(0)).optional()?;
    let Some(ver) = ver else { return Ok(()) };
    let ev: Vec<(String, Strength)> = {
        let mut st = c.prepare("SELECT e.source, re.strength FROM osint_relationship_evidence re JOIN osint_evidence e ON e.id = re.evidence_id WHERE re.relationship_id = ?1")?;
        let v = st.query_map(params![rid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
        v.into_iter().map(|(s, st)| (s, Strength::parse(&st).unwrap_or(Strength::Weak))).collect()
    };
    let (conf, reason) = confidence::assess(Verification::parse(&ver).unwrap_or(Verification::Observed), &ev);
    c.execute("UPDATE osint_relationships SET confidence = ?2, confidence_reason = ?3 WHERE id = ?1", params![rid, conf.as_str(), reason])?;
    Ok(())
}

pub fn recompute_entity(c: &Connection, eid: i64) -> rusqlite::Result<()> {
    let ver: Option<String> = c.query_row("SELECT verification FROM osint_entities WHERE id = ?1", params![eid], |r| r.get(0)).optional()?;
    let Some(ver) = ver else { return Ok(()) };
    let ev: Vec<(String, Strength)> = {
        let mut st = c.prepare("SELECT e.source, e.strength FROM osint_entity_evidence x JOIN osint_evidence e ON e.id = x.evidence_id WHERE x.entity_id = ?1")?;
        let v = st.query_map(params![eid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
        v.into_iter().map(|(s, st)| (s, Strength::parse(&st).unwrap_or(Strength::Weak))).collect()
    };
    let (conf, _) = confidence::assess(Verification::parse(&ver).unwrap_or(Verification::Observed), &ev);
    c.execute("UPDATE osint_entities SET confidence = ?2 WHERE id = ?1", params![eid, conf.as_str()])?;
    Ok(())
}

/// Record a timeline event; the optional ids link it to what it is about.
#[allow(clippy::too_many_arguments)] // one argument per stored column
pub fn event(c: &Connection, inv: i64, kind: &str, summary: &str, source: Option<&str>, entity: Option<i64>, rel: Option<i64>, op: Option<i64>, graph: Option<i64>, data: Value) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO osint_events (investigation_id, at, kind, summary, source, entity_id, relationship_id, operation_id, graph_id, data) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![inv, now(), kind, clip(summary, 500), source, entity, rel, op, graph, data.to_string()],
    )?;
    Ok(())
}

/// Confidence recomputation postponed to the end of a batch of observations (Mission 6): a graph
/// import whose element lists many evidence records re-read all of that element's evidence links
/// once per record. Confidence depends only on the stored links and the verification, so
/// computing it once at the end gives the same result.
#[derive(Default)]
pub struct Deferred {
    entities: BTreeSet<i64>,
    relationships: BTreeSet<i64>,
}

impl Deferred {
    /// Recomputes every element the batch touched, once.
    pub fn finish(self, c: &Connection) -> rusqlite::Result<()> {
        for rid in self.relationships {
            recompute_relationship(c, rid)?;
        }
        for eid in self.entities {
            recompute_entity(c, eid)?;
        }
        Ok(())
    }
}

/// Run the mapping pipeline for one observation. Call inside a transaction.
pub fn ingest(c: &Connection, inv: i64, obs: &Observation) -> rusqlite::Result<ChangeSummary> {
    ingest_with(c, inv, obs, None)
}

/// [`ingest`], leaving the confidence recomputation to `deferred` (call [`Deferred::finish`]).
pub fn ingest_deferred(c: &Connection, inv: i64, obs: &Observation, deferred: &mut Deferred) -> rusqlite::Result<ChangeSummary> {
    ingest_with(c, inv, obs, Some(deferred))
}

fn ingest_with(c: &Connection, inv: i64, obs: &Observation, deferred: Option<&mut Deferred>) -> rusqlite::Result<ChangeSummary> {
    let evidence_id = store_evidence(c, inv, &obs.evidence)?;
    let mut ctx = Ctx { c, inv, at: now(), summary: ChangeSummary { evidence_id: Some(evidence_id), ..Default::default() }, touched_entities: BTreeSet::new(), touched_relationships: BTreeSet::new(), new_entity_set: HashSet::new(), structured: HashSet::new() };

    // entities
    let mut ids: Vec<Option<i64>> = Vec::with_capacity(obs.entities.len());
    let mut normalized: Vec<Option<Normalized>> = Vec::with_capacity(obs.entities.len());
    for e in &obs.entities {
        match normalize(e.entity_type, &e.value) {
            Ok(n) => {
                let id = ctx.upsert_entity(e.entity_type, &n, &e.value, Some(e), evidence_id)?;
                ids.push(Some(id));
                normalized.push(Some(n));
            }
            Err(why) => {
                ctx.summary.rejected.push(format!("{} \"{}\": {why}", e.entity_type.as_str(), clip(&e.value, 80)));
                ids.push(None);
                normalized.push(None);
            }
        }
    }
    // structural relationships (only once per distinct entity)
    for (i, e) in obs.entities.iter().enumerate() {
        if let (Some(id), Some(n)) = (ids[i], &normalized[i]) {
            ctx.structural_once(id, e.entity_type, n)?;
        }
    }
    // observed relationships
    for r in &obs.relationships {
        if let (Some(Some(s)), Some(Some(t))) = (ids.get(r.source), ids.get(r.target)) {
            ctx.upsert_relationship(*s, *t, &r.rel_type, r.origin, r.strength, &r.metadata, evidence_id)?;
        } else if r.source >= ids.len() || r.target >= ids.len() {
            ctx.summary.rejected.push(format!("relationship {} refers to a missing entity", r.rel_type));
        }
    }
    ctx.correlate()?;
    match deferred {
        Some(d) => {
            d.entities.extend(ctx.touched_entities.iter().copied());
            d.relationships.extend(ctx.touched_relationships.iter().copied());
        }
        None => ctx.recompute_confidence()?,
    }

    // timeline
    let summary = ctx.summary.clone();
    let src = obs.evidence.source.as_str();
    event(c, inv, "collection", &format!("{}: {}", obs.evidence.summary.lines().next().map(|l| clip(l, 160)).unwrap_or_default(), summary.line()), Some(src), None, None, obs.evidence.operation_id, None, json!({ "evidence": evidence_id, "kind": obs.evidence.kind }))?;
    if summary.new_entities.len() <= PER_ITEM_EVENT_LIMIT {
        for id in &summary.new_entities {
            let (t, v): (String, String) = c.query_row("SELECT type, value FROM osint_entities WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            event(c, inv, "entity_discovered", &format!("New {t}: {v}"), Some(src), Some(*id), None, obs.evidence.operation_id, None, json!({}))?;
        }
    }
    if summary.new_relationships.len() <= PER_ITEM_EVENT_LIMIT {
        for id in &summary.new_relationships {
            let line: String = c.query_row(
                "SELECT s.value || ' ' || r.type || ' ' || t.value FROM osint_relationships r JOIN osint_entities s ON s.id = r.source_id JOIN osint_entities t ON t.id = r.target_id WHERE r.id = ?1",
                params![id],
                |r| r.get(0),
            )?;
            let kind = if summary.inferred_relationships.contains(id) { "relationship_inferred" } else { "relationship_discovered" };
            event(c, inv, kind, &line, Some(src), None, Some(*id), obs.evidence.operation_id, None, json!({}))?;
        }
    }

    // graphs that follow the investigation receive new entities (positions are chosen by the
    // workspace when the graph is opened)
    if !summary.new_entities.is_empty() {
        let graphs: Vec<i64> = {
            let mut st = c.prepare("SELECT id FROM osint_graphs WHERE investigation_id = ?1 AND follow_new = 1")?;
            let v = st.query_map(params![inv], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
            v
        };
        for g in graphs {
            for id in &summary.new_entities {
                c.execute("INSERT OR IGNORE INTO osint_graph_nodes (graph_id, entity_id) VALUES (?1, ?2)", params![g, id])?;
            }
            c.execute("UPDATE osint_graphs SET revision = revision + 1, updated_at = ?2 WHERE id = ?1", params![g, now()])?;
        }
    }
    c.execute("UPDATE osint_investigations SET updated_at = ?2 WHERE id = ?1", params![inv, now()])?;
    Ok(summary)
}

/// Group entity ids by a loose key to show *possible* duplicates; never merges.
pub fn possible_duplicates(c: &Connection, inv: i64) -> rusqlite::Result<Vec<Vec<i64>>> {
    let mut st = c.prepare("SELECT id, type, match_key FROM osint_entities WHERE investigation_id = ?1")?;
    let rows = st.query_map(params![inv], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?.collect::<Result<Vec<_>, _>>()?;
    let mut groups: HashMap<(String, String), Vec<i64>> = HashMap::new();
    for (id, t, key) in rows {
        if let Some(et) = EntityType::parse(&t) {
            if let Some(lk) = normalize::loose_key(et, &key) {
                if !lk.is_empty() {
                    groups.entry((t, lk)).or_default().push(id);
                }
            }
        }
    }
    let mut out: Vec<Vec<i64>> = groups.into_values().filter(|g| g.len() > 1).collect();
    out.sort();
    Ok(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::db::Db;

    pub fn inv(db: &Db) -> i64 {
        db.with(|c| {
            c.execute(
                "INSERT INTO osint_investigations (name, target_type, target_value, created_at, updated_at) VALUES ('t', 'domain', 'example.com', 'x', 'x')",
                [],
            )?;
            Ok(c.last_insert_rowid())
        })
        .unwrap()
    }

    pub fn ev(source: &str, summary: &str) -> EvidenceInput {
        EvidenceInput { kind: "provider_response".into(), source: source.into(), reference: None, observed_at: None, summary: summary.into(), data: json!({}), strength: Strength::Direct, operation_id: None, execution_id: None }
    }

    pub fn ent(t: EntityType, v: &str) -> EntityInput {
        EntityInput { entity_type: t, value: v.into(), display_name: None, metadata: Map::new(), flagged: false }
    }

    pub fn rel(s: usize, t: usize, ty: &str) -> RelationshipInput {
        RelationshipInput { source: s, target: t, rel_type: ty.into(), strength: Strength::Direct, origin: Origin::Observed, metadata: Map::new() }
    }

    fn count(db: &Db, sql: &str) -> i64 {
        db.with(|c| Ok(c.query_row(sql, [], |r| r.get(0))?)).unwrap()
    }

    pub fn run(db: &Db, i: i64, o: &Observation) -> ChangeSummary {
        db.with(|c| {
            let tx = c.unchecked_transaction()?;
            let s = ingest(&tx, i, o)?;
            tx.commit()?;
            Ok(s)
        })
        .unwrap()
    }

    #[test]
    fn dedupes_entities_and_relationships_and_keeps_aliases() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        let o = Observation { evidence: ev("dns", "A example.com"), entities: vec![ent(EntityType::Domain, "Example.COM."), ent(EntityType::Ip, "93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] };
        let s1 = run(&db, i, &o);
        assert_eq!((s1.new_entities.len(), s1.new_relationships.len()), (2, 1));
        // same facts again from the same evidence: nothing new, evidence not duplicated
        let s2 = run(&db, i, &o);
        assert!(s2.new_entities.is_empty() && s2.new_relationships.is_empty());
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_evidence"), 1);
        // a differently written value resolves to the same entity and is kept as an alias
        let o3 = Observation { evidence: ev("otx", "passive DNS"), entities: vec![ent(EntityType::Domain, "EXAMPLE.com"), ent(EntityType::Ip, "::ffff:93.184.216.34")], relationships: vec![rel(0, 1, "RESOLVES_TO")] };
        let s3 = run(&db, i, &o3);
        assert!(s3.new_entities.is_empty() && s3.new_relationships.is_empty() && s3.updated_relationships.len() == 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_entities"), 2);
        let aliases: String = db.with(|c| Ok(c.query_row("SELECT aliases FROM osint_entities WHERE type = 'domain'", [], |r| r.get(0))?)).unwrap();
        assert!(aliases.contains("Example.COM.") && aliases.contains("EXAMPLE.com"), "{aliases}");
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_relationship_evidence"), 2, "two independent sources");
        let conf: String = db.with(|c| Ok(c.query_row("SELECT confidence FROM osint_relationships", [], |r| r.get(0))?)).unwrap();
        assert_eq!(conf, "high");
    }

    #[test]
    fn invalid_values_are_reported_not_stored() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        let o = Observation { evidence: ev("x", "bad"), entities: vec![ent(EntityType::Domain, "not a domain"), ent(EntityType::Ip, "1.2.3.4")], relationships: vec![rel(0, 1, "RESOLVES_TO"), rel(1, 7, "RESOLVES_TO")] };
        let s = run(&db, i, &o);
        assert_eq!(s.new_entities.len(), 1);
        assert_eq!(s.rejected.len(), 2, "{:?}", s.rejected);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_relationships"), 0);
    }

    #[test]
    fn structural_relationships_follow_from_values() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        run(&db, i, &Observation { evidence: ev("a", "1"), entities: vec![ent(EntityType::Domain, "example.com")], relationships: vec![] });
        run(&db, i, &Observation { evidence: ev("a", "2"), entities: vec![ent(EntityType::Domain, "a.b.example.com"), ent(EntityType::Url, "https://shop.example.com/cart?x=1"), ent(EntityType::Email, "Bob@Example.com")], relationships: vec![] });
        let q = |sql: &str| count(&db, sql);
        // a.b.example.com → example.com (nearest known ancestor), url → host, host → example.com, email → domain
        assert_eq!(q("SELECT COUNT(*) FROM osint_relationships WHERE type = 'SUBDOMAIN_OF'"), 2);
        assert_eq!(q("SELECT COUNT(*) FROM osint_relationships WHERE type = 'ON_HOST'"), 1);
        assert_eq!(q("SELECT COUNT(*) FROM osint_relationships WHERE type = 'BELONGS_TO'"), 1);
        // adding the intermediate parent re-links the deeper subdomain to it
        run(&db, i, &Observation { evidence: ev("a", "3"), entities: vec![ent(EntityType::Domain, "b.example.com")], relationships: vec![] });
        let parent_of_ab: String = db
            .with(|c| Ok(c.query_row("SELECT t.value FROM osint_relationships r JOIN osint_entities s ON s.id = r.source_id JOIN osint_entities t ON t.id = r.target_id WHERE s.value = 'a.b.example.com' AND r.type = 'SUBDOMAIN_OF'", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(parent_of_ab, "b.example.com");
        // addresses inside a known block
        run(&db, i, &Observation { evidence: ev("a", "4"), entities: vec![ent(EntityType::Ip, "192.0.2.10"), ent(EntityType::Netblock, "192.0.2.0/24")], relationships: vec![] });
        assert_eq!(q("SELECT COUNT(*) FROM osint_relationships WHERE type = 'PART_OF'"), 1);
    }

    #[test]
    fn shared_infrastructure_is_only_inferred_and_analyst_decisions_stick() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        let o = Observation {
            evidence: ev("dns", "A records"),
            entities: vec![ent(EntityType::Domain, "one.example"), ent(EntityType::Domain, "two.example"), ent(EntityType::Ip, "203.0.113.5")],
            relationships: vec![rel(0, 2, "RESOLVES_TO"), rel(1, 2, "RESOLVES_TO")],
        };
        let s = run(&db, i, &o);
        assert_eq!(s.inferred_relationships.len(), 1);
        let (ver, conf, reason): (String, String, String) =
            db.with(|c| Ok(c.query_row("SELECT verification, confidence, confidence_reason FROM osint_relationships WHERE type = 'SHARES_INFRASTRUCTURE'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?)).unwrap();
        assert_eq!((ver.as_str(), conf.as_str()), ("inferred", "low"));
        assert!(reason.contains("needs analyst review"), "{reason}");
        // the analyst rejects it; a later identical observation must not resurrect it
        db.with(|c| Ok(c.execute("UPDATE osint_relationships SET verification = 'rejected' WHERE type = 'SHARES_INFRASTRUCTURE'", [])?)).unwrap();
        run(&db, i, &Observation { evidence: ev("dns", "A records again"), ..o.clone() });
        let ver: String = db.with(|c| Ok(c.query_row("SELECT verification FROM osint_relationships WHERE type = 'SHARES_INFRASTRUCTURE'", [], |r| r.get(0))?)).unwrap();
        assert_eq!(ver, "rejected");
    }

    #[test]
    fn heavily_shared_infrastructure_is_not_correlated() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        let mut entities = vec![ent(EntityType::Ip, "198.51.100.1")];
        let mut relationships = vec![];
        for n in 0..(SHARED_INFRA_FANOUT_LIMIT + 1) {
            entities.push(ent(EntityType::Domain, &format!("site{n}.example")));
            relationships.push(rel(n + 1, 0, "RESOLVES_TO"));
        }
        let s = run(&db, i, &Observation { evidence: ev("dns", "cdn"), entities, relationships });
        assert!(s.inferred_relationships.is_empty(), "a CDN address must not link everything");
    }

    #[test]
    fn undirected_relationships_are_stored_once_and_possible_duplicates_are_listed() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        let o = Observation { evidence: ev("a", "x"), entities: vec![ent(EntityType::Organization, "Example Corp"), ent(EntityType::Organization, "Example, Inc."), ent(EntityType::Organization, "Other Ltd")], relationships: vec![rel(0, 1, "ASSOCIATED_WITH"), rel(1, 0, "ASSOCIATED_WITH")] };
        run(&db, i, &o);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_relationships"), 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_entities"), 3, "similar names are not merged");
        let dups = db.with(|c| Ok(possible_duplicates(c, i)?)).unwrap();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].len(), 2);
    }

    #[test]
    fn new_entities_join_following_graphs() {
        let db = Db::open_in_memory().unwrap();
        let i = inv(&db);
        db.with(|c| {
            c.execute("INSERT INTO osint_graphs (investigation_id, name, follow_new, created_at, updated_at) VALUES (?1, 'main', 1, 'x', 'x')", params![i])?;
            c.execute("INSERT INTO osint_graphs (investigation_id, name, follow_new, created_at, updated_at) VALUES (?1, 'snapshot', 0, 'x', 'x')", params![i])?;
            Ok(())
        })
        .unwrap();
        run(&db, i, &Observation { evidence: ev("a", "x"), entities: vec![ent(EntityType::Domain, "example.com")], relationships: vec![] });
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_graph_nodes n JOIN osint_graphs g ON g.id = n.graph_id WHERE g.name = 'main'"), 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM osint_graph_nodes n JOIN osint_graphs g ON g.id = n.graph_id WHERE g.name = 'snapshot'"), 0);
        assert_eq!(count(&db, "SELECT revision FROM osint_graphs WHERE name = 'main'"), 2);
        assert!(count(&db, "SELECT COUNT(*) FROM osint_events WHERE kind = 'entity_discovered'") == 1);
    }
}
