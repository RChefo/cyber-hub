// SPDX-License-Identifier: Apache-2.0
//! Correlation rules over a project's records (docs/DATA_MODEL.md#correlation): explainable
//! matches between results of different modules, stored as suggestions for the analyst
//! (`relations::suggest`). Every rule compares exact or normalized values (hosts, addresses, URLs,
//! CVE IDs, package URLs, file hashes, API paths); nothing is matched by similarity, and nothing is
//! merged. Each suggestion names its rule, the fields and values that matched, and how.
//!
//! The rules index each side once (hash maps), so a run is linear in the number of records.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::Serialize;

use super::analysis::indicator_of;
use super::relations::{Candidate, Match, Ref, SuggestResult};
use crate::error::AppResult;

/// (rule, what it matches)
pub const RULES: &[(&str, &str)] = &[
    ("finding-asset", "A finding's affected target is an asset: the same URL, the same web origin, or the same host or address"),
    ("finding-vulnerability", "A finding names the CVE of a tracked vulnerability on the same host (or one without an asset)"),
    ("vulnerability-component", "A tracked vulnerability's CVE is a known vulnerability of an SBOM component"),
    ("finding-component", "A finding's target is the package URL of an SBOM component (the same version, or the package in another version)"),
    ("hash", "The same file hash in evidence, a finding's text, and OSINT file-hash entities"),
    ("finding-endpoint", "A finding's URL is a server URL of an API definition followed by one endpoint's path"),
    ("entity-asset", "An entity of a linked OSINT investigation is the same host or address as an asset"),
    ("finding-entity", "A finding's affected target is the host, address or URL of an entity of a linked OSINT investigation"),
    ("shared-evidence", "Two findings are linked to the same evidence record"),
    ("duplicate", "Two findings have the same CVE on the same host, or the same title on the same target"),
];

/// Pairs proposed per group of findings that share something, so one large group cannot flood the
/// queue.
const MAX_PAIRS_PER_GROUP: usize = 50;
/// Assets proposed for one finding.
const MAX_PER_FINDING: usize = 5;

static HASHES: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b").expect("hashes"));
static CVE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d{4,}\b").expect("cve"));
static PATH_PARAM: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{[^}/]*\}").expect("path parameter"));

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// candidates per rule, before the ones the analyst decided on or that are linked already
    pub by_rule: BTreeMap<String, usize>,
    pub stored: SuggestResult,
    pub elapsed_ms: u64,
}

struct Finding {
    id: i64,
    title: String,
    target: String,
    cves: Vec<String>,
    text: String,
}

fn m(field_a: &str, value_a: &str, field_b: &str, value_b: &str, how: &str) -> Match {
    let cut = |s: &str| s.chars().take(300).collect::<String>();
    Match { field_a: field_a.into(), value_a: cut(value_a), field_b: field_b.into(), value_b: cut(value_b), how: how.into() }
}

#[allow(clippy::too_many_arguments)]
fn cand(a: Ref, b: Ref, rel_type: &'static str, rule: &'static str, reason: String, matched: Vec<Match>, confidence: &'static str, origin: &'static str) -> Candidate {
    Candidate { a, b, rel_type, rule, reason, matched, confidence, origin }
}

/// `scheme://host[:port]` of a URL, lower-case.
fn origin(url: &str) -> Option<String> {
    let u = url::Url::parse(url.trim()).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some(match u.port() {
        Some(p) => format!("{}://{host}:{p}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    })
}

fn norm_title(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_alphanumeric() { c } else { ' ' }).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The package URL without its version (and qualifiers): `pkg:npm/lodash`.
fn purl_base(purl: &str) -> Option<(String, String)> {
    let p = purl.trim();
    if !p.starts_with("pkg:") {
        return None;
    }
    let p = p.split(['?', '#']).next().unwrap_or(p);
    let (base, version) = match p.rsplit_once('@') {
        Some((b, v)) if !b.ends_with('/') && b.contains('/') => (b, v),
        _ => (p, ""),
    };
    Some((base.to_ascii_lowercase(), version.to_string()))
}

/// Runs every rule over the project and stores the results as suggestions.
pub fn run(c: &Connection, project_id: i64) -> AppResult<Report> {
    let started = Instant::now();
    super::relations::require_open(c, project_id)?;
    let candidates = candidates(c, project_id)?;
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    for x in &candidates {
        *by_rule.entry(x.rule.to_string()).or_default() += 1;
    }
    let tx = c.unchecked_transaction()?;
    let stored = super::relations::suggest(&tx, project_id, candidates, "correlation")?;
    let summary = format!(
        "Correlation: {} new suggestion{}, {} updated, {} already decided",
        stored.new,
        if stored.new == 1 { "" } else { "s" },
        stored.updated,
        stored.decided
    );
    tx.execute(
        "INSERT INTO relation_events (project_id, relation_id, action, summary, note, actor, at) VALUES (?1, NULL, 'correlated', ?2, ?3, 'correlation', ?4)",
        params![project_id, summary, if stored.truncated { "The review queue is full; resolve suggestions to see more" } else { "" }, crate::util::now()],
    )?;
    tx.commit()?;
    Ok(Report { by_rule, stored, elapsed_ms: started.elapsed().as_millis() as u64 })
}

/// What every rule finds, without storing anything.
pub fn candidates(c: &Connection, project_id: i64) -> AppResult<Vec<Candidate>> {
    let mut out: Vec<Candidate> = Vec::new();

    // ── records
    let findings: Vec<Finding> = c
        .prepare("SELECT id, title, affected_target, cve, substr(description, 1, 100000) || ' ' || substr(technical_details, 1, 100000) FROM findings WHERE project_id = ?1")?
        .query_map(params![project_id], |r| {
            let cve: String = r.get(3)?;
            Ok(Finding { id: r.get(0)?, title: r.get(1)?, target: r.get::<_, String>(2)?.trim().to_string(), cves: CVE.find_iter(&cve).map(|x| x.as_str().to_ascii_uppercase()).collect(), text: r.get(4)? })
        })?
        .collect::<Result<_, _>>()?;
    let assets: Vec<(i64, String, String)> = c.prepare("SELECT id, type, value FROM assets WHERE project_id = ?1")?.query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    let vulns: Vec<(i64, String, Option<i64>)> = c.prepare("SELECT id, cve_id, asset_id FROM vulnerabilities WHERE project_id = ?1")?.query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    let evidence: Vec<(i64, String, String)> = c
        .prepare("SELECT id, title, lower(sha256) FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 IS NOT NULL")?
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let entities: Vec<(i64, String, String, String)> = c
        .prepare("SELECT e.id, e.type, e.value, i.name FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id WHERE i.project_id = ?1 AND e.type IN ('domain','ip','url','file_hash')")?
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;

    // ── assets by what identifies them
    let mut by_value: HashMap<String, Vec<(i64, String, String)>> = HashMap::new();
    let mut by_origin: HashMap<String, Vec<(i64, String, String)>> = HashMap::new();
    let mut by_host: HashMap<String, Vec<(i64, String, String)>> = HashMap::new();
    let mut asset_host: HashMap<i64, String> = HashMap::new();
    for (id, kind, value) in &assets {
        by_value.entry(value.trim().to_ascii_lowercase()).or_default().push((*id, kind.clone(), value.clone()));
        if kind == "http_service" {
            if let Some(o) = origin(value) {
                by_origin.entry(o).or_default().push((*id, kind.clone(), value.clone()));
            }
        }
        let raw = if kind == "service" { super::discovery::service_host(value).unwrap_or_default() } else { value.clone() };
        if let Some((_, host)) = indicator_of(&raw) {
            asset_host.insert(*id, host.clone());
            if matches!(kind.as_str(), "domain" | "subdomain" | "ip") {
                by_host.entry(host).or_default().push((*id, kind.clone(), value.clone()));
            }
        }
    }

    // ── finding → asset: the most specific match only
    for f in &findings {
        if f.target.is_empty() {
            continue;
        }
        let key = f.target.to_ascii_lowercase();
        let mut found: Vec<Candidate> = Vec::new();
        for (aid, kind, value) in by_value.get(&key).into_iter().flatten() {
            found.push(cand(Ref::new("finding", f.id), Ref::new("asset", *aid), "affects", "finding-asset", format!("The finding's affected target is the {} asset {value}", kind.replace('_', " ")), vec![m("finding.affected_target", &f.target, "asset.value", value, "exact")], "high", "derived"));
        }
        if found.is_empty() {
            if let Some(o) = origin(&f.target) {
                for (aid, _, value) in by_origin.get(&o).into_iter().flatten() {
                    found.push(cand(Ref::new("finding", f.id), Ref::new("asset", *aid), "affects", "finding-asset", format!("The finding's URL is on the web service {value}"), vec![m("finding.affected_target", &f.target, "asset.value", value, "normalized")], "high", "derived"));
                }
            }
        }
        if found.is_empty() {
            if let Some((_, host)) = indicator_of(&f.target) {
                for (aid, kind, value) in by_host.get(&host).into_iter().flatten() {
                    found.push(cand(Ref::new("finding", f.id), Ref::new("asset", *aid), "affects", "finding-asset", format!("The finding's target is on the {} {value}", kind.replace('_', " ")), vec![m("finding.affected_target", &f.target, "asset.value", value, "normalized")], "medium", "derived"));
                }
            }
        }
        found.truncate(MAX_PER_FINDING);
        out.extend(found);
    }

    // ── finding ↔ vulnerability by CVE, on the same host or without an asset
    let mut vulns_by_cve: HashMap<String, Vec<(i64, Option<i64>)>> = HashMap::new();
    for (id, cve, asset) in &vulns {
        vulns_by_cve.entry(cve.to_ascii_uppercase()).or_default().push((*id, *asset));
    }
    for f in &findings {
        let host = indicator_of(&f.target).map(|(_, h)| h);
        for cve in &f.cves {
            for (vid, asset) in vulns_by_cve.get(cve).into_iter().flatten() {
                let (ok, confidence, why) = match (asset.and_then(|a| asset_host.get(&a)), &host) {
                    (Some(ah), Some(fh)) if ah == fh => (true, "high", format!("on the same host {fh}")),
                    (Some(_), _) => (false, "low", String::new()),
                    (None, _) => (true, "medium", "tracked without an asset".to_string()),
                };
                if ok {
                    out.push(cand(Ref::new("finding", f.id), Ref::new("vulnerability", *vid), "corresponds_to", "finding-vulnerability", format!("The finding names {cve}, a tracked vulnerability {why}"), vec![m("finding.cve", cve, "vulnerability.cve_id", cve, "exact")], confidence, "derived"));
                }
            }
        }
    }

    // ── SBOM components: packages and their vulnerabilities
    let docs: Vec<i64> = c.prepare("SELECT id FROM sbom_docs WHERE project_id = ?1 ORDER BY id")?.query_map(params![project_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut packages: HashMap<String, Vec<(i64, usize, String, String)>> = HashMap::new();
    for doc in docs {
        let (summary, sbom, osv) = super::sbom::get(c, doc)?;
        for (i, comp) in sbom.components.iter().enumerate() {
            if let Some((base, version)) = purl_base(&comp.purl) {
                packages.entry(base).or_default().push((doc, i, version, comp.label()));
            }
        }
        for v in super::sbom::merged(&sbom, &osv) {
            let mut ids: BTreeSet<String> = v.aliases.iter().chain(std::iter::once(&v.id)).filter(|x| CVE.is_match(x)).map(|x| x.to_ascii_uppercase()).collect();
            ids.retain(|x| vulns_by_cve.contains_key(x));
            for cve in ids {
                for (vid, _) in &vulns_by_cve[&cve] {
                    for &ci in &v.components {
                        if let Some(comp) = sbom.components.get(ci) {
                            out.push(cand(
                                Ref::new("vulnerability", *vid),
                                Ref::sub("sbom_component", doc, ci.to_string()),
                                "affects",
                                "vulnerability-component",
                                format!("{cve} is a known vulnerability of {} in {}", comp.label(), summary.name),
                                vec![m("vulnerability.cve_id", &cve, "sbom.vulnerability", &v.id, if v.id.eq_ignore_ascii_case(&cve) { "exact" } else { "alias" })],
                                "high",
                                "derived",
                            ));
                        }
                    }
                }
            }
        }
    }
    for f in &findings {
        let Some((base, version)) = purl_base(&f.target) else { continue };
        for (doc, i, v, label) in packages.get(&base).into_iter().flatten() {
            let same = !version.is_empty() && *v == version;
            out.push(if same {
                cand(Ref::new("finding", f.id), Ref::sub("sbom_component", *doc, i.to_string()), "affects", "finding-component", format!("The finding is about {label}, a component of SBOM #{doc}"), vec![m("finding.affected_target", &f.target, "component.purl", &format!("{base}@{v}"), "exact")], "high", "derived")
            } else {
                cand(Ref::new("finding", f.id), Ref::sub("sbom_component", *doc, i.to_string()), "corresponds_to", "finding-component", format!("The finding's package is in SBOM #{doc} as {label} (the finding names version {})", if version.is_empty() { "none" } else { &version }), vec![m("finding.affected_target", &f.target, "component.purl", &format!("{base}@{v}"), "normalized")], "medium", "derived")
            });
        }
    }

    // ── file hashes
    let mut hash_evidence: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    for (id, title, sha) in &evidence {
        hash_evidence.entry(sha.clone()).or_default().push((*id, title.clone()));
    }
    let mut hash_entities: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    for (id, kind, value, inv) in &entities {
        if kind == "file_hash" {
            hash_entities.entry(value.trim().to_ascii_lowercase()).or_default().push((*id, inv.clone()));
        }
    }
    for (sha, evs) in &hash_evidence {
        for (eid, title) in evs {
            for (oid, inv) in hash_entities.get(sha).into_iter().flatten() {
                out.push(cand(Ref::new("evidence", *eid), Ref::new("osint_entity", *oid), "corresponds_to", "hash", format!("The evidence file {title} has the SHA-256 of a file-hash entity of {inv}"), vec![m("evidence.sha256", sha, "entity.value", sha, "exact")], "high", "derived"));
            }
        }
    }
    for f in &findings {
        let found: BTreeSet<String> = HASHES.find_iter(&f.text).map(|x| x.as_str().to_ascii_lowercase()).collect();
        for h in found {
            for (eid, title) in hash_evidence.get(&h).into_iter().flatten() {
                out.push(cand(Ref::new("finding", f.id), Ref::new("evidence", *eid), "supported_by", "hash", format!("The finding names the SHA-256 of the evidence file {title}"), vec![m("finding.text", &h, "evidence.sha256", &h, "exact")], "high", "derived"));
            }
            for (oid, inv) in hash_entities.get(&h).into_iter().flatten() {
                out.push(cand(Ref::new("finding", f.id), Ref::new("osint_entity", *oid), "corresponds_to", "hash", format!("The finding names a file hash that is an entity of {inv}"), vec![m("finding.text", &h, "entity.value", &h, "exact")], "high", "derived"));
            }
        }
    }

    // ── finding → API endpoint: a server URL followed by the endpoint's path
    // URLs are compared without regard to case. Endpoints are indexed by server and first path
    // segment (a parameter there goes to the "" bucket), so each finding is matched against the
    // few endpoints that can fit, not against every endpoint of every definition.
    let specs: Vec<i64> = c.prepare("SELECT id FROM api_specs WHERE project_id = ?1 ORDER BY id")?.query_map(params![project_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut templates: Vec<(i64, usize, String, Regex, String)> = Vec::new();
    let mut by_segment: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for spec in specs {
        let (_, doc) = super::apisec::get(c, spec)?;
        for (i, e) in doc.endpoints.iter().enumerate() {
            let servers: Vec<&String> = if e.servers.is_empty() { doc.servers.iter().collect() } else { e.servers.iter().collect() };
            let path = e.path.trim_end_matches('/').to_ascii_lowercase();
            let first = path.split('/').find(|s| !s.is_empty()).filter(|s| !s.contains('{')).unwrap_or("").to_string();
            let path_re = regex::escape(&path).replace(r"\{", "{").replace(r"\}", "}");
            let path_re = PATH_PARAM.replace_all(&path_re, "[^/]+").to_string();
            for s in servers {
                let base = s.trim_end_matches('/').to_ascii_lowercase();
                if let Ok(re) = Regex::new(&format!("^{}{}/?$", regex::escape(&base), path_re)) {
                    by_segment.entry((base.clone(), first.clone())).or_default().push(templates.len());
                    templates.push((spec, i, format!("{} {}", e.method, e.path), re, base));
                }
            }
        }
    }
    let bases: BTreeSet<String> = templates.iter().map(|t| t.4.clone()).collect();
    for f in findings.iter().filter(|f| !templates.is_empty() && f.target.contains("://")) {
        let url = f.target.split(['?', '#']).next().unwrap_or(&f.target).to_ascii_lowercase();
        let mut hits: Vec<usize> = Vec::new();
        for base in bases.iter().filter(|b| url.starts_with(b.as_str())) {
            let first = url[base.len()..].split('/').find(|s| !s.is_empty()).unwrap_or("").to_string();
            for key in [(base.clone(), first), (base.clone(), String::new())] {
                hits.extend(by_segment.get(&key).into_iter().flatten().copied().filter(|t| templates[*t].3.is_match(&url)));
            }
        }
        hits.sort_unstable();
        hits.dedup();
        let confidence = if hits.len() == 1 { "high" } else { "medium" };
        for t in hits.into_iter().take(MAX_PER_FINDING) {
            let (spec, i, label, _, base) = &templates[t];
            out.push(cand(Ref::new("finding", f.id), Ref::sub("api_endpoint", *spec, i.to_string()), "affects", "finding-endpoint", format!("The finding's URL is the endpoint {label} of API definition #{spec}"), vec![m("finding.affected_target", &f.target, "endpoint", &format!("{base} + {label}"), "normalized")], confidence, "derived"));
        }
    }

    // ── OSINT entities and assets, findings and entities
    let mut entity_hosts: HashMap<String, Vec<(i64, String, String)>> = HashMap::new();
    for (id, kind, value, inv) in &entities {
        if kind == "file_hash" {
            continue;
        }
        if let Some((_, host)) = indicator_of(value) {
            entity_hosts.entry(host).or_default().push((*id, value.clone(), inv.clone()));
        }
    }
    let asset_entity: HashMap<i64, Option<i64>> = c.prepare("SELECT id, osint_entity_id FROM assets WHERE project_id = ?1")?.query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    for (aid, host) in &asset_host {
        for (oid, value, inv) in entity_hosts.get(host).into_iter().flatten() {
            if asset_entity.get(aid).copied().flatten() == Some(*oid) {
                continue;
            }
            let avalue = assets.iter().find(|(id, _, _)| id == aid).map(|(_, _, v)| v.as_str()).unwrap_or("");
            out.push(cand(Ref::new("asset", *aid), Ref::new("osint_entity", *oid), "corresponds_to", "entity-asset", format!("The asset {avalue} is the host of the entity {value} of {inv}"), vec![m("asset.value", avalue, "entity.value", value, "normalized")], "high", "derived"));
        }
    }
    for f in &findings {
        let Some((_, host)) = indicator_of(&f.target) else { continue };
        for (oid, value, inv) in entity_hosts.get(&host).into_iter().flatten().take(MAX_PER_FINDING) {
            out.push(cand(Ref::new("finding", f.id), Ref::new("osint_entity", *oid), "affects", "finding-entity", format!("The finding's target is the host of the entity {value} of {inv}"), vec![m("finding.affected_target", &f.target, "entity.value", value, "normalized")], "medium", "derived"));
        }
    }

    // ── findings that share evidence
    let mut by_evidence: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    let mut st = c.prepare("SELECT l.ref_id, l.finding_id FROM finding_links l JOIN findings f ON f.id = l.finding_id WHERE f.project_id = ?1 AND l.kind = 'evidence' ORDER BY l.ref_id, l.finding_id")?;
    for row in st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))? {
        let (ev, f) = row?;
        by_evidence.entry(ev).or_default().push(f);
    }
    for (ev, fs) in &by_evidence {
        let mut pairs = 0;
        'outer: for (i, a) in fs.iter().enumerate() {
            for b in &fs[i + 1..] {
                if pairs >= MAX_PAIRS_PER_GROUP {
                    break 'outer;
                }
                pairs += 1;
                out.push(cand(Ref::new("finding", *a), Ref::new("finding", *b), "related_to", "shared-evidence", format!("Both findings are linked to evidence #{ev}"), vec![m("finding.evidence", &format!("#{ev}"), "finding.evidence", &format!("#{ev}"), "exact")], "medium", "derived"));
            }
        }
    }

    // ── possible duplicates: the same CVE on the same host, or the same title on the same target
    let mut groups: BTreeMap<(String, String, String), Vec<&Finding>> = BTreeMap::new();
    for f in &findings {
        let host = indicator_of(&f.target).map(|(_, h)| h).unwrap_or_else(|| f.target.to_ascii_lowercase());
        if host.is_empty() {
            continue;
        }
        for cve in &f.cves {
            groups.entry(("cve".into(), cve.clone(), host.clone())).or_default().push(f);
        }
        groups.entry(("title".into(), norm_title(&f.title), f.target.to_ascii_lowercase())).or_default().push(f);
    }
    for ((how, value, place), fs) in groups {
        if fs.len() < 2 || value.is_empty() {
            continue;
        }
        let mut pairs = 0;
        'pairs: for (i, a) in fs.iter().enumerate() {
            for b in &fs[i + 1..] {
                if pairs >= MAX_PAIRS_PER_GROUP {
                    break 'pairs;
                }
                pairs += 1;
                let (reason, matched, confidence) = if how == "cve" {
                    (format!("Both findings name {value} on {place}"), vec![m("finding.cve", &value, "finding.cve", &value, "exact"), m("finding.affected_target", &a.target, "finding.affected_target", &b.target, "normalized")], "high")
                } else {
                    (format!("Both findings have the title “{}” on {place}", a.title), vec![m("finding.title", &a.title, "finding.title", &b.title, "normalized"), m("finding.affected_target", &a.target, "finding.affected_target", &b.target, "exact")], "medium")
                };
                out.push(cand(Ref::new("finding", a.id), Ref::new("finding", b.id), "possible_duplicate", "duplicate", reason, matched, confidence, "inferred"));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "correlate_tests.rs"]
mod tests;
