// SPDX-License-Identifier: Apache-2.0
//! Analysis over data already stored (nothing here contacts a network):
//!
//! * IOC correlation: where each indicator (address, domain, URL host, e-mail, file hash) of a
//!   project appears (assets, scope, findings, linked OSINT investigations, saved indicators) and
//!   what cached threat-intelligence results say about it.
//! * Exposure paths: entry → name → address → service → vulnerability → finding chains, ranked
//!   by vulnerability priority.
//! * Run comparison: a line diff of two tool runs' stored output (free text is compared as text).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::osint::normalize;
use crate::scope::{self, Target};

/* ───────────────────────── IOC correlation ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sighting {
    /// asset, scope, finding, osint, saved, evidence
    pub source: &'static str,
    pub detail: String,
    pub ref_kind: Option<&'static str>,
    pub ref_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TiVerdict {
    pub provider: String,
    pub level: String,
    pub label: String,
    pub fetched_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    pub kind: &'static str,
    pub value: String,
    pub sightings: Vec<Sighting>,
    /// number of different kinds of sources
    pub sources: usize,
    pub ti: Vec<TiVerdict>,
    /// a provider reported it as malicious or suspicious, or an OSINT entity is flagged
    pub flagged: bool,
}

/// (kind, normalized value) for a raw host, address or URL; None when it is neither.
pub fn indicator_of(raw: &str) -> Option<(&'static str, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("://") {
        let host = url::Url::parse(raw).ok()?.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
        return indicator_of(&host);
    }
    if let Ok(ip) = normalize::ip(raw) {
        return Some(("ip", ip));
    }
    match scope::parse_target(raw) {
        Some(Target::Host(h)) => normalize::domain(&h).ok().map(|d| ("domain", d)),
        Some(Target::Ip(ip)) => Some(("ip", ip.to_string())),
        _ => None,
    }
}

#[derive(Default)]
struct Collector {
    map: BTreeMap<(&'static str, String), Vec<Sighting>>,
    flagged: BTreeSet<(&'static str, String)>,
    /// saved indicators the analyst marked false positives
    dismissed: BTreeSet<(&'static str, String)>,
}

impl Collector {
    fn add(&mut self, key: (&'static str, String), s: Sighting) {
        let list = self.map.entry(key).or_default();
        if list.len() < 50 && !list.contains(&s) {
            list.push(s);
        }
    }
    fn add_raw(&mut self, raw: &str, s: Sighting) {
        if let Some(k) = indicator_of(raw) {
            self.add(k, s);
        }
    }
}

fn sighting(source: &'static str, detail: String, ref_kind: Option<&'static str>, ref_id: Option<i64>) -> Sighting {
    Sighting { source, detail: detail.chars().take(300).collect(), ref_kind, ref_id }
}

pub fn correlate(c: &Connection, project_id: i64) -> AppResult<Vec<Indicator>> {
    let mut col = Collector::default();

    // assets: names, addresses, hosts of web services and endpoints, addresses of services
    let mut st = c.prepare("SELECT id, type, value FROM assets WHERE project_id = ?1 AND type IN ('domain','subdomain','ip','http_service','endpoint','service')")?;
    for row in st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, kind, value) = row?;
        let raw = if kind == "service" { crate::workspace::discovery::service_host(&value).unwrap_or_default() } else { value.clone() };
        col.add_raw(&raw, sighting("asset", format!("{kind}: {value}"), Some("asset"), Some(id)));
    }
    // in-scope entries
    for e in crate::commands::projects::scope_entries(c, project_id)? {
        if matches!(e.kind.as_str(), "domain" | "ip" | "url") {
            col.add_raw(&e.value, sighting("scope", if e.in_scope { "In scope".into() } else { "Excluded from scope".into() }, None, None));
        }
    }
    // findings' affected targets
    let mut st = c.prepare("SELECT id, title, affected_target FROM findings WHERE project_id = ?1 AND affected_target <> ''")?;
    for row in st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, title, target) = row?;
        col.add_raw(&target, sighting("finding", title, Some("finding"), Some(id)));
    }
    // files analysed by the file triage and kept as evidence (suspicious samples, not every
    // stored file: an imported scan report's hash is no indicator)
    let mut st = c.prepare("SELECT id, file_name, sha256 FROM evidence WHERE project_id = ?1 AND kind = 'file' AND source_module = 'file_triage' AND sha256 IS NOT NULL")?;
    for row in st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?)))? {
        let (id, name, sha) = row?;
        col.add(("file_hash", sha.to_ascii_lowercase()), sighting("evidence", format!("Analysed file {}", name.unwrap_or_default()), Some("evidence"), Some(id)));
    }
    // entities of OSINT investigations linked to the project
    let mut st = c.prepare(
        "SELECT e.id, e.type, e.value, e.flagged, i.name FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id
         WHERE i.project_id = ?1 AND e.type IN ('domain','ip','url','email','file_hash')",
    )?;
    for row in st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0, r.get::<_, String>(4)?)))? {
        let (id, kind, value, flagged, inv) = row?;
        let key = match kind.as_str() {
            "email" => Some(("email", value.to_ascii_lowercase())),
            "file_hash" => Some(("file_hash", value.to_ascii_lowercase())),
            _ => indicator_of(&value),
        };
        if let Some(k) = key {
            if flagged {
                col.flagged.insert(k.clone());
            }
            col.add(k, sighting("osint", format!("{inv}: {kind} {value}"), Some("osint_entity"), Some(id)));
        }
    }

    // cached threat intelligence and saved indicators for exactly these indicators
    let mut ti: HashMap<(&'static str, String), Vec<TiVerdict>> = HashMap::new();
    let mut ti_st = c.prepare("SELECT provider, data, fetched_at FROM ti_cache WHERE indicator_key = ?1 AND found = 1")?;
    let keys: Vec<(&'static str, String)> = col.map.keys().cloned().collect();
    for key in &keys {
        let ti_kind = match key.0 {
            "file_hash" => "file",
            "email" => continue,
            k => k,
        };
        for row in ti_st.query_map(params![format!("{ti_kind}:{}", key.1)], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (provider, data, at) = row?;
            let v: Value = serde_json::from_str(&data).unwrap_or(Value::Null);
            let verdict = &v["verdict"];
            let level = verdict["level"].as_str().unwrap_or("unknown").to_string();
            if matches!(level.as_str(), "malicious" | "suspicious") {
                col.flagged.insert(key.clone());
            }
            ti.entry(key.clone()).or_default().push(TiVerdict { provider, label: verdict["label"].as_str().unwrap_or("").to_string(), level, fetched_at: at });
        }
        // a saved indicator says where it stands: expired, revoked and false positives are not
        // current, and the analyst's false positive outweighs a provider's verdict
        if let Some(s) = crate::ti::lifecycle::find(c, &key.1)? {
            if s.effective == "false_positive" {
                col.dismissed.insert(key.clone());
            }
            col.map.get_mut(key).expect("known key").push(sighting("saved", crate::ti::lifecycle::sighting_detail(&s), Some("ti_saved"), Some(s.id)));
        }
    }

    let mut out: Vec<Indicator> = col
        .map
        .into_iter()
        .map(|(key, sightings)| {
            let sources = sightings.iter().map(|s| s.source).collect::<BTreeSet<_>>().len();
            Indicator { flagged: col.flagged.contains(&key) && !col.dismissed.contains(&key), ti: ti.remove(&key).unwrap_or_default(), kind: key.0, value: key.1, sightings, sources }
        })
        .collect();
    out.sort_by(|a, b| b.flagged.cmp(&a.flagged).then(b.sources.cmp(&a.sources)).then(a.value.cmp(&b.value)));
    out.truncate(2000);
    Ok(out)
}

/* ───────────────────────── exposure paths ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathNode {
    /// entry, name, ip, service, web, vulnerability, finding
    pub kind: &'static str,
    pub label: String,
    pub ref_kind: Option<&'static str>,
    pub ref_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposurePath {
    pub nodes: Vec<PathNode>,
    pub priority: Option<String>,
    pub score: f64,
    pub exposure: String,
}

fn node(kind: &'static str, label: impl Into<String>, ref_kind: Option<&'static str>, ref_id: Option<i64>) -> PathNode {
    PathNode { kind, label: label.into(), ref_kind, ref_id }
}

/// Names that resolve to an address, from DNS records and the address asset's own data.
fn names_for(c: &Connection, project_id: i64, ip: &str) -> AppResult<Vec<String>> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut st = c.prepare("SELECT value FROM assets WHERE project_id = ?1 AND type = 'dns_record' AND (value LIKE '% A ' || ?2 OR value LIKE '% AAAA ' || ?2)")?;
    for v in st.query_map(params![project_id, ip], |r| r.get::<_, String>(0))? {
        if let Some(n) = v?.split_whitespace().next() {
            names.insert(n.to_string());
        }
    }
    if let Some(data) = c.query_row("SELECT data FROM assets WHERE project_id = ?1 AND type = 'ip' AND value = ?2", params![project_id, ip], |r| r.get::<_, String>(0)).optional()? {
        if let Some(list) = serde_json::from_str::<Value>(&data).ok().and_then(|v| v["names"].as_array().cloned()) {
            names.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    Ok(names.into_iter().take(3).collect())
}

/// Chains from the network entry to each open vulnerability with an asset, and to open findings
/// linked to assets, highest priority first.
pub fn exposure_paths(c: &Connection, project_id: i64) -> AppResult<Vec<ExposurePath>> {
    let mut paths = Vec::new();
    let mut st = c.prepare(
        "SELECT v.id, v.cve_id, v.priority, v.priority_score, v.exposure, a.id, a.type, a.value
         FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
         WHERE v.project_id = ?1 AND v.status IN ('open','triaged','in_remediation')
         ORDER BY v.priority, v.priority_score DESC LIMIT 200",
    )?;
    type Row = (i64, String, String, f64, String, i64, String, String);
    let rows: Vec<Row> = st
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)))?
        .collect::<Result<_, _>>()?;
    for (vid, cve, priority, score, exposure, aid, akind, avalue) in rows {
        let mut nodes = vec![node("entry", if exposure == "internet" { "Internet" } else if exposure == "internal" { "Internal network" } else { "Unknown entry" }, None, None)];
        nodes.extend(chain_to(c, project_id, aid, &akind, &avalue)?);
        nodes.push(node("vulnerability", format!("{cve} ({})", priority.to_uppercase()), Some("vulnerability"), Some(vid)));
        let mut fst = c.prepare(
            "SELECT f.id, f.title FROM finding_links l JOIN findings f ON f.id = l.finding_id
             WHERE l.kind = 'vulnerability' AND l.ref_id = ?1 AND f.status IN ('new','under_review','confirmed','in_remediation','reopened') LIMIT 3",
        )?;
        for f in fst.query_map(params![vid], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
            let (fid, title) = f?;
            nodes.push(node("finding", title, Some("finding"), Some(fid)));
        }
        paths.push(ExposurePath { nodes, priority: Some(priority), score, exposure });
    }
    // open findings linked to an asset but not reached through a vulnerability above
    let mut st = c.prepare(
        "SELECT f.id, f.title, f.severity, a.id, a.type, a.value FROM findings f
         JOIN finding_links l ON l.finding_id = f.id AND l.kind = 'asset' JOIN assets a ON a.id = l.ref_id
         WHERE f.project_id = ?1 AND f.status IN ('new','under_review','confirmed','in_remediation','reopened')
           AND NOT EXISTS (SELECT 1 FROM finding_links x WHERE x.finding_id = f.id AND x.kind = 'vulnerability') LIMIT 200",
    )?;
    type FRow = (i64, String, String, i64, String, String);
    let rows: Vec<FRow> = st.query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect::<Result<_, _>>()?;
    for (fid, title, severity, aid, akind, avalue) in rows {
        let exposure = crate::workspace::vulns::exposure_of_asset(c, aid)?;
        let mut nodes = vec![node("entry", if exposure == "internet" { "Internet" } else if exposure == "internal" { "Internal network" } else { "Unknown entry" }, None, None)];
        nodes.extend(chain_to(c, project_id, aid, &akind, &avalue)?);
        nodes.push(node("finding", format!("{title} ({severity})"), Some("finding"), Some(fid)));
        let score = match severity.as_str() {
            "critical" => 10.0,
            "high" => 8.0,
            "medium" => 5.5,
            "low" => 3.0,
            _ => 1.0,
        };
        paths.push(ExposurePath { nodes, priority: None, score, exposure: exposure.to_string() });
    }
    paths.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(paths)
}

/// name → address → service (or web service) leading to an asset.
fn chain_to(c: &Connection, project_id: i64, aid: i64, kind: &str, value: &str) -> AppResult<Vec<PathNode>> {
    let mut out = Vec::new();
    let names_label = |names: Vec<String>| if names.is_empty() { None } else { Some(names.join(", ")) };
    match kind {
        "service" => {
            if let Some(ip) = crate::workspace::discovery::service_host(value) {
                if let Some(n) = names_label(names_for(c, project_id, &ip)?) {
                    out.push(node("name", n, None, None));
                }
                out.push(node("ip", ip, None, None));
            }
            out.push(node("service", value, Some("asset"), Some(aid)));
        }
        "http_service" | "endpoint" => {
            if let Some((k, host)) = indicator_of(value) {
                if k == "ip" {
                    if let Some(n) = names_label(names_for(c, project_id, &host)?) {
                        out.push(node("name", n, None, None));
                    }
                    out.push(node("ip", host, None, None));
                } else {
                    out.push(node("name", host, None, None));
                }
            }
            out.push(node("web", value, Some("asset"), Some(aid)));
        }
        "ip" => {
            if let Some(n) = names_label(names_for(c, project_id, value)?) {
                out.push(node("name", n, None, None));
            }
            out.push(node("ip", value, Some("asset"), Some(aid)));
        }
        "domain" | "subdomain" => out.push(node("name", value, Some("asset"), Some(aid))),
        _ => out.push(node("service", value, Some("asset"), Some(aid))),
    }
    Ok(out)
}

/* ───────────────────────── run comparison ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    /// same, added, removed, gap (unchanged lines left out)
    pub op: &'static str,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunDiff {
    pub lines: Vec<DiffLine>,
    pub added: usize,
    pub removed: usize,
    /// one of the outputs was longer than the compared part
    pub truncated: bool,
}

const MAX_DIFF_LINES: usize = 4000;
const CONTEXT: usize = 2;

/// Line diff (longest common subsequence) with unchanged stretches reduced to 2 lines of context.
pub fn diff_text(a: &str, b: &str) -> RunDiff {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let truncated = al.len() > MAX_DIFF_LINES || bl.len() > MAX_DIFF_LINES;
    let (al, bl) = (&al[..al.len().min(MAX_DIFF_LINES)], &bl[..bl.len().min(MAX_DIFF_LINES)]);
    let (n, m) = (al.len(), bl.len());
    // lcs[i][j] = LCS length of al[i..] and bl[j..], in one flat table
    let mut lcs = vec![0u32; (n + 1) * (m + 1)];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i * (m + 1) + j] = if al[i] == bl[j] { lcs[(i + 1) * (m + 1) + j + 1] + 1 } else { lcs[(i + 1) * (m + 1) + j].max(lcs[i * (m + 1) + j + 1]) };
        }
    }
    let mut ops: Vec<(&'static str, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && al[i] == bl[j] {
            ops.push(("same", al[i]));
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i * (m + 1) + j + 1] >= lcs[(i + 1) * (m + 1) + j]) {
            ops.push(("added", bl[j]));
            j += 1;
        } else {
            ops.push(("removed", al[i]));
            i += 1;
        }
    }
    let changed: Vec<bool> = ops.iter().map(|(op, _)| *op != "same").collect();
    let near = |k: usize| (k.saturating_sub(CONTEXT)..=(k + CONTEXT).min(ops.len().saturating_sub(1))).any(|x| changed[x]);
    let mut lines = Vec::new();
    let mut gap = 0usize;
    for (k, (op, text)) in ops.iter().enumerate() {
        if *op == "same" && !near(k) {
            gap += 1;
            continue;
        }
        if gap > 0 {
            lines.push(DiffLine { op: "gap", text: format!("{gap} unchanged line{}", if gap == 1 { "" } else { "s" }) });
            gap = 0;
        }
        lines.push(DiffLine { op, text: text.to_string() });
    }
    if gap > 0 {
        lines.push(DiffLine { op: "gap", text: format!("{gap} unchanged line{}", if gap == 1 { "" } else { "s" }) });
    }
    RunDiff { added: ops.iter().filter(|o| o.0 == "added").count(), removed: ops.iter().filter(|o| o.0 == "removed").count(), lines, truncated }
}

/// Compares the stored (redacted) output of two tool runs.
pub fn compare_runs(c: &Connection, a: i64, b: i64) -> AppResult<RunDiff> {
    let out = |id: i64| -> AppResult<String> {
        c.query_row("SELECT COALESCE(output, '') FROM executions WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("tool run {id}")))
    };
    Ok(diff_text(&out(a)?, &out(b)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn indicators_are_normalized() {
        assert_eq!(indicator_of("HTTPS://WWW.Example.com:8443/x"), Some(("domain", "www.example.com".into())));
        assert_eq!(indicator_of("::ffff:192.0.2.1"), Some(("ip", "192.0.2.1".into())));
        assert_eq!(indicator_of("http://[2001:db8::1]/"), Some(("ip", "2001:db8::1".into())));
        assert_eq!(indicator_of("not a host"), None);
    }

    #[test]
    fn correlation_joins_sources_and_cached_verdicts() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (2,'Other','active','t','t')", [])?;
            c.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (1,'ip','203.0.113.7','203.0.113.7','passive','t','t','t','t')", [])?;
            c.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (1,'service','203.0.113.7:22/tcp','203.0.113.7:22/tcp','nmap','t','t','t','t')", [])?;
            c.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (2,'ip','198.51.100.1','198.51.100.1','passive','t','t','t','t')", [])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (1,'Weak SSH','medium','new','ssh://203.0.113.7:22','t','t')", [])?;
            c.execute("INSERT INTO osint_investigations (id, name, target_type, target_value, project_id, created_at, updated_at) VALUES (1,'Recon','domain','example.com',1,'t','t')", [])?;
            c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, flagged, first_seen, last_seen) VALUES (1,'ip','203.0.113.7','203.0.113.7','203.0.113.7',0,'t','t')", [])?;
            c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, flagged, first_seen, last_seen) VALUES (1,'domain','evil.example.net','evil.example.net','evil.example.net',1,'t','t')", [])?;
            c.execute(
                "INSERT INTO ti_cache (provider, indicator_key, kind, indicator, found, data, fetched_at) VALUES ('abuseipdb','ip:203.0.113.7','ip','203.0.113.7',1,'{\"verdict\":{\"level\":\"suspicious\",\"label\":\"37% confidence\"}}','t')",
                [],
            )?;
            let list = correlate(c, 1)?;
            let ip = list.iter().find(|i| i.value == "203.0.113.7").expect("address correlated");
            assert_eq!(ip.sources, 3, "asset, finding and OSINT: {:?}", ip.sightings);
            assert!(ip.flagged);
            assert_eq!(ip.ti[0].label, "37% confidence");
            assert_eq!(list[0].value, "203.0.113.7", "flagged and most-seen first");
            assert!(list.iter().any(|i| i.value == "evil.example.net" && i.flagged), "flagged OSINT entities are flagged");
            assert!(!list.iter().any(|i| i.value == "198.51.100.1"), "other projects stay separate");

            // a file the file triage analysed is an indicator with its cached verdict; other stored files are not
            let sha = "ab".repeat(32);
            c.execute("INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at, source_module) VALUES (1,'file','File triage: drop.exe','utility',?1,10,'drop.exe','t','file_triage')", params![sha])?;
            c.execute("INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at, source_module) VALUES (1,'file','Nessus results','import',?1,10,'scan.nessus','t','scan_import')", params!["cd".repeat(32)])?;
            c.execute(
                "INSERT INTO ti_cache (provider, indicator_key, kind, indicator, found, data, fetched_at) VALUES ('virustotal',?1,'file',?2,1,'{\"verdict\":{\"level\":\"malicious\",\"label\":\"41/70\"}}','t')",
                params![format!("file:{sha}"), sha],
            )?;
            let list = correlate(c, 1)?;
            let file = list.iter().find(|i| i.value == sha).expect("analysed file");
            assert_eq!((file.kind, file.flagged, file.sightings[0].source, file.sightings[0].ref_kind), ("file_hash", true, "evidence", Some("evidence")));
            assert!(!list.iter().any(|i| i.value == "cd".repeat(32)), "an imported report's hash is not an indicator");

            // a saved indicator says where it stands; the analyst's false positive outweighs the provider
            c.execute("INSERT INTO ti_saved (kind, indicator, note, created_at, updated_at) VALUES ('ip','203.0.113.7','Scanner','t','t')", [])?;
            let id = c.last_insert_rowid();
            let saved = |list: &[Indicator]| list.iter().find(|i| i.value == "203.0.113.7").map(|i| (i.flagged, i.sightings.iter().find(|s| s.source == "saved").map(|s| s.detail.clone()).unwrap_or_default())).unwrap();
            assert_eq!(saved(&correlate(c, 1)?), (true, "Scanner".to_string()));
            crate::ti::lifecycle::update(c, id, &crate::ti::lifecycle::Changes { valid_until: Some("2020-01-31".into()), ..Default::default() })?;
            assert_eq!(saved(&correlate(c, 1)?), (true, "Scanner · expired 2020-01-31: no longer current".to_string()), "a stale save does not hide a provider's verdict");
            crate::ti::lifecycle::update(c, id, &crate::ti::lifecycle::Changes { status: Some("false_positive".into()), ..Default::default() })?;
            let (flagged, detail) = saved(&correlate(c, 1)?);
            assert!(!flagged && detail == "Scanner · marked a false positive", "{detail}");
            assert_eq!(correlate(c, 1)?.iter().find(|i| i.value == "203.0.113.7").unwrap().ti.len(), 1, "the provider's verdict stays visible");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn exposure_paths_lead_from_the_entry_to_the_finding() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO assets (id, project_id, type, value, key, source, data, first_seen, last_seen, created_at, updated_at) VALUES (1,1,'ip','203.0.113.7','203.0.113.7','passive','{\"names\":[\"www.example.com\"]}','t','t','t','t')", [])?;
            c.execute("INSERT INTO assets (id, project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (2,1,'service','203.0.113.7:443/tcp','203.0.113.7:443/tcp','nmap','t','t','t','t')", [])?;
            c.execute(
                "INSERT INTO vulnerabilities (id, project_id, cve_id, asset_id, status, exposure, priority, priority_score, created_at, updated_at) VALUES (1,1,'CVE-2024-3094',2,'open','internet','p1',13.0,'t','t')",
                [],
            )?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (1,1,'Backdoored xz','critical','new','t','t')", [])?;
            c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (1,'vulnerability',1,'t')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (2,1,'Default page','low','new','t','t')", [])?;
            c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (2,'asset',1,'t')", [])?;
            let paths = exposure_paths(c, 1)?;
            assert_eq!(paths.len(), 2);
            let labels: Vec<&str> = paths[0].nodes.iter().map(|n| n.label.as_str()).collect();
            assert_eq!(labels, vec!["Internet", "www.example.com", "203.0.113.7", "203.0.113.7:443/tcp", "CVE-2024-3094 (P1)", "Backdoored xz"]);
            assert_eq!(paths[1].nodes.last().map(|n| n.label.as_str()), Some("Default page (low)"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn run_outputs_are_compared_line_by_line() {
        let a = "Nmap scan report\n22/tcp open ssh\n80/tcp open http\nline\nline\nline\nline\nline\nDone";
        let b = "Nmap scan report\n22/tcp open ssh\n443/tcp open https\nline\nline\nline\nline\nline\nDone";
        let d = diff_text(a, b);
        assert_eq!((d.added, d.removed), (1, 1));
        let ops: Vec<&str> = d.lines.iter().map(|l| l.op).collect();
        assert!(ops.contains(&"gap"), "long unchanged stretches are reduced: {ops:?}");
        assert!(d.lines.iter().any(|l| l.op == "removed" && l.text == "80/tcp open http"));
        assert!(d.lines.iter().any(|l| l.op == "added" && l.text == "443/tcp open https"));
        assert_eq!(diff_text("same", "same").lines, vec![DiffLine { op: "gap", text: "1 unchanged line".into() }]);
        assert!(!diff_text("a", "b").truncated);
    }
}
