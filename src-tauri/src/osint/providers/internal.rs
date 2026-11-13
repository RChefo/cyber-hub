//! Importers for data ExploitX already holds: tool runs (Nmap output is parsed; other tools'
//! output is scanned for indicators), stored threat-intelligence lookups, cached CVE records,
//! project findings and authorized scope entries. No request leaves the computer.

use std::net::IpAddr;

use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::json;

use super::{ent, Builder, Error, Output};
use crate::db::Db;
use crate::osint::ingest::{EvidenceInput, Observation};
use crate::osint::model::{EntityType, Strength};
use crate::osint::normalize;

static IPV4: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap());
static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bhttps?://[^\s"'<>()\[\]{}]+"#).unwrap());
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b").unwrap());
static HASH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b").unwrap());
static CVE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d{4,8}\b").unwrap());

/// Endings that look like TLDs but are file names in tool output.
const FILE_EXTENSIONS: &[&str] = &[
    "json", "txt", "xml", "html", "htm", "js", "css", "php", "asp", "aspx", "jsp", "py", "rb", "pl", "sh", "exe", "dll", "so", "png", "jpg", "jpeg", "gif", "svg", "ico", "zip", "gz", "tar", "conf", "cfg", "ini", "log", "yml", "yaml", "md", "csv", "pdf", "doc", "docx", "bak", "old", "tmp", "lua", "nse", "jar", "war", "class", "go", "rs", "ts", "tsx", "map", "lock", "pem", "crt", "key", "db", "sqlite",
];

const MAX_EXTRACTED: usize = 500;

/// Indicators found in free text (no relationships: their meaning is unknown).
pub fn extract(text: &str) -> Vec<(EntityType, String)> {
    let mut out: Vec<(EntityType, String)> = vec![];
    // the normalized keys kept so far: each candidate is normalized once (Mission 6: every
    // candidate normalized all the kept ones again)
    let mut keys: std::collections::HashSet<(EntityType, String)> = std::collections::HashSet::new();
    let mut push = |t: EntityType, v: &str| {
        if out.len() < MAX_EXTRACTED {
            if let Ok(n) = normalize::normalize(t, v) {
                if keys.insert((t, n.key)) {
                    out.push((t, v.to_string()));
                }
            }
        }
    };
    let mut url_spans = vec![];
    for m in URL_RE.find_iter(text) {
        let v = m.as_str().trim_end_matches(['.', ',', ';', ':']);
        url_spans.push(m.range());
        push(EntityType::Url, v);
    }
    let mut email_spans = vec![];
    for m in EMAIL_RE.find_iter(text) {
        email_spans.push(m.range());
        push(EntityType::Email, m.as_str());
    }
    for m in IPV4.find_iter(text) {
        push(EntityType::Ip, m.as_str());
    }
    for tok in text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')' || c == '[' || c == ']') {
        if tok.matches(':').count() >= 2 {
            if let Ok(ip) = tok.trim_end_matches(['.', ';']).parse::<IpAddr>() {
                if ip.is_ipv6() {
                    push(EntityType::Ip, &ip.to_string());
                }
            }
        }
    }
    for m in DOMAIN_RE.find_iter(text) {
        // spans come in order and do not overlap: the one that could hold the match is found by
        // binary search (a scan of every URL per domain was quadratic in long tool output)
        let inside = |spans: &[std::ops::Range<usize>]| {
            let i = spans.partition_point(|s| s.start <= m.start());
            i > 0 && m.end() <= spans[i - 1].end
        };
        if inside(&url_spans) || inside(&email_spans) {
            continue;
        }
        let d = m.as_str();
        let tld = d.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        if FILE_EXTENSIONS.contains(&tld.as_str()) || d.chars().all(|c| c.is_ascii_digit() || c == '.') {
            continue;
        }
        push(EntityType::Domain, d);
    }
    for m in CVE_RE.find_iter(text) {
        push(EntityType::Vulnerability, m.as_str());
    }
    for m in HASH_RE.find_iter(text) {
        push(EntityType::FileHash, m.as_str());
    }
    out
}

static NMAP_HOST: Lazy<Regex> = Lazy::new(|| Regex::new(r"^Nmap scan report for (\S+)(?: \(([0-9a-fA-F:.]+)\))?").unwrap());
static NMAP_PORT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\d{1,5})/(tcp|udp|sctp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.+))?$").unwrap());
static NMAP_RDNS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^rDNS record for ([0-9a-fA-F:.]+): (\S+)").unwrap());

/// Nmap normal output → hosts, resolutions, open services and announced versions.
pub fn parse_nmap(output: &str, b: &mut Builder) -> usize {
    let mut host: Option<(usize, String)> = None;
    let mut found = 0;
    for line in output.lines().map(|l| l.trim_start_matches("[stderr] ").trim_end()) {
        if let Some(c) = NMAP_HOST.captures(line) {
            let first = c.get(1).unwrap().as_str();
            match c.get(2) {
                Some(ip) => {
                    let i = b.add(ent(EntityType::Ip, ip.as_str()));
                    if normalize::domain(first).is_ok() {
                        let d = b.add(ent(EntityType::Domain, first));
                        b.rel(d, i, "RESOLVES_TO", Strength::Direct);
                    }
                    host = Some((i, ip.as_str().to_string()));
                }
                None if normalize::ip(first).is_ok() => {
                    let i = b.add(ent(EntityType::Ip, first));
                    host = Some((i, first.to_string()));
                }
                None => host = None,
            }
            found += 1;
            continue;
        }
        if let Some(c) = NMAP_RDNS.captures(line) {
            let (ip, name) = (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str());
            if normalize::domain(name).is_ok() {
                let i = b.add(ent(EntityType::Ip, ip));
                let d = b.add(ent(EntityType::Domain, name));
                b.rel(i, d, "REVERSE_DNS", Strength::Direct);
            }
            continue;
        }
        if let (Some(c), Some((hi, hv))) = (NMAP_PORT.captures(line), host.as_ref()) {
            let (port, proto, name) = (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str(), c.get(4).unwrap().as_str());
            let shown = if hv.contains(':') { format!("[{hv}]") } else { hv.clone() };
            let mut s = ent(EntityType::Service, format!("{shown}:{port}/{proto}"));
            s.metadata.insert("service".into(), json!(name));
            let version = c.get(5).map(|m| m.as_str().trim().to_string()).filter(|v| !v.is_empty());
            if let Some(v) = &version {
                s.metadata.insert("version".into(), json!(v));
            }
            let si = b.add(s);
            b.rel(*hi, si, "EXPOSES_SERVICE", Strength::Direct);
            if let Some(v) = version {
                // "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)" → "OpenSSH 8.9p1"
                let tech: String = v.split(['(', ';']).next().unwrap_or("").split_whitespace().take(2).collect::<Vec<_>>().join(" ");
                if tech.chars().next().is_some_and(char::is_alphabetic) {
                    let t = b.add(ent(EntityType::Technology, tech));
                    b.rel(si, t, "USES_TECHNOLOGY", Strength::Direct);
                }
            }
            found += 1;
        }
    }
    found
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSource {
    pub kind: String,
    pub id: String,
    pub label: String,
    pub detail: String,
    pub at: String,
    /// the project the item belongs to (runs, findings, scope); None for items without a
    /// project (lookups, CVEs, runs started outside a project)
    pub project_id: Option<i64>,
    pub project_name: Option<String>,
    /// "linked" (the investigation's project), "other" (another project) or "none"
    pub association: String,
}

fn association(item: Option<i64>, linked: Option<i64>) -> String {
    match (item, linked) {
        (None, _) => "none".into(),
        (Some(a), Some(b)) if a == b => "linked".into(),
        _ => "other".into(),
    }
}

/// Importable items, newest first.
pub fn list_sources(db: &Db, project_id: Option<i64>) -> crate::error::AppResult<Vec<ImportSource>> {
    db.with(|c| {
        let mut out = vec![];
        // runs of the linked project first, then the others (each labelled with its project)
        let mut st = c.prepare(
            "SELECT e.id, e.tool_id, e.args, e.status, e.started_at, e.project_id, p.name FROM executions e LEFT JOIN projects p ON p.id = e.project_id
             WHERE e.kind = 'run' AND e.status != 'running' ORDER BY (e.project_id IS ?1) DESC, e.id DESC LIMIT 150",
        )?;
        let rows = st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, Option<i64>>(5)?, r.get::<_, Option<String>>(6)?)))?;
        for r in rows {
            let (id, tool, args, status, at, pid, pname) = r?;
            let args: Vec<String> = serde_json::from_str(&args).unwrap_or_default();
            out.push(ImportSource {
                kind: "run".into(),
                id: id.to_string(),
                label: format!("{tool} run #{id}"),
                detail: format!("{} · {status}", args.join(" ").chars().take(120).collect::<String>()),
                at,
                association: association(pid, project_id),
                project_id: pid,
                project_name: pname,
            });
        }
        let mut st = c.prepare("SELECT kind, indicator, MAX(searched_at) FROM ti_history GROUP BY kind, indicator ORDER BY MAX(searched_at) DESC LIMIT 100")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (kind, ind, at) = r?;
            out.push(ImportSource { kind: "lookup".into(), id: ind.clone(), label: format!("Threat intel lookup: {ind}"), detail: kind, at, project_id: None, project_name: None, association: "none".into() });
        }
        let mut st = c.prepare("SELECT id, fetched_at FROM cve_cache ORDER BY fetched_at DESC LIMIT 100")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, at) = r?;
            out.push(ImportSource { kind: "cve".into(), id: id.clone(), label: id, detail: "cached NVD record".into(), at, project_id: None, project_name: None, association: "none".into() });
        }
        if let Some(p) = project_id {
            let mut st = c.prepare("SELECT id, title, severity, created_at FROM findings WHERE project_id = ?1 ORDER BY id DESC LIMIT 200")?;
            for r in st.query_map(params![p], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))? {
                let (id, title, sev, at) = r?;
                out.push(ImportSource { kind: "finding".into(), id: id.to_string(), label: title, detail: format!("finding · {sev}"), at, project_id: Some(p), project_name: None, association: "linked".into() });
            }
            let n: i64 = c.query_row("SELECT COUNT(*) FROM project_targets WHERE project_id = ?1 AND in_scope = 1", params![p], |r| r.get(0))?;
            if n > 0 {
                out.push(ImportSource { kind: "scope".into(), id: p.to_string(), label: "Authorized scope of the linked project".into(), detail: format!("{n} in-scope entr{}", if n == 1 { "y" } else { "ies" }), at: String::new(), project_id: Some(p), project_name: None, association: "linked".into() });
            }
        }
        Ok(out)
    })
}

fn obs(kind: &str, source: &str, reference: Option<String>, summary: String, b: Builder, execution_id: Option<i64>, strength: Strength) -> Observation {
    b.finish(EvidenceInput { kind: kind.into(), source: source.into(), reference, observed_at: None, summary, data: json!({}), strength, operation_id: None, execution_id })
}

/// Build the observation for one importable item.
pub fn import(db: &Db, kind: &str, id: &str, project_id: Option<i64>) -> Result<Output, Error> {
    match kind {
        "run" => {
            let rid: i64 = id.parse().map_err(|_| Error::Invalid("Invalid run".into()))?;
            let row: Option<(String, String, String, String)> = db
                .with(|c| Ok(c.query_row("SELECT tool_id, args, output, started_at FROM executions WHERE id = ?1 AND kind = 'run'", params![rid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?))
                .map_err(|e| Error::Unavailable(e.to_string()))?;
            let (tool, args, output, at) = row.ok_or_else(|| Error::Invalid("Run not found".into()))?;
            let mut b = Builder::default();
            let parsed = if tool == "nmap" { parse_nmap(&output, &mut b) } else { 0 };
            if parsed == 0 {
                for (t, v) in extract(&output) {
                    b.add(ent(t, v));
                }
            }
            let n = b.entities.len();
            let args: Vec<String> = serde_json::from_str(&args).unwrap_or_default();
            let summary = format!("{tool} run #{rid} ({at}): {} {}\n{}", tool, args.join(" ").chars().take(300).collect::<String>(), if parsed > 0 { "Parsed Nmap hosts, resolutions and open services." } else { "Indicators extracted from the stored (redacted) output." });
            let strength = if parsed > 0 { Strength::Direct } else { Strength::Corroborating };
            let mut o = obs("tool_run", &tool, Some(format!("ExploitX run #{rid}")), summary, b, Some(rid), strength);
            o.evidence.observed_at = Some(at);
            Ok(Output { observations: if n > 0 { vec![o] } else { vec![] }, summary: format!("{n} entit{} from {tool} run #{rid}", if n == 1 { "y" } else { "ies" }), rate_note: None, from_cache: true })
        }
        "lookup" => {
            let ind = crate::ti::indicator::detect(id).map_err(Error::Invalid)?;
            let results = crate::commands::threat_intel::stored_results(db, &ind).map_err(|e| Error::Unavailable(e.to_string()))?;
            let mut out = super::ti::map_results(super::ti::entity_type_of(ind.kind), &ind.value, &results);
            out.from_cache = true;
            Ok(out)
        }
        "cve" => {
            let rec: Option<(String, String)> = db.with(|c| Ok(c.query_row("SELECT data, fetched_at FROM cve_cache WHERE id = ?1", params![id.to_uppercase()], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)).map_err(|e| Error::Unavailable(e.to_string()))?;
            let (data, _) = rec.ok_or_else(|| Error::Invalid("CVE not in the local cache".into()))?;
            let rec: crate::commands::intel::CveRecord = serde_json::from_str(&data).map_err(|_| Error::Invalid("Unreadable cached CVE record".into()))?;
            Ok(Output { observations: vec![super::ti::map_cve(&rec, "cache")], summary: format!("Cached NVD record {}", rec.id), rate_note: None, from_cache: true })
        }
        "finding" => {
            let fid: i64 = id.parse().map_err(|_| Error::Invalid("Invalid finding".into()))?;
            let p = project_id.ok_or_else(|| Error::Refused("Link the investigation to a project to import its findings".into()))?;
            let row: Option<(String, String, String, String, String)> = db
                .with(|c| Ok(c.query_row("SELECT title, severity, affected_target, description, cve FROM findings WHERE id = ?1 AND project_id = ?2", params![fid, p], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()?))
                .map_err(|e| Error::Unavailable(e.to_string()))?;
            let (title, sev, target, desc, cve) = row.ok_or_else(|| Error::Invalid("Finding not found in the linked project".into()))?;
            let mut b = Builder::default();
            for (t, v) in extract(&format!("{target}\n{cve}")) {
                b.add(ent(t, v));
            }
            let n = b.entities.len();
            let o = obs("finding", "findings", Some(format!("ExploitX finding #{fid}")), format!("Finding \"{title}\" ({sev}) on {target}: {}", desc.chars().take(400).collect::<String>()), b, None, Strength::Corroborating);
            Ok(Output { observations: if n > 0 { vec![o] } else { vec![] }, summary: format!("{n} entit{} from finding #{fid}", if n == 1 { "y" } else { "ies" }), rate_note: None, from_cache: true })
        }
        "scope" => {
            let p = project_id.ok_or_else(|| Error::Refused("Link the investigation to a project to import its scope".into()))?;
            let rows: Vec<(String, String)> = db
                .with(|c| {
                    let mut st = c.prepare("SELECT value, kind FROM project_targets WHERE project_id = ?1 AND in_scope = 1 ORDER BY id")?;
                    let v = st.query_map(params![p], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
                    Ok(v)
                })
                .map_err(|e| Error::Unavailable(e.to_string()))?;
            let mut b = Builder::default();
            for (v, t) in &rows {
                let et = match t.as_str() {
                    "ip" => EntityType::Ip,
                    "cidr" => EntityType::Netblock,
                    "url" => EntityType::Url,
                    "wildcard" => {
                        b.add(ent(EntityType::Domain, v.trim_start_matches("*.")));
                        continue;
                    }
                    _ => EntityType::Domain,
                };
                b.add(ent(et, v.clone()));
            }
            let n = b.entities.len();
            let o = obs("scope", "project_scope", Some(format!("ExploitX project #{p} scope")), format!("Authorized in-scope targets of project #{p}"), b, None, Strength::Direct);
            Ok(Output { observations: if n > 0 { vec![o] } else { vec![] }, summary: format!("{n} scope entr{}", if n == 1 { "y" } else { "ies" }), rate_note: None, from_cache: true })
        }
        _ => Err(Error::Unsupported("Unknown import source".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_labelled_with_their_project() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute_batch(
                "INSERT INTO projects (id, name, description, status, scope_notes, notes, created_at, updated_at) VALUES
                   (1, 'Linked', '', 'active', '', '', 'x', 'x'), (2, 'Other', '', 'active', '', '', 'x', 'x');",
            )?;
            for (id, pid) in [(1, Some(1)), (2, Some(2)), (3, None)] {
                c.execute(
                    "INSERT INTO executions (id, kind, tool_id, program, args, project_id, status, started_at, output) VALUES (?1, 'run', 'nmap', 'nmap', '[]', ?2, 'succeeded', 'x', '')",
                    params![id, pid],
                )?;
            }
            Ok(())
        })
        .unwrap();
        let list = list_sources(&db, Some(1)).unwrap();
        let runs: Vec<(String, String, Option<String>)> = list.iter().filter(|s| s.kind == "run").map(|s| (s.id.clone(), s.association.clone(), s.project_name.clone())).collect();
        assert_eq!(runs[0], ("1".into(), "linked".into(), Some("Linked".into())), "the linked project's runs come first");
        assert!(runs.contains(&("2".into(), "other".into(), Some("Other".into()))));
        assert!(runs.contains(&("3".into(), "none".into(), None)));
        let unlinked = list_sources(&db, None).unwrap();
        assert!(unlinked.iter().filter(|s| s.kind == "run").all(|s| s.association != "linked"));
    }

    #[test]
    fn extracts_indicators_without_file_name_noise() {
        let text = "Found admin@example.org on https://shop.example.com/a?x=1, host 93.184.216.34 and 2001:db8::5; \
                    config.json and report.pdf are files; see CVE-2021-44228, hash d41d8cd98f00b204e9800998ecf8427e; api.example.com";
        let got = extract(text);
        let has = |t: EntityType, v: &str| got.iter().any(|(gt, gv)| *gt == t && gv == v);
        assert!(has(EntityType::Email, "admin@example.org"));
        assert!(has(EntityType::Url, "https://shop.example.com/a?x=1"));
        assert!(has(EntityType::Ip, "93.184.216.34") && has(EntityType::Ip, "2001:db8::5"));
        assert!(has(EntityType::Domain, "api.example.com"));
        assert!(!has(EntityType::Domain, "config.json") && !has(EntityType::Domain, "report.pdf"));
        assert!(!has(EntityType::Domain, "example.org"), "the email's domain is not extracted separately");
        assert!(!has(EntityType::Domain, "shop.example.com"), "URL hosts come from the URL itself");
        assert!(has(EntityType::Vulnerability, "CVE-2021-44228"));
        assert!(has(EntityType::FileHash, "d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn parses_nmap_normal_output() {
        let out = "Starting Nmap 7.94 ( https://nmap.org )\n\
                   Nmap scan report for scanme.example.org (45.33.32.156)\n\
                   Host is up (0.12s latency).\n\
                   rDNS record for 45.33.32.156: li982-156.members.linode.com\n\
                   PORT     STATE    SERVICE VERSION\n\
                   22/tcp   open     ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)\n\
                   25/tcp   filtered smtp\n\
                   80/tcp   open     http    Apache httpd 2.4.7 ((Ubuntu))\n\
                   Nmap scan report for 192.0.2.10\n\
                   443/tcp  open     https\n";
        let mut b = Builder::default();
        assert_eq!(parse_nmap(out, &mut b), 5);
        let rels: Vec<&str> = b.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["RESOLVES_TO", "REVERSE_DNS", "EXPOSES_SERVICE", "USES_TECHNOLOGY", "EXPOSES_SERVICE", "USES_TECHNOLOGY", "EXPOSES_SERVICE"]);
        let techs: Vec<&str> = b.entities.iter().filter(|e| e.entity_type == EntityType::Technology).map(|e| e.value.as_str()).collect();
        assert_eq!(techs, vec!["OpenSSH 6.6.1p1", "Apache httpd"]);
        assert!(b.entities.iter().any(|e| e.value == "192.0.2.10:443/tcp"));
        assert!(!b.entities.iter().any(|e| e.value.contains(":25/")), "filtered ports are not services");
    }
}
