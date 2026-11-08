//! Import of scanner output into a project (docs/DATA_MODEL.md#scan-import).
//!
//! Supported files: Nmap XML, Nuclei JSON lines (or its JSON array export), Nessus v2 (`.nessus`),
//! Burp Suite issue export (XML), OWASP ZAP JSON report and SARIF 2.1.0. Reading a file never
//! contacts anything. The file itself is kept in the evidence vault and every imported finding is
//! linked to it.
//!
//! * Findings are deduplicated by a fingerprint of tool, rule and location. A finding seen again in
//!   a later import is not duplicated: its history records the sighting, a resolved finding can be
//!   reopened, and a finding the analyst dismissed (false positive, accepted risk) stays dismissed.
//! * Every network target is checked against the project scope. Items outside it are counted and
//!   listed in the preview, never recorded. Source-code locations (SARIF) have no network target.
//! * Request and response bodies are not copied into findings; they stay in the stored file. Text
//!   that is copied (plugin output, extracted values, evidence strings) goes through the secret
//!   redaction used for tool output.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::commands::activity::log;
use crate::commands::projects::{finding_write, scope_entries, Evidence, FindingInput};
use crate::error::{validation, AppResult};
use crate::redact::redact_text;
use crate::scope::{self, ScopeEntry};
use crate::util::now;
use crate::workspace::assets::{self, with_savepoint};
use crate::workspace::discovery::{self, Batch, Certainty};
use crate::workspace::findings as lifecycle;
use crate::workspace::templates::{self, FindingTemplate};
use crate::workspace::timeline;

/// Largest file accepted for import.
pub const MAX_FILE_BYTES: usize = 50 * 1024 * 1024;
/// Findings read from one file; the rest is reported, not read.
pub const MAX_FINDINGS: usize = 10_000;
/// Asset values read from one file.
pub const MAX_ASSETS: usize = 20_000;
/// Locations listed per grouped finding (ZAP alert instances, SARIF results of one rule).
const MAX_INSTANCES: usize = 25;
/// Imports kept in a project's history list (older ones stay in the database).
pub const HISTORY_LIMIT: i64 = 50;

/* ───────────────────────── formats ───────────────────────── */

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Nmap,
    Nuclei,
    Nessus,
    Burp,
    Zap,
    Sarif,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Nmap => "nmap",
            Format::Nuclei => "nuclei",
            Format::Nessus => "nessus",
            Format::Burp => "burp",
            Format::Zap => "zap",
            Format::Sarif => "sarif",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Format::Nmap => "Nmap XML",
            Format::Nuclei => "Nuclei JSON",
            Format::Nessus => "Nessus (.nessus)",
            Format::Burp => "Burp Suite issues (XML)",
            Format::Zap => "OWASP ZAP report (JSON)",
            Format::Sarif => "SARIF 2.1.0",
        }
    }
}

/// A finding as read from the file, before scope and deduplication.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: &'static str,
    pub confidence: &'static str,
    /// what the finding is about, as shown (URL, `host:port/proto`, `file:line`)
    pub target: String,
    /// network host checked against the scope; `None` for source-code locations
    #[serde(skip)]
    pub host: Option<String>,
    /// the asset the finding belongs to, linked after import (`type`, value)
    #[serde(skip)]
    pub asset: Option<(&'static str, String)>,
    #[serde(skip)]
    pub description: String,
    #[serde(skip)]
    pub remediation: String,
    #[serde(skip)]
    pub technical: String,
    #[serde(skip)]
    pub references: Vec<String>,
    #[serde(skip)]
    pub cve: String,
    #[serde(skip)]
    pub category: String,
    #[serde(skip)]
    pub tags: Vec<String>,
    #[serde(skip)]
    pub fingerprint: String,
    /// canonical CVSS vector reported by the tool, when it is a valid v3.x or v4.0 vector
    #[serde(skip)]
    pub cvss: String,
}

/// The canonical form of a tool's CVSS vector, or empty when it is missing or not valid (the text
/// stays in the finding's details either way).
fn valid_cvss(raw: &str) -> String {
    crate::cvss::parse(raw).map(|c| c.vector).unwrap_or_default()
}

/// An asset value found in the file. `kind` `name` becomes a domain or subdomain once the scope is
/// known.
#[derive(Clone, Debug, PartialEq)]
pub struct AssetItem {
    pub kind: &'static str,
    pub value: String,
    pub host: String,
    pub data: Value,
}

#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub format: Option<Format>,
    pub tool: String,
    pub findings: Vec<ImportedFinding>,
    pub assets: Vec<AssetItem>,
    pub warnings: Vec<String>,
    /// findings or assets past the limits, not read
    pub truncated: usize,
    /// findings the file itself marks as false positives (ZAP confidence 0), not imported
    pub marked_false_positive: usize,
    /// findings with the same fingerprint inside the file, merged into the first
    pub merged: usize,
}

impl Parsed {
    fn new(format: Format, tool: &str) -> Self {
        Parsed { format: Some(format), tool: tool.into(), ..Default::default() }
    }
    fn push_finding(&mut self, f: ImportedFinding) {
        if self.findings.len() >= MAX_FINDINGS {
            self.truncated += 1;
        } else {
            self.findings.push(f);
        }
    }
    fn push_asset(&mut self, kind: &'static str, value: &str, host: &str, data: Value) {
        if value.trim().is_empty() {
            return;
        }
        if self.assets.len() >= MAX_ASSETS {
            self.truncated += 1;
        } else {
            self.assets.push(AssetItem { kind, value: value.trim().to_string(), host: host.trim().to_string(), data });
        }
    }
    /// Merges findings with the same fingerprint (keeps the first, adds the other locations).
    fn dedupe(&mut self) {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut out: Vec<ImportedFinding> = Vec::with_capacity(self.findings.len());
        for f in std::mem::take(&mut self.findings) {
            match seen.get(&f.fingerprint) {
                Some(&i) => {
                    self.merged += 1;
                    if !f.technical.is_empty() && out[i].technical.len() < 20_000 && !out[i].technical.contains(&f.technical) {
                        out[i].technical.push_str("\n\n");
                        out[i].technical.push_str(&f.technical);
                    }
                }
                None => {
                    seen.insert(f.fingerprint.clone(), out.len());
                    out.push(f);
                }
            }
        }
        self.findings = out;
    }
}

/* ───────────────────────── helpers ───────────────────────── */

/// At most `max` characters, cut on a character boundary, with an ellipsis when cut.
pub fn trunc(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Plain text from the small HTML fragments scanners write (ZAP, Burp): tags dropped, block ends
/// and line breaks kept as new lines, entities decoded. The result is only ever shown as text.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let Some(end) = after.find('>') else {
            // a lone '<' is text
            out.push_str(after);
            rest = "";
            break;
        };
        let tag = after[1..end].trim().to_ascii_lowercase();
        let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        match name {
            "br" | "p" | "div" | "tr" | "ul" | "ol" | "h1" | "h2" | "h3" | "h4" | "table" => out.push('\n'),
            "li" if !tag.starts_with('/') => out.push_str("\n• "),
            _ => {}
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    let decoded = decode_entities(&out);
    // collapse runs of blank lines and trailing spaces
    let mut lines: Vec<&str> = Vec::new();
    for l in decoded.lines().map(str::trim_end) {
        if l.trim().is_empty() && lines.last().map_or(true, |p| p.trim().is_empty()) {
            continue;
        }
        lines.push(l);
    }
    lines.join("\n").trim().to_string()
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let semi = after[..after.len().min(12)].find(';');
        let decoded = semi.and_then(|j| {
            let name = &after[1..j];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" | "#39" => Some('\''),
                "nbsp" => Some(' '),
                _ if name.starts_with("#x") || name.starts_with("#X") => u32::from_str_radix(&name[2..], 16).ok().and_then(char::from_u32),
                _ if name.starts_with('#') => name[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            ch.map(|c| (c, j))
        });
        match decoded {
            Some((c, j)) => {
                out.push(if c.is_control() && c != '\n' && c != '\t' { ' ' } else { c });
                rest = &after[j + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn severity_word(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        _ => "info",
    }
}

fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.trim().to_lowercase().as_bytes());
        h.update([0x1f]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Host of a URL, `host:port`, `[v6]:port` or plain host value.
pub fn host_of(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains("://") {
        let u = url::Url::parse(s).ok()?;
        return u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_lowercase());
    }
    let s = s.split('/').next().unwrap_or(s);
    if let Some(v6) = s.strip_prefix('[') {
        return v6.split(']').next().map(str::to_lowercase);
    }
    match s.rsplit_once(':') {
        // one colon and a numeric suffix: host:port (several colons: a bare IPv6 address)
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => Some(h.to_lowercase()),
        _ => Some(s.to_lowercase()),
    }
}

/// `scheme://host[:port]` of an http(s) URL.
fn origin_of(s: &str) -> Option<String> {
    let u = url::Url::parse(s.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    let host = u.host_str()?;
    Some(match u.port() {
        Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
        None => format!("{}://{}", u.scheme(), host),
    })
}

fn bracket(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Strings of a JSON value that may be a string, a list of strings, or a comma-separated string.
fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => Vec::new(),
    }
}

fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn cve_list(items: impl IntoIterator<Item = String>) -> String {
    let mut out: Vec<String> = Vec::new();
    for c in items {
        let c = c.trim().to_uppercase();
        if c.starts_with("CVE-") && c.len() <= 20 && !out.contains(&c) && out.len() < 10 {
            out.push(c);
        }
    }
    out.join(", ")
}

fn tool_tags(tool: &str, extra: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut tags = vec!["imported".to_string(), tool.to_lowercase().replace(' ', "-")];
    for t in extra {
        let t = trunc(&t.to_lowercase(), 40);
        if !t.is_empty() && !tags.contains(&t) && tags.len() < 8 {
            tags.push(t);
        }
    }
    tags
}

/* ───────────────────────── detection ───────────────────────── */

/// The format of a file, from its content (the extension is not trusted).
pub fn detect(text: &str) -> Result<Format, String> {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('<') {
        return match xml_root(t).as_deref() {
            Some("nmaprun") => Ok(Format::Nmap),
            Some("NessusClientData_v2") => Ok(Format::Nessus),
            Some("issues") => Ok(Format::Burp),
            Some("NessusClientData") => Err("This is a Nessus v1 file; export the scan as .nessus (v2) instead".into()),
            Some(other) => Err(format!("XML files with a <{}> root are not a supported scan format", trunc(other, 40))),
            None => Err("The file is not valid XML".into()),
        };
    }
    if t.starts_with('{') || t.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            if v.get("runs").is_some_and(Value::is_array) && (v.get("version").and_then(Value::as_str).is_some_and(|x| x.starts_with("2.1")) || s(&v, "$schema").contains("sarif")) {
                return Ok(Format::Sarif);
            }
            if v.get("site").is_some() && (v.get("@programName").is_some() || v.get("@version").is_some() || v["site"].is_array()) {
                return Ok(Format::Zap);
            }
            let first = if v.is_array() { v.get(0).cloned().unwrap_or(Value::Null) } else { v.clone() };
            if first.get("template-id").is_some() || first.get("templateID").is_some() {
                return Ok(Format::Nuclei);
            }
            if v.as_array().is_some_and(|a| a.is_empty()) {
                return Err("The file is an empty list".into());
            }
            return Err("JSON files are accepted from Nuclei, OWASP ZAP and SARIF tools; this one is none of them".into());
        }
        // JSON lines
        if let Some(line) = t.lines().map(str::trim).find(|l| !l.is_empty()) {
            if serde_json::from_str::<Value>(line).ok().is_some_and(|v| v.get("template-id").is_some() || v.get("templateID").is_some()) {
                return Ok(Format::Nuclei);
            }
        }
        return Err("The file is not valid JSON".into());
    }
    Err("Choose an Nmap, Nessus or Burp Suite XML file, a Nuclei, OWASP ZAP or SARIF JSON file".into())
}

fn xml_root(xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    for _ in 0..64 {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => return Some(e.local_name().into_inner().to_string()),
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
    None
}

/// Reads a file: detects the format and parses it.
pub fn parse(text: &str) -> Result<Parsed, String> {
    let text = text.trim_start_matches('\u{feff}');
    let mut p = match detect(text)? {
        Format::Nmap => parse_nmap(text)?,
        Format::Nuclei => parse_nuclei(text)?,
        Format::Nessus => parse_nessus(text),
        Format::Burp => parse_burp(text),
        Format::Zap => parse_zap(text)?,
        Format::Sarif => parse_sarif(text)?,
    };
    p.dedupe();
    if p.findings.is_empty() && p.assets.is_empty() {
        p.warnings.push("The file contains no findings or hosts".into());
    }
    if p.truncated > 0 {
        p.warnings.push(format!("{} items past the import limits ({MAX_FINDINGS} findings, {MAX_ASSETS} hosts and services) were not read", p.truncated));
    }
    Ok(p)
}

/* ───────────────────────── XML streaming ───────────────────────── */

struct El {
    name: String,
    attrs: BTreeMap<String, String>,
    text: String,
}

impl El {
    fn attr(&self, k: &str) -> String {
        self.attrs.get(k).cloned().unwrap_or_default()
    }
}

enum Step<'a> {
    Open(&'a [El]),
    Close(&'a [El]),
}

/// Text kept per element; longer text is cut (a plugin output can be megabytes).
const MAX_ELEMENT_TEXT: usize = 256 * 1024;

fn element(e: &quick_xml::events::BytesStart) -> El {
    let mut attrs = BTreeMap::new();
    for a in e.attributes().flatten() {
        let k = a.key.local_name().into_inner().to_string();
        let v = a.normalized_value(quick_xml::XmlVersion::default()).map(|v| v.to_string()).unwrap_or_default();
        attrs.insert(k, v);
    }
    El { name: e.local_name().into_inner().to_string(), attrs, text: String::new() }
}

fn push_text(stack: &mut [El], t: &str) {
    if let Some(el) = stack.last_mut() {
        if el.text.len() < MAX_ELEMENT_TEXT {
            el.text.push_str(t);
        }
    }
}

/// Streams an XML document: `on` sees each element when it opens (attributes known) and when it
/// closes (its own text known), with the open elements as a stack. A DOCTYPE is skipped and never
/// processed (no entity expansion, nothing external is read); entities other than the predefined
/// and numeric ones are kept as written. A document that breaks off yields what came before.
fn walk_xml(xml: &str, warnings: &mut Vec<String>, mut on: impl FnMut(Step<'_>)) {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<El> = Vec::new();
    loop {
        match reader.read_event() {
            Err(e) => {
                warnings.push(format!("The file is not valid XML after byte {} ({e}); only what came before it was read", reader.buffer_position()));
                break;
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if stack.len() >= 64 {
                    warnings.push("The document is nested too deeply; the rest was not read".into());
                    break;
                }
                stack.push(element(&e));
                on(Step::Open(&stack));
            }
            Ok(Event::Empty(e)) => {
                stack.push(element(&e));
                on(Step::Open(&stack));
                on(Step::Close(&stack));
                stack.pop();
            }
            Ok(Event::End(_)) => {
                if !stack.is_empty() {
                    on(Step::Close(&stack));
                    stack.pop();
                }
            }
            Ok(Event::Text(t)) => push_text(&mut stack, &t.xml10_content()),
            Ok(Event::CData(t)) => push_text(&mut stack, &t.xml10_content()),
            Ok(Event::GeneralRef(r)) => {
                let name = r.xml10_content().to_string();
                let ch = match r.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    _ => match name.as_str() {
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "amp" => "&".into(),
                        "quot" => "\"".into(),
                        "apos" => "'".into(),
                        other => format!("&{other};"),
                    },
                };
                push_text(&mut stack, &ch);
            }
            _ => {}
        }
    }
}

/* ───────────────────────── Nmap ───────────────────────── */

fn parse_nmap(text: &str) -> Result<Parsed, String> {
    let run = discovery::parse_nmap(text)?;
    let mut p = Parsed::new(Format::Nmap, "Nmap");
    if !run.finished {
        p.warnings.push("The scan did not finish (no <finished> element); hosts it had not reached are not in the file".into());
    }
    for h in run.hosts.iter().filter(|h| h.up) {
        p.push_asset("ip", &h.address, &h.address, json!({ "names": h.hostnames }));
        for name in &h.hostnames {
            p.push_asset("name", name, name, json!({ "addresses": [h.address] }));
        }
        for port in h.ports.iter().filter(|x| x.state == "open" && x.port > 0) {
            let svc = format!("{}:{}/{}", bracket(&h.address), port.port, if port.proto.is_empty() { "tcp" } else { &port.proto });
            p.push_asset("service", &svc, &h.address, json!({ "service": port.service, "product": port.product, "version": port.version, "names": h.hostnames }));
            if !port.product.is_empty() {
                let version = [port.product.as_str(), port.version.as_str()].iter().filter(|x| !x.is_empty()).copied().collect::<Vec<_>>().join(" ");
                p.push_asset("technology", &port.product, &h.address, json!({ "seenOn": [svc], "versions": if port.version.is_empty() { json!([]) } else { json!([version]) } }));
            }
        }
    }
    Ok(p)
}

/* ───────────────────────── Nuclei ───────────────────────── */

fn parse_nuclei(text: &str) -> Result<Parsed, String> {
    let t = text.trim_start();
    let mut records: Vec<Value> = Vec::new();
    let mut bad_lines = 0usize;
    if t.starts_with('[') {
        match serde_json::from_str::<Value>(t) {
            Ok(Value::Array(a)) => records = a,
            _ => return Err("The Nuclei export is not a valid JSON list".into()),
        }
    } else {
        for line in t.lines().map(str::trim).filter(|l| !l.is_empty()) {
            match serde_json::from_str::<Value>(line) {
                Ok(v) if v.is_object() => records.push(v),
                _ => bad_lines += 1,
            }
        }
    }
    let mut p = Parsed::new(Format::Nuclei, "Nuclei");
    if bad_lines > 0 {
        p.warnings.push(format!("{bad_lines} lines were not valid JSON and were skipped"));
    }
    let mut failed = 0usize;
    for r in &records {
        let id = { let a = s(r, "template-id"); if a.is_empty() { s(r, "templateID") } else { a } };
        if id.is_empty() {
            continue;
        }
        // `-ms` also writes templates that did not match (`matcher-status: false`)
        if r.get("matcher-status").and_then(Value::as_bool) == Some(false) {
            failed += 1;
            continue;
        }
        let info = r.get("info").cloned().unwrap_or(Value::Null);
        let class = info.get("classification").cloned().unwrap_or(Value::Null);
        let matched = { let a = s(r, "matched-at"); if a.is_empty() { s(r, "matched") } else { a } };
        let url = s(r, "url");
        let host_field = s(r, "host");
        let target = [matched.as_str(), url.as_str(), host_field.as_str()].into_iter().find(|x| !x.is_empty()).unwrap_or("").to_string();
        let host = host_of(&host_field).or_else(|| host_of(&target));
        let matcher = s(r, "matcher-name");
        let ip = s(r, "ip");
        let origin = origin_of(&target).or_else(|| origin_of(&url)).or_else(|| origin_of(&host_field));
        if let (Some(o), Some(h)) = (origin.as_ref(), host.as_ref()) {
            p.push_asset("http_service", o, h, json!({ "sources": ["nuclei"] }));
        }
        if !ip.is_empty() {
            p.push_asset("ip", &ip, &ip, json!({ "names": host.iter().filter(|h| crate::osint::normalize::ip(h).is_err()).collect::<Vec<_>>() }));
        }
        let tags = strings(info.get("tags"));
        if tags.iter().any(|t| t == "tech") && !matcher.is_empty() {
            if let Some(h) = host.as_ref() {
                p.push_asset("technology", &matcher, h, json!({ "seenOn": [origin.clone().unwrap_or_else(|| target.clone())] }));
            }
        }
        let mut technical = String::new();
        if !matcher.is_empty() {
            technical.push_str(&format!("Matcher: {matcher}\n"));
        }
        if !target.is_empty() {
            technical.push_str(&format!("Matched at: {target}\n"));
        }
        let extracted = strings(r.get("extracted-results"));
        if !extracted.is_empty() {
            technical.push_str("Extracted:\n");
            for x in extracted.iter().take(10) {
                technical.push_str(&format!("  {}\n", trunc(x, 300)));
            }
        }
        let ts = s(r, "timestamp");
        if !ts.is_empty() {
            technical.push_str(&format!("Reported at: {ts}\n"));
        }
        let mut references = strings(info.get("reference"));
        references.truncate(20);
        let cwe = strings(class.get("cwe-id"));
        let cvss = s(&class, "cvss-score");
        let mut description = html_to_text(&s(&info, "description"));
        if !cvss.is_empty() {
            description.push_str(&format!("\n\nCVSS score reported by the template: {cvss} ({})", s(&class, "cvss-metrics")));
        }
        let category = cwe.first().map(|c| c.to_uppercase()).unwrap_or_else(|| { let ty = s(r, "type"); if ty.is_empty() { String::new() } else { format!("Nuclei {ty}") } });
        p.push_finding(ImportedFinding {
            rule_id: id.clone(),
            title: trunc(&{ let n = s(&info, "name"); if n.is_empty() { id.clone() } else if matcher.is_empty() { n } else { format!("{n} ({matcher})") } }, 200),
            severity: severity_word(&s(&info, "severity")),
            confidence: "medium",
            asset: origin.clone().map(|o| ("http_service", o)).or_else(|| (!ip.is_empty()).then(|| ("ip", ip.clone()))),
            target: trunc(&target, 500),
            host,
            description: trunc(description.trim(), 50_000),
            remediation: trunc(&s(&info, "remediation"), 50_000),
            technical: trunc(&redact_text(technical.trim()), 50_000),
            references,
            cve: cve_list(strings(class.get("cve-id"))),
            category: trunc(&category, 100),
            tags: tool_tags("nuclei", tags.into_iter().take(5)),
            fingerprint: fingerprint(&["nuclei", &id, &matcher, &target]),
            cvss: valid_cvss(&s(&class, "cvss-metrics")),
        });
    }
    if failed > 0 {
        p.warnings.push(format!("{failed} results that did not match (matcher-status false) were skipped"));
    }
    Ok(p)
}

/* ───────────────────────── Nessus ───────────────────────── */

/// A `ReportItem`: its attributes, and the text of its child elements by name.
type NessusItem = (BTreeMap<String, String>, BTreeMap<String, Vec<String>>);

#[derive(Default)]
struct NessusHost {
    name: String,
    props: BTreeMap<String, String>,
}

fn nessus_severity(s: &str) -> &'static str {
    match s.trim() {
        "4" => "critical",
        "3" => "high",
        "2" => "medium",
        "1" => "low",
        _ => "info",
    }
}

fn parse_nessus(text: &str) -> Parsed {
    let mut p = Parsed::new(Format::Nessus, "Nessus");
    let mut warnings = Vec::new();
    let mut host = NessusHost::default();
    let mut item: Option<NessusItem> = None;
    let mut done: Vec<(NessusHost, Vec<NessusItem>)> = Vec::new();
    let mut items: Vec<NessusItem> = Vec::new();
    walk_xml(text, &mut warnings, |step| match step {
        Step::Open(stack) => {
            let el = stack.last().expect("open element");
            match el.name.as_str() {
                "ReportHost" => {
                    host = NessusHost { name: el.attr("name"), props: BTreeMap::new() };
                    items.clear();
                }
                "ReportItem" => item = Some((el.attrs.clone(), BTreeMap::new())),
                _ => {}
            }
        }
        Step::Close(stack) => {
            let el = stack.last().expect("closing element");
            let parent = stack.len().checked_sub(2).map(|i| stack[i].name.as_str());
            match (el.name.as_str(), parent) {
                ("tag", Some("HostProperties")) => {
                    host.props.insert(el.attr("name"), el.text.trim().to_string());
                }
                ("ReportItem", _) => {
                    if let Some(it) = item.take() {
                        items.push(it);
                    }
                }
                ("ReportHost", _) => done.push((std::mem::take(&mut host), std::mem::take(&mut items))),
                (child, Some("ReportItem")) => {
                    if let Some((_, fields)) = item.as_mut() {
                        let list = fields.entry(child.to_string()).or_default();
                        if list.len() < 50 {
                            list.push(el.text.trim().to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    });
    p.warnings.extend(warnings);
    for (h, items) in done {
        let ip = h.props.get("host-ip").cloned().filter(|x| !x.is_empty()).unwrap_or_else(|| h.name.clone());
        let fqdn = h.props.get("host-fqdn").cloned().filter(|x| !x.is_empty()).or_else(|| (crate::osint::normalize::ip(&h.name).is_err()).then(|| h.name.clone()));
        let is_ip = crate::osint::normalize::ip(&ip).is_ok();
        let scope_host = ip.clone();
        if is_ip {
            p.push_asset("ip", &ip, &scope_host, json!({ "names": fqdn.iter().collect::<Vec<_>>() }));
        }
        if let Some(n) = fqdn.as_ref() {
            p.push_asset("name", n, n, json!({ "addresses": if is_ip { json!([ip]) } else { json!([]) } }));
        }
        for (attrs, fields) in items {
            let get = |k: &str| attrs.get(k).cloned().unwrap_or_default();
            let field = |k: &str| fields.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
            let port: u32 = get("port").parse().unwrap_or(0);
            let proto = { let x = get("protocol"); if x.is_empty() { "tcp".to_string() } else { x.to_lowercase() } };
            let plugin = get("pluginID");
            let svc = (port > 0 && is_ip).then(|| format!("{}:{port}/{proto}", bracket(&ip)));
            if let Some(svc) = svc.as_ref() {
                p.push_asset("service", svc, &scope_host, json!({ "service": get("svc_name"), "names": fqdn.iter().collect::<Vec<_>>() }));
            }
            let shown_host = fqdn.clone().filter(|_| !is_ip).unwrap_or_else(|| ip.clone());
            let target = if port > 0 { format!("{}:{port}/{proto}", bracket(&shown_host)) } else { shown_host.clone() };
            let synopsis = field("synopsis");
            let desc = field("description");
            let description = [synopsis.as_str(), desc.as_str()].iter().filter(|x| !x.is_empty()).copied().collect::<Vec<_>>().join("\n\n");
            let solution = field("solution");
            let mut technical = String::new();
            let cvss3 = field("cvss3_base_score");
            if !cvss3.is_empty() {
                technical.push_str(&format!("CVSS v3 base score (Nessus): {cvss3} {}\n", field("cvss3_vector")));
            }
            let output = field("plugin_output");
            if !output.is_empty() {
                technical.push_str("Plugin output:\n");
                technical.push_str(&trunc(&output, 8_000));
            }
            let mut references: Vec<String> = field("see_also").lines().map(str::trim).filter(|x| !x.is_empty()).map(String::from).take(20).collect();
            references.dedup();
            let cves = fields.get("cve").cloned().unwrap_or_default();
            p.push_finding(ImportedFinding {
                rule_id: plugin.clone(),
                title: trunc(&{ let n = get("pluginName"); if n.is_empty() { format!("Nessus plugin {plugin}") } else { n } }, 200),
                severity: nessus_severity(&get("severity")),
                confidence: "medium",
                asset: svc.clone().map(|s| ("service", s)).or_else(|| is_ip.then(|| ("ip", ip.clone()))),
                target: trunc(&target, 500),
                host: Some(scope_host.clone()),
                description: trunc(&description, 50_000),
                remediation: if solution.eq_ignore_ascii_case("n/a") { String::new() } else { trunc(&solution, 50_000) },
                technical: trunc(&redact_text(technical.trim()), 50_000),
                references,
                cve: cve_list(cves),
                category: trunc(&get("pluginFamily"), 100),
                tags: tool_tags("nessus", std::iter::empty()),
                fingerprint: fingerprint(&["nessus", &plugin, &ip, &port.to_string(), &proto]),
                cvss: { let v4 = valid_cvss(&field("cvss4_vector")); if v4.is_empty() { valid_cvss(&field("cvss3_vector")) } else { v4 } },
            });
        }
    }
    p
}

/* ───────────────────────── Burp Suite ───────────────────────── */

fn burp_severity(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
}

fn burp_confidence(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "certain" => "high",
        "firm" => "medium",
        _ => "low",
    }
}

fn parse_burp(text: &str) -> Parsed {
    let mut p = Parsed::new(Format::Burp, "Burp Suite");
    let mut warnings = Vec::new();
    let mut issues: Vec<(BTreeMap<String, String>, String)> = Vec::new(); // fields, host ip
    let mut cur: Option<(BTreeMap<String, String>, String)> = None;
    walk_xml(text, &mut warnings, |step| match step {
        Step::Open(stack) => {
            if stack.last().is_some_and(|e| e.name == "issue") {
                cur = Some((BTreeMap::new(), String::new()));
            }
        }
        Step::Close(stack) => {
            let el = stack.last().expect("closing element");
            let parent = stack.len().checked_sub(2).map(|i| stack[i].name.as_str());
            if el.name == "issue" {
                if let Some(i) = cur.take() {
                    issues.push(i);
                }
                return;
            }
            let Some((fields, ip)) = cur.as_mut() else { return };
            match (el.name.as_str(), parent) {
                // request/response pairs stay in the stored file
                ("requestresponse", Some("issue")) => {}
                (name, Some("issue")) => {
                    if name == "host" {
                        *ip = el.attr("ip");
                    }
                    fields.insert(name.to_string(), el.text.trim().to_string());
                }
                // only the request line of the first request is kept (method and path)
                ("request", Some("requestresponse")) if !fields.contains_key("_request_line") => {
                    let raw = if el.attr("base64") == "true" { decode_base64(el.text.trim()).unwrap_or_default() } else { el.text.clone() };
                    if let Some(line) = raw.lines().next() {
                        fields.insert("_request_line".into(), trunc(line, 300));
                    }
                }
                _ => {}
            }
        }
    });
    p.warnings.extend(warnings);
    for (f, ip) in issues {
        let get = |k: &str| f.get(k).cloned().unwrap_or_default();
        let host_url = get("host");
        let path = get("path");
        let location = get("location");
        let host = host_of(&host_url);
        let origin = origin_of(&host_url);
        if let (Some(o), Some(h)) = (origin.as_ref(), host.as_ref()) {
            p.push_asset("http_service", o, h, json!({ "sources": ["burp"] }));
        }
        if !ip.is_empty() {
            if let Some(h) = host.as_ref() {
                p.push_asset("ip", &ip, h, json!({ "names": [h] }));
            }
        }
        let target = format!("{}{}", host_url.trim_end_matches('/'), if path.starts_with('/') { path.clone() } else { format!("/{path}") });
        let mut description = html_to_text(&get("issueBackground"));
        let detail = html_to_text(&get("issueDetail"));
        if !detail.is_empty() {
            description = if description.is_empty() { detail.clone() } else { format!("{detail}\n\n{description}") };
        }
        let remediation = [html_to_text(&get("remediationDetail")), html_to_text(&get("remediationBackground"))].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join("\n\n");
        let mut technical = String::new();
        if !location.is_empty() {
            technical.push_str(&format!("Location: {location}\n"));
        }
        let rl = get("_request_line");
        if !rl.is_empty() {
            technical.push_str(&format!("Request: {rl}\n"));
        }
        technical.push_str("The full requests and responses are in the imported file (evidence).");
        let classifications = html_to_text(&get("vulnerabilityClassifications"));
        let cwe = classifications.split(|c: char| !c.is_ascii_alphanumeric() && c != '-').find(|w| w.starts_with("CWE-")).unwrap_or("").to_string();
        let references: Vec<String> = extract_urls(&get("references")).into_iter().take(20).collect();
        let ty = get("type");
        p.push_finding(ImportedFinding {
            rule_id: ty.clone(),
            title: trunc(&{ let n = get("name"); if n.is_empty() { format!("Burp issue {ty}") } else { n } }, 200),
            severity: burp_severity(&get("severity")),
            confidence: burp_confidence(&get("confidence")),
            asset: origin.clone().map(|o| ("http_service", o)),
            target: trunc(&target, 500),
            host,
            description: trunc(&description, 50_000),
            remediation: trunc(&remediation, 50_000),
            technical: trunc(&redact_text(&technical), 50_000),
            references,
            cve: String::new(),
            category: trunc(&cwe, 100),
            tags: tool_tags("burp", std::iter::empty()),
            cvss: String::new(),
            fingerprint: fingerprint(&["burp", &ty, &host_url, &path, &location]),
        });
    }
    p
}

fn decode_base64(s: &str) -> Option<String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    // the request line is at the start; 4 KB of input is plenty
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()).take(4096) {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(String::from_utf8_lossy(&out).to_string())
}

fn extract_urls(html: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in html.split(|c: char| c == '"' || c == '\'' || c == '<' || c == '>' || c.is_whitespace()) {
        if (part.starts_with("http://") || part.starts_with("https://")) && part.len() <= 2000 && !out.iter().any(|x| x == part) {
            out.push(decode_entities(part));
        }
    }
    out
}

/* ───────────────────────── OWASP ZAP ───────────────────────── */

fn zap_severity(riskcode: &str) -> &'static str {
    match riskcode.trim() {
        "3" => "high",
        "2" => "medium",
        "1" => "low",
        _ => "info",
    }
}

fn parse_zap(text: &str) -> Result<Parsed, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("The ZAP report is not valid JSON: {e}"))?;
    let mut p = Parsed::new(Format::Zap, "OWASP ZAP");
    let sites: Vec<Value> = match v.get("site") {
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        _ => Vec::new(),
    };
    for site in &sites {
        let name = s(site, "@name");
        let host = host_of(&name).or_else(|| { let h = s(site, "@host"); (!h.is_empty()).then(|| h.to_lowercase()) });
        let origin = origin_of(&name);
        if let (Some(o), Some(h)) = (origin.as_ref(), host.as_ref()) {
            p.push_asset("http_service", o, h, json!({ "sources": ["zap"] }));
        }
        for a in site.get("alerts").and_then(Value::as_array).into_iter().flatten() {
            let confidence = s(a, "confidence");
            if confidence == "0" {
                p.marked_false_positive += 1;
                continue;
            }
            let plugin = s(a, "pluginid");
            let alert_ref = { let r = s(a, "alertRef"); if r.is_empty() { plugin.clone() } else { r } };
            let instances: Vec<&Value> = a.get("instances").and_then(Value::as_array).map(|x| x.iter().collect()).unwrap_or_default();
            let mut technical = String::new();
            let count = { let c = s(a, "count"); if c.is_empty() { instances.len().to_string() } else { c } };
            technical.push_str(&format!("Instances: {count}\n"));
            for i in instances.iter().take(MAX_INSTANCES) {
                let mut line = format!("  {} {}", s(i, "method"), s(i, "uri"));
                let param = s(i, "param");
                if !param.is_empty() {
                    line.push_str(&format!(" (parameter {param})"));
                }
                let ev = s(i, "evidence");
                if !ev.is_empty() {
                    line.push_str(&format!(" evidence: {}", trunc(&ev, 200)));
                }
                technical.push_str(&line);
                technical.push('\n');
            }
            if instances.len() > MAX_INSTANCES {
                technical.push_str(&format!("  … and {} more in the imported file\n", instances.len() - MAX_INSTANCES));
            }
            let other = html_to_text(&s(a, "otherinfo"));
            if !other.is_empty() {
                technical.push_str(&format!("\n{}", trunc(&other, 4_000)));
            }
            let cwe = s(a, "cweid");
            let title = { let n = s(a, "alert"); if n.is_empty() { s(a, "name") } else { n } };
            let shown = if name.is_empty() { instances.first().map(|i| s(i, "uri")).unwrap_or_default() } else { name.clone() };
            p.push_finding(ImportedFinding {
                rule_id: alert_ref.clone(),
                title: trunc(if title.is_empty() { &plugin } else { &title }, 200),
                severity: zap_severity(&s(a, "riskcode")),
                confidence: match confidence.as_str() {
                    "3" | "4" => "high",
                    "1" => "low",
                    _ => "medium",
                },
                asset: origin.clone().map(|o| ("http_service", o)),
                target: trunc(&shown, 500),
                host: host.clone(),
                description: trunc(&html_to_text(&s(a, "desc")), 50_000),
                remediation: trunc(&html_to_text(&s(a, "solution")), 50_000),
                technical: trunc(&redact_text(technical.trim()), 50_000),
                references: extract_urls(&s(a, "reference")).into_iter().take(20).collect(),
                cve: String::new(),
                category: if cwe.is_empty() || cwe == "-1" || cwe == "0" { String::new() } else { format!("CWE-{cwe}") },
                tags: tool_tags("zap", std::iter::empty()),
                cvss: String::new(),
                fingerprint: fingerprint(&["zap", &alert_ref, &name]),
            });
        }
    }
    Ok(p)
}

/* ───────────────────────── SARIF ───────────────────────── */

/// GitHub's mapping of `security-severity` (CVSS-like 0–10) to a level.
fn security_severity(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "info"
    }
}

fn sarif_level(level: &str) -> &'static str {
    match level {
        "error" => "high",
        "warning" => "medium",
        "note" => "low",
        _ => "info",
    }
}

fn parse_sarif(text: &str) -> Result<Parsed, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("The SARIF file is not valid JSON: {e}"))?;
    let runs = v.get("runs").and_then(Value::as_array).cloned().unwrap_or_default();
    let tool = runs.first().map(|r| s(&r["tool"]["driver"], "name")).filter(|n| !n.is_empty()).unwrap_or_else(|| "SARIF".into());
    let mut p = Parsed::new(Format::Sarif, &trunc(&tool, 60));
    let mut skipped_kinds = 0usize;
    for run in &runs {
        let driver = &run["tool"]["driver"];
        let run_tool = { let n = s(driver, "name"); if n.is_empty() { tool.clone() } else { n } };
        let rules: Vec<Value> = driver.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
        let rule_by_id: BTreeMap<String, &Value> = rules.iter().map(|r| (s(r, "id"), r)).collect();
        for res in run.get("results").and_then(Value::as_array).into_iter().flatten() {
            // SARIF 2.1.0 §3.27.9: `pass` and `notApplicable` are not problems; other kinds
            // than `fail` (the default) carry no severity
            let kind = s(res, "kind");
            if kind == "pass" || kind == "notApplicable" {
                skipped_kinds += 1;
                continue;
            }
            let rule_id = { let r = s(res, "ruleId"); if r.is_empty() { res.get("rule").map(|x| s(x, "id")).unwrap_or_default() } else { r } };
            let rule = res.get("ruleIndex").and_then(Value::as_u64).and_then(|i| rules.get(i as usize)).or_else(|| rule_by_id.get(&rule_id).copied());
            let message = s(&res["message"], "text");
            let loc = &res["locations"][0]["physicalLocation"];
            let uri = s(&loc["artifactLocation"], "uri");
            let line = loc["region"].get("startLine").and_then(Value::as_u64);
            let target = match (uri.is_empty(), line) {
                (true, _) => String::new(),
                (false, Some(l)) => format!("{uri}:{l}"),
                (false, None) => uri.clone(),
            };
            let score = rule.and_then(|r| r["properties"].get("security-severity")).and_then(|x| x.as_f64().or_else(|| x.as_str().and_then(|t| t.parse().ok())));
            let level = { let l = s(res, "level"); if l.is_empty() { rule.map(|r| s(&r["defaultConfiguration"], "level")).unwrap_or_default() } else { l } };
            let severity = if !kind.is_empty() && kind != "fail" {
                "info"
            } else {
                score.map(security_severity).unwrap_or_else(|| sarif_level(if level.is_empty() { "warning" } else { &level }))
            };
            let title = rule.map(|r| { let t = s(&r["shortDescription"], "text"); if t.is_empty() { s(r, "name") } else { t } }).filter(|t| !t.is_empty()).unwrap_or_else(|| if rule_id.is_empty() { trunc(&message, 120) } else { rule_id.clone() });
            let rule_text = rule.map(|r| { let t = s(&r["fullDescription"], "text"); if t.is_empty() { s(&r["help"], "text") } else { t } }).unwrap_or_default();
            let description = [message.as_str(), rule_text.as_str()].iter().filter(|x| !x.is_empty()).copied().collect::<Vec<_>>().join("\n\n");
            let partial = res.get("partialFingerprints").or_else(|| res.get("fingerprints")).and_then(Value::as_object).and_then(|m| m.values().next()).and_then(Value::as_str).unwrap_or("").to_string();
            let line_s = line.map(|l| l.to_string()).unwrap_or_default();
            let fp = if partial.is_empty() { fingerprint(&["sarif", &run_tool, &rule_id, &uri, &line_s]) } else { fingerprint(&["sarif", &run_tool, &rule_id, &uri, &partial]) };
            let tags: Vec<String> = rule.map(|r| strings(r["properties"].get("tags"))).unwrap_or_default();
            let cwe = tags.iter().find_map(|t| t.to_lowercase().strip_prefix("external/cwe/cwe-").map(|n| format!("CWE-{n}")));
            let help_uri = rule.map(|r| s(r, "helpUri")).filter(|u| u.starts_with("http"));
            let snippet = s(&loc["region"]["snippet"], "text");
            p.push_finding(ImportedFinding {
                rule_id: rule_id.clone(),
                title: trunc(&title, 200),
                severity,
                confidence: match rule.map(|r| s(&r["properties"], "precision")).as_deref() {
                    Some("very-high") | Some("high") => "high",
                    Some("low") => "low",
                    _ => "medium",
                },
                asset: None,
                target: trunc(&target, 500),
                host: None,
                description: trunc(&description, 50_000),
                remediation: String::new(),
                technical: trunc(&redact_text(&if snippet.is_empty() { format!("Location: {target}") } else { format!("Location: {target}\n{}", trunc(&snippet, 2_000)) }), 50_000),
                references: help_uri.into_iter().collect(),
                cve: String::new(),
                category: trunc(&cwe.unwrap_or_default(), 100),
                tags: tool_tags(&run_tool, tags.into_iter().filter(|t| !t.starts_with("external/")).take(4)),
                cvss: String::new(),
                fingerprint: fp,
            });
        }
    }
    if skipped_kinds > 0 {
        p.warnings.push(format!("{skipped_kinds} results of kind pass or notApplicable were skipped"));
    }
    Ok(p)
}

/* ───────────────────────── preview and import ───────────────────────── */

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    /// also import informational findings (off by default: they are mostly inventory)
    #[serde(default)]
    pub include_info: bool,
    /// reopen resolved findings that the file reports again
    #[serde(default)]
    pub reopen_resolved: bool,
    /// use finding-library templates whose import rule matches (on by default)
    #[serde(default = "yes")]
    pub use_templates: bool,
    /// resolve open findings of earlier imports of the same tool that this file no longer reports
    /// on a host it covers (off by default: the analyst decides)
    #[serde(default)]
    pub resolve_missing: bool,
}

fn yes() -> bool {
    true
}

impl Default for Options {
    fn default() -> Self {
        Options { include_info: false, reopen_resolved: false, use_templates: true, resolve_missing: false }
    }
}

type Library = HashMap<String, FindingTemplate>;

fn library(c: &Connection, opts: Options) -> AppResult<Library> {
    if opts.use_templates {
        templates::by_rule(c)
    } else {
        Ok(HashMap::new())
    }
}

/// The library template whose import rule names this finding's rule.
fn template_for<'a>(lib: &'a Library, format: Format, f: &ImportedFinding) -> Option<&'a FindingTemplate> {
    if f.rule_id.is_empty() {
        return None;
    }
    lib.get(&templates::rule_key(format.as_str(), &f.rule_id))
}

/// A new finding written from a template: the template's vetted text replaces the scanner's
/// boilerplate; the location, CVEs and the scanner's evidence (technical details) stay.
fn apply_template(input: &mut FindingInput, t: &FindingTemplate) {
    input.title = t.title.clone();
    input.severity = t.severity.clone();
    if !t.category.is_empty() {
        input.category = t.category.clone();
    }
    if !t.description.is_empty() {
        input.description = t.description.clone();
    }
    if !t.remediation.is_empty() {
        input.remediation = t.remediation.clone();
    }
    let mut refs: Vec<Evidence> = t.references.iter().map(|u| Evidence { label: "Reference".into(), reference: u.clone() }).collect();
    for e in input.evidence.drain(..) {
        if refs.len() < 50 && !refs.iter().any(|r| r.reference == e.reference) {
            refs.push(e);
        }
    }
    input.evidence = refs;
    for tag in &t.tags {
        if input.tags.len() < 20 && !input.tags.contains(tag) {
            input.tags.push(tag.clone());
        }
    }
}

/// What an imported finding would do to the project.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    New,
    SeenAgain,
    /// resolved earlier, reported again
    Recurring,
    /// dismissed by the analyst (false positive or accepted risk); stays dismissed
    Dismissed,
    OutOfScope,
    /// informational and not selected
    Info,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewItem {
    pub title: String,
    pub severity: String,
    pub target: String,
    pub outcome: Outcome,
    pub finding_id: Option<i64>,
    /// the library template a new finding would be written from
    pub template: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub new: usize,
    pub seen_again: usize,
    pub recurring: usize,
    pub dismissed: usize,
    pub out_of_scope: usize,
    pub info: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub format: String,
    pub format_label: String,
    pub tool: String,
    pub findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub counts: Counts,
    pub assets: usize,
    pub assets_new: usize,
    pub assets_out_of_scope: usize,
    pub out_of_scope_hosts: Vec<String>,
    pub items: Vec<PreviewItem>,
    pub warnings: Vec<String>,
    pub merged: usize,
    pub marked_false_positive: usize,
    pub has_scope: bool,
    /// new findings that would be written from a library template
    pub templated: usize,
    /// open findings of earlier imports of this tool that the file no longer reports on a host
    /// it covers (at most 200 listed)
    pub not_reported: Vec<PreviewItem>,
    pub not_reported_count: usize,
}

const SEVERITY_ORDER: &[&str] = &["critical", "high", "medium", "low", "info"];

fn in_scope(entries: &[ScopeEntry], host: &str) -> bool {
    entries.iter().any(|e| e.in_scope) && scope::parse_target(host).is_some_and(|t| scope::check_target(entries, &t).is_ok())
}

/// The existing finding for a fingerprint, with its status.
fn known(c: &Connection, project_id: i64, fp: &str) -> AppResult<Option<(i64, String)>> {
    Ok(c
        .query_row(
            "SELECT f.id, f.status FROM finding_fingerprints x JOIN findings f ON f.id = x.finding_id WHERE x.project_id = ?1 AND x.fingerprint = ?2",
            params![project_id, fp],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

fn outcome(c: &Connection, project_id: i64, entries: &[ScopeEntry], f: &ImportedFinding, opts: Options) -> AppResult<(Outcome, Option<i64>)> {
    if let Some(h) = f.host.as_deref() {
        if !in_scope(entries, h) {
            return Ok((Outcome::OutOfScope, None));
        }
    }
    match known(c, project_id, &f.fingerprint)? {
        Some((id, status)) => Ok((
            match status.as_str() {
                "resolved" => Outcome::Recurring,
                "false_positive" | "accepted_risk" => Outcome::Dismissed,
                _ => Outcome::SeenAgain,
            },
            Some(id),
        )),
        None if f.severity == "info" && !opts.include_info => Ok((Outcome::Info, None)),
        None => Ok((Outcome::New, None)),
    }
}

/// Assets of the file that are inside the scope, as a discovery batch; also the hosts left out.
fn asset_batch(entries: &[ScopeEntry], items: &[AssetItem]) -> (Batch, usize, BTreeSet<String>) {
    let roots: BTreeSet<String> = entries.iter().filter(|e| e.in_scope && e.kind == "domain").map(|e| e.value.trim().trim_start_matches("*.").to_lowercase()).collect();
    let mut batch = Batch::default();
    let mut left_out = 0;
    let mut hosts = BTreeSet::new();
    for it in items {
        if !in_scope(entries, &it.host) {
            left_out += 1;
            if hosts.len() < 20 {
                hosts.insert(it.host.clone());
            }
            continue;
        }
        let kind = match it.kind {
            "name" => {
                if roots.contains(&it.value.to_lowercase()) {
                    "domain"
                } else {
                    "subdomain"
                }
            }
            k => k,
        };
        batch.add(kind, &it.value, Certainty::Observed, it.data.clone());
    }
    (batch, left_out, hosts)
}

/// What importing the file would do, without changing anything.
pub fn preview(c: &Connection, project_id: i64, parsed: &Parsed, opts: Options) -> AppResult<Preview> {
    let entries = scope_entries(c, project_id)?;
    let format = parsed.format.ok_or_else(|| validation("Unknown file format"))?;
    let mut pv = Preview {
        format: format.as_str().into(),
        format_label: format.label().into(),
        tool: parsed.tool.clone(),
        findings: parsed.findings.len(),
        warnings: parsed.warnings.clone(),
        merged: parsed.merged,
        marked_false_positive: parsed.marked_false_positive,
        has_scope: entries.iter().any(|e| e.in_scope),
        ..Default::default()
    };
    if !pv.has_scope {
        pv.warnings.push("The project has no scope entries, so every host in the file is outside the scope. Add the scope first.".into());
    }
    let mut out_hosts: BTreeSet<String> = BTreeSet::new();
    let lib = library(c, opts)?;
    for f in &parsed.findings {
        *pv.by_severity.entry(f.severity.to_string()).or_default() += 1;
        let (o, id) = outcome(c, project_id, &entries, f, opts)?;
        let template = if o == Outcome::New { template_for(&lib, format, f) } else { None };
        if template.is_some() {
            pv.templated += 1;
        }
        match o {
            Outcome::New => pv.counts.new += 1,
            Outcome::SeenAgain => pv.counts.seen_again += 1,
            Outcome::Recurring => pv.counts.recurring += 1,
            Outcome::Dismissed => pv.counts.dismissed += 1,
            Outcome::OutOfScope => {
                pv.counts.out_of_scope += 1;
                if let Some(h) = f.host.as_ref() {
                    if out_hosts.len() < 20 {
                        out_hosts.insert(h.clone());
                    }
                }
            }
            Outcome::Info => pv.counts.info += 1,
        }
        pv.items.push(PreviewItem {
            title: template.map(|t| t.title.clone()).unwrap_or_else(|| f.title.clone()),
            severity: template.map(|t| t.severity.clone()).unwrap_or_else(|| f.severity.to_string()),
            target: f.target.clone(),
            outcome: o,
            finding_id: id,
            template: template.map(|t| t.title.clone()),
        });
    }
    pv.items.sort_by_key(|i| (SEVERITY_ORDER.iter().position(|s| *s == i.severity).unwrap_or(9), i.outcome as u8));
    pv.items.truncate(200);
    let (batch, left_out, hosts) = asset_batch(&entries, &parsed.assets);
    out_hosts.extend(hosts);
    pv.assets = batch.len();
    pv.assets_out_of_scope = left_out;
    pv.assets_new = count_new_assets(c, project_id, &parsed.assets, &entries)?;
    pv.out_of_scope_hosts = out_hosts.into_iter().take(20).collect();
    let missing = not_reported(c, project_id, parsed)?;
    pv.not_reported_count = missing.len();
    pv.not_reported = missing
        .into_iter()
        .take(200)
        .map(|m| PreviewItem { title: m.title, severity: m.severity, target: m.target, outcome: Outcome::SeenAgain, finding_id: Some(m.finding_id), template: None })
        .collect();
    Ok(pv)
}

/// Hosts the file shows results for (findings and assets): a host it covers was scanned.
pub fn covered_hosts(parsed: &Parsed) -> BTreeSet<String> {
    let mut hosts: BTreeSet<String> = parsed.findings.iter().filter_map(|f| f.host.as_ref()).map(|h| h.trim().to_lowercase()).collect();
    hosts.extend(parsed.assets.iter().map(|a| a.host.trim().to_lowercase()).filter(|h| !h.is_empty()));
    hosts
}

/// An open finding of an earlier import that the file does not report again.
#[derive(Clone, Debug, PartialEq)]
pub struct Missing {
    pub finding_id: i64,
    pub title: String,
    pub severity: String,
    pub target: String,
    pub host: String,
}

/// Open findings first imported from the same tool, on hosts the file covers, whose fingerprints
/// are not in the file. Findings without a recorded host (imported before schema 15) and source-code
/// findings (no host) are never listed: their absence proves nothing.
pub fn not_reported(c: &Connection, project_id: i64, parsed: &Parsed) -> AppResult<Vec<Missing>> {
    let covered = covered_hosts(parsed);
    if covered.is_empty() {
        return Ok(Vec::new());
    }
    let present: BTreeSet<&str> = parsed.findings.iter().map(|f| f.fingerprint.as_str()).collect();
    let mut stmt = c.prepare(&format!(
        "SELECT x.fingerprint, x.host, f.id, f.title, f.severity, f.affected_target FROM finding_fingerprints x JOIN findings f ON f.id = x.finding_id
         WHERE x.project_id = ?1 AND x.tool = ?2 AND x.host <> '' AND f.status IN {} ORDER BY f.id",
        lifecycle::OPEN_SQL
    ))?;
    let rows = stmt
        .query_map(params![project_id, parsed.tool], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, Missing { finding_id: r.get(2)?, title: r.get(3)?, severity: r.get(4)?, target: r.get(5)?, host: r.get(1)? })))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows.into_iter().filter(|(fp, host, _)| covered.contains(&host.to_lowercase()) && !present.contains(fp.as_str())).map(|(_, _, m)| m).collect())
}

fn count_new_assets(c: &Connection, project_id: i64, items: &[AssetItem], entries: &[ScopeEntry]) -> AppResult<usize> {
    let roots: BTreeSet<String> = entries.iter().filter(|e| e.in_scope && e.kind == "domain").map(|e| e.value.trim().trim_start_matches("*.").to_lowercase()).collect();
    let mut keys: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for it in items.iter().filter(|i| in_scope(entries, &i.host)) {
        let kind = if it.kind == "name" { if roots.contains(&it.value.to_lowercase()) { "domain" } else { "subdomain" } } else { it.kind };
        if let Ok((_, key)) = assets::normalize_asset(kind, &it.value) {
            keys.insert((kind, key));
        }
    }
    let mut n = 0;
    for (kind, key) in keys {
        let exists: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM assets WHERE project_id = ?1 AND type = ?2 AND key = ?3)", params![project_id, kind, key], |r| r.get(0))?;
        if !exists {
            n += 1;
        }
    }
    Ok(n)
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub import_id: i64,
    pub created: usize,
    pub seen_again: usize,
    pub reopened: usize,
    pub dismissed: usize,
    pub out_of_scope: usize,
    pub info_skipped: usize,
    pub assets_new: usize,
    pub assets_seen: usize,
    pub templated: usize,
    /// open findings of earlier imports that this file no longer reports (noted in their history)
    pub not_reported: usize,
    /// of those, resolved as verified by this rescan (when asked)
    pub resolved: usize,
    pub summary: String,
}

/// File facts recorded with an import.
pub struct FileInfo<'a> {
    pub file_name: &'a str,
    pub sha256: &'a str,
    pub evidence_id: Option<i64>,
}

fn asset_id(c: &Connection, project_id: i64, kind: &str, value: &str) -> AppResult<Option<i64>> {
    let Ok((_, key)) = assets::normalize_asset(kind, value) else { return Ok(None) };
    Ok(c.query_row("SELECT id FROM assets WHERE project_id = ?1 AND type = ?2 AND key = ?3", params![project_id, kind, key], |r| r.get(0)).optional()?)
}

/// Imports a parsed file (one savepoint: all or nothing).
pub fn import(c: &Connection, project_id: i64, parsed: &Parsed, opts: Options, file: &FileInfo) -> AppResult<ImportResult> {
    let format = parsed.format.ok_or_else(|| validation("Unknown file format"))?;
    let status: Option<String> = c.query_row("SELECT status FROM projects WHERE id = ?1", params![project_id], |r| r.get(0)).optional()?;
    match status.as_deref() {
        None => return Err(validation("The project does not exist")),
        Some("archived") => return Err(validation("The project is archived; reopen it before importing")),
        _ => {}
    }
    with_savepoint(c, || {
        let entries = scope_entries(c, project_id)?;
        let ts = now();
        c.execute(
            "INSERT INTO scan_imports (project_id, format, tool, file_name, sha256, evidence_id, summary, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '{}', ?7)",
            params![project_id, format.as_str(), parsed.tool, trunc(file.file_name, 200), file.sha256, file.evidence_id, ts],
        )?;
        let import_id = c.last_insert_rowid();
        let mut r = ImportResult { import_id, ..Default::default() };

        // assets first, so findings can link to them
        let (batch, left_out, _) = asset_batch(&entries, &parsed.assets);
        let snapshot = if batch.is_empty() {
            None
        } else {
            let sid = assets::start_snapshot(c, project_id, "manual", &format!("import:{}", format.as_str()), None, None)?;
            let stats = discovery::record(c, project_id, sid, &format!("import:{}", format.as_str()), &batch)?;
            r.assets_new = stats.new;
            r.assets_seen = stats.seen;
            assets::finish_snapshot(c, sid, "completed", &format!("Imported from {} ({}): {} ({} new)", trunc(file.file_name, 80), parsed.tool, discovery::plural(stats.new + stats.seen, "asset", "assets"), stats.new))?;
            Some(sid)
        };
        let source_note = format!("{} import of {}", parsed.tool, trunc(file.file_name, 80));
        let lib = library(c, opts)?;
        // decided before this file's findings are recorded
        let missing = not_reported(c, project_id, parsed)?;
        for f in &parsed.findings {
            let (o, existing) = outcome(c, project_id, &entries, f, opts)?;
            match o {
                Outcome::OutOfScope => r.out_of_scope += 1,
                Outcome::Info => r.info_skipped += 1,
                Outcome::SeenAgain | Outcome::Recurring | Outcome::Dismissed => {
                    let id = existing.expect("known finding");
                    c.execute(
                        "UPDATE finding_fingerprints SET last_import_id = ?3, times_seen = times_seen + 1, last_seen = ?4, host = CASE WHEN host = '' THEN ?5 ELSE host END WHERE project_id = ?1 AND fingerprint = ?2",
                        params![project_id, f.fingerprint, import_id, ts, f.host.as_deref().unwrap_or("").to_lowercase()],
                    )?;
                    if o == Outcome::Recurring && opts.reopen_resolved {
                        lifecycle::set_status(c, id, "reopened", &format!("Reported again by the {source_note}"), "import")?;
                        r.reopened += 1;
                    } else {
                        lifecycle::add_note(c, id, &format!("Reported again by the {source_note}"), "import")?;
                        if o == Outcome::Dismissed {
                            r.dismissed += 1;
                        } else {
                            r.seen_again += 1;
                        }
                    }
                    if let Some(ev) = file.evidence_id {
                        lifecycle::link(c, id, "evidence", ev, "import")?;
                    }
                }
                Outcome::New => {
                    let mut input = FindingInput {
                        id: None,
                        project_id,
                        title: f.title.clone(),
                        severity: f.severity.to_string(),
                        status: "new".into(),
                        category: f.category.clone(),
                        confidence: Some(f.confidence.to_string()),
                        description: f.description.clone(),
                        affected_target: f.target.clone(),
                        cve: f.cve.clone(),
                        evidence: f.references.iter().take(50).map(|u| Evidence { label: "Reference".into(), reference: trunc(u, 2000) }).collect(),
                        reproduction: String::new(),
                        technical_details: f.technical.clone(),
                        remediation: f.remediation.clone(),
                        tags: f.tags.clone(),
                        assignee: String::new(),
                        due_date: None,
                        cvss_vector: f.cvss.clone(),
                    };
                    let template = template_for(&lib, format, f);
                    if let Some(t) = template {
                        apply_template(&mut input, t);
                    }
                    let id = finding_write(c, &input, "import", false)?;
                    if let Some(t) = template {
                        let note = format!("Written from the finding library template “{}” (import rule {}:{})", t.title, format.as_str(), trunc(&f.rule_id, 100));
                        lifecycle::add_note(c, id, &note, "import")?;
                        templates::mark_used(c, t.id)?;
                        r.templated += 1;
                    }
                    c.execute(
                        "INSERT INTO finding_fingerprints (project_id, fingerprint, finding_id, tool, rule_id, first_import_id, last_import_id, times_seen, first_seen, last_seen, host)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1, ?7, ?7, ?8)",
                        params![project_id, f.fingerprint, id, parsed.tool, trunc(&f.rule_id, 200), import_id, ts, f.host.as_deref().unwrap_or("").to_lowercase()],
                    )?;
                    if let Some(ev) = file.evidence_id {
                        lifecycle::link(c, id, "evidence", ev, "import")?;
                    }
                    if let Some((kind, value)) = f.asset.as_ref() {
                        if let Some(aid) = asset_id(c, project_id, kind, value)? {
                            lifecycle::link(c, id, "asset", aid, "import")?;
                        }
                    }
                    r.created += 1;
                }
            }
        }
        for m in &missing {
            if opts.resolve_missing {
                lifecycle::set_status(c, m.finding_id, "resolved", &format!("Verified by rescan: not reported again for {} by the {source_note}", m.host), "import")?;
                r.resolved += 1;
            } else {
                lifecycle::add_note(c, m.finding_id, &format!("Not reported again for {} by the {source_note}", m.host), "import")?;
            }
            r.not_reported += 1;
        }
        let mut summary = format!("{} new, {} seen again", discovery::plural(r.created, "finding", "findings"), r.seen_again).replacen(" finding new", " new finding", 1).replacen(" findings new", " new findings", 1);
        if r.reopened > 0 {
            summary.push_str(&format!(", {} reopened", r.reopened));
        }
        if r.dismissed > 0 {
            summary.push_str(&format!(", {} still dismissed", r.dismissed));
        }
        if r.out_of_scope + left_out > 0 {
            summary.push_str(&format!(
                ", {} and {} outside the scope (not recorded)",
                discovery::plural(r.out_of_scope, "finding", "findings"),
                discovery::plural(left_out, "asset", "assets")
            ));
        }
        if r.info_skipped > 0 {
            summary.push_str(&format!(", {} informational not imported", r.info_skipped));
        }
        if r.templated > 0 {
            summary.push_str(&format!(", {} written from library templates", r.templated));
        }
        if r.not_reported > 0 {
            summary.push_str(&format!(", {} no longer reported", r.not_reported));
            if r.resolved > 0 {
                summary.push_str(&format!(" ({} resolved as verified by this rescan)", r.resolved));
            }
        }
        summary.push_str(&format!("; {} ({} new)", discovery::plural(r.assets_new + r.assets_seen, "asset", "assets"), r.assets_new));
        r.summary = summary.clone();
        c.execute(
            "UPDATE scan_imports SET snapshot_id = ?2, summary = ?3 WHERE id = ?1",
            params![import_id, snapshot, json!({ "created": r.created, "seenAgain": r.seen_again, "reopened": r.reopened, "dismissed": r.dismissed, "outOfScope": r.out_of_scope + left_out, "infoSkipped": r.info_skipped, "templated": r.templated, "notReported": r.not_reported, "resolved": r.resolved, "assetsNew": r.assets_new, "assetsSeen": r.assets_seen, "text": summary }).to_string()],
        )?;
        let title = format!("Imported {} results from {}", parsed.tool, trunc(file.file_name, 80));
        timeline::record(c, project_id, "finding", &title, &summary, Some("scan_import"), Some(import_id))?;
        log(c, "finding", &title, &summary, Some("scan_import"), Some(&import_id.to_string()), Some(project_id))?;
        c.execute("UPDATE projects SET updated_at = ?2 WHERE id = ?1", params![project_id, ts])?;
        Ok(r)
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRecord {
    pub id: i64,
    pub format: String,
    pub tool: String,
    pub file_name: String,
    pub sha256: String,
    pub evidence_id: Option<i64>,
    pub snapshot_id: Option<i64>,
    pub summary: Value,
    pub created_at: String,
}

pub fn history(c: &Connection, project_id: i64) -> AppResult<Vec<ImportRecord>> {
    let mut stmt = c.prepare("SELECT id, format, tool, file_name, sha256, evidence_id, snapshot_id, summary, created_at FROM scan_imports WHERE project_id = ?1 ORDER BY id DESC LIMIT ?2")?;
    let rows = stmt
        .query_map(params![project_id, HISTORY_LIMIT], |r| {
            Ok(ImportRecord {
                id: r.get(0)?,
                format: r.get(1)?,
                tool: r.get(2)?,
                file_name: r.get(3)?,
                sha256: r.get(4)?,
                evidence_id: r.get(5)?,
                snapshot_id: r.get(6)?,
                summary: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
                created_at: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
#[path = "scan_import_tests.rs"]
mod tests;
