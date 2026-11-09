//! SBOM analysis (docs/DATA_MODEL.md#sbom-analysis-schema-21): the components a software bill of
//! materials lists, their licenses, the known vulnerabilities that affect them, and how complete
//! the SBOM is.
//!
//! * **Formats.** CycloneDX JSON and XML (1.2 to 1.6), SPDX 2.2 and 2.3 JSON and tag-value.
//!   Reading a file contacts nothing.
//! * **Known vulnerabilities** come from the file itself (CycloneDX `vulnerabilities`, with any
//!   VEX analysis) and, only when the analyst asks, from OSV.dev: the lookup sends package URLs
//!   (ecosystem, name and version) and nothing else.
//! * **Licenses** are classified from SPDX identifiers and expressions (OR takes the most
//!   permissive choice, AND the most restrictive), and unknown ones are reported as unknown.
//! * **Completeness** follows the NTIA minimum elements: supplier, name, version, a unique
//!   identifier, dependency relationships, the SBOM's author and timestamp.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{validation, AppError, AppResult};

pub const MAX_FILE_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_COMPONENTS: usize = 20_000;
pub const OSV_BASE: &str = "https://api.osv.dev";
const OSV_BATCH: usize = 1000;
const MAX_VULN_DETAILS: usize = 2000;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub name: String,
    /// CycloneDX group, Maven group id
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub purl: String,
    #[serde(default)]
    pub cpe: String,
    /// library, application, framework, container, operating-system, file…
    #[serde(default)]
    pub kind: String,
    /// the package URL type: npm, pypi, maven, golang, cargo, nuget, gem, deb, rpm…
    #[serde(default)]
    pub ecosystem: String,
    /// SPDX identifiers, names or expressions as written
    #[serde(default)]
    pub licenses: Vec<String>,
    /// permissive, weak-copyleft, copyleft, network-copyleft, restricted or unknown
    #[serde(default)]
    pub license_risk: String,
    #[serde(default)]
    pub supplier: String,
    /// "SHA-256:…"
    #[serde(default)]
    pub hashes: Vec<String>,
    /// a direct dependency of the described software (when the SBOM has relationships)
    #[serde(default)]
    pub direct: bool,
    /// bom-ref or SPDX id
    #[serde(default)]
    pub reference: String,
    /// a development dependency (lockfiles)
    #[serde(default)]
    pub dev: bool,
    /// where a lockfile resolves the package from: a registry, a Git repository, a URL (lockfiles)
    #[serde(default)]
    pub resolved: String,
}

impl Component {
    pub fn label(&self) -> String {
        let name = if self.group.is_empty() { self.name.clone() } else { format!("{}/{}", self.group, self.name) };
        if self.version.is_empty() {
            name
        } else {
            format!("{name}@{}", self.version)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Vuln {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: String,
    /// critical, high, medium, low or unknown
    pub severity: String,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub vector: String,
    /// versions that fix it, for the affected components' packages
    #[serde(default)]
    pub fixed: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub published: String,
    /// indices of the affected components
    pub components: Vec<usize>,
    /// osv (looked up) or sbom (stated in the file)
    pub source: String,
    /// VEX analysis state from the file (not_affected, exploitable, in_triage…), or ""
    #[serde(default)]
    pub analysis: String,
}

impl Vuln {
    /// The CVE id, if the vulnerability has one.
    pub fn cve(&self) -> Option<&str> {
        std::iter::once(&self.id).chain(self.aliases.iter()).find(|a| a.starts_with("CVE-")).map(String::as_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Sbom {
    /// cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag, or lockfile-<kind> for a dependency
    /// lockfile (`lockfiles.rs`)
    pub format: String,
    pub spec_version: String,
    /// the software the SBOM describes ("name version")
    pub subject: String,
    /// when the SBOM was created, as written
    pub created: String,
    /// tools and authors that made it
    pub tools: Vec<String>,
    pub components: Vec<Component>,
    /// the SBOM states dependency relationships
    pub relationships: bool,
    /// vulnerabilities stated in the file
    pub vulns: Vec<Vuln>,
    pub warnings: Vec<String>,
    /// package indexes the file names (requirements.txt index options, Pipfile and Gemfile sources)
    #[serde(default)]
    pub sources: Vec<String>,
}

/* ───────────────────────────── helpers ───────────────────────────── */

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Object(o)) => o.get("#text").map(|t| text(Some(t))).unwrap_or_default(),
        _ => String::new(),
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        Some(Value::Object(o)) => o.get("#text").and_then(|t| num(Some(t))),
        _ => None,
    }
}

/// A value as a list: arrays as they are, a single object as a list of one.
fn list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other],
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_else(|| s.to_string())
}

/// (type, namespace, name, version) of a package URL.
pub fn purl_parts(purl: &str) -> Option<(String, String, String, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (ty, rest) = rest.split_once('/')?;
    let (path, version) = match rest.rsplit_once('@') {
        Some((p, v)) => (p, percent_decode(v)),
        None => (rest, String::new()),
    };
    let (namespace, name) = match path.rsplit_once('/') {
        Some((ns, n)) => (percent_decode(ns), percent_decode(n)),
        None => (String::new(), percent_decode(path)),
    };
    (!ty.is_empty() && !name.is_empty()).then(|| (ty.to_ascii_lowercase(), namespace, name, version))
}

fn finish(c: &mut Component) {
    if let Some((ty, ns, name, version)) = purl_parts(&c.purl) {
        c.ecosystem = ty;
        if c.version.is_empty() {
            c.version = version;
        }
        if c.name.is_empty() {
            c.name = name;
        }
        if c.group.is_empty() && !ns.is_empty() && c.ecosystem == "maven" {
            c.group = ns;
        }
    }
    c.license_risk = license_risk(&c.licenses).into();
}

/* ───────────────────────────── licenses ───────────────────────────── */

const RISKS: [&str; 6] = ["permissive", "weak-copyleft", "copyleft", "network-copyleft", "restricted", "unknown"];

fn classify_id(id: &str) -> usize {
    let u = id.trim().trim_end_matches('+').to_ascii_uppercase();
    let starts = |p: &[&str]| p.iter().any(|x| u.starts_with(x));
    if u.is_empty() || u == "NOASSERTION" || u == "NONE" || u.starts_with("LICENSEREF-") {
        5
    } else if starts(&["CC-BY-NC", "CC-BY-ND", "BUSL-", "ELASTIC-", "SSPL-", "POLYFORM-", "COMMONS-CLAUSE", "CC-BY-NC-SA"]) {
        4
    } else if starts(&["AGPL-", "OSL-", "RPL-", "CPAL-"]) {
        3
    } else if starts(&["GPL-", "EUPL-", "CC-BY-SA-", "CECILL-2", "SLEEPYCAT", "QPL-", "GFDL-"]) {
        2
    } else if starts(&["LGPL-", "MPL-", "EPL-", "CDDL-", "CPL-", "MS-RL", "APSL-", "ERLPL-", "CECILL-C", "IPL-", "OFL-"]) {
        1
    } else if starts(&[
        "MIT", "APACHE-", "BSD-", "ISC", "ZLIB", "UNLICENSE", "0BSD", "CC0-", "PSF-", "PYTHON-", "BSL-1.0", "X11", "WTFPL", "NCSA", "POSTGRESQL", "OPENSSL", "ARTISTIC-2", "UNICODE-",
        "BLUEOAK-", "CURL", "LIBPNG", "CC-BY-3", "CC-BY-4", "BOOST", "JSON", "UPL-", "HPND", "ZPL-",
    ]) {
        0
    } else {
        5
    }
}

/// The risk of one SPDX expression (or plain name).
fn expression_risk(expr: &str) -> usize {
    let spaced = expr.replace(['(', ')'], " ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut ids = Vec::new();
    let mut skip = false;
    for t in &tokens {
        if skip {
            skip = false;
            continue;
        }
        match t.to_ascii_uppercase().as_str() {
            "AND" | "OR" => {}
            "WITH" => skip = true,
            _ => ids.push(classify_id(t)),
        }
    }
    if ids.is_empty() {
        return 5;
    }
    let any_or = tokens.iter().any(|t| t.eq_ignore_ascii_case("OR"));
    let any_and = tokens.iter().any(|t| t.eq_ignore_ascii_case("AND"));
    let known: Vec<usize> = ids.iter().copied().filter(|r| *r != 5).collect();
    if known.is_empty() {
        5
    } else if any_or && !any_and {
        *known.iter().min().unwrap_or(&5)
    } else {
        *known.iter().max().unwrap_or(&5)
    }
}

/// The license risk of a component: the most restrictive of its license entries.
pub fn license_risk(licenses: &[String]) -> &'static str {
    let risks: Vec<usize> = licenses.iter().map(|l| expression_risk(l)).collect();
    let known: Vec<usize> = risks.iter().copied().filter(|r| *r != 5).collect();
    RISKS[known.iter().max().copied().unwrap_or(5)]
}

/* ───────────────────────────── reading ───────────────────────────── */

/// Reads an SBOM: CycloneDX (JSON or XML) or SPDX 2.x (JSON or tag-value).
pub fn parse(text_in: &str) -> Result<Sbom, String> {
    let body = text_in.trim_start_matches('\u{feff}').trim_start();
    let mut sbom = if body.starts_with('{') {
        let root: Value = serde_json::from_str(body).map_err(|e| format!("not valid JSON: {e}"))?;
        if text(root.get("bomFormat")).eq_ignore_ascii_case("cyclonedx") {
            cyclonedx(&root, "cyclonedx-json")
        } else if root.get("spdxVersion").is_some() {
            spdx_json(&root)?
        } else if root.get("@context").is_some() && body.contains("spdx") {
            return Err("SPDX 3.0 (JSON-LD) is not supported yet; export SPDX 2.3 or CycloneDX".into());
        } else {
            return Err("This JSON file is not a CycloneDX or SPDX SBOM".into());
        }
    } else if body.starts_with('<') {
        if !body.contains("cyclonedx.org/schema/bom") {
            return Err("Only CycloneDX XML is supported (SPDX RDF/XML is not)".into());
        }
        let root = xml_tree(body)?;
        cyclonedx(&root, "cyclonedx-xml")
    } else if body.lines().take(50).any(|l| l.trim_start().starts_with("SPDXVersion:")) {
        spdx_tag(body)
    } else {
        return Err("This is not a CycloneDX or SPDX SBOM".into());
    };
    if sbom.components.len() > MAX_COMPONENTS {
        sbom.warnings.push(format!("Only the first {MAX_COMPONENTS} of {} components were kept", sbom.components.len()));
        sbom.components.truncate(MAX_COMPONENTS);
    }
    for c in &mut sbom.components {
        finish(c);
    }
    Ok(sbom)
}

/// An SBOM, or a dependency lockfile recognised by its file name (`lockfiles.rs`).
pub fn parse_file(file_name: &str, text_in: &str) -> Result<Sbom, String> {
    let Some(parsed) = super::lockfiles::parse(file_name, text_in) else { return parse(text_in) };
    let mut sbom = parsed?;
    for c in &mut sbom.components {
        finish(c);
    }
    Ok(sbom)
}

/* CycloneDX (JSON, or XML turned into the same shape) */

fn cdx_licenses(v: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    for entry in list(v) {
        // JSON: {"license": {"id"|"name"}} or {"expression"}; XML: license/expression elements
        let lic = entry.get("license").unwrap_or(entry);
        let expr = text(entry.get("expression"));
        let tag = text(entry.get("#tag"));
        let value = if !expr.is_empty() {
            expr
        } else if tag == "expression" {
            text(Some(entry))
        } else {
            let id = text(lic.get("id"));
            if id.is_empty() {
                text(lic.get("name"))
            } else {
                id
            }
        };
        if !value.is_empty() && !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

fn cdx_component(v: &Value, out: &mut Vec<Component>, depth: usize) {
    if depth > 32 || out.len() > MAX_COMPONENTS {
        return;
    }
    let hashes = list(v.get("hashes"))
        .into_iter()
        .filter_map(|h| {
            let alg = text(h.get("alg"));
            let content = text(h.get("content"));
            let content = if content.is_empty() { text(h.get("#text")) } else { content };
            (!content.is_empty()).then(|| format!("{alg}:{content}"))
        })
        .take(4)
        .collect();
    out.push(Component {
        name: text(v.get("name")),
        group: text(v.get("group")),
        version: text(v.get("version")),
        purl: text(v.get("purl")),
        cpe: text(v.get("cpe")),
        kind: text(v.get("type")),
        licenses: cdx_licenses(v.get("licenses")),
        supplier: {
            let s = text(v.pointer("/supplier/name"));
            if s.is_empty() {
                text(v.get("publisher"))
            } else {
                s
            }
        },
        hashes,
        reference: text(v.get("bom-ref")),
        ..Default::default()
    });
    for child in list(v.get("components")) {
        cdx_component(child, out, depth + 1);
    }
}

fn cyclonedx(root: &Value, format: &str) -> Sbom {
    let mut sbom = Sbom { format: format.into(), spec_version: text(root.get("specVersion")).to_string(), ..Default::default() };
    if sbom.spec_version.is_empty() {
        // XML: the version is in the namespace
        if let Some(ns) = root.get("xmlns").and_then(Value::as_str) {
            sbom.spec_version = ns.rsplit('/').next().unwrap_or("").to_string();
        }
    }
    let meta = root.get("metadata");
    sbom.created = text(meta.and_then(|m| m.get("timestamp")));
    if let Some(m) = meta {
        // 1.2–1.4: a list of tools; 1.5+: {components: [...]}
        let tools = m.get("tools");
        let entries = match tools {
            Some(Value::Object(o)) if o.contains_key("components") || o.contains_key("services") => list(o.get("components")).into_iter().chain(list(o.get("services"))).collect(),
            other => list(other),
        };
        for t in entries {
            let name = [text(t.get("vendor")), text(t.get("name")), text(t.get("version"))].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
            if !name.is_empty() {
                sbom.tools.push(name);
            }
        }
        for a in list(m.get("authors")) {
            let n = text(a.get("name"));
            if !n.is_empty() {
                sbom.tools.push(n);
            }
        }
    }
    let subject = meta.and_then(|m| m.get("component"));
    let subject_ref = subject.map(|s| text(s.get("bom-ref"))).unwrap_or_default();
    if let Some(s) = subject {
        sbom.subject = [text(s.get("name")), text(s.get("version"))].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ");
    }
    let mut components = Vec::new();
    for c in list(root.get("components")) {
        cdx_component(c, &mut components, 0);
    }
    // dependencies: JSON {ref, dependsOn: [..]}; XML <dependency ref><dependency ref/></dependency>
    let mut direct: BTreeSet<String> = BTreeSet::new();
    let deps = list(root.get("dependencies"));
    sbom.relationships = !deps.is_empty();
    for d in deps {
        if text(d.get("ref")) != subject_ref || subject_ref.is_empty() {
            continue;
        }
        for r in list(d.get("dependsOn")) {
            direct.insert(text(Some(r)));
        }
        for r in list(d.get("dependency")) {
            direct.insert(text(r.get("ref")));
        }
    }
    for c in &mut components {
        c.direct = !c.reference.is_empty() && direct.contains(&c.reference);
    }
    let index: HashMap<String, usize> = components.iter().enumerate().filter(|(_, c)| !c.reference.is_empty()).map(|(i, c)| (c.reference.clone(), i)).collect();
    for v in list(root.get("vulnerabilities")) {
        let id = text(v.get("id"));
        if id.is_empty() {
            continue;
        }
        let mut best: Option<(f64, String, String)> = None;
        for r in list(v.get("ratings")) {
            let score = num(r.get("score"));
            let sev = text(r.get("severity")).to_ascii_lowercase();
            let vector = text(r.get("vector"));
            if best.as_ref().is_none_or(|b| score.unwrap_or(0.0) > b.0) {
                best = Some((score.unwrap_or(0.0), sev, vector));
            }
        }
        let (score, severity, vector) = best.unwrap_or((0.0, String::new(), String::new()));
        let affected: Vec<usize> = list(v.get("affects")).into_iter().filter_map(|a| index.get(&text(a.get("ref"))).copied()).collect();
        let severity = match severity.as_str() {
            "critical" | "high" | "medium" | "low" => severity,
            _ if score > 0.0 => crate::cvss::rating(score).to_string(),
            _ => "unknown".into(),
        };
        sbom.vulns.push(Vuln {
            aliases: list(v.get("references")).into_iter().map(|r| text(r.get("id"))).filter(|s| !s.is_empty() && *s != id).collect(),
            summary: short(&text(v.get("description")), 300),
            severity,
            score: (score > 0.0).then_some(score),
            vector,
            fixed: Vec::new(),
            references: list(v.get("advisories")).into_iter().map(|a| text(a.get("url"))).filter(|s| s.starts_with("https://")).take(5).collect(),
            published: text(v.get("published")),
            components: affected,
            source: "sbom".into(),
            analysis: text(v.pointer("/analysis/state")),
            id,
        });
    }
    sbom.components = components;
    sbom
}

fn short(s: &str, n: usize) -> String {
    let line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
    line.chars().take(n).collect()
}

/// CycloneDX XML as a JSON-like tree: attributes and child elements become keys, repeated
/// elements and the children of list elements (`components`, `licenses`…) become arrays, and an
/// element with only text becomes its text. No DTD is processed and only the predefined and
/// numeric entities are read, so external entities cannot be loaded.
fn xml_tree(xml: &str) -> Result<Value, String> {
    use quick_xml::events::Event;
    const LISTS: &[&str] = &["components", "licenses", "hashes", "dependencies", "tools", "vulnerabilities", "ratings", "affects", "advisories", "references", "authors", "services", "externalReferences", "properties"];
    struct Node {
        name: String,
        map: Map<String, Value>,
        items: Vec<Value>,
        text: String,
    }
    fn open(e: &quick_xml::events::BytesStart) -> Node {
        let mut map = Map::new();
        for a in e.attributes().flatten() {
            let k = a.key.local_name().into_inner().to_string();
            let v = a.normalized_value(quick_xml::XmlVersion::default()).map(|v| v.to_string()).unwrap_or_default();
            map.insert(k, Value::String(v));
        }
        Node { name: e.local_name().into_inner().to_string(), map, items: Vec::new(), text: String::new() }
    }
    fn close(node: Node) -> (String, Value) {
        let value = if LISTS.contains(&node.name.as_str()) {
            Value::Array(node.items)
        } else if node.map.is_empty() {
            Value::String(node.text.trim().to_string())
        } else {
            let mut m = node.map;
            if !node.text.trim().is_empty() {
                m.insert("#text".into(), Value::String(node.text.trim().to_string()));
            }
            Value::Object(m)
        };
        (node.name, value)
    }
    fn attach(stack: &mut [Node], root: &mut Option<Value>, name: String, value: Value) {
        let Some(parent) = stack.last_mut() else {
            *root = Some(value);
            return;
        };
        if LISTS.contains(&parent.name.as_str()) {
            let item = match value {
                Value::Object(mut m) => {
                    m.insert("#tag".into(), Value::String(name));
                    Value::Object(m)
                }
                Value::String(s) => json!({"#tag": name, "#text": s}),
                other => other,
            };
            parent.items.push(item);
            return;
        }
        // a dependency's nested dependencies are always a list
        if name == "dependency" {
            match parent.map.get_mut("dependency") {
                Some(Value::Array(a)) => a.push(value),
                _ => {
                    parent.map.insert(name, Value::Array(vec![value]));
                }
            }
            return;
        }
        match parent.map.get_mut(&name) {
            Some(Value::Array(a)) => a.push(value),
            Some(existing) => {
                let prev = existing.take();
                *existing = Value::Array(vec![prev, value]);
            }
            None => {
                parent.map.insert(name, value);
            }
        }
    }
    fn push_text(stack: &mut [Node], t: &str) {
        if let Some(n) = stack.last_mut() {
            if n.text.len() < 100_000 {
                n.text.push_str(t);
            }
        }
    }
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Value> = None;
    loop {
        match reader.read_event() {
            Err(e) => return Err(format!("not valid XML after byte {}: {e}", reader.buffer_position())),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if stack.len() >= 128 {
                    return Err("the XML is nested deeper than 128 levels".into());
                }
                stack.push(open(&e));
            }
            Ok(Event::Empty(e)) => {
                let (name, value) = close(open(&e));
                attach(&mut stack, &mut root, name, value);
            }
            Ok(Event::End(_)) => {
                if let Some(node) = stack.pop() {
                    let (name, value) = close(node);
                    attach(&mut stack, &mut root, name, value);
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
    root.ok_or_else(|| "the XML has no root element".to_string())
}

/* SPDX 2.x */

fn spdx_purl(refs: Option<&Value>) -> (String, String) {
    let (mut purl, mut cpe) = (String::new(), String::new());
    for r in list(refs) {
        let ty = text(r.get("referenceType")).to_ascii_lowercase();
        let loc = text(r.get("referenceLocator"));
        if ty == "purl" && purl.is_empty() {
            purl = loc;
        } else if ty.starts_with("cpe") && cpe.is_empty() {
            cpe = loc;
        }
    }
    (purl, cpe)
}

fn spdx_license(concluded: &str, declared: &str) -> Vec<String> {
    let pick = |s: &str| !s.is_empty() && s != "NOASSERTION" && s != "NONE";
    if pick(concluded) {
        vec![concluded.to_string()]
    } else if pick(declared) {
        vec![declared.to_string()]
    } else {
        Vec::new()
    }
}

fn supplier_name(s: &str) -> String {
    let s = s.trim();
    if s == "NOASSERTION" {
        return String::new();
    }
    s.split_once(':').map(|(_, n)| n.trim().to_string()).unwrap_or_else(|| s.to_string())
}

fn spdx_json(root: &Value) -> Result<Sbom, String> {
    let version = text(root.get("spdxVersion"));
    if !version.starts_with("SPDX-2.") {
        return Err(format!("{version} is not supported; SPDX 2.2 and 2.3 are"));
    }
    let mut sbom = Sbom { format: "spdx-json".into(), spec_version: version.trim_start_matches("SPDX-").into(), ..Default::default() };
    sbom.created = text(root.pointer("/creationInfo/created"));
    sbom.tools = list(root.pointer("/creationInfo/creators")).into_iter().map(|c| text(Some(c))).filter(|s| !s.is_empty()).collect();
    let described: BTreeSet<String> = list(root.get("documentDescribes")).into_iter().map(|d| text(Some(d))).collect();
    let mut described = described;
    let mut direct: BTreeSet<String> = BTreeSet::new();
    let rels = list(root.get("relationships"));
    for r in &rels {
        if text(r.get("relationshipType")) == "DESCRIBES" {
            described.insert(text(r.get("relatedSpdxElement")));
        }
    }
    for r in &rels {
        let ty = text(r.get("relationshipType"));
        let (a, b) = (text(r.get("spdxElementId")), text(r.get("relatedSpdxElement")));
        if matches!(ty.as_str(), "DEPENDS_ON" | "CONTAINS") && described.contains(&a) {
            direct.insert(b);
        } else if matches!(ty.as_str(), "DEPENDENCY_OF" | "CONTAINED_BY") && described.contains(&b) {
            direct.insert(a);
        }
    }
    sbom.relationships = rels.iter().any(|r| text(r.get("relationshipType")) != "DESCRIBES");
    for p in list(root.get("packages")) {
        let id = text(p.get("SPDXID"));
        let (purl, cpe) = spdx_purl(p.get("externalRefs"));
        let c = Component {
            name: text(p.get("name")),
            version: text(p.get("versionInfo")),
            purl,
            cpe,
            kind: text(p.get("primaryPackagePurpose")).to_ascii_lowercase(),
            licenses: spdx_license(&text(p.get("licenseConcluded")), &text(p.get("licenseDeclared"))),
            supplier: supplier_name(&text(p.get("supplier"))),
            hashes: list(p.get("checksums")).into_iter().map(|h| format!("{}:{}", text(h.get("algorithm")), text(h.get("checksumValue")))).take(4).collect(),
            direct: direct.contains(&id),
            reference: id.clone(),
            ..Default::default()
        };
        if described.contains(&id) {
            sbom.subject = [c.name.clone(), c.version.clone()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ");
            continue;
        }
        sbom.components.push(c);
    }
    if sbom.subject.is_empty() {
        sbom.subject = text(root.get("name"));
    }
    Ok(sbom)
}

fn spdx_tag(body: &str) -> Sbom {
    let mut sbom = Sbom { format: "spdx-tag".into(), ..Default::default() };
    let mut packages: Vec<(String, Component, String, String)> = Vec::new();
    let mut described = BTreeSet::new();
    let mut rels: Vec<(String, String, String)> = Vec::new();
    let mut in_text = false;
    for line in body.lines() {
        let l = line.trim();
        if in_text {
            if l.contains("</text>") {
                in_text = false;
            }
            continue;
        }
        let Some((key, value)) = l.split_once(':') else { continue };
        let value = value.trim();
        if value.starts_with("<text>") && !value.contains("</text>") {
            in_text = true;
            continue;
        }
        match key.trim() {
            "SPDXVersion" => sbom.spec_version = value.trim_start_matches("SPDX-").to_string(),
            "DocumentName" => sbom.subject = value.to_string(),
            "Creator" => sbom.tools.push(value.to_string()),
            "Created" => sbom.created = value.to_string(),
            "PackageName" => packages.push((String::new(), Component { name: value.to_string(), ..Default::default() }, String::new(), String::new())),
            "SPDXID" => {
                if let Some(p) = packages.last_mut() {
                    p.0 = value.to_string();
                }
            }
            "PackageVersion" => {
                if let Some(p) = packages.last_mut() {
                    p.1.version = value.to_string();
                }
            }
            "PackageSupplier" => {
                if let Some(p) = packages.last_mut() {
                    p.1.supplier = supplier_name(value);
                }
            }
            "PackageLicenseConcluded" => {
                if let Some(p) = packages.last_mut() {
                    p.2 = value.to_string();
                }
            }
            "PackageLicenseDeclared" => {
                if let Some(p) = packages.last_mut() {
                    p.3 = value.to_string();
                }
            }
            "PackageChecksum" => {
                if let Some(p) = packages.last_mut() {
                    if p.1.hashes.len() < 4 {
                        p.1.hashes.push(value.replacen(": ", ":", 1));
                    }
                }
            }
            "ExternalRef" => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if let (Some(p), [_, ty, loc, ..]) = (packages.last_mut(), parts.as_slice()) {
                    if ty.eq_ignore_ascii_case("purl") && p.1.purl.is_empty() {
                        p.1.purl = loc.to_string();
                    } else if ty.to_ascii_lowercase().starts_with("cpe") && p.1.cpe.is_empty() {
                        p.1.cpe = loc.to_string();
                    }
                }
            }
            "Relationship" => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if let [a, ty, b, ..] = parts.as_slice() {
                    if *ty == "DESCRIBES" {
                        described.insert(b.to_string());
                    }
                    rels.push((a.to_string(), ty.to_string(), b.to_string()));
                }
            }
            _ => {}
        }
    }
    let mut direct = BTreeSet::new();
    for (a, ty, b) in &rels {
        if matches!(ty.as_str(), "DEPENDS_ON" | "CONTAINS") && described.contains(a) {
            direct.insert(b.clone());
        }
    }
    sbom.relationships = rels.iter().any(|(_, ty, _)| ty != "DESCRIBES");
    for (id, mut c, concluded, declared) in packages {
        c.licenses = spdx_license(&concluded, &declared);
        c.direct = direct.contains(&id);
        if described.contains(&id) {
            sbom.subject = [c.name.clone(), c.version.clone()].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ");
            continue;
        }
        c.reference = id;
        sbom.components.push(c);
    }
    sbom
}

/* ───────────────────────────── OSV.dev ───────────────────────────── */

/// The package URL of a component with its version, for the lookup (None without a version).
fn query_purl(c: &Component) -> Option<String> {
    let (_, _, _, version) = purl_parts(&c.purl)?;
    let version = if version.is_empty() { c.version.clone() } else { version };
    if version.is_empty() {
        return None;
    }
    let base = c.purl.split(['?', '#']).next().unwrap_or(&c.purl);
    let base = base.rsplit_once('@').map(|(b, _)| b).unwrap_or(base);
    Some(format!("{base}@{version}"))
}

/// The OSV ids per query, from a `querybatch` response.
pub fn parse_osv_batch(v: &Value) -> Vec<Vec<String>> {
    list(v.get("results")).into_iter().map(|r| list(r.get("vulns")).into_iter().map(|x| text(x.get("id"))).filter(|s| !s.is_empty()).collect()).collect()
}

/// An OSV record as a vulnerability of the given components.
pub fn parse_osv_vuln(v: &Value, components: &[Component], affected: Vec<usize>) -> Vuln {
    let id = text(v.get("id"));
    // severity: the GitHub advisory's rating, else the highest CVSS score
    let ghsa = text(v.pointer("/database_specific/severity")).to_ascii_lowercase();
    let mut best: Option<(f64, String)> = None;
    for s in list(v.get("severity")) {
        if let Ok(c) = crate::cvss::parse(&text(s.get("score"))) {
            if best.as_ref().is_none_or(|b| c.score > b.0) {
                best = Some((c.score, c.vector));
            }
        }
    }
    let severity = match ghsa.as_str() {
        "critical" | "high" | "low" => ghsa.clone(),
        "moderate" | "medium" => "medium".into(),
        _ => best.as_ref().map(|b| crate::cvss::rating(b.0).to_string()).filter(|r| r != "none").unwrap_or_else(|| "unknown".into()),
    };
    // fixed versions of the affected components' packages
    let mut fixed = BTreeSet::new();
    let names: Vec<(String, String)> = affected
        .iter()
        .filter_map(|i| components.get(*i))
        .filter_map(|c| purl_parts(&c.purl).map(|(ty, ns, name, _)| (ty, if ns.is_empty() { name } else { format!("{ns}/{name}") })))
        .collect();
    for a in list(v.get("affected")) {
        let apurl = text(a.pointer("/package/purl"));
        let matches = purl_parts(&apurl).map(|(ty, ns, name, _)| names.contains(&(ty, if ns.is_empty() { name } else { format!("{ns}/{name}") }))).unwrap_or(names.len() <= 1);
        if !matches {
            continue;
        }
        for r in list(a.get("ranges")) {
            for e in list(r.get("events")) {
                let f = text(e.get("fixed"));
                if !f.is_empty() {
                    fixed.insert(f);
                }
            }
        }
    }
    let summary = {
        let s = text(v.get("summary"));
        if s.is_empty() {
            short(&text(v.get("details")), 300)
        } else {
            s
        }
    };
    Vuln {
        aliases: list(v.get("aliases")).into_iter().map(|a| text(Some(a))).filter(|s| !s.is_empty()).collect(),
        summary,
        severity,
        score: best.as_ref().map(|b| b.0),
        vector: best.map(|b| b.1).unwrap_or_default(),
        fixed: fixed.into_iter().take(10).collect(),
        references: list(v.get("references")).into_iter().map(|r| text(r.get("url"))).filter(|u| u.starts_with("https://")).take(5).collect(),
        published: text(v.get("published")),
        components: affected,
        source: "osv".into(),
        analysis: String::new(),
        id,
    }
}

/// A transport error without its URL, with the innermost cause.
fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "the request timed out".into();
    }
    let mut cause: &dyn std::error::Error = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    let inner = cause.to_string();
    let top = e.to_string();
    let top = match e.url() {
        Some(u) => top.replace(u.as_str(), "OSV.dev"),
        None => top,
    };
    if inner == top { top } else { format!("{top} ({inner})") }
}

async fn read_json(resp: reqwest::Response, what: &str) -> AppResult<Value> {
    if !resp.status().is_success() {
        return Err(AppError::Network(format!("OSV.dev returned HTTP {} for {what}", resp.status())));
    }
    let mut resp = resp;
    let mut raw = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| AppError::Network(e.to_string()))? {
        if raw.len() + chunk.len() > MAX_RESPONSE {
            return Err(AppError::Network(format!("OSV.dev returned an unexpectedly large response for {what}")));
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&raw)?)
}

/// What a lookup found: the vulnerabilities, and how many components could be checked.
pub struct Lookup {
    pub vulns: Vec<Vuln>,
    pub checked: usize,
    pub skipped: usize,
}

/// Looks the components up on OSV.dev (`base` is the API root). Only package URLs with versions
/// are sent; components without a package URL or a version are skipped and counted.
pub async fn osv_lookup(base: &str, components: &[Component]) -> AppResult<Lookup> {
    let mut by_purl: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut skipped = 0;
    for (i, c) in components.iter().enumerate() {
        match query_purl(c) {
            Some(p) => by_purl.entry(p).or_default().push(i),
            None => skipped += 1,
        }
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client: {e}")))?;
    let purls: Vec<(String, Vec<usize>)> = by_purl.into_iter().collect();
    let mut affected: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for chunk in purls.chunks(OSV_BATCH) {
        let queries: Vec<Value> = chunk.iter().map(|(p, _)| json!({ "package": { "purl": p } })).collect();
        let resp = client
            .post(format!("{base}/v1/querybatch"))
            .json(&json!({ "queries": queries }))
            .send()
            .await
            .map_err(|e| AppError::Network(format!("OSV.dev is not reachable: {}", describe(&e))))?;
        let ids = parse_osv_batch(&read_json(resp, "the batch query").await?);
        for ((_, idx), found) in chunk.iter().zip(ids) {
            for id in found {
                affected.entry(id).or_default().extend(idx.iter().copied());
            }
        }
    }
    let wanted: Vec<(String, Vec<usize>)> = affected.into_iter().map(|(id, s)| (id, s.into_iter().collect())).take(MAX_VULN_DETAILS).collect();
    use futures_util::stream::{self, StreamExt};
    let results: Vec<AppResult<Vuln>> = stream::iter(wanted.into_iter().map(|(id, idx)| {
        let client = client.clone();
        let url = format!("{base}/v1/vulns/{}", url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>());
        async move {
            let resp = client.get(url).send().await.map_err(|e| AppError::Network(format!("OSV.dev is not reachable: {}", describe(&e))))?;
            let v = read_json(resp, &id).await?;
            Ok(parse_osv_vuln(&v, components, idx))
        }
    }))
    .buffer_unordered(8)
    .collect()
    .await;
    let mut vulns = Vec::with_capacity(results.len());
    for r in results {
        vulns.push(r?);
    }
    vulns.sort_by(|a, b| (severity_rank(&a.severity), a.id.as_str()).cmp(&(severity_rank(&b.severity), b.id.as_str())));
    Ok(Lookup { checked: components.len() - skipped, skipped, vulns })
}

/* ───────────────────────────── checks ───────────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    /// license, completeness or supply-chain
    pub area: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    /// affected components ("name@version")
    pub components: Vec<String>,
    pub recommendation: String,
}

pub fn severity_rank(s: &str) -> usize {
    ["critical", "high", "medium", "low", "unknown", "info"].iter().position(|x| *x == s).unwrap_or(6)
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// License and completeness checks (vulnerabilities are listed separately).
pub fn audit(s: &Sbom) -> Vec<Issue> {
    let mut out = Vec::new();
    let by = |pred: &dyn Fn(&Component) -> bool| -> Vec<String> { s.components.iter().filter(|c| pred(c)).map(Component::label).collect() };
    let mut push = |id: &str, area: &str, severity: &str, title: String, detail: String, components: Vec<String>, recommendation: &str| {
        out.push(Issue { id: id.into(), area: area.into(), severity: severity.into(), title, detail, components, recommendation: recommendation.into() });
    };
    // a lockfile is not an SBOM: no supplier, author or timestamp to expect, and most record no licenses
    let lockfile = s.format.starts_with("lockfile-");
    let licensed = !lockfile || s.components.iter().any(|c| !c.licenses.is_empty());
    if lockfile {
        lockfile_issues(s, &mut push);
    }
    let licenses = |risk: &str| if licensed { by(&|c| c.license_risk == risk) } else { Vec::new() };
    let network = licenses("network-copyleft");
    if !network.is_empty() {
        push("LIC-NETWORK-COPYLEFT", "license", "medium", format!("Network copyleft licenses ({})", network.len()),
            format!("{} use AGPL-style licenses: offering the software over a network can oblige you to publish your source code.", plural(network.len(), "component")),
            network, "Check with your legal or open-source office whether these components are allowed, and how they are used.");
    }
    let restricted = licenses("restricted");
    if !restricted.is_empty() {
        push("LIC-RESTRICTED", "license", "medium", format!("Licenses that restrict use ({})", restricted.len()),
            format!("{} use licenses that are not open source, such as non-commercial, no-derivatives or source-available terms.", plural(restricted.len(), "component")),
            restricted, "Confirm that your use is allowed, or replace these components.");
    }
    let copyleft = licenses("copyleft");
    if !copyleft.is_empty() {
        push("LIC-COPYLEFT", "license", "low", format!("Copyleft licenses ({})", copyleft.len()),
            format!("{} use GPL-style licenses: distributing the software can oblige you to provide its source under the same license.", plural(copyleft.len(), "component")),
            copyleft, "Check that the way the software is distributed complies with these licenses.");
    }
    let unknown = licenses("unknown");
    if !unknown.is_empty() {
        push("LIC-UNKNOWN", "license", "low", format!("Components without a recognised license ({})", unknown.len()),
            format!("{} have no license in the SBOM, or one that is not a known SPDX identifier.", plural(unknown.len(), "component")),
            unknown, "Find out the licenses of these components and add them to the SBOM.");
    }
    let no_version = by(&|c| c.version.is_empty());
    if !no_version.is_empty() {
        push("SBOM-NO-VERSION", "completeness", "low", format!("Components without a version ({})", no_version.len()),
            format!("{} have no version, so they cannot be checked for known vulnerabilities.", plural(no_version.len(), "component")),
            no_version, "Generate the SBOM from the build or lock files, so every component carries its exact version.");
    }
    let no_id = by(&|c| c.purl.is_empty() && c.cpe.is_empty());
    if !no_id.is_empty() && !lockfile {
        push("SBOM-NO-IDENTIFIER", "completeness", "low", format!("Components without a package URL or CPE ({})", no_id.len()),
            format!("{} have neither a package URL nor a CPE, so vulnerability databases cannot match them reliably.", plural(no_id.len(), "component")),
            no_id, "Use an SBOM generator that records package URLs (purl).");
    }
    let no_supplier = by(&|c| c.supplier.is_empty());
    if !no_supplier.is_empty() && no_supplier.len() * 2 > s.components.len() && !lockfile {
        push("SBOM-NO-SUPPLIER", "completeness", "info", format!("Most components have no supplier ({} of {})", no_supplier.len(), s.components.len()),
            "The NTIA minimum elements include the supplier of each component.".into(), Vec::new(), "Record suppliers where the generator can find them.");
    }
    if !s.relationships && !s.components.is_empty() && !lockfile {
        push("SBOM-NO-RELATIONSHIPS", "completeness", "info", "No dependency relationships".into(),
            "The SBOM lists components but not which depends on which, so direct and transitive dependencies cannot be told apart.".into(),
            Vec::new(), "Generate the SBOM with dependency relationships (CycloneDX dependencies, SPDX DEPENDS_ON).");
    }
    if (s.created.is_empty() || s.tools.is_empty()) && !lockfile {
        push("SBOM-NO-AUTHOR", "completeness", "info", "No author or timestamp".into(),
            "The NTIA minimum elements include who made the SBOM data and when; without them its age and origin are unknown.".into(),
            Vec::new(), "Make sure the generator records the tool or author and the creation time.");
    }
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in &s.components {
        if !c.version.is_empty() {
            versions.entry(format!("{}{}", if c.ecosystem.is_empty() { String::new() } else { format!("{}:", c.ecosystem) }, if c.group.is_empty() { c.name.clone() } else { format!("{}/{}", c.group, c.name) })).or_default().insert(c.version.clone());
        }
    }
    let multi: Vec<String> = versions.iter().filter(|(_, v)| v.len() > 1).map(|(k, v)| format!("{k} ({})", v.iter().cloned().collect::<Vec<_>>().join(", "))).collect();
    if !multi.is_empty() {
        push("SBOM-SEVERAL-VERSIONS", "completeness", "info", format!("Packages included in several versions ({})", multi.len()),
            "The same package appears in more than one version; older copies are often missed when vulnerabilities are fixed.".into(),
            multi, "Deduplicate dependency versions where the package manager allows it.");
    }
    out
}

/// The registry a lockfile resolved a registry package from, for `LOCK-MIXED-REGISTRIES`.
fn registry_of(format: &str, c: &Component) -> Option<String> {
    if c.purl.is_empty() {
        return None;
    }
    let r = c.resolved.trim();
    if r.is_empty() {
        // pnpm writes no tarball address for packages of the default registry
        return (format == "lockfile-pnpm").then(|| "registry.npmjs.org".to_string());
    }
    let url = r.trim_start_matches("registry+").trim_start_matches("sparse+");
    let host = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_ascii_lowercase)).unwrap_or_else(|| r.to_ascii_lowercase());
    Some(match host.as_str() {
        "registry.yarnpkg.com" => "registry.npmjs.org".into(),
        "files.pythonhosted.org" => "pypi.org".into(),
        "index.crates.io" => "crates.io".into(),
        _ => host,
    })
}

/// Supply-chain indicators of a dependency lockfile.
fn lockfile_issues(s: &Sbom, push: &mut impl FnMut(&str, &str, &str, String, String, Vec<String>, &str)) {
    let by = |pred: &dyn Fn(&Component) -> bool| -> Vec<String> { s.components.iter().filter(|c| pred(c)).map(Component::label).collect() };
    let http = by(&|c| {
        let r = c.resolved.to_ascii_lowercase();
        r.starts_with("http://") || r.contains("+http://")
    });
    if !http.is_empty() {
        push("LOCK-HTTP", "supply-chain", "high", format!("Packages downloaded over plain HTTP ({})", http.len()),
            format!("{} from http:// addresses: anyone on the network path can replace {} with other code.", if http.len() == 1 { "1 package comes".to_string() } else { format!("{} packages come", http.len()) }, if http.len() == 1 { "it" } else { "them" }),
            http, "Use the registry's https:// address and regenerate the lockfile.");
    }
    if super::lockfiles::HASHED.contains(&s.format.as_str()) {
        let unhashed = by(&|c| !c.purl.is_empty() && c.hashes.is_empty());
        if !unhashed.is_empty() {
            push("LOCK-NO-INTEGRITY", "supply-chain", "medium", format!("Packages without an integrity hash ({})", unhashed.len()),
                format!("The lockfile records no hash for {}, so the package manager cannot tell when a download has changed.", plural(unhashed.len(), "package")),
                unhashed, "Regenerate the lockfile with a current version of the package manager, which records hashes.");
        }
    }
    let elsewhere = by(&|c| c.purl.is_empty() && !c.resolved.is_empty());
    if !elsewhere.is_empty() {
        push("LOCK-NON-REGISTRY", "supply-chain", "low", format!("Dependencies from Git, URLs or local paths ({})", elsewhere.len()),
            format!("{} from a registry: no vulnerability database matches {}, and a branch or an address can change what gets installed.", if elsewhere.len() == 1 { "1 dependency does not come".to_string() } else { format!("{} dependencies do not come", elsewhere.len()) }, if elsewhere.len() == 1 { "it" } else { "them" }),
            elsewhere, "Pin Git dependencies to a commit, prefer released versions from the registry, and review these dependencies yourself.");
    }
    if s.sources.iter().any(|x| x.starts_with("extra-index-url")) {
        push("LOCK-EXTRA-INDEX", "supply-chain", "medium", "Several package indexes (--extra-index-url)".into(),
            "pip gives every index the same priority and installs the highest version it finds in any of them, so a package published on PyPI under the name of an internal package can be installed instead (dependency confusion; the PyTorch-nightly compromise of December 2022 worked this way).".into(),
            s.sources.clone(), "Use one index that mirrors PyPI and serves the internal packages, or install with --require-hashes.");
    }
    if s.format != "lockfile-composer" {
        let registries: BTreeSet<String> = s.components.iter().filter_map(|c| registry_of(&s.format, c)).collect();
        if registries.len() > 1 {
            push("LOCK-MIXED-REGISTRIES", "supply-chain", "low", format!("Packages from {} registries", registries.len()),
                "Private packages whose names are not taken on the public registry are exposed to dependency confusion when the lockfile is regenerated: someone can publish the same name there with a higher version.".into(),
                registries.into_iter().collect(), "Publish private packages under a scope or namespace you own on the public registry, and send each scope to one registry.");
        }
    }
}

/* ───────────────────────────── storage ───────────────────────────── */

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SbomSummary {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub format: String,
    pub subject: String,
    pub components: usize,
    pub sha256: String,
    pub evidence_id: Option<i64>,
    pub imported_at: String,
    /// when OSV.dev was last asked (None: never)
    pub checked_at: Option<String>,
    /// vulnerabilities per severity: critical, high, medium, low, unknown
    pub vulns: [usize; 5],
    pub vulnerable: usize,
}

/// The vulnerabilities to show: the file's own and the looked-up ones (the same id once, the
/// looked-up record first).
pub fn merged(sbom: &Sbom, osv: &[Vuln]) -> Vec<Vuln> {
    let mut out: Vec<Vuln> = osv.to_vec();
    for v in &sbom.vulns {
        match out.iter_mut().find(|o| o.id == v.id || o.aliases.contains(&v.id) || v.aliases.contains(&o.id)) {
            Some(o) => {
                if o.analysis.is_empty() {
                    o.analysis = v.analysis.clone();
                }
                for c in &v.components {
                    if !o.components.contains(c) {
                        o.components.push(*c);
                    }
                }
            }
            None => out.push(v.clone()),
        }
    }
    out.sort_by(|a, b| (severity_rank(&a.severity), a.id.as_str()).cmp(&(severity_rank(&b.severity), b.id.as_str())));
    out
}

fn summarize(row: (i64, i64, String, String, Option<i64>, String, Option<String>), sbom: &Sbom, osv: &[Vuln]) -> SbomSummary {
    let (id, project_id, name, sha256, evidence_id, imported_at, checked_at) = row;
    let all = merged(sbom, osv);
    let mut counts = [0usize; 5];
    let mut vulnerable = BTreeSet::new();
    for v in all.iter().filter(|v| v.analysis != "not_affected" && v.analysis != "false_positive") {
        counts[severity_rank(&v.severity).min(4)] += 1;
        vulnerable.extend(v.components.iter().copied());
    }
    SbomSummary { id, project_id, name, format: sbom.format.clone(), subject: sbom.subject.clone(), components: sbom.components.len(), sha256, evidence_id, imported_at, checked_at, vulns: counts, vulnerable: vulnerable.len() }
}

pub fn store(c: &Connection, project_id: i64, name: &str, sha256: &str, evidence_id: Option<i64>, sbom: &Sbom) -> AppResult<i64> {
    let dup: Option<i64> = c.query_row("SELECT id FROM sbom_docs WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?;
    if dup.is_some() {
        return Err(validation("This SBOM is already in the project"));
    }
    let doc = serde_json::to_string(sbom).map_err(|e| AppError::Internal(e.to_string()))?;
    c.execute(
        "INSERT INTO sbom_docs (project_id, name, format, subject, components, sha256, evidence_id, doc, imported_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![project_id, name, sbom.format, sbom.subject, sbom.components.len() as i64, sha256, evidence_id, doc, crate::util::now()],
    )?;
    Ok(c.last_insert_rowid())
}

type Loaded = (SbomSummary, Sbom, Vec<Vuln>);

fn load(c: &Connection, sql: &str, p: impl rusqlite::Params) -> AppResult<Vec<Loaded>> {
    let mut st = c.prepare(sql)?;
    let rows = st
        .query_map(p, |r| {
            Ok(((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, String>(5)?, r.get::<_, Option<String>>(6)?), r.get::<_, String>(7)?, r.get::<_, String>(8)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(row, doc, vulns)| {
            let id = row.0;
            let sbom: Sbom = serde_json::from_str(&doc).map_err(|e| AppError::Internal(format!("stored SBOM {id} cannot be read: {e}")))?;
            let osv: Vec<Vuln> = serde_json::from_str(&vulns).map_err(|e| AppError::Internal(format!("stored vulnerabilities of SBOM {id} cannot be read: {e}")))?;
            Ok((summarize(row, &sbom, &osv), sbom, osv))
        })
        .collect()
}

const COLS: &str = "id, project_id, name, sha256, evidence_id, imported_at, checked_at, doc, vulns";

pub fn list_docs(c: &Connection, project_id: i64) -> AppResult<Vec<SbomSummary>> {
    Ok(load(c, &format!("SELECT {COLS} FROM sbom_docs WHERE project_id = ?1 ORDER BY id DESC"), params![project_id])?.into_iter().map(|(s, _, _)| s).collect())
}

pub fn get(c: &Connection, id: i64) -> AppResult<Loaded> {
    load(c, &format!("SELECT {COLS} FROM sbom_docs WHERE id = ?1"), params![id])?.into_iter().next().ok_or_else(|| AppError::NotFound(format!("SBOM {id}")))
}

pub fn save_lookup(c: &Connection, id: i64, vulns: &[Vuln]) -> AppResult<()> {
    let json = serde_json::to_string(vulns).map_err(|e| AppError::Internal(e.to_string()))?;
    if c.execute("UPDATE sbom_docs SET vulns = ?1, checked_at = ?2 WHERE id = ?3", params![json, crate::util::now(), id])? == 0 {
        return Err(AppError::NotFound(format!("SBOM {id}")));
    }
    Ok(())
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    if c.execute("DELETE FROM sbom_docs WHERE id = ?1", params![id])? == 0 {
        return Err(AppError::NotFound(format!("SBOM {id}")));
    }
    Ok(())
}

/// The finding for a vulnerability of one component.
pub fn vuln_finding(summary: &SbomSummary, sbom: &Sbom, v: &Vuln, component: usize) -> Option<crate::commands::projects::FindingInput> {
    let c = sbom.components.get(component)?;
    let mut description = if v.summary.is_empty() { format!("{} affects {}.", v.id, c.label()) } else { format!("{}\n\n{} affects {}.", v.summary, v.id, c.label()) };
    if !v.aliases.is_empty() {
        description.push_str(&format!(" Also known as {}.", v.aliases.join(", ")));
    }
    if !v.analysis.is_empty() {
        description.push_str(&format!(" The SBOM's own analysis says: {}.", v.analysis));
    }
    if !sbom.subject.is_empty() {
        description.push_str(&format!("\n\nSoftware: {}", sbom.subject));
    }
    if !v.references.is_empty() {
        description.push_str(&format!("\n\nReferences:\n{}", v.references.iter().map(|r| format!("- {r}")).collect::<Vec<_>>().join("\n")));
    }
    let severity = if v.severity == "unknown" { "medium".to_string() } else { v.severity.clone() };
    Some(crate::commands::projects::FindingInput {
        id: None,
        project_id: summary.project_id,
        title: format!("{} in {}", v.id, c.label()).chars().take(200).collect(),
        severity,
        status: "new".into(),
        category: "Vulnerable component".into(),
        confidence: Some(if c.version.is_empty() { "medium" } else { "high" }.into()),
        description,
        affected_target: if c.purl.is_empty() { c.label() } else { c.purl.clone() },
        cve: v.cve().unwrap_or("").to_string(),
        evidence: Vec::new(),
        reproduction: String::new(),
        technical_details: format!("{} from {} ({}) in {} (SHA-256 {}).", v.id, if v.source == "osv" { "OSV.dev" } else { "the SBOM" }, if v.severity == "unknown" { "severity not published".to_string() } else { v.score.map(|s| format!("score {s:.1}")).unwrap_or_else(|| format!("rated {}", v.severity)) }, summary.name, summary.sha256),
        remediation: if v.fixed.is_empty() { format!("No fixed version is listed. Follow {}'s advisory, and replace or mitigate {} if no fix comes.", v.id, c.name) } else { format!("Upgrade {} to {} or later.", c.name, v.fixed.join(", ")) },
        tags: vec!["sbom".into(), if c.ecosystem.is_empty() { "component".into() } else { c.ecosystem.clone() }],
        assignee: String::new(),
        due_date: None,
        cvss_vector: if crate::cvss::parse(&v.vector).is_ok() { v.vector.clone() } else { String::new() },
    })
}

/// The finding for a license or completeness issue.
pub fn issue_finding(summary: &SbomSummary, sbom: &Sbom, issue: &Issue) -> crate::commands::projects::FindingInput {
    let mut description = issue.detail.clone();
    if !issue.components.is_empty() {
        let shown: Vec<String> = issue.components.iter().take(50).map(|c| format!("- {c}")).collect();
        description.push_str(&format!("\n\nComponents:\n{}", shown.join("\n")));
        if issue.components.len() > 50 {
            description.push_str(&format!("\n- … and {} more", issue.components.len() - 50));
        }
    }
    crate::commands::projects::FindingInput {
        id: None,
        project_id: summary.project_id,
        title: format!("{} ({})", issue.title, if sbom.subject.is_empty() { &summary.name } else { &sbom.subject }).chars().take(200).collect(),
        severity: if issue.severity == "info" { "info".into() } else { issue.severity.clone() },
        status: "new".into(),
        category: if issue.area == "license" { "License compliance".into() } else { "SBOM quality".into() },
        confidence: Some("high".into()),
        description,
        affected_target: if sbom.subject.is_empty() { summary.name.clone() } else { sbom.subject.clone() },
        cve: String::new(),
        evidence: Vec::new(),
        reproduction: String::new(),
        technical_details: format!("Check {} on {} (SHA-256 {}).", issue.id, summary.name, summary.sha256),
        remediation: issue.recommendation.clone(),
        tags: vec!["sbom".into(), issue.area.clone()],
        assignee: String::new(),
        due_date: None,
        cvss_vector: String::new(),
    }
}

#[cfg(test)]
#[path = "sbom_tests.rs"]
mod tests;
