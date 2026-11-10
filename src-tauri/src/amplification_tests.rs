//! Amplification checks of the importers (Mission 6): small hostile files whose cost used to grow
//! faster than their size: one host copied into every finding, a rule's texts re-read for every
//! result, quadratic duplicate checks, one database pass per listed evidence id.
//!
//! * `amp_*` tests are ignored timings for an optimized build, one per process so each peak memory
//!   is its own: `cargo test --release --lib amp_ -- --ignored --nocapture --test-threads=1`.
//!   Each prints `AMP <name> <milliseconds> ms <what>` and, on Linux, the peak memory.
//! * The other tests are regressions: the same shapes, smaller, under a time budget, with the
//!   import's meaning checked (what is read, what is left out, and why).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use crate::db::Db;

fn peak_kb() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string()))
        .map(|k| format!(" peak {} MB", k.parse::<u64>().unwrap_or(0) / 1024))
        .unwrap_or_default()
}

fn report(name: &str, started: Instant, what: &str) {
    println!("AMP {name} {} ms {what}{}", started.elapsed().as_millis(), peak_kb());
}

/// A .nessus file with one host named by `host` and `items` findings on it.
pub fn nessus(host: &str, items: usize) -> String {
    let mut x = String::from("<?xml version=\"1.0\"?><NessusClientData_v2><Report name=\"amp\">");
    let _ = write!(x, "<ReportHost name=\"{host}\"><HostProperties><tag name=\"host-ip\">{host}</tag></HostProperties>");
    for i in 0..items {
        let _ = write!(x, "<ReportItem port=\"{}\" svc_name=\"www\" protocol=\"tcp\" severity=\"2\" pluginID=\"{}\" pluginName=\"Plugin {i}\" pluginFamily=\"Web\"><synopsis>s</synopsis></ReportItem>", 1 + i % 60000, 10000 + i);
    }
    x.push_str("</ReportHost></Report></NessusClientData_v2>");
    x
}

/// A Burp XML export with `items` issues on one host.
pub fn burp(host: &str, items: usize) -> String {
    let mut x = String::from("<?xml version=\"1.0\"?><issues burpVersion=\"2024\">");
    for i in 0..items {
        let _ = write!(x, "<issue><serialNumber>{i}</serialNumber><type>{}</type><name>Issue {i}</name><host ip=\"10.0.0.1\">https://{host}</host><path>/p{i}</path><location>/p{i}</location><severity>Low</severity><confidence>Firm</confidence></issue>", 1000 + i);
    }
    x.push_str("</issues>");
    x
}

/// A Greenbone report with `items` results on one host.
pub fn openvas(host: &str, items: usize) -> String {
    let mut x = String::from("<?xml version=\"1.0\"?><report id=\"amp\"><report><results>");
    for i in 0..items {
        let _ = write!(x, "<result id=\"r{i}\"><name>NVT {i}</name><host>{host}</host><port>{}/tcp</port><nvt oid=\"1.3.6.1.4.1.25623.1.0.{i}\"><family>General</family><tags>summary=x</tags></nvt><threat>Medium</threat><severity>5.0</severity><qod><value>80</value></qod><description>d</description></result>", 1 + i % 60000);
    }
    x.push_str("</results></report></report>");
    x
}

/// A SARIF log whose one rule has texts of `text_len` bytes (and a tool name as long), with
/// `results` results of that rule.
pub fn sarif(text_len: usize, results: usize) -> String {
    let long = "a".repeat(text_len);
    let mut x = format!(
        r#"{{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{{"tool":{{"driver":{{"name":"{long}","rules":[{{"id":"R1","shortDescription":{{"text":"{long}"}},"fullDescription":{{"text":"{long}"}},"helpUri":"https://example.com/{long}","properties":{{"tags":["security","{long}"]}}}}]}}}},"results":["#
    );
    for i in 0..results {
        if i > 0 {
            x.push(',');
        }
        let _ = write!(x, r#"{{"ruleIndex":0,"ruleId":"R1","message":{{"text":"m{i}"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"src/f{i}.rs"}},"region":{{"startLine":{}}}}}}}]}}"#, i + 1);
    }
    x.push_str("]}]}");
    x
}

/// Prowler's OCSF output: `items` passed checks; the first names the product with `product_len`
/// bytes (the first product name found is the one used for every item).
pub fn ocsf_passed(product_len: usize, items: usize) -> String {
    let product = "p".repeat(product_len);
    let mut x = String::from("[");
    for i in 0..items {
        if i > 0 {
            x.push(',');
        }
        let meta = if i == 0 { format!(r#""product":{{"name":"{product}"}},"#) } else { String::new() };
        let _ = write!(x, r#"{{"class_uid":2004,"status_code":"PASS","metadata":{{{meta}"event_code":"check_{i}"}},"finding_info":{{"title":"t"}},"resources":[{{"uid":"arn:aws:s3:::b{i}","region":"eu-west-1"}}],"cloud":{{"account":{{"uid":"123456789012"}}}}}}"#);
    }
    x.push(']');
    x
}

/// One failed OCSF check listing `attacks` ATT&CK entries.
pub fn ocsf_attacks(attacks: usize) -> String {
    let mut list = String::new();
    for i in 0..attacks {
        if i > 0 {
            list.push(',');
        }
        let _ = write!(list, r#"{{"technique":{{"uid":"T{}","name":"n"}},"tactic":{{"name":"t"}}}}"#, 1000 + i);
    }
    format!(r#"[{{"class_uid":2004,"status_code":"FAIL","severity_id":3,"metadata":{{"product":{{"name":"Prowler"}},"event_code":"c"}},"finding_info":{{"title":"t","attacks":[{list}]}},"resources":[{{"uid":"r"}}],"cloud":{{"account":{{"uid":"1"}}}}}}]"#)
}

/// A Cyber Hub graph file with one entity that lists `known` evidence records and `unknown` ids
/// that name no record.
pub fn osint_ids(known: usize, unknown: usize) -> Vec<u8> {
    let ids: Vec<String> = (0..known).map(|i| format!("ev{i}")).chain((0..unknown).map(|i| format!("missing{i}"))).collect();
    let evidence: Vec<serde_json::Value> = (0..known).map(|i| serde_json::json!({ "id": format!("ev{i}"), "kind": "dns", "source": "dns", "summary": format!("lookup {i}"), "data": {} })).collect();
    serde_json::to_vec(&serde_json::json!({
        "format": crate::osint::io::FORMAT,
        "version": crate::osint::io::FORMAT_VERSION,
        "investigation": { "name": "amp", "targetType": "domain", "targetValue": "example.com" },
        "graph": { "name": "g", "nodes": [] },
        "entities": [{ "id": "e1", "type": "domain", "value": "example.com", "evidence": ids }],
        "evidence": evidence,
    }))
    .unwrap()
}

/// A CycloneDX SBOM of `components` components where one vulnerability id appears `copies`
/// times, each listing every component `repeat` times.
pub fn sbom_duplicates(components: usize, copies: usize, repeat: usize) -> String {
    let comps: Vec<String> = (0..components).map(|i| format!(r#"{{"type":"library","name":"c{i}","version":"1.0.{i}","purl":"pkg:npm/c{i}@1.0.{i}","bom-ref":"c{i}"}}"#)).collect();
    let mut affects: Vec<String> = Vec::with_capacity(components * repeat);
    for _ in 0..repeat {
        affects.extend((0..components).map(|i| format!(r#"{{"ref":"c{i}"}}"#)));
    }
    let vuln = format!(r#"{{"id":"CVE-2021-23337","affects":[{}]}}"#, affects.join(","));
    format!(r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{}],"vulnerabilities":[{}]}}"#, comps.join(","), vec![vuln; copies].join(","))
}

/// A Postman collection with one request whose URL has `params` distinct query names.
pub fn postman_query(params: usize) -> String {
    let q: Vec<String> = (0..params).map(|i| format!("q{i}=1")).collect();
    format!(r#"{{"info":{{"name":"amp","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}},"item":[{{"name":"x","request":{{"method":"GET","url":"https://api.example.com/users?{}"}}}}]}}"#, q.join("&"))
}

fn osint_apply(bytes: &[u8]) -> (usize, i64) {
    let db = Db::open_in_memory().unwrap();
    let doc = crate::osint::io::parse(bytes, "json").unwrap();
    db.with(|c| {
        let (inv, _) = crate::osint::io::apply(c, &doc, None, "g", "amp.json")?;
        let links: i64 = c.query_row("SELECT COUNT(*) FROM osint_entity_evidence x JOIN osint_entities e ON e.id = x.entity_id WHERE e.investigation_id = ?1", [inv], |r| r.get(0))?;
        let events: i64 = c.query_row("SELECT COUNT(*) FROM osint_events WHERE investigation_id = ?1", [inv], |r| r.get(0))?;
        Ok((links as usize, events))
    })
    .unwrap()
}

/* ───────────────────────── timings (ignored) ───────────────────────── */

#[test]
#[ignore]
fn amp_nessus_long_host() {
    let host = "h".repeat(100 * 1024);
    let file = nessus(&host, 2_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("nessus_long_host", t, &format!("{} KB file, 100 KB host, 2,000 items ({} findings)", file.len() / 1024, p.findings.len()));
}

#[test]
#[ignore]
fn amp_nessus_normal() {
    let file = nessus("10.0.0.1", 10_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("nessus_normal", t, &format!("{} KB file, 10,000 items ({} findings)", file.len() / 1024, p.findings.len()));
}

#[test]
#[ignore]
fn amp_burp_and_openvas_long_hosts() {
    let host = "h".repeat(20 * 1024);
    let file = burp(&host, 2_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("burp_long_hosts", t, &format!("{} KB file, a 20 KB host per issue, 2,000 issues ({} findings)", file.len() / 1024, p.findings.len()));
    let file = openvas(&host, 2_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("openvas_long_hosts", t, &format!("{} KB file, a 20 KB host per result, 2,000 results ({} findings)", file.len() / 1024, p.findings.len()));
}

#[test]
#[ignore]
fn amp_sarif_long_rule() {
    let file = sarif(256 * 1024, 2_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("sarif_long_rule", t, &format!("{} KB file, 256 KB rule texts and tool name, 2,000 results ({} findings)", file.len() / 1024, p.findings.len()));
}

#[test]
#[ignore]
fn amp_ocsf() {
    let file = ocsf_passed(256 * 1024, 2_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("ocsf_long_product", t, &format!("{} KB file, 256 KB product name, 2,000 passed checks ({} passed)", file.len() / 1024, p.passed.len()));
    let file = ocsf_attacks(30_000);
    let t = Instant::now();
    let p = crate::workspace::scan_import::parse(&file).unwrap();
    report("ocsf_attacks", t, &format!("{} KB file, one check with 30,000 ATT&CK entries ({} findings)", file.len() / 1024, p.findings.len()));
}

#[test]
#[ignore]
fn amp_osint_evidence_ids() {
    let file = osint_ids(1_000, 3_000);
    let t = Instant::now();
    let (links, events) = osint_apply(&file);
    report("osint_evidence_ids", t, &format!("{} KB file, one entity listing 1,000 evidence records and 3,000 unknown ids ({links} evidence links, {events} events)", file.len() / 1024));
}

#[test]
#[ignore]
fn amp_sbom_duplicate_refs() {
    let file = sbom_duplicates(20_000, 3, 3);
    let t = Instant::now();
    let s = crate::workspace::sbom::parse(&file).unwrap();
    let merged = crate::workspace::sbom::merged(&s, &[]);
    report("sbom_duplicate_refs", t, &format!("{} KB file, 20,000 components, one id 3 times listing each component 3 times ({} vulnerability, {} components affected)", file.len() / 1024, merged.len(), merged.first().map_or(0, |v| v.components.len())));
}

#[test]
#[ignore]
fn amp_postman_query() {
    let file = postman_query(30_000);
    let t = Instant::now();
    let spec = crate::workspace::apisec::parse(&file).unwrap();
    report("postman_query", t, &format!("{} KB file, one request with 30,000 query names ({} parameters kept)", file.len() / 1024, spec.endpoints.first().map_or(0, |e| e.params.len())));
}

/* ───────────────────────── regressions (run every time) ───────────────────────── */

/// Debug builds are slow; these budgets are still far below what the old code took on the same
/// input in an optimized build.
const BUDGET: Duration = Duration::from_secs(20);

#[test]
fn a_host_longer_than_a_host_name_is_never_copied_into_findings() {
    crate::hostile::run("nessus", "100 KB host × 500 items", BUDGET, || {
        let host = "h".repeat(100 * 1024);
        let p = crate::workspace::scan_import::parse(&nessus(&host, 500)).unwrap();
        assert_eq!(p.findings.len(), 500, "the findings are kept");
        assert!(p.findings.iter().all(|f| f.host.is_none() && f.target.len() < 100), "without a host, outside any scope");
        assert!(p.assets.is_empty(), "no asset is named after it");
        assert!(p.warnings.iter().any(|w| w.contains("500 findings name a host longer than 253 characters")), "{:?}", p.warnings);
    });
    // a real host is untouched: the same host, findings and fingerprints as before
    let p = crate::workspace::scan_import::parse(&nessus("10.0.0.1", 3)).unwrap();
    assert!(p.findings.iter().all(|f| f.host.as_deref() == Some("10.0.0.1")));
    assert_eq!(p.findings[0].fingerprint, crate::workspace::scan_import::fingerprint(&["nessus", "10000", "10.0.0.1", "1", "tcp"]));
    let host = "a".repeat(253);
    let p = crate::workspace::scan_import::parse(&nessus(&host, 1)).unwrap();
    assert_eq!(p.findings[0].host.as_deref(), Some(host.as_str()), "253 characters is still a host name");
    crate::hostile::run("burp and greenbone", "20 KB hosts × 300 items", BUDGET, || {
        let host = "h".repeat(20 * 1024);
        let b = crate::workspace::scan_import::parse(&burp(&host, 300)).unwrap();
        assert!(b.findings.iter().all(|f| f.host.is_none()) && b.assets.is_empty());
        let g = crate::workspace::scan_import::parse(&openvas(&host, 300)).unwrap();
        assert!(g.findings.is_empty(), "a result without a usable host is not read, as one without a host");
        assert!(g.warnings.iter().any(|w| w.contains("300 results name a host longer than 253 characters")), "{:?}", g.warnings);
    });
}

#[test]
fn a_sarif_rule_is_read_once_and_results_past_the_limit_are_only_counted() {
    crate::hostile::run("sarif", "64 KB rule texts × 1,000 results", BUDGET, || {
        let p = crate::workspace::scan_import::parse(&sarif(64 * 1024, 1_000)).unwrap();
        assert_eq!(p.findings.len(), 1_000);
        let f = &p.findings[0];
        assert!(f.title.chars().count() <= 200 && f.description.chars().count() <= 2_200);
        assert!(f.references.iter().all(|r| r.chars().count() <= 2_000));
        assert!(f.tags.iter().all(|t| t.chars().count() <= 40) && p.tool.chars().count() <= 60);
    });
    crate::hostile::run("sarif", "10,005 results", BUDGET, || {
        let p = crate::workspace::scan_import::parse(&sarif(8, crate::workspace::scan_import::MAX_FINDINGS + 5)).unwrap();
        assert_eq!(p.findings.len(), crate::workspace::scan_import::MAX_FINDINGS);
        assert!(p.truncated == 5 && p.incomplete);
    });
}

#[test]
fn ocsf_reads_its_product_once_and_dedupes_techniques_through_a_set() {
    crate::hostile::run("ocsf", "256 KB product × 2,000 passed checks", BUDGET, || {
        let p = crate::workspace::scan_import::parse(&ocsf_passed(256 * 1024, 2_000)).unwrap();
        assert_eq!(p.passed.len(), 2_000);
        assert!(p.tool.chars().count() <= 60);
    });
    crate::hostile::run("ocsf", "30,000 ATT&CK entries", BUDGET, || {
        let p = crate::workspace::scan_import::parse(&ocsf_attacks(30_000)).unwrap();
        assert_eq!(p.findings.len(), 1);
        assert!(p.findings[0].technical.contains("T1000 n (t)"));
    });
}

#[test]
fn an_osint_import_reads_each_evidence_record_once_and_ignores_repeated_or_unknown_ids() {
    let file = osint_ids(200, 2_000);
    let started = Instant::now();
    let (links, events) = osint_apply(&file);
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    // 200 records, one shared "import" evidence for the 2,000 ids that name nothing, and the new
    // investigation's own record of its target (the same 3 kinds as before the change)
    assert_eq!(links, 202);
    assert!(events < 300, "one collection event per evidence group, not per listed id: {events}");
    // repeated ids add nothing; confidence is the same as computing it right away
    let mut doc: serde_json::Value = serde_json::from_slice(&osint_ids(3, 0)).unwrap();
    let ids = doc["entities"][0]["evidence"].as_array().unwrap().clone();
    doc["entities"][0]["evidence"] = serde_json::Value::Array(ids.iter().cycle().take(300).cloned().collect());
    let db = Db::open_in_memory().unwrap();
    let parsed = crate::osint::io::parse(&serde_json::to_vec(&doc).unwrap(), "json").unwrap();
    db.with(|c| {
        let (inv, _) = crate::osint::io::apply(c, &parsed, None, "g", "amp.json")?;
        let (eid, conf): (i64, String) = c.query_row("SELECT id, confidence FROM osint_entities WHERE investigation_id = ?1", [inv], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let links: i64 = c.query_row("SELECT COUNT(*) FROM osint_entity_evidence WHERE entity_id = ?1", [eid], |r| r.get(0))?;
        // three records listed 100 times each are three links (the fourth is the target's record)
        assert_eq!(links, 4);
        crate::osint::ingest::recompute_entity(c, eid)?;
        let again: String = c.query_row("SELECT confidence FROM osint_entities WHERE id = ?1", [eid], |r| r.get(0))?;
        assert_eq!(conf, again);
        Ok(())
    })
    .unwrap();
}

#[test]
fn sbom_references_count_once_and_merge_through_a_set() {
    crate::hostile::run("sbom", "20,000 components, one id 3 times × 3", BUDGET, || {
        let s = crate::workspace::sbom::parse(&sbom_duplicates(20_000, 3, 3)).unwrap();
        assert!(s.vulns.iter().all(|v| v.components.len() == 20_000), "a repeated reference is the same component");
        let merged = crate::workspace::sbom::merged(&s, &[]);
        assert_eq!((merged.len(), merged[0].components.len()), (1, 20_000));
    });
}

#[test]
fn postman_endpoints_keep_at_most_200_parameters() {
    crate::hostile::run("postman", "30,000 query names", BUDGET, || {
        let spec = crate::workspace::apisec::parse(&postman_query(30_000)).unwrap();
        assert_eq!(spec.endpoints.len(), 1);
        assert_eq!(spec.endpoints[0].params.len(), 200);
        assert_eq!(spec.endpoints[0].params[0].name, "q0", "in the file's order");
    });
}

/// Tool output with `urls` URLs (the first 400 distinct, then repeats of the first), for the OSINT
/// indicator extraction.
pub fn tool_output(urls: usize) -> String {
    let mut x = String::with_capacity(urls * 40);
    for i in 0..urls {
        let n = if i < 400 { i } else { 0 };
        let _ = writeln!(x, "found https://host{n}.example.com/path/{n} and admin{n}@mail.example.org");
    }
    x
}

/// JSON Lines events with `fields` fields each.
pub fn wide_events(events: usize, fields: usize) -> Vec<u8> {
    let mut x = String::new();
    for e in 0..events {
        let mut o = serde_json::Map::new();
        o.insert("@timestamp".into(), serde_json::json!(format!("2026-11-10T10:00:{:02}Z", e % 60)));
        for f in 0..fields {
            o.insert(format!("group{}.field{f}", f % 7), serde_json::json!(f));
        }
        x.push_str(&serde_json::Value::Object(o).to_string());
        x.push('\n');
    }
    x.into_bytes()
}

#[test]
#[ignore]
fn amp_indicators_and_events() {
    let text = tool_output(50_000);
    let t = Instant::now();
    let found = crate::osint::providers::internal::extract(&text);
    report("osint_indicators", t, &format!("{} KB of tool output, 50,000 URL lines ({} indicators)", text.len() / 1024, found.len()));
    let file = wide_events(3_000, 500);
    let t = Instant::now();
    let s = crate::detection::events::read(&file[..]).unwrap();
    report("wide_events", t, &format!("{} MB, 3,000 events of 500 fields ({} events, {} fields in the first)", file.len() >> 20, s.events.len(), s.events.first().map_or(0, |e| e.fields.len())));
}

#[test]
fn indicator_extraction_and_wide_events_are_linear() {
    crate::hostile::run("indicators", "20,000 URL lines", BUDGET, || {
        let found = crate::osint::providers::internal::extract(&tool_output(20_000));
        assert!(found.iter().any(|(_, v)| v == "https://host0.example.com/path/0"));
        // domains inside a URL or an e-mail address are not extracted again
        assert!(!found.iter().any(|(t, v)| *t == crate::osint::model::EntityType::Domain && v == "host0.example.com"));
        assert!(found.len() <= 500);
    });
    crate::hostile::run("events", "1,000 events of 500 fields", BUDGET, || {
        let s = crate::detection::events::read(&wide_events(1_000, 500)[..]).unwrap();
        assert_eq!(s.events.len(), 1_000);
        let e = &s.events[0];
        assert_eq!(e.time, "2026-11-10T10:00:00Z");
        // dotted names first, then unambiguous leaf names while there is room (512 fields)
        assert!(e.get("group0.field0").is_some() && e.get("field0").is_some());
        assert_eq!(e.fields.len(), 512);
    });
}

/// The largest files an import accepts (about 45 MB each), parsed, and 10,000 findings committed:
/// how long an import can take after the fixes, which decides whether it needs a cancel button
/// (the preview can always be discarded; the commit is one transaction).
#[test]
#[ignore]
fn amp_largest_files() {
    let output = "x".repeat(4_200);
    let mut nessus_file = String::from("<?xml version=\"1.0\"?><NessusClientData_v2><Report name=\"amp\"><ReportHost name=\"10.0.0.1\"><HostProperties><tag name=\"host-ip\">10.0.0.1</tag></HostProperties>");
    for i in 0..10_000 {
        let _ = write!(nessus_file, "<ReportItem port=\"{}\" svc_name=\"www\" protocol=\"tcp\" severity=\"2\" pluginID=\"{}\" pluginName=\"Plugin {i}\" pluginFamily=\"Web\"><synopsis>s</synopsis><description>d</description><plugin_output>{output}</plugin_output></ReportItem>", 1 + i % 60000, 10000 + i);
    }
    nessus_file.push_str("</ReportHost></Report></NessusClientData_v2>");
    let t = Instant::now();
    let parsed = crate::workspace::scan_import::parse(&nessus_file).unwrap();
    report("largest_nessus_parse", t, &format!("{} MB file, {} findings", nessus_file.len() >> 20, parsed.findings.len()));

    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Amp', 'active', 't', 't')", [])?;
        c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES (1, '10.0.0.1', 'ip', 1, '', 't')", [])?;
        let t = Instant::now();
        let opts = crate::workspace::scan_import::Options { include_info: true, ..Default::default() };
        let r = crate::workspace::scan_import::import(c, 1, &parsed, opts, &crate::workspace::scan_import::FileInfo { file_name: "amp.nessus", sha256: "00", evidence_id: None })?;
        report("largest_nessus_commit", t, &format!("{} findings created", r.created));
        Ok(())
    })
    .unwrap();

    let mut results = String::new();
    for i in 0..10_000 {
        let _ = write!(results, r#"{}{{"ruleIndex":0,"ruleId":"R1","message":{{"text":"{output}"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"src/f{i}.rs"}},"region":{{"startLine":{}}}}}}}]}}"#, if i == 0 { "" } else { "," }, i + 1);
    }
    let sarif_file = format!(r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"Amp","rules":[{{"id":"R1","shortDescription":{{"text":"rule"}}}}]}}}},"results":[{results}]}}]}}"#);
    let t = Instant::now();
    let parsed = crate::workspace::scan_import::parse(&sarif_file).unwrap();
    report("largest_sarif_parse", t, &format!("{} MB file, {} findings", sarif_file.len() >> 20, parsed.findings.len()));

    let mut ocsf_file = String::from("[");
    for i in 0..10_000 {
        let _ = write!(ocsf_file, r#"{}{{"class_uid":2004,"status_code":"FAIL","severity_id":3,"status_detail":"{output}","metadata":{{"product":{{"name":"Prowler"}},"event_code":"check_{i}"}},"finding_info":{{"title":"t{i}"}},"resources":[{{"uid":"arn:aws:s3:::b{i}"}}],"cloud":{{"account":{{"uid":"1"}}}}}}"#, if i == 0 { "" } else { "," });
    }
    ocsf_file.push(']');
    let t = Instant::now();
    let parsed = crate::workspace::scan_import::parse(&ocsf_file).unwrap();
    report("largest_ocsf_parse", t, &format!("{} MB file, {} findings", ocsf_file.len() >> 20, parsed.findings.len()));
}
