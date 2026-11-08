//! Tests of the scan importers (fixtures follow each tool's documented output).

use super::*;
use crate::db::Db;
use crate::workspace::evidence;

const NUCLEI: &str = r#"{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 - Path Traversal","severity":"critical","description":"<p>Path traversal &amp; RCE</p>","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],"tags":["cve","apache"],"classification":{"cve-id":["cve-2021-41773"],"cwe-id":["cwe-22"],"cvss-score":7.5,"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},"remediation":"Upgrade to 2.4.51"},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/cgi-bin/.%2e/etc/passwd","ip":"93.184.215.7","extracted-results":["root:x:0:0","api_key=FAKE-test-value-not-a-credential"],"timestamp":"2026-11-01T10:00:00Z","curl-command":"curl -H 'Authorization: Bearer secret' https://app.example.com"}
not json
{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info","tags":"tech,discovery"},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com","matcher-name":"nginx"}
{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 - Path Traversal","severity":"critical"},"host":"https://app.example.com","matched-at":"https://app.example.com/cgi-bin/.%2e/etc/passwd"}
{"template-id":"exposed-panel","info":{"name":"Admin panel","severity":"medium"},"host":"https://other.org","matched-at":"https://other.org/admin"}
"#;

const NESSUS: &str = r#"<?xml version="1.0" ?>
<NessusClientData_v2><Report name="Weekly">
<ReportHost name="93.184.215.7"><HostProperties><tag name="host-ip">93.184.215.7</tag><tag name="host-fqdn">app.example.com</tag></HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><description>Info</description><plugin_output>Scanner IP : 10.0.0.5</plugin_output></ReportItem>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="156860" pluginName="Apache 2.4.x &lt; 2.4.52 Multiple Vulnerabilities" pluginFamily="Web Servers"><synopsis>The remote web server is affected.</synopsis><description>The version of Apache httpd installed is prior to 2.4.52.</description><solution>Upgrade to Apache version 2.4.52 or later.</solution><see_also>https://httpd.apache.org/security/vulnerabilities_24.html
https://example.org/advisory</see_also><cve>CVE-2021-44790</cve><cve>CVE-2021-44224</cve><cvss3_base_score>9.8</cvss3_base_score><cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector><plugin_output>Login with password=hunter2 succeeded</plugin_output></ReportItem>
</ReportHost>
<ReportHost name="10.9.9.9"><HostProperties><tag name="host-ip">10.9.9.9</tag></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="70658" pluginName="SSH Server CBC Mode Ciphers Enabled" pluginFamily="Misc."><description>CBC</description><solution>Disable CBC</solution></ReportItem>
</ReportHost></Report></NessusClientData_v2>"#;

const BURP: &str = r#"<?xml version="1.0"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<issues burpVersion="2026.1" exportTime="Sun Nov 01 10:00:00 UTC 2026">
<issue><serialNumber>1</serialNumber><type>1049088</type><name>SQL injection</name><host ip="93.184.215.7">https://app.example.com</host><path><![CDATA[/search]]></path><location><![CDATA[/search [q parameter]]]></location><severity>High</severity><confidence>Firm</confidence><issueBackground><![CDATA[<p>SQL injection vulnerabilities arise when&nbsp;user-controllable data is incorporated into queries.</p><ul><li>One</li><li>Two</li></ul>]]></issueBackground><remediationBackground><![CDATA[Use parameterized queries.]]></remediationBackground><issueDetail>The q parameter appears to be vulnerable &xxe; here.</issueDetail><vulnerabilityClassifications><![CDATA[<ul><li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: SQL Injection</a></li></ul>]]></vulnerabilityClassifications><references><![CDATA[<ul><li><a href="https://portswigger.net/web-security/sql-injection">SQL injection</a></li></ul>]]></references><requestresponse><request method="GET" base64="true"><![CDATA[R0VUIC9zZWFyY2g/cT0xJyBIVFRQLzEuMQ0KQ29va2llOiBzZXNzaW9uPWFiYw0KDQo=]]></request><response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9L]]></response></requestresponse></issue>
</issues>"#;

const NMAP: &str = r#"<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="93.184.215.7" addrtype="ipv4"/><hostnames><hostname name="app.example.com" type="user"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0"/></port><port protocol="tcp" portid="25"><state state="filtered"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>"#;

fn zap() -> String {
    let instances: Vec<Value> = (0..30).map(|i| json!({ "uri": format!("https://app.example.com/p{i}"), "method": "GET", "param": "", "evidence": "" })).collect();
    json!({
        "@programName": "ZAP", "@version": "2.16.0",
        "site": [{ "@name": "https://app.example.com", "@host": "app.example.com", "@port": "443", "@ssl": "true", "alerts": [
            { "pluginid": "10038", "alertRef": "10038-1", "alert": "Content Security Policy (CSP) Header Not Set", "riskcode": "2", "confidence": "3", "desc": "<p>CSP is missing.</p>", "solution": "<p>Set the header.</p>", "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>", "cweid": "693", "instances": instances, "count": "30" },
            { "pluginid": "10021", "alertRef": "10021", "alert": "X-Content-Type-Options Header Missing", "riskcode": "1", "confidence": "0", "desc": "", "instances": [] }
        ]}]
    })
    .to_string()
}

fn sarif() -> String {
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "Semgrep OSS", "rules": [
            { "id": "python.sqli", "shortDescription": { "text": "SQL built from user input" }, "fullDescription": { "text": "Use parameters." }, "helpUri": "https://semgrep.dev/r/python.sqli", "properties": { "security-severity": "9.8", "precision": "high", "tags": ["security", "external/cwe/cwe-89"] } },
            { "id": "style.todo", "shortDescription": { "text": "TODO left in code" } }
        ]}}, "results": [
            { "ruleId": "python.sqli", "ruleIndex": 0, "level": "error", "message": { "text": "User input reaches execute()" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app/db.py" }, "region": { "startLine": 42, "snippet": { "text": "cur.execute(\"SELECT * FROM t WHERE id=\" + id)" } } } }], "partialFingerprints": { "primaryLocationLineHash": "abc123" } },
            { "ruleId": "style.todo", "level": "note", "message": { "text": "TODO" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app/main.py" }, "region": { "startLine": 3 } } }] }
        ]}]
    })
    .to_string()
}

#[test]
fn formats_are_recognized_from_the_content() {
    assert_eq!(detect(NUCLEI), Ok(Format::Nuclei));
    assert_eq!(detect(&format!("[{}]", NUCLEI.lines().next().unwrap())), Ok(Format::Nuclei), "the JSON array export");
    assert_eq!(detect(NESSUS), Ok(Format::Nessus));
    assert_eq!(detect(BURP), Ok(Format::Burp));
    assert_eq!(detect(&zap()), Ok(Format::Zap));
    assert_eq!(detect(&sarif()), Ok(Format::Sarif));
    assert_eq!(detect(&format!("\u{feff}{NMAP}")), Ok(Format::Nmap), "a byte-order mark is ignored");
    assert!(detect("<graphml></graphml>").unwrap_err().contains("<graphml>"));
    assert!(detect(r#"{"a":1}"#).is_err());
    assert!(detect("hello").is_err());
    assert!(detect("<NessusClientData></NessusClientData>").unwrap_err().contains("v2"));
}

#[test]
fn nuclei_results_become_findings_with_redacted_details() {
    let p = parse(NUCLEI).unwrap();
    assert_eq!(p.format, Some(Format::Nuclei));
    assert!(p.warnings.iter().any(|w| w.contains("1 line skipped (not valid JSON)")), "{:?}", p.warnings);
    assert_eq!(p.merged, 1, "the repeated result is merged");
    assert_eq!(p.findings.len(), 3);
    let crit = &p.findings[0];
    assert_eq!((crit.severity, crit.cve.as_str(), crit.category.as_str()), ("critical", "CVE-2021-41773", "CWE-22"));
    assert_eq!(crit.description.lines().next(), Some("Path traversal & RCE"));
    assert!(crit.description.contains("CVSS score reported by the template: 7.5"));
    assert_eq!(crit.host.as_deref(), Some("app.example.com"));
    assert!(crit.technical.contains("root:x:0:0"));
    assert!(!crit.technical.contains("FAKE-test-value-not-a-credential"), "secrets in extracted values are redacted: {}", crit.technical);
    assert!(!crit.technical.contains("Bearer secret"), "the curl command is not copied");
    assert_eq!(crit.asset, Some(("http_service", "https://app.example.com".to_string())));
    assert_eq!(crit.cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "the template's vector is kept in canonical form");
    let tech = &p.findings[1];
    assert_eq!((tech.severity, tech.title.as_str()), ("info", "Wappalyzer Technology Detection (nginx)"));
    assert!(p.assets.iter().any(|a| a.kind == "technology" && a.value == "nginx"));
    assert!(p.assets.iter().any(|a| a.kind == "ip" && a.value == "93.184.215.7"));
    // the same result gives the same fingerprint; another location another one
    assert_eq!(parse(NUCLEI).unwrap().findings[0].fingerprint, crit.fingerprint);
    assert_ne!(p.findings[2].fingerprint, crit.fingerprint);
}

#[test]
fn nessus_items_keep_host_port_cves_and_redact_output() {
    let p = parse(NESSUS).unwrap();
    assert_eq!(p.findings.len(), 3);
    let apache = p.findings.iter().find(|f| f.rule_id == "156860").unwrap();
    assert_eq!(apache.title, "Apache 2.4.x < 2.4.52 Multiple Vulnerabilities");
    assert_eq!((apache.severity, apache.target.as_str()), ("high", "93.184.215.7:443/tcp"));
    assert_eq!(apache.cve, "CVE-2021-44790, CVE-2021-44224");
    assert_eq!(apache.references.len(), 2);
    assert!(apache.description.starts_with("The remote web server is affected."));
    assert!(apache.technical.contains("9.8"));
    assert!(!apache.technical.contains("hunter2"), "plugin output is redacted: {}", apache.technical);
    assert_eq!(apache.asset, Some(("service", "93.184.215.7:443/tcp".to_string())));
    assert_eq!(apache.cvss, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    assert_eq!(p.findings.iter().find(|f| f.rule_id == "19506").unwrap().severity, "info");
    assert!(p.assets.iter().any(|a| a.kind == "name" && a.value == "app.example.com"));
    assert!(p.assets.iter().any(|a| a.kind == "service" && a.value == "10.9.9.9:22/tcp"));
}

#[test]
fn burp_issues_are_read_without_expanding_entities() {
    let p = parse(BURP).unwrap();
    assert_eq!(p.findings.len(), 1);
    let f = &p.findings[0];
    assert_eq!((f.title.as_str(), f.severity, f.confidence), ("SQL injection", "high", "medium"));
    assert_eq!(f.target, "https://app.example.com/search");
    assert_eq!(f.category, "CWE-89");
    assert!(f.description.contains("&xxe;"), "an external entity is kept as written, never resolved: {}", f.description);
    assert!(!f.description.contains("root:"));
    assert!(f.description.contains("SQL injection vulnerabilities arise when user-controllable data"), "{}", f.description);
    assert!(f.description.contains("• One"));
    assert!(f.technical.contains("Request: GET /search?q=1' HTTP/1.1"), "{}", f.technical);
    assert!(!f.technical.contains("session=abc"), "headers of the request are not copied");
    assert_eq!(f.references, vec!["https://portswigger.net/web-security/sql-injection"]);
    assert!(p.assets.iter().any(|a| a.kind == "http_service" && a.value == "https://app.example.com"));
}

#[test]
fn zap_alerts_are_grouped_and_its_false_positives_skipped() {
    let p = parse(&zap()).unwrap();
    assert_eq!(p.findings.len(), 1);
    assert_eq!(p.marked_false_positive, 1);
    let f = &p.findings[0];
    assert_eq!((f.severity, f.confidence, f.category.as_str()), ("medium", "high", "CWE-693"));
    assert_eq!(f.description, "CSP is missing.");
    assert!(f.technical.contains("Instances: 30"));
    assert!(f.technical.contains("… and 5 more in the imported file"));
    assert_eq!(f.references, vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]);
}

#[test]
fn sarif_results_use_security_severity_and_have_no_network_target() {
    let p = parse(&sarif()).unwrap();
    assert_eq!(p.tool, "Semgrep OSS");
    assert_eq!(p.findings.len(), 2);
    let sqli = &p.findings[0];
    assert_eq!((sqli.severity, sqli.confidence, sqli.category.as_str()), ("critical", "high", "CWE-89"));
    assert_eq!(sqli.target, "app/db.py:42");
    assert_eq!(sqli.host, None);
    assert!(sqli.technical.contains("cur.execute"));
    assert_eq!(p.findings[1].severity, "low", "a note without a score is low");
}

#[test]
fn helpers_handle_edge_cases() {
    assert_eq!(host_of("https://[2001:db8::1]:8443/x"), Some("2001:db8::1".into()));
    assert_eq!(host_of("app.example.com:443"), Some("app.example.com".into()));
    assert_eq!(host_of("2001:db8::1"), Some("2001:db8::1".into()));
    assert_eq!(host_of("[2001:db8::1]:22"), Some("2001:db8::1".into()));
    assert_eq!(host_of(""), None);
    assert_eq!(html_to_text("a<br/>b &lt;c&gt; &#x41;&#66; &bogus; <"), "a\nb <c> AB &bogus; <");
    assert_eq!(trunc("ééééé", 3), "éé…");
    assert_eq!(decode_base64("R0VU"), Some("GET".into()));
    assert_eq!(decode_base64("!!"), None);
}

#[test]
fn truncated_xml_keeps_what_came_before() {
    let cut = &NESSUS[..NESSUS.find("<ReportHost name=\"10.9.9.9\"").unwrap() + 40];
    let p = parse(cut).unwrap();
    assert!(p.findings.iter().any(|f| f.rule_id == "156860"));
    assert!(!p.findings.iter().any(|f| f.rule_id == "70658"));
}

fn setup(c: &Connection) -> i64 {
    c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Acme','active','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z')", []).unwrap();
    let p = c.last_insert_rowid();
    crate::commands::projects::target_add(c, p, "example.com", "domain", true, "").unwrap();
    crate::commands::projects::target_add(c, p, "*.example.com", "wildcard", true, "").unwrap();
    crate::commands::projects::target_add(c, p, "93.184.215.0/24", "cidr", true, "").unwrap();
    p
}

fn count(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn imports_respect_scope_and_never_duplicate_findings() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let ev = evidence::add_text(c, p, "scan file stand-in", "x", "", "user")?;
        let parsed = parse(NESSUS).unwrap();
        let file = FileInfo { file_name: "weekly.nessus", sha256: "ab", evidence_id: Some(ev.id) };

        // preview: the private host is outside the scope, the informational item not selected
        let pv = preview(c, p, &parsed, Options::default())?;
        assert_eq!((pv.counts.new, pv.counts.out_of_scope, pv.counts.info), (1, 1, 1));
        assert_eq!(pv.out_of_scope_hosts, vec!["10.9.9.9"]);
        assert!(pv.has_scope);
        assert_eq!(count(c, "SELECT COUNT(*) FROM findings"), 0, "a preview changes nothing");

        let r = import(c, p, &parsed, Options::default(), &file)?;
        assert_eq!((r.created, r.out_of_scope, r.info_skipped), (1, 1, 1));
        assert!(r.assets_new >= 3, "address, name and service: {r:?}");
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE value LIKE '10.9.9.9%'"), 0, "out-of-scope assets are not recorded");
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE type = 'subdomain' AND value = 'app.example.com'"), 1);
        let fid: i64 = c.query_row("SELECT id FROM findings", [], |r| r.get(0))?;
        let f = crate::commands::projects::finding_get(c, fid)?;
        assert_eq!((f.source.as_str(), f.status.as_str(), f.severity.as_str()), ("import", "new", "high"));
        assert_eq!((f.cvss_vector.as_str(), f.cvss_score), ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Some(9.8)), "the scanner's vector is scored");
        assert!(f.tags.contains(&"nessus".to_string()));
        let links = lifecycle::links(c, fid)?;
        assert!(links.iter().any(|l| l.kind == "evidence" && l.ref_id == ev.id), "linked to the imported file");
        assert!(links.iter().any(|l| l.kind == "asset"), "linked to its service");

        // the same file again: nothing is duplicated, the sighting is recorded
        let r2 = import(c, p, &parsed, Options::default(), &file)?;
        assert_eq!((r2.created, r2.seen_again), (0, 1));
        assert_eq!(count(c, "SELECT COUNT(*) FROM findings"), 1);
        assert_eq!(count(c, "SELECT times_seen FROM finding_fingerprints"), 2);

        // a resolved finding reported again is reopened when asked
        lifecycle::set_status(c, fid, "resolved", "patched", "user")?;
        let pv = preview(c, p, &parsed, Options::default())?;
        assert_eq!(pv.counts.recurring, 1);
        let r3 = import(c, p, &parsed, Options { reopen_resolved: true, ..Default::default() }, &file)?;
        assert_eq!(r3.reopened, 1);
        assert_eq!(crate::commands::projects::finding_get(c, fid)?.status, "reopened");

        // a dismissed finding stays dismissed
        lifecycle::set_status(c, fid, "false_positive", "not exploitable", "user")?;
        let r4 = import(c, p, &parsed, Options { reopen_resolved: true, include_info: true, ..Default::default() }, &file)?;
        assert_eq!((r4.dismissed, r4.created), (1, 1), "only the informational item is new");
        assert_eq!(crate::commands::projects::finding_get(c, fid)?.status, "false_positive");

        let h = history(c, p)?;
        assert_eq!(h.len(), 4);
        assert_eq!(h[0].summary["created"], 1);
        assert!(timeline::project_timeline(c, p, &[], None, 50)?.iter().any(|e| e.title.contains("Imported Nessus results")));
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_project_without_scope_records_nothing_but_code_findings() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Empty','planning','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z')", [])?;
        let p = c.last_insert_rowid();
        let pv = preview(c, p, &parse(NUCLEI).unwrap(), Options::default())?;
        assert!(!pv.has_scope);
        assert_eq!(pv.counts.new, 0);
        assert!(pv.warnings.iter().any(|w| w.contains("no scope entries")));
        let file = FileInfo { file_name: "semgrep.sarif", sha256: "cd", evidence_id: None };
        let r = import(c, p, &parse(&sarif()).unwrap(), Options::default(), &file)?;
        assert_eq!(r.created, 2, "source-code findings have no network target to check");
        c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", params![p])?;
        assert!(import(c, p, &parse(&sarif()).unwrap(), Options::default(), &file).is_err(), "archived projects are read-only");
        Ok(())
    })
    .unwrap();
}

#[test]
fn nmap_files_add_assets_only() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let parsed = parse(NMAP).unwrap();
        assert!(parsed.findings.is_empty());
        let r = import(c, p, &parsed, Options::default(), &FileInfo { file_name: "scan.xml", sha256: "ef", evidence_id: None })?;
        assert_eq!(r.created, 0);
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE type = 'service'"), 1, "the filtered port is not a service");
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE type = 'technology' AND value = 'nginx'"), 1);
        assert_eq!(count(c, "SELECT COUNT(*) FROM discovery_snapshots WHERE source = 'import:nmap' AND status = 'completed'"), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn library_templates_replace_scanner_text_for_matching_rules() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let tid = crate::workspace::templates::save(
            c,
            &crate::workspace::templates::TemplateInput {
                title: "Outdated Apache httpd".into(),
                severity: "critical".into(),
                category: "Vulnerable components".into(),
                description: "Our vetted description.".into(),
                remediation: "Upgrade httpd.".into(),
                references: vec!["https://httpd.apache.org/security/vulnerabilities_24.html".into(), "https://internal/kb/42".into()],
                tags: vec!["patching".into()],
                rules: vec!["NESSUS:156860".into()],
                ..Default::default()
            },
        )?;
        let parsed = parse(NESSUS).unwrap();
        let pv = preview(c, p, &parsed, Options::default())?;
        assert_eq!(pv.templated, 1);
        assert!(pv.items.iter().any(|i| i.template.as_deref() == Some("Outdated Apache httpd") && i.severity == "critical"));
        let off = preview(c, p, &parsed, Options { use_templates: false, ..Default::default() })?;
        assert_eq!(off.templated, 0);

        let r = import(c, p, &parsed, Options::default(), &FileInfo { file_name: "weekly.nessus", sha256: "ab", evidence_id: None })?;
        assert_eq!((r.created, r.templated), (1, 1));
        let fid: i64 = c.query_row("SELECT id FROM findings", [], |r| r.get(0))?;
        let f = crate::commands::projects::finding_get(c, fid)?;
        assert_eq!((f.title.as_str(), f.severity.as_str(), f.description.as_str(), f.remediation.as_str()), ("Outdated Apache httpd", "critical", "Our vetted description.", "Upgrade httpd."));
        assert_eq!(f.cve, "CVE-2021-44790, CVE-2021-44224", "the instance's CVEs stay");
        assert!(f.technical_details.contains("Plugin output"), "the scanner's evidence stays");
        let refs: Vec<&str> = f.evidence.iter().map(|e| e.reference.as_str()).collect();
        assert_eq!(refs, vec!["https://httpd.apache.org/security/vulnerabilities_24.html", "https://internal/kb/42", "https://example.org/advisory"], "merged without duplicates");
        assert!(f.tags.contains(&"patching".to_string()) && f.tags.contains(&"nessus".to_string()));
        assert!(lifecycle::history(c, fid)?.iter().any(|e| e.note.contains("Outdated Apache httpd")));
        assert_eq!(crate::workspace::templates::get(c, tid)?.use_count, 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn unmatched_nuclei_results_and_passing_sarif_results_are_skipped() {
    let nuclei = r#"{"template-id":"a","info":{"name":"A","severity":"high"},"host":"https://app.example.com","matched-at":"https://app.example.com/a","matcher-status":true}
{"template-id":"b","info":{"name":"B","severity":"high"},"host":"https://app.example.com","matched-at":"https://app.example.com/b","matcher-status":false}"#;
    let p = parse(nuclei).unwrap();
    assert_eq!(p.findings.len(), 1);
    assert!(p.warnings.iter().any(|w| w.contains("did not match")));

    let sarif = json!({ "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "T" } }, "results": [
        { "ruleId": "r1", "kind": "pass", "message": { "text": "ok" } },
        { "ruleId": "r2", "kind": "review", "level": "error", "message": { "text": "look" } },
        { "ruleId": "r3", "message": { "text": "bad" } }
    ]}]}).to_string();
    let p = parse(&sarif).unwrap();
    assert_eq!(p.findings.len(), 2);
    assert_eq!(p.findings[0].severity, "info", "a review result carries no severity");
    assert_eq!(p.findings[1].severity, "medium", "no level means warning");
    assert!(p.warnings.iter().any(|w| w.contains("pass or notApplicable")));
}

/// A Nessus file with one item per (host, plugin, port, severity).
fn nessus_doc(items: &[(&str, &str, u16, u8)]) -> String {
    let mut hosts: Vec<&str> = items.iter().map(|i| i.0).collect();
    hosts.dedup();
    let mut out = String::from("<NessusClientData_v2><Report name=\"r\">");
    for h in hosts {
        out.push_str(&format!("<ReportHost name=\"{h}\"><HostProperties><tag name=\"host-ip\">{h}</tag></HostProperties>"));
        for (_, plugin, port, sev) in items.iter().filter(|i| i.0 == h) {
            out.push_str(&format!("<ReportItem port=\"{port}\" protocol=\"tcp\" severity=\"{sev}\" pluginID=\"{plugin}\" pluginName=\"Plugin {plugin}\" pluginFamily=\"F\"><description>d</description></ReportItem>"));
        }
        out.push_str("</ReportHost>");
    }
    out.push_str("</Report></NessusClientData_v2>");
    out
}

#[test]
fn a_rescan_shows_fixed_findings_on_covered_hosts_only() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let file = |name: &'static str| FileInfo { file_name: name, sha256: "ab", evidence_id: None };
        // first scan: two hosts, three findings
        let first = parse(&nessus_doc(&[("93.184.215.7", "1001", 443, 3), ("93.184.215.7", "1002", 22, 2), ("93.184.215.8", "1003", 80, 2)])).unwrap();
        assert_eq!(import(c, p, &first, Options::default(), &file("week1.nessus"))?.created, 3);
        let id_of = |c: &Connection, plugin: &str| -> i64 { c.query_row("SELECT finding_id FROM finding_fingerprints WHERE rule_id = ?1", params![plugin], |r| r.get(0)).unwrap() };
        let (f1001, f1002, f1003) = (id_of(c, "1001"), id_of(c, "1002"), id_of(c, "1003"));

        // rescan of .7 only: 1002 is gone, 1001 is still there; .8 was not scanned
        let second = parse(&nessus_doc(&[("93.184.215.7", "1001", 443, 3), ("93.184.215.7", "19506", 0, 0)])).unwrap();
        let pv = preview(c, p, &second, Options::default())?;
        assert_eq!(pv.not_reported_count, 1);
        assert_eq!(pv.not_reported[0].finding_id, Some(f1002));
        assert!(!pv.not_reported.iter().any(|m| m.finding_id == Some(f1003)), "a host the file did not cover proves nothing");

        // without the option the finding stays open with a note
        let r = import(c, p, &second, Options::default(), &file("week2.nessus"))?;
        assert_eq!((r.not_reported, r.resolved), (1, 0));
        assert_eq!(crate::commands::projects::finding_get(c, f1002)?.status, "new");
        assert!(lifecycle::history(c, f1002)?.iter().any(|e| e.note.contains("Not reported again for 93.184.215.7")));

        // with it, the finding is resolved as verified by the rescan
        let r = import(c, p, &second, Options { resolve_missing: true, ..Default::default() }, &file("week2b.nessus"))?;
        assert_eq!((r.not_reported, r.resolved), (1, 1));
        let f = crate::commands::projects::finding_get(c, f1002)?;
        assert_eq!(f.status, "resolved");
        assert!(lifecycle::history(c, f1002)?.iter().any(|e| e.note.starts_with("Verified by rescan")));
        assert_eq!(crate::commands::projects::finding_get(c, f1001)?.status, "new", "a finding still reported stays open");
        assert_eq!(crate::commands::projects::finding_get(c, f1003)?.status, "new");

        // a resolved finding is not listed again, and other tools' files never resolve Nessus findings
        assert_eq!(preview(c, p, &second, Options::default())?.not_reported_count, 0);
        let zap_like = parse(&zap()).unwrap();
        assert!(not_reported(c, p, &zap_like)?.is_empty());
        Ok(())
    })
    .unwrap();
}

const OPENVAS: &str = r#"<report id="r1" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml"><report id="r1"><gmp><version>22.4</version></gmp>
<results start="1" max="100">
<result id="a"><name>OpenSSH Multiple Vulnerabilities</name><host>93.184.215.7<asset asset_id="x"/><hostname>app.example.com</hostname></host><port>22/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.170001"><type>nvt</type><name>OpenSSH Multiple Vulnerabilities</name><family>General</family><cvss_base>8.1</cvss_base>
<severities score="8.1"><severity type="cvss_base_v3"><score>8.1</score><value>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</value></severity></severities>
<tags>cvss_base_vector=AV:N/AC:H/Au:N/C:C/I:C/A:C|summary=OpenSSH is prone to multiple vulnerabilities.|insight=A race condition in a signal handler.|affected=OpenSSH 8.5 through 9.7.|impact=Remote code execution as root.|solution=Update to version 9.8 or later.|vuldetect=Checks if a vulnerable version is present on the target host.|solution_type=VendorFix</tags>
<solution type="VendorFix">Update to version 9.8 or later.</solution>
<refs><ref type="cve" id="CVE-2024-6387"/><ref type="url" id="https://www.openssh.com/txt/release-9.8"/><ref type="cert-bund" id="WID-SEC-2024-1"/></refs></nvt>
<threat>High</threat><severity>8.1</severity><qod><value>80</value><type>remote_banner</type></qod><description>Installed version: 9.6p1
Fixed version: 9.8 password=hunter2</description></result>
<result id="b"><name>OS Detection Consolidation</name><host>93.184.215.7</host><port>general/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.105937"><name>OS Detection Consolidation</name><family>Product detection</family><tags>summary=OS detection.</tags></nvt><threat>Log</threat><severity>0.0</severity><qod><value>80</value></qod><description>Best matching OS: Debian</description></result>
<result id="c"><name>Weak guess</name><host>93.184.215.7</host><port>80/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Weak guess</name></nvt><threat>Medium</threat><severity>5.0</severity><qod><value>30</value></qod></result>
<result id="d"><name>Dismissed</name><host>93.184.215.7</host><port>443/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.2"><name>Dismissed</name></nvt><threat>False Positive</threat><severity>-1.0</severity><qod><value>99</value></qod></result>
</results>
<host><ip>93.184.215.7</ip><detail><name>hostname</name><value>app.example.com</value></detail></host>
</report></report>"#;

#[test]
fn greenbone_reports_follow_its_default_filter() {
    assert_eq!(detect(OPENVAS), Ok(Format::OpenVas));
    assert!(detect("<report><title>x</title></report>").is_err(), "other XML with a report root is not mistaken for Greenbone");
    let p = parse(OPENVAS).unwrap();
    assert_eq!(p.tool, "Greenbone");
    assert_eq!(p.findings.len(), 2, "the low-QoD and false-positive results are left out");
    assert_eq!(p.marked_false_positive, 1);
    assert!(p.warnings.iter().any(|w| w.contains("quality of detection below 70%")));
    let ssh = &p.findings[0];
    assert_eq!((ssh.severity, ssh.confidence, ssh.rule_id.as_str()), ("high", "medium", "1.3.6.1.4.1.25623.1.0.170001"));
    assert_eq!(ssh.target, "93.184.215.7:22/tcp");
    assert_eq!(ssh.cve, "CVE-2024-6387");
    assert_eq!(ssh.cvss, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
    assert!(ssh.description.starts_with("OpenSSH is prone to multiple vulnerabilities."));
    assert_eq!(ssh.remediation, "Update to version 9.8 or later.");
    assert!(ssh.technical.contains("Installed version: 9.6p1") && ssh.technical.contains("Quality of detection: 80%"));
    assert!(!ssh.technical.contains("hunter2"), "result text is redacted");
    assert_eq!(ssh.references, vec!["https://www.openssh.com/txt/release-9.8"]);
    assert_eq!(p.findings[1].severity, "info", "Log results are informational");
    assert_eq!(p.findings[1].target, "93.184.215.7 (general/tcp)");
    assert!(p.assets.iter().any(|a| a.kind == "service" && a.value == "93.184.215.7:22/tcp"));
    assert!(p.assets.iter().any(|a| a.kind == "name" && a.value == "app.example.com"));
}

#[test]
fn parsers_never_panic_on_cut_or_multibyte_input() {
    // with panic = "abort" a parser panic would end the app
    let zap_multibyte = zap().replace("CSP is missing.", "R&amp;D 日本語 &x日本語; caf&eacute; &#x1F600;");
    assert!(parse(&zap_multibyte).unwrap().findings[0].description.contains("R&D 日本語"));
    assert_eq!(html_to_text("a&日本語日本語日本語;b"), "a&日本語日本語日本語;b");
    for doc in [NUCLEI.to_string(), NESSUS.to_string(), BURP.to_string(), NMAP.to_string(), OPENVAS.to_string(), zap_multibyte, sarif()] {
        let doc = doc.replace("Path traversal", "Pfad-Überquerung &日本").replace("OpenSSH is prone", "OpenSSH é &日本 prone");
        for (i, _) in doc.char_indices().step_by(7) {
            let _ = parse(&doc[..i]);
        }
    }
}

#[test]
fn network_findings_without_a_usable_or_in_scope_host_are_left_out() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let nuclei = r#"{"template-id":"a","info":{"name":"Bad port","severity":"high"},"matched-at":"http://out.example:99999/a"}
{"template-id":"b","info":{"name":"Mismatch","severity":"high"},"host":"https://app.example.com","matched-at":"https://evil.example.org/x"}
{"template-id":"c","info":{"name":"Fine","severity":"high"},"host":"https://app.example.com","matched-at":"https://app.example.com/x"}"#;
        let pv = preview(c, p, &parse(nuclei).unwrap(), Options::default())?;
        assert_eq!((pv.counts.new, pv.counts.out_of_scope), (1, 2), "an unparseable target and a target outside the scope are left out");
        let sarif_urls = json!({ "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "DAST" } }, "results": [
            { "ruleId": "x", "message": { "text": "m" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "https://other.org/login" } } }] },
            { "ruleId": "y", "message": { "text": "m" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "https://app.example.com/login" } } }] },
            { "ruleId": "z", "message": { "text": "m" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/app.py" }, "region": { "startLine": 1 } } }] }
        ]}]}).to_string();
        let pv = preview(c, p, &parse(&sarif_urls).unwrap(), Options::default())?;
        assert_eq!((pv.counts.new, pv.counts.out_of_scope), (2, 1), "URL locations in SARIF are scope-checked, file paths are not");
        assert_eq!(host_of("[2001:db8::1]evil.example"), None);
        assert_eq!(host_of("[2001:db8::1]:443"), Some("2001:db8::1".into()));
        Ok(())
    })
    .unwrap();
}

#[test]
fn burp_address_assets_are_checked_as_addresses() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Names only','active','t','t')", [])?;
        let p = c.last_insert_rowid();
        crate::commands::projects::target_add(c, p, "*.example.com", "wildcard", true, "")?;
        import(c, p, &parse(BURP).unwrap(), Options::default(), &FileInfo { file_name: "b.xml", sha256: "x", evidence_id: None })?;
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE type = 'ip'"), 0, "the address is not in the scope even though the name is");
        assert_eq!(count(c, "SELECT COUNT(*) FROM assets WHERE type = 'http_service'"), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_incomplete_file_never_verifies_fixes() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let full = parse(&nessus_doc(&[("93.184.215.7", "1001", 443, 3), ("93.184.215.7", "1002", 22, 2)])).unwrap();
        import(c, p, &full, Options::default(), &FileInfo { file_name: "w1", sha256: "a", evidence_id: None })?;
        // the second file breaks off after the first item of the host
        let doc = nessus_doc(&[("93.184.215.7", "1001", 443, 3), ("93.184.215.7", "1002", 22, 2)]);
        let cut = &doc[..doc.find("pluginID=\"1002\"").unwrap()];
        let partial = parse(cut).unwrap();
        assert!(partial.incomplete);
        let pv = preview(c, p, &partial, Options::default())?;
        assert_eq!(pv.not_reported_count, 0, "nothing is listed as fixed from a partial file");
        assert!(pv.warnings.iter().any(|w| w.contains("not read completely")));
        let r = import(c, p, &partial, Options { resolve_missing: true, ..Default::default() }, &FileInfo { file_name: "w2", sha256: "b", evidence_id: None })?;
        assert_eq!(r.resolved, 0);
        assert_eq!(count(c, "SELECT COUNT(*) FROM findings WHERE status = 'resolved'"), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn copied_text_is_redacted_in_every_field() {
    let nuclei = r#"{"template-id":"t","info":{"name":"Token in URL","severity":"high"},"host":"https://app.example.com","matched-at":"https://app.example.com/cb?access_token=abc123secret","extracted-results":["AKIAIOSFODNN7EXAMPLE"]}"#;
    let f = &parse(nuclei).unwrap().findings[0];
    assert!(!f.target.contains("abc123secret") && f.target.contains("access_token="), "{}", f.target);
    assert!(!f.technical.contains("AKIAIOSFODNN7EXAMPLE") && !f.technical.contains("abc123secret"), "{}", f.technical);
    let burp = BURP.replace("appears to be vulnerable &xxe; here.", "leaks session=abcdef0123 here.");
    assert!(!parse(&burp).unwrap().findings[0].description.contains("abcdef0123"));
    let nessus = NESSUS.replace("Login with password=hunter2 succeeded", "Password : admin");
    let apache = parse(&nessus).unwrap().findings.into_iter().find(|f| f.rule_id == "156860").unwrap();
    assert!(!apache.technical.contains("admin"), "{}", apache.technical);
    let sarif_msg = json!({ "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "T" } }, "results": [
        { "ruleId": "", "message": { "text": "Hard-coded api_key=zzzSECRETzzz" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.py" } } }] }
    ]}]}).to_string();
    let s = &parse(&sarif_msg).unwrap().findings[0];
    assert!(!s.title.contains("zzzSECRETzzz") && !s.description.contains("zzzSECRETzzz"));
}

#[test]
fn one_odd_record_does_not_abort_an_import() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = setup(c);
        let nul = "{\"template-id\":\"n\",\"info\":{\"name\":\"Null\\u0000byte\",\"severity\":\"low\",\"tags\":[\"a-tag-that-is-much-longer-than-forty-characters-for-sure\"]},\"host\":\"https://app.example.com\",\"matched-at\":\"https://app.example.com/\\u0000x\"}";
        let r = import(c, p, &parse(nul).unwrap(), Options::default(), &FileInfo { file_name: "n.jsonl", sha256: "a", evidence_id: None })?;
        assert_eq!(r.created, 1);
        let long_tool = json!({ "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "An Exceptionally Long Static Analysis Tool Name Beyond Forty" } }, "results": [
            { "ruleId": "", "message": { "text": "" }, "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.py" } } }] }
        ]}]}).to_string();
        let r = import(c, p, &parse(&long_tool).unwrap(), Options::default(), &FileInfo { file_name: "s.sarif", sha256: "b", evidence_id: None })?;
        assert_eq!(r.created, 1, "an empty title and a long tool name do not fail the import");
        Ok(())
    })
    .unwrap();
}
