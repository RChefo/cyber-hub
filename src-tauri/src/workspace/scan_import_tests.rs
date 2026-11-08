//! Tests of the scan importers (fixtures follow each tool's documented output).

use super::*;
use crate::db::Db;
use crate::workspace::evidence;

const NUCLEI: &str = r#"{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 - Path Traversal","severity":"critical","description":"<p>Path traversal &amp; RCE</p>","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],"tags":["cve","apache"],"classification":{"cve-id":["cve-2021-41773"],"cwe-id":["cwe-22"],"cvss-score":7.5,"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},"remediation":"Upgrade to 2.4.51"},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/cgi-bin/.%2e/etc/passwd","ip":"93.184.215.7","extracted-results":["root:x:0:0","api_key=sk_live_1234567890abcdef"],"timestamp":"2026-11-01T10:00:00Z","curl-command":"curl -H 'Authorization: Bearer secret' https://app.example.com"}
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
https://example.org/advisory</see_also><cve>CVE-2021-44790</cve><cve>CVE-2021-44224</cve><cvss3_base_score>9.8</cvss3_base_score><plugin_output>Login with password=hunter2 succeeded</plugin_output></ReportItem>
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
    assert!(p.warnings.iter().any(|w| w.contains("1 lines were not valid JSON")), "{:?}", p.warnings);
    assert_eq!(p.merged, 1, "the repeated result is merged");
    assert_eq!(p.findings.len(), 3);
    let crit = &p.findings[0];
    assert_eq!((crit.severity, crit.cve.as_str(), crit.category.as_str()), ("critical", "CVE-2021-41773", "CWE-22"));
    assert_eq!(crit.description.lines().next(), Some("Path traversal & RCE"));
    assert!(crit.description.contains("CVSS score reported by the template: 7.5"));
    assert_eq!(crit.host.as_deref(), Some("app.example.com"));
    assert!(crit.technical.contains("root:x:0:0"));
    assert!(!crit.technical.contains("sk_live_1234567890abcdef"), "secrets in extracted values are redacted: {}", crit.technical);
    assert!(!crit.technical.contains("Bearer secret"), "the curl command is not copied");
    assert_eq!(crit.asset, Some(("http_service", "https://app.example.com".to_string())));
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
        let r4 = import(c, p, &parsed, Options { reopen_resolved: true, include_info: true }, &file)?;
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
