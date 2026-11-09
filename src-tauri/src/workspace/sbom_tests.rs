use super::*;
use crate::db::Db;

const CDX_JSON: &str = r#"{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {
    "timestamp": "2026-11-01T10:00:00Z",
    "tools": {"components": [{"type": "application", "name": "syft", "version": "1.0"}]},
    "component": {"type": "application", "bom-ref": "app", "name": "shop", "version": "1.0.0"}
  },
  "components": [
    {"type": "library", "bom-ref": "lodash", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
     "licenses": [{"license": {"id": "MIT"}}], "supplier": {"name": "OpenJS"}, "hashes": [{"alg": "SHA-256", "content": "abc"}]},
    {"type": "library", "bom-ref": "spring", "group": "org.springframework", "name": "spring-core", "purl": "pkg:maven/org.springframework/spring-core@5.3.0",
     "licenses": [{"expression": "Apache-2.0 OR GPL-2.0-only"}]},
    {"type": "library", "bom-ref": "gpl", "name": "readline", "version": "8.0", "purl": "pkg:deb/debian/readline@8.0", "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]},
    {"type": "library", "bom-ref": "agpl", "name": "ghostscript", "version": "9.5", "purl": "pkg:deb/debian/ghostscript@9.5", "licenses": [{"license": {"name": "AGPL-3.0-only"}}]},
    {"type": "library", "bom-ref": "mystery", "name": "internal-lib"},
    {"type": "framework", "bom-ref": "parent", "name": "parent", "version": "2.0", "purl": "pkg:npm/parent@2.0",
     "components": [{"type": "library", "bom-ref": "child", "name": "child", "version": "1.0.0", "purl": "pkg:npm/child@1.0.0", "licenses": [{"license": {"id": "ISC"}}]}]},
    {"type": "library", "bom-ref": "lodash-old", "name": "lodash", "version": "3.10.1", "purl": "pkg:npm/lodash@3.10.1", "licenses": [{"license": {"id": "MIT"}}]}
  ],
  "dependencies": [{"ref": "app", "dependsOn": ["lodash", "parent"]}, {"ref": "parent", "dependsOn": ["child"]}],
  "vulnerabilities": [
    {"id": "CVE-2021-23337", "ratings": [{"score": 7.2, "severity": "high", "method": "CVSSv31", "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
     "description": "Command injection in lodash template.", "affects": [{"ref": "lodash"}], "analysis": {"state": "exploitable"}}
  ]
}"#;

const CDX_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:1" version="1">
  <metadata>
    <timestamp>2026-11-02T08:00:00Z</timestamp>
    <tools><tool><vendor>CycloneDX</vendor><name>cyclonedx-maven-plugin</name><version>2.7.9</version></tool></tools>
    <component type="application" bom-ref="pkg:maven/com.acme/web@1.2"><group>com.acme</group><name>web</name><version>1.2</version></component>
  </metadata>
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <group>org.apache.logging.log4j</group><name>log4j-core</name><version>2.14.1</version>
      <hashes><hash alg="SHA-256">7a1f</hash></hashes>
      <licenses><license><id>Apache-2.0</id></license></licenses>
      <purl>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</purl>
    </component>
    <component type="library" bom-ref="x">
      <name>Tom &amp; Jerry &xxe;</name><version>1.0</version>
      <licenses><expression>MPL-2.0 AND MIT</expression></licenses>
      <purl>pkg:maven/acme/tj@1.0</purl>
    </component>
  </components>
  <dependencies>
    <dependency ref="pkg:maven/com.acme/web@1.2"><dependency ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"/></dependency>
  </dependencies>
  <vulnerabilities>
    <vulnerability bom-ref="v1">
      <id>CVE-2021-44228</id>
      <ratings><rating><score>10.0</score><severity>critical</severity><method>CVSSv31</method></rating></ratings>
      <affects><target><ref>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</ref></target></affects>
      <analysis><state>not_affected</state></analysis>
    </vulnerability>
  </vulnerabilities>
</bom>"#;

const SPDX_JSON: &str = r#"{
  "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "com.github.acme/shop",
  "creationInfo": {"created": "2026-11-03T00:00:00Z", "creators": ["Tool: GitHub.com-Dependency-Graph"]},
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "com.github.acme/shop", "versionInfo": "main"},
    {"SPDXID": "SPDXRef-npm-lodash", "name": "npm:lodash", "versionInfo": "4.17.20", "licenseConcluded": "MIT", "supplier": "Organization: OpenJS",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
    {"SPDXID": "SPDXRef-pip-jinja2", "name": "pip:jinja2", "versionInfo": "2.4.1", "licenseConcluded": "NOASSERTION", "licenseDeclared": "BSD-3-Clause",
     "externalRefs": [{"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/jinja2@2.4.1"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"},
    {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-npm-lodash"}
  ]
}"#;

const SPDX_TAG: &str = "SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\nDocumentName: image\nCreator: Tool: trivy\nCreated: 2026-11-04T00:00:00Z\n\nPackageName: openssl\nSPDXID: SPDXRef-openssl\nPackageVersion: 1.1.1k\nPackageSupplier: Organization: Debian\nPackageLicenseConcluded: OpenSSL\nPackageChecksum: SHA1: 85ed0817af83a24ad8da68c2b5094de69833983c\nExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/openssl@1.1.1k\nPackageComment: <text>multi\nline: comment</text>\n\nPackageName: zlib\nSPDXID: SPDXRef-zlib\nPackageVersion: 1.2.11\nPackageLicenseDeclared: Zlib\n\nRelationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-openssl\n";

fn by_name<'a>(s: &'a Sbom, name: &str) -> &'a Component {
    s.components.iter().find(|c| c.name == name).unwrap()
}

#[test]
fn cyclonedx_json_is_read_with_nested_components_and_relationships() {
    let s = parse(CDX_JSON).unwrap();
    assert_eq!((s.format.as_str(), s.spec_version.as_str(), s.subject.as_str()), ("cyclonedx-json", "1.5", "shop 1.0.0"));
    assert_eq!((s.created.as_str(), s.tools.clone()), ("2026-11-01T10:00:00Z", vec!["syft 1.0".to_string()]));
    assert_eq!(s.components.len(), 8, "the nested child is a component too");
    let lodash = s.components.iter().find(|c| c.label() == "lodash@4.17.20").unwrap();
    assert!(lodash.direct && s.relationships);
    assert_eq!((lodash.ecosystem.as_str(), lodash.supplier.as_str(), lodash.license_risk.as_str()), ("npm", "OpenJS", "permissive"));
    assert_eq!(lodash.hashes, vec!["SHA-256:abc"]);
    assert!(!by_name(&s, "child").direct, "only the described component's own dependencies are direct");
    let spring = by_name(&s, "spring-core");
    assert_eq!((spring.group.as_str(), spring.version.as_str(), spring.label().as_str()), ("org.springframework", "5.3.0", "org.springframework/spring-core@5.3.0"), "version from the package URL");
    assert_eq!(spring.license_risk, "permissive", "OR: the most permissive choice");
    assert_eq!(by_name(&s, "readline").license_risk, "copyleft");
    assert_eq!(by_name(&s, "ghostscript").license_risk, "network-copyleft", "license names are classified too");
    assert_eq!(by_name(&s, "internal-lib").license_risk, "unknown");
    assert_eq!(s.vulns.len(), 1);
    let v = &s.vulns[0];
    assert_eq!((v.id.as_str(), v.severity.as_str(), v.score, v.analysis.as_str(), v.source.as_str()), ("CVE-2021-23337", "high", Some(7.2), "exploitable", "sbom"));
    assert_eq!(s.components[v.components[0]].label(), "lodash@4.17.20");
}

#[test]
fn cyclonedx_xml_is_read_without_external_entities() {
    let s = parse(CDX_XML).unwrap();
    assert_eq!((s.format.as_str(), s.spec_version.as_str(), s.subject.as_str()), ("cyclonedx-xml", "1.4", "web 1.2"));
    assert_eq!(s.tools, vec!["CycloneDX cyclonedx-maven-plugin 2.7.9"]);
    let log4j = by_name(&s, "log4j-core");
    assert_eq!((log4j.group.as_str(), log4j.version.as_str(), log4j.license_risk.as_str(), log4j.direct), ("org.apache.logging.log4j", "2.14.1", "permissive", true));
    assert_eq!(log4j.hashes, vec!["SHA-256:7a1f"]);
    let tj = s.components.iter().find(|c| c.purl == "pkg:maven/acme/tj@1.0").unwrap();
    assert_eq!(tj.name, "Tom & Jerry &xxe;", "predefined entities are read, declared ones are not expanded");
    assert_eq!(tj.licenses, vec!["MPL-2.0 AND MIT"]);
    assert_eq!(tj.license_risk, "weak-copyleft", "AND: the most restrictive");
    let v = &s.vulns[0];
    assert_eq!((v.id.as_str(), v.severity.as_str(), v.analysis.as_str()), ("CVE-2021-44228", "critical", "not_affected"));
    assert_eq!(s.components[v.components[0]].name, "log4j-core");
    assert!(parse("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.4\"><components><component>").is_err() || parse("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.4\"><components><component>").unwrap().components.is_empty());
}

#[test]
fn spdx_json_and_tag_value_are_read() {
    let s = parse(SPDX_JSON).unwrap();
    assert_eq!((s.format.as_str(), s.spec_version.as_str(), s.subject.as_str()), ("spdx-json", "2.3", "com.github.acme/shop main"));
    assert_eq!(s.components.len(), 2, "the described package is the subject, not a component");
    let lodash = s.components.iter().find(|c| c.purl.contains("lodash")).unwrap();
    assert_eq!((lodash.ecosystem.as_str(), lodash.supplier.as_str(), lodash.direct), ("npm", "OpenJS", true));
    let jinja = s.components.iter().find(|c| c.purl.contains("jinja2")).unwrap();
    assert_eq!((jinja.licenses.clone(), jinja.license_risk.as_str(), jinja.direct), (vec!["BSD-3-Clause".to_string()], "permissive", false), "the declared license when none is concluded");
    let t = parse(SPDX_TAG).unwrap();
    assert_eq!((t.format.as_str(), t.spec_version.as_str(), t.subject.as_str(), t.created.as_str()), ("spdx-tag", "2.2", "openssl 1.1.1k", "2026-11-04T00:00:00Z"));
    assert_eq!(t.components.len(), 1);
    assert_eq!((t.components[0].name.as_str(), t.components[0].license_risk.as_str(), t.components[0].purl.as_str()), ("zlib", "permissive", ""));
    assert!(!t.relationships);
}

#[test]
fn other_files_are_refused() {
    assert!(parse(r#"{"hello": 1}"#).unwrap_err().contains("not a CycloneDX or SPDX"));
    assert!(parse(r#"{"spdxVersion": "SPDX-3.0"}"#).unwrap_err().contains("not supported"));
    assert!(parse("<rdf:RDF></rdf:RDF>").unwrap_err().contains("CycloneDX XML"));
    assert!(parse("just text").is_err());
}

#[test]
fn license_expressions_are_classified() {
    let r = |l: &[&str]| license_risk(&l.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(r(&["MIT"]), "permissive");
    assert_eq!(r(&["(MIT OR GPL-3.0-only)"]), "permissive");
    assert_eq!(r(&["MIT AND GPL-3.0-only"]), "copyleft");
    assert_eq!(r(&["GPL-2.0-only WITH Classpath-exception-2.0"]), "copyleft");
    assert_eq!(r(&["LGPL-2.1-or-later"]), "weak-copyleft");
    assert_eq!(r(&["AGPL-3.0"]), "network-copyleft");
    assert_eq!(r(&["CC-BY-NC-4.0"]), "restricted");
    assert_eq!(r(&["BUSL-1.1"]), "restricted");
    assert_eq!(r(&["NOASSERTION"]), "unknown");
    assert_eq!(r(&["LicenseRef-proprietary"]), "unknown");
    assert_eq!(r(&[]), "unknown");
    assert_eq!(r(&["MIT", "GPL-2.0+"]), "copyleft", "several entries: the most restrictive");
}

#[test]
fn checks_cover_licenses_and_completeness() {
    let s = parse(CDX_JSON).unwrap();
    let issues = audit(&s);
    let ids: Vec<&str> = issues.iter().map(|i| i.id.as_str()).collect();
    for id in ["LIC-NETWORK-COPYLEFT", "LIC-COPYLEFT", "LIC-UNKNOWN", "SBOM-NO-VERSION", "SBOM-NO-IDENTIFIER", "SBOM-SEVERAL-VERSIONS"] {
        assert!(ids.contains(&id), "{id} in {ids:?}");
    }
    assert!(!ids.contains(&"SBOM-NO-RELATIONSHIPS") && !ids.contains(&"SBOM-NO-AUTHOR"));
    assert_eq!(issues.iter().find(|i| i.id == "LIC-NETWORK-COPYLEFT").unwrap().components, vec!["ghostscript@9.5"]);
    assert_eq!(issues.iter().find(|i| i.id == "SBOM-NO-VERSION").unwrap().components, vec!["internal-lib"]);
    assert!(issues.iter().find(|i| i.id == "SBOM-SEVERAL-VERSIONS").unwrap().components[0].contains("npm:lodash (3.10.1, 4.17.20)"));
    let tag = parse(SPDX_TAG).unwrap();
    let ids: Vec<String> = audit(&tag).into_iter().map(|i| i.id).collect();
    assert!(ids.contains(&"SBOM-NO-RELATIONSHIPS".to_string()) && ids.contains(&"SBOM-NO-IDENTIFIER".to_string()));
}

const OSV_RECORD: &str = r#"{
  "id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
  "published": "2021-05-06T16:05:51Z",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [
    {"package": {"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
    {"package": {"ecosystem": "npm", "name": "lodash-es", "purl": "pkg:npm/lodash-es"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.99"}]}]}
  ],
  "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}, {"type": "WEB", "url": "http://insecure.example"}],
  "database_specific": {"severity": "HIGH"}
}"#;

#[test]
fn osv_records_become_vulnerabilities_of_the_components() {
    let s = parse(CDX_JSON).unwrap();
    let lodash = s.components.iter().position(|c| c.label() == "lodash@4.17.20").unwrap();
    let batch: Value = serde_json::from_str(r#"{"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "x"}]}, {}]}"#).unwrap();
    assert_eq!(parse_osv_batch(&batch), vec![vec!["GHSA-35jh-r3h4-6jhm".to_string()], vec![]]);
    let v = parse_osv_vuln(&serde_json::from_str(OSV_RECORD).unwrap(), &s.components, vec![lodash]);
    assert_eq!((v.severity.as_str(), v.cve(), v.score), ("high", Some("CVE-2021-23337"), Some(7.2)));
    assert_eq!(v.fixed, vec!["4.17.21"], "only the affected package's fixed versions");
    assert_eq!(v.references, vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"], "https references only");
    // merged with the SBOM's own statement of the same CVE: one entry, the analysis kept
    let all = merged(&s, &[v]);
    assert_eq!(all.len(), 1);
    assert_eq!((all[0].id.as_str(), all[0].analysis.as_str()), ("GHSA-35jh-r3h4-6jhm", "exploitable"));
    let q: Vec<Option<String>> = s.components.iter().map(query_purl).collect();
    assert!(q.contains(&Some("pkg:npm/lodash@4.17.20".into())) && q.contains(&Some("pkg:maven/org.springframework/spring-core@5.3.0".into())));
    assert_eq!(q.iter().filter(|x| x.is_none()).count(), 1, "the component without a version or package URL is not sent");
}

/// A minimal OSV.dev stand-in on a local port: answers the batch query and one record.
fn mock_osv(record: &'static str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4).flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push(format!("{} {}", first.trim(), String::from_utf8_lossy(&body)));
            let reply = if first.starts_with("POST /v1/querybatch") {
                r#"{"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}, {}, {}, {}, {}, {}, {}]}"#.to_string()
            } else {
                record.to_string()
            };
            let mut out = stream;
            write!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply).unwrap();
        }
    });
    (base, seen)
}

#[tokio::test]
async fn the_lookup_sends_package_urls_only() {
    let s = parse(CDX_JSON).unwrap();
    let (base, seen) = mock_osv(OSV_RECORD);
    let found = osv_lookup(&base, &s.components).await.unwrap();
    assert_eq!((found.checked, found.skipped), (7, 1));
    assert_eq!(found.vulns.len(), 1);
    let v = &found.vulns[0];
    assert_eq!(v.id, "GHSA-35jh-r3h4-6jhm");
    // the batch answers in query order; queries are sorted by package URL, the first is ghostscript
    assert_eq!(s.components[v.components[0]].purl, "pkg:deb/debian/ghostscript@9.5");
    let requests = seen.lock().unwrap().clone();
    let batch = requests.iter().find(|r| r.starts_with("POST /v1/querybatch")).unwrap();
    assert!(batch.contains("pkg:npm/lodash@4.17.20") && !batch.contains("internal-lib") && !batch.contains("OpenJS"), "{batch}");
    assert!(requests.iter().any(|r| r.starts_with("GET /v1/vulns/GHSA-35jh-r3h4-6jhm")));
}

#[test]
fn sboms_are_stored_and_become_findings() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
        let pid = c.last_insert_rowid();
        let s = parse(CDX_JSON).unwrap();
        let id = store(c, pid, "bom.json", "ef56", None, &s)?;
        assert!(store(c, pid, "copy.json", "ef56", None, &s).is_err());
        let listed = list_docs(c, pid)?;
        assert_eq!((listed[0].components, listed[0].vulns, listed[0].vulnerable, listed[0].checked_at.clone()), (8, [0, 1, 0, 0, 0], 1, None));
        let lodash = s.components.iter().position(|c| c.label() == "lodash@4.17.20").unwrap();
        let v = parse_osv_vuln(&serde_json::from_str(OSV_RECORD).unwrap(), &s.components, vec![lodash]);
        save_lookup(c, id, std::slice::from_ref(&v))?;
        let (summary, back, osv) = get(c, id)?;
        assert!(summary.checked_at.is_some());
        assert_eq!((back, osv.len()), (s.clone(), 1));
        let f = vuln_finding(&summary, &s, &v, lodash).unwrap();
        assert_eq!(f.title, "GHSA-35jh-r3h4-6jhm in lodash@4.17.20");
        assert_eq!((f.severity.as_str(), f.cve.as_str(), f.affected_target.as_str()), ("high", "CVE-2021-23337", "pkg:npm/lodash@4.17.20"));
        assert_eq!(f.remediation, "Upgrade lodash to 4.17.21 or later.");
        assert_eq!(f.cvss_vector, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
        assert!(crate::commands::projects::finding_write(c, &f, "sbom", false)? > 0);
        let issue = audit(&s).into_iter().find(|i| i.id == "LIC-NETWORK-COPYLEFT").unwrap();
        let fi = issue_finding(&summary, &s, &issue);
        assert!(fi.title.ends_with("(shop 1.0.0)") && fi.category == "License compliance");
        assert!(crate::commands::projects::finding_write(c, &fi, "sbom", false)? > 0);
        delete(c, id)?;
        assert!(list_docs(c, pid)?.is_empty());
        Ok(())
    })
    .unwrap();
}
