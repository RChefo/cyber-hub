// SPDX-License-Identifier: Apache-2.0
//! Findings export (CSV and JSON) for spreadsheets, ticket systems and other tools
//! (docs/DATA_MODEL.md#findings-export).
//!
//! CSV follows RFC 4180 (every field quoted, CRLF line ends) with a UTF-8 byte-order mark so
//! spreadsheet programs read it as UTF-8. Finding text can come from scanners and so from the
//! assessed systems, so a cell that a spreadsheet would read as a formula (`=`, `+`, `-`, `@`, tab,
//! carriage return) is prefixed with an apostrophe (CSV injection, OWASP).

use serde_json::json;

use crate::commands::projects::Finding;

const COLUMNS: &[&str] = &[
    "id",
    "title",
    "severity",
    "cvss_score",
    "cvss_vector",
    "status",
    "category",
    "confidence",
    "affected_target",
    "cve",
    "tags",
    "assignee",
    "due_date",
    "source",
    "created_at",
    "updated_at",
    "description",
    "reproduction",
    "technical_details",
    "remediation",
    "references",
];

/// One CSV field: formula-like values neutralized, then quoted.
pub fn cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_string() };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

pub fn csv(findings: &[Finding]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(&COLUMNS.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
    out.push_str("\r\n");
    for f in findings {
        let row = [
            f.id.to_string(),
            f.title.clone(),
            f.severity.clone(),
            f.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
            f.cvss_vector.clone(),
            f.status.clone(),
            f.category.clone(),
            f.confidence.clone(),
            f.affected_target.clone(),
            f.cve.clone(),
            f.tags.join(", "),
            f.assignee.clone(),
            f.due_date.clone().unwrap_or_default(),
            f.source.clone(),
            f.created_at.clone(),
            f.updated_at.clone(),
            f.description.clone(),
            f.reproduction.clone(),
            f.technical_details.clone(),
            f.remediation.clone(),
            f.evidence.iter().map(|e| format!("{}: {}", e.label, e.reference)).collect::<Vec<_>>().join("\n"),
        ];
        out.push_str(&row.iter().map(|v| cell(v)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

pub fn json(project: &str, generated: &str, findings: &[Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&json!({ "format": "cyberhub-findings", "version": 1, "project": project, "exportedAt": generated, "findings": findings }))
}

/// SARIF level of a severity: critical and high are errors, medium a warning, the rest notes.
fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// The score code-scanning platforms read as `security-severity`: the CVSS score when the finding
/// has one, otherwise a score in the middle of its severity's CVSS band.
fn security_severity(f: &Finding) -> f64 {
    f.cvss_score.unwrap_or(match f.severity.as_str() {
        "critical" => 9.5,
        "high" => 8.0,
        "medium" => 5.5,
        "low" => 3.0,
        _ => 0.0,
    })
}

/// A file path as a URI reference: separators become `/`, characters a URI path cannot hold are
/// percent-encoded, and an absolute Windows path becomes a `file:` URI.
fn path_uri(path: &str) -> String {
    let path = path.replace('\\', "/");
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":/";
    let mut out = String::from(if drive { "file:///" } else { "" });
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/!$&'()*+,;=:@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A file name without a directory that is still a file: build and deployment files (`Dockerfile`,
/// `Dockerfile.prod`) and common source, configuration and data extensions. Host names stay out:
/// none of these extensions is a top-level domain in common use.
fn looks_like_file(name: &str) -> bool {
    const NAMES: &[&str] = &["dockerfile", "containerfile", "makefile", "jenkinsfile", "vagrantfile", "procfile", "gemfile"];
    const EXTS: &[&str] = &[
        "yml", "yaml", "json", "jsonc", "xml", "toml", "ini", "conf", "cfg", "config", "env", "properties", "txt", "log", "csv", "pcap", "pcapng", "cap", "har",
        "lock", "gradle", "tf", "tfvars", "hcl", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "php", "java", "kt", "go", "rs", "cs", "c", "h", "cpp", "hpp",
        "swift", "scala", "sql", "html", "htm", "vue", "svelte", "sh", "bash", "ps1", "psm1", "bat", "cmd", "md", "pem", "key", "crt", "cer", "p12", "pfx", "jks",
        "sarif", "zip", "jar", "war", "apk", "ipa", "exe", "dll", "so", "bin", "db", "sqlite", "bak",
    ];
    let lower = name.to_ascii_lowercase();
    NAMES.iter().any(|n| lower == *n || lower.strip_prefix(n).is_some_and(|rest| rest.starts_with('.')))
        || lower.rsplit_once('.').is_some_and(|(stem, ext)| !stem.is_empty() && EXTS.contains(&ext))
}

/// Where a finding is: a URL or a file path as a physical location, anything else (a host, an
/// address, a package, free text) as a logical location.
fn sarif_location(target: &str) -> Option<serde_json::Value> {
    let t = target.trim();
    if t.is_empty() {
        return None;
    }
    let is_url = t.contains("://") && !t.contains(char::is_whitespace);
    let is_path = !is_url
        && !t.starts_with("pkg:")
        && !t.contains(char::is_whitespace)
        && (t.contains('/') || t.contains('\\') || (!t.contains(':') && looks_like_file(t)));
    Some(if is_url {
        json!({ "physicalLocation": { "artifactLocation": { "uri": t } } })
    } else if is_path {
        json!({ "physicalLocation": { "artifactLocation": { "uri": path_uri(t) } } })
    } else {
        json!({ "logicalLocations": [{ "name": t, "kind": "resource" }] })
    })
}

/// The project name as an automation category: lowercase letters, digits and dashes.
fn category_slug(project: &str) -> String {
    let mut out = String::new();
    for ch in project.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-');
    if out.is_empty() { "project".into() } else { out.into() }
}

/// SARIF 2.1.0 (OASIS), for code-scanning platforms and vulnerability managers. A finding is an
/// analyst's judgement rather than a scanner rule, so each gets its own rule; `partialFingerprints`
/// keeps it the same alert across exports.
pub fn sarif(project: &str, generated: &str, findings: &[Finding]) -> serde_json::Result<String> {
    let rule_id = |f: &Finding| format!("cyberhub/finding/{}", f.id);
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut tags: Vec<String> = vec!["security".into()];
            for t in std::iter::once(&f.category).chain(f.tags.iter()) {
                if !t.is_empty() && !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                    tags.push(t.clone());
                }
            }
            json!({
                "id": rule_id(f),
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": if f.description.is_empty() { f.title.clone() } else { f.description.clone() } },
                "help": { "text": if f.remediation.is_empty() { "See the finding's description.".to_string() } else { f.remediation.clone() } },
                "properties": {
                    "security-severity": format!("{:.1}", security_severity(f)),
                    "precision": match f.confidence.as_str() { "high" => "high", "low" => "low", _ => "medium" },
                    "tags": tags,
                },
            })
        })
        .collect();
    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut message = f.title.clone();
            if !f.affected_target.is_empty() {
                message.push_str(&format!(" ({})", f.affected_target));
            }
            let mut r = json!({
                "ruleId": rule_id(f),
                "ruleIndex": i,
                "level": sarif_level(&f.severity),
                "message": { "text": message },
                "locations": sarif_location(&f.affected_target).into_iter().collect::<Vec<_>>(),
                "partialFingerprints": { "cyberhubFindingId/v1": f.id.to_string() },
                "properties": {
                    "severity": f.severity,
                    "status": f.status,
                    "confidence": f.confidence,
                    "category": f.category,
                    "affectedTarget": f.affected_target,
                    "createdAt": f.created_at,
                    "updatedAt": f.updated_at,
                },
            });
            let props = r["properties"].as_object_mut().expect("properties is an object");
            if !f.cve.is_empty() {
                props.insert("cve".into(), json!(f.cve));
            }
            if !f.cvss_vector.is_empty() {
                props.insert("cvssVector".into(), json!(f.cvss_vector));
                props.insert("cvssScore".into(), json!(f.cvss_score));
            }
            if matches!(f.status.as_str(), "false_positive" | "accepted_risk") {
                r["suppressions"] = json!([{ "kind": "external", "status": "accepted", "justification": f.status.replace('_', " ") }]);
            }
            r
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "ExploitX", "version": env!("CARGO_PKG_VERSION"), "rules": rules } },
            "automationDetails": { "id": format!("cyberhub/{}/", category_slug(project)) },
            "properties": { "project": project, "exportedAt": generated },
            "results": results,
        }],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::projects::{finding_get, finding_save, FindingInput};
    use crate::db::Db;

    #[test]
    fn sarif_exports_follow_the_2_1_0_shape() {
        let db = Db::open_in_memory().unwrap();
        let findings = db
            .with(|c| {
                c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
                let pid = c.last_insert_rowid();
                let mk = |title: &str, severity: &str, target: &str, status: &str, cvss: &str| FindingInput {
                    project_id: pid,
                    title: title.into(),
                    severity: severity.into(),
                    status: status.into(),
                    category: "Injection".into(),
                    confidence: Some("high".into()),
                    description: "d".into(),
                    affected_target: target.into(),
                    cve: if cvss.is_empty() { String::new() } else { "CVE-2021-44228".into() },
                    remediation: "Fix it.".into(),
                    tags: vec!["web".into(), "injection".into()],
                    cvss_vector: cvss.into(),
                    ..Default::default()
                };
                for input in [
                    mk("SQL injection", "high", "https://app.example.com/item?id=1", "new", ""),
                    mk("Log4Shell", "critical", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "confirmed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                    mk("Runs as root", "medium", "deploy/my app/Dockerfile", "false_positive", ""),
                    mk("Banner", "info", "", "new", ""),
                    mk("Weak key", "low", r"C:\certs\server[old]#2.key", "new", ""),
                ] {
                    finding_save(c, &input, "user")?;
                }
                crate::commands::projects::findings_of(c, pid)
            })
            .unwrap();
        let out: serde_json::Value = serde_json::from_str(&sarif("Shop", "2026-11-09T00:00:00Z", &findings).unwrap()).unwrap();
        assert_eq!(out["version"], "2.1.0");
        let run = &out["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ExploitX");
        let results = run["results"].as_array().unwrap();
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!((results.len(), rules.len()), (5, 5));
        assert_eq!(run["automationDetails"]["id"], "cyberhub/shop/");
        let by = |title: &str| results.iter().find(|r| r["message"]["text"].as_str().unwrap().starts_with(title)).unwrap();
        let sqli = by("SQL injection");
        assert_eq!(sqli["level"], "error");
        assert_eq!(sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "https://app.example.com/item?id=1");
        let rule = &rules[sqli["ruleIndex"].as_u64().unwrap() as usize];
        assert_eq!((rule["id"].clone(), rule["properties"]["security-severity"].clone()), (sqli["ruleId"].clone(), serde_json::json!("8.0")));
        assert_eq!(rule["properties"]["tags"], serde_json::json!(["security", "Injection", "web"]), "tags are unique");
        let log4j = by("Log4Shell");
        assert_eq!(log4j["locations"][0]["logicalLocations"][0]["name"], "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        assert_eq!(log4j["properties"]["cve"], "CVE-2021-44228");
        assert_eq!(rules[log4j["ruleIndex"].as_u64().unwrap() as usize]["properties"]["security-severity"], "10.0", "the CVSS score wins");
        let root = by("Runs as root");
        assert_eq!(root["level"], "warning");
        assert_eq!(root["locations"][0]["logicalLocations"][0]["name"], "deploy/my app/Dockerfile", "text with spaces is not taken for a path");
        assert_eq!(root["suppressions"][0]["justification"], "false positive");
        let banner = by("Banner");
        assert_eq!((banner["level"].clone(), banner["locations"].as_array().unwrap().len()), (serde_json::json!("note"), 0));
        let key = by("Weak key");
        assert_eq!(key["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "file:///C:/certs/server%5Bold%5D%232.key");
        assert_eq!(path_uri("/srv/ünïcode dir/a.txt"), "/srv/%C3%BCn%C3%AFcode%20dir/a.txt");
        assert_eq!(path_uri("src/app/main.rs"), "src/app/main.rs");
        let uri = |t: &str| sarif_location(t).and_then(|l| l["physicalLocation"]["artifactLocation"]["uri"].as_str().map(String::from));
        for (target, want) in [
            ("docker-compose.yml", Some("docker-compose.yml")),
            ("Dockerfile", Some("Dockerfile")),
            ("Dockerfile.prod", Some("Dockerfile.prod")),
            ("main.tf", Some("main.tf")),
            ("api.example.com", None),
            ("10.0.0.5", None),
            ("10.0.0.5:22", None),
            ("localhost:8080", None),
            (".yml", None),
            ("pasted log", None),
        ] {
            assert_eq!(uri(target).as_deref(), want, "{target}");
        }
        assert!(results.iter().all(|r| r["partialFingerprints"]["cyberhubFindingId/v1"].is_string()));
        assert_eq!(category_slug("  Acme — External 2026! "), "acme-external-2026");
    }

    #[test]
    fn csv_quotes_every_field_and_neutralizes_formulas() {
        assert_eq!(cell("plain"), "\"plain\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        assert_eq!(cell("+1"), "\"'+1\"");
        assert_eq!(cell("@SUM(A1)"), "\"'@SUM(A1)\"");
        assert_eq!(cell("-2"), "\"'-2\"");
        assert_eq!(cell("a\nb"), "\"a\nb\"", "line breaks stay inside the quoted field");
    }

    #[test]
    fn exports_contain_every_finding_field() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Acme','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            let id = finding_save(
                c,
                &FindingInput { project_id: p, title: "=cmd|' /C calc'!A0".into(), severity: "high".into(), status: "new".into(), tags: vec!["web".into(), "auth".into()], cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(), ..Default::default() },
                "user",
            )?;
            let f = finding_get(c, id)?;
            let text = csv(std::slice::from_ref(&f));
            assert!(text.starts_with('\u{feff}'));
            let lines: Vec<&str> = text.trim_start_matches('\u{feff}').split("\r\n").filter(|l| !l.is_empty()).collect();
            assert_eq!(lines.len(), 2);
            assert!(lines[0].starts_with("\"id\",\"title\",\"severity\",\"cvss_score\""));
            assert!(lines[1].contains("\"'=cmd|' /C calc'!A0\""), "the formula is neutralized: {}", lines[1]);
            assert!(lines[1].contains("\"9.8\",\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\""));
            assert!(lines[1].contains("\"web, auth\""));
            let j: serde_json::Value = serde_json::from_str(&json("Acme", "2026-11-08", &[f])?)?;
            assert_eq!(j["format"], "cyberhub-findings");
            assert_eq!(j["findings"][0]["cvssScore"], 9.8);
            assert_eq!(j["findings"][0]["tags"][1], "auth");
            Ok(())
        })
        .unwrap();
    }
}
