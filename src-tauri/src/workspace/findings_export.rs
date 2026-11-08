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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::projects::{finding_get, finding_save, FindingInput};
    use crate::db::Db;

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
