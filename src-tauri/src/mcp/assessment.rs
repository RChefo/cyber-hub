// SPDX-License-Identifier: Apache-2.0
//! MCP operations for the assessment features: CVSS scoring, the finding library and the
//! methodology checklist (docs/MCP.md). They are plain functions over the database, so they are
//! tested without the app; `ops` adds the policy, approvals and audit log.

use std::collections::HashMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{validation, AppError, AppResult};
use crate::methodology;
use crate::workspace::templates;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CvssArg {
    pub vector: String,
}

/// The canonical vector and its scores, or the reason it is not a valid vector.
pub fn score_cvss(a: &CvssArg) -> Result<Value, String> {
    let c = crate::cvss::parse(&a.vector)?;
    Ok(json!({
        "version": c.version,
        "vector": c.vector,
        "score": c.score,
        "baseScore": c.base_score,
        "rating": c.rating,
        "label": c.label,
        "note": "The rating is CVSS's qualitative scale. A finding's severity stays the analyst's choice."
    }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateQuery {
    pub query: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateArg {
    pub template_id: i64,
}

fn excerpt(text: &str, max: usize) -> String {
    let t = text.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(max).collect::<String>())
    }
}

/// Templates of the finding library, most used first, filtered by a text and a severity.
pub fn list_templates(c: &Connection, q: &TemplateQuery) -> AppResult<Value> {
    if let Some(s) = q.severity.as_deref() {
        if !templates::SEVERITIES.contains(&s) {
            return Err(validation("severity must be critical, high, medium, low or info"));
        }
    }
    let needle = q.query.as_deref().map(|s| s.trim().chars().take(200).collect::<String>()).filter(|s| !s.is_empty()).map(|s| s.to_lowercase());
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let matching: Vec<templates::FindingTemplate> = templates::list(c)?
        .into_iter()
        .filter(|t| q.severity.as_deref().is_none_or(|s| t.severity == s))
        .filter(|t| {
            needle.as_deref().is_none_or(|n| {
                [&t.title, &t.category, &t.description].iter().any(|f| f.to_lowercase().contains(n)) || t.tags.iter().chain(&t.rules).any(|f| f.to_lowercase().contains(n))
            })
        })
        .collect();
    let total = matching.len();
    let items: Vec<Value> = matching
        .into_iter()
        .take(limit)
        .map(|t| {
            json!({
                "id": t.id,
                "title": t.title,
                "severity": t.severity,
                "category": t.category,
                "tags": t.tags,
                "importRules": t.rules,
                "useCount": t.use_count,
                "summary": excerpt(&t.description, 300),
            })
        })
        .collect();
    Ok(json!({ "total": total, "returned": items.len(), "templates": items }))
}

/// One template with its full write-up.
pub fn get_template(c: &Connection, id: i64) -> AppResult<Value> {
    serde_json::to_value(templates::get(c, id)?).map_err(|e| AppError::Internal(e.to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecklistQuery {
    pub project_id: i64,
    pub category: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecklistSet {
    pub project_id: i64,
    pub test_id: String,
    pub status: String,
    pub note: Option<String>,
    pub finding_id: Option<i64>,
    /// remove the test's finding link
    #[serde(default)]
    pub unlink_finding: bool,
}

fn require_project(c: &Connection, id: i64) -> AppResult<String> {
    c.query_row("SELECT name FROM projects WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("project {id}")))
}

fn check_status(status: &str) -> AppResult<()> {
    if methodology::STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(validation("status must be not_started, in_progress, passed, failed or not_applicable"))
    }
}

/// The OWASP WSTG checklist of a project: coverage and every test with its status (tests never
/// touched are not_started), optionally only one category or one status.
pub fn checklist(c: &Connection, q: &ChecklistQuery) -> AppResult<Value> {
    require_project(c, q.project_id)?;
    if let Some(s) = q.status.as_deref() {
        check_status(s)?;
    }
    let cat = methodology::catalog();
    if let Some(id) = q.category.as_deref() {
        if !cat.categories.iter().any(|g| g.id == id) {
            let ids: Vec<&str> = cat.categories.iter().map(|g| g.id.as_str()).collect();
            return Err(validation(format!("category must be one of {}", ids.join(", "))));
        }
    }
    let states: HashMap<String, methodology::ItemState> = methodology::items(c, q.project_id)?.into_iter().map(|i| (i.test_id.clone(), i)).collect();
    let cov = methodology::coverage(c, q.project_id)?;
    let mut tests = Vec::new();
    for group in cat.categories.iter().filter(|g| q.category.as_deref().is_none_or(|id| g.id == id)) {
        for t in &group.tests {
            let state = states.get(&t.id);
            let status = state.map_or("not_started", |s| s.status.as_str());
            if q.status.as_deref().is_some_and(|s| s != status) {
                continue;
            }
            tests.push(json!({
                "id": t.id,
                "name": t.name,
                "category": group.name,
                "status": status,
                "note": state.map_or("", |s| s.note.as_str()),
                "findingId": state.and_then(|s| s.finding_id),
                "reference": t.reference,
            }));
        }
    }
    Ok(json!({
        "projectId": q.project_id,
        "source": cat.source,
        "url": cat.url,
        "license": cat.license,
        "coverage": {
            "total": cov.total,
            "done": cov.done(),
            "passed": cov.passed,
            "failed": cov.failed,
            "notApplicable": cov.not_applicable,
            "inProgress": cov.in_progress,
        },
        "returned": tests.len(),
        "tests": tests,
    }))
}

/// What an approval shows for a checklist change, after the same checks the change makes. Err
/// for a request that would be refused, so it never reaches the user.
pub fn describe_checklist_set(c: &Connection, a: &ChecklistSet) -> AppResult<(String, Vec<(String, String)>)> {
    let project = require_project(c, a.project_id)?;
    crate::commands::projects::refuse_archived_for_clients(c, a.project_id)?;
    check_status(&a.status)?;
    let test = methodology::catalog()
        .categories
        .iter()
        .flat_map(|g| g.tests.iter())
        .find(|t| t.id == a.test_id)
        .ok_or_else(|| validation(format!("{} is not a test of the bundled checklist", a.test_id.chars().take(40).collect::<String>())))?;
    let mut details = vec![("Test".to_string(), format!("{} {}", test.id, test.name)), ("Status".to_string(), a.status.replace('_', " "))];
    if let Some(note) = &a.note {
        // the same check as the write: a note it would refuse never reaches the user
        let note = crate::util::clean("Note", note, 2000, false)?;
        let existing: Option<String> =
            c.query_row("SELECT note FROM checklist_items WHERE project_id = ?1 AND test_id = ?2", params![a.project_id, a.test_id], |r| r.get(0)).optional()?;
        let replaces = existing.filter(|e| !e.is_empty() && *e != note).map(|_| "; replaces the existing note").unwrap_or("");
        let shown = if note.is_empty() { "(empty: clears the note)".to_string() } else { excerpt(&note, 600) };
        details.push(("Note".to_string(), format!("{shown} ({} characters{replaces})", note.chars().count())));
    }
    let link = methodology::Link::from_args(a.finding_id, a.unlink_finding)?;
    if let methodology::Link::To(fid) = link {
        let owner: Option<(i64, String)> = c.query_row("SELECT project_id, title FROM findings WHERE id = ?1", params![fid], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        match owner {
            Some((pid, title)) if pid == a.project_id => details.push(("Linked finding".to_string(), format!("#{fid} {}", excerpt(&title, 200)))),
            _ => return Err(validation("The finding belongs to another project")),
        }
    }
    if link == methodology::Link::Clear {
        let linked: Option<Option<i64>> =
            c.query_row("SELECT finding_id FROM checklist_items WHERE project_id = ?1 AND test_id = ?2", params![a.project_id, a.test_id], |r| r.get(0)).optional()?;
        details.push((
            "Linked finding".to_string(),
            match linked.flatten() {
                Some(f) => format!("Removes the link to finding #{f} (the finding itself stays)"),
                None => "No finding is linked; nothing to remove".to_string(),
            },
        ));
    }
    Ok((project, details))
}

/// Sets a test's status. A note that is not given keeps the note already there.
pub fn set_checklist(c: &Connection, a: &ChecklistSet) -> AppResult<Value> {
    crate::commands::projects::refuse_archived_for_clients(c, a.project_id)?;
    let note = match &a.note {
        Some(n) => n.clone(),
        None => c
            .query_row("SELECT note FROM checklist_items WHERE project_id = ?1 AND test_id = ?2", params![a.project_id, a.test_id], |r| r.get::<_, String>(0))
            .optional()?
            .unwrap_or_default(),
    };
    let link = methodology::Link::from_args(a.finding_id, a.unlink_finding)?;
    let state = methodology::set(c, a.project_id, &a.test_id, &a.status, &note, link, "mcp")?;
    serde_json::to_value(state).map_err(|e| AppError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn project(c: &Connection) -> i64 {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Acme', 'active', 't', 't')", []).unwrap();
        c.last_insert_rowid()
    }

    #[test]
    fn cvss_vectors_are_scored_or_refused_with_the_reason() {
        let v = score_cvss(&CvssArg { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into() }).unwrap();
        assert_eq!((v["score"].as_f64(), v["rating"].as_str(), v["label"].as_str()), (Some(9.8), Some("critical"), Some("Base")));
        let v = score_cvss(&CvssArg { vector: "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:P/PR:N/AT:P/AC:L/AV:N/E:U".into() }).unwrap();
        assert_eq!(v["vector"], "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", "canonical order");
        assert_eq!(v["score"].as_f64(), Some(5.2));
        let e = score_cvss(&CvssArg { vector: "CVSS:3.1/AV:N/AC:L".into() }).unwrap_err();
        assert!(e.contains("missing"), "{e}");
        assert!(serde_json::from_value::<CvssArg>(json!({ "vector": "x", "score": 10 })).is_err(), "unknown fields are refused");
    }

    #[test]
    fn templates_are_listed_filtered_and_read() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            templates::add_starters(c)?;
            let all = list_templates(c, &TemplateQuery::default())?;
            assert_eq!(all["total"], 14);
            let sqli = list_templates(c, &TemplateQuery { query: Some("sql injection".into()), ..Default::default() })?;
            assert_eq!(sqli["returned"], 1, "{sqli}");
            let id = sqli["templates"][0]["id"].as_i64().unwrap();
            assert!(sqli["templates"][0]["summary"].as_str().unwrap().chars().count() <= 301);
            let by_rule = list_templates(c, &TemplateQuery { query: Some("zap:".into()), limit: Some(2), ..Default::default() })?;
            assert_eq!(by_rule["returned"], 2, "import rules are searched and the limit applies");
            let high = list_templates(c, &TemplateQuery { severity: Some("high".into()), ..Default::default() })?;
            assert!(high["templates"].as_array().unwrap().iter().all(|t| t["severity"] == "high"));
            assert!(list_templates(c, &TemplateQuery { severity: Some("urgent".into()), ..Default::default() }).is_err());
            let full = get_template(c, id)?;
            assert!(full["remediation"].as_str().is_some_and(|r| !r.is_empty()), "{full}");
            assert!(get_template(c, 9999).is_err());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn mcp_clients_cannot_change_archived_projects() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let pid = project(c);
            c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", [pid])?;
            let set = ChecklistSet { project_id: pid, test_id: "WSTG-ATHZ-04".into(), status: "failed".into(), note: None, finding_id: None, unlink_finding: false };
            let err = describe_checklist_set(c, &set).unwrap_err().to_string();
            assert!(err.contains("archived"), "{err}");
            assert!(set_checklist(c, &set).is_err(), "also when the project was archived after the approval");
            let unlink = ChecklistSet { unlink_finding: true, ..set.clone() };
            assert!(describe_checklist_set(c, &unlink).unwrap_err().to_string().contains("archived"), "unlinking is refused too");
            assert!(set_checklist(c, &unlink).is_err());
            assert!(crate::commands::projects::refuse_archived_for_clients(c, pid + 100).is_err());
            c.execute("UPDATE projects SET status = 'completed' WHERE id = ?1", [pid])?;
            assert!(describe_checklist_set(c, &set).is_ok() && set_checklist(c, &set).is_ok());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn the_checklist_is_read_and_changed_with_the_same_rules_as_the_app() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let pid = project(c);
            let other = project(c);
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1, 'IDOR', 'high', 'new', 't', 't')", [pid])?;
            let fid = c.last_insert_rowid();
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1, 'Elsewhere', 'low', 'new', 't', 't')", [other])?;
            let foreign = c.last_insert_rowid();

            let all = checklist(c, &ChecklistQuery { project_id: pid, category: None, status: None })?;
            assert_eq!(all["coverage"]["total"], all["returned"]);
            assert!(all["tests"].as_array().unwrap().iter().all(|t| t["status"] == "not_started"));

            let set = ChecklistSet { project_id: pid, test_id: "WSTG-ATHZ-04".into(), status: "failed".into(), note: Some("IDOR on /api/orders".into()), finding_id: Some(fid), unlink_finding: false };
            let (project_name, details) = describe_checklist_set(c, &set)?;
            assert_eq!(project_name, "Acme");
            assert!(details.iter().any(|(k, v)| k == "Linked finding" && v.contains("IDOR")), "{details:?}");
            set_checklist(c, &set)?;
            // a later change without a note keeps the note
            set_checklist(c, &ChecklistSet { note: None, finding_id: None, status: "failed".into(), ..set })?;
            let failed = checklist(c, &ChecklistQuery { project_id: pid, category: None, status: Some("failed".into()) })?;
            assert_eq!(failed["returned"], 1);
            assert_eq!(failed["tests"][0]["note"], "IDOR on /api/orders");
            assert_eq!(failed["tests"][0]["findingId"], fid);
            assert_eq!((failed["coverage"]["failed"].as_u64(), failed["coverage"]["done"].as_u64()), (Some(1), Some(1)));
            let athz = checklist(c, &ChecklistQuery { project_id: pid, category: Some("WSTG-ATHZ".into()), status: None })?;
            assert!(athz["tests"].as_array().unwrap().iter().all(|t| t["id"].as_str().unwrap().starts_with("WSTG-ATHZ")));

            // the approval says when a note replaces another, and shows its length
            let (_, d) = describe_checklist_set(c, &ChecklistSet { note: Some("New note".into()), finding_id: None, status: "failed".into(), project_id: pid, test_id: "WSTG-ATHZ-04".into(), unlink_finding: false })?;
            assert!(d.iter().any(|(k, v)| k == "Note" && v.contains("8 characters; replaces the existing note")), "{d:?}");

            // refused before an approval is asked
            let bad = |s: ChecklistSet| describe_checklist_set(c, &s).unwrap_err().to_string();
            let base = || ChecklistSet { project_id: pid, test_id: "WSTG-ATHZ-04".into(), status: "passed".into(), note: None, finding_id: None, unlink_finding: false };
            assert!(bad(ChecklistSet { finding_id: Some(fid), unlink_finding: true, ..base() }).contains("not both"));
            // unlinking through MCP: the approval says what goes, the write removes only the link
            let (_, d) = describe_checklist_set(c, &ChecklistSet { unlink_finding: true, status: "failed".into(), ..base() })?;
            assert!(d.iter().any(|(k, v)| k == "Linked finding" && v.contains(&format!("Removes the link to finding #{fid}"))), "{d:?}");
            let after = set_checklist(c, &ChecklistSet { unlink_finding: true, status: "failed".into(), ..base() })?;
            assert!(after["findingId"].is_null() && after["note"] == "IDOR on /api/orders", "{after}");
            set_checklist(c, &ChecklistSet { finding_id: Some(fid), status: "failed".into(), ..base() })?;
            assert!(bad(ChecklistSet { test_id: "WSTG-NOPE-99".into(), ..base() }).contains("not a test"));
            assert!(bad(ChecklistSet { status: "done".into(), ..base() }).contains("status must be"));
            assert!(bad(ChecklistSet { finding_id: Some(foreign), ..base() }).contains("another project"));
            assert!(bad(ChecklistSet { project_id: 999, ..base() }).contains("project 999"));
            assert!(bad(ChecklistSet { note: Some("x".repeat(2001)), ..base() }).contains("Note"), "too long for the write");
            assert!(bad(ChecklistSet { note: Some("a\u{0}b".into()), ..base() }).contains("Note"), "control characters"); 
            assert!(checklist(c, &ChecklistQuery { project_id: pid, category: Some("WSTG-XXXX".into()), status: None }).is_err());
            assert!(serde_json::from_value::<ChecklistSet>(json!({ "project_id": 1, "test_id": "WSTG-INFO-01", "status": "passed", "verified": true })).is_err());
            Ok(())
        })
        .unwrap();
    }
}
