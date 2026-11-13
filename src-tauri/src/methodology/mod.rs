// SPDX-License-Identifier: Apache-2.0
//! Methodology checklist (docs/DATA_MODEL.md#methodology-checklist-schema-17): the OWASP WSTG
//! test catalog bundled with the app (`wstg.json`, CC BY-SA 4.0, see THIRD_PARTY_NOTICES.md) and
//! each project's progress through it.

use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, now};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Test {
    pub id: String,
    pub name: String,
    pub reference: String,
    pub objectives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    pub id: String,
    pub name: String,
    pub tests: Vec<Test>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub source: String,
    pub url: String,
    pub commit: String,
    pub retrieved: String,
    pub license: String,
    pub categories: Vec<Category>,
}

static WSTG: Lazy<Catalog> = Lazy::new(|| serde_json::from_str(include_str!("wstg.json")).expect("the bundled WSTG checklist is valid"));

pub fn catalog() -> &'static Catalog {
    &WSTG
}

pub fn test_exists(id: &str) -> bool {
    WSTG.categories.iter().any(|c| c.tests.iter().any(|t| t.id == id))
}

pub const STATUSES: &[&str] = &["not_started", "in_progress", "passed", "failed", "not_applicable"];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ItemState {
    pub test_id: String,
    pub status: String,
    pub note: String,
    pub finding_id: Option<i64>,
    pub updated_at: String,
}

pub fn items(c: &Connection, project_id: i64) -> AppResult<Vec<ItemState>> {
    let mut stmt = c.prepare("SELECT test_id, status, note, finding_id, updated_at FROM checklist_items WHERE project_id = ?1 ORDER BY test_id")?;
    let rows = stmt
        .query_map(params![project_id], |r| Ok(ItemState { test_id: r.get(0)?, status: r.get(1)?, note: r.get(2)?, finding_id: r.get(3)?, updated_at: r.get(4)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// What to do with the finding a test is linked to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// keep the current link (none, or the finding already linked)
    Keep,
    /// link this finding of the same project
    To(i64),
    /// remove the link
    Clear,
}

impl Link {
    /// From the API's optional finding and unlink flag; both at once is a contradiction.
    pub fn from_args(finding_id: Option<i64>, unlink: bool) -> AppResult<Link> {
        match (finding_id, unlink) {
            (Some(_), true) => Err(validation("Give a finding to link or ask to unlink, not both")),
            (Some(id), false) if id < 1 => Err(validation("A finding id is a positive number")),
            (Some(id), false) => Ok(Link::To(id)),
            (None, true) => Ok(Link::Clear),
            (None, false) => Ok(Link::Keep),
        }
    }
}

/// Sets a test's status and note, and links the finding it led to (same project only), keeps the
/// link or removes it. Every change is recorded on the project timeline with who made it.
pub fn set(c: &Connection, project_id: i64, test_id: &str, status: &str, note: &str, link: Link, source: &str) -> AppResult<ItemState> {
    let finding_id = match link {
        Link::To(id) => Some(id),
        _ => None,
    };
    if !test_exists(test_id) {
        return Err(validation(format!("{test_id} is not a test of the bundled checklist")));
    }
    if !STATUSES.contains(&status) {
        return Err(validation("Status must be not started, in progress, passed, failed or not applicable"));
    }
    let note = clean("Note", note, 2000, false)?;
    let exists: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM projects WHERE id = ?1)", params![project_id], |r| r.get(0))?;
    if !exists {
        return Err(AppError::NotFound(format!("project {project_id}")));
    }
    if let Some(fid) = finding_id {
        let owner: Option<i64> = c.query_row("SELECT project_id FROM findings WHERE id = ?1", params![fid], |r| r.get(0)).optional()?;
        if owner != Some(project_id) {
            return Err(validation("The finding belongs to another project"));
        }
    }
    let ts = now();
    let read = |c: &Connection| -> AppResult<Option<ItemState>> {
        Ok(c.query_row(
            "SELECT test_id, status, note, finding_id, updated_at FROM checklist_items WHERE project_id = ?1 AND test_id = ?2",
            params![project_id, test_id],
            |r| Ok(ItemState { test_id: r.get(0)?, status: r.get(1)?, note: r.get(2)?, finding_id: r.get(3)?, updated_at: r.get(4)? }),
        )
        .optional()?)
    };
    let tx = c.unchecked_transaction()?;
    let before = read(&tx)?;
    tx.execute(
        "INSERT INTO checklist_items (project_id, test_id, status, note, finding_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (project_id, test_id) DO UPDATE SET status = excluded.status, note = excluded.note,
             finding_id = CASE WHEN ?7 THEN NULL ELSE COALESCE(excluded.finding_id, checklist_items.finding_id) END, updated_at = excluded.updated_at",
        params![project_id, test_id, status, note, finding_id, ts, link == Link::Clear],
    )?;
    let after = read(&tx)?.ok_or_else(|| AppError::Internal("the checklist item was not stored".into()))?;
    // the history: what changed, and who changed it
    let (old_status, old_note, old_finding) = before.as_ref().map_or(("not_started", "", None), |b| (b.status.as_str(), b.note.as_str(), b.finding_id));
    let mut changes: Vec<String> = Vec::new();
    if old_status != after.status {
        changes.push(format!("{} → {}", old_status.replace('_', " "), after.status.replace('_', " ")));
    }
    if old_note != after.note {
        changes.push(if after.note.is_empty() { "note removed".into() } else { "note changed".into() });
    }
    match (old_finding, after.finding_id) {
        (a, b) if a == b => {}
        (_, Some(f)) => changes.push(format!("linked to finding #{f}")),
        (Some(f), None) => changes.push(format!("link to finding #{f} removed")),
        (None, None) => {}
    }
    if !changes.is_empty() {
        let by = if source == "mcp" { "by an MCP client" } else { "by the analyst" };
        crate::workspace::timeline::record(&tx, project_id, "checklist", &format!("Checklist {test_id}: {}", changes.join(", ")), by, Some("checklist"), None)?;
    }
    // an exception covers a failed test; any other result ends it (Mission 6)
    if old_status == "failed" && after.status != "failed" {
        crate::workspace::risk::release(&tx, "wstg", project_id, test_id, &format!("the test is now {}", after.status.replace('_', " ")), source)?;
    }
    tx.commit()?;
    Ok(after)
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub in_progress: usize,
}

impl Coverage {
    /// Tests with a result (passed, failed or not applicable).
    pub fn done(&self) -> usize {
        self.passed + self.failed + self.not_applicable
    }
}

pub fn coverage(c: &Connection, project_id: i64) -> AppResult<Coverage> {
    let mut cov = Coverage { total: WSTG.categories.iter().map(|c| c.tests.len()).sum(), ..Default::default() };
    for it in items(c, project_id)?.into_iter().filter(|i| test_exists(&i.test_id)) {
        match it.status.as_str() {
            "passed" => cov.passed += 1,
            "failed" => cov.failed += 1,
            "not_applicable" => cov.not_applicable += 1,
            "in_progress" => cov.in_progress += 1,
            _ => {}
        }
    }
    Ok(cov)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn the_bundled_catalog_is_complete_and_well_formed() {
        let c = catalog();
        assert_eq!(c.categories.len(), 13);
        let tests: Vec<&Test> = c.categories.iter().flat_map(|c| c.tests.iter()).collect();
        assert_eq!(tests.len(), 115);
        let mut ids: Vec<&str> = tests.iter().map(|t| t.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 115, "test IDs are unique");
        assert!(tests.iter().all(|t| t.reference.starts_with("https://wstg.owasp.org/") && !t.name.is_empty()));
        assert!(c.license.contains("CC BY-SA 4.0") && c.url.contains(&c.commit));
        assert!(test_exists("WSTG-INFO-01") && !test_exists("WSTG-INFO-99"));
    }

    #[test]
    fn progress_is_recorded_per_project_and_counted() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('A','active','t','t'), ('B','active','t','t')", [])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1, 'XSS', 'medium', 'new', 't', 't')", [])?;
            set(c, 1, "WSTG-INFO-01", "passed", "", Link::Keep, "user")?;
            set(c, 1, "WSTG-CONF-01", "in_progress", "halfway", Link::Keep, "user")?;
            let failed = set(c, 1, "WSTG-CLNT-01", "failed", "Reflected XSS", Link::To(1), "user")?;
            assert_eq!(failed.finding_id, Some(1));
            // changing the status keeps the finding link
            assert_eq!(set(c, 1, "WSTG-CLNT-01", "failed", "confirmed", Link::Keep, "user")?.finding_id, Some(1));
            set(c, 1, "WSTG-ATHN-01", "not_applicable", "no login", Link::Keep, "user")?;
            let cov = coverage(c, 1)?;
            assert_eq!((cov.total, cov.passed, cov.failed, cov.not_applicable, cov.in_progress, cov.done()), (115, 1, 1, 1, 1, 3));
            assert_eq!(coverage(c, 2)?.done(), 0, "another project has its own progress");
            assert!(set(c, 1, "WSTG-XXXX-01", "passed", "", Link::Keep, "user").is_err());
            assert!(set(c, 1, "WSTG-INFO-01", "done", "", Link::Keep, "user").is_err());
            assert!(set(c, 2, "WSTG-INFO-01", "failed", "", Link::To(1), "user").is_err(), "a finding of another project cannot be linked");
            // deleting the finding keeps the checklist item
            c.execute("DELETE FROM findings WHERE id = 1", [])?;
            assert_eq!(items(c, 1)?.iter().find(|i| i.test_id == "WSTG-CLNT-01").unwrap().finding_id, None);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_finding_link_can_be_removed_and_every_change_is_in_the_history() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('A','active','t','t')", [])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1, 'IDOR', 'high', 'new', 't', 't')", [])?;
            set(c, 1, "WSTG-ATHZ-04", "failed", "IDOR on /api/orders", Link::To(1), "user")?;
            let cleared = set(c, 1, "WSTG-ATHZ-04", "failed", "IDOR on /api/orders", Link::Clear, "mcp")?;
            assert_eq!((cleared.finding_id, cleared.status.as_str(), cleared.note.as_str()), (None, "failed", "IDOR on /api/orders"), "only the link goes");
            let finding: i64 = c.query_row("SELECT COUNT(*) FROM findings WHERE id = 1", [], |r| r.get(0))?;
            assert_eq!(finding, 1, "the finding itself stays");
            // clearing again, or keeping, changes nothing and records nothing
            set(c, 1, "WSTG-ATHZ-04", "failed", "IDOR on /api/orders", Link::Clear, "user")?;
            let history: Vec<(String, String)> = c
                .prepare("SELECT title, detail FROM timeline_events WHERE project_id = 1 AND type = 'checklist' ORDER BY id")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            assert_eq!(
                history,
                vec![
                    ("Checklist WSTG-ATHZ-04: not started → failed, note changed, linked to finding #1".to_string(), "by the analyst".to_string()),
                    ("Checklist WSTG-ATHZ-04: link to finding #1 removed".to_string(), "by an MCP client".to_string()),
                ]
            );
            // identifiers are checked
            assert!(Link::from_args(Some(1), true).is_err(), "a finding and unlink together");
            assert!(Link::from_args(Some(0), false).is_err() && Link::from_args(Some(-4), false).is_err());
            assert_eq!(Link::from_args(None, true)?, Link::Clear);
            assert!(set(c, 1, "WSTG-ATHZ-99", "failed", "", Link::Clear, "user").is_err(), "unknown test");
            assert!(set(c, 7, "WSTG-ATHZ-04", "failed", "", Link::Clear, "user").is_err(), "unknown project");
            assert!(set(c, 1, "WSTG-ATHZ-04", "failed", "", Link::To(99), "user").is_err(), "unknown finding");
            Ok(())
        })
        .unwrap();
    }
}
