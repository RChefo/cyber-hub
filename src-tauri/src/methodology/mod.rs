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

/// Sets a test's status and note, and optionally links the finding it led to (same project only).
pub fn set(c: &Connection, project_id: i64, test_id: &str, status: &str, note: &str, finding_id: Option<i64>) -> AppResult<ItemState> {
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
    c.execute(
        "INSERT INTO checklist_items (project_id, test_id, status, note, finding_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (project_id, test_id) DO UPDATE SET status = excluded.status, note = excluded.note,
             finding_id = COALESCE(excluded.finding_id, checklist_items.finding_id), updated_at = excluded.updated_at",
        params![project_id, test_id, status, note, finding_id, ts],
    )?;
    Ok(c.query_row(
        "SELECT test_id, status, note, finding_id, updated_at FROM checklist_items WHERE project_id = ?1 AND test_id = ?2",
        params![project_id, test_id],
        |r| Ok(ItemState { test_id: r.get(0)?, status: r.get(1)?, note: r.get(2)?, finding_id: r.get(3)?, updated_at: r.get(4)? }),
    )?)
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
            set(c, 1, "WSTG-INFO-01", "passed", "", None)?;
            set(c, 1, "WSTG-CONF-01", "in_progress", "halfway", None)?;
            let failed = set(c, 1, "WSTG-CLNT-01", "failed", "Reflected XSS", Some(1))?;
            assert_eq!(failed.finding_id, Some(1));
            // changing the status keeps the finding link
            assert_eq!(set(c, 1, "WSTG-CLNT-01", "failed", "confirmed", None)?.finding_id, Some(1));
            set(c, 1, "WSTG-ATHN-01", "not_applicable", "no login", None)?;
            let cov = coverage(c, 1)?;
            assert_eq!((cov.total, cov.passed, cov.failed, cov.not_applicable, cov.in_progress, cov.done()), (115, 1, 1, 1, 1, 3));
            assert_eq!(coverage(c, 2)?.done(), 0, "another project has its own progress");
            assert!(set(c, 1, "WSTG-XXXX-01", "passed", "", None).is_err());
            assert!(set(c, 1, "WSTG-INFO-01", "done", "", None).is_err());
            assert!(set(c, 2, "WSTG-INFO-01", "failed", "", Some(1)).is_err(), "a finding of another project cannot be linked");
            // deleting the finding keeps the checklist item
            c.execute("DELETE FROM findings WHERE id = 1", [])?;
            assert_eq!(items(c, 1)?.iter().find(|i| i.test_id == "WSTG-CLNT-01").unwrap().finding_id, None);
            Ok(())
        })
        .unwrap();
    }
}
