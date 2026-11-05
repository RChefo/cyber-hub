//! Findings lifecycle: statuses, the history of every change, and links to the records a finding
//! is based on (assets, runs, evidence, OSINT entities). History rows are never edited; they are
//! removed only together with their finding.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const STATUSES: &[&str] = &["new", "under_review", "confirmed", "accepted_risk", "in_remediation", "resolved", "reopened", "false_positive"];
/// Statuses that still need attention (dashboards, project counts), as an SQL list.
pub const OPEN_SQL: &str = "('new','under_review','confirmed','in_remediation','reopened')";
const CLOSED: &[&str] = &["resolved", "false_positive", "accepted_risk"];
pub const CONFIDENCES: &[&str] = &["low", "medium", "high"];
pub const LINK_KINDS: &[&str] = &["asset", "vulnerability", "osint_entity", "execution", "evidence"];

/// The current name of a status, accepting the names of earlier versions (`open`, `reported`)
/// so older clients (MCP, saved forms) keep working.
pub fn canonical_status(s: &str) -> Option<&'static str> {
    match s.trim() {
        "open" => Some("new"),
        "reported" => Some("confirmed"),
        other => STATUSES.iter().copied().find(|x| *x == other),
    }
}

pub fn status_or_err(s: &str) -> AppResult<&'static str> {
    canonical_status(s).ok_or_else(|| validation(format!("Status must be one of: {}", STATUSES.join(", "))))
}

/// Whether moving from `from` to `to` is a valid lifecycle step. Reopening is only possible for a
/// closed finding; everything else may move freely (triage is not always linear).
pub fn transition_ok(from: &str, to: &str) -> Result<(), String> {
    if from == to {
        return Err("The finding already has this status".into());
    }
    if to == "reopened" && !CLOSED.contains(&from) {
        return Err("Only a resolved, accepted or false-positive finding can be reopened".into());
    }
    Ok(())
}

pub fn record_event(c: &Connection, finding_id: i64, project_id: i64, kind: &str, (from, to): (Option<&str>, Option<&str>), note: &str, source: &str) -> AppResult<()> {
    c.execute(
        "INSERT INTO finding_events (finding_id, project_id, kind, from_status, to_status, note, source, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![finding_id, project_id, kind, from, to, note.chars().take(4000).collect::<String>(), source, now()],
    )?;
    Ok(())
}

fn owner(c: &Connection, finding_id: i64) -> AppResult<(i64, String)> {
    c.query_row("SELECT project_id, status FROM findings WHERE id = ?1", params![finding_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("finding {finding_id}")))
}

/// Changes the status, records it with an optional reason, and returns the new status.
pub fn set_status(c: &Connection, finding_id: i64, status: &str, note: &str, source: &str) -> AppResult<&'static str> {
    let to = status_or_err(status)?;
    let (project_id, from) = owner(c, finding_id)?;
    transition_ok(&from, to).map_err(validation)?;
    let ts = now();
    c.execute("UPDATE findings SET status = ?2, updated_at = ?3 WHERE id = ?1", params![finding_id, to, ts])?;
    c.execute("UPDATE projects SET updated_at = ?2 WHERE id = ?1", params![project_id, ts])?;
    record_event(c, finding_id, project_id, "status", (Some(&from), Some(to)), note, source)?;
    Ok(to)
}

pub fn add_note(c: &Connection, finding_id: i64, note: &str, source: &str) -> AppResult<()> {
    let note = note.trim();
    if note.is_empty() || note.chars().count() > 4000 {
        return Err(validation("A note needs 1 to 4000 characters"));
    }
    let (project_id, _) = owner(c, finding_id)?;
    record_event(c, finding_id, project_id, "note", (None, None), note, source)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingEvent {
    pub id: i64,
    pub kind: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub note: String,
    pub source: String,
    pub at: String,
}

/// Oldest first: the history reads like a log.
pub fn history(c: &Connection, finding_id: i64) -> AppResult<Vec<FindingEvent>> {
    owner(c, finding_id)?;
    let mut st = c.prepare("SELECT id, kind, from_status, to_status, note, source, at FROM finding_events WHERE finding_id = ?1 ORDER BY id")?;
    let rows = st
        .query_map(params![finding_id], |r| Ok(FindingEvent { id: r.get(0)?, kind: r.get(1)?, from_status: r.get(2)?, to_status: r.get(3)?, note: r.get(4)?, source: r.get(5)?, at: r.get(6)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The project a referenced record belongs to, or why it cannot be linked.
fn ref_project(c: &Connection, kind: &str, ref_id: i64) -> AppResult<Option<i64>> {
    let sql = match kind {
        "asset" => "SELECT project_id FROM assets WHERE id = ?1",
        "execution" => "SELECT project_id FROM executions WHERE id = ?1",
        "evidence" => "SELECT project_id FROM evidence WHERE id = ?1",
        "osint_entity" => "SELECT i.project_id FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id WHERE e.id = ?1",
        "vulnerability" => "SELECT project_id FROM vulnerabilities WHERE id = ?1",
        _ => return Err(validation(format!("Links can point to: {}", LINK_KINDS.join(", ")))),
    };
    let found: Option<Option<i64>> = c.query_row(sql, params![ref_id], |r| r.get(0)).optional()?;
    match found {
        None => Err(AppError::NotFound(format!("{kind} {ref_id}"))),
        Some(p) => Ok(p),
    }
}

/// Links a finding to a record of the same project. Linking twice changes nothing.
pub fn link(c: &Connection, finding_id: i64, kind: &str, ref_id: i64, source: &str) -> AppResult<bool> {
    let (project_id, _) = owner(c, finding_id)?;
    if ref_project(c, kind, ref_id)? != Some(project_id) {
        return Err(validation("Only records of the finding's own project can be linked"));
    }
    let added = c.execute("INSERT OR IGNORE INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (?1, ?2, ?3, ?4)", params![finding_id, kind, ref_id, now()])? == 1;
    if added {
        record_event(c, finding_id, project_id, "link", (None, None), &format!("{kind} #{ref_id}"), source)?;
    }
    Ok(added)
}

pub fn unlink(c: &Connection, finding_id: i64, kind: &str, ref_id: i64, source: &str) -> AppResult<bool> {
    let (project_id, _) = owner(c, finding_id)?;
    let removed = c.execute("DELETE FROM finding_links WHERE finding_id = ?1 AND kind = ?2 AND ref_id = ?3", params![finding_id, kind, ref_id])? == 1;
    if removed {
        record_event(c, finding_id, project_id, "unlink", (None, None), &format!("{kind} #{ref_id}"), source)?;
    }
    Ok(removed)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingLink {
    pub kind: String,
    pub ref_id: i64,
    /// What the linked record is called now; None when it was deleted since.
    pub label: Option<String>,
    pub created_at: String,
}

pub fn links(c: &Connection, finding_id: i64) -> AppResult<Vec<FindingLink>> {
    owner(c, finding_id)?;
    let mut st = c.prepare(
        "SELECT l.kind, l.ref_id, CASE l.kind
             WHEN 'asset' THEN (SELECT a.value FROM assets a WHERE a.id = l.ref_id)
             WHEN 'execution' THEN (SELECT x.tool_id || ' run #' || x.id FROM executions x WHERE x.id = l.ref_id)
             WHEN 'evidence' THEN (SELECT e.title FROM evidence e WHERE e.id = l.ref_id)
             WHEN 'osint_entity' THEN (SELECT o.display_name FROM osint_entities o WHERE o.id = l.ref_id)
             WHEN 'vulnerability' THEN (SELECT v.cve_id FROM vulnerabilities v WHERE v.id = l.ref_id)
           END, l.created_at
         FROM finding_links l WHERE l.finding_id = ?1 ORDER BY l.kind, l.id",
    )?;
    let rows = st
        .query_map(params![finding_id], |r| Ok(FindingLink { kind: r.get(0)?, ref_id: r.get(1)?, label: r.get(2)?, created_at: r.get(3)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Removes links to a record that is being deleted (links have no foreign key: they point into
/// several tables).
pub fn forget_ref(c: &Connection, kind: &str, ref_id: i64) -> AppResult<()> {
    c.execute("DELETE FROM finding_links WHERE kind = ?1 AND ref_id = ?2", params![kind, ref_id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn setup(db: &Db) -> (i64, i64, i64) {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('A','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('B','active','t','t')", [])?;
            let other = c.last_insert_rowid();
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1,'SQLi','high','new','t','t')", params![p])?;
            Ok((p, other, c.last_insert_rowid()))
        })
        .unwrap()
    }

    #[test]
    fn legacy_status_names_are_accepted_and_mapped() {
        assert_eq!(canonical_status("open"), Some("new"));
        assert_eq!(canonical_status("reported"), Some("confirmed"));
        assert_eq!(canonical_status("in_remediation"), Some("in_remediation"));
        assert_eq!(canonical_status("closed"), None);
        let open: Vec<&str> = STATUSES.iter().copied().filter(|s| OPEN_SQL.contains(&format!("'{s}'"))).collect();
        assert_eq!(open, vec!["new", "under_review", "confirmed", "in_remediation", "reopened"]);
        assert_eq!(OPEN_SQL.matches('\'').count(), open.len() * 2, "the list names only known statuses");
    }

    #[test]
    fn status_changes_follow_the_lifecycle_and_are_recorded() {
        let db = Db::open_in_memory().unwrap();
        let (_, _, f) = setup(&db);
        db.with(|c| {
            assert!(set_status(c, f, "reopened", "", "user").is_err(), "an open finding cannot be reopened");
            assert!(set_status(c, f, "new", "", "user").is_err(), "no change is not a change");
            set_status(c, f, "under_review", "", "user")?;
            set_status(c, f, "reported", "sent to the client", "mcp")?;
            set_status(c, f, "resolved", "patched in 2.4.1", "user")?;
            set_status(c, f, "reopened", "regression found", "user")?;
            add_note(c, f, "Retest scheduled", "user")?;
            assert!(add_note(c, f, "  ", "user").is_err());
            let h = history(c, f)?;
            let steps: Vec<(Option<&str>, Option<&str>)> = h.iter().filter(|e| e.kind == "status").map(|e| (e.from_status.as_deref(), e.to_status.as_deref())).collect();
            assert_eq!(steps, vec![(Some("new"), Some("under_review")), (Some("under_review"), Some("confirmed")), (Some("confirmed"), Some("resolved")), (Some("resolved"), Some("reopened"))]);
            assert_eq!(h[1].source, "mcp");
            assert_eq!(h.last().unwrap().kind, "note");
            assert!(set_status(c, 999, "new", "", "user").is_err());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn links_stay_within_the_project_and_survive_deleted_records() {
        let db = Db::open_in_memory().unwrap();
        let (p, other, f) = setup(&db);
        db.with(|c| {
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','t')", params![p])?;
            let run = c.last_insert_rowid();
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','t')", params![other])?;
            let foreign = c.last_insert_rowid();
            c.execute("INSERT INTO executions (tool_id, kind, program, args, status, started_at) VALUES ('nmap','run','nmap','[]','succeeded','t')", [])?;
            let unassigned = c.last_insert_rowid();
            assert!(link(c, f, "execution", run, "user")?);
            assert!(!link(c, f, "execution", run, "user")?, "linking twice changes nothing");
            assert!(link(c, f, "execution", foreign, "user").is_err());
            assert!(link(c, f, "execution", unassigned, "user").is_err());
            assert!(link(c, f, "execution", 12345, "user").is_err());
            assert!(link(c, f, "vulnerability", 1, "user").is_err(), "no such vulnerability");
            assert!(link(c, f, "nonsense", run, "user").is_err());
            assert_eq!(links(c, f)?[0].label.as_deref(), Some(format!("nmap run #{run}").as_str()));
            c.execute("DELETE FROM executions WHERE id = ?1", params![run])?;
            assert_eq!(links(c, f)?[0].label, None, "a deleted record shows as missing instead of breaking the finding");
            assert!(unlink(c, f, "execution", run, "user")?);
            assert!(links(c, f)?.is_empty());
            let kinds: Vec<String> = history(c, f)?.into_iter().map(|e| e.kind).collect();
            assert_eq!(kinds, vec!["link", "unlink"]);
            Ok(())
        })
        .unwrap();
    }
}
