//! Project timeline: one chronological view over what already records time (tool runs, finding
//! history, scope changes, evidence, OSINT events of linked investigations, discovery snapshots)
//! plus `timeline_events` for event types that have no table of their own. Nothing is copied:
//! the view is a query, so history stays in the records it belongs to.

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::{validation, AppResult};
use crate::util::now;

pub const TYPES: &[&str] = &["execution", "finding", "vulnerability", "scope", "evidence", "investigation", "discovery", "asset", "workflow", "remediation", "report", "note"];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub ref_kind: Option<String>,
    pub ref_id: Option<i64>,
    pub at: String,
}

/// Records an event that has no table of its own (asset discoveries, workflow runs, reports…).
pub fn record(c: &Connection, project_id: i64, kind: &str, title: &str, detail: &str, ref_kind: Option<&str>, ref_id: Option<i64>) -> AppResult<()> {
    if !TYPES.contains(&kind) {
        return Err(validation(format!("Unknown timeline event type '{kind}'")));
    }
    let title: String = title.chars().take(300).collect();
    let detail: String = detail.chars().take(2000).collect();
    c.execute(
        "INSERT INTO timeline_events (project_id, type, title, detail, ref_kind, ref_id, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![project_id, kind, title, detail, ref_kind, ref_id, now()],
    )?;
    Ok(())
}

/// The newest `limit` events (before `before`, when given), optionally limited to some types.
pub fn project_timeline(c: &Connection, project_id: i64, types: &[String], before: Option<&str>, limit: i64) -> AppResult<Vec<TimelineEvent>> {
    for t in types {
        if !TYPES.contains(&t.as_str()) {
            return Err(validation(format!("Unknown timeline event type '{t}'")));
        }
    }
    let limit = limit.clamp(1, 1000);
    let sql = "
        SELECT type, title, detail, ref_kind, ref_id, at FROM (
            SELECT type, title, detail, ref_kind, ref_id, at FROM timeline_events WHERE project_id = ?1
          UNION ALL
            SELECT 'execution',
                   CASE kind WHEN 'install' THEN 'Installed ' ELSE 'Ran ' END || tool_id || ' (' || status || ')',
                   program, 'execution', id, started_at
            FROM executions WHERE project_id = ?1
          UNION ALL
            SELECT 'finding',
                   CASE e.kind
                     WHEN 'created' THEN 'Finding recorded: ' || f.title
                     WHEN 'status' THEN 'Finding ' || COALESCE(e.from_status, '?') || ' → ' || COALESCE(e.to_status, '?') || ': ' || f.title
                     WHEN 'migrated' THEN 'Finding status migrated: ' || f.title
                     WHEN 'note' THEN 'Note on finding: ' || f.title
                     WHEN 'link' THEN 'Finding linked: ' || f.title
                     WHEN 'unlink' THEN 'Finding unlinked: ' || f.title
                     ELSE 'Finding updated: ' || f.title END,
                   e.note, 'finding', f.id, e.at
            FROM finding_events e JOIN findings f ON f.id = e.finding_id WHERE e.project_id = ?1
          UNION ALL
            SELECT CASE WHEN e.kind IN ('remediation','verification') THEN 'remediation' ELSE 'vulnerability' END,
                   CASE e.kind
                     WHEN 'created' THEN 'Vulnerability tracked: ' || v.cve_id
                     WHEN 'status' THEN v.cve_id || ': ' || COALESCE(e.from_value, '?') || ' → ' || COALESCE(e.to_value, '?')
                     WHEN 'priority' THEN v.cve_id || ' priority ' || upper(COALESCE(e.from_value, '?')) || ' → ' || upper(COALESCE(e.to_value, '?'))
                     WHEN 'remediation' THEN 'Remediation plan for ' || v.cve_id
                     WHEN 'verification' THEN 'Fix verified: ' || v.cve_id
                     ELSE v.cve_id || ' updated' END,
                   e.note, 'vulnerability', v.id, e.at
            FROM vulnerability_events e JOIN vulnerabilities v ON v.id = e.vulnerability_id WHERE e.project_id = ?1
          UNION ALL
            SELECT 'scope',
                   CASE action WHEN 'added' THEN 'Scope ' || CASE in_scope WHEN 0 THEN 'exclusion added: ' ELSE 'entry added: ' END
                               WHEN 'updated' THEN 'Scope entry changed: '
                               WHEN 'removed' THEN 'Scope entry removed: '
                               ELSE 'Blocked (out of scope): ' END || value,
                   note, 'scope', id, at
            FROM scope_events WHERE project_id = ?1
          UNION ALL
            SELECT 'evidence', 'Evidence added: ' || title, kind, 'evidence', id, created_at FROM evidence WHERE project_id = ?1
          UNION ALL
            SELECT 'investigation', i.name || ': ' || ev.summary, ev.kind, 'investigation', i.id, ev.at
            FROM osint_events ev JOIN osint_investigations i ON i.id = ev.investigation_id WHERE i.project_id = ?1
          UNION ALL
            SELECT 'discovery', 'Discovery (' || mode || ', ' || source || '): ' || status, note, 'discovery', id, started_at
            FROM discovery_snapshots WHERE project_id = ?1
        )
        WHERE (?2 IS NULL OR at < ?2)
        ORDER BY at DESC
        LIMIT ?3";
    let mut st = c.prepare(sql)?;
    let rows = st
        .query_map(params![project_id, before, if types.is_empty() { limit } else { limit * 20 }], |r| {
            Ok(TimelineEvent { kind: r.get(0)?, title: r.get(1)?, detail: r.get(2)?, ref_kind: r.get(3)?, ref_id: r.get(4)?, at: r.get(5)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows.into_iter().filter(|e| types.is_empty() || types.contains(&e.kind)).take(limit as usize).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn the_timeline_merges_every_source_in_order_and_filters_by_type() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Other','active','t','t')", [])?;
            let other = c.last_insert_rowid();
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','2026-11-01T10:00:00Z')", params![p])?;
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','2026-11-01T10:00:00Z')", params![other])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1,'XSS','high','new','2026-11-02T10:00:00Z','2026-11-02T10:00:00Z')", params![p])?;
            let f = c.last_insert_rowid();
            c.execute("INSERT INTO finding_events (finding_id, project_id, kind, to_status, at) VALUES (?1, ?2, 'created', 'new', '2026-11-02T10:00:00Z')", params![f, p])?;
            c.execute("INSERT INTO scope_events (project_id, action, value, kind, in_scope, at) VALUES (?1,'added','example.com','domain',1,'2026-10-31T09:00:00Z')", params![p])?;
            c.execute("INSERT INTO osint_investigations (name, target_type, target_value, project_id, created_at, updated_at) VALUES ('Map','domain','example.com',?1,'t','t')", params![p])?;
            let inv = c.last_insert_rowid();
            c.execute("INSERT INTO osint_events (investigation_id, at, kind, summary) VALUES (?1, '2026-11-03T08:00:00Z', 'import', 'Imported 7 results')", params![inv])?;
            record(c, p, "report", "Report generated", "", None, None)?;
            assert!(record(c, p, "bogus", "x", "", None, None).is_err());

            let all = project_timeline(c, p, &[], None, 100)?;
            assert_eq!(all.len(), 5);
            assert_eq!(all[0].kind, "report", "newest first");
            let kinds: Vec<&str> = all.iter().map(|e| e.kind.as_str()).collect();
            assert_eq!(&kinds[1..], &["investigation", "finding", "execution", "scope"]);
            assert_eq!(all[2].title, "Finding recorded: XSS");
            let only = project_timeline(c, p, &["scope".into(), "execution".into()], None, 100)?;
            assert_eq!(only.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), vec!["execution", "scope"]);
            let page = project_timeline(c, p, &[], Some("2026-11-02T10:00:00Z"), 100)?;
            assert_eq!(page.len(), 2, "paging by time");
            assert!(project_timeline(c, p, &["nope".into()], None, 10).is_err());
            assert_eq!(project_timeline(c, other, &[], None, 10)?.len(), 1, "other projects stay separate");
            Ok(())
        })
        .unwrap();
    }
}
