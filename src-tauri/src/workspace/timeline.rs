//! Project timeline: one chronological view over what already records time (tool runs, finding
//! history, scope changes, evidence, OSINT events of linked investigations, discovery snapshots)
//! plus `timeline_events` for event types that have no table of their own. Nothing is copied:
//! the view is a query, so history stays in the records it belongs to.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::{validation, AppResult};
use crate::util::now;

pub const TYPES: &[&str] = &["execution", "finding", "vulnerability", "scope", "evidence", "investigation", "discovery", "asset", "workflow", "remediation", "report", "note", "utility", "checklist", "correlation"];

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
    /// when the source observed or collected what the event is about, when that is known and
    /// differs from when Cyber Hub recorded it (evidence collected earlier)
    pub observed_at: Option<String>,
    /// where the next page starts (`before`): unique, so events of the same second are not skipped
    pub cursor: String,
}

/// Which events to return: types, a record, text, a time range, a page.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    #[serde(default)]
    pub types: Vec<String>,
    /// the `cursor` of the last event of the previous page, or a time
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    /// events about one record (`finding`, `asset`, `evidence`, `vulnerability`, `execution`…)
    #[serde(default)]
    pub ref_kind: Option<String>,
    #[serde(default)]
    pub ref_id: Option<i64>,
    /// words in the title or the detail
    #[serde(default)]
    pub search: Option<String>,
    /// events at or after this time (or date)
    #[serde(default)]
    pub from: Option<String>,
    /// events before this time (or date)
    #[serde(default)]
    pub to: Option<String>,
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

/// The newest `limit` events, optionally limited to some types. `before` is the `cursor` of the
/// last event of the previous page (or a time: events before it). Events are ordered by time, then
/// by source and row, so a page boundary inside one second skips nothing.
pub fn project_timeline(c: &Connection, project_id: i64, types: &[String], before: Option<&str>, limit: i64) -> AppResult<Vec<TimelineEvent>> {
    query(c, project_id, &Query { types: types.to_vec(), before: before.map(str::to_string), limit: Some(limit), ..Default::default() })
}

/// Events about one record of the investigation layer (`relations::Ref`), newest first.
pub fn events_about(c: &Connection, project_id: i64, r: &crate::workspace::relations::Ref, limit: i64) -> AppResult<Vec<TimelineEvent>> {
    let kind = match r.kind.as_str() {
        "finding" | "asset" | "evidence" | "vulnerability" | "execution" => r.kind.clone(),
        _ => return Ok(Vec::new()),
    };
    query(c, project_id, &Query { ref_kind: Some(kind), ref_id: Some(r.id), limit: Some(limit), ..Default::default() })
}

pub fn query(c: &Connection, project_id: i64, q: &Query) -> AppResult<Vec<TimelineEvent>> {
    let types = &q.types;
    for t in types {
        if !TYPES.contains(&t.as_str()) {
            return Err(validation(format!("Unknown timeline event type '{t}'")));
        }
    }
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let search = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let (before_at, before_src, before_rid): (Option<&str>, Option<&str>, Option<i64>) = match q.before.as_deref().map(|b| b.splitn(3, '|').collect::<Vec<_>>()) {
        None => (None, None, None),
        Some(parts) if parts.len() == 3 => (Some(parts[0]), Some(parts[1]), Some(parts[2].parse().map_err(|_| validation("Invalid timeline cursor"))?)),
        Some(_) => (q.before.as_deref(), None, None),
    };
    let types_json = (!types.is_empty()).then(|| serde_json::to_string(types).unwrap_or_default());
    let sql = "
        SELECT type, title, detail, ref_kind, ref_id, at, src, rid, observed FROM (
            SELECT type, title, detail, ref_kind, ref_id, at, 'a' AS src, id AS rid, NULL AS observed FROM timeline_events WHERE project_id = ?1
          UNION ALL
            SELECT 'execution',
                   CASE kind WHEN 'install' THEN 'Installed ' ELSE 'Ran ' END || tool_id || ' (' || status || ')',
                   program, 'execution', id, started_at, 'b', id, NULL
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
                   e.note, 'finding', f.id, e.at, 'c', e.id, NULL
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
                   e.note, 'vulnerability', v.id, e.at, 'd', e.id, NULL
            FROM vulnerability_events e JOIN vulnerabilities v ON v.id = e.vulnerability_id WHERE e.project_id = ?1
          UNION ALL
            SELECT 'scope',
                   CASE action WHEN 'added' THEN 'Scope ' || CASE in_scope WHEN 0 THEN 'exclusion added: ' ELSE 'entry added: ' END
                               WHEN 'updated' THEN 'Scope entry changed: '
                               WHEN 'removed' THEN 'Scope entry removed: '
                               ELSE 'Blocked (out of scope): ' END || value
                               || CASE WHEN repeats > 0 THEN ' (' || (repeats + 1) || ' attempts)' ELSE '' END,
                   note, 'scope', id, at, 'e', id, NULL
            FROM scope_events WHERE project_id = ?1
          UNION ALL
            SELECT 'evidence', 'Evidence added: ' || title, kind || CASE WHEN source_module <> '' THEN ' · ' || source_module ELSE '' END, 'evidence', id, created_at, 'f', id,
                   CASE WHEN collected_at IS NOT NULL AND collected_at <> created_at THEN collected_at END FROM evidence WHERE project_id = ?1
          UNION ALL
            SELECT 'investigation', i.name || ': ' || ev.summary, ev.kind, 'investigation', i.id, ev.at, 'g', ev.id, NULL
            FROM osint_events ev JOIN osint_investigations i ON i.id = ev.investigation_id WHERE i.project_id = ?1
          UNION ALL
            SELECT 'workflow', 'Workflow ' || w.name || ' (' || r.trigger || '): ' || r.status, r.summary, 'workflow_run', r.id, r.started_at, 'h', r.id, NULL
            FROM workflow_runs r JOIN workflows w ON w.id = r.workflow_id WHERE r.project_id = ?1
          UNION ALL
            SELECT 'discovery',
                   CASE source WHEN 'passive' THEN 'Passive discovery' WHEN 'http' THEN 'Web services check' WHEN 'nmap' THEN 'Service scan' ELSE 'Discovery' END || ': ' || status,
                   note, 'discovery', id, started_at, 'i', id, NULL
            FROM discovery_snapshots WHERE project_id = ?1
          UNION ALL
            SELECT 'correlation', summary, note, 'relation', relation_id, at, 'j', id, NULL FROM relation_events WHERE project_id = ?1
        )
        WHERE (?2 IS NULL OR at < ?2 OR (at = ?2 AND ?3 IS NOT NULL AND (src < ?3 OR (src = ?3 AND rid < ?4))))
          AND (?5 IS NULL OR type IN (SELECT value FROM json_each(?5)))
          AND (?7 IS NULL OR (ref_kind = ?7 AND ref_id = ?8))
          AND (?9 IS NULL OR instr(lower(title), lower(?9)) > 0 OR instr(lower(detail), lower(?9)) > 0)
          AND (?10 IS NULL OR at >= ?10)
          AND (?11 IS NULL OR at < ?11)
        ORDER BY at DESC, src DESC, rid DESC
        LIMIT ?6";
    let mut st = c.prepare(sql)?;
    let rows = st
        .query_map(params![project_id, before_at, before_src, before_rid, types_json, limit, q.ref_kind, q.ref_id, search, q.from, q.to], |r| {
            let (at, src, rid): (String, String, i64) = (r.get(5)?, r.get(6)?, r.get(7)?);
            Ok(TimelineEvent { kind: r.get(0)?, title: r.get(1)?, detail: r.get(2)?, ref_kind: r.get(3)?, ref_id: r.get(4)?, observed_at: r.get(8)?, cursor: format!("{at}|{src}|{rid}"), at })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
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
            // pages follow each other without gaps, also inside one second
            for i in 0..250 {
                c.execute("INSERT INTO timeline_events (project_id, type, title, at) VALUES (?1, 'asset', ?2, '2026-11-04T09:00:00Z')", params![p, format!("Asset {i}")])?;
            }
            let mut seen = Vec::new();
            let mut before: Option<String> = None;
            loop {
                let page = project_timeline(c, p, &[], before.as_deref(), 100)?;
                if page.is_empty() {
                    break;
                }
                before = page.last().map(|e| e.cursor.clone());
                seen.extend(page.into_iter().map(|e| e.title));
            }
            assert_eq!(seen.len(), 255, "every event once");
            assert_eq!(seen.iter().collect::<std::collections::BTreeSet<_>>().len(), 255);
            // a type filter finds its events behind many newer ones of other types
            let scope = project_timeline(c, p, &["scope".into()], None, 10)?;
            assert_eq!(scope.len(), 1, "{scope:?}");
            assert!(project_timeline(c, p, &[], Some("x|a|notanumber"), 10).is_err());
            assert!(project_timeline(c, p, &["nope".into()], None, 10).is_err());
            assert_eq!(project_timeline(c, other, &[], None, 10)?.len(), 1, "other projects stay separate");
            Ok(())
        })
        .unwrap();
    }
}
