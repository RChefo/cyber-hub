//! Projects workspace: assessments, authorized scope, findings.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::activity::log;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::scope::{self, ScopeEntry};
use crate::util::{clean, now, one_of};
use crate::workspace::findings::{self as lifecycle, OPEN_SQL};

const STATUSES: &[&str] = &["planning", "active", "paused", "completed", "archived"];
pub const ENGAGEMENT_TYPES: &[&str] = &["", "external", "internal", "web_application", "api", "cloud", "mobile", "wireless", "red_team", "osint", "other"];
const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub status: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub target_count: i64,
    pub finding_count: i64,
    pub open_findings: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub id: i64,
    pub value: String,
    pub kind: String,
    pub in_scope: bool,
    pub note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub status: String,
    pub scope_notes: String,
    pub notes: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub client: String,
    pub engagement_type: String,
    /// reference of the written authorization (contract, ticket, letter)
    pub authorization_ref: String,
    pub objectives: String,
    pub methodology: String,
    /// who to contact, including in an emergency
    pub contacts: String,
    pub created_at: String,
    pub updated_at: String,
    pub targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInput {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub status: String,
    #[serde(default)]
    pub scope_notes: String,
    #[serde(default)]
    pub notes: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub engagement_type: String,
    #[serde(default)]
    pub authorization_ref: String,
    #[serde(default)]
    pub objectives: String,
    #[serde(default)]
    pub methodology: String,
    #[serde(default)]
    pub contacts: String,
}

fn date_opt(field: &str, v: &Option<String>) -> AppResult<Option<String>> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(d) => {
            chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| validation(format!("{field} must be YYYY-MM-DD")))?;
            Ok(Some(d.to_string()))
        }
    }
}

#[tauri::command]
pub async fn projects_list(db: State<'_, Db>) -> AppResult<Vec<ProjectSummary>> {
    db.with(|c| {
        let mut stmt = c.prepare(&format!(
            "SELECT p.id, p.name, p.description, p.status, p.start_date, p.end_date,
                (SELECT COUNT(*) FROM project_targets t WHERE t.project_id = p.id),
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id),
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.status IN {OPEN_SQL}),
                p.created_at, p.updated_at
             FROM projects p ORDER BY p.updated_at DESC"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ProjectSummary {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    status: r.get(3)?,
                    start_date: r.get(4)?,
                    end_date: r.get(5)?,
                    target_count: r.get(6)?,
                    finding_count: r.get(7)?,
                    open_findings: r.get(8)?,
                    created_at: r.get(9)?,
                    updated_at: r.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

pub fn load_targets(c: &Connection, project_id: i64) -> AppResult<Vec<Target>> {
    let mut stmt = c.prepare(
        "SELECT id, value, kind, in_scope, note FROM project_targets WHERE project_id = ?1 ORDER BY in_scope DESC, value",
    )?;
    let rows = stmt
        .query_map(params![project_id], |r| {
            Ok(Target {
                id: r.get(0)?,
                value: r.get(1)?,
                kind: r.get(2)?,
                in_scope: r.get::<_, i64>(3)? != 0,
                note: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn scope_entries(c: &Connection, project_id: i64) -> AppResult<Vec<ScopeEntry>> {
    Ok(load_targets(c, project_id)?
        .into_iter()
        .map(|t| ScopeEntry { value: t.value, kind: t.kind, in_scope: t.in_scope })
        .collect())
}

#[tauri::command]
pub async fn project_get(db: State<'_, Db>, id: i64) -> AppResult<Project> {
    db.with(|c| project_load(c, id))
}

pub(crate) fn project_load(c: &Connection, id: i64) -> AppResult<Project> {
    {
        let p = c
            .query_row(
                "SELECT id, name, description, status, scope_notes, notes, start_date, end_date, created_at, updated_at,
                        client, engagement_type, authorization_ref, objectives, methodology, contacts FROM projects WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Project {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        description: r.get(2)?,
                        status: r.get(3)?,
                        scope_notes: r.get(4)?,
                        notes: r.get(5)?,
                        start_date: r.get(6)?,
                        end_date: r.get(7)?,
                        created_at: r.get(8)?,
                        updated_at: r.get(9)?,
                        client: r.get(10)?,
                        engagement_type: r.get(11)?,
                        authorization_ref: r.get(12)?,
                        objectives: r.get(13)?,
                        methodology: r.get(14)?,
                        contacts: r.get(15)?,
                        targets: vec![],
                    })
                },
            )
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("project {id}")))?;
        let targets = load_targets(c, id)?;
        Ok(Project { targets, ..p })
    }
}

/// Statuses of an engagement that has ended. Leaving them reopens it (Mission 8).
const CLOSED: &[&str] = &["completed", "archived"];

/// The native question before a completed or archived project is reopened (Mission 8): reopened,
/// its scope can be used again, by the HTTP request builder and the TLS analyzer without a dialog
/// per request, and by MCP clients. A compromised page could otherwise reopen an ended engagement
/// by itself.
fn reopen_question(name: &str, before: &str, after: &str, in_scope: i64, excluded: i64) -> String {
    format!(
        "Reopen the project “{name}”? It is {before}.\n\nAs {after}, its scope can be used again ({in_scope} in-scope {}, {excluded} {}): the HTTP request builder and the TLS analyzer send requests to an active project's targets without asking each time, and MCP clients can change the project. Every tool run still asks for its own confirmation.",
        if in_scope == 1 { "entry" } else { "entries" },
        if excluded == 1 { "exclusion" } else { "exclusions" },
    )
}

#[tauri::command]
pub async fn project_upsert(app: tauri::AppHandle, db: State<'_, Db>, input: ProjectInput) -> AppResult<i64> {
    let name = clean("Project name", &input.name, 120, true)?;
    let description = clean("Description", &input.description, 2000, false)?;
    let status = one_of("Status", &input.status, STATUSES)?;
    let scope_notes = clean("Rules of engagement", &input.scope_notes, 10000, false)?;
    let notes = clean("Notes", &input.notes, 100_000, false)?;
    let start = date_opt("Start date", &input.start_date)?;
    let end = date_opt("End date", &input.end_date)?;
    let client = clean("Client", &input.client, 200, false)?;
    let engagement_type = one_of("Engagement type", &input.engagement_type, ENGAGEMENT_TYPES)?;
    let authorization_ref = clean("Authorization reference", &input.authorization_ref, 300, false)?;
    let objectives = clean("Objectives", &input.objectives, 10_000, false)?;
    let methodology = clean("Methodology", &input.methodology, 10_000, false)?;
    let contacts = clean("Contacts", &input.contacts, 5_000, false)?;
    if let (Some(s), Some(e)) = (&start, &end) {
        if e < s {
            return Err(validation("End date must be after the start date"));
        }
    }
    let ts = now();
    // reopening an ended engagement is decided outside the page (Mission 8); the status asked
    // about must still be the project's when it is saved
    let before = match input.id {
        Some(id) => {
            let (stored_name, before, in_scope, excluded) = db.with(|c| {
                let row: Option<(String, String)> = c.query_row("SELECT name, status FROM projects WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
                let (stored_name, before) = row.ok_or_else(|| AppError::NotFound(format!("project {id}")))?;
                let (in_scope, excluded): (i64, i64) = c.query_row(
                    "SELECT COALESCE(SUM(in_scope != 0), 0), COALESCE(SUM(in_scope = 0), 0) FROM project_targets WHERE project_id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                Ok((stored_name, before, in_scope, excluded))
            })?;
            if CLOSED.contains(&before.as_str()) && !CLOSED.contains(&status.as_str()) {
                let question = reopen_question(&stored_name, &before, &status, in_scope, excluded);
                if !crate::confirm::native(&app, "Reopen a project", question, "Reopen").await {
                    return Err(AppError::Cancelled(format!("The project stays {before}")));
                }
            }
            Some(before)
        }
        None => None,
    };
    db.with(|c| match input.id {
        Some(id) => {
            let before = before.unwrap_or_default();
            let tx = c.unchecked_transaction()?;
            let changed = tx.execute(
                "UPDATE projects SET name=?2, description=?3, status=?4, scope_notes=?5, notes=?6, start_date=?7, end_date=?8, updated_at=?9,
                     client=?10, engagement_type=?11, authorization_ref=?12, objectives=?13, methodology=?14, contacts=?15 WHERE id=?1 AND status=?16",
                params![id, name, description, status, scope_notes, notes, start, end, ts, client, engagement_type, authorization_ref, objectives, methodology, contacts, before],
            )?;
            if changed == 0 {
                return Err(validation("The project's status changed while it was being saved; review the project and save again"));
            }
            // a status change (active, completed, archived…) changes what may run against the project
            if before != status {
                let what = format!("Project status changed: {before} → {status}");
                crate::workspace::timeline::record(&tx, id, "note", &what, "", None, None)?;
                log(&tx, "project", &format!("{what} (“{name}”)"), "", Some("project"), Some(&id.to_string()), Some(id))?;
            }
            tx.commit()?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO projects (name, description, status, scope_notes, notes, start_date, end_date, created_at, updated_at,
                     client, engagement_type, authorization_ref, objectives, methodology, contacts) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,?9,?10,?11,?12,?13,?14)",
                params![name, description, status, scope_notes, notes, start, end, ts, client, engagement_type, authorization_ref, objectives, methodology, contacts],
            )?;
            let id = c.last_insert_rowid();
            log(c, "project", &format!("Created project “{name}”"), "", Some("project"), Some(&id.to_string()), Some(id))?;
            Ok(id)
        }
    })
}

#[tauri::command]
pub async fn project_delete(app: tauri::AppHandle, db: State<'_, Db>, id: i64) -> AppResult<()> {
    use tauri::Manager;
    // deleting a project cannot be undone: the analyst confirms it outside the page, with what is
    // lost (Mission 7)
    let summary = db.with(|c| {
        let Some(name) = c.query_row("SELECT name FROM projects WHERE id = ?1", params![id], |r| r.get::<_, String>(0)).optional()? else {
            return Ok(None);
        };
        refuse_running(c, id, &name)?;
        let count = |sql: &str| -> rusqlite::Result<i64> { c.query_row(sql, params![id], |r| r.get(0)) };
        let findings = count("SELECT COUNT(*) FROM findings WHERE project_id = ?1")?;
        let evidence = count("SELECT COUNT(*) FROM evidence WHERE project_id = ?1")?;
        let targets = count("SELECT COUNT(*) FROM project_targets WHERE project_id = ?1")?;
        Ok(Some((name, findings, evidence, targets)))
    })?;
    let Some((name, findings, evidence, targets)) = summary else {
        return Ok(());
    };
    let n = |count: i64, one: &str, many: &str| format!("{count} {}", if count == 1 { one } else { many });
    if !crate::confirm::native(
        &app,
        "Delete a project",
        format!(
            "Delete the project “{name}” permanently?\n\nIts {}, {} and {} are deleted with its other records, and evidence files that no other record uses are removed. Tool runs and the activity log are kept, without the project. This cannot be undone.",
            n(findings, "finding", "findings"),
            n(evidence, "evidence record", "evidence records"),
            n(targets, "scope entry", "scope entries")
        ),
        "Delete project",
    )
    .await
    {
        return Err(AppError::Cancelled("The project was not deleted".into()));
    }
    let dir = crate::util::data_dir(&app)?;
    let store = app.state::<std::sync::Arc<crate::workspace::evidence::EvidenceStore>>();
    db.with(|c| {
        let orphaned = delete_project(c, id)?;
        // still under the database lock; not while a restore is sorted, when some files belong to
        // the previous database (the start-up sweep handles them later)
        if !crate::restore::sorting_evidence(&dir) {
            for sha in orphaned {
                store.remove_unreferenced(c, &sha);
            }
        }
        Ok(())
    })
}

/// What still runs for a project: tool runs, workflow runs and discovery.
pub(crate) fn running_work(c: &Connection, project_id: i64) -> AppResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let queries = [
        "SELECT tool_id || ' run #' || id FROM executions WHERE project_id = ?1 AND status = 'running' ORDER BY id",
        "SELECT 'workflow ' || w.name || ' (run #' || r.id || ')' FROM workflow_runs r JOIN workflows w ON w.id = r.workflow_id WHERE r.project_id = ?1 AND r.status = 'running' ORDER BY r.id",
        "SELECT source || ' discovery #' || id FROM discovery_snapshots WHERE project_id = ?1 AND status = 'running' ORDER BY id",
    ];
    for sql in queries {
        let mut st = c.prepare(sql)?;
        for row in st.query_map(params![project_id], |r| r.get::<_, String>(0))? {
            out.push(row?);
        }
    }
    Ok(out)
}

/// Refuses while work still runs for a project (its results would have nowhere to go).
fn refuse_running(c: &Connection, id: i64, name: &str) -> AppResult<()> {
    let running = running_work(c, id)?;
    if running.is_empty() {
        return Ok(());
    }
    let more = if running.len() > 5 { format!(" and {} more", running.len() - 5) } else { String::new() };
    Err(validation(format!(
        "Project “{name}” still has work running: {}{more}. Stop it or wait for it to finish, then delete the project.",
        running.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
    )))
}

/// Deletes a project and everything it owns, in one transaction, unless work still runs for it
/// (its results would have nowhere to go). Tool runs, command history, activity entries and OSINT
/// investigations are not project records: they stay, with no project. Returns the SHA-256 of
/// evidence files that no record refers to any more.
pub(crate) fn delete_project(c: &Connection, id: i64) -> AppResult<Vec<String>> {
    let tx = c.unchecked_transaction()?;
    let Some(name) = tx.query_row("SELECT name FROM projects WHERE id = ?1", params![id], |r| r.get::<_, String>(0)).optional()? else {
        return Ok(Vec::new());
    };
    refuse_running(&tx, id, &name)?;
    let files: Vec<String> = tx
        .prepare("SELECT DISTINCT sha256 FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 IS NOT NULL")?
        .query_map(params![id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    tx.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
    log(&tx, "project", &format!("Deleted project “{name}”"), "", None, None, None)?;
    let mut orphaned = Vec::new();
    for sha in files {
        let used: i64 = tx.query_row("SELECT COUNT(*) FROM evidence WHERE kind = 'file' AND sha256 = ?1", params![sha], |r| r.get(0))?;
        if used == 0 {
            orphaned.push(sha);
        }
    }
    tx.commit()?;
    Ok(orphaned)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInput {
    pub value: String,
    #[serde(default = "default_true")]
    pub in_scope: bool,
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

/// Validate a scope value without saving (used for live form feedback).
#[tauri::command]
pub async fn scope_classify(value: String) -> AppResult<(String, String)> {
    let (v, k) = scope::classify(&value)?;
    Ok((v, k.to_string()))
}

#[tauri::command]
pub async fn project_target_add(app: tauri::AppHandle, db: State<'_, Db>, project_id: i64, input: TargetInput) -> AppResult<i64> {
    let (value, kind) = scope::classify(&input.value)?;
    let note = clean("Note", &input.note, 300, false)?;
    // authorizing non-public addresses lets the project's tools and requests reach the analyst's
    // own network and cloud metadata services: confirmed outside the web page (Mission 7)
    if input.in_scope && scope::covers_non_public(&value, kind) {
        let (name, already): (String, bool) = db.with(|c| {
            let name: String = c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0)).optional()?.ok_or_else(|| validation("Unknown project"))?;
            let already = c.query_row("SELECT in_scope FROM project_targets WHERE project_id = ?1 AND value = ?2", params![project_id, value], |r| r.get::<_, i64>(0)).optional()? == Some(1);
            Ok((name, already))
        })?;
        if !already
            && !crate::confirm::native(
                &app,
                "Authorize internal addresses",
                format!("Add {value} to the scope of the project “{name}”?\n\nIt covers addresses that are not on the public Internet: your own network, this computer, or cloud metadata services (169.254.169.254). The project's tools and HTTP requests will be able to reach them."),
                "Authorize",
            )
            .await
        {
            return Err(AppError::Cancelled("The scope was not changed".into()));
        }
    }
    db.with(|c| target_add(c, project_id, &value, kind, input.in_scope, &note))
}

/// Adds or changes a scope entry and records the change in the project's scope history.
pub(crate) fn target_add(c: &Connection, project_id: i64, value: &str, kind: &str, in_scope: bool, note: &str) -> AppResult<i64> {
    let tx = c.unchecked_transaction()?;
    let before: Option<(i64, bool, String)> = tx
        .query_row("SELECT id, in_scope, note FROM project_targets WHERE project_id=?1 AND value=?2", params![project_id, value], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?)))
        .optional()?;
    let ts = now();
    let id = match &before {
        Some((id, ..)) => {
            tx.execute("UPDATE project_targets SET in_scope=?2, note=?3 WHERE id=?1", params![id, in_scope as i64, note])?;
            *id
        }
        None => {
            tx.execute(
                "INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![project_id, value, kind, in_scope as i64, note, ts],
            )?;
            tx.last_insert_rowid()
        }
    };
    let action = match &before {
        None => Some("added"),
        Some((_, was, old_note)) if *was != in_scope || old_note != note => Some("updated"),
        Some(_) => None,
    };
    if let Some(action) = action {
        tx.execute(
            "INSERT INTO scope_events (project_id, action, value, kind, in_scope, note, source, at) VALUES (?1,?2,?3,?4,?5,?6,'user',?7)",
            params![project_id, action, value, kind, in_scope as i64, note, ts],
        )?;
    }
    tx.execute("UPDATE projects SET updated_at=?2 WHERE id=?1", params![project_id, ts])?;
    tx.commit()?;
    Ok(id)
}

#[tauri::command]
pub async fn project_target_delete(app: tauri::AppHandle, db: State<'_, Db>, id: i64) -> AppResult<()> {
    // removing an exclusion widens the scope: confirmed outside the web page (Mission 7)
    let exclusion: Option<(String, String)> = db.with(|c| {
        Ok(c.query_row("SELECT t.value, p.name FROM project_targets t JOIN projects p ON p.id = t.project_id WHERE t.id = ?1 AND t.in_scope = 0", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    })?;
    if let Some((value, name)) = exclusion {
        if !crate::confirm::native(
            &app,
            "Remove an exclusion",
            format!("Remove the exclusion of {value} from the project “{name}”?\n\nWhatever the rest of the scope covers, the project's tools and requests will then be able to reach it."),
            "Remove exclusion",
        )
        .await
        {
            return Err(AppError::Cancelled("The scope was not changed".into()));
        }
    }
    db.with(|c| target_delete(c, id))
}

/// Removes a scope entry; the removal stays in the project's scope history.
pub(crate) fn target_delete(c: &Connection, id: i64) -> AppResult<()> {
    let tx = c.unchecked_transaction()?;
    let row: Option<(i64, String, String, bool)> = tx
        .query_row("SELECT project_id, value, kind, in_scope FROM project_targets WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? != 0)))
        .optional()?;
    if let Some((project_id, value, kind, in_scope)) = row {
        let ts = now();
        tx.execute("DELETE FROM project_targets WHERE id=?1", params![id])?;
        tx.execute(
            "INSERT INTO scope_events (project_id, action, value, kind, in_scope, source, at) VALUES (?1,'removed',?2,?3,?4,'user',?5)",
            params![project_id, value, kind, in_scope as i64, ts],
        )?;
        tx.execute("UPDATE projects SET updated_at=?2 WHERE id=?1", params![project_id, ts])?;
    }
    tx.commit()?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCheck {
    pub target: String,
    pub allowed: bool,
    pub reason: String,
}

/// Check arbitrary targets against a project's scope (used by the UI before execution).
#[tauri::command]
pub async fn scope_check(db: State<'_, Db>, project_id: i64, targets: Vec<String>) -> AppResult<Vec<ScopeCheck>> {
    let entries = db.with(|c| scope_entries(c, project_id))?;
    Ok(targets
        .into_iter()
        .take(200)
        .map(|raw| match scope::parse_target(&raw) {
            None => ScopeCheck { target: raw, allowed: false, reason: "Not a recognizable host, IP, CIDR or URL".into() },
            Some(t) => match scope::check_target(&entries, &t) {
                Ok(()) => ScopeCheck { target: raw, allowed: true, reason: "In scope".into() },
                Err(reason) => ScopeCheck { target: raw, allowed: false, reason },
            },
        })
        .collect())
}

/* ─────────────── findings ─────────────── */

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub label: String,
    pub reference: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: i64,
    pub project_id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub category: String,
    pub confidence: String,
    pub description: String,
    pub affected_target: String,
    pub cve: String,
    /// Free-form references (labels and paths/URLs) kept from earlier versions; stored evidence
    /// lives in the evidence registry and is attached through finding links.
    pub evidence: Vec<Evidence>,
    pub reproduction: String,
    pub technical_details: String,
    pub remediation: String,
    pub source: String,
    pub tags: Vec<String>,
    pub assignee: String,
    pub due_date: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// canonical CVSS v3.1 or v4.0 vector, empty when none was given
    pub cvss_vector: String,
    /// computed by the backend from `cvss_vector`
    pub cvss_score: Option<f64>,
}

/// Fields added after the first release default to empty, so older clients keep working.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingInput {
    pub id: Option<i64>,
    pub project_id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub affected_target: String,
    #[serde(default)]
    pub cve: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub reproduction: String,
    #[serde(default)]
    pub technical_details: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub due_date: Option<String>,
    /// CVSS v3.1 or v4.0 vector; the score is computed from it
    #[serde(default)]
    pub cvss_vector: String,
}

const FINDING_COLS: &str = "id, project_id, title, severity, status, category, confidence, description, affected_target, cve, evidence,
    reproduction, technical_details, remediation, source, tags, assignee, due_date, created_at, updated_at, cvss_vector, cvss_score";

fn finding_row(r: &rusqlite::Row) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: r.get(0)?,
        project_id: r.get(1)?,
        title: r.get(2)?,
        severity: r.get(3)?,
        status: r.get(4)?,
        category: r.get(5)?,
        confidence: r.get(6)?,
        description: r.get(7)?,
        affected_target: r.get(8)?,
        cve: r.get(9)?,
        evidence: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
        reproduction: r.get(11)?,
        technical_details: r.get(12)?,
        remediation: r.get(13)?,
        source: r.get(14)?,
        tags: serde_json::from_str(&r.get::<_, String>(15)?).unwrap_or_default(),
        assignee: r.get(16)?,
        due_date: r.get(17)?,
        created_at: r.get(18)?,
        updated_at: r.get(19)?,
        cvss_vector: r.get(20)?,
        cvss_score: r.get(21)?,
    })
}

pub(crate) fn finding_get(c: &Connection, id: i64) -> AppResult<Finding> {
    c.query_row(&format!("SELECT {FINDING_COLS} FROM findings WHERE id = ?1"), params![id], finding_row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("finding {id}")))
}

#[tauri::command]
pub async fn findings_list(db: State<'_, Db>, project_id: Option<i64>) -> AppResult<Vec<Finding>> {
    db.with(|c| {
        let mut stmt = c.prepare(&format!(
            "SELECT {FINDING_COLS} FROM findings WHERE (?1 IS NULL OR project_id = ?1)
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC"
        ))?;
        let rows = stmt.query_map(params![project_id], finding_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// All findings of a project, highest severity first.
pub(crate) fn findings_of(c: &Connection, project_id: i64) -> AppResult<Vec<Finding>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {FINDING_COLS} FROM findings WHERE project_id = ?1
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC"
    ))?;
    let rows = stmt.query_map(params![project_id], finding_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[tauri::command]
pub async fn finding_upsert(db: State<'_, Db>, input: FindingInput) -> AppResult<i64> {
    db.with(|c| finding_save(c, &input, "user"))
}

/// Validated finding in its stored form.
struct CleanFinding {
    title: String,
    severity: String,
    status: &'static str,
    category: String,
    confidence: String,
    description: String,
    affected: String,
    cve: String,
    evidence_json: String,
    reproduction: String,
    technical: String,
    remediation: String,
    tags_json: String,
    assignee: String,
    due_date: Option<String>,
    cvss_vector: String,
    cvss_score: Option<f64>,
}

fn clean_finding(input: &FindingInput) -> AppResult<CleanFinding> {
    if input.evidence.len() > 50 {
        return Err(validation("At most 50 evidence references"));
    }
    let mut evidence = Vec::new();
    for e in &input.evidence {
        evidence.push(Evidence {
            label: clean("Evidence label", &e.label, 200, true)?,
            reference: clean("Evidence reference", &e.reference, 2000, true)?,
        });
    }
    if input.tags.len() > 20 {
        return Err(validation("At most 20 tags"));
    }
    let mut tags: Vec<String> = Vec::new();
    for t in &input.tags {
        let t = clean("Tag", t, 40, true)?;
        if !tags.contains(&t) {
            tags.push(t);
        }
    }
    let confidence = input.confidence.as_deref().unwrap_or("medium");
    if !lifecycle::CONFIDENCES.contains(&confidence) {
        return Err(validation("Confidence must be low, medium or high"));
    }
    let (cvss_vector, cvss_score) = match input.cvss_vector.trim() {
        "" => (String::new(), None),
        v => {
            let c = crate::cvss::parse(v).map_err(|e| validation(format!("CVSS vector: {e}")))?;
            (c.vector, Some(c.score))
        }
    };
    let due_date = match input.due_date.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        None => None,
        Some(d) => Some(chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| validation("The due date must be a date (YYYY-MM-DD)"))?.to_string()),
    };
    Ok(CleanFinding {
        title: clean("Title", &input.title, 200, true)?,
        severity: one_of("Severity", &input.severity, SEVERITIES)?,
        status: lifecycle::status_or_err(&input.status)?,
        category: clean("Category", &input.category, 100, false)?,
        confidence: confidence.to_string(),
        description: clean("Description", &input.description, 50_000, false)?,
        affected: clean("Affected target", &input.affected_target, 500, false)?,
        cve: clean("CVE", &input.cve, 200, false)?.to_uppercase(),
        evidence_json: serde_json::to_string(&evidence)?,
        reproduction: clean("Reproduction steps", &input.reproduction, 50_000, false)?,
        technical: clean("Technical details", &input.technical_details, 50_000, false)?,
        remediation: clean("Remediation", &input.remediation, 50_000, false)?,
        tags_json: serde_json::to_string(&tags)?,
        assignee: clean("Assignee", &input.assignee, 100, false)?,
        due_date,
        cvss_vector,
        cvss_score,
    })
}

/// The checks a save makes, without saving (an MCP approval is only shown for a finding that
/// would be saved).
pub(crate) fn validate_finding(input: &FindingInput) -> AppResult<()> {
    clean_finding(input).map(|_| ())
}

/// Creates or updates a finding and records what changed in its history. `source` says who made
/// the change (`user`, `mcp`, …).
pub(crate) fn finding_save(c: &Connection, input: &FindingInput, source: &str) -> AppResult<i64> {
    let tx = c.unchecked_transaction()?;
    let id = finding_write(&tx, input, source, true)?;
    tx.commit()?;
    Ok(id)
}

/// [`finding_save`] without its own transaction, for callers that already hold one (imports).
/// `log_activity` adds the activity-log line for a new finding (bulk callers log once instead).
pub(crate) fn finding_write(tx: &Connection, input: &FindingInput, source: &str, log_activity: bool) -> AppResult<i64> {
    let f = clean_finding(input)?;
    let ts = now();
    let id = match input.id {
        Some(id) => {
            let old = finding_get(tx, id)?;
            if old.project_id != input.project_id {
                return Err(validation("A finding cannot be moved to another project"));
            }
            if old.status != f.status {
                lifecycle::transition_ok(&old.status, f.status).map_err(validation)?;
                // the editor meets the same rule as a status change
                if f.status == "accepted_risk" {
                    crate::workspace::risk::require_cover(tx, "finding", id)?;
                }
            }
            tx.execute(
                "UPDATE findings SET title=?2, severity=?3, status=?4, category=?5, confidence=?6, description=?7, affected_target=?8, cve=?9, evidence=?10,
                     reproduction=?11, technical_details=?12, remediation=?13, tags=?14, assignee=?15, due_date=?16, updated_at=?17, cvss_vector=?18, cvss_score=?19 WHERE id=?1",
                params![id, f.title, f.severity, f.status, f.category, f.confidence, f.description, f.affected, f.cve, f.evidence_json, f.reproduction, f.technical, f.remediation, f.tags_json, f.assignee, f.due_date, ts, f.cvss_vector, f.cvss_score],
            )?;
            let new = finding_get(tx, id)?;
            let changed = changed_fields(&old, &new);
            if !changed.is_empty() {
                lifecycle::record_event(tx, id, new.project_id, "updated", (None, None), &format!("Changed: {}", changed.join(", ")), source)?;
            }
            if old.status != new.status {
                lifecycle::record_event(tx, id, new.project_id, "status", (Some(&old.status), Some(&new.status)), "", source)?;
                if old.status == "accepted_risk" {
                    crate::workspace::risk::release(tx, "finding", id, "", &format!("its status became {}", new.status.replace('_', " ")), source)?;
                }
            }
            id
        }
        None => {
            // a new finding cannot already be an accepted risk: record it, then accept the risk
            if f.status == "accepted_risk" {
                return Err(validation(crate::workspace::risk::NOT_COVERED));
            }
            tx.execute(
                "INSERT INTO findings (project_id, title, severity, status, category, confidence, description, affected_target, cve, evidence,
                     reproduction, technical_details, remediation, source, tags, assignee, due_date, created_at, updated_at, cvss_vector, cvss_score)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?18,?19,?20)",
                params![input.project_id, f.title, f.severity, f.status, f.category, f.confidence, f.description, f.affected, f.cve, f.evidence_json, f.reproduction, f.technical, f.remediation, source, f.tags_json, f.assignee, f.due_date, ts, f.cvss_vector, f.cvss_score],
            )?;
            let id = tx.last_insert_rowid();
            lifecycle::record_event(tx, id, input.project_id, "created", (None, Some(f.status)), "", source)?;
            if log_activity {
                log(tx, "finding", &format!("Recorded {} finding “{}”", f.severity, f.title), "", Some("finding"), Some(&id.to_string()), Some(input.project_id))?;
            }
            id
        }
    };
    tx.execute("UPDATE projects SET updated_at=?2 WHERE id=?1", params![input.project_id, ts])?;
    Ok(id)
}

/// Names of the fields that differ (the status has its own history entry).
fn changed_fields(a: &Finding, b: &Finding) -> Vec<&'static str> {
    [
        ("title", a.title != b.title),
        ("severity", a.severity != b.severity),
        ("category", a.category != b.category),
        ("confidence", a.confidence != b.confidence),
        ("description", a.description != b.description),
        ("affected target", a.affected_target != b.affected_target),
        ("CVE", a.cve != b.cve),
        ("evidence references", serde_json::to_string(&a.evidence).ok() != serde_json::to_string(&b.evidence).ok()),
        ("reproduction steps", a.reproduction != b.reproduction),
        ("technical details", a.technical_details != b.technical_details),
        ("remediation", a.remediation != b.remediation),
        ("tags", a.tags != b.tags),
        ("assignee", a.assignee != b.assignee),
        ("due date", a.due_date != b.due_date),
        ("CVSS vector", a.cvss_vector != b.cvss_vector),
    ]
    .into_iter()
    .filter(|(_, d)| *d)
    .map(|(n, _)| n)
    .collect()
}

#[tauri::command]
pub async fn finding_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        // the finding's own history goes with it; the project timeline keeps that it existed
        if let Some((project_id, title, severity)) = tx
            .query_row("SELECT project_id, title, severity FROM findings WHERE id=?1", params![id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .optional()?
        {
            tx.execute("DELETE FROM findings WHERE id=?1", params![id])?;
            crate::workspace::timeline::record(&tx, project_id, "finding", &format!("Finding deleted: {title}"), &severity, None, None)?;
        }
        tx.commit()?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectExecution {
    pub id: i64,
    pub tool_id: String,
    pub kind: String,
    pub args: Vec<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[tauri::command]
pub async fn project_tool_history(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<ProjectExecution>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, tool_id, kind, args, status, exit_code, started_at, finished_at FROM executions WHERE project_id = ?1 ORDER BY id DESC LIMIT 200",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| {
                Ok(ProjectExecution {
                    id: r.get(0)?,
                    tool_id: r.get(1)?,
                    kind: r.get(2)?,
                    args: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
                    status: r.get(4)?,
                    exit_code: r.get(5)?,
                    started_at: r.get(6)?,
                    finished_at: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// MCP clients may not change an archived project (kept for reference); the analyst can, in the
/// app, or set another status first.
pub fn refuse_archived_for_clients(c: &Connection, project_id: i64) -> AppResult<()> {
    let status: Option<String> = c.query_row("SELECT status FROM projects WHERE id = ?1", params![project_id], |r| r.get(0)).optional()?;
    match status.as_deref() {
        None => Err(AppError::NotFound(format!("project {project_id}"))),
        Some("archived") => Err(validation(format!("Project #{project_id} is archived (kept for reference), so MCP clients cannot change it. Set another status in Cyber Hub first"))),
        Some(_) => Ok(()),
    }
}

/// Markdown report for a project (Projects → Export report, MCP, the workflow `save_report` step):
/// the same sections, terms and rules as the HTML report with its default options.
#[tauri::command]
pub async fn project_report(db: State<'_, Db>, id: i64) -> AppResult<String> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    db.with(|c| crate::workspace::report::markdown(c, id, &crate::workspace::report::ReportOptions::default(), &today))
}

/// Save a project report through a native save dialog. Returns the file name, or None if the
/// user cancelled.
#[tauri::command]
pub async fn project_report_export(app: tauri::AppHandle, db: State<'_, Db>, id: i64) -> AppResult<Option<String>> {
    use tauri::Manager;
    use tauri_plugin_dialog::DialogExt;
    let project = project_get(db.clone(), id).await?;
    let md = project_report(db, id).await?;
    let safe: String = project.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Export assessment report").set_file_name(format!("{safe}-report.md")).add_filter("Markdown", &["md"]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, md).map_err(|e| AppError::Internal(format!("Could not write the report: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| crate::workspace::timeline::record(c, id, "report", "Report exported (Markdown)", &file, None, None));
    Ok(Some(file))
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    /// Mission 7: widening the scope toward non-public space, or removing an exclusion, is
    /// confirmed in a native dialog; a page cannot authorize itself.
    #[test]
    fn widening_the_scope_is_confirmed_outside_the_page() {
        let src = include_str!("projects.rs");
        for (command, needle) in [("pub async fn project_target_add(", "covers_non_public"), ("pub async fn project_target_delete(", "t.in_scope = 0")] {
            let start = src.find(command).unwrap_or_else(|| panic!("{command}"));
            let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
            assert!(body.contains(needle) && body.contains("crate::confirm::native("), "{command} confirms natively");
        }
    }

    /// Mission 8: reopening a completed or archived project is confirmed in a native dialog (a page
    /// could otherwise make an ended engagement's scope usable again by itself), the dialog says
    /// what becomes usable, and the save only applies to the status that was asked about.
    #[test]
    fn reopening_an_ended_project_is_confirmed_outside_the_page() {
        let src = include_str!("projects.rs");
        let start = src.find("pub async fn project_upsert(").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        let ask = body.find("crate::confirm::native(").expect("project_upsert confirms natively");
        let check = body.find("CLOSED.contains(&before.as_str()) && !CLOSED.contains(&status.as_str())").expect("the question is asked when an ended project is reopened");
        let write = body.find("UPDATE projects SET").unwrap();
        assert!(check < ask && ask < write, "it asks before it writes");
        assert!(body.contains("WHERE id=?1 AND status=?16"), "the save applies only to the status that was asked about");
        assert_eq!(super::CLOSED, &["completed", "archived"]);
        for s in super::CLOSED {
            assert!(super::STATUSES.contains(s));
        }
        let q = super::reopen_question("Acme \u{202E}x", "archived", "active", 3, 1);
        assert!(q.starts_with("Reopen the project “Acme \u{202E}x”? It is archived."), "{q}");
        assert!(q.contains("As active, its scope can be used again (3 in-scope entries, 1 exclusion)"), "{q}");
        assert!(super::reopen_question("P", "completed", "paused", 1, 0).contains("(1 in-scope entry, 0 exclusions)"));
        // the hidden character in the name is shown as its code point by the dialog itself
        assert_eq!(crate::util::dialog_text(&q).matches("<U+202E>").count(), 1);
    }

    fn setup(db: &Db) -> i64 {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            Ok(c.last_insert_rowid())
        })
        .unwrap()
    }

    fn input(p: i64) -> FindingInput {
        FindingInput { project_id: p, title: "Open redirect".into(), severity: "medium".into(), status: "open".into(), ..Default::default() }
    }

    #[test]
    fn saving_findings_maps_legacy_statuses_and_records_history() {
        let db = Db::open_in_memory().unwrap();
        let p = setup(&db);
        db.with(|c| {
            let id = finding_save(c, &input(p), "mcp")?;
            let f = finding_get(c, id)?;
            assert_eq!((f.status.as_str(), f.source.as_str(), f.confidence.as_str()), ("new", "mcp", "medium"), "\"open\" from older clients is stored as \"new\"");
            finding_save(c, &FindingInput { id: Some(id), status: "reported".into(), remediation: "Allow-list redirect targets".into(), tags: vec!["web".into(), "web".into()], due_date: Some("2026-12-01".into()), ..input(p) }, "user")?;
            let f = finding_get(c, id)?;
            assert_eq!(f.status, "confirmed");
            assert_eq!(f.tags, vec!["web"]);
            assert_eq!(f.source, "mcp", "the original source is kept");
            let h = lifecycle::history(c, id)?;
            let kinds: Vec<&str> = h.iter().map(|e| e.kind.as_str()).collect();
            assert_eq!(kinds, vec!["created", "updated", "status"]);
            assert_eq!(h[1].note, "Changed: remediation, tags, due date");
            assert_eq!((h[2].from_status.as_deref(), h[2].to_status.as_deref()), (Some("new"), Some("confirmed")));
            // saving without changes records nothing
            finding_save(c, &FindingInput { id: Some(id), status: "confirmed".into(), remediation: "Allow-list redirect targets".into(), tags: vec!["web".into()], due_date: Some("2026-12-01".into()), ..input(p) }, "user")?;
            assert_eq!(lifecycle::history(c, id)?.len(), 3);
            // invalid input changes nothing
            for bad in [
                FindingInput { id: Some(id), status: "reopened".into(), ..input(p) },
                FindingInput { id: Some(id), status: "closed".into(), ..input(p) },
                FindingInput { id: Some(id), confidence: Some("certain".into()), ..input(p) },
                FindingInput { id: Some(id), due_date: Some("next week".into()), ..input(p) },
                FindingInput { id: Some(id), project_id: p + 1, ..input(p) },
            ] {
                assert!(finding_save(c, &bad, "user").is_err());
            }
            assert_eq!(finding_get(c, id)?.status, "confirmed");
            assert_eq!(lifecycle::history(c, id)?.len(), 3);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn open_finding_counts_use_the_new_lifecycle() {
        let db = Db::open_in_memory().unwrap();
        let p = setup(&db);
        db.with(|c| {
            for s in lifecycle::STATUSES {
                c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1,'x','low',?2,'t','t')", params![p, s])?;
            }
            Ok(())
        })
        .unwrap();
        let open: i64 = db.with(|c| Ok(c.query_row(&format!("SELECT COUNT(*) FROM findings WHERE project_id = ?1 AND status IN {OPEN_SQL}"), params![p], |r| r.get(0))?)).unwrap();
        assert_eq!(open, 5, "resolved, accepted risk and false positives are not open");
    }

    #[test]
    fn scope_changes_are_recorded() {
        let db = Db::open_in_memory().unwrap();
        let p = setup(&db);
        db.with(|c| {
            let id = target_add(c, p, "example.com", "domain", true, "")?;
            assert_eq!(target_add(c, p, "example.com", "domain", true, "")?, id, "re-adding the same entry is not a change");
            target_add(c, p, "example.com", "domain", false, "Out of scope since the call")?;
            target_delete(c, id)?;
            target_delete(c, id)?;
            let mut st = c.prepare("SELECT action, in_scope, note FROM scope_events WHERE project_id = ?1 ORDER BY id")?;
            let rows: Vec<(String, Option<i64>, String)> = st.query_map(params![p], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
            assert_eq!(
                rows,
                vec![("added".into(), Some(1), String::new()), ("updated".into(), Some(0), "Out of scope since the call".into()), ("removed".into(), Some(0), String::new())]
            );
            Ok(())
        })
        .unwrap();
    }
}

#[cfg(test)]
mod deletion_tests {
    use super::*;
    use crate::process::{record_end, RunEnd};
    use std::sync::Arc;

    /// Project 1 with a running tool run (#10) that a finding links to, and two evidence files: one
    /// only project 1 uses, one project 2 uses too.
    fn setup(db: &Db) {
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Acme', 'active', 't', 't'), (2, 'Other', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO executions (id, tool_id, kind, program, args, project_id, status, started_at) VALUES (10, 'nmap', 'run', 'nmap', '[]', 1, 'running', 't')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (5, 1, 'F', 'low', 'new', 't', 't')", [])?;
            c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (5, 'execution', 10, 't')", [])?;
            c.execute(
                "INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (1, 'file', 'own', 'user', ?1, 1, 'a', 't'), (1, 'file', 'shared', 'user', ?2, 1, 'b', 't'), (2, 'file', 'shared', 'user', ?2, 1, 'b', 't')",
                params!["a".repeat(64), "b".repeat(64)],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn end(started_for: Option<i64>) -> RunEnd<'static> {
        RunEnd { id: 10, kind: "run", tool_id: "nmap", status: "succeeded", code: Some(0), output: "done", truncated: false, started_for }
    }

    fn count(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_project_is_not_deleted_while_work_runs_for_it() {
        let db = Db::open_in_memory().unwrap();
        setup(&db);
        db.with(|c| {
            let err = delete_project(c, 1).unwrap_err().to_string();
            assert!(err.contains("still has work running") && err.contains("nmap run #10"), "{err}");
            assert_eq!(count(c, "SELECT COUNT(*) FROM projects WHERE id = 1"), 1, "nothing was deleted");
            // running workflows and discovery hold it back too
            c.execute("INSERT INTO workflows (id, project_id, name, definition, created_at, updated_at) VALUES (3, 2, 'Nightly', '[]', 't', 't')", [])?;
            c.execute("INSERT INTO workflow_runs (workflow_id, project_id, trigger, status, definition, started_at) VALUES (3, 2, 'manual', 'running', '[]', 't')", [])?;
            c.execute("INSERT INTO discovery_snapshots (project_id, mode, source, status, started_at) VALUES (2, 'passive', 'passive', 'running', 't')", [])?;
            let err = delete_project(c, 2).unwrap_err().to_string();
            assert!(err.contains("workflow Nightly") && err.contains("passive discovery"), "{err}");
            // the run ends and is recorded with its project; then the project can go
            record_end(c, &end(Some(1)))?;
            let orphaned = delete_project(c, 1)?;
            assert_eq!(orphaned, vec!["a".repeat(64)], "only the file no other project uses");
            // the run and its activity entry stay, without a project; the records of the project go
            let (project, status): (Option<i64>, String) = c.query_row("SELECT project_id, status FROM executions WHERE id = 10", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            assert_eq!((project, status.as_str()), (None, "succeeded"));
            assert_eq!(count(c, "SELECT COUNT(*) FROM activity_logs WHERE title = 'Ran nmap: succeeded' AND project_id IS NULL"), 1);
            assert_eq!(count(c, "SELECT COUNT(*) FROM activity_logs WHERE title = 'Deleted project “Acme”'"), 1);
            assert_eq!(count(c, "SELECT COUNT(*) FROM finding_links"), 0, "no link points at a deleted finding");
            assert_eq!(count(c, "SELECT COUNT(*) FROM evidence WHERE project_id = 2"), 1, "the other project keeps its evidence");
            assert_eq!(count(c, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
            assert!(delete_project(c, 1)?.is_empty(), "deleting again changes nothing");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn the_end_of_a_run_is_recorded_when_its_project_is_gone() {
        let db = Db::open_in_memory().unwrap();
        setup(&db);
        db.with(|c| {
            // a project removed without the check (an older version, a direct database change)
            c.execute("DELETE FROM projects WHERE id = 1", [])?;
            record_end(c, &end(Some(1)))?;
            let (project, detail): (Option<i64>, String) = c.query_row("SELECT project_id, detail FROM activity_logs WHERE title = 'Ran nmap: succeeded'", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            assert_eq!(project, None);
            assert!(detail.contains("its project was deleted while it ran"), "{detail}");
            assert_eq!(count(c, "SELECT COUNT(*) FROM executions WHERE id = 10 AND status = 'succeeded' AND output = 'done'"), 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn an_interrupted_end_of_run_leaves_nothing_half_written() {
        let db = Db::open_in_memory().unwrap();
        setup(&db);
        db.with(|c| {
            // the activity entry cannot be written (a full disk, for example)
            c.execute_batch("CREATE TEMP TRIGGER fail BEFORE INSERT ON activity_logs BEGIN SELECT RAISE(ABORT, 'disk full'); END;")?;
            assert!(record_end(c, &end(Some(1))).is_err());
            assert_eq!(count(c, "SELECT COUNT(*) FROM executions WHERE id = 10 AND status = 'running' AND output = ''"), 1, "the run is untouched, marked as interrupted at the next start");
            c.execute_batch("DROP TRIGGER fail;")?;
            record_end(c, &end(Some(1)))?;
            assert_eq!(count(c, "SELECT COUNT(*) FROM executions WHERE id = 10 AND status = 'succeeded'"), 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn deleting_a_project_while_its_run_ends_is_safe() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        setup(&db);
        let d = db.clone();
        // the analyst keeps trying to delete the project while the run goes on
        let deleter = std::thread::spawn(move || {
            for _ in 0..500 {
                if d.with(|c| delete_project(c, 1)).is_ok() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            false
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        db.with(|c| record_end(c, &end(Some(1)))).unwrap();
        assert!(deleter.join().unwrap(), "deleted once the run had ended");
        db.with(|c| {
            assert_eq!(count(c, "SELECT COUNT(*) FROM projects WHERE id = 1"), 0);
            assert_eq!(count(c, "SELECT COUNT(*) FROM executions WHERE id = 10 AND status = 'succeeded' AND project_id IS NULL"), 1);
            assert_eq!(count(c, "SELECT COUNT(*) FROM activity_logs WHERE title = 'Ran nmap: succeeded'"), 1);
            assert_eq!(count(c, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
            let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            assert_eq!(ok, "ok");
            Ok(())
        })
        .unwrap();
    }
}
