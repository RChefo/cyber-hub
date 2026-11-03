//! Projects workspace: assessments, authorized scope, findings.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::activity::log;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::scope::{self, ScopeEntry};
use crate::util::{clean, now, one_of};

const STATUSES: &[&str] = &["planning", "active", "paused", "completed", "archived"];
const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
const FINDING_STATUSES: &[&str] = &["open", "confirmed", "reported", "resolved", "false_positive"];

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
        let mut stmt = c.prepare(
            "SELECT p.id, p.name, p.description, p.status, p.start_date, p.end_date,
                (SELECT COUNT(*) FROM project_targets t WHERE t.project_id = p.id),
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id),
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.status IN ('open','confirmed')),
                p.created_at, p.updated_at
             FROM projects p ORDER BY p.updated_at DESC",
        )?;
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
    db.with(|c| {
        let p = c
            .query_row(
                "SELECT id, name, description, status, scope_notes, notes, start_date, end_date, created_at, updated_at FROM projects WHERE id = ?1",
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
                        targets: vec![],
                    })
                },
            )
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("project {id}")))?;
        let targets = load_targets(c, id)?;
        Ok(Project { targets, ..p })
    })
}

#[tauri::command]
pub async fn project_upsert(db: State<'_, Db>, input: ProjectInput) -> AppResult<i64> {
    let name = clean("Project name", &input.name, 120, true)?;
    let description = clean("Description", &input.description, 2000, false)?;
    let status = one_of("Status", &input.status, STATUSES)?;
    let scope_notes = clean("Rules of engagement", &input.scope_notes, 10000, false)?;
    let notes = clean("Notes", &input.notes, 100_000, false)?;
    let start = date_opt("Start date", &input.start_date)?;
    let end = date_opt("End date", &input.end_date)?;
    if let (Some(s), Some(e)) = (&start, &end) {
        if e < s {
            return Err(validation("End date must be after the start date"));
        }
    }
    let ts = now();
    db.with(|c| match input.id {
        Some(id) => {
            let n = c.execute(
                "UPDATE projects SET name=?2, description=?3, status=?4, scope_notes=?5, notes=?6, start_date=?7, end_date=?8, updated_at=?9 WHERE id=?1",
                params![id, name, description, status, scope_notes, notes, start, end, ts],
            )?;
            if n == 0 {
                return Err(AppError::NotFound(format!("project {id}")));
            }
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO projects (name, description, status, scope_notes, notes, start_date, end_date, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8)",
                params![name, description, status, scope_notes, notes, start, end, ts],
            )?;
            let id = c.last_insert_rowid();
            log(c, "project", &format!("Created project “{name}”"), "", Some("project"), Some(&id.to_string()), Some(id))?;
            Ok(id)
        }
    })
}

#[tauri::command]
pub async fn project_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        let name: Option<String> = c.query_row("SELECT name FROM projects WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        c.execute("DELETE FROM projects WHERE id=?1", params![id])?;
        if let Some(n) = name {
            log(c, "project", &format!("Deleted project “{n}”"), "", None, None, None)?;
        }
        Ok(())
    })
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
pub async fn project_target_add(db: State<'_, Db>, project_id: i64, input: TargetInput) -> AppResult<i64> {
    let (value, kind) = scope::classify(&input.value)?;
    let note = clean("Note", &input.note, 300, false)?;
    db.with(|c| {
        c.execute(
            "INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(project_id, value) DO UPDATE SET in_scope=excluded.in_scope, note=excluded.note",
            params![project_id, value, kind, input.in_scope as i64, note, now()],
        )?;
        c.execute("UPDATE projects SET updated_at=?2 WHERE id=?1", params![project_id, now()])?;
        Ok(c.last_insert_rowid())
    })
}

#[tauri::command]
pub async fn project_target_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM project_targets WHERE id=?1", params![id])?;
        Ok(())
    })
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
    pub description: String,
    pub affected_target: String,
    pub cve: String,
    pub evidence: Vec<Evidence>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingInput {
    pub id: Option<i64>,
    pub project_id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub affected_target: String,
    #[serde(default)]
    pub cve: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

#[tauri::command]
pub async fn findings_list(db: State<'_, Db>, project_id: Option<i64>) -> AppResult<Vec<Finding>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, project_id, title, severity, status, description, affected_target, cve, evidence, created_at, updated_at
             FROM findings WHERE (?1 IS NULL OR project_id = ?1)
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| {
                Ok(Finding {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    title: r.get(2)?,
                    severity: r.get(3)?,
                    status: r.get(4)?,
                    description: r.get(5)?,
                    affected_target: r.get(6)?,
                    cve: r.get(7)?,
                    evidence: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
                    created_at: r.get(9)?,
                    updated_at: r.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn finding_upsert(db: State<'_, Db>, input: FindingInput) -> AppResult<i64> {
    let title = clean("Title", &input.title, 200, true)?;
    let severity = one_of("Severity", &input.severity, SEVERITIES)?;
    let status = one_of("Status", &input.status, FINDING_STATUSES)?;
    let description = clean("Description", &input.description, 50_000, false)?;
    let affected = clean("Affected target", &input.affected_target, 500, false)?;
    let cve = clean("CVE", &input.cve, 200, false)?.to_uppercase();
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
    let evidence_json = serde_json::to_string(&evidence)?;
    let ts = now();
    db.with(|c| {
        let id = match input.id {
            Some(id) => {
                c.execute(
                    "UPDATE findings SET title=?2, severity=?3, status=?4, description=?5, affected_target=?6, cve=?7, evidence=?8, updated_at=?9 WHERE id=?1",
                    params![id, title, severity, status, description, affected, cve, evidence_json, ts],
                )?;
                id
            }
            None => {
                c.execute(
                    "INSERT INTO findings (project_id, title, severity, status, description, affected_target, cve, evidence, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
                    params![input.project_id, title, severity, status, description, affected, cve, evidence_json, ts],
                )?;
                let id = c.last_insert_rowid();
                log(c, "finding", &format!("Recorded {severity} finding “{title}”"), "", Some("finding"), Some(&id.to_string()), Some(input.project_id))?;
                id
            }
        };
        c.execute("UPDATE projects SET updated_at=?2 WHERE id=?1", params![input.project_id, ts])?;
        Ok(id)
    })
}

#[tauri::command]
pub async fn finding_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM findings WHERE id=?1", params![id])?;
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
