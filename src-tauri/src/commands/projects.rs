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

#[tauri::command]
pub async fn project_upsert(db: State<'_, Db>, input: ProjectInput) -> AppResult<i64> {
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
    db.with(|c| match input.id {
        Some(id) => {
            let n = c.execute(
                "UPDATE projects SET name=?2, description=?3, status=?4, scope_notes=?5, notes=?6, start_date=?7, end_date=?8, updated_at=?9,
                     client=?10, engagement_type=?11, authorization_ref=?12, objectives=?13, methodology=?14, contacts=?15 WHERE id=?1",
                params![id, name, description, status, scope_notes, notes, start, end, ts, client, engagement_type, authorization_ref, objectives, methodology, contacts],
            )?;
            if n == 0 {
                return Err(AppError::NotFound(format!("project {id}")));
            }
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
pub async fn project_target_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
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
            }
            id
        }
        None => {
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

/* ─────────────── assessment report (shared by the GUI and MCP) ─────────────── */

const SEVERITY_LABEL: &[(&str, &str)] = &[("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")];
const STATUS_LABEL: &[(&str, &str)] = &[
    ("new", "New"),
    ("under_review", "Under review"),
    ("confirmed", "Confirmed"),
    ("accepted_risk", "Accepted risk"),
    ("in_remediation", "In remediation"),
    ("resolved", "Resolved"),
    ("reopened", "Reopened"),
    ("false_positive", "False positive"),
];

fn label<'a>(table: &'a [(&'a str, &'a str)], key: &'a str) -> &'a str {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or(key)
}

fn severity_rank(s: &str) -> usize {
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(SEVERITIES.len())
}

/// Escape characters that would break Markdown table cells.
fn md_cell(v: &str) -> String {
    let t = v.replace('|', "\\|").replace("\r\n", " ").replace('\n', " ");
    let t = t.trim();
    if t.is_empty() {
        "—".into()
    } else {
        t.to_string()
    }
}

/// Finding statuses a report leaves out, as the HTML report does by default.
const REPORT_CLOSED: &[&str] = &["resolved", "accepted_risk", "false_positive"];

/// Self-contained Markdown assessment report from local project data. `generated` is a
/// YYYY-MM-DD date. Like the HTML report by default, it lists open findings only (closed ones are
/// counted) and leaves out the project's internal notes.
pub fn markdown_report(project: &Project, findings: &[Finding], generated: &str) -> String {
    let closed = findings.iter().filter(|f| REPORT_CLOSED.contains(&f.status.as_str())).count();
    let findings: Vec<&Finding> = findings.iter().filter(|f| !REPORT_CLOSED.contains(&f.status.as_str())).collect();
    let mut l: Vec<String> = Vec::new();
    l.push(format!("# {}", project.name));
    l.push(String::new());
    l.push(format!("_Assessment report generated by Cyber Hub on {generated}._"));
    l.push(String::new());
    l.push("## Summary".into());
    l.push(String::new());
    let mut status = project.status.clone();
    if let Some(first) = status.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    l.push(format!("- **Status:** {status}"));
    if !project.client.trim().is_empty() {
        l.push(format!("- **Client:** {}", project.client.trim()));
    }
    if !project.engagement_type.is_empty() {
        l.push(format!("- **Engagement:** {}", project.engagement_type.replace('_', " ")));
    }
    if !project.authorization_ref.trim().is_empty() {
        l.push(format!("- **Authorization:** {}", project.authorization_ref.trim()));
    }
    l.push(format!("- **Period:** {} → {}", project.start_date.as_deref().unwrap_or("not set"), project.end_date.as_deref().unwrap_or("not set")));
    let counts: Vec<String> = SEVERITY_LABEL.iter().map(|(k, v)| format!("{v} {}", findings.iter().filter(|f| f.severity == *k).count())).collect();
    let closed_note = if closed > 0 { format!("; {closed} closed not listed") } else { String::new() };
    l.push(format!("- **Findings:** {} ({}){closed_note}", findings.len(), counts.join(", ")));
    if !project.description.trim().is_empty() {
        l.push(String::new());
        l.push(project.description.trim().to_string());
    }

    l.push(String::new());
    l.push("## Authorized scope".into());
    l.push(String::new());
    if project.targets.is_empty() {
        l.push("No scope entries recorded.".into());
    } else {
        l.push("| Target | Type | Scope | Note |".into());
        l.push("| --- | --- | --- | --- |".into());
        for t in project.targets.iter().filter(|t| t.in_scope).chain(project.targets.iter().filter(|t| !t.in_scope)) {
            l.push(format!("| `{}` | {} | {} | {} |", md_cell(&t.value), t.kind, if t.in_scope { "In scope" } else { "Out of scope" }, md_cell(&t.note)));
        }
    }
    if !project.scope_notes.trim().is_empty() {
        l.push(String::new());
        l.push("### Rules of engagement".into());
        l.push(String::new());
        l.push(project.scope_notes.trim().to_string());
    }

    l.push(String::new());
    l.push("## Findings".into());
    l.push(String::new());
    let mut sorted: Vec<&Finding> = findings.clone();
    sorted.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)).then(b.updated_at.cmp(&a.updated_at)));
    if closed > 0 {
        l.push(format!(
            "_{closed} closed finding{} (resolved, accepted risk or false positive) {} not listed._",
            if closed == 1 { "" } else { "s" },
            if closed == 1 { "is" } else { "are" }
        ));
        l.push(String::new());
    }
    if sorted.is_empty() {
        l.push(if closed > 0 { "No open findings." } else { "No findings recorded." }.into());
    } else {
        l.push("| # | Title | Severity | Status | Affected |".into());
        l.push("| --- | --- | --- | --- | --- |".into());
        for (i, f) in sorted.iter().enumerate() {
            l.push(format!("| {} | {} | {} | {} | {} |", i + 1, md_cell(&f.title), label(SEVERITY_LABEL, &f.severity), label(STATUS_LABEL, &f.status), md_cell(&f.affected_target)));
        }
        for (i, f) in sorted.iter().enumerate() {
            l.push(String::new());
            l.push(format!("### {}. {}", i + 1, f.title));
            l.push(String::new());
            l.push(format!("- **Severity:** {}", label(SEVERITY_LABEL, &f.severity)));
            if let (Some(score), false) = (f.cvss_score, f.cvss_vector.is_empty()) {
                l.push(format!("- **CVSS:** {score:.1} `{}`", f.cvss_vector));
            }
            l.push(format!("- **Status:** {}", label(STATUS_LABEL, &f.status)));
            if !f.affected_target.is_empty() {
                l.push(format!("- **Affected target:** `{}`", f.affected_target));
            }
            if !f.cve.is_empty() {
                l.push(format!("- **CVE:** {}", f.cve));
            }
            if !f.category.trim().is_empty() {
                l.push(format!("- **Category:** {}", f.category.trim()));
            }
            if !f.description.trim().is_empty() {
                l.push(String::new());
                l.push(f.description.trim().to_string());
            }
            for (heading, text) in [("Reproduction", &f.reproduction), ("Technical details", &f.technical_details), ("Remediation", &f.remediation)] {
                if !text.trim().is_empty() {
                    l.push(String::new());
                    l.push(format!("**{heading}**"));
                    l.push(String::new());
                    l.push(text.trim().to_string());
                }
            }
            if !f.evidence.is_empty() {
                l.push(String::new());
                l.push("**Evidence**".into());
                l.push(String::new());
                for e in &f.evidence {
                    l.push(format!("- {}: `{}`", e.label, e.reference));
                }
            }
        }
    }
    l.push(String::new());
    l.join("\n")
}

/// Markdown report for a project (used by Projects → Export report and by MCP).
#[tauri::command]
pub async fn project_report(db: State<'_, Db>, id: i64) -> AppResult<String> {
    let project = project_get(db.clone(), id).await?;
    let findings = findings_list(db, Some(id)).await?;
    Ok(markdown_report(&project, &findings, &chrono::Utc::now().format("%Y-%m-%d").to_string()))
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
mod report_tests {
    use super::*;

    fn project(targets: bool) -> Project {
        Project {
            id: 1,
            name: "Acme external assessment".into(),
            description: if targets { "Quarterly external test.".into() } else { String::new() },
            status: "active".into(),
            scope_notes: if targets { "Testing window 09:00-17:00 UTC.".into() } else { String::new() },
            notes: String::new(),
            start_date: Some("2026-11-01".into()),
            end_date: Some("2026-11-15".into()),
            client: if targets { "Acme Corp".into() } else { String::new() },
            engagement_type: "external".into(),
            authorization_ref: if targets { "SOW-2026-117".into() } else { String::new() },
            objectives: String::new(),
            methodology: String::new(),
            contacts: String::new(),
            created_at: "2026-11-01T00:00:00Z".into(),
            updated_at: "2026-11-02T00:00:00Z".into(),
            targets: if targets {
                vec![
                    Target { id: 1, value: "*.acme.test".into(), kind: "wildcard".into(), in_scope: true, note: String::new() },
                    Target { id: 2, value: "vpn.acme.test".into(), kind: "domain".into(), in_scope: false, note: "Production VPN | do not touch".into() },
                ]
            } else {
                vec![]
            },
        }
    }

    fn f(id: i64, severity: &str, status: &str) -> Finding {
        Finding {
            id,
            project_id: 1,
            title: format!("Finding {id}"),
            severity: severity.into(),
            status: status.into(),
            description: if id == 2 { "Line one\nLine two".into() } else { String::new() },
            affected_target: "app.acme.test".into(),
            cve: if id == 2 { "CVE-2021-44228".into() } else { String::new() },
            evidence: if id == 2 { vec![Evidence { label: "Request".into(), reference: "evidence/req-2.txt".into() }] } else { vec![] },
            category: String::new(),
            confidence: "medium".into(),
            reproduction: String::new(),
            technical_details: String::new(),
            remediation: if id == 2 { "Upgrade log4j-core to 2.17.1.".into() } else { String::new() },
            source: "user".into(),
            tags: vec![],
            assignee: String::new(),
            due_date: None,
            created_at: "2026-11-02T00:00:00Z".into(),
            updated_at: "2026-11-02T00:00:00Z".into(),
            cvss_vector: String::new(),
            cvss_score: None,
        }
    }

    #[test]
    fn report_includes_summary_scope_and_findings_in_severity_order() {
        let md = markdown_report(&project(true), &[f(1, "low", "new"), f(2, "critical", "in_remediation")], "2026-11-03");
        assert!(md.contains("# Acme external assessment"));
        assert!(md.contains("generated by Cyber Hub on 2026-11-03"));
        assert!(md.contains("Critical 1"));
        assert!(md.find("### 1. Finding 2").unwrap() < md.find("### 2. Finding 1").unwrap());
        assert!(md.contains("- **CVE:** CVE-2021-44228"));
        assert!(md.contains("- Request: `evidence/req-2.txt`"));
        assert!(md.contains("### Rules of engagement"));
        assert!(md.contains("Production VPN \\| do not touch"));
        assert!(md.contains("| `vpn.acme.test` | domain | Out of scope |"));
        assert!(md.contains("- **Status:** Active"));
        assert!(md.contains("- **Client:** Acme Corp") && md.contains("- **Authorization:** SOW-2026-117"));
        assert!(md.contains("- **Status:** In remediation"));
        assert!(md.contains("**Remediation**

Upgrade log4j-core to 2.17.1."));
    }

    #[test]
    fn empty_projects_do_not_fabricate_content() {
        let md = markdown_report(&project(false), &[], "2026-11-03");
        assert!(md.contains("No scope entries recorded.") && md.contains("No findings recorded."));
    }

    #[test]
    fn closed_findings_and_internal_notes_stay_out_of_the_report() {
        let mut p = project(true);
        p.notes = "Internal: client contact is difficult".into();
        let md = markdown_report(&p, &[f(1, "low", "false_positive"), f(2, "critical", "confirmed"), f(3, "high", "resolved")], "2026-11-03");
        assert!(!md.contains("Internal: client contact") && !md.contains("## Notes"), "{md}");
        assert!(md.contains("### 1. Finding 2") && !md.contains("Finding 1") && !md.contains("Finding 3"));
        assert!(md.contains("2 closed findings (resolved, accepted risk or false positive) are not listed."));
        assert!(md.contains("- **Findings:** 1 (") && md.contains("; 2 closed not listed"));
        let none_open = markdown_report(&p, &[f(1, "low", "resolved")], "2026-11-03");
        assert!(none_open.contains("No open findings."));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

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
