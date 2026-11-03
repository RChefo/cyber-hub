//! Activity log, preferences, favorites, tasks and dashboard aggregates.

use std::collections::HashMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::db::Db;
use crate::error::{validation, AppResult};
use crate::util::{clean, now};

pub fn log(
    c: &Connection,
    kind: &str,
    title: &str,
    detail: &str,
    ref_kind: Option<&str>,
    ref_id: Option<&str>,
    project_id: Option<i64>,
) -> AppResult<()> {
    c.execute(
        "INSERT INTO activity_logs (kind, title, detail, ref_kind, ref_id, project_id, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![kind, title, detail, ref_kind, ref_id, project_id, now()],
    )?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub ref_kind: Option<String>,
    pub ref_id: Option<String>,
    pub project_id: Option<i64>,
    pub created_at: String,
}

const ACTIVITY_KINDS: &[&str] = &[
    "tool_run", "tool_install", "tool_launch", "tool_scan", "command_copy", "command_saved", "dork_search",
    "dork_saved", "resource_open", "project", "finding", "wordlist", "cve_search", "utility", "payload_copy", "vt_lookup",
    "vt_upload", "ti_lookup",
];

#[tauri::command]
pub async fn activity_list(db: State<'_, Db>, limit: Option<i64>, kind: Option<String>) -> AppResult<Vec<Activity>> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, kind, title, detail, ref_kind, ref_id, project_id, created_at FROM activity_logs
             WHERE (?1 IS NULL OR kind = ?1) ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![kind, limit], |r| {
                Ok(Activity {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    title: r.get(2)?,
                    detail: r.get(3)?,
                    ref_kind: r.get(4)?,
                    ref_id: r.get(5)?,
                    project_id: r.get(6)?,
                    created_at: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityInput {
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    pub ref_kind: Option<String>,
    pub ref_id: Option<String>,
    pub project_id: Option<i64>,
}

#[tauri::command]
pub async fn activity_log(db: State<'_, Db>, input: ActivityInput) -> AppResult<()> {
    if !ACTIVITY_KINDS.contains(&input.kind.as_str()) {
        return Err(validation("Unknown activity kind"));
    }
    let title = clean("Title", &input.title, 300, true)?;
    let detail = clean("Detail", &input.detail, 2000, false)?;
    let ref_kind = input.ref_kind.as_deref().map(|v| clean("Reference kind", v, 40, false)).transpose()?;
    let ref_id = input.ref_id.as_deref().map(|v| clean("Reference id", v, 200, false)).transpose()?;
    let detail = crate::redact::redact_text(&detail);
    db.with(|c| log(c, &input.kind, &title, &detail, ref_kind.as_deref(), ref_id.as_deref(), input.project_id))
}

#[tauri::command]
pub async fn activity_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM activity_logs", [])?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyCount {
    pub date: String,
    pub kind: String,
    pub count: i64,
}

#[tauri::command]
pub async fn activity_daily(db: State<'_, Db>, days: Option<i64>) -> AppResult<Vec<DailyCount>> {
    let days = days.unwrap_or(30).clamp(1, 365);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT substr(created_at, 1, 10) AS d, kind, COUNT(*) FROM activity_logs
             WHERE created_at >= datetime('now', ?1) GROUP BY d, kind ORDER BY d",
        )?;
        let rows = stmt
            .query_map(params![format!("-{days} days")], |r| {
                Ok(DailyCount { date: r.get(0)?, kind: r.get(1)?, count: r.get(2)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/* ─────────────── preferences ─────────────── */

const PREF_KEYS: &[&str] = &[
    "dashboard.layout", "dashboard.hidden", "ui.sidebarCollapsed", "ui.reducedMotion", "ui.density",
    "terminal.preferred", "tools.lastScan", "dorks.defaultEngine", "onboarding.dismissed",
    "cve.preferLive", "user.displayName", "notifications.lastSeen", "vt.uploadLimitMb",
];

#[tauri::command]
pub async fn prefs_get_all(db: State<'_, Db>) -> AppResult<HashMap<String, serde_json::Value>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT key, value FROM user_preferences")?;
        let mut out = HashMap::new();
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (k, v) = row?;
            out.insert(k, serde_json::from_str(&v).unwrap_or(serde_json::Value::Null));
        }
        Ok(out)
    })
}

#[tauri::command]
pub async fn prefs_set(db: State<'_, Db>, key: String, value: serde_json::Value) -> AppResult<()> {
    if !PREF_KEYS.contains(&key.as_str()) {
        return Err(validation(format!("Unknown preference '{key}'")));
    }
    if key == "vt.uploadLimitMb" && !value.as_f64().is_some_and(|v| (1.0..=650.0).contains(&v)) {
        return Err(validation("The upload limit must be between 1 and 650 MB"));
    }
    let raw = serde_json::to_string(&value)?;
    if raw.len() > 64 * 1024 {
        return Err(validation("Preference value too large"));
    }
    db.with(|c| {
        c.execute(
            "INSERT INTO user_preferences (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, raw, now()],
        )?;
        Ok(())
    })
}

/* ─────────────── favorites ─────────────── */

const FAVORITE_KINDS: &[&str] = &["tool", "resource", "command", "dork", "payload", "wordlist", "utility", "template"];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Favorite {
    pub kind: String,
    pub item_id: String,
    pub created_at: String,
}

#[tauri::command]
pub async fn favorites_list(db: State<'_, Db>) -> AppResult<Vec<Favorite>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT kind, item_id, created_at FROM favorites ORDER BY created_at DESC")?;
        let rows = stmt
            .query_map([], |r| Ok(Favorite { kind: r.get(0)?, item_id: r.get(1)?, created_at: r.get(2)? }))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// Toggles a favorite; returns the new state.
#[tauri::command]
pub async fn favorite_toggle(db: State<'_, Db>, kind: String, item_id: String) -> AppResult<bool> {
    if !FAVORITE_KINDS.contains(&kind.as_str()) {
        return Err(validation("Unknown favorite kind"));
    }
    let item_id = clean("Item", &item_id, 200, true)?;
    db.with(|c| {
        let exists: Option<i64> = c
            .query_row("SELECT 1 FROM favorites WHERE kind = ?1 AND item_id = ?2", params![kind, item_id], |r| r.get(0))
            .optional()?;
        if exists.is_some() {
            c.execute("DELETE FROM favorites WHERE kind = ?1 AND item_id = ?2", params![kind, item_id])?;
            Ok(false)
        } else {
            c.execute("INSERT INTO favorites (kind, item_id, created_at) VALUES (?1, ?2, ?3)", params![kind, item_id, now()])?;
            Ok(true)
        }
    })
}

/* ─────────────── tasks ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub id: i64,
    pub title: String,
    pub done: bool,
    pub project_id: Option<i64>,
    pub project_name: Option<String>,
    pub due_date: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskInput {
    pub id: Option<i64>,
    pub title: String,
    #[serde(default)]
    pub done: bool,
    pub project_id: Option<i64>,
    pub due_date: Option<String>,
}

#[tauri::command]
pub async fn tasks_list(db: State<'_, Db>) -> AppResult<Vec<Task>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT t.id, t.title, t.done, t.project_id, p.name, t.due_date, t.created_at FROM tasks t
             LEFT JOIN projects p ON p.id = t.project_id ORDER BY t.done ASC, COALESCE(t.due_date, '9999') ASC, t.id DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Task {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    done: r.get::<_, i64>(2)? != 0,
                    project_id: r.get(3)?,
                    project_name: r.get(4)?,
                    due_date: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn task_upsert(db: State<'_, Db>, input: TaskInput) -> AppResult<i64> {
    let title = clean("Task", &input.title, 300, true)?;
    let due = match input.due_date.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(d) => {
            chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| validation("Due date must be YYYY-MM-DD"))?;
            Some(d.to_string())
        }
    };
    db.with(|c| match input.id {
        Some(id) => {
            c.execute(
                "UPDATE tasks SET title=?2, done=?3, project_id=?4, due_date=?5 WHERE id=?1",
                params![id, title, input.done as i64, input.project_id, due],
            )?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO tasks (title, done, project_id, due_date, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![title, input.done as i64, input.project_id, due, now()],
            )?;
            Ok(c.last_insert_rowid())
        }
    })
}

#[tauri::command]
pub async fn task_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM tasks WHERE id = ?1", params![id])?;
        Ok(())
    })
}
