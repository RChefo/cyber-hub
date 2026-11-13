// SPDX-License-Identifier: Apache-2.0
//! User libraries: custom resources and visits, saved commands and history,
//! saved dorks and history, custom payloads.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::activity::log;
use crate::db::Db;
use crate::error::AppResult;
use crate::util::{clean, http_url, now, one_of};

fn tags_to_json(tags: &[String]) -> AppResult<String> {
    let cleaned: Vec<String> = tags
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 40)
        .take(20)
        .collect();
    Ok(serde_json::to_string(&cleaned)?)
}

fn json_to_tags(raw: String) -> Vec<String> {
    serde_json::from_str(&raw).unwrap_or_default()
}

/* ─────────────── custom resources ─────────────── */

const RESOURCE_CATEGORIES: &[&str] =
    &["learning", "intelligence", "documentation", "vulnerability-databases", "tools-online", "community", "custom"];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResource {
    pub id: i64,
    pub title: String,
    pub url: String,
    pub category: String,
    pub description: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResourceInput {
    pub id: Option<i64>,
    pub title: String,
    pub url: String,
    pub category: String,
    #[serde(default)]
    pub description: String,
}

#[tauri::command]
pub async fn custom_resources_list(db: State<'_, Db>) -> AppResult<Vec<CustomResource>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT id, title, url, category, description, created_at FROM resources ORDER BY title")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(CustomResource {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    url: r.get(2)?,
                    category: r.get(3)?,
                    description: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn custom_resource_upsert(db: State<'_, Db>, input: CustomResourceInput) -> AppResult<i64> {
    let title = clean("Title", &input.title, 120, true)?;
    let url = http_url("URL", &input.url)?.to_string();
    let category = one_of("Category", &input.category, RESOURCE_CATEGORIES)?;
    let description = clean("Description", &input.description, 500, false)?;
    db.with(|c| match input.id {
        Some(id) => {
            c.execute(
                "UPDATE resources SET title=?2, url=?3, category=?4, description=?5 WHERE id=?1",
                params![id, title, url, category, description],
            )?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO resources (title, url, category, description, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![title, url, category, description, now()],
            )?;
            Ok(c.last_insert_rowid())
        }
    })
}

#[tauri::command]
pub async fn custom_resource_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM resources WHERE id=?1", params![id])?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceVisit {
    pub resource_key: String,
    pub title: String,
    pub url: String,
    pub visited_at: String,
}

#[tauri::command]
pub async fn resource_visit(db: State<'_, Db>, resource_key: String, title: String, url: String) -> AppResult<()> {
    let key = clean("Resource", &resource_key, 200, true)?;
    let title = clean("Title", &title, 200, true)?;
    let url = http_url("URL", &url)?.to_string();
    db.with(|c| {
        c.execute(
            "INSERT INTO resource_visits (resource_key, title, url, visited_at) VALUES (?1,?2,?3,?4)",
            params![key, title, url, now()],
        )?;
        log(c, "resource_open", &format!("Opened {title}"), &url, Some("resource"), Some(&key), None)
    })
}

#[tauri::command]
pub async fn resource_recent(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<ResourceVisit>> {
    let limit = limit.unwrap_or(10).clamp(1, 100);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT resource_key, title, url, MAX(visited_at) AS v FROM resource_visits GROUP BY resource_key ORDER BY v DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(ResourceVisit { resource_key: r.get(0)?, title: r.get(1)?, url: r.get(2)?, visited_at: r.get(3)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/* ─────────────── saved commands & history ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedCommand {
    pub id: i64,
    pub title: String,
    pub command: String,
    pub description: String,
    pub category_id: String,
    pub os: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedCommandInput {
    pub id: Option<i64>,
    pub title: String,
    pub command: String,
    #[serde(default)]
    pub description: String,
    pub category_id: String,
    pub os: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

const COMMAND_CATEGORIES: &[&str] = &["general", "network", "web", "recon", "password", "forensics", "system"];

#[tauri::command]
pub async fn saved_commands_list(db: State<'_, Db>) -> AppResult<Vec<SavedCommand>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, title, command, description, category_id, os, tags, created_at, updated_at FROM commands ORDER BY updated_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SavedCommand {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    command: r.get(2)?,
                    description: r.get(3)?,
                    category_id: r.get(4)?,
                    os: r.get(5)?,
                    tags: json_to_tags(r.get(6)?),
                    created_at: r.get(7)?,
                    updated_at: r.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn saved_command_upsert(db: State<'_, Db>, input: SavedCommandInput) -> AppResult<i64> {
    let title = clean("Title", &input.title, 150, true)?;
    let command = clean("Command", &input.command, 8000, true)?;
    let description = clean("Description", &input.description, 2000, false)?;
    let category = one_of("Category", &input.category_id, COMMAND_CATEGORIES)?;
    let os = one_of("OS", &input.os, &["any", "windows", "macos", "linux"])?;
    let tags = tags_to_json(&input.tags)?;
    let ts = now();
    db.with(|c| match input.id {
        Some(id) => {
            c.execute(
                "UPDATE commands SET title=?2, command=?3, description=?4, category_id=?5, os=?6, tags=?7, updated_at=?8 WHERE id=?1",
                params![id, title, command, description, category, os, tags, ts],
            )?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO commands (title, command, description, category_id, os, tags, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
                params![title, command, description, category, os, tags, ts],
            )?;
            let id = c.last_insert_rowid();
            log(c, "command_saved", &format!("Saved command “{title}”"), "", Some("command"), Some(&id.to_string()), None)?;
            Ok(id)
        }
    })
}

#[tauri::command]
pub async fn saved_command_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM commands WHERE id=?1", params![id])?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandHistoryItem {
    pub id: i64,
    pub command: String,
    pub source: String,
    pub tool_id: Option<String>,
    pub project_id: Option<i64>,
    pub created_at: String,
}

#[tauri::command]
pub async fn command_history_list(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<CommandHistoryItem>> {
    let limit = limit.unwrap_or(100).clamp(1, 1000);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, command, source, tool_id, project_id, created_at FROM command_history ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(CommandHistoryItem {
                    id: r.get(0)?,
                    command: r.get(1)?,
                    source: r.get(2)?,
                    tool_id: r.get(3)?,
                    project_id: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn command_history_add(
    db: State<'_, Db>,
    command: String,
    source: String,
    tool_id: Option<String>,
    project_id: Option<i64>,
) -> AppResult<()> {
    let command = crate::redact::redact_command_line(&clean("Command", &command, 8000, true)?);
    let source = one_of("Source", &source, &["builder", "template", "saved", "tool", "execution", "manual"])?;
    if let Some(t) = &tool_id {
        if crate::catalog::tool(t).is_none() {
            return Err(crate::error::validation("Unknown tool"));
        }
    }
    db.with(|c| {
        // collapse immediate duplicates
        let last: Option<String> = c
            .query_row("SELECT command FROM command_history ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .ok();
        if last.as_deref() != Some(command.as_str()) {
            c.execute(
                "INSERT INTO command_history (command, source, tool_id, project_id, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![command, source, tool_id, project_id, now()],
            )?;
        }
        let short: String = command.chars().take(120).collect();
        log(c, "command_copy", "Copied command", &short, tool_id.as_deref().map(|_| "tool"), tool_id.as_deref(), project_id)
    })
}

#[tauri::command]
pub async fn command_history_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM command_history", [])?;
        Ok(())
    })
}

/* ─────────────── dorks ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedDork {
    pub id: i64,
    pub title: String,
    pub query: String,
    pub category: String,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedDorkInput {
    pub id: Option<i64>,
    pub title: String,
    pub query: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub notes: String,
}

#[tauri::command]
pub async fn saved_dorks_list(db: State<'_, Db>) -> AppResult<Vec<SavedDork>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, title, query, category, notes, created_at, updated_at FROM saved_dorks ORDER BY updated_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SavedDork {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    query: r.get(2)?,
                    category: r.get(3)?,
                    notes: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn saved_dork_upsert(db: State<'_, Db>, input: SavedDorkInput) -> AppResult<i64> {
    let title = clean("Title", &input.title, 150, true)?;
    let query = clean("Query", &input.query, 2000, true)?;
    let category = clean("Category", if input.category.is_empty() { "custom" } else { &input.category }, 60, true)?;
    let notes = clean("Notes", &input.notes, 2000, false)?;
    let ts = now();
    db.with(|c| match input.id {
        Some(id) => {
            c.execute(
                "UPDATE saved_dorks SET title=?2, query=?3, category=?4, notes=?5, updated_at=?6 WHERE id=?1",
                params![id, title, query, category, notes, ts],
            )?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO saved_dorks (title, query, category, notes, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?5)",
                params![title, query, category, notes, ts],
            )?;
            log(c, "dork_saved", &format!("Saved dork “{title}”"), &query, None, None, None)?;
            Ok(c.last_insert_rowid())
        }
    })
}

#[tauri::command]
pub async fn saved_dork_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM saved_dorks WHERE id=?1", params![id])?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DorkHistoryItem {
    pub id: i64,
    pub query: String,
    pub created_at: String,
}

#[tauri::command]
pub async fn dork_history_list(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<DorkHistoryItem>> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    db.with(|c| {
        let mut stmt = c.prepare("SELECT id, query, created_at FROM dork_history ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt
            .query_map(params![limit], |r| Ok(DorkHistoryItem { id: r.get(0)?, query: r.get(1)?, created_at: r.get(2)? }))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn dork_history_add(db: State<'_, Db>, query: String) -> AppResult<()> {
    let query = clean("Query", &query, 2000, true)?;
    db.with(|c| {
        c.execute("INSERT INTO dork_history (query, created_at) VALUES (?1, ?2)", params![query, now()])?;
        log(c, "dork_search", "Opened Google search", &query, None, None, None)
    })
}

#[tauri::command]
pub async fn dork_history_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM dork_history", [])?;
        Ok(())
    })
}

/* ─────────────── custom payloads ─────────────── */

const PAYLOAD_CATEGORIES: &[&str] =
    &["xss", "sqli", "ssrf", "lfi", "path-traversal", "ssti", "xxe", "auth", "input-validation", "http"];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomPayload {
    pub id: i64,
    pub title: String,
    pub payload: String,
    pub category: String,
    pub description: String,
    pub context: String,
    pub tags: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomPayloadInput {
    pub id: Option<i64>,
    pub title: String,
    pub payload: String,
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[tauri::command]
pub async fn custom_payloads_list(db: State<'_, Db>) -> AppResult<Vec<CustomPayload>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, title, payload, category, description, context, tags, created_at FROM payloads ORDER BY id DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(CustomPayload {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    payload: r.get(2)?,
                    category: r.get(3)?,
                    description: r.get(4)?,
                    context: r.get(5)?,
                    tags: json_to_tags(r.get(6)?),
                    created_at: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn custom_payload_upsert(db: State<'_, Db>, input: CustomPayloadInput) -> AppResult<i64> {
    let title = clean("Title", &input.title, 150, true)?;
    let payload = clean("Payload", &input.payload, 20000, true)?;
    let category = one_of("Category", &input.category, PAYLOAD_CATEGORIES)?;
    let description = clean("Description", &input.description, 1000, false)?;
    let context = clean("Context", &input.context, 200, false)?;
    let tags = tags_to_json(&input.tags)?;
    db.with(|c| match input.id {
        Some(id) => {
            c.execute(
                "UPDATE payloads SET title=?2, payload=?3, category=?4, description=?5, context=?6, tags=?7 WHERE id=?1",
                params![id, title, payload, category, description, context, tags],
            )?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO payloads (title, payload, category, description, context, tags, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![title, payload, category, description, context, tags, now()],
            )?;
            Ok(c.last_insert_rowid())
        }
    })
}

#[tauri::command]
pub async fn custom_payload_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM payloads WHERE id=?1", params![id])?;
        Ok(())
    })
}
