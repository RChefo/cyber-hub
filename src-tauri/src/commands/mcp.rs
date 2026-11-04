//! Settings → Integrations → MCP: bridge status and start/stop, permission policy, pending
//! approvals (decided only here, by the user), audit log and client configuration snippets.
//!
//! These are Tauri commands for Cyber Hub's own window. None of them is reachable through the
//! MCP bridge, so an MCP client cannot approve its own requests or change its permissions.

use std::sync::Arc;

use rusqlite::params;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::mcp::approvals::PendingView;
use crate::mcp::bridge::{Bridge, ConnView};
use crate::mcp::catalog::{self, Category, Policy};
use crate::mcp::ops::{self, AppDispatcher, ENABLED_PREF, EVENT_APPROVALS};
use crate::mcp::prompts;

/// Path of the `cyberhub-mcp` executable shipped next to the app binary, if present.
pub fn server_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join(format!("cyberhub-mcp{}", std::env::consts::EXE_SUFFIX));
    p.is_file().then_some(p)
}

fn set_enabled_pref(db: &Db, on: bool) -> AppResult<()> {
    db.with(|c| {
        c.execute(
            "INSERT INTO user_preferences (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![ENABLED_PREF, if on { "true" } else { "false" }, crate::util::now()],
        )?;
        Ok(())
    })
}

pub fn enabled_pref(db: &Db) -> bool {
    db.with(|c| Ok(c.query_row("SELECT value FROM user_preferences WHERE key = ?1", params![ENABLED_PREF], |r| r.get::<_, String>(0)).ok()))
        .ok()
        .flatten()
        .as_deref()
        == Some("true")
}

/// Start the loopback bridge (used at startup when enabled and from Settings).
pub async fn start_bridge(app: &AppHandle) -> AppResult<()> {
    let dir = app.path().app_data_dir()?.join("mcp");
    let bridge = app.state::<Arc<Bridge>>();
    let (_, started) = bridge.start(dir, Arc::new(AppDispatcher { app: app.clone() })).map_err(AppError::Internal)?;
    if !started {
        return Ok(());
    }
    // expire unanswered approvals in the background (one loop per running bridge)
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let b = app2.state::<Arc<Bridge>>();
            if b.info().is_none() {
                break;
            }
            if b.approvals.expire() > 0 {
                let _ = app2.emit(EVENT_APPROVALS, b.approvals.pending_count());
            }
        }
    });
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRow {
    pub category: &'static str,
    pub label: &'static str,
    pub policy: Policy,
    pub options: Vec<Policy>,
    pub tools: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub enabled: bool,
    pub running: bool,
    /// always 127.0.0.1
    pub address: Option<String>,
    pub started_at: Option<String>,
    pub transport: &'static str,
    pub server_path: Option<String>,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub connections: Vec<ConnView>,
    pub pending: usize,
    pub policy: Vec<PolicyRow>,
}

#[tauri::command]
pub async fn mcp_status(db: State<'_, Db>, bridge: State<'_, Arc<Bridge>>) -> AppResult<McpStatus> {
    let info = bridge.info();
    let policy = ops::load_policy(&db);
    Ok(McpStatus {
        enabled: enabled_pref(&db),
        running: info.is_some(),
        address: info.as_ref().map(|(p, _)| format!("127.0.0.1:{p}")),
        started_at: info.map(|(_, s)| s),
        transport: "stdio (MCP client ↔ cyberhub-mcp) · authenticated loopback bridge (cyberhub-mcp ↔ Cyber Hub)",
        server_path: server_path().map(|p| p.to_string_lossy().to_string()),
        tool_count: catalog::TOOLS.len(),
        resource_count: catalog::RESOURCES.len() + 1,
        prompt_count: prompts::PROMPTS.len(),
        connections: bridge.connections(),
        pending: bridge.approvals.pending_count(),
        policy: Category::ALL
            .into_iter()
            .map(|c| PolicyRow {
                category: c.as_str(),
                label: c.label(),
                policy: policy[&c],
                options: c.allowed_policies().to_vec(),
                tools: catalog::TOOLS.iter().filter(|t| t.category == c).map(|t| t.name).collect(),
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn mcp_set_enabled(app: AppHandle, db: State<'_, Db>, enabled: bool) -> AppResult<()> {
    set_enabled_pref(&db, enabled)?;
    if enabled {
        start_bridge(&app).await
    } else {
        app.state::<Arc<Bridge>>().stop();
        let _ = app.emit(EVENT_APPROVALS, 0);
        Ok(())
    }
}

#[tauri::command]
pub async fn mcp_set_policy(db: State<'_, Db>, category: String, policy: String) -> AppResult<()> {
    let c = Category::parse(&category).ok_or_else(|| validation("Unknown category"))?;
    let p = Policy::parse(&policy).ok_or_else(|| validation("Unknown policy"))?;
    ops::save_policy(&db, c, p)
}

#[tauri::command]
pub async fn mcp_pending(bridge: State<'_, Arc<Bridge>>) -> AppResult<Vec<PendingView>> {
    Ok(bridge.approvals.list())
}

/// The user's decision on a pending MCP request. Only Cyber Hub's own window can call this.
#[tauri::command]
pub async fn mcp_decide(app: AppHandle, bridge: State<'_, Arc<Bridge>>, id: String, approve: bool) -> AppResult<bool> {
    let ok = bridge.approvals.decide(&id, approve);
    let _ = app.emit(EVENT_APPROVALS, bridge.approvals.pending_count());
    Ok(ok)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub client: String,
    pub connection: i64,
    pub tool: String,
    pub arguments: String,
    pub project_id: Option<i64>,
    pub approval: String,
    pub approval_id: Option<String>,
    pub execution_id: Option<i64>,
    pub result: String,
    pub message: String,
    pub duration_ms: i64,
}

#[tauri::command]
pub async fn mcp_audit(db: State<'_, Db>, limit: Option<i64>) -> AppResult<Vec<AuditRow>> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, at, client, connection, tool, arguments, project_id, approval, approval_id, execution_id, result, message, duration_ms FROM mcp_audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(AuditRow {
                id: r.get(0)?,
                at: r.get(1)?,
                client: r.get(2)?,
                connection: r.get(3)?,
                tool: r.get(4)?,
                arguments: r.get(5)?,
                project_id: r.get(6)?,
                approval: r.get(7)?,
                approval_id: r.get(8)?,
                execution_id: r.get(9)?,
                result: r.get(10)?,
                message: r.get(11)?,
                duration_ms: r.get(12)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
}

#[tauri::command]
pub async fn mcp_audit_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM mcp_audit", [])?;
        Ok(())
    })
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClientConfigs {
    /// `claude mcp add …` command line
    pub claude_code_command: String,
    /// project `.mcp.json` content
    pub claude_code_json: String,
    /// `claude_desktop_config.json` content
    pub claude_desktop_json: String,
    /// where Claude Desktop keeps its configuration on this OS (None where unsupported)
    pub claude_desktop_config_path: Option<String>,
}

/// Quote an argument for the shell the user is likely to paste into.
fn shell_quote(s: &str) -> String {
    if cfg!(windows) {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn client_configs(server: &str) -> ClientConfigs {
    let code_json = serde_json::json!({ "mcpServers": { "cyberhub": { "type": "stdio", "command": server, "args": [] } } });
    let desktop_json = serde_json::json!({ "mcpServers": { "cyberhub": { "command": server, "args": [] } } });
    let desktop_path = if cfg!(windows) {
        dirs::config_dir().map(|d| d.join("Claude").join("claude_desktop_config.json"))
    } else if cfg!(target_os = "macos") {
        dirs::home_dir().map(|d| d.join("Library").join("Application Support").join("Claude").join("claude_desktop_config.json"))
    } else {
        None
    };
    ClientConfigs {
        claude_code_command: format!("claude mcp add --transport stdio --scope user cyberhub -- {}", shell_quote(server)),
        claude_code_json: serde_json::to_string_pretty(&code_json).unwrap_or_default(),
        claude_desktop_json: serde_json::to_string_pretty(&desktop_json).unwrap_or_default(),
        claude_desktop_config_path: desktop_path.map(|p| p.to_string_lossy().to_string()),
    }
}

/// Configuration snippets that use the actual `cyberhub-mcp` path, or an error if the
/// executable is not installed next to Cyber Hub.
#[tauri::command]
pub async fn mcp_client_configs() -> AppResult<ClientConfigs> {
    let p = server_path().ok_or_else(|| AppError::NotFound("cyberhub-mcp was not found next to the Cyber Hub executable. Build it with `cargo build --bin cyberhub-mcp` (see docs/MCP.md).".into()))?;
    Ok(client_configs(&p.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_configs_use_the_real_path_and_escape_it() {
        let path = if cfg!(windows) { r#"C:\Program Files\Cyber Hub\cyberhub-mcp.exe"# } else { "/opt/cyber hub/cyberhub-mcp" };
        let c = client_configs(path);
        let code: serde_json::Value = serde_json::from_str(&c.claude_code_json).unwrap();
        assert_eq!(code["mcpServers"]["cyberhub"]["command"], path);
        assert_eq!(code["mcpServers"]["cyberhub"]["type"], "stdio");
        let desk: serde_json::Value = serde_json::from_str(&c.claude_desktop_json).unwrap();
        assert_eq!(desk["mcpServers"]["cyberhub"]["command"], path);
        assert!(c.claude_code_command.starts_with("claude mcp add --transport stdio --scope user cyberhub -- "));
        assert!(c.claude_code_command.ends_with(&shell_quote(path)), "{}", c.claude_code_command);
        assert!(!c.claude_code_json.contains("key") && !c.claude_desktop_json.contains("env"), "no credentials or environment in client configs");
        if cfg!(windows) || cfg!(target_os = "macos") {
            assert!(c.claude_desktop_config_path.unwrap().ends_with("claude_desktop_config.json"));
        }
    }

    #[test]
    fn decisions_and_policy_are_not_bridge_operations() {
        // the bridge only dispatches catalog tools; approving or changing policy is not one
        for t in catalog::TOOLS {
            for banned in ["approve", "decide", "policy", "enable", "key", "secret", "credential"] {
                assert!(!t.name.contains(banned), "{} must not be exposed to MCP clients", t.name);
            }
        }
    }
}
