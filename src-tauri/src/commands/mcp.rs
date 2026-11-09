//! The MCP page: bridge status and start/stop, the server catalogue, clients, permission
//! policy, pending approvals (decided only here, by the user), audit log and client
//! configuration snippets.
//!
//! These are Tauri commands for Cyber Hub's own window. None of them is reachable through the
//! MCP bridge, so an MCP client cannot approve its own requests or change its permissions.

use std::sync::Arc;

use std::collections::BTreeMap;

use rusqlite::{params, params_from_iter, types::Value as SqlValue};
use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::mcp::approvals::PendingView;
use crate::mcp::bridge::{Bridge, ConnView};
use crate::mcp::catalog::{self, Category, Policy};
use crate::mcp::ops::{self, AppDispatcher, ENABLED_PREF, EVENT_APPROVALS};
use crate::mcp::prompts;

/// Path of the `cyberhub-mcp` executable shipped next to the app binary, if present.
///
/// Installers place it (the bundler ships every `[[bin]]` of this crate) in the same
/// directory as the Cyber Hub executable: the installation folder on Windows and `/usr/bin` for
/// the Linux packages. In development
/// cargo builds it into the same `target/<profile>` directory. The lookup never uses the working
/// directory or PATH.
pub fn server_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join(format!("cyberhub-mcp{}", std::env::consts::EXE_SUFFIX));
    p.is_file().then_some(p)
}

/// A warning about the server path for the MCP page: missing executable, or a path that will not
/// survive a restart (AppImage mount).
pub fn server_path_note(path: Option<&std::path::Path>) -> Option<String> {
    let appdir = std::env::var_os("APPIMAGE").and(std::env::var_os("APPDIR"));
    path_note(path, appdir.as_deref().map(std::path::Path::new), cfg!(debug_assertions))
}

fn path_note(path: Option<&std::path::Path>, appimage_dir: Option<&std::path::Path>, dev_build: bool) -> Option<String> {
    let Some(path) = path else {
        return Some(if dev_build {
            "cyberhub-mcp was not found next to the Cyber Hub executable. Build it with `cargo build --bin cyberhub-mcp` (see docs/MCP.md).".into()
        } else {
            "cyberhub-mcp is missing from the Cyber Hub installation folder. Reinstall Cyber Hub to restore it.".into()
        });
    };
    if appimage_dir.is_some_and(|d| path.starts_with(d)) {
        return Some("Cyber Hub is running from an AppImage, so this path is inside a temporary mount that changes every time Cyber Hub starts. MCP clients configured with it stop working after a restart. Install the .deb or .rpm package for a fixed path.".into());
    }
    None
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
    let dir = crate::util::data_dir(app)?.join("mcp");
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
    /// why the server path is missing or will not stay valid, if so
    pub server_path_note: Option<String>,
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
    let server = server_path();
    Ok(McpStatus {
        enabled: enabled_pref(&db),
        running: info.is_some(),
        address: info.as_ref().map(|(p, _)| format!("127.0.0.1:{p}")),
        started_at: info.map(|(_, s)| s),
        transport: "stdio (MCP client ↔ cyberhub-mcp) · authenticated loopback bridge (cyberhub-mcp ↔ Cyber Hub)",
        server_path: server.as_ref().map(|p| p.to_string_lossy().to_string()),
        server_path_note: server_path_note(server.as_deref()),
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
    /// permission category that applied (older rows: the tool's catalogue category)
    pub category: Option<String>,
}

/// Optional filters for the audit log.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditFilter {
    pub client: Option<String>,
    pub category: Option<String>,
    /// ok | awaiting_approval | refused | error
    pub result: Option<String>,
}

const RESULTS: [&str; 4] = ["ok", "awaiting_approval", "refused", "error"];

/// Query the audit log, newest first. Filters are validated and bound as parameters.
pub fn audit_rows(db: &Db, limit: i64, f: &AuditFilter) -> AppResult<Vec<AuditRow>> {
    let mut sql = String::from(
        "SELECT id, at, client, connection, tool, arguments, project_id, approval, approval_id, execution_id, result, message, duration_ms, category FROM mcp_audit WHERE 1=1",
    );
    let mut args: Vec<SqlValue> = vec![];
    if let Some(cl) = f.client.as_deref().filter(|c| !c.is_empty()) {
        sql.push_str(" AND client = ?");
        args.push(SqlValue::Text(cl.chars().take(128).collect()));
    }
    if let Some(cat) = f.category.as_deref().filter(|c| !c.is_empty()) {
        let c = Category::parse(cat).ok_or_else(|| validation("Unknown category"))?;
        // rows written before the category column existed fall back to the tool's category
        let tools: Vec<&str> = catalog::TOOLS.iter().filter(|t| t.category == c).map(|t| t.name).collect();
        sql.push_str(" AND (category = ? OR (category IS NULL AND tool IN (SELECT value FROM json_each(?))))");
        args.push(SqlValue::Text(c.as_str().into()));
        args.push(SqlValue::Text(serde_json::to_string(&tools).unwrap_or_else(|_| "[]".into())));
    }
    if let Some(r) = f.result.as_deref().filter(|r| !r.is_empty()) {
        if !RESULTS.contains(&r) {
            return Err(validation("Unknown result"));
        }
        sql.push_str(" AND result = ?");
        args.push(SqlValue::Text(r.into()));
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    args.push(SqlValue::Integer(limit.clamp(1, 1000)));
    db.with(|c| {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
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
                category: r.get::<_, Option<String>>(13)?.or_else(|| catalog::tool(&r.get::<_, String>(4).unwrap_or_default()).map(|t| t.category.as_str().to_string())),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
}

#[tauri::command]
pub async fn mcp_audit(db: State<'_, Db>, limit: Option<i64>, filter: Option<AuditFilter>) -> AppResult<Vec<AuditRow>> {
    audit_rows(&db, limit.unwrap_or(50), &filter.unwrap_or_default())
}

/* ───────────────────────── catalogue ───────────────────────── */

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Param {
    pub name: String,
    /// JSON type, e.g. "string", "integer", "array of string"
    pub kind: String,
    pub required: bool,
    pub description: String,
    pub values: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogTool {
    pub name: &'static str,
    pub title: &'static str,
    pub group: &'static str,
    pub group_label: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub category_label: &'static str,
    pub policy: Policy,
    /// the user is asked before it runs (current policy)
    pub requires_approval: bool,
    /// a native system dialog always follows approval
    pub native_confirmation: bool,
    pub available: bool,
    /// why it is unavailable, or a note about conditional permission
    pub note: Option<String>,
    pub read_only: bool,
    pub parameters: Vec<Param>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResource {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mime_type: &'static str,
    pub template: bool,
    /// the read-only tool that serves it
    pub served_by: &'static str,
    pub parameters: Vec<Param>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPrompt {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub arguments: Vec<Param>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCatalog {
    pub groups: Vec<(&'static str, &'static str)>,
    pub tools: Vec<CatalogTool>,
    pub resources: Vec<CatalogResource>,
    pub prompts: Vec<CatalogPrompt>,
    pub instructions: &'static str,
}

/// Parameters of an object JSON schema, required ones first.
pub fn schema_params(schema: &Value) -> Vec<Param> {
    let required: Vec<&str> = schema.get("required").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let kind_of = |v: &Value| -> String {
        match v.get("type").and_then(Value::as_str) {
            Some("array") => format!("array of {}", v.get("items").and_then(|i| i.get("type")).and_then(Value::as_str).unwrap_or("values")),
            Some(t) => t.to_string(),
            None => "value".into(),
        }
    };
    let mut out: Vec<Param> = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| {
            props
                .iter()
                .map(|(name, v)| Param {
                    name: name.clone(),
                    kind: kind_of(v),
                    required: required.contains(&name.as_str()),
                    description: v.get("description").and_then(Value::as_str).unwrap_or_default().to_string(),
                    values: v.get("enum").and_then(Value::as_array).map(|e| e.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|p| !p.required);
    out
}

pub fn build_catalog(policy: &std::collections::HashMap<Category, Policy>, running: bool) -> McpCatalog {
    let tools = catalog::TOOLS
        .iter()
        .map(|t| {
            let p = policy.get(&t.category).copied().unwrap_or(Policy::Deny);
            let conditional = catalog::CONDITIONAL_CATEGORY.iter().find(|(name, _, _)| *name == t.name);
            let note = if !running {
                Some("MCP is off".to_string())
            } else if p == Policy::Deny {
                Some(format!("Blocked by your policy for “{}”", t.category.label()))
            } else {
                conditional.map(|(_, arg, c)| {
                    let cp = policy.get(c).copied().unwrap_or(Policy::Deny);
                    format!(
                        "With {arg}: true it queries NVD and follows “{}” ({})",
                        c.label(),
                        match cp {
                            Policy::Allow => "allowed",
                            Policy::Ask => "asks you",
                            Policy::Deny => "blocked",
                        }
                    )
                })
            };
            CatalogTool {
                name: t.name,
                title: t.title,
                group: t.group,
                group_label: catalog::GROUPS.iter().find(|(g, _)| *g == t.group).map(|(_, l)| *l).unwrap_or(t.group),
                description: t.description,
                category: t.category.as_str(),
                category_label: t.category.label(),
                policy: p,
                requires_approval: p == Policy::Ask,
                native_confirmation: matches!(t.category, Category::RunTools | Category::FileUpload | Category::Export),
                available: running && p != Policy::Deny,
                note,
                read_only: t.category == Category::Read,
                parameters: schema_params(&(t.schema)()),
            }
        })
        .collect();
    let mut resources: Vec<CatalogResource> = catalog::RESOURCES
        .iter()
        .map(|(uri, name, description, tool)| CatalogResource { uri, name, description, mime_type: "application/json", template: false, served_by: tool, parameters: vec![] })
        .collect();
    resources.push(CatalogResource {
        uri: catalog::SCOPE_TEMPLATE,
        name: catalog::SCOPE_TEMPLATE_NAME,
        description: catalog::SCOPE_TEMPLATE_DESCRIPTION,
        mime_type: "application/json",
        template: true,
        served_by: "cyberhub_get_project_scope",
        parameters: vec![Param { name: "project_id".into(), kind: "integer".into(), required: true, description: "Cyber Hub project ID".into(), values: vec![] }],
    });
    let prompts = prompts::PROMPTS
        .iter()
        .map(|p| CatalogPrompt {
            name: p.name,
            title: p.title,
            description: p.description,
            arguments: p.arguments.iter().map(|(n, d, r)| Param { name: (*n).into(), kind: "string".into(), required: *r, description: (*d).into(), values: vec![] }).collect(),
        })
        .collect();
    McpCatalog { groups: catalog::GROUPS.to_vec(), tools, resources, prompts, instructions: catalog::SERVER_INSTRUCTIONS }
}

/// The catalogue `cyberhub-mcp` advertises, with the current policy and availability of each tool.
#[tauri::command]
pub async fn mcp_catalog(db: State<'_, Db>, bridge: State<'_, Arc<Bridge>>) -> AppResult<McpCatalog> {
    Ok(build_catalog(&ops::load_policy(&db), bridge.info().is_some()))
}

/* ───────────────────────── clients ───────────────────────── */

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpClientRow {
    /// self-reported "name version" (never verified)
    pub label: String,
    pub name: String,
    pub version: String,
    pub connected: bool,
    pub connections: usize,
    pub connected_since: Option<String>,
    /// requests on the current connections
    pub session_requests: u64,
    /// requests in the audit log
    pub logged_requests: i64,
    pub last_activity: Option<String>,
    pub last_tool: Option<String>,
    pub last_result: Option<String>,
    pub last_approval: Option<String>,
}

/// Split a logged "name version" label; the version is the last word if it starts with a digit.
pub fn split_label(label: &str) -> (String, String) {
    match label.rsplit_once(' ') {
        Some((name, v)) if !name.trim().is_empty() && v.chars().next().is_some_and(|c| c.is_ascii_digit()) => (name.to_string(), v.to_string()),
        _ => (label.to_string(), String::new()),
    }
}

/// Connected clients (from the bridge) merged with recently active ones (from the audit log).
pub fn client_rows(db: &Db, live: &[ConnView]) -> AppResult<Vec<McpClientRow>> {
    let mut rows: BTreeMap<String, McpClientRow> = BTreeMap::new();
    for c in live {
        let r = rows.entry(c.client.clone()).or_default();
        r.label = c.client.clone();
        r.name = c.client_name.clone();
        r.version = c.client_version.clone();
        r.connected = true;
        r.connections += 1;
        r.session_requests += c.requests;
        if r.connected_since.as_deref().is_none_or(|s| c.connected_at.as_str() < s) {
            r.connected_since = Some(c.connected_at.clone());
        }
    }
    let logged: Vec<(String, i64, String, String, String, String)> = db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT a.client, g.n, a.at, a.tool, a.result, a.approval FROM mcp_audit a
             JOIN (SELECT client, COUNT(*) AS n, MAX(id) AS last FROM mcp_audit GROUP BY client) g ON a.id = g.last
             ORDER BY a.id DESC LIMIT 50",
        )?;
        let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?;
        Ok(it.collect::<Result<Vec<_>, _>>()?)
    })?;
    for (label, n, at, tool, result, approval) in logged {
        let r = rows.entry(label.clone()).or_default();
        if r.label.is_empty() {
            let (name, version) = split_label(&label);
            r.label = label;
            r.name = name;
            r.version = version;
        }
        r.logged_requests = n;
        r.last_activity = Some(at);
        r.last_tool = Some(tool);
        r.last_result = Some(result);
        r.last_approval = Some(approval);
    }
    let mut v: Vec<McpClientRow> = rows.into_values().collect();
    v.sort_by(|a, b| b.connected.cmp(&a.connected).then_with(|| b.last_activity.cmp(&a.last_activity)));
    Ok(v)
}

#[tauri::command]
pub async fn mcp_clients(db: State<'_, Db>, bridge: State<'_, Arc<Bridge>>) -> AppResult<Vec<McpClientRow>> {
    client_rows(&db, &bridge.connections())
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
    // Claude Desktop exists for Windows, not for Linux
    let desktop_path = if cfg!(windows) { dirs::config_dir().map(|d| d.join("Claude").join("claude_desktop_config.json")) } else { None };
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
    let p = server_path().ok_or_else(|| AppError::NotFound(server_path_note(None).unwrap_or_default()))?;
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
        if cfg!(windows) {
            assert!(c.claude_desktop_config_path.unwrap().ends_with("claude_desktop_config.json"));
        }
    }

    #[test]
    fn server_path_notes() {
        use std::path::Path;
        let installed = if cfg!(windows) { r#"C:\Users\a b\AppData\Local\Cyber Hub\cyberhub-mcp.exe"# } else { "/usr/bin/cyberhub-mcp" };
        assert_eq!(path_note(Some(Path::new(installed)), None, false), None);
        assert!(path_note(None, None, false).unwrap().contains("Reinstall"));
        assert!(path_note(None, None, true).unwrap().contains("cargo build --bin cyberhub-mcp"));
        let mount = Path::new("/tmp/.mount_CyberHXy12/usr/bin/cyberhub-mcp");
        assert!(path_note(Some(mount), Some(Path::new("/tmp/.mount_CyberHXy12")), false).unwrap().contains("AppImage"));
        // AppImage variables inherited from a parent process do not affect an installed copy
        assert_eq!(path_note(Some(Path::new("/usr/bin/cyberhub-mcp")), Some(Path::new("/tmp/.mount_CyberHXy12")), false), None);
    }

    fn audit_db() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let ins = "INSERT INTO mcp_audit (at, client, connection, tool, arguments, project_id, approval, result, message, duration_ms, category) VALUES (?1, ?2, 1, ?3, '{}', NULL, 'not_required', ?4, '', 1, ?5)";
            c.execute(ins, params!["2026-01-01T00:00:01Z", "claude-code 2.1", "cyberhub_get_status", "ok", "read"])?;
            c.execute(ins, params!["2026-01-01T00:00:02Z", "claude-code 2.1", "cyberhub_lookup_cve", "ok", "external_lookup"])?;
            c.execute(ins, params!["2026-01-01T00:00:03Z", "other", "cyberhub_run_tool", "refused", "run_tools"])?;
            // a row written before migration 5 (no category)
            c.execute(ins, params!["2026-01-01T00:00:04Z", "other", "cyberhub_vt_lookup", "error", None::<String>])?;
            Ok(())
        })
        .unwrap();
        db
    }

    #[test]
    fn audit_filters_by_client_category_and_result() {
        let db = audit_db();
        let all = audit_rows(&db, 50, &AuditFilter::default()).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].category.as_deref(), Some("external_lookup"), "older rows fall back to the tool's category");
        let by_client = audit_rows(&db, 50, &AuditFilter { client: Some("claude-code 2.1".into()), ..Default::default() }).unwrap();
        assert_eq!(by_client.len(), 2);
        // the effective category is used: a live CVE lookup is an external lookup, not a read
        let ext = audit_rows(&db, 50, &AuditFilter { category: Some("external_lookup".into()), ..Default::default() }).unwrap();
        assert_eq!(ext.iter().map(|r| r.tool.as_str()).collect::<Vec<_>>(), ["cyberhub_vt_lookup", "cyberhub_lookup_cve"]);
        let refused = audit_rows(&db, 50, &AuditFilter { result: Some("refused".into()), ..Default::default() }).unwrap();
        assert_eq!(refused.len(), 1);
        assert!(audit_rows(&db, 50, &AuditFilter { category: Some("x' OR 1=1 --".into()), ..Default::default() }).is_err());
        assert!(audit_rows(&db, 50, &AuditFilter { result: Some("ok' --".into()), ..Default::default() }).is_err());
        assert_eq!(audit_rows(&db, 1, &AuditFilter::default()).unwrap().len(), 1);
    }

    #[test]
    fn clients_merge_live_connections_with_the_log() {
        let db = audit_db();
        let live = vec![ConnView { id: 3, client: "claude-code 2.1".into(), client_name: "claude-code".into(), client_version: "2.1".into(), connected_at: "2026-01-01T00:00:00Z".into(), requests: 2, last_request_at: None }];
        let rows = client_rows(&db, &live).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].connected && rows[0].name == "claude-code" && rows[0].version == "2.1");
        assert_eq!(rows[0].logged_requests, 2);
        assert_eq!(rows[0].last_tool.as_deref(), Some("cyberhub_lookup_cve"));
        assert!(!rows[1].connected);
        assert_eq!((rows[1].name.as_str(), rows[1].version.as_str()), ("other", ""));
        assert_eq!(split_label("claude-code 2.1.318"), ("claude-code".into(), "2.1.318".into()));
        assert_eq!(split_label("unknown MCP client"), ("unknown MCP client".into(), String::new()));
        assert_eq!(split_label("Claude Desktop 0.9"), ("Claude Desktop".into(), "0.9".into()));
        assert_eq!(rows[1].last_result.as_deref(), Some("error"));
    }

    #[test]
    fn catalog_matches_the_server_and_reflects_policy() {
        let mut policy: std::collections::HashMap<Category, Policy> = Category::ALL.into_iter().map(|c| (c, c.default_policy())).collect();
        policy.insert(Category::Export, Policy::Deny);
        let c = build_catalog(&policy, true);
        assert_eq!(c.tools.len(), catalog::TOOLS.len());
        assert_eq!(c.resources.len(), catalog::RESOURCES.len() + 1);
        assert_eq!(c.prompts.len(), prompts::PROMPTS.len());
        let run = c.tools.iter().find(|t| t.name == "cyberhub_run_tool").unwrap();
        assert!(run.requires_approval && run.native_confirmation && run.available);
        assert_eq!(run.parameters.iter().filter(|p| p.required).map(|p| p.name.as_str()).collect::<Vec<_>>().len(), 2);
        let export = c.tools.iter().find(|t| t.name == "cyberhub_export_report").unwrap();
        assert!(!export.available && export.note.as_deref().unwrap().contains("Blocked"));
        let status = c.tools.iter().find(|t| t.name == "cyberhub_get_status").unwrap();
        assert!(status.read_only && !status.requires_approval);
        assert!(c.tools.iter().find(|t| t.name == "cyberhub_lookup_cve").unwrap().note.is_some());
        let off = build_catalog(&policy, false);
        assert!(off.tools.iter().all(|t| !t.available));
        assert!(c.resources.iter().any(|r| r.template && r.parameters.len() == 1));
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
