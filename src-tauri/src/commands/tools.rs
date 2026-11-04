//! Tool registry, detection, managed installation, GUI launch and execution.

use std::path::PathBuf;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use crate::catalog::{self, Catalog, CATALOG};
use crate::commands::activity::log;
use crate::commands::projects::scope_entries;
use crate::db::Db;
use crate::detect::{self, Detection};
use crate::error::{validation, AppError, AppResult};
use crate::process::{self, ExecEvent, ProcessManager, SpawnSpec};
use crate::util::{current_os, now};
use crate::{confirm, redact, targets};

/// Keep the `tools`/`tool_categories` tables aligned with the compiled catalog.
pub fn sync_catalog(db: &Db) -> AppResult<()> {
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        for (i, cat) in CATALOG.categories.iter().enumerate() {
            tx.execute(
                "INSERT INTO tool_categories (id, name, sort_order) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, sort_order = excluded.sort_order",
                params![cat.id, cat.name, i as i64],
            )?;
        }
        for t in &CATALOG.tools {
            tx.execute(
                "INSERT INTO tools (id, name, category_id, catalog_version) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, category_id = excluded.category_id, catalog_version = excluded.catalog_version",
                params![t.id, t.name, t.category, CATALOG.version],
            )?;
        }
        let ids: Vec<String> = CATALOG.tools.iter().map(|t| format!("'{}'", t.id.replace('\'', ""))).collect();
        tx.execute(&format!("DELETE FROM tools WHERE id NOT IN ({})", ids.join(",")), [])?;
        tx.commit()?;
        Ok(())
    })
}

#[tauri::command]
pub async fn tools_catalog() -> AppResult<&'static Catalog> {
    Ok(&*CATALOG)
}

fn save_detection(c: &Connection, d: &Detection) -> AppResult<()> {
    c.execute(
        "INSERT INTO tool_installations (tool_id, status, path, version, missing_dependencies, message, checked_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(tool_id) DO UPDATE SET status=excluded.status, path=excluded.path, version=excluded.version,
           missing_dependencies=excluded.missing_dependencies, message=excluded.message, checked_at=excluded.checked_at",
        params![
            d.tool_id,
            d.status,
            d.path,
            d.version,
            serde_json::to_string(&d.missing_dependencies)?,
            d.message,
            d.checked_at
        ],
    )?;
    Ok(())
}

fn read_detection(r: &rusqlite::Row) -> rusqlite::Result<Detection> {
    Ok(Detection {
        tool_id: r.get(0)?,
        status: r.get(1)?,
        path: r.get(2)?,
        version: r.get(3)?,
        missing_dependencies: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        message: r.get(5)?,
        checked_at: r.get(6)?,
    })
}

#[tauri::command]
pub async fn tools_detection_list(db: State<'_, Db>) -> AppResult<Vec<Detection>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT tool_id, status, path, version, missing_dependencies, message, checked_at FROM tool_installations",
        )?;
        let rows = stmt.query_map([], read_detection)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// Scan the system for catalog tools. PATH lookup always; version probing (which runs
/// each detected CLI with fixed, catalog-defined version flags) only when requested.
#[tauri::command]
pub async fn tools_scan(db: State<'_, Db>, probe_versions: bool, tool_ids: Option<Vec<String>>) -> AppResult<Vec<Detection>> {
    let wanted: Vec<&'static catalog::ToolDef> = CATALOG
        .tools
        .iter()
        .filter(|t| tool_ids.as_ref().map(|ids| ids.iter().any(|i| i == &t.id)).unwrap_or(true))
        .collect();
    let results = tauri::async_runtime::spawn_blocking(move || {
        std::thread::scope(|s| {
            let handles: Vec<_> = wanted
                .chunks(6)
                .map(|chunk| s.spawn(move || chunk.iter().filter_map(|t| detect::detect_tool(t, probe_versions)).collect::<Vec<_>>()))
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect::<Vec<_>>()
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        for d in &results {
            let prev: Option<String> = tx
                .query_row("SELECT status FROM tool_installations WHERE tool_id=?1", params![d.tool_id], |r| r.get(0))
                .optional()?;
            // keep a failed-install marker visible until the tool is actually found
            if prev.as_deref() == Some("installation_failed") && d.status == "not_installed" {
                continue;
            }
            save_detection(&tx, d)?;
        }
        let installed = results.iter().filter(|d| d.status == "installed").count();
        log(&tx, "tool_scan", &format!("Tool scan: {installed} of {} detected", results.len()), "", None, None, None)?;
        tx.execute(
            "INSERT INTO user_preferences (key, value, updated_at) VALUES ('tools.lastScan', ?1, ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            params![serde_json::to_string(&now())?],
        )?;
        tx.commit()?;
        Ok(())
    })?;
    Ok(results)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerAvailability {
    pub manager: String,
    pub available: bool,
    pub path: Option<String>,
}

#[tauri::command]
pub async fn package_managers() -> AppResult<Vec<ManagerAvailability>> {
    Ok(catalog::ALLOWED_MANAGERS
        .iter()
        .map(|m| {
            let p = detect::find_binary(m);
            ManagerAvailability { manager: m.to_string(), available: p.is_some(), path: p.map(|p| p.to_string_lossy().to_string()) }
        })
        .collect())
}

/// Install a tool through a supported package manager using the exact arguments
/// defined in the catalog. Requires explicit confirmation from the UI.
#[tauri::command]
pub async fn tool_install(
    app: AppHandle,
    tool_id: String,
    manager: String,
    confirmed: bool,
    on_event: Channel<ExecEvent>,
) -> AppResult<i64> {
    if !confirmed {
        return Err(validation("Installation must be explicitly confirmed"));
    }
    let tool = catalog::tool(&tool_id).ok_or_else(|| AppError::NotFound(format!("tool {tool_id}")))?;
    let entry = tool
        .managed
        .iter()
        .find(|m| m.manager == manager && m.os.iter().any(|o| o == current_os()))
        .ok_or_else(|| validation(format!("No {manager} install recipe for {} on {}", tool.name, current_os())))?;
    let program = detect::find_binary(&entry.manager)
        .ok_or_else(|| validation(format!("Package manager '{}' was not found on PATH", entry.manager)))?;
    let command_line = std::iter::once(program.to_string_lossy().to_string()).chain(entry.args.iter().cloned()).collect::<Vec<_>>().join(" ");
    let text = format!(
        "Install {} using {}?\n\nThis runs:\n{command_line}\n\nSoftware is downloaded from the {} source and installed with your user account.",
        tool.name, entry.manager, entry.manager
    );
    if !confirm::native(&app, "Confirm installation", text, "Install").await {
        return Err(AppError::Cancelled("Installation was cancelled in the confirmation dialog".into()));
    }

    let id_for_hook = tool.id.clone();
    let hook: process::FinishHook = Box::new(move |app: &AppHandle, ok: bool| {
        let db = app.state::<Db>();
        let tool = catalog::tool(&id_for_hook);
        let detection = tool.and_then(|t| detect::detect_tool(t, true));
        let _ = db.with(|c| {
            match detection {
                Some(d) if d.status == "installed" || d.status == "dependency_missing" => save_detection(c, &d)?,
                _ => {
                    let msg = if ok {
                        "Package manager reported success but the executable was not found on PATH. Restart Cyber Hub or add the install directory to PATH."
                    } else {
                        "Package manager exited with an error. See the installation log."
                    };
                    save_detection(
                        c,
                        &Detection {
                            tool_id: id_for_hook.clone(),
                            status: "installation_failed".into(),
                            path: None,
                            version: None,
                            missing_dependencies: vec![],
                            message: Some(msg.into()),
                            checked_at: now(),
                        },
                    )?
                }
            }
            Ok(())
        });
    });

    process::start(
        &app,
        SpawnSpec {
            tool_id: tool.id.clone(),
            kind: "install",
            program,
            args: entry.args.clone(),
            project_id: None,
            cleanup_dir: None,
        },
        on_event,
        Some(hook),
    )
}

/// Launch a GUI tool (no arguments).
#[tauri::command]
pub async fn tool_launch(db: State<'_, Db>, tool_id: String) -> AppResult<()> {
    let tool = catalog::tool(&tool_id).ok_or_else(|| AppError::NotFound(format!("tool {tool_id}")))?;
    if tool.kind != "gui" {
        return Err(validation("Only GUI tools can be launched directly; use Run for CLI tools"));
    }
    let detect = tool.detect.as_ref().ok_or_else(|| validation("Tool has no detection rules"))?;
    let path = detect::locate(detect).ok_or_else(|| validation(format!("{} is not installed", tool.name)))?;
    let mut cmd = if path.extension().map(|e| e == "app").unwrap_or(false) {
        let mut c = std::process::Command::new(crate::util::MACOS_OPEN);
        c.arg("-a").arg(&path);
        c
    } else {
        std::process::Command::new(&path)
    };
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn().map_err(|e| AppError::Internal(format!("Failed to launch {}: {e}", tool.name)))?;
    db.with(|c| log(c, "tool_launch", &format!("Launched {}", tool.name), "", Some("tool"), Some(&tool.id), None))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    pub tool_id: String,
    pub args: Vec<String>,
    pub project_id: Option<i64>,
    #[serde(default)]
    pub targets: Vec<String>,
    pub confirmed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecValidation {
    pub program: String,
    /// arguments with credentials redacted (what the UI and history may show)
    pub args: Vec<String>,
    pub checked_targets: Vec<String>,
    pub file_targets: usize,
    pub requires_scope: bool,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
}

struct Validated {
    program: PathBuf,
    args: Vec<String>,
    project_name: Option<String>,
    info: ExecValidation,
}

/// Windows runs `.bat`/`.cmd` files through cmd.exe, which re-parses arguments.
/// Only native executables are allowed for argument-carrying runs.
fn ensure_native_executable(program: &std::path::Path) -> AppResult<()> {
    if cfg!(windows) {
        let ext = program.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        if !matches!(ext.as_str(), "exe" | "com") {
            return Err(validation(format!(
                "{} is a script wrapper (.{ext}); Cyber Hub only runs native executables because scripts re-interpret arguments through cmd.exe",
                program.display()
            )));
        }
    }
    Ok(())
}

fn validate_args(args: &[String]) -> AppResult<()> {
    if args.len() > 256 {
        return Err(validation("Too many arguments (max 256)"));
    }
    for a in args {
        if a.len() > 4096 {
            return Err(validation("An argument exceeds 4096 characters"));
        }
        if a.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
            return Err(validation("Arguments may not contain NUL or newline characters"));
        }
    }
    Ok(())
}

/// `snapshot_dir`: Some(dir) for a real run (target files are snapshotted and arguments
/// rewritten), None for the preview (nothing is written).
fn validate_exec(db: &Db, req: &ExecRequest, snapshot_dir: Option<&std::path::Path>) -> AppResult<Validated> {
    let tool = catalog::tool(&req.tool_id).ok_or_else(|| AppError::NotFound(format!("tool {}", req.tool_id)))?;
    if tool.kind != "cli" {
        return Err(validation(format!("{} is not a command-line tool", tool.name)));
    }
    let detect = tool.detect.as_ref().ok_or_else(|| validation("Tool has no detection rules"))?;
    let program = detect::locate(detect).ok_or_else(|| {
        validation(format!("{} is not installed (or not on PATH). Install it from the Tools Library.", tool.name))
    })?;
    ensure_native_executable(&program)?;
    validate_args(&req.args)?;

    let mut info = ExecValidation {
        program: program.to_string_lossy().to_string(),
        args: redact::redact_args(&req.args),
        checked_targets: vec![],
        file_targets: 0,
        requires_scope: tool.requires_scope,
        warnings: vec![],
        notes: vec![],
    };
    let mut args = req.args.clone();
    let mut project_name = None;

    if tool.requires_scope {
        let project_id = req
            .project_id
            .ok_or_else(|| AppError::Scope(format!("{} sends traffic to targets: select a project with an authorized scope", tool.name)))?;
        let (project, entries) = db.with(|c| {
            let p: Option<(String, String)> = c
                .query_row("SELECT name, status FROM projects WHERE id=?1", params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            Ok((p, scope_entries(c, project_id)?))
        })?;
        let (name, status) = project.ok_or_else(|| AppError::NotFound(format!("project {project_id}")))?;
        if status != "active" {
            return Err(AppError::Scope(format!("Project is '{status}'. Set it to 'active' to run tools against its scope.")));
        }
        if !entries.iter().any(|e| e.in_scope) {
            return Err(AppError::Scope("The project has no in-scope targets defined".into()));
        }
        let res = targets::resolve(&req.args, &req.targets, &entries, snapshot_dir).map_err(AppError::Scope)?;
        args = res.args;
        info.checked_targets = res.checked;
        info.file_targets = res.file_targets;
        info.warnings = res.warnings;
        info.notes = res.notes;
        project_name = Some(name);
    }

    Ok(Validated { program, args, project_name, info })
}

/// Dry-run validation for the execution preview. Reads (but never writes) target files.
#[tauri::command]
pub async fn exec_validate(db: State<'_, Db>, request: ExecRequest) -> AppResult<ExecValidation> {
    preview_execution(&db, &request)
}

/// Dry-run validation shared by the GUI preview and MCP `cyberhub_preview_run`.
pub fn preview_execution(db: &Db, request: &ExecRequest) -> AppResult<ExecValidation> {
    Ok(validate_exec(db, request, None)?.info)
}

fn runtime_dir(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(app.path().app_data_dir()?.join("runtime"))
}

/// Remove leftover per-run directories (e.g. after a crash). Called at startup.
pub fn clean_runtime_dir(app: &AppHandle) {
    if let Ok(dir) = runtime_dir(app) {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn confirmation_text(tool: &str, v: &Validated) -> String {
    let mut s = String::new();
    s.push_str(&format!("Run {tool} now?\n\nProgram:\n{}\n\nArguments:\n", v.info.program));
    let shown = v.info.args.join(" ");
    s.push_str(if shown.is_empty() { "(none)" } else { &shown });
    if let Some(p) = &v.project_name {
        s.push_str(&format!("\n\nProject: {p}"));
    }
    if !v.info.checked_targets.is_empty() {
        let mut list: Vec<String> = v.info.checked_targets.iter().take(12).cloned().collect();
        if v.info.checked_targets.len() > 12 {
            list.push(format!("… and {} more", v.info.checked_targets.len() - 12));
        }
        s.push_str(&format!("\nAuthorized targets: {}", list.join(", ")));
    }
    for w in &v.info.warnings {
        s.push_str(&format!("\n\nNote: {w}"));
    }
    s.push_str("\n\nOnly continue if you are authorized to test these targets.");
    s
}

#[tauri::command]
pub async fn exec_start(app: AppHandle, db: State<'_, Db>, request: ExecRequest, on_event: Channel<ExecEvent>) -> AppResult<i64> {
    start_execution(&app, &db, request, on_event, None).await
}

/// The single execution path used by the GUI and by MCP clients: validation, scope
/// enforcement, native OS confirmation, target-file snapshots and process-tree management.
/// `requester` names an AI client (self-reported MCP client name) shown in the native dialog.
pub async fn start_execution(app: &AppHandle, db: &Db, request: ExecRequest, on_event: Channel<ExecEvent>, requester: Option<&str>) -> AppResult<i64> {
    if !request.confirmed {
        return Err(validation("Execution must be explicitly confirmed"));
    }
    let tool_name = catalog::tool(&request.tool_id).map(|t| t.name.clone()).unwrap_or_else(|| request.tool_id.clone());
    // Validate once without side effects to build the confirmation text…
    let preview = validate_exec(db, &request, None)?;
    let mut text = confirmation_text(&tool_name, &preview);
    if let Some(who) = requester {
        text = format!("Requested by an AI client through MCP: {who} (name reported by the client).\n\n{text}");
    }
    // …then require a native OS confirmation the web view (or an MCP client) cannot click.
    if !confirm::native(app, "Confirm tool execution", text, "Run").await {
        return Err(AppError::Cancelled("Execution was cancelled in the confirmation dialog".into()));
    }
    // Re-validate for the real run: target files are snapshotted into a private directory.
    let run_dir = runtime_dir(app)?.join(format!("run-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()));
    let validated = match validate_exec(db, &request, Some(&run_dir)) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&run_dir);
            return Err(e);
        }
    };
    if validated.info.checked_targets != preview.info.checked_targets {
        let _ = std::fs::remove_dir_all(&run_dir);
        return Err(AppError::Scope("Targets changed between confirmation and start; review and try again".into()));
    }
    let rendered = std::iter::once(request.tool_id.clone())
        .chain(validated.info.args.iter().map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() }))
        .collect::<Vec<_>>()
        .join(" ");
    db.with(|c| {
        c.execute(
            "INSERT INTO command_history (command, source, tool_id, project_id, created_at) VALUES (?1,'execution',?2,?3,?4)",
            params![rendered, request.tool_id, request.project_id, now()],
        )?;
        Ok(())
    })?;
    process::start(
        app,
        SpawnSpec {
            tool_id: request.tool_id.clone(),
            kind: "run",
            program: validated.program,
            args: validated.args,
            project_id: request.project_id,
            cleanup_dir: Some(run_dir),
        },
        on_event,
        None,
    )
}

#[tauri::command]
pub async fn exec_cancel(pm: State<'_, ProcessManager>, execution_id: i64) -> AppResult<bool> {
    Ok(pm.cancel(execution_id))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRecord {
    pub id: i64,
    pub tool_id: String,
    pub kind: String,
    pub program: String,
    pub args: Vec<String>,
    pub project_id: Option<i64>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
    pub truncated: bool,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub running: bool,
}

#[tauri::command]
pub async fn exec_list(db: State<'_, Db>, pm: State<'_, ProcessManager>, limit: Option<i64>) -> AppResult<Vec<ExecutionRecord>> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let running = pm.running_ids();
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, tool_id, kind, program, args, project_id, status, exit_code, truncated, started_at, finished_at
             FROM executions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                let id: i64 = r.get(0)?;
                let status: String = r.get(6)?;
                Ok(ExecutionRecord {
                    id,
                    tool_id: r.get(1)?,
                    kind: r.get(2)?,
                    program: r.get(3)?,
                    args: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                    project_id: r.get(5)?,
                    // a 'running' row without a live process means the app exited mid-run
                    running: running.contains(&id),
                    status: if status == "running" && !running.contains(&id) { "error".into() } else { status },
                    exit_code: r.get(7)?,
                    output: None,
                    truncated: r.get::<_, i64>(8)? != 0,
                    started_at: r.get(9)?,
                    finished_at: r.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// One execution record (no output), with the live/stale status logic used by `exec_list`.
pub fn execution_record(db: &Db, pm: &ProcessManager, id: i64) -> AppResult<Option<ExecutionRecord>> {
    let running = pm.running_ids();
    db.with(|c| {
        Ok(c.query_row(
            "SELECT id, tool_id, kind, program, args, project_id, status, exit_code, truncated, started_at, finished_at FROM executions WHERE id = ?1",
            params![id],
            |r| {
                let status: String = r.get(6)?;
                Ok(ExecutionRecord {
                    id,
                    tool_id: r.get(1)?,
                    kind: r.get(2)?,
                    program: r.get(3)?,
                    args: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                    project_id: r.get(5)?,
                    running: running.contains(&id),
                    status: if status == "running" && !running.contains(&id) { "error".into() } else { status },
                    exit_code: r.get(7)?,
                    output: None,
                    truncated: r.get::<_, i64>(8)? != 0,
                    started_at: r.get(9)?,
                    finished_at: r.get(10)?,
                })
            },
        )
        .optional()?)
    })
}

#[tauri::command]
pub async fn exec_output(db: State<'_, Db>, execution_id: i64) -> AppResult<String> {
    db.with(|c| {
        c.query_row("SELECT output FROM executions WHERE id=?1", params![execution_id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("execution {execution_id}")))
    })
}

#[tauri::command]
pub async fn exec_history_clear(db: State<'_, Db>, pm: State<'_, ProcessManager>) -> AppResult<()> {
    let running = pm.running_ids();
    db.with(|c| {
        if running.is_empty() {
            c.execute("DELETE FROM executions", [])?;
        } else {
            let ids: Vec<String> = running.iter().map(|i| i.to_string()).collect();
            c.execute(&format!("DELETE FROM executions WHERE id NOT IN ({})", ids.join(",")), [])?;
        }
        Ok(())
    })
}
