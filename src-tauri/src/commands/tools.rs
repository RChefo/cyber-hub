// SPDX-License-Identifier: Apache-2.0
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
    let hook: process::FinishHook = Box::new(move |app: &AppHandle, _id: i64, ok: bool| {
        let db = app.state::<Db>();
        let tool = catalog::tool(&id_for_hook);
        let detection = tool.and_then(|t| detect::detect_tool(t, true));
        let _ = db.with(|c| {
            match detection {
                Some(d) if d.status == "installed" || d.status == "dependency_missing" => save_detection(c, &d)?,
                _ => {
                    let msg = if ok {
                        "Package manager reported success but the executable was not found on PATH. Restart ExploitX or add the install directory to PATH."
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

/// Launch a GUI tool (no arguments). It starts a program, so it asks in a native dialog first
/// (Mission 8): GUI tools act on their own once started (a proxy listener, a vendor's update or
/// licence check), and a page must not start them by itself.
#[tauri::command]
pub async fn tool_launch(app: AppHandle, db: State<'_, Db>, tool_id: String) -> AppResult<()> {
    let tool = catalog::tool(&tool_id).ok_or_else(|| AppError::NotFound(format!("tool {tool_id}")))?;
    if tool.kind != "gui" {
        return Err(validation("Only GUI tools can be launched directly; use Run for CLI tools"));
    }
    let detect = tool.detect.as_ref().ok_or_else(|| validation("Tool has no detection rules"))?;
    let path = detect::locate(detect).ok_or_else(|| validation(format!("{} is not installed", tool.name)))?;
    let message = format!("Start {}?\n\nProgram: {}\n\nExploitX passes it no arguments. Once started, it works as it does when you start it yourself.", tool.name, path.display());
    if !confirm::native(&app, "Start a program", message, "Start").await {
        return Err(AppError::Cancelled(format!("{} was not started", tool.name)));
    }
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
                "{} is a script wrapper (.{ext}); ExploitX only runs native executables because scripts re-interpret arguments through cmd.exe",
                program.display()
            )));
        }
    }
    Ok(())
}

/// A run as command history records it, ready to paste into a shell (see `util::shell_word`).
fn history_line(tool_id: &str, args: &[String]) -> String {
    std::iter::once(crate::util::shell_word(tool_id)).chain(args.iter().map(|a| crate::util::shell_word(a))).collect::<Vec<_>>().join(" ")
}

/// All arguments together, in characters: the native confirmation shows them all.
const MAX_ARGS_TEXT: usize = 16_384;

fn validate_args(args: &[String]) -> AppResult<()> {
    if args.len() > 256 {
        return Err(validation("Too many arguments (max 256)"));
    }
    for a in args {
        if a.len() > 4096 {
            return Err(validation("An argument exceeds 4096 characters"));
        }
        // the native confirmation is where the analyst reads what will run: nothing may reorder,
        // hide or break the arguments there (Mission 7)
        if let Some(c) = a.chars().find(|c| crate::util::is_deceptive_char(*c)) {
            return Err(validation(format!(
                "Arguments may not contain control, invisible or text-direction characters (U+{:04X} found): they could disguise the command in the confirmation",
                c as u32
            )));
        }
    }
    if args.iter().map(|a| a.chars().count() + 1).sum::<usize>() > MAX_ARGS_TEXT {
        return Err(validation(format!("The arguments are longer than {MAX_ARGS_TEXT} characters together; put long lists in a file")));
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
        let redirect_warning = check_redirects(&tool.name, &tool.id, &req.args, &res).map_err(AppError::Scope)?;
        args = res.args;
        info.checked_targets = res.checked;
        info.file_targets = res.file_targets;
        info.warnings = res.warnings;
        info.warnings.extend(redirect_warning);
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

/// Refuses a run that would follow redirects when one of its URLs is authorized only by path or sits
/// on a host with an excluded path: a redirect can leave the authorized paths, or reach the excluded
/// one, and ExploitX cannot check where an external tool's redirects go. A run that loads a file of
/// options is refused too, because the file can turn redirects on. Returns a warning naming the
/// files of options the tool reads on its own, which ExploitX does not read. The options are not
/// changed.
pub(crate) fn check_redirects(name: &str, tool_id: &str, args: &[String], res: &targets::Resolution) -> Result<Option<String>, String> {
    if res.path_only.is_empty() && res.near_exclusions.is_empty() {
        return Ok(None);
    }
    if let Some(arg) = crate::redirects::option_file(tool_id, args) {
        let why = format!("{arg} loads a file of options, and ExploitX cannot check whether that file turns on redirects");
        return Err(redirect_refusal(name, tool_id, &why, true, &res.path_only, &res.near_exclusions));
    }
    if let Some(why) = crate::redirects::follows(tool_id, args) {
        return Err(redirect_refusal(name, tool_id, &why, false, &res.path_only, &res.near_exclusions));
    }
    let own = crate::redirects::own_option_files(tool_id);
    Ok((!own.is_empty()).then(|| {
        format!("{name} also reads options from {own}. ExploitX does not read these files: make sure they do not turn on redirects, because this run's URLs need host-level authorization for redirects.")
    }))
}

/// Why a run that would follow redirects is refused, and what the analyst can do. `option_file`:
/// the run was refused because it loads a file of options.
fn redirect_refusal(name: &str, tool_id: &str, why: &str, option_file: bool, path_only: &[String], near: &[String]) -> String {
    let list = |v: &[String]| {
        let shown: Vec<&str> = v.iter().take(3).map(String::as_str).collect();
        let more = if v.len() > 3 { format!(" and {} more", v.len() - 3) } else { String::new() };
        format!("{}{more}", shown.join(", "))
    };
    let mut reasons = Vec::new();
    if !path_only.is_empty() {
        reasons.push(format!(
            "{} {} authorized only by path (URL scope entries), and a redirect can lead outside the authorized paths",
            list(path_only),
            if path_only.len() == 1 { "is" } else { "are" }
        ));
    }
    if !near.is_empty() {
        reasons.push(format!("{} {} on a host with an excluded path, which a redirect can reach", list(near), if near.len() == 1 { "is" } else { "are" }));
    }
    let stop = crate::redirects::how_to_stop(tool_id);
    let fix = if option_file {
        "Put the options on the command line instead (without following redirects), or authorize the host itself (a domain, wildcard or address entry) without excluded paths".to_string()
    } else if stop.is_empty() {
        format!("{name} cannot be run on these URLs: authorize the host itself (a domain, wildcard or address entry) without excluded paths")
    } else {
        format!("Run it without following redirects ({stop}), or authorize the host itself (a domain, wildcard or address entry) without excluded paths")
    };
    format!(
        "{name} was not started: {why}. {}. ExploitX cannot check where an external tool's redirects lead, so redirects need explicit host-level authorization. {fix}. The options you set were not changed.",
        reasons.join("; ")
    )
}

/// Dry-run validation shared by the GUI preview and MCP `cyberhub_preview_run`.
pub fn preview_execution(db: &Db, request: &ExecRequest) -> AppResult<ExecValidation> {
    Ok(validate_exec(db, request, None)?.info)
}

fn runtime_dir(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(crate::util::data_dir(app)?.join("runtime"))
}

/// Remove leftover per-run directories (e.g. after a crash). Called at startup.
pub fn clean_runtime_dir(app: &AppHandle) {
    if let Ok(dir) = runtime_dir(app) {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Arguments as given, for confirmations: values with spaces are quoted. Not redacted, because
/// the user must see exactly what runs; never use it for anything that is stored.
pub fn display_args(args: &[String]) -> String {
    args.iter().map(|a| display_arg(a)).collect::<Vec<_>>().join(" ")
}

/// One argument as confirmations show it: as it is when that is unambiguous, otherwise in double
/// quotes with `"` and `\` escaped, so where each argument starts and ends is exact (`x" "--safe`
/// cannot pass for two arguments). Mission 7.
fn display_arg(a: &str) -> String {
    if !a.is_empty() && !a.chars().any(|c| c.is_whitespace() || c == '"') {
        return a.to_string();
    }
    let mut s = String::with_capacity(a.len() + 2);
    s.push('"');
    for c in a.chars() {
        if c == '"' || c == '\\' {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    s
}

fn confirmation_text(tool: &str, args: &[String], v: &Validated) -> String {
    let mut s = String::new();
    s.push_str(&format!("Run {tool} now?\n\nProgram:\n{}\n\nArguments:\n", v.info.program));
    let shown = display_args(args);
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
    if !v.info.requires_scope {
        s.push_str(&format!("\n\nExploitX does not check targets or scope for {tool}; review the arguments yourself."));
    }
    s.push_str("\n\nOnly continue if you are authorized to test these targets.");
    s
}

#[tauri::command]
pub async fn exec_start(app: AppHandle, db: State<'_, Db>, request: ExecRequest, on_event: Channel<ExecEvent>) -> AppResult<i64> {
    start_execution(&app, &db, request, on_event, None, None).await
}

/// The single execution path used by the GUI and by MCP clients: validation, scope
/// enforcement, native OS confirmation, target-file snapshots and process-tree management.
/// `requester` names an AI client (self-reported MCP client name) shown in the native dialog.
/// `on_finish` runs after the end of the run was recorded (used by discovery to read the results).
pub async fn start_execution(app: &AppHandle, db: &Db, request: ExecRequest, on_event: Channel<ExecEvent>, requester: Option<&str>, on_finish: Option<process::FinishHook>) -> AppResult<i64> {
    if !request.confirmed {
        return Err(validation("Execution must be explicitly confirmed"));
    }
    let tool_name = catalog::tool(&request.tool_id).map(|t| t.name.clone()).unwrap_or_else(|| request.tool_id.clone());
    // Validate once without side effects to build the confirmation text…
    let preview = validate_exec(db, &request, None)?;
    let mut text = confirmation_text(&tool_name, &request.args, &preview);
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
    // the history line is copied into terminals: every argument is quoted for POSIX shells and
    // PowerShell alike, so pasting it runs this command and nothing else (Mission 7)
    let rendered = history_line(&request.tool_id, &validated.info.args);
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
        on_finish,
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

/// What clearing the run history did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryCleared {
    pub removed: i64,
    /// finished runs kept because evidence, a finding, OSINT evidence or a discovery snapshot
    /// refers to them
    pub kept: i64,
}

/// Removes finished runs that nothing refers to. Running processes are kept, and so are runs that
/// evidence, a finding link, OSINT evidence or an attack-surface snapshot refers to: removing them
/// would leave those records pointing at nothing.
pub fn clear_history(c: &Connection, running: &[i64]) -> AppResult<HistoryCleared> {
    let running = running.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let finished = if running.is_empty() { "1".to_string() } else { format!("id NOT IN ({running})") };
    let removed = c.execute(
        &format!(
            "DELETE FROM executions WHERE {finished}
               AND id NOT IN (SELECT execution_id FROM evidence WHERE execution_id IS NOT NULL)
               AND id NOT IN (SELECT ref_id FROM finding_links WHERE kind = 'execution')
               AND id NOT IN (SELECT execution_id FROM osint_evidence WHERE execution_id IS NOT NULL)
               AND id NOT IN (SELECT execution_id FROM discovery_snapshots WHERE execution_id IS NOT NULL)"
        ),
        [],
    )? as i64;
    let kept: i64 = c.query_row(&format!("SELECT COUNT(*) FROM executions WHERE {finished}"), [], |r| r.get(0))?;
    Ok(HistoryCleared { removed, kept })
}

#[tauri::command]
pub async fn exec_history_clear(app: AppHandle, db: State<'_, Db>, pm: State<'_, ProcessManager>) -> AppResult<HistoryCleared> {
    // the run history is the record of what ran: it is cleared only after a native confirmation
    // (Mission 7)
    if !confirm::native(
        &app,
        "Clear the run history",
        "Delete the finished runs and their stored output permanently?\n\nRuns that evidence, findings, OSINT evidence or discovery snapshots refer to are kept, and so are running ones. This cannot be undone.".into(),
        "Clear history",
    )
    .await
    {
        return Err(AppError::Cancelled("The run history was not cleared".into()));
    }
    let running = pm.running_ids();
    db.with(|c| clear_history(c, &running))
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use crate::scope::ScopeEntry;

    fn e(value: &str, in_scope: bool) -> ScopeEntry {
        let (v, kind) = crate::scope::classify(value).unwrap();
        ScopeEntry { value: v, kind: kind.to_string(), in_scope }
    }
    fn run(tool: &str, args: &[&str], scope: &[ScopeEntry]) -> Result<Option<String>, String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let res = targets::resolve(&args, &[], scope, None)?;
        check_redirects(tool, tool, &args, &res)
    }

    #[test]
    fn redirects_need_host_level_authorization() {
        let path = vec![e("https://app.example.com/api/", true)];
        let host = vec![e("*.example.com", true)];
        let excluded = vec![e("*.example.com", true), e("https://app.example.com/admin", false)];
        // path-only authorization: a run that follows redirects is refused, with what to do
        let err = run("ffuf", &["-u", "https://app.example.com/api/FUZZ", "-w", "words.txt", "-r"], &path).unwrap_err();
        assert!(err.contains("authorized only by path") && err.contains("leave out -r") && err.contains("host-level authorization"), "{err}");
        assert!(err.contains("were not changed"), "{err}");
        assert!(run("ffuf", &["-uhttps://app.example.com/api/FUZZ", "-r"], &path).is_err(), "an attached URL is read too");
        // the same run without following redirects is allowed
        assert!(run("ffuf", &["-u", "https://app.example.com/api/FUZZ", "-w", "words.txt"], &path).is_ok());
        // tools that follow unless told not to need the option that stops it
        let err = run("katana", &["-u", "https://app.example.com/api/"], &path).unwrap_err();
        assert!(err.contains("add -dr"), "{err}");
        assert!(run("katana", &["-u", "https://app.example.com/api/", "-dr"], &path).is_ok());
        assert!(run("sqlmap", &["-u", "https://app.example.com/api/item?id=1", "--batch"], &path).is_err());
        assert!(run("sqlmap", &["-u", "https://app.example.com/api/item?id=1", "--batch", "--ignore-redirects"], &path).is_ok());
        // tools that always follow cannot run on path-only URLs
        let err = run("wpscan", &["--url", "https://app.example.com/api/"], &path).unwrap_err();
        assert!(err.contains("cannot be run on these URLs"), "{err}");
        // an explicitly authorized host keeps the normal behaviour
        assert!(run("ffuf", &["-u", "https://app.example.com/FUZZ", "-r"], &host).is_ok());
        assert!(run("wpscan", &["--url", "https://app.example.com/"], &host).is_ok());
        // a host with an excluded path: a redirect could reach the excluded path
        let err = run("ffuf", &["-u", "https://app.example.com/FUZZ", "-r"], &excluded).unwrap_err();
        assert!(err.contains("excluded path"), "{err}");
        assert!(run("ffuf", &["-u", "https://www.example.com/FUZZ", "-r"], &excluded).is_ok(), "other hosts are not affected");
        // exclusions and path checks still apply before any redirect question
        assert!(run("ffuf", &["-u", "https://app.example.com/admin/FUZZ"], &excluded).unwrap_err().contains("excluded"));
        assert!(run("ffuf", &["-u", "https://app.example.com/other/FUZZ"], &path).unwrap_err().contains("outside the authorized URLs"));
    }

    /// A file of options that turns redirects on (no endpoints in it, so it is not a target list)
    fn options_file(name: &str, content: &str) -> String {
        let p = std::env::temp_dir().join(format!("cyberhub-redirect-test-{}-{name}", std::process::id()));
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }

    #[test]
    fn files_of_options_are_refused_or_named_when_redirects_need_host_authorization() {
        let path = vec![e("https://app.example.com/api/", true)];
        let host = vec![e("*.example.com", true)];
        let excluded = vec![e("*.example.com", true), e("https://app.example.com/admin", false)];
        let ffufrc = options_file("ffufrc", "[http]\n    followredirects = true\n");
        let profile = options_file("profile.yaml", "follow-redirects: true\n");
        let sqlmap = options_file("sqlmap.conf", "[Request]\nignoreRedirects = False\n");
        // an option that loads a file of options: refused, with what to do instead
        let err = run("ffuf", &["-u", "https://app.example.com/api/FUZZ", "-config", &ffufrc], &path).unwrap_err();
        assert!(err.contains("-config loads a file of options") && err.contains("Put the options on the command line"), "{err}");
        assert!(err.contains("were not changed"), "{err}");
        let err = run("nuclei", &["-u", "https://app.example.com/api/", "-dr", "-tp", &profile], &excluded).unwrap_err();
        assert!(err.contains("-tp loads a file of options") && err.contains("excluded path"), "{err}");
        assert!(run("sqlmap", &["-u", "https://app.example.com/api/item?id=1", "--ignore-redirects", "-c", &sqlmap], &path).is_err());
        // browser modes count as following redirects
        let err = run("nuclei", &["-u", "https://app.example.com/api/", "-dr", "-headless"], &path).unwrap_err();
        assert!(err.contains("-headless makes nuclei follow redirects"), "{err}");
        assert!(run("httpx", &["-u", "https://app.example.com/api/", "-ss"], &path).is_err());
        // allowed runs name the files the tool reads on its own
        let warning = run("ffuf", &["-u", "https://app.example.com/api/FUZZ", "-w", "words.txt"], &path).unwrap().expect("a warning");
        assert!(warning.contains("ffufrc") && warning.contains("does not read these files"), "{warning}");
        assert!(run("katana", &["-u", "https://app.example.com/api/", "-dr"], &path).unwrap().is_some_and(|w| w.contains("config.yaml")));
        // sqlmap reads no file of options on its own: no warning
        assert_eq!(run("sqlmap", &["-u", "https://app.example.com/api/item?id=1", "--ignore-redirects"], &path), Ok(None));
        // host-level authorization without excluded paths: files of options are the analyst's choice
        assert_eq!(run("ffuf", &["-u", "https://app.example.com/FUZZ", "-config", &ffufrc], &host), Ok(None));
        assert_eq!(run("nuclei", &["-u", "https://app.example.com/", "-headless"], &host), Ok(None));
        for f in [ffufrc, profile, sqlmap] {
            let _ = std::fs::remove_file(f);
        }
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;

    /// The words a POSIX shell reads in `line` (quotes and backslashes; no expansions, which the
    /// quoted forms never leave to the shell), or None when a quote is not closed.
    fn posix_words(line: &str) -> Option<Vec<String>> {
        let (mut words, mut cur, mut any) = (Vec::new(), String::new(), false);
        let mut it = line.chars();
        while let Some(c) = it.next() {
            match c {
                ' ' | '\t' => {
                    if any {
                        words.push(std::mem::take(&mut cur));
                        any = false;
                    }
                }
                '\'' => {
                    any = true;
                    loop {
                        match it.next()? {
                            '\'' => break,
                            q => cur.push(q),
                        }
                    }
                }
                '"' => {
                    any = true;
                    loop {
                        match it.next()? {
                            '"' => break,
                            '\\' => cur.push(it.next()?),
                            q => cur.push(q),
                        }
                    }
                }
                '\\' => {
                    any = true;
                    cur.push(it.next()?);
                }
                _ => {
                    any = true;
                    cur.push(c);
                }
            }
        }
        if any {
            words.push(cur);
        }
        Some(words)
    }

    /// Mission 7: a run's history line pastes back into a shell as the same words, and nothing in
    /// an argument can end a quote or start another command, in POSIX shells or PowerShell.
    #[test]
    fn history_lines_paste_back_as_the_same_words() {
        let mut cases: Vec<Vec<&str>> = vec![
            vec!["-u", "https://app.example.com/a;calc"],
            vec!["-H", "X: $(curl -s x|sh)", "--data", "`whoami`"],
            vec!["x\u{2019};calc;\u{2019}", "it's", "\u{2018}\u{201A}\u{201B}"],
            vec!["-p", "80,443", "@splat", "--%", "~root", "a*b?[c]", "#c", "{x}", "a&b|c", "<in", ">out"],
            vec!["", "two words", "C:\\Program Files\\x.txt", "naïve", "例え"],
        ];
        // Mission 8: words with a quote and nothing else special in double quotes
        cases.push(vec!["it's", "' OR 1=1--", "O\u{2019}Brien & co", "a'b;c|d", "'"]);
        // ... and words that keep the joined form: a quote together with $ ` " \ or !
        cases.push(vec!["it's $HOME", "'`x`'", "say \"it's\"", "C:\\it's", "it's!", "\u{201C}it's\u{201D}"]);
        let single = |c: char| matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}');
        let special = |c: char| matches!(c, '$' | '`' | '"' | '\\' | '!' | '\u{201C}' | '\u{201D}' | '\u{201E}');
        for args in cases {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            let line = history_line("nmap", &args);
            let words = posix_words(&line).unwrap_or_else(|| panic!("unclosed quote: {line}"));
            assert_eq!(words[0], "nmap");
            assert_eq!(&words[1..], &args[..], "{line}");
            // PowerShell: outside quoted text, only plain words, spaces, the `"q"` joins and whole
            // words in double quotes with nothing special inside, which PowerShell reads exactly
            let mut quoted = false;
            let mut rest = line.as_str();
            while let Some(c) = rest.chars().next() {
                rest = &rest[c.len_utf8()..];
                if quoted {
                    if single(c) {
                        assert_eq!(c, '\'', "a typographic quote ends PowerShell's quoted text: {line}");
                        quoted = false;
                    }
                } else if c == '\'' {
                    quoted = true;
                } else if c == '"' {
                    let q = rest.chars().next().unwrap();
                    if single(q) && rest[q.len_utf8()..].starts_with('"') {
                        rest = &rest[q.len_utf8() + 1..];
                        continue;
                    }
                    let end = rest.find('"').unwrap_or_else(|| panic!("unclosed double quote: {line}"));
                    let inner = &rest[..end];
                    assert!(!inner.chars().any(special), "nothing in a double-quoted word is special to PowerShell or a POSIX shell: {line}");
                    assert!(args.iter().any(|a| a == inner), "a double-quoted word is exactly an argument: {line}");
                    rest = &rest[end + 1..];
                    assert!(rest.is_empty() || rest.starts_with(' '), "a double-quoted word stands alone: {line}");
                } else {
                    assert!(c == ' ' || c.is_ascii_alphanumeric() || "_+=:./-".contains(c), "{c:?} outside quotes: {line}");
                }
            }
            assert!(!quoted, "{line}");
            // the joined form, which PowerShell splits, is left only for a quote with a special character
            for a in &args {
                let w = crate::util::shell_word(a);
                if a.chars().any(single) && w.starts_with('\'') {
                    assert!(a.chars().any(special), "{a:?} could be written exactly for PowerShell too: {w}");
                }
            }
        }
        assert_eq!(history_line("nmap", &["-sV".into(), "10.0.0.1".into()]), "nmap -sV 10.0.0.1");
        assert_eq!(crate::util::shell_word("x\u{2019};calc"), "\"x\u{2019};calc\"");
        assert_eq!(crate::util::shell_word("it's $HOME"), "'it'\"'\"'s $HOME'");
        assert_eq!(crate::util::shell_word("' OR 1=1--"), "\"' OR 1=1--\"");
    }

    /// Mission 7: arguments that could disguise the command in the native confirmation are
    /// refused, and the confirmation shows where every argument starts and ends.
    #[test]
    fn arguments_cannot_disguise_the_confirmation() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        for bad in ["x\u{202E}y", "a\u{2028}b", "a\u{2029}b", "z\u{200B}w", "\u{2066}isolate", "tab\there", "vt\u{0B}x", "nel\u{85}x", "bom\u{FEFF}", "blank\u{2800}x", "nul\0", "line\nbreak"] {
            assert!(validate_args(&s(&[bad])).is_err(), "{bad:?}");
        }
        // ordinary text, other scripts and paths stay accepted
        assert!(validate_args(&s(&["-sV", "例え.example.jp", "مثال.example", r"C:\Program Files\x.txt", "naïve", "a b"])).is_ok());
        // the arguments together are capped
        let long = vec!["x".repeat(4000); 5];
        assert!(validate_args(&long).unwrap_err().to_string().contains("together"));
        // boundaries are exact
        assert_ne!(display_args(&s(&["x\" \"--safe"])), display_args(&s(&["x", "--safe"])));
        assert_eq!(display_args(&s(&["x\" \"--safe"])), r#""x\" \"--safe""#);
        assert_eq!(display_args(&s(&["-u", "", "a b", r"C:\x y\z"])), r#"-u "" "a b" "C:\\x y\\z""#);
        assert_eq!(display_args(&s(&["no\u{A0}break"])), "\"no\u{A0}break\"", "a space-like character is quoted");
        assert_eq!(display_args(&s(&[r"C:\tools\list.txt", "it's"])), r"C:\tools\list.txt it's");
    }

    /// Mission 7: whatever a value carries, a native dialog shows it without reordering, hiding or
    /// adding text; line breaks of the message itself stay.
    #[test]
    fn dialog_text_shows_hidden_characters() {
        assert_eq!(crate::util::dialog_text("Run x?\n\nProject: a\u{202E}b"), "Run x?\n\nProject: a<U+202E>b");
        assert_eq!(crate::util::dialog_text("p\u{2028}Authorized targets: all"), "p<U+2028>Authorized targets: all");
        assert_eq!(crate::util::dialog_text("t\tz\u{200D}\r"), "t<U+0009>z<U+200D><U+000D>");
        assert_eq!(crate::util::dialog_text("plain text, عربي, 日本"), "plain text, عربي, 日本");
    }

    #[test]
    fn clearing_the_history_keeps_runs_that_records_refer_to() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'P', 'active', 't', 't')", [])?;
            for id in 1..=7 {
                c.execute("INSERT INTO executions (id, tool_id, kind, program, args, project_id, status, started_at) VALUES (?1, 'nmap', 'run', 'nmap', '[]', 1, 'succeeded', 't')", params![id])?;
            }
            c.execute("INSERT INTO evidence (project_id, kind, title, source, execution_id, created_at) VALUES (1, 'execution', 'Run', 'tool run', 1, 't')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (1, 1, 'F', 'low', 'new', 't', 't')", [])?;
            c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (1, 'execution', 2, 't')", [])?;
            c.execute("INSERT INTO osint_investigations (id, name, target_type, target_value, created_at, updated_at) VALUES (1, 'I', 'domain', 'example.com', 't', 't')", [])?;
            c.execute("INSERT INTO osint_evidence (investigation_id, kind, source, observed_at, collected_at, summary, strength, fingerprint, execution_id) VALUES (1, 'tool_run', 'nmap', 't', 't', 's', 'direct', 'fp', 3)", [])?;
            c.execute("INSERT INTO discovery_snapshots (project_id, mode, source, status, started_at, execution_id) VALUES (1, 'active', 'nmap', 'completed', 't', 4)", [])?;
            // run 7 is still running
            let done = clear_history(c, &[7])?;
            assert_eq!((done.removed, done.kept), (2, 4));
            let left: Vec<i64> = c.prepare("SELECT id FROM executions ORDER BY id")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            assert_eq!(left, vec![1, 2, 3, 4, 7]);
            Ok(())
        })
        .unwrap();
    }
}
