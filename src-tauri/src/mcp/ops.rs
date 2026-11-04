//! MCP operations, executed inside the running Cyber Hub app.
//!
//! Every tool is implemented by calling the same functions the GUI uses (scope engine,
//! `start_execution`, native file picker and upload, provider lookups, CVE search, report
//! generation). Arguments are parsed into strict types (unknown fields are refused) and
//! validated *before* a user is asked to approve anything. Each call is checked against the
//! user's MCP policy and written to the MCP audit log.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter, Manager};

use super::approvals::{ApprovalStatus, Decision, Detail, NewRequest};
use super::bridge::{Bridge, ConnCtx, DispatchFuture, Dispatcher};
use super::catalog::{self, Category, Policy};
use super::proto::ErrorBody;
use crate::catalog::CATALOG;
use crate::commands::threat_intel::TiState;
use crate::commands::tools::ExecRequest;
use crate::commands::virustotal::VtState;
use crate::commands::{activity, intel, projects, threat_intel, tools, virustotal};
use crate::db::Db;
use crate::error::AppError;
use crate::process::ProcessManager;
use crate::redact;

/// How long a tool call waits for the user's decision before returning `awaiting_approval`.
const APPROVAL_WAIT: Duration = Duration::from_secs(50);
/// Largest accepted argument object.
const MAX_ARGS: usize = 256 * 1024;
/// Lines of live output kept per MCP-started run.
const LIVE_LINES: usize = 5000;

pub const EVENT_APPROVALS: &str = "mcp-approvals";

/* ───────────────────────── errors ───────────────────────── */

fn err(kind: &str, message: impl Into<String>) -> ErrorBody {
    ErrorBody { kind: kind.into(), message: message.into() }
}

fn app_err(e: AppError) -> ErrorBody {
    err(e.kind(), e.to_string())
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T, ErrorBody> {
    serde_json::from_value(args.clone()).map_err(|e| err("invalid_params", format!("Invalid arguments: {e}")))
}

/* ───────────────────────── policy ───────────────────────── */

pub const POLICY_PREF: &str = "mcp.policy";
pub const ENABLED_PREF: &str = "mcp.enabled";

pub fn load_policy(db: &Db) -> HashMap<Category, Policy> {
    let stored: HashMap<String, String> = db
        .with(|c| Ok(c.query_row("SELECT value FROM user_preferences WHERE key = ?1", params![POLICY_PREF], |r| r.get::<_, String>(0)).optional()?))
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Category::ALL
        .into_iter()
        .map(|c| {
            let p = stored.get(c.as_str()).and_then(|v| Policy::parse(v)).filter(|p| c.allowed_policies().contains(p)).unwrap_or(c.default_policy());
            (c, p)
        })
        .collect()
}

pub fn save_policy(db: &Db, category: Category, policy: Policy) -> Result<(), AppError> {
    if !category.allowed_policies().contains(&policy) {
        return Err(AppError::Validation(format!("{} cannot be set to that policy", category.label())));
    }
    let mut p = load_policy(db);
    p.insert(category, policy);
    let map: HashMap<&str, Policy> = p.into_iter().map(|(c, v)| (c.as_str(), v)).collect();
    let raw = serde_json::to_string(&map)?;
    db.with(|c| {
        c.execute(
            "INSERT INTO user_preferences (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![POLICY_PREF, raw, crate::util::now()],
        )?;
        Ok(())
    })
}

/* ───────────────────────── live output of MCP-started runs ───────────────────────── */

#[derive(Default)]
pub struct LiveRuns {
    runs: Mutex<HashMap<i64, Arc<Mutex<VecDeque<String>>>>>,
}

impl LiveRuns {
    fn insert(&self, id: i64, buf: Arc<Mutex<VecDeque<String>>>) {
        if let Ok(mut m) = self.runs.lock() {
            if m.len() >= 50 {
                if let Some(oldest) = m.keys().min().copied() {
                    m.remove(&oldest);
                }
            }
            m.insert(id, buf);
        }
    }
    fn contains(&self, id: i64) -> bool {
        self.runs.lock().map(|m| m.contains_key(&id)).unwrap_or(false)
    }
    fn tail(&self, id: i64, n: usize) -> Option<Vec<String>> {
        let buf = self.runs.lock().ok()?.get(&id)?.clone();
        let b = buf.lock().ok()?;
        Some(b.iter().skip(b.len().saturating_sub(n)).cloned().collect())
    }
}

fn capture_channel(buf: Arc<Mutex<VecDeque<String>>>) -> Channel<crate::process::ExecEvent> {
    Channel::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                let line = match v.get("type").and_then(Value::as_str) {
                    Some("stdout") => v.get("line").and_then(Value::as_str).map(str::to_string),
                    Some("stderr") => v.get("line").and_then(Value::as_str).map(|l| format!("[stderr] {l}")),
                    _ => None,
                };
                if let (Some(l), Ok(mut b)) = (line, buf.lock()) {
                    b.push_back(l);
                    while b.len() > LIVE_LINES {
                        b.pop_front();
                    }
                }
            }
        }
        Ok(())
    })
}

fn tail_text(text: &str, n: usize) -> (Vec<String>, usize) {
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    (lines[total.saturating_sub(n)..].iter().map(|s| s.to_string()).collect(), total)
}

/* ───────────────────────── arguments ───────────────────────── */

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolFilter {
    category: Option<String>,
    installed_only: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolIdArg {
    tool_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectArg {
    project_id: i64,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OptProject {
    project_id: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateTargets {
    project_id: i64,
    targets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateFinding {
    project_id: i64,
    title: String,
    severity: String,
    status: Option<String>,
    description: Option<String>,
    affected_target: Option<String>,
    cve: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ExecArgs {
    tool_id: String,
    project_id: Option<i64>,
    args: Vec<String>,
}

impl ExecArgs {
    fn request(&self, confirmed: bool) -> ExecRequest {
        ExecRequest { tool_id: self.tool_id.clone(), args: self.args.clone(), project_id: self.project_id, targets: vec![], confirmed }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunIdArg {
    run_id: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunOutput {
    run_id: i64,
    tail_lines: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListRuns {
    limit: Option<i64>,
    project_id: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndicatorArg {
    indicator: String,
    refresh: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashArg {
    hash: String,
    refresh: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UploadArg {
    expected_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisArg {
    analysis_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TiLookup {
    indicator: String,
    providers: Option<Vec<String>>,
    refresh: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveIndicator {
    indicator: String,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CveArg {
    cve_id: String,
    live: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CveSearch {
    query: String,
    live: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportArg {
    kind: String,
    project_id: Option<i64>,
    indicator: Option<String>,
    format: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ActivityArg {
    limit: Option<i64>,
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalArg {
    approval_id: String,
}

fn opt_obj<T: DeserializeOwned + Default>(args: &Value) -> Result<T, ErrorBody> {
    if args.as_object().is_some_and(|o| o.is_empty()) {
        Ok(T::default())
    } else {
        parse(args)
    }
}

/* ───────────────────────── dispatcher ───────────────────────── */

pub struct AppDispatcher {
    pub app: AppHandle,
}

impl Dispatcher for AppDispatcher {
    fn call(&self, conn: ConnCtx, tool: String, arguments: Value) -> DispatchFuture {
        let app = self.app.clone();
        Box::pin(async move { handle(app, conn, tool, arguments).await })
    }
}

struct AuditEntry {
    approval: &'static str,
    approval_id: Option<String>,
    execution_id: Option<i64>,
}

fn approval_word(r: &Result<Value, ErrorBody>) -> &'static str {
    match r.as_ref().err().map(|e| e.kind.as_str()) {
        Some("denied") => "denied",
        Some("expired") => "expired",
        Some("cancelled") => "cancelled",
        _ => "approved",
    }
}

async fn handle(app: AppHandle, conn: ConnCtx, tool: String, args: Value) -> Result<Value, ErrorBody> {
    let started = Instant::now();
    let args = if args.is_null() { json!({}) } else { args };
    let name: String = tool.chars().filter(|c| !c.is_control()).take(64).collect();
    let mut audit = AuditEntry { approval: "not_required", approval_id: None, execution_id: None };
    let refuse = |e: ErrorBody, audit: &AuditEntry| {
        let r = Err(e);
        write_audit(&app, &conn, &name, &json!({}), audit, &r, started.elapsed());
        r
    };

    // requests that arrive while MCP is being turned off are refused
    if app.state::<Arc<Bridge>>().info().is_none() {
        return refuse(err("unavailable", "MCP is turned off in Cyber Hub."), &audit);
    }
    let Some(spec) = catalog::tool(&tool) else {
        return refuse(err("not_found", format!("Unknown tool `{name}`")), &audit);
    };
    if !args.is_object() {
        return refuse(err("invalid_params", "Arguments must be a JSON object"), &audit);
    }
    if serde_json::to_string(&args).map(|s| s.len()).unwrap_or(usize::MAX) > MAX_ARGS {
        return refuse(err("invalid_params", "Arguments are too large"), &audit);
    }
    let category = catalog::effective_category(spec, &args);
    let policy = load_policy(&app.state::<Db>()).get(&category).copied().unwrap_or(Policy::Deny);

    let result = match policy {
        Policy::Deny => {
            audit.approval = "denied_by_policy";
            Err(err("denied", format!("{} is turned off for MCP clients in Cyber Hub (Settings → Integrations → MCP).", category.label())))
        }
        Policy::Allow => run_op(&app, &conn, spec.name, &args).await,
        Policy::Ask => match describe(&app, spec.name, &args) {
            Err(e) => Err(e), // invalid or out-of-scope requests never reach the user
            Ok((summary, details, project_id)) => {
                let bridge = app.state::<Arc<Bridge>>();
                // a client that already disconnected cannot leave a request behind
                if !bridge.is_connected(conn.id) || bridge.info().is_none() {
                    Err(err("cancelled", "The client disconnected."))
                } else {
                    match bridge.approvals.request(NewRequest { connection: conn.id, client: conn.client.label(), tool: spec.name.into(), category, summary, details, project_id }) {
                        Err(m) => Err(err("busy", m)),
                        Ok((id, rx)) => {
                            audit.approval_id = Some(id.clone());
                            let _ = app.emit(EVENT_APPROVALS, bridge.approvals.pending_count());
                            // draw the user's attention to Cyber Hub (taskbar flash / dock bounce)
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.request_user_attention(Some(tauri::UserAttentionType::Informational));
                            }
                            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<Value, ErrorBody>>();
                            let (app2, conn2, tname, args2, id2) = (app.clone(), conn.clone(), spec.name, args.clone(), id.clone());
                            tauri::async_runtime::spawn(async move {
                                let decision = rx.await.unwrap_or(Decision::Cancelled);
                                let bridge = app2.state::<Arc<Bridge>>();
                                let _ = app2.emit(EVENT_APPROVALS, bridge.approvals.pending_count());
                                let outcome = match decision {
                                    Decision::Approved => {
                                        let r = run_op(&app2, &conn2, tname, &args2).await;
                                        bridge.approvals.record(ApprovalStatus {
                                            approval_id: id2.clone(),
                                            status: if r.is_ok() { "completed" } else { "failed" }.into(),
                                            result: r.as_ref().ok().cloned(),
                                            error: r.as_ref().err().map(|e| e.message.clone()),
                                        });
                                        r
                                    }
                                    Decision::Denied => Err(err("denied", "The user declined this request in Cyber Hub.")),
                                    Decision::Expired => Err(err("expired", "The request expired before the user approved it.")),
                                    Decision::Cancelled => Err(err("cancelled", "The request was cancelled.")),
                                };
                                // the final outcome is always audited here, also when it is decided after the
                                // client stopped waiting (runs and uploads included)
                                let entry = AuditEntry {
                                    approval: approval_word(&outcome),
                                    approval_id: Some(id2.clone()),
                                    execution_id: outcome.as_ref().ok().and_then(|v| v.get("runId")).and_then(Value::as_i64),
                                };
                                write_audit(&app2, &conn2, tname, &args2, &entry, &outcome, started.elapsed());
                                let _ = done_tx.send(outcome);
                            });
                            match tokio::time::timeout(APPROVAL_WAIT, done_rx).await {
                                // already audited by the decision task
                                Ok(Ok(r)) => return r,
                                _ => {
                                    audit.approval = "pending";
                                    Ok(json!({
                                        "status": "awaiting_approval",
                                        "approvalId": id,
                                        "message": "The user has not decided yet. Poll cyberhub_get_approval_status with this approvalId; the request expires if it is not approved in time.",
                                        "expiresInSecs": super::approvals::TTL.as_secs()
                                    }))
                                }
                            }
                        }
                    }
                }
            }
        },
    };
    if let Ok(v) = &result {
        audit.execution_id = v.get("runId").and_then(Value::as_i64);
    }
    write_audit(&app, &conn, spec.name, &args, &audit, &result, started.elapsed());
    result
}

fn write_audit(app: &AppHandle, conn: &ConnCtx, tool: &str, args: &Value, a: &AuditEntry, result: &Result<Value, ErrorBody>, took: Duration) {
    let (status, message) = match result {
        Ok(v) if v.get("status").and_then(Value::as_str) == Some("awaiting_approval") => ("awaiting_approval", String::new()),
        Ok(_) => ("ok", String::new()),
        Err(e) => (
            if e.kind == "denied" || e.kind == "cancelled" || e.kind == "expired" { "refused" } else { "error" },
            redact::redact_text(&e.message.chars().take(300).collect::<String>()),
        ),
    };
    let project_id = args.get("project_id").and_then(Value::as_i64);
    let db = app.state::<Db>();
    let _ = db.with(|c| {
        c.execute(
            "INSERT INTO mcp_audit (at, client, connection, tool, arguments, project_id, approval, approval_id, execution_id, result, message, duration_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![crate::util::now(), conn.client.label(), conn.id as i64, tool, redacted_args(args), project_id, a.approval, a.approval_id, a.execution_id, status, message, took.as_millis() as i64],
        )?;
        c.execute("DELETE FROM mcp_audit WHERE id NOT IN (SELECT id FROM mcp_audit ORDER BY id DESC LIMIT 1000)", [])?;
        Ok(())
    });
}

/* ───────────────────────── local paths ───────────────────────── */

/// MCP clients may not name local files: the execution engine opens existing files named in
/// arguments (target lists, request files) to validate them, which would let a client probe
/// or read files. Everything that looks like a path is refused with one generic message, so
/// the answer reveals nothing about whether a file exists.
pub fn refuse_local_paths(args: &[String]) -> Result<(), ErrorBody> {
    for a in args {
        let value = if a.starts_with('-') { a.split_once('=').map(|(_, v)| v).unwrap_or("") } else { a.as_str() };
        if value.is_empty() {
            continue;
        }
        if looks_like_path(value) {
            return Err(err(
                "invalid_params",
                "Arguments that refer to local files (target lists, wordlists, request or configuration files) are not accepted from MCP clients. Pass targets directly, or start file-based runs in Cyber Hub.",
            ));
        }
    }
    Ok(())
}

fn looks_like_path(v: &str) -> bool {
    if v.contains("://") {
        return false; // URLs are targets
    }
    if v.contains('\\') || v.starts_with('.') || v.starts_with('~') || v.starts_with('@') {
        return true;
    }
    let b = v.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b.len() == 2 || b[2] == b'/' || b[2] == b'\\') {
        return true; // drive letter
    }
    if v.contains('/') {
        // CIDR ranges are targets, not paths
        return v.parse::<ipnet::IpNet>().is_err();
    }
    // a bare name that exists relative to the working directory
    std::path::Path::new(v).exists()
}

/// Program path → file name; absolute paths in arguments (e.g. target-file snapshots of
/// runs started in the GUI) → placeholder. MCP outputs do not reveal local paths.
fn scrub_exec(mut v: Value) -> Value {
    fn fix(o: &mut serde_json::Map<String, Value>) {
        if let Some(Value::String(p)) = o.get("program") {
            let name = p.rsplit(['/', '\\']).next().unwrap_or(p).to_string();
            o.insert("program".into(), Value::String(name));
        }
        if let Some(Value::Array(args)) = o.get_mut("args") {
            for a in args.iter_mut() {
                if let Value::String(s) = a {
                    let value = if s.starts_with('-') { s.split_once('=').map(|(_, v)| v).unwrap_or("") } else { s.as_str() };
                    if !value.is_empty() && !value.contains("://") && (value.contains('\\') || value.starts_with('/') || (value.len() > 2 && value.as_bytes()[1] == b':')) {
                        *s = "<local file>".into();
                    }
                }
            }
        }
    }
    match &mut v {
        Value::Object(o) => fix(o),
        Value::Array(items) => {
            for i in items.iter_mut() {
                if let Value::Object(o) = i {
                    fix(o);
                }
            }
        }
        _ => {}
    }
    v
}

/// Arguments as stored in the audit log: credential-like values redacted, length capped.
pub fn redacted_args(args: &Value) -> String {
    let mut v = args.clone();
    // command-line arguments get the same redaction as stored runs
    if let Some(list) = v.get("args").and_then(Value::as_array) {
        let strings: Vec<String> = list.iter().map(|x| x.as_str().unwrap_or_default().to_string()).collect();
        v["args"] = json!(redact::redact_args(&strings));
    }
    let s = redact::redact_text(&serde_json::to_string(&v).unwrap_or_default());
    if s.chars().count() > 1000 {
        format!("{}…", s.chars().take(1000).collect::<String>())
    } else {
        s
    }
}

/* ───────────────────────── approval descriptions ───────────────────────── */

fn d(label: &str, value: impl Into<String>) -> Detail {
    Detail { label: label.into(), value: value.into() }
}

/// Validate a sensitive request and describe it for the approval prompt. Fails for invalid or
/// out-of-scope requests, so those are refused without bothering the user.
fn describe(app: &AppHandle, tool: &str, args: &Value) -> Result<(String, Vec<Detail>, Option<i64>), ErrorBody> {
    let db = app.state::<Db>();
    match tool {
        "cyberhub_run_tool" => {
            let a: ExecArgs = parse(args)?;
            refuse_local_paths(&a.args)?;
            let v = tools::preview_execution(&db, &a.request(false)).map_err(app_err)?;
            let name = crate::catalog::tool(&a.tool_id).map(|t| t.name.clone()).unwrap_or(a.tool_id.clone());
            let mut details = vec![d("Program", v.program.clone()), d("Arguments", v.args.join(" "))];
            if let Some(p) = a.project_id {
                details.push(d("Project", project_name(&db, p)));
            }
            if !v.checked_targets.is_empty() {
                details.push(d("Authorized targets", v.checked_targets.join(", ")));
            }
            for w in &v.warnings {
                details.push(d("Warning", w.clone()));
            }
            Ok((format!("Run {name}"), details, a.project_id))
        }
        "cyberhub_vt_upload_file" => {
            let a: UploadArg = opt_obj(args)?;
            let mut details = vec![
                d("What happens", "You choose a file in the system file picker. Cyber Hub hashes it, then asks again in a system dialog before uploading."),
                d("Privacy", "Uploaded files are shared with VirusTotal, its partners and the security community. Never upload sensitive, confidential, proprietary or personal files."),
            ];
            if let Some(h) = &a.expected_sha256 {
                if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(err("invalid_params", "expected_sha256 must be 64 hexadecimal characters"));
                }
                details.push(d("Expected SHA-256", h.to_ascii_lowercase()));
            }
            Ok(("Upload a file to VirusTotal (public submission)".into(), details, None))
        }
        "cyberhub_create_finding" => {
            let a: CreateFinding = parse(args)?;
            check_project(&db, a.project_id)?;
            let desc = a.description.unwrap_or_default();
            let preview = if desc.chars().count() > 600 { format!("{}… ({} characters in total)", desc.chars().take(600).collect::<String>(), desc.chars().count()) } else { desc };
            Ok((
                format!("Create a finding in {}", project_name(&db, a.project_id)),
                vec![
                    d("Title", a.title.chars().take(300).collect::<String>()),
                    d("Severity", a.severity),
                    d("Status", a.status.unwrap_or_else(|| "open".into())),
                    d("Affected target", a.affected_target.unwrap_or_default()),
                    d("CVE", a.cve.unwrap_or_default()),
                    d("Description", preview),
                ],
                Some(a.project_id),
            ))
        }
        "cyberhub_save_indicator" => {
            let a: SaveIndicator = parse(args)?;
            let ind = crate::ti::indicator::detect(&a.indicator).map_err(|e| err("validation", e))?;
            Ok(("Save an indicator in Threat Intel".into(), vec![d("Indicator", ind.value), d("Note", a.note.unwrap_or_default())], None))
        }
        "cyberhub_export_report" => {
            let a: ExportArg = parse(args)?;
            match a.kind.as_str() {
                "project" => {
                    let p = a.project_id.ok_or_else(|| err("invalid_params", "project_id is required for a project report"))?;
                    check_project(&db, p)?;
                    Ok((format!("Save the report of {} to a file", project_name(&db, p)), vec![d("Location", "You choose it in the system save dialog")], Some(p)))
                }
                "threat_intel" => {
                    let i = a.indicator.ok_or_else(|| err("invalid_params", "indicator is required for a threat-intelligence report"))?;
                    let ind = crate::ti::indicator::detect(&i).map_err(|e| err("validation", e))?;
                    Ok(("Save a threat-intelligence report to a file".into(), vec![d("Indicator", ind.value), d("Location", "You choose it in the system save dialog")], None))
                }
                _ => Err(err("invalid_params", "kind must be project or threat_intel")),
            }
        }
        // external lookups
        _ => {
            let summary = match tool {
                "cyberhub_vt_lookup" | "cyberhub_vt_lookup_hash" => "Send an indicator to VirusTotal",
                "cyberhub_vt_get_analysis" => "Ask VirusTotal for an analysis status",
                "cyberhub_threat_intel_lookup" | "cyberhub_threat_intel_compare" => "Send an indicator to threat-intelligence providers",
                "cyberhub_lookup_cve" | "cyberhub_search_vulnerabilities" => "Search NVD (live)",
                _ => "External lookup",
            };
            let mut details = vec![];
            for k in ["indicator", "hash", "query", "cve_id", "analysis_id"] {
                if let Some(v) = args.get(k).and_then(Value::as_str) {
                    if matches!(k, "indicator" | "hash") {
                        crate::ti::indicator::detect(v).map_err(|e| err("validation", e))?;
                    }
                    details.push(d(k, v.chars().take(300).collect::<String>()));
                }
            }
            if let Some(p) = args.get("providers").and_then(Value::as_array) {
                details.push(d("providers", p.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")));
            }
            Ok((summary.into(), details, None))
        }
    }
}

fn project_name(db: &Db, id: i64) -> String {
    db.with(|c| Ok(c.query_row("SELECT name FROM projects WHERE id = ?1", params![id], |r| r.get::<_, String>(0)).optional()?))
        .ok()
        .flatten()
        .map(|n| format!("“{n}” (#{id})"))
        .unwrap_or_else(|| format!("project #{id}"))
}

fn check_project(db: &Db, id: i64) -> Result<(), ErrorBody> {
    let exists = db.with(|c| Ok(c.query_row("SELECT 1 FROM projects WHERE id = ?1", params![id], |_| Ok(())).optional()?)).map_err(app_err)?;
    exists.ok_or_else(|| err("not_found", format!("Project {id} does not exist")))
}

/* ───────────────────────── operations ───────────────────────── */

fn to_json<T: serde::Serialize>(v: T) -> Result<Value, ErrorBody> {
    serde_json::to_value(v).map_err(|e| err("internal", e.to_string()))
}

pub const MODULES: &[(&str, &str, &[&str])] = &[
    ("Tools Library", "Security tool catalog, local detection and installation status", &["cyberhub_list_tools", "cyberhub_get_tool_details"]),
    ("Command Center / Runs", "Scoped execution of catalog tools with preview, output and cancellation", &["cyberhub_preview_run", "cyberhub_run_tool", "cyberhub_get_run_status", "cyberhub_get_run_output", "cyberhub_cancel_run", "cyberhub_list_runs", "cyberhub_get_run_details"]),
    ("Projects & Scope", "Assessments, authorized scope with exclusions, findings", &["cyberhub_list_projects", "cyberhub_get_project", "cyberhub_get_project_scope", "cyberhub_validate_target", "cyberhub_list_findings", "cyberhub_create_finding"]),
    ("VirusTotal", "Reputation lookups and public file analysis", &["cyberhub_vt_lookup", "cyberhub_vt_lookup_hash", "cyberhub_vt_upload_file", "cyberhub_vt_get_analysis", "cyberhub_vt_get_report"]),
    ("Threat Intel", "Multi-provider indicator lookups with per-provider verdicts", &["cyberhub_threat_intel_lookup", "cyberhub_threat_intel_compare", "cyberhub_get_saved_indicators", "cyberhub_save_indicator", "cyberhub_list_supported_providers"]),
    ("Vulnerability Intel", "NVD CVE search and cached CVE details", &["cyberhub_lookup_cve", "cyberhub_search_vulnerabilities", "cyberhub_get_vulnerability_details"]),
    ("Reports & Activity", "Project reports, exports and the activity log", &["cyberhub_generate_report", "cyberhub_export_report", "cyberhub_get_activity"]),
];

async fn run_op(app: &AppHandle, conn: &ConnCtx, tool: &str, args: &Value) -> Result<Value, ErrorBody> {
    let db = app.state::<Db>();
    match tool {
        "cyberhub_get_status" => {
            let _: NoArgs = opt_obj(args)?;
            let detections = tools::tools_detection_list(app.state::<Db>()).await.map_err(app_err)?;
            let installed = detections.iter().filter(|d| d.status == "installed").count();
            let providers = threat_intel::ti_providers(app.state::<Db>(), app.state::<TiState>()).await.map_err(app_err)?;
            let bridge = app.state::<Arc<Bridge>>();
            let policy: HashMap<&str, Policy> = load_policy(&db).into_iter().map(|(c, p)| (c.as_str(), p)).collect();
            Ok(json!({
                "app": "Cyber Hub",
                "version": env!("CARGO_PKG_VERSION"),
                "os": crate::util::current_os(),
                "catalogTools": CATALOG.tools.len(),
                "installedTools": installed,
                "runningRuns": app.state::<ProcessManager>().running_ids().len(),
                "pendingApprovals": bridge.approvals.pending_count(),
                "mcpConnections": bridge.connections().len(),
                "providers": providers.providers.iter().map(|p| json!({ "id": p.id, "name": p.name, "configured": p.configured, "enabled": p.enabled })).collect::<Vec<_>>(),
                "nvdKeyConfigured": providers.nvd_configured,
                "policy": policy,
            }))
        }
        "cyberhub_list_modules" => {
            let _: NoArgs = opt_obj(args)?;
            Ok(json!(MODULES.iter().map(|(n, d, t)| json!({ "module": n, "description": d, "tools": t })).collect::<Vec<_>>()))
        }
        "cyberhub_list_tools" => {
            let f: ToolFilter = opt_obj_default(args)?;
            let det: HashMap<String, crate::detect::Detection> = tools::tools_detection_list(app.state::<Db>()).await.map_err(app_err)?.into_iter().map(|d| (d.tool_id.clone(), d)).collect();
            let list: Vec<Value> = CATALOG
                .tools
                .iter()
                .filter(|t| f.category.as_deref().is_none_or_eq(&t.category))
                .map(|t| {
                    let d = det.get(&t.id);
                    let status = d.map(|d| d.status.as_str()).unwrap_or("unknown");
                    json!({ "id": t.id, "name": t.name, "category": t.category, "kind": t.kind, "requiresScope": t.requires_scope, "status": status, "version": d.and_then(|d| d.version.clone()), "runnable": t.kind == "cli" && status == "installed" })
                })
                .filter(|v| f.installed_only != Some(true) || v["status"] == "installed")
                .collect();
            Ok(json!({ "count": list.len(), "tools": list, "categories": CATALOG.categories.iter().map(|c| &c.id).collect::<Vec<_>>() }))
        }
        "cyberhub_get_tool_details" => {
            let a: ToolIdArg = parse(args)?;
            let t = crate::catalog::tool(&a.tool_id).ok_or_else(|| err("not_found", format!("No tool `{}` in the catalog", a.tool_id.chars().take(64).collect::<String>())))?;
            let d = tools::tools_detection_list(app.state::<Db>()).await.map_err(app_err)?.into_iter().find(|d| d.tool_id == t.id);
            let status = d.as_ref().map(|d| d.status.clone()).unwrap_or_else(|| "unknown".into());
            Ok(json!({
                "id": t.id, "name": t.name, "category": t.category, "kind": t.kind, "description": t.description,
                "website": t.website, "docs": t.docs, "os": t.os, "tags": t.tags, "requiresScope": t.requires_scope,
                "status": status, "version": d.as_ref().and_then(|d| d.version.clone()),
                "missingDependencies": d.as_ref().map(|d| d.missing_dependencies.clone()).unwrap_or_default(),
                "runnable": t.kind == "cli" && status == "installed",
                "examples": t.commands.iter().map(|c| json!({ "title": c.title, "command": c.command, "description": c.description })).collect::<Vec<_>>(),
            }))
        }
        "cyberhub_list_supported_providers" => {
            let _: NoArgs = opt_obj(args)?;
            to_json(threat_intel::ti_providers(app.state::<Db>(), app.state::<TiState>()).await.map_err(app_err)?)
        }
        "cyberhub_list_projects" => {
            let _: NoArgs = opt_obj(args)?;
            to_json(projects::projects_list(app.state::<Db>()).await.map_err(app_err)?)
        }
        "cyberhub_get_project" => {
            let a: ProjectArg = parse(args)?;
            to_json(projects::project_get(app.state::<Db>(), a.project_id).await.map_err(app_err)?)
        }
        "cyberhub_get_project_scope" => {
            let a: ProjectArg = parse(args)?;
            let p = projects::project_get(app.state::<Db>(), a.project_id).await.map_err(app_err)?;
            let pick = |inside: bool| p.targets.iter().filter(|t| t.in_scope == inside).map(|t| json!({ "value": t.value, "kind": t.kind, "note": t.note })).collect::<Vec<_>>();
            Ok(json!({ "projectId": p.id, "name": p.name, "status": p.status, "active": p.status == "active", "inScope": pick(true), "excluded": pick(false), "rulesOfEngagement": p.scope_notes }))
        }
        "cyberhub_validate_target" => {
            let a: ValidateTargets = parse(args)?;
            if a.targets.is_empty() || a.targets.len() > 50 {
                return Err(err("invalid_params", "Pass 1–50 targets"));
            }
            check_project(&db, a.project_id)?;
            to_json(projects::scope_check(app.state::<Db>(), a.project_id, a.targets).await.map_err(app_err)?)
        }
        "cyberhub_list_findings" => {
            let a: OptProject = opt_obj(args)?;
            to_json(projects::findings_list(app.state::<Db>(), a.project_id).await.map_err(app_err)?)
        }
        "cyberhub_create_finding" => {
            let a: CreateFinding = parse(args)?;
            check_project(&db, a.project_id)?;
            let id = projects::finding_upsert(
                app.state::<Db>(),
                projects::FindingInput {
                    id: None,
                    project_id: a.project_id,
                    title: a.title,
                    severity: a.severity,
                    status: a.status.unwrap_or_else(|| "open".into()),
                    description: a.description.unwrap_or_default(),
                    affected_target: a.affected_target.unwrap_or_default(),
                    cve: a.cve.unwrap_or_default(),
                    evidence: vec![],
                },
            )
            .await
            .map_err(app_err)?;
            Ok(json!({ "findingId": id, "projectId": a.project_id }))
        }
        "cyberhub_preview_run" => {
            let a: ExecArgs = parse(args)?;
            refuse_local_paths(&a.args)?;
            Ok(scrub_exec(to_json(tools::preview_execution(&db, &a.request(false)).map_err(app_err)?)?))
        }
        "cyberhub_run_tool" => {
            let a: ExecArgs = parse(args)?;
            refuse_local_paths(&a.args)?;
            let buf: Arc<Mutex<VecDeque<String>>> = Arc::default();
            let id = tools::start_execution(app, &db, a.request(true), capture_channel(buf.clone()), Some(&conn.client.label())).await.map_err(app_err)?;
            app.state::<LiveRuns>().insert(id, buf);
            Ok(json!({ "runId": id, "status": "running", "message": "The run started. Use cyberhub_get_run_status and cyberhub_get_run_output to follow it." }))
        }
        "cyberhub_get_run_status" => {
            let a: RunIdArg = parse(args)?;
            Ok(scrub_exec(to_json(tools::execution_record(&db, &app.state::<ProcessManager>(), a.run_id).map_err(app_err)?.ok_or_else(|| err("not_found", format!("Run {} does not exist", a.run_id)))?)?))
        }
        "cyberhub_get_run_output" => {
            let a: RunOutput = parse(args)?;
            let n = a.tail_lines.unwrap_or(200).clamp(1, 2000);
            let rec = tools::execution_record(&db, &app.state::<ProcessManager>(), a.run_id).map_err(app_err)?.ok_or_else(|| err("not_found", format!("Run {} does not exist", a.run_id)))?;
            if rec.running {
                let lines = app.state::<LiveRuns>().tail(a.run_id, n).unwrap_or_default();
                let text = redact::redact_text(&lines.join("\n"));
                return Ok(json!({ "runId": a.run_id, "running": true, "lines": text.lines().collect::<Vec<_>>(), "note": if lines.is_empty() { "Live output is available for runs started through MCP; the stored output appears when the run ends." } else { "" } }));
            }
            let text = tools::exec_output(app.state::<Db>(), a.run_id).await.map_err(app_err)?;
            let (lines, total) = tail_text(&text, n);
            Ok(json!({ "runId": a.run_id, "running": false, "status": rec.status, "totalLines": total, "truncatedAtSource": rec.truncated, "lines": lines }))
        }
        "cyberhub_cancel_run" => {
            let a: RunIdArg = parse(args)?;
            // MCP clients may only stop runs they started; GUI runs and installations are the user's
            if !app.state::<LiveRuns>().contains(a.run_id) {
                return Err(err("denied", "Only runs started through MCP can be cancelled by an MCP client. Cancel other runs in Cyber Hub."));
            }
            Ok(json!({ "runId": a.run_id, "cancelled": app.state::<ProcessManager>().cancel(a.run_id) }))
        }
        "cyberhub_list_runs" => {
            let a: ListRuns = opt_obj(args)?;
            let limit = a.limit.unwrap_or(25).clamp(1, 200);
            let mut runs = tools::exec_list(app.state::<Db>(), app.state::<ProcessManager>(), Some(if a.project_id.is_some() { 500 } else { limit })).await.map_err(app_err)?;
            if let Some(p) = a.project_id {
                runs.retain(|r| r.project_id == Some(p));
                runs.truncate(limit as usize);
            }
            Ok(scrub_exec(to_json(runs)?))
        }
        "cyberhub_vt_lookup" => {
            let a: IndicatorArg = parse(args)?;
            to_json(virustotal::vt_lookup(app.state::<Db>(), app.state::<VtState>(), a.indicator, a.refresh.unwrap_or(false)).await.map_err(app_err)?)
        }
        "cyberhub_vt_lookup_hash" => {
            let a: HashArg = parse(args)?;
            let ind = crate::ti::indicator::detect(&a.hash).map_err(|e| err("validation", e))?;
            if ind.kind != crate::ti::indicator::Kind::File {
                return Err(err("invalid_params", "hash must be an MD5, SHA-1 or SHA-256 hash"));
            }
            to_json(virustotal::vt_lookup(app.state::<Db>(), app.state::<VtState>(), ind.value, a.refresh.unwrap_or(false)).await.map_err(app_err)?)
        }
        "cyberhub_vt_upload_file" => {
            let a: UploadArg = opt_obj(args)?;
            // the user chooses the file in the native picker; the client never supplies a path
            let picked = virustotal::vt_file_pick(app.clone(), app.state::<Db>(), app.state::<VtState>())
                .await
                .map_err(app_err)?
                .ok_or_else(|| err("cancelled", "The user closed the file picker; nothing was uploaded."))?;
            let forget = |h: String| async { let _ = virustotal::vt_file_forget(app.state::<VtState>(), h).await; };
            if let Some(expected) = &a.expected_sha256 {
                if !expected.eq_ignore_ascii_case(&picked.sha256) {
                    forget(picked.handle.clone()).await;
                    return Err(err("validation", "The chosen file's SHA-256 does not match expected_sha256; nothing was uploaded."));
                }
            }
            let result = virustotal::vt_file_upload(app.clone(), app.state::<Db>(), app.state::<VtState>(), picked.handle.clone(), Channel::new(|_| Ok(()))).await;
            forget(picked.handle.clone()).await;
            let r = result.map_err(app_err)?;
            Ok(json!({ "analysisId": r.analysis_id, "sha256": r.sha256, "fileName": picked.name, "size": picked.size, "uploadMode": picked.upload_mode,
                       "message": "Uploaded. Poll cyberhub_vt_get_analysis; when it is completed, cyberhub_vt_lookup_hash returns the report." }))
        }
        "cyberhub_vt_get_analysis" => {
            let a: AnalysisArg = parse(args)?;
            to_json(virustotal::vt_analysis(app.state::<VtState>(), a.analysis_id).await.map_err(app_err)?)
        }
        "cyberhub_vt_get_report" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                indicator: String,
            }
            let a: A = parse(args)?;
            let ind = crate::ti::indicator::detect(&a.indicator).map_err(|e| err("validation", e))?;
            match virustotal::cached(&db, &ind).map_err(app_err)? {
                Some((report, at, not_found)) => Ok(json!({ "cached": true, "fetchedAt": at, "notFound": not_found, "report": report })),
                None => Ok(json!({ "cached": false, "message": "No cached VirusTotal result. Use cyberhub_vt_lookup (external lookup) to fetch one." })),
            }
        }
        "cyberhub_threat_intel_lookup" => {
            let a: TiLookup = parse(args)?;
            to_json(threat_intel::ti_lookup(app.state::<Db>(), app.state::<VtState>(), app.state::<TiState>(), a.indicator, a.providers, a.refresh.unwrap_or(false)).await.map_err(app_err)?)
        }
        "cyberhub_threat_intel_compare" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                indicator: String,
                providers: Option<Vec<String>>,
            }
            let a: A = parse(args)?;
            let inv = threat_intel::ti_lookup(app.state::<Db>(), app.state::<VtState>(), app.state::<TiState>(), a.indicator, a.providers, false).await.map_err(app_err)?;
            Ok(compare(&to_json(&inv)?))
        }
        "cyberhub_get_saved_indicators" => {
            let _: NoArgs = opt_obj(args)?;
            to_json(threat_intel::ti_saved_list(app.state::<Db>()).await.map_err(app_err)?)
        }
        "cyberhub_save_indicator" => {
            let a: SaveIndicator = parse(args)?;
            threat_intel::ti_saved_add(app.state::<Db>(), a.indicator.clone(), a.note.unwrap_or_default()).await.map_err(app_err)?;
            Ok(json!({ "saved": true }))
        }
        "cyberhub_lookup_cve" => {
            let a: CveArg = parse(args)?;
            let id = a.cve_id.trim().to_ascii_uppercase();
            if let Some((rec, at)) = intel::cve_get_cached(app.state::<Db>(), id.clone()).await.map_err(app_err)? {
                return Ok(json!({ "found": true, "source": "cache", "cachedAt": at, "record": rec }));
            }
            if a.live == Some(true) {
                let r = intel::cve_search(app.state::<Db>(), id.clone(), true).await.map_err(app_err)?;
                return Ok(match r.records.into_iter().find(|x| x.id.eq_ignore_ascii_case(&id)) {
                    Some(rec) => json!({ "found": true, "source": "live", "record": rec }),
                    None => json!({ "found": false, "source": "live", "message": "NVD has no record of this CVE." }),
                });
            }
            Ok(json!({ "found": false, "source": "cache", "message": "Not in the local cache. Pass live=true to fetch it from NVD." }))
        }
        "cyberhub_search_vulnerabilities" => {
            let a: CveSearch = parse(args)?;
            to_json(intel::cve_search(app.state::<Db>(), a.query, a.live == Some(true)).await.map_err(app_err)?)
        }
        "cyberhub_get_vulnerability_details" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                cve_id: String,
            }
            let a: A = parse(args)?;
            match intel::cve_get_cached(app.state::<Db>(), a.cve_id.trim().to_ascii_uppercase()).await.map_err(app_err)? {
                Some((rec, at)) => Ok(json!({ "found": true, "cachedAt": at, "record": rec })),
                None => Ok(json!({ "found": false, "message": "Not cached. Use cyberhub_lookup_cve with live=true or cyberhub_search_vulnerabilities first." })),
            }
        }
        "cyberhub_generate_report" => {
            let a: ProjectArg = parse(args)?;
            let md = projects::project_report(app.state::<Db>(), a.project_id).await.map_err(app_err)?;
            Ok(json!({ "projectId": a.project_id, "format": "markdown", "report": md }))
        }
        "cyberhub_export_report" => {
            let a: ExportArg = parse(args)?;
            let saved = match a.kind.as_str() {
                "project" => projects::project_report_export(app.clone(), app.state::<Db>(), a.project_id.ok_or_else(|| err("invalid_params", "project_id is required"))?).await.map_err(app_err)?,
                "threat_intel" => threat_intel::ti_export(app.clone(), app.state::<Db>(), a.indicator.ok_or_else(|| err("invalid_params", "indicator is required"))?, a.format.unwrap_or_else(|| "md".into())).await.map_err(app_err)?,
                _ => return Err(err("invalid_params", "kind must be project or threat_intel")),
            };
            Ok(match saved {
                Some(name) => json!({ "saved": true, "fileName": name }),
                None => json!({ "saved": false, "message": "The user cancelled the save dialog." }),
            })
        }
        "cyberhub_get_activity" => {
            let a: ActivityArg = opt_obj(args)?;
            to_json(activity::activity_list(app.state::<Db>(), Some(a.limit.unwrap_or(50).clamp(1, 500)), a.kind).await.map_err(app_err)?)
        }
        "cyberhub_get_run_details" => {
            let a: RunIdArg = parse(args)?;
            let rec = tools::execution_record(&db, &app.state::<ProcessManager>(), a.run_id).map_err(app_err)?.ok_or_else(|| err("not_found", format!("Run {} does not exist", a.run_id)))?;
            let text = tools::exec_output(app.state::<Db>(), a.run_id).await.unwrap_or_default();
            let head: Vec<&str> = text.lines().take(200).collect();
            Ok(json!({ "run": scrub_exec(to_json(rec)?), "outputHead": head, "outputLines": text.lines().count() }))
        }
        "cyberhub_get_approval_status" => {
            let a: ApprovalArg = parse(args)?;
            to_json(app.state::<Arc<Bridge>>().approvals.status(&a.approval_id).ok_or_else(|| err("not_found", "Unknown or expired approval ID"))?)
        }
        other => Err(err("not_found", format!("Unknown tool `{other}`"))),
    }
}

fn opt_obj_default<T: DeserializeOwned>(args: &Value) -> Result<T, ErrorBody> {
    parse(args)
}

trait OptEq {
    fn is_none_or_eq(&self, other: &str) -> bool;
}
impl OptEq for Option<&str> {
    fn is_none_or_eq(&self, other: &str) -> bool {
        self.map_or(true, |s| s == other)
    }
}

/// Side-by-side rows built from an investigation, in each provider's own wording.
pub fn compare(inv: &Value) -> Value {
    let results: Vec<&Value> = inv["results"].as_array().map(|a| a.iter().filter(|r| matches!(r["status"].as_str(), Some("found") | Some("not_found"))).collect()).unwrap_or_default();
    let list = |r: &Value, k: &str| -> Value {
        let v: Vec<&str> = r["report"][k].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        if v.is_empty() { Value::Null } else { json!(v) }
    };
    let providers: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "provider": r["providerName"],
                "status": r["status"],
                "verdict": r["report"]["verdict"]["label"],
                "level": r["report"]["verdict"]["level"],
                "scores": r["report"]["scores"],
                "families": list(r, "families"),
                "categories": list(r, "categories"),
                "firstSeen": r["report"]["firstSeen"],
                "lastSeen": r["report"]["lastSeen"],
                "source": r["report"]["permalink"],
                "retrieved": r["fetchedAt"],
                "fromCache": r["source"] == "cache",
            })
        })
        .collect();
    json!({
        "indicator": inv["indicator"],
        "kind": inv["kind"],
        "providers": providers,
        "summary": inv["summary"],
        "note": "Each provider's verdict and scores are reported in its own terms; scales differ and are not combined.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_tool_has_an_operation() {
        // run_op ends with a catch-all; make sure no catalog name falls into it
        let src = include_str!("ops.rs");
        for t in catalog::TOOLS {
            assert!(src.contains(&format!("\"{}\" =>", t.name)) || src.contains(&format!("\"{}\" |", t.name)), "no operation for {}", t.name);
        }
    }

    #[test]
    fn arguments_are_strict() {
        assert!(parse::<ExecArgs>(&json!({"tool_id": "nmap", "args": ["-sV"], "project_id": 1, "shell": "rm -rf /"})).is_err(), "unknown fields are refused");
        assert!(parse::<ExecArgs>(&json!({"tool_id": "nmap", "args": "-sV 10.0.0.1"})).is_err(), "args must be an array");
        assert!(parse::<RunIdArg>(&json!({"run_id": "1; DROP TABLE"})).is_err());
        let e: ExecArgs = parse(&json!({"tool_id": "nmap", "args": ["-sV", "scanme.nmap.org"], "project_id": 3})).unwrap();
        let r = e.request(false);
        assert_eq!((r.tool_id.as_str(), r.project_id, r.args.len(), r.targets.len(), r.confirmed), ("nmap", Some(3), 2, 0, false));
        assert!(opt_obj::<OptProject>(&json!({})).unwrap().project_id.is_none());
    }

    #[test]
    fn local_paths_are_refused_without_revealing_existence() {
        let exists = std::env::current_exe().unwrap().to_string_lossy().to_string();
        let missing = if cfg!(windows) { r"C:\no\such\file.txt".to_string() } else { "/no/such/file.txt".to_string() };
        let e1 = refuse_local_paths(&["-iL".into(), exists]).unwrap_err();
        let e2 = refuse_local_paths(&["-iL".into(), missing]).unwrap_err();
        assert_eq!(e1.message, e2.message, "same answer for existing and missing files");
        for bad in ["--input-file=../targets.txt", "./hosts", "~/.ssh/id_rsa", "@targets.txt", "C:/Windows/win.ini", "/etc/passwd", "lists/hosts.txt"] {
            assert!(refuse_local_paths(&[bad.to_string()]).is_err(), "{bad}");
        }
        for ok in ["-sT", "-p", "1-1000", "127.0.0.1", "10.0.0.0/24", "https://example.org/a/b", "--top-ports=100", "example.org"] {
            assert!(refuse_local_paths(&[ok.to_string()]).is_ok(), "{ok}");
        }
    }

    #[test]
    fn outputs_hide_local_paths() {
        let v = scrub_exec(json!({"program": "C:\\Program Files (x86)\\Nmap\\nmap.exe", "args": ["-iL", "C:\\Users\\me\\AppData\\run-1\\t.txt", "-sT", "https://x.org/a"]}));
        assert_eq!(v["program"], "nmap.exe");
        assert_eq!(v["args"], json!(["-iL", "<local file>", "-sT", "https://x.org/a"]));
        let list = scrub_exec(json!([{"program": "/usr/bin/nmap", "args": ["--script-args-file=/home/me/a"]}]));
        assert_eq!(list[0]["program"], "nmap");
        assert_eq!(list[0]["args"][0], "<local file>");
    }

    #[test]
    fn audit_arguments_are_redacted_and_capped() {
        let s = redacted_args(&json!({"args": ["--password", "hunter2hunter2", "-H", "Authorization: Bearer abcdefabcdefabcdef"]}));
        assert!(!s.contains("hunter2hunter2") && !s.contains("abcdefabcdefabcdef"), "{s}");
        assert!(redacted_args(&json!({"x": "a".repeat(5000)})).chars().count() <= 1001);
    }

    #[test]
    fn compare_keeps_provider_wording_and_skips_unrun_providers() {
        let inv = json!({"indicator": "evil.xyz", "kind": "domain", "summary": {}, "results": [
            {"providerName": "URLhaus", "status": "found", "source": "live", "fetchedAt": "t", "report": {"verdict": {"label": "Listed malware URL (online)", "level": "malicious"}, "scores": [], "families": ["AgentTesla"], "categories": [], "permalink": "https://urlhaus.abuse.ch/x"}},
            {"providerName": "Shodan", "status": "unsupported", "report": null}
        ]});
        let c = compare(&inv);
        assert_eq!(c["providers"].as_array().unwrap().len(), 1);
        assert_eq!(c["providers"][0]["verdict"], "Listed malware URL (online)");
        assert_eq!(c["providers"][0]["families"], json!(["AgentTesla"]));
    }

    #[test]
    fn live_output_is_bounded() {
        let buf: Arc<Mutex<VecDeque<String>>> = Arc::default();
        let ch = capture_channel(buf.clone());
        for i in 0..(LIVE_LINES + 10) {
            ch.send(crate::process::ExecEvent::Stdout { line: format!("line {i}") }).unwrap();
        }
        ch.send(crate::process::ExecEvent::Stderr { line: "oops".into() }).unwrap();
        let b = buf.lock().unwrap();
        assert_eq!(b.len(), LIVE_LINES);
        assert_eq!(b.back().unwrap(), "[stderr] oops");
        assert_eq!(tail_text("a\nb\nc", 2), (vec!["b".to_string(), "c".to_string()], 3));
    }
}
