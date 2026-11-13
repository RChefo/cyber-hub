//! Attack-surface discovery commands (see `workspace::discovery`). Passive and HTTP runs execute
//! in the background, one per project at a time; service scans are tool runs. The UI follows
//! progress through the `asm-changed` event.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::params;
use serde_json::json;
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::projects::scope_entries;
use crate::commands::tools::{start_execution, ExecRequest};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::process::FinishHook;
use crate::workspace::discovery::{self as disc, Progress};
use crate::workspace::{assets, scope_gate};

pub const EVENT: &str = "asm-changed";

/// Background discoveries in progress: project → (snapshot, cancel flag).
#[derive(Default)]
pub struct DiscoveryState(Mutex<HashMap<i64, (i64, Arc<AtomicBool>)>>);

impl DiscoveryState {
    fn claim(&self, project_id: i64, snapshot_id: i64) -> AppResult<Arc<AtomicBool>> {
        let mut m = self.0.lock().map_err(|_| AppError::Internal("discovery state poisoned".into()))?;
        if m.contains_key(&project_id) {
            return Err(AppError::Conflict("A discovery is already running for this project".into()));
        }
        let flag = Arc::new(AtomicBool::new(false));
        m.insert(project_id, (snapshot_id, flag.clone()));
        Ok(flag)
    }
    fn busy(&self, project_id: i64) -> bool {
        self.0.lock().map(|m| m.contains_key(&project_id)).unwrap_or(true)
    }
    /// Asks the project's background discovery to stop; false when none runs.
    pub fn cancel(&self, project_id: i64) -> bool {
        match self.0.lock() {
            Ok(m) => m.get(&project_id).map(|(_, flag)| flag.store(true, Ordering::Relaxed)).is_some(),
            Err(_) => false,
        }
    }
    fn release(&self, project_id: i64) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(&project_id);
        }
    }
}

fn emit(app: &AppHandle, project_id: i64, snapshot_id: i64, message: Option<String>) {
    let _ = app.emit(EVENT, json!({ "projectId": project_id, "snapshotId": snapshot_id, "message": message }));
}

fn progress(app: &AppHandle, project_id: i64, snapshot_id: i64) -> Progress {
    let app = app.clone();
    Arc::new(move |m: String| emit(&app, project_id, snapshot_id, Some(m)))
}

fn run_status(cancelled: bool, recorded: usize, problems: &[String]) -> &'static str {
    if cancelled {
        "cancelled"
    } else if problems.is_empty() {
        "completed"
    } else if recorded == 0 {
        "failed"
    } else {
        "partial"
    }
}

/* ───────────────────────── shared run handling ───────────────────────── */

/// How a background discovery ended.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunOutcome {
    pub snapshot_id: i64,
    pub status: String,
    pub note: String,
}

/// Starts a snapshot and claims the project's discovery slot.
fn begin(app: &AppHandle, project_id: i64, mode: &str, source: &str) -> AppResult<(i64, Arc<AtomicBool>)> {
    let db = app.state::<Db>();
    let state = app.state::<DiscoveryState>();
    if state.busy(project_id) {
        return Err(AppError::Conflict("A discovery is already running for this project".into()));
    }
    let snapshot_id = db.with(|c| assets::start_snapshot(c, project_id, mode, source, None, None))?;
    match state.claim(project_id, snapshot_id) {
        Ok(f) => Ok((snapshot_id, f)),
        Err(e) => {
            let _ = db.with(|c| assets::finish_snapshot(c, snapshot_id, "cancelled", "Another discovery was running"));
            Err(e)
        }
    }
}

/// Ends a run however it stops: normally, with an error, or when its future is dropped (a
/// workflow step that ran out of time). The snapshot never stays "running".
struct RunGuard {
    app: AppHandle,
    project_id: i64,
    snapshot_id: i64,
}

impl RunGuard {
    fn finish(self, result: AppResult<String>) -> RunOutcome {
        let db = self.app.state::<Db>();
        if let Err(e) = &result {
            let _ = db.with(|c| assets::finish_snapshot(c, self.snapshot_id, "failed", &e.to_string()));
        }
        let snap = db.with(|c| disc::snapshot(c, self.snapshot_id)).ok();
        let out = RunOutcome {
            snapshot_id: self.snapshot_id,
            status: snap.as_ref().map(|s| s.status.clone()).unwrap_or_else(|| "failed".into()),
            note: snap.map(|s| s.note).unwrap_or_default(),
        };
        drop(self);
        out
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let db = self.app.state::<Db>();
        // still running here means the run was stopped before it could finish
        let _ = db.with(|c| {
            c.execute(
                "UPDATE discovery_snapshots SET status = 'failed', note = 'Stopped before it finished (time limit or cancellation)', finished_at = ?2 WHERE id = ?1 AND status = 'running'",
                params![self.snapshot_id, crate::util::now()],
            )?;
            Ok(())
        });
        self.app.state::<DiscoveryState>().release(self.project_id);
        emit(&self.app, self.project_id, self.snapshot_id, None);
    }
}

/* ───────────────────────── passive ───────────────────────── */

/// Scope entries and the public in-scope domains passive discovery may ask about.
pub(crate) fn passive_targets(c: &rusqlite::Connection, project_id: i64) -> AppResult<(Vec<crate::scope::ScopeEntry>, Vec<String>)> {
    let entries = scope_entries(c, project_id)?;
    let roots = disc::passive_roots(&entries);
    let decision = scope_gate::decide(c, Some(project_id), &roots, scope_gate::Mode::Passive)?;
    let allowed: Vec<String> = decision.verdicts.into_iter().filter(|v| v.allowed).map(|v| v.target).collect();
    if allowed.is_empty() {
        return Err(validation("Add an in-scope public domain (for example example.com or *.example.com) to the project's scope first"));
    }
    Ok((entries, allowed))
}

pub(crate) type PassiveStart = (i64, Arc<AtomicBool>, Vec<crate::scope::ScopeEntry>, Vec<String>);

pub(crate) fn passive_begin(app: &AppHandle, project_id: i64) -> AppResult<PassiveStart> {
    let (entries, roots) = app.state::<Db>().with(|c| passive_targets(c, project_id))?;
    let (snapshot_id, cancel) = begin(app, project_id, "passive", "passive")?;
    emit(app, project_id, snapshot_id, Some(format!("Passive discovery started for {}", roots.join(", "))));
    Ok((snapshot_id, cancel, entries, roots))
}

pub(crate) async fn passive_run(app: AppHandle, project_id: i64, (snapshot_id, cancel, entries, roots): PassiveStart) -> RunOutcome {
    let guard = RunGuard { app: app.clone(), project_id, snapshot_id };
    let db = app.state::<Db>();
    let (batch, problems, outside) = disc::passive_collect(&db, &entries, &roots, &cancel, progress(&app, project_id, snapshot_id)).await;
    let status = run_status(cancel.load(Ordering::Relaxed), batch.len(), &problems);
    let covers = |a: &assets::Asset| matches!(a.kind.as_str(), "domain" | "subdomain" | "ip" | "dns_record");
    let result = db.with(|c| {
        // names outside the authorized scope are deliberately not recorded; the note says how many
        let mut note_problems = problems.clone();
        if outside > 0 {
            note_problems.push(format!("{} outside the authorized scope not recorded", disc::plural(outside, "name", "names")));
        }
        disc::complete(c, project_id, snapshot_id, "passive", &batch, (status, &note_problems), &covers)
    });
    guard.finish(result)
}

/// Certificate transparency and DNS for the project's in-scope domains. Nothing is sent to the
/// targets; private and internal names are never sent to public sources.
#[tauri::command]
pub async fn discovery_passive_start(app: AppHandle, project_id: i64) -> AppResult<i64> {
    let start = passive_begin(&app, project_id)?;
    let snapshot_id = start.0;
    tauri::async_runtime::spawn(passive_run(app.clone(), project_id, start));
    Ok(snapshot_id)
}

/* ───────────────────────── HTTP probe ───────────────────────── */

/// Hosts to check when none are given: in-scope domain and IP entries and active name assets.
fn default_hosts(c: &rusqlite::Connection, project_id: i64) -> AppResult<Vec<String>> {
    let mut hosts = BTreeSet::new();
    for e in scope_entries(c, project_id)?.into_iter().filter(|e| e.in_scope) {
        match e.kind.as_str() {
            // URL entries authorize paths, never their host: they are not checked as hosts
            "domain" | "ip" => {
                hosts.insert(e.value);
            }
            _ => {}
        }
    }
    let names: Vec<String> = c
        .prepare("SELECT value FROM assets WHERE project_id = ?1 AND status = 'active' AND type IN ('domain','subdomain') ORDER BY value")?
        .query_map(params![project_id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    hosts.extend(names);
    Ok(hosts.into_iter().collect())
}

/// The hosts an HTTP check may contact. Named hosts must all be authorized (refusals are
/// recorded); without names, the in-scope defaults are used.
pub(crate) fn http_targets(c: &rusqlite::Connection, project_id: i64, hosts: Option<Vec<String>>) -> AppResult<Vec<String>> {
    let explicit = hosts.as_ref().is_some_and(|h| !h.is_empty());
    let list: Vec<String> = match hosts.filter(|h| !h.is_empty()) {
        Some(h) => h.into_iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<BTreeSet<_>>().into_iter().collect(),
        None => default_hosts(c, project_id)?,
    };
    let hosts = if explicit {
        // the value checked is the value contacted: URLs and other forms become their host
        let list = list
            .iter()
            .map(|x| match crate::scope::parse_target(x).as_ref().map(crate::scope::Target::host_level) {
                // a URL becomes its host: the check contacts the host (GET / over HTTPS and HTTP),
                // so the host itself must be authorized, not only a path of it
                Some(crate::scope::Target::Host(h)) => Ok(h.clone()),
                Some(crate::scope::Target::Ip(ip)) => Ok(ip.to_string()),
                _ => Err(validation(format!("'{x}' is not a host name or IP address"))),
            })
            .collect::<AppResult<BTreeSet<String>>>()?
            .into_iter()
            .collect::<Vec<_>>();
        if list.len() > disc::MAX_HTTP_HOSTS {
            return Err(validation(format!("At most {} hosts per check", disc::MAX_HTTP_HOSTS)));
        }
        scope_gate::enforce(c, Some(project_id), &list, scope_gate::Mode::Active, "HTTP check")?;
        list
    } else {
        let d = scope_gate::decide(c, Some(project_id), &list, scope_gate::Mode::Active)?;
        if let Some(v) = d.verdicts.iter().find(|v| !v.allowed && v.reason.contains("project")) {
            return Err(AppError::Scope(v.reason.clone()));
        }
        d.verdicts.into_iter().filter(|v| v.allowed).map(|v| v.target).take(disc::MAX_HTTP_HOSTS).collect()
    };
    if hosts.is_empty() {
        return Err(validation("No in-scope host to check. Add domains or IP addresses to the scope, or run passive discovery first."));
    }
    Ok(hosts)
}

/// What an HTTP check sends, for confirmation dialogs.
pub(crate) fn http_description(hosts: &[String]) -> String {
    let shown: Vec<&str> = hosts.iter().take(15).map(String::as_str).collect();
    let more = if hosts.len() > 15 { format!("\n... and {} more", hosts.len() - 15) } else { String::new() };
    format!(
        "one HTTPS and one HTTP request (GET /, no redirects followed, no credentials) to each of these {} in-scope hosts:\n\n{}{more}",
        hosts.len(),
        shown.join("\n")
    )
}

pub(crate) fn http_begin(app: &AppHandle, project_id: i64, hosts: &[String]) -> AppResult<(i64, Arc<AtomicBool>)> {
    let (snapshot_id, cancel) = begin(app, project_id, "active", "http")?;
    emit(app, project_id, snapshot_id, Some(format!("Checking {} hosts", hosts.len())));
    Ok((snapshot_id, cancel))
}

pub(crate) async fn http_run(app: AppHandle, project_id: i64, snapshot_id: i64, cancel: Arc<AtomicBool>, hosts: Vec<String>) -> RunOutcome {
    let guard = RunGuard { app: app.clone(), project_id, snapshot_id };
    let db = app.state::<Db>();
    let entries = db.with(|c| scope_entries(c, project_id)).unwrap_or_default();
    let result = match disc::http_collect(&hosts, &entries, &cancel, progress(&app, project_id, snapshot_id)).await {
        Ok((batch, problems, probed)) => {
            let status = run_status(cancel.load(Ordering::Relaxed), batch.len(), &problems);
            let covers = move |a: &assets::Asset| a.kind == "http_service" && disc::origin_host(&a.value).is_some_and(|h| probed.contains(&h));
            db.with(|c| disc::complete(c, project_id, snapshot_id, "http", &batch, (status, &problems), &covers))
        }
        Err(e) => Err(e),
    };
    guard.finish(result)
}

/// Sends one HTTPS and one HTTP request to each in-scope host (natively confirmed).
#[tauri::command]
pub async fn discovery_http_start(app: AppHandle, db: State<'_, Db>, state: State<'_, DiscoveryState>, project_id: i64, hosts: Option<Vec<String>>) -> AppResult<i64> {
    let hosts = db.with(|c| http_targets(c, project_id, hosts))?;
    if state.busy(project_id) {
        return Err(AppError::Conflict("A discovery is already running for this project".into()));
    }
    let project_name: String = db.with(|c| Ok(c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?))?;
    let text = format!("Project: {project_name}\n\nExploitX will send {}", http_description(&hosts));
    if !crate::confirm::native(&app, "Confirm attack surface check", text, "Check hosts").await {
        return Err(AppError::Cancelled("The check was cancelled in the confirmation dialog".into()));
    }
    let (snapshot_id, cancel) = http_begin(&app, project_id, &hosts)?;
    tauri::async_runtime::spawn(http_run(app.clone(), project_id, snapshot_id, cancel, hosts));
    Ok(snapshot_id)
}

/* ───────────────────────── service scan ───────────────────────── */

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    pub snapshot_id: i64,
    pub execution_id: i64,
}

/// Runs an Nmap service scan through the normal execution path (scope check, native
/// confirmation, process tree), then records its XML results as a snapshot.
#[tauri::command]
pub async fn discovery_scan_start(app: AppHandle, project_id: i64, targets: Vec<String>, profile: String) -> AppResult<ScanStarted> {
    start_scan(&app, project_id, targets, &profile).await
}

/// Starts a service scan (the execution engine asks for native confirmation of the command).
pub(crate) async fn start_scan(app: &AppHandle, project_id: i64, targets: Vec<String>, profile: &str) -> AppResult<ScanStarted> {
    let db = app.state::<Db>();
    let targets: Vec<String> = targets.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect::<BTreeSet<_>>().into_iter().collect();
    if targets.is_empty() || targets.len() > 64 {
        return Err(validation("Give 1 to 64 targets (hosts, addresses or networks)"));
    }
    scope_gate::refuse_urls(&targets, "Service scan")?;
    let args = disc::nmap_args(profile, &targets)?;
    let entries = db.with(|c| {
        scope_gate::enforce(c, Some(project_id), &targets, scope_gate::Mode::Active, "Service scan")?;
        scope_entries(c, project_id)
    })?;
    // names must not point at unauthorized internal addresses (Nmap resolves them again itself)
    for t in &targets {
        if let Some(crate::scope::Target::Host(h)) = crate::scope::parse_target(t) {
            if let Err(reason) = scope_gate::resolve_vetted(&entries, &h, 80).await {
                if reason.contains("authorized scope") {
                    db.with(|c| scope_gate::record_blocked(c, project_id, &h, &reason, "Service scan"))?;
                    return Err(AppError::Scope(format!("Service scan was not started. {reason}")));
                }
            }
        }
    }
    let snapshot_id = db.with(|c| assets::start_snapshot(c, project_id, "active", "nmap", None, None))?;
    let hook: FinishHook = Box::new(move |app: &AppHandle, execution_id: i64, ok: bool| {
        let db = app.state::<Db>();
        let result = db.with(|c| {
            c.execute("UPDATE discovery_snapshots SET execution_id = ?2 WHERE id = ?1", params![snapshot_id, execution_id])?;
            let (output, truncated, status): (String, bool, String) =
                c.query_row("SELECT COALESCE(output, ''), truncated, status FROM executions WHERE id = ?1", params![execution_id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?)))?;
            let run = match disc::parse_nmap(&disc::xml_from_output(&output)) {
                Ok(r) => r,
                Err(e) => {
                    let s = if status == "cancelled" { "cancelled" } else { "failed" };
                    return assets::finish_snapshot(c, snapshot_id, s, &format!("{e} (run #{execution_id} {status})")).map(|_| ());
                }
            };
            let batch = disc::nmap_batch(&run);
            let mut problems = Vec::new();
            if truncated {
                problems.push("the output exceeded the stored size; later hosts are missing".to_string());
            }
            if !run.finished || !ok {
                problems.push(format!("the scan did not finish (run #{execution_id} {status})"));
            }
            let st = if status == "cancelled" && batch.is_empty() { "cancelled" } else { run_status(false, batch.len(), &problems) };
            let up = disc::up_hosts(&run);
            let covers = move |a: &assets::Asset| a.kind == "service" && disc::service_host(&a.value).is_some_and(|h| up.contains(&h));
            disc::complete(c, project_id, snapshot_id, "nmap", &batch, (st, &problems), &covers).map(|_| ())
        });
        if let Err(e) = result {
            let _ = db.with(|c| assets::finish_snapshot(c, snapshot_id, "failed", &e.to_string()));
        }
        emit(app, project_id, snapshot_id, None);
    });
    let request = ExecRequest { tool_id: "nmap".into(), args, project_id: Some(project_id), targets, confirmed: true };
    // output is stored with the run; the live view is the project's run history
    let sink: Channel<crate::process::ExecEvent> = Channel::new(|_| Ok(()));
    match start_execution(app, &db, request, sink, None, Some(hook)).await {
        Ok(execution_id) => {
            let _ = db.with(|c| Ok(c.execute("UPDATE discovery_snapshots SET execution_id = ?2 WHERE id = ?1", params![snapshot_id, execution_id])?));
            emit(app, project_id, snapshot_id, Some("Service scan started".into()));
            Ok(ScanStarted { snapshot_id, execution_id })
        }
        Err(e) => {
            let status = if matches!(e, AppError::Cancelled(_)) { "cancelled" } else { "failed" };
            let _ = db.with(|c| assets::finish_snapshot(c, snapshot_id, status, &e.to_string()));
            emit(app, project_id, snapshot_id, None);
            Err(e)
        }
    }
}

/* ───────────────────────── queries ───────────────────────── */

#[tauri::command]
pub async fn discovery_cancel(state: State<'_, DiscoveryState>, project_id: i64) -> AppResult<bool> {
    Ok(state.cancel(project_id))
}

/// The snapshot of the background discovery running for a project, if any.
#[tauri::command]
pub async fn discovery_running(state: State<'_, DiscoveryState>, project_id: i64) -> AppResult<Option<i64>> {
    let m = state.0.lock().map_err(|_| AppError::Internal("discovery state poisoned".into()))?;
    Ok(m.get(&project_id).map(|(s, _)| *s))
}

#[tauri::command]
pub async fn discovery_snapshots(db: State<'_, Db>, project_id: i64, limit: Option<i64>) -> AppResult<Vec<disc::Snapshot>> {
    db.with(|c| disc::snapshots(c, project_id, limit.unwrap_or(50)))
}

#[tauri::command]
pub async fn discovery_changes(db: State<'_, Db>, snapshot_id: i64) -> AppResult<disc::SnapshotChanges> {
    db.with(|c| disc::changes(c, snapshot_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_hosts_are_checked_and_contacted_in_the_same_form() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (1,'*.example.com','wildcard',1,'t')", [])?;
            let hosts = http_targets(c, 1, Some(vec!["https://app.example.com/login".into(), "APP.example.com".into(), "api.example.com".into()]))?;
            assert_eq!(hosts, vec!["api.example.com", "app.example.com"], "URLs become their host; duplicates collapse");
            assert!(http_targets(c, 1, Some(vec!["192.0.2.0/24".into()])).is_err(), "networks are not hosts");
            assert!(http_targets(c, 1, Some(vec!["evil.example.net".into()])).is_err());
            Ok(())
        })
        .unwrap();
    }
}
