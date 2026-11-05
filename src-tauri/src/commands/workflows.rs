//! Workflow executor and commands (definitions in `workspace::workflows`).
//!
//! * Steps run in order. Each has a time limit, optional retries with a growing pause (only for
//!   steps that are safe to repeat), and may let the run continue after a failure.
//! * A run with steps that contact targets starts only after a native confirmation listing those
//!   steps and their targets; every step checks the scope again when it runs. Service scans also
//!   show the execution engine's own confirmation of the exact command.
//! * Scheduled runs (passive steps only) are started by a background loop while Cyber Hub runs.
//! * State and logs are stored per step; runs interrupted by an exit are marked failed at start.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::discovery::{self as discovery, DiscoveryState, RunOutcome};
use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::process::ProcessManager;
use crate::workspace::workflows::{self as wf, Step, Workflow};

pub const EVENT: &str = "workflow-changed";

/// Runs in progress: run id → (project, cancel flag).
#[derive(Default)]
pub struct WorkflowState(Mutex<HashMap<i64, (i64, Arc<AtomicBool>)>>);

fn emit(app: &AppHandle, project_id: i64, run_id: i64) {
    let _ = app.emit(EVENT, json!({ "projectId": project_id, "runId": run_id }));
}

fn log(app: &AppHandle, run: i64, pos: usize, line: &str) {
    let _ = app.state::<Db>().with(|c| wf::step_log(c, run, pos, line));
}

/* ───────────────────────── steps ───────────────────────── */

fn outcome_result(o: RunOutcome) -> Result<String, String> {
    match o.status.as_str() {
        "completed" => Ok(o.note),
        "partial" => Ok(format!("Partial: {}", o.note)),
        _ => Err(if o.note.is_empty() { format!("Discovery {}", o.status) } else { o.note }),
    }
}

/// Stops the scan's process when the step is abandoned (time limit, cancellation).
struct ScanGuard {
    app: AppHandle,
    execution_id: i64,
    done: bool,
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if !self.done {
            self.app.state::<ProcessManager>().cancel(self.execution_id);
        }
    }
}

/// Runs one step to its end. Errors are messages for the step's summary.
async fn run_step(app: &AppHandle, project_id: i64, wf_name: &str, step: &Step, cancel: &Arc<AtomicBool>, run: i64, pos: usize) -> Result<String, String> {
    let db = app.state::<Db>();
    match step.kind.as_str() {
        "passive_discovery" => {
            let start = discovery::passive_begin(app, project_id).map_err(|e| e.to_string())?;
            log(app, run, pos, &format!("Snapshot #{} started", start.0));
            outcome_result(discovery::passive_run(app.clone(), project_id, start).await)
        }
        "web_check" => {
            let hosts = db.with(|c| discovery::http_targets(c, project_id, Some(step.list("hosts")))).map_err(|e| e.to_string())?;
            let (snapshot, flag) = discovery::http_begin(app, project_id, &hosts).map_err(|e| e.to_string())?;
            log(app, run, pos, &format!("Snapshot #{snapshot}: checking {} hosts", hosts.len()));
            outcome_result(discovery::http_run(app.clone(), project_id, snapshot, flag, hosts).await)
        }
        "service_scan" => {
            let started = discovery::start_scan(app, project_id, step.list("targets"), step.text("profile").as_deref().unwrap_or("quick")).await.map_err(|e| e.to_string())?;
            log(app, run, pos, &format!("Run #{} started (snapshot #{})", started.execution_id, started.snapshot_id));
            let mut guard = ScanGuard { app: app.clone(), execution_id: started.execution_id, done: false };
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled".into());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                let snap = db.with(|c| crate::workspace::discovery::snapshot(c, started.snapshot_id)).map_err(|e| e.to_string())?;
                if snap.status != "running" {
                    guard.done = true;
                    return outcome_result(RunOutcome { snapshot_id: snap.id, status: snap.status, note: snap.note });
                }
            }
        }
        "update_vuln_scores" => {
            let r = crate::commands::vulns::vulns_refresh(app.state::<Db>(), project_id).await.map_err(|e| e.to_string())?;
            for w in &r.warnings {
                log(app, run, pos, w);
            }
            Ok(format!(
                "{} updated{}",
                crate::workspace::discovery::plural(r.updated, "vulnerability", "vulnerabilities"),
                if r.warnings.is_empty() { String::new() } else { format!("; {}", crate::workspace::discovery::plural(r.warnings.len(), "warning", "warnings")) }
            ))
        }
        "save_report" => {
            let md = crate::commands::projects::project_report(app.state::<Db>(), project_id).await.map_err(|e| e.to_string())?;
            let title = step.text("title").unwrap_or_else(|| format!("{wf_name} report {}", chrono::Utc::now().format("%Y-%m-%d %H:%M")));
            let rec = db
                .with(|c| crate::workspace::evidence::add_text(c, project_id, &title.chars().take(200).collect::<String>(), &md, &format!("Generated by the workflow “{wf_name}”"), "workflow"))
                .map_err(|e| e.to_string())?;
            Ok(format!("Saved as evidence #{}", rec.id))
        }
        "wait" => {
            let secs = step.number("seconds").unwrap_or(1).clamp(1, 3600) as u64;
            if pause(Duration::from_secs(secs), cancel).await {
                Ok(format!("Waited {secs} s"))
            } else {
                Err("Cancelled".into())
            }
        }
        other => Err(format!("Unknown step type {other}")),
    }
}

/* ───────────────────────── runs ───────────────────────── */

/// What the driver reports while it runs (stored and emitted by the caller).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Progress {
    Running { pos: usize, attempt: u32 },
    Log { pos: usize, line: String },
    Done { pos: usize, status: &'static str, attempt: u32, summary: Option<String> },
}

/// Timing of the driver: per-step limit and the pause unit between retries (attempt × unit).
pub(crate) struct Timing {
    pub limit: fn(&Step) -> Duration,
    pub pause_unit: Duration,
}

pub(crate) const REAL_TIMING: Timing = Timing { limit: |s| Duration::from_secs(s.timeout()), pause_unit: Duration::from_secs(5) };

async fn pause(d: Duration, cancel: &AtomicBool) -> bool {
    let tick = Duration::from_millis(50).min(d.max(Duration::from_millis(1)));
    let mut waited = Duration::ZERO;
    while waited < d {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        tokio::time::sleep(tick).await;
        waited += tick;
    }
    true
}

/// Runs the steps in order: time limit per attempt, retries for failures (never after a
/// cancellation), skip the rest after a failure unless the step continues on error, cancel the
/// rest after a cancellation. Returns the run's status and summary.
pub(crate) async fn drive<R, Fut>(steps: &[Step], cancel: &AtomicBool, timing: &Timing, mut run: R, mut report: impl FnMut(Progress)) -> (&'static str, String)
where
    R: FnMut(usize, Step) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let (mut ok, mut failed, mut stopped) = (0usize, 0usize, false);
    for (pos, step) in steps.iter().enumerate() {
        if stopped || cancel.load(Ordering::Relaxed) {
            let status = if cancel.load(Ordering::Relaxed) { "cancelled" } else { "skipped" };
            report(Progress::Done { pos, status, attempt: 0, summary: None });
            continue;
        }
        let limit = (timing.limit)(step);
        let mut attempt = 0u32;
        let result = loop {
            attempt += 1;
            report(Progress::Running { pos, attempt });
            report(Progress::Log { pos, line: format!("Attempt {attempt} (time limit {} s)", limit.as_secs()) });
            let r = match tokio::time::timeout(limit, run(pos, step.clone())).await {
                Ok(r) => r,
                Err(_) => Err(format!("Stopped after the time limit of {} s", limit.as_secs())),
            };
            match r {
                Ok(s) => break Ok(s),
                Err(e) if cancel.load(Ordering::Relaxed) => break Err(e),
                Err(e) if attempt <= step.retries => {
                    let wait = timing.pause_unit * attempt;
                    report(Progress::Log { pos, line: format!("Failed: {e}. Retrying in {} s", wait.as_secs()) });
                    if !pause(wait, cancel).await {
                        break Err("Cancelled".into());
                    }
                }
                Err(e) => break Err(e),
            }
        };
        match result {
            Ok(summary) => {
                ok += 1;
                report(Progress::Log { pos, line: format!("Succeeded: {summary}") });
                report(Progress::Done { pos, status: "succeeded", attempt, summary: Some(summary) });
            }
            Err(e) => {
                let status = if cancel.load(Ordering::Relaxed) { "cancelled" } else { "failed" };
                if status == "failed" {
                    failed += 1;
                    if !step.continue_on_error {
                        stopped = true;
                    }
                }
                report(Progress::Log { pos, line: format!("{}: {e}", if status == "failed" { "Failed" } else { "Cancelled" }) });
                report(Progress::Done { pos, status, attempt, summary: Some(e) });
            }
        }
    }
    let total = steps.len();
    let status = if cancel.load(Ordering::Relaxed) {
        "cancelled"
    } else if ok == total {
        "succeeded"
    } else if ok == 0 || stopped {
        "failed"
    } else {
        "partial"
    };
    (status, format!("{ok} of {total} steps succeeded{}", if failed > 0 { format!(", {failed} failed") } else { String::new() }))
}

async fn execute(app: AppHandle, workflow: Workflow, run: i64, cancel: Arc<AtomicBool>) {
    let steps = workflow.definition.steps.clone();
    let report = |p: Progress| {
        let db = app.state::<Db>();
        let _ = match &p {
            Progress::Running { pos, attempt } => db.with(|c| wf::step_update(c, run, *pos, "running", *attempt, None)),
            Progress::Log { pos, line } => db.with(|c| wf::step_log(c, run, *pos, line)),
            Progress::Done { pos, status, attempt, summary } => db.with(|c| wf::step_update(c, run, *pos, status, *attempt, summary.as_deref())),
        };
        if !matches!(p, Progress::Log { .. }) {
            emit(&app, workflow.project_id, run);
        }
    };
    let (app_ref, cancel_ref, name, project_id) = (&app, &cancel, workflow.name.as_str(), workflow.project_id);
    let runner = move |pos: usize, step: Step| async move { run_step(app_ref, project_id, name, &step, cancel_ref, run, pos).await };
    let (status, summary) = drive(&steps, &cancel, &REAL_TIMING, runner, report).await;
    let _ = app.state::<Db>().with(|c| wf::finish_run(c, run, status, &summary));
    if let Ok(mut m) = app.state::<WorkflowState>().0.lock() {
        m.remove(&run);
    }
    emit(&app, workflow.project_id, run);
}

fn spawn_run(app: &AppHandle, workflow: Workflow, trigger: &str) -> AppResult<i64> {
    let run = app.state::<Db>().with(|c| wf::create_run(c, &workflow, trigger))?;
    let cancel = Arc::new(AtomicBool::new(false));
    if let Ok(mut m) = app.state::<WorkflowState>().0.lock() {
        m.insert(run, (workflow.project_id, cancel.clone()));
    }
    emit(app, workflow.project_id, run);
    tauri::async_runtime::spawn(execute(app.clone(), workflow, run, cancel));
    Ok(run)
}

/// What the confirmation dialog lists for a run with active steps. Fails early when a target is
/// out of scope or the project is not active.
fn active_summary(db: &Db, workflow: &Workflow) -> AppResult<String> {
    let mut lines = Vec::new();
    for (i, s) in workflow.definition.steps.iter().enumerate().filter(|(_, s)| s.spec().active) {
        let what = match s.kind.as_str() {
            "web_check" => format!("sends {}", discovery::http_description(&db.with(|c| discovery::http_targets(c, workflow.project_id, Some(s.list("hosts"))))?)),
            "service_scan" => {
                let targets = s.list("targets");
                db.with(|c| crate::workspace::scope_gate::enforce(c, Some(workflow.project_id), &targets, crate::workspace::scope_gate::Mode::Active, "Workflow service scan"))?;
                format!("runs an Nmap service scan of {} (you will confirm the exact command)", targets.join(", "))
            }
            _ => s.spec().description.to_string(),
        };
        lines.push(format!("Step {}: {} {what}", i + 1, s.label()));
    }
    Ok(lines.join("\n\n"))
}

/* ───────────────────────── commands ───────────────────────── */

#[tauri::command]
pub async fn workflow_nodes() -> AppResult<&'static [wf::NodeSpec]> {
    Ok(wf::NODES)
}

#[tauri::command]
pub async fn workflow_templates() -> AppResult<Vec<wf::Template>> {
    Ok(wf::templates())
}

#[tauri::command]
pub async fn workflows_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<Workflow>> {
    db.with(|c| wf::list(c, project_id))
}

#[tauri::command]
pub async fn workflow_save(db: State<'_, Db>, input: wf::WorkflowInput) -> AppResult<Workflow> {
    db.with(|c| wf::save(c, &input))
}

#[tauri::command]
pub async fn workflow_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    let running = db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = ?1 AND status = 'running'", [id], |r| r.get::<_, i64>(0))?))?;
    if running > 0 {
        return Err(AppError::Conflict("Cancel the running workflow first".into()));
    }
    db.with(|c| {
        c.execute("DELETE FROM workflows WHERE id = ?1", [id])?;
        Ok(())
    })
}

/// Starts a run. Runs with steps that contact targets are confirmed natively first.
#[tauri::command]
pub async fn workflow_run(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<i64> {
    let workflow = db.with(|c| wf::get(c, id))?;
    wf::validate(&workflow.definition, false)?;
    if workflow.definition.has_active() {
        let text = format!("Project workflow “{}”\n\nThese steps contact targets:\n\n{}", workflow.name, active_summary(&db, &workflow)?);
        if !crate::confirm::native(&app, "Confirm workflow run", text, "Run workflow").await {
            return Err(AppError::Cancelled("The workflow was cancelled in the confirmation dialog".into()));
        }
    }
    spawn_run(&app, workflow, "manual")
}

#[tauri::command]
pub async fn workflow_cancel(app: AppHandle, state: State<'_, WorkflowState>, run_id: i64) -> AppResult<bool> {
    let entry = state.0.lock().map_err(|_| AppError::Internal("workflow state poisoned".into()))?.get(&run_id).cloned();
    Ok(match entry {
        Some((project_id, flag)) => {
            flag.store(true, Ordering::Relaxed);
            // a discovery step of this run stops too
            app.state::<DiscoveryState>().cancel(project_id);
            true
        }
        None => false,
    })
}

#[tauri::command]
pub async fn workflow_runs(db: State<'_, Db>, workflow_id: i64, limit: Option<i64>) -> AppResult<Vec<wf::RunSummary>> {
    db.with(|c| wf::runs(c, workflow_id, limit.unwrap_or(30)))
}

#[tauri::command]
pub async fn workflow_run_detail(db: State<'_, Db>, run_id: i64) -> AppResult<wf::RunDetail> {
    db.with(|c| wf::run_detail(c, run_id))
}

/// Starts due scheduled workflows every minute while Cyber Hub runs. Only passive workflows can
/// be scheduled; a definition that is no longer valid for a schedule is not run.
pub fn start_scheduler(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let due = app.state::<Db>().with(wf::due).unwrap_or_default();
            for w in due {
                let hours = w.schedule_hours.unwrap_or(24);
                let _ = app.state::<Db>().with(|c| wf::set_next_run(c, w.id, hours));
                if wf::validate(&w.definition, true).is_err() {
                    eprintln!("Cyber Hub: scheduled workflow {} skipped: it contains steps that contact targets", w.id);
                    continue;
                }
                if let Err(e) = spawn_run(&app, w, "schedule") {
                    eprintln!("Cyber Hub: scheduled workflow not started: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn step(kind: &str, retries: u32, continue_on_error: bool) -> Step {
        Step { kind: kind.into(), name: String::new(), params: Default::default(), timeout_secs: 0, retries, continue_on_error }
    }

    const FAST: Timing = Timing { limit: |_| Duration::from_millis(200), pause_unit: Duration::from_millis(1) };

    fn statuses(events: &[Progress]) -> Vec<(usize, &'static str, u32)> {
        events.iter().filter_map(|e| if let Progress::Done { pos, status, attempt, .. } = e { Some((*pos, *status, *attempt)) } else { None }).collect()
    }

    #[tokio::test]
    async fn steps_run_in_order_and_failures_stop_the_rest() {
        let cancel = AtomicBool::new(false);
        let order = RefCell::new(Vec::new());
        let mut events = Vec::new();
        let steps = vec![step("a", 0, false), step("b", 0, false), step("c", 0, false)];
        let (status, summary) = drive(
            &steps,
            &cancel,
            &FAST,
            |pos, _| {
                order.borrow_mut().push(pos);
                async move { if pos == 1 { Err("boom".to_string()) } else { Ok("fine".to_string()) } }
            },
            |e| events.push(e),
        )
        .await;
        assert_eq!(*order.borrow(), vec![0, 1], "nothing runs after a failed step");
        assert_eq!(statuses(&events), vec![(0, "succeeded", 1), (1, "failed", 1), (2, "skipped", 0)]);
        assert_eq!((status, summary.as_str()), ("failed", "1 of 3 steps succeeded, 1 failed"));
    }

    #[tokio::test]
    async fn retries_and_continue_on_error_give_a_partial_run() {
        let cancel = AtomicBool::new(false);
        let calls = RefCell::new(0);
        let mut events = Vec::new();
        let steps = vec![step("flaky", 2, false), step("broken", 1, true), step("last", 0, false)];
        let (status, _) = drive(
            &steps,
            &cancel,
            &FAST,
            |pos, _| {
                *calls.borrow_mut() += 1;
                let n = *calls.borrow();
                async move {
                    match pos {
                        0 if n < 3 => Err("temporary".to_string()),
                        1 => Err("permanent".to_string()),
                        _ => Ok("ok".to_string()),
                    }
                }
            },
            |e| events.push(e),
        )
        .await;
        assert_eq!(statuses(&events), vec![(0, "succeeded", 3), (1, "failed", 2), (2, "succeeded", 1)]);
        assert_eq!(status, "partial");
        assert!(events.iter().any(|e| matches!(e, Progress::Log { line, .. } if line.contains("Retrying"))));
    }

    #[tokio::test]
    async fn time_limits_stop_a_step() {
        let cancel = AtomicBool::new(false);
        let mut events = Vec::new();
        let (status, _) = drive(
            &[step("slow", 0, false)],
            &cancel,
            &FAST,
            |_, _| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok("never".to_string())
            },
            |e| events.push(e),
        )
        .await;
        assert_eq!(status, "failed");
        assert!(events.iter().any(|e| matches!(e, Progress::Done { summary: Some(s), .. } if s.contains("time limit"))));
    }

    #[tokio::test]
    async fn cancellation_is_not_retried_and_cancels_the_rest() {
        let cancel = AtomicBool::new(false);
        let mut events = Vec::new();
        let (status, _) = drive(
            &[step("a", 3, false), step("b", 0, false)],
            &cancel,
            &FAST,
            |_, _| {
                cancel.store(true, Ordering::Relaxed);
                async { Err("Cancelled".to_string()) }
            },
            |e| events.push(e),
        )
        .await;
        assert_eq!(statuses(&events), vec![(0, "cancelled", 1), (1, "cancelled", 0)]);
        assert_eq!(status, "cancelled");
    }
}

