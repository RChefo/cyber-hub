//! Workflow definitions: an ordered list of predefined steps with validated parameters. There is
//! no scripting: every step type is implemented in Cyber Hub and goes through the same scope
//! gate, confirmations and limits as the matching manual action. The executor lives in
//! `commands::workflows`.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const MAX_STEPS: usize = 20;
pub const MAX_RETRIES: u32 = 3;
pub const MIN_TIMEOUT: u64 = 10;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ParamKind {
    /// a list of hosts, addresses or networks
    Targets,
    Select,
    Number,
    Text,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParamSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: ParamKind,
    pub required: bool,
    pub help: &'static str,
    pub options: &'static [(&'static str, &'static str)],
    pub min: i64,
    pub max: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSpec {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    /// contacts targets: needs an active project, a native confirmation when the run starts, and
    /// is never allowed in scheduled workflows
    pub active: bool,
    pub retryable: bool,
    pub default_timeout: u64,
    pub max_timeout: u64,
    pub params: &'static [ParamSpec],
}

const NO_PARAMS: &[ParamSpec] = &[];
const TARGETS_HELP: &str = "One per line; every target is checked against the project's scope when the step runs.";

pub const NODES: &[NodeSpec] = &[
    NodeSpec {
        kind: "passive_discovery",
        label: "Passive discovery",
        description: "Certificate transparency and DNS for the project's in-scope domains. Asks public sources only.",
        active: false,
        retryable: true,
        default_timeout: 900,
        max_timeout: 3600,
        params: NO_PARAMS,
    },
    NodeSpec {
        kind: "web_check",
        label: "Check web services",
        description: "One HTTPS and one HTTP request to in-scope hosts; records web services and technologies.",
        active: true,
        retryable: true,
        default_timeout: 900,
        max_timeout: 3600,
        params: &[ParamSpec { key: "hosts", label: "Hosts", kind: ParamKind::Targets, required: false, help: "Leave empty to check the in-scope domains, addresses and discovered names.", options: &[], min: 0, max: 100 }],
    },
    NodeSpec {
        kind: "service_scan",
        label: "Service scan",
        description: "Nmap service detection through the tool execution engine; the command is confirmed in a system dialog when the step starts.",
        active: true,
        retryable: false,
        default_timeout: 3600,
        max_timeout: 14_400,
        params: &[
            ParamSpec { key: "targets", label: "Targets", kind: ParamKind::Targets, required: true, help: TARGETS_HELP, options: &[], min: 1, max: 64 },
            ParamSpec { key: "profile", label: "Ports", kind: ParamKind::Select, required: true, help: "", options: &[("quick", "100 most common ports"), ("standard", "1,000 most common ports")], min: 0, max: 0 },
        ],
    },
    NodeSpec {
        kind: "update_vuln_scores",
        label: "Update vulnerability scores",
        description: "Re-reads CVSS and KEV, fetches EPSS when it is on, and recomputes priorities of open vulnerabilities.",
        active: false,
        retryable: true,
        default_timeout: 300,
        max_timeout: 1800,
        params: NO_PARAMS,
    },
    NodeSpec {
        kind: "save_report",
        label: "Save project report",
        description: "Generates the project's Markdown report and stores it as text evidence.",
        active: false,
        retryable: false,
        default_timeout: 60,
        max_timeout: 300,
        params: &[ParamSpec { key: "title", label: "Evidence title", kind: ParamKind::Text, required: false, help: "Defaults to the workflow name and date.", options: &[], min: 0, max: 200 }],
    },
    NodeSpec {
        kind: "wait",
        label: "Wait",
        description: "Pauses before the next step (for example to respect a rate limit).",
        active: false,
        retryable: false,
        default_timeout: 3700,
        max_timeout: 3700,
        params: &[ParamSpec { key: "seconds", label: "Seconds", kind: ParamKind::Number, required: true, help: "", options: &[], min: 1, max: 3600 }],
    },
];

pub fn node(kind: &str) -> Option<&'static NodeSpec> {
    NODES.iter().find(|n| n.kind == kind)
}

fn default_timeout() -> u64 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Step {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub params: Map<String, Value>,
    /// 0 = the node's default
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub continue_on_error: bool,
}

impl Step {
    pub fn spec(&self) -> &'static NodeSpec {
        node(&self.kind).expect("validated step")
    }
    pub fn timeout(&self) -> u64 {
        if self.timeout_secs == 0 {
            self.spec().default_timeout
        } else {
            self.timeout_secs
        }
    }
    pub fn label(&self) -> String {
        if self.name.trim().is_empty() {
            self.spec().label.to_string()
        } else {
            self.name.trim().to_string()
        }
    }
    pub fn list(&self, key: &str) -> Vec<String> {
        self.params.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
    }
    pub fn text(&self, key: &str) -> Option<String> {
        self.params.get(key).and_then(Value::as_str).map(str::to_string)
    }
    pub fn number(&self, key: &str) -> Option<i64> {
        self.params.get(key).and_then(Value::as_i64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Definition {
    pub steps: Vec<Step>,
}

impl Definition {
    pub fn has_active(&self) -> bool {
        self.steps.iter().any(|s| node(&s.kind).is_some_and(|n| n.active))
    }
}

/// Checks a definition completely; returns it with list values trimmed and deduplicated.
pub fn validate(def: &Definition, scheduled: bool) -> AppResult<Definition> {
    if def.steps.is_empty() || def.steps.len() > MAX_STEPS {
        return Err(validation(format!("A workflow has 1 to {MAX_STEPS} steps")));
    }
    let mut out = def.clone();
    for (i, step) in out.steps.iter_mut().enumerate() {
        let n = i + 1;
        let spec = node(&step.kind).ok_or_else(|| validation(format!("Step {n}: unknown step type '{}'", step.kind)))?;
        if step.name.chars().count() > 100 || step.name.chars().any(char::is_control) {
            return Err(validation(format!("Step {n}: the name is limited to 100 characters")));
        }
        if scheduled && spec.active {
            return Err(validation(format!("Step {n} ({}) contacts targets; scheduled workflows may only contain passive steps", spec.label)));
        }
        if step.timeout_secs != 0 && !(MIN_TIMEOUT..=spec.max_timeout).contains(&step.timeout_secs) {
            return Err(validation(format!("Step {n}: the time limit must be between {MIN_TIMEOUT} and {} seconds", spec.max_timeout)));
        }
        if step.retries > MAX_RETRIES || (step.retries > 0 && !spec.retryable) {
            return Err(validation(format!("Step {n}: {}", if spec.retryable { format!("at most {MAX_RETRIES} retries") } else { format!("{} is not retried automatically", spec.label) })));
        }
        for key in step.params.keys() {
            if !spec.params.iter().any(|p| p.key == key) {
                return Err(validation(format!("Step {n}: unknown setting '{key}'")));
            }
        }
        for p in spec.params {
            let v = step.params.get(p.key).cloned().unwrap_or(Value::Null);
            let clean = match p.kind {
                ParamKind::Targets => {
                    let items: Vec<String> = match &v {
                        Value::Null => vec![],
                        Value::Array(a) => a
                            .iter()
                            .map(|x| x.as_str().map(|s| s.trim().to_string()).ok_or_else(|| validation(format!("Step {n}: {} must be text", p.label))))
                            .collect::<AppResult<Vec<_>>>()?,
                        _ => return Err(validation(format!("Step {n}: {} must be a list", p.label))),
                    };
                    let mut list: Vec<String> = Vec::new();
                    for t in items.into_iter().filter(|t| !t.is_empty()) {
                        if t.len() > 255 || t.chars().any(|c| c.is_whitespace() || c.is_control()) || t.starts_with('-') {
                            return Err(validation(format!("Step {n}: '{t}' is not a host, address or network")));
                        }
                        if !list.contains(&t) {
                            list.push(t);
                        }
                    }
                    if list.len() < p.min as usize || list.len() > p.max as usize {
                        return Err(validation(format!("Step {n}: {} needs {} to {} entries", p.label, p.min, p.max)));
                    }
                    (!list.is_empty()).then(|| json!(list))
                }
                ParamKind::Select => match v.as_str() {
                    Some(s) if p.options.iter().any(|(k, _)| *k == s) => Some(v.clone()),
                    None if !p.required => None,
                    _ => return Err(validation(format!("Step {n}: choose a value for {}", p.label))),
                },
                ParamKind::Number => match v.as_i64() {
                    Some(x) if (p.min..=p.max).contains(&x) => Some(v.clone()),
                    None if !p.required && v.is_null() => None,
                    _ => return Err(validation(format!("Step {n}: {} must be between {} and {}", p.label, p.min, p.max))),
                },
                ParamKind::Text => match &v {
                    Value::Null => None,
                    Value::String(s) if s.chars().count() <= p.max as usize && !s.chars().any(char::is_control) => (!s.trim().is_empty()).then(|| json!(s.trim())),
                    _ => return Err(validation(format!("Step {n}: {} is limited to {} characters", p.label, p.max))),
                },
            };
            if p.required && clean.is_none() {
                return Err(validation(format!("Step {n}: {} is required", p.label)));
            }
            match clean {
                Some(c) => {
                    step.params.insert(p.key.into(), c);
                }
                None => {
                    step.params.remove(p.key);
                }
            }
        }
    }
    Ok(out)
}

/* ───────────────────────── templates ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Template {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub definition: Definition,
}

fn step(kind: &str, params: Value) -> Step {
    Step { kind: kind.into(), name: String::new(), params: params.as_object().cloned().unwrap_or_default(), timeout_secs: 0, retries: 0, continue_on_error: false }
}

pub fn templates() -> Vec<Template> {
    vec![
        Template {
            id: "passive-refresh",
            name: "Passive attack surface refresh",
            description: "Passive discovery, updated vulnerability scores and a saved report. Passive only, so it can run on a schedule.",
            definition: Definition {
                steps: vec![
                    Step { retries: 1, continue_on_error: true, ..step("passive_discovery", json!({})) },
                    Step { continue_on_error: true, ..step("update_vuln_scores", json!({})) },
                    step("save_report", json!({})),
                ],
            },
        },
        Template {
            id: "external-exposure",
            name: "External exposure check",
            description: "Passive discovery followed by a check of the web services it found.",
            definition: Definition { steps: vec![step("passive_discovery", json!({})), step("web_check", json!({}))] },
        },
        Template {
            id: "service-baseline",
            name: "Service baseline",
            description: "A quick service scan of the given targets, then a saved report.",
            definition: Definition { steps: vec![step("service_scan", json!({ "targets": [], "profile": "quick" })), step("save_report", json!({}))] },
        },
    ]
}

/* ───────────────────────── persistence ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Workflow {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub description: String,
    pub definition: Definition,
    pub schedule_hours: Option<i64>,
    pub enabled: bool,
    pub next_run_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_run: Option<RunSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub id: i64,
    pub status: String,
    pub trigger: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub summary: String,
}

const WF_COLS: &str = "w.id, w.project_id, w.name, w.description, w.definition, w.schedule_hours, w.enabled, w.next_run_at, w.created_at, w.updated_at,
    r.id, r.status, r.trigger, r.started_at, r.finished_at, r.summary";
const WF_FROM: &str = "FROM workflows w LEFT JOIN workflow_runs r ON r.id = (SELECT MAX(id) FROM workflow_runs WHERE workflow_id = w.id)";

fn wf_row(r: &rusqlite::Row) -> rusqlite::Result<Workflow> {
    let run_id: Option<i64> = r.get(10)?;
    Ok(Workflow {
        id: r.get(0)?,
        project_id: r.get(1)?,
        name: r.get(2)?,
        description: r.get(3)?,
        definition: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        schedule_hours: r.get(5)?,
        enabled: r.get::<_, i64>(6)? != 0,
        next_run_at: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
        last_run: match run_id {
            Some(id) => Some(RunSummary { id, status: r.get(11)?, trigger: r.get(12)?, started_at: r.get(13)?, finished_at: r.get(14)?, summary: r.get(15)? }),
            None => None,
        },
    })
}

pub fn get(c: &Connection, id: i64) -> AppResult<Workflow> {
    c.query_row(&format!("SELECT {WF_COLS} {WF_FROM} WHERE w.id = ?1"), params![id], wf_row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("workflow {id}")))
}

pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<Workflow>> {
    let mut st = c.prepare(&format!("SELECT {WF_COLS} {WF_FROM} WHERE w.project_id = ?1 ORDER BY w.name"))?;
    let rows = st.query_map(params![project_id], wf_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInput {
    pub id: Option<i64>,
    pub project_id: i64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub definition: Definition,
    #[serde(default)]
    pub schedule_hours: Option<i64>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

pub fn next_run(hours: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::hours(hours)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn save(c: &Connection, input: &WorkflowInput) -> AppResult<Workflow> {
    let name = crate::util::clean("Name", &input.name, 100, true)?;
    let description = crate::util::clean("Description", &input.description, 2000, false)?;
    if let Some(h) = input.schedule_hours {
        if !(1..=720).contains(&h) {
            return Err(validation("Scheduled workflows run every 1 to 720 hours"));
        }
    }
    let def = validate(&input.definition, input.schedule_hours.is_some())?;
    let json = serde_json::to_string(&def)?;
    let ts = now();
    let next = input.schedule_hours.filter(|_| input.enabled).map(next_run);
    let id = match input.id {
        Some(id) => {
            let old = get(c, id)?;
            if old.project_id != input.project_id {
                return Err(validation("A workflow cannot be moved to another project"));
            }
            // an unchanged schedule keeps its next run
            let next = if old.schedule_hours == input.schedule_hours && old.enabled == input.enabled { old.next_run_at.or(next) } else { next };
            c.execute(
                "UPDATE workflows SET name = ?2, description = ?3, definition = ?4, schedule_hours = ?5, enabled = ?6, next_run_at = ?7, updated_at = ?8 WHERE id = ?1",
                params![id, name, description, json, input.schedule_hours, input.enabled as i64, next, ts],
            )?;
            id
        }
        None => {
            let exists: i64 = c.query_row("SELECT COUNT(*) FROM projects WHERE id = ?1", params![input.project_id], |r| r.get(0))?;
            if exists == 0 {
                return Err(AppError::NotFound(format!("project {}", input.project_id)));
            }
            c.execute(
                "INSERT INTO workflows (project_id, name, description, definition, schedule_hours, enabled, next_run_at, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8)",
                params![input.project_id, name, description, json, input.schedule_hours, input.enabled as i64, next, ts],
            )?;
            c.last_insert_rowid()
        }
    };
    get(c, id)
}

/* ───────────────────────── runs ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunStep {
    pub id: i64,
    pub position: i64,
    pub kind: String,
    pub name: String,
    pub status: String,
    pub attempts: i64,
    pub summary: String,
    pub log: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunDetail {
    pub run: RunSummary,
    pub workflow_id: i64,
    pub steps: Vec<RunStep>,
}

/// Creates a run with one pending row per step.
pub fn create_run(c: &Connection, wf: &Workflow, trigger: &str) -> AppResult<i64> {
    let tx = c.unchecked_transaction()?;
    let running: i64 = tx.query_row("SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = ?1 AND status = 'running'", params![wf.id], |r| r.get(0))?;
    if running > 0 {
        return Err(AppError::Conflict(format!("“{}” is already running", wf.name)));
    }
    tx.execute(
        "INSERT INTO workflow_runs (workflow_id, project_id, trigger, status, definition, started_at) VALUES (?1,?2,?3,'running',?4,?5)",
        params![wf.id, wf.project_id, trigger, serde_json::to_string(&wf.definition)?, now()],
    )?;
    let run = tx.last_insert_rowid();
    for (i, s) in wf.definition.steps.iter().enumerate() {
        tx.execute("INSERT INTO workflow_run_steps (run_id, position, kind, name, status) VALUES (?1,?2,?3,?4,'pending')", params![run, i as i64, s.kind, s.label()])?;
    }
    tx.commit()?;
    Ok(run)
}

pub fn step_update(c: &Connection, run: i64, position: usize, status: &str, attempts: u32, summary: Option<&str>) -> AppResult<()> {
    let ts = now();
    c.execute(
        "UPDATE workflow_run_steps SET status = ?3, attempts = ?4,
             summary = COALESCE(?5, summary),
             started_at = CASE WHEN ?3 = 'running' THEN COALESCE(started_at, ?6) ELSE started_at END,
             finished_at = CASE WHEN ?3 IN ('succeeded','failed','skipped','cancelled') THEN ?6 ELSE finished_at END
         WHERE run_id = ?1 AND position = ?2",
        params![run, position as i64, status, attempts, summary.map(|s| s.chars().take(2000).collect::<String>()), ts],
    )?;
    Ok(())
}

/// Appends to a step's log, keeping its last 64 KB.
pub fn step_log(c: &Connection, run: i64, position: usize, line: &str) -> AppResult<()> {
    let line = format!("{} {}\n", now(), line.chars().take(2000).collect::<String>());
    c.execute(
        "UPDATE workflow_run_steps SET log = substr(log || ?3, -65536) WHERE run_id = ?1 AND position = ?2",
        params![run, position as i64, line],
    )?;
    Ok(())
}

pub fn finish_run(c: &Connection, run: i64, status: &str, summary: &str) -> AppResult<()> {
    c.execute("UPDATE workflow_runs SET status = ?2, summary = ?3, finished_at = ?4 WHERE id = ?1 AND status = 'running'", params![run, status, summary, now()])?;
    Ok(())
}

pub fn runs(c: &Connection, workflow_id: i64, limit: i64) -> AppResult<Vec<RunSummary>> {
    let mut st = c.prepare("SELECT id, status, trigger, started_at, finished_at, summary FROM workflow_runs WHERE workflow_id = ?1 ORDER BY id DESC LIMIT ?2")?;
    let rows = st
        .query_map(params![workflow_id, limit.clamp(1, 200)], |r| Ok(RunSummary { id: r.get(0)?, status: r.get(1)?, trigger: r.get(2)?, started_at: r.get(3)?, finished_at: r.get(4)?, summary: r.get(5)? }))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn run_detail(c: &Connection, run: i64) -> AppResult<RunDetail> {
    let (workflow_id, summary) = c
        .query_row("SELECT workflow_id, id, status, trigger, started_at, finished_at, summary FROM workflow_runs WHERE id = ?1", params![run], |r| {
            Ok((r.get::<_, i64>(0)?, RunSummary { id: r.get(1)?, status: r.get(2)?, trigger: r.get(3)?, started_at: r.get(4)?, finished_at: r.get(5)?, summary: r.get(6)? }))
        })
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("workflow run {run}")))?;
    let mut st = c.prepare("SELECT id, position, kind, name, status, attempts, summary, log, started_at, finished_at FROM workflow_run_steps WHERE run_id = ?1 ORDER BY position")?;
    let steps = st
        .query_map(params![run], |r| {
            Ok(RunStep { id: r.get(0)?, position: r.get(1)?, kind: r.get(2)?, name: r.get(3)?, status: r.get(4)?, attempts: r.get(5)?, summary: r.get(6)?, log: r.get(7)?, started_at: r.get(8)?, finished_at: r.get(9)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RunDetail { run: summary, workflow_id, steps })
}

/// Workflows whose schedule is due (enabled, scheduled, passive only).
pub fn due(c: &Connection) -> AppResult<Vec<Workflow>> {
    let mut st = c.prepare(&format!("SELECT {WF_COLS} {WF_FROM} WHERE w.enabled = 1 AND w.schedule_hours IS NOT NULL AND w.next_run_at IS NOT NULL AND w.next_run_at <= ?1"))?;
    let rows = st.query_map(params![now()], wf_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn set_next_run(c: &Connection, id: i64, hours: i64) -> AppResult<()> {
    c.execute("UPDATE workflows SET next_run_at = ?2 WHERE id = ?1", params![id, next_run(hours)])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn def(steps: Vec<Value>) -> Definition {
        serde_json::from_value(json!({ "steps": steps })).unwrap()
    }

    #[test]
    fn definitions_are_validated_strictly() {
        assert!(validate(&def(vec![]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "shell", "params": { "cmd": "rm -rf /" } })]), false).is_err(), "only predefined steps exist");
        assert!(serde_json::from_value::<Definition>(json!({ "steps": [{ "type": "wait", "script": "x" }] })).is_err(), "unknown fields are refused");
        assert!(validate(&def(vec![json!({ "type": "wait", "params": { "seconds": 5, "extra": 1 } })]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "wait", "params": { "seconds": 0 } })]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "wait" })]), false).is_err(), "required settings");
        assert!(validate(&def(vec![json!({ "type": "service_scan", "params": { "targets": ["192.0.2.1"], "profile": "--script=all" } })]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "service_scan", "params": { "targets": ["-sS"], "profile": "quick" } })]), false).is_err(), "option-like targets are refused");
        assert!(validate(&def(vec![json!({ "type": "service_scan", "params": { "targets": ["a b"], "profile": "quick" } })]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "service_scan", "params": { "targets": ["192.0.2.1"], "profile": "quick" }, "retries": 1 })]), false).is_err(), "scans are not retried");
        assert!(validate(&def(vec![json!({ "type": "passive_discovery", "retries": 4 })]), false).is_err());
        assert!(validate(&def(vec![json!({ "type": "passive_discovery", "timeoutSecs": 5 })]), false).is_err());
        let many: Vec<Value> = (0..21).map(|_| json!({ "type": "wait", "params": { "seconds": 1 } })).collect();
        assert!(validate(&def(many), false).is_err());

        let ok = validate(&def(vec![json!({ "type": "web_check", "params": { "hosts": [" a.example.com ", "a.example.com", ""] } }), json!({ "type": "save_report", "params": { "title": "  " } })]), false).unwrap();
        assert_eq!(ok.steps[0].list("hosts"), vec!["a.example.com"], "lists are trimmed and deduplicated");
        assert!(!ok.steps[1].params.contains_key("title"), "empty optional text is dropped");
        assert!(ok.has_active());
    }

    #[test]
    fn schedules_allow_passive_steps_only() {
        let passive = def(vec![json!({ "type": "passive_discovery" }), json!({ "type": "update_vuln_scores" })]);
        assert!(validate(&passive, true).is_ok());
        let active = def(vec![json!({ "type": "passive_discovery" }), json!({ "type": "web_check" })]);
        let err = validate(&active, true).unwrap_err().to_string();
        assert!(err.contains("passive"), "{err}");
        for t in templates() {
            assert_eq!(validate(&t.definition, false).is_ok(), t.id != "service-baseline", "{}: the baseline template needs targets first", t.id);
        }
        assert!(validate(&templates()[0].definition, true).is_ok(), "the passive template can be scheduled");
    }

    #[test]
    fn workflows_and_runs_are_stored() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            let p = c.last_insert_rowid();
            let input = WorkflowInput { id: None, project_id: p, name: "Weekly".into(), description: String::new(), definition: templates()[0].definition.clone(), schedule_hours: Some(168), enabled: true };
            let wf = save(c, &input)?;
            assert!(wf.next_run_at.is_some());
            assert!(save(c, &WorkflowInput { definition: templates()[1].definition.clone(), ..input.clone() }).is_err(), "an active step cannot be scheduled");
            assert!(save(c, &WorkflowInput { schedule_hours: Some(0), ..input.clone() }).is_err());
            let unscheduled = save(c, &WorkflowInput { id: Some(wf.id), schedule_hours: None, ..input.clone() })?;
            assert_eq!(unscheduled.next_run_at, None);

            let run = create_run(c, &unscheduled, "manual")?;
            assert!(create_run(c, &unscheduled, "manual").is_err(), "one run at a time per workflow");
            step_update(c, run, 0, "running", 1, None)?;
            step_log(c, run, 0, "started")?;
            step_update(c, run, 0, "succeeded", 1, Some("12 assets"))?;
            step_update(c, run, 1, "skipped", 0, None)?;
            finish_run(c, run, "partial", "1 of 3 steps succeeded")?;
            let d = run_detail(c, run)?;
            assert_eq!(d.steps.len(), 3);
            assert_eq!((d.steps[0].status.as_str(), d.steps[0].summary.as_str()), ("succeeded", "12 assets"));
            assert!(d.steps[0].log.contains("started") && d.steps[0].finished_at.is_some());
            assert_eq!(get(c, wf.id)?.last_run.map(|r| r.status), Some("partial".into()));
            assert_eq!(runs(c, wf.id, 10)?.len(), 1);

            // the schedule
            c.execute("UPDATE workflows SET schedule_hours = 1, next_run_at = '2000-01-01T00:00:00Z' WHERE id = ?1", params![wf.id])?;
            assert_eq!(due(c)?.len(), 1);
            set_next_run(c, wf.id, 1)?;
            assert!(due(c)?.is_empty());
            Ok(())
        })
        .unwrap();
    }
}
