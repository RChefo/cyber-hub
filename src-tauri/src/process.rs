//! Process manager: spawns catalog-resolved executables with structured argv (never
//! through a shell), streams stdout/stderr to the frontend over a Tauri channel,
//! cancels whole process trees, persists redacted execution history and removes
//! per-run temporary files.
//!
//! Process trees:
//! * Windows — each run is assigned to a Job Object with KILL_ON_JOB_CLOSE. Cancelling
//!   terminates the job; when the run ends (or Cyber Hub exits) the job handle is closed
//!   and any leftover descendants are killed by the OS.
//! * Unix — each run starts in its own process group; cancelling sends SIGTERM and then
//!   SIGKILL to the group. On exit Cyber Hub kills every running group.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::oneshot;

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::redact;
use crate::util::{hide_console_tokio, now};

const MAX_STORED_OUTPUT: usize = 2 * 1024 * 1024;
/// Output without newlines is split into chunks of this size.
const MAX_LINE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ExecEvent {
    #[serde(rename_all = "camelCase")]
    Started { execution_id: i64, program: String, args: Vec<String> },
    Stdout { line: String },
    Stderr { line: String },
    #[serde(rename_all = "camelCase")]
    Exit { status: String, code: Option<i32> },
}

/* ───────────────────────── process trees ───────────────────────── */

#[cfg(windows)]
mod tree {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Owned Job Object handle. Closing it kills every process still in the job.
    pub struct Tree(HANDLE);
    // The handle is only used through thread-safe Win32 calls.
    unsafe impl Send for Tree {}
    unsafe impl Sync for Tree {}

    impl Tree {
        pub fn attach(child: &tokio::process::Child) -> Option<Tree> {
            let process = child.raw_handle()? as HANDLE;
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 || AssignProcessToJobObject(job, process) == 0 {
                    CloseHandle(job);
                    return None;
                }
                Some(Tree(job))
            }
        }

        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }

        pub fn id(&self) -> i64 {
            self.0 as i64
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// Terminate a job synchronously (used on app exit). `id` is the job handle value of a
    /// `Tree` that is still owned by its run task, so the handle is valid here.
    pub fn kill_group(id: i64) {
        unsafe {
            TerminateJobObject(id as isize as HANDLE, 1);
        }
    }
}

#[cfg(unix)]
mod tree {
    /// Process group of a run (the child was started with `process_group(0)`).
    pub struct Tree(i32);

    impl Tree {
        pub fn attach(child: &tokio::process::Child) -> Option<Tree> {
            child.id().map(|pid| Tree(pid as i32))
        }

        pub fn terminate(&self) {
            let pg = self.0;
            unsafe {
                libc::killpg(pg, libc::SIGTERM);
            }
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                unsafe {
                    libc::killpg(pg, libc::SIGKILL);
                }
            });
        }

        pub fn id(&self) -> i64 {
            self.0 as i64
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // leftover descendants of a finished run are not kept alive
            unsafe {
                libc::killpg(self.0, libc::SIGKILL);
            }
        }
    }

    pub fn kill_group(id: i64) {
        unsafe {
            libc::killpg(id as i32, libc::SIGKILL);
        }
    }
}

pub use tree::Tree;

/// Spawn a command so that its whole tree can be terminated (process group on Unix).
pub fn prepare_tree(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    #[cfg(not(unix))]
    {
        let _ = cmd;
    }
}

/* ───────────────────────── registry ───────────────────────── */

struct Running {
    cancel: oneshot::Sender<()>,
    tree_id: Option<i64>,
}

#[derive(Default)]
pub struct ProcessManager {
    running: Mutex<HashMap<i64, Running>>,
}

impl ProcessManager {
    pub fn cancel(&self, id: i64) -> bool {
        let entry = self.running.lock().ok().and_then(|mut m| m.remove(&id));
        match entry {
            Some(r) => r.cancel.send(()).is_ok(),
            None => false,
        }
    }

    pub fn running_ids(&self) -> Vec<i64> {
        self.running.lock().map(|m| m.keys().copied().collect()).unwrap_or_default()
    }

    /// Called when Cyber Hub exits: synchronously kill every running process tree.
    /// (On Windows the OS also kills job members when the job handles close.)
    pub fn kill_all_now(&self) {
        if let Ok(mut m) = self.running.lock() {
            for (_, r) in m.drain() {
                if let Some(id) = r.tree_id {
                    tree::kill_group(id);
                }
                let _ = r.cancel.send(());
            }
        }
    }
}

/* ───────────────────────── spawning ───────────────────────── */

pub struct SpawnSpec {
    pub tool_id: String,
    pub kind: &'static str,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub project_id: Option<i64>,
    /// directory removed when the run ends (validated target-file snapshots)
    pub cleanup_dir: Option<PathBuf>,
}

pub type FinishHook = Box<dyn FnOnce(&AppHandle, bool) + Send + 'static>;

struct OutputBuf {
    text: String,
    truncated: bool,
}

impl OutputBuf {
    fn push(&mut self, prefix: &str, line: &str) {
        if self.text.len() + line.len() + prefix.len() + 1 > MAX_STORED_OUTPUT {
            self.truncated = true;
            return;
        }
        self.text.push_str(prefix);
        self.text.push_str(line);
        self.text.push('\n');
    }
}

async fn pump<R: AsyncRead + Unpin>(reader: R, is_err: bool, channel: Channel<ExecEvent>, buf: Arc<Mutex<OutputBuf>>) {
    let mut reader = BufReader::new(reader);
    let mut raw = Vec::with_capacity(1024);
    loop {
        raw.clear();
        // bounded read: a line longer than MAX_LINE_BYTES is delivered in chunks
        match (&mut reader).take(MAX_LINE_BYTES).read_until(b'\n', &mut raw).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&raw).trim_end_matches(['\r', '\n']).to_string();
                if let Ok(mut b) = buf.lock() {
                    b.push(if is_err { "[stderr] " } else { "" }, &line);
                }
                let ev = if is_err { ExecEvent::Stderr { line } } else { ExecEvent::Stdout { line } };
                let _ = channel.send(ev);
            }
        }
    }
}

pub fn start(app: &AppHandle, spec: SpawnSpec, channel: Channel<ExecEvent>, on_finish: Option<FinishHook>) -> AppResult<i64> {
    let db = app.state::<Db>();
    let shown_args = redact::redact_args(&spec.args);
    let args_json = serde_json::to_string(&shown_args)?;
    let program_str = spec.program.to_string_lossy().to_string();
    let id = db.with(|c| {
        c.execute(
            "INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6)",
            rusqlite::params![spec.tool_id, spec.kind, program_str, args_json, spec.project_id, now()],
        )?;
        Ok(c.last_insert_rowid())
    })?;

    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    hide_console_tokio(&mut cmd);
    prepare_tree(&mut cmd);

    let cleanup = spec.cleanup_dir.clone();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to start process: {e}");
            if let Some(d) = &cleanup {
                let _ = std::fs::remove_dir_all(d);
            }
            db.with(|c| {
                c.execute(
                    "UPDATE executions SET status = 'error', output = ?2, finished_at = ?3 WHERE id = ?1",
                    rusqlite::params![id, msg, now()],
                )?;
                Ok(())
            })?;
            return Err(AppError::Internal(msg));
        }
    };
    let tree = Tree::attach(&child);

    let (tx, rx) = oneshot::channel::<()>();
    app.state::<ProcessManager>()
        .running
        .lock()
        .map_err(|_| AppError::Internal("process registry poisoned".into()))?
        .insert(id, Running { cancel: tx, tree_id: tree.as_ref().map(Tree::id) });

    let _ = channel.send(ExecEvent::Started { execution_id: id, program: program_str, args: shown_args });

    let app = app.clone();
    let tool_id = spec.tool_id.clone();
    let kind = spec.kind;
    let project_id = spec.project_id;
    tauri::async_runtime::spawn(async move {
        let buf = Arc::new(Mutex::new(OutputBuf { text: String::new(), truncated: false }));
        let t_out = child.stdout.take().map(|s| tauri::async_runtime::spawn(pump(s, false, channel.clone(), buf.clone())));
        let t_err = child.stderr.take().map(|s| tauri::async_runtime::spawn(pump(s, true, channel.clone(), buf.clone())));

        let (status, code) = tokio::select! {
            res = child.wait() => match res {
                Ok(s) if s.success() => ("succeeded", s.code()),
                Ok(s) => ("failed", s.code()),
                Err(_) => ("error", None),
            },
            _ = rx => {
                if let Some(t) = &tree {
                    t.terminate();
                }
                let _ = child.kill().await;
                ("cancelled", None)
            }
        };
        // Descendants may keep the pipes open; do not wait for them forever.
        for t in [t_out, t_err].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
        drop(tree); // Windows: closes the job (kills leftovers). Unix: kills the group.
        if let Some(d) = &cleanup {
            let _ = std::fs::remove_dir_all(d);
        }
        if let Ok(mut m) = app.state::<ProcessManager>().running.lock() {
            m.remove(&id);
        }

        let (text, truncated) = buf.lock().map(|b| (redact::redact_text(&b.text), b.truncated)).unwrap_or_default();
        let db = app.state::<Db>();
        let _ = db.with(|c| {
            c.execute(
                "UPDATE executions SET status = ?2, exit_code = ?3, output = ?4, truncated = ?5, finished_at = ?6 WHERE id = ?1",
                rusqlite::params![id, status, code, text, truncated as i64, now()],
            )?;
            let title = match kind {
                "install" => format!("Install {tool_id}: {status}"),
                _ => format!("Ran {tool_id}: {status}"),
            };
            crate::commands::activity::log(
                c,
                if kind == "install" { "tool_install" } else { "tool_run" },
                &title,
                &code.map(|c| format!("exit code {c}")).unwrap_or_default(),
                Some("tool"),
                Some(&tool_id),
                project_id,
            )?;
            Ok(())
        });
        let _ = channel.send(ExecEvent::Exit { status: status.to_string(), code });
        if let Some(hook) = on_finish {
            hook(&app, status == "succeeded");
        }
    });

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a parent that starts a long-running grandchild, terminate the tree and
    /// verify the grandchild is gone (real processes, no mocks).
    #[tokio::test]
    async fn terminating_a_tree_kills_grandchildren() {
        let marker = format!("cyberhub-tree-{}", std::process::id());
        #[cfg(windows)]
        let mut cmd = {
            // parent cmd.exe starts a child ping that would run ~60 s
            let mut c = tokio::process::Command::new("cmd.exe");
            c.args(["/C", &format!("title {marker} & ping -n 60 127.0.0.1 > NUL")]);
            c
        };
        #[cfg(unix)]
        let mut cmd = {
            let mut c = tokio::process::Command::new("sh");
            c.args(["-c", &format!("sleep 60 & echo {marker}; wait")]);
            c
        };
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        hide_console_tokio(&mut cmd);
        prepare_tree(&mut cmd);
        let mut child = cmd.spawn().expect("spawn");
        let tree = Tree::attach(&child).expect("attach tree");
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(count_descendants(child.id().unwrap()) >= 1, "grandchild should be running");
        let root = child.id().unwrap();
        tree.terminate();
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        tokio::time::sleep(Duration::from_millis(2000)).await;
        assert_eq!(count_descendants(root), 0, "no descendant may survive termination");
        drop(tree);
    }

    /// Count live processes whose parent is `pid` (direct children).
    fn count_descendants(pid: u32) -> usize {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        sys.processes()
            .values()
            .filter(|p| p.parent().map(|pp| pp.as_u32()) == Some(pid))
            .filter(|p| !matches!(p.status(), sysinfo::ProcessStatus::Zombie | sysinfo::ProcessStatus::Dead))
            .count()
    }
}
