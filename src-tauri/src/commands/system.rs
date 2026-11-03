//! System information, terminal integration and OS-keychain secret storage.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::db::Db;
use crate::detect::find_binary;
use crate::error::{validation, AppError, AppResult};
use crate::process::ProcessManager;
use crate::util::current_os;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub os: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub arch: String,
    pub cpu_brand: String,
    pub cpu_cores: usize,
    pub total_memory: u64,
    pub used_memory: u64,
    pub uptime_secs: u64,
    pub app_version: String,
    pub data_dir: String,
    pub db_schema_version: i64,
    pub running_processes: usize,
}

#[tauri::command]
pub async fn system_info(app: AppHandle, db: State<'_, Db>, pm: State<'_, ProcessManager>) -> AppResult<SystemInfo> {
    let (cpu_brand, cpu_cores, total, used) = tauri::async_runtime::spawn_blocking(|| {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        sys.refresh_cpu_all();
        let brand = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
        (brand, sys.cpus().len(), sys.total_memory(), sys.used_memory())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let data_dir = app.path().app_data_dir()?.to_string_lossy().to_string();
    Ok(SystemInfo {
        os: current_os().into(),
        os_name: sysinfo::System::name().unwrap_or_default(),
        os_version: sysinfo::System::os_version().unwrap_or_default(),
        kernel_version: sysinfo::System::kernel_version().unwrap_or_default(),
        hostname: sysinfo::System::host_name().unwrap_or_default(),
        arch: std::env::consts::ARCH.into(),
        cpu_brand,
        cpu_cores,
        total_memory: total,
        used_memory: used,
        uptime_secs: sysinfo::System::uptime(),
        app_version: app.package_info().version.to_string(),
        data_dir,
        db_schema_version: db.schema_version()?,
        running_processes: pm.running_ids().len(),
    })
}

/// Opens a new system terminal window (optionally in a directory). No command is
/// passed to the terminal: the UI copies commands to the clipboard instead, so
/// nothing runs without the user pressing Enter.
#[tauri::command]
pub async fn open_terminal(cwd: Option<String>) -> AppResult<String> {
    let dir = match cwd.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => {
            let p = PathBuf::from(d);
            if !p.is_dir() {
                return Err(validation("Directory does not exist"));
            }
            p
        }
        _ => dirs_home().unwrap_or_else(|| PathBuf::from(".")),
    };

    let spawn = |mut cmd: Command| -> std::io::Result<()> {
        cmd.current_dir(&dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().map(|_| ())
    };

    match current_os() {
        "windows" => {
            if let Some(wt) = find_binary("wt") {
                let mut c = Command::new(wt);
                c.arg("-d").arg(&dir);
                if spawn(c).is_ok() {
                    return Ok("Windows Terminal".into());
                }
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let mut c = Command::new(crate::util::system_powershell());
                c.arg("-NoLogo").creation_flags(0x0000_0010); // CREATE_NEW_CONSOLE
                c.current_dir(&dir);
                c.spawn().map_err(|e| AppError::Internal(format!("Could not open a terminal: {e}")))?;
                return Ok("PowerShell".into());
            }
            #[allow(unreachable_code)]
            Err(AppError::Internal("Could not open a terminal".into()))
        }
        "macos" => {
            let mut c = Command::new(crate::util::MACOS_OPEN);
            c.arg("-a").arg("Terminal").arg(&dir);
            spawn(c).map_err(|e| AppError::Internal(format!("Could not open Terminal.app: {e}")))?;
            Ok("Terminal".into())
        }
        _ => {
            for term in ["x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "kitty", "alacritty", "xterm"] {
                if let Some(p) = find_binary(term) {
                    if spawn(Command::new(p)).is_ok() {
                        return Ok(term.into());
                    }
                }
            }
            Err(AppError::Internal("No supported terminal emulator found".into()))
        }
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/* ─────────────── secrets (OS keychain) ─────────────── */

const SERVICE: &str = "dev.cyberhub.workstation";
/// Every secret Cyber Hub may store (used by backend code).
const KNOWN_SECRETS: &[&str] = &["nvd_api_key", crate::commands::virustotal::KEY_NAME];
/// Secrets the generic UI commands may set / check / delete. The VirusTotal key is managed
/// only through `vt_key_set` (verifies before storing) and `vt_key_delete`.
const UI_SECRETS: &[&str] = &["nvd_api_key"];

fn entry(name: &str) -> AppResult<keyring::Entry> {
    if !KNOWN_SECRETS.contains(&name) {
        return Err(validation("Unknown secret name"));
    }
    keyring::Entry::new(SERVICE, name).map_err(|e| AppError::Secret(e.to_string()))
}

fn ui_entry(name: &str) -> AppResult<keyring::Entry> {
    if !UI_SECRETS.contains(&name) {
        return Err(validation("Unknown secret name"));
    }
    entry(name)
}

/// Backend-only read. Secret values are never returned to the web view.
pub fn read_secret(name: &str) -> Option<String> {
    entry(name).ok()?.get_password().ok().filter(|v| !v.is_empty())
}

pub fn store_secret(name: &str, value: &str) -> AppResult<()> {
    entry(name)?.set_password(value).map_err(|e| AppError::Secret(e.to_string()))
}

pub fn delete_secret(name: &str) -> AppResult<()> {
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Secret(e.to_string())),
    }
}

/// Secrets are write-only from the frontend: values are never returned.
#[tauri::command]
pub async fn secret_set(name: String, value: String) -> AppResult<()> {
    let v = value.trim();
    if v.is_empty() || v.len() > 512 {
        return Err(validation("Secret must be 1-512 characters"));
    }
    ui_entry(&name)?.set_password(v).map_err(|e| AppError::Secret(e.to_string()))
}

#[tauri::command]
pub async fn secret_exists(name: String) -> AppResult<bool> {
    match ui_entry(&name)?.get_password() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(AppError::Secret(e.to_string())),
    }
}

#[tauri::command]
pub async fn secret_delete(name: String) -> AppResult<()> {
    ui_entry(&name)?;
    delete_secret(&name)
}
