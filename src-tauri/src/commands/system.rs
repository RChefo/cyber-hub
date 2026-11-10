//! System information, terminal integration and OS-keychain secret storage.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;
use tauri::{AppHandle, State};

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
    let data_dir = crate::util::data_dir(&app)?.to_string_lossy().to_string();
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
//
// Provider credentials are provisioned by the application owner with the developer-only
// `cyberhub-keys` tool (see docs/PROVISIONING.md). The app itself only reads them, inside
// the Rust functions that call a provider. No IPC command can read or list a credential, or
// pass one in; the web view only learns whether a service is configured.
//
// TAXII servers (Mission 6) are the analyst's own, so the app can also store their credential:
// the analyst types it into a native OS dialog (`native_prompt`), never into the web view, and
// `store_taxii_secret` writes it to the credential store. Provider keys stay provisioning-only.

pub const SERVICE: &str = "dev.cyberhub.workstation";
pub const NVD_KEY: &str = "nvd_api_key";
/// Every credential Cyber Hub may use.
pub const KNOWN_SECRETS: &[&str] = &[NVD_KEY, "virustotal_api_key", "abuseipdb_api_key", "otx_api_key", "abusech_auth_key", "shodan_api_key", crate::commands::assistant::ANTHROPIC_KEY];

/// A TAXII server's credential: `taxii_<server id>`.
pub fn is_taxii_secret(name: &str) -> bool {
    name.strip_prefix("taxii_").is_some_and(|id| !id.is_empty() && id.len() <= 18 && id.bytes().all(|b| b.is_ascii_digit()))
}

fn entry(name: &str) -> AppResult<keyring::Entry> {
    if !KNOWN_SECRETS.contains(&name) && !is_taxii_secret(name) {
        return Err(validation("Unknown secret name"));
    }
    keyring::Entry::new(SERVICE, name).map_err(|e| AppError::Secret(e.to_string()))
}

/// Backend-only read. Secret values are never returned to the web view.
pub fn read_secret(name: &str) -> Option<String> {
    entry(name).ok()?.get_password().ok().filter(|v| !v.is_empty())
}

/// Whether a credential is present (never its value).
pub fn secret_configured(name: &str) -> bool {
    read_secret(name).is_some()
}

/// Stores a TAXII server's credential (typed into a native dialog). Only `taxii_<id>` names.
pub fn store_taxii_secret(server_id: i64, value: &str) -> AppResult<()> {
    let name = crate::ti::taxii::secret_name(server_id);
    if !is_taxii_secret(&name) {
        return Err(validation("Unknown secret name"));
    }
    entry(&name)?.set_password(value).map_err(|e| AppError::Secret(e.to_string()))
}

/// Deletes a TAXII server's credential; nothing stored is not an error.
pub fn delete_taxii_secret(server_id: i64) -> AppResult<()> {
    let name = crate::ti::taxii::secret_name(server_id);
    if !is_taxii_secret(&name) {
        return Err(validation("Unknown secret name"));
    }
    match entry(&name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Secret(e.to_string())),
    }
}

/// Write a credential. Only compiled into the developer provisioning tool.
#[cfg(feature = "provisioning")]
pub fn store_secret(name: &str, value: &str) -> AppResult<()> {
    entry(name)?.set_password(value).map_err(|e| AppError::Secret(e.to_string()))
}

/// Delete a credential. Only compiled into the developer provisioning tool.
#[cfg(feature = "provisioning")]
pub fn delete_secret(name: &str) -> AppResult<()> {
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Secret(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    /// Guard: the web view must not be able to read, list, set, test or delete credentials.
    /// Fails if such a command is ever registered in the IPC handler list again.
    #[test]
    fn no_credential_commands_are_exposed_over_ipc() {
        let lib = include_str!("../lib.rs");
        let start = lib.find("generate_handler![").expect("handler list");
        let handlers = &lib[start..start + lib[start..].find("])").expect("end of handler list")];
        let names: Vec<&str> = handlers.lines().map(str::trim).filter(|l| l.contains("::")).collect();
        assert!(names.len() > 50, "handler list parsed");
        for name in names {
            let n = name.to_ascii_lowercase();
            for banned in ["secret", "_key_set", "_key_test", "_key_delete", "credential", "provision", "keychain"] {
                assert!(!n.contains(banned), "credential command exposed over IPC: {name}");
            }
        }
        // the only credential-related information the UI gets is "configured or not"
        assert!(handlers.contains("vt_key_status") && handlers.contains("ti_providers"));
    }

    /// Mission 6: the only commands that store or delete a credential are the TAXII ones, and they
    /// take no credential: the value is typed into a native dialog and never crosses the IPC
    /// boundary, in either direction.
    #[test]
    fn taxii_credentials_are_typed_into_a_native_dialog_never_passed_in() {
        let src = include_str!("taxii.rs");
        for (name, signature) in [
            ("taxii_auth_prompt", "pub async fn taxii_auth_prompt(app: AppHandle, id: i64) -> AppResult<bool>"),
            ("taxii_auth_forget", "pub async fn taxii_auth_forget(app: AppHandle, id: i64) -> AppResult<bool>"),
        ] {
            assert!(src.contains(signature), "{name} keeps its signature: an id in, a yes or no out");
        }
        // only those two commands write or delete one
        for (fun, calls) in [("store_taxii_secret(", 1), ("delete_taxii_secret(", 1)] {
            assert_eq!(src.matches(fun).count(), calls, "{fun} in taxii.rs");
            for other in [include_str!("threat_intel.rs"), include_str!("intel.rs"), include_str!("projects.rs"), include_str!("workspace.rs")] {
                assert!(!other.contains(fun), "{fun} called elsewhere");
            }
        }
    }

    #[test]
    fn unknown_secret_names_are_refused() {
        assert!(super::read_secret("not_a_known_secret").is_none());
        assert!(super::is_taxii_secret("taxii_12") && !super::is_taxii_secret("taxii_") && !super::is_taxii_secret("taxii_1x") && !super::is_taxii_secret("taxii_../a"));
    }
}
