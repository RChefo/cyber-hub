use crate::error::{validation, AppResult};

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Trim and enforce a maximum length on user-provided text.
pub fn clean(field: &str, value: &str, max: usize, required: bool) -> AppResult<String> {
    let v = value.trim();
    if required && v.is_empty() {
        return Err(validation(format!("{field} is required")));
    }
    if v.chars().count() > max {
        return Err(validation(format!("{field} must be at most {max} characters")));
    }
    if v.contains('\0') {
        return Err(validation(format!("{field} contains invalid characters")));
    }
    Ok(v.to_string())
}

pub fn one_of(field: &str, value: &str, allowed: &[&str]) -> AppResult<String> {
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(validation(format!("{field} must be one of: {}", allowed.join(", "))))
    }
}

/// Validates that a URL is an absolute http(s) URL.
pub fn http_url(field: &str, value: &str) -> AppResult<url::Url> {
    let parsed = url::Url::parse(value.trim()).map_err(|_| validation(format!("{field} is not a valid URL")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(validation(format!("{field} must use http or https"))),
    }
    if parsed.host_str().is_none() {
        return Err(validation(format!("{field} must include a host")));
    }
    Ok(parsed)
}

pub fn current_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Configure a std Command so it never flashes a console window on Windows.
#[allow(unused_variables)]
pub fn hide_console_std(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
}

#[allow(unused_variables)]
pub fn hide_console_tokio(cmd: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
}

/// Absolute path of macOS `open` (never resolved through PATH).
#[allow(dead_code)]
pub const MACOS_OPEN: &str = "/usr/bin/open";

/// Absolute path of Windows PowerShell under %SystemRoot% (never resolved through PATH
/// or the application directory).
#[allow(dead_code)]
pub fn system_powershell() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
    root.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
}

/// The application data folder. Debug builds accept `CYBERHUB_DATA_DIR`, as the MCP sidecar does
/// (`mcp::proto::bridge_dir`), so development and testing never touch the real data; release
/// builds ignore the variable.
pub fn data_dir<R: tauri::Runtime, M: tauri::Manager<R>>(app: &M) -> tauri::Result<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(d) = std::env::var_os("CYBERHUB_DATA_DIR").filter(|d| !d.is_empty()) {
        return Ok(std::path::PathBuf::from(d));
    }
    app.path().app_data_dir()
}
