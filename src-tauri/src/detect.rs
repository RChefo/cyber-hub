// SPDX-License-Identifier: Apache-2.0
//! Tool detection adapter: PATH lookup, known install locations, dependency checks
//! and (optionally) a version probe using fixed, catalog-defined arguments.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::catalog::{Detect, ToolDef};
use crate::util::{current_os, hide_console_std};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub tool_id: String,
    /// installed | not_installed | dependency_missing | installation_failed | unsupported_os
    pub status: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub missing_dependencies: Vec<String>,
    pub message: Option<String>,
    pub checked_at: String,
}

static GENERIC_VERSION: Lazy<Regex> = Lazy::new(|| Regex::new(r"v?(\d+\.\d+(?:\.\d+)*)").unwrap());

fn expand(template: &str) -> Option<PathBuf> {
    let mut out = template.to_string();
    for var in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA", "APPDATA", "HOME", "USERPROFILE"] {
        let token = format!("{{{var}}}");
        if out.contains(&token) {
            let val = std::env::var(var).ok().or_else(|| {
                if var == "HOME" {
                    std::env::var("USERPROFILE").ok()
                } else {
                    None
                }
            })?;
            out = out.replace(&token, &val);
        }
    }
    Some(PathBuf::from(out))
}

/// PATH entries that are absolute. Relative entries (".", "bin", "") would make lookups
/// depend on the current working directory, which enables binary planting.
fn absolute_path_entries() -> Option<std::ffi::OsString> {
    let path = std::env::var_os("PATH")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&path).filter(|p| p.is_absolute()).collect();
    std::env::join_paths(dirs).ok()
}

pub fn find_binary(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\']) {
        return None; // only bare executable names are resolved through PATH
    }
    let paths = absolute_path_entries()?;
    // `which_in` with an absolute cwd that is never consulted for bare names
    let cwd = std::env::temp_dir();
    which::which_in(name, Some(paths), cwd).ok().filter(|p| p.is_absolute())
}

/// Resolve the executable for a tool (PATH first, then known locations).
pub fn locate(detect: &Detect) -> Option<PathBuf> {
    for b in &detect.binaries {
        if let Some(p) = find_binary(b) {
            return Some(p);
        }
    }
    if let Some(candidates) = detect.paths.get(current_os()) {
        for c in candidates {
            if let Some(p) = expand(c) {
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Run a program with fixed args, capturing combined output with a hard timeout.
pub fn run_capture(program: &Path, args: &[String], timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    hide_console_std(&mut cmd);
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let out_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.by_ref().take(64 * 1024).read_to_end(&mut buf);
        buf
    });
    let err_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.by_ref().take(64 * 1024).read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(40)),
            Err(_) => break,
        }
    }
    let mut text = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).to_string();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&err_t.join().unwrap_or_default()));
    Some(text)
}

fn strip_ansi(s: &str) -> String {
    static ANSI: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x1b\[[0-9;?]*[a-zA-Z]").unwrap());
    ANSI.replace_all(s, "").to_string()
}

pub fn parse_version(output: &str, custom: Option<&str>) -> Option<String> {
    let clean = strip_ansi(output);
    if let Some(r) = custom.and_then(|r| Regex::new(r).ok()) {
        if let Some(c) = r.captures(&clean) {
            return c.get(1).or_else(|| c.get(0)).map(|m| m.as_str().trim().to_string());
        }
    }
    GENERIC_VERSION.captures(&clean).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

pub fn detect_tool(tool: &ToolDef, probe_version: bool) -> Option<Detection> {
    let detect = tool.detect.as_ref()?;
    if tool.kind == "web" || tool.kind == "script" {
        return None;
    }
    let now = crate::util::now();
    if !tool.os.iter().any(|o| o == current_os()) {
        // Still look: users sometimes run tools on unofficial platforms.
        if locate(detect).is_none() {
            return Some(Detection {
                tool_id: tool.id.clone(),
                status: "unsupported_os".into(),
                path: None,
                version: None,
                missing_dependencies: vec![],
                message: Some(format!("{} is not officially supported on {}", tool.name, current_os())),
                checked_at: now,
            });
        }
    }
    let Some(path) = locate(detect) else {
        return Some(Detection {
            tool_id: tool.id.clone(),
            status: "not_installed".into(),
            path: None,
            version: None,
            missing_dependencies: vec![],
            message: None,
            checked_at: now,
        });
    };

    let missing: Vec<String> = tool
        .dependencies
        .iter()
        .filter(|d| !d.optional && !d.binaries.iter().any(|b| find_binary(b).is_some()))
        .map(|d| d.name.clone())
        .collect();

    let is_app_bundle = path.extension().map(|e| e == "app").unwrap_or(false);
    let version = if probe_version && tool.kind == "cli" && !detect.version_args.is_empty() && !is_app_bundle {
        run_capture(&path, &detect.version_args, Duration::from_secs(5))
            .and_then(|out| parse_version(&out, detect.version_regex.as_deref()))
    } else {
        None
    };

    Some(Detection {
        tool_id: tool.id.clone(),
        status: if missing.is_empty() { "installed".into() } else { "dependency_missing".into() },
        path: Some(path.to_string_lossy().to_string()),
        version,
        message: if missing.is_empty() { None } else { Some(format!("Missing: {}", missing.join(", "))) },
        missing_dependencies: missing,
        checked_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("Nmap version 7.95 ( https://nmap.org )", Some(r"Nmap version ([\d.]+)")).as_deref(), Some("7.95"));
        assert_eq!(parse_version("\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.3.2", None).as_deref(), Some("3.3.2"));
        assert_eq!(parse_version("no digits", None), None);
    }

    #[test]
    fn find_binary_ignores_relative_path_entries_and_paths() {
        assert!(find_binary("../evil").is_none());
        assert!(find_binary("C:\\x\\evil.exe").is_none());
        assert!(find_binary("").is_none());
        // a real system binary is still found, as an absolute path
        let probe = if cfg!(windows) { "cmd" } else { "sh" };
        let p = find_binary(probe).expect("system shell on PATH");
        assert!(p.is_absolute());
    }

    #[test]
    fn expands_known_vars() {
        std::env::set_var("LOCALAPPDATA", "C:\\Users\\x\\AppData\\Local");
        assert_eq!(
            expand("{LOCALAPPDATA}\\Programs\\a.exe").unwrap(),
            PathBuf::from("C:\\Users\\x\\AppData\\Local\\Programs\\a.exe")
        );
    }
}
