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

/// Whether a value is a network (UNC) or device path for Windows: two leading separators of either
/// kind (`\\host\share`, `//host/share`, `\\?\UNC\…`, `\\.\pipe\…`), or an NT object path
/// (`\??\…`). Touching such a path, even reading its metadata, makes Windows connect to the host
/// and authenticate with the user's credentials (NTLM), so Cyber Hub refuses these values on
/// Windows before any file-system call (Mission 7).
pub fn is_network_or_device_path(value: &str) -> bool {
    let v = value.trim_start().as_bytes();
    let sep = |c: u8| c == b'\\' || c == b'/';
    (v.len() >= 2 && sep(v[0]) && sep(v[1])) || v.starts_with(b"\\??\\")
}

/// Unicode format characters (general category Cf, Unicode 15.1): bidirectional overrides and
/// isolates, zero-width characters, the soft hyphen and other invisible marks.
const FORMAT_CHARS: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether a character can disguise text where a person reads it to decide (a native
/// confirmation, an approval): a control character, a format character (bidi overrides,
/// zero-width characters), a line or paragraph separator (U+2028, U+2029), or a blank-looking
/// filler (Braille blank, Hangul fillers). Mission 7.
pub fn is_deceptive_char(c: char) -> bool {
    let u = c as u32;
    c.is_control() || matches!(u, 0x2028 | 0x2029 | 0x2800 | 0x115F | 0x1160 | 0x3164 | 0xFFA0) || FORMAT_CHARS.iter().any(|(lo, hi)| (*lo..=*hi).contains(&u))
}

/// Text as a native dialog shows it: line breaks stay, every other character that could disguise
/// it is shown as its code point (`<U+202E>`), so nothing in a value can reorder, hide or add lines
/// to the text around it.
pub fn dialog_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c != '\n' && is_deceptive_char(c) {
            out.push_str(&format!("<U+{:04X}>", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Every raw HTML or image that a CommonMark parser (pulldown-cmark) finds in `md`: the tests of
/// the Markdown reports check that collected or imported text never becomes markup (Mission 7).
#[cfg(test)]
pub fn commonmark_markup(md: &str) -> Vec<String> {
    use pulldown_cmark::{Event, Parser, Tag};
    Parser::new(md)
        .filter_map(|e| match e {
            Event::Html(h) | Event::InlineHtml(h) => Some(format!("html {h}")),
            Event::Start(Tag::Image { dest_url, .. }) => Some(format!("image {dest_url}")),
            _ => None,
        })
        .collect()
}
