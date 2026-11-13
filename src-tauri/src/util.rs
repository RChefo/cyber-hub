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
/// and authenticate with the user's credentials (NTLM), so ExploitX refuses these values on
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

fn not_regular() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file (a folder, pipe, device or socket)")
}

/// Opens a file for reading only when it is a regular file (Mission 7). A pipe with no writer would
/// block the open or the read forever, and a device has no end, so folders, pipes, devices and
/// sockets are refused: first by their metadata (a special file is never opened), then on the open
/// file itself, so nothing can be swapped in between. On Unix the open does not block.
pub fn open_regular(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Reads a whole regular file (see `open_regular`) of at most `max` bytes. The read stops after
/// `max + 1` bytes whatever the metadata said, so a file that grows is refused too.
pub fn read_regular(path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_regular(path)?;
    let too_large = || std::io::Error::new(std::io::ErrorKind::InvalidData, format!("the file is larger than {max} bytes"));
    let len = file.metadata()?.len();
    if len > max {
        return Err(too_large());
    }
    let mut buf = Vec::with_capacity(len as usize);
    file.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(too_large());
    }
    Ok(buf)
}

/// One word of a command line that an analyst pastes into a shell (Mission 7): pasted into a POSIX
/// shell or PowerShell, it runs nothing else, and a POSIX shell reads it back as exactly this word.
/// Plain words (ASCII letters, digits and `_ + = : . / -`) stay as they are. A word with a quote
/// (`'`, or one of the typographic quotes U+2018–U+201B that PowerShell also reads as `'`) and
/// nothing else that is special in double quotes is double-quoted, which PowerShell reads back
/// exactly too (Mission 8). Anything else is single-quoted, and a quote inside is written as
/// `'"q"'`: the quoted text ends, the quote follows in double quotes, the quoted text goes on.
/// PowerShell reads such a word as several arguments; only words with a quote and `$`, a
/// backtick, `"`, `\` or `!` still take this form.
pub fn shell_word(a: &str) -> String {
    if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "_+=:./-".contains(c)) {
        return a.to_string();
    }
    // A word with a single quote (`it's`, `' OR 1=1--`) in double quotes, when nothing in it is
    // special there: POSIX shells (bash, zsh, sh, fish) and PowerShell then read it as one word,
    // exactly (Mission 8). Single-quoted text joined around the quote, below, is exact in POSIX
    // shells only, because PowerShell passes adjacent quoted texts as separate arguments.
    if a.chars().any(is_single_quote) && !a.chars().any(|c| matches!(c, '$' | '`' | '"' | '\\' | '!' | '\u{201C}' | '\u{201D}' | '\u{201E}')) {
        return format!("\"{a}\"");
    }
    let mut s = String::with_capacity(a.len() + 2);
    s.push('\'');
    for c in a.chars() {
        if is_single_quote(c) {
            s.push('\'');
            s.push('"');
            s.push(c);
            s.push('"');
            s.push('\'');
        } else {
            s.push(c);
        }
    }
    s.push('\'');
    s
}

/// `'` and the typographic single quotes PowerShell reads as `'` (U+2018–U+201B).
fn is_single_quote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
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

/// Mission 7: special files are refused without blocking; regular files are read within a bound.
#[cfg(test)]
mod special_file_tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cyberhub-special-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs `f` on another thread and fails if it has not finished after 10 seconds (a blocked open
    /// or read of a pipe never finishes).
    #[cfg(unix)]
    fn within_10s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("blocked on a special file")
    }

    #[test]
    fn regular_files_are_read_within_their_bound() {
        let d = tmpdir("regular");
        let f = d.join("a.txt");
        std::fs::write(&f, b"0123456789").unwrap();
        assert_eq!(read_regular(&f, 10).unwrap(), b"0123456789");
        assert!(read_regular(&f, 9).unwrap_err().to_string().contains("larger"));
        assert!(open_regular(&d).is_err(), "a folder is not a regular file");
        assert!(open_regular(&d.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn pipes_and_devices_are_refused_without_blocking() {
        let d = tmpdir("fifo");
        let fifo = d.join("hang.fifo");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
        let f2 = fifo.clone();
        assert!(within_10s(move || open_regular(&f2).is_err()), "a pipe is refused");
        let f3 = fifo.clone();
        assert!(within_10s(move || read_regular(&f3, 1024).is_err()));
        assert!(within_10s(|| read_regular(std::path::Path::new("/dev/zero"), 1024).is_err()), "a device is refused");
        // a folder scan skips the pipe and still reads the regular file next to it
        std::fs::write(d.join("config.env"), b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n").unwrap();
        let root = d.clone();
        let res = within_10s(move || crate::sectools::secrets::scan_path(&root));
        assert_eq!((res.files_scanned, res.files_skipped), (1, 1), "the pipe is skipped");
        let _ = std::fs::remove_dir_all(&d);
    }
}
