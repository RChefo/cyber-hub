//! Secrets scanner: finds credentials in pasted text or in local files and folders chosen with a
//! native dialog. Runs locally; matches are returned masked (the full value is never returned to
//! the web view or stored).

use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

struct Rule {
    id: &'static str,
    label: &'static str,
    re: Regex,
    /// capture group holding the secret (0 = whole match)
    group: usize,
    /// minimum Shannon entropy (bits per character) of the secret, for generic rules
    min_entropy: f64,
}

fn rule(id: &'static str, label: &'static str, re: &str, group: usize, min_entropy: f64) -> Rule {
    Rule { id, label, re: Regex::new(re).expect("valid secret rule"), group, min_entropy }
}

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        rule("private_key", "Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", 0, 0.0),
        rule("aws_access_key", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, 0.0),
        rule("aws_secret_key", "AWS secret access key", r#"(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#, 1, 3.5),
        rule("github_token", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 0, 0.0),
        rule("gitlab_token", "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", 0, 0.0),
        rule("slack_token", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 0, 0.0),
        rule("slack_webhook", "Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", 0, 0.0),
        rule("stripe_key", "Stripe secret key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", 0, 0.0),
        rule("google_api_key", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0, 0.0),
        rule("anthropic_key", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 0, 0.0),
        rule("openai_key", "OpenAI API key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b", 0, 0.0),
        rule("sendgrid_key", "SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0, 0.0),
        rule("twilio_key", "Twilio API key", r"\bSK[0-9a-f]{32}\b", 0, 0.0),
        rule("jwt", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0, 0.0),
        rule("url_credentials", "Credentials in a URL", r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+", 1, 0.0),
        rule(
            "generic_secret",
            "Password or secret assignment",
            r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,200})["']"#,
            1,
            3.0,
        ),
    ]
});

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// First four and last two characters, the rest hidden.
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len());
    }
    format!("{}{}{}", chars[..4].iter().collect::<String>(), "•".repeat((chars.len() - 6).min(12)), chars[chars.len() - 2..].iter().collect::<String>())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub rule: &'static str,
    pub label: &'static str,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub masked: String,
}

pub fn scan_text(file: &str, text: &str, out: &mut Vec<Hit>, limit: usize) {
    for (n, line) in text.lines().enumerate() {
        if line.len() > 20_000 {
            continue; // minified or binary-like lines
        }
        for r in RULES.iter() {
            for caps in r.re.captures_iter(line) {
                let Some(m) = caps.get(r.group) else { continue };
                let secret = m.as_str();
                if r.min_entropy > 0.0 && entropy(secret) < r.min_entropy {
                    continue;
                }
                // obvious placeholders
                let lower = secret.to_ascii_lowercase();
                if ["example", "changeme", "placeholder", "your_", "xxxxxxxx", "<", "${", "{{"].iter().any(|p| lower.contains(p)) {
                    continue;
                }
                if out.len() >= limit {
                    return;
                }
                out.push(Hit { rule: r.id, label: r.label, file: file.to_string(), line: n + 1, column: m.start() + 1, masked: mask(secret) });
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub hits: Vec<Hit>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// limits reached (files or findings); the scan stopped early
    pub truncated: bool,
}

pub const MAX_FILES: usize = 20_000;
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_HITS: usize = 5_000;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "venv", "__pycache__", ".idea", ".gradle"];

/// Scans a file or a folder tree (symbolic links are not followed).
pub fn scan_path(root: &Path) -> ScanResult {
    let mut res = ScanResult::default();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if p != root && p.file_name().is_some_and(|n| SKIP_DIRS.contains(&n.to_string_lossy().as_ref())) {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&p) {
                let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                stack.extend(entries.into_iter().rev());
            }
            continue;
        }
        if res.files_scanned >= MAX_FILES || res.hits.len() >= MAX_HITS {
            res.truncated = true;
            break;
        }
        if meta.len() > MAX_FILE_BYTES {
            res.files_skipped += 1;
            continue;
        }
        // a pipe or device in the tree is skipped, never read (Mission 7)
        let Ok(bytes) = crate::util::read_regular(&p, MAX_FILE_BYTES) else {
            res.files_skipped += 1;
            continue;
        };
        if bytes.iter().take(8192).any(|b| *b == 0) {
            res.files_skipped += 1; // binary
            continue;
        }
        res.files_scanned += 1;
        let shown = p.strip_prefix(root).ok().filter(|r| !r.as_os_str().is_empty()).unwrap_or(&p).to_string_lossy().to_string();
        scan_text(&shown, &String::from_utf8_lossy(&bytes), &mut res.hits, MAX_HITS);
    }
    if res.hits.len() >= MAX_HITS {
        res.truncated = true;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Vec<Hit> {
        let mut out = vec![];
        scan_text("t", text, &mut out, 100);
        out
    }

    #[test]
    fn common_secrets_are_found_and_masked() {
        let text = [
            concat!("aws_access_key_id = AKIA", "IOSFODNN7ABCDEFG"),
            concat!("token: gh", "p_1234567890abcdefghijABCDEFGHIJ123456"),
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "db = \"postgres://app:S3cr3tPassw0rd@db.internal:5432/app\"",
            "password = \"Tr0ub4dor&3xK9#q\"",
            concat!("key = AI", "zaSyA1234567890abcdefghijklmnopqrstuv"),
        ]
        .join("\n");
        let hits = scan(&text);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule).collect();
        for r in ["aws_access_key", "github_token", "private_key", "url_credentials", "generic_secret", "google_api_key"] {
            assert!(rules.contains(&r), "{r} missing: {rules:?}");
        }
        assert!(hits.iter().all(|h| !h.masked.contains("S3cr3tPassw0rd") && !h.masked.contains("1234567890abcdef")), "values are masked");
        assert_eq!(hits.iter().find(|h| h.rule == "github_token").unwrap().line, 2);
    }

    #[test]
    fn placeholders_and_low_entropy_values_are_ignored() {
        assert!(scan("password = \"changeme123\"").is_empty());
        assert!(scan("password = \"aaaaaaaaaaaa\"").is_empty(), "low entropy");
        assert!(scan("api_key: \"${API_KEY}\"").is_empty());
        assert!(scan("The password must be at least 8 characters").is_empty());
        assert_eq!(mask("abcdefghijklmnop"), "abcd••••••••••op");
        assert_eq!(mask("short"), "•••••");
        assert!(entropy("aaaa") < 0.1 && entropy("aB3$xY9!") > 2.5);
    }

    #[test]
    fn folders_are_scanned_with_limits() {
        let dir = std::env::temp_dir().join(format!("cyberhub-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        let line = concat!("const k = 'xo", "xb-1234567890-abcdefghij';\n");
        std::fs::write(dir.join("src/config.js"), line).unwrap();
        std::fs::write(dir.join("node_modules/dep.js"), line).unwrap();
        std::fs::write(dir.join("image.bin"), [0u8, 1, 2, 3]).unwrap();
        let r = scan_path(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r.hits.len(), 1, "dependency folders are skipped: {r:?}");
        assert!(r.hits[0].file.ends_with("config.js"));
        assert_eq!((r.files_scanned, r.files_skipped), (1, 1));
    }
}
