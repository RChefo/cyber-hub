//! Redaction of credentials before anything is persisted (run history, command
//! history, activity log, stored process output). Tool-independent and pattern based.
//! Redaction is lossy by design: the original values are never written to disk.

use once_cell::sync::Lazy;
use regex::{Captures, Regex};

pub const MASK: &str = "••••••";

/// Long options whose value is a credential (`--password x`, `--api-key=x`, `-token x`).
static SECRET_OPTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^--?[a-z0-9_-]*(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|cookie|session|auth[-_]?(cred|token|header)?|hashes|aes[-_]?key|private[-_]?key|bearer|credential)s?$").unwrap()
});
/// scheme://user:password@host
static URL_USERINFO: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@").unwrap());
/// Header-style secrets: `Authorization: Bearer x`, `Cookie: a=b`, `X-Api-Key: x`
static HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-apikey|x-api-key|x-auth-token|x-access-token|api-key)(\s*[:=]\s*)([^\r\n]+)").unwrap()
});
/// key=value pairs with secret-looking keys (query strings, form bodies, cookies)
static KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b([a-z0-9_.-]*(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|session(id)?|sid|jwt|auth|credential)[a-z0-9_.-]*)=([^&\s;,]+)").unwrap()
});
/// impacket-style `domain/user:password@target` and `user:password@host`
static USER_PASS_AT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(^|[\s/])([^\s/:@]+):([^\s@]+)@([^\s@]+)").unwrap());
/// JSON Web Tokens
static JWT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap());

/// Redact secrets inside a free-form text (one argument, a command line, or output).
pub fn redact_text(s: &str) -> String {
    let s = URL_USERINFO.replace_all(s, |c: &Captures| format!("{}:{MASK}@", &c[1]));
    let s = HEADER.replace_all(&s, |c: &Captures| format!("{}{}{MASK}", &c[1], &c[2]));
    let s = KV.replace_all(&s, |c: &Captures| format!("{}={MASK}", &c[1]));
    let s = USER_PASS_AT.replace_all(&s, |c: &Captures| {
        // `scheme://…` URLs were handled above; `scheme:` + `//user:pw@host` must not be rewritten here
        if c[3].starts_with("//") {
            return c[0].to_string();
        }
        // e-mail like `user@host` has no `:secret` part and is never matched
        format!("{}{}:{MASK}@{}", &c[1], &c[2], &c[4])
    });
    JWT.replace_all(&s, MASK).into_owned()
}

/// `--password value`, `--api-key="v"`, `-token 'v'` inside a free-form command line.
static OPTION_IN_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)((?:^|\s)--?[a-z0-9_-]*(?:pass(?:word|wd)?|pwd|secret|token|api[-_]?key|apikey|cookie|session|hashes|aes[-_]?key|bearer|credential)s?)(=|\s+)("[^"]*"|'[^']*'|\S+)"#).unwrap()
});

/// Redact a free-form command line (as copied from builders, templates or typed by hand).
pub fn redact_command_line(s: &str) -> String {
    let s = OPTION_IN_LINE.replace_all(s, |c: &Captures| format!("{}{}{MASK}", &c[1], &c[2]));
    redact_text(&s)
}

/// Redact an argv vector: secret options (separate or `=` form) and secrets inside values.
pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for a in args {
        if mask_next {
            out.push(MASK.to_string());
            mask_next = false;
            continue;
        }
        if a.starts_with('-') {
            if let Some((name, _)) = a.split_once('=') {
                if SECRET_OPTION.is_match(name) {
                    out.push(format!("{name}={MASK}"));
                    continue;
                }
            } else if SECRET_OPTION.is_match(a) {
                out.push(a.clone());
                mask_next = true;
                continue;
            }
        }
        out.push(redact_text(a));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redacts_secret_options() {
        let r = redact_args(&v(&["--password", "hunter2", "--api-key=abc", "-token", "t0k", "--cookie=sid=1", "-p", "80"]));
        assert_eq!(r, v(&["--password", MASK, &format!("--api-key={MASK}"), "-token", MASK, &format!("--cookie={MASK}"), "-p", "80"]));
    }

    #[test]
    fn redacts_values_inside_arguments() {
        let r = redact_args(&v(&[
            "https://admin:S3cret@app.example.com/x",
            "Authorization: Bearer abc.def",
            "user=bob&password=hunter2&next=/",
            "corp/alice:Passw0rd!@10.0.0.5",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig",
        ]));
        assert_eq!(r[0], format!("https://admin:{MASK}@app.example.com/x"));
        assert_eq!(r[1], format!("Authorization: {MASK}"));
        assert_eq!(r[2], format!("user=bob&password={MASK}&next=/"));
        assert_eq!(r[3], format!("corp/alice:{MASK}@10.0.0.5"));
        assert_eq!(r[4], MASK);
    }

    #[test]
    fn leaves_ordinary_arguments_alone() {
        let a = v(&["-sV", "-p", "22,80", "10.0.0.5", "user@example.com", "https://app.example.com/a?page=2", "-oN", "scan.txt"]);
        assert_eq!(redact_args(&a), a);
    }

    #[test]
    fn redacts_command_lines() {
        let line = r#"sqlmap -u 'https://a.example.com/?id=1' --cookie="PHPSESSID=abc" --password hunter2 -H "Authorization: Bearer xyz""#;
        let r = redact_command_line(line);
        assert!(!r.contains("abc") && !r.contains("hunter2") && !r.contains("xyz"), "{r}");
        assert!(r.contains("https://a.example.com/?id=1"), "{r}");
        assert_eq!(redact_command_line("nmap -sV -p 22,80 10.0.0.5"), "nmap -sV -p 22,80 10.0.0.5");
    }

    #[test]
    fn redacts_text_blocks() {
        let t = redact_text("GET / HTTP/1.1\nCookie: session=abc\nX-Api-Key: zzz\n");
        assert!(!t.contains("abc") && !t.contains("zzz"), "{t}");
    }
}
