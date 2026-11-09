//! Log triage (docs/UTILITIES.md): web server access logs (Apache and Nginx, combined or common
//! format) and OpenSSH authentication logs are read on this device and searched for attacks,
//! scans and password guessing. Nothing is contacted.
//!
//! Detections describe what was *attempted*; a matched request is not proof of a compromise. A
//! sensitive file that was answered with 200, or a login that succeeded after many failures, is
//! rated higher because it suggests success. Example lines go through the credential redaction
//! used for tool output.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::BufRead;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_TEXT: usize = 20 * 1024 * 1024;
const MAX_LINES: u64 = 10_000_000;
const MAX_LINE: usize = 65_536;
const MAX_CLIENTS: usize = 500_000;

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub ip: String,
    pub count: u64,
    /// up to three example lines, redacted
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub remediation: String,
    pub count: u64,
    /// the clients behind it, most active first (at most 20)
    pub sources: Vec<Source>,
    /// the MITRE ATT&CK technique ("T1070.001 Indicator Removal: Clear Windows Event Logs"), when one fits
    #[serde(skip_serializing_if = "String::is_empty")]
    pub technique: String,
}

/// How often an event ID occurs in a Windows event log.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventCount {
    pub id: u32,
    pub channel: String,
    /// what the event means, for well-known IDs
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub ip: String,
    pub requests: u64,
    pub client_errors: u64,
    pub server_errors: u64,
    pub ssh_failures: u64,
    pub ssh_logins: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// web, ssh, mixed or unknown
    pub kind: String,
    pub lines: u64,
    /// lines in a recognised format
    pub recognised: u64,
    pub first: String,
    pub last: String,
    pub clients: Vec<Client>,
    pub detections: Vec<Detection>,
    pub warnings: Vec<String>,
    /// Windows event logs: the most frequent event IDs
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventCount>,
    /// Windows event logs: the computers that wrote the events
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub computers: Vec<String>,
}

static WEB: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?"#).expect("valid pattern"));
static SSH_FAILED: Lazy<Regex> = Lazy::new(|| Regex::new(r"sshd\[\d+\]: Failed (\S+) for (invalid user )?(\S*) from (\S+)").expect("valid pattern"));
static SSH_INVALID: Lazy<Regex> = Lazy::new(|| Regex::new(r"sshd\[\d+\]: Invalid user (\S*) from (\S+)").expect("valid pattern"));
static SSH_ACCEPTED: Lazy<Regex> = Lazy::new(|| Regex::new(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+)").expect("valid pattern"));
static SYSLOG_TIME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)").expect("valid pattern"));

struct Pattern {
    rule: &'static str,
    severity: &'static str,
    title: &'static str,
    detail: &'static str,
    remediation: &'static str,
    re: Regex,
}

fn pattern(rule: &'static str, severity: &'static str, title: &'static str, detail: &'static str, remediation: &'static str, re: &str) -> Pattern {
    Pattern { rule, severity, title, detail, remediation, re: Regex::new(re).expect("valid pattern") }
}

/// Patterns matched against the decoded request (method, path and query), lower case.
static REQUEST_PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        pattern("WEB-LOG4SHELL", "high", "Log4Shell attempts", "Requests carried a ${jndi:…} lookup, which vulnerable Log4j versions execute.", "Upgrade Log4j to 2.17.1 or later on every Java service, and check outbound LDAP and DNS traffic from the servers at those times.", r"\$\{(jndi|\$\{[^}]*\}j)"),
        pattern("WEB-SQLI", "medium", "SQL injection attempts", "Requests contained SQL injection payloads.", "Check that every query uses bound parameters, and look for database errors or unusual response sizes at those times.", r"(union(\s|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|sleep\(\s*\d+\s*\)|benchmark\(|waitfor\s+delay|information_schema|extractvalue\(|updatexml\(|load_file\()"),
        pattern("WEB-XSS", "medium", "Cross-site scripting attempts", "Requests contained script payloads.", "Check that the application encodes output and sends a restrictive Content-Security-Policy.", r#"(<script|javascript:|onerror\s*=|onload\s*=|<svg[\s/>]|document\.cookie|alert\()"#),
        pattern("WEB-TRAVERSAL", "medium", "Path traversal attempts", "Requests tried to climb out of the web root or read system files.", "Check that file paths from requests are resolved and confined to their directory.", r#"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self/)"#),
        pattern("WEB-COMMAND-INJECTION", "medium", "Command injection attempts", "Requests contained shell commands.", "Check that no request data reaches a shell, and look for unexpected processes or downloads on the servers.", r"([;|`]\s*(wget|curl|nc|ncat|bash|sh|python|perl)\b|\$\((wget|curl|id|whoami|cat)\b|/bin/(ba)?sh\b|cmd\.exe|powershell)"),
    ]
});

const SCANNERS: &[&str] = &["sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "gobuster", "dirbuster", "feroxbuster", "ffuf", "wpscan", "acunetix", "nessus", "openvas", "wfuzz", "hydra", "whatweb", "joomscan", "commix", "dirsearch", "netsparker", "qualys"];

static SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(/\.git(/|$)|/\.env(\.|$)|/\.svn/|/\.aws/|/\.ssh/|wp-config\.php|phpinfo\.php|/server-status|/actuator(/|$)|/\.ds_store|id_rsa|\.(sql|bak|old|swp)$|/phpmyadmin|/adminer|/\.htpasswd|/config\.json$|/web\.config$)").expect("valid pattern")
});

/// %XX sequences decoded byte by byte (invalid ones kept), "+" read as a space.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Default)]
struct Hits {
    count: u64,
    by_ip: HashMap<String, (u64, Vec<String>)>,
}

impl Hits {
    fn add(&mut self, ip: &str, line: &str) {
        self.count += 1;
        let e = self.by_ip.entry(ip.to_string()).or_default();
        e.0 += 1;
        if e.1.len() < 3 {
            e.1.push(crate::redact::redact_text(&line.chars().take(300).collect::<String>()));
        }
    }

    fn sources(&self) -> Vec<Source> {
        let mut v: Vec<Source> = self.by_ip.iter().map(|(ip, (count, ex))| Source { ip: ip.clone(), count: *count, examples: ex.clone() }).collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.ip.cmp(&b.ip)));
        v.truncate(20);
        v
    }
}

#[derive(Default)]
struct Acc {
    report: Report,
    web: u64,
    ssh: u64,
    clients: HashMap<String, Client>,
    hits: BTreeMap<&'static str, Hits>,
    sensitive_served: Hits,
    sensitive_probed: Hits,
    scanners: Hits,
    shellshock: Hits,
    login_failures: HashMap<String, u64>,
    not_found: HashMap<String, u64>,
    ssh_fail: HashMap<String, (u64, Vec<String>)>,
    ssh_invalid_users: BTreeSet<String>,
    ssh_after_failures: Hits,
    ssh_root: Hits,
    ssh_password: Hits,
    capped: bool,
}

impl Acc {
    fn client(&mut self, ip: &str) -> Option<&mut Client> {
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(ip) {
            self.capped = true;
            return None;
        }
        Some(self.clients.entry(ip.to_string()).or_insert_with(|| Client { ip: ip.to_string(), ..Default::default() }))
    }

    fn line(&mut self, line: &str) {
        self.report.lines += 1;
        if let Some(c) = WEB.captures(line) {
            self.web += 1;
            self.report.recognised += 1;
            let ip = c[1].to_string();
            let time = c[2].to_string();
            if self.report.first.is_empty() {
                self.report.first = time.clone();
            }
            self.report.last = time;
            let request = &c[3];
            let status: u16 = c[4].parse().unwrap_or(0);
            let referrer = c.get(6).map(|m| m.as_str()).unwrap_or("");
            let ua = c.get(7).map(|m| m.as_str()).unwrap_or("");
            if let Some(cl) = self.client(&ip) {
                cl.requests += 1;
                if (400..500).contains(&status) {
                    cl.client_errors += 1;
                }
                if status >= 500 {
                    cl.server_errors += 1;
                }
            }
            let decoded = percent_decode(&percent_decode(request)).to_ascii_lowercase();
            let haystack = format!("{decoded} {} {}", referrer.to_ascii_lowercase(), ua.to_ascii_lowercase());
            for p in REQUEST_PATTERNS.iter() {
                let target = if p.rule == "WEB-LOG4SHELL" { &haystack } else { &decoded };
                if p.re.is_match(target) {
                    self.hits.entry(p.rule).or_default().add(&ip, line);
                }
            }
            if ua.trim_start().starts_with("() {") || referrer.trim_start().starts_with("() {") {
                self.shellshock.add(&ip, line);
            }
            let lua = ua.to_ascii_lowercase();
            if SCANNERS.iter().any(|s| lua.contains(s)) {
                self.scanners.add(&ip, line);
            }
            let path = decoded.split_whitespace().nth(1).unwrap_or("").split('?').next().unwrap_or("").to_string();
            if SENSITIVE.is_match(&path) {
                if status == 200 {
                    self.sensitive_served.add(&ip, line);
                } else {
                    self.sensitive_probed.add(&ip, line);
                }
            }
            if status == 404 {
                *self.not_found.entry(ip.clone()).or_default() += 1;
            }
            let login = path.contains("login") || path.contains("signin") || path.contains("wp-login") || path.contains("/auth") || path.contains("xmlrpc.php");
            if status == 401 || (login && decoded.starts_with("post") && matches!(status, 200 | 302 | 403)) {
                *self.login_failures.entry(ip).or_default() += 1;
            }
            return;
        }
        let time = SYSLOG_TIME.captures(line).map(|c| c[1].to_string());
        if let Some(c) = SSH_FAILED.captures(line) {
            self.ssh_line(time);
            let ip = c[4].to_string();
            if c.get(2).is_some() {
                self.ssh_invalid_users.insert(c[3].to_string());
            }
            if let Some(cl) = self.client(&ip) {
                cl.ssh_failures += 1;
            }
            let e = self.ssh_fail.entry(ip).or_default();
            e.0 += 1;
            if e.1.len() < 3 {
                e.1.push(crate::redact::redact_text(&line.chars().take(300).collect::<String>()));
            }
        } else if let Some(c) = SSH_INVALID.captures(line) {
            self.ssh_line(time);
            self.ssh_invalid_users.insert(c[1].to_string());
        } else if let Some(c) = SSH_ACCEPTED.captures(line) {
            self.ssh_line(time);
            let (method, user, ip) = (c[1].to_string(), c[2].to_string(), c[3].to_string());
            if let Some(cl) = self.client(&ip) {
                cl.ssh_logins += 1;
            }
            if self.ssh_fail.get(&ip).is_some_and(|f| f.0 >= 5) {
                self.ssh_after_failures.add(&ip, line);
            }
            if user == "root" {
                self.ssh_root.add(&ip, line);
            }
            if method == "password" || method.starts_with("keyboard-interactive") {
                self.ssh_password.add(&ip, line);
            }
        }
    }

    fn ssh_line(&mut self, time: Option<String>) {
        self.ssh += 1;
        self.report.recognised += 1;
        if let Some(t) = time {
            if self.report.first.is_empty() {
                self.report.first = t.clone();
            }
            self.report.last = t;
        }
    }

    fn finish(mut self) -> Report {
        let mut r = std::mem::take(&mut self.report);
        r.kind = match (self.web > 0, self.ssh > 0) {
            (true, true) => "mixed",
            (true, false) => "web",
            (false, true) => "ssh",
            _ => "unknown",
        }
        .into();
        let mut out: Vec<Detection> = Vec::new();
        let mut push = |rule: &str, severity: &str, title: &str, detail: String, remediation: &str, hits: &Hits| {
            if hits.count > 0 {
                out.push(Detection { rule: rule.into(), severity: severity.into(), title: title.into(), detail, remediation: remediation.into(), count: hits.count, sources: hits.sources(), technique: String::new() });
            }
        };
        for p in REQUEST_PATTERNS.iter() {
            if let Some(h) = self.hits.get(p.rule) {
                push(p.rule, p.severity, p.title, format!("{} {} requests from {} clients.", p.detail, h.count, h.by_ip.len()), p.remediation, h);
            }
        }
        push("WEB-SHELLSHOCK", "high", "Shellshock attempts", format!("{} requests sent a () {{ … }} function definition in a header, which old Bash versions execute through CGI.", self.shellshock.count), "Make sure no CGI script runs under a Bash older than 4.3 patch 25.", &self.shellshock);
        push("WEB-SENSITIVE-SERVED", "high", "Sensitive files answered with 200", format!("{} requests for files such as .git, .env, backups or server-status were answered with 200: they may have been downloaded.", self.sensitive_served.count), "Check what was served, block these paths at the server, and rotate any secret they contained.", &self.sensitive_served);
        push("WEB-SENSITIVE-PROBED", "low", "Probing for sensitive files", format!("{} requests looked for files such as .git, .env, backups or admin consoles (not answered with 200).", self.sensitive_probed.count), "Nothing to fix if these paths stay unavailable; keep them blocked.", &self.sensitive_probed);
        push("WEB-SCANNER", "low", "Security scanners at work", format!("{} requests came from known scanning tools (by User-Agent).", self.scanners.count), "Confirm whether the scan was authorized; if not, block the sources and review what they found.", &self.scanners);
        // per-client thresholds
        let threshold = |map: &HashMap<String, u64>, min: u64| -> Hits {
            let mut h = Hits::default();
            for (ip, n) in map.iter().filter(|(_, n)| **n >= min) {
                h.count += n;
                h.by_ip.insert(ip.clone(), (*n, Vec::new()));
            }
            h
        };
        let scans = threshold(&self.not_found, 100);
        push("WEB-CONTENT-DISCOVERY", "medium", "Content discovery scans", format!("{} clients each received 100 or more 404 responses ({} in all): wordlist scans for hidden paths.", scans.by_ip.len(), scans.count), "Make sure nothing sensitive is reachable under guessable paths.", &scans);
        let guessing = threshold(&self.login_failures, 20);
        push("WEB-PASSWORD-GUESSING", "medium", "Password guessing against web logins", format!("{} clients each made 20 or more failed or repeated login attempts ({} in all).", guessing.by_ip.len(), guessing.count), "Rate-limit logins per account and per client, add MFA, and check the accounts that were targeted.", &guessing);
        let fail_map: HashMap<String, u64> = self.ssh_fail.iter().map(|(k, v)| (k.clone(), v.0)).collect();
        let mut brute = threshold(&fail_map, 10);
        for (ip, v) in brute.by_ip.iter_mut() {
            v.1 = self.ssh_fail.get(ip).map(|f| f.1.clone()).unwrap_or_default();
        }
        let heavy = brute.by_ip.values().any(|(n, _)| *n >= 100);
        push("SSH-BRUTE-FORCE", if heavy { "high" } else { "medium" }, "SSH password guessing", format!("{} clients each failed 10 or more SSH logins ({} failures in all).", brute.by_ip.len(), brute.count), "Allow keys only (PasswordAuthentication no), limit sources with a firewall, and use fail2ban or similar.", &brute);
        push("SSH-SUCCESS-AFTER-FAILURES", "high", "SSH login after repeated failures", format!("{} logins succeeded from clients that had failed at least five times before: possibly a guessed password.", self.ssh_after_failures.count), "Check these sessions and accounts now, and reset their credentials.", &self.ssh_after_failures);
        push("SSH-ROOT-LOGIN", "medium", "Direct root logins over SSH", format!("{} SSH logins went straight to root.", self.ssh_root.count), "Set PermitRootLogin no and log in as a named user who escalates with sudo.", &self.ssh_root);
        push("SSH-PASSWORD-LOGIN", "low", "SSH password logins", format!("{} SSH logins used a password, so the server accepts guessable credentials.", self.ssh_password.count), "Switch to key-based authentication (PasswordAuthentication no).", &self.ssh_password);
        if self.ssh_invalid_users.len() >= 10 {
            let h = Hits { count: self.ssh_invalid_users.len() as u64, by_ip: HashMap::new() };
            let names: Vec<String> = self.ssh_invalid_users.iter().take(20).cloned().collect();
            push("SSH-USER-ENUMERATION", "low", "Many unknown SSH user names", format!("{} different non-existent user names were tried, for example {}.", self.ssh_invalid_users.len(), names.join(", ")), "Expected background noise on exposed SSH; restrict who can reach the port.", &h);
        }
        out.sort_by_key(|d| ["critical", "high", "medium", "low", "info"].iter().position(|s| *s == d.severity).unwrap_or(5));
        r.detections = out;
        let mut clients: Vec<Client> = self.clients.into_values().collect();
        clients.sort_by(|a, b| (b.requests + b.ssh_failures + b.ssh_logins).cmp(&(a.requests + a.ssh_failures + a.ssh_logins)).then(a.ip.cmp(&b.ip)));
        clients.truncate(200);
        r.clients = clients;
        if self.capped {
            r.warnings.push(format!("More than {MAX_CLIENTS} clients: the rest were counted in the totals only"));
        }
        if r.recognised == 0 && r.lines > 0 {
            r.warnings.push("No line was recognised: Cyber Hub reads Apache/Nginx access logs (combined or common format) and OpenSSH authentication logs".into());
        }
        r
    }
}

/// Reads a log line by line (lines longer than 64 KB are cut, at most ten million lines).
pub fn analyze(mut input: impl BufRead) -> Result<Report, String> {
    let mut acc = Acc::default();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = input.read_until(b'\n', &mut buf).map_err(|e| format!("The log cannot be read: {e}"))?;
        if n == 0 {
            break;
        }
        if acc.report.lines >= MAX_LINES {
            acc.report.warnings.push(format!("Only the first {MAX_LINES} lines were read"));
            break;
        }
        buf.truncate(MAX_LINE);
        let line = String::from_utf8_lossy(&buf);
        acc.line(line.trim_end_matches(['\r', '\n']));
    }
    Ok(acc.finish())
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
