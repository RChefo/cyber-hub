// SPDX-License-Identifier: Apache-2.0
//! Persistence triage of a Linux file system: a mounted or copied disk image, or the files a triage
//! collection gathered (UAC's `[root]` folder, CatScale). Files are only read: symbolic links are
//! never followed (in an image they point into the analyst's own system) and nothing is run.
//!
//! The places where Linux starts programs (cron, systemd, rc scripts, the dynamic linker's preload
//! list, shell start-up files, SSH keys, accounts, sudo, PAM, desktop autostart, udev, MOTD) are
//! checked for what attackers leave there: downloads piped into a shell, reverse shells, miners,
//! decoded payloads, programs in temporary or hidden system folders. Locally added services,
//! timers, boot scripts, user cron jobs, SSH keys and login accounts are listed for review. Each
//! issue names the MITRE ATT&CK technique of its place (IDs checked against ATT&CK v20.1).

use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::containers::{FileReport, Issue, ScanResult};
use crate::redact::redact_text;

/// Files larger than this are not read (start-up files are small).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_TEXT: usize = 1024 * 1024;
/// Files read per scan, and file systems looked for under the chosen folder.
const MAX_FILES: usize = 5_000;
const MAX_ROOTS: usize = 8;
/// Entries listed in one inventory issue.
const MAX_LISTED: usize = 15;

const CRON: &str = "MITRE ATT&CK T1053.003 Scheduled Task/Job: Cron";
const SYSTEMD: &str = "MITRE ATT&CK T1543.002 Create or Modify System Process: Systemd Service";
const TIMER: &str = "MITRE ATT&CK T1053.006 Scheduled Task/Job: Systemd Timers";
const RC: &str = "MITRE ATT&CK T1037.004 Boot or Logon Initialization Scripts: RC Scripts";
const LOGON: &str = "MITRE ATT&CK T1037 Boot or Logon Initialization Scripts";
const PRELOAD: &str = "MITRE ATT&CK T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking";
const SHELL: &str = "MITRE ATT&CK T1546.004 Event Triggered Execution: Unix Shell Configuration Modification";
const KEYS: &str = "MITRE ATT&CK T1098.004 Account Manipulation: SSH Authorized Keys";
const ACCOUNT: &str = "MITRE ATT&CK T1136.001 Create Account: Local Account";
const SUDO: &str = "MITRE ATT&CK T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching";
const PAM: &str = "MITRE ATT&CK T1556.003 Modify Authentication Process: Pluggable Authentication Modules";
const XDG: &str = "MITRE ATT&CK T1547.013 Boot or Logon Autostart Execution: XDG Autostart Entries";
const UDEV: &str = "MITRE ATT&CK T1546.017 Event Triggered Execution: Udev Rules";

const REVIEW: &str = "Find out who added it and when (package files, change history, the file's times in the image). If it is not legitimate, remove it, stop what it started and look for the other persistence of the same intrusion.";
const INVENTORY: &str = "Confirm each entry is expected on this host; remove the ones nobody can explain.";

/// The kinds of files, for pasted text (`auto` guesses from the content).
pub const KINDS: &[&str] = &["auto", "crontab", "system-crontab", "systemd", "shell", "authorized-keys", "sudoers", "passwd", "shadow", "preload", "pam", "autostart", "udev"];

struct Sign {
    id: &'static str,
    severity: &'static str,
    what: &'static str,
    re: Regex,
}

/// Command patterns that matter wherever Linux starts a program.
static SIGNS: Lazy<Vec<Sign>> = Lazy::new(|| {
    let s = |id, severity, what, re: &str| Sign { id, severity, what, re: Regex::new(re).expect("persistence pattern") };
    vec![
        s("DOWNLOAD-EXEC", "high", "downloads a script and runs it", r"(?i)\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b|\b(curl|wget)\b[^\n;&]*\s(-o|-O|--output|--output-document)\s*\S+[^\n]*(;|&&)\s*(chmod\b|(ba)?sh\s|\./|/tmp/|/var/tmp/|/dev/shm/)"),
        s("REVERSE-SHELL", "high", "opens a shell for a remote host", r"(?i)/dev/(tcp|udp)/|\bnc(at)?\b[^\n]*\s-[a-z]*e\s|\bsocat\b[^\n]*exec:|\b(ba)?sh\s+-i\b|python[0-9.]*\s+-c[^\n]*socket|perl\s+-e[^\n]*socket|\bmkfifo\b[^\n]*\bnc\b|\bphp\s+-r[^\n]*fsockopen"),
        s("MINER", "high", "starts a cryptocurrency miner", r"(?i)stratum\+(tcp|ssl|tls)://|\bxmrig\b|\bminerd\b|\bkdevtmpfsi\b|\bkinsing\b|--donate-level"),
        s("ENCODED", "medium", "decodes hidden content and runs it", r"(?i)\bbase64\s+(-d|--decode)\b|\bxxd\s+-r\b|\bopenssl\s+(enc|base64)\b[^\n]*\s-d\b|\becho\s+['\x22]?[A-Za-z0-9+/]{60,}={0,2}['\x22]?\s*\|"),
        s("TEMP-EXEC", "medium", "runs a program from a temporary, world-writable folder", r"(^|[;&|(`]\s*|\b(nohup|exec|setsid|sudo|sh|bash|source)\s+|\.\s+)(/tmp|/var/tmp|/dev/shm)/[^\s;|&]+"),
        s("HIDDEN-EXEC", "medium", "runs a program from a hidden folder inside a system folder", r"(^|[;&|(`]\s*|\b(nohup|exec|setsid|sudo|sh|bash|source)\s+|\.\s+)/(usr|lib|lib64|etc|bin|sbin|var|dev|boot)/([^\s/]+/)*\.[^\s/.][^\s/]*/[^\s;|&]+"),
        s("IMMUTABLE", "medium", "changes the immutable attribute of files, which malware uses to protect its own", r"\bchattr\s+[-+]i\b|\bchattr\s+[-+][a-z]*i[a-z]*\s"),
        s("HISTORY", "low", "turns off or clears the shell history", r"(?i)\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bhistory\s+-c\b|\bHISTSIZE=0\b"),
    ]
});

/// Binaries GTFOBins lists as able to start a shell when run through sudo.
const SHELL_ESCAPES: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "vi", "vim", "nano", "ed", "less", "more", "man", "find", "awk", "gawk", "sed", "perl", "python", "python2", "python3", "ruby", "lua", "php", "node", "env", "tar", "zip", "git", "rsync", "docker", "systemctl", "journalctl", "gdb", "strace", "tcpdump", "nmap", "apt", "apt-get", "yum", "dnf", "pip", "pip3",
];
const LOGIN_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash", "mksh"];

/// Issues reported for one collection (a file of 1 MiB can be a million one-character lines).
const MAX_ISSUES: usize = 5_000;

struct Out<'a> {
    file: &'a str,
    issues: Vec<Issue>,
    /// (rule, location) pairs already reported
    seen: std::collections::HashSet<(String, String)>,
}

impl Out<'_> {
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, rule: String, severity: &str, title: String, line: usize, detail: String, remediation: &str, reference: &str) {
        let location = if line == 0 { "whole file".to_string() } else { format!("line {line}") };
        if self.issues.len() >= MAX_ISSUES || !self.seen.insert((rule.clone(), location.clone())) {
            return;
        }
        self.issues.push(Issue { rule, severity: severity.into(), title, location, detail, remediation: remediation.into(), reference: reference.into() });
    }

    /// The command patterns found in one command or line. `place` names it in titles ("Cron job").
    fn signs(&mut self, text: &str, line: usize, place: &str, prefix: &str, reference: &str) -> bool {
        let mut hit = false;
        let mut temp = false;
        for s in SIGNS.iter() {
            // a hidden folder inside /var/tmp is already reported as a temporary one
            if s.id == "HIDDEN-EXEC" && temp {
                continue;
            }
            if s.re.is_match(text) {
                temp |= s.id == "TEMP-EXEC";
                hit = true;
                self.add(format!("LNX-{prefix}-{}", s.id), s.severity, format!("{place} {}", s.what), line, format!("{} {line_of}: {}", s.what[..1].to_uppercase() + &s.what[1..], shown(text), line_of = where_(self.file, line)), REVIEW, reference);
            }
        }
        hit
    }
}

fn where_(file: &str, line: usize) -> String {
    if line == 0 {
        format!("in {file}")
    } else {
        format!("on line {line} of {file}")
    }
}

/// A line as shown in a report: redacted, without control characters, cut.
fn shown(s: &str) -> String {
    let clean: String = redact_text(s.trim()).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if clean.chars().count() > 300 {
        format!("{}…", clean.chars().take(299).collect::<String>())
    } else {
        clean
    }
}

/// Lines without comments and blanks, with their numbers; `\` continuations joined.
fn lines(text: &str, comment: char) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let l = raw.trim_end_matches('\r');
        let (n, mut joined) = pending.take().unwrap_or((i + 1, String::new()));
        if let Some(head) = l.strip_suffix('\\') {
            joined.push_str(head);
            joined.push(' ');
            pending = Some((n, joined));
            continue;
        }
        joined.push_str(l);
        let t = joined.trim();
        if !t.is_empty() && !t.starts_with(comment) {
            out.push((n, t.to_string()));
        }
    }
    if let Some((n, j)) = pending {
        if !j.trim().is_empty() {
            out.push((n, j.trim().to_string()));
        }
    }
    out
}

/// The first word of a command line, without systemd's `-@:+!` prefixes.
fn program(cmd: &str) -> &str {
    cmd.split_whitespace().next().map(|t| t.trim_start_matches(['-', '@', ':', '+', '!'])).unwrap_or("")
}

/* ───────────────────────── one file ───────────────────────── */

/// Checks one file. `path` is its path inside the file system (`/etc/crontab`), which decides
/// the kind unless `hint` names one; pasted text has no path.
pub fn analyze(path: &str, text: &str, hint: &str) -> Option<FileReport> {
    let kind = if hint == "auto" || hint.is_empty() { kind_of(path).or_else(|| guess(text))? } else { KINDS.contains(&hint).then_some(hint)? };
    let mut out = Out { file: path, issues: Vec::new(), seen: Default::default() };
    let user = owner(path);
    match kind {
        "crontab" | "system-crontab" => crontab(&mut out, text, kind == "system-crontab", user.as_deref()),
        "cron-script" => script(&mut out, text, "Cron script", "CRON", CRON),
        "systemd" => systemd(&mut out, path, text),
        "rc" => rc(&mut out, path, text),
        "init-script" => script(&mut out, text, "Init script", "INIT", RC),
        "motd" => script(&mut out, text, "Login message script", "MOTD", LOGON),
        "preload" => preload(&mut out, text),
        "shell" | "environment" => shell(&mut out, text),
        "authorized-keys" => keys(&mut out, text, user.as_deref().unwrap_or("this user")),
        "sudoers" => sudoers(&mut out, text),
        "passwd" => passwd(&mut out, text),
        "shadow" => shadow(&mut out, text),
        "pam" => pam(&mut out, text),
        "autostart" => autostart(&mut out, path, text, user.as_deref()),
        "udev" => udev(&mut out, path, text),
        _ => return None,
    }
    Some(FileReport { file: path.to_string(), kind: kind.to_string(), issues: out.issues, error: String::new(), sha256: sha256(text.as_bytes()) })
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The kind of a file from its path inside the file system.
pub fn kind_of(path: &str) -> Option<&'static str> {
    let p = path.replace('\\', "/");
    let p = p.as_str();
    let name = p.rsplit('/').next().unwrap_or(p);
    let under = |dir: &str| p.contains(dir);
    let in_home = |rest: &str| (p.starts_with("/root/") || p.starts_with("/home/")) && p.ends_with(rest);
    Some(match () {
        _ if p == "/etc/crontab" || under("/etc/cron.d/") => "system-crontab",
        _ if under("/var/spool/cron/") || p == "/etc/anacrontab" => "crontab",
        _ if under("/etc/cron.hourly/") || under("/etc/cron.daily/") || under("/etc/cron.weekly/") || under("/etc/cron.monthly/") => "cron-script",
        _ if (under("/systemd/system/") || under("/systemd/user/")) && (name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".socket") || name.ends_with(".path") || name.ends_with(".conf")) => "systemd",
        _ if p == "/etc/rc.local" || p == "/etc/rc.d/rc.local" => "rc",
        _ if under("/etc/init.d/") || under("/etc/rc.d/init.d/") => "init-script",
        _ if under("/etc/update-motd.d/") => "motd",
        _ if p == "/etc/ld.so.preload" => "preload",
        _ if p == "/etc/environment" => "environment",
        _ if ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshenv", "/etc/zprofile", "/etc/zlogin", "/etc/zshrc", "/etc/zsh/zshrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zlogin"].contains(&p) || (under("/etc/profile.d/") && name.ends_with(".sh")) => "shell",
        _ if [".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zlogin", ".zshenv"].iter().any(|f| in_home(&format!("/{f}"))) => "shell",
        _ if in_home("/.ssh/authorized_keys") || in_home("/.ssh/authorized_keys2") => "authorized-keys",
        _ if p == "/etc/sudoers" || under("/etc/sudoers.d/") => "sudoers",
        _ if p == "/etc/passwd" => "passwd",
        _ if p == "/etc/shadow" => "shadow",
        _ if under("/etc/pam.d/") => "pam",
        _ if (under("/etc/xdg/autostart/") || under("/.config/autostart/")) && name.ends_with(".desktop") => "autostart",
        _ if under("/udev/rules.d/") && name.ends_with(".rules") => "udev",
        _ => return None,
    })
}

/// The kind of pasted text, from its content.
fn guess(text: &str) -> Option<&'static str> {
    static CRON_LINE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|([0-9*/,\-]+\s+){4}[0-9*/,\-A-Za-z]+)\s+\S").expect("cron"));
    static KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)(^|\s)(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+AAAA").expect("key"));
    static PASSWD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[a-z_][a-z0-9_.-]*\$?:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*$").expect("passwd"));
    static SHADOW: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[a-z_][a-z0-9_.-]*\$?:[^:\n]*:\d*:\d*:\d*:\d*:\d*:\d*:[^:\n]*$").expect("shadow"));
    let t = text.trim_start();
    Some(match () {
        _ if t.contains("[Service]") || t.contains("[Timer]") || (t.contains("[Unit]") && t.contains("[Install]")) => "systemd",
        _ if t.contains("[Desktop Entry]") => "autostart",
        _ if KEY.is_match(text) => "authorized-keys",
        _ if PASSWD.is_match(text) => "passwd",
        _ if SHADOW.is_match(text) => "shadow",
        _ if text.contains("RUN+=") || text.contains("ACTION==") => "udev",
        _ if text.lines().any(|l| l.trim_start().starts_with("Defaults") || (l.contains("ALL=(") && !l.trim_start().starts_with('#'))) => "sudoers",
        _ if text.lines().any(|l| { let w: Vec<&str> = l.split_whitespace().collect(); w.len() >= 3 && ["auth", "account", "password", "session", "-auth", "-session"].contains(&w[0]) && w.iter().any(|x| x.contains("pam_")) }) => "pam",
        _ if CRON_LINE.is_match(text) => "crontab",
        _ => "shell",
    })
}

/// The user a file belongs to: the crontab's name in a spool, or the home folder's owner.
fn owner(path: &str) -> Option<String> {
    let p = path.replace('\\', "/");
    if let Some(rest) = p.strip_prefix("/home/") {
        return rest.split('/').next().map(str::to_string);
    }
    if p.starts_with("/root/") {
        return Some("root".into());
    }
    if p.contains("/var/spool/cron/") {
        return p.rsplit('/').next().map(str::to_string);
    }
    None
}

/* ───────────────────────── checks ───────────────────────── */

fn crontab(out: &mut Out, text: &str, system: bool, user: Option<&str>) {
    let mut listed: Vec<String> = Vec::new();
    for (n, l) in lines(text, '#') {
        // variable assignments: SHELL=, PATH=, MAILTO=, and the preload variable
        if let Some((k, v)) = l.split_once('=') {
            if !k.trim().contains(char::is_whitespace) && !k.trim().is_empty() {
                if k.trim() == "LD_PRELOAD" {
                    out.add("LNX-CRON-PRELOAD".into(), "high", "Cron preloads a library into its jobs".into(), n, format!("LD_PRELOAD={} {}: every job of this crontab loads that library first.", shown(v), where_(out.file, n)), REVIEW, PRELOAD);
                }
                continue;
            }
        }
        let words: Vec<&str> = l.split_whitespace().collect();
        let (when, skip) = if words.first().is_some_and(|w| w.starts_with('@')) { (words[0].to_string(), 1) } else { (words.iter().take(5).copied().collect::<Vec<_>>().join(" "), 5) };
        let skip = if system { skip + 1 } else { skip };
        if words.len() <= skip {
            continue;
        }
        let run_as = if system { words[skip - 1].to_string() } else { user.unwrap_or("its owner").to_string() };
        let command = words[skip..].join(" ");
        out.signs(&command, n, "Cron job", "CRON", CRON);
        if when == "@reboot" {
            out.add("LNX-CRON-REBOOT".into(), "low", "Cron job runs at every boot".into(), n, format!("@reboot as {run_as} {}: {}", where_(out.file, n), shown(&command)), REVIEW, CRON);
        }
        if listed.len() < MAX_LISTED {
            listed.push(format!("{when} as {run_as}: {}", shown(&command)));
        }
    }
    // user crontabs are rare on servers: all their jobs are listed
    if !system && !listed.is_empty() {
        let who = user.unwrap_or("a user");
        out.add("LNX-CRON-USER".into(), "info", format!("Scheduled jobs of {who}"), 0, format!("{} in {}: {}", plural(listed.len(), "job"), out.file, listed.join(" · ")), INVENTORY, CRON);
    }
}

fn script(out: &mut Out, text: &str, place: &str, prefix: &str, reference: &str) {
    for (n, l) in lines(text, '#') {
        out.signs(&l, n, place, prefix, reference);
    }
}

fn systemd(out: &mut Out, path: &str, text: &str) {
    let name = path.rsplit('/').next().unwrap_or(path).to_string();
    let user_unit = path.contains("/.config/systemd/user/") || path.starts_with("/etc/systemd/user/");
    let local = path.starts_with("/etc/systemd/") || user_unit;
    let timer = name.ends_with(".timer");
    let mut exec: Vec<(usize, String)> = Vec::new();
    let mut schedule: Vec<String> = Vec::new();
    let mut unit = String::new();
    let mut installed = false;
    for (n, l) in lines(text, '#') {
        if l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "ExecStart" | "ExecStartPre" | "ExecStartPost" | "ExecStop" | "ExecStopPost" | "ExecReload" | "ExecCondition" if !v.is_empty() => exec.push((n, v.trim_start_matches(['-', '@', ':', '+', '!']).to_string())),
            "Environment" if v.contains("LD_PRELOAD") => out.add("LNX-SYSTEMD-PRELOAD".into(), "high", format!("Unit {name} preloads a library"), n, format!("{} {}: the program loads that library first.", shown(l.as_str()), where_(out.file, n)), REVIEW, PRELOAD),
            "OnCalendar" | "OnBootSec" | "OnStartupSec" | "OnUnitActiveSec" | "OnUnitInactiveSec" | "OnActiveSec" => schedule.push(format!("{k}={v}")),
            "Unit" => unit = v.to_string(),
            "WantedBy" | "RequiredBy" | "UpheldBy" => installed = true,
            _ => {}
        }
    }
    let place = if timer { format!("Timer {name}") } else { format!("Unit {name}") };
    for (n, cmd) in &exec {
        out.signs(cmd, *n, &place, "SYSTEMD", if timer { TIMER } else { SYSTEMD });
    }
    // services and timers added on this host (not by packages) are listed
    if local && !name.ends_with(".conf") {
        if timer {
            let target = if unit.is_empty() { name.trim_end_matches(".timer").to_string() + ".service" } else { unit };
            out.add("LNX-SYSTEMD-TIMER".into(), "info", format!("Timer {name} added on this host"), 0, format!("{} starts {target} ({}).", out.file, if schedule.is_empty() { "no schedule found".into() } else { schedule.join(", ") }), INVENTORY, TIMER);
        } else if let Some((n, first)) = exec.first() {
            let who = if user_unit { "a user's login" } else if installed { "boot" } else { "demand (not enabled by this file)" };
            out.add("LNX-SYSTEMD-LOCAL".into(), "info", format!("{} {name} added on this host", if user_unit { "User service" } else { "Service" }), *n, format!("{} runs {} at {who}: {}", out.file, program(first), shown(first)), INVENTORY, SYSTEMD);
        }
    }
}

fn rc(out: &mut Out, path: &str, text: &str) {
    let mut listed: Vec<String> = Vec::new();
    let mut first = 0;
    for (n, l) in lines(text, '#') {
        if l == "exit 0" || l.starts_with("#!") {
            continue;
        }
        out.signs(&l, n, "Boot script", "RC", RC);
        if first == 0 {
            first = n;
        }
        if listed.len() < MAX_LISTED {
            listed.push(shown(&l));
        }
    }
    if !listed.is_empty() {
        out.add("LNX-RC-COMMANDS".into(), "low", format!("{path} runs commands at boot"), first, format!("{} at boot: {}", plural(listed.len(), "command"), listed.join(" · ")), INVENTORY, RC);
    }
}

fn preload(out: &mut Out, text: &str) {
    for (n, l) in lines(text, '#') {
        for lib in l.split([' ', ':']).filter(|x| !x.is_empty()) {
            out.add("LNX-PRELOAD".into(), "high", "Library preloaded into every program".into(), n, format!("{} loads {} into every program that starts, a way to hide files and processes or steal credentials (libprocesshider and many rootkits work like this).", out.file, shown(lib)), "Check the library: package ownership, hashes against threat intelligence, and its strings. If nothing legitimate needs it, empty the file and replace the binaries the intrusion touched.", PRELOAD);
        }
    }
}

fn shell(out: &mut Out, text: &str) {
    static ALIAS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(alias\s+(sudo|su|ssh|passwd)=|(function\s+)?(sudo|su|passwd)\s*\(\)\s*\{)").expect("alias"));
    for (n, l) in lines(text, '#') {
        if l.contains("LD_PRELOAD=") {
            out.add("LNX-SHELL-PRELOAD".into(), "high", "Shell start-up file preloads a library".into(), n, format!("{} {}: every program started from these shells loads that library first.", shown(&l), where_(out.file, n)), REVIEW, PRELOAD);
        }
        if ALIAS.is_match(&l) {
            out.add("LNX-SHELL-WRAPPER".into(), "high", "Shell start-up file replaces sudo, su, ssh or passwd".into(), n, format!("{} {}: a wrapper around these commands can capture the passwords typed into them.", shown(&l), where_(out.file, n)), REVIEW, SHELL);
        }
        out.signs(&l, n, "Shell start-up file", "SHELL", SHELL);
    }
}

/// `SHA256:…` of an OpenSSH public key, as `ssh-keygen -l` prints it.
fn fingerprint(blob_b64: &str) -> Option<String> {
    let blob = super::pcap::base64_decode(blob_b64)?;
    let digest = Sha256::digest(&blob);
    Some(format!("SHA256:{}", crate::vt::base64url_nopad(&digest).replace('-', "+").replace('_', "/")))
}

fn keys(out: &mut Out, text: &str, user: &str) {
    static TYPE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(^|\s)(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+([A-Za-z0-9+/=]+)(\s+(.*))?$").expect("key"));
    let mut listed: Vec<String> = Vec::new();
    let mut count = 0;
    for (n, l) in lines(text, '#') {
        let Some(c) = TYPE.captures(&l) else { continue };
        count += 1;
        let start = c.get(2).map_or(0, |m| m.start());
        let options = l[..start].trim();
        let kind = &c[2];
        let comment = c.get(7).map(|m| m.as_str().trim()).unwrap_or("");
        let fp = fingerprint(&c[5]).unwrap_or_else(|| "unreadable key".into());
        if listed.len() < MAX_LISTED {
            listed.push(format!("{kind} {fp}{}", if comment.is_empty() { " (no comment)".to_string() } else { format!(" {}", shown(comment)) }));
        }
        if options.contains("command=") {
            out.add("LNX-KEYS-COMMAND".into(), "low", format!("SSH key for {user} runs a fixed command"), n, format!("The key {fp} {} has the options {}: whoever holds it runs that command on login. It is often a legitimate restriction, and sometimes a backdoor.", where_(out.file, n), shown(options)), INVENTORY, KEYS);
        }
        if options.contains("environment=") {
            out.add("LNX-KEYS-ENVIRONMENT".into(), "low", format!("SSH key for {user} sets environment variables"), n, format!("The key {fp} {} sets {}; with PermitUserEnvironment this can preload libraries into the login shell.", where_(out.file, n), shown(options)), INVENTORY, KEYS);
        }
    }
    if count > 0 {
        out.add("LNX-KEYS".into(), "info", format!("{} can log in as {user}", plural(count, "SSH key")), 0, format!("{}: {}", out.file, listed.join(" · ")), "Compare the keys with the ones the account's owners use; remove the others and rotate what the attacker could reach.", KEYS);
    }
}

fn sudoers(out: &mut Out, text: &str) {
    for (n, l) in lines(text, '#') {
        if l.starts_with("Defaults") {
            if l.contains("!authenticate") {
                out.add("LNX-SUDO-NOAUTH".into(), "high", "sudo never asks for a password".into(), n, format!("{} {}: users run commands as root without proving who they are.", shown(&l), where_(out.file, n)), REVIEW, SUDO);
            }
            continue;
        }
        if l.starts_with('@') || l.contains("_Alias") {
            continue;
        }
        let Some((who, rest)) = l.split_once(char::is_whitespace) else { continue };
        let Some((_, spec)) = rest.split_once('=') else { continue };
        if !spec.contains("NOPASSWD") {
            continue;
        }
        if who == "root" {
            continue;
        }
        let commands = spec.rsplit(':').next().unwrap_or("").trim();
        let everyone = who == "ALL";
        let anything = commands.split(',').any(|c| c.trim() == "ALL");
        // a command without arguments (or with a wildcard) may be run with any arguments
        let escapes: Vec<&str> = commands
            .split(',')
            .filter_map(|c| {
                let t: Vec<&str> = c.split_whitespace().collect();
                let bin = t.first()?.rsplit('/').next()?;
                (SHELL_ESCAPES.contains(&bin) && (t.len() == 1 || t[1..].iter().any(|a| a.contains('*')))).then_some(bin)
            })
            .collect();
        if anything {
            out.add("LNX-SUDO-NOPASSWD-ALL".into(), if everyone { "high" } else { "medium" }, format!("{} run any command as root without a password", if everyone { "All users can".to_string() } else { format!("{who} can") }), n, format!("{} {}.", shown(&l), where_(out.file, n)), REVIEW, SUDO);
        } else if !escapes.is_empty() {
            out.add("LNX-SUDO-SHELL-ESCAPE".into(), "medium", format!("{who} can start a root shell through sudo without a password"), n, format!("{} {}: {} can start a shell (GTFOBins), so this is root access.", shown(&l), where_(out.file, n), escapes.join(", ")), REVIEW, SUDO);
        }
    }
}

fn passwd(out: &mut Out, text: &str) {
    let mut logins: Vec<String> = Vec::new();
    for (n, l) in lines(text, '#') {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let (name, pw, uid, shell_path) = (f[0], f[1], f[2].parse::<u64>().unwrap_or(u64::MAX), f[6]);
        let login = LOGIN_SHELLS.contains(&shell_path.rsplit('/').next().unwrap_or(""));
        if uid == 0 && name != "root" {
            out.add(format!("LNX-ACCOUNT-UID0-{name}"), "high", format!("Second superuser account {name}"), n, format!("{name} has UID 0 {}: it is root under another name.", where_(out.file, n)), "Unless it is a documented break-glass account, lock and remove it, and review what it did (auth logs, its home folder).", ACCOUNT);
        }
        if pw.is_empty() {
            out.add(format!("LNX-ACCOUNT-NOPASS-{name}"), "high", format!("Account {name} has no password"), n, format!("The password field of {name} is empty {}: anyone can log in as {name} where password logins are allowed.", where_(out.file, n)), "Lock the account (passwd -l) or set a password, and check its logins.", ACCOUNT);
        } else if !["x", "*", "!", "!!"].contains(&pw) && !pw.starts_with('!') {
            out.add(format!("LNX-ACCOUNT-HASH-{name}"), "medium", format!("Password hash of {name} stored in {}", out.file), n, format!("The password of {name} is stored {} (the hash is not shown), which every user can read and crack offline.", where_(out.file, n)), "Move the password to /etc/shadow (pwconv) and change it.", ACCOUNT);
        }
        if login && (1..1000).contains(&uid) {
            out.add(format!("LNX-ACCOUNT-SYSTEM-SHELL-{name}"), "low", format!("System account {name} has a login shell"), n, format!("{name} (UID {uid}) {} has the shell {shell_path}; service accounts usually have /usr/sbin/nologin, and attackers give them shells to log in unnoticed.", where_(out.file, n)), INVENTORY, ACCOUNT);
        }
        if login && logins.len() < MAX_LISTED {
            logins.push(format!("{name} (UID {})", f[2]));
        }
    }
    if !logins.is_empty() {
        out.add("LNX-ACCOUNT-LOGINS".into(), "info", "Accounts with a login shell".into(), 0, format!("{}: {}", out.file, logins.join(", ")), INVENTORY, ACCOUNT);
    }
}

fn shadow(out: &mut Out, text: &str) {
    for (n, l) in lines(text, '#') {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 2 && f[1].is_empty() {
            let name = f[0];
            out.add(format!("LNX-SHADOW-EMPTY-{name}"), "high", format!("Account {name} has an empty password"), n, format!("The password of {name} is empty {}: it logs in without one where password logins are allowed.", where_(out.file, n)), "Lock the account (passwd -l) or set a password, and check its logins.", ACCOUNT);
        }
    }
}

fn pam(out: &mut Out, text: &str) {
    for (n, l) in lines(text, '#') {
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.len() < 3 {
            continue;
        }
        let (kind, control) = (w[0].trim_start_matches('-'), w[1]);
        let Some(mi) = w.iter().position(|x| x.contains(".so")) else { continue };
        let module = w[mi];
        let base = module.rsplit('/').next().unwrap_or(module);
        if module.starts_with('/') && ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"].iter().any(|d| module.starts_with(d)) {
            out.add("LNX-PAM-WRITABLE".into(), "high", "PAM loads a module from a writable folder".into(), n, format!("{} {}: the module sees every password typed for this service.", shown(&l), where_(out.file, n)), REVIEW, PAM);
        }
        if base == "pam_permit.so" && kind == "auth" && control == "sufficient" {
            out.add("LNX-PAM-PERMIT".into(), "high", "PAM accepts any password".into(), n, format!("{} {}: pam_permit always succeeds, so authentication for this service succeeds without a valid password.", shown(&l), where_(out.file, n)), REVIEW, PAM);
        }
        if base == "pam_exec.so" {
            let args = w[mi + 1..].join(" ");
            // the program is the first argument that is a path; the others are pam_exec options
            let prog = w[mi + 1..].iter().find(|a| a.starts_with('/')).copied().unwrap_or("a program");
            out.add("LNX-PAM-EXEC".into(), "medium", format!("PAM runs a program at {kind}"), n, format!("{} {}: {} runs with the user's details{}.", shown(&l), where_(out.file, n), shown(prog), if args.contains("expose_authtok") { ", and receives the password (expose_authtok)" } else { "" }), REVIEW, PAM);
            out.signs(&args, n, "PAM program", "PAM", PAM);
        }
    }
}

fn autostart(out: &mut Out, path: &str, text: &str, user: Option<&str>) {
    for (n, l) in lines(text, '#') {
        let Some(cmd) = l.strip_prefix("Exec=") else { continue };
        let hit = out.signs(cmd, n, "Autostart entry", "AUTOSTART", XDG);
        if !hit && path.contains("/.config/autostart/") {
            out.add("LNX-AUTOSTART-USER".into(), "info", format!("Program starts at {}'s desktop login", user.unwrap_or("a user")), n, format!("{} starts {}: {}", out.file, program(cmd), shown(cmd)), INVENTORY, XDG);
        }
    }
}

fn udev(out: &mut Out, path: &str, text: &str) {
    static RUN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\b(RUN|PROGRAM)\s*\+?=\s*"([^"]*)""#).expect("run"));
    for (n, l) in lines(text, '#') {
        for c in RUN.captures_iter(&l) {
            let cmd = c[2].to_string();
            let hit = out.signs(&cmd, n, "Udev rule", "UDEV", UDEV);
            if !hit && path.starts_with("/etc/udev/") && !cmd.starts_with("builtin") {
                out.add("LNX-UDEV-LOCAL".into(), "info", "Udev rule added on this host runs a program".into(), n, format!("{} runs {} when a device event matches: {}", out.file, program(&cmd), shown(&cmd)), INVENTORY, UDEV);
            }
        }
    }
}

fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

/* ───────────────────────── file systems ───────────────────────── */

/// File systems under a chosen folder: the folder itself, or folders up to four levels below it
/// that hold `etc/passwd` or `etc/crontab` (a UAC collection's `[root]`, an image mounted in a
/// subfolder). A chosen `etc` folder stands for its parent.
pub fn roots(chosen: &Path) -> Vec<PathBuf> {
    let is_root = |p: &Path| p.join("etc").join("passwd").is_file() || p.join("etc").join("crontab").is_file() || p.join("etc").join("systemd").is_dir();
    if chosen.file_name().is_some_and(|n| n == "etc") && chosen.join("passwd").is_file() {
        return chosen.parent().map(|p| vec![p.to_path_buf()]).unwrap_or_default();
    }
    let mut found = Vec::new();
    let mut level = vec![chosen.to_path_buf()];
    for _ in 0..5 {
        let mut next = Vec::new();
        for d in level {
            if is_root(&d) {
                found.push(d);
                if found.len() >= MAX_ROOTS {
                    return found;
                }
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten().take(500) {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    next.push(e.path());
                }
            }
        }
        level = next;
        if level.is_empty() || level.len() > 5_000 {
            break;
        }
    }
    found
}

/// The files of one file system worth reading, as (path inside it, path on disk).
fn candidates(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut add = |inside: String| {
        let disk = root.join(inside.trim_start_matches('/'));
        out.push((inside, disk));
    };
    for f in ["/etc/crontab", "/etc/anacrontab", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/ld.so.preload", "/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshenv", "/etc/zprofile", "/etc/zlogin", "/etc/zshrc", "/etc/zsh/zshrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zlogin", "/etc/passwd", "/etc/shadow", "/etc/sudoers"] {
        add(f.to_string());
    }
    let dirs = [
        "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/profile.d", "/etc/sudoers.d", "/etc/pam.d", "/etc/xdg/autostart", "/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d", "/etc/update-motd.d", "/etc/init.d", "/etc/rc.d/init.d",
    ];
    for d in dirs {
        for name in list(&root.join(d.trim_start_matches('/'))) {
            add(format!("{d}/{name}"));
        }
    }
    for d in ["/etc/systemd/system", "/etc/systemd/user", "/lib/systemd/system", "/usr/lib/systemd/system", "/usr/lib/systemd/user"] {
        for rel in walk(&root.join(d.trim_start_matches('/')), 3) {
            add(format!("{d}/{rel}"));
        }
    }
    let mut homes: Vec<String> = vec!["/root".into()];
    homes.extend(list_dirs(&root.join("home")).into_iter().map(|h| format!("/home/{h}")));
    for h in homes {
        for f in [".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zlogin", ".zshenv", ".ssh/authorized_keys", ".ssh/authorized_keys2"] {
            add(format!("{h}/{f}"));
        }
        let home = root.join(h.trim_start_matches('/'));
        for name in list(&home.join(".config").join("autostart")) {
            add(format!("{h}/.config/autostart/{name}"));
        }
        for rel in walk(&home.join(".config").join("systemd").join("user"), 3) {
            add(format!("{h}/.config/systemd/user/{rel}"));
        }
    }
    out
}

/// Regular files of a folder (symbolic links are never followed).
fn list(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut names: Vec<String> = rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    names.sort();
    names.truncate(2_000);
    names
}

fn list_dirs(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut names: Vec<String> = rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    names.sort();
    names.truncate(2_000);
    names
}

/// Regular files below a folder, `depth` levels deep at most, as relative paths.
fn walk(dir: &Path, depth: usize) -> Vec<String> {
    let mut out: Vec<String> = list(dir);
    if depth > 1 {
        for sub in list_dirs(dir) {
            out.extend(walk(&dir.join(&sub), depth - 1).into_iter().map(|r| format!("{sub}/{r}")));
            if out.len() > 4_000 {
                break;
            }
        }
    }
    out
}

/// Reads a file of the file system at `root` (canonical) with the SHA-256 of its bytes. A file
/// that is a symbolic link is skipped, and so is one that a link in its folders leads out of the
/// file system: an absolute link in an image points into the analyst's own system.
fn read(root: &Path, path: &Path) -> Result<Option<(String, String)>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.file_type().is_file() {
        return Ok(None);
    }
    if !std::fs::canonicalize(path).is_ok_and(|real| real.starts_with(root)) {
        return Ok(None);
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("larger than {} MB, not read", MAX_FILE_BYTES / 1024 / 1024));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(Some((String::from_utf8_lossy(&bytes).into_owned(), sha256(&bytes))))
}

/// Checks every file system under a chosen folder. Files without issues are counted, not listed.
pub fn scan_path(chosen: &Path) -> Result<ScanResult, String> {
    let found = roots(chosen);
    if found.is_empty() {
        return Err("No Linux file system was found here. Choose the folder that holds etc/ (the root of a mounted or copied image, or the [root] folder of a UAC collection).".into());
    }
    let mut res = ScanResult::default();
    let several = found.len() > 1;
    for root in &found {
        let label = root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let Ok(real_root) = std::fs::canonicalize(root) else { continue };
        for (inside, disk) in candidates(root) {
            if res.files_seen >= MAX_FILES {
                res.truncated = true;
                return Ok(res);
            }
            let shown_path = if several { format!("{label}: {inside}") } else { inside.clone() };
            match read(&real_root, &disk) {
                Ok(None) => {}
                Ok(Some((text, hash))) => {
                    res.files_seen += 1;
                    if let Some(mut r) = analyze(&inside, &text, "auto") {
                        if !r.issues.is_empty() {
                            r.file = shown_path;
                            r.sha256 = hash;
                            res.files.push(r);
                        }
                    }
                }
                Err(e) => {
                    res.files_seen += 1;
                    if kind_of(&inside).is_some() {
                        res.files.push(FileReport { file: shown_path, kind: kind_of(&inside).unwrap_or("unknown").into(), error: format!("Not read: {e}"), ..Default::default() });
                    }
                }
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
#[path = "linux_persist_tests.rs"]
mod tests;
