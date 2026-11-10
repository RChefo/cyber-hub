//! Windows event log triage (docs/UTILITIES.md, "Log triage"): detections over the events of an
//! EVTX file (`evtx.rs`), each mapped to a MITRE ATT&CK technique. Event IDs and fields follow
//! Microsoft's documentation of the Security, System, PowerShell, Defender and Sysmon events.
//! A detection is a lead for an investigation, not proof of a compromise. Nothing is contacted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

use once_cell::sync::Lazy;
use regex::Regex;

use super::evtx::{self, Event};
use super::logs::{AccountLogons, Detection, EventCount, Report, Source};

const MAX_EVENTS: u64 = 5_000_000;
const MAX_KEYS: usize = 100_000;
const EXAMPLES: usize = 3;

struct Rule {
    id: &'static str,
    severity: &'static str,
    title: &'static str,
    technique: &'static str,
    detail: &'static str,
    remediation: &'static str,
}

macro_rules! rule {
    ($id:literal, $sev:literal, $title:literal, $tech:literal, $detail:literal, $fix:literal) => {
        Rule { id: $id, severity: $sev, title: $title, technique: $tech, detail: $detail, remediation: $fix }
    };
}

const LOG_CLEARED: Rule = rule!("EVT-LOG-CLEARED", "high", "Event log cleared", "T1070.001 Indicator Removal: Clear Windows Event Logs",
    "An event log was cleared (Security 1102 or System 104). Attackers clear logs to remove traces; administrators rarely need to.",
    "Find out who cleared the log and why; collect the logs centrally so clearing them locally does not erase the record.");
const AUDIT_POLICY: Rule = rule!("EVT-AUDIT-POLICY", "medium", "Audit policy changed", "T1562.002 Impair Defenses: Disable Windows Event Logging",
    "The system audit policy was changed (4719); turning auditing off hides later activity.",
    "Confirm the change was planned, and enforce the audit policy through Group Policy.");
const GUESSING: Rule = rule!("EVT-PASSWORD-GUESSING", "medium", "Password guessing", "T1110.001 Brute Force: Password Guessing",
    "Many failed logons (4625) came from the same source.",
    "Block or rate-limit the source, check whether any of the accounts then logged on, and enforce account lockout and MFA.");
const SPRAYING: Rule = rule!("EVT-PASSWORD-SPRAYING", "high", "Password spraying", "T1110.003 Brute Force: Password Spraying",
    "Failed logons (4625) for many different accounts came from the same source: one or a few passwords tried against many users.",
    "Block the source, reset the passwords of accounts that logged on afterwards, and enforce MFA.");
const LOGON_AFTER: Rule = rule!("EVT-LOGON-AFTER-FAILURES", "high", "Logon after repeated failures", "T1110 Brute Force",
    "A logon succeeded (4624) from a source that had failed five times or more before: the guessing may have worked.",
    "Check the account's activity after this logon, reset its password, and end its sessions.");
const RDP: Rule = rule!("EVT-RDP-LOGON", "info", "Remote Desktop logons", "T1021.001 Remote Services: Remote Desktop Protocol",
    "Interactive logons over Remote Desktop (4624, logon type 10).",
    "Check that these sources and accounts are expected to use Remote Desktop.");
const SERVER_CREDS: Rule = rule!("EVT-SERVER-PROCESS-CREDENTIALS", "high", "Explicit credentials used by a server process", "T1505.003 Server Software Component: Web Shell",
    "A web or database server process logged on with explicit credentials (4648), as code running inside it does when it starts programs as another user, typical of a web shell.",
    "Inspect the web application for uploaded scripts and the server for processes started by its worker.");
const REMOTE_CREDS: Rule = rule!("EVT-EXPLICIT-CREDENTIALS", "low", "Explicit credentials for another host", "T1021 Remote Services",
    "A logon with explicit credentials (4648) targeted another server, as runas, PsExec or mapped drives do.",
    "Check that these account and host pairs are expected.");
const ACCOUNT: Rule = rule!("EVT-ACCOUNT-CREATED", "medium", "User account created", "T1136 Create Account",
    "A user account was created (4720).",
    "Confirm each new account was requested, and disable those that were not.");
const FAKE_MACHINE: Rule = rule!("EVT-ACCOUNT-LIKE-COMPUTER", "high", "User account named like a computer account", "T1136.002 Create Account: Domain Account",
    "A user account whose name ends with $ was created (4720). Computer accounts are created with 4741; a user account named this way hides among them.",
    "Disable the account and find out which process created it.");
const PRIV_GROUP: Rule = rule!("EVT-PRIVILEGED-GROUP", "high", "Member added to a privileged group", "T1098 Account Manipulation",
    "An account was added to an administrative group (4728, 4732 or 4756), such as Administrators or Domain Admins.",
    "Confirm the change was approved; remove the member otherwise and review what it did with these rights.");
const SERVICE_CMD: Rule = rule!("EVT-SERVICE-COMMAND", "high", "Service installed with a command line", "T1569.002 System Services: Service Execution",
    "A service was installed (7045 or 4697) whose program is a shell command, a script interpreter or a named pipe, as PsExec-style tools and privilege escalation kits do.",
    "Find out who installed the service, remove it, and check what it ran.");
const SERVICE_WRITABLE: Rule = rule!("EVT-SERVICE-WRITABLE-FOLDER", "medium", "Service or driver in a writable folder", "T1543.003 Create or Modify System Process: Windows Service",
    "A service or driver was installed (7045 or 4697) from a folder any user or process can write to, such as Temp, AppData or Users\\Public. Attackers load malicious or vulnerable drivers this way; some legitimate tools, such as hardware monitors, extract their driver there too.",
    "Check the file's signature and origin, and remove the service if it does not belong to a known tool.");
const SERVICE: Rule = rule!("EVT-SERVICE-INSTALLED", "low", "Service installed", "T1543.003 Create or Modify System Process: Windows Service",
    "A service was installed (7045 or 4697).",
    "Check that the installed software was expected.");
const TASK_CMD: Rule = rule!("EVT-TASK-COMMAND", "high", "Scheduled task runs a shell command", "T1053.005 Scheduled Task/Job: Scheduled Task",
    "A scheduled task was created (4698) to run a shell, script interpreter or a file in a writable folder; remote execution tools (for example Impacket's atexec) work this way.",
    "Delete the task if it is not known, and check what it ran and who created it.");
const TASK: Rule = rule!("EVT-TASK-CREATED", "medium", "Scheduled task created", "T1053.005 Scheduled Task/Job: Scheduled Task",
    "A scheduled task was created (4698).",
    "Check that the task belongs to known software.");
const ENCODED_PS: Rule = rule!("EVT-ENCODED-POWERSHELL", "high", "Encoded PowerShell command", "T1027 Obfuscated Files or Information",
    "PowerShell was started with a Base64-encoded command (-EncodedCommand), which hides what it runs.",
    "Decode the command and investigate the parent process.");
const DOWNLOAD: Rule = rule!("EVT-DOWNLOAD-COMMAND", "high", "Command downloads and runs code", "T1105 Ingress Tool Transfer",
    "A command line downloads content with built-in tools (PowerShell download cradles, certutil -urlcache, bitsadmin /transfer).",
    "Find what was downloaded and whether it ran; block the address.");
const PROXY_EXEC: Rule = rule!("EVT-PROXY-EXECUTION", "high", "Signed binary used to run remote or script content", "T1218 System Binary Proxy Execution",
    "mshta, regsvr32 or rundll32 was used to run a script or a remote file, a common way to slip past application control.",
    "Investigate the parent process and the loaded content.");
const CRED_DUMP: Rule = rule!("EVT-CREDENTIAL-DUMP", "high", "Credential dumping tools or commands", "T1003 OS Credential Dumping",
    "A command or script dumps credentials: LSASS memory (comsvcs MiniDump, procdump, MiniDumpWriteDump), Mimikatz, or the SAM, SECURITY and NTDS databases.",
    "Treat the credentials on this host as stolen: reset them, and isolate the host.");
const RECOVERY: Rule = rule!("EVT-RECOVERY-INHIBITED", "high", "Backups or shadow copies deleted", "T1490 Inhibit System Recovery",
    "Shadow copies, the backup catalog or boot recovery were deleted or disabled, which ransomware does before encrypting.",
    "Isolate the host at once and check other hosts for the same commands.");
const LOG_CLEAR_CMD: Rule = rule!("EVT-LOG-CLEAR-COMMAND", "high", "Command clears event logs", "T1070.001 Indicator Removal: Clear Windows Event Logs",
    "wevtutil cl or Clear-EventLog was run.",
    "Find out who ran it, and recover the logs from central collection.");
const WMI_CHILD: Rule = rule!("EVT-WMI-PROCESS", "medium", "Process started through WMI", "T1047 Windows Management Instrumentation",
    "WmiPrvSE.exe started a process, which is how remote WMI execution (wmic process call create, Impacket wmiexec) appears on the target.",
    "Check the logon that preceded it and whether the source host is expected to manage this one.");
const ACCOUNT_CMD: Rule = rule!("EVT-ACCOUNT-COMMAND", "medium", "Command adds a user or an administrator", "T1098 Account Manipulation",
    "net user /add or net localgroup administrators /add was run.",
    "Confirm the change was approved, and remove the account or membership otherwise.");
const PS_SCRIPT: Rule = rule!("EVT-SUSPICIOUS-SCRIPT", "high", "Suspicious PowerShell script block", "T1059.001 Command and Scripting Interpreter: PowerShell",
    "PowerShell script block logging (4104) recorded code that dumps credentials, disables AMSI, loads code in memory or downloads and runs content.",
    "Read the whole script block, find how it was started, and isolate the host if it ran.");
const PS_OBFUSCATED: Rule = rule!("EVT-OBFUSCATED-SCRIPT", "medium", "Obfuscated PowerShell script block", "T1027 Obfuscated Files or Information",
    "A script block (4104) is built from many concatenated string fragments, a common obfuscation of malicious PowerShell.",
    "Deobfuscate the script and check what it does.");
const LSASS: Rule = rule!("EVT-LSASS-ACCESS", "high", "LSASS memory opened for reading", "T1003.001 OS Credential Dumping: LSASS Memory",
    "A process opened lsass.exe with access rights that allow reading its memory (Sysmon 10), as credential dumpers do.",
    "Identify the process; treat the host's credentials as stolen.");
const DCSYNC: Rule = rule!("EVT-DCSYNC", "high", "Directory replication requested by an account", "T1003.006 OS Credential Dumping: DCSync",
    "An account that is not a domain controller used the directory replication rights (4662 with DS-Replication-Get-Changes), which DCSync uses to copy password hashes.",
    "Reset the krbtgt and affected passwords, and remove replication rights from accounts that do not need them.");
const KERBEROAST: Rule = rule!("EVT-KERBEROASTING", "medium", "Service tickets with RC4 encryption", "T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting",
    "Service tickets were requested with RC4 encryption (4769, type 0x17) for user service accounts; their passwords can then be cracked offline.",
    "Use AES for service accounts, give them long random passwords or group-managed accounts, and check the requesting accounts.");
const ASREP: Rule = rule!("EVT-ASREP-ROASTING", "medium", "Kerberos logon without pre-authentication", "T1558.004 Steal or Forge Kerberos Tickets: AS-REP Roasting",
    "A ticket was issued without pre-authentication (4768, type 0), so its response can be cracked offline.",
    "Turn on Kerberos pre-authentication for these accounts.");
const DEFENDER: Rule = rule!("EVT-DEFENDER-DETECTION", "high", "Microsoft Defender detected malware", "",
    "Microsoft Defender reported malware (1116) or acted on it (1117).",
    "Check that the threat was removed, and look for how it arrived.");
const DEFENDER_OFF: Rule = rule!("EVT-DEFENDER-DISABLED", "high", "Microsoft Defender protection turned off", "T1562.001 Impair Defenses: Disable or Modify Tools",
    "Real-time protection or scanning was disabled (5001, 5010, 5012).",
    "Turn protection back on, enable tamper protection, and find out who disabled it.");
const RUN_KEY: Rule = rule!("EVT-RUN-KEY", "medium", "Autostart registry value set", "T1547.001 Boot or Logon Autostart Execution: Registry Run Keys",
    "A Run, RunOnce or Winlogon value was written (Sysmon 13), which starts a program at every logon.",
    "Check that the program belongs to known software.");
const SERVICE_REG: Rule = rule!("EVT-SERVICE-REGISTRY", "high", "Service program set to a command line", "T1543.003 Create or Modify System Process: Windows Service",
    "A service's ImagePath was set to a shell or script command in the registry (Sysmon 13), as PsExec-style tools do.",
    "Find the service, remove it, and check what it ran.");
const REMOTE_THREAD: Rule = rule!("EVT-REMOTE-THREAD", "medium", "Thread created in another process", "T1055 Process Injection",
    "A process created a thread in another process (Sysmon 8), a step of code injection.",
    "Check whether the source process is a known tool; inspect the target process.");

/// Every rule, in the order detections are listed within a severity.
const RULES: &[&Rule] = &[
    &LOG_CLEARED, &AUDIT_POLICY, &GUESSING, &SPRAYING, &LOGON_AFTER, &RDP, &SERVER_CREDS, &REMOTE_CREDS, &ACCOUNT, &FAKE_MACHINE, &PRIV_GROUP, &SERVICE_CMD, &SERVICE_WRITABLE, &SERVICE, &TASK_CMD, &TASK, &ENCODED_PS, &DOWNLOAD, &PROXY_EXEC,
    &CRED_DUMP, &RECOVERY, &LOG_CLEAR_CMD, &WMI_CHILD, &ACCOUNT_CMD, &PS_SCRIPT, &PS_OBFUSCATED, &LSASS, &DCSYNC, &KERBEROAST, &ASREP, &DEFENDER, &DEFENDER_OFF, &RUN_KEY, &SERVICE_REG, &REMOTE_THREAD,
];

static ENCODED: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(powershell|pwsh)(\.exe)?\b.*\s[-/]e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}").expect("valid pattern"));
static DOWNLOADS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\s|start-bitstransfer|certutil(\.exe)?\s.*(-urlcache|-verifyctl)|bitsadmin(\.exe)?\s.*/transfer)").expect("valid pattern")
});
static PROXIES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(mshta(\.exe)?\s+["']?(https?:|javascript:|vbscript:)|regsvr32(\.exe)?\s.*/i:\s*["']?https?:|regsvr32(\.exe)?\s.*scrobj|rundll32(\.exe)?\s.*(javascript:|url\.dll|shell32\.dll,\s*shellexec_rundll))"#).expect("valid pattern")
});
static DUMPS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(comsvcs(\.dll)?[\s,]+(#\s*24|minidump)|procdump(64)?(\.exe)?\s.*-ma\s.*lsass|sekurlsa::|lsadump::|invoke-mimikatz|\bmimikatz\b|minidumpwritedump|reg(\.exe)?\s+(save|export)\s+hklm\\(sam|security|system)\b|ntdsutil.*\b(ifm|create full)\b)").expect("valid pattern")
});
static RECOVERY_CMD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?\s.*recoveryenabled\s+no|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup))").expect("valid pattern")
});
static CLEAR_CMD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog)").expect("valid pattern"));
static ACCOUNT_ADD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bnet1?(\.exe)?\s+(user\s+\S+\s+\S*\s*/add|localgroup\s+administrators\s+\S+\s+/add)").expect("valid pattern"));
static SCRIPT_BAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(invoke-mimikatz|sekurlsa|minidumpwritedump|get-process\s+lsass|amsiutils|amsiinitfailed|reflection\.assembly\]::load|getdelegateforfunctionpointer|virtualalloc|invoke-shellcode|powersploit|(iex|invoke-expression).{0,80}(downloadstring|net\.webclient)|downloadstring|net\.webclient)").expect("valid pattern")
});
/// a command in a service or task: a shell, a script interpreter, a pipe, a remote admin share
static COMMANDISH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(^"?(cmd|%comspec%)(\.exe)?"?(\s|$)|\\cmd(\.exe)?"?\s+/[ck]\b|%comspec%|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|\\\\\.\\pipe\\|\\\\127\.0\.0\.1\\|\\admin\$|psexesvc|\.(bat|cmd|ps1|vbs|js|hta)\b)"#).expect("valid pattern")
});
/// a program in a folder any user or process can write to
static WRITABLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\\(windows\\temp|temp|appdata|users\\public)\\").expect("valid pattern"));

const SERVER_PROCESSES: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "tomcat.exe", "tomcat9.exe", "java.exe", "sqlservr.exe", "beasvc.exe"];
/// access masks that let a process read LSASS memory (Sysmon writes them with or without leading zeroes)
const LSASS_ACCESS: &[u64] = &[0x1010, 0x1410, 0x1418, 0x1438, 0x143a, 0x1f0fff, 0x1f1fff, 0x1f3fff, 0x1fffff, 0x40];
const LSASS_OK: &[&str] = &["\\csrss.exe", "\\wininit.exe", "\\msmpeng.exe", "\\lsm.exe", "\\services.exe", "\\svchost.exe", "\\wmiprvse.exe", "\\taskmgr.exe", "\\mrt.exe"];
const REPLICATION: &[&str] = &["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"];
/// Administrators, Account/Server/Print/Backup Operators (BUILTIN); Domain, Schema and Enterprise Admins (domain RIDs)
const PRIV_SIDS: &[&str] = &["S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"];
const PRIV_RIDS: &[&str] = &["-512", "-518", "-519"];
const PRIV_NAMES: &[&str] = &["administrators", "domain admins", "enterprise admins", "schema admins", "account operators", "backup operators", "server operators", "print operators", "dnsadmins", "group policy creator owners"];

#[derive(Default)]
struct Hits {
    count: u64,
    /// source → (count, examples)
    by: BTreeMap<String, (u64, Vec<String>)>,
}

#[derive(Default)]
struct State {
    hits: HashMap<&'static str, Hits>,
    failures: HashMap<String, u64>,
    failed_accounts: HashMap<String, BTreeSet<String>>,
    failure_examples: HashMap<String, Vec<String>>,
    rc4: HashMap<String, BTreeSet<String>>,
    rc4_examples: HashMap<String, Vec<String>>,
    counts: HashMap<(u32, String), u64>,
    /// process images by (computer, process ID), for 4688 events that name no parent
    procs: HashMap<(String, u64), String>,
    /// processes linked to their parents (Mission 6)
    tree: crate::sectools::proc_chains::Tree,
    /// logons per account (Mission 6)
    logons: HashMap<String, Logons>,
    computers: BTreeSet<String>,
    first: String,
    last: String,
}

#[derive(Default)]
struct Logons {
    shown: String,
    logons: u64,
    failures: u64,
    types: BTreeMap<String, u64>,
    sources: HashMap<String, u64>,
    first: String,
    last: String,
}

/// Service identities that log on all the time; the summary is about people and service accounts.
fn system_identity(user: &str) -> bool {
    let u = user.to_ascii_uppercase();
    user.ends_with('$') || user.is_empty() || user == "-" || matches!(u.as_str(), "SYSTEM" | "LOCAL SERVICE" | "NETWORK SERVICE" | "ANONYMOUS LOGON") || u.starts_with("DWM-") || u.starts_with("UMFD-")
}

fn short(s: &str, n: usize) -> String {
    let s = s.replace(['\r', '\n', '\t'], " ");
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s
    }
}

fn account(domain: &str, user: &str) -> String {
    match (domain.trim(), user.trim()) {
        ("" | "-", u) => u.to_string(),
        (d, u) => format!("{d}\\{u}"),
    }
}

/// "0x0000000000000ae8", "0x1010" or "1010" as a number.
fn hexnum(s: &str) -> Option<u64> {
    let t = s.trim();
    u64::from_str_radix(t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t), 16).ok()
}

fn file_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_ascii_lowercase()
}

impl State {
    fn logon(&mut self, ev: &Event, ok: bool) {
        let g = |k: &str| ev.get(k);
        let user = g("TargetUserName");
        if system_identity(user) {
            return;
        }
        let shown = account(g("TargetDomainName"), user);
        let key = shown.to_ascii_lowercase();
        if self.logons.len() >= MAX_KEYS && !self.logons.contains_key(&key) {
            return;
        }
        let l = self.logons.entry(key).or_default();
        if l.shown.is_empty() {
            l.shown = shown;
        }
        if ok {
            l.logons += 1;
            *l.types.entry(g("LogonType").to_string()).or_default() += 1;
        } else {
            l.failures += 1;
        }
        let source = [g("IpAddress"), g("WorkstationName")].into_iter().find(|s| !s.is_empty() && *s != "-").unwrap_or("local");
        if l.sources.len() < 200 || l.sources.contains_key(source) {
            *l.sources.entry(source.to_string()).or_default() += 1;
        }
        if !ev.time.is_empty() {
            if l.first.is_empty() || ev.time < l.first {
                l.first = ev.time.clone();
            }
            if ev.time > l.last {
                l.last = ev.time.clone();
            }
        }
    }

    fn hit(&mut self, rule: &Rule, who: &str, ev: &Event, what: &str) {
        let h = self.hits.entry(rule.id).or_default();
        h.count += 1;
        let who = if who.trim().is_empty() || who.trim() == "-" { ev.computer.clone() } else { who.trim().to_string() };
        if h.by.len() >= MAX_KEYS && !h.by.contains_key(&who) {
            return;
        }
        let e = h.by.entry(who).or_default();
        e.0 += 1;
        if e.1.len() < EXAMPLES {
            e.1.push(example(ev, what));
        }
    }

    fn event(&mut self, ev: &Event) {
        if !ev.time.is_empty() {
            if self.first.is_empty() || ev.time < self.first {
                self.first = ev.time.clone();
            }
            if ev.time > self.last {
                self.last = ev.time.clone();
            }
        }
        if self.computers.len() < 50 && !ev.computer.is_empty() {
            self.computers.insert(ev.computer.clone());
        }
        if self.counts.len() < MAX_KEYS || self.counts.contains_key(&(ev.event_id, ev.channel.clone())) {
            *self.counts.entry((ev.event_id, ev.channel.clone())).or_default() += 1;
        }
        let channel = ev.channel.to_ascii_lowercase();
        let provider = ev.provider.to_ascii_lowercase();
        let sysmon = channel.contains("sysmon");
        let g = |k: &str| ev.get(k);
        match (ev.event_id, channel.as_str()) {
            (1102, "security") | (104, "system") if provider.contains("eventlog") || provider.is_empty() => {
                let who = account(g("SubjectDomainName"), g("SubjectUserName"));
                let log = if ev.event_id == 104 { format!("{} log", if g("Channel").is_empty() { "System" } else { g("Channel") }) } else { "Security log".into() };
                self.hit(&LOG_CLEARED, &who, ev, &format!("{log} cleared by {who}"));
            }
            (4719, "security") => self.hit(&AUDIT_POLICY, &account(g("SubjectDomainName"), g("SubjectUserName")), ev, &format!("audit policy changed: {} {}", g("CategoryId"), g("AuditPolicyChanges"))),
            (4625, "security") => {
                self.logon(ev, false);
                let source = [g("IpAddress"), g("WorkstationName")].into_iter().find(|s| !s.is_empty() && *s != "-" && *s != "::1" && *s != "127.0.0.1").unwrap_or("local").to_string();
                if self.failures.len() < MAX_KEYS || self.failures.contains_key(&source) {
                    *self.failures.entry(source.clone()).or_default() += 1;
                    let accounts = self.failed_accounts.entry(source.clone()).or_default();
                    if accounts.len() < 1000 {
                        accounts.insert(account(g("TargetDomainName"), g("TargetUserName")).to_ascii_lowercase());
                    }
                    let ex = self.failure_examples.entry(source).or_default();
                    if ex.len() < EXAMPLES {
                        ex.push(example(ev, &format!("failed logon for {} (type {}, status {})", account(g("TargetDomainName"), g("TargetUserName")), g("LogonType"), g("SubStatus"))));
                    }
                }
            }
            (4624, "security") => {
                self.logon(ev, true);
                let ip = g("IpAddress");
                let user = account(g("TargetDomainName"), g("TargetUserName"));
                if !ip.is_empty() && ip != "-" && self.failures.get(ip).copied().unwrap_or(0) >= 5 && !g("TargetUserName").ends_with('$') {
                    let n = self.failures[ip];
                    self.hit(&LOGON_AFTER, ip, ev, &format!("{user} logged on (type {}) after {n} failures from {ip}", g("LogonType")));
                }
                if g("LogonType") == "10" {
                    self.hit(&RDP, &format!("{user} from {ip}"), ev, &format!("Remote Desktop logon of {user} from {ip}"));
                }
            }
            (4648, "security") => {
                let process = file_of(g("ProcessName"));
                let target = g("TargetServerName");
                let user = account(g("TargetDomainName"), g("TargetUserName"));
                if SERVER_PROCESSES.contains(&process.as_str()) {
                    self.hit(&SERVER_CREDS, &process, ev, &format!("{process} logged on as {user} (run by {})", g("SubjectUserName")));
                } else if !target.is_empty() && !target.eq_ignore_ascii_case("localhost") && target != "-" && !ev.computer.to_ascii_lowercase().starts_with(&target.to_ascii_lowercase()) {
                    self.hit(&REMOTE_CREDS, &format!("{} → {target}", g("SubjectUserName")), ev, &format!("{} used the credentials of {user} for {target} ({process})", g("SubjectUserName")));
                }
            }
            (4720, "security") => {
                let name = g("TargetUserName");
                let who = account(g("SubjectDomainName"), g("SubjectUserName"));
                let rule = if name.ends_with('$') { &FAKE_MACHINE } else { &ACCOUNT };
                self.hit(rule, &who, ev, &format!("{who} created the account {}", account(g("TargetDomainName"), name)));
            }
            (4728 | 4732 | 4756, "security") => {
                let sid = g("TargetSid");
                let group = g("TargetUserName");
                if PRIV_SIDS.contains(&sid) || PRIV_RIDS.iter().any(|r| sid.starts_with("S-1-5-21-") && sid.ends_with(r)) || PRIV_NAMES.contains(&group.to_ascii_lowercase().as_str()) {
                    let member = [g("MemberName"), g("MemberSid")].into_iter().find(|s| !s.is_empty() && *s != "-").unwrap_or("?");
                    self.hit(&PRIV_GROUP, group, ev, &format!("{} added {member} to {group}", g("SubjectUserName")));
                }
            }
            (7045, "system") | (4697, "security") => {
                let path = if ev.event_id == 7045 { g("ImagePath") } else { g("ServiceFileName") };
                let name = g("ServiceName");
                let rule = if COMMANDISH.is_match(path) {
                    &SERVICE_CMD
                } else if WRITABLE.is_match(path) {
                    &SERVICE_WRITABLE
                } else {
                    &SERVICE
                };
                self.hit(rule, name, ev, &format!("service {name}: {path}"));
            }
            (4698, "security") => {
                let content = g("TaskContent");
                let command: String = content.split("<Command>").nth(1).and_then(|c| c.split("</Command>").next()).map(|c| format!("{c} {}", content.split("<Arguments>").nth(1).and_then(|a| a.split("</Arguments>").next()).unwrap_or(""))).unwrap_or_default();
                let rule = if COMMANDISH.is_match(&command) || WRITABLE.is_match(&command) { &TASK_CMD } else { &TASK };
                self.hit(rule, &account(g("SubjectDomainName"), g("SubjectUserName")), ev, &format!("task {}: {}", g("TaskName"), command.trim()));
            }
            (4688, "security") => {
                let image = g("NewProcessName");
                if let Some(pid) = hexnum(g("NewProcessId")) {
                    if self.procs.len() < MAX_KEYS {
                        self.procs.insert((ev.computer.clone(), pid), image.to_string());
                    }
                }
                // Windows before 10 names no parent: the creator's process ID leads to it
                let parent = match g("ParentProcessName") {
                    "" => hexnum(g("ProcessId")).and_then(|p| self.procs.get(&(ev.computer.clone(), p))).cloned().unwrap_or_default(),
                    p => p.to_string(),
                };
                // the new process's account (Windows 10 and later), else the creator's
                let user = if g("TargetUserName").is_empty() || g("TargetUserName") == "-" { account(g("SubjectDomainName"), g("SubjectUserName")) } else { account(g("TargetDomainName"), g("TargetUserName")) };
                let pid = hexnum(g("NewProcessId")).map(|p| p.to_string()).unwrap_or_default();
                let creator = hexnum(g("ProcessId")).map(|p| p.to_string()).unwrap_or_default();
                self.tree.add(crate::sectools::proc_chains::Start { computer: &ev.computer, time: &ev.time, record: ev.record_id, event_id: 4688, key: pid.clone(), parent_key: creator, parent_image: &parent, parent_command: "", pid, image, command: g("CommandLine"), user: &user });
                self.process(ev, image, g("CommandLine"), &parent, &account(g("SubjectDomainName"), g("SubjectUserName")));
            }
            (1, _) if sysmon => {
                self.tree.add(crate::sectools::proc_chains::Start {
                    computer: &ev.computer,
                    time: &ev.time,
                    record: ev.record_id,
                    event_id: 1,
                    key: g("ProcessGuid").to_ascii_lowercase(),
                    parent_key: g("ParentProcessGuid").to_ascii_lowercase(),
                    parent_image: g("ParentImage"),
                    parent_command: g("ParentCommandLine"),
                    pid: g("ProcessId").to_string(),
                    image: g("Image"),
                    command: g("CommandLine"),
                    user: g("User"),
                });
                self.process(ev, g("Image"), g("CommandLine"), g("ParentImage"), g("User"))
            }
            (4104, _) if channel.contains("powershell") => {
                let text = g("ScriptBlockText");
                let path = if g("Path").is_empty() { "interactive" } else { g("Path") };
                if let Some(m) = SCRIPT_BAD.find(text) {
                    let rule = if DUMPS.is_match(text) || text.to_ascii_lowercase().contains("get-process lsass") { &CRED_DUMP } else { &PS_SCRIPT };
                    self.hit(rule, path, ev, &format!("script block with {}: {}", m.as_str(), short(text, 160)));
                } else if text.matches("'+'").count() + text.matches("\"+\"").count() >= 5 {
                    self.hit(&PS_OBFUSCATED, path, ev, &format!("script block: {}", short(text, 160)));
                }
            }
            (10, _) if sysmon => {
                let target = g("TargetImage").to_ascii_lowercase();
                let source = g("SourceImage");
                let access = g("GrantedAccess");
                if target.ends_with("\\lsass.exe") && hexnum(access).is_some_and(|a| LSASS_ACCESS.contains(&a)) && !LSASS_OK.iter().any(|ok| source.to_ascii_lowercase().ends_with(ok)) {
                    self.hit(&LSASS, source, ev, &format!("{source} opened lsass.exe with access {access}"));
                }
            }
            (13, _) if sysmon => {
                let key = g("TargetObject");
                let lower = key.to_ascii_lowercase();
                let details = g("Details");
                if lower.contains("\\currentversion\\run") || lower.ends_with("\\winlogon\\userinit") || lower.ends_with("\\winlogon\\shell") {
                    self.hit(&RUN_KEY, g("Image"), ev, &format!("{key} = {details}"));
                } else if lower.contains("\\services\\") && lower.ends_with("\\imagepath") && COMMANDISH.is_match(details) {
                    self.hit(&SERVICE_REG, g("Image"), ev, &format!("{key} = {details}"));
                }
            }
            (8, _) if sysmon => {
                let (source, target) = (g("SourceImage"), g("TargetImage"));
                if !source.eq_ignore_ascii_case(target) {
                    self.hit(&REMOTE_THREAD, source, ev, &format!("{source} created a thread in {target}"));
                }
            }
            (4662, "security") => {
                let props = g("Properties").to_ascii_lowercase();
                let user = g("SubjectUserName");
                if REPLICATION.iter().any(|guid| props.contains(guid)) && !user.ends_with('$') {
                    self.hit(&DCSYNC, &account(g("SubjectDomainName"), user), ev, &format!("{user} used directory replication rights"));
                }
            }
            (4769, "security") => {
                let enc = g("TicketEncryptionType").to_ascii_lowercase();
                let service = g("ServiceName");
                if (enc == "0x17" || enc == "23") && !service.ends_with('$') && !service.eq_ignore_ascii_case("krbtgt") {
                    let who = g("TargetUserName").to_string();
                    if self.rc4.len() < MAX_KEYS || self.rc4.contains_key(&who) {
                        let services = self.rc4.entry(who.clone()).or_default();
                        if services.len() < 1000 {
                            services.insert(service.to_string());
                        }
                        let ex = self.rc4_examples.entry(who).or_default();
                        if ex.len() < EXAMPLES {
                            ex.push(example(ev, &format!("RC4 ticket for {service} from {}", g("IpAddress"))));
                        }
                    }
                }
            }
            (4768, "security") if g("PreAuthType") == "0" => self.hit(&ASREP, g("TargetUserName"), ev, &format!("ticket for {} without pre-authentication, from {}", g("TargetUserName"), g("IpAddress"))),
            (1116 | 1117, _) if provider.contains("defender") => {
                let threat = [g("Threat Name"), g("ThreatName")].into_iter().find(|s| !s.is_empty()).unwrap_or("unknown threat");
                self.hit(&DEFENDER, threat, ev, &format!("{threat} in {}", g("Path")));
            }
            (5001 | 5010 | 5012, _) if provider.contains("defender") => self.hit(&DEFENDER_OFF, &ev.computer, ev, &format!("Defender event {}", ev.event_id)),
            _ => {}
        }
    }

    /// Process creation (4688 or Sysmon 1).
    fn process(&mut self, ev: &Event, image: &str, command: &str, parent: &str, user: &str) {
        let line = if command.is_empty() { image } else { command };
        let shown = short(line, 200);
        let who = if user.is_empty() { file_of(image) } else { user.to_string() };
        if ENCODED.is_match(line) {
            self.hit(&ENCODED_PS, &who, ev, &shown);
        }
        if DOWNLOADS.is_match(line) {
            self.hit(&DOWNLOAD, &who, ev, &shown);
        }
        if PROXIES.is_match(line) {
            self.hit(&PROXY_EXEC, &who, ev, &shown);
        }
        if DUMPS.is_match(line) {
            self.hit(&CRED_DUMP, &who, ev, &shown);
        }
        if RECOVERY_CMD.is_match(line) {
            self.hit(&RECOVERY, &who, ev, &shown);
        }
        if CLEAR_CMD.is_match(line) {
            self.hit(&LOG_CLEAR_CMD, &who, ev, &shown);
        }
        if ACCOUNT_ADD.is_match(line) {
            self.hit(&ACCOUNT_CMD, &who, ev, &shown);
        }
        if file_of(parent) == "wmiprvse.exe" && file_of(image) != "wmiprvse.exe" {
            self.hit(&WMI_CHILD, &who, ev, &format!("WmiPrvSE.exe started {shown}"));
        }
    }

    fn finish(mut self, summary: &evtx::Summary) -> Report {
        // per-source thresholds
        let failures = std::mem::take(&mut self.failures);
        for (source, n) in failures {
            let accounts = self.failed_accounts.get(&source).map(BTreeSet::len).unwrap_or(0);
            let rule = if accounts >= 5 { &SPRAYING } else if n >= 10 { &GUESSING } else { continue };
            let h = self.hits.entry(rule.id).or_default();
            h.count += n;
            let examples = self.failure_examples.remove(&source).unwrap_or_default();
            h.by.insert(format!("{source} ({accounts} accounts)"), (n, examples));
        }
        let rc4 = std::mem::take(&mut self.rc4);
        for (who, services) in rc4 {
            let h = self.hits.entry(KERBEROAST.id).or_default();
            h.count += services.len() as u64;
            h.by.insert(format!("{who} ({} services)", services.len()), (services.len() as u64, self.rc4_examples.remove(&who).unwrap_or_default()));
        }
        let mut detections: Vec<Detection> = Vec::new();
        for r in RULES {
            let Some(h) = self.hits.remove(r.id) else { continue };
            let mut severity = r.severity;
            // many service tickets from one account is the shape of a Kerberoasting run
            if r.id == KERBEROAST.id && h.by.values().any(|(n, _)| *n >= 5) {
                severity = "high";
            }
            let mut sources: Vec<Source> = h.by.into_iter().map(|(ip, (count, examples))| Source { ip, count, examples: examples.into_iter().map(|e| crate::redact::redact_text(&e)).collect() }).collect();
            sources.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
            sources.truncate(20);
            detections.push(Detection { rule: r.id.into(), severity: severity.into(), title: r.title.into(), detail: r.detail.into(), remediation: r.remediation.into(), count: h.count, sources, technique: r.technique.into() });
        }
        detections.sort_by_key(|d| ["critical", "high", "medium", "low", "info"].iter().position(|s| *s == d.severity).unwrap_or(5));
        let mut events: Vec<EventCount> = self.counts.into_iter().map(|((id, channel), count)| EventCount { name: event_name(id, &channel).to_string(), id, channel, count }).collect();
        events.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
        events.truncate(40);
        let mut warnings = Vec::new();
        if summary.damaged_chunks > 0 || summary.damaged_records > 0 {
            warnings.push(format!("{} damaged chunks and {} damaged records were skipped", summary.damaged_chunks, summary.damaged_records));
        }
        if summary.records >= MAX_EVENTS {
            warnings.push(format!("Only the first {MAX_EVENTS} events were read"));
        }
        let tree = std::mem::take(&mut self.tree);
        if tree.dropped > 0 {
            warnings.push(format!("{} process starts past the first 100,000 were not linked into chains", tree.dropped));
        }
        if tree.unreported > 0 {
            warnings.push(format!("{} more flagged process relationships are not listed (50 per pattern, 200 in all)", tree.unreported));
        }
        let chains = tree.finish();
        let mut logons: Vec<AccountLogons> = std::mem::take(&mut self.logons)
            .into_values()
            .map(|l| {
                let mut sources: Vec<(String, u64)> = l.sources.into_iter().collect();
                sources.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                sources.truncate(5);
                AccountLogons { account: l.shown, logons: l.logons, failures: l.failures, types: l.types.into_iter().collect(), sources, first: l.first, last: l.last }
            })
            .collect();
        logons.sort_by(|a, b| (b.logons + b.failures).cmp(&(a.logons + a.failures)).then_with(|| a.account.cmp(&b.account)));
        if logons.len() > 100 {
            warnings.push(format!("Logons per account: the 100 busiest of {} accounts are listed", logons.len()));
        }
        logons.truncate(100);
        Report {
            kind: "windows".into(),
            lines: summary.records + summary.damaged_records,
            recognised: summary.records,
            first: self.first,
            last: self.last,
            clients: Vec::new(),
            detections,
            warnings,
            events,
            computers: self.computers.into_iter().collect(),
            chains,
            logons,
        }
    }
}

fn example(ev: &Event, what: &str) -> String {
    short(&format!("{} · {} · event {} · record {} · {what}", ev.time.get(..19).unwrap_or(&ev.time), ev.computer, ev.event_id, ev.record_id), 400)
}

/// What a well-known event ID means.
fn event_name(id: u32, channel: &str) -> &'static str {
    let c = channel.to_ascii_lowercase();
    if c.contains("sysmon") {
        return match id {
            1 => "Process created",
            3 => "Network connection",
            7 => "Image loaded",
            8 => "Remote thread created",
            10 => "Process accessed",
            11 => "File created",
            12..=14 => "Registry changed",
            22 => "DNS query",
            _ => "",
        };
    }
    match (id, c.as_str()) {
        (4624, _) => "Logon",
        (4625, _) => "Failed logon",
        (4634 | 4647, _) => "Logoff",
        (4648, _) => "Logon with explicit credentials",
        (4662, _) => "Directory object accessed",
        (4663, _) => "Object accessed",
        (4672, _) => "Special privileges at logon",
        (4688, _) => "Process created",
        (4697, _) => "Service installed",
        (4698, _) => "Scheduled task created",
        (4699, _) => "Scheduled task deleted",
        (4702, _) => "Scheduled task updated",
        (4719, _) => "Audit policy changed",
        (4720, _) => "User account created",
        (4722, _) => "User account enabled",
        (4724, _) => "Password reset",
        (4728 | 4732 | 4756, _) => "Member added to a group",
        (4740, _) => "Account locked out",
        (4768, _) => "Kerberos ticket (TGT) requested",
        (4769, _) => "Kerberos service ticket requested",
        (4776, _) => "NTLM authentication",
        (5140 | 5145, _) => "Network share accessed",
        (5156, _) => "Network connection allowed",
        (1102, _) => "Security log cleared",
        (104, "system") => "Event log cleared",
        (7045, _) => "Service installed",
        (7036, _) => "Service state changed",
        (7040, _) => "Service start type changed",
        (4104, _) => "PowerShell script block",
        (4103, _) => "PowerShell pipeline",
        (1116, _) => "Malware detected",
        (1117, _) => "Malware action taken",
        (5001, _) => "Real-time protection disabled",
        _ => "",
    }
}

/// Reads an EVTX file and runs the detections.
pub fn analyze(input: impl Read) -> Result<Report, String> {
    let mut state = State::default();
    let mut seen = 0u64;
    let summary = evtx::read(input, |ev| {
        seen += 1;
        if seen <= MAX_EVENTS {
            state.event(&ev);
        }
    })?;
    if summary.records == 0 {
        return Err("No events could be read from this file".into());
    }
    Ok(state.finish(&summary))
}

#[cfg(test)]
#[path = "winevents_tests.rs"]
mod tests;
