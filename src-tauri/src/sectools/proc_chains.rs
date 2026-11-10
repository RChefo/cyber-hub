//! Process chains in Windows event logs (Mission 6): processes from Security 4688 and Sysmon 1
//! linked to their parents, and a few parent → child relationships that are rare in normal use.
//!
//! What a chain reports is kept apart, as the findings recorded from it are:
//! * **observed**: the processes, each with its time, event record, process ID, program, command
//!   line and user, exactly as the log has them (command lines cut to 400 characters);
//! * **derived**: the pattern that flagged the relationship and why it is unusual;
//! * **hypotheses**: what it may mean, including the ordinary explanations to rule out.
//!
//! A technique is named only when the relationship itself is the technique's behaviour (a web
//! server starting a shell is how a web shell runs). Nothing here confirms anything: a chain is a
//! lead, recorded as a finding under review only when the analyst chooses to.

use std::collections::HashMap;

use serde::Serialize;

/// Processes kept from one log; further ones are counted.
const MAX_PROCS: usize = 100_000;
/// Children remembered per process.
const MAX_CHILDREN: usize = 50;
/// Chains reported per pattern, and in all.
const MAX_PER_PATTERN: usize = 50;
const MAX_CHAINS: usize = 200;
const ANCESTORS: usize = 5;
const DESCENDANTS: usize = 25;
const COMMAND: usize = 400;

/// Programs that run commands or scripts, or are commonly used to.
const SHELLS: &[&str] = &[
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "schtasks.exe", "bash.exe", "wsl.exe",
];
/// Discovery commands an intruder runs first.
const RECON: &[&str] = &["whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "nltest.exe", "tasklist.exe", "quser.exe", "hostname.exe", "netstat.exe", "arp.exe", "route.exe"];
const OFFICE: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe"];
const WEB_SERVERS: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "php.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe", "tomcat10.exe", "beasvc.exe", "umworkerprocess.exe"];

struct Pattern {
    id: &'static str,
    title: &'static str,
    severity: &'static str,
    technique: &'static str,
    why: &'static str,
    hypotheses: &'static str,
    parents: &'static [&'static str],
    /// empty: any child
    children: &'static [&'static [&'static str]],
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        id: "CHAIN-OFFICE-SHELL",
        title: "Office application started a shell or script host",
        severity: "high",
        technique: "T1204.002 User Execution: Malicious File",
        why: "A document application started a program that runs commands or scripts. Opening a document does not do this; a macro, an embedded object or an exploit does.",
        hypotheses: "A document ran code: find the document on the Office command line and what the started program did next (below). Rule out add-ins and IT macros that call scripts: check who wrote the macro and the command line.",
        parents: OFFICE,
        children: &[SHELLS],
    },
    Pattern {
        id: "CHAIN-WEB-SERVER-SHELL",
        title: "Web server process started a shell or a discovery command",
        severity: "high",
        technique: "T1505.003 Server Software Component: Web Shell",
        why: "A web server worker started a command interpreter or a discovery command. Web applications rarely need one; a web shell or a command injection does.",
        hypotheses: "A request ran commands on the server: match the time with the web server's access log and look for the file it requested. Rule out applications that call command-line tools by design (document converters, backup scripts): their command lines repeat the same tool.",
        parents: WEB_SERVERS,
        children: &[SHELLS, RECON],
    },
    Pattern {
        id: "CHAIN-SQL-SERVER-SHELL",
        title: "SQL Server started a shell or a discovery command",
        severity: "high",
        technique: "T1505.001 Server Software Component: SQL Stored Procedures",
        why: "sqlservr.exe started a command interpreter or a discovery command, which is what xp_cmdshell does.",
        hypotheses: "Someone with sysadmin rights ran operating-system commands through the database (xp_cmdshell, often after a SQL injection). Rule out maintenance jobs that use xp_cmdshell: they run on a schedule with the same command.",
        parents: &["sqlservr.exe"],
        children: &[SHELLS, RECON],
    },
    Pattern {
        id: "CHAIN-SERVICE-SHELL",
        title: "Service Control Manager started a shell",
        severity: "medium",
        technique: "T1569.002 System Services: Service Execution",
        why: "services.exe started a command interpreter directly: the service's program is a command line, as remote execution tools create it.",
        hypotheses: "A service was created to run a command, as PsExec, Impacket and many intrusion tools do: look for the service installation (System 7045, Security 4697) just before. Rule out software deployment and management agents that install such services.",
        parents: &["services.exe"],
        children: &[&["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]],
    },
    Pattern {
        id: "CHAIN-WMI-SHELL",
        title: "WMI provider host started a shell",
        severity: "medium",
        technique: "T1047 Windows Management Instrumentation",
        why: "WmiPrvSE.exe started a command interpreter: a process was created through WMI, locally or from another computer.",
        hypotheses: "Remote execution over WMI (wmic /node, Impacket wmiexec, management scripts). Look for a network logon (4624 type 3) of the same account just before. Rule out monitoring and management agents.",
        parents: &["wmiprvse.exe"],
        children: &[SHELLS],
    },
    Pattern {
        id: "CHAIN-LSASS-CHILD",
        title: "LSASS started a process",
        severity: "high",
        technique: "",
        why: "lsass.exe, which holds credentials, almost never starts other programs.",
        hypotheses: "Code running inside LSASS (a malicious authentication or password-filter package, or an exploit) started a program. Check the packages registered under the LSA registry keys and the program's location and signer.",
        parents: &["lsass.exe"],
        children: &[],
    },
];

/// One process of a chain, as the log has it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainProcess {
    /// ancestor, flagged or descendant
    pub role: String,
    /// generations from the flagged process (negative for its ancestors)
    pub depth: i32,
    pub time: String,
    /// the event record that started it (0 when the log does not have it)
    pub record: u64,
    /// 4688 or 1 (Sysmon); 0 for a parent known only by name
    pub event_id: u32,
    pub pid: String,
    pub image: String,
    pub command_line: String,
    pub user: String,
}

/// A flagged parent → child relationship with the processes around it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessChain {
    pub pattern: String,
    pub title: String,
    pub severity: String,
    /// the ATT&CK technique the relationship itself shows, or empty
    #[serde(skip_serializing_if = "String::is_empty")]
    pub technique: String,
    /// derived: why the relationship was flagged
    pub why: String,
    /// what it may mean, including the ordinary explanations to rule out
    pub hypotheses: String,
    pub computer: String,
    /// observed: ancestors (oldest first), the flagged process, then what it started
    pub processes: Vec<ChainProcess>,
}

struct Proc {
    computer: String,
    time: String,
    record: u64,
    event_id: u32,
    pid: String,
    image: String,
    command: String,
    user: String,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// A process start as read from an event.
pub struct Start<'a> {
    pub computer: &'a str,
    pub time: &'a str,
    pub record: u64,
    pub event_id: u32,
    /// the process's own key: its Sysmon GUID, or its process ID for 4688
    pub key: String,
    /// the parent's key, when the event names one
    pub parent_key: String,
    pub parent_image: &'a str,
    pub parent_command: &'a str,
    pub pid: String,
    pub image: &'a str,
    pub command: &'a str,
    pub user: &'a str,
}

#[derive(Default)]
pub struct Tree {
    procs: Vec<Proc>,
    /// (computer, key) → the latest process with that key (process IDs are reused)
    latest: HashMap<(String, String), usize>,
    flagged: Vec<(usize, usize)>,
    per_pattern: HashMap<usize, usize>,
    /// processes past MAX_PROCS, and flagged relationships past the limits
    pub dropped: u64,
    pub unreported: u64,
}

fn file_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).trim().to_ascii_lowercase()
}

fn cut(s: &str) -> String {
    let s = s.trim();
    match s.char_indices().nth(COMMAND) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

impl Tree {
    pub fn add(&mut self, s: Start) {
        if self.procs.len() >= MAX_PROCS {
            self.dropped += 1;
            return;
        }
        let computer = s.computer.to_string();
        let mut parent = (!s.parent_key.is_empty()).then(|| self.latest.get(&(computer.clone(), s.parent_key.clone())).copied()).flatten();
        // a parent that started before the log begins is known only by the name the event gives
        if parent.is_none() && !s.parent_image.is_empty() {
            let idx = self.procs.len();
            self.procs.push(Proc { computer: computer.clone(), time: String::new(), record: 0, event_id: 0, pid: String::new(), image: s.parent_image.to_string(), command: cut(s.parent_command), user: String::new(), parent: None, children: Vec::new() });
            if !s.parent_key.is_empty() {
                self.latest.insert((computer.clone(), s.parent_key.clone()), idx);
            }
            parent = Some(idx);
        }
        let idx = self.procs.len();
        self.procs.push(Proc { computer: computer.clone(), time: s.time.to_string(), record: s.record, event_id: s.event_id, pid: s.pid, image: s.image.to_string(), command: cut(s.command), user: s.user.to_string(), parent, children: Vec::new() });
        if !s.key.is_empty() {
            self.latest.insert((computer, s.key), idx);
        }
        let Some(p) = parent else { return };
        if self.procs[p].children.len() < MAX_CHILDREN {
            self.procs[p].children.push(idx);
        }
        // the parent's name: the event's, or the linked process's
        let parent_name = if s.parent_image.is_empty() { file_of(&self.procs[p].image) } else { file_of(s.parent_image) };
        let child = file_of(s.image);
        for (i, pat) in PATTERNS.iter().enumerate() {
            let parent_ok = pat.parents.contains(&parent_name.as_str());
            let child_ok = pat.children.is_empty() || pat.children.iter().any(|list| list.contains(&child.as_str()));
            if !(parent_ok && child_ok) {
                continue;
            }
            let n = self.per_pattern.entry(i).or_default();
            if *n >= MAX_PER_PATTERN || self.flagged.len() >= MAX_CHAINS {
                self.unreported += 1;
            } else {
                *n += 1;
                self.flagged.push((idx, i));
            }
            break;
        }
    }

    fn row(&self, i: usize, role: &str, depth: i32) -> ChainProcess {
        let p = &self.procs[i];
        ChainProcess {
            role: role.into(),
            depth,
            time: p.time.clone(),
            record: p.record,
            event_id: p.event_id,
            pid: p.pid.clone(),
            image: p.image.clone(),
            command_line: crate::redact::redact_text(&p.command),
            user: p.user.clone(),
        }
    }

    pub fn finish(self) -> Vec<ProcessChain> {
        let mut out = Vec::with_capacity(self.flagged.len());
        for &(idx, pi) in &self.flagged {
            let pat = &PATTERNS[pi];
            let mut ancestors = Vec::new();
            let mut cur = self.procs[idx].parent;
            while let Some(a) = cur {
                if ancestors.len() >= ANCESTORS || ancestors.contains(&a) {
                    break;
                }
                ancestors.push(a);
                cur = self.procs[a].parent;
            }
            let mut processes: Vec<ChainProcess> = ancestors.iter().enumerate().rev().map(|(n, a)| self.row(*a, "ancestor", -(n as i32 + 1))).collect();
            processes.push(self.row(idx, "flagged", 0));
            // what it started, breadth first
            let mut queue: std::collections::VecDeque<(usize, i32)> = self.procs[idx].children.iter().map(|c| (*c, 1)).collect();
            let mut n = 0;
            while let Some((c, d)) = queue.pop_front() {
                if n >= DESCENDANTS {
                    break;
                }
                processes.push(self.row(c, "descendant", d));
                n += 1;
                queue.extend(self.procs[c].children.iter().map(|x| (*x, d + 1)));
            }
            out.push(ProcessChain {
                pattern: pat.id.into(),
                title: pat.title.into(),
                severity: pat.severity.into(),
                technique: pat.technique.into(),
                why: pat.why.into(),
                hypotheses: pat.hypotheses.into(),
                computer: self.procs[idx].computer.clone(),
                processes,
            });
        }
        out.sort_by_key(|c| (if c.severity == "high" { 0 } else { 1 }, c.processes.iter().find(|p| p.role == "flagged").map(|p| p.time.clone()).unwrap_or_default()));
        out
    }
}
