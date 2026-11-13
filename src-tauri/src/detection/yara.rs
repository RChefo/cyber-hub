// SPDX-License-Identifier: Apache-2.0
//! YARA rules on boreal 1.4, a YARA 4.5 evaluator written in Rust (no C library, no JIT
//! compiler). A rule file is compiled from its text only: `include` is refused, so a rule never
//! reads another file, and the console, magic and cuckoo modules are absent. Scans run on bytes
//! already read into memory, with a time limit and bounded match lists. Nothing in a rule or in a
//! scanned file is executed.

use std::time::Duration;

use boreal::compiler::{CompilerBuilder, CompilerParams};
use boreal::scanner::{ScanError, ScanParams};
use boreal::{MetadataValue, Scanner};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::sigma::Issue;

/// A rule file larger than this is refused.
pub const MAX_RULE_BYTES: usize = 2 * 1024 * 1024;
/// Files are scanned up to the size of the evidence and sample stores.
pub const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
/// A scan that takes longer stops; the rules that matched so far are reported, with a note.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STRINGS_PER_RULE: usize = 1_000;
const MAX_CONDITION_DEPTH: u32 = 40;
/// Bytes kept of each match (boreal still reports the full length).
const MATCH_BYTES: usize = 64;
/// Matches kept per string in an explanation; the count says how many were found.
const KEPT_PER_STRING: usize = 10;
/// Rules reported per scan.
const MAX_MATCHED_RULES: usize = 200;
/// boreal's default limit of matches per string, which `#a` counts too.
const MATCHES_PER_STRING: usize = 1_000;
/// Modules a rule can import.
pub const MODULES: &[&str] = &["time", "math", "string", "hash", "pe", "elf", "macho", "dotnet", "dex"];
/// Conditions nesting deeper than this (brackets, prefix operators, operator chains) are refused
/// before boreal reads them: its parser recurses on some of these without a limit, and a deep
/// enough condition would overflow the stack. boreal itself refuses conditions deeper than 40.
const MAX_NESTING: usize = 64;
/// Stack of the thread that compiles rules (a margin over what [`MAX_NESTING`] allows).
const COMPILE_STACK: usize = 16 * 1024 * 1024;

/// An upper estimate of how deep the conditions of a rule file nest: per bracketed group, the
/// longest run of operators between `and`, `or` and commas, plus the deepest group inside it.
/// Comments, text strings, regular expressions and hex strings are skipped (YARA divides with
/// `\`, so `/` always starts a regular expression or a comment).
pub fn nesting(text: &str) -> usize {
    #[derive(Default)]
    struct Group {
        longest: usize,
        run: usize,
        inner: usize,
    }
    fn close(stack: &mut Vec<Group>, worst: &mut usize) {
        if stack.len() < 2 {
            return;
        }
        let g = stack.pop().expect("a group");
        let v = g.longest.max(g.run) + g.inner + 1;
        *worst = (*worst).max(v);
        let p = stack.last_mut().expect("the outer group");
        p.inner = p.inner.max(v);
    }
    let b = text.as_bytes();
    let mut stack = vec![Group::default()];
    let mut worst = 0;
    let mut i = 0;
    let op = |stack: &mut Vec<Group>| stack.last_mut().expect("a group").run += 1;
    let sep = |stack: &mut Vec<Group>| {
        let g = stack.last_mut().expect("a group");
        g.longest = g.longest.max(g.run);
        g.run = 0;
    };
    // skips to just after the closing byte, honouring backslash escapes; stops at a line end
    let skip_quoted = |mut j: usize, end: u8| {
        while j < b.len() && b[j] != end && b[j] != b'\n' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        j + 1
    };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match c {
            b'/' if next == Some(b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if next == Some(b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'/' => i = skip_quoted(i + 1, b'/'),
            b'"' => i = skip_quoted(i + 1, b'"'),
            b'=' if next == Some(b'=') => {
                op(&mut stack);
                i += 2;
            }
            b'=' => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if b.get(j) == Some(&b'{') {
                    // a hex string: its groups are bounded by boreal
                    while j < b.len() && b[j] != b'}' {
                        j += 1;
                    }
                    i = j + 1;
                } else {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                stack.push(Group::default());
                i += 1;
            }
            b')' | b']' | b'}' => {
                close(&mut stack, &mut worst);
                i += 1;
            }
            b',' => {
                sep(&mut stack);
                i += 1;
            }
            b'<' | b'>' | b'!' => {
                op(&mut stack);
                i += if next == Some(b'=') || next == Some(c) { 2 } else { 1 };
            }
            b'+' | b'-' | b'*' | b'\\' | b'%' | b'&' | b'|' | b'^' | b'~' => {
                op(&mut stack);
                i += 1;
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'#' || c == b'@' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'$' | b'#' | b'@' | b'.')) {
                    i += 1;
                }
                match &text[start..i] {
                    "and" | "or" => sep(&mut stack),
                    "not" | "defined" | "contains" | "icontains" | "startswith" | "istartswith" | "endswith" | "iendswith" | "iequals" | "matches" | "at" | "in" | "of" => op(&mut stack),
                    _ => {}
                }
            }
            _ => i += 1,
        }
    }
    while stack.len() > 1 {
        close(&mut stack, &mut worst);
    }
    let root = &stack[0];
    worst.max(root.longest.max(root.run) + root.inner)
}

/// Runs a compilation on a thread with a large stack (falls back to the current thread when one
/// cannot be started).
fn on_compile_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    let job = std::sync::Arc::new(std::sync::Mutex::new(Some(f)));
    let worker = job.clone();
    let started = std::thread::Builder::new().name("yara-compile".into()).stack_size(COMPILE_STACK).spawn(move || {
        if let Some(f) = worker.lock().ok().and_then(|mut g| g.take()) {
            let _ = tx.send(f());
        }
    });
    match started {
        Ok(handle) => match handle.join() {
            Ok(()) => rx.recv().expect("the compile thread sent its result"),
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(_) => {
            let f = job.lock().ok().and_then(|mut g| g.take()).expect("the job was not taken");
            f()
        }
    }
}

fn issue(level: &str, message: impl Into<String>) -> Issue {
    Issue { level: level.into(), message: message.into() }
}

/// One rule of a file: its name, tags, metadata and whether it is private or global.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub name: String,
    pub tags: Vec<String>,
    pub metas: Vec<(String, String)>,
    pub private: bool,
    pub global: bool,
}

/// What a rule file says about itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub rules: Vec<RuleInfo>,
    pub imports: Vec<String>,
    pub description: String,
    pub author: String,
    /// critical, high, medium, low or informational, from a `severity` or `level` meta
    pub level: String,
    pub references: Vec<String>,
    pub techniques: Vec<String>,
    pub tags: Vec<String>,
}

impl Meta {
    /// The rules that report matches (not private).
    pub fn public(&self) -> impl Iterator<Item = &RuleInfo> {
        self.rules.iter().filter(|r| !r.private)
    }
}

/// A rule file as read: what it says, its problems, and the compiled rules when it is valid.
pub struct Checked {
    pub meta: Meta,
    pub issues: Vec<Issue>,
    pub scanner: Option<Scanner>,
}

impl Checked {
    pub fn errors(&self) -> usize {
        self.issues.iter().filter(|i| i.level == "error").count()
    }
}

fn compiler() -> boreal::Compiler {
    let mut c = CompilerBuilder::new().build();
    c.set_params(CompilerParams::default().disable_includes(true).max_strings_per_rule(MAX_STRINGS_PER_RULE).max_condition_depth(MAX_CONDITION_DEPTH));
    // a second lock: an include that reached the callback is refused as well
    c.set_include_callback(|name, _, _| Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("include \"{name}\" refused"))));
    c
}

fn scan_params() -> ScanParams {
    ScanParams::default().timeout_duration(Some(SCAN_TIMEOUT)).match_max_length(MATCH_BYTES).compute_full_matches(true)
}

/// boreal's one-line diagnostics name the input `mem` (`mem:3:7: error: …`); they read as
/// `Line 3, column 7: …`.
pub fn plain(desc: &str) -> String {
    let s = desc.trim();
    if let Some(rest) = s.strip_prefix("mem:") {
        let mut parts = rest.splitn(3, ':');
        if let (Some(l), Some(c), Some(msg)) = (parts.next(), parts.next(), parts.next()) {
            if !l.is_empty() && !c.is_empty() && l.chars().all(|x| x.is_ascii_digit()) && c.chars().all(|x| x.is_ascii_digit()) {
                let msg = msg.trim_start();
                let msg = match msg.split_once(": ") {
                    Some((head, m)) if head.starts_with("error") || head.starts_with("warning") => m,
                    _ => msg,
                };
                return format!("Line {l}, column {c}: {msg}");
            }
        }
    }
    s.to_string()
}

fn meta_value(s: &Scanner, v: &MetadataValue) -> String {
    match v {
        MetadataValue::Bytes(b) => String::from_utf8_lossy(s.get_bytes_symbol(*b)).chars().take(2000).collect(),
        MetadataValue::Integer(i) => i.to_string(),
        MetadataValue::Boolean(b) => b.to_string(),
    }
}

/// `import "pe"` lines (outside line comments).
fn imports(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let rest = l.trim_start().strip_prefix("import")?;
            let rest = rest.trim_start().strip_prefix('"')?;
            let name = rest.split('"').next()?;
            (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then(|| name.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn level_of(v: &str) -> Option<&'static str> {
    match v.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "medium" | "moderate" => Some("medium"),
        "low" => Some("low"),
        "info" | "informational" => Some("informational"),
        _ => None,
    }
}

/// ATT&CK technique IDs named in a meta value or a tag (`T1059`, `T1059.001`).
fn technique_ids(v: &str) -> Vec<String> {
    let up = v.to_ascii_uppercase();
    let b = up.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if boundary && b[i] == b'T' && b.len() >= i + 5 && b[i + 1..i + 5].iter().all(u8::is_ascii_digit) && (b.len() == i + 5 || !b[i + 5].is_ascii_digit()) {
            let mut end = i + 5;
            if b.len() >= i + 9 && b[i + 5] == b'.' && b[i + 6..i + 9].iter().all(u8::is_ascii_digit) && (b.len() == i + 9 || !b[i + 9].is_ascii_digit()) {
                end = i + 9;
            }
            // `T1027.0021` is neither T1027 nor a sub-technique
            let malformed = b.get(end) == Some(&b'.') && b.get(end + 1).is_some_and(u8::is_ascii_digit);
            if !malformed && (b.len() == end || !b[end].is_ascii_alphanumeric()) {
                out.push(up[i..end].to_string());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn describe(s: &Scanner, text: &str, issues: &mut Vec<Issue>) -> Meta {
    let rules: Vec<RuleInfo> = s
        .rules()
        .map(|r| RuleInfo {
            name: r.name.to_string(),
            tags: r.tags.iter().map(|t| s.get_string_symbol(*t).to_string()).collect(),
            metas: r.metadatas.iter().map(|m| (s.get_string_symbol(m.name).to_string(), meta_value(s, &m.value))).collect(),
            private: r.is_private,
            global: r.is_global,
        })
        .collect();
    let mut meta = Meta { imports: imports(text), ..Default::default() };
    let find = |keys: &[&str]| rules.iter().filter(|r| !r.private).flat_map(|r| r.metas.iter()).find(|(k, v)| keys.contains(&k.to_ascii_lowercase().as_str()) && !v.trim().is_empty()).map(|(_, v)| v.trim().to_string());
    meta.description = find(&["description", "desc"]).unwrap_or_default();
    meta.author = find(&["author", "authors"]).unwrap_or_default();
    if let Some(l) = find(&["severity", "level", "threat_level"]) {
        match level_of(&l) {
            Some(l) => meta.level = l.into(),
            None => issues.push(issue("warning", format!("The severity '{l}' is not one of critical, high, medium, low or informational; the rule has no level"))),
        }
    }
    for r in rules.iter().filter(|r| !r.private) {
        for (k, v) in &r.metas {
            let key = k.to_ascii_lowercase();
            if ["reference", "references", "ref", "url", "link"].contains(&key.as_str()) && !v.trim().is_empty() && !meta.references.contains(v) {
                meta.references.push(v.trim().to_string());
            }
        }
        for t in &r.tags {
            if !meta.tags.contains(t) {
                meta.tags.push(t.clone());
            }
        }
    }
    let mut named: Vec<(String, String)> = Vec::new();
    for r in rules.iter().filter(|r| !r.private) {
        for (k, v) in &r.metas {
            let key = k.to_ascii_lowercase();
            if key.contains("mitre") || key.contains("attack") || key.contains("technique") || key == "ttp" || key == "ttps" {
                named.extend(technique_ids(v).into_iter().map(|t| (t, format!("the meta {k} of {}", r.name))));
            }
        }
        for t in &r.tags {
            named.extend(technique_ids(t).into_iter().map(|id| (id, format!("the tag {t} of {}", r.name))));
        }
    }
    for (id, place) in named {
        match crate::workspace::attack::id_state(&id) {
            crate::workspace::attack::IdState::Current => meta.techniques.push(id),
            crate::workspace::attack::IdState::Revoked { by } => {
                issues.push(issue("warning", format!("{id} ({place}) is a technique ATT&CK revoked; it is now {by}")));
                meta.techniques.push(by);
            }
            crate::workspace::attack::IdState::Deprecated => {
                issues.push(issue("warning", format!("{id} ({place}) is a deprecated ATT&CK technique")));
                meta.techniques.push(id);
            }
            crate::workspace::attack::IdState::Unknown => issues.push(issue("warning", format!("{id} ({place}) names no ATT&CK Enterprise technique"))),
        }
    }
    meta.techniques.sort();
    meta.techniques.dedup();
    meta.rules = rules;
    meta
}

/// Reads and compiles a rule file. Problems are listed with a level, as for Sigma rules: *error*
/// (the file does not compile) or *warning*.
pub fn check(text: &str) -> Checked {
    let mut issues = Vec::new();
    let refuse = |issues: Vec<Issue>| Checked { meta: Meta { imports: imports(text), ..Default::default() }, issues, scanner: None };
    if text.len() > MAX_RULE_BYTES {
        issues.push(issue("error", format!("The rule file is larger than {} KB", MAX_RULE_BYTES / 1024)));
        return refuse(issues);
    }
    let depth = nesting(text);
    if depth > MAX_NESTING {
        issues.push(issue("error", format!("A condition nests about {depth} levels deep (brackets, operators and `not`); ExploitX reads at most {MAX_NESTING}")));
        return refuse(issues);
    }
    let owned = text.to_string();
    let compiled = on_compile_stack(move || {
        let mut c = compiler();
        let added = c.add_rules_str(&owned).map(|status| status.warnings().map(|w| plain(&w.to_string())).collect::<Vec<_>>()).map_err(|e| plain(&e.to_string()));
        added.map(|warnings| {
            let mut scanner = c.finalize();
            scanner.set_scan_params(scan_params());
            (scanner, warnings)
        })
    });
    let scanner = match compiled {
        Ok((scanner, warnings)) => {
            issues.extend(warnings.into_iter().map(|w| issue("warning", w)));
            scanner
        }
        Err(mut message) => {
            if let Some(m) = imports(text).iter().find(|m| !MODULES.contains(&m.as_str())) {
                message = format!("{message} (ExploitX has the modules {}, not {m})", MODULES.join(", "));
            }
            issues.push(issue("error", message));
            return refuse(issues);
        }
    };
    let meta = describe(&scanner, text, &mut issues);
    if meta.rules.is_empty() {
        issues.push(issue("error", "The file holds no rule"));
        return Checked { meta, issues, scanner: None };
    }
    if meta.public().next().is_none() {
        issues.push(issue("warning", "Every rule is private: a scan never reports a match"));
    }
    Checked { meta, issues, scanner: Some(scanner) }
}

/// The rule names a text declares (`rule`, `private rule`, `global rule`), read without compiling
/// it: a name for a file written in the app before it compiles.
pub fn declared(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut t = line.trim_start();
        while let Some(rest) = t.strip_prefix("private ").or_else(|| t.strip_prefix("global ")) {
            t = rest.trim_start();
        }
        if let Some(rest) = t.strip_prefix("rule ") {
            let name: String = rest.trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit()) {
                out.push(name);
            }
        }
    }
    out
}

/// The name a file of rules goes by in the library: its only public rule, or the first one with
/// the number of rules.
pub fn title(meta: &Meta) -> String {
    let public: Vec<&RuleInfo> = meta.public().collect();
    match public.as_slice() {
        [] => meta.rules.first().map(|r| r.name.clone()).unwrap_or_else(|| "YARA rules".into()),
        [one] => one.name.clone(),
        [first, ..] => format!("{} and {} more", first.name, public.len() - 1),
    }
}

/* ───────────────────────── scanning ───────────────────────── */

/// One match of a string: where, how long, and the first bytes as text and hexadecimal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub offset: u64,
    pub length: u64,
    pub text: String,
    pub hex: String,
    /// the key of a `xor` string
    pub xor: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StringHit {
    pub id: String,
    /// matches found (boreal stops counting at 1,000 per string, as `#a` does)
    pub count: usize,
    pub matches: Vec<Hit>,
}

/// A rule that matched, with the strings that matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metas: Vec<(String, String)>,
    pub strings: Vec<StringHit>,
}

#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub matches: Vec<RuleMatch>,
    /// the scan reached the time limit: rules that would have matched later are missing
    pub timed_out: bool,
    /// more rules matched than are reported
    pub more: usize,
}

/// Printable text of matched bytes: ASCII as is, UTF-16LE text decoded, other bytes escaped.
pub fn preview(data: &[u8]) -> String {
    let wide = data.len() >= 4 && data.len().is_multiple_of(2) && data.chunks(2).all(|p| p[1] == 0 && (0x20..0x7f).contains(&p[0]));
    if wide {
        return format!("{} (UTF-16LE)", data.chunks(2).map(|p| p[0] as char).collect::<String>());
    }
    let mut out = String::new();
    for &b in data {
        match b {
            0x20..=0x7e => out.push(b as char),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Scans bytes with compiled rules.
pub fn scan(scanner: &Scanner, data: &[u8]) -> Scan {
    let (res, timed_out) = match scanner.scan_mem(data) {
        Ok(r) => (r, false),
        Err((e, r)) => (r, matches!(e, ScanError::Timeout)),
    };
    let matched: Vec<_> = res.rules.iter().filter(|r| r.matched).collect();
    let more = matched.len().saturating_sub(MAX_MATCHED_RULES);
    let matches = matched
        .into_iter()
        .take(MAX_MATCHED_RULES)
        .map(|r| RuleMatch {
            rule: r.name.to_string(),
            namespace: r.namespace.to_string(),
            tags: r.tags.iter().map(|t| scanner.get_string_symbol(*t).to_string()).collect(),
            metas: r.metadatas.iter().map(|m| (scanner.get_string_symbol(m.name).to_string(), meta_value(scanner, &m.value))).collect(),
            strings: r
                .matches
                .iter()
                .filter(|s| !s.matches.is_empty())
                .map(|s| StringHit {
                    id: format!("${}", s.name),
                    count: s.matches.len(),
                    matches: s.matches.iter().take(KEPT_PER_STRING).map(|m| Hit { offset: (m.base + m.offset) as u64, length: m.length as u64, text: preview(&m.data), hex: m.data.iter().map(|b| format!("{b:02x}")).collect(), xor: s.has_xor_modifier.then_some(m.xor_key) }).collect(),
                })
                .collect(),
        })
        .collect();
    Scan { matches, timed_out, more }
}

/// Why a rule matched, as stored with a test or a hit (`kind` tells it from a Sigma explanation).
pub fn explanation(m: &RuleMatch) -> Value {
    json!({
        "kind": "yara",
        "rule": m.rule,
        "tags": m.tags,
        "metas": m.metas,
        "strings": m.strings,
        "limit": MATCHES_PER_STRING,
        "kept": KEPT_PER_STRING,
    })
}

/// Several rule files compiled together, each in its own namespace (`r<id>`), so one pass over
/// a file runs them all. A file that does not compile is left out and named.
pub struct Library {
    pub scanner: Scanner,
    pub failed: Vec<(i64, String)>,
}

pub fn library(entries: &[(i64, &str)]) -> Library {
    let mut failed = Vec::new();
    let mut ok: Vec<(i64, String)> = Vec::new();
    for (id, text) in entries {
        if text.len() > MAX_RULE_BYTES {
            failed.push((*id, "The rule file is too large".to_string()));
        } else if nesting(text) > MAX_NESTING {
            failed.push((*id, format!("A condition nests deeper than {MAX_NESTING} levels")));
        } else {
            ok.push((*id, text.to_string()));
        }
    }
    let (scanner, more_failed) = on_compile_stack(move || {
        let mut c = compiler();
        let mut failed = Vec::new();
        for (id, text) in &ok {
            if let Err(e) = c.add_rules_str_in_namespace(text, format!("r{id}")) {
                failed.push((*id, plain(&e.to_string())));
            }
        }
        let mut scanner = c.finalize();
        scanner.set_scan_params(scan_params());
        (scanner, failed)
    });
    failed.extend(more_failed);
    Library { scanner, failed }
}

/// The library entry a namespace of [`library`] belongs to.
pub fn namespace_id(ns: &str) -> Option<i64> {
    ns.strip_prefix('r')?.parse().ok()
}

/// What the YARA engine supports, for the Detections page.
pub fn capabilities() -> Value {
    json!({
        "engine": "boreal 1.4 (compatible with YARA 4.5)",
        "modules": MODULES,
        "unsupported": [
            "include (refused: a rule never reads files)",
            "the console, magic and cuckoo modules",
            "Authenticode verification: pe.signatures are read, never verified",
            "external variables",
        ],
        "limits": {
            "ruleFileKb": MAX_RULE_BYTES / 1024,
            "stringsPerRule": MAX_STRINGS_PER_RULE,
            "scanSeconds": SCAN_TIMEOUT.as_secs(),
            "fileMb": MAX_SCAN_BYTES / 1024 / 1024,
            "matchesPerString": MATCHES_PER_STRING,
        },
    })
}

#[cfg(test)]
#[path = "yara_tests.rs"]
mod tests;
