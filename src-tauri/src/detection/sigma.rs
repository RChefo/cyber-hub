//! Sigma rules (SigmaHQ's specification v2.1.0 of 2025-08-02, with its value-modifier appendix):
//! reading, validation and evaluation against events, with an explanation of every match.
//!
//! Rules are data: nothing in a rule is executed. Values become literal comparisons, wildcard
//! patterns or regular expressions run by the `regex` crate, whose matching time is linear in the
//! input, with a size limit on every compiled expression.
//!
//! What a rule uses but ExploitX cannot evaluate is reported, never ignored: a rule with an
//! unsupported feature (placeholders, time modifiers, the obsolete `| count()` aggregations,
//! value_percentile correlations) is refused for evaluation with the reason. Correlation rules
//! are validated here and evaluated by [`super::correlation`].

use std::collections::BTreeMap;
use std::net::IpAddr;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::events::Event;

pub const SPEC_VERSION: &str = "2.1.0";
/// A rule file.
pub const MAX_RULE_BYTES: usize = 512 * 1024;
const MAX_VALUES: usize = 5_000;
const MAX_REGEX: usize = 1 << 20;
const STATUSES: &[&str] = &["stable", "test", "experimental", "deprecated", "unsupported"];
const LEVELS: &[&str] = &["informational", "low", "medium", "high", "critical"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    /// error (the rule is invalid), unsupported (valid, but ExploitX cannot evaluate it), warning
    pub level: String,
    pub message: String,
}

fn issue(level: &str, message: impl Into<String>) -> Issue {
    Issue { level: level.into(), message: message.into() }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

impl LogSource {
    pub fn label(&self) -> String {
        [self.product.as_deref(), self.service.as_deref(), self.category.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" / ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub description: String,
    pub author: String,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub license: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
    pub fields: Vec<String>,
    pub logsource: LogSource,
    /// ATT&CK technique IDs from the `attack.tNNNN` tags, upper-case
    pub techniques: Vec<String>,
    /// ATT&CK tactic short names from `attack.<tactic>` tags
    pub tactics: Vec<String>,
    /// the correlation section of a valid correlation rule
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<super::correlation::Correlation>,
}

/* ───────────────────────── values ───────────────────────── */

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Lit(String),
    /// `*`
    Star,
    /// `?`
    Quest,
    /// one of these characters (windash)
    Class(&'static str),
}

/// A Sigma string: `*` and `?` are wildcards; `\*`, `\?` and `\\` are the plain characters; any
/// other backslash is a plain backslash (Windows paths).
fn tokens(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.peek() {
                Some('*') | Some('?') | Some('\\') => lit.push(it.next().unwrap_or('\\')),
                _ => lit.push('\\'),
            },
            '*' | '?' => {
                if !lit.is_empty() {
                    out.push(Tok::Lit(std::mem::take(&mut lit)));
                }
                out.push(if c == '*' { Tok::Star } else { Tok::Quest });
            }
            _ => lit.push(c),
        }
    }
    if !lit.is_empty() {
        out.push(Tok::Lit(lit));
    }
    out
}

fn plain(t: &[Tok]) -> Option<String> {
    let mut s = String::new();
    for x in t {
        match x {
            Tok::Lit(l) => s.push_str(l),
            _ => return None,
        }
    }
    Some(s)
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

/// A value on its way through the modifiers.
#[derive(Debug, Clone)]
enum Val {
    Toks(Vec<Tok>),
    Bytes(Vec<u8>),
}

impl Val {
    fn bytes(&self, modifier: &str) -> Result<Vec<u8>, String> {
        match self {
            Val::Bytes(b) => Ok(b.clone()),
            Val::Toks(t) => plain(t).map(String::into_bytes).ok_or_else(|| format!("'{modifier}' cannot encode a value with wildcards")),
        }
    }
    fn into_toks(self) -> Vec<Tok> {
        match self {
            Val::Toks(t) => t,
            // encoded bytes are compared as text (base64 is ASCII; UTF-16 keeps its zero bytes)
            Val::Bytes(b) => vec![Tok::Lit(b.iter().map(|&c| c as char).collect())],
        }
    }
}

fn utf16(s: &[u8], be: bool, bom: bool) -> Vec<u8> {
    let text = String::from_utf8_lossy(s);
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(if be { &[0xFE, 0xFF] } else { &[0xFF, 0xFE] });
    }
    for u in text.encode_utf16() {
        let b = if be { u.to_be_bytes() } else { u.to_le_bytes() };
        out.extend_from_slice(&b);
    }
    out
}

/// `-` and `/` that start an option (at the start or after a space) become any of the dashes
/// Windows accepts.
fn windash(t: Vec<Tok>) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut prev_space = true;
    for x in t {
        match x {
            Tok::Lit(l) => {
                let mut cur = String::new();
                for c in l.chars() {
                    if (c == '-' || c == '/') && prev_space {
                        if !cur.is_empty() {
                            out.push(Tok::Lit(std::mem::take(&mut cur)));
                        }
                        out.push(Tok::Class("-/\u{2013}\u{2014}\u{2015}"));
                    } else {
                        cur.push(c);
                    }
                    prev_space = c == ' ';
                }
                if !cur.is_empty() {
                    out.push(Tok::Lit(cur));
                }
            }
            other => {
                prev_space = false;
                out.push(other);
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Matcher {
    /// a plain value: equality, case-insensitive unless `cased`
    Eq { value: String, cased: bool },
    /// wildcards or contains/startswith/endswith
    Pattern { re: Regex, shown: String },
    Regex { re: Regex, shown: String },
    Num { op: &'static str, value: f64 },
    Cidr(ipnet::IpNet),
    /// `null`: the field is absent
    Null,
    /// the value of another field
    FieldRef(String),
}

impl Matcher {
    fn shown(&self) -> String {
        match self {
            Matcher::Eq { value, .. } => format!("'{value}'"),
            Matcher::Pattern { shown, .. } => shown.clone(),
            Matcher::Regex { shown, .. } => format!("/{shown}/"),
            Matcher::Num { op, value } => format!("{op} {value}"),
            Matcher::Cidr(n) => format!("in {n}"),
            Matcher::Null => "null".into(),
            Matcher::FieldRef(f) => format!("field {f}"),
        }
    }
    fn test(&self, v: Option<&str>, ev: &Event) -> bool {
        match (self, v) {
            (Matcher::Null, v) => v.is_none(),
            (_, None) => false,
            (Matcher::Eq { value, cased: true }, Some(v)) => v == value,
            (Matcher::Eq { value, cased: false }, Some(v)) => v.eq_ignore_ascii_case(value) || (!value.is_ascii() && v.to_lowercase() == value.to_lowercase()),
            (Matcher::Pattern { re, .. }, Some(v)) | (Matcher::Regex { re, .. }, Some(v)) => re.is_match(v),
            (Matcher::Num { op, value }, Some(v)) => number(v).is_some_and(|n| match *op {
                "lt" => n < *value,
                "lte" => n <= *value,
                "gt" => n > *value,
                "gte" => n >= *value,
                _ => n == *value,
            }),
            (Matcher::Cidr(net), Some(v)) => v.trim().parse::<IpAddr>().is_ok_and(|ip| net.contains(&ip)),
            (Matcher::FieldRef(f), Some(v)) => field(ev, f).is_some_and(|o| o.eq_ignore_ascii_case(v)),
        }
    }
}

fn number(v: &str) -> Option<f64> {
    let t = v.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).ok().map(|n| n as f64);
    }
    t.parse::<f64>().ok()
}

fn compile(t: Vec<Tok>, cased: bool) -> Result<Matcher, String> {
    if let Some(p) = plain(&t) {
        return Ok(Matcher::Eq { value: p, cased });
    }
    let mut re = String::from("^");
    let mut shown = String::new();
    for x in &t {
        match x {
            Tok::Lit(l) => {
                re.push_str(&regex::escape(l));
                shown.push_str(l);
            }
            Tok::Star => {
                re.push_str(".*");
                shown.push('*');
            }
            Tok::Quest => {
                re.push('.');
                shown.push('?');
            }
            Tok::Class(c) => {
                re.push('[');
                re.push_str(&regex::escape(c));
                re.push(']');
                shown.push('-');
            }
        }
    }
    re.push('$');
    let re = RegexBuilder::new(&re).case_insensitive(!cased).dot_matches_new_line(true).size_limit(MAX_REGEX).build().map_err(|e| format!("pattern too large: {e}"))?;
    Ok(Matcher::Pattern { re, shown: format!("'{shown}'") })
}

/// One field condition of a selection: `field|modifiers: value(s)`.
#[derive(Debug, Clone)]
struct FieldTest {
    /// empty for keyword searches with modifiers (`'|all'`)
    field: String,
    modifiers: Vec<String>,
    kind: TestKind,
}

#[derive(Debug, Clone)]
enum TestKind {
    Exists(bool),
    Values { matchers: Vec<Matcher>, all: bool, negate: bool },
}

/// What matched, for the explanation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub field: String,
    /// the rule's side: modifiers and value
    pub condition: String,
    /// the event's value (cut)
    pub value: String,
}

fn field<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    if let Some(v) = ev.get(name) {
        return Some(v);
    }
    // Security 4688 names the process fields differently from Sysmon (pySigma's windows mapping)
    let alias = match name.to_ascii_lowercase().as_str() {
        "image" => "NewProcessName",
        "parentimage" => "ParentProcessName",
        "processid" if ev.get("NewProcessId").is_some() => "NewProcessId",
        "user" => "SubjectUserName",
        _ => return None,
    };
    (ev.get("EventID") == Some("4688")).then(|| ev.get(alias)).flatten()
}

fn shorten(v: &str) -> String {
    if v.chars().count() > 300 {
        format!("{}…", v.chars().take(300).collect::<String>())
    } else {
        v.to_string()
    }
}

impl FieldTest {
    fn eval(&self, ev: &Event) -> Option<Hit> {
        let label = if self.modifiers.is_empty() { self.field.clone() } else { format!("{}|{}", self.field, self.modifiers.join("|")) };
        if self.field.is_empty() {
            // keywords: anywhere in the event
            let TestKind::Values { matchers, all, .. } = &self.kind else { return None };
            let text = haystack(ev);
            let ok = if *all { matchers.iter().all(|m| m.test(Some(&text), ev)) } else { matchers.iter().any(|m| m.test(Some(&text), ev)) };
            return ok.then(|| Hit { field: "(keywords)".into(), condition: format!("{} {}", if *all { "all of" } else { "any of" }, matchers.iter().map(Matcher::shown).collect::<Vec<_>>().join(", ")), value: shorten(&text) });
        }
        let v = field(ev, &self.field);
        match &self.kind {
            TestKind::Exists(want) => (v.is_some() == *want).then(|| Hit { field: self.field.clone(), condition: format!("exists: {want}"), value: v.map(shorten).unwrap_or_else(|| "(absent)".into()) }),
            TestKind::Values { matchers, all, negate } => {
                let hits: Vec<&Matcher> = matchers.iter().filter(|m| m.test(v, ev)).collect();
                let ok = if *all { hits.len() == matchers.len() } else { !hits.is_empty() };
                let ok = ok != *negate;
                ok.then(|| Hit {
                    field: self.field.clone(),
                    condition: format!(
                        "{label} {}{}",
                        if *negate { "is not " } else { "" },
                        if *negate || hits.is_empty() { matchers.iter().map(Matcher::shown).collect::<Vec<_>>().join(" or ") } else { hits.iter().map(|m| m.shown()).collect::<Vec<_>>().join(" and ") }
                    ),
                    value: v.map(shorten).unwrap_or_else(|| "(absent)".into()),
                })
            }
        }
    }
}

/// Keywords are searched in every value of a structured event, and in the line of a text log.
fn haystack(ev: &Event) -> String {
    if !ev.text.is_empty() {
        return ev.text.clone();
    }
    ev.fields.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("\n")
}

/// A search identifier: OR of AND-maps, or keywords.
#[derive(Debug, Clone)]
struct Selection {
    maps: Vec<Vec<FieldTest>>,
}

impl Selection {
    fn eval(&self, ev: &Event) -> Option<Vec<Hit>> {
        'maps: for m in &self.maps {
            let mut hits = Vec::new();
            for t in m {
                match t.eval(ev) {
                    Some(h) => hits.push(h),
                    None => continue 'maps,
                }
            }
            return Some(hits);
        }
        None
    }
}

/* ───────────────────────── conditions ───────────────────────── */

#[derive(Debug, Clone, PartialEq)]
enum Quant {
    Any,
    All,
    AtLeast(usize),
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Or(Vec<Expr>),
    And(Vec<Expr>),
    Not(Box<Expr>),
    Ident(String),
    Of(Quant, Option<String>),
}

fn lex(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            '|' => return Err("aggregations (`| count() …`) are not part of Sigma 2.x; use a correlation rule".into()),
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// Parentheses and `not`s around one point of a condition. The parser recurses once per level,
/// so a crafted condition of a few kilobytes would otherwise overflow the stack and end the app.
const MAX_CONDITION_DEPTH: usize = 64;

struct P<'a> {
    t: &'a [String],
    i: usize,
    depth: usize,
}

impl P<'_> {
    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_CONDITION_DEPTH {
            return Err(format!("the condition nests deeper than {MAX_CONDITION_DEPTH} levels of parentheses and 'not'"));
        }
        Ok(())
    }
    fn peek(&self) -> Option<&str> {
        self.t.get(self.i).map(String::as_str)
    }
    fn next(&mut self) -> Option<&str> {
        let r = self.t.get(self.i).map(String::as_str);
        self.i += 1;
        r
    }
    fn or(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.and()?];
        while self.peek().is_some_and(|w| w.eq_ignore_ascii_case("or")) {
            self.i += 1;
            v.push(self.and()?);
        }
        Ok(if v.len() == 1 { v.remove(0) } else { Expr::Or(v) })
    }
    fn and(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.not()?];
        while self.peek().is_some_and(|w| w.eq_ignore_ascii_case("and")) {
            self.i += 1;
            v.push(self.not()?);
        }
        Ok(if v.len() == 1 { v.remove(0) } else { Expr::And(v) })
    }
    fn not(&mut self) -> Result<Expr, String> {
        if self.peek().is_some_and(|w| w.eq_ignore_ascii_case("not")) {
            self.i += 1;
            self.enter()?;
            let e = self.not()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(e)));
        }
        self.atom()
    }
    fn atom(&mut self) -> Result<Expr, String> {
        let w = self.next().ok_or("the condition ends too early")?.to_string();
        if w == "(" {
            self.enter()?;
            let e = self.or()?;
            self.depth -= 1;
            if self.next() != Some(")") {
                return Err("a parenthesis is not closed".into());
            }
            return Ok(e);
        }
        if w == ")" {
            return Err("unexpected ')'".into());
        }
        let quant = if w.eq_ignore_ascii_case("all") {
            Some(Quant::All)
        } else if w.eq_ignore_ascii_case("any") {
            Some(Quant::Any)
        } else if let Ok(n) = w.parse::<usize>() {
            Some(if n == 1 { Quant::Any } else { Quant::AtLeast(n) })
        } else {
            None
        };
        if let Some(q) = quant {
            if !self.peek().is_some_and(|x| x.eq_ignore_ascii_case("of")) {
                return Err(format!("'{w}' must be followed by 'of'"));
            }
            self.i += 1;
            let target = self.next().ok_or("'of' needs 'them' or a pattern")?.to_string();
            if q == Quant::AtLeast(0) {
                return Err("'0 of' is not defined in Sigma".into());
            }
            return Ok(Expr::Of(q, if target.eq_ignore_ascii_case("them") { None } else { Some(target) }));
        }
        if ["and", "or", "of", "them"].iter().any(|k| w.eq_ignore_ascii_case(k)) {
            return Err(format!("unexpected '{w}'"));
        }
        Ok(Expr::Ident(w))
    }
}

fn parse_condition(s: &str) -> Result<Expr, String> {
    let t = lex(s)?;
    if t.is_empty() {
        return Err("the condition is empty".into());
    }
    let mut p = P { t: &t, i: 0, depth: 0 };
    let e = p.or()?;
    if p.i < t.len() {
        return Err(format!("unexpected '{}' in the condition", t[p.i]));
    }
    Ok(e)
}

fn glob(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == n[ni] || p[pi] == '?') {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn targets<'a>(target: &Option<String>, names: &'a [String]) -> Vec<&'a String> {
    names.iter().filter(|n| match target {
        None => !n.starts_with('_'),
        Some(p) => glob(p, n),
    })
    .collect()
}

fn check_refs(e: &Expr, names: &[String], out: &mut Vec<String>) {
    match e {
        Expr::Or(v) | Expr::And(v) => v.iter().for_each(|x| check_refs(x, names, out)),
        Expr::Not(x) => check_refs(x, names, out),
        Expr::Ident(i) if !names.contains(i) => out.push(format!("the condition names '{i}', which the detection does not define")),
        Expr::Of(_, t) if targets(t, names).is_empty() => out.push(format!("'of {}' matches no search identifier", t.as_deref().unwrap_or("them"))),
        _ => {}
    }
}

fn used(e: &Expr, names: &[String], out: &mut Vec<String>) {
    match e {
        Expr::Or(v) | Expr::And(v) => v.iter().for_each(|x| used(x, names, out)),
        Expr::Not(x) => used(x, names, out),
        Expr::Ident(i) => out.push(i.clone()),
        Expr::Of(_, t) => out.extend(targets(t, names).into_iter().cloned()),
    }
}

fn eval_expr(e: &Expr, r: &BTreeMap<&str, bool>, names: &[String]) -> bool {
    match e {
        Expr::Or(v) => v.iter().any(|x| eval_expr(x, r, names)),
        Expr::And(v) => v.iter().all(|x| eval_expr(x, r, names)),
        Expr::Not(x) => !eval_expr(x, r, names),
        Expr::Ident(i) => r.get(i.as_str()).copied().unwrap_or(false),
        Expr::Of(q, t) => {
            let set = targets(t, names);
            let n = set.iter().filter(|s| r.get(s.as_str()).copied().unwrap_or(false)).count();
            match q {
                Quant::Any => n >= 1,
                Quant::All => n == set.len() && !set.is_empty(),
                Quant::AtLeast(k) => n >= *k,
            }
        }
    }
}

/* ───────────────────────── log sources ───────────────────────── */

/// Windows log sources: Sigma service → channel, category → (channel, event IDs), after the
/// mapping of pySigma's Windows pipeline.
const SERVICES: &[(&str, &str)] = &[
    ("security", "Security"),
    ("system", "System"),
    ("application", "Application"),
    ("sysmon", "Microsoft-Windows-Sysmon/Operational"),
    ("powershell", "Microsoft-Windows-PowerShell/Operational"),
    ("powershell-classic", "Windows PowerShell"),
    ("taskscheduler", "Microsoft-Windows-TaskScheduler/Operational"),
    ("wmi", "Microsoft-Windows-WMI-Activity/Operational"),
    ("windefend", "Microsoft-Windows-Windows Defender/Operational"),
    ("bits-client", "Microsoft-Windows-Bits-Client/Operational"),
    ("codeintegrity-operational", "Microsoft-Windows-CodeIntegrity/Operational"),
    ("firewall-as", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"),
    ("dns-server", "DNS Server"),
    ("ntlm", "Microsoft-Windows-NTLM/Operational"),
    ("openssh", "OpenSSH/Operational"),
    ("terminalservices-localsessionmanager", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
    ("printservice-operational", "Microsoft-Windows-PrintService/Operational"),
    ("smbclient-security", "Microsoft-Windows-SmbClient/Security"),
];

const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
/// (category, [(channel, event IDs)])
type Category = (&'static str, &'static [(&'static str, &'static [u32])]);
const CATEGORIES: &[Category] = &[
    ("process_creation", &[(SYSMON, &[1]), ("Security", &[4688])]),
    ("file_change", &[(SYSMON, &[2])]),
    ("network_connection", &[(SYSMON, &[3])]),
    ("sysmon_status", &[(SYSMON, &[4, 16])]),
    ("process_termination", &[(SYSMON, &[5])]),
    ("driver_load", &[(SYSMON, &[6])]),
    ("image_load", &[(SYSMON, &[7])]),
    ("create_remote_thread", &[(SYSMON, &[8])]),
    ("raw_access_thread", &[(SYSMON, &[9])]),
    ("process_access", &[(SYSMON, &[10])]),
    ("file_event", &[(SYSMON, &[11])]),
    ("registry_add", &[(SYSMON, &[12])]),
    ("registry_delete", &[(SYSMON, &[12])]),
    ("registry_set", &[(SYSMON, &[13])]),
    ("registry_rename", &[(SYSMON, &[14])]),
    ("registry_event", &[(SYSMON, &[12, 13, 14])]),
    ("create_stream_hash", &[(SYSMON, &[15])]),
    ("pipe_created", &[(SYSMON, &[17, 18])]),
    ("wmi_event", &[(SYSMON, &[19, 20, 21])]),
    ("dns_query", &[(SYSMON, &[22])]),
    ("file_delete", &[(SYSMON, &[23, 26])]),
    ("clipboard_capture", &[(SYSMON, &[24])]),
    ("process_tampering", &[(SYSMON, &[25])]),
    ("file_block_executable", &[(SYSMON, &[27])]),
    ("file_block_shredding", &[(SYSMON, &[28])]),
    ("file_executable_detected", &[(SYSMON, &[29])]),
    ("sysmon_error", &[(SYSMON, &[255])]),
    ("ps_module", &[("Microsoft-Windows-PowerShell/Operational", &[4103])]),
    ("ps_script", &[("Microsoft-Windows-PowerShell/Operational", &[4104])]),
    ("ps_classic_start", &[("Windows PowerShell", &[400])]),
    ("ps_classic_provider_start", &[("Windows PowerShell", &[600])]),
];

/// Whether the rule's log source can be checked against events, and how.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum SourceCheck {
    /// events are filtered by channel and event IDs
    Windows { channels: Vec<(String, Vec<u32>)> },
    /// the log source is not mapped: the rule is evaluated against every event
    Unmapped { reason: String },
}

pub fn source_check(ls: &LogSource) -> SourceCheck {
    let product = ls.product.as_deref().unwrap_or("");
    if !product.is_empty() && product != "windows" {
        return SourceCheck::Unmapped { reason: format!("the product '{product}' has no channel mapping; the rule is evaluated against every event") };
    }
    if let Some(c) = ls.category.as_deref() {
        if let Some((_, list)) = CATEGORIES.iter().find(|(k, _)| *k == c) {
            return SourceCheck::Windows { channels: list.iter().map(|(ch, ids)| (ch.to_string(), ids.to_vec())).collect() };
        }
        return SourceCheck::Unmapped { reason: format!("the category '{c}' has no channel mapping; the rule is evaluated against every event") };
    }
    if let Some(s) = ls.service.as_deref() {
        if let Some((_, ch)) = SERVICES.iter().find(|(k, _)| *k == s) {
            return SourceCheck::Windows { channels: vec![(ch.to_string(), vec![])] };
        }
        return SourceCheck::Unmapped { reason: format!("the service '{s}' has no channel mapping; the rule is evaluated against every event") };
    }
    SourceCheck::Unmapped { reason: "the log source names no category or service; the rule is evaluated against every event".into() }
}

/// Whether an event belongs to the rule's log source. Events without a channel (JSON without
/// one, text logs) are not filtered.
fn in_source(check: &SourceCheck, ev: &Event) -> bool {
    match check {
        SourceCheck::Unmapped { .. } => true,
        SourceCheck::Windows { channels } => {
            let Some(ch) = ev.get("Channel") else { return true };
            let id = ev.get("EventID").and_then(|v| v.trim().parse::<u32>().ok());
            channels.iter().any(|(c, ids)| c.eq_ignore_ascii_case(ch) && (ids.is_empty() || id.is_some_and(|i| ids.contains(&i))))
        }
    }
}

/// What the engine evaluates, and what it reports as unsupported.
pub fn capabilities() -> Value {
    serde_json::json!({
        "spec": SPEC_VERSION,
        "modifiers": ["contains", "startswith", "endswith", "all", "exists", "cased", "re", "re|i", "re|m", "re|s", "base64", "base64offset", "utf16le", "wide", "utf16be", "utf16", "windash", "cidr", "lt", "lte", "gt", "gte", "neq", "fieldref"],
        "unsupported": ["expand (placeholders)", "minute, hour, day, week, month, year", "aggregations (| count() …): use a correlation rule", "value_percentile correlations", "rule collections with action", "regular-expression look-around and back-references"],
        "correlation": super::correlation::capabilities(),
        "categories": CATEGORIES.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
        "services": SERVICES.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
    })
}

/* ───────────────────────── rules ───────────────────────── */

/// A rule ready to evaluate.
#[derive(Debug, Clone)]
pub struct Rule {
    names: Vec<String>,
    selections: BTreeMap<String, Selection>,
    conditions: Vec<Expr>,
    pub source: SourceCheck,
}

/// One rule document as read: its metadata, problems, and the compiled rule when it can run.
#[derive(Debug, Clone)]
pub struct Checked {
    pub meta: Meta,
    pub issues: Vec<Issue>,
    pub rule: Option<Rule>,
    /// a valid correlation rule (it has no detection of its own)
    pub correlation: Option<super::correlation::Correlation>,
}

impl Checked {
    pub fn errors(&self) -> usize {
        self.issues.iter().filter(|i| i.level != "warning").count()
    }
    /// A detection rule that compiled, or a valid correlation rule.
    pub fn runnable(&self) -> bool {
        self.rule.is_some() || self.correlation.is_some()
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(text).collect(),
        Some(v) => text(v).into_iter().collect(),
        None => vec![],
    }
}

fn uuid_like(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, x)| x.len() == *n && x.chars().all(|c| c.is_ascii_hexdigit()))
}

fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && s.chars().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// Reads a rule file: every YAML document in it is one rule.
pub fn read(text_in: &str) -> Result<Vec<Checked>, String> {
    if text_in.len() > MAX_RULE_BYTES {
        return Err(format!("The rule file is larger than {} KB", MAX_RULE_BYTES / 1024));
    }
    let docs = crate::yaml::parse_documents(text_in).map_err(|e| format!("This is not valid YAML: {e}"))?;
    let docs: Vec<Value> = docs.into_iter().filter(|d| !d.is_null()).collect();
    if docs.is_empty() {
        return Err("The file holds no rule".into());
    }
    Ok(docs.iter().map(check).collect())
}

/// Checks one rule document and compiles it.
pub fn check(doc: &Value) -> Checked {
    let mut issues = Vec::new();
    let Some(o) = doc.as_object() else {
        return Checked { meta: Meta::default(), issues: vec![issue("error", "A Sigma rule is a YAML mapping")], rule: None, correlation: None };
    };
    let get = |k: &str| o.get(k);
    let s = |k: &str| get(k).and_then(text).map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
    let mut meta = Meta {
        title: s("title").unwrap_or_default(),
        id: s("id"),
        name: s("name"),
        status: s("status"),
        level: s("level"),
        description: s("description").unwrap_or_default(),
        author: s("author").unwrap_or_default(),
        date: s("date"),
        modified: s("modified"),
        license: s("license"),
        references: list(get("references").or(get("reference"))),
        tags: list(get("tags")),
        falsepositives: list(get("falsepositives")),
        fields: list(get("fields")),
        ..Default::default()
    };
    if let Some(Value::Object(ls)) = get("logsource") {
        let f = |k: &str| ls.get(k).and_then(text).map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
        meta.logsource = LogSource { category: f("category"), product: f("product"), service: f("service") };
    }
    // a correlation rule: validated by the correlation module, evaluated over its rules' matches
    let mut correlation = None;
    if get("correlation").is_some() {
        let (c, found) = super::correlation::parse(o);
        issues.extend(found.into_iter().map(|(level, m)| issue(level, m)));
        correlation = c;
    }
    if get("action").is_some() {
        issues.push(issue("unsupported", "Rule collections with 'action' (global, reset, repeat) were removed in Sigma 2.0; split them into separate rules"));
    }
    if meta.title.is_empty() {
        issues.push(issue("error", "The rule has no title"));
    } else if meta.title.chars().count() > 256 {
        issues.push(issue("warning", "The title is longer than 256 characters"));
    }
    if get("logsource").is_none_or(|v| !v.is_object()) && get("correlation").is_none() {
        issues.push(issue("error", "The rule has no logsource mapping"));
    } else if meta.logsource == LogSource::default() && get("correlation").is_none() {
        issues.push(issue("warning", "The logsource names no category, product or service"));
    }
    match &meta.id {
        Some(id) if !uuid_like(id) => issues.push(issue("warning", format!("The id '{id}' is not a UUID; the specification recommends a random UUIDv4"))),
        None => issues.push(issue("warning", "The rule has no id; it is identified by its title and log source")),
        _ => {}
    }
    if let Some(st) = &meta.status {
        if !STATUSES.contains(&st.as_str()) {
            issues.push(issue("warning", format!("Unknown status '{st}' (stable, test, experimental, deprecated, unsupported)")));
        }
        if st == "unsupported" {
            issues.push(issue("warning", "The author marked this rule unsupported: it may not work with common tools"));
        }
    }
    if let Some(l) = &meta.level {
        if !LEVELS.contains(&l.as_str()) {
            issues.push(issue("warning", format!("Unknown level '{l}' (informational, low, medium, high, critical)")));
        }
    }
    for (k, v) in [("date", &meta.date), ("modified", &meta.modified)] {
        if let Some(d) = v {
            if !date_ok(d) {
                issues.push(issue("warning", format!("The {k} '{d}' is not YYYY-MM-DD")));
            }
        }
    }
    for t in &meta.tags {
        if t.chars().any(|c| c.is_ascii_uppercase() || c.is_whitespace()) {
            issues.push(issue("warning", format!("The tag '{t}' should be lower-case without spaces")));
        }
        let Some(rest) = t.strip_prefix("attack.") else { continue };
        let up = rest.to_ascii_uppercase();
        if up.starts_with('T') && up.get(1..5).is_some_and(|d| d.chars().all(|c| c.is_ascii_digit())) {
            match crate::workspace::attack::id_state(&up) {
                crate::workspace::attack::IdState::Current => meta.techniques.push(up),
                crate::workspace::attack::IdState::Revoked { by } => {
                    issues.push(issue("warning", format!("The tag {t} names a technique ATT&CK revoked; it is now {by}")));
                    meta.techniques.push(by);
                }
                crate::workspace::attack::IdState::Deprecated => {
                    issues.push(issue("warning", format!("The tag {t} names a deprecated ATT&CK technique")));
                    meta.techniques.push(up);
                }
                crate::workspace::attack::IdState::Unknown => issues.push(issue("warning", format!("The tag {t} names no ATT&CK Enterprise technique"))),
            }
        } else if crate::workspace::attack::catalog().tactics.iter().any(|x| x.shortname == rest.replace('_', "-")) {
            meta.tactics.push(rest.replace('_', "-"));
        }
    }
    meta.techniques.sort();
    meta.techniques.dedup();

    let Some(Value::Object(det)) = get("detection") else {
        if get("correlation").is_none() {
            issues.push(issue("error", "The rule has no detection section"));
        }
        let correlation = correlation.filter(|_| !issues.iter().any(|i| i.level != "warning"));
        meta.correlation = correlation.clone();
        return Checked { meta, issues, rule: None, correlation };
    };
    let mut selections = BTreeMap::new();
    let mut names = Vec::new();
    let mut values = 0usize;
    for (name, v) in det {
        if name == "condition" {
            continue;
        }
        if name == "timeframe" {
            issues.push(issue("unsupported", "'timeframe' belongs to correlation rules"));
            continue;
        }
        names.push(name.clone());
        match selection(name, v, &mut values) {
            Ok(sel) => {
                selections.insert(name.clone(), sel);
            }
            Err((level, msg)) => issues.push(issue(level, format!("{name}: {msg}"))),
        }
    }
    if values > MAX_VALUES {
        issues.push(issue("error", format!("The rule has more than {MAX_VALUES} values")));
    }
    let mut conditions = Vec::new();
    match det.get("condition") {
        None => issues.push(issue("error", "The detection has no condition")),
        Some(c) => {
            for raw in list(Some(c)) {
                match parse_condition(&raw) {
                    Ok(e) => {
                        let mut problems = Vec::new();
                        check_refs(&e, &names, &mut problems);
                        for p in problems {
                            issues.push(issue("error", p));
                        }
                        if matches!(&e, Expr::Of(Quant::All, None)) {
                            issues.push(issue("warning", "'all of them' is discouraged by the specification"));
                        }
                        conditions.push(e);
                    }
                    Err(e) if e.starts_with("aggregations") => issues.push(issue("unsupported", e)),
                    Err(e) => issues.push(issue("error", format!("condition: {e}"))),
                }
            }
        }
    }
    let mut referenced = Vec::new();
    for e in &conditions {
        used(e, &names, &mut referenced);
    }
    for n in &names {
        if !n.starts_with('_') && !referenced.contains(n) {
            issues.push(issue("warning", format!("The search identifier '{n}' is not used by the condition")));
        }
    }
    let source = source_check(&meta.logsource);
    if let SourceCheck::Unmapped { reason } = &source {
        issues.push(issue("warning", format!("Log source: {reason}")));
    }
    let runnable = !issues.iter().any(|i| i.level != "warning") && !conditions.is_empty();
    let rule = runnable.then(|| Rule { names, selections, conditions, source });
    Checked { meta, issues, rule, correlation: None }
}

type Fail = (&'static str, String);

fn selection(name: &str, v: &Value, values: &mut usize) -> Result<Selection, Fail> {
    match v {
        Value::Object(map) => Ok(Selection { maps: vec![field_map(map, values)?] }),
        Value::Array(items) if items.iter().all(Value::is_object) && !items.is_empty() => {
            let mut maps = Vec::new();
            for it in items {
                maps.push(field_map(it.as_object().expect("checked"), values)?);
            }
            Ok(Selection { maps })
        }
        Value::Array(items) if items.iter().all(|x| !x.is_object() && !x.is_array()) => Ok(Selection { maps: vec![vec![keywords(items, &[], values)?]] }),
        Value::Array(_) => Err(("error", "a list mixes field maps and keywords".into())),
        Value::String(_) | Value::Number(_) => Ok(Selection { maps: vec![vec![keywords(std::slice::from_ref(v), &[], values)?]] }),
        _ => Err(("error", format!("'{name}' must be a field map, a list of maps or a list of keywords"))),
    }
}

fn keywords(items: &[Value], modifiers: &[String], values: &mut usize) -> Result<FieldTest, Fail> {
    let all = modifiers.iter().any(|m| m == "all");
    let mut matchers = Vec::new();
    for it in items {
        *values += 1;
        let s = text(it).ok_or(("error", "keywords must be text".to_string()))?;
        // keywords are searched anywhere in the event
        let mut t = tokens(&s);
        t.insert(0, Tok::Star);
        t.push(Tok::Star);
        matchers.push(compile(t, modifiers.iter().any(|m| m == "cased")).map_err(|e| ("error", e))?);
    }
    if let Some(m) = modifiers.iter().find(|m| !["all", "cased"].contains(&m.as_str())) {
        return Err(("unsupported", format!("the keyword modifier '{m}' is not supported")));
    }
    Ok(FieldTest { field: String::new(), modifiers: modifiers.to_vec(), kind: TestKind::Values { matchers, all, negate: false } })
}

fn field_map(map: &serde_json::Map<String, Value>, values: &mut usize) -> Result<Vec<FieldTest>, Fail> {
    if map.is_empty() {
        return Err(("error", "an empty map would match every event".into()));
    }
    let mut out = Vec::new();
    for (key, v) in map {
        let mut parts = key.split('|');
        let field = parts.next().unwrap_or("").trim().to_string();
        let modifiers: Vec<String> = parts.map(|m| m.trim().to_ascii_lowercase()).collect();
        if field.is_empty() {
            let items: Vec<Value> = match v {
                Value::Array(a) => a.clone(),
                other => vec![other.clone()],
            };
            out.push(keywords(&items, &modifiers, values)?);
            continue;
        }
        out.push(field_test(&field, &modifiers, v, values)?);
    }
    Ok(out)
}

const TRANSFORMS: &[&str] = &["base64", "base64offset", "utf16le", "wide", "utf16be", "utf16", "windash"];
const WRAPS: &[&str] = &["contains", "startswith", "endswith"];
const NUMERIC: &[&str] = &["lt", "lte", "gt", "gte"];
const TIME: &[&str] = &["minute", "hour", "day", "week", "month", "year"];

fn field_test(field: &str, modifiers: &[String], v: &Value, values: &mut usize) -> Result<FieldTest, Fail> {
    for m in modifiers {
        let known = TRANSFORMS.contains(&m.as_str()) || WRAPS.contains(&m.as_str()) || NUMERIC.contains(&m.as_str()) || ["all", "exists", "cased", "re", "i", "m", "s", "cidr", "neq", "fieldref"].contains(&m.as_str());
        if m == "expand" {
            return Err(("unsupported", "placeholders (|expand) need values defined by a processing pipeline; ExploitX has none, so the rule is refused as the specification requires".into()));
        }
        if TIME.contains(&m.as_str()) {
            return Err(("unsupported", format!("the time modifier '{m}' is not supported")));
        }
        if !known {
            return Err(("error", format!("unknown modifier '{m}'")));
        }
    }
    let has = |m: &str| modifiers.iter().any(|x| x == m);
    let label = || format!("{field}|{}", modifiers.join("|"));
    if has("exists") {
        let b = match v {
            Value::Bool(b) => *b,
            _ => return Err(("error", format!("{}: exists takes true or false", label()))),
        };
        *values += 1;
        return Ok(FieldTest { field: field.into(), modifiers: modifiers.to_vec(), kind: TestKind::Exists(b) });
    }
    let raw: Vec<Value> = match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    if raw.iter().any(Value::is_null) && raw.len() > 1 {
        return Err(("error", "null cannot be part of a list of values".into()));
    }
    let all = has("all");
    if all && raw.len() < 2 {
        return Err(("error", format!("{}: 'all' needs a list of values", label())));
    }
    let cased = has("cased");
    let negate = has("neq") && !NUMERIC.iter().any(|n| has(n));
    let mut matchers = Vec::new();
    for item in raw {
        *values += 1;
        if item.is_null() {
            matchers.push(Matcher::Null);
            continue;
        }
        let s = text(&item).ok_or(("error", format!("{field}: values must be text or numbers")))?;
        if has("fieldref") {
            matchers.push(Matcher::FieldRef(s));
            continue;
        }
        if has("cidr") {
            let net = s.trim().parse::<ipnet::IpNet>().or_else(|_| s.trim().parse::<IpAddr>().map(ipnet::IpNet::from)).map_err(|_| ("error", format!("{field}: '{s}' is not a CIDR range")))?;
            matchers.push(Matcher::Cidr(net));
            continue;
        }
        if let Some(op) = NUMERIC.iter().find(|n| has(n)) {
            let n = number(&s).ok_or(("error", format!("{field}|{op}: '{s}' is not a number")))?;
            matchers.push(Matcher::Num { op, value: n });
            continue;
        }
        if has("re") {
            if modifiers.iter().any(|m| TRANSFORMS.contains(&m.as_str()) || WRAPS.contains(&m.as_str())) {
                return Err(("unsupported", format!("{}: 're' cannot be combined with transformations or contains/startswith/endswith", label())));
            }
            let re = RegexBuilder::new(&s)
                .case_insensitive(has("i"))
                .multi_line(has("m"))
                .dot_matches_new_line(has("s"))
                .size_limit(MAX_REGEX)
                .build()
                .map_err(|e| {
                    // PCRE features the linear-time engine does not have (look-around, back-references)
                    let level = if e.to_string().contains("not supported") { "unsupported" } else { "error" };
                    (level, format!("{field}|re: {e}"))
                })?;
            matchers.push(Matcher::Regex { re, shown: s });
            continue;
        }
        // transformations and wildcards, in the order the modifiers are written
        let mut vals = vec![Val::Toks(tokens(&s))];
        for m in modifiers {
            vals = match m.as_str() {
                "base64" => vals.iter().map(|x| x.bytes(m).map(|b| Val::Bytes(b64(&b).into_bytes()))).collect::<Result<_, _>>().map_err(|e| ("error", e))?,
                "base64offset" => {
                    let mut out = Vec::new();
                    for x in &vals {
                        let b = x.bytes(m).map_err(|e| ("error", e))?;
                        // pySigma's three shifted encodings: the stable middle of each
                        for i in 0..3usize {
                            let mut padded = vec![b' '; i];
                            padded.extend_from_slice(&b);
                            let enc = b64(&padded);
                            let start = [0, 2, 3][i];
                            let end = enc.len() - [0, 3, 2][(b.len() + i) % 3];
                            if start < end {
                                out.push(Val::Bytes(enc.as_bytes()[start..end].to_vec()));
                            }
                        }
                    }
                    out
                }
                "utf16le" | "wide" | "utf16be" | "utf16" => vals.iter().map(|x| x.bytes(m).map(|b| Val::Bytes(utf16(&b, m == "utf16be", m == "utf16")))).collect::<Result<_, _>>().map_err(|e| ("error", e))?,
                "windash" => vals.into_iter().map(|x| Val::Toks(windash(x.into_toks()))).collect(),
                "contains" | "startswith" | "endswith" => vals
                    .into_iter()
                    .map(|x| {
                        let mut t = x.into_toks();
                        if m != "startswith" {
                            t.insert(0, Tok::Star);
                        }
                        if m != "endswith" {
                            t.push(Tok::Star);
                        }
                        Val::Toks(t)
                    })
                    .collect(),
                _ => vals,
            };
        }
        for v in vals {
            matchers.push(compile(v.into_toks(), cased).map_err(|e| ("error", e))?);
        }
    }
    let numeric_neq = has("neq") && NUMERIC.iter().any(|n| has(n));
    if numeric_neq {
        return Err(("error", format!("{}: 'neq' cannot be combined with lt, lte, gt or gte", label())));
    }
    Ok(FieldTest { field: field.into(), modifiers: modifiers.to_vec(), kind: TestKind::Values { matchers, all, negate } })
}

/* ───────────────────────── evaluation ───────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SelectionResult {
    pub name: String,
    pub matched: bool,
    pub hits: Vec<Hit>,
}

/// Why an event matched: every search identifier with its result, and what matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub condition: String,
    pub selections: Vec<SelectionResult>,
}

impl Rule {
    /// Whether the event belongs to the rule's log source.
    pub fn in_source(&self, ev: &Event) -> bool {
        in_source(&self.source, ev)
    }

    /// The rule's result for one event: Some with the explanation when it matches.
    pub fn evaluate(&self, ev: &Event) -> Option<Explanation> {
        if !in_source(&self.source, ev) {
            return None;
        }
        let mut results: BTreeMap<&str, (bool, Vec<Hit>)> = BTreeMap::new();
        for (name, sel) in &self.selections {
            let r = sel.eval(ev);
            results.insert(name.as_str(), (r.is_some(), r.unwrap_or_default()));
        }
        let bools: BTreeMap<&str, bool> = results.iter().map(|(k, (b, _))| (*k, *b)).collect();
        let idx = self.conditions.iter().position(|c| eval_expr(c, &bools, &self.names))?;
        let mut referenced = Vec::new();
        used(&self.conditions[idx], &self.names, &mut referenced);
        Some(Explanation {
            condition: format!("condition {}", idx + 1),
            selections: results
                .into_iter()
                .filter(|(k, _)| referenced.iter().any(|r| r == k))
                .map(|(k, (matched, hits))| SelectionResult { name: k.to_string(), matched, hits })
                .collect(),
        })
    }
}

#[cfg(test)]
#[path = "sigma_tests.rs"]
mod tests;
