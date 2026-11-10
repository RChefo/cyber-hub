//! Sigma correlation rules (specification v2.1.0): meta-rules that combine the matches of other
//! rules over time, separately for each group of events (the same user, the same host…).
//!
//! * Supported types: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`
//!   and `value_avg`, with `group-by`, field `aliases`, `timespan`, conditions (`gt`, `gte`, `lt`,
//!   `lte`, `eq`, `neq`, two of them for a range), `generate`, and chains (a correlation that
//!   refers to another correlation).
//! * Refused with the reason: `value_percentile` (the specification does not say how the
//!   percentile is computed, so Cyber Hub does not guess), and anything malformed.
//! * Windows slide: they are not cut at clock boundaries, as the specification recommends. In each
//!   group a window starts at each matching event and covers the timespan after it; a match is a
//!   window whose count, distinct count, sum or average satisfies the condition, and the next
//!   window starts after its last event, so a long burst is reported once rather than per event.
//! * Events without a usable time, or without the fields the correlation groups or measures by,
//!   take no part; the outcome says how many were left out and why. Nothing is inferred.
//! * Bounded: [`MAX_OCCURRENCES`] rule matches per correlation, [`MAX_GROUPS`] groups,
//!   [`MAX_TIMESPAN`], chains of [`MAX_CHAIN`] correlations, [`EVENTS_KEPT`] events listed per match.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::events::{Event, Sample};
use super::sigma;

pub const MAX_TIMESPAN: i64 = 31 * 86_400;
pub const MAX_RULES: usize = 20;
pub const MAX_CHAIN: usize = 5;
pub const MAX_OCCURRENCES: usize = 1_000_000;
pub const MAX_GROUPS: usize = 100_000;
pub const EVENTS_KEPT: usize = 25;
/// matches listed per correlation (the count is always complete)
pub const MAX_FOUND: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
    ValueSum,
    ValueAvg,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::EventCount => "event_count",
            Kind::ValueCount => "value_count",
            Kind::Temporal => "temporal",
            Kind::TemporalOrdered => "temporal_ordered",
            Kind::ValueSum => "value_sum",
            Kind::ValueAvg => "value_avg",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        [Kind::EventCount, Kind::ValueCount, Kind::Temporal, Kind::TemporalOrdered, Kind::ValueSum, Kind::ValueAvg].into_iter().find(|k| k.name() == s)
    }
    fn measures_field(self) -> bool {
        matches!(self, Kind::ValueCount | Kind::ValueSum | Kind::ValueAvg)
    }
    fn temporal(self) -> bool {
        matches!(self, Kind::Temporal | Kind::TemporalOrdered)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
}

impl Op {
    fn parse(k: &str) -> Option<Op> {
        Some(match k {
            "gt" => Op::Gt,
            "gte" => Op::Gte,
            "lt" => Op::Lt,
            "lte" => Op::Lte,
            "eq" => Op::Eq,
            "neq" => Op::Neq,
            _ => return None,
        })
    }
    fn holds(self, x: f64, v: f64) -> bool {
        match self {
            Op::Gt => x > v,
            Op::Gte => x >= v,
            Op::Lt => x < v,
            Op::Lte => x <= v,
            Op::Eq => (x - v).abs() < 1e-9,
            Op::Neq => (x - v).abs() >= 1e-9,
        }
    }
    fn symbol(self) -> &'static str {
        match self {
            Op::Gt => ">",
            Op::Gte => "≥",
            Op::Lt => "<",
            Op::Lte => "≤",
            Op::Eq => "=",
            Op::Neq => "≠",
        }
    }
}

/// A validated correlation section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Correlation {
    #[serde(rename = "type")]
    pub kind: Kind,
    /// the referenced rules or correlations, by name or id, in the order written
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    /// seconds
    pub timespan: i64,
    pub timespan_text: String,
    pub condition: Vec<(Op, f64)>,
    /// `condition.field`: one field, or several for value_count (counted together)
    pub fields: Vec<String>,
    /// alias → (rule name → field name in that rule's events)
    pub aliases: BTreeMap<String, BTreeMap<String, String>>,
    /// the referenced rules also run on their own
    pub generate: bool,
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn strings(v: Option<&Value>) -> Result<Vec<String>, ()> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::String(s)) => Ok(vec![s.trim().to_string()]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(|s| s.trim().to_string()).ok_or(())).collect(),
        _ => Err(()),
    }
}

/// `30s`, `5m`, `1h`, `2d` (lowercase, as the specification requires).
pub fn timespan(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let unit = s.chars().last().ok_or("The timespan is empty")?;
    let n: i64 = s[..s.len() - unit.len_utf8()].parse().map_err(|_| format!("The timespan '{s}' is not a number and a unit (30s, 5m, 1h, 2d)"))?;
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err(format!("The timespan '{s}' has no unit: s, m, h or d (lowercase)")),
    };
    let secs = n.checked_mul(mult).filter(|v| *v > 0).ok_or_else(|| format!("The timespan '{s}' must be greater than zero"))?;
    if secs > MAX_TIMESPAN {
        return Err(format!("The timespan '{s}' is longer than Cyber Hub's limit of 31 days"));
    }
    Ok(secs)
}

/// Validates a rule document that has a `correlation` section. Issues are (level, message) with
/// the levels of [`sigma::Issue`]: error, unsupported, warning.
pub fn parse(doc: &serde_json::Map<String, Value>) -> (Option<Correlation>, Vec<(&'static str, String)>) {
    let mut issues: Vec<(&'static str, String)> = Vec::new();
    let Some(Value::Object(o)) = doc.get("correlation") else {
        return (None, vec![("error", "The correlation section is not a mapping".into())]);
    };
    for k in o.keys() {
        if !["type", "rules", "group-by", "timespan", "condition", "aliases", "generate"].contains(&k.as_str()) {
            issues.push(("warning", format!("Unknown correlation attribute '{k}'")));
        }
    }
    if doc.contains_key("detection") {
        issues.push(("error", "A correlation rule has no detection section: it refers to other rules instead".into()));
    }
    let kind = match o.get("type").and_then(Value::as_str).map(str::trim) {
        Some("value_percentile") => {
            issues.push(("unsupported", "value_percentile correlations: the specification does not define how the percentile is computed, so Cyber Hub does not evaluate them".into()));
            None
        }
        Some(t) => match Kind::parse(t) {
            Some(k) => Some(k),
            None => {
                issues.push(("error", format!("Unknown correlation type '{t}' (event_count, value_count, temporal, temporal_ordered, value_sum, value_avg)")));
                None
            }
        },
        None => {
            issues.push(("error", "The correlation has no type".into()));
            None
        }
    };
    let rules = match strings(o.get("rules")) {
        Ok(r) if r.iter().all(|x| !x.is_empty()) && !r.is_empty() => r,
        Ok(_) => {
            issues.push(("error", "The correlation refers to no rules".into()));
            vec![]
        }
        Err(()) => {
            issues.push(("error", "rules is a list of rule names or ids".into()));
            vec![]
        }
    };
    if rules.len() > MAX_RULES {
        issues.push(("error", format!("The correlation refers to more than {MAX_RULES} rules")));
    }
    let mut seen = Vec::new();
    for r in &rules {
        if seen.contains(r) {
            issues.push(("warning", format!("The rule '{r}' is listed twice")));
        }
        seen.push(r.clone());
    }
    let group_by = match strings(o.get("group-by")) {
        Ok(g) => g.into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>(),
        Err(()) => {
            issues.push(("error", "group-by is a list of field names".into()));
            vec![]
        }
    };
    if group_by.is_empty() && !o.contains_key("group-by") {
        issues.push(("warning", "No group-by: every matching event belongs to one group".into()));
    }
    let (span, span_text) = match o.get("timespan").and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }) {
        Some(t) => match timespan(&t) {
            Ok(s) => (s, t.trim().to_string()),
            Err(e) => {
                issues.push(("error", e));
                (0, String::new())
            }
        },
        None => {
            issues.push(("error", "The correlation has no timespan (30s, 5m, 1h, 2d)".into()));
            (0, String::new())
        }
    };
    let mut condition = Vec::new();
    let mut fields = Vec::new();
    match o.get("condition") {
        None | Some(Value::Null) => {}
        Some(Value::Object(c)) => {
            for (k, v) in c {
                if k == "field" {
                    match strings(Some(v)) {
                        Ok(f) if !f.is_empty() && f.iter().all(|x| !x.is_empty()) => fields = f,
                        _ => issues.push(("error", "condition.field is a field name".into())),
                    }
                    continue;
                }
                match (Op::parse(k), num(v)) {
                    (Some(op), Some(n)) => condition.push((op, n)),
                    (Some(_), None) => issues.push(("error", format!("condition.{k} must be a number"))),
                    (None, _) => issues.push(("error", format!("Unknown condition '{k}' (gt, gte, lt, lte, eq, neq, field)"))),
                }
            }
            if condition.len() > 2 {
                issues.push(("error", "A condition has one criterion, or two for a range".into()));
            }
        }
        Some(_) => issues.push(("error", "The condition is a mapping such as {gte: 10}".into())),
    }
    if let Some(k) = kind {
        if !k.temporal() && condition.is_empty() {
            issues.push(("error", format!("A {} correlation needs a condition such as gte: 10", k.name())));
        }
        if k.measures_field() && fields.is_empty() {
            issues.push(("error", format!("A {} correlation needs condition.field", k.name())));
        }
        if matches!(k, Kind::ValueSum | Kind::ValueAvg) && fields.len() > 1 {
            issues.push(("error", format!("A {} correlation measures one field", k.name())));
        }
        if !k.measures_field() && !fields.is_empty() {
            issues.push(("warning", format!("condition.field has no effect on a {} correlation", k.name())));
            fields.clear();
        }
        if k == Kind::TemporalOrdered && !condition.is_empty() {
            issues.push(("warning", "Cyber Hub requires every rule of a temporal_ordered correlation, in order; its condition is not used".into()));
            condition.clear();
        }
    }
    let mut aliases = BTreeMap::new();
    match o.get("aliases") {
        None | Some(Value::Null) => {}
        Some(Value::Object(a)) => {
            for (alias, map) in a {
                let Value::Object(m) = map else {
                    issues.push(("error", format!("The alias '{alias}' maps rule names to field names")));
                    continue;
                };
                let mut per = BTreeMap::new();
                for (rule, field) in m {
                    match field.as_str() {
                        Some(f) if !f.trim().is_empty() => {
                            if !rules.contains(rule) {
                                issues.push(("warning", format!("The alias '{alias}' names '{rule}', which the correlation does not refer to")));
                            }
                            per.insert(rule.clone(), f.trim().to_string());
                        }
                        _ => issues.push(("error", format!("The alias '{alias}' needs a field name for '{rule}'"))),
                    }
                }
                aliases.insert(alias.clone(), per);
            }
        }
        Some(_) => issues.push(("error", "aliases is a mapping of alias names".into())),
    }
    // the specification lists `generate` with the top-level attributes; pySigma reads it inside
    // the correlation section: both are accepted
    let generate = match o.get("generate").or_else(|| doc.get("generate")) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            issues.push(("error", "generate is true or false".into()));
            false
        }
    };
    let ok = !issues.iter().any(|(l, _)| *l != "warning");
    let corr = match kind {
        Some(kind) if ok => Some(Correlation { kind, rules, group_by, timespan: span, timespan_text: span_text, condition, fields, aliases, generate }),
        _ => None,
    };
    (corr, issues)
}

impl Correlation {
    fn holds(&self, x: f64) -> bool {
        self.condition.iter().all(|(op, v)| op.holds(x, *v))
    }

    /// "count ≥ 10", "distinct User ≥ 100", "sum of bytes_sent > 1000000", "all 3 rules in order".
    pub fn condition_text(&self) -> String {
        let ops = |what: &str| self.condition.iter().map(|(op, v)| format!("{what} {} {v}", op.symbol())).collect::<Vec<_>>().join(" and ");
        match self.kind {
            Kind::EventCount => ops("count"),
            Kind::ValueCount => ops(&format!("distinct {}", self.fields.join("+"))),
            Kind::ValueSum => ops(&format!("sum of {}", self.fields.join(""))),
            Kind::ValueAvg => ops(&format!("average of {}", self.fields.join(""))),
            Kind::Temporal if self.condition.is_empty() => format!("all {} rules", self.rules.len()),
            Kind::Temporal => ops("rules matched"),
            Kind::TemporalOrdered => format!("all {} rules in order", self.rules.len()),
        }
    }

    /// The event's field for a group-by entry or the condition field, through the aliases.
    fn field_of<'a>(&self, name: &str, rule_name: &str, ev: &'a Event) -> Option<&'a str> {
        let field = self.aliases.get(name).and_then(|m| m.get(rule_name)).map(String::as_str).unwrap_or(name);
        ev.get(field).filter(|v| !v.is_empty())
    }
}

/* ───────────────────────── time ───────────────────────── */

/// Seconds since the epoch of an event time: RFC 3339 / ISO 8601 (with Z, an offset, or none,
/// read as UTC), "YYYY-MM-DD HH:MM:SS[.f]", or epoch seconds or milliseconds.
pub fn epoch(t: &str) -> Option<f64> {
    let t = t.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
        return Some(d.timestamp_micros() as f64 / 1e6);
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(t.trim_end_matches('Z'), f) {
            return Some(d.and_utc().timestamp_micros() as f64 / 1e6);
        }
    }
    if t.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let v: f64 = t.parse().ok()?;
        // milliseconds from 2001 on are larger than any plausible time in seconds
        return Some(if v > 1e12 { v / 1000.0 } else { v });
    }
    None
}

fn iso(at: f64) -> String {
    chrono::DateTime::from_timestamp_micros((at * 1e6).round() as i64).map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/* ───────────────────────── evaluation ───────────────────────── */

/// One event that a referenced rule matched (or one match of a referenced correlation).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventRef {
    /// the referenced rule's name or id, as the correlation writes it
    pub rule: String,
    pub position: String,
    pub time: String,
    /// where the event is: the evidence or sample it was read from
    pub source: String,
    /// the evidence (or sample) id
    pub source_id: i64,
}

#[derive(Debug, Clone)]
pub struct Occurrence {
    /// index of the rule in the correlation's `rules`
    pub rule: usize,
    pub at: f64,
    /// order of reading, for events with the same time
    pub seq: usize,
    pub group: Vec<String>,
    pub value: Option<String>,
    pub event: EventRef,
}

/// A correlation match: the group, the window and what was measured in it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    pub group: Vec<(String, String)>,
    pub first: String,
    pub last: String,
    #[serde(skip)]
    pub last_at: f64,
    /// the count, distinct count, sum, average, or number of rules matched
    pub value: f64,
    pub events: Vec<EventRef>,
    /// events in the window (all of them, even when only the first are listed)
    pub total: usize,
}

impl Found {
    /// The evidence or sample of the window's last event: where the match is stored.
    pub fn source_id(&self) -> i64 {
        self.events.last().map(|e| e.source_id).unwrap_or_default()
    }

    /// "window 2026-11-09T10:00:00Z – 2026-11-09T10:09:30Z · User=alice": stable across runs.
    pub fn position(&self) -> String {
        let g = self.group.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
        if g.is_empty() {
            format!("window {} – {}", self.first, self.last)
        } else {
            format!("window {} – {} · {g}", self.first, self.last)
        }
    }

    pub fn explanation(&self, c: &Correlation, titles: &[String]) -> Value {
        json!({
            "kind": "correlation",
            "type": c.kind.name(),
            "rules": c.rules.iter().zip(titles).map(|(r, t)| json!({ "ref": r, "title": t })).collect::<Vec<_>>(),
            "groupBy": self.group,
            "timespan": c.timespan_text,
            "condition": c.condition_text(),
            "value": self.value,
            "first": self.first,
            "last": self.last,
            "events": self.events,
            "total": self.total,
            "kept": self.events.len(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub found: Vec<Found>,
    /// every match, even beyond the listed ones
    pub matched: usize,
    pub notes: Vec<String>,
}

fn emit(c: &Correlation, g: &[&Occurrence], picked: &[usize], value: f64, out: &mut Outcome) {
    out.matched += 1;
    if out.found.len() >= MAX_FOUND {
        return;
    }
    let first = g[picked[0]];
    let last = g[*picked.last().expect("a window has events")];
    out.found.push(Found {
        group: c.group_by.iter().cloned().zip(first.group.iter().cloned()).collect(),
        first: iso(first.at),
        last: iso(last.at),
        last_at: last.at,
        value,
        events: picked.iter().take(EVENTS_KEPT).map(|i| g[*i].event.clone()).collect(),
        total: picked.len(),
    });
}

/// The windows of one group: a window starts at each event and covers the timespan after it (it
/// slides; it is not cut at clock boundaries). `add`/`remove` keep the measure, `measure` reads
/// it. A match is a window whose measure satisfies the condition; the next window starts after
/// its last event, so a long burst is one match rather than one per event.
fn slide(c: &Correlation, g: &[&Occurrence], mut add: impl FnMut(usize), mut remove: impl FnMut(usize), measure: impl Fn() -> f64, out: &mut Outcome) {
    let n = g.len();
    let span = c.timespan as f64;
    let (mut i, mut j) = (0usize, 0usize); // the window is [i, j)
    while i < n {
        while j < n && g[j].at - g[i].at <= span {
            add(j);
            j += 1;
        }
        let value = measure();
        if c.holds(value) {
            emit(c, g, &(i..j).collect::<Vec<_>>(), value, out);
            for k in i..j {
                remove(k);
            }
            i = j;
            continue;
        }
        remove(i);
        i += 1;
    }
}

/// Evaluates the correlation over the occurrences of its rules.
pub fn evaluate(c: &Correlation, occ: Vec<Occurrence>) -> Outcome {
    let mut out = Outcome::default();
    let mut groups: BTreeMap<Vec<String>, Vec<Occurrence>> = BTreeMap::new();
    let mut overflow = 0usize;
    for o in occ {
        let len = groups.len();
        match groups.get_mut(&o.group) {
            Some(v) => v.push(o),
            None if len < MAX_GROUPS => {
                groups.insert(o.group.clone(), vec![o]);
            }
            None => overflow += 1,
        }
    }
    if overflow > 0 {
        out.notes.push(format!("More than {MAX_GROUPS} groups: {overflow} matching events of further groups were not correlated"));
    }
    for (_, mut list) in groups {
        list.sort_by(|a, b| a.at.total_cmp(&b.at).then(a.seq.cmp(&b.seq)));
        let g: Vec<&Occurrence> = list.iter().collect();
        match c.kind {
            Kind::EventCount => {
                let count = std::cell::Cell::new(0usize);
                slide(c, &g, |_| count.set(count.get() + 1), |_| count.set(count.get() - 1), || count.get() as f64, &mut out);
            }
            Kind::ValueCount => {
                let seen: std::cell::RefCell<HashMap<&str, usize>> = Default::default();
                let val = |k: usize| g[k].value.as_deref().unwrap_or_default();
                slide(
                    c,
                    &g,
                    |k| *seen.borrow_mut().entry(val(k)).or_default() += 1,
                    |k| {
                        let mut s = seen.borrow_mut();
                        if let Some(n) = s.get_mut(val(k)) {
                            *n -= 1;
                            if *n == 0 {
                                s.remove(val(k));
                            }
                        }
                    },
                    || seen.borrow().len() as f64,
                    &mut out,
                );
            }
            Kind::ValueSum | Kind::ValueAvg => {
                let nums: Vec<f64> = g.iter().map(|o| o.value.as_deref().and_then(|v| v.trim().parse().ok()).unwrap_or(0.0)).collect();
                let acc = std::cell::Cell::new((0.0f64, 0usize));
                let avg = c.kind == Kind::ValueAvg;
                slide(
                    c,
                    &g,
                    |k| acc.set((acc.get().0 + nums[k], acc.get().1 + 1)),
                    |k| acc.set((acc.get().0 - nums[k], acc.get().1 - 1)),
                    || {
                        let (s, n) = acc.get();
                        if avg { if n == 0 { 0.0 } else { s / n as f64 } } else { s }
                    },
                    &mut out,
                );
            }
            Kind::Temporal => {
                let per: std::cell::RefCell<Vec<usize>> = std::cell::RefCell::new(vec![0; c.rules.len()]);
                let all = c.condition.is_empty();
                let wanted = c.rules.len() as f64;
                let measure = || per.borrow().iter().filter(|n| **n > 0).count() as f64;
                if all {
                    // without a condition every rule must appear
                    let c2 = Correlation { condition: vec![(Op::Gte, wanted)], ..c.clone() };
                    slide(&c2, &g, |k| per.borrow_mut()[g[k].rule] += 1, |k| per.borrow_mut()[g[k].rule] -= 1, measure, &mut out);
                } else {
                    slide(c, &g, |k| per.borrow_mut()[g[k].rule] += 1, |k| per.borrow_mut()[g[k].rule] -= 1, measure, &mut out);
                }
            }
            Kind::TemporalOrdered => ordered(c, &g, &mut out),
        }
    }
    out
}

/// temporal_ordered: an occurrence of every rule, in the listed order, within the timespan from
/// the first one. Matches do not overlap.
fn ordered(c: &Correlation, g: &[&Occurrence], out: &mut Outcome) {
    let k = c.rules.len();
    let mut by_rule: Vec<Vec<usize>> = vec![Vec::new(); k];
    for (i, o) in g.iter().enumerate() {
        if o.rule < k {
            by_rule[o.rule].push(i);
        }
    }
    let span = c.timespan as f64;
    let mut done_until: Option<usize> = None;
    for &start in &by_rule[0] {
        if done_until.is_some_and(|d| start <= d) {
            continue;
        }
        let mut chain = vec![start];
        let mut cur = start;
        let mut complete = true;
        for list in by_rule.iter().skip(1) {
            let next = list.partition_point(|&p| p <= cur);
            match list.get(next) {
                Some(&p) if g[p].at - g[start].at <= span => {
                    chain.push(p);
                    cur = p;
                }
                Some(_) => {
                    complete = false;
                    break;
                }
                // no later event of that rule at all: no later start can complete either
                None => return,
            }
        }
        if complete {
            emit(c, g, &chain, k as f64, out);
            done_until = Some(cur);
        }
    }
}

/* ───────────────────────── chains of correlations over samples ───────────────────────── */

/// What a reference of a correlation resolves to.
pub enum Resolved {
    Rule { title: String, rule: Box<sigma::Rule> },
    Correlation { key: String, title: String, correlation: Correlation },
}

struct Node {
    corr: Correlation,
    titles: Vec<String>,
    /// the node a match feeds, and its reference index there
    parent: Option<(usize, usize)>,
    occ: Vec<Occurrence>,
    left_out: BTreeMap<&'static str, usize>,
    capped: bool,
}

struct Leaf {
    node: usize,
    index: usize,
    rule: Box<sigma::Rule>,
}

/// A correlation with everything it refers to, resolved: base rules (leaves) and correlations
/// (nodes, the first one being the root). Feed it samples, then finish it.
pub struct Tree {
    nodes: Vec<Node>,
    leaves: Vec<Leaf>,
    seq: usize,
}

impl Tree {
    /// Resolves every reference (`resolve` looks a name or id up in the library) and refuses
    /// cycles, chains deeper than [`MAX_CHAIN`] and references that resolve to nothing.
    pub fn build(root_key: &str, root: Correlation, resolve: &mut dyn FnMut(&str) -> Result<Resolved, String>) -> Result<Tree, String> {
        let mut t = Tree { nodes: Vec::new(), leaves: Vec::new(), seq: 0 };
        t.add(root, None, &mut vec![root_key.to_ascii_lowercase()], resolve)?;
        Ok(t)
    }

    fn add(&mut self, corr: Correlation, parent: Option<(usize, usize)>, path: &mut Vec<String>, resolve: &mut dyn FnMut(&str) -> Result<Resolved, String>) -> Result<(), String> {
        if path.len() > MAX_CHAIN {
            return Err(format!("The chain of correlations is deeper than {MAX_CHAIN}"));
        }
        let id = self.nodes.len();
        let refs = corr.rules.clone();
        self.nodes.push(Node { corr, titles: Vec::new(), parent, occ: Vec::new(), left_out: BTreeMap::new(), capped: false });
        for (i, r) in refs.iter().enumerate() {
            match resolve(r)? {
                Resolved::Rule { title, rule } => {
                    self.nodes[id].titles.push(title);
                    self.leaves.push(Leaf { node: id, index: i, rule });
                }
                Resolved::Correlation { key, title, correlation } => {
                    let key = key.to_ascii_lowercase();
                    if path.contains(&key) {
                        return Err(format!("The correlation refers to itself through '{r}'"));
                    }
                    self.nodes[id].titles.push(title);
                    path.push(key);
                    self.add(correlation, Some((id, i)), path, resolve)?;
                    path.pop();
                }
            }
        }
        Ok(())
    }

    /// Every referenced base rule, run over the sample's events; their matches are kept (small)
    /// and the sample can be dropped.
    pub fn feed(&mut self, sample: &Sample, source_id: i64, source: &str) {
        for li in 0..self.leaves.len() {
            let (node, index) = (self.leaves[li].node, self.leaves[li].index);
            let rule_name = self.nodes[node].corr.rules[index].clone();
            for ev in &sample.events {
                if self.leaves[li].rule.evaluate(ev).is_none() {
                    continue;
                }
                let n = &mut self.nodes[node];
                let Some(at) = epoch(&ev.time) else {
                    *n.left_out.entry("without a usable time").or_default() += 1;
                    continue;
                };
                let group: Option<Vec<String>> = n.corr.group_by.iter().map(|g| n.corr.field_of(g, &rule_name, ev).map(str::to_string)).collect();
                let Some(group) = group else {
                    *n.left_out.entry("without a group-by field").or_default() += 1;
                    continue;
                };
                let value = if n.corr.fields.is_empty() {
                    None
                } else {
                    let vals: Option<Vec<&str>> = n.corr.fields.iter().map(|f| n.corr.field_of(f, &rule_name, ev)).collect();
                    match vals {
                        Some(v) if matches!(n.corr.kind, Kind::ValueSum | Kind::ValueAvg) && v[0].trim().parse::<f64>().is_err() => {
                            *n.left_out.entry("with a value that is not a number").or_default() += 1;
                            continue;
                        }
                        Some(v) => Some(v.join("\u{1f}")),
                        None => {
                            *n.left_out.entry("without the measured field").or_default() += 1;
                            continue;
                        }
                    }
                };
                if n.occ.len() >= MAX_OCCURRENCES {
                    n.capped = true;
                    continue;
                }
                self.seq += 1;
                n.occ.push(Occurrence { rule: index, at, seq: self.seq, group, value, event: EventRef { rule: rule_name.clone(), position: ev.position.clone(), time: ev.time.clone(), source: source.to_string(), source_id } });
            }
        }
    }

    /// The referenced rules' titles, in the root correlation's order.
    pub fn titles(&self) -> &[String] {
        &self.nodes[0].titles
    }

    pub fn correlation(&self) -> &Correlation {
        &self.nodes[0].corr
    }

    /// Evaluates the correlations from the innermost out; a correlation's matches are events for
    /// the correlation that refers to it (at the time of the window's last event).
    pub fn finish(mut self) -> Outcome {
        let mut root = Outcome::default();
        let mut inner_notes: Vec<String> = Vec::new();
        for id in (0..self.nodes.len()).rev() {
            let occ = std::mem::take(&mut self.nodes[id].occ);
            let mut out = evaluate(&self.nodes[id].corr, occ);
            let n = &self.nodes[id];
            for (why, count) in &n.left_out {
                out.notes.push(format!("{count} matching event{} {why} took no part", if *count == 1 { "" } else { "s" }));
            }
            if n.capped {
                out.notes.push(format!("Only the first {MAX_OCCURRENCES} matching events were correlated"));
            }
            match n.parent {
                None => root = out,
                Some((p, index)) => {
                    let inner_name = self.nodes[p].corr.rules[index].clone();
                    let notes = out.notes.clone();
                    for f in out.found {
                        let outer = &self.nodes[p].corr;
                        // the outer group-by values, from the inner match's group (through aliases)
                        let group: Option<Vec<String>> = outer
                            .group_by
                            .iter()
                            .map(|g| {
                                let field = outer.aliases.get(g).and_then(|m| m.get(&inner_name)).cloned().unwrap_or_else(|| g.clone());
                                f.group.iter().find(|(k, _)| k.eq_ignore_ascii_case(&field)).map(|(_, v)| v.clone())
                            })
                            .collect();
                        let Some(group) = group else {
                            *self.nodes[p].left_out.entry("from a correlation that does not group by the same fields").or_default() += 1;
                            continue;
                        };
                        self.seq += 1;
                        let last = f.events.last().cloned().unwrap_or(EventRef { rule: inner_name.clone(), position: String::new(), time: f.last.clone(), source: String::new(), source_id: 0 });
                        let ev = EventRef { rule: inner_name.clone(), position: f.position(), time: f.last.clone(), source: last.source, source_id: last.source_id };
                        self.nodes[p].occ.push(Occurrence { rule: index, at: f.last_at, seq: self.seq, group, value: None, event: ev });
                    }
                    inner_notes.extend(notes.into_iter().map(|n| format!("{inner_name}: {n}")));
                }
            }
        }
        root.notes.extend(inner_notes);
        root.notes.sort();
        root.notes.dedup();
        root
    }
}

/// What correlation rules support, for the engine description.
pub fn capabilities() -> Value {
    json!({
        "types": ["event_count", "value_count", "temporal", "temporal_ordered", "value_sum", "value_avg"],
        "unsupported": ["value_percentile"],
        "maxTimespan": "31d",
        "maxChain": MAX_CHAIN,
    })
}

#[cfg(test)]
#[path = "correlation_tests.rs"]
mod tests;
