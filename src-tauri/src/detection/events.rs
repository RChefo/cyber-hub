//! Events that detection rules run on: Windows event logs (EVTX), JSON and JSON Lines exports
//! (Sysmon or Winlogbeat output, cloud audit logs), and plain-text logs (one event per line).
//! Everything is read locally and bounded: at most [`MAX_EVENTS`] events per sample, and long
//! values are cut.

use std::collections::HashSet;
use std::io::{BufRead, Read};

use serde::Serialize;
use serde_json::Value;

/// Events read from one sample.
pub const MAX_EVENTS: usize = 500_000;
/// A sample file.
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_VALUE: usize = 32 * 1024;
const MAX_FIELDS: usize = 512;
/// A field name (a nested key is copied into the name of every leaf under it).
const MAX_KEY: usize = 1024;

/// One event: named fields (`EventID`, `Channel`, `CommandLine`…) and, for text logs, the line.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// where it is in the sample: "record 1234", "line 17"
    pub position: String,
    pub time: String,
    pub fields: Vec<(String, String)>,
    /// the raw line of a text log; empty for structured events
    pub text: String,
}

impl Event {
    /// A field by name, ignoring case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    fn push(&mut self, k: String, v: String) {
        if self.fields.len() < MAX_FIELDS && !self.fields.iter().any(|(x, _)| x.eq_ignore_ascii_case(&k)) {
            self.fields.push((k, cut(v)));
        }
    }
    /// [`Event::push`] for a key the caller already knows is new (it keeps its own set).
    fn push_new(&mut self, k: String, v: String) {
        if self.fields.len() < MAX_FIELDS {
            self.fields.push((k, cut(v)));
        }
    }
    /// A short description: channel and event ID, or the first characters of the line.
    pub fn label(&self) -> String {
        match (self.get("Channel"), self.get("EventID")) {
            (Some(c), Some(id)) => format!("{c} {id}"),
            _ if !self.text.is_empty() => self.text.chars().take(120).collect(),
            _ => self.fields.iter().take(3).map(|(k, v)| format!("{k}={}", v.chars().take(40).collect::<String>())).collect::<Vec<_>>().join(" "),
        }
    }
}

fn cut(v: String) -> String {
    cut_to(v, MAX_VALUE)
}

fn cut_to(mut v: String, max: usize) -> String {
    if v.len() > max {
        let mut end = max;
        while !v.is_char_boundary(end) {
            end -= 1;
        }
        v.truncate(end);
    }
    v
}

/// What a sample is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Evtx,
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub kind: Kind,
    pub events: Vec<Event>,
    /// more events than [`MAX_EVENTS`] were in the file
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// Recognizes the sample by its content: the EVTX signature, a JSON document or JSON lines, or text.
pub fn kind_of(head: &[u8]) -> Kind {
    if head.starts_with(b"ElfFile\0") {
        return Kind::Evtx;
    }
    let t = head.iter().skip_while(|b| b.is_ascii_whitespace() || **b == 0xEF || **b == 0xBB || **b == 0xBF).copied().next();
    if matches!(t, Some(b'{') | Some(b'[')) {
        Kind::Json
    } else {
        Kind::Text
    }
}

/// Reads a sample of any supported kind.
pub fn read(mut input: impl Read) -> Result<Sample, String> {
    let mut head = [0u8; 64];
    let n = read_head(&mut input, &mut head)?;
    let kind = kind_of(&head[..n]);
    if kind == Kind::Text && head[..n].contains(&0) {
        return Err("The file holds binary data, not a log (UTF-16 text logs are not read: save them as UTF-8)".into());
    }
    let chained = std::io::Cursor::new(head[..n].to_vec()).chain(input);
    match kind {
        Kind::Evtx => read_evtx(chained),
        Kind::Json => read_json(std::io::BufReader::new(chained)),
        Kind::Text => read_text(std::io::BufReader::new(chained)),
    }
}

fn read_head(input: &mut impl Read, buf: &mut [u8]) -> Result<usize, String> {
    let mut n = 0;
    while n < buf.len() {
        let r = input.read(&mut buf[n..]).map_err(|e| e.to_string())?;
        if r == 0 {
            break;
        }
        n += r;
    }
    Ok(n)
}

/// Windows event log: the system fields as Sigma names them, then the event's data fields.
pub fn read_evtx(input: impl Read) -> Result<Sample, String> {
    let mut events = Vec::new();
    let mut truncated = false;
    let summary = crate::sectools::evtx::read(input, |e| {
        if events.len() >= MAX_EVENTS {
            truncated = true;
            return;
        }
        let mut ev = Event { position: format!("record {}", e.record_id), time: e.time.clone(), ..Default::default() };
        ev.push("EventID".into(), e.event_id.to_string());
        ev.push("Channel".into(), e.channel.clone());
        ev.push("Provider_Name".into(), e.provider.clone());
        ev.push("Computer".into(), e.computer.clone());
        ev.push("Level".into(), e.level.to_string());
        if !e.user_sid.is_empty() {
            ev.push("UserID".into(), e.user_sid.clone());
        }
        for (k, v) in e.data {
            ev.push(k, windows_hex(v));
        }
        events.push(ev);
    })?;
    let mut warnings = Vec::new();
    if summary.damaged_chunks + summary.damaged_records > 0 {
        warnings.push(format!("{} damaged chunks and {} damaged records were skipped", summary.damaged_chunks, summary.damaged_records));
    }
    Ok(Sample { kind: Kind::Evtx, events, truncated, warnings })
}

/// Hexadecimal values as Windows renders them (`0x1010`, not `0x00001010`), which is what Sigma
/// rules are written against.
fn windows_hex(v: String) -> String {
    match v.strip_prefix("0x") {
        Some(h) if h.len() > 1 && h.starts_with('0') && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            let t = h.trim_start_matches('0');
            format!("0x{}", if t.is_empty() { "0" } else { t })
        }
        _ => v,
    }
}

/// A JSON array of events, one JSON object, or JSON Lines. Nested objects are flattened with dots
/// (`winlog.event_data.Image`), and each leaf is also reachable by its own name (`Image`) unless
/// two leaves share it.
pub fn read_json(mut input: impl BufRead) -> Result<Sample, String> {
    let mut events = Vec::new();
    let mut truncated = false;
    let mut warnings = Vec::new();
    let mut first = String::new();
    // JSON Lines when the first non-empty line is a complete object
    loop {
        first.clear();
        if input.read_line(&mut first).map_err(|e| e.to_string())? == 0 {
            break;
        }
        if !first.trim().is_empty() {
            break;
        }
    }
    // a one-line wrapper such as {"Records": [...]} is a document, not JSON Lines
    let line_value: Option<Value> = serde_json::from_str(first.trim_start_matches('\u{feff}').trim()).ok().filter(|v: &Value| v.is_object() && !is_wrapper(v));
    if let Some(v) = line_value {
        let mut bad = 0usize;
        let mut add = |v: Value, n: usize, events: &mut Vec<Event>| {
            if events.len() >= MAX_EVENTS {
                truncated = true;
            } else {
                events.push(event_of(&v, format!("line {n}")));
            }
        };
        add(v, 1, &mut events);
        let mut n = 1;
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                break;
            }
            n += 1;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line.trim()) {
                Ok(v) if v.is_object() => add(v, n, &mut events),
                _ => bad += 1,
            }
        }
        if bad > 0 {
            warnings.push(format!("{bad} lines were not JSON objects and were skipped"));
        }
        return Ok(Sample { kind: Kind::Json, events, truncated, warnings });
    }
    let mut rest = first;
    input.read_to_string(&mut rest).map_err(|e| e.to_string())?;
    let doc: Value = serde_json::from_str(rest.trim_start_matches('\u{feff}')).map_err(|e| format!("This is not JSON or JSON Lines: {e}"))?;
    let list: Vec<Value> = match doc {
        Value::Array(a) => a,
        // a wrapper such as {"Records": [...]} (CloudTrail) or {"events": [...]}
        ref v if is_wrapper(v) => v.as_object().and_then(|o| o.values().find(|x| x.is_array())).and_then(Value::as_array).cloned().unwrap_or_default(),
        v @ Value::Object(_) => vec![v],
        _ => return Err("The JSON holds no events (an object, an array of objects, or JSON Lines)".into()),
    };
    for (i, v) in list.into_iter().enumerate() {
        if events.len() >= MAX_EVENTS {
            truncated = true;
            break;
        }
        if v.is_object() {
            events.push(event_of(&v, format!("event {}", i + 1)));
        }
    }
    Ok(Sample { kind: Kind::Json, events, truncated, warnings })
}

/// An object whose only list holds the events: `{"Records": [{…}, …]}`.
fn is_wrapper(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        let lists: Vec<&Value> = o.values().filter(|x| x.is_array()).collect();
        lists.len() == 1 && lists[0].as_array().is_some_and(|a| !a.is_empty() && a.iter().all(Value::is_object))
    })
}

fn event_of(v: &Value, position: String) -> Event {
    let mut flat: Vec<(String, String)> = Vec::new();
    flatten("", v, &mut flat, 0);
    let mut ev = Event { position, ..Default::default() };
    // every key lowercased once (Mission 6: the lookups below lowercased and formatted strings
    // for each pair of fields, and searched lists linearly)
    let lower: Vec<String> = flat.iter().map(|(f, _)| f.to_ascii_lowercase()).collect();
    for k in ["@timestamp", "timestamp", "timecreated", "time", "eventtime", "utctime"] {
        let suffix = format!(".{k}");
        if let Some(i) = lower.iter().position(|f| f == k || f.ends_with(&suffix)) {
            ev.time = flat[i].1.clone();
            break;
        }
    }
    // leaf names, unless ambiguous
    let mut leaf: Vec<(String, String)> = Vec::new();
    let mut leaf_names: HashSet<String> = HashSet::new();
    let mut ambiguous: HashSet<String> = HashSet::new();
    for (k, val) in &flat {
        if let Some((_, name)) = k.rsplit_once('.') {
            let low = name.to_ascii_lowercase();
            if leaf_names.contains(&low) {
                ambiguous.insert(low);
            } else {
                leaf_names.insert(low);
                leaf.push((name.to_string(), val.clone()));
            }
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    for (i, (k, val)) in flat.iter().enumerate() {
        if seen.insert(lower[i].clone()) {
            ev.push_new(k.clone(), val.clone());
        }
    }
    for (k, val) in leaf {
        let low = k.to_ascii_lowercase();
        if !ambiguous.contains(&low) && seen.insert(low) {
            ev.push_new(k, val);
        }
    }
    ev
}

fn flatten(prefix: &str, v: &Value, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 16 || out.len() >= MAX_FIELDS {
        return;
    }
    let key = |k: &str| {
        let full = if prefix.is_empty() { k.to_string() } else { format!("{prefix}.{k}") };
        if full.len() <= MAX_KEY {
            return full;
        }
        // the end is kept, so the leaf's own name stays reachable
        let mut start = full.len() - MAX_KEY;
        while !full.is_char_boundary(start) {
            start += 1;
        }
        format!("…{}", &full[start..])
    };
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                flatten(&key(k), x, out, depth + 1);
            }
        }
        // lists of scalars become one value; lists of objects are flattened by index
        Value::Array(a) if a.iter().all(|x| !x.is_object() && !x.is_array()) => {
            if !prefix.is_empty() {
                out.push((prefix.to_string(), cut(a.iter().map(scalar).collect::<Vec<_>>().join(", "))));
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(64) {
                flatten(&key(&i.to_string()), x, out, depth + 1);
            }
        }
        _ => {
            if !prefix.is_empty() {
                // cut here, before the value is copied into the leaf list
                out.push((prefix.to_string(), cut(scalar(v))));
            }
        }
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// A text log: one event per line, the line as its `message`.
pub fn read_text(input: impl BufRead) -> Result<Sample, String> {
    let mut events = Vec::new();
    let mut truncated = false;
    for (i, line) in input.split(b'\n').enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&line).trim_end_matches('\r').to_string();
        if text.trim().is_empty() {
            continue;
        }
        if events.len() >= MAX_EVENTS {
            truncated = true;
            break;
        }
        let text = cut(text);
        events.push(Event { position: format!("line {}", i + 1), time: String::new(), fields: vec![("message".into(), text.clone())], text });
    }
    Ok(Sample { kind: Kind::Text, events, truncated, warnings: vec![] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_recognized_and_flattened() {
        assert_eq!(kind_of(b"ElfFile\0rest"), Kind::Evtx);
        assert_eq!(kind_of(b"  \n{\"a\":1}"), Kind::Json);
        assert_eq!(kind_of(b"\xEF\xBB\xBF[{}]"), Kind::Json);
        assert_eq!(kind_of(b"Nov  9 13:46:00 web1 sshd[1]: x"), Kind::Text);
        assert!(read(&b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"[..]).unwrap_err().contains("binary data"));
        assert!(read(&b"\xff\xfeN\x00o\x00v\x00"[..]).unwrap_err().contains("UTF-16"));

        let lines = "{\"winlog\":{\"channel\":\"Security\",\"event_data\":{\"Image\":\"C:\\\\x.exe\",\"User\":\"a\"}},\"@timestamp\":\"2026-11-09T10:00:00Z\"}\n\nnot json\n{\"Image\":\"b\"}\n";
        let s = read(lines.as_bytes()).unwrap();
        assert_eq!((s.kind, s.events.len()), (Kind::Json, 2));
        let e = &s.events[0];
        assert_eq!(e.get("winlog.event_data.image"), Some("C:\\x.exe"), "flattened, any case");
        assert_eq!(e.get("Image"), Some("C:\\x.exe"), "and by the leaf name");
        assert_eq!(e.time, "2026-11-09T10:00:00Z");
        assert_eq!(s.warnings, vec!["1 lines were not JSON objects and were skipped".to_string()]);

        let wrapped = read(r#"{"Records":[{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"}},{"eventName":"GetObject"}]}"#.as_bytes()).unwrap();
        assert_eq!(wrapped.events.len(), 2, "a CloudTrail-style wrapper is unwrapped");
        assert_eq!(wrapped.events[0].get("userIdentity.type"), Some("Root"));

        let dup = read(r#"[{"a":{"name":"x"},"b":{"name":"y"}}]"#.as_bytes()).unwrap();
        assert_eq!(dup.events[0].get("name"), None, "an ambiguous leaf name is not guessed");

        assert_eq!(
            (windows_hex("0x00001010".into()).as_str(), windows_hex("0x0000".into()).as_str(), windows_hex("0x1fffff".into()).as_str(), windows_hex("0xZZ".into()).as_str()),
            ("0x1010", "0x0", "0x1fffff", "0xZZ"),
            "hexadecimal values as Windows renders them"
        );
        let text = read("first line\r\n\nsecond line\n".as_bytes()).unwrap();
        assert_eq!((text.kind, text.events.len(), text.events[1].position.as_str(), text.events[0].get("message")), (Kind::Text, 2, "line 3", Some("first line")));
    }

    #[test]
    fn long_keys_and_values_are_cut_while_flattening() {
        let key = "k".repeat(100_000);
        let line = format!("{{\"{key}\":{{\"a\":\"x\",\"b\":\"{}\"}}}}\n", "v".repeat(100_000));
        let s = read(line.as_bytes()).unwrap();
        let ev = &s.events[0];
        assert!(ev.fields.iter().all(|(k, v)| k.len() <= MAX_KEY + 3 && v.len() <= MAX_VALUE), "{:?}", ev.fields.iter().map(|(k, v)| (k.len(), v.len())).collect::<Vec<_>>());
        assert_eq!(ev.get("a"), Some("x"), "the leaf keeps its own name");
    }
}
