//! YAML documents read into JSON values, for the files Cyber Hub analyzes (API definitions,
//! Kubernetes manifests, Compose files).
//!
//! The input is untrusted:
//! * the caller limits its size;
//! * nesting is limited to [`MAX_DEPTH`] levels;
//! * aliases are expanded against a budget of [`MAX_NODES`] values, so a document built to
//!   multiply itself through aliases ("billion laughs") is refused instead of filling memory.
//!
//! Plain scalars follow the YAML 1.2 core schema (`true`, `null`, integers, floats); quoted and
//! block scalars stay strings. Merge keys (`<<: *defaults`, YAML 1.1, common in Compose files) are
//! applied: keys written in the mapping win over merged ones.

use std::collections::HashMap;

use serde_json::{Map, Number, Value};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Deepest nesting accepted (mappings and sequences).
pub const MAX_DEPTH: usize = 128;
/// Values in all documents together, with every alias expansion counted.
pub const MAX_NODES: usize = 1_000_000;
/// Scalar text in all documents together, with every alias expansion counted: a 256 KB scalar
/// aliased 60,000 times is 60,000 nodes but 15 GB of text.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;

/// Every document of a YAML stream.
///
/// Events are pulled one at a time from yaml-rust2's parser, which is iterative, rather than
/// through its `load`, which recurses once per nesting level without a limit: a few kilobytes of
/// indented YAML would overflow the stack and end the app. Reading stops at the first problem,
/// including nesting deeper than [`MAX_DEPTH`].
pub fn parse_documents(text: &str) -> Result<Vec<Value>, String> {
    let mut b = Builder::default();
    let mut parser = Parser::new_from_str(text);
    loop {
        let (ev, mark) = parser.next_token().map_err(|e| format!("not valid YAML: {e}"))?;
        let end = matches!(ev, Event::StreamEnd);
        b.on_event(ev, mark);
        if let Some(e) = b.error.take() {
            return Err(e);
        }
        if end {
            return Ok(b.docs);
        }
    }
}

/// The first document of a YAML stream (an empty stream is an error).
pub fn parse_one(text: &str) -> Result<Value, String> {
    parse_documents(text)?.into_iter().next().ok_or_else(|| "the file has no YAML document".to_string())
}

/// A value with its size: the nodes it holds and its depth.
struct Sized {
    value: Value,
    nodes: usize,
    depth: usize,
    /// scalar text it holds, in bytes
    bytes: usize,
}

enum Frame {
    Seq { items: Vec<Value>, anchor: usize, nodes: usize, depth: usize, bytes: usize },
    Map { map: Map<String, Value>, key: Option<String>, anchor: usize, nodes: usize, depth: usize, bytes: usize },
}

#[derive(Default)]
struct Builder {
    docs: Vec<Value>,
    stack: Vec<Frame>,
    root: Option<Value>,
    anchors: HashMap<usize, (Value, usize, usize, usize)>,
    nodes: usize,
    bytes: usize,
    error: Option<String>,
}

impl Builder {
    fn fail(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(msg);
        }
        self.stack.clear();
        self.anchors.clear();
        self.root = None;
    }

    fn remember(&mut self, anchor: usize, s: &Sized) {
        if anchor > 0 {
            self.anchors.insert(anchor, (s.value.clone(), s.nodes, s.depth, s.bytes));
        }
    }

    /// Places a finished value into the collection being built, or makes it the document.
    fn emit(&mut self, s: Sized, mark: Marker) {
        if self.stack.len() + s.depth > MAX_DEPTH {
            return self.fail(format!("the YAML nesting is deeper than {MAX_DEPTH} levels (line {})", mark.line()));
        }
        match self.stack.last_mut() {
            None => self.root = Some(s.value),
            Some(Frame::Seq { items, nodes, depth, bytes, .. }) => {
                items.push(s.value);
                *nodes += s.nodes;
                *bytes += s.bytes;
                *depth = (*depth).max(s.depth + 1);
            }
            Some(Frame::Map { map, key, nodes, depth, bytes, .. }) => {
                *nodes += s.nodes;
                *bytes += s.bytes;
                *depth = (*depth).max(s.depth + 1);
                match key.take() {
                    None => match key_text(s.value) {
                        Ok(k) => *key = Some(k),
                        Err(e) => {
                            let msg = format!("{e} (line {})", mark.line());
                            self.fail(msg);
                        }
                    },
                    Some(k) => {
                        map.insert(k, s.value);
                    }
                }
            }
        }
    }

    fn count(&mut self, n: usize, bytes: usize, mark: Marker) -> bool {
        self.nodes = self.nodes.saturating_add(n);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.nodes > MAX_NODES {
            self.fail(format!("the YAML document expands to more than {MAX_NODES} values (line {}); aliases may multiply it", mark.line()));
            return false;
        }
        if self.bytes > MAX_BYTES {
            self.fail(format!("the YAML document expands to more than {} MB of text (line {}); aliases may multiply it", MAX_BYTES / 1024 / 1024, mark.line()));
            return false;
        }
        true
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::DocumentStart => {
                self.root = None;
                self.anchors.clear();
            }
            Event::DocumentEnd => {
                let doc = self.root.take().unwrap_or(Value::Null);
                self.docs.push(doc);
            }
            Event::Scalar(text, style, anchor, tag) => {
                let bytes = text.len();
                if !self.count(1, bytes, mark) {
                    return;
                }
                let s = Sized { value: scalar(text, style, tag.as_ref()), nodes: 1, depth: 0, bytes };
                self.remember(anchor, &s);
                self.emit(s, mark);
            }
            Event::Alias(id) => {
                let Some((value, nodes, depth, bytes)) = self.anchors.get(&id).cloned() else {
                    return self.fail(format!("an alias refers to an unknown anchor (line {})", mark.line()));
                };
                if !self.count(nodes, bytes, mark) {
                    return;
                }
                self.emit(Sized { value, nodes, depth, bytes }, mark);
            }
            Event::SequenceStart(..) | Event::MappingStart(..) if self.stack.len() >= MAX_DEPTH => {
                self.fail(format!("the YAML nesting is deeper than {MAX_DEPTH} levels (line {})", mark.line()));
            }
            Event::SequenceStart(anchor, _) => {
                if self.count(1, 0, mark) {
                    self.stack.push(Frame::Seq { items: Vec::new(), anchor, nodes: 1, depth: 1, bytes: 0 });
                }
            }
            Event::MappingStart(anchor, _) => {
                if self.count(1, 0, mark) {
                    self.stack.push(Frame::Map { map: Map::new(), key: None, anchor, nodes: 1, depth: 1, bytes: 0 });
                }
            }
            Event::SequenceEnd => {
                if let Some(Frame::Seq { items, anchor, nodes, depth, bytes }) = self.stack.pop() {
                    let s = Sized { value: Value::Array(items), nodes, depth, bytes };
                    self.remember(anchor, &s);
                    self.emit(s, mark);
                }
            }
            Event::MappingEnd => {
                if let Some(Frame::Map { mut map, anchor, nodes, depth, bytes, .. }) = self.stack.pop() {
                    merge_keys(&mut map);
                    let s = Sized { value: Value::Object(map), nodes, depth, bytes };
                    self.remember(anchor, &s);
                    self.emit(s, mark);
                }
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}

/// `<<: *base` or `<<: [*a, *b]`: the merged mappings' keys, unless the mapping has them already
/// (earlier sources in a list win over later ones).
fn merge_keys(map: &mut Map<String, Value>) {
    let Some(merged) = map.remove("<<") else { return };
    let sources = match merged {
        Value::Object(m) => vec![m],
        Value::Array(list) => list.into_iter().filter_map(|v| if let Value::Object(m) = v { Some(m) } else { None }).collect(),
        // not a mapping: keep it as an ordinary key
        other => {
            map.insert("<<".into(), other);
            return;
        }
    };
    for source in sources {
        for (k, v) in source {
            map.entry(k).or_insert(v);
        }
    }
}

/// The longest mapping key, the YAML specification's limit for implicit keys. A key that is
/// itself a mapping or a sequence is written as JSON, and nested ones (`? ? ? …`) would re-escape
/// the inner key at every level: 434 bytes of YAML grew past 2^34 characters (found by fuzzing).
pub const MAX_KEY: usize = 1024;

/// Mapping keys are strings in JSON: scalars keep their text, other keys are written as JSON.
fn key_text(v: Value) -> Result<String, String> {
    let k = match v {
        Value::String(s) => s,
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => {
            let mut out = String::new();
            // written into a bounded buffer: serde_json stops at the first write past the limit
            struct Bounded<'a>(&'a mut String);
            impl std::io::Write for Bounded<'_> {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    if self.0.len() + buf.len() > MAX_KEY {
                        return Err(std::io::Error::other("key too long"));
                    }
                    self.0.push_str(&String::from_utf8_lossy(buf));
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            serde_json::to_writer(Bounded(&mut out), &other).map_err(|_| format!("a mapping key is longer than {MAX_KEY} characters"))?;
            out
        }
    };
    if k.len() > MAX_KEY {
        return Err(format!("a mapping key is longer than {MAX_KEY} characters"));
    }
    Ok(k)
}

/// A scalar's value: quoted and block scalars are strings, plain ones follow the YAML 1.2 core
/// schema, and the standard tags (`!!str`, `!!int`, …) are honoured.
fn scalar(text: String, style: TScalarStyle, tag: Option<&Tag>) -> Value {
    if let Some(t) = tag {
        if t.handle == "tag:yaml.org,2002:" || t.handle == "!!" {
            return match t.suffix.as_str() {
                "str" => Value::String(text),
                "null" => Value::Null,
                "bool" => plain(&text).filter(Value::is_boolean).unwrap_or(Value::String(text)),
                "int" | "float" => plain(&text).filter(Value::is_number).unwrap_or(Value::String(text)),
                _ => Value::String(text),
            };
        }
        return Value::String(text);
    }
    if style != TScalarStyle::Plain {
        return Value::String(text);
    }
    plain(&text).unwrap_or(Value::String(text))
}

/// The core schema's resolution of a plain scalar; None for a string.
fn plain(t: &str) -> Option<Value> {
    match t {
        "" | "~" | "null" | "Null" | "NULL" => return Some(Value::Null),
        "true" | "True" | "TRUE" => return Some(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Some(Value::Bool(false)),
        _ => {}
    }
    let (sign, digits) = match t.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1, t.strip_prefix('+').unwrap_or(t)),
    };
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        // beyond 64 bits the text is kept, not rounded
        return digits.parse::<i64>().ok().map(|n| Value::Number(Number::from(n * sign)));
    }
    if let Some(hex) = t.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok().map(|n| Value::Number(n.into()));
    }
    if let Some(oct) = t.strip_prefix("0o") {
        return i64::from_str_radix(oct, 8).ok().map(|n| Value::Number(n.into()));
    }
    let looks_float = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        && digits.bytes().any(|b| b.is_ascii_digit())
        && (digits.contains('.') || digits.contains(['e', 'E']));
    if looks_float {
        if let Ok(f) = t.parse::<f64>() {
            return Number::from_f64(f).map(Value::Number);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalars_follow_the_core_schema() {
        let v = parse_one("a: 1\nb: -2\nc: 1.5\nd: true\ne: ~\nf: 'true'\ng: yes\nh: 0x1f\ni: \"42\"\nj: 99999999999999999999\nk: 1e3\nl: v1.2\n").unwrap();
        assert_eq!(
            v,
            json!({"a": 1, "b": -2, "c": 1.5, "d": true, "e": null, "f": "true", "g": "yes", "h": 31, "i": "42", "j": "99999999999999999999", "k": 1000.0, "l": "v1.2"})
        );
        assert_eq!(parse_one("x: !!str 12\ny: !!int '7'\n").unwrap(), json!({"x": "12", "y": 7}));
    }

    #[test]
    fn documents_anchors_and_merge_keys() {
        let docs = parse_documents("---\nkind: A\n---\nkind: B\nlist: [1, 2]\n").unwrap();
        assert_eq!(docs, vec![json!({"kind": "A"}), json!({"kind": "B", "list": [1, 2]})]);
        let compose = "x-base: &base\n  privileged: true\n  restart: always\nservices:\n  web:\n    <<: *base\n    restart: 'no'\n    image: nginx\n";
        let v = parse_one(compose).unwrap();
        assert_eq!(v["services"]["web"], json!({"privileged": true, "restart": "no", "image": "nginx"}));
        let many = parse_one("a: &a {x: 1}\nb: &b {y: 2}\nc:\n  <<: [*a, *b]\n  x: 3\n").unwrap();
        assert_eq!(many["c"], json!({"x": 3, "y": 2}));
    }

    #[test]
    fn expansion_bombs_and_deep_nesting_are_refused() {
        let mut bomb = String::from("a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n");
        for (prev, name) in ["a", "b", "c", "d", "e", "f", "g", "h"].windows(2).map(|w| (w[0], w[1])) {
            bomb.push_str(&format!("{name}: &{name} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]\n"));
        }
        let err = parse_one(&bomb).unwrap_err();
        assert!(err.contains("expands to more than"), "{err}");
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(parse_one(&deep).unwrap_err().contains("deeper than"));
        // aliases cannot stack depth past the limit either
        let mut stacked = format!("a: &a {}1{}\n", "[".repeat(100), "]".repeat(100));
        stacked.push_str("b: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[*a]]]]]]]]]]]]]]]]]]]]]]]]]]]]]\n");
        assert!(parse_one(&stacked).unwrap_err().contains("deeper than"));
    }

    #[test]
    fn errors_name_the_line() {
        let err = parse_one("a: 1\nb: [1, 2\nc: 3\n").unwrap_err();
        assert!(err.starts_with("not valid YAML") && err.contains("line"), "{err}");
        assert!(parse_one("x: *missing\n").is_err());
        assert!(parse_one("").is_err());
    }

    #[test]
    fn alias_expansion_is_bounded_in_bytes() {
        // 60,000 aliases of a 256 KB scalar: 60,000 nodes, but 15 GB of text
        let mut doc = format!("x: &a \"{}\"\ny:\n", "A".repeat(256 * 1024));
        for _ in 0..60_000 {
            doc.push_str("  - *a\n");
        }
        let err = parse_one(&doc).unwrap_err();
        assert!(err.contains("MB of text"), "{err}");
    }

    #[test]
    fn deep_block_nesting_is_refused_without_recursion() {
        // yaml-rust2's own loader recursed once per level: 5,000 indented keys overflowed a
        // 2 MiB stack. Parsed here on a 256 KiB stack, 2,000 levels must be refused, not crash.
        let doc: String = (0..2_000).map(|i| format!("{}k{i}:\n", " ".repeat(i))).collect();
        let err = std::thread::Builder::new().stack_size(256 * 1024).spawn(move || parse_documents(&doc)).unwrap().join().unwrap().unwrap_err();
        assert!(err.contains("deeper than 128"), "{err}");
    }

    #[test]
    fn nested_complex_keys_are_bounded() {
        // found by fuzzing (434 bytes): nested complex keys (`?`), each written as the JSON of the
        // one inside it, doubling its escapes at every level
        let input = String::from_utf8_lossy(b"         ?               ?         ?               ?         ?      ?         ?                      ?         ?      ?         ?        ?               ?         ?      ?         ?        ?         ?      ?      ?         ?                      ?         ?      ?         ?        ?               ?         ?      ?         ?        ?         ?      ?   s:\x0d ::\x0d\n\x00~\x92        ?      ?         ?            ?  \x92\x92\x92\x92\x92\x0d - l  openapi: 3.0.3\n").into_owned();
        let started = std::time::Instant::now();
        let _ = parse_documents(&input);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        // nested keys are refused once the key text passes the limit
        let mut doc = String::from("x");
        for _ in 0..40 {
            doc = format!("? {}\n: v\n", doc.replace('\n', "\n  "));
        }
        let err = parse_documents(&doc).unwrap_err();
        assert!(err.contains("longer than 1024"), "{err}");
    }
}
