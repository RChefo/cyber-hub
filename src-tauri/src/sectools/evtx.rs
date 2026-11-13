// SPDX-License-Identifier: Apache-2.0
//! Windows XML Event Log files (EVTX) read without Windows APIs, after Microsoft's MS-EVEN6: the
//! file header, 64 KB chunks, event records, and their binary XML with templates, substitutions
//! and nested fragments. Only what triage needs is kept: the System fields and the EventData or
//! UserData values. Bounded: every read is checked, recursion and elements per record are capped,
//! and damaged chunks or records are counted and skipped instead of stopping the file.
//!
//! The `evtx` crate is not used because it switches on serde_json's `preserve_order` feature for
//! the whole application.

use std::collections::HashMap;
use std::io::Read;

pub const CHUNK: usize = 65_536;
const FILE_HEADER: usize = 4096;
const MAX_DEPTH: u32 = 24;
const MAX_NODES: usize = 25_000;
const MAX_VALUES: usize = 4096;
const MAX_DATA: usize = 512;

/// One event, flattened.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Event {
    pub record_id: u64,
    /// RFC 3339, UTC
    pub time: String,
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub computer: String,
    pub level: u8,
    pub user_sid: String,
    /// EventData `Data` values by their Name (unnamed ones as Data1, Data2…), or UserData fields
    pub data: Vec<(String, String)>,
}

impl Event {
    /// A data value by name, ignoring case; "" when absent.
    pub fn get(&self, name: &str) -> &str {
        self.data.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub chunks: u64,
    pub records: u64,
    pub damaged_chunks: u64,
    pub damaged_records: u64,
}

/// Reads an EVTX stream chunk by chunk and hands each event to `each`.
pub fn read(mut input: impl Read, mut each: impl FnMut(Event)) -> Result<Summary, String> {
    let mut header = vec![0u8; FILE_HEADER];
    input.read_exact(&mut header).map_err(|_| "This file is too short to be an EVTX event log".to_string())?;
    if &header[..8] != b"ElfFile\0" {
        return Err("This is not a Windows event log (EVTX) file".into());
    }
    let mut summary = Summary::default();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        match read_full(&mut input, &mut chunk) {
            Ok(0) => break,
            Ok(n) if n < CHUNK => {
                if chunk[..n].iter().any(|b| *b != 0) {
                    summary.damaged_chunks += 1;
                }
                break;
            }
            Ok(_) => {}
            Err(e) => return Err(format!("The file could not be read: {e}")),
        }
        if &chunk[..8] != b"ElfChnk\0" {
            // preallocated chunks at the end are all zeroes
            if chunk.iter().any(|b| *b != 0) {
                summary.damaged_chunks += 1;
            }
            continue;
        }
        summary.chunks += 1;
        parse_chunk(&chunk, &mut summary, &mut each);
    }
    Ok(summary)
}

fn read_full(input: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match input.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn parse_chunk(chunk: &[u8], summary: &mut Summary, each: &mut impl FnMut(Event)) {
    let free = le32(chunk, 48).map(|v| v as usize).unwrap_or(CHUNK).min(CHUNK);
    let mut ctx = Ctx { chunk, names: HashMap::new(), nodes: 0 };
    let mut pos = 512;
    while pos + 28 <= free {
        if le32(chunk, pos) != Some(0x0000_2a2a) {
            break;
        }
        let size = le32(chunk, pos + 4).unwrap_or(0) as usize;
        if size < 28 || pos + size > free {
            summary.damaged_records += 1;
            break;
        }
        let record_id = le64(chunk, pos + 8).unwrap_or(0);
        let written = le64(chunk, pos + 16).map(filetime).unwrap_or_default();
        ctx.nodes = 0;
        let mut p = pos + 24;
        match ctx.fragment(&mut p, pos + size - 4, &[], 0) {
            Ok(nodes) => {
                summary.records += 1;
                let mut ev = flatten(&nodes);
                ev.record_id = record_id;
                if ev.time.is_empty() {
                    ev.time = written;
                }
                each(ev);
            }
            Err(_) => summary.damaged_records += 1,
        }
        pos += size;
    }
}

/* ───────────────────────────── bytes ───────────────────────────── */

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at.checked_add(2)?).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at.checked_add(4)?).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at.checked_add(8)?).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

fn utf16(b: &[u8]) -> String {
    let (pairs, _) = b.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
}

/// FILETIME (100 ns since 1601) as RFC 3339 UTC.
pub fn filetime(v: u64) -> String {
    if v == 0 {
        return String::new();
    }
    let secs = (v / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((v % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)).unwrap_or_default()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return hex(b);
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}", hex(&b[8..10]), hex(&b[10..16]))
}

fn sid(b: &[u8]) -> String {
    if b.len() < 8 {
        return hex(b);
    }
    let count = b[1] as usize;
    let authority = b[2..8].iter().fold(0u64, |a, x| (a << 8) | u64::from(*x));
    let mut out = format!("S-{}-{authority}", b[0]);
    for i in 0..count {
        match le32(b, 8 + i * 4) {
            Some(v) => out.push_str(&format!("-{v}")),
            None => break,
        }
    }
    out
}

fn systemtime(b: &[u8]) -> String {
    let w = |i: usize| le16(b, i * 2).unwrap_or(0) as u32;
    if b.len() < 16 {
        return hex(b);
    }
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", w(0), w(1), w(3), w(4), w(5), w(6), w(7))
}

/// A substitution value's text.
fn value_text(ty: u8, b: &[u8]) -> String {
    let n = |len: usize| -> Option<u64> { (b.len() >= len).then(|| b[..len].iter().rev().fold(0u64, |a, x| (a << 8) | u64::from(*x))) };
    match ty {
        0x00 => String::new(),
        0x01 => utf16(b),
        0x02 => String::from_utf8_lossy(b).trim_end_matches('\0').to_string(),
        0x03 => b.first().map(|v| (*v as i8).to_string()).unwrap_or_default(),
        0x04 => b.first().map(u8::to_string).unwrap_or_default(),
        0x05 => n(2).map(|v| (v as u16 as i16).to_string()).unwrap_or_default(),
        0x06 => n(2).map(|v| v.to_string()).unwrap_or_default(),
        0x07 => n(4).map(|v| (v as u32 as i32).to_string()).unwrap_or_default(),
        0x08 => n(4).map(|v| v.to_string()).unwrap_or_default(),
        0x09 => n(8).map(|v| (v as i64).to_string()).unwrap_or_default(),
        0x0a => n(8).map(|v| v.to_string()).unwrap_or_default(),
        0x0b => n(4).map(|v| f32::from_bits(v as u32).to_string()).unwrap_or_default(),
        0x0c => n(8).map(|v| f64::from_bits(v).to_string()).unwrap_or_default(),
        0x0d => n(4).map(|v| (v != 0).to_string()).unwrap_or_default(),
        0x0f => guid(b),
        0x10 => match b.len() {
            8 => format!("0x{:016x}", n(8).unwrap_or(0)),
            _ => format!("0x{:08x}", n(4).unwrap_or(0)),
        },
        0x11 => n(8).map(filetime).unwrap_or_default(),
        0x12 => systemtime(b),
        0x13 => sid(b),
        0x14 => n(4).map(|v| format!("0x{v:08x}")).unwrap_or_default(),
        0x15 => n(8).map(|v| format!("0x{v:016x}")).unwrap_or_default(),
        0x81 => utf16(b).split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "),
        t if t & 0x80 != 0 => {
            let size = match t & 0x7f {
                0x03 | 0x04 => 1,
                0x05 | 0x06 => 2,
                0x07 | 0x08 | 0x0b | 0x0d | 0x14 => 4,
                0x09 | 0x0a | 0x0c | 0x11 | 0x15 => 8,
                0x0f | 0x12 => 16,
                _ => return hex(b),
            };
            b.chunks_exact(size).map(|c| value_text(t & 0x7f, c)).collect::<Vec<_>>().join(", ")
        }
        _ => hex(b),
    }
}

/* ───────────────────────────── binary XML ───────────────────────────── */

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Elem { name: String, attrs: Vec<(String, String)>, children: Vec<Node> },
    Text(String),
}

/// A substitution value: its type and where its bytes are in the chunk.
#[derive(Debug, Clone, Copy)]
struct Val {
    ty: u8,
    start: usize,
    len: usize,
}

struct Ctx<'a> {
    chunk: &'a [u8],
    names: HashMap<usize, String>,
    nodes: usize,
}

type R<T> = Result<T, &'static str>;

impl Ctx<'_> {
    fn u8(&self, at: usize) -> R<u8> {
        self.chunk.get(at).copied().ok_or("out of bounds")
    }
    fn u16(&self, at: usize) -> R<u16> {
        le16(self.chunk, at).ok_or("out of bounds")
    }
    fn u32(&self, at: usize) -> R<u32> {
        le32(self.chunk, at).ok_or("out of bounds")
    }
    fn bytes(&self, at: usize, len: usize) -> R<&[u8]> {
        self.chunk.get(at..at.checked_add(len).ok_or("overflow")?).ok_or("out of bounds")
    }

    fn count(&mut self) -> R<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err("too many elements");
        }
        Ok(())
    }

    /// A name structure (next offset, hash, length, UTF-16, terminator); when it sits at `pos`
    /// (inline), `pos` moves past it.
    fn name(&mut self, off: usize, pos: &mut usize) -> R<String> {
        let count = self.u16(off + 6)? as usize;
        if off == *pos {
            *pos = off + 8 + count * 2 + 2;
        }
        if let Some(n) = self.names.get(&off) {
            return Ok(n.clone());
        }
        let n = utf16(self.bytes(off + 8, count * 2)?);
        if self.names.len() < 4096 {
            self.names.insert(off, n.clone());
        }
        Ok(n)
    }

    /// Tokens up to the end of stream (or `end`).
    fn fragment(&mut self, pos: &mut usize, end: usize, vals: &[Val], depth: u32) -> R<Vec<Node>> {
        if depth > MAX_DEPTH {
            return Err("nested too deeply");
        }
        let mut out = Vec::new();
        while *pos < end {
            match self.u8(*pos)? {
                0x00 => {
                    *pos += 1;
                    break;
                }
                0x0f => *pos += 4,
                0x0c => out.extend(self.template(pos, depth)?),
                0x01 | 0x41 => out.push(self.element(pos, end, vals, depth)?),
                0x04 => return Err("unexpected end of element"),
                _ => out.extend(self.content(pos, vals, depth)?),
            }
        }
        Ok(out)
    }

    fn element(&mut self, pos: &mut usize, end: usize, vals: &[Val], depth: u32) -> R<Node> {
        if depth > MAX_DEPTH {
            return Err("nested too deeply");
        }
        self.count()?;
        let has_attrs = self.u8(*pos)? & 0x40 != 0;
        let mut p = *pos + 1;
        // the dependency identifier (2 bytes) is sometimes missing: an impossible data size tells
        if (self.u32(p + 2)? as usize) < self.chunk.len() {
            p += 2;
        }
        p += 4; // data size
        let name_off = self.u32(p)? as usize;
        p += 4;
        let name = self.name(name_off, &mut p)?;
        if has_attrs {
            p += 4; // attribute list size
        }
        *pos = p;
        let mut attrs = Vec::new();
        // attribute tokens until the element's close token
        while has_attrs && self.u8(*pos)? & 0x3f == 0x06 {
            *pos += 1;
            let off = self.u32(*pos)? as usize;
            *pos += 4;
            let attr = self.name(off, pos)?;
            let mut value = String::new();
            while matches!(self.u8(*pos)? & 0x3f, 0x05 | 0x07 | 0x08 | 0x09 | 0x0d | 0x0e) {
                for n in self.content(pos, vals, depth + 1)? {
                    text_of(&n, &mut value);
                }
            }
            attrs.push((attr, value));
        }
        let mut children = Vec::new();
        match self.u8(*pos)? {
            0x02 => {
                *pos += 1;
                loop {
                    if *pos >= end {
                        return Err("element not closed");
                    }
                    match self.u8(*pos)? {
                        0x04 => {
                            *pos += 1;
                            break;
                        }
                        0x00 => return Err("end of stream inside an element"),
                        0x01 | 0x41 => children.push(self.element(pos, end, vals, depth + 1)?),
                        0x0c => children.extend(self.template(pos, depth + 1)?),
                        _ => children.extend(self.content(pos, vals, depth + 1)?),
                    }
                }
            }
            0x03 => *pos += 1,
            _ => return Err("element without a closing token"),
        }
        Ok(Node::Elem { name, attrs, children })
    }

    /// Text, character and entity references, CDATA, processing instructions and substitutions.
    fn content(&mut self, pos: &mut usize, vals: &[Val], depth: u32) -> R<Vec<Node>> {
        let t = self.u8(*pos)?;
        *pos += 1;
        match t & 0x3f {
            0x05 => {
                let ty = self.u8(*pos)?;
                *pos += 1;
                if ty != 0x01 {
                    return Err("value text that is not a string");
                }
                self.count()?;
                let n = self.u16(*pos)? as usize;
                let s = utf16(self.bytes(*pos + 2, n * 2)?);
                *pos += 2 + n * 2;
                Ok(vec![Node::Text(s)])
            }
            0x0d | 0x0e => {
                let id = self.u16(*pos)? as usize;
                *pos += 3;
                match vals.get(id) {
                    Some(v) if v.ty == 0x21 => {
                        let mut p = v.start;
                        self.fragment(&mut p, v.start + v.len, &[], depth + 1)
                    }
                    Some(v) => {
                        // text nodes count too: a template referring to one value thousands of
                        // times would otherwise expand without a bound
                        self.count()?;
                        let s = value_text(v.ty, self.bytes(v.start, v.len)?);
                        Ok(if s.is_empty() { Vec::new() } else { vec![Node::Text(s)] })
                    }
                    None => Ok(Vec::new()),
                }
            }
            0x07 => {
                self.count()?;
                let n = self.u16(*pos)? as usize;
                let s = utf16(self.bytes(*pos + 2, n * 2)?);
                *pos += 2 + n * 2;
                Ok(vec![Node::Text(s)])
            }
            0x08 => {
                self.count()?;
                let c = self.u16(*pos)?;
                *pos += 2;
                Ok(char::from_u32(u32::from(c)).map(|c| vec![Node::Text(c.to_string())]).unwrap_or_default())
            }
            0x09 => {
                let off = self.u32(*pos)? as usize;
                *pos += 4;
                let name = self.name(off, pos)?;
                let c = match name.as_str() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => "",
                };
                Ok(vec![Node::Text(c.to_string())])
            }
            0x0a => {
                let off = self.u32(*pos)? as usize;
                *pos += 4;
                self.name(off, pos)?;
                Ok(Vec::new())
            }
            0x0b => {
                let n = self.u16(*pos)? as usize;
                *pos += 2 + n * 2;
                Ok(Vec::new())
            }
            _ => Err("unknown token"),
        }
    }

    /// A template instance: the definition (inline or earlier in the chunk) filled with the values.
    fn template(&mut self, pos: &mut usize, depth: u32) -> R<Vec<Node>> {
        if depth > MAX_DEPTH {
            return Err("nested too deeply");
        }
        // instances count like elements, so templates that expand into templates stay bounded
        self.count()?;
        let def = self.u32(*pos + 6)? as usize;
        *pos += 10;
        let (def_start, def_len) = if def == *pos {
            let len = self.u32(def + 20)? as usize;
            *pos = def + 24 + len;
            (def + 24, len)
        } else {
            (def + 24, self.u32(def + 20)? as usize)
        };
        let n = self.u32(*pos)? as usize;
        *pos += 4;
        if n > MAX_VALUES {
            return Err("too many template values");
        }
        let mut descriptors = Vec::with_capacity(n);
        for _ in 0..n {
            descriptors.push((self.u16(*pos)? as usize, self.u8(*pos + 2)?));
            *pos += 4;
        }
        let mut vals = Vec::with_capacity(n);
        for (len, ty) in descriptors {
            self.bytes(*pos, len)?;
            vals.push(Val { ty, start: *pos, len });
            *pos += len;
        }
        let def_end = def_start.checked_add(def_len).ok_or("overflow")?.min(self.chunk.len());
        let mut p = def_start;
        self.fragment(&mut p, def_end, &vals, depth + 1)
    }
}

fn text_of(n: &Node, out: &mut String) {
    match n {
        Node::Text(t) => out.push_str(t),
        Node::Elem { children, .. } => children.iter().for_each(|c| text_of(c, out)),
    }
}

fn find<'a>(nodes: &'a [Node], name: &str) -> Option<&'a Node> {
    nodes.iter().find(|n| matches!(n, Node::Elem { name: x, .. } if x == name))
}

fn children(n: &Node) -> &[Node] {
    match n {
        Node::Elem { children, .. } => children,
        Node::Text(_) => &[],
    }
}

fn attr<'a>(n: &'a Node, name: &str) -> &'a str {
    match n {
        Node::Elem { attrs, .. } => attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or(""),
        Node::Text(_) => "",
    }
}

fn text(n: Option<&Node>) -> String {
    let mut s = String::new();
    if let Some(n) = n {
        text_of(n, &mut s);
    }
    s.trim().to_string()
}

fn flatten(nodes: &[Node]) -> Event {
    let mut ev = Event::default();
    let Some(event) = find(nodes, "Event") else { return ev };
    let top = children(event);
    if let Some(system) = find(top, "System") {
        let sys = children(system);
        ev.provider = find(sys, "Provider").map(|p| attr(p, "Name").to_string()).unwrap_or_default();
        ev.event_id = text(find(sys, "EventID")).parse().unwrap_or(0);
        ev.level = text(find(sys, "Level")).parse().unwrap_or(0);
        ev.time = find(sys, "TimeCreated").map(|t| attr(t, "SystemTime").to_string()).unwrap_or_default();
        ev.channel = text(find(sys, "Channel"));
        ev.computer = text(find(sys, "Computer"));
        ev.user_sid = find(sys, "Security").map(|s| attr(s, "UserID").to_string()).unwrap_or_default();
    }
    if let Some(data) = find(top, "EventData") {
        let mut unnamed = 0;
        for d in children(data).iter().filter(|n| matches!(n, Node::Elem { name, .. } if name == "Data")) {
            let key = match attr(d, "Name") {
                "" => {
                    unnamed += 1;
                    format!("Data{unnamed}")
                }
                k => k.to_string(),
            };
            if ev.data.len() < MAX_DATA {
                ev.data.push((key, text(Some(d))));
            }
        }
    } else if let Some(user) = find(top, "UserData") {
        for wrapper in children(user) {
            for f in children(wrapper) {
                if let Node::Elem { name, .. } = f {
                    if ev.data.len() < MAX_DATA {
                        ev.data.push((name.clone(), text(Some(f))));
                    }
                }
            }
        }
    }
    ev
}

#[cfg(test)]
#[path = "evtx_tests.rs"]
pub(crate) mod tests;
