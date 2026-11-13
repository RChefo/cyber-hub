// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

use super::*;

/// A chunk writer for tests: binary XML as Windows writes it (inline names on first use, back
/// references after; template definitions inline once, then referenced by offset).
struct W {
    b: Vec<u8>,
    names: HashMap<String, u32>,
}

impl W {
    fn new() -> Self {
        let mut b = vec![0u8; 512];
        b[..8].copy_from_slice(b"ElfChnk\0");
        W { b, names: HashMap::new() }
    }
    fn pos(&self) -> u32 {
        self.b.len() as u32
    }
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn utf16(&mut self, s: &str) {
        for u in s.encode_utf16() {
            self.u16(u);
        }
    }
    fn name(&mut self, s: &str) {
        if let Some(off) = self.names.get(s).copied() {
            self.u32(off);
            return;
        }
        let off = self.pos() + 4;
        self.u32(off);
        self.names.insert(s.to_string(), off);
        self.u32(0);
        self.u16(0);
        self.u16(s.encode_utf16().count() as u16);
        self.utf16(s);
        self.u16(0);
    }
    fn open(&mut self, name: &str, attrs: bool) {
        self.u8(if attrs { 0x41 } else { 0x01 });
        self.u16(0xffff);
        self.u32(0);
        self.name(name);
        if attrs {
            self.u32(0);
        }
    }
    fn attr(&mut self, name: &str) {
        self.u8(0x06);
        self.name(name);
    }
    fn text(&mut self, s: &str) {
        self.u8(0x05);
        self.u8(0x01);
        self.u16(s.encode_utf16().count() as u16);
        self.utf16(s);
    }
    fn sub(&mut self, id: u16, ty: u8) {
        self.u8(0x0e);
        self.u16(id);
        self.u8(ty);
    }
    /// <Name>substitution</Name>
    fn field(&mut self, name: &str, id: u16, ty: u8) {
        self.open(name, false);
        self.u8(0x02);
        self.sub(id, ty);
        self.u8(0x04);
    }
    /// <Data Name="name">substitution</Data>
    fn data(&mut self, name: &str, id: u16, ty: u8) {
        self.open("Data", true);
        self.attr("Name");
        self.text(name);
        self.u8(0x02);
        self.sub(id, ty);
        self.u8(0x04);
    }
    /// The Security logon template: System fields 0-6, EventData 7-9.
    fn logon_template(&mut self) {
        self.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        self.open("Event", true);
        self.attr("xmlns");
        self.text("http://schemas.microsoft.com/win/2004/08/events/event");
        self.u8(0x02);
        self.open("System", false);
        self.u8(0x02);
        self.open("Provider", true);
        self.attr("Name");
        self.sub(0, 0x01);
        self.u8(0x03);
        self.field("EventID", 1, 0x06);
        self.open("TimeCreated", true);
        self.attr("SystemTime");
        self.sub(2, 0x11);
        self.u8(0x03);
        self.field("EventRecordID", 3, 0x0a);
        self.field("Channel", 4, 0x01);
        self.field("Computer", 5, 0x01);
        self.open("Security", true);
        self.attr("UserID");
        self.sub(6, 0x13);
        self.u8(0x03);
        self.u8(0x04);
        self.open("EventData", false);
        self.u8(0x02);
        self.data("TargetUserName", 7, 0x01);
        self.data("IpAddress", 8, 0x01);
        self.data("LogonType", 9, 0x08);
        self.u8(0x04);
        self.u8(0x04);
        self.u8(0x00);
    }
    fn values(&mut self, vals: &[(u8, Vec<u8>)]) {
        self.u32(vals.len() as u32);
        for (ty, v) in vals {
            self.u16(v.len() as u16);
            self.u8(*ty);
            self.u8(0);
        }
        for (_, v) in vals {
            self.b.extend_from_slice(v);
        }
    }
    /// A record around the binary XML written by `body`.
    fn record(&mut self, id: u64, body: impl FnOnce(&mut W)) {
        let start = self.b.len();
        self.u32(0x2a2a);
        self.u32(0);
        self.u64(id);
        self.u64(133_000_000_000_000_000);
        body(self);
        let size = (self.b.len() - start + 4) as u32;
        self.u32(size);
        self.b[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
    }
    fn file(mut self) -> Vec<u8> {
        let free = self.pos();
        self.b[48..52].copy_from_slice(&free.to_le_bytes());
        self.b.resize(CHUNK, 0);
        let mut f = vec![0u8; 4096];
        f[..8].copy_from_slice(b"ElfFile\0");
        f.extend_from_slice(&self.b);
        f.extend(std::iter::repeat_n(0u8, CHUNK)); // an unused, zeroed chunk
        f
    }
}

fn s16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn logon_values(user: &str, ip: &str, logon_type: u32, record: u64) -> Vec<(u8, Vec<u8>)> {
    // S-1-5-18
    let sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    vec![
        (0x01, s16("Microsoft-Windows-Security-Auditing")),
        (0x06, 4625u16.to_le_bytes().to_vec()),
        (0x11, 132_000_000_000_000_000u64.to_le_bytes().to_vec()),
        (0x0a, record.to_le_bytes().to_vec()),
        (0x01, s16("Security")),
        (0x01, s16("DC01.corp.example")),
        (0x13, sid),
        (0x01, s16(user)),
        (0x01, s16(ip)),
        (0x08, logon_type.to_le_bytes().to_vec()),
    ]
}

pub(crate) fn sample() -> Vec<u8> {
    let mut w = W::new();
    let mut def = 0u32;
    // 1: the template inline
    w.record(101, |w| {
        w.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        let at = w.pos();
        w.u8(0x0c);
        w.u8(1);
        w.u32(7);
        def = at + 10;
        w.u32(def);
        w.u32(0);
        w.b.extend_from_slice(&[0xaa; 16]);
        let size_at = w.b.len();
        w.u32(0);
        let start = w.b.len();
        w.logon_template();
        let len = (w.b.len() - start) as u32;
        w.b[size_at..size_at + 4].copy_from_slice(&len.to_le_bytes());
        w.values(&logon_values("alice", "203.0.113.7", 3, 101));
        w.u8(0x00);
    });
    // 2: the same template by reference
    w.record(102, |w| {
        w.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        w.u8(0x0c);
        w.u8(1);
        w.u32(7);
        w.u32(def);
        w.values(&logon_values("bob", "203.0.113.8", 10, 102));
        w.u8(0x00);
    });
    // 3: no template; the System fields as literal text and UserData from a nested fragment
    w.record(103, |w| {
        w.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        w.open("Event", false);
        w.u8(0x02);
        w.open("System", false);
        w.u8(0x02);
        w.open("EventID", false);
        w.u8(0x02);
        w.text("1102");
        w.u8(0x04);
        w.open("Channel", false);
        w.u8(0x02);
        w.text("Security");
        w.u8(0x04);
        w.u8(0x04);
        // UserData comes from a template whose only value is a nested binary XML fragment
        w.u8(0x0c);
        w.u8(1);
        w.u32(9);
        let at = w.pos() + 4;
        w.u32(at);
        w.u32(0);
        w.b.extend_from_slice(&[0xbb; 16]);
        let size_at = w.b.len();
        w.u32(0);
        let start = w.b.len();
        w.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        w.open("UserData", false);
        w.u8(0x02);
        w.sub(0, 0x21);
        w.u8(0x04);
        w.u8(0x00);
        let len = (w.b.len() - start) as u32;
        w.b[size_at..size_at + 4].copy_from_slice(&len.to_le_bytes());
        // the nested fragment: <LogFileCleared><SubjectUserName>mallory</SubjectUserName></LogFileCleared>
        let mut nested = W { b: Vec::new(), names: HashMap::new() };
        // names in a nested fragment are chunk offsets too: build it in place
        let value_at = w.b.len() + 4 + 4;
        nested.b = vec![0u8; value_at];
        nested.b.extend_from_slice(&[0x0f, 1, 1, 0]);
        nested.open("LogFileCleared", false);
        nested.u8(0x02);
        nested.open("SubjectUserName", false);
        nested.u8(0x02);
        nested.text("mallory");
        nested.u8(0x04);
        nested.u8(0x04);
        nested.u8(0x00);
        let bytes = nested.b[value_at..].to_vec();
        w.values(&[(0x21, bytes)]);
        w.u8(0x04);
        w.u8(0x00);
    });
    w.file()
}

#[test]
fn records_templates_and_nested_fragments_are_read() {
    let mut events = Vec::new();
    let summary = read(&sample()[..], |e| events.push(e)).unwrap();
    assert_eq!((summary.chunks, summary.records, summary.damaged_chunks, summary.damaged_records), (1, 3, 0, 0));
    let e = &events[0];
    assert_eq!((e.record_id, e.event_id, e.provider.as_str(), e.channel.as_str(), e.computer.as_str()), (101, 4625, "Microsoft-Windows-Security-Auditing", "Security", "DC01.corp.example"));
    assert_eq!(e.user_sid, "S-1-5-18");
    assert_eq!(e.time, "2019-04-17T18:40:00.000000Z", "FILETIME 132000000000000000 = 1555526400 s after 1970");
    assert_eq!((e.get("TargetUserName"), e.get("ipaddress"), e.get("LogonType")), ("alice", "203.0.113.7", "3"));
    let r = &events[1];
    assert_eq!((r.record_id, r.get("TargetUserName"), r.get("LogonType")), (102, "bob", "10"), "the template by reference, with its own values");
    let c = &events[2];
    assert_eq!((c.event_id, c.channel.as_str(), c.get("SubjectUserName")), (1102, "Security", "mallory"));
    assert_eq!(c.time, filetime(133_000_000_000_000_000), "the record's own time when the event has none");
}

#[test]
fn values_are_rendered_like_the_event_viewer() {
    assert_eq!(value_text(0x13, &[1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 244, 1, 0, 0]), "S-1-5-21-1-2-3-500");
    assert_eq!(value_text(0x0f, &[0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 1, 2, 3, 4, 5, 6, 7, 8]), "{12345678-1234-5678-0102-030405060708}");
    assert_eq!(value_text(0x14, &0x1010u32.to_le_bytes()), "0x00001010");
    assert_eq!(value_text(0x81, &s16("a\0bb\0")), "a, bb");
    assert_eq!(value_text(0x88, &[1, 0, 0, 0, 2, 0, 0, 0]), "1, 2");
    assert_eq!(value_text(0x12, &[0xe3, 0x07, 3, 0, 2, 0, 19, 0, 23, 0, 34, 0, 25, 0, 7, 0]), "2019-03-19T23:34:25.007Z");
    assert_eq!(value_text(0x0d, &[1, 0, 0, 0]), "true");
}

#[test]
fn other_files_and_damage_are_handled_without_panicking() {
    assert!(read(&b"MZ\x90\0"[..], |_| {}).is_err());
    assert!(read(&[0u8; 4096][..], |_| {}).unwrap_err().contains("not a Windows event log"));
    let good = sample();
    // truncated anywhere
    for cut in [4096, 4100, 4096 + 600, 4096 + 900, 4096 + CHUNK / 2, good.len() - 1] {
        let _ = read(&good[..cut], |_| {});
    }
    // flipped bytes in the records area, deterministically
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..3000 {
        let mut f = good.clone();
        for _ in 0..4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = 4096 + 512 + (seed as usize % 1600);
            f[at] = (seed >> 32) as u8;
        }
        let mut n = 0;
        let summary = read(&f[..], |_| n += 1).unwrap();
        assert!(summary.records <= 3 && n as u64 == summary.records);
    }
}

/// Reads the EVTX files in `CYBERHUB_EVTX_DIR` and writes one JSON line per event to
/// `CYBERHUB_EVTX_OUT`, to compare with another parser (docs/autonomous/IMPLEMENTATION_LOG.md).
#[test]
#[ignore]
fn dump_a_folder_of_evtx_files() {
    use std::io::Write;
    let dir = std::env::var("CYBERHUB_EVTX_DIR").expect("CYBERHUB_EVTX_DIR");
    let mut out = std::fs::File::create(std::env::var("CYBERHUB_EVTX_OUT").expect("CYBERHUB_EVTX_OUT")).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "evtx")).collect();
    files.sort();
    for p in files {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let summary = read(std::fs::File::open(&p).unwrap(), |e| {
            let data: serde_json::Map<String, serde_json::Value> = e.data.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
            let line = serde_json::json!({ "file": name, "record": e.record_id, "id": e.event_id, "channel": e.channel, "provider": e.provider, "computer": e.computer, "time": e.time, "data": data });
            writeln!(out, "{line}").unwrap();
        })
        .unwrap();
        eprintln!("{name}: {summary:?}");
    }
}
