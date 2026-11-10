//! Hostile-input harness for parser tests (Mission 5).
//!
//! * **Generators** of what an attacker or a damaged file supplies: every short prefix and a
//!   spread of longer cuts of a valid file (truncation), seeded byte mutations of it (a cheap,
//!   deterministic mutation fuzzer), random bytes, text that breaks naive string handling (NUL,
//!   invalid UTF-8, byte-order marks, bidirectional overrides, combining marks, lone CR), deep
//!   nesting in each structured syntax, and oversized lines.
//! * **A runner** that gives each case to the parser on a thread with the stack Cyber Hub's
//!   blocking work gets (2 MiB, tokio's default), under a time budget. A panic or a hang fails
//!   the test with the parser and case named. A stack overflow aborts the test process, and Rust
//!   names the thread that overflowed, which is the case (`hostile:<parser>:<case>`).
//!
//! The release build aborts on panic, so a panic here is a crash of the app there. Fixtures are
//! generated, never real data. A defect found is fixed and its input kept as a regression test
//! next to the parser.

use std::time::Duration;

/// The stack of a tokio blocking thread, where Cyber Hub parses files.
pub const STACK: usize = 2 * 1024 * 1024;

pub struct Case {
    pub name: String,
    pub data: Vec<u8>,
}

impl Case {
    pub fn new(name: impl Into<String>, data: impl Into<Vec<u8>>) -> Case {
        Case { name: name.into(), data: data.into() }
    }
}

/// A deterministic generator (xorshift64*), so a failing case is the same on every run.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// `open` × depth, `inner`, `close` × depth.
pub fn nested(open: &str, inner: &str, close: &str, depth: usize) -> String {
    let mut s = String::with_capacity((open.len() + close.len()) * depth + inner.len());
    for _ in 0..depth {
        s.push_str(open);
    }
    s.push_str(inner);
    for _ in 0..depth {
        s.push_str(close);
    }
    s
}

/// Every prefix of the first 64 bytes, then 48 cuts spread over the rest.
pub fn truncations(valid: &[u8]) -> Vec<Case> {
    let mut out = Vec::new();
    for n in 0..valid.len().min(64) {
        out.push(Case::new(format!("cut at {n}"), &valid[..n]));
    }
    if valid.len() > 64 {
        for k in 1..=48 {
            let n = 64 + (valid.len() - 64) * k / 49;
            out.push(Case::new(format!("cut at {n}"), &valid[..n]));
        }
    }
    out
}

/// Seeded mutations of a valid file: bytes replaced, inserted, removed, runs duplicated and
/// interesting values (0x00, 0xff, 0x7f, 0x80, large lengths) written over integers.
pub fn mutations(valid: &[u8], seed: u64, count: usize) -> Vec<Case> {
    let mut rng = Rng::new(seed);
    let interesting: [&[u8]; 8] = [&[0], &[0xff], &[0x7f], &[0x80], &[0xff, 0xff, 0xff, 0xff], &[0, 0, 0, 0], &[0xff, 0xff, 0xff, 0x7f], &[0x0c, 0, 0, 0]];
    (0..count)
        .map(|i| {
            let mut d = valid.to_vec();
            for _ in 0..1 + rng.below(4) {
                if d.is_empty() {
                    d.push(rng.next() as u8);
                    continue;
                }
                let at = rng.below(d.len());
                match rng.below(5) {
                    0 => d[at] = rng.next() as u8,
                    1 => d.insert(at, rng.next() as u8),
                    2 => {
                        d.remove(at);
                    }
                    3 => {
                        let end = (at + 1 + rng.below(32)).min(d.len());
                        let run = d[at..end].to_vec();
                        for _ in 0..1 + rng.below(8) {
                            d.splice(at..at, run.iter().copied());
                        }
                    }
                    _ => {
                        let v = interesting[rng.below(interesting.len())];
                        for (k, b) in v.iter().enumerate() {
                            if let Some(x) = d.get_mut(at + k) {
                                *x = *b;
                            }
                        }
                    }
                }
            }
            Case::new(format!("mutation {i} (seed {seed})"), d)
        })
        .collect()
}

/// Random bytes of several lengths.
pub fn noise(seed: u64) -> Vec<Case> {
    let mut rng = Rng::new(seed);
    [0usize, 1, 2, 7, 64, 511, 4096, 65_537].iter().map(|&n| Case::new(format!("noise {n}"), (0..n).map(|_| rng.next() as u8).collect::<Vec<u8>>())).collect()
}

/// Text that breaks naive string handling.
pub fn hostile_text() -> Vec<Case> {
    vec![
        Case::new("empty", ""),
        Case::new("NUL bytes", b"a\0b\0\0c\n\0".to_vec()),
        Case::new("invalid UTF-8", vec![0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1, 0xf0, 0x28, 0x8c, 0xbc, 0xff, 0xfe, b'\n']),
        Case::new("overlong and surrogate encodings", vec![0xc0, 0xaf, 0xe0, 0x80, 0xaf, 0xed, 0xa0, 0x80, 0xed, 0xbf, 0xbf]),
        Case::new("UTF-8 BOM", "\u{feff}{\"a\":1}\n"),
        Case::new("UTF-16LE BOM", vec![0xff, 0xfe, b'{', 0, b'}', 0]),
        Case::new("UTF-16BE BOM", vec![0xfe, 0xff, 0, b'{', 0, b'}']),
        Case::new("bidi override", "name\u{202e}gpj.exe\n\u{2066}x\u{2069}"),
        Case::new("combining marks", format!("a{}", "\u{0301}".repeat(10_000))),
        Case::new("lone CRs", "a\rb\rc\r"),
        Case::new("multi-byte at every boundary", "日本語€😀é".repeat(512)),
        Case::new("only whitespace", " \t\n\r\x0b\x0c".repeat(1000)),
    ]
}

/// One long line, and many short ones.
pub fn oversized() -> Vec<Case> {
    vec![Case::new("one 4 MB line", "a".repeat(4 * 1024 * 1024)), Case::new("200,000 short lines", "x\n".repeat(200_000))]
}

/// Deep nesting in the syntaxes Cyber Hub reads.
pub fn deep_structures(depth: usize) -> Vec<Case> {
    vec![
        Case::new(format!("JSON arrays × {depth}"), nested("[", "1", "]", depth)),
        Case::new(format!("JSON objects × {depth}"), nested("{\"a\":", "1", "}", depth)),
        Case::new(format!("YAML flow × {depth}"), format!("a: {}", nested("[", "1", "]", depth))),
        Case::new(format!("YAML blocks × {}", depth.min(5_000)), (0..depth.min(5_000)).map(|i| format!("{}k{i}:\n", " ".repeat(i))).collect::<String>()),
        Case::new(format!("XML elements × {depth}"), format!("<?xml version=\"1.0\"?>{}", nested("<a>", "x", "</a>", depth))),
        Case::new(format!("HCL blocks × {depth}"), nested("a {\n", "b = 1\n", "}\n", depth)),
        Case::new(format!("parentheses × {depth}"), nested("(", "x", ")", depth)),
    ]
}

/// Runs `f` on a thread named after the case, with [`STACK`], under `budget`.
pub fn run(parser: &str, case: &str, budget: Duration, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = std::sync::mpsc::channel();
    let name = format!("hostile:{parser}:{case}");
    let handle = std::thread::Builder::new()
        .name(name.clone())
        .stack_size(STACK)
        .spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            let _ = tx.send(r.err().map(|e| e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()));
        })
        .expect("a thread for the case");
    match rx.recv_timeout(budget) {
        Ok(None) => {
            let _ = handle.join();
        }
        Ok(Some(msg)) => panic!("{parser} panicked on {case}: {msg}"),
        Err(_) => panic!("{parser} took longer than {budget:?} on {case}"),
    }
}

/// Every case of `cases` through `parse`.
pub fn sweep(parser: &str, cases: Vec<Case>, budget: Duration, parse: impl Fn(&[u8]) + Send + Sync + Clone + 'static) {
    for c in cases {
        let p = parse.clone();
        let data = c.data;
        run(parser, &c.name, budget, move || p(&data));
    }
}
