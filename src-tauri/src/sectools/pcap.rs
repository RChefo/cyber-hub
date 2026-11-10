//! Packet capture triage (docs/UTILITIES.md): a pcap or pcapng file is read on this device and
//! summarized: hosts, conversations, DNS names, HTTP requests, TLS server names and credentials
//! sent in cleartext. Nothing is contacted or replayed.
//!
//! * **Formats.** pcap (microsecond or nanosecond timestamps, either byte order) and pcapng
//!   (section, interface, enhanced and simple packet blocks). Link types: Ethernet (with VLAN tags),
//!   Linux cooked capture v1 and v2, raw IP, and BSD loopback.
//! * **Passwords are never shown.** A cleartext credential is reported with its user name and the
//!   length of its secret.
//! * **Bounded.** The file is streamed, at most [`MAX_PACKETS`] packets are read, and every table
//!   is capped; the report says when a limit was reached.
//! * **Hunting leads** (`pcap_hunt.rs`): connections on a regular schedule and DNS patterns of
//!   tunneling or generated domains, kept apart from the issues and reported as leads.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_PACKETS: u64 = 5_000_000;
const MAX_PACKET_LEN: usize = 262_144;
const MAX_ROWS: usize = 500;
const MAX_KEYS: usize = 200_000;

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct HostStat {
    pub ip: String,
    pub packets: u64,
    pub bytes: u64,
    pub peers: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub client: String,
    pub server: String,
    /// tcp or udp
    pub protocol: String,
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DnsName {
    pub name: String,
    /// A, AAAA, CNAME, MX, TXT…
    pub kind: String,
    pub answers: Vec<String>,
    pub queries: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub user_agent: String,
    pub server: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsServer {
    pub name: String,
    pub server: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    /// http-basic, ftp, pop3, imap, smtp
    pub protocol: String,
    pub client: String,
    pub server: String,
    pub user: String,
    /// the length of the secret; the secret itself is never kept
    pub secret_length: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub remediation: String,
    /// the hosts or flows it concerns
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// pcap or pcapng
    pub format: String,
    pub links: Vec<String>,
    pub packets: u64,
    pub bytes: u64,
    /// Unix time in seconds of the first and last packet
    pub first: Option<f64>,
    pub last: Option<f64>,
    pub hosts: Vec<HostStat>,
    pub conversations: Vec<Conversation>,
    pub dns: Vec<DnsName>,
    pub http: Vec<HttpRequest>,
    pub tls: Vec<TlsServer>,
    pub credentials: Vec<Credential>,
    pub issues: Vec<Issue>,
    /// beacon-like timing and DNS patterns: leads to check, not findings
    pub hunting: super::pcap_hunt::Hunting,
    /// packets not decoded (other protocols, truncated or fragments)
    pub undecoded: u64,
    pub warnings: Vec<String>,
}

/* ───────────────────────────── helpers ───────────────────────────── */

fn be16(b: &[u8], i: usize) -> Option<u16> {
    b.get(i..i + 2).map(|x| u16::from_be_bytes([x[0], x[1]]))
}

fn u32_at(b: &[u8], i: usize, le: bool) -> Option<u32> {
    let x: [u8; 4] = b.get(i..i + 4)?.try_into().ok()?;
    Some(if le { u32::from_le_bytes(x) } else { u32::from_be_bytes(x) })
}

fn u16_at(b: &[u8], i: usize, le: bool) -> Option<u16> {
    let x: [u8; 2] = b.get(i..i + 2)?.try_into().ok()?;
    Some(if le { u16::from_le_bytes(x) } else { u16::from_be_bytes(x) })
}

/// Standard base64 (padding optional); None for anything else.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.trim().bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn endpoint(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    }
}

fn link_name(link: u32) -> String {
    match link {
        0 => "BSD loopback".into(),
        1 => "Ethernet".into(),
        12 | 101 => "raw IP".into(),
        113 => "Linux cooked capture".into(),
        228 => "raw IPv4".into(),
        229 => "raw IPv6".into(),
        276 => "Linux cooked capture v2".into(),
        n => format!("link type {n}"),
    }
}

/* ───────────────────────────── packets ───────────────────────────── */

/// The IP packet inside a frame of the given link type.
fn ip_payload(link: u32, frame: &[u8]) -> Option<&[u8]> {
    match link {
        1 => {
            let mut ty = be16(frame, 12)?;
            let mut off = 14;
            // VLAN tags (802.1Q, 802.1ad), at most two
            for _ in 0..2 {
                if ty == 0x8100 || ty == 0x88a8 {
                    ty = be16(frame, off + 2)?;
                    off += 4;
                }
            }
            (ty == 0x0800 || ty == 0x86dd).then(|| frame.get(off..)).flatten()
        }
        113 => {
            let ty = be16(frame, 14)?;
            (ty == 0x0800 || ty == 0x86dd).then(|| frame.get(16..)).flatten()
        }
        276 => {
            let ty = be16(frame, 0)?;
            (ty == 0x0800 || ty == 0x86dd).then(|| frame.get(20..)).flatten()
        }
        12 | 101 | 228 | 229 => Some(frame),
        0 => frame.get(4..),
        _ => None,
    }
}

struct Segment<'a> {
    src: IpAddr,
    dst: IpAddr,
    tcp: bool,
    /// a TCP SYN without ACK: a connection attempt
    syn: bool,
    sport: u16,
    dport: u16,
    payload: &'a [u8],
}

fn transport(ip: &[u8]) -> Option<Segment<'_>> {
    let version = ip.first()? >> 4;
    let (src, dst, mut proto, mut rest): (IpAddr, IpAddr, u8, &[u8]) = match version {
        4 => {
            // the fixed header is 20 bytes; a shorter frame is not a packet (indexing it would panic)
            let hdr = ip.get(..20)?;
            let ihl = (hdr[0] & 0x0f) as usize * 4;
            let total = be16(ip, 2)? as usize;
            let frag = be16(ip, 6)? & 0x1fff;
            if ihl < 20 || frag != 0 {
                return None;
            }
            let end = total.min(ip.len()).max(ihl);
            let src = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
            let dst = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
            (IpAddr::V4(src), IpAddr::V4(dst), hdr[9], ip.get(ihl..end)?)
        }
        6 => {
            let plen = be16(ip, 4)? as usize;
            let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            let body = ip.get(40..(40 + plen).min(ip.len()))?;
            (IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)), ip[6], body)
        }
        _ => return None,
    };
    // IPv6 extension headers (hop-by-hop, routing, fragment, destination options)
    for _ in 0..8 {
        match proto {
            0 | 43 | 60 => {
                let next = *rest.first()?;
                let len = (*rest.get(1)? as usize + 1) * 8;
                proto = next;
                rest = rest.get(len..)?;
            }
            44 => {
                if be16(rest, 2)? & 0xfff8 != 0 {
                    return None; // not the first fragment
                }
                proto = *rest.first()?;
                rest = rest.get(8..)?;
            }
            _ => break,
        }
    }
    match proto {
        6 => {
            let off = ((*rest.get(12)? >> 4) as usize) * 4;
            Some(Segment { src, dst, tcp: true, syn: rest.get(13).is_some_and(|f| f & 0x12 == 0x02), sport: be16(rest, 0)?, dport: be16(rest, 2)?, payload: rest.get(off.max(20)..).unwrap_or(&[]) })
        }
        17 => Some(Segment { src, dst, tcp: false, syn: false, sport: be16(rest, 0)?, dport: be16(rest, 2)?, payload: rest.get(8..).unwrap_or(&[]) }),
        _ => None,
    }
}

/// A DNS name at `off` (compression pointers followed, at most 32 jumps); the offset after it.
fn dns_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            end.get_or_insert(off + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(off + 1)? as usize;
            end.get_or_insert(off + 2);
            if ptr >= off {
                return None; // pointers must point backwards
            }
            off = ptr;
            continue;
        }
        let label = msg.get(off + 1..off + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end?))
}

fn rr_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// (query name, type, answers) of a DNS message; answers only for responses.
fn dns(msg: &[u8]) -> Option<(String, String, Vec<String>, bool)> {
    let flags = be16(msg, 2)?;
    let response = flags & 0x8000 != 0;
    let qd = be16(msg, 4)?;
    let an = be16(msg, 6)?;
    if qd == 0 {
        return None;
    }
    let (name, mut off) = dns_name(msg, 12)?;
    let qtype = be16(msg, off)?;
    off += 4;
    let mut answers = Vec::new();
    if response {
        for _ in 0..an.min(50) {
            let (_, o) = dns_name(msg, off)?;
            let ty = be16(msg, o)?;
            let rdlen = be16(msg, o + 8)? as usize;
            let rdata = msg.get(o + 10..o + 10 + rdlen)?;
            match (ty, rdlen) {
                (1, 4) => answers.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()),
                (28, 16) => {
                    let a: [u8; 16] = rdata.try_into().ok()?;
                    answers.push(Ipv6Addr::from(a).to_string());
                }
                (5, _) | (2, _) | (12, _) => {
                    if let Some((n, _)) = dns_name(msg, o + 10) {
                        answers.push(n);
                    }
                }
                _ => {}
            }
            off = o + 10 + rdlen;
        }
    }
    Some((name, rr_type(qtype), answers, response))
}

/// The server name of a TLS ClientHello.
pub fn tls_sni(p: &[u8]) -> Option<String> {
    if p.first()? != &0x16 || p.get(1)? != &0x03 || p.get(5)? != &0x01 {
        return None;
    }
    let mut off = 9 + 2 + 32; // record + handshake headers, version, random
    off += 1 + *p.get(off)? as usize; // session id
    off += 2 + be16(p, off)? as usize; // cipher suites
    off += 1 + *p.get(off)? as usize; // compression methods
    let ext_end = off + 2 + be16(p, off)? as usize;
    off += 2;
    while off + 4 <= ext_end.min(p.len()) {
        let ty = be16(p, off)?;
        let len = be16(p, off + 2)? as usize;
        if ty == 0 {
            // server_name list: list length (2), name type (1), name length (2), name
            let nlen = be16(p, off + 7)? as usize;
            let name = p.get(off + 9..off + 9 + nlen)?;
            return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
        }
        off += 4 + len;
    }
    None
}

const METHODS: &[&str] = &["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "];

/* ───────────────────────────── the analysis ───────────────────────────── */

#[derive(Default)]
struct Acc {
    report: Report,
    hosts: HashMap<IpAddr, (u64, u64, BTreeSet<IpAddr>)>,
    convs: HashMap<(String, String, bool, u16), (u64, u64)>,
    dns: BTreeMap<(String, String), (BTreeSet<String>, u64)>,
    http: BTreeMap<(String, String, String, String, String), u64>,
    tls: BTreeMap<(String, String), u64>,
    creds: Vec<Credential>,
    pending_user: HashMap<(String, String), (String, String)>,
    cleartext_ports: BTreeMap<u16, BTreeSet<String>>,
    capped: bool,
    hunt: super::pcap_hunt::Hunt,
}

const CLEARTEXT: &[(u16, &str)] = &[(21, "FTP"), (23, "Telnet"), (69, "TFTP"), (110, "POP3"), (143, "IMAP"), (161, "SNMP"), (512, "rexec"), (513, "rlogin"), (514, "rsh"), (389, "LDAP"), (5900, "VNC")];

impl Acc {
    fn packet(&mut self, link: u32, frame: &[u8], len: u64, ts: f64) {
        let r = &mut self.report;
        r.packets += 1;
        r.bytes += len;
        // simple packet blocks carry no time (0)
        if ts > 0.0 {
            r.first = Some(r.first.map_or(ts, |f| f.min(ts)));
            r.last = Some(r.last.map_or(ts, |l| l.max(ts)));
        }
        let Some(seg) = ip_payload(link, frame).and_then(transport) else {
            r.undecoded += 1;
            return;
        };
        for (a, b) in [(seg.src, seg.dst), (seg.dst, seg.src)] {
            if self.hosts.len() < MAX_KEYS || self.hosts.contains_key(&a) {
                let h = self.hosts.entry(a).or_default();
                h.0 += 1;
                h.1 += len;
                if h.2.len() < 10_000 {
                    h.2.insert(b);
                }
            } else {
                self.capped = true;
            }
        }
        // the client is the side with the higher (ephemeral) port
        let (client, server, port) = if seg.sport > seg.dport { (endpoint(&seg.src, seg.sport), endpoint(&seg.dst, seg.dport), seg.dport) } else { (endpoint(&seg.dst, seg.dport), endpoint(&seg.src, seg.sport), seg.sport) };
        let client_ip = client.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']']).to_string()).unwrap_or_default();
        if seg.sport > seg.dport {
            // from the client to the server
            self.hunt.packet(&client_ip, &server, seg.tcp, port, ts, seg.syn);
        }
        let key = (client_ip.clone(), server.clone(), seg.tcp, port);
        if self.convs.len() < MAX_KEYS || self.convs.contains_key(&key) {
            let c = self.convs.entry(key).or_default();
            c.0 += 1;
            c.1 += len;
        } else {
            self.capped = true;
        }
        if let Some((_, name)) = CLEARTEXT.iter().find(|(p, _)| *p == port) {
            if !seg.payload.is_empty() || !seg.tcp {
                self.cleartext_ports.entry(port).or_default().insert(format!("{client_ip} → {server} ({name})"));
            }
        }
        let p = seg.payload;
        if p.is_empty() {
            return;
        }
        if !seg.tcp && (seg.sport == 53 || seg.dport == 53) {
            if let Some((name, kind, answers, response)) = dns(p) {
                if response {
                    self.hunt.response(&client_ip, &name, be16(p, 2).unwrap_or(0) & 0x000f);
                } else {
                    self.hunt.query(&client_ip, &name, &kind);
                }
                if self.dns.len() < MAX_KEYS || self.dns.contains_key(&(name.clone(), kind.clone())) {
                    let e = self.dns.entry((name, kind)).or_default();
                    e.1 += 1;
                    for a in answers {
                        if e.0.len() < 20 {
                            e.0.insert(a);
                        }
                    }
                }
            }
            return;
        }
        if !seg.tcp {
            return;
        }
        if METHODS.iter().any(|m| p.starts_with(m.as_bytes())) {
            self.http_request(p, &client_ip, &server);
        } else if p[0] == 0x16 {
            if let Some(name) = tls_sni(p) {
                *self.tls.entry((name, server.clone())).or_default() += 1;
            }
        } else if matches!(port, 21 | 110 | 143 | 25 | 587) {
            self.mail_ftp(p, port, &client_ip, &server);
        }
    }

    fn http_request(&mut self, p: &[u8], client: &str, server: &str) {
        let head = &p[..p.len().min(16_384)];
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let first = lines.next().unwrap_or("");
        let mut parts = first.split(' ');
        let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
        let (mut host, mut ua) = (String::new(), String::new());
        for l in lines.take(100) {
            if l.is_empty() {
                break;
            }
            let Some((k, v)) = l.split_once(':') else { continue };
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "host" => host = v.chars().take(200).collect(),
                "user-agent" => ua = v.chars().take(200).collect(),
                "authorization" => {
                    if let Some(b) = v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")) {
                        if let Some(raw) = base64_decode(b) {
                            let s = String::from_utf8_lossy(&raw);
                            let (user, secret) = s.split_once(':').unwrap_or((&s, ""));
                            self.creds.push(Credential { protocol: "http-basic".into(), client: client.into(), server: server.into(), user: user.chars().take(100).collect(), secret_length: secret.chars().count() });
                        }
                    }
                }
                _ => {}
            }
        }
        let path: String = target.split('?').next().unwrap_or("").chars().take(200).collect();
        let key = (method, host, path, ua, server.to_string());
        if self.http.len() < MAX_KEYS || self.http.contains_key(&key) {
            *self.http.entry(key).or_default() += 1;
        }
    }

    fn mail_ftp(&mut self, p: &[u8], port: u16, client: &str, server: &str) {
        let text = String::from_utf8_lossy(&p[..p.len().min(4096)]);
        let proto = match port {
            21 => "ftp",
            110 => "pop3",
            143 => "imap",
            _ => "smtp",
        };
        for line in text.split("\r\n").filter(|l| !l.is_empty()).take(20) {
            let upper = line.to_ascii_uppercase();
            let flow = (client.to_string(), server.to_string());
            if (port == 21 || port == 110) && upper.starts_with("USER ") {
                self.pending_user.insert(flow, (proto.into(), line[5..].trim().chars().take(100).collect()));
            } else if (port == 21 || port == 110) && upper.starts_with("PASS ") {
                let user = self.pending_user.remove(&flow).map(|(_, u)| u).unwrap_or_default();
                self.creds.push(Credential { protocol: proto.into(), client: client.into(), server: server.into(), user, secret_length: line[5..].trim().chars().count() });
            } else if port == 143 {
                // a1 LOGIN user password
                let words: Vec<&str> = line.split_whitespace().collect();
                if words.len() >= 4 && words[1].eq_ignore_ascii_case("LOGIN") {
                    self.creds.push(Credential { protocol: proto.into(), client: client.into(), server: server.into(), user: words[2].trim_matches('"').chars().take(100).collect(), secret_length: words[3].trim_matches('"').chars().count() });
                }
            } else if (port == 25 || port == 587) && upper.starts_with("AUTH PLAIN ") {
                if let Some(raw) = base64_decode(&line[11..]) {
                    let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                    if parts.len() == 3 {
                        self.creds.push(Credential { protocol: proto.into(), client: client.into(), server: server.into(), user: String::from_utf8_lossy(parts[1]).chars().take(100).collect(), secret_length: parts[2].len() });
                    }
                }
            }
        }
    }

    fn finish(mut self) -> Report {
        let mut r = std::mem::take(&mut self.report);
        r.hunting = std::mem::take(&mut self.hunt).finish();
        let mut hosts: Vec<HostStat> = self.hosts.into_iter().map(|(ip, (packets, bytes, peers))| HostStat { ip: ip.to_string(), packets, bytes, peers: peers.len() }).collect();
        hosts.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.ip.cmp(&b.ip)));
        hosts.truncate(MAX_ROWS);
        r.hosts = hosts;
        let mut convs: Vec<Conversation> = self
            .convs
            .into_iter()
            .map(|((client, server, tcp, port), (packets, bytes))| Conversation { client, server, protocol: if tcp { "tcp" } else { "udp" }.into(), port, packets, bytes })
            .collect();
        convs.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.server.cmp(&b.server)));
        convs.truncate(MAX_ROWS);
        r.conversations = convs;
        r.dns = self.dns.into_iter().map(|((name, kind), (answers, queries))| DnsName { name, kind, answers: answers.into_iter().collect(), queries }).collect();
        r.dns.sort_by(|a, b| b.queries.cmp(&a.queries).then(a.name.cmp(&b.name)));
        r.dns.truncate(MAX_ROWS);
        r.http = self.http.into_iter().map(|((method, host, path, user_agent, server), count)| HttpRequest { method, host, path, user_agent, server, count }).collect();
        r.http.sort_by(|a, b| b.count.cmp(&a.count).then(a.host.cmp(&b.host)));
        r.http.truncate(MAX_ROWS);
        r.tls = self.tls.into_iter().map(|((name, server), count)| TlsServer { name, server, count }).collect();
        r.tls.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
        r.tls.truncate(MAX_ROWS);
        self.creds.dedup();
        self.creds.truncate(MAX_ROWS);
        r.credentials = self.creds;
        if self.capped {
            r.warnings.push(format!("More than {MAX_KEYS} hosts or conversations: the rest were counted in the totals only"));
        }
        // issues
        if !r.credentials.is_empty() {
            let protocols: BTreeSet<&str> = r.credentials.iter().map(|c| c.protocol.as_str()).collect();
            r.issues.push(Issue {
                rule: "PCAP-CLEARTEXT-CREDENTIALS".into(),
                severity: "high".into(),
                title: format!("Credentials sent in cleartext ({})", protocols.into_iter().collect::<Vec<_>>().join(", ")),
                detail: format!("{} logins were readable on the network, so anyone on the path could reuse them.", r.credentials.len()),
                remediation: "Require TLS for these services (HTTPS, FTPS or SFTP, POP3S, IMAPS, SMTP with STARTTLS enforced), and change the passwords that were exposed.".into(),
                evidence: r.credentials.iter().take(50).map(|c| format!("{} {} → {} user {}", c.protocol, c.client, c.server, if c.user.is_empty() { "(unknown)" } else { &c.user })).collect(),
            });
        }
        let cleartext: Vec<String> = self.cleartext_ports.values().flat_map(|v| v.iter().cloned()).take(100).collect();
        if !cleartext.is_empty() {
            let names: BTreeSet<&str> = self.cleartext_ports.keys().filter_map(|p| CLEARTEXT.iter().find(|(x, _)| x == p).map(|(_, n)| *n)).collect();
            r.issues.push(Issue {
                rule: "PCAP-CLEARTEXT-PROTOCOL".into(),
                severity: "medium".into(),
                title: format!("Cleartext protocols in use ({})", names.into_iter().collect::<Vec<_>>().join(", ")),
                detail: "These protocols carry data, and often logins, without encryption.".into(),
                remediation: "Replace them with encrypted equivalents (SSH, SFTP, LDAPS, SNMPv3, IMAPS…), or confine them to an isolated management network.".into(),
                evidence: cleartext,
            });
        }
        if !r.http.is_empty() {
            let hosts: BTreeSet<String> = r.http.iter().map(|h| if h.host.is_empty() { h.server.clone() } else { h.host.clone() }).collect();
            r.issues.push(Issue {
                rule: "PCAP-PLAIN-HTTP".into(),
                severity: "low".into(),
                title: format!("Unencrypted HTTP to {} {}", hosts.len(), if hosts.len() == 1 { "host" } else { "hosts" }),
                detail: "HTTP requests were sent without TLS; their contents, cookies and tokens were readable on the network.".into(),
                remediation: "Serve these sites over HTTPS only and send HSTS.".into(),
                evidence: hosts.into_iter().take(100).collect(),
            });
        }
        r
    }
}

/// Reads a capture from `input` (pcap or pcapng, detected from its first bytes).
pub fn analyze(mut input: impl Read) -> Result<Report, String> {
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic).map_err(|_| "The file is too short to be a packet capture".to_string())?;
    let mut acc = Acc::default();
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d] => pcap(&mut acc, &mut input, magic)?,
        [0x0a, 0x0d, 0x0d, 0x0a] => pcapng(&mut acc, &mut input)?,
        _ => return Err("This is not a pcap or pcapng file".into()),
    }
    if acc.report.packets >= MAX_PACKETS {
        acc.report.warnings.push(format!("Only the first {MAX_PACKETS} packets were read"));
    }
    Ok(acc.finish())
}

fn read_exact_or_end(input: &mut impl Read, buf: &mut [u8]) -> Result<bool, String> {
    let mut got = 0;
    while got < buf.len() {
        match input.read(&mut buf[got..]) {
            Ok(0) => return if got == 0 { Ok(false) } else { Err("The capture ends in the middle of a packet".into()) },
            Ok(n) => got += n,
            Err(e) => return Err(format!("The file cannot be read: {e}")),
        }
    }
    Ok(true)
}

fn pcap(acc: &mut Acc, input: &mut impl Read, magic: [u8; 4]) -> Result<(), String> {
    let le = magic[0] == 0xd4 || magic[0] == 0x4d;
    let nanos = magic == [0x4d, 0x3c, 0xb2, 0xa1] || magic == [0xa1, 0xb2, 0x3c, 0x4d];
    let mut header = [0u8; 20];
    if !read_exact_or_end(input, &mut header)? {
        return Err("The pcap header is incomplete".into());
    }
    let link = u32_at(&header, 16, le).unwrap_or(0) & 0x0fff_ffff;
    acc.report.format = "pcap".into();
    acc.report.links = vec![link_name(link)];
    let mut rec = [0u8; 16];
    let mut frame = Vec::new();
    while acc.report.packets < MAX_PACKETS {
        match read_exact_or_end(input, &mut rec) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                acc.report.warnings.push(e);
                break;
            }
        }
        let secs = u32_at(&rec, 0, le).unwrap_or(0) as f64;
        let frac = u32_at(&rec, 4, le).unwrap_or(0) as f64;
        let incl = u32_at(&rec, 8, le).unwrap_or(0) as usize;
        let orig = u32_at(&rec, 12, le).unwrap_or(0) as u64;
        if incl > MAX_PACKET_LEN {
            acc.report.warnings.push(format!("A packet record claims {incl} bytes; the file is damaged after packet {}", acc.report.packets));
            break;
        }
        frame.resize(incl, 0);
        if let Err(e) = read_exact_or_end(input, &mut frame).and_then(|ok| if ok || incl == 0 { Ok(()) } else { Err("The capture ends in the middle of a packet".into()) }) {
            acc.report.warnings.push(e);
            break;
        }
        acc.packet(link, &frame, orig, secs + frac / if nanos { 1e9 } else { 1e6 });
    }
    Ok(())
}

fn pcapng(acc: &mut Acc, input: &mut impl Read) -> Result<(), String> {
    acc.report.format = "pcapng".into();
    // the section header: total length (4), byte-order magic (4)
    let mut head = [0u8; 8];
    if !read_exact_or_end(input, &mut head)? {
        return Err("The pcapng section header is incomplete".into());
    }
    let le = match &head[4..8] {
        [0x4d, 0x3c, 0x2b, 0x1a] => true,
        [0x1a, 0x2b, 0x3c, 0x4d] => false,
        _ => return Err("The pcapng byte-order mark is not valid".into()),
    };
    let first_len = u32_at(&head, 0, le).unwrap_or(0) as usize;
    if !(28..=1_048_576).contains(&first_len) {
        return Err("The pcapng section header is not valid".into());
    }
    let mut skip = vec![0u8; first_len - 12];
    read_exact_or_end(input, &mut skip)?;
    // interfaces of the current section: (link type, timestamp units per second)
    let mut ifaces: Vec<(u32, f64)> = Vec::new();
    let mut le = le;
    let mut bh = [0u8; 8];
    while acc.report.packets < MAX_PACKETS {
        match read_exact_or_end(input, &mut bh) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                acc.report.warnings.push(e);
                break;
            }
        }
        let ty = u32_at(&bh, 0, le).unwrap_or(0);
        let total = u32_at(&bh, 4, le).unwrap_or(0) as usize;
        if ty == 0x0a0d_0d0a {
            // a new section: its own byte order and interfaces
            let mut magic = [0u8; 4];
            read_exact_or_end(input, &mut magic)?;
            le = magic == [0x4d, 0x3c, 0x2b, 0x1a];
            let total = u32_at(&bh, 4, le).unwrap_or(0) as usize;
            if !(28..=1_048_576).contains(&total) {
                acc.report.warnings.push("A section header is damaged; the rest was not read".into());
                break;
            }
            let mut rest = vec![0u8; total - 12];
            read_exact_or_end(input, &mut rest)?;
            ifaces.clear();
            continue;
        }
        if !(12..=MAX_PACKET_LEN + 64).contains(&total) || !total.is_multiple_of(4) {
            acc.report.warnings.push(format!("A block claims {total} bytes; the file is damaged after packet {}", acc.report.packets));
            break;
        }
        let mut body = vec![0u8; total - 8];
        if let Err(e) = read_exact_or_end(input, &mut body).and_then(|ok| if ok { Ok(()) } else { Err("The capture ends in the middle of a block".into()) }) {
            acc.report.warnings.push(e);
            break;
        }
        let body = &body[..body.len() - 4]; // the trailing length
        match ty {
            1 => {
                let link = u16_at(body, 0, le).unwrap_or(0) as u32;
                // options: if_tsresol (code 9)
                let mut units = 1e6;
                let mut off = 8;
                while off + 4 <= body.len() {
                    let code = u16_at(body, off, le).unwrap_or(0);
                    let len = u16_at(body, off + 2, le).unwrap_or(0) as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && len == 1 {
                        let v = body.get(off + 4).copied().unwrap_or(6);
                        units = if v & 0x80 != 0 { 2f64.powi((v & 0x7f) as i32) } else { 10f64.powi(v as i32) };
                    }
                    off += 4 + len.div_ceil(4) * 4;
                }
                let name = link_name(link);
                if !acc.report.links.contains(&name) {
                    acc.report.links.push(name);
                }
                ifaces.push((link, units));
            }
            6 => {
                let iface = u32_at(body, 0, le).unwrap_or(0) as usize;
                let ts = ((u32_at(body, 4, le).unwrap_or(0) as u64) << 32) | u32_at(body, 8, le).unwrap_or(0) as u64;
                let cap = u32_at(body, 12, le).unwrap_or(0) as usize;
                let orig = u32_at(body, 16, le).unwrap_or(0) as u64;
                let (link, units) = ifaces.get(iface).copied().unwrap_or((1, 1e6));
                if let Some(frame) = body.get(20..20 + cap) {
                    acc.packet(link, frame, orig, ts as f64 / units);
                }
            }
            3 => {
                let orig = u32_at(body, 0, le).unwrap_or(0) as u64;
                let (link, _) = ifaces.first().copied().unwrap_or((1, 1e6));
                let cap = (orig as usize).min(body.len().saturating_sub(4));
                // a block of the minimum length has no frame at all
                if let Some(frame) = body.get(4..4 + cap) {
                    acc.packet(link, frame, orig, 0.0);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "pcap_tests.rs"]
pub(crate) mod tests;
