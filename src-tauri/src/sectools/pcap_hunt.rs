//! Threat-hunting leads in a packet capture (docs/UTILITIES.md#packet-capture-triage): connections
//! made on a regular schedule (beacon-like timing) and DNS patterns of tunneling, data carried in
//! records, and algorithmically generated domains. These are patterns, not verdicts: updaters,
//! time and health checks keep schedules too, and CDNs and security products use long DNS names.
//! Each lead says what else it can be.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

/// Events (connection starts) kept per flow.
const MAX_EVENTS: usize = 2_000;
/// Flows and DNS domains followed.
const MAX_FLOWS: usize = 100_000;
const MAX_DOMAINS: usize = 50_000;
/// UDP packets closer than this to the previous one belong to the same exchange.
const UDP_GAP: f64 = 1.0;
/// A schedule needs this many connections over at least this many seconds.
const MIN_EVENTS: usize = 6;
const MIN_SPAN: f64 = 120.0;
const MAX_LEADS: usize = 100;

/// Ports of services that run on a schedule by design.
const SCHEDULED: &[(u16, &str)] = &[
    (53, "DNS"),
    (67, "DHCP"),
    (68, "DHCP"),
    (123, "NTP"),
    (137, "NetBIOS name service"),
    (138, "NetBIOS datagrams"),
    (161, "SNMP"),
    (162, "SNMP traps"),
    (514, "syslog"),
    (1900, "SSDP"),
    (3702, "WS-Discovery"),
    (5353, "mDNS"),
    (5355, "LLMNR"),
];

/// Connections on a regular schedule between two hosts.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Beacon {
    pub client: String,
    pub server: String,
    pub protocol: String,
    pub port: u16,
    pub connections: usize,
    /// the time between connections, in seconds: the mean of the gaps within a quarter of the
    /// median gap
    pub interval: f64,
    /// the mean distance of those gaps from the interval, in percent of it
    pub jitter: f64,
    /// connections within a quarter of the interval from it, in percent
    pub on_schedule: f64,
    /// first and last connection (Unix seconds)
    pub first: f64,
    pub last: f64,
    /// "regular" (jitter under 10%) or "jittered" (under 25%)
    pub regularity: String,
    /// why the schedule may be benign, for services that keep one by design
    pub note: Option<String>,
}

/// A DNS pattern worth a look.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsLead {
    /// DNS-TUNNEL, DNS-LONG, DNS-TXT or DNS-NXDOMAIN
    pub rule: String,
    pub title: String,
    pub detail: String,
    /// what else it can be
    pub benign: String,
    /// the domain (or the client, for failed lookups)
    pub subject: String,
    pub clients: Vec<String>,
    pub examples: Vec<String>,
    pub count: u64,
    /// ATT&CK techniques the pattern would fit if it were confirmed
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Hunting {
    pub beacons: Vec<Beacon>,
    pub dns: Vec<DnsLead>,
    pub notes: Vec<String>,
}

#[derive(Default)]
struct Domain {
    queries: u64,
    prefixes: BTreeSet<String>,
    /// sum of the length and of the entropy of the leftmost label of each distinct name
    label_len: usize,
    entropy: f64,
    longest: usize,
    long_names: BTreeSet<String>,
    txt: u64,
    clients: BTreeSet<String>,
}

#[derive(Default)]
pub struct Hunt {
    flows: HashMap<(String, String, bool, u16), Vec<f64>>,
    domains: HashMap<String, Domain>,
    /// per client: failed lookups and the domains they were for
    nx: HashMap<String, (u64, BTreeSet<String>, Vec<String>)>,
    capped: bool,
}

/// Shannon entropy of a label, in bits per character.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&k| k as f64 / n).map(|p| -p * p.log2()).sum()
}

/// The registered domain of a name, approximately: its last two labels, or three under a
/// two-letter country code whose second level is a common category (`example.co.uk`).
pub fn parent(name: &str) -> Option<String> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let n = labels.len();
    let tld = labels[n - 1];
    let take = if n >= 3 && tld.len() == 2 && ["co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go", "ltd", "plc"].contains(&labels[n - 2]) { 3 } else { 2 };
    Some(labels[n - take..].join("."))
}

fn local(name: &str) -> bool {
    let n = name.trim_end_matches('.');
    n.ends_with(".arpa") || [".local", ".lan", ".home", ".internal", ".localdomain", ".corp", ".home.arpa"].iter().any(|s| n.ends_with(s)) || !n.contains('.')
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

impl Hunt {
    /// A packet from the client to the server: a connection start for TCP (a SYN without ACK), or
    /// the start of an exchange for UDP (more than a second after the previous packet).
    pub fn packet(&mut self, client: &str, server: &str, tcp: bool, port: u16, ts: f64, starts: bool) {
        if ts <= 0.0 || (tcp && !starts) {
            return;
        }
        let key = (client.to_string(), server.to_string(), tcp, port);
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            self.capped = true;
            return;
        }
        let ev = self.flows.entry(key).or_default();
        if ev.len() >= MAX_EVENTS {
            return;
        }
        if !tcp && ev.last().is_some_and(|l| (ts - l).abs() < UDP_GAP) {
            return;
        }
        ev.push(ts);
    }

    /// A DNS question asked by a client.
    pub fn query(&mut self, client: &str, name: &str, kind: &str) {
        if local(name) {
            return;
        }
        let Some(p) = parent(name) else { return };
        if self.domains.len() >= MAX_DOMAINS && !self.domains.contains_key(&p) {
            self.capped = true;
            return;
        }
        let d = self.domains.entry(p.clone()).or_default();
        d.queries += 1;
        if matches!(kind, "TXT" | "NULL" | "TYPE10" | "ANY") {
            d.txt += 1;
        }
        if d.clients.len() < 50 {
            d.clients.insert(client.to_string());
        }
        let prefix = name.trim_end_matches('.').strip_suffix(&p).unwrap_or("").trim_end_matches('.').to_string();
        let longest = name.split('.').map(str::len).max().unwrap_or(0);
        if longest > 52 || name.len() > 120 {
            d.longest = d.longest.max(longest);
            if d.long_names.len() < 10 {
                d.long_names.insert(name.to_string());
            }
        }
        if !prefix.is_empty() && d.prefixes.len() < 5_000 && d.prefixes.insert(prefix.clone()) {
            let left = prefix.split('.').next().unwrap_or("");
            d.label_len += left.len();
            d.entropy += entropy(left);
        }
    }

    /// A DNS response to a client; rcode 3 is NXDOMAIN (the name does not exist).
    pub fn response(&mut self, client: &str, name: &str, rcode: u16) {
        if rcode != 3 || local(name) {
            return;
        }
        let Some(p) = parent(name) else { return };
        if self.nx.len() >= MAX_FLOWS && !self.nx.contains_key(client) {
            return;
        }
        let e = self.nx.entry(client.to_string()).or_default();
        e.0 += 1;
        if e.1.len() < 2_000 {
            e.1.insert(p);
        }
        if e.2.len() < 10 && !e.2.iter().any(|x| x == name) {
            e.2.push(name.to_string());
        }
    }

    pub fn finish(self) -> Hunting {
        let mut out = Hunting::default();
        for ((client, server, tcp, port), mut ev) in self.flows {
            if ev.len() < MIN_EVENTS {
                continue;
            }
            ev.sort_by(|a, b| a.total_cmp(b));
            let (first, last) = (ev[0], ev[ev.len() - 1]);
            if last - first < MIN_SPAN {
                continue;
            }
            let mut gaps: Vec<f64> = ev.windows(2).map(|w| w[1] - w[0]).filter(|g| *g > 0.0).collect();
            if gaps.len() + 1 < MIN_EVENTS {
                continue;
            }
            let m = median(&mut gaps);
            if m < 1.0 {
                continue;
            }
            // the gaps within a quarter of the median: missed connections (double gaps) and bursts
            // are left out, and alternating jitter (57 s, 63 s…) averages to its period
            let near: Vec<f64> = gaps.iter().copied().filter(|g| (g - m).abs() <= 0.25 * m).collect();
            let on = near.len() as f64 / gaps.len() as f64;
            let interval = near.iter().sum::<f64>() / near.len().max(1) as f64;
            let jitter = near.iter().map(|g| (g - interval).abs()).sum::<f64>() / near.len().max(1) as f64 / interval.max(f64::EPSILON);
            let regularity = if jitter <= 0.10 && on >= 0.8 {
                "regular"
            } else if jitter <= 0.25 && on >= 0.6 {
                "jittered"
            } else {
                continue;
            };
            let note = SCHEDULED.iter().find(|(p, _)| *p == port).map(|(_, s)| format!("{s} runs on a schedule by design"));
            out.beacons.push(Beacon {
                client,
                server,
                protocol: if tcp { "tcp".into() } else { "udp".into() },
                port,
                connections: ev.len(),
                interval: (interval * 10.0).round() / 10.0,
                jitter: (jitter * 1000.0).round() / 10.0,
                on_schedule: (on * 1000.0).round() / 10.0,
                first,
                last,
                regularity: regularity.into(),
                note,
            });
        }
        // regular before jittered, unexplained before services that keep a schedule, then the most connections
        out.beacons.sort_by(|a, b| (a.regularity != "regular", a.note.is_some(), std::cmp::Reverse(a.connections)).cmp(&(b.regularity != "regular", b.note.is_some(), std::cmp::Reverse(b.connections))));
        out.beacons.truncate(MAX_LEADS);

        let mut leads = Vec::new();
        for (domain, d) in &self.domains {
            let distinct = d.prefixes.len();
            let clients: Vec<String> = d.clients.iter().take(10).cloned().collect();
            let examples = || d.prefixes.iter().take(5).map(|p| format!("{p}.{domain}")).collect::<Vec<_>>();
            if distinct >= 30 {
                let avg_len = d.label_len as f64 / distinct as f64;
                let avg_entropy = d.entropy / distinct as f64;
                if avg_len >= 20.0 || avg_entropy >= 3.5 {
                    leads.push(DnsLead {
                        rule: "DNS-TUNNEL".into(),
                        title: format!("{distinct} long, random-looking names under {domain}"),
                        detail: format!("{} queries for {distinct} different names under one domain; their first labels average {avg_len:.0} characters with {avg_entropy:.1} bits of entropy per character. Data encoded into names is how DNS tunnels and exfiltration carry it.", d.queries),
                        benign: "CDNs, anti-virus and reputation lookups, and telemetry also send many encoded names under one domain.".into(),
                        subject: domain.clone(),
                        clients: clients.clone(),
                        examples: examples(),
                        count: d.queries,
                        techniques: vec!["T1071.004".into(), "T1572".into()],
                    });
                }
            }
            if !d.long_names.is_empty() {
                leads.push(DnsLead {
                    rule: "DNS-LONG".into(),
                    title: format!("Very long names under {domain}"),
                    detail: format!("A label of {} characters, or a name longer than 120: close to the limits of DNS, where tunnels put their data.", d.longest),
                    benign: "Some services encode identifiers or signatures into names.".into(),
                    subject: domain.clone(),
                    clients: clients.clone(),
                    examples: d.long_names.iter().cloned().collect(),
                    count: d.long_names.len() as u64,
                    techniques: vec!["T1071.004".into()],
                });
            }
            if d.txt >= 20 {
                leads.push(DnsLead {
                    rule: "DNS-TXT".into(),
                    title: format!("{} TXT, NULL or ANY queries to {domain}", d.txt),
                    detail: "These record types carry free text, which tools use to move commands or data over DNS.".into(),
                    benign: "Mail checks (SPF, DKIM, DMARC), domain verification and some services query TXT records routinely.".into(),
                    subject: domain.clone(),
                    clients: clients.clone(),
                    examples: examples(),
                    count: d.txt,
                    techniques: vec!["T1071.004".into()],
                });
            }
        }
        for (client, (failed, domains, names)) in &self.nx {
            if *failed >= 25 && domains.len() >= 15 {
                leads.push(DnsLead {
                    rule: "DNS-NXDOMAIN".into(),
                    title: format!("{client}: {failed} lookups of names that do not exist, under {} domains", domains.len()),
                    detail: "Malware with a domain generation algorithm tries many generated names until one resolves.".into(),
                    benign: "Typos, browser and search prefetching, misconfigured software and blocked domains also fail.".into(),
                    subject: client.clone(),
                    clients: vec![client.clone()],
                    examples: names.clone(),
                    count: *failed,
                    techniques: vec!["T1568.002".into()],
                });
            }
        }
        leads.sort_by(|a, b| b.count.cmp(&a.count).then(a.subject.cmp(&b.subject)));
        leads.truncate(MAX_LEADS);
        out.dns = leads;
        if self.capped {
            out.notes.push(format!("More than {MAX_FLOWS} flows or {MAX_DOMAINS} domains: the rest were not followed for hunting"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_schedule_is_a_beacon_lead_and_a_busy_flow_is_not() {
        let mut h = Hunt::default();
        // every 60 s (±2 s) for an hour
        for i in 0..60 {
            let jitter = if i % 2 == 0 { 1.5 } else { -1.5 };
            h.packet("10.0.0.5", "203.0.113.9:443", true, 443, 1_000.0 + i as f64 * 60.0 + jitter, true);
        }
        // a browser: bursts at irregular times
        for (i, t) in [0.0, 3.0, 4.0, 90.0, 400.0, 410.0, 1300.0, 1302.0, 2900.0, 2950.0].iter().enumerate() {
            h.packet("10.0.0.5", "198.51.100.7:443", true, 443, 2_000.0 + t + i as f64 * 0.01, true);
        }
        // NTP keeps a schedule by design
        for i in 0..20 {
            h.packet("10.0.0.5", "192.0.2.123:123", false, 123, 5_000.0 + i as f64 * 64.0, false);
        }
        // packets that do not start a TCP connection are not counted
        for i in 0..50 {
            h.packet("10.0.0.6", "203.0.113.10:443", true, 443, 9_000.0 + i as f64 * 30.0, false);
        }
        let r = h.finish();
        assert_eq!(r.beacons.len(), 2, "{:?}", r.beacons);
        let b = &r.beacons[0];
        assert_eq!((b.server.as_str(), b.connections, b.regularity.as_str(), b.note.is_none()), ("203.0.113.9:443", 60, "regular", true));
        // gaps alternate 57 s and 63 s: the period is 60 s and the jitter 5%, not one mode and 0%
        assert!((b.interval - 60.0).abs() < 0.2 && (b.jitter - 5.0).abs() < 0.2 && b.on_schedule >= 99.0, "{b:?}");
        assert_eq!((r.beacons[1].port, r.beacons[1].note.as_deref()), (123, Some("NTP runs on a schedule by design")));
    }

    #[test]
    fn udp_exchanges_collapse_and_short_captures_say_nothing() {
        let mut h = Hunt::default();
        for i in 0..10 {
            // three packets per exchange, every 30 s
            for k in 0..3 {
                h.packet("10.0.0.7", "203.0.113.5:9999", false, 9999, 100.0 + i as f64 * 30.0 + k as f64 * 0.1, false);
            }
        }
        // a schedule over less than two minutes is not one
        for i in 0..10 {
            h.packet("10.0.0.8", "203.0.113.6:443", true, 443, 100.0 + i as f64 * 5.0, true);
        }
        let r = h.finish();
        assert_eq!(r.beacons.len(), 1);
        assert_eq!((r.beacons[0].connections, r.beacons[0].interval), (10, 30.0));
    }

    #[test]
    fn dns_patterns_are_leads_with_their_benign_explanations() {
        let mut h = Hunt::default();
        // tunnel-like: 60 distinct 40-character hex labels under one domain
        for i in 0..60u64 {
            let label = format!("{:040x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x1234_5678_9abc_def0);
            h.query("10.0.0.9", &format!("{label}.t.badtunnel.example"), "A");
        }
        // TXT volume
        for i in 0..25 {
            h.query("10.0.0.9", &format!("cmd{i}.c2.example"), "TXT");
        }
        // a very long name
        h.query("10.0.0.9", &format!("{}.long.example", "a".repeat(60)), "A");
        // ordinary browsing under a CDN with short labels
        for i in 0..40 {
            h.query("10.0.0.10", &format!("img{i}.cdn.example"), "A");
        }
        // reverse lookups and local names are left out
        for i in 0..100 {
            h.query("10.0.0.10", &format!("{i}.2.0.192.in-addr.arpa"), "PTR");
            h.query("10.0.0.10", &format!("printer{i}.local"), "A");
        }
        // failed lookups of many generated domains
        for i in 0..30 {
            h.response("10.0.0.11", &format!("q{}x{}.com", i * 7919, i), 3);
        }
        h.response("10.0.0.12", "typo.example", 3);
        let r = h.finish();
        let rules: Vec<(&str, &str)> = r.dns.iter().map(|d| (d.rule.as_str(), d.subject.as_str())).collect();
        assert!(rules.contains(&("DNS-TUNNEL", "badtunnel.example")), "{rules:?}");
        assert!(rules.contains(&("DNS-TXT", "c2.example")), "{rules:?}");
        assert!(rules.contains(&("DNS-LONG", "long.example")), "{rules:?}");
        assert!(rules.contains(&("DNS-NXDOMAIN", "10.0.0.11")), "{rules:?}");
        assert!(!rules.iter().any(|(_, s)| *s == "cdn.example" || s.ends_with("arpa") || *s == "10.0.0.12"), "{rules:?}");
        assert!(r.dns.iter().all(|d| !d.benign.is_empty() && !d.techniques.is_empty()));
        for t in r.dns.iter().flat_map(|d| d.techniques.iter()) {
            assert_eq!(crate::workspace::attack::id_state(t), crate::workspace::attack::IdState::Current, "{t}");
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(parent("a.b.example.com").as_deref(), Some("example.com"));
        assert_eq!(parent("www.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(parent("localhost"), None);
        assert!(entropy("aaaa") < 0.01);
        assert!((entropy("abcd") - 2.0).abs() < 1e-9);
        assert!(local("1.2.0.192.in-addr.arpa") && local("nas.local") && local("intranet") && !local("example.com"));
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
    }
}
