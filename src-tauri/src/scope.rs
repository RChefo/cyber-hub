//! Authorized-scope enforcement.
//!
//! Semantics (documented in docs/SECURITY.md):
//! - `domain`   `example.com`     matches exactly `example.com` (no subdomains)
//! - `wildcard` `*.example.com`   matches any subdomain (`a.example.com`, `a.b.example.com`), not the apex
//! - `ip`       `10.0.0.5`        matches that address
//! - `cidr`     `10.0.0.0/24`     matches addresses and sub-networks fully contained in it
//! - `url`      `https://app.x`   authorizes the URL's host (treated like `domain`)
//!
//! Out-of-scope entries (`in_scope = false`) always win over in-scope entries.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{validation, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeEntry {
    pub value: String,
    pub kind: String,
    pub in_scope: bool,
}

static HOST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?i)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$").unwrap()
});
static IP_RANGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$").unwrap());

/// Classify and normalize a user-entered scope value.
pub fn classify(value: &str) -> AppResult<(String, &'static str)> {
    let v = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if v.is_empty() {
        return Err(validation("Scope value is empty"));
    }
    if v.contains("://") {
        let u = url::Url::parse(&v).map_err(|_| validation(format!("Invalid URL: {v}")))?;
        if u.host_str().is_none() {
            return Err(validation(format!("URL has no host: {v}")));
        }
        return Ok((v, "url"));
    }
    if let Some(rest) = v.strip_prefix("*.") {
        if HOST_RE.is_match(rest) {
            return Ok((v, "wildcard"));
        }
        return Err(validation(format!("Invalid wildcard domain: {v}")));
    }
    if v.contains('/') {
        let net = IpNet::from_str(&v).map_err(|_| validation(format!("Invalid CIDR range: {v}")))?;
        return Ok((net.trunc().to_string(), "cidr"));
    }
    if IpAddr::from_str(&v).is_ok() {
        return Ok((v, "ip"));
    }
    if HOST_RE.is_match(&v) {
        return Ok((v, "domain"));
    }
    Err(validation(format!(
        "'{v}' is not a valid domain, wildcard (*.example.com), IP, CIDR or URL"
    )))
}

/// A target as extracted from a command argument.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Host(String),
    Ip(IpAddr),
    Net(IpNet),
    /// inclusive IPv4 range like 10.0.0.1-50
    Range(IpAddr, IpAddr),
}

/// Normalize IPv4-mapped IPv6 (`::ffff:10.0.0.1`) to IPv4 so it is compared against IPv4 scope entries.
fn canon(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Parse a single target string (host, host:port, URL, IP, [IPv6]:port, CIDR, IPv4 range).
pub fn parse_target(raw: &str) -> Option<Target> {
    let s = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if s.contains("://") {
        let u = url::Url::parse(s).ok()?;
        return match u.host()? {
            url::Host::Domain(d) => {
                // Any host in a URL is a real destination — including single-label names
                // like `intranet`, which can never match a scope entry and are therefore rejected.
                let h = d.trim_end_matches('.').to_ascii_lowercase();
                if h == "localhost" {
                    return Some(Target::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
                }
                (!h.is_empty()).then_some(Target::Host(h))
            }
            url::Host::Ipv4(ip) => Some(Target::Ip(IpAddr::V4(ip))),
            url::Host::Ipv6(ip) => Some(Target::Ip(canon(IpAddr::V6(ip)))),
        };
    }
    // [IPv6] or [IPv6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        if !(after.is_empty() || (after.starts_with(':') && after[1..].chars().all(|c| c.is_ascii_digit()) && after.len() > 1)) {
            return None;
        }
        return IpAddr::from_str(inner).ok().map(|ip| Target::Ip(canon(ip)));
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Some(Target::Ip(canon(ip)));
    }
    if let Ok(net) = IpNet::from_str(s) {
        return Some(Target::Net(net.trunc()));
    }
    if let Some(c) = IP_RANGE_RE.captures(s) {
        let start = IpAddr::from_str(&format!("{}{}", &c[1], &c[2])).ok()?;
        let end = IpAddr::from_str(&format!("{}{}", &c[1], &c[3])).ok()?;
        if start > end {
            return None;
        }
        return Some(Target::Range(start, end));
    }
    // host:port
    let host = match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h,
        _ => s,
    };
    if let Ok(ip) = IpAddr::from_str(host) {
        return Some(Target::Ip(canon(ip)));
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" {
        return Some(Target::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    }
    if HOST_RE.is_match(&host) {
        return Some(Target::Host(host));
    }
    // single-label host with an explicit port (`intranet:445`) is unambiguous enough to treat as a host
    if s.contains(':') && LABEL_RE.is_match(&host) {
        return Some(Target::Host(host));
    }
    None
}

static LABEL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?i)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$").unwrap());

fn host_matches(entry: &ScopeEntry, host: &str) -> bool {
    match entry.kind.as_str() {
        "domain" => entry.value == host,
        "wildcard" => {
            let base = entry.value.trim_start_matches("*.");
            host.len() > base.len() && host.ends_with(base) && host[..host.len() - base.len()].ends_with('.')
        }
        "url" => url::Url::parse(&entry.value)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
            .map(|h| h == host)
            .unwrap_or(false),
        _ => false,
    }
}

fn ip_matches(entry: &ScopeEntry, ip: &IpAddr) -> bool {
    let ip = &canon(*ip);
    match entry.kind.as_str() {
        "ip" => IpAddr::from_str(&entry.value).map(|e| &canon(e) == ip).unwrap_or(false),
        "cidr" => IpNet::from_str(&entry.value).map(|n| n.contains(ip)).unwrap_or(false),
        "url" => url::Url::parse(&entry.value)
            .ok()
            .and_then(|u| u.host_str().and_then(|h| IpAddr::from_str(h.trim_matches(['[', ']'])).ok()))
            .map(|e| &e == ip)
            .unwrap_or(false),
        _ => false,
    }
}

fn net_matches(entry: &ScopeEntry, net: &IpNet) -> bool {
    match entry.kind.as_str() {
        "cidr" => IpNet::from_str(&entry.value).map(|n| n.contains(net)).unwrap_or(false),
        "ip" => net.prefix_len() == net.max_prefix_len() && ip_matches(entry, &net.addr()),
        _ => false,
    }
}

fn any_match(entries: &[ScopeEntry], in_scope: bool, t: &Target) -> bool {
    entries.iter().filter(|e| e.in_scope == in_scope).any(|e| match t {
        Target::Host(h) => host_matches(e, h),
        Target::Ip(ip) => ip_matches(e, ip),
        Target::Net(n) => net_matches(e, n),
        Target::Range(a, b) => ip_matches(e, a) && ip_matches(e, b),
    })
}

/// Any overlap with an exclusion. For ranges/networks a partial overlap with an
/// out-of-scope entry also counts as a violation.
fn excluded(entries: &[ScopeEntry], t: &Target) -> bool {
    if any_match(entries, false, t) {
        return true;
    }
    match t {
        Target::Net(n) => entries.iter().filter(|e| !e.in_scope).any(|e| match e.kind.as_str() {
            "ip" => IpAddr::from_str(&e.value).map(|ip| n.contains(&ip)).unwrap_or(false),
            "cidr" => IpNet::from_str(&e.value).map(|x| n.contains(&x) || x.contains(n)).unwrap_or(false),
            _ => false,
        }),
        Target::Range(IpAddr::V4(a), IpAddr::V4(b)) => {
            let (lo, hi) = (u32::from(*a), u32::from(*b));
            entries.iter().filter(|e| !e.in_scope).any(|e| match e.kind.as_str() {
                "ip" => match IpAddr::from_str(&e.value) {
                    Ok(IpAddr::V4(ip)) => (lo..=hi).contains(&u32::from(ip)),
                    _ => false,
                },
                "cidr" => match IpNet::from_str(&e.value) {
                    Ok(IpNet::V4(n)) => u32::from(n.network()) <= hi && u32::from(n.broadcast()) >= lo,
                    _ => false,
                },
                _ => false,
            })
        }
        _ => false,
    }
}

pub fn target_label(t: &Target) -> String {
    match t {
        Target::Host(h) => h.clone(),
        Target::Ip(ip) => ip.to_string(),
        Target::Net(n) => n.to_string(),
        Target::Range(a, b) => format!("{a}-{b}"),
    }
}

/// Returns Ok(()) when the target is authorized, Err(reason) otherwise.
pub fn check_target(entries: &[ScopeEntry], t: &Target) -> Result<(), String> {
    let label = target_label(t);
    if excluded(entries, t) {
        return Err(format!("{label} is explicitly excluded from the project scope"));
    }
    if any_match(entries, true, t) {
        Ok(())
    } else {
        Err(format!("{label} is not in the authorized project scope"))
    }
}

/// Last labels that indicate a file name rather than a host (e.g. `common.txt`).
///
/// SECURITY: only extensions that are NOT delegated top-level domains may appear here.
/// `.zip`, `.py`, `.sh`, `.pl`, `.md`, `.mov`, `.app`, `.dev` … are real TLDs; excluding them
/// would let `evil.pl` pass unchecked. Existing files are recognized as files before this
/// heuristic runs, so real file arguments with such extensions are still handled.
const FILE_SUFFIXES: &[&str] = &[
    "txt", "lst", "json", "xml", "csv", "yaml", "yml", "html", "htm", "log", "conf", "cfg", "ini", "out", "nmap",
    "gnmap", "js", "php", "asp", "aspx", "jsp", "rb", "exe", "dll", "bin", "gz", "tar", "db", "sqlite", "pcap",
    "pcapng", "dic", "hash", "hashes", "pot", "rules", "rule", "pem", "crt", "req", "har", "tmp", "bak", "jpg", "png",
    "pdf", "docx", "img", "raw", "mem", "vmem", "dmp", "apk", "jar", "nse", "lua", "jsonl", "xlsx", "pptx",
];

fn looks_like_hostname(token: &str) -> bool {
    if token.contains('/') || token.contains('\\') || token.starts_with('@') {
        return false;
    }
    let (host, has_port) = match token.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, true),
        _ => (token, false),
    };
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || (has_port && LABEL_RE.is_match(&lower) && !lower.chars().all(|c| c.is_ascii_digit())) {
        return true;
    }
    match lower.rsplit_once('.') {
        Some((_, last)) if !FILE_SUFFIXES.contains(&last) => HOST_RE.is_match(&lower),
        _ => false,
    }
}

/// Loose scan of a single argument value for anything that names a network endpoint.
/// Used for values whose meaning is not modelled by a tool policy (e.g. `--script-args`
/// or values of unknown options). Unambiguous forms are reported: URLs, IPs, [IPv6],
/// CIDRs, IPv4 ranges, `user@host` and domain-like tokens whose last label is not a
/// common file extension (so `common.txt` is not treated as a host).
pub fn loose_targets(value: &str) -> Vec<Target> {
    let mut out = Vec::new();
    for raw in value.split([',', ';', '=', ' ', '\t', '(', ')', '"', '\'', '|', '<', '>']) {
        let mut p = raw.trim();
        if p.is_empty() || p.starts_with('-') {
            continue;
        }
        if p.contains("://") {
            if let Some(t) = parse_target(p) {
                out.push(t);
            }
            continue;
        }
        if let Some((_, host)) = p.rsplit_once('@') {
            p = host;
        }
        if let Ok(ip) = IpAddr::from_str(p) {
            out.push(Target::Ip(canon(ip)));
        } else if p.starts_with('[') {
            if let Some(t) = parse_target(p) {
                out.push(t);
            }
        } else if p.contains('/') && p.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            if let Ok(n) = IpNet::from_str(p) {
                out.push(Target::Net(n.trunc()));
            }
        } else if IP_RANGE_RE.is_match(p) || looks_like_hostname(p) {
            if let Some(t) = parse_target(p) {
                out.push(t);
            }
        }
    }
    out
}

/// Loose scan of every argument (flag values after `=` included). Test helper.
#[cfg(test)]
pub fn extract_targets_from_args(args: &[String]) -> Vec<Target> {
    args.iter()
        .flat_map(|arg| {
            let value = if arg.starts_with('-') { arg.split_once('=').map(|(_, v)| v).unwrap_or("") } else { arg.as_str() };
            loose_targets(value)
        })
        .collect()
}

/// Strictly parse a value that must be a target (a positional target or a target flag).
/// Comma-separated lists are split. Anything unparseable is an error, never ignored.
pub fn strict_targets(value: &str) -> Result<Vec<Target>, String> {
    let mut out = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match parse_target(part) {
            Some(t) => out.push(t),
            None => return Err(format!("'{part}' is not a recognizable host, IP, CIDR, range or URL")),
        }
    }
    if out.is_empty() {
        return Err("Empty target value".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(value: &str, in_scope: bool) -> ScopeEntry {
        let (v, kind) = classify(value).unwrap();
        ScopeEntry { value: v, kind: kind.to_string(), in_scope }
    }

    #[test]
    fn classify_values() {
        assert_eq!(classify("Example.COM.").unwrap(), ("example.com".into(), "domain"));
        assert_eq!(classify("*.example.com").unwrap().1, "wildcard");
        assert_eq!(classify("10.0.0.7/24").unwrap(), ("10.0.0.0/24".into(), "cidr"));
        assert_eq!(classify("::1").unwrap().1, "ip");
        assert_eq!(classify("https://app.example.com/login").unwrap().1, "url");
        assert!(classify("not a host").is_err());
        assert!(classify("*.").is_err());
    }

    #[test]
    fn domain_and_wildcard() {
        let s = vec![e("example.com", true), e("*.example.com", true), e("admin.example.com", false)];
        assert!(check_target(&s, &parse_target("example.com").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("https://api.example.com/v1").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("a.b.example.com:8443").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("admin.example.com").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("evilexample.com").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("example.com.evil.net").unwrap()).is_err());
    }

    #[test]
    fn wildcard_excludes_apex() {
        let s = vec![e("*.example.com", true)];
        assert!(check_target(&s, &parse_target("example.com").unwrap()).is_err());
    }

    #[test]
    fn ip_and_cidr() {
        let s = vec![e("10.0.0.0/24", true), e("10.0.0.13", false), e("192.168.1.10", true)];
        assert!(check_target(&s, &parse_target("10.0.0.5").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("10.0.0.128/25").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("10.0.0.0/25").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("10.0.0.0/16").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("10.0.0.13").unwrap()).is_err());
        // a network overlapping an excluded host is rejected
        assert!(check_target(&s, &parse_target("10.0.0.0/28").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("10.0.0.20-30").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("10.0.0.20-255").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("10.0.0.1-50").unwrap()).is_err());
        assert!(check_target(&s, &parse_target("192.168.1.10").unwrap()).is_ok());
        assert!(check_target(&s, &parse_target("192.168.1.11").unwrap()).is_err());
    }

    #[test]
    fn extracts_only_unambiguous_tokens() {
        let args: Vec<String> = ["-u", "https://t.example.com/FUZZ?a=b", "-w", "common.txt", "10.1.1.1,10.1.1.2", "--target=192.168.0.0/24", "-p", "80", "-d", "corp.example.org", "-o", "out.json", "/usr/share/x.y"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let t = extract_targets_from_args(&args);
        assert_eq!(t.len(), 5, "{t:?}");
        assert_eq!(t[4], Target::Host("corp.example.org".into()));
        assert_eq!(t[0], Target::Host("t.example.com".into()));
    }

    #[test]
    fn empty_scope_rejects_everything() {
        assert!(check_target(&[], &parse_target("example.com").unwrap()).is_err());
    }
}
