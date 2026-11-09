//! Authorized-scope enforcement.
//!
//! Semantics (documented in docs/SECURITY.md#scope):
//! - `domain`   `example.com`     authorizes exactly `example.com` (no subdomains): the host, every
//!   port and every URL on it
//! - `wildcard` `*.example.com`   authorizes any subdomain (`a.example.com`, `a.b.example.com`),
//!   not the apex
//! - `ip`       `10.0.0.5`        authorizes that address
//! - `cidr`     `10.0.0.0/24`     authorizes addresses and sub-networks fully contained in it
//! - `url`      `https://app.example.com/api/` authorizes **only URLs** with the same scheme,
//!   host and port whose path is inside the entry's path (`/api/…`; an entry `/api` also covers
//!   `/api` itself, never `/apix`). A path-level authorization never implies host-level
//!   authorization: a host name or address in a tool's arguments, a port or service scan, a TLS
//!   check or an HTTP check of the host needs a `domain`, `wildcard`, `ip` or `cidr` entry.
//!
//! Out-of-scope entries (`in_scope = false`) always win over in-scope entries. An out-of-scope URL
//! excludes its path on every scheme and port of its host; because a host-level operation could
//! reach that path, it also refuses host-level operations on the host.
//!
//! Paths are compared after URL parsing (dot segments resolved, `\` as `/`), byte for byte and
//! case-sensitively; queries and fragments do not matter. Nothing here ever adds to a scope.

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
        // the path is case-sensitive: parsed from the value as entered (the parser lowercases the
        // scheme and host and resolves dot segments)
        let raw = value.trim();
        let mut u = url::Url::parse(raw).map_err(|_| validation(format!("Invalid URL: {raw}")))?;
        if u.host_str().map_or(true, str::is_empty) {
            return Err(validation(format!("URL has no host: {raw}")));
        }
        // a scope entry is not a place for credentials; queries and fragments do not limit a scope
        let _ = u.set_username("");
        let _ = u.set_password(None);
        u.set_query(None);
        u.set_fragment(None);
        return Ok((u.to_string(), "url"));
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
    /// a URL: authorized by a URL entry that covers it, or by a host-level entry for its host
    Url(Box<WebTarget>),
}

/// A URL target.
#[derive(Debug, Clone, PartialEq)]
pub struct WebTarget {
    /// the URL as parsed: scheme and host lowercased, dot segments resolved
    pub url: url::Url,
    /// its host as a host-level target (`Host` or `Ip`)
    pub host: Target,
}

impl Target {
    /// The host-level part of a target: the host of a URL, otherwise the target itself.
    pub fn host_level(&self) -> &Target {
        match self {
            Target::Url(w) => &w.host,
            t => t,
        }
    }
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
        let host = match u.host()? {
            url::Host::Domain(d) => {
                // Any host in a URL is a real destination — including single-label names
                // like `intranet`, which can never match a scope entry and are therefore rejected.
                let h = d.trim_end_matches('.').to_ascii_lowercase();
                if h == "localhost" {
                    Target::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                } else if h.is_empty() {
                    return None;
                } else {
                    Target::Host(h)
                }
            }
            url::Host::Ipv4(ip) => Target::Ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Target::Ip(canon(IpAddr::V6(ip))),
        };
        return Some(Target::Url(Box::new(WebTarget { url: u, host })));
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
        _ => false,
    }
}

fn ip_matches(entry: &ScopeEntry, ip: &IpAddr) -> bool {
    let ip = &canon(*ip);
    match entry.kind.as_str() {
        "ip" => IpAddr::from_str(&entry.value).map(|e| &canon(e) == ip).unwrap_or(false),
        "cidr" => IpNet::from_str(&entry.value).map(|n| n.contains(ip)).unwrap_or(false),
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

/// A `url` entry: the URL as a target (its scheme, host, port and path).
fn url_entry(e: &ScopeEntry) -> Option<WebTarget> {
    if e.kind != "url" {
        return None;
    }
    match parse_target(&e.value)? {
        Target::Url(w) => Some(*w),
        _ => None,
    }
}

/// Whether `path` is inside the entry path `prefix`: `/api/` covers `/api/…`; `/api` covers `/api`
/// and `/api/…`, never `/apix`; `/` covers every path.
fn path_within(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
    }
}

/// An in-scope URL entry authorizes a URL with the same scheme, host and port inside its path.
fn url_authorizes(e: &WebTarget, w: &WebTarget) -> bool {
    e.url.scheme() == w.url.scheme() && e.host == w.host && e.url.port_or_known_default() == w.url.port_or_known_default() && path_within(e.url.path(), w.url.path())
}

/// An out-of-scope URL entry covers its path on every scheme and port of its host.
fn url_excludes(e: &WebTarget, w: &WebTarget) -> bool {
    e.host == w.host && path_within(e.url.path(), w.url.path())
}

/// Whether a host-level target touches the host of an excluded URL (a host-level operation could
/// reach the excluded path).
fn touches_host(url_host: &Target, t: &Target) -> bool {
    match (url_host, t) {
        (Target::Host(a), Target::Host(b)) => a == b,
        (Target::Ip(a), Target::Ip(b)) => canon(*a) == canon(*b),
        (Target::Ip(a), Target::Net(n)) => n.contains(&canon(*a)),
        (Target::Ip(IpAddr::V4(a)), Target::Range(IpAddr::V4(lo), IpAddr::V4(hi))) => (u32::from(*lo)..=u32::from(*hi)).contains(&u32::from(*a)),
        _ => false,
    }
}

/// Whether an in-scope entry authorizes the target. URL entries authorize URLs only.
fn authorizes(e: &ScopeEntry, t: &Target) -> bool {
    match t {
        Target::Url(w) => match url_entry(e) {
            Some(u) => url_authorizes(&u, w),
            // a host-level entry authorizes every URL of its hosts
            None => authorizes(e, &w.host),
        },
        Target::Host(h) => host_matches(e, h),
        Target::Ip(ip) => ip_matches(e, ip),
        Target::Net(n) => net_matches(e, n),
        Target::Range(a, b) => ip_matches(e, a) && ip_matches(e, b),
    }
}

/// Whether an out-of-scope entry covers the target, wholly or in part. For ranges and networks a
/// partial overlap counts.
fn excludes(e: &ScopeEntry, t: &Target) -> bool {
    if let Some(u) = url_entry(e) {
        return match t {
            Target::Url(w) => url_excludes(&u, w),
            other => touches_host(&u.host, other),
        };
    }
    match t {
        Target::Url(w) => excludes(e, &w.host),
        Target::Host(h) => host_matches(e, h),
        Target::Ip(ip) => ip_matches(e, ip),
        Target::Net(n) => match e.kind.as_str() {
            "ip" => IpAddr::from_str(&e.value).map(|ip| n.contains(&canon(ip))).unwrap_or(false),
            "cidr" => IpNet::from_str(&e.value).map(|x| n.contains(&x) || x.contains(n)).unwrap_or(false),
            _ => false,
        },
        Target::Range(a, b) => match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let (lo, hi) = (u32::from(*a), u32::from(*b));
                match e.kind.as_str() {
                    "ip" => match IpAddr::from_str(&e.value) {
                        Ok(IpAddr::V4(ip)) => (lo..=hi).contains(&u32::from(ip)),
                        _ => false,
                    },
                    "cidr" => match IpNet::from_str(&e.value) {
                        Ok(IpNet::V4(n)) => u32::from(n.network()) <= hi && u32::from(n.broadcast()) >= lo,
                        _ => false,
                    },
                    _ => false,
                }
            }
            _ => ip_matches(e, a) || ip_matches(e, b),
        },
    }
}

/// A URL for messages and history: scheme, host, port and path (no credentials, query or fragment).
fn url_label(u: &url::Url) -> String {
    let host = u.host_str().unwrap_or("");
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{host}{port}{}", u.scheme(), u.path())
}

pub fn target_label(t: &Target) -> String {
    match t {
        Target::Host(h) => h.clone(),
        Target::Ip(ip) => ip.to_string(),
        Target::Net(n) => n.to_string(),
        Target::Range(a, b) => format!("{a}-{b}"),
        Target::Url(w) => url_label(&w.url),
    }
}

/// The reason a target is excluded, if an out-of-scope entry covers it. `host_level_paths`: whether
/// an excluded URL path also refuses host-level operations on its host (it does for operations
/// that contact the target; passive lookups of a host do not reach paths).
pub fn exclusion(entries: &[ScopeEntry], t: &Target, host_level_paths: bool) -> Option<String> {
    let label = target_label(t);
    let e = entries.iter().filter(|e| !e.in_scope).find(|e| (host_level_paths || e.kind != "url" || matches!(t, Target::Url(_))) && excludes(e, t))?;
    Some(if e.kind == "url" && !matches!(t, Target::Url(_)) {
        format!("{label} has an excluded path ({}); a host-level operation could reach it, so {label} is not authorized as a whole. Use URLs outside the excluded path", e.value)
    } else {
        format!("{label} is explicitly excluded from the project scope")
    })
}

/// Returns Ok(()) when the target is authorized, Err(reason) otherwise.
pub fn check_target(entries: &[ScopeEntry], t: &Target) -> Result<(), String> {
    if let Some(reason) = exclusion(entries, t, true) {
        return Err(reason);
    }
    if entries.iter().filter(|e| e.in_scope).any(|e| authorizes(e, t)) {
        return Ok(());
    }
    let label = target_label(t);
    // a near miss: the host is authorized only for some URLs
    let host = t.host_level();
    let paths: Vec<String> = entries.iter().filter(|e| e.in_scope).filter_map(|e| url_entry(e).filter(|u| &u.host == host).map(|u| url_label(&u.url))).collect();
    if !paths.is_empty() {
        let more = if paths.len() > 5 { format!(" and {} more", paths.len() - 5) } else { String::new() };
        let list = format!("{}{more}", paths.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
        return Err(match t {
            Target::Url(_) => format!("{label} is outside the authorized URLs of {} ({list}): only those paths, with the same scheme and port, are in scope", target_label(host)),
            _ => format!("{label} is authorized only for specific URLs ({list}); a host-level operation (for example a port, service or TLS scan, or a host name in a tool's arguments) needs the host, its domain or its address range in the scope"),
        });
    }
    Err(format!("{label} is not in the authorized project scope"))
}

/// Whether any in-scope URL entry has the same origin (scheme, host and port) as `url`: its web
/// service may be recorded in the asset inventory. Operations on it are checked on their own.
pub fn origin_has_authorized_paths(entries: &[ScopeEntry], url: &str) -> bool {
    let Some(Target::Url(w)) = parse_target(url) else { return false };
    entries.iter().filter(|e| e.in_scope).filter_map(url_entry).any(|u| u.url.scheme() == w.url.scheme() && u.host == w.host && u.url.port_or_known_default() == w.url.port_or_known_default())
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
        // a URL stays a URL (with its path), its host is the host-level part
        assert!(matches!(&t[0], Target::Url(w) if w.url.path() == "/FUZZ"), "{:?}", t[0]);
        assert_eq!(t[0].host_level(), &Target::Host("t.example.com".into()));
        assert_eq!(target_label(&t[0]), "https://t.example.com/FUZZ", "labels carry no query");
    }

    #[test]
    fn empty_scope_rejects_everything() {
        assert!(check_target(&[], &parse_target("example.com").unwrap()).is_err());
    }

    fn ok(s: &[ScopeEntry], t: &str) -> bool {
        check_target(s, &parse_target(t).unwrap_or_else(|| panic!("{t} is not a target"))).is_ok()
    }
    fn why(s: &[ScopeEntry], t: &str) -> String {
        check_target(s, &parse_target(t).unwrap()).unwrap_err()
    }

    #[test]
    fn url_entries_authorize_their_paths_only() {
        let s = vec![e("https://app.example.com/api/", true)];
        for t in [
            "https://app.example.com/api/",
            "https://app.example.com/api/v1/users?id=1#x",
            "https://APP.Example.com:443/api/v1",
            "https://app.example.com/api/../api/v2",
            "https://app.example.com\\api\\v3",
            "https://user:pw@app.example.com/api/v1",
        ] {
            assert!(ok(&s, t), "{t} is inside https://app.example.com/api/");
        }
        for t in [
            "https://app.example.com/apix",
            "https://app.example.com/api",
            "https://app.example.com/",
            "https://app.example.com/admin",
            "https://app.example.com/API/v1",
            "https://app.example.com/api/../admin",
            "https://app.example.com/api/%2e%2e/admin",
            "https://app.example.com/api%2F..%2Fadmin",
            "http://app.example.com/api/v1",
            "https://app.example.com:8443/api/v1",
            "https://api.app.example.com/api/v1",
            "https://app.example.com@evil.net/api/v1",
        ] {
            assert!(!ok(&s, t), "{t} must be refused");
        }
        // without a trailing slash, the entry covers the path itself and below it
        let s = vec![e("https://app.example.com/api", true)];
        assert!(ok(&s, "https://app.example.com/api") && ok(&s, "https://app.example.com/api/x"));
        assert!(!ok(&s, "https://app.example.com/apix") && !ok(&s, "https://app.example.com/api.json"));
        // an origin entry covers every path of that scheme, host and port, still not the host
        let s = vec![e("https://app.example.com", true)];
        assert!(ok(&s, "https://app.example.com/anything/at/all"));
        assert!(!ok(&s, "http://app.example.com/") && !ok(&s, "https://app.example.com:8443/"));
        assert!(!ok(&s, "app.example.com"));
    }

    #[test]
    fn a_path_level_authorization_never_implies_the_host() {
        let s = vec![e("https://app.example.com/api/", true), e("https://[2001:db8::1]/app/", true), e("http://10.0.0.5:8080/x/", true)];
        for t in ["app.example.com", "app.example.com:443", "2001:db8::1", "[2001:db8::1]:443", "10.0.0.5", "10.0.0.0/30", "10.0.0.1-9"] {
            let err = why(&s, t);
            assert!(err.contains("authorized only for specific URLs") || err.contains("not in the authorized"), "{t}: {err}");
        }
        let err = why(&s, "app.example.com");
        assert!(err.contains("https://app.example.com/api/") && err.contains("host-level operation"), "the refusal names the authorized URLs: {err}");
        let err = why(&s, "https://app.example.com/admin");
        assert!(err.contains("outside the authorized URLs of app.example.com"), "{err}");
        assert!(ok(&s, "https://[2001:db8::1]/app/x") && ok(&s, "http://10.0.0.5:8080/x/y"));
        assert!(!ok(&s, "https://[2001:db8::1]/other") && !ok(&s, "http://10.0.0.5/x/"));
        // host-level entries authorize every URL of their hosts, any scheme and port
        let s = vec![e("example.com", true), e("10.0.0.0/24", true)];
        for t in ["https://example.com/a", "http://example.com:8080/b?c", "ftp://example.com/x", "http://10.0.0.7/admin"] {
            assert!(ok(&s, t), "{t}");
        }
    }

    #[test]
    fn excluded_paths_win_and_keep_host_level_operations_away() {
        let s = vec![e("*.example.com", true), e("https://app.example.com/admin", false)];
        assert!(ok(&s, "https://app.example.com/api/x") && ok(&s, "https://www.example.com/admin"));
        for t in ["https://app.example.com/admin", "https://app.example.com/admin/users", "http://app.example.com:8080/admin"] {
            assert!(why(&s, t).contains("explicitly excluded"), "{t}: an excluded path is excluded on every scheme and port");
        }
        let err = why(&s, "app.example.com");
        assert!(err.contains("has an excluded path") && err.contains("https://app.example.com/admin"), "{err}");
        assert!(ok(&s, "www.example.com"), "other hosts are not affected");
        // passive lookups of the host do not reach paths
        assert!(exclusion(&s, &parse_target("app.example.com").unwrap(), false).is_none());
        assert!(exclusion(&s, &parse_target("https://app.example.com/admin/x").unwrap(), false).is_some());
        // an excluded host or range covers its URLs
        let s = vec![e("example.com", true), e("10.0.0.0/24", true), e("10.0.0.9", false)];
        assert!(why(&s, "http://10.0.0.9/").contains("explicitly excluded"));
    }

    #[test]
    fn url_entries_are_stored_without_credentials_query_or_fragment() {
        let (v, kind) = classify("HTTPS://User:Secret@App.Example.COM:443/Api/V1?token=x#frag").unwrap();
        assert_eq!((v.as_str(), kind), ("https://app.example.com/Api/V1", "url"), "the path keeps its case");
        assert_eq!(classify("https://app.example.com/a/./b/../c").unwrap().0, "https://app.example.com/a/c");
        assert!(classify("https://").is_err());
        assert!(origin_has_authorized_paths(&[e("https://app.example.com/api/", true)], "https://app.example.com"));
        assert!(!origin_has_authorized_paths(&[e("https://app.example.com/api/", true)], "http://app.example.com"));
        assert!(!origin_has_authorized_paths(&[e("https://app.example.com/api/", false)], "https://app.example.com"));
    }
}
