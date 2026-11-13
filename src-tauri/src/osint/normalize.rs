// SPDX-License-Identifier: Apache-2.0
//! Type-specific normalization. `value` is the canonical form shown to the analyst; `key` is the
//! match key used for deduplication inside an investigation. Normalization is deliberately
//! conservative: it removes formatting differences (case where the system is case-insensitive,
//! trailing dots, default ports, IPv4-mapped IPv6) but never merges values that can name
//! different things (email local parts keep their case, URL paths and queries are kept,
//! usernames stay tied to their platform).

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde_json::{json, Map, Value};

use super::model::EntityType;

#[derive(Debug, Clone, PartialEq)]
pub struct Normalized {
    pub value: String,
    pub key: String,
    pub display: String,
    /// facts derived from the value itself (hash algorithm, platform, port...)
    pub metadata: Map<String, Value>,
}

impl Normalized {
    fn plain(value: String, key: String) -> Self {
        Normalized { display: value.clone(), value, key, metadata: Map::new() }
    }
}

const MAX_VALUE: usize = 2048;

pub fn normalize(t: EntityType, raw: &str) -> Result<Normalized, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    if s.len() > MAX_VALUE || s.chars().any(|c| c.is_control()) {
        return Err("value is too long or contains control characters".into());
    }
    match t {
        EntityType::Domain => domain(s).map(|d| Normalized::plain(d.clone(), d)),
        EntityType::Ip => ip(s).map(|v| Normalized::plain(v.clone(), v)),
        EntityType::Netblock => {
            let n = IpNet::from_str(s).map_err(|_| "not a network block (CIDR)".to_string())?.trunc();
            let v = n.to_string();
            Ok(Normalized::plain(v.clone(), v))
        }
        EntityType::Url | EntityType::Profile => url(s).map(|(v, host)| {
            let mut n = Normalized::plain(v.clone(), v);
            n.metadata.insert("host".into(), json!(host));
            n
        }),
        EntityType::Email => email(s),
        EntityType::Username => username(s),
        EntityType::Asn => asn(s).map(|n| Normalized::plain(format!("AS{n}"), format!("AS{n}"))),
        EntityType::Certificate => certificate(s),
        EntityType::Repository => repository(s),
        EntityType::Vulnerability => vulnerability(s).map(|v| Normalized::plain(v.clone(), v)),
        EntityType::FileHash => file_hash(s),
        EntityType::Service => service(s),
        EntityType::Organization | EntityType::Person | EntityType::HostingProvider | EntityType::Location | EntityType::Technology | EntityType::Threat | EntityType::Other => {
            let v = collapse(s);
            if v.chars().count() > 300 {
                return Err("name is too long".into());
            }
            Ok(Normalized::plain(v.clone(), v.to_lowercase()))
        }
    }
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Lower-case ASCII (IDNA) host name with at least two labels.
pub fn domain(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('.');
    if s.contains(['/', ':', '@', ' ']) {
        return Err("not a domain name".into());
    }
    let host = match url::Host::parse(s) {
        Ok(url::Host::Domain(d)) => d,
        _ => return Err("not a domain name".into()),
    };
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let ok = host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        && labels.last().is_some_and(|tld| tld.chars().any(|c| c.is_ascii_alphabetic()));
    if !ok {
        return Err("not a domain name".into());
    }
    Ok(host)
}

pub fn ip(s: &str) -> Result<String, String> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    let a = IpAddr::from_str(s).map_err(|_| "not an IP address".to_string())?;
    Ok(a.to_canonical().to_string())
}

/// URL with scheme and host lower-cased, default port and fragment removed, credentials dropped;
/// the path and query are kept as they are.
fn url(s: &str) -> Result<(String, String), String> {
    let mut u = url::Url::parse(s).map_err(|_| "not a URL".to_string())?;
    if !matches!(u.scheme(), "http" | "https" | "ftp") {
        return Err("only http, https and ftp URLs are supported".into());
    }
    let host = u.host_str().ok_or("URL without host")?.to_ascii_lowercase();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_fragment(None);
    Ok((u.to_string(), host.trim_start_matches('[').trim_end_matches(']').to_string()))
}

fn email(s: &str) -> Result<Normalized, String> {
    let s = s.trim().trim_start_matches("mailto:");
    let (local, dom) = s.rsplit_once('@').ok_or("not an email address")?;
    if local.is_empty() || local.len() > 64 || local.chars().any(|c| c.is_whitespace() || c == '@') {
        return Err("not an email address".into());
    }
    let dom = domain(dom)?;
    // the local part may be case-sensitive; only the domain is case-folded
    let v = format!("{local}@{dom}");
    let mut n = Normalized::plain(v.clone(), v);
    n.metadata.insert("domain".into(), json!(dom));
    Ok(n)
}

/// Platforms whose account names are case-insensitive.
const CASE_INSENSITIVE_PLATFORMS: &[&str] = &["github", "gitlab", "x", "twitter", "instagram", "reddit", "linkedin", "tiktok", "telegram", "keybase", "bitbucket", "docker", "npm", "pypi"];

/// `platform:handle` (platform required to avoid merging different people with the same name).
fn username(s: &str) -> Result<Normalized, String> {
    let (platform, handle) = match s.split_once(':') {
        Some((p, h)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') => (p.to_ascii_lowercase(), h.trim()),
        _ => ("unknown".to_string(), s),
    };
    let handle = handle.trim_start_matches('@');
    if handle.is_empty() || handle.chars().count() > 100 || handle.chars().any(char::is_whitespace) {
        return Err("not a username".into());
    }
    let key_handle = if CASE_INSENSITIVE_PLATFORMS.contains(&platform.as_str()) { handle.to_lowercase() } else { handle.to_string() };
    let mut n = Normalized { value: format!("{platform}:{handle}"), key: format!("{platform}:{key_handle}"), display: format!("{handle} ({platform})"), metadata: Map::new() };
    n.metadata.insert("platform".into(), json!(platform));
    n.metadata.insert("handle".into(), json!(handle));
    Ok(n)
}

pub fn asn(s: &str) -> Result<u32, String> {
    let digits = s.trim().trim_start_matches(['A', 'S', 'a', 's']).trim();
    let n: u32 = digits.parse().map_err(|_| "not an AS number".to_string())?;
    if n == 0 {
        return Err("AS0 is reserved".into());
    }
    Ok(n)
}

/// `sha256:<hex>` fingerprint, `crtsh:<id>` (crt.sh log entry) or `serial:<hex>`.
fn certificate(s: &str) -> Result<Normalized, String> {
    let lower = s.to_ascii_lowercase();
    // an explicit scheme prefix, otherwise a bare (possibly colon-separated) fingerprint
    let (scheme, rest) = match lower.split_once(':') {
        Some((a, b)) if matches!(a, "sha256" | "sha1" | "crtsh" | "serial") => (a.to_string(), b.to_string()),
        _ => ((if lower.chars().filter(|c| c.is_ascii_hexdigit()).count() == 40 { "sha1" } else { "sha256" }).to_string(), lower.clone()),
    };
    let hexish: String = rest.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    let v = match scheme.as_str() {
        "sha256" if hexish.len() == 64 && hexish.chars().all(|c| c.is_ascii_hexdigit()) => format!("sha256:{hexish}"),
        "sha1" if hexish.len() == 40 && hexish.chars().all(|c| c.is_ascii_hexdigit()) => format!("sha1:{hexish}"),
        "crtsh" if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) => format!("crtsh:{rest}"),
        "serial" if !hexish.is_empty() && hexish.len() <= 64 && hexish.chars().all(|c| c.is_ascii_hexdigit()) => format!("serial:{hexish}"),
        _ => return Err("certificate needs a sha256:/sha1: fingerprint, crtsh:<id> or serial:<hex>".into()),
    };
    Ok(Normalized::plain(v.clone(), v))
}

const CASE_INSENSITIVE_HOSTS: &[&str] = &["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"];

/// `host/owner/name` from a URL, `host/owner/name` or `owner/name` (GitHub).
fn repository(s: &str) -> Result<Normalized, String> {
    let s = s.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = if let Ok(u) = url::Url::parse(s) {
        format!("{}{}", u.host_str().ok_or("repository URL without host")?, u.path())
    } else {
        s.to_string()
    };
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let (host, owner, name) = match parts.as_slice() {
        [owner, name] => ("github.com".to_string(), *owner, *name),
        [host, owner, name, ..] if host.contains('.') => (host.to_ascii_lowercase(), *owner, *name),
        _ => return Err("repository needs host/owner/name or owner/name".into()),
    };
    let valid = |p: &str| !p.is_empty() && p.len() <= 100 && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !valid(owner) || !valid(name) {
        return Err("invalid repository owner or name".into());
    }
    let value = format!("{host}/{owner}/{name}");
    let key = if CASE_INSENSITIVE_HOSTS.contains(&host.as_str()) { value.to_ascii_lowercase() } else { value.clone() };
    let mut n = Normalized { display: format!("{owner}/{name}"), value, key, metadata: Map::new() };
    n.metadata.insert("platform".into(), json!(host));
    Ok(n)
}

fn vulnerability(s: &str) -> Result<String, String> {
    let u = s.trim().to_ascii_uppercase();
    if let Some(rest) = u.strip_prefix("CVE-") {
        let mut it = rest.split('-');
        let (y, n) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        if y.len() == 4 && y.chars().all(|c| c.is_ascii_digit()) && n.len() >= 4 && n.len() <= 8 && n.chars().all(|c| c.is_ascii_digit()) && it.next().is_none() {
            return Ok(u);
        }
    }
    if let Some(rest) = u.strip_prefix("GHSA-") {
        let parts: Vec<&str> = rest.split('-').collect();
        if parts.len() == 3 && parts.iter().all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_alphanumeric())) {
            return Ok(format!("GHSA-{}", rest.to_ascii_lowercase()));
        }
    }
    Err("vulnerability needs a CVE or GHSA identifier".into())
}

fn file_hash(s: &str) -> Result<Normalized, String> {
    let h = s.trim().to_ascii_lowercase();
    let algo = match h.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        128 => "sha512",
        _ => return Err("hash must be MD5, SHA-1, SHA-256 or SHA-512 hex".into()),
    };
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hash must be hexadecimal".into());
    }
    let mut n = Normalized::plain(h.clone(), h);
    n.metadata.insert("algorithm".into(), json!(algo));
    Ok(n)
}

/// `host:port/proto` with host an IP address or domain.
fn service(s: &str) -> Result<Normalized, String> {
    let (hp, proto) = s.rsplit_once('/').map(|(a, b)| (a, b.to_ascii_lowercase())).unwrap_or((s, "tcp".into()));
    if !matches!(proto.as_str(), "tcp" | "udp" | "sctp") {
        return Err("protocol must be tcp, udp or sctp".into());
    }
    let (host, port) = hp.rsplit_once(':').ok_or("service needs host:port/protocol")?;
    let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
    if port == 0 {
        return Err("invalid port".into());
    }
    let host_n = ip(host).or_else(|_| domain(host))?;
    let shown_host = if host_n.contains(':') { format!("[{host_n}]") } else { host_n.clone() };
    let v = format!("{shown_host}:{port}/{proto}");
    let mut n = Normalized::plain(v.clone(), v);
    n.metadata.insert("host".into(), json!(host_n));
    n.metadata.insert("port".into(), json!(port));
    n.metadata.insert("protocol".into(), json!(proto));
    Ok(n)
}

const ORG_SUFFIXES: &[&str] = &["inc", "incorporated", "llc", "ltd", "limited", "gmbh", "ag", "sa", "sas", "bv", "nv", "plc", "corp", "corporation", "co", "company", "srl", "oy", "ab", "as", "pty", "kk"];

/// A looser key for *possible* duplicates the analyst should review. Never used to merge.
pub fn loose_key(t: EntityType, key: &str) -> Option<String> {
    match t {
        EntityType::Organization | EntityType::HostingProvider => {
            let words: Vec<String> = key.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(|w| w.to_lowercase()).collect();
            let mut core: Vec<String> = words.clone();
            while core.len() > 1 && core.last().is_some_and(|w| ORG_SUFFIXES.contains(&w.as_str())) {
                core.pop();
            }
            Some(core.join(" "))
        }
        EntityType::Person | EntityType::Technology | EntityType::Location | EntityType::Threat => Some(key.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase()),
        EntityType::Email => Some(key.to_lowercase()),
        EntityType::Username => key.split_once(':').map(|(_, h)| h.to_lowercase()),
        EntityType::Domain => Some(key.trim_start_matches("www.").to_string()),
        EntityType::Url => Some(key.trim_end_matches('/').to_lowercase()),
        _ => None,
    }
}

/// Parent domain one label up, if it still has two labels.
pub fn parent_domain(d: &str) -> Option<&str> {
    let (_, rest) = d.split_once('.')?;
    rest.contains('.').then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use EntityType as T;

    fn v(t: EntityType, s: &str) -> String {
        normalize(t, s).unwrap().value
    }
    fn k(t: EntityType, s: &str) -> String {
        normalize(t, s).unwrap().key
    }

    #[test]
    fn domains_and_addresses_have_one_canonical_form() {
        assert_eq!(v(T::Domain, "WWW.Example.COM."), "www.example.com");
        assert_eq!(v(T::Domain, "bücher.example"), "xn--bcher-kva.example");
        for bad in ["example", "http://a.com", "a..com", "-a.com", "a b.com", "1.2.3.4", "user@a.com"] {
            assert!(normalize(T::Domain, bad).is_err(), "{bad}");
        }
        assert_eq!(v(T::Ip, "::ffff:192.0.2.10"), "192.0.2.10");
        assert_eq!(v(T::Ip, "2001:DB8::0:1"), "2001:db8::1");
        assert_eq!(v(T::Netblock, "192.0.2.77/24"), "192.0.2.0/24");
        assert_eq!(v(T::Asn, "as 13335"), "AS13335");
        assert!(normalize(T::Asn, "AS0").is_err());
    }

    #[test]
    fn urls_keep_path_and_query_but_drop_credentials_and_fragment() {
        assert_eq!(v(T::Url, "HTTPS://User:pw@Example.COM:443/A/b?x=1#frag"), "https://example.com/A/b?x=1");
        assert_ne!(k(T::Url, "https://example.com/a"), k(T::Url, "https://example.com/A"), "paths are case-sensitive");
        assert!(normalize(T::Url, "javascript:alert(1)").is_err());
        assert!(normalize(T::Url, "file:///etc/passwd").is_err());
    }

    #[test]
    fn identities_are_not_over_merged() {
        // the local part keeps its case: two keys, flagged as possible duplicates instead
        assert_eq!(v(T::Email, "John.Doe@EXAMPLE.org"), "John.Doe@example.org");
        assert_ne!(k(T::Email, "John.Doe@example.org"), k(T::Email, "john.doe@example.org"));
        assert_eq!(loose_key(T::Email, &k(T::Email, "John.Doe@example.org")), loose_key(T::Email, &k(T::Email, "john.doe@example.org")));
        // usernames are tied to their platform; case-folded only where the platform ignores case
        assert_eq!(k(T::Username, "GitHub:OctoCat"), "github:octocat");
        assert_ne!(k(T::Username, "github:alice"), k(T::Username, "mastodon:alice"));
        assert_eq!(k(T::Username, "mastodon:Alice"), "mastodon:Alice");
        assert_eq!(k(T::Username, "alice"), "unknown:alice");
        // organizations: exact key after whitespace/case folding; suffixes only in the loose key
        assert_eq!(k(T::Organization, "  Example   Corp "), "example corp");
        assert_ne!(k(T::Organization, "Example Corp"), k(T::Organization, "Example Inc"));
        assert_eq!(loose_key(T::Organization, "example corp"), loose_key(T::Organization, "example, inc."));
    }

    #[test]
    fn structured_identifiers() {
        assert_eq!(v(T::Repository, "https://github.com/Owner/Repo.git"), "github.com/Owner/Repo");
        assert_eq!(k(T::Repository, "Owner/Repo"), "github.com/owner/repo");
        assert_eq!(k(T::Repository, "git.example.org/Team/Tool"), "git.example.org/Team/Tool");
        assert_eq!(v(T::Vulnerability, "cve-2021-44228"), "CVE-2021-44228");
        assert_eq!(v(T::Vulnerability, "GHSA-JFH8-C2JP-5V3Q"), "GHSA-jfh8-c2jp-5v3q");
        assert!(normalize(T::Vulnerability, "CVE-21-1").is_err());
        let h = normalize(T::FileHash, "D41D8CD98F00B204E9800998ECF8427E").unwrap();
        assert_eq!((h.value.as_str(), h.metadata["algorithm"].as_str()), ("d41d8cd98f00b204e9800998ecf8427e", Some("md5")));
        assert_eq!(v(T::Certificate, "AB:CD:".repeat(16).trim_end_matches(':')), format!("sha256:{}", "abcd".repeat(16)));
        assert_eq!(v(T::Certificate, "crtsh:12345"), "crtsh:12345");
        assert_eq!(v(T::Service, "192.0.2.1:443/TCP"), "192.0.2.1:443/tcp");
        assert_eq!(v(T::Service, "2001:db8::1:22"), "[2001:db8::1]:22/tcp");
        assert!(normalize(T::Service, "192.0.2.1:0/tcp").is_err());
        assert!(normalize(T::Other, "a\u{0}b").is_err());
        assert_eq!(parent_domain("a.b.example.com"), Some("b.example.com"));
        assert_eq!(parent_domain("example.com"), None);
    }
}
