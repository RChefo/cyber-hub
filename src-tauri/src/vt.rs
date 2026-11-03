//! VirusTotal API v3 provider — reputation lookups only.
//!
//! * Lookups are read-only GET requests (`/ip_addresses`, `/domains`, `/urls/{id}`, `/files`).
//!   Nothing is ever uploaded or submitted for scanning.
//! * The API key is read from the OS credential store by the caller and sent only in the
//!   `x-apikey` header to the fixed API base. It never appears in URLs, errors or storage.
//! * Private / reserved IP addresses and internal domain names are refused before any
//!   request, so local network details are not disclosed.
//! * A client-side limiter keeps requests within the public API allowance.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const API_BASE: &str = "https://www.virustotal.com/api/v3";
pub const GUI_BASE: &str = "https://www.virustotal.com/gui";
/// Fresh-cache lifetime for a report.
pub const REPORT_TTL_SECS: i64 = 24 * 3600;
/// Fresh-cache lifetime for "VirusTotal has no record of this".
pub const NOT_FOUND_TTL_SECS: i64 = 3600;
/// Public API allowance: 4 requests per minute.
pub const PUBLIC_RATE_PER_MIN: usize = 4;

/* ───────────────────────── indicators ───────────────────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ip,
    Domain,
    Url,
    File,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Ip => "ip",
            Kind::Domain => "domain",
            Kind::Url => "url",
            Kind::File => "file",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Kind::Ip => "IP address",
            Kind::Domain => "Domain",
            Kind::Url => "URL",
            Kind::File => "File hash",
        }
    }

    /// Lower-case form for use inside a sentence ("VirusTotal URL lookup").
    pub fn noun(self) -> &'static str {
        match self {
            Kind::Ip => "IP address",
            Kind::Domain => "domain",
            Kind::Url => "URL",
            Kind::File => "file hash",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    pub kind: Kind,
    /// normalized value (lower-case hash/domain, canonical IP, URL as entered)
    pub value: String,
    /// API path below the base, e.g. `/ip_addresses/8.8.8.8`
    #[serde(skip)]
    pub path: String,
    /// hash type for files
    pub hash_type: Option<&'static str>,
}

impl Indicator {
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
}

static DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap());

/// Suffixes that only exist on private networks or are reserved; never sent to VirusTotal.
const INTERNAL_SUFFIXES: &[&str] = &[
    "local", "localhost", "internal", "intranet", "lan", "home", "corp", "home.arpa", "test", "invalid", "example",
    "localdomain",
];

/// RFC 4648 base64url without padding (VirusTotal URL identifiers).
pub fn base64url_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for c in chars.iter().take(chunk.len() + 1) {
            out.push(ALPHABET[*c as usize] as char);
        }
    }
    out
}

/// True for addresses that are not routable on the public Internet.
pub fn is_non_public(ip: &IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        }
    }
}

/// Detect and validate the indicator type. Pure: no I/O.
pub fn detect(input: &str) -> Result<Indicator, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Enter an IP address, domain, URL or file hash".into());
    }
    if s.len() > 2048 || s.chars().any(|c| c.is_control()) {
        return Err("The value is too long or contains control characters".into());
    }

    // file hashes
    if HEX_RE.is_match(s) {
        let hash_type = match s.len() {
            32 => Some("MD5"),
            40 => Some("SHA-1"),
            64 => Some("SHA-256"),
            _ => None,
        };
        if let Some(t) = hash_type {
            let h = s.to_ascii_lowercase();
            return Ok(Indicator { kind: Kind::File, path: format!("/files/{h}"), value: h, hash_type: Some(t) });
        }
    }

    // URLs (looked up by identifier; never submitted for scanning)
    if s.contains("://") {
        let u = url::Url::parse(s).map_err(|_| "This URL is not valid".to_string())?;
        if !matches!(u.scheme(), "http" | "https") {
            return Err("Only http and https URLs can be looked up".into());
        }
        match u.host() {
            None => return Err("The URL has no host".into()),
            Some(url::Host::Ipv4(ip)) if is_non_public(&IpAddr::V4(ip)) => {
                return Err("URLs on private or reserved addresses are not sent to VirusTotal".into())
            }
            Some(url::Host::Ipv6(ip)) if is_non_public(&IpAddr::V6(ip)) => {
                return Err("URLs on private or reserved addresses are not sent to VirusTotal".into())
            }
            Some(url::Host::Domain(d)) if is_internal_domain(d) => {
                return Err("URLs on internal host names are not sent to VirusTotal".into())
            }
            _ => {}
        }
        return Ok(Indicator {
            kind: Kind::Url,
            path: format!("/urls/{}", base64url_nopad(s.as_bytes())),
            value: s.to_string(),
            hash_type: None,
        });
    }

    // IP addresses
    if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        let ip = ip.to_canonical();
        if is_non_public(&ip) {
            return Err("Private, loopback and reserved addresses are not sent to VirusTotal".into());
        }
        let v = ip.to_string();
        return Ok(Indicator { kind: Kind::Ip, path: format!("/ip_addresses/{v}"), value: v, hash_type: None });
    }

    // domains
    let d = s.trim_end_matches('.').to_ascii_lowercase();
    if DOMAIN_RE.is_match(&d) {
        if is_internal_domain(&d) {
            return Err("Internal or reserved domain names are not sent to VirusTotal".into());
        }
        return Ok(Indicator { kind: Kind::Domain, path: format!("/domains/{d}"), value: d, hash_type: None });
    }

    if HEX_RE.is_match(s) {
        return Err("Hashes must be MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal characters".into());
    }
    Err("Enter a public IP address, a domain, an http(s) URL, or an MD5, SHA-1 or SHA-256 hash".into())
}

fn is_internal_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.').to_ascii_lowercase();
    !d.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

/* ───────────────────────── reports ───────────────────────── */

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub timeout: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineVerdict {
    pub engine: String,
    pub category: String,
    pub result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub kind: Kind,
    pub indicator: String,
    pub stats: Stats,
    pub engines_total: u32,
    pub reputation: Option<i64>,
    /// unix seconds
    pub last_analysis_date: Option<i64>,
    pub votes_harmless: Option<i64>,
    pub votes_malicious: Option<i64>,
    /// engines that flagged the indicator (malicious first)
    pub flagged: Vec<EngineVerdict>,
    pub threat_label: Option<String>,
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub details: Vec<Detail>,
    pub permalink: String,
}

fn u(v: &Value, k: &str) -> u32 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0) as u32
}
fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| match x {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}
fn date(ts: Option<i64>) -> Option<String> {
    ts.and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
}
fn human_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}

/// Normalize a VirusTotal v3 object (`{"data": {...}}`) into a report.
pub fn parse_report(ind: &Indicator, body: &Value) -> Result<Report, String> {
    let data = body.get("data").ok_or("VirusTotal returned an unexpected response")?;
    let a = data.get("attributes").ok_or("VirusTotal returned an object without attributes")?;
    let id = data.get("id").and_then(Value::as_str).unwrap_or(&ind.value).to_string();

    let st = a.get("last_analysis_stats").cloned().unwrap_or(Value::Null);
    let stats = Stats {
        malicious: u(&st, "malicious"),
        suspicious: u(&st, "suspicious"),
        harmless: u(&st, "harmless"),
        undetected: u(&st, "undetected"),
        timeout: u(&st, "timeout"),
    };

    // The total is taken from the statistics (engines that returned a verdict), not from the
    // per-engine map, so the headline "x of y" always matches the tiles and the distribution bar.
    // Timeouts and unsupported types are not verdicts and are reported separately.
    let engines_total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    let mut flagged = Vec::new();
    if let Some(results) = a.get("last_analysis_results").and_then(Value::as_object) {
        for (name, r) in results {
            let cat = r.get("category").and_then(Value::as_str).unwrap_or("");
            if cat == "malicious" || cat == "suspicious" {
                flagged.push(EngineVerdict {
                    engine: r.get("engine_name").and_then(Value::as_str).unwrap_or(name).to_string(),
                    category: cat.to_string(),
                    result: r.get("result").and_then(Value::as_str).map(str::to_string),
                });
            }
        }
        flagged.sort_by(|x, y| (x.category != "malicious").cmp(&(y.category != "malicious")).then(x.engine.cmp(&y.engine)));
    }

    let votes = a.get("total_votes");
    let tags = a
        .get("tags")
        .and_then(Value::as_array)
        .map(|t| t.iter().filter_map(|x| x.as_str().map(str::to_string)).take(30).collect())
        .unwrap_or_default();
    let mut categories: Vec<String> = a
        .get("categories")
        .and_then(Value::as_object)
        .map(|m| m.values().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    categories.sort();
    categories.dedup();

    let threat_label = a
        .get("popular_threat_classification")
        .and_then(|p| p.get("suggested_threat_label"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut details = Vec::new();
    let mut push = |label: &str, value: Option<String>| {
        if let Some(v) = value {
            details.push(Detail { label: label.into(), value: v });
        }
    };
    let permalink = match ind.kind {
        Kind::Ip => {
            push("Country", s(a, "country"));
            push("Continent", s(a, "continent"));
            push("Owner (AS)", s(a, "as_owner"));
            push("ASN", s(a, "asn"));
            push("Network", s(a, "network"));
            push("Registry", s(a, "regional_internet_registry"));
            format!("{GUI_BASE}/ip-address/{}", ind.value)
        }
        Kind::Domain => {
            push("Registrar", s(a, "registrar"));
            push("Created", date(a.get("creation_date").and_then(Value::as_i64)));
            push("Last updated", date(a.get("last_update_date").and_then(Value::as_i64)));
            push("TLD", s(a, "tld"));
            format!("{GUI_BASE}/domain/{}", ind.value)
        }
        Kind::Url => {
            push("URL", s(a, "url"));
            push("Final URL", s(a, "last_final_url"));
            push("Page title", s(a, "title"));
            push("HTTP status", s(a, "last_http_response_code"));
            push("First submitted", date(a.get("first_submission_date").and_then(Value::as_i64)));
            format!("{GUI_BASE}/url/{id}")
        }
        Kind::File => {
            push("Name", s(a, "meaningful_name"));
            push("Type", s(a, "type_description"));
            push("Size", a.get("size").and_then(Value::as_u64).map(human_bytes));
            push("SHA-256", s(a, "sha256"));
            push("SHA-1", s(a, "sha1"));
            push("MD5", s(a, "md5"));
            push("First submitted", date(a.get("first_submission_date").and_then(Value::as_i64)));
            push("Times submitted", s(a, "times_submitted"));
            format!("{GUI_BASE}/file/{}", s(a, "sha256").unwrap_or_else(|| ind.value.clone()))
        }
    };

    Ok(Report {
        kind: ind.kind,
        indicator: ind.value.clone(),
        stats,
        engines_total,
        reputation: a.get("reputation").and_then(Value::as_i64),
        last_analysis_date: a.get("last_analysis_date").and_then(Value::as_i64),
        votes_harmless: votes.and_then(|v| v.get("harmless")).and_then(Value::as_i64),
        votes_malicious: votes.and_then(|v| v.get("malicious")).and_then(Value::as_i64),
        flagged,
        threat_label,
        tags,
        categories,
        details,
        permalink,
    })
}

/// Whether a cached entry fetched at `fetched_at` is still fresh at `now`.
pub fn is_fresh(fetched_at: &str, not_found: bool, now: chrono::DateTime<chrono::Utc>) -> bool {
    let ttl = if not_found { NOT_FOUND_TTL_SECS } else { REPORT_TTL_SECS };
    chrono::DateTime::parse_from_rfc3339(fetched_at)
        .map(|t| (now - t.with_timezone(&chrono::Utc)).num_seconds() < ttl)
        .unwrap_or(false)
}

/* ───────────────────────── rate limiting ───────────────────────── */

pub struct RateLimiter {
    max: usize,
    window: Duration,
    hits: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self { max, window, hits: Mutex::new(VecDeque::new()) }
    }

    /// Ok when a request may be made now; Err(seconds to wait) otherwise.
    pub fn try_acquire(&self, now: Instant) -> Result<(), u64> {
        let mut hits = self.hits.lock().map_err(|_| 60u64)?;
        while hits.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            hits.pop_front();
        }
        if hits.len() >= self.max {
            let oldest = *hits.front().expect("non-empty");
            let wait = self.window.saturating_sub(now.duration_since(oldest));
            return Err(wait.as_secs().max(1));
        }
        hits.push_back(now);
        Ok(())
    }
}

/* ───────────────────────── HTTP client ───────────────────────── */

#[derive(Debug, Clone, PartialEq)]
pub enum VtError {
    /// VirusTotal has no record of this indicator
    NotFound,
    /// key missing, wrong or not authorized
    Unauthorized,
    /// quota or rate limit exceeded (message from VirusTotal)
    Quota(String),
    Forbidden(String),
    BadRequest(String),
    Server(u16),
    Network(String),
}

impl VtError {
    pub fn user_message(&self) -> String {
        match self {
            VtError::NotFound => "VirusTotal has no record of this indicator.".into(),
            VtError::Unauthorized => "VirusTotal rejected the API key. Check or replace it in Settings.".into(),
            VtError::Quota(m) => {
                let m = m.trim().trim_end_matches('.');
                if m.is_empty() {
                    "VirusTotal quota or rate limit reached. Try again later.".into()
                } else {
                    format!("VirusTotal quota or rate limit reached ({m}). Try again later.")
                }
            }
            VtError::Forbidden(m) => format!("VirusTotal refused the request: {m}"),
            VtError::BadRequest(m) => format!("VirusTotal did not accept the request: {m}"),
            VtError::Server(code) => format!("VirusTotal is unavailable (HTTP {code}). Try again later."),
            VtError::Network(m) => format!("Could not reach VirusTotal: {m}"),
        }
    }
}

pub struct Client {
    base: String,
    http: reqwest::Client,
}

/// Remove any occurrence of the key from text that may be shown or stored.
pub fn scrub(text: &str, key: &str) -> String {
    if key.len() >= 8 {
        text.replace(key, "••••••")
    } else {
        text.to_string()
    }
}

impl Client {
    pub fn new(base: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http })
    }

    /// GET `{base}{path}` with the key in the `x-apikey` header.
    pub async fn get(&self, path: &str, key: &str) -> Result<Value, VtError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| VtError::Network(scrub(&e.without_url().to_string(), key)))?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status == 200 {
            return Ok(body);
        }
        let code = body.pointer("/error/code").and_then(Value::as_str).unwrap_or("");
        let msg = scrub(body.pointer("/error/message").and_then(Value::as_str).unwrap_or(""), key);
        Err(match (status, code) {
            (404, _) | (_, "NotFoundError") => VtError::NotFound,
            (401, _) | (_, "WrongCredentialsError") | (_, "AuthenticationRequiredError") => VtError::Unauthorized,
            (429, _) | (_, "QuotaExceededError") | (_, "TooManyRequestsError") => VtError::Quota(msg),
            (403, _) => VtError::Forbidden(msg),
            (400, _) => VtError::BadRequest(msg),
            (s, _) => VtError::Server(s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn detects_indicator_types() {
        assert_eq!(detect("8.8.8.8").unwrap().kind, Kind::Ip);
        assert_eq!(detect("2001:4860:4860::8888").unwrap().path, "/ip_addresses/2001:4860:4860::8888");
        assert_eq!(detect("Example.COM.").unwrap().value, "example.com");
        assert_eq!(detect("https://example.com/a?b=1").unwrap().kind, Kind::Url);
        let md5 = detect("44D88612FEA8A8F36DE82E1278ABB02F").unwrap();
        assert_eq!((md5.kind, md5.hash_type, md5.value.as_str()), (Kind::File, Some("MD5"), "44d88612fea8a8f36de82e1278abb02f"));
        assert_eq!(detect(&"a".repeat(40)).unwrap().hash_type, Some("SHA-1"));
        assert_eq!(detect(&"b".repeat(64)).unwrap().hash_type, Some("SHA-256"));
    }

    #[test]
    fn refuses_private_internal_and_invalid_values() {
        for v in [
            "10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1",
            "printer.local", "intranet", "srv.corp", "app.internal", "http://10.0.0.5/admin", "http://nas.lan/", "ftp://example.com/",
            "", "not a thing", "abc123", &"c".repeat(50), "http://\u{7}x.com",
        ] {
            assert!(detect(v).is_err(), "should refuse {v:?}");
        }
        assert!(detect(&"d".repeat(50)).unwrap_err().contains("MD5"));
    }

    #[test]
    fn url_identifier_is_base64url_without_padding() {
        assert_eq!(base64url_nopad(b"http://example.com/"), "aHR0cDovL2V4YW1wbGUuY29tLw");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(&[0xfb, 0xff]), "-_8");
        assert_eq!(detect("http://example.com/").unwrap().path, "/urls/aHR0cDovL2V4YW1wbGUuY29tLw");
    }

    fn file_fixture() -> Value {
        serde_json::json!({"data": {"id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "type": "file", "attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 0, "undetected": 3, "timeout": 0},
            "last_analysis_results": {
                "EngA": {"category": "malicious", "engine_name": "EngA", "result": "EICAR-Test-File"},
                "EngB": {"category": "undetected", "engine_name": "EngB", "result": null},
                "EngC": {"category": "suspicious", "engine_name": "EngC", "result": "heur"},
                "EngD": {"category": "malicious", "engine_name": "EngD", "result": "Eicar"},
                "EngE": {"category": "undetected", "engine_name": "EngE", "result": null},
                "EngF": {"category": "undetected", "engine_name": "EngF", "result": null}},
            "reputation": -5, "last_analysis_date": 1700000000,
            "total_votes": {"harmless": 1, "malicious": 7},
            "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"},
            "meaningful_name": "eicar.com", "type_description": "DOS COM", "size": 68,
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "md5": "44d88612fea8a8f36de82e1278abb02f",
            "tags": ["eicar", "attachment"]}}})
    }

    #[test]
    fn parses_file_report() {
        let ind = detect("44d88612fea8a8f36de82e1278abb02f").unwrap();
        let r = parse_report(&ind, &file_fixture()).unwrap();
        assert_eq!(r.stats, Stats { malicious: 2, suspicious: 1, harmless: 0, undetected: 3, timeout: 0 });
        assert_eq!(r.engines_total, 6);
        assert_eq!(r.flagged.iter().map(|f| f.engine.as_str()).collect::<Vec<_>>(), vec!["EngA", "EngD", "EngC"]);
        assert_eq!(r.reputation, Some(-5));
        assert_eq!(r.threat_label.as_deref(), Some("virus.eicar/test"));
        assert_eq!(r.votes_malicious, Some(7));
        assert!(r.details.iter().any(|d| d.label == "Size" && d.value == "68 B"));
        assert!(r.permalink.ends_with("/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
    }

    #[test]
    fn parses_ip_domain_and_url_reports() {
        let ip = detect("8.8.8.8").unwrap();
        let body = serde_json::json!({"data": {"id": "8.8.8.8", "attributes": {"last_analysis_stats": {"harmless": 60, "undetected": 30}, "country": "US", "as_owner": "GOOGLE", "asn": 15169, "reputation": 520}}});
        let r = parse_report(&ip, &body).unwrap();
        assert_eq!((r.stats.harmless, r.engines_total, r.reputation), (60, 90, Some(520)));
        assert!(r.details.iter().any(|d| d.label == "ASN" && d.value == "15169"));
        assert!(r.permalink.ends_with("/ip-address/8.8.8.8"));

        // the total follows the statistics even when the per-engine map is partial
        let partial = serde_json::json!({"data": {"id": "8.8.8.8", "attributes": {
            "last_analysis_stats": {"malicious": 1, "harmless": 50, "undetected": 20, "timeout": 2, "type-unsupported": 4},
            "last_analysis_results": {"EngA": {"category": "malicious", "engine_name": "EngA", "result": "bad"}}}}});
        let r = parse_report(&ip, &partial).unwrap();
        assert_eq!((r.engines_total, r.stats.timeout, r.flagged.len()), (71, 2, 1));

        let dom = detect("example.com").unwrap();
        let body = serde_json::json!({"data": {"attributes": {"categories": {"A": "information technology", "B": "information technology", "C": "search engines"}, "creation_date": 808372800, "registrar": "RESERVED-Internet Assigned Numbers Authority"}}});
        let r = parse_report(&dom, &body).unwrap();
        assert_eq!(r.categories, vec!["information technology", "search engines"]);
        assert!(r.details.iter().any(|d| d.label == "Created" && d.value.starts_with("1995-")));

        let url = detect("http://example.com/").unwrap();
        let body = serde_json::json!({"data": {"id": "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4", "attributes": {"url": "http://example.com/", "last_http_response_code": 200}}});
        let r = parse_report(&url, &body).unwrap();
        assert!(r.permalink.ends_with("/url/f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"));
        assert!(parse_report(&url, &serde_json::json!({"error": {}})).is_err());
    }

    #[test]
    fn cache_freshness() {
        let now = chrono::Utc::now();
        let iso = |secs: i64| (now - chrono::Duration::seconds(secs)).to_rfc3339();
        assert!(is_fresh(&iso(60), false, now));
        assert!(!is_fresh(&iso(REPORT_TTL_SECS + 5), false, now));
        assert!(is_fresh(&iso(60), true, now));
        assert!(!is_fresh(&iso(NOT_FOUND_TTL_SECS + 5), true, now));
        assert!(!is_fresh("garbage", false, now));
    }

    #[test]
    fn rate_limiter_allows_window_budget() {
        let l = RateLimiter::new(4, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..4 {
            assert!(l.try_acquire(t0 + Duration::from_secs(i)).is_ok());
        }
        let wait = l.try_acquire(t0 + Duration::from_secs(10)).unwrap_err();
        assert!((49..=50).contains(&wait), "{wait}");
        assert!(l.try_acquire(t0 + Duration::from_secs(61)).is_ok());
    }

    /// Minimal one-shot HTTP server returning a canned response; returns the raw request.
    fn mock_server(status: u16, body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
            req
        });
        (base, handle)
    }

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn sends_key_only_in_header_and_parses_success() {
        let (base, h) = mock_server(200, r#"{"data":{"id":"8.8.8.8","attributes":{"last_analysis_stats":{"harmless":1}}}}"#);
        let c = Client::new(&base).unwrap();
        let ind = detect("8.8.8.8").unwrap();
        let body = c.get(&ind.path, KEY).await.unwrap();
        assert_eq!(parse_report(&ind, &body).unwrap().stats.harmless, 1);
        let req = h.join().unwrap();
        let first_line = req.lines().next().unwrap().to_string();
        assert_eq!(first_line, "GET /ip_addresses/8.8.8.8 HTTP/1.1");
        assert!(!first_line.contains(KEY), "key must never be in the URL");
        assert!(req.to_ascii_lowercase().contains(&format!("x-apikey: {KEY}")));
    }

    #[tokio::test]
    async fn maps_api_errors_without_leaking_the_key() {
        let cases: [(u16, &'static str, VtError); 5] = [
            (404, r#"{"error":{"code":"NotFoundError","message":"not found"}}"#, VtError::NotFound),
            (401, r#"{"error":{"code":"WrongCredentialsError","message":"Wrong API key"}}"#, VtError::Unauthorized),
            (429, r#"{"error":{"code":"QuotaExceededError","message":"Quota exceeded"}}"#, VtError::Quota("Quota exceeded".into())),
            (400, r#"{"error":{"code":"InvalidArgumentError","message":"bad 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#, VtError::BadRequest("bad ••••••".into())),
            (503, "<html>down</html>", VtError::Server(503)),
        ];
        for (status, body, expected) in cases {
            let (base, h) = mock_server(status, body);
            let err = Client::new(&base).unwrap().get("/domains/example.com", KEY).await.unwrap_err();
            h.join().unwrap();
            assert_eq!(err, expected);
            assert!(!err.user_message().contains(KEY));
        }
    }

    #[tokio::test]
    async fn network_errors_do_not_leak_the_key() {
        // nothing listens on this port
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = Client::new(&format!("http://127.0.0.1:{port}")).unwrap().get("/domains/example.com", KEY).await.unwrap_err();
        assert!(matches!(err, VtError::Network(_)));
        assert!(!err.user_message().contains(KEY));
    }

    #[test]
    fn quota_messages_read_cleanly() {
        assert_eq!(VtError::Quota("Quota exceeded.".into()).user_message(), "VirusTotal quota or rate limit reached (Quota exceeded). Try again later.");
        assert_eq!(VtError::Quota(" ".into()).user_message(), "VirusTotal quota or rate limit reached. Try again later.");
    }
}
