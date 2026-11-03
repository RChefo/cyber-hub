//! Indicator detection shared by every threat-intelligence provider.
//!
//! Detection is pure (no I/O). Private / reserved IP addresses, URLs on such addresses,
//! single-label host names and internal suffixes are refused here, before any provider is
//! contacted, so local network details are never disclosed to an external service.

use std::net::{IpAddr, Ipv4Addr};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub fn plural(self) -> &'static str {
        match self {
            Kind::Ip => "IP addresses",
            Kind::Domain => "domains",
            Kind::Url => "URLs",
            Kind::File => "file hashes",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HashType {
    #[serde(rename = "MD5")]
    Md5,
    #[serde(rename = "SHA-1")]
    Sha1,
    #[serde(rename = "SHA-256")]
    Sha256,
}

impl HashType {
    pub fn label(self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA-1",
            HashType::Sha256 => "SHA-256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Indicator {
    pub kind: Kind,
    /// normalized value (lower-case hash/domain, canonical IP, URL as entered)
    pub value: String,
    pub hash_type: Option<HashType>,
}

impl Indicator {
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
    pub fn is_ipv6(&self) -> bool {
        self.kind == Kind::Ip && self.value.contains(':')
    }
    pub fn hash_label(&self) -> Option<&'static str> {
        self.hash_type.map(HashType::label)
    }
}

static DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap());

/// Suffixes that only exist on private networks or are reserved; never sent anywhere.
const INTERNAL_SUFFIXES: &[&str] = &[
    "local", "localhost", "internal", "intranet", "lan", "home", "corp", "home.arpa", "test", "invalid", "example",
    "localdomain",
];

/// True for addresses that are not routable on the public Internet. IPv6 forms that embed an
/// IPv4 address (mapped, IPv4-compatible, NAT64, 6to4) are judged by the embedded address.
pub fn is_non_public(ip: &IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4_non_public(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
            // ::a.b.c.d (deprecated IPv4-compatible)
            if s[..6].iter().all(|x| *x == 0) && !v6.is_loopback() && !v6.is_unspecified() {
                return v4_non_public(embedded(s[6], s[7]));
            }
            // 64:ff9b::/96 NAT64 well-known prefix
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
                return v4_non_public(embedded(s[6], s[7]));
            }
            // 2002::/16 6to4
            if s[0] == 0x2002 {
                return v4_non_public(embedded(s[1], s[2]));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] & 0xffc0) == 0xfec0 // deprecated site local fec0::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0100 && s[1..4].iter().all(|x| *x == 0)) // discard-only 100::/64
        }
    }
}

fn v4_non_public(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments 192.0.0.0/24
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
}

pub fn is_internal_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.').to_ascii_lowercase();
    !d.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

/// Detect and validate the indicator type.
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
            32 => Some(HashType::Md5),
            40 => Some(HashType::Sha1),
            64 => Some(HashType::Sha256),
            _ => None,
        };
        if hash_type.is_some() {
            return Ok(Indicator { kind: Kind::File, value: s.to_ascii_lowercase(), hash_type });
        }
    }

    // URLs (looked up by identifier; never submitted for scanning)
    if s.contains("://") {
        let u = url::Url::parse(s).map_err(|_| "This URL is not valid".to_string())?;
        if !matches!(u.scheme(), "http" | "https") {
            return Err("Only http and https URLs can be looked up".into());
        }
        if !u.username().is_empty() || u.password().is_some() {
            return Err("URLs containing a user name or password are not sent to external services; remove the credentials first".into());
        }
        match u.host() {
            None => return Err("The URL has no host".into()),
            Some(url::Host::Ipv4(ip)) if is_non_public(&IpAddr::V4(ip)) => {
                return Err("URLs on private or reserved addresses are not sent to external services".into())
            }
            Some(url::Host::Ipv6(ip)) if is_non_public(&IpAddr::V6(ip)) => {
                return Err("URLs on private or reserved addresses are not sent to external services".into())
            }
            Some(url::Host::Domain(d)) if is_internal_domain(d) => {
                return Err("URLs on internal host names are not sent to external services".into())
            }
            _ => {}
        }
        return Ok(Indicator { kind: Kind::Url, value: s.to_string(), hash_type: None });
    }

    // IP addresses
    if let Ok(ip) = s.trim_matches(['[', ']']).parse::<IpAddr>() {
        let ip = ip.to_canonical();
        if is_non_public(&ip) {
            return Err("Private, loopback and reserved addresses are not sent to external services".into());
        }
        return Ok(Indicator { kind: Kind::Ip, value: ip.to_string(), hash_type: None });
    }

    // domains
    let d = s.trim_end_matches('.').to_ascii_lowercase();
    if DOMAIN_RE.is_match(&d) {
        if is_internal_domain(&d) {
            return Err("Internal or reserved domain names are not sent to external services".into());
        }
        return Ok(Indicator { kind: Kind::Domain, value: d, hash_type: None });
    }

    if HEX_RE.is_match(s) {
        return Err("Hashes must be MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal characters".into());
    }
    Err("Enter a public IP address, a domain, an http(s) URL, or an MD5, SHA-1 or SHA-256 hash".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_indicator_types() {
        assert_eq!(detect("8.8.8.8").unwrap().kind, Kind::Ip);
        assert!(detect("2001:4860:4860::8888").unwrap().is_ipv6());
        assert_eq!(detect("Example.COM.").unwrap().value, "example.com");
        assert_eq!(detect("https://example.com/a?b=1").unwrap().kind, Kind::Url);
        let md5 = detect("44D88612FEA8A8F36DE82E1278ABB02F").unwrap();
        assert_eq!((md5.kind, md5.hash_type, md5.value.as_str()), (Kind::File, Some(HashType::Md5), "44d88612fea8a8f36de82e1278abb02f"));
        assert_eq!(detect(&"a".repeat(40)).unwrap().hash_type, Some(HashType::Sha1));
        assert_eq!(detect(&"b".repeat(64)).unwrap().hash_type, Some(HashType::Sha256));
        assert_eq!(detect("::ffff:8.8.8.8").unwrap().value, "8.8.8.8");
        // embedded public addresses stay usable
        assert!(detect("64:ff9b::808:808").is_ok());
        assert!(detect("2002:0808:0808::1").is_ok());
    }

    #[test]
    fn refuses_private_and_internal_indicators() {
        for v in [
            "10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1",
            "http://10.1.2.3/x", "http://[::1]/", "https://intranet/", "fileserver.corp", "printer.local", "localhost",
            "ftp://example.org/", "abc", "12345", "64:ff9b::10.0.0.1", "::10.0.0.1", "2002:c0a8:0101::", "fec0::1",
            "192.0.0.8", "https://admin:S3cret@portal.example.org/", "https://user@portal.example.org/",
        ] {
            assert!(detect(v).is_err(), "{v} must be refused");
        }
    }
}
