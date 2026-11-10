//! Threat-intelligence providers.
//!
//! Each provider has a fixed API base, its own credential (or a shared one, e.g. one abuse.ch
//! Auth-Key for URLhaus, MalwareBazaar and ThreatFox), its own client-side rate limit and cache
//! lifetime. Requests are made only by the Rust backend; keys never cross IPC.

pub mod abusech;
pub mod abuseipdb;
pub mod http;
pub mod indicator;
pub mod lifecycle;
pub mod limit;
pub mod model;
pub mod otx;
pub mod shodan;
pub mod stix;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use indicator::{HashType, Indicator, Kind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Virustotal,
    Abuseipdb,
    Otx,
    Urlhaus,
    Malwarebazaar,
    Threatfox,
    Shodan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyId {
    Virustotal,
    Abuseipdb,
    Otx,
    Abusech,
    Shodan,
}

impl ProviderId {
    pub const ALL: [ProviderId; 7] = [
        ProviderId::Virustotal,
        ProviderId::Abuseipdb,
        ProviderId::Otx,
        ProviderId::Urlhaus,
        ProviderId::Malwarebazaar,
        ProviderId::Threatfox,
        ProviderId::Shodan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "virustotal",
            ProviderId::Abuseipdb => "abuseipdb",
            ProviderId::Otx => "otx",
            ProviderId::Urlhaus => "urlhaus",
            ProviderId::Malwarebazaar => "malwarebazaar",
            ProviderId::Threatfox => "threatfox",
            ProviderId::Shodan => "shodan",
        }
    }

    pub fn parse(s: &str) -> Option<ProviderId> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    pub fn name(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "VirusTotal",
            ProviderId::Abuseipdb => "AbuseIPDB",
            ProviderId::Otx => "AlienVault OTX",
            ProviderId::Urlhaus => "URLhaus",
            ProviderId::Malwarebazaar => "MalwareBazaar",
            ProviderId::Threatfox => "ThreatFox",
            ProviderId::Shodan => "Shodan",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "Multi-engine verdicts and reputation for IPs, domains, URLs and files.",
            ProviderId::Abuseipdb => "Crowd-sourced abuse reports and a confidence score for IP addresses.",
            ProviderId::Otx => "Community threat pulses that reference an indicator, with malware families and adversaries.",
            ProviderId::Urlhaus => "Malware distribution URLs, the hosts serving them and the payloads they deliver.",
            ProviderId::Malwarebazaar => "Known malware samples by hash: family, file metadata and vendor intelligence.",
            ProviderId::Threatfox => "Indicators of compromise linked to malware families (C2 servers, payload URLs).",
            ProviderId::Shodan => "Internet-exposed services on an IP: open ports, banners, hostnames and CVE tags.",
        }
    }

    pub fn key(self) -> KeyId {
        match self {
            ProviderId::Virustotal => KeyId::Virustotal,
            ProviderId::Abuseipdb => KeyId::Abuseipdb,
            ProviderId::Otx => KeyId::Otx,
            ProviderId::Urlhaus | ProviderId::Malwarebazaar | ProviderId::Threatfox => KeyId::Abusech,
            ProviderId::Shodan => KeyId::Shodan,
        }
    }

    /// Indicator types the provider can look up (hash types matter for some).
    pub fn supports(self, ind: &Indicator) -> bool {
        match self {
            ProviderId::Virustotal | ProviderId::Otx => true,
            ProviderId::Abuseipdb | ProviderId::Shodan => ind.kind == Kind::Ip,
            ProviderId::Urlhaus | ProviderId::Threatfox => ind.kind != Kind::File || ind.hash_type != Some(HashType::Sha1),
            ProviderId::Malwarebazaar => ind.kind == Kind::File,
        }
    }

    pub fn kinds(self) -> &'static [&'static str] {
        match self {
            ProviderId::Virustotal | ProviderId::Otx => &["ip", "domain", "url", "file"],
            ProviderId::Abuseipdb | ProviderId::Shodan => &["ip"],
            ProviderId::Urlhaus | ProviderId::Threatfox => &["ip", "domain", "url", "file"],
            ProviderId::Malwarebazaar => &["file"],
        }
    }

    /// Fixed production API base.
    pub fn production_base(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "https://www.virustotal.com/api/v3",
            ProviderId::Abuseipdb => "https://api.abuseipdb.com/api/v2",
            ProviderId::Otx => "https://otx.alienvault.com/api/v1",
            ProviderId::Urlhaus => "https://urlhaus-api.abuse.ch/v1",
            ProviderId::Malwarebazaar => "https://mb-api.abuse.ch/api/v1",
            ProviderId::Threatfox => "https://threatfox-api.abuse.ch/api/v1",
            ProviderId::Shodan => "https://api.shodan.io",
        }
    }

    /// The API base in use. Release builds always use `production_base`. Debug builds may
    /// point every provider at a local mock server (loopback only) through
    /// `CYBERHUB_MOCK_API_BASE`; each provider then lives under `/<provider id>`.
    pub fn base(self) -> String {
        match mock_base() {
            Some(m) => format!("{m}/{}", self.as_str()),
            None => self.production_base().to_string(),
        }
    }

    /// Client-side limit, kept at or below the provider's documented allowance.
    pub fn rate(self) -> (usize, Duration) {
        match self {
            // public API: 4 requests / minute
            ProviderId::Virustotal => (4, Duration::from_secs(60)),
            // 1,000 checks / day on the free tier; avoid bursts
            ProviderId::Abuseipdb => (30, Duration::from_secs(60)),
            // no documented limit; stay conservative
            ProviderId::Otx => (30, Duration::from_secs(60)),
            // abuse.ch fair use
            ProviderId::Urlhaus | ProviderId::Malwarebazaar | ProviderId::Threatfox => (20, Duration::from_secs(60)),
            // all API plans: 1 request / second
            ProviderId::Shodan => (1, Duration::from_secs(1)),
        }
    }

    /// Cache lifetime in seconds for a record / for "no record".
    pub fn ttl(self, found: bool) -> i64 {
        if !found {
            return 3600;
        }
        match self {
            ProviderId::Virustotal | ProviderId::Shodan => 24 * 3600,
            ProviderId::Otx => 12 * 3600,
            ProviderId::Abuseipdb | ProviderId::Urlhaus | ProviderId::Malwarebazaar | ProviderId::Threatfox => 6 * 3600,
        }
    }

    pub fn docs_url(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "https://docs.virustotal.com/reference/overview",
            ProviderId::Abuseipdb => "https://docs.abuseipdb.com/",
            ProviderId::Otx => "https://otx.alienvault.com/api",
            ProviderId::Urlhaus => "https://urlhaus-api.abuse.ch/",
            ProviderId::Malwarebazaar => "https://bazaar.abuse.ch/api/",
            ProviderId::Threatfox => "https://threatfox.abuse.ch/api/",
            ProviderId::Shodan => "https://developer.shodan.io/api",
        }
    }

    /// Service limits shown in Settings. Deliberately no credential instructions: credentials
    /// are provisioned by the application owner.
    pub fn service_note(self) -> &'static str {
        match self {
            ProviderId::Virustotal => "Public API: 4 requests per minute plus daily caps. Indicators looked up and files uploaded can become part of the VirusTotal dataset.",
            ProviderId::Abuseipdb => "Up to 1,000 IP checks per day; the remaining quota is shown after a lookup.",
            ProviderId::Otx => "No published request limit; Cyber Hub stays under 30 requests per minute.",
            ProviderId::Urlhaus | ProviderId::Malwarebazaar | ProviderId::Threatfox => "abuse.ch community API under fair use.",
            ProviderId::Shodan => "1 request per second; host lookups do not use query credits.",
        }
    }
}

impl KeyId {
    pub const ALL: [KeyId; 5] = [KeyId::Virustotal, KeyId::Abuseipdb, KeyId::Otx, KeyId::Abusech, KeyId::Shodan];

    #[cfg(feature = "provisioning")]
    pub fn as_str(self) -> &'static str {
        match self {
            KeyId::Virustotal => "virustotal",
            KeyId::Abuseipdb => "abuseipdb",
            KeyId::Otx => "otx",
            KeyId::Abusech => "abusech",
            KeyId::Shodan => "shodan",
        }
    }

    #[cfg(feature = "provisioning")]
    pub fn parse(s: &str) -> Option<KeyId> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// Name of the entry in the OS credential store.
    pub fn secret_name(self) -> &'static str {
        match self {
            KeyId::Virustotal => "virustotal_api_key",
            KeyId::Abuseipdb => "abuseipdb_api_key",
            KeyId::Otx => "otx_api_key",
            KeyId::Abusech => "abusech_auth_key",
            KeyId::Shodan => "shodan_api_key",
        }
    }

    #[cfg(any(test, feature = "provisioning"))]
    pub fn label(self) -> &'static str {
        match self {
            KeyId::Virustotal => "VirusTotal API key",
            KeyId::Abuseipdb => "AbuseIPDB API key",
            KeyId::Otx => "AlienVault OTX API key",
            KeyId::Abusech => "abuse.ch Auth-Key",
            KeyId::Shodan => "Shodan API key",
        }
    }

    #[cfg(any(test, feature = "provisioning"))]
    pub fn providers(self) -> Vec<ProviderId> {
        ProviderId::ALL.into_iter().filter(|p| p.key() == self).collect()
    }

    #[cfg(feature = "provisioning")]
    pub fn signup_url(self) -> &'static str {
        match self {
            KeyId::Virustotal => "https://www.virustotal.com/gui/my-apikey",
            KeyId::Abuseipdb => "https://www.abuseipdb.com/account/api",
            KeyId::Otx => "https://otx.alienvault.com/settings",
            KeyId::Abusech => "https://auth.abuse.ch/",
            KeyId::Shodan => "https://account.shodan.io/",
        }
    }

    /// Local format check before a key is sent anywhere.
    #[cfg(any(test, feature = "provisioning"))]
    pub fn check_format(self, key: &str) -> Result<(), String> {
        let ok = match self {
            KeyId::Virustotal => key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()),
            _ => (8..=256).contains(&key.len()) && key.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
        };
        if ok {
            Ok(())
        } else if self == KeyId::Virustotal {
            Err("A VirusTotal API key is 64 hexadecimal characters.".into())
        } else {
            Err(format!("This does not look like a {} (8–256 letters, digits, '-', '_' or '.').", self.label()))
        }
    }
}

/// One read-only request proving a credential works, using a fixed public probe (never user
/// data). Returns quota / plan information where the provider reports it. Used only by the
/// developer provisioning tool and tests; no IPC command reaches it.
#[cfg(feature = "provisioning")]
pub async fn probe(k: KeyId, client: &reqwest::Client, key: &str) -> Result<Option<String>, http::ApiError> {
    match k {
        KeyId::Virustotal => match crate::vt::get(client, &ProviderId::Virustotal.base(), "/ip_addresses/8.8.8.8", key).await {
            Ok(_) | Err(http::ApiError::NotFound) => Ok(None),
            Err(http::ApiError::Quota(_)) => Ok(Some("credentials accepted; VirusTotal reports the quota is used up for now".into())),
            Err(e) => Err(e),
        },
        KeyId::Abuseipdb => abuseipdb::validate(client, &ProviderId::Abuseipdb.base(), key).await,
        KeyId::Otx => otx::validate(client, &ProviderId::Otx.base(), key).await,
        KeyId::Abusech => abusech::validate(client, &ProviderId::Malwarebazaar.base(), key).await,
        KeyId::Shodan => shodan::validate(client, &ProviderId::Shodan.base(), key).await,
    }
}

fn mock_base() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(raw) = std::env::var("CYBERHUB_MOCK_API_BASE") {
            return loopback_base(&raw);
        }
    }
    None
}

/// Accept only `http://127.0.0.1:<port>` or `http://localhost:<port>` with no credentials,
/// path, query or fragment.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
fn loopback_base(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw.trim()).ok()?;
    let host_ok = matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"));
    let clean = u.scheme() == "http" && u.username().is_empty() && u.password().is_none() && u.port().is_some() && matches!(u.path(), "" | "/") && u.query().is_none() && u.fragment().is_none();
    if !(host_ok && clean) {
        return None;
    }
    Some(format!("http://{}:{}", u.host_str()?, u.port()?))
}

/// True when the debug-only mock base is active (used to accept loopback upload URLs).
pub fn mock_active() -> bool {
    mock_base().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_have_fixed_https_bases_and_support_matrix() {
        for p in ProviderId::ALL {
            assert!(p.production_base().starts_with("https://"), "{p:?}");
            assert_eq!(ProviderId::parse(p.as_str()), Some(p));
        }
        let ip = indicator::detect("8.8.8.8").unwrap();
        let sha1 = indicator::detect(&"a".repeat(40)).unwrap();
        assert!(ProviderId::Abuseipdb.supports(&ip) && ProviderId::Shodan.supports(&ip));
        assert!(!ProviderId::Malwarebazaar.supports(&ip));
        assert!(ProviderId::Malwarebazaar.supports(&sha1));
        assert!(!ProviderId::Urlhaus.supports(&sha1) && !ProviderId::Threatfox.supports(&sha1));
        assert_eq!(KeyId::Abusech.providers(), vec![ProviderId::Urlhaus, ProviderId::Malwarebazaar, ProviderId::Threatfox]);
    }

    #[test]
    fn key_formats_are_checked_locally() {
        assert!(KeyId::Virustotal.check_format(&"a".repeat(64)).is_ok());
        assert!(KeyId::Virustotal.check_format("short").is_err());
        assert!(KeyId::Shodan.check_format("AbCdEf0123456789AbCdEf0123456789").is_ok());
        assert!(KeyId::Otx.check_format("has space in it").is_err());
        assert!(KeyId::Abuseipdb.check_format("abc\ndef12345").is_err());
    }

    #[test]
    fn mock_base_is_loopback_only() {
        std::env::set_var("CYBERHUB_MOCK_API_BASE", "https://evil.example/api");
        assert_eq!(ProviderId::Shodan.base(), "https://api.shodan.io");
        std::env::set_var("CYBERHUB_MOCK_API_BASE", "http://127.0.0.1:9999/");
        assert_eq!(ProviderId::Shodan.base(), "http://127.0.0.1:9999/shodan");
        std::env::remove_var("CYBERHUB_MOCK_API_BASE");
        assert_eq!(ProviderId::Otx.base(), "https://otx.alienvault.com/api/v1");
        for bad in ["http://127.0.0.1:1@evil.example", "http://127.0.0.1.evil.example:80", "https://127.0.0.1:9", "http://127.0.0.1", "http://localhost:9/x", "http://127.0.0.1:9/?a"] {
            assert_eq!(loopback_base(bad), None, "{bad}");
        }
        assert_eq!(loopback_base("http://localhost:8787/").as_deref(), Some("http://localhost:8787"));
    }
}
