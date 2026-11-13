//! Discovery providers. Each provider takes one entity (type + value) and returns proposed
//! observations; nothing is written to the investigation until the analyst imports them (or
//! chose automatic import when starting the operation).
//!
//! Every provider here uses a real, documented public interface or an existing ExploitX
//! integration. Providers that need credentials use the owner-provisioned keys through the
//! existing threat-intelligence pipeline; keys never reach this module's results, the web view
//! or MCP clients.

pub mod crtsh;
pub mod dns;
pub mod github;
pub mod internal;
pub mod rdap;
pub mod ti;
pub mod web;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use super::ingest::{EntityInput, Observation};
use super::model::EntityType;
use crate::db::Db;
use crate::ti::limit::RateLimiter;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub inputs: &'static [EntityType],
    /// threat-intelligence providers reached through the existing integration (keys, quotas)
    pub uses_threat_intel: bool,
    /// contacts the target itself (requires a linked project whose scope covers the target)
    pub contacts_target: bool,
    pub rate: (usize, u64),
    pub cache_hours: i64,
    pub source_url: &'static str,
    pub terms: &'static str,
}

pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "dns",
        name: "DNS records",
        category: "Domain & infrastructure",
        description: "A, AAAA, CNAME, NS and MX records for a domain, or the PTR record of an address, through the system resolver.",
        inputs: &[EntityType::Domain, EntityType::Ip],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (30, 60),
        cache_hours: 1,
        source_url: "https://www.rfc-editor.org/rfc/rfc1035",
        terms: "Standard DNS queries through the resolver configured on this computer.",
    },
    ProviderInfo {
        id: "asn",
        name: "IP to ASN (Team Cymru)",
        category: "Domain & infrastructure",
        description: "Origin AS, announced prefix and AS name for an address, from Team Cymru's IP-to-ASN mapping service over DNS.",
        inputs: &[EntityType::Ip],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (20, 60),
        cache_hours: 24,
        source_url: "https://www.team-cymru.com/ip-asn-mapping",
        terms: "Free public service; Team Cymru asks for reasonable query volumes.",
    },
    ProviderInfo {
        id: "rdap",
        name: "RDAP registration data",
        category: "Domain & infrastructure",
        description: "Registrar, registration dates, status and name servers of a domain, or the network and holder of an address or AS, from the authoritative registry (IANA bootstrap).",
        inputs: &[EntityType::Domain, EntityType::Ip, EntityType::Asn],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (10, 60),
        cache_hours: 24,
        source_url: "https://data.iana.org/rdap/",
        terms: "Public registration data; registries rate-limit and redact personal data.",
    },
    ProviderInfo {
        id: "crtsh",
        name: "Certificate Transparency (crt.sh)",
        category: "Domain & infrastructure",
        description: "Certificates logged for the domain and its subdomains, and the names they cover.",
        inputs: &[EntityType::Domain],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (6, 60),
        cache_hours: 24,
        source_url: "https://crt.sh/",
        terms: "Free public service by Sectigo; slow for large domains, please query sparingly.",
    },
    ProviderInfo {
        id: "github",
        name: "GitHub public search",
        category: "Code & repositories",
        description: "Public repositories whose name, description or README mention the value, or a GitHub user's public profile and repositories.",
        inputs: &[EntityType::Domain, EntityType::Organization, EntityType::Email, EntityType::Username],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (8, 60),
        cache_hours: 6,
        source_url: "https://docs.github.com/en/rest/search/search",
        terms: "GitHub REST API without authentication: 10 searches per minute and 60 requests per hour per address. Code search needs a token and is not used.",
    },
    ProviderInfo {
        id: "http",
        name: "Web server fingerprint",
        category: "Search & web",
        description: "One request to the site: status, redirect target and the technologies announced in Server, X-Powered-By and similar headers. The body is not read and redirects are not followed.",
        inputs: &[EntityType::Domain, EntityType::Url],
        uses_threat_intel: false,
        contacts_target: true,
        rate: (20, 60),
        cache_hours: 0,
        source_url: "https://www.rfc-editor.org/rfc/rfc9110",
        terms: "Contacts the target directly: only for targets inside the linked project's authorized scope.",
    },
    ProviderInfo {
        id: "threat_intel",
        name: "Threat intelligence providers",
        category: "Threat intelligence",
        description: "VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan through ExploitX's existing integration (owner-provisioned keys, caching, rate limits).",
        inputs: &[EntityType::Domain, EntityType::Ip, EntityType::Url, EntityType::FileHash],
        uses_threat_intel: true,
        contacts_target: false,
        rate: (30, 60),
        cache_hours: 0,
        source_url: "",
        terms: "Each provider's terms apply; see Settings → Threat intelligence providers for availability.",
    },
    ProviderInfo {
        id: "nvd",
        name: "NVD vulnerability record",
        category: "Vulnerability intelligence",
        description: "CVSS, description, weaknesses and references of a CVE from the local cache or the NVD API.",
        inputs: &[EntityType::Vulnerability],
        uses_threat_intel: false,
        contacts_target: false,
        rate: (5, 30),
        cache_hours: 0,
        source_url: "https://nvd.nist.gov/developers/vulnerabilities",
        terms: "NVD public API; the optional NVD key raises the rate limit.",
    },
];

pub fn info(id: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS.iter().find(|p| p.id == id)
}

/// What a provider run produced.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub observations: Vec<Observation>,
    pub summary: String,
    /// rate-limit or quota information reported by the source, if any
    pub rate_note: Option<String>,
    pub from_cache: bool,
}

#[derive(Debug, Clone)]
pub enum Error {
    Unsupported(String),
    Refused(String),
    RateLimited(u64),
    Unavailable(String),
    Network(String),
    Invalid(String),
}

impl Error {
    pub fn message(&self) -> String {
        match self {
            Error::Unsupported(m) | Error::Refused(m) | Error::Unavailable(m) | Error::Network(m) | Error::Invalid(m) => m.clone(),
            Error::RateLimited(s) => format!("Rate limit reached for this source; try again in {s} s."),
        }
    }
}

/// Per-provider request limiters (in-process, like the threat-intelligence limiters).
pub struct Limits(Mutex<HashMap<&'static str, RateLimiter>>);

impl Default for Limits {
    fn default() -> Self {
        Limits(Mutex::new(PROVIDERS.iter().map(|p| (p.id, RateLimiter::new(p.rate.0, Duration::from_secs(p.rate.1)))).collect()))
    }
}

impl Limits {
    pub fn acquire(&self, id: &str) -> Result<(), Error> {
        let map = self.0.lock().map_err(|_| Error::Unavailable("rate limiter unavailable".into()))?;
        match map.get(id) {
            Some(l) => l.try_acquire(Instant::now()).map_err(Error::RateLimited),
            None => Ok(()),
        }
    }
}

/// Cached provider response (raw JSON as fetched), keyed by provider and query.
pub fn cache_get(db: &Db, provider: &str, key: &str, hours: i64) -> Option<Value> {
    if hours <= 0 {
        return None;
    }
    db.with(|c| {
        let row: Option<(String, String)> = c.query_row("SELECT fetched_at, data FROM osint_source_cache WHERE provider = ?1 AND query_key = ?2", params![provider, key], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        Ok(row)
    })
    .ok()
    .flatten()
    .and_then(|(at, data)| {
        let fresh = chrono::DateTime::parse_from_rfc3339(&at).map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() < hours).unwrap_or(false);
        fresh.then(|| serde_json::from_str(&data).ok()).flatten()
    })
}

pub fn cache_put(db: &Db, provider: &str, key: &str, data: &Value) {
    let text = data.to_string();
    if text.len() > 4 * 1024 * 1024 {
        return;
    }
    let _ = db.with(|c| {
        c.execute(
            "INSERT INTO osint_source_cache (provider, query_key, fetched_at, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(provider, query_key) DO UPDATE SET fetched_at = excluded.fetched_at, data = excluded.data",
            params![provider, key, crate::util::now(), text],
        )?;
        Ok(())
    });
}

/// Entity input helper.
pub fn ent(t: EntityType, v: impl Into<String>) -> EntityInput {
    EntityInput { entity_type: t, value: v.into(), display_name: None, metadata: serde_json::Map::new(), flagged: false }
}

/// Collects entities for an observation, reusing indexes for repeated values.
#[derive(Default)]
pub struct Builder {
    pub entities: Vec<EntityInput>,
    index: HashMap<(EntityType, String), usize>,
    pub relationships: Vec<super::ingest::RelationshipInput>,
}

impl Builder {
    pub fn add(&mut self, e: EntityInput) -> usize {
        let key = (e.entity_type, e.value.trim().to_lowercase());
        if let Some(i) = self.index.get(&key) {
            let existing = &mut self.entities[*i];
            existing.flagged |= e.flagged;
            for (k, v) in e.metadata {
                existing.metadata.entry(k).or_insert(v);
            }
            if existing.display_name.is_none() {
                existing.display_name = e.display_name;
            }
            return *i;
        }
        self.entities.push(e);
        self.index.insert(key, self.entities.len() - 1);
        self.entities.len() - 1
    }
    pub fn rel(&mut self, s: usize, t: usize, ty: &str, strength: super::model::Strength) {
        if s != t && !self.relationships.iter().any(|r| r.source == s && r.target == t && r.rel_type == ty) {
            self.relationships.push(super::ingest::RelationshipInput { source: s, target: t, rel_type: ty.into(), strength, origin: super::ingest::Origin::Observed, metadata: serde_json::Map::new() });
        }
    }
    pub fn finish(self, evidence: super::ingest::EvidenceInput) -> Observation {
        Observation { evidence, entities: self.entities, relationships: self.relationships }
    }
}

/// HTTPS client for public provider APIs (no redirects, bounded time).
/// HTTP client for public sources: no redirects, a timeout, size-capped bodies (in `get_json`),
/// and a resolver that only returns public addresses. Even a registry or API host taken from a
/// fixed list or the IANA bootstrap can therefore never be pointed at an internal service through
/// DNS (rebinding or a hostile record).
pub fn client(timeout_secs: u64) -> Result<reqwest::Client, Error> {
    crate::tls_trust::build(
        reqwest::Client::builder()
            // no system proxy: a proxy resolves names itself, past the public-only resolver (Mission 7)
            .no_proxy()
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(std::sync::Arc::new(PublicOnlyResolver)),
    )
    .map_err(Error::Unavailable)
}

/// Keep only public addresses; fail when none remain.
pub fn public_addresses(addrs: impl IntoIterator<Item = std::net::IpAddr>) -> Result<Vec<std::net::IpAddr>, String> {
    let all: Vec<std::net::IpAddr> = addrs.into_iter().collect();
    if all.is_empty() {
        return Err("the host name does not resolve".into());
    }
    let public: Vec<std::net::IpAddr> = all.iter().copied().filter(|a| !crate::ti::indicator::is_non_public(a)).collect();
    if public.is_empty() {
        return Err(format!("the host resolves only to non-public addresses ({}); it is not contacted", all[0]));
    }
    Ok(public)
}

struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let err = |m: String| -> Box<dyn std::error::Error + Send + Sync> { Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, m)) };
            let r = hickory_resolver::Resolver::builder_tokio().map_err(|e| err(e.to_string()))?.build().map_err(|e| err(e.to_string()))?;
            let l = tokio::time::timeout(Duration::from_secs(8), r.lookup_ip(host.as_str())).await.map_err(|_| err("DNS resolution timed out".into()))?.map_err(|e| err(format!("DNS resolution failed: {e}")))?;
            let public = public_addresses(l.iter()).map_err(err)?;
            let addrs: reqwest::dns::Addrs = Box::new(public.into_iter().map(|ip| std::net::SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// GET a JSON document with a size cap; maps transport and status errors.
pub async fn get_json(client: &reqwest::Client, url: &str, accept: &str) -> Result<(u16, Value, Option<String>), Error> {
    let rb = client.get(url).header("Accept", accept);
    let resp = crate::ti::http::send(rb, "").await.map_err(|e| match e {
        crate::ti::http::ApiError::Network(m) => Error::Network(format!("Network error: {m}")),
        other => Error::Invalid(other.message("source")),
    })?;
    let rate = ["x-ratelimit-remaining", "ratelimit-remaining", "retry-after"].iter().find_map(|h| resp.header(h).map(|v| format!("{h}: {v}")));
    Ok((resp.status, resp.body, rate))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mission 7: the public-source client never uses a system proxy, which would resolve names
    /// itself and bypass the public-only resolver.
    #[test]
    fn the_public_source_client_uses_no_proxy() {
        let src = include_str!("mod.rs");
        let start = src.find("pub fn client(").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        assert!(body.contains(".no_proxy()") && body.contains(".dns_resolver("));
    }

    #[test]
    fn only_public_addresses_are_connected_to() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(public_addresses([ip("93.184.216.34"), ip("10.0.0.1")]).unwrap(), vec![ip("93.184.216.34")]);
        for bad in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "::1", "fc00::1", "::ffff:127.0.0.1", "100.64.0.1", "0.0.0.0"] {
            assert!(public_addresses([ip(bad)]).is_err(), "{bad} must be refused");
        }
        assert!(public_addresses(Vec::new()).is_err());
    }

    #[test]
    fn registry_is_consistent_and_builder_dedupes() {
        let mut ids: Vec<_> = PROVIDERS.iter().map(|p| p.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), PROVIDERS.len());
        assert!(PROVIDERS.iter().filter(|p| p.contacts_target).all(|p| p.id == "http"), "only the web fingerprint touches the target");
        let l = Limits::default();
        for _ in 0..6 {
            l.acquire("crtsh").unwrap();
        }
        assert!(matches!(l.acquire("crtsh"), Err(Error::RateLimited(_))));
        let mut b = Builder::default();
        let a = b.add(ent(EntityType::Domain, "Example.com"));
        let a2 = b.add(ent(EntityType::Domain, "example.com"));
        let i = b.add(ent(EntityType::Ip, "192.0.2.1"));
        b.rel(a, i, "RESOLVES_TO", super::super::model::Strength::Direct);
        b.rel(a2, i, "RESOLVES_TO", super::super::model::Strength::Direct);
        assert_eq!((a, b.entities.len(), b.relationships.len()), (a2, 2, 1));
    }
}
