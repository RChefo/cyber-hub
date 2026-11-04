//! Web server fingerprint: one HEAD (or GET) request to the site. SSRF protections: http(s)
//! only, every resolved address must be public, the connection is pinned to the checked
//! addresses (no DNS rebinding between check and connect), redirects are recorded but never
//! followed, the body is never read, and the request is bounded in time. The caller must have
//! checked that the target is inside the investigation's authorized scope.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde_json::{json, Map};

use super::{ent, Builder, Error, Output};
use crate::osint::ingest::EvidenceInput;
use crate::osint::model::{EntityType, Strength};
use crate::ti::indicator::{is_internal_domain, is_non_public};

/// Headers that announce technologies, in the order they are reported.
const TECH_HEADERS: &[&str] = &["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-varnish", "via"];
const REPORTED_HEADERS: &[&str] = &["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "location", "content-type", "strict-transport-security", "x-frame-options", "content-security-policy"];

/// The URL to fingerprint for an entity.
pub fn target_url(t: EntityType, value: &str) -> Result<url::Url, Error> {
    let raw = match t {
        EntityType::Domain => format!("https://{value}/"),
        EntityType::Url => value.to_string(),
        _ => return Err(Error::Unsupported("The web fingerprint works on domains and URLs".into())),
    };
    let u = url::Url::parse(&raw).map_err(|_| Error::Invalid("Invalid URL".into()))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(Error::Refused("Only http and https URLs can be fingerprinted".into()));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Error::Refused("URLs with credentials are not requested".into()));
    }
    match u.host() {
        Some(url::Host::Domain(d)) if is_internal_domain(d) => Err(Error::Refused("Internal host names are not contacted".into())),
        Some(url::Host::Ipv4(a)) if is_non_public(&IpAddr::V4(a)) => Err(Error::Refused("Private, loopback and reserved addresses are not contacted".into())),
        Some(url::Host::Ipv6(a)) if is_non_public(&IpAddr::V6(a)) => Err(Error::Refused("Private, loopback and reserved addresses are not contacted".into())),
        Some(_) => Ok(u),
        None => Err(Error::Invalid("URL without host".into())),
    }
}

/// Resolve and require every address to be public.
pub fn check_addresses(addrs: &[IpAddr]) -> Result<(), Error> {
    if addrs.is_empty() {
        return Err(Error::Network("The host name does not resolve".into()));
    }
    if let Some(bad) = addrs.iter().find(|a| is_non_public(a)) {
        return Err(Error::Refused(format!("The host resolves to a non-public address ({bad}); it is not contacted")));
    }
    Ok(())
}

async fn resolve(host: &str) -> Result<Vec<IpAddr>, Error> {
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let r = hickory_resolver::Resolver::builder_tokio().map_err(|e| Error::Unavailable(e.to_string()))?.build().map_err(|e| Error::Unavailable(e.to_string()))?;
    let l = tokio::time::timeout(Duration::from_secs(8), r.lookup_ip(host)).await.map_err(|_| Error::Network("DNS resolution timed out".into()))?.map_err(|e| Error::Network(format!("DNS resolution failed: {e}")))?;
    Ok(l.iter().collect())
}

/// Parse "nginx/1.18.0 (Ubuntu)" → ["nginx/1.18.0"]; "Apache" → ["Apache"].
pub fn technologies(header: &str, value: &str) -> Vec<String> {
    let v = value.trim();
    if v.is_empty() || v.len() > 200 {
        return vec![];
    }
    match header {
        "via" => v.split(',').filter_map(|p| p.split_whitespace().nth(1)).map(|s| s.trim_matches(|c| c == '(' || c == ')').to_string()).filter(|s| s.chars().any(char::is_alphabetic) && !s.contains('.')).take(3).collect(),
        "x-varnish" | "x-drupal-cache" => vec![if header == "x-varnish" { "Varnish".into() } else { "Drupal".into() }],
        "x-aspnet-version" => vec![format!("ASP.NET/{v}")],
        "x-aspnetmvc-version" => vec![format!("ASP.NET MVC/{v}")],
        _ => v.split(|c: char| c == ',' || c.is_whitespace()).map(|t| t.trim_matches(|c| c == '(' || c == ')' || c == ';')).filter(|t| !t.is_empty() && t.chars().next().is_some_and(char::is_alphabetic)).take(4).map(String::from).collect(),
    }
}

pub fn observation(t: EntityType, value: &str, url: &url::Url, status: u16, headers: &[(String, String)]) -> Output {
    let mut b = Builder::default();
    let me = b.add(ent(t, value));
    let mut meta = Map::new();
    meta.insert("httpStatus".into(), json!(status));
    let mut lines = vec![format!("{} {} → HTTP {status}", if t == EntityType::Url { "GET/HEAD" } else { "HEAD" }, url)];
    for (h, v) in headers {
        lines.push(format!("{h}: {v}"));
        if TECH_HEADERS.contains(&h.as_str()) {
            for tech in technologies(h, v) {
                let mut te = ent(EntityType::Technology, tech);
                te.metadata.insert("announcedBy".into(), json!(h));
                let ti = b.add(te);
                b.rel(me, ti, "USES_TECHNOLOGY", Strength::Direct);
            }
        }
        if h == "location" && (300..400).contains(&status) {
            if let Ok(target) = url.join(v) {
                if matches!(target.scheme(), "http" | "https") {
                    let r = b.add(ent(EntityType::Url, target.to_string()));
                    b.rel(me, r, "REDIRECTS_TO", Strength::Direct);
                }
            }
        }
    }
    b.entities[me].metadata.extend(meta);
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "http".into(),
        reference: Some(url.to_string()),
        observed_at: None,
        summary: lines.join("\n"),
        data: json!({ "status": status, "headers": headers }),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    });
    let n = obs.relationships.len();
    Output { observations: vec![obs], summary: format!("HTTP {status} from {url}; {n} announced technolog{} or redirect{}", if n == 1 { "y" } else { "ies" }, if n == 1 { "" } else { "s" }), rate_note: None, from_cache: false }
}

pub async fn run(t: EntityType, value: &str) -> Result<Output, Error> {
    let url = target_url(t, value)?;
    let host = url.host_str().ok_or_else(|| Error::Invalid("URL without host".into()))?.to_string();
    let addrs = resolve(&host).await?;
    check_addresses(&addrs)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let pinned: Vec<SocketAddr> = addrs.iter().map(|a| SocketAddr::new(*a, port)).collect();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION"), " (OSINT fingerprint)"))
        .resolve_to_addrs(&host, &pinned)
        .build()
        .map_err(|e| Error::Unavailable(e.to_string()))?;
    let mut resp = client.head(url.clone()).send().await.map_err(|e| Error::Network(format!("Request failed: {}", e.without_url())))?;
    if matches!(resp.status().as_u16(), 405 | 501) {
        resp = client.get(url.clone()).send().await.map_err(|e| Error::Network(format!("Request failed: {}", e.without_url())))?;
    }
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = REPORTED_HEADERS
        .iter()
        .filter_map(|h| resp.headers().get(*h).and_then(|v| v.to_str().ok()).map(|v| (h.to_string(), v.chars().take(300).collect::<String>())))
        .collect();
    drop(resp); // the body is never read
    Ok(observation(t, value, &url, status, &headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_internal_and_non_http_targets() {
        assert!(target_url(EntityType::Domain, "example.com").is_ok());
        for (t, v) in [
            (EntityType::Url, "http://127.0.0.1/admin"),
            (EntityType::Url, "http://[::1]/"),
            (EntityType::Url, "http://169.254.169.254/latest/meta-data/"),
            (EntityType::Url, "http://10.0.0.5/"),
            (EntityType::Url, "ftp://example.com/"),
            (EntityType::Url, "https://user:pw@example.com/"),
            (EntityType::Domain, "printer.local"),
            (EntityType::Ip, "93.184.216.34"),
        ] {
            assert!(target_url(t, v).is_err(), "{v}");
        }
        assert!(check_addresses(&["93.184.216.34".parse().unwrap()]).is_ok());
        assert!(check_addresses(&["93.184.216.34".parse().unwrap(), "192.168.1.1".parse().unwrap()]).is_err(), "one private answer is enough to refuse (rebinding)");
        assert!(check_addresses(&[]).is_err());
    }

    #[test]
    fn maps_headers_to_technologies_and_redirects() {
        assert_eq!(technologies("server", "nginx/1.18.0 (Ubuntu)"), vec!["nginx/1.18.0", "Ubuntu"]);
        assert_eq!(technologies("x-powered-by", "PHP/8.1.2"), vec!["PHP/8.1.2"]);
        assert_eq!(technologies("x-aspnet-version", "4.0.30319"), vec!["ASP.NET/4.0.30319"]);
        let url = url::Url::parse("http://example.com/").unwrap();
        let out = observation(EntityType::Domain, "example.com", &url, 301, &[("server".into(), "cloudflare".into()), ("location".into(), "/login?x=<script>".into())]);
        let o = &out.observations[0];
        let rels: Vec<&str> = o.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["USES_TECHNOLOGY", "REDIRECTS_TO"]);
        assert!(o.entities.iter().any(|e| e.value == "http://example.com/login?x=%3Cscript%3E"));
        assert_eq!(o.entities[0].metadata["httpStatus"], 301);
    }
}
