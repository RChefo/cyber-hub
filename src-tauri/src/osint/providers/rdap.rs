//! RDAP (RFC 9082/9083) through the IANA bootstrap registries (RFC 9224). The authoritative
//! registry server is chosen from the bootstrap file and queried directly; redirects are not
//! followed and only HTTPS servers with public host names are used.

use std::net::IpAddr;

use serde_json::{json, Value};

use super::{ent, get_json, Builder, Error, Output};
use crate::db::Db;
use crate::osint::ingest::EvidenceInput;
use crate::osint::model::{EntityType, Strength};
use crate::osint::normalize;

const BOOTSTRAP: &str = "https://data.iana.org/rdap/";

pub fn bootstrap_file(t: EntityType, value: &str) -> Option<&'static str> {
    match t {
        EntityType::Domain => Some("dns.json"),
        EntityType::Ip => Some(if value.contains(':') { "ipv6.json" } else { "ipv4.json" }),
        EntityType::Asn => Some("asn.json"),
        _ => None,
    }
}

/// Only HTTPS registry servers with a public DNS name (no IP literals, no internal names).
pub fn acceptable_server(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(u) => {
            u.scheme() == "https"
                && u.username().is_empty()
                && u.password().is_none()
                && matches!(u.host(), Some(url::Host::Domain(d)) if !crate::ti::indicator::is_internal_domain(d))
        }
        Err(_) => false,
    }
}

/// Pick the registry base URL for a value from an IANA bootstrap document.
pub fn pick_server(bootstrap: &Value, t: EntityType, value: &str) -> Option<String> {
    let services = bootstrap.get("services")?.as_array()?;
    let urls_of = |svc: &Value| -> Option<String> { svc.get(1)?.as_array()?.iter().filter_map(Value::as_str).find(|u| acceptable_server(u)).map(String::from) };
    match t {
        EntityType::Domain => {
            // longest matching suffix ("co.uk" over "uk")
            let mut best: Option<(usize, String)> = None;
            for svc in services {
                for s in svc.get(0)?.as_array()?.iter().filter_map(Value::as_str) {
                    let s = s.to_ascii_lowercase();
                    if (value == s || value.ends_with(&format!(".{s}"))) && best.as_ref().map_or(true, |(n, _)| s.len() > *n) {
                        if let Some(u) = urls_of(svc) {
                            best = Some((s.len(), u));
                        }
                    }
                }
            }
            best.map(|(_, u)| u)
        }
        EntityType::Ip => {
            let ip: IpAddr = value.parse().ok()?;
            let mut best: Option<(u8, String)> = None;
            for svc in services {
                for s in svc.get(0)?.as_array()?.iter().filter_map(Value::as_str) {
                    if let Ok(net) = s.parse::<ipnet::IpNet>() {
                        if net.contains(&ip) && best.as_ref().map_or(true, |(p, _)| net.prefix_len() > *p) {
                            if let Some(u) = urls_of(svc) {
                                best = Some((net.prefix_len(), u));
                            }
                        }
                    }
                }
            }
            best.map(|(_, u)| u)
        }
        EntityType::Asn => {
            let n: u32 = normalize::asn(value).ok()?;
            for svc in services {
                for s in svc.get(0)?.as_array()?.iter().filter_map(Value::as_str) {
                    let (a, b) = s.split_once('-').unwrap_or((s, s));
                    if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                        if a <= n && n <= b {
                            return urls_of(svc);
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub fn query_url(base: &str, t: EntityType, value: &str) -> String {
    let base = base.trim_end_matches('/');
    match t {
        EntityType::Domain => format!("{base}/domain/{value}"),
        EntityType::Ip => format!("{base}/ip/{value}"),
        _ => format!("{base}/autnum/{}", value.trim_start_matches("AS")),
    }
}

/// `fn` (formatted name) or `org` from a jCard.
fn vcard_name(entity: &Value) -> Option<String> {
    let items = entity.get("vcardArray")?.get(1)?.as_array()?;
    let field = |name: &str| {
        items.iter().find(|i| i.get(0).and_then(Value::as_str) == Some(name)).and_then(|i| i.get(3)).and_then(|v| v.as_str().map(String::from).or_else(|| v.as_array()?.first()?.as_str().map(String::from)))
    };
    field("org").or_else(|| field("fn")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !is_redacted(s))
}

fn is_redacted(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["redacted", "privacy", "not disclosed", "withheld", "data protected", "domains by proxy", "whoisguard", "contact privacy"].iter().any(|w| l.contains(w))
}

fn roles(entity: &Value) -> Vec<String> {
    entity.get("roles").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

fn all_entities(v: &Value, out: &mut Vec<Value>, depth: usize) {
    if depth > 3 {
        return;
    }
    for e in v.get("entities").and_then(Value::as_array).into_iter().flatten() {
        out.push(e.clone());
        all_entities(e, out, depth + 1);
    }
}

/// Map an RDAP response to an observation.
pub fn parse(t: EntityType, value: &str, url: &str, body: &Value) -> Output {
    let mut b = Builder::default();
    let mut me_e = ent(t, value);
    let mut facts = vec![];
    for ev in body.get("events").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(action), Some(date)) = (ev.get("eventAction").and_then(Value::as_str), ev.get("eventDate").and_then(Value::as_str)) {
            me_e.metadata.insert(format!("rdap.{}", action.replace(' ', "_")), json!(date));
            facts.push(format!("{action}: {date}"));
        }
    }
    if let Some(st) = body.get("status").and_then(Value::as_array) {
        let s: Vec<&str> = st.iter().filter_map(Value::as_str).collect();
        me_e.metadata.insert("rdap.status".into(), json!(s));
        facts.push(format!("status: {}", s.join(", ")));
    }
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        me_e.metadata.insert("rdap.name".into(), json!(name));
        facts.push(format!("name: {name}"));
    }
    let me = b.add(me_e);

    let mut entities = vec![];
    all_entities(body, &mut entities, 0);
    for e in &entities {
        let Some(name) = vcard_name(e) else { continue };
        let r = roles(e);
        let org = b.add(ent(EntityType::Organization, name.clone()));
        if r.iter().any(|x| x == "registrar") {
            b.rel(me, org, "REGISTERED_WITH", Strength::Direct);
            facts.push(format!("registrar: {name}"));
        } else if r.iter().any(|x| x == "registrant") {
            b.rel(me, org, if t == EntityType::Domain { "REGISTERED_TO" } else { "OPERATED_BY" }, Strength::Direct);
            facts.push(format!("registrant: {name}"));
        } else if t != EntityType::Domain && r.iter().any(|x| x == "administrative" || x == "technical" || x == "abuse") {
            // network contacts are often the operator's NOC: corroborating, not ownership
            b.rel(me, org, "ASSOCIATED_WITH", Strength::Corroborating);
        }
    }
    for ns in body.get("nameservers").and_then(Value::as_array).into_iter().flatten() {
        if let Some(n) = ns.get("ldhName").and_then(Value::as_str) {
            let i = b.add(ent(EntityType::Domain, n.trim_end_matches('.').to_ascii_lowercase()));
            b.rel(me, i, "USES_NAMESERVER", Strength::Direct);
        }
    }
    // networks: CIDRs (RFC 9083 cidr0 extension) and country
    for c in body.get("cidr0_cidrs").and_then(Value::as_array).into_iter().flatten() {
        let prefix = c.get("v4prefix").or_else(|| c.get("v6prefix")).and_then(Value::as_str);
        if let (Some(p), Some(len)) = (prefix, c.get("length").and_then(Value::as_u64)) {
            let cidr = format!("{p}/{len}");
            if normalize::normalize(EntityType::Netblock, &cidr).is_ok() {
                let n = b.add(ent(EntityType::Netblock, cidr));
                if t == EntityType::Ip {
                    b.rel(me, n, "PART_OF", Strength::Direct);
                }
            }
        }
    }
    if let Some(cc) = body.get("country").and_then(Value::as_str).filter(|c| !c.is_empty()) {
        let loc = b.add(ent(EntityType::Location, cc));
        b.rel(me, loc, "LOCATED_IN", Strength::Corroborating);
    }
    let summary = format!("RDAP record for {value} ({url}):\n{}", facts.join("\n"));
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "rdap".into(),
        reference: Some(url.to_string()),
        observed_at: None,
        summary,
        data: json!({ "handle": body.get("handle"), "port43": body.get("port43") }),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    });
    let n = obs.entities.len().saturating_sub(1);
    Output { observations: vec![obs], summary: format!("RDAP record for {value}: {n} related entit{}", if n == 1 { "y" } else { "ies" }), rate_note: None, from_cache: false }
}

pub async fn run(db: &Db, t: EntityType, value: &str, refresh: bool) -> Result<Output, Error> {
    let file = bootstrap_file(t, value).ok_or_else(|| Error::Unsupported("RDAP supports domains, IP addresses and AS numbers".into()))?;
    let client = super::client(20)?;
    let boot = match super::cache_get(db, "rdap-bootstrap", file, 24 * 7) {
        Some(v) => v,
        None => {
            let (status, body, _) = get_json(&client, &format!("{BOOTSTRAP}{file}"), "application/json").await?;
            if status != 200 || !body.is_object() {
                return Err(Error::Unavailable(format!("IANA RDAP bootstrap returned HTTP {status}")));
            }
            super::cache_put(db, "rdap-bootstrap", file, &body);
            body
        }
    };
    let server = pick_server(&boot, t, value).ok_or_else(|| Error::Unavailable(format!("No RDAP service is registered for {value}")))?;
    let url = query_url(&server, t, value);
    if !refresh {
        if let Some(cached) = super::cache_get(db, "rdap", &url, 24) {
            let mut out = parse(t, value, &url, &cached);
            out.from_cache = true;
            return Ok(out);
        }
    }
    let (status, body, rate) = get_json(&client, &url, "application/rdap+json, application/json").await?;
    match status {
        200 => {}
        404 => return Ok(Output { observations: vec![], summary: format!("The registry has no RDAP record for {value}"), rate_note: rate, from_cache: false }),
        429 => return Err(Error::RateLimited(60)),
        301 | 302 | 303 | 307 | 308 => return Err(Error::Unavailable("The registry redirected the query; redirects are not followed".into())),
        s => return Err(Error::Network(format!("The registry returned HTTP {s}"))),
    }
    super::cache_put(db, "rdap", &url, &body);
    let mut out = parse(t, value, &url, &body);
    out.rate_note = rate;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_picks_the_most_specific_safe_server() {
        let dns = json!({ "services": [
            [["uk"], ["https://rdap.nominet.uk/uk/"]],
            [["co.uk"], ["http://insecure.example/", "https://rdap.nominet.uk/co/"]],
            [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
            [["evil"], ["https://127.0.0.1/", "https://rdap.local/"]]
        ]});
        assert_eq!(pick_server(&dns, EntityType::Domain, "shop.example.co.uk").as_deref(), Some("https://rdap.nominet.uk/co/"));
        assert_eq!(pick_server(&dns, EntityType::Domain, "example.com").as_deref(), Some("https://rdap.verisign.com/com/v1/"));
        assert_eq!(pick_server(&dns, EntityType::Domain, "x.evil"), None, "IP literals and internal hosts are refused");
        let v4 = json!({ "services": [[["104.0.0.0/8"], ["https://rdap.arin.net/registry/"]], [["104.16.0.0/12"], ["https://rdap.more-specific.net/"]]] });
        assert_eq!(pick_server(&v4, EntityType::Ip, "104.16.1.1").as_deref(), Some("https://rdap.more-specific.net/"));
        let asn = json!({ "services": [[["1-1876", "1902-2042"], ["https://rdap.arin.net/registry/"]]] });
        assert_eq!(pick_server(&asn, EntityType::Asn, "AS1900"), None);
        assert!(pick_server(&asn, EntityType::Asn, "AS1000").is_some());
        assert_eq!(query_url("https://rdap.arin.net/registry/", EntityType::Asn, "AS13335"), "https://rdap.arin.net/registry/autnum/13335");
    }

    #[test]
    fn parses_domain_records_and_ignores_redacted_contacts() {
        let body = json!({
            "objectClassName": "domain", "ldhName": "EXAMPLE.COM", "status": ["client delete prohibited"],
            "events": [{ "eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z" }, { "eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z" }],
            "nameservers": [{ "ldhName": "A.IANA-SERVERS.NET" }],
            "entities": [
                { "roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]] },
                { "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]] }
            ]
        });
        let out = parse(EntityType::Domain, "example.com", "https://rdap.verisign.com/com/v1/domain/example.com", &body);
        let o = &out.observations[0];
        let rels: Vec<&str> = o.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["REGISTERED_WITH", "USES_NAMESERVER"]);
        assert_eq!(o.entities[0].metadata["rdap.registration"], "1995-08-14T04:00:00Z");
        assert!(o.evidence.summary.contains("registrar: RESERVED-Internet Assigned Numbers Authority"));
        assert_eq!(o.evidence.reference.as_deref(), Some("https://rdap.verisign.com/com/v1/domain/example.com"));
        let net = json!({ "name": "CLOUDFLARENET", "country": "US", "cidr0_cidrs": [{ "v4prefix": "104.16.0.0", "length": 13 }], "entities": [{ "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]] }] });
        let out = parse(EntityType::Ip, "104.16.1.1", "u", &net);
        let rels: Vec<&str> = out.observations[0].relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["OPERATED_BY", "PART_OF", "LOCATED_IN"]);
    }
}
