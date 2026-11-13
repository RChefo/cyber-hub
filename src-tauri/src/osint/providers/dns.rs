// SPDX-License-Identifier: Apache-2.0
//! DNS records (system resolver) and IP-to-ASN mapping (Team Cymru, also over DNS).

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use serde_json::json;

use super::{ent, Builder, Error, Output};
use crate::osint::ingest::EvidenceInput;
use crate::osint::model::{EntityType, Strength};
use crate::osint::normalize;

async fn resolver() -> Result<hickory_resolver::TokioResolver, Error> {
    Resolver::builder_tokio().map_err(|e| Error::Unavailable(format!("Resolver configuration error: {e}")))?.build().map_err(|e| Error::Unavailable(format!("Resolver configuration error: {e}")))
}

async fn lookup(r: &hickory_resolver::TokioResolver, name: &str, t: RecordType) -> Result<Vec<String>, Error> {
    match tokio::time::timeout(Duration::from_secs(8), r.lookup(name, t)).await {
        Err(_) => Err(Error::Network(format!("DNS {t} query for {name} timed out"))),
        Ok(Ok(l)) => Ok(l.answers().iter().filter(|a| a.record_type() == t).map(|a| a.data.to_string()).collect()),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => Ok(vec![]),
        Ok(Err(e)) => Err(Error::Network(format!("DNS {t} query for {name} failed: {e}"))),
    }
}

/// Answers per record type, as text (MX keeps its preference: "10 mail.example.com.").
pub type Answers = Vec<(String, Vec<String>)>;

pub async fn query_domain(domain: &str) -> Result<Answers, Error> {
    let r = resolver().await?;
    let mut out = vec![];
    for t in [RecordType::A, RecordType::AAAA, RecordType::CNAME, RecordType::NS, RecordType::MX] {
        out.push((t.to_string(), lookup(&r, domain, t).await?));
    }
    Ok(out)
}

pub async fn query_ptr(ip: &IpAddr) -> Result<Answers, Error> {
    let r = resolver().await?;
    Ok(vec![("PTR".into(), lookup(&r, &reverse_name(ip, "in-addr.arpa.", "ip6.arpa."), RecordType::PTR).await?)])
}

pub fn reverse_name(ip: &IpAddr, v4_zone: &str, v6_zone: &str) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{v4_zone}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            let mut parts: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            parts.push(v6_zone.trim_end_matches('.').to_string());
            format!("{}.", parts.join("."))
        }
    }
}

fn host_of(rdata: &str) -> String {
    rdata.split_whitespace().last().unwrap_or("").trim_end_matches('.').to_string()
}

/// Map DNS answers for `name` (a domain, or an address for PTR) to an observation.
pub fn domain_observation(name: &str, input: EntityType, answers: &Answers) -> Output {
    let mut b = Builder::default();
    let me = b.add(ent(input, name));
    let mut lines = vec![];
    let mut count = 0;
    for (t, values) in answers {
        if values.is_empty() {
            continue;
        }
        lines.push(format!("{t}: {}", values.join(", ")));
        for v in values {
            count += 1;
            match t.as_str() {
                "A" | "AAAA" => {
                    if normalize::ip(v).is_ok() {
                        let i = b.add(ent(EntityType::Ip, v.clone()));
                        b.rel(me, i, "RESOLVES_TO", Strength::Direct);
                    }
                }
                "CNAME" => {
                    let i = b.add(ent(EntityType::Domain, host_of(v)));
                    b.rel(me, i, "ALIAS_OF", Strength::Direct);
                }
                "NS" => {
                    let i = b.add(ent(EntityType::Domain, host_of(v)));
                    b.rel(me, i, "USES_NAMESERVER", Strength::Direct);
                }
                "MX" => {
                    let h = host_of(v);
                    if !h.is_empty() {
                        let i = b.add(ent(EntityType::Domain, h));
                        b.rel(me, i, "USES_MAIL_SERVER", Strength::Direct);
                    }
                }
                "PTR" => {
                    let i = b.add(ent(EntityType::Domain, host_of(v)));
                    b.rel(me, i, "REVERSE_DNS", Strength::Direct);
                }
                _ => {}
            }
        }
    }
    let summary = if lines.is_empty() { format!("No DNS records found for {name}.") } else { format!("DNS answers for {name}:\n{}", lines.join("\n")) };
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "dns".into(),
        reference: Some(format!(
            "DNS {} query for {name} (system resolver)",
            answers.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join("/")
        )),
        observed_at: None,
        summary: summary.clone(),
        data: json!({ "answers": answers }),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    });
    Output { observations: if count > 0 { vec![obs] } else { vec![] }, summary: format!("{count} DNS record{} for {name}", if count == 1 { "" } else { "s" }), rate_note: None, from_cache: false }
}

/* ─────────────── Team Cymru IP to ASN ─────────────── */

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Origin {
    pub asn: u32,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
    pub as_name: Option<String>,
}

/// "13335 | 104.16.0.0/13 | US | arin | 2014-03-28" (several ASNs may be space-separated)
pub fn parse_origin(txt: &str) -> Option<Origin> {
    let f: Vec<String> = txt.trim_matches('"').split('|').map(|s| s.trim().to_string()).collect();
    if f.len() < 5 {
        return None;
    }
    let asn = f[0].split_whitespace().next()?.parse().ok()?;
    Some(Origin { asn, prefix: f[1].clone(), country: f[2].clone(), registry: f[3].clone(), allocated: f[4].clone(), as_name: None })
}

/// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
pub fn parse_as_name(txt: &str) -> Option<String> {
    let f: Vec<&str> = txt.trim_matches('"').split('|').map(str::trim).collect();
    f.get(4).filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Organization part of an AS name: "CLOUDFLARENET - Cloudflare, Inc., US" → "Cloudflare, Inc."
pub fn as_org(as_name: &str) -> Option<String> {
    let (_, rest) = as_name.split_once(" - ")?;
    let rest = rest.trim();
    let org = match rest.rsplit_once(", ") {
        Some((head, cc)) if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_uppercase()) => head,
        _ => rest,
    };
    (!org.is_empty()).then(|| org.to_string())
}

pub async fn query_asn(ip: &IpAddr) -> Result<Option<Origin>, Error> {
    let r = resolver().await?;
    let name = reverse_name(ip, "origin.asn.cymru.com.", "origin6.asn.cymru.com.");
    let Some(txt) = lookup(&r, &name, RecordType::TXT).await?.into_iter().next() else { return Ok(None) };
    let Some(mut o) = parse_origin(&txt) else { return Err(Error::Invalid("Unexpected answer from the IP-to-ASN service".into())) };
    if let Some(t) = lookup(&r, &format!("AS{}.asn.cymru.com.", o.asn), RecordType::TXT).await?.into_iter().next() {
        o.as_name = parse_as_name(&t);
    }
    Ok(Some(o))
}

pub fn asn_observation(ip: &str, o: &Origin) -> Output {
    let mut b = Builder::default();
    let me = b.add(ent(EntityType::Ip, ip));
    let mut a = ent(EntityType::Asn, format!("AS{}", o.asn));
    if let Some(n) = &o.as_name {
        a.display_name = Some(format!("AS{} {}", o.asn, n.split(" - ").next().unwrap_or(n)));
        a.metadata.insert("asName".into(), json!(n));
    }
    a.metadata.insert("registry".into(), json!(o.registry));
    let asn = b.add(a);
    b.rel(me, asn, "ROUTES_THROUGH", Strength::Direct);
    if normalize::normalize(EntityType::Netblock, &o.prefix).is_ok() {
        let mut p = ent(EntityType::Netblock, o.prefix.clone());
        p.metadata.insert("allocated".into(), json!(o.allocated));
        p.metadata.insert("country".into(), json!(o.country));
        let net = b.add(p);
        b.rel(me, net, "PART_OF", Strength::Direct);
        b.rel(asn, net, "ANNOUNCES_PREFIX", Strength::Direct);
    }
    if let Some(org) = o.as_name.as_deref().and_then(as_org) {
        let org = b.add(ent(EntityType::Organization, org));
        b.rel(asn, org, "OPERATED_BY", Strength::Corroborating);
    }
    if !o.country.is_empty() {
        let loc = b.add(ent(EntityType::Location, o.country.clone()));
        b.rel(me, loc, "LOCATED_IN", Strength::Corroborating);
    }
    let summary = format!(
        "Team Cymru IP-to-ASN: {ip} is announced by AS{} ({}) in prefix {}, registry {}, country {}.",
        o.asn,
        o.as_name.as_deref().unwrap_or("name unknown"),
        o.prefix,
        o.registry,
        o.country
    );
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "asn".into(),
        reference: Some("https://www.team-cymru.com/ip-asn-mapping".into()),
        observed_at: None,
        summary: summary.clone(),
        data: serde_json::to_value(o).unwrap_or_default(),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    });
    Output { observations: vec![obs], summary: format!("AS{} for {ip}", o.asn), rate_note: None, from_cache: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cymru_answers() {
        let o = parse_origin("\"13335 | 104.16.0.0/13 | US | arin | 2014-03-28\"").unwrap();
        assert_eq!((o.asn, o.prefix.as_str(), o.country.as_str()), (13335, "104.16.0.0/13", "US"));
        assert_eq!(parse_origin("23028 3356 | 216.90.108.0/24 | US | arin | 1998-09-25").unwrap().asn, 23028);
        assert!(parse_origin("garbage").is_none());
        let n = parse_as_name("13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US").unwrap();
        assert_eq!(as_org(&n).as_deref(), Some("Cloudflare, Inc."));
        assert_eq!(as_org("NOHYPHEN"), None);
        assert_eq!(reverse_name(&"192.0.2.1".parse().unwrap(), "origin.asn.cymru.com.", "x."), "1.2.0.192.origin.asn.cymru.com.");
        assert!(reverse_name(&"2001:db8::1".parse().unwrap(), "x.", "origin6.asn.cymru.com.").ends_with(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com."));
    }

    #[test]
    fn maps_dns_answers_and_asn_to_entities() {
        let answers: Answers = vec![
            ("A".into(), vec!["93.184.216.34".into()]),
            ("AAAA".into(), vec![]),
            ("CNAME".into(), vec![]),
            ("NS".into(), vec!["a.iana-servers.net.".into(), "b.iana-servers.net.".into()]),
            ("MX".into(), vec!["10 mail.example.com.".into()]),
        ];
        let out = domain_observation("example.com", EntityType::Domain, &answers);
        let o = &out.observations[0];
        assert_eq!(o.entities.len(), 5);
        let types: Vec<&str> = o.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(types, vec!["RESOLVES_TO", "USES_NAMESERVER", "USES_NAMESERVER", "USES_MAIL_SERVER"]);
        assert!(o.evidence.summary.contains("NS: a.iana-servers.net."));
        assert!(domain_observation("none.example", EntityType::Domain, &vec![("A".into(), vec![])]).observations.is_empty());
        let a = asn_observation("104.16.1.1", &Origin { asn: 13335, prefix: "104.16.0.0/13".into(), country: "US".into(), registry: "arin".into(), allocated: "2014-03-28".into(), as_name: Some("CLOUDFLARENET - Cloudflare, Inc., US".into()) });
        let rels: Vec<&str> = a.observations[0].relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["ROUTES_THROUGH", "PART_OF", "ANNOUNCES_PREFIX", "OPERATED_BY", "LOCATED_IN"]);
    }
}
