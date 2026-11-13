//! Threat intelligence (VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox, Shodan)
//! through ExploitX's existing integration, and NVD records for vulnerabilities. Keys, caching,
//! provider enablement and rate limits are those of the existing integration; this module only
//! maps its normalized reports to entities and relationships.

use serde_json::json;

use super::{ent, Builder, Error, Output};
use crate::commands::intel::CveRecord;
use crate::osint::ingest::{EvidenceInput, Observation};
use crate::osint::model::{EntityType, Strength};
use crate::osint::normalize;
use crate::ti::indicator::{self, Kind};
use crate::ti::model::{Level, ProviderResult, Status};

pub fn entity_type_of(k: Kind) -> EntityType {
    match k {
        Kind::Ip => EntityType::Ip,
        Kind::Domain => EntityType::Domain,
        Kind::Url => EntityType::Url,
        Kind::File => EntityType::FileHash,
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.split([',', ';']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).take(50).collect()
}

/// Map one provider's normalized result about `subject` to an observation (None when the
/// provider had nothing to say).
pub fn map_result(t: EntityType, subject: &str, r: &ProviderResult) -> Option<Observation> {
    if r.status != Status::Found {
        return None;
    }
    let report = r.report.as_ref()?;
    let mut b = Builder::default();
    let mut me_e = ent(t, subject);
    let level = report.verdict.as_ref().map(|v| v.level);
    me_e.flagged = matches!(level, Some(Level::Malicious | Level::Suspicious));
    if let Some(v) = &report.verdict {
        me_e.metadata.insert(format!("threat.{}", r.provider), json!({ "level": v.level, "label": v.label }));
    }
    let me = b.add(me_e);

    for rel in &report.related {
        let other_t = entity_type_of(rel.kind);
        let o = b.add(ent(other_t, rel.value.clone()));
        match (rel.relation.as_str(), t, other_t) {
            // URLhaus/ThreatFox: the URL's host
            ("host" | "hostname", EntityType::Url, _) => b.rel(me, o, "ON_HOST", Strength::Direct),
            // a URL delivering the file / payload served by the URL
            ("delivered from", EntityType::FileHash, EntityType::Url) => b.rel(o, me, "SERVES_FILE", Strength::Corroborating),
            ("payload served", EntityType::Url, EntityType::FileHash) => b.rel(me, o, "SERVES_FILE", Strength::Corroborating),
            ("hostname" | "host", EntityType::Ip, EntityType::Domain) => b.rel(o, me, "RESOLVES_TO", Strength::Corroborating),
            _ => b.rel(me, o, "ASSOCIATED_WITH", Strength::Corroborating),
        }
    }
    for f in &report.facts {
        match f.label.as_str() {
            "ASN" => {
                if let Ok(n) = normalize::asn(f.value.split_whitespace().next().unwrap_or("")) {
                    let a = b.add(ent(EntityType::Asn, format!("AS{n}")));
                    b.rel(me, a, "ROUTES_THROUGH", Strength::Corroborating);
                }
            }
            "ISP" | "Organization" if t == EntityType::Ip => {
                let h = b.add(ent(EntityType::HostingProvider, f.value.clone()));
                b.rel(me, h, "HOSTED_ON", Strength::Corroborating);
            }
            "Country" | "Origin country" | "Location" => {
                let l = b.add(ent(EntityType::Location, f.value.clone()));
                b.rel(me, l, "LOCATED_IN", Strength::Corroborating);
            }
            "Hostnames" if t == EntityType::Ip => {
                for h in split_list(&f.value) {
                    if normalize::domain(&h).is_ok() {
                        let d = b.add(ent(EntityType::Domain, h));
                        b.rel(d, me, "RESOLVES_TO", Strength::Corroborating);
                    }
                }
            }
            "Ports" if t == EntityType::Ip => {
                for p in split_list(&f.value) {
                    if let Ok(port) = p.trim_end_matches("/tcp").trim_end_matches("/udp").parse::<u16>() {
                        let proto = if p.ends_with("/udp") { "udp" } else { "tcp" };
                        let s = b.add(ent(EntityType::Service, format!("{subject}:{port}/{proto}")));
                        b.rel(me, s, "EXPOSES_SERVICE", Strength::Corroborating);
                    }
                }
            }
            _ => {}
        }
    }
    for fam in report.families.iter().take(20) {
        let th = b.add(ent(EntityType::Threat, fam.clone()));
        b.rel(me, th, "ASSOCIATED_WITH_THREAT", Strength::Corroborating);
    }
    // Shodan lists CVEs from banner versions: possible, not confirmed vulnerabilities
    for cat in report.categories.iter().filter(|c| c.to_ascii_uppercase().starts_with("CVE-")).take(30) {
        let v = b.add(ent(EntityType::Vulnerability, cat.clone()));
        b.rel(me, v, "AFFECTED_BY", Strength::Weak);
    }
    let verdict = report.verdict.as_ref().map(|v| format!("verdict: {}", v.label)).unwrap_or_else(|| "no verdict".into());
    let facts: Vec<String> = report.facts.iter().take(12).map(|f| format!("{}: {}", f.label, f.value)).collect();
    let summary = format!("{} report for {subject} — {verdict}{}{}", r.provider_name, if facts.is_empty() { "" } else { "\n" }, facts.join("\n"));
    Some(b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: r.provider.clone(),
        reference: report.permalink.clone(),
        observed_at: r.fetched_at.clone(),
        summary,
        data: json!({ "verdict": report.verdict, "tags": report.tags, "families": report.families, "firstSeen": report.first_seen, "lastSeen": report.last_seen, "source": r.source }),
        strength: Strength::Corroborating,
        operation_id: None,
        execution_id: None,
    }))
}

/// Map a set of provider results; the summary names each provider's status.
pub fn map_results(t: EntityType, subject: &str, results: &[ProviderResult]) -> Output {
    let mut observations = vec![];
    let mut status = vec![];
    let mut rate = None;
    for r in results {
        let s = match r.status {
            Status::Found => "found",
            Status::NotFound => "no record",
            Status::Unsupported => "not applicable",
            Status::NoKey => "not configured",
            Status::Disabled => "turned off",
            Status::RateLimited => "rate limited",
            Status::Error => "error",
        };
        status.push(format!("{}: {s}", r.provider_name));
        if r.status == Status::RateLimited {
            rate = r.message.clone();
        }
        if let Some(o) = map_result(t, subject, r) {
            observations.push(o);
        }
    }
    Output { summary: format!("{} provider report{} for {subject} ({})", observations.len(), if observations.len() == 1 { "" } else { "s" }, status.join(", ")), observations, rate_note: rate, from_cache: false }
}

pub fn indicator_for(t: EntityType, value: &str) -> Result<indicator::Indicator, Error> {
    if !matches!(t, EntityType::Ip | EntityType::Domain | EntityType::Url | EntityType::FileHash) {
        return Err(Error::Unsupported("Threat intelligence covers IP addresses, domains, URLs and file hashes".into()));
    }
    // the existing integration refuses private and internal indicators without a request
    indicator::detect(value).map_err(Error::Refused)
}

/// NVD record → vulnerability entity with its facts; references stay in the evidence.
pub fn map_cve(rec: &CveRecord, source: &str) -> Observation {
    let mut b = Builder::default();
    let mut v = ent(EntityType::Vulnerability, rec.id.clone());
    if let Some(best) = rec.cvss.iter().max_by(|a, b| a.version.cmp(&b.version)) {
        v.metadata.insert("cvss".into(), json!({ "version": best.version, "score": best.score, "severity": best.severity, "vector": best.vector }));
    }
    v.metadata.insert("published".into(), json!(rec.published));
    v.metadata.insert("knownExploited".into(), json!(rec.kev));
    v.metadata.insert("description".into(), json!(rec.description.chars().take(600).collect::<String>()));
    if !rec.cwes.is_empty() {
        v.metadata.insert("cwe".into(), json!(rec.cwes));
    }
    b.add(v);
    let summary = format!(
        "NVD record {}{}: {}",
        rec.id,
        rec.cvss.first().map(|c| format!(" (CVSS {} {})", c.score, c.severity)).unwrap_or_default(),
        rec.description.chars().take(400).collect::<String>()
    );
    b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "nvd".into(),
        reference: Some(format!("https://nvd.nist.gov/vuln/detail/{}", rec.id)),
        observed_at: Some(rec.last_modified.clone()),
        summary,
        data: json!({ "references": rec.references.iter().take(20).map(|r| &r.url).collect::<Vec<_>>(), "source": source }),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::model::{Fact, Related, Report, Verdict};

    fn result(provider: &str, report: Report) -> ProviderResult {
        ProviderResult { provider: provider.into(), provider_name: provider.into(), status: Status::Found, report: Some(report), message: None, source: Some("live".into()), fetched_at: Some("2026-11-05T00:00:00Z".into()), fresh_until: None, quota: None }
    }

    #[test]
    fn maps_provider_reports_without_inventing_relationships() {
        let mut r = Report { verdict: Some(Verdict { level: Level::Malicious, label: "Malicious".into() }), families: vec!["Emotet".into()], categories: vec!["CVE-2024-0001".into(), "not-a-cve".into()], ..Default::default() };
        r.facts = vec![
            Fact { label: "ASN".into(), value: "AS13335".into() },
            Fact { label: "ISP".into(), value: "Example Hosting".into() },
            Fact { label: "Ports".into(), value: "22, 443/tcp, 53/udp".into() },
            Fact { label: "Hostnames".into(), value: "a.example.com, not a host".into() },
        ];
        let o = map_result(EntityType::Ip, "203.0.113.7", &result("shodan", r)).unwrap();
        assert!(o.entities[0].flagged);
        let rels: Vec<&str> = o.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["ROUTES_THROUGH", "HOSTED_ON", "EXPOSES_SERVICE", "EXPOSES_SERVICE", "EXPOSES_SERVICE", "RESOLVES_TO", "ASSOCIATED_WITH_THREAT", "AFFECTED_BY"]);
        assert_eq!(o.relationships.last().unwrap().strength, Strength::Weak, "banner-based CVEs are weak");
        assert!(o.entities.iter().any(|e| e.value == "203.0.113.7:53/udp"));

        let url = Report { related: vec![Related { kind: Kind::Domain, value: "bad.example".into(), relation: "host".into() }, Related { kind: Kind::File, value: "a".repeat(64), relation: "payload served".into() }], ..Default::default() };
        let o = map_result(EntityType::Url, "http://bad.example/x", &result("urlhaus", url)).unwrap();
        let rels: Vec<&str> = o.relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["ON_HOST", "SERVES_FILE"]);
        assert!(!o.entities[0].flagged);

        let mut missing = result("otx", Report::default());
        missing.status = Status::NoKey;
        let out = map_results(EntityType::Ip, "203.0.113.7", &[missing]);
        assert!(out.observations.is_empty() && out.summary.contains("not configured"));
        assert!(indicator_for(EntityType::Ip, "10.0.0.1").is_err(), "private indicators are refused");
        assert!(indicator_for(EntityType::Organization, "Acme").is_err());
    }
}
