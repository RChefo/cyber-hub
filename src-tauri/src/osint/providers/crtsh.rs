//! Certificate Transparency through crt.sh's JSON output.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::{ent, get_json, Builder, Error, Output};
use crate::db::Db;
use crate::osint::ingest::EvidenceInput;
use crate::osint::model::{EntityType, Strength};
use crate::osint::normalize;

const BASE: &str = "https://crt.sh/";
/// Bounds per run: the most recent certificates and the names they cover.
pub const MAX_CERTS: usize = 60;
pub const MAX_NAMES: usize = 400;

pub fn query_url(base: &str, domain: &str) -> String {
    format!("{}?q=%25.{}&output=json", base, domain)
}

/// Identity search for the name itself; much cheaper for crt.sh than the subdomain (`%.`) search
/// and still lists certificates whose names include subdomains.
pub fn identity_url(base: &str, domain: &str) -> String {
    format!("{}?q={}&output=json", base, domain)
}

/// One observation per certificate (its own evidence: the crt.sh entry).
pub fn parse(domain: &str, body: &Value) -> Result<Output, Error> {
    let rows = body.as_array().ok_or_else(|| Error::Invalid("crt.sh returned an unexpected document".into()))?;
    // newest first, one entry per certificate id
    // one entry per certificate; crt.sh may return a row per matching identity, so names are
    // combined and the first row's details are kept
    let mut certs: BTreeMap<i64, &Value> = BTreeMap::new();
    let mut cert_names: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for r in rows {
        if let Some(id) = r.get("id").and_then(Value::as_i64) {
            certs.entry(id).or_insert(r);
            let names = cert_names.entry(id).or_default();
            for n in r.get("name_value").and_then(Value::as_str).unwrap_or("").lines().map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    let total = certs.len();
    let mut names_seen: BTreeSet<String> = BTreeSet::new();
    let mut observations = vec![];
    for (id, r) in certs.iter().rev().take(MAX_CERTS) {
        let names: Vec<String> = cert_names.get(id).cloned().unwrap_or_default();
        let mut b = Builder::default();
        let mut cert = ent(EntityType::Certificate, format!("crtsh:{id}"));
        let issuer = r.get("issuer_name").and_then(Value::as_str).unwrap_or("");
        let cn = r.get("common_name").and_then(Value::as_str).unwrap_or("");
        cert.display_name = Some(format!("{} ({})", if cn.is_empty() { "certificate" } else { cn }, r.get("not_before").and_then(Value::as_str).unwrap_or("").get(..10).unwrap_or("")));
        for (k, f) in [("issuer", "issuer_name"), ("serial", "serial_number"), ("notBefore", "not_before"), ("notAfter", "not_after"), ("loggedAt", "entry_timestamp"), ("commonName", "common_name")] {
            if let Some(v) = r.get(f).and_then(Value::as_str) {
                cert.metadata.insert(k.into(), json!(v));
            }
        }
        let c = b.add(cert);
        let mut used = 0;
        for n in &names {
            let wildcard = n.starts_with("*.");
            let host = n.trim_start_matches("*.");
            // only names inside the queried domain; CT entries can carry unrelated SANs
            if !(host == domain || host.ends_with(&format!(".{domain}"))) || normalize::domain(host).is_err() {
                continue;
            }
            if names_seen.len() >= MAX_NAMES && !names_seen.contains(host) {
                continue;
            }
            names_seen.insert(host.to_string());
            let mut d = ent(EntityType::Domain, host);
            if wildcard {
                d.metadata.insert("wildcardCertificate".into(), json!(true));
            }
            let di = b.add(d);
            b.rel(di, c, "USES_CERTIFICATE", Strength::Direct);
            used += 1;
        }
        if used == 0 {
            continue;
        }
        observations.push(b.finish(EvidenceInput {
            kind: "provider_response".into(),
            source: "crtsh".into(),
            reference: Some(format!("https://crt.sh/?id={id}")),
            observed_at: r.get("entry_timestamp").and_then(Value::as_str).map(String::from),
            summary: format!("Certificate Transparency log entry {id}, issued by {issuer}, covers: {}", names.join(", ")),
            data: json!({ "id": id, "issuer": issuer, "notBefore": r.get("not_before"), "notAfter": r.get("not_after") }),
            strength: Strength::Direct,
            operation_id: None,
            execution_id: None,
        }));
    }
    let mut summary = format!("{} certificate{} and {} name{} for {domain}", observations.len(), if observations.len() == 1 { "" } else { "s" }, names_seen.len(), if names_seen.len() == 1 { "" } else { "s" });
    if total > MAX_CERTS {
        summary.push_str(&format!(" (the {MAX_CERTS} most recent of {total} logged certificates)"));
    }
    Ok(Output { observations, summary, rate_note: None, from_cache: false })
}

pub async fn run(db: &Db, domain: &str, refresh: bool) -> Result<Output, Error> {
    if !refresh {
        if let Some(cached) = super::cache_get(db, "crtsh", domain, 24) {
            let mut out = parse(domain, &cached)?;
            out.from_cache = true;
            return Ok(out);
        }
    }
    let client = super::client(60)?;
    let (mut status, mut body, mut rate) = get_json(&client, &query_url(BASE, domain), "application/json").await?;
    let mut fallback = false;
    // the subdomain search is expensive for crt.sh and often fails upstream (502-504, or 404
    // from its proxy); the exact-identity search is cheaper and is tried once instead
    if matches!(status, 404 | 502..=504) {
        let (s, b, r) = get_json(&client, &identity_url(BASE, domain), "application/json").await?;
        (status, body, rate, fallback) = (s, b, r, true);
    }
    match status {
        200 => {}
        429 => return Err(Error::RateLimited(60)),
        404 | 502..=504 => return Err(Error::Unavailable(format!("crt.sh did not answer (HTTP {status}); it is often overloaded, try again later"))),
        s => return Err(Error::Network(format!("crt.sh returned HTTP {s}"))),
    }
    let body = if body.is_null() { json!([]) } else { body };
    super::cache_put(db, "crtsh", domain, &body);
    let mut out = parse(domain, &body)?;
    if fallback {
        out.summary.push_str(" (exact-name search: crt.sh's subdomain search was unavailable)");
    }
    out.rate_note = rate;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_certificates_to_names_and_ignores_foreign_sans() {
        let body = json!([
            { "id": 100, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "example.com", "name_value": "example.com\n*.example.com\nwww.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "entry_timestamp": "2026-01-01T01:00:00.000", "serial_number": "abc" },
            { "id": 100, "name_value": "api.example.com" },
            { "id": 101, "issuer_name": "X", "common_name": "mail.example.com", "name_value": "mail.example.com\nunrelated.example.org", "not_before": "2026-02-01T00:00:00" }
        ]);
        let out = parse("example.com", &body).unwrap();
        assert_eq!(out.observations.len(), 2);
        let all_names: BTreeSet<String> = out.observations.iter().flat_map(|o| o.entities.iter().filter(|e| e.entity_type == EntityType::Domain).map(|e| e.value.clone())).collect();
        assert_eq!(all_names, BTreeSet::from(["example.com".to_string(), "www.example.com".into(), "mail.example.com".into(), "api.example.com".into()]));
        assert_eq!(out.observations[1].evidence.reference.as_deref(), Some("https://crt.sh/?id=100"));
        assert!(out.observations.iter().all(|o| o.relationships.iter().all(|r| r.rel_type == "USES_CERTIFICATE")));
        assert!(parse("example.com", &json!({ "error": 1 })).is_err());
        assert_eq!(query_url(BASE, "example.com"), "https://crt.sh/?q=%25.example.com&output=json");
    }

    #[test]
    fn caps_large_result_sets() {
        let rows: Vec<Value> = (0..(MAX_CERTS as i64 + 20)).map(|i| json!({ "id": i, "name_value": format!("h{i}.example.com") })).collect();
        let out = parse("example.com", &Value::Array(rows)).unwrap();
        assert_eq!(out.observations.len(), MAX_CERTS);
        assert!(out.summary.contains("most recent"));
    }
}
