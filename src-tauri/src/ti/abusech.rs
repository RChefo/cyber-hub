// SPDX-License-Identifier: Apache-2.0
//! abuse.ch community APIs — URLhaus, MalwareBazaar and ThreatFox (one Auth-Key for all).
//!
//! These databases only contain malicious items, so a match is reported as Malicious with
//! the provider's own context (URL status, malware family, ThreatFox confidence). No match is
//! "no record", never "clean".

use serde_json::Value;

use super::http::{self, ApiError, Response};
use super::indicator::{HashType, Indicator, Kind};
use super::model::{min_max, tidy, Level, Parsed, Report, Score, Table, Verdict};

/// A public, harmless test hash (EICAR test file, SHA-256) used to validate an Auth-Key.
#[cfg(any(test, feature = "provisioning"))]
pub const PROBE_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

const AUTH_STATUSES: &[&str] = &["unknown_auth_key", "no_api_key", "user_blacklisted", "unauthorized"];

fn query_status(body: &Value) -> &str {
    body.get("query_status").and_then(Value::as_str).unwrap_or("")
}

fn check(resp: &Response) -> Result<(), ApiError> {
    match resp.status {
        200 => {}
        401 | 403 => return Err(ApiError::Unauthorized),
        s => return Err(http::status_error(s, http::short(query_status(&resp.body), 80))),
    }
    let qs = query_status(&resp.body);
    if AUTH_STATUSES.contains(&qs) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| match x {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/* ───────────────────────── URLhaus ───────────────────────── */

pub async fn urlhaus_lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<Parsed, ApiError> {
    let (path, field) = match ind.kind {
        Kind::Url => ("url", "url"),
        Kind::Domain | Kind::Ip => ("host", "host"),
        Kind::File => (
            "payload",
            match ind.hash_type {
                Some(HashType::Md5) => "md5_hash",
                Some(HashType::Sha256) => "sha256_hash",
                _ => return Err(ApiError::BadRequest("URLhaus accepts MD5 or SHA-256 hashes".into())),
            },
        ),
    };
    let resp = http::send(client.post(format!("{base}/{path}/")).header("Auth-Key", key).form(&[(field, ind.value.as_str())]), key).await?;
    check(&resp)?;
    urlhaus_parse(ind, &resp.body)
}

pub fn urlhaus_parse(ind: &Indicator, body: &Value) -> Result<Parsed, ApiError> {
    match query_status(body) {
        "ok" => {}
        "no_results" => return Ok(Parsed::none()),
        other => return Err(ApiError::BadRequest(http::short(other, 80))),
    }
    // only accept links back to URLhaus itself
    let permalink = s(body, "urlhaus_reference").filter(|l| l.starts_with("https://urlhaus.abuse.ch/") && !l.chars().any(|c| c.is_whitespace() || c.is_control()));
    let mut r = Report { permalink, ..Default::default() };
    let blacklists = body.get("blacklists").and_then(Value::as_object).map(|m| {
        m.iter().filter_map(|(k, v)| v.as_str().map(|v| format!("{k}: {v}"))).collect::<Vec<_>>().join(", ")
    });
    let urls = body.get("urls").and_then(Value::as_array).cloned().unwrap_or_default();
    match ind.kind {
        Kind::Url => {
            let status = s(body, "url_status").unwrap_or_else(|| "unknown".into());
            let threat = s(body, "threat");
            r.verdict = Some(Verdict { level: Level::Malicious, label: format!("Listed malware URL ({status})") });
            r.categories = tidy(threat.iter().cloned().collect(), 4);
            r.tags = tidy(strings(body.get("tags")), 20);
            r.first_seen = s(body, "date_added");
            r.last_seen = s(body, "last_online");
            r.fact("URL status", Some(status));
            r.fact("Threat", threat);
            r.fact("Host", s(body, "host"));
            r.fact("Reporter", s(body, "reporter"));
            r.fact("Blacklists", blacklists);
            if let Some(h) = s(body, "host") {
                r.relate(&h, "host");
            }
            let payloads = body.get("payloads").and_then(Value::as_array).cloned().unwrap_or_default();
            r.families = tidy(payloads.iter().filter_map(|p| s(p, "signature")).collect(), 10);
            for p in &payloads {
                if let Some(h) = s(p, "response_sha256") {
                    r.relate(&h, "payload served");
                }
            }
            if !payloads.is_empty() {
                r.tables.push(Table {
                    title: "Payloads served".into(),
                    columns: vec!["First seen".into(), "File name".into(), "Type".into(), "Signature".into(), "SHA-256".into()],
                    rows: payloads
                        .iter()
                        .take(10)
                        .map(|p| vec![s(p, "firstseen").unwrap_or_default(), s(p, "filename").unwrap_or_default(), s(p, "file_type").unwrap_or_default(), s(p, "signature").unwrap_or_default(), s(p, "response_sha256").unwrap_or_default()])
                        .collect(),
                    note: None,
                });
            }
        }
        Kind::Domain | Kind::Ip => {
            let count = s(body, "url_count").and_then(|c| c.parse::<i64>().ok()).unwrap_or(urls.len() as i64);
            let online = urls.iter().filter(|u| s(u, "url_status").as_deref() == Some("online")).count();
            r.verdict = Some(Verdict {
                level: if online > 0 { Level::Malicious } else { Level::Suspicious },
                label: format!("Hosted {count} malware URL{} ({online} online)", if count == 1 { "" } else { "s" }),
            });
            r.scores.push(Score { label: "Malware URLs".into(), value: count as f64, max: None, display: count.to_string() });
            r.first_seen = s(body, "firstseen");
            let (_, last) = min_max(urls.iter().filter_map(|u| s(u, "date_added")));
            r.last_seen = last;
            r.categories = tidy(urls.iter().filter_map(|u| s(u, "threat")).collect(), 6);
            r.tags = tidy(urls.iter().flat_map(|u| strings(u.get("tags"))).collect(), 20);
            r.fact("Malware URLs", Some(count.to_string()));
            r.fact("Online now", Some(online.to_string()));
            r.fact("Blacklists", blacklists);
            for u in urls.iter().take(10) {
                if let Some(v) = s(u, "url") {
                    r.relate(&v, "malware URL on this host");
                }
            }
            r.tables.push(url_table(&urls, "URLs on this host"));
        }
        Kind::File => {
            let sig = s(body, "signature");
            r.verdict = Some(Verdict { level: Level::Malicious, label: format!("Payload delivered by malware URLs{}", sig.as_ref().map(|s| format!(" ({s})")).unwrap_or_default()) });
            r.families = tidy(sig.into_iter().collect(), 4);
            r.first_seen = s(body, "firstseen");
            r.last_seen = s(body, "lastseen");
            r.fact("File type", s(body, "file_type"));
            r.fact("File size", s(body, "file_size").map(|b| format!("{b} bytes")));
            r.fact("URLs delivering it", s(body, "url_count"));
            r.fact("SHA-256", s(body, "sha256_hash"));
            r.fact("MD5", s(body, "md5_hash"));
            r.fact("imphash", s(body, "imphash"));
            for u in urls.iter().take(10) {
                if let Some(v) = s(u, "url") {
                    r.relate(&v, "delivered from");
                }
            }
            r.tables.push(url_table(&urls, "URLs delivering this payload"));
        }
    }
    Ok(Parsed::found(r))
}

fn url_table(urls: &[Value], title: &str) -> Table {
    Table {
        title: title.into(),
        columns: vec!["URL".into(), "Status".into(), "Threat".into(), "Added".into()],
        rows: urls
            .iter()
            .take(15)
            .map(|u| vec![http::short(&s(u, "url").unwrap_or_default(), 160), s(u, "url_status").unwrap_or_default(), s(u, "threat").unwrap_or_default(), s(u, "date_added").or_else(|| s(u, "firstseen")).unwrap_or_default()])
            .collect(),
        note: (urls.len() > 15).then(|| format!("Showing 15 of {} URLs.", urls.len())),
    }
}

/* ───────────────────────── MalwareBazaar ───────────────────────── */

pub async fn bazaar_lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<Parsed, ApiError> {
    if ind.kind != Kind::File {
        return Err(ApiError::BadRequest("MalwareBazaar looks up file hashes only".into()));
    }
    let resp = http::send(client.post(format!("{base}/")).header("Auth-Key", key).form(&[("query", "get_info"), ("hash", ind.value.as_str())]), key).await?;
    check(&resp)?;
    bazaar_parse(&resp.body)
}

#[cfg(any(test, feature = "provisioning"))]
/// Validate an abuse.ch Auth-Key with one MalwareBazaar query for a harmless public hash.
pub async fn validate(client: &reqwest::Client, base: &str, key: &str) -> Result<Option<String>, ApiError> {
    let resp = http::send(client.post(format!("{base}/")).header("Auth-Key", key).form(&[("query", "get_info"), ("hash", PROBE_SHA256)]), key).await?;
    check(&resp)?;
    match query_status(&resp.body) {
        "ok" | "hash_not_found" => Ok(None),
        other => Err(ApiError::Unexpected(http::short(other, 80))),
    }
}

pub fn bazaar_parse(body: &Value) -> Result<Parsed, ApiError> {
    match query_status(body) {
        "ok" => {}
        "hash_not_found" | "no_results" => return Ok(Parsed::none()),
        other => return Err(ApiError::BadRequest(http::short(other, 80))),
    }
    let d = body.get("data").and_then(|d| if d.is_array() { d.get(0) } else { Some(d) }).cloned().ok_or_else(|| ApiError::Unexpected("missing data".into()))?;
    let sha = s(&d, "sha256_hash").unwrap_or_default();
    let sig = s(&d, "signature");
    let mut r = Report { permalink: (!sha.is_empty()).then(|| format!("https://bazaar.abuse.ch/sample/{sha}/")), ..Default::default() };
    r.verdict = Some(Verdict { level: Level::Malicious, label: format!("Known malware sample{}", sig.as_ref().map(|s| format!(" ({s})")).unwrap_or_default()) });
    r.families = tidy(sig.into_iter().collect(), 4);
    r.tags = tidy(strings(d.get("tags")), 20);
    r.first_seen = s(&d, "first_seen");
    r.last_seen = s(&d, "last_seen");
    r.fact("File name", s(&d, "file_name"));
    r.fact("File type", s(&d, "file_type"));
    r.fact("MIME type", s(&d, "file_type_mime"));
    r.fact("File size", s(&d, "file_size").map(|b| format!("{b} bytes")));
    r.fact("Delivery method", s(&d, "delivery_method"));
    r.fact("Origin country", s(&d, "origin_country"));
    r.fact("Reporter", s(&d, "reporter"));
    r.fact("SHA-256", Some(sha.clone()).filter(|x| !x.is_empty()));
    r.fact("SHA-1", s(&d, "sha1_hash"));
    r.fact("MD5", s(&d, "md5_hash"));
    r.fact("imphash", s(&d, "imphash"));
    r.fact("ssdeep", s(&d, "ssdeep"));
    if let Some(intel) = d.get("intelligence") {
        r.fact("ClamAV", Some(strings(intel.get("clamav")).join(", ")));
        r.fact("Downloads", s(intel, "downloads"));
        r.fact("Uploads", s(intel, "uploads"));
    }
    if let Some(v) = d.get("vendor_intel").and_then(Value::as_object) {
        let vendors: Vec<String> = v.keys().cloned().collect();
        r.fact("Vendor intelligence", (!vendors.is_empty()).then(|| vendors.join(", ")));
    }
    let yara: Vec<Vec<String>> = d
        .get("yara_rules")
        .and_then(Value::as_array)
        .map(|a| a.iter().take(15).map(|y| vec![s(y, "rule_name").unwrap_or_default(), s(y, "author").unwrap_or_default(), http::short(&s(y, "description").unwrap_or_default(), 120)]).collect())
        .unwrap_or_default();
    if !yara.is_empty() {
        r.tables.push(Table { title: "YARA matches".into(), columns: vec!["Rule".into(), "Author".into(), "Description".into()], rows: yara, note: None });
    }
    Ok(Parsed::found(r))
}

/* ───────────────────────── ThreatFox ───────────────────────── */

pub async fn threatfox_lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<Parsed, ApiError> {
    let body = match ind.kind {
        Kind::File => match ind.hash_type {
            Some(HashType::Md5) | Some(HashType::Sha256) => serde_json::json!({"query": "search_hash", "hash": ind.value}),
            _ => return Err(ApiError::BadRequest("ThreatFox accepts MD5 or SHA-256 hashes".into())),
        },
        // IP IOCs are stored as ip:port, so IPs use a wildcard search filtered below
        Kind::Ip => serde_json::json!({"query": "search_ioc", "search_term": ind.value, "exact_match": false}),
        Kind::Domain | Kind::Url => serde_json::json!({"query": "search_ioc", "search_term": ind.value, "exact_match": true}),
    };
    let resp = http::send(client.post(format!("{base}/")).header("Auth-Key", key).json(&body), key).await?;
    check(&resp)?;
    threatfox_parse(ind, &resp.body)
}

pub fn threatfox_parse(ind: &Indicator, body: &Value) -> Result<Parsed, ApiError> {
    let qs = query_status(body);
    if qs != "ok" {
        if qs.starts_with("no_result") || body.get("data").is_some_and(|d| d.is_string() || d.is_null()) {
            return Ok(Parsed::none());
        }
        return Err(ApiError::BadRequest(http::short(qs, 80)));
    }
    let mut entries: Vec<Value> = body.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
    if ind.kind == Kind::Ip {
        // keep exact IP or ip:port matches only
        entries.retain(|e| s(e, "ioc").is_some_and(|v| v == ind.value || v.strip_prefix(&ind.value).is_some_and(|rest| rest.starts_with(':'))));
    }
    if entries.is_empty() {
        return Ok(Parsed::none());
    }
    let families = tidy(entries.iter().filter_map(|e| s(e, "malware_printable")).collect(), 10);
    let max_conf = entries.iter().filter_map(|e| e.get("confidence_level").and_then(Value::as_f64)).fold(0.0, f64::max);
    let mut r = Report::default();
    let what = if ind.kind == Kind::File { "IOCs linked to this sample" } else { "ThreatFox IOC entr" };
    r.verdict = Some(Verdict {
        level: Level::Malicious,
        label: if ind.kind == Kind::File {
            format!("{} {what}{}", entries.len(), families.first().map(|f| format!(" ({f})")).unwrap_or_default())
        } else {
            format!("{} {what}{}{}", entries.len(), if entries.len() == 1 { "y" } else { "ies" }, families.first().map(|f| format!(" ({f})")).unwrap_or_default())
        },
    });
    r.scores.push(Score { label: "Highest ThreatFox confidence".into(), value: max_conf, max: Some(100.0), display: format!("{max_conf:.0}%") });
    r.families = families;
    r.categories = tidy(entries.iter().filter_map(|e| s(e, "threat_type_desc").or_else(|| s(e, "threat_type"))).collect(), 8);
    r.tags = tidy(entries.iter().flat_map(|e| strings(e.get("tags"))).collect(), 20);
    let (first, _) = min_max(entries.iter().filter_map(|e| s(e, "first_seen")));
    let (_, last) = min_max(entries.iter().filter_map(|e| s(e, "last_seen").or_else(|| s(e, "first_seen"))));
    r.first_seen = first;
    r.last_seen = last;
    r.permalink = entries.first().and_then(|e| s(e, "id")).map(|id| format!("https://threatfox.abuse.ch/ioc/{id}/"));
    r.fact("Malpedia", entries.iter().find_map(|e| s(e, "malware_malpedia")));
    if ind.kind == Kind::File {
        for e in entries.iter().take(20) {
            if let Some(v) = s(e, "ioc") {
                // ip:port IOCs pivot on the IP
                let v = match v.rsplit_once(':') {
                    Some((ip, port)) if port.chars().all(|c| c.is_ascii_digit()) && !v.contains("://") => ip.to_string(),
                    _ => v,
                };
                r.relate(&v, "IOC linked to this sample");
            }
        }
    }
    r.tables.push(Table {
        title: "IOC entries".into(),
        columns: vec!["IOC".into(), "Type".into(), "Malware".into(), "Confidence".into(), "First seen".into()],
        rows: entries
            .iter()
            .take(15)
            .map(|e| vec![http::short(&s(e, "ioc").unwrap_or_default(), 160), s(e, "ioc_type").unwrap_or_default(), s(e, "malware_printable").unwrap_or_default(), s(e, "confidence_level").map(|c| format!("{c}%")).unwrap_or_default(), s(e, "first_seen").unwrap_or_default()])
            .collect(),
        note: Some("ThreatFox expires IOCs older than six months.".into()),
    });
    Ok(Parsed::found(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;
    use crate::ti::indicator::detect;

    const KEY: &str = "abusech-test-auth-key-0123456789";

    #[test]
    fn parses_urlhaus_url_host_and_payload() {
        let url = detect("http://malware-host.xyz/bin.exe").unwrap();
        let p = urlhaus_parse(&url, &serde_json::json!({
            "query_status": "ok", "url_status": "online", "threat": "malware_download", "host": "malware-host.xyz",
            "date_added": "2026-10-01 10:00:00 UTC", "last_online": "2026-11-01 10:00:00 UTC", "tags": ["exe", "AgentTesla"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/", "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
            "payloads": [{"firstseen": "2026-10-01", "filename": "bin.exe", "file_type": "exe", "signature": "AgentTesla", "response_sha256": "c".repeat(64)}]
        })).unwrap();
        assert_eq!(p.report.verdict.as_ref().unwrap().label, "Listed malware URL (online)");
        assert_eq!(p.report.families, vec!["AgentTesla"]);
        assert!(p.report.related.iter().any(|r| r.relation == "payload served"));
        assert!(p.report.related.iter().any(|r| r.value == "malware-host.xyz"));

        let host = detect("malware-host.xyz").unwrap();
        let h = urlhaus_parse(&host, &serde_json::json!({"query_status": "ok", "url_count": "2", "firstseen": "2026-09-01",
            "urls": [{"url": "http://malware-host.xyz/a", "url_status": "offline", "threat": "malware_download", "date_added": "2026-09-01"},
                     {"url": "http://malware-host.xyz/b", "url_status": "offline", "threat": "malware_download", "date_added": "2026-10-01"}]})).unwrap();
        let v = h.report.verdict.unwrap();
        assert_eq!((v.level, v.label.as_str()), (Level::Suspicious, "Hosted 2 malware URLs (0 online)"));
        assert_eq!(h.report.last_seen.as_deref(), Some("2026-10-01"));

        assert!(!urlhaus_parse(&host, &serde_json::json!({"query_status": "no_results"})).unwrap().found);
        assert!(urlhaus_parse(&host, &serde_json::json!({"query_status": "invalid_host"})).is_err());
        let evil = urlhaus_parse(&host, &serde_json::json!({"query_status": "ok", "urlhaus_reference": "https://evil.example/x", "urls": []})).unwrap();
        assert_eq!(evil.report.permalink, None);
    }

    #[test]
    fn parses_bazaar_and_threatfox() {
        let mb = bazaar_parse(&serde_json::json!({"query_status": "ok", "data": [{
            "sha256_hash": "d".repeat(64), "md5_hash": "e".repeat(32), "file_name": "invoice.exe", "file_type": "exe",
            "signature": "FormBook", "tags": ["exe", "FormBook"], "first_seen": "2026-10-01 08:00:00", "last_seen": null,
            "intelligence": {"clamav": ["Win.Trojan.Formbook"], "downloads": "12", "uploads": "1"},
            "vendor_intel": {"ANY.RUN": [], "Triage": {}}, "yara_rules": [{"rule_name": "win_formbook", "author": "x", "description": "FormBook"}]}]})).unwrap();
        assert_eq!(mb.report.verdict.unwrap().label, "Known malware sample (FormBook)");
        assert!(mb.report.facts.iter().any(|f| f.label == "Vendor intelligence" && f.value.contains("Triage")));
        assert_eq!(mb.report.tables[0].rows[0][0], "win_formbook");
        assert!(!bazaar_parse(&serde_json::json!({"query_status": "hash_not_found"})).unwrap().found);

        let ip = detect("45.9.148.10").unwrap();
        let tf = threatfox_parse(&ip, &serde_json::json!({"query_status": "ok", "data": [
            {"id": "100", "ioc": "45.9.148.10:443", "ioc_type": "ip:port", "threat_type_desc": "Botnet C&C", "malware_printable": "Cobalt Strike", "confidence_level": 75, "first_seen": "2026-10-02 00:00:00 UTC", "tags": ["c2"]},
            {"id": "101", "ioc": "45.9.148.100:80", "ioc_type": "ip:port", "malware_printable": "Other", "confidence_level": 100}
        ]})).unwrap();
        assert_eq!(tf.report.verdict.as_ref().unwrap().label, "1 ThreatFox IOC entry (Cobalt Strike)");
        assert_eq!(tf.report.scores[0].display, "75%");
        assert_eq!(tf.report.permalink.as_deref(), Some("https://threatfox.abuse.ch/ioc/100/"));
        assert!(!threatfox_parse(&ip, &serde_json::json!({"query_status": "no_result", "data": "Your search did not yield any results"})).unwrap().found);
    }

    #[tokio::test]
    async fn sends_auth_key_header_and_maps_auth_failures() {
        let srv = mock::serve(vec![
            mock::ok(r#"{"query_status":"hash_not_found"}"#),
            mock::ok(r#"{"query_status":"unknown_auth_key"}"#),
            mock::status(401, r#"{"query_status":"unknown_auth_key"}"#),
        ]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap(), None);
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap_err(), ApiError::Unauthorized);
        let ind = detect(&"f".repeat(64)).unwrap();
        assert_eq!(bazaar_lookup(&c, &srv.base, KEY, &ind).await.unwrap_err(), ApiError::Unauthorized);
        let seen = srv.seen.lock().unwrap().clone();
        assert_eq!(seen[0].header("auth-key").as_deref(), Some(KEY));
        assert_eq!(String::from_utf8_lossy(&seen[0].body), format!("query=get_info&hash={PROBE_SHA256}"));
        assert!(seen.iter().all(|s| !s.first_line().contains(KEY)));
    }

    #[tokio::test]
    async fn urlhaus_sha1_is_refused_without_a_request() {
        let srv = mock::serve(vec![]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        let ind = detect(&"a".repeat(40)).unwrap();
        assert!(urlhaus_lookup(&c, &srv.base, KEY, &ind).await.is_err());
        assert!(srv.seen.lock().unwrap().is_empty());
    }
}
