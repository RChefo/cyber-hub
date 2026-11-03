//! VirusTotal API v3 provider.
//!
//! * Reputation lookups are read-only GET requests (`/ip_addresses`, `/domains`, `/urls/{id}`,
//!   `/files`). File uploads live in `vtfile.rs` and always require a native confirmation.
//! * The API key is read from the OS credential store by the caller and sent only in the
//!   `x-apikey` header to the fixed API base. It never appears in URLs, errors or storage.
//! * Indicator detection (and refusal of private / internal values) is shared with the other
//!   providers (`ti::indicator`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ti::http::{self, ApiError, Response};
pub use crate::ti::indicator::{detect, Indicator, Kind};
use crate::ti::model;

pub const GUI_BASE: &str = "https://www.virustotal.com/gui";
/// Fresh-cache lifetime for a report.
pub const REPORT_TTL_SECS: i64 = 24 * 3600;
/// Fresh-cache lifetime for "VirusTotal has no record of this".
pub const NOT_FOUND_TTL_SECS: i64 = 3600;
pub const NAME: &str = "VirusTotal";

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

/// API path below the base for a lookup, e.g. `/ip_addresses/8.8.8.8`. URLs are looked up
/// by their identifier, computed locally; they are never submitted for scanning.
pub fn path(ind: &Indicator) -> String {
    match ind.kind {
        Kind::Ip => format!("/ip_addresses/{}", ind.value),
        Kind::Domain => format!("/domains/{}", ind.value),
        Kind::Url => format!("/urls/{}", base64url_nopad(ind.value.as_bytes())),
        Kind::File => format!("/files/{}", ind.value),
    }
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

/* ───────────────────────── HTTP ───────────────────────── */

pub fn map_error(resp: &Response, key: &str) -> ApiError {
    let code = resp.body.pointer("/error/code").and_then(Value::as_str).unwrap_or("");
    let msg = http::scrub(&http::short(resp.body.pointer("/error/message").and_then(Value::as_str).unwrap_or(""), 300), key);
    match (resp.status, code) {
        (404, _) | (_, "NotFoundError") => ApiError::NotFound,
        (401, _) | (_, "WrongCredentialsError") | (_, "AuthenticationRequiredError") => ApiError::Unauthorized,
        (429, _) | (_, "QuotaExceededError") | (_, "TooManyRequestsError") => ApiError::Quota(msg),
        (403, _) => ApiError::Forbidden(msg),
        (400, _) | (413, _) => ApiError::BadRequest(msg),
        (s, _) => ApiError::Server(s),
    }
}

/// GET `{base}{path}` with the key in the `x-apikey` header.
pub async fn get(client: &reqwest::Client, base: &str, path: &str, key: &str) -> Result<Value, ApiError> {
    let resp = http::send(client.get(format!("{base}{path}")).header("x-apikey", key).header("accept", "application/json"), key).await?;
    if resp.status == 200 {
        Ok(resp.body)
    } else {
        Err(map_error(&resp, key))
    }
}

/* ───────────────────────── threat-intel view ───────────────────────── */

/// The report in the provider-neutral shape. Level: any malicious engine → Malicious; any
/// suspicious → Suspicious; harmless verdicts only → Clean; no verdicts → Unknown.
pub fn to_ti(r: &Report) -> model::Report {
    use model::{Fact, Level, Score, Table, Verdict};
    let st = &r.stats;
    let of = if r.engines_total > 0 { format!(" of {}", r.engines_total) } else { String::new() };
    let verdict = if st.malicious > 0 {
        Verdict { level: Level::Malicious, label: format!("{}{of} engines: malicious", st.malicious) }
    } else if st.suspicious > 0 {
        Verdict { level: Level::Suspicious, label: format!("{}{of} engines: suspicious", st.suspicious) }
    } else if st.harmless > 0 {
        Verdict { level: Level::Clean, label: format!("No detections; {} engines rated it harmless", st.harmless) }
    } else {
        Verdict { level: Level::Unknown, label: "No engine verdicts".into() }
    };
    let mut scores = vec![Score {
        label: "Engines flagging (malicious + suspicious)".into(),
        value: (st.malicious + st.suspicious) as f64,
        max: Some(r.engines_total as f64),
        display: format!("{}/{}", st.malicious + st.suspicious, r.engines_total),
    }];
    if let Some(rep) = r.reputation {
        scores.push(Score { label: "VirusTotal community reputation".into(), value: rep as f64, max: None, display: rep.to_string() });
    }
    let mut tables = Vec::new();
    if !r.flagged.is_empty() {
        tables.push(Table {
            title: "Flagging engines".into(),
            columns: vec!["Engine".into(), "Category".into(), "Result".into()],
            rows: r.flagged.iter().take(30).map(|f| vec![f.engine.clone(), f.category.clone(), f.result.clone().unwrap_or_default()]).collect(),
            note: None,
        });
    }
    model::Report {
        verdict: Some(verdict),
        scores,
        categories: r.categories.clone(),
        families: r.threat_label.iter().cloned().collect(),
        tags: r.tags.clone(),
        first_seen: None,
        last_seen: r.last_analysis_date.and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| d.to_rfc3339()),
        facts: r.details.iter().map(|d| Fact { label: d.label.clone(), value: d.value.clone() }).collect(),
        tables,
        related: vec![],
        permalink: Some(r.permalink.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn url_identifier_is_base64url_without_padding() {
        assert_eq!(base64url_nopad(b"http://example.com/"), "aHR0cDovL2V4YW1wbGUuY29tLw");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(&[0xfb, 0xff]), "-_8");
        assert_eq!(path(&detect("http://example.com/").unwrap()), "/urls/aHR0cDovL2V4YW1wbGUuY29tLw");
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
    fn maps_to_the_provider_neutral_view() {
        let ind = detect("44d88612fea8a8f36de82e1278abb02f").unwrap();
        let t = to_ti(&parse_report(&ind, &file_fixture()).unwrap());
        let v = t.verdict.unwrap();
        assert_eq!((v.level, v.label.as_str()), (model::Level::Malicious, "2 of 6 engines: malicious"));
        assert_eq!(t.scores[0].display, "3/6");
        assert_eq!(t.families, vec!["virus.eicar/test"]);
        assert_eq!(t.tables[0].rows.len(), 3);
    }

    #[tokio::test]
    async fn sends_key_only_in_header_and_parses_success() {
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"id":"8.8.8.8","attributes":{"last_analysis_stats":{"harmless":1}}}}"#)]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        let ind = detect("8.8.8.8").unwrap();
        let body = get(&c, &srv.base, &path(&ind), KEY).await.unwrap();
        assert_eq!(parse_report(&ind, &body).unwrap().stats.harmless, 1);
        let seen = srv.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.first_line(), "GET /ip_addresses/8.8.8.8 HTTP/1.1");
        assert_eq!(seen.header("x-apikey").as_deref(), Some(KEY));
    }

    #[tokio::test]
    async fn maps_api_errors_without_leaking_the_key() {
        let cases: Vec<(u16, String, ApiError)> = vec![
            (404, r#"{"error":{"code":"NotFoundError","message":"not found"}}"#.into(), ApiError::NotFound),
            (401, r#"{"error":{"code":"WrongCredentialsError","message":"Wrong API key"}}"#.into(), ApiError::Unauthorized),
            (429, r#"{"error":{"code":"QuotaExceededError","message":"Quota exceeded"}}"#.into(), ApiError::Quota("Quota exceeded".into())),
            (400, format!(r#"{{"error":{{"code":"InvalidArgumentError","message":"bad {KEY}"}}}}"#), ApiError::BadRequest("bad ••••••".into())),
            (503, "<html>down</html>".into(), ApiError::Server(503)),
        ];
        let srv = mock::serve(cases.iter().map(|(s, b, _)| mock::status(*s, b)).collect());
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        for (_, _, expected) in cases {
            let err = get(&c, &srv.base, "/domains/example.com", KEY).await.unwrap_err();
            assert_eq!(err, expected);
            assert!(!err.message(NAME).contains(KEY));
        }
    }
}
