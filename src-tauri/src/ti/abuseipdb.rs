//! AbuseIPDB APIv2 — `GET /check` (IP reputation from community abuse reports).
//!
//! Verdict mapping (the provider gives a 0–100 "abuse confidence score", no verdict):
//! * whitelisted by AbuseIPDB → Clean
//! * score ≥ 75 → Malicious, 25–74 → Suspicious
//! * reported but score < 25 → Unknown ("low confidence")
//! * no reports in the window → no record
//!
//! The original score is always shown next to the bucket.

use serde_json::Value;

use super::http::{self, ApiError, Response};
use super::indicator::Indicator;
use super::model::{tidy, Level, Parsed, Report, Score, Table, Verdict};

pub const MAX_AGE_DAYS: u32 = 90;

/// Category IDs from https://www.abuseipdb.com/categories
pub fn category(id: i64) -> Option<&'static str> {
    Some(match id {
        1 => "DNS Compromise",
        2 => "DNS Poisoning",
        3 => "Fraud Orders",
        4 => "DDoS Attack",
        5 => "FTP Brute-Force",
        6 => "Ping of Death",
        7 => "Phishing",
        8 => "Fraud VoIP",
        9 => "Open Proxy",
        10 => "Web Spam",
        11 => "Email Spam",
        12 => "Blog Spam",
        13 => "VPN IP",
        14 => "Port Scan",
        15 => "Hacking",
        16 => "SQL Injection",
        17 => "Spoofing",
        18 => "Brute-Force",
        19 => "Bad Web Bot",
        20 => "Exploited Host",
        21 => "Web App Attack",
        22 => "SSH",
        23 => "IoT Targeted",
        _ => return None,
    })
}

fn error_detail(body: &Value) -> String {
    body.pointer("/errors/0/detail").and_then(Value::as_str).map(|s| http::short(s, 200)).unwrap_or_default()
}

pub fn map_error(resp: &Response) -> ApiError {
    let detail = error_detail(&resp.body);
    match resp.status {
        401 | 403 => ApiError::Unauthorized,
        s => http::status_error(s, detail),
    }
}

/// "812 of 1000 daily checks left" from the rate-limit headers.
pub fn quota(resp: &Response) -> Option<String> {
    let remaining = resp.header("x-ratelimit-remaining")?;
    let limit = resp.header("x-ratelimit-limit")?;
    Some(format!("{remaining} of {limit} daily checks left"))
}

pub fn request(client: &reqwest::Client, base: &str, key: &str, ip: &str, max_age: u32) -> reqwest::RequestBuilder {
    client
        .get(format!("{base}/check"))
        .query(&[("ipAddress", ip), ("maxAgeInDays", &max_age.to_string())])
        .query(&[("verbose", "")])
        .header("Key", key)
        .header("Accept", "application/json")
}

pub async fn lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<(Parsed, Option<String>), ApiError> {
    let resp = http::send(request(client, base, key, &ind.value, MAX_AGE_DAYS), key).await?;
    if resp.status != 200 {
        return Err(map_error(&resp));
    }
    Ok((parse(&resp.body)?, quota(&resp)))
}

#[cfg(any(test, feature = "provisioning"))]
/// Validate a key with one check of a fixed public address. Returns the quota line.
pub async fn validate(client: &reqwest::Client, base: &str, key: &str) -> Result<Option<String>, ApiError> {
    let resp = http::send(request(client, base, key, "8.8.8.8", 1), key).await?;
    if resp.status != 200 {
        return Err(map_error(&resp));
    }
    Ok(quota(&resp))
}

pub fn parse(body: &Value) -> Result<Parsed, ApiError> {
    let d = body.get("data").filter(|d| d.is_object()).ok_or_else(|| ApiError::Unexpected("missing data".into()))?;
    let ip = d.get("ipAddress").and_then(Value::as_str).unwrap_or_default().to_string();
    let score = d.get("abuseConfidenceScore").and_then(Value::as_f64).unwrap_or(0.0);
    let total = d.get("totalReports").and_then(Value::as_i64).unwrap_or(0);
    let whitelisted = d.get("isWhitelisted").and_then(Value::as_bool) == Some(true);
    let str_of = |k: &str| d.get(k).and_then(Value::as_str).map(str::to_string);

    let mut r = Report { permalink: Some(format!("https://www.abuseipdb.com/check/{ip}")), ..Default::default() };
    r.scores.push(Score {
        label: "Abuse confidence score".into(),
        value: score,
        max: Some(100.0),
        display: format!("{score:.0}%"),
    });
    r.verdict = Some(if whitelisted {
        Verdict { level: Level::Clean, label: "Whitelisted by AbuseIPDB".into() }
    } else if score >= 75.0 {
        Verdict { level: Level::Malicious, label: format!("Abuse confidence {score:.0}% · {total} reports") }
    } else if score >= 25.0 {
        Verdict { level: Level::Suspicious, label: format!("Abuse confidence {score:.0}% · {total} reports") }
    } else if total > 0 {
        Verdict { level: Level::Unknown, label: format!("Low abuse confidence ({score:.0}%) · {total} reports") }
    } else {
        Verdict { level: Level::Unknown, label: format!("No reports in the last {MAX_AGE_DAYS} days") }
    });

    r.fact("ISP", str_of("isp"));
    r.fact("Usage type", str_of("usageType"));
    r.fact("Domain", str_of("domain"));
    r.fact("Country", str_of("countryName").or_else(|| str_of("countryCode")));
    let hostnames: Vec<String> =
        d.get("hostnames").and_then(Value::as_array).map(|a| a.iter().filter_map(|h| h.as_str().map(str::to_string)).collect()).unwrap_or_default();
    r.fact("Hostnames", (!hostnames.is_empty()).then(|| hostnames.iter().take(5).cloned().collect::<Vec<_>>().join(", ")));
    if d.get("isTor").and_then(Value::as_bool) == Some(true) {
        r.fact("Tor exit node", Some("Yes".into()));
    }
    r.fact("Reports", Some(total.to_string()));
    r.fact("Distinct reporters", d.get("numDistinctUsers").and_then(Value::as_i64).map(|n| n.to_string()));
    r.last_seen = str_of("lastReportedAt");
    for h in &hostnames {
        r.relate(h, "hostname");
    }

    // categories across reports, most frequent first
    let reports = d.get("reports").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut counts: Vec<(String, usize)> = Vec::new();
    for rep in &reports {
        for c in rep.get("categories").and_then(Value::as_array).into_iter().flatten() {
            if let Some(name) = c.as_i64().and_then(category) {
                match counts.iter_mut().find(|(n, _)| n == name) {
                    Some(e) => e.1 += 1,
                    None => counts.push((name.to_string(), 1)),
                }
            }
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    r.categories = tidy(counts.iter().map(|(n, c)| format!("{n} ({c})")).collect(), 12);
    if let Some(first) = reports.iter().filter_map(|x| x.get("reportedAt").and_then(Value::as_str)).min() {
        r.first_seen = Some(first.to_string());
    }
    if !reports.is_empty() {
        r.tables.push(Table {
            title: "Recent reports".into(),
            columns: vec!["Reported".into(), "Categories".into(), "Reporter country".into(), "Comment".into()],
            rows: reports
                .iter()
                .take(10)
                .map(|x| {
                    let cats: Vec<&str> = x.get("categories").and_then(Value::as_array).into_iter().flatten().filter_map(|c| c.as_i64().and_then(category)).collect();
                    vec![
                        x.get("reportedAt").and_then(Value::as_str).unwrap_or("").to_string(),
                        cats.join(", "),
                        x.get("reporterCountryName").or_else(|| x.get("reporterCountryCode")).and_then(Value::as_str).unwrap_or("").to_string(),
                        http::short(x.get("comment").and_then(Value::as_str).unwrap_or(""), 160),
                    ]
                })
                .collect(),
            note: Some(format!("Reports from the last {MAX_AGE_DAYS} days; comments are written by reporters.")),
        });
    }

    Ok(if total > 0 || whitelisted { Parsed::found(r) } else { Parsed::none_with(r) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;

    const KEY: &str = "abuseipdb-test-key-0123456789";

    fn fixture(score: i64, total: i64) -> String {
        serde_json::json!({"data": {
            "ipAddress": "203.0.113.9", "isPublic": true, "ipVersion": 4, "isWhitelisted": false,
            "abuseConfidenceScore": score, "countryCode": "NL", "countryName": "Netherlands",
            "usageType": "Data Center/Web Hosting/Transit", "isp": "Example Hosting", "domain": "example.net",
            "hostnames": ["scanner.example.net"], "isTor": false, "totalReports": total, "numDistinctUsers": 4,
            "lastReportedAt": "2026-10-30T10:00:00+00:00",
            "reports": [
                {"reportedAt": "2026-10-30T10:00:00+00:00", "comment": "ssh brute force", "categories": [18, 22], "reporterId": 1, "reporterCountryCode": "DE", "reporterCountryName": "Germany"},
                {"reportedAt": "2026-10-20T10:00:00+00:00", "comment": "", "categories": [14], "reporterId": 2, "reporterCountryCode": "US", "reporterCountryName": "United States"}
            ]}})
        .to_string()
    }

    #[test]
    fn parses_scores_categories_and_buckets() {
        let p = parse(&serde_json::from_str(&fixture(87, 12)).unwrap()).unwrap();
        assert!(p.found);
        let v = p.report.verdict.unwrap();
        assert_eq!((v.level, v.label.as_str()), (Level::Malicious, "Abuse confidence 87% · 12 reports"));
        assert_eq!(p.report.scores[0].display, "87%");
        assert_eq!(p.report.categories, vec!["Brute-Force (1)", "Port Scan (1)", "SSH (1)"]);
        assert_eq!(p.report.first_seen.as_deref(), Some("2026-10-20T10:00:00+00:00"));
        assert_eq!(p.report.tables[0].rows.len(), 2);
        assert_eq!(p.report.related[0].value, "scanner.example.net");

        assert_eq!(parse(&serde_json::from_str(&fixture(30, 3)).unwrap()).unwrap().report.verdict.unwrap().level, Level::Suspicious);
        let none = parse(&serde_json::from_str(&fixture(0, 0)).unwrap()).unwrap();
        assert!(!none.found);
        assert!(none.report.facts.iter().any(|f| f.label == "ISP"));
    }

    #[tokio::test]
    async fn sends_key_in_header_and_reads_quota() {
        let srv = mock::serve(vec![(
            200,
            vec![("X-RateLimit-Limit".into(), "1000".into()), ("X-RateLimit-Remaining".into(), "998".into())],
            fixture(87, 12),
        )]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        let ind = crate::ti::indicator::detect("185.220.101.5").unwrap();
        let (p, q) = lookup(&c, &srv.base, KEY, &ind).await.unwrap();
        assert!(p.found);
        assert_eq!(q.as_deref(), Some("998 of 1000 daily checks left"));
        let seen = srv.seen.lock().unwrap()[0].clone();
        assert!(seen.first_line().starts_with("GET /check?ipAddress=185.220.101.5&maxAgeInDays=90&verbose"));
        assert!(!seen.first_line().contains(KEY));
        assert_eq!(seen.header("key").as_deref(), Some(KEY));
    }

    #[tokio::test]
    async fn maps_errors() {
        let srv = mock::serve(vec![
            mock::status(401, r#"{"errors":[{"detail":"Authentication failed","status":401}]}"#),
            mock::status(429, r#"{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint.","status":429}]}"#),
        ]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap_err(), ApiError::Unauthorized);
        let e = validate(&c, &srv.base, KEY).await.unwrap_err();
        assert!(matches!(e, ApiError::Quota(ref m) if m.contains("Daily rate limit")));
    }
}
