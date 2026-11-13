//! Shodan REST API — `GET /shodan/host/{ip}` (exposed services) and `GET /api-info` (plan).
//!
//! Shodan's API takes the key as the `key` query parameter. The request URL is therefore
//! never logged or shown: transport errors are reported without their URL and every message
//! is scrubbed of the key (see `ti::http`).
//!
//! Shodan describes exposure, not maliciousness, so results are informational (Level::Info).

use serde_json::Value;

use super::http::{self, ApiError, Response};
use super::indicator::Indicator;
use super::model::{tidy, Level, Parsed, Report, Score, Table, Verdict};

pub fn map_error(resp: &Response, key: &str) -> ApiError {
    let msg = http::scrub(&http::short(resp.body.get("error").and_then(Value::as_str).unwrap_or(""), 200), key);
    match resp.status {
        401 => ApiError::Unauthorized,
        404 => ApiError::NotFound,
        s => http::status_error(s, msg),
    }
}

pub async fn lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<Parsed, ApiError> {
    let resp = http::send(client.get(format!("{base}/shodan/host/{}", ind.value)).query(&[("key", key)]), key).await?;
    match resp.status {
        200 => parse(&resp.body),
        404 => Ok(Parsed::none()),
        _ => Err(map_error(&resp, key)),
    }
}

#[cfg(any(test, feature = "provisioning"))]
/// Validate a key and describe the plan (`/api-info`; costs no credits).
pub async fn validate(client: &reqwest::Client, base: &str, key: &str) -> Result<Option<String>, ApiError> {
    let resp = http::send(client.get(format!("{base}/api-info")).query(&[("key", key)]), key).await?;
    if resp.status != 200 {
        return Err(map_error(&resp, key));
    }
    let b = &resp.body;
    let plan = b.get("plan").and_then(Value::as_str).unwrap_or("unknown");
    let q = b.get("query_credits").and_then(Value::as_i64).unwrap_or(0);
    let sc = b.get("scan_credits").and_then(Value::as_i64).unwrap_or(0);
    Ok(Some(format!("Plan {plan} · {q} query credits · {sc} scan credits")))
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| match x {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        // `vulns` is sometimes an object keyed by CVE id
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        _ => vec![],
    }
}

pub fn parse(b: &Value) -> Result<Parsed, ApiError> {
    if !b.is_object() {
        return Err(ApiError::Unexpected("not an object".into()));
    }
    let ip = s(b, "ip_str").unwrap_or_default();
    let mut ports: Vec<i64> = b.get("ports").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
    ports.sort_unstable();
    ports.dedup();
    let services = b.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut vulns = strings(b.get("vulns"));
    for svc in &services {
        vulns.extend(strings(svc.get("vulns")));
    }
    vulns.sort();
    vulns.dedup();

    let mut r = Report { permalink: (!ip.is_empty()).then(|| format!("https://www.shodan.io/host/{ip}")), ..Default::default() };
    r.verdict = Some(Verdict {
        level: Level::Info,
        label: format!(
            "{} open port{}{}",
            ports.len(),
            if ports.len() == 1 { "" } else { "s" },
            if vulns.is_empty() { String::new() } else { format!(" · {} CVE tag{}", vulns.len(), if vulns.len() == 1 { "" } else { "s" }) }
        ),
    });
    r.scores.push(Score { label: "Open ports".into(), value: ports.len() as f64, max: None, display: ports.len().to_string() });
    r.tags = tidy(strings(b.get("tags")), 15);
    r.categories = tidy(vulns.clone(), 40);
    r.last_seen = s(b, "last_update");
    r.fact("Ports", (!ports.is_empty()).then(|| ports.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")));
    r.fact("Organization", s(b, "org"));
    r.fact("ISP", s(b, "isp"));
    r.fact("ASN", s(b, "asn"));
    r.fact("Operating system", s(b, "os"));
    r.fact("Location", match (s(b, "city"), s(b, "country_name")) {
        (Some(c), Some(n)) => Some(format!("{c}, {n}")),
        (None, n) => n,
        (c, None) => c,
    });
    let hostnames = strings(b.get("hostnames"));
    let domains = strings(b.get("domains"));
    r.fact("Hostnames", (!hostnames.is_empty()).then(|| hostnames.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
    for h in hostnames.iter().chain(domains.iter()).take(15) {
        r.relate(h, "hostname / domain");
    }
    if !vulns.is_empty() {
        r.fact("CVE tags", Some(format!("{} (from service metadata, not verified)", vulns.len())));
    }
    if !services.is_empty() {
        r.tables.push(Table {
            title: "Services".into(),
            columns: vec!["Port".into(), "Product".into(), "Module".into(), "Seen".into()],
            rows: services
                .iter()
                .take(25)
                .map(|svc| {
                    let port = format!("{}/{}", s(svc, "port").unwrap_or_default(), s(svc, "transport").unwrap_or_else(|| "tcp".into()));
                    let product = [s(svc, "product"), s(svc, "version")].into_iter().flatten().collect::<Vec<_>>().join(" ");
                    vec![port, product, svc.pointer("/_shodan/module").and_then(Value::as_str).unwrap_or("").to_string(), s(svc, "timestamp").unwrap_or_default()]
                })
                .collect(),
            note: Some("Banners are collected by Shodan's crawlers; ExploitX does not contact the host.".into()),
        });
    }
    Ok(Parsed::found(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;
    use crate::ti::indicator::detect;

    const KEY: &str = "ShodanTestKey0123456789abcdefABCD";

    fn fixture() -> String {
        serde_json::json!({
            "ip_str": "93.184.216.34", "ports": [443, 80, 80], "hostnames": ["web.example-cdn.net"], "domains": ["example-cdn.net"],
            "org": "Example CDN", "isp": "Example ISP", "asn": "AS15133", "os": null, "country_name": "United States", "city": "Norwell",
            "last_update": "2026-10-30T12:00:00.000000", "tags": ["cdn"], "vulns": ["CVE-2023-44487"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "ECAcc", "version": "1.0", "timestamp": "2026-10-30T12:00:00", "_shodan": {"module": "http"}},
                {"port": 443, "transport": "tcp", "timestamp": "2026-10-29T12:00:00", "_shodan": {"module": "https"}, "vulns": {"CVE-2023-44487": {}, "CVE-2024-0001": {}}}
            ]
        })
        .to_string()
    }

    #[test]
    fn parses_ports_services_and_cve_tags() {
        let p = parse(&serde_json::from_str(&fixture()).unwrap()).unwrap();
        let v = p.report.verdict.unwrap();
        assert_eq!((v.level, v.label.as_str()), (Level::Info, "2 open ports · 2 CVE tags"));
        assert_eq!(p.report.categories, vec!["CVE-2023-44487", "CVE-2024-0001"]);
        assert_eq!(p.report.tables[0].rows[0], vec!["80/tcp", "ECAcc 1.0", "http", "2026-10-30T12:00:00"]);
        assert!(p.report.related.iter().any(|r| r.value == "example-cdn.net"));
    }

    #[tokio::test]
    async fn never_leaks_the_query_key_in_errors() {
        let srv = mock::serve(vec![
            mock::ok(&fixture()),
            mock::status(404, r#"{"error":"No information available for that IP."}"#),
            mock::status(403, &format!(r#"{{"error":"Access denied for key {KEY}"}}"#)),
            mock::status(401, r#"{"error":"Invalid API key"}"#),
            mock::ok(r#"{"plan":"dev","query_credits":100,"scan_credits":0}"#),
        ]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        let ind = detect("93.184.216.34").unwrap();
        assert!(lookup(&c, &srv.base, KEY, &ind).await.unwrap().found);
        assert!(!lookup(&c, &srv.base, KEY, &ind).await.unwrap().found);
        let e = lookup(&c, &srv.base, KEY, &ind).await.unwrap_err();
        assert!(matches!(e, ApiError::Forbidden(_)));
        assert!(!e.message("Shodan").contains(KEY));
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap_err(), ApiError::Unauthorized);
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap().as_deref(), Some("Plan dev · 100 query credits · 0 scan credits"));
        assert_eq!(srv.seen.lock().unwrap()[0].first_line(), format!("GET /shodan/host/93.184.216.34?key={KEY} HTTP/1.1"));
    }
}
