// SPDX-License-Identifier: Apache-2.0
//! AlienVault OTX DirectConnect API — `GET /indicators/{type}/{indicator}/general`.
//!
//! OTX does not issue verdicts. It reports the community "pulses" (threat reports) that
//! reference an indicator. Mapping:
//! * on an OTX allow-list (`validation`) → Clean
//! * referenced by ≥ 1 pulse → Suspicious ("Referenced in N OTX pulses")
//! * no pulses → no record

use serde_json::Value;

use super::http::{self, ApiError, Response};
use super::indicator::{Indicator, Kind};
use super::model::{min_max, tidy, Level, Parsed, Report, Score, Table, Verdict};

/// OTX path type for an indicator.
pub fn otx_type(ind: &Indicator) -> &'static str {
    match ind.kind {
        Kind::Ip if ind.is_ipv6() => "IPv6",
        Kind::Ip => "IPv4",
        Kind::Domain if ind.value.split('.').count() > 2 => "hostname",
        Kind::Domain => "domain",
        Kind::Url => "url",
        Kind::File => "file",
    }
}

fn ui_type(ind: &Indicator) -> &'static str {
    match otx_type(ind) {
        "IPv4" | "IPv6" => "ip",
        t => t,
    }
}

fn encode(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

pub fn map_error(resp: &Response) -> ApiError {
    let detail = resp.body.get("detail").and_then(Value::as_str).map(|s| http::short(s, 200)).unwrap_or_default();
    match resp.status {
        401 | 403 => ApiError::Unauthorized,
        s => http::status_error(s, detail),
    }
}

pub async fn lookup(client: &reqwest::Client, base: &str, key: &str, ind: &Indicator) -> Result<Parsed, ApiError> {
    let url = format!("{base}/indicators/{}/{}/general", otx_type(ind), encode(&ind.value));
    let resp = http::send(client.get(url).header("X-OTX-API-KEY", key).header("Accept", "application/json"), key).await?;
    if resp.status != 200 {
        return Err(map_error(&resp));
    }
    parse(ind, &resp.body)
}

#[cfg(any(test, feature = "provisioning"))]
/// Validate a key: the subscribed-pulses endpoint requires authentication.
pub async fn validate(client: &reqwest::Client, base: &str, key: &str) -> Result<Option<String>, ApiError> {
    let resp = http::send(client.get(format!("{base}/pulses/subscribed")).query(&[("limit", "1")]).header("X-OTX-API-KEY", key), key).await?;
    if resp.status != 200 {
        return Err(map_error(&resp));
    }
    Ok(None)
}

fn names(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(_) => x.get("display_name").or_else(|| x.get("name")).and_then(Value::as_str).map(str::to_string),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse(ind: &Indicator, body: &Value) -> Result<Parsed, ApiError> {
    if !body.is_object() {
        return Err(ApiError::Unexpected("not an object".into()));
    }
    let info = body.get("pulse_info").cloned().unwrap_or(Value::Null);
    let count = info.get("count").and_then(Value::as_i64).unwrap_or(0);
    let pulses = info.get("pulses").and_then(Value::as_array).cloned().unwrap_or_default();
    let str_of = |k: &str| body.get(k).and_then(|x| match x {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    });

    let mut r = Report { permalink: Some(format!("https://otx.alienvault.com/indicator/{}/{}", ui_type(ind), encode(&ind.value))), ..Default::default() };

    let allow: Vec<String> = body
        .get("validation")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.get("message").or_else(|| v.get("name")).and_then(Value::as_str).map(str::to_string)).collect())
        .unwrap_or_default();

    r.verdict = Some(if !allow.is_empty() {
        Verdict { level: Level::Clean, label: format!("On an OTX allow-list ({})", http::short(&allow[0], 80)) }
    } else if count > 0 {
        Verdict { level: Level::Suspicious, label: format!("Referenced in {count} OTX pulse{}", if count == 1 { "" } else { "s" }) }
    } else {
        Verdict { level: Level::Unknown, label: "Not referenced in any OTX pulse".into() }
    });
    r.scores.push(Score { label: "Pulses".into(), value: count as f64, max: None, display: count.to_string() });
    if let Some(rep) = body.get("reputation").and_then(Value::as_i64).filter(|r| *r != 0) {
        r.scores.push(Score { label: "OTX reputation".into(), value: rep as f64, max: None, display: rep.to_string() });
    }

    let mut families = Vec::new();
    let mut tags = Vec::new();
    let mut adversaries = Vec::new();
    let mut attack = Vec::new();
    for p in &pulses {
        families.extend(names(p.get("malware_families")));
        tags.extend(names(p.get("tags")));
        attack.extend(names(p.get("attack_ids")));
        if let Some(a) = p.get("adversary").and_then(Value::as_str).filter(|a| !a.is_empty()) {
            adversaries.push(a.to_string());
        }
    }
    if let Some(rel) = info.get("related") {
        for side in ["alienvault", "other"] {
            families.extend(names(rel.pointer(&format!("/{side}/malware_families"))));
            adversaries.extend(names(rel.pointer(&format!("/{side}/adversary"))));
        }
    }
    r.families = tidy(families, 15);
    r.tags = tidy(tags, 25);
    r.categories = tidy(attack, 15);
    r.fact("Adversaries", Some(tidy(adversaries, 8).join(", ")));
    r.fact("Country", str_of("country_name"));
    r.fact("ASN", str_of("asn"));
    r.fact("Type", str_of("type_title"));
    r.fact("Allow-list", (!allow.is_empty()).then(|| allow.join("; ")));
    let (first, _) = min_max(pulses.iter().filter_map(|p| p.get("created").and_then(Value::as_str).map(str::to_string)));
    let (_, last) = min_max(pulses.iter().filter_map(|p| p.get("modified").and_then(Value::as_str).map(str::to_string)));
    r.first_seen = first;
    r.last_seen = last;

    if !pulses.is_empty() {
        r.tables.push(Table {
            title: "Pulses".into(),
            columns: vec!["Pulse".into(), "Author".into(), "Modified".into(), "Malware families".into()],
            rows: pulses
                .iter()
                .take(10)
                .map(|p| {
                    vec![
                        http::short(p.get("name").and_then(Value::as_str).unwrap_or(""), 140),
                        p.pointer("/author/username").or_else(|| p.get("author_name")).and_then(Value::as_str).unwrap_or("").to_string(),
                        p.get("modified").and_then(Value::as_str).unwrap_or("").to_string(),
                        names(p.get("malware_families")).join(", "),
                    ]
                })
                .collect(),
            note: (count as usize > pulses.len().min(10)).then(|| format!("Showing {} of {count} pulses.", pulses.len().min(10))),
        });
    }

    Ok(if count > 0 || !allow.is_empty() { Parsed::found(r) } else { Parsed::none_with(r) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;
    use crate::ti::indicator::detect;

    const KEY: &str = "otx-test-key-0123456789abcdef";

    fn fixture() -> String {
        serde_json::json!({
            "indicator": "evil-domain.xyz", "type_title": "Domain", "validation": [],
            "pulse_info": {"count": 2, "pulses": [
                {"id": "p1", "name": "Phishing kit wave", "created": "2026-09-01T00:00:00", "modified": "2026-10-01T00:00:00",
                 "author": {"username": "analyst1"}, "tags": ["phishing", "kit"], "adversary": "",
                 "malware_families": [{"id": "Agent Tesla", "display_name": "Agent Tesla"}], "attack_ids": [{"id": "T1566", "display_name": "T1566 - Phishing"}]},
                {"id": "p2", "name": "Stealer infra", "created": "2026-08-15T00:00:00", "modified": "2026-10-20T00:00:00",
                 "author": {"username": "analyst2"}, "tags": ["Phishing"], "adversary": "TA-Example", "malware_families": ["FormBook"]}
            ], "related": {"alienvault": {"malware_families": ["Agent Tesla"], "adversary": []}, "other": {"malware_families": [], "adversary": []}}}
        })
        .to_string()
    }

    #[test]
    fn parses_pulses_into_families_tags_and_dates() {
        let ind = detect("evil-domain.xyz").unwrap();
        let p = parse(&ind, &serde_json::from_str(&fixture()).unwrap()).unwrap();
        assert!(p.found);
        assert_eq!(p.report.verdict.as_ref().unwrap().label, "Referenced in 2 OTX pulses");
        assert_eq!(p.report.families, vec!["Agent Tesla", "FormBook"]);
        assert_eq!(p.report.tags, vec!["phishing", "kit"]);
        assert_eq!(p.report.first_seen.as_deref(), Some("2026-08-15T00:00:00"));
        assert_eq!(p.report.last_seen.as_deref(), Some("2026-10-20T00:00:00"));
        assert!(p.report.facts.iter().any(|f| f.label == "Adversaries" && f.value == "TA-Example"));

        let none = parse(&ind, &serde_json::json!({"pulse_info": {"count": 0, "pulses": []}, "validation": []})).unwrap();
        assert!(!none.found);
        let clean = parse(&ind, &serde_json::json!({"pulse_info": {"count": 0}, "validation": [{"source": "alexa", "message": "Alexa top 1000"}]})).unwrap();
        assert_eq!(clean.report.verdict.unwrap().level, Level::Clean);
    }

    #[test]
    fn builds_type_specific_paths() {
        assert_eq!(otx_type(&detect("8.8.8.8").unwrap()), "IPv4");
        assert_eq!(otx_type(&detect("2001:4860:4860::8888").unwrap()), "IPv6");
        assert_eq!(otx_type(&detect("a.b.example.org").unwrap()), "hostname");
        assert_eq!(otx_type(&detect(&"c".repeat(64)).unwrap()), "file");
    }

    #[tokio::test]
    async fn sends_key_in_header_and_encodes_urls() {
        let srv = mock::serve(vec![mock::ok(&fixture()), mock::status(403, r#"{"detail":"Authentication required"}"#)]);
        let c = http::client(std::time::Duration::from_secs(5)).unwrap();
        let ind = detect("https://evil-domain.xyz/a b?x=1").unwrap();
        assert!(lookup(&c, &srv.base, KEY, &ind).await.unwrap().found);
        let seen = srv.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.first_line(), "GET /indicators/url/https%3A%2F%2Fevil-domain.xyz%2Fa+b%3Fx%3D1/general HTTP/1.1");
        assert_eq!(seen.header("x-otx-api-key").as_deref(), Some(KEY));
        assert_eq!(validate(&c, &srv.base, KEY).await.unwrap_err(), ApiError::Unauthorized);
    }
}
