//! Network utilities (DNS lookup, HTTP header inspection) and vulnerability
//! intelligence (NVD CVE API 2.0 with a local cache). Every request here is
//! initiated by an explicit user action; nothing runs in the background.

use std::collections::BTreeSet;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::commands::activity::log;
use crate::commands::system::{read_secret, NVD_KEY};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, http_url, now};

const USER_AGENT: &str = concat!("CyberHub/", env!("CARGO_PKG_VERSION"));

/* ─────────────── DNS ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

static HOST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?i)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.?$").unwrap());

#[tauri::command]
pub async fn dns_lookup(db: State<'_, Db>, name: String, record_type: String) -> AppResult<Vec<DnsRecord>> {
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::Resolver;

    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 253 {
        return Err(validation("Enter a host name"));
    }
    let rtype = match record_type.to_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "CNAME" => RecordType::CNAME,
        "SOA" => RecordType::SOA,
        "CAA" => RecordType::CAA,
        "PTR" => RecordType::PTR,
        "SRV" => RecordType::SRV,
        _ => return Err(validation("Unsupported record type")),
    };
    let query = if rtype == RecordType::PTR {
        let ip: std::net::IpAddr = name.parse().map_err(|_| validation("PTR lookups need an IP address"))?;
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
            }
            std::net::IpAddr::V6(v6) => {
                let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
                let mut parts: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
                parts.push("ip6.arpa.".into());
                parts.join(".")
            }
        }
    } else {
        if !HOST_RE.is_match(&name) {
            return Err(validation("Invalid host name"));
        }
        name.clone()
    };

    let resolver = Resolver::builder_tokio()
        .map_err(|e| AppError::Network(format!("Resolver configuration error: {e}")))?
        .build()
        .map_err(|e| AppError::Network(format!("Resolver configuration error: {e}")))?;
    let lookup = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query.as_str(), rtype))
        .await
        .map_err(|_| AppError::Network("DNS query timed out".into()))?;
    let records = match lookup {
        Ok(l) => l
            .answers()
            .iter()
            .map(|r| DnsRecord { record_type: r.record_type().to_string(), value: r.data.to_string(), ttl: r.ttl })
            .collect(),
        Err(e) if e.is_no_records_found() => vec![],
        Err(e) => return Err(AppError::Network(e.to_string())),
    };
    db.with(|c| log(c, "utility", &format!("DNS {record_type} lookup"), &name, None, None, None))?;
    Ok(records)
}

/* ─────────────── HTTP header inspection ─────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpInspection {
    pub url: String,
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub remote_addr: Option<String>,
    pub headers: Vec<(String, String)>,
    pub elapsed_ms: u128,
}

/// Largest NVD response accepted (a full page of 2,000 CVE records is well below this).
const MAX_NVD_BODY: usize = 32 * 1024 * 1024;

/// URL as recorded in the activity log: no user name, password, query or fragment, which can
/// carry tokens a user pasted.
fn loggable_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "(invalid URL)".into(),
    }
}

#[tauri::command]
pub async fn http_inspect(db: State<'_, Db>, url: String, method: Option<String>) -> AppResult<HttpInspection> {
    let parsed = http_url("URL", &url)?;
    let method = match method.as_deref().unwrap_or("GET").to_uppercase().as_str() {
        "HEAD" => reqwest::Method::HEAD,
        "GET" => reqwest::Method::GET,
        _ => return Err(validation("Method must be GET or HEAD")),
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .user_agent(USER_AGENT)
        .build()?;
    let start = std::time::Instant::now();
    let resp = client.request(method, parsed.clone()).send().await?;
    let elapsed_ms = start.elapsed().as_millis();
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).to_string()))
        .collect();
    let out = HttpInspection {
        url: parsed.to_string(),
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").to_string(),
        http_version: format!("{:?}", resp.version()),
        remote_addr: resp.remote_addr().map(|a| a.to_string()),
        headers,
        elapsed_ms,
    };
    drop(resp); // body is never downloaded
    db.with(|c| log(c, "utility", "HTTP header inspection", &loggable_url(&out.url), None, None, None))?;
    Ok(out)
}

/* ─────────────── CVE intelligence ─────────────── */

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssScore {
    pub version: String,
    pub score: f64,
    pub severity: String,
    pub vector: String,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CveReference {
    pub url: String,
    pub source: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CveRecord {
    pub id: String,
    pub published: String,
    pub last_modified: String,
    pub status: String,
    pub description: String,
    pub cvss: Vec<CvssScore>,
    pub cwes: Vec<String>,
    pub products: Vec<String>,
    pub references: Vec<CveReference>,
    pub kev: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveSearchResult {
    pub records: Vec<CveRecord>,
    /// "live" (fetched now from NVD) or "cache" (local database)
    pub source: String,
    pub total_results: i64,
    pub fetched_at: Option<String>,
    pub cached_at: Vec<(String, String)>,
}

static CVE_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^CVE-\d{4}-\d{4,}$").unwrap());

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

pub fn normalize_nvd(cve: &Value) -> Option<CveRecord> {
    let id = cve.get("id")?.as_str()?.to_string();
    let description = cve
        .get("descriptions")
        .and_then(Value::as_array)
        .and_then(|d| d.iter().find(|x| s(x, "lang") == "en").or_else(|| d.first()))
        .map(|d| s(d, "value"))
        .unwrap_or_default();

    let mut cvss = Vec::new();
    if let Some(metrics) = cve.get("metrics").and_then(Value::as_object) {
        for (key, version) in [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")] {
            if let Some(list) = metrics.get(key).and_then(Value::as_array) {
                for m in list {
                    let data = m.get("cvssData").cloned().unwrap_or(Value::Null);
                    let severity = data
                        .get("baseSeverity")
                        .and_then(Value::as_str)
                        .or_else(|| m.get("baseSeverity").and_then(Value::as_str))
                        .unwrap_or_default()
                        .to_string();
                    cvss.push(CvssScore {
                        version: version.into(),
                        score: data.get("baseScore").and_then(Value::as_f64).unwrap_or(0.0),
                        severity,
                        vector: s(&data, "vectorString"),
                        source: format!("{} ({})", s(m, "source"), s(m, "type")),
                    });
                }
            }
        }
    }

    let mut cwes = BTreeSet::new();
    if let Some(ws) = cve.get("weaknesses").and_then(Value::as_array) {
        for w in ws {
            if let Some(ds) = w.get("description").and_then(Value::as_array) {
                for d in ds {
                    let v = s(d, "value");
                    if v.starts_with("CWE-") {
                        cwes.insert(v);
                    }
                }
            }
        }
    }

    let mut products = BTreeSet::new();
    if let Some(cfgs) = cve.get("configurations").and_then(Value::as_array) {
        for cfg in cfgs {
            for node in cfg.get("nodes").and_then(Value::as_array).into_iter().flatten() {
                for m in node.get("cpeMatch").and_then(Value::as_array).into_iter().flatten() {
                    if m.get("vulnerable").and_then(Value::as_bool) == Some(false) {
                        continue;
                    }
                    let crit = s(m, "criteria");
                    let parts: Vec<&str> = crit.split(':').collect();
                    if parts.len() > 5 {
                        let version = match parts[5] {
                            "*" | "-" => {
                                let mut r = String::new();
                                if let Some(v) = m.get("versionStartIncluding").and_then(Value::as_str) {
                                    r.push_str(&format!(" ≥{v}"));
                                }
                                if let Some(v) = m.get("versionEndExcluding").and_then(Value::as_str) {
                                    r.push_str(&format!(" <{v}"));
                                }
                                if let Some(v) = m.get("versionEndIncluding").and_then(Value::as_str) {
                                    r.push_str(&format!(" ≤{v}"));
                                }
                                r
                            }
                            v => format!(" {v}"),
                        };
                        products.insert(format!("{}:{}{}", parts[3], parts[4], version));
                    }
                    if products.len() >= 60 {
                        break;
                    }
                }
            }
        }
    }

    let references = cve
        .get("references")
        .and_then(Value::as_array)
        .map(|rs| {
            rs.iter()
                .take(80)
                .map(|r| CveReference {
                    url: s(r, "url"),
                    source: s(r, "source"),
                    tags: r
                        .get("tags")
                        .and_then(Value::as_array)
                        .map(|t| t.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    Some(CveRecord {
        id,
        published: s(cve, "published"),
        last_modified: s(cve, "lastModified"),
        status: s(cve, "vulnStatus"),
        description,
        cvss,
        cwes: cwes.into_iter().collect(),
        products: products.into_iter().collect(),
        references,
        kev: cve.get("cisaExploitAdd").is_some(),
    })
}

fn search_cache(db: &Db, query: &str) -> AppResult<CveSearchResult> {
    db.with(|c| {
        let like = format!("%{}%", query.replace(['%', '_'], ""));
        let mut stmt = c.prepare(
            "SELECT data, fetched_at FROM cve_cache WHERE id LIKE ?1 OR data LIKE ?1 ORDER BY id DESC LIMIT 50",
        )?;
        let mut records = Vec::new();
        let mut cached_at = Vec::new();
        let rows = stmt.query_map(params![like], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (data, at) = row?;
            if let Ok(rec) = serde_json::from_str::<CveRecord>(&data) {
                cached_at.push((rec.id.clone(), at));
                records.push(rec);
            }
        }
        Ok(CveSearchResult { total_results: records.len() as i64, records, source: "cache".into(), fetched_at: None, cached_at })
    })
}

#[tauri::command]
pub async fn cve_search(db: State<'_, Db>, query: String, live: bool) -> AppResult<CveSearchResult> {
    let query = clean("Query", &query, 200, true)?;
    if !live {
        let res = search_cache(&db, &query)?;
        db.with(|c| {
            c.execute(
                "INSERT INTO cve_search_history (query, result_count, live, created_at) VALUES (?1,?2,0,?3)",
                params![query, res.total_results, now()],
            )?;
            crate::db::trim_history(c, "cve_search_history")?;
            Ok(())
        })?;
        return Ok(res);
    }

    let mut url = url::Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0").unwrap();
    if CVE_ID_RE.is_match(&query) {
        url.query_pairs_mut().append_pair("cveId", &query.to_uppercase());
    } else {
        if query.len() < 3 {
            return Err(validation("Keyword searches need at least 3 characters"));
        }
        url.query_pairs_mut()
            .append_pair("keywordSearch", &query)
            .append_pair("resultsPerPage", "40")
            .append_pair("startIndex", "0");
    }

    // no redirects: a custom `apiKey` header would otherwise be forwarded to another host
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).user_agent(USER_AGENT).redirect(reqwest::redirect::Policy::none()).build()?;
    let mut req = client.get(url);
    if let Some(key) = read_secret(NVD_KEY) {
        req = req.header("apiKey", key);
    }
    let resp = req.send().await?;
    let status = resp.status();
    if status.as_u16() == 403 || status.as_u16() == 429 {
        return Err(AppError::Network(
            "NVD rate limit reached. Wait 30 seconds or search the local cache.".into(),
        ));
    }
    if !status.is_success() {
        return Err(AppError::Network(format!("NVD returned HTTP {status}")));
    }
    // read with a size cap: a broken or hostile response must not exhaust memory
    let mut resp = resp;
    let mut raw = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if raw.len() + chunk.len() > MAX_NVD_BODY {
            return Err(AppError::Network("NVD returned an unexpectedly large response".into()));
        }
        raw.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&raw)?;
    let total = body.get("totalResults").and_then(Value::as_i64).unwrap_or(0);
    let records: Vec<CveRecord> = body
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(|vs| vs.iter().filter_map(|v| v.get("cve").and_then(normalize_nvd)).collect())
        .unwrap_or_default();
    let ts = now();
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        for r in &records {
            tx.execute(
                "INSERT INTO cve_cache (id, data, fetched_at) VALUES (?1,?2,?3)
                 ON CONFLICT(id) DO UPDATE SET data=excluded.data, fetched_at=excluded.fetched_at",
                params![r.id, serde_json::to_string(r)?, ts],
            )?;
        }
        tx.execute(
            "INSERT INTO cve_search_history (query, result_count, live, created_at) VALUES (?1,?2,1,?3)",
            params![query, total, ts],
        )?;
        crate::db::trim_history(&tx, "cve_search_history")?;
        log(&tx, "cve_search", &format!("CVE search “{query}”"), &format!("{total} results from NVD"), None, None, None)?;
        tx.commit()?;
        Ok(())
    })?;
    Ok(CveSearchResult { records, source: "live".into(), total_results: total, fetched_at: Some(ts), cached_at: vec![] })
}

/// A cached CVE record and when it was fetched (used by MCP; not an IPC command).
pub async fn cve_get_cached(db: State<'_, Db>, id: String) -> AppResult<Option<(CveRecord, String)>> {
    db.with(|c| {
        let row: Option<(String, String)> = c
            .query_row("SELECT data, fetched_at FROM cve_cache WHERE id = ?1", params![id.to_uppercase()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        Ok(row.and_then(|(d, at)| serde_json::from_str(&d).ok().map(|r| (r, at))))
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveHistoryItem {
    pub id: i64,
    pub query: String,
    pub result_count: i64,
    pub live: bool,
    pub created_at: String,
}

#[tauri::command]
pub async fn cve_history(db: State<'_, Db>) -> AppResult<Vec<CveHistoryItem>> {
    db.with(|c| {
        let mut stmt =
            c.prepare("SELECT id, query, result_count, live, created_at FROM cve_search_history ORDER BY id DESC LIMIT 50")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(CveHistoryItem {
                    id: r.get(0)?,
                    query: r.get(1)?,
                    result_count: r.get(2)?,
                    live: r.get::<_, i64>(3)? != 0,
                    created_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[tauri::command]
pub async fn cve_cache_stats(db: State<'_, Db>) -> AppResult<(i64, Option<String>)> {
    db.with(|c| Ok(c.query_row("SELECT COUNT(*), MAX(fetched_at) FROM cve_cache", [], |r| Ok((r.get(0)?, r.get(1)?)))?))
}

#[tauri::command]
pub async fn cve_history_clear(db: State<'_, Db>) -> AppResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM cve_search_history", [])?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn activity_log_urls_drop_credentials_and_queries() {
        assert_eq!(loggable_url("https://user:pw@example.org/a/b?token=abc#frag"), "https://example.org/a/b");
        assert_eq!(loggable_url("http://example.org:8080/"), "http://example.org:8080/");
        assert_eq!(loggable_url("not a url"), "(invalid URL)");
    }

    use super::*;

    #[test]
    fn normalizes_nvd_record() {
        let v: Value = serde_json::from_str(
            r#"{"id":"CVE-2021-44228","published":"2021-12-10T10:15:09.143","lastModified":"2024-01-01T00:00:00.000","vulnStatus":"Analyzed",
            "cisaExploitAdd":"2021-12-10",
            "descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI features..."}],
            "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0,"baseSeverity":"CRITICAL"}}]},
            "weaknesses":[{"description":[{"lang":"en","value":"CWE-917"},{"lang":"en","value":"NVD-CWE-Other"}]}],
            "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0.1","versionEndExcluding":"2.3.1"}]}]}],
            "references":[{"url":"https://logging.apache.org/log4j/2.x/security.html","source":"security@apache.org","tags":["Vendor Advisory"]}]}"#,
        )
        .unwrap();
        let r = normalize_nvd(&v).unwrap();
        assert_eq!(r.id, "CVE-2021-44228");
        assert_eq!(r.cvss[0].score, 10.0);
        assert_eq!(r.cvss[0].severity, "CRITICAL");
        assert_eq!(r.cwes, vec!["CWE-917"]);
        assert_eq!(r.products, vec!["apache:log4j ≥2.0.1 <2.3.1"]);
        assert!(r.kev);
    }
}
