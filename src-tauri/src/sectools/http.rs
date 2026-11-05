//! HTTP request builder: one request, built by the analyst, to an in-scope target. Redirects are
//! never followed (the Location is shown), requests and responses are size-limited, and nothing
//! is stored except an activity entry with credentials redacted.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const MAX_HEADERS: usize = 50;
const MAX_BODY: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequestInput {
    pub project_id: i64,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
    /// accept certificates that are not trusted (testing self-signed services)
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpResponseOut {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_bytes: usize,
    pub truncated: bool,
    pub elapsed_ms: u64,
}

/// Validated request parts, and the targets to check against the scope (URL host, Host header).
pub struct Prepared {
    pub method: reqwest::Method,
    pub url: url::Url,
    pub headers: reqwest::header::HeaderMap,
    pub targets: Vec<String>,
}

pub fn prepare(input: &HttpRequestInput) -> Result<Prepared, String> {
    let method = input.method.trim().to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(format!("The method must be one of {}", METHODS.join(", ")));
    }
    let url = url::Url::parse(input.url.trim()).map_err(|_| "Enter a full http:// or https:// URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("Enter a full http:// or https:// URL".into());
    }
    if input.headers.len() > MAX_HEADERS {
        return Err(format!("At most {MAX_HEADERS} headers"));
    }
    if input.body.len() > MAX_BODY {
        return Err("The body is limited to 1 MB".into());
    }
    let mut headers = reqwest::header::HeaderMap::new();
    let mut targets = vec![url.to_string()];
    for (k, v) in &input.headers {
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            continue;
        }
        if v.len() > 8192 || v.contains(['\r', '\n', '\0']) {
            return Err(format!("The value of {k} is too long or contains line breaks"));
        }
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).map_err(|_| format!("{k} is not a valid header name"))?;
        if name == reqwest::header::CONTENT_LENGTH || name == reqwest::header::TRANSFER_ENCODING {
            return Err(format!("{k} is set automatically"));
        }
        if name == reqwest::header::HOST {
            // a different virtual host is a different target: it is scope-checked too
            targets.push(v.split(':').next().unwrap_or(v).to_string());
        }
        let value = reqwest::header::HeaderValue::from_str(v).map_err(|_| format!("The value of {k} is not valid"))?;
        headers.append(name, value);
    }
    Ok(Prepared { method: method.parse().map_err(|_| "Invalid method".to_string())?, url, headers, targets })
}

pub async fn send(p: Prepared, body: String, insecure: bool) -> Result<HttpResponseOut, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(insecure)
        .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut rb = client.request(p.method, p.url).headers(p.headers);
    if !body.is_empty() {
        rb = rb.body(body);
    }
    let resp = rb.send().await.map_err(|e| {
        if crate::updates::is_certificate_error(&e) {
            "The certificate is not trusted. Turn on “Accept untrusted certificates” to test this service anyway.".to_string()
        } else if e.is_timeout() {
            "No answer within 20 seconds".to_string()
        } else if e.is_connect() {
            "Could not connect".to_string()
        } else {
            e.to_string()
        }
    })?;
    let status = resp.status();
    let version = format!("{:?}", resp.version());
    let headers = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).to_string())).collect();
    let mut resp = resp;
    let mut raw = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if raw.len() + chunk.len() > MAX_RESPONSE {
            raw.extend_from_slice(&chunk[..MAX_RESPONSE - raw.len()]);
            truncated = true;
            break;
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(HttpResponseOut {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
        version,
        headers,
        body_bytes: raw.len(),
        body: String::from_utf8_lossy(&raw).to_string(),
        truncated,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(method: &str, url: &str, headers: &[(&str, &str)]) -> HttpRequestInput {
        HttpRequestInput { project_id: 1, method: method.into(), url: url.into(), headers: headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), body: String::new(), insecure: false }
    }

    #[test]
    fn requests_are_validated() {
        let p = prepare(&input("post", "https://app.example.com/login?x=1", &[("Content-Type", "application/json"), ("Host", "admin.example.com:8443")])).unwrap();
        assert_eq!(p.method, reqwest::Method::POST);
        assert_eq!(p.targets, vec!["https://app.example.com/login?x=1".to_string(), "admin.example.com".into()], "a Host header is a target too");
        assert!(prepare(&input("TRACE", "https://a.example.com", &[])).is_err());
        assert!(prepare(&input("GET", "ftp://a.example.com", &[])).is_err());
        assert!(prepare(&input("GET", "a.example.com", &[])).is_err());
        assert!(prepare(&input("GET", "https://a.example.com", &[("X-Test", "a\r\nInjected: 1")])).is_err(), "header injection");
        assert!(prepare(&input("GET", "https://a.example.com", &[("Bad Name", "x")])).is_err());
        assert!(prepare(&input("GET", "https://a.example.com", &[("Content-Length", "5")])).is_err());
        let many: Vec<(&str, &str)> = (0..51).map(|_| ("X-A", "1")).collect();
        assert!(prepare(&input("GET", "https://a.example.com", &many)).is_err());
    }
}
