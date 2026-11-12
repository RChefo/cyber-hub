//! HTTP request builder: one request, built by the analyst, to an in-scope target. Redirects are
//! followed only when the analyst asks, at most [`MAX_REDIRECTS`], and every hop is checked like
//! the first request (scope, path, DNS) before it is sent. Requests and responses are
//! size-limited, and nothing is stored except an activity entry with credentials redacted.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
/// Redirects followed at most per request.
pub const MAX_REDIRECTS: usize = 5;
const MAX_HEADERS: usize = 50;
const MAX_BODY: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
/// Headers that servers and proxies may read as the request's host instead of `Host` (Mission 7).
const HOST_HEADERS: &[&str] = &["host", "x-forwarded-host", "x-host", "x-forwarded-server", "x-http-host-override"];
/// Headers that IIS, Symfony and some proxies read as the request's path (Mission 7).
const PATH_HEADERS: &[&str] = &["x-original-url", "x-rewrite-url"];

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
    /// follow redirects, each one checked against the scope before it is sent
    #[serde(default)]
    pub follow_redirects: bool,
}

/// A redirect that was followed.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RedirectHop {
    pub status: u16,
    pub from: String,
    pub to: String,
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
    /// redirects followed before this response (empty when none were followed)
    pub redirects: Vec<RedirectHop>,
    /// why a redirect of this response was not followed, when the analyst asked to follow them
    pub redirect_stopped: Option<String>,
}

/// Validated request parts, and the targets to check against the scope (URL host, Host header).
#[derive(Clone)]
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
    if input.url.len() > 8192 {
        return Err("The URL is limited to 8,192 characters".into());
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
        if name.as_str() == "forwarded" && v.to_ascii_lowercase().contains("host=") {
            return Err("A Forwarded header that names a host is not sent: put the host in the Host header, which is checked against the scope".into());
        }
        if PATH_HEADERS.contains(&name.as_str()) {
            // a path the server handles instead of the URL's: checked on the URL's origin, like
            // the URL itself (Mission 7)
            if !v.starts_with('/') || v.starts_with("//") || v.contains('\\') {
                return Err(format!("{k} must be a path starting with a single /"));
            }
            let path = url.join(v).map_err(|_| format!("{k} is not a valid path"))?;
            targets.push(path.to_string());
        }
        if HOST_HEADERS.contains(&name.as_str()) {
            // a different virtual host is a different target: the same scheme and path on that
            // host (and its port, if the header names one) is scope-checked too. Headers that
            // proxies read as the host are checked the same way (Mission 7)
            let mut vhost = url.clone();
            let (host, port) = match v.strip_prefix('[') {
                Some(rest) => {
                    let (h, after) = rest.split_once(']').unwrap_or((rest, ""));
                    (format!("[{h}]"), after.strip_prefix(':'))
                }
                None => match v.split_once(':') {
                    Some((h, p)) => (h.to_string(), Some(p)),
                    None => (v.to_string(), None),
                },
            };
            let port = match port {
                Some(p) => Some(p.parse::<u16>().map_err(|_| format!("The Host header {v} has an invalid port"))?),
                None => None,
            };
            // exactly one host name or address: a comma, for example, would let a shared proxy
            // read another host (Mission 7)
            let literal = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(&host);
            let one_host = crate::scope::is_host_name(&host) || literal.parse::<std::net::IpAddr>().is_ok();
            if !one_host || host.contains(['/', '@', '?', '#', '\\']) || vhost.set_host(Some(&host)).is_err() || vhost.set_port(port.or(url.port())).is_err() {
                return Err(format!("The {k} header {v} is not a valid host"));
            }
            targets.push(vhost.to_string());
        }
        let value = reqwest::header::HeaderValue::from_str(v).map_err(|_| format!("The value of {k} is not valid"))?;
        headers.append(name, value);
    }
    Ok(Prepared { method: method.parse().map_err(|_| "Invalid method".to_string())?, url, headers, targets })
}

/// What a redirect leads to: the next request, or why it is not followed. None when the response
/// is not a redirect.
pub enum Next {
    Follow { request: Box<Prepared>, keep_body: bool },
    Stop(String),
}

/// The URL for messages and the activity log: no credentials, query or fragment.
pub fn label(u: &url::Url) -> String {
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{}{port}{}", u.scheme(), u.host_str().unwrap_or(""), u.path())
}

/// The request a redirect asks for, built like the first one: its targets are the new URL only (a
/// Host header set for the first URL is dropped), credentials are dropped when the origin changes,
/// and the method follows browsers (303, and 301/302 after a POST, become GET without a body;
/// 307/308 keep the method and body).
pub fn next_request(current: &Prepared, status: u16, location: Option<&str>) -> Option<Next> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let Some(location) = location.map(str::trim).filter(|l| !l.is_empty()) else {
        return Some(Next::Stop(format!("The {status} response has no Location header")));
    };
    let next = match current.url.join(location) {
        Ok(u) => u,
        Err(_) => return Some(Next::Stop("The redirect's Location is not a valid URL".into())),
    };
    if !matches!(next.scheme(), "http" | "https") || next.host_str().is_none() {
        return Some(Next::Stop(format!("The redirect leads to {}, which is not an http or https URL", label(&next))));
    }
    let to_get = status == 303 && current.method != reqwest::Method::HEAD || matches!(status, 301 | 302) && current.method == reqwest::Method::POST;
    let method = if to_get { reqwest::Method::GET } else { current.method.clone() };
    let same_origin = next.origin() == current.url.origin();
    let mut headers = current.headers.clone();
    // headers that chose the host or the path were checked for the first URL only
    for h in HOST_HEADERS.iter().chain(PATH_HEADERS) {
        headers.remove(*h);
    }
    if !same_origin {
        // every header that carries a credential stays with its origin: the standard ones, and
        // any whose name says it is one (`X-Api-Key`, `PRIVATE-TOKEN`), Mission 7
        let credentials: Vec<reqwest::header::HeaderName> = headers
            .keys()
            .filter(|n| matches!(*n, &reqwest::header::AUTHORIZATION | &reqwest::header::COOKIE | &reqwest::header::PROXY_AUTHORIZATION) || crate::redact::secret_name(n.as_str()))
            .cloned()
            .collect();
        for h in credentials {
            headers.remove(h);
        }
    }
    if to_get {
        headers.remove(reqwest::header::CONTENT_TYPE);
    }
    Some(Next::Follow { request: Box::new(Prepared { method, targets: vec![next.to_string()], url: next, headers }), keep_body: !to_get })
}

/// Sends the request. `pin` holds the vetted addresses of the URL's host name: the client
/// connects only to them (no second DNS resolution).
pub async fn send(p: Prepared, body: String, insecure: bool, pin: Option<(String, Vec<std::net::SocketAddr>)>) -> Result<HttpResponseOut, String> {
    // straight to the vetted addresses: a system proxy would resolve names itself
    let mut builder = reqwest::Client::builder().no_proxy();
    if let Some((host, addrs)) = &pin {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    let client = crate::tls_trust::build(
        builder
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(insecure)
            .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION"))),
    )?;
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
            format!("The service did not answer with valid HTTP ({})", root_cause(&e))
        }
    })?;
    let status = resp.status();
    let version = format!("{:?}", resp.version());
    let headers = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).to_string())).collect();
    let mut resp = resp;
    let mut raw = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp.chunk().await.map_err(|e| if e.is_timeout() { "The response did not finish within 20 seconds".to_string() } else { format!("The response ended early or was not valid ({})", root_cause(&e)) })? {
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
        redirects: Vec::new(),
        redirect_stopped: None,
    })
}

/// The innermost error message (reqwest's own text only repeats the URL).
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(method: &str, url: &str, headers: &[(&str, &str)]) -> HttpRequestInput {
        HttpRequestInput { project_id: 1, method: method.into(), url: url.into(), headers: headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), body: String::new(), insecure: false, follow_redirects: false }
    }

    #[test]
    fn redirects_become_new_checked_requests() {
        let mut first = prepare(&input("POST", "https://app.example.com/api/login", &[("Host", "app.example.com"), ("Authorization", "Bearer x"), ("Content-Type", "application/json")])).unwrap();
        first.headers.insert(reqwest::header::COOKIE, "s=1".parse().unwrap());
        assert!(next_request(&first, 200, Some("/x")).is_none(), "not a redirect");
        let Some(Next::Follow { request, keep_body }) = next_request(&first, 302, Some("/api/home?x=1")) else { panic!("a relative redirect is followed") };
        assert_eq!((request.method.as_str(), keep_body), ("GET", false), "302 after POST becomes GET");
        assert_eq!(request.targets, vec!["https://app.example.com/api/home?x=1".to_string()], "the new URL is the only target");
        assert!(request.headers.get(reqwest::header::HOST).is_none(), "the Host header of the first URL is not reused");
        assert!(request.headers.get(reqwest::header::AUTHORIZATION).is_some(), "same origin keeps credentials");
        assert!(request.headers.get(reqwest::header::CONTENT_TYPE).is_none());
        let Some(Next::Follow { request, keep_body }) = next_request(&first, 307, Some("https://sso.example.com/api/login")) else { panic!() };
        assert_eq!((request.method.as_str(), keep_body), ("POST", true), "307 keeps the method and body");
        assert!(request.headers.get(reqwest::header::AUTHORIZATION).is_none() && request.headers.get(reqwest::header::COOKIE).is_none(), "another origin gets no credentials");
        for (status, loc) in [(301, None), (302, Some("javascript:alert(1)")), (308, Some("file:///etc/passwd")), (303, Some("ftp://x.example.com/"))] {
            assert!(matches!(next_request(&first, status, loc), Some(Next::Stop(_))), "{status} {loc:?}");
        }
        let head = prepare(&input("HEAD", "https://a.example.com/", &[])).unwrap();
        let Some(Next::Follow { request, .. }) = next_request(&head, 303, Some("/b")) else { panic!() };
        assert_eq!(request.method.as_str(), "HEAD", "HEAD stays HEAD");
        assert_eq!(label(&url::Url::parse("https://u:p@a.example.com:8443/x?token=1#f").unwrap()), "https://a.example.com:8443/x");
    }

    /// Mission 7: on another origin, every header whose name says it carries a credential is
    /// dropped, not only the standard ones; headers that chose the host or the path are not reused.
    #[test]
    fn credential_headers_stay_with_their_origin() {
        let first = prepare(&input("GET", "https://app.example.com/api/", &[("X-Api-Key", "k1"), ("PRIVATE-TOKEN", "t1"), ("X-Auth-Token", "a1"), ("Accept", "text/html"), ("X-Forwarded-Host", "app.example.com")])).unwrap();
        for to in ["http://app.example.com/api/", "https://other.example.com/api/"] {
            let Some(Next::Follow { request, .. }) = next_request(&first, 302, Some(to)) else { panic!("{to}") };
            for h in ["x-api-key", "private-token", "x-auth-token", "x-forwarded-host"] {
                assert!(request.headers.get(h).is_none(), "{h} sent to {to}");
            }
            assert!(request.headers.get("accept").is_some());
        }
        let Some(Next::Follow { request, .. }) = next_request(&first, 302, Some("/api/next")) else { panic!() };
        assert!(request.headers.get("x-api-key").is_some(), "the same origin keeps them");
    }

    /// Mission 7: a header that names a host names exactly one, and headers that servers and
    /// proxies read as the host or the path are scope-checked like the Host header.
    #[test]
    fn routing_headers_are_scope_checked() {
        let url = "https://app.example.com/api/";
        assert!(prepare(&input("GET", url, &[("Host", "victim.other.net,app.example.com")])).is_err());
        assert!(prepare(&input("GET", url, &[("Host", "a b.example.com")])).is_err());
        assert!(prepare(&input("GET", url, &[("Host", "app.example.com")])).is_ok());
        let p = prepare(&input("GET", url, &[("X-Forwarded-Host", "admin.example.com")])).unwrap();
        assert!(p.targets.contains(&"https://admin.example.com/api/".to_string()), "{:?}", p.targets);
        assert!(prepare(&input("GET", url, &[("X-Host", "victim.other.net,app.example.com")])).is_err());
        let p = prepare(&input("GET", url, &[("X-Original-URL", "/admin/delete?id=1")])).unwrap();
        assert!(p.targets.contains(&"https://app.example.com/admin/delete?id=1".to_string()), "{:?}", p.targets);
        for bad in ["//evil.example.net/x", "https://evil.example.net/", "admin", "/a\\b"] {
            assert!(prepare(&input("GET", url, &[("X-Rewrite-URL", bad)])).is_err(), "{bad}");
        }
        assert!(prepare(&input("GET", url, &[("Forwarded", "for=192.0.2.1;host=admin.example.com")])).is_err());
        assert!(prepare(&input("GET", url, &[("Forwarded", "for=192.0.2.1")])).is_ok());
    }

    #[test]
    fn requests_are_validated() {
        let p = prepare(&input("post", "https://app.example.com/login?x=1", &[("Content-Type", "application/json"), ("Host", "admin.example.com:8443")])).unwrap();
        assert_eq!(p.method, reqwest::Method::POST);
        assert_eq!(p.targets, vec!["https://app.example.com/login?x=1".to_string(), "https://admin.example.com:8443/login?x=1".into()], "a Host header is a target too: the same path on that virtual host");
        assert!(prepare(&input("TRACE", "https://a.example.com", &[])).is_err());
        assert_eq!(prepare(&input("GET", "https://a.example.com", &[("Host", "[2001:db8::1]:8443")])).unwrap().targets[1], "https://[2001:db8::1]:8443/");
        assert_eq!(prepare(&input("GET", "https://a.example.com:8443/x", &[("Host", "b.example.com")])).unwrap().targets[1], "https://b.example.com:8443/x", "without a port the URL's port stays");
        for bad in ["evil.net/x", "user@evil.net", "a.example.com:99999"] {
            assert!(prepare(&input("GET", "https://a.example.com/", &[("Host", bad)])).is_err(), "{bad}");
        }
        assert!(prepare(&input("GET", &format!("https://a.example.com/{}", "a".repeat(9000)), &[])).is_err());
        assert!(prepare(&input("GET", "ftp://a.example.com", &[])).is_err());
        assert!(prepare(&input("GET", "a.example.com", &[])).is_err());
        assert!(prepare(&input("GET", "https://a.example.com", &[("X-Test", "a\r\nInjected: 1")])).is_err(), "header injection");
        assert!(prepare(&input("GET", "https://a.example.com", &[("Bad Name", "x")])).is_err());
        assert!(prepare(&input("GET", "https://a.example.com", &[("Content-Length", "5")])).is_err());
        let many: Vec<(&str, &str)> = (0..51).map(|_| ("X-A", "1")).collect();
        assert!(prepare(&input("GET", "https://a.example.com", &many)).is_err());
    }

    #[tokio::test]
    async fn a_service_that_does_not_speak_http_gets_a_readable_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(b"\x00\x01garbage-not-http\r\n\r\n").await;
        });
        let p = prepare(&input("GET", &format!("http://{addr}/"), &[])).unwrap();
        let err = send(p, String::new(), false, None).await.unwrap_err();
        assert!(err.starts_with("The service did not answer with valid HTTP ("), "{err}");
        assert!(!err.contains("error sending request"), "{err}");
    }
}
