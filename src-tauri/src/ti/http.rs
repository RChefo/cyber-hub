// SPDX-License-Identifier: Apache-2.0
//! HTTP plumbing shared by all providers.
//!
//! * Bases are fixed per provider (see `ti::ProviderId::base`); requests never follow
//!   redirects, so a response cannot bounce a request (and its credentials) elsewhere.
//! * Transport errors are reported without their URL (`without_url`) and every message that
//!   can reach the UI is scrubbed of the credential, which matters for providers that take
//!   the key as a query parameter.
//! * Response bodies are size-capped before parsing.

use std::time::Duration;

use reqwest::header::HeaderMap;
use serde_json::Value;

/// Upper bound for a JSON response body.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    /// the provider has no record of this indicator
    NotFound,
    /// key missing, wrong or not authorized
    Unauthorized,
    /// quota or rate limit exceeded (message from the provider)
    Quota(String),
    /// the plan or account does not allow this request
    Forbidden(String),
    BadRequest(String),
    Server(u16),
    Network(String),
    /// the response could not be understood
    Unexpected(String),
}

impl ApiError {
    /// Message for the UI. `provider` is the display name ("VirusTotal").
    pub fn message(&self, provider: &str) -> String {
        match self {
            ApiError::NotFound => format!("{provider} has no record of this indicator."),
            ApiError::Unauthorized => format!("{provider} rejected the configured credentials. The application owner needs to update them."),
            ApiError::Quota(m) => {
                let m = m.trim().trim_end_matches('.');
                if m.is_empty() {
                    format!("{provider} quota or rate limit reached. Try again later.")
                } else {
                    format!("{provider} quota or rate limit reached ({m}). Try again later.")
                }
            }
            ApiError::Forbidden(m) if m.is_empty() => format!("{provider} refused the request (your plan may not include it)."),
            ApiError::Forbidden(m) => format!("{provider} refused the request: {m}"),
            ApiError::BadRequest(m) => format!("{provider} did not accept the request: {m}"),
            ApiError::Server(code) => format!("{provider} is unavailable (HTTP {code}). Try again later."),
            ApiError::Network(m) => format!("Could not reach {provider}: {m}"),
            ApiError::Unexpected(m) => format!("{provider} returned an unexpected response: {m}"),
        }
    }
}

/// Remove any occurrence of the secret from text that may be shown or stored.
pub fn scrub(text: &str, secret: &str) -> String {
    if secret.len() >= 8 {
        text.replace(secret, "••••••")
    } else {
        text.to_string()
    }
}

pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    }
}

pub fn client(timeout: Duration) -> Result<reqwest::Client, String> {
    crate::tls_trust::build(
        reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION"))),
    )
}

/// Send a prepared request. Any status is returned as a `Response`; only transport
/// failures and oversized / non-JSON bodies on success become errors here.
/// A transport error without its URL, with the innermost cause (timeout, refused, TLS…), which
/// reqwest's own message ("error sending request") leaves out.
fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        return "the request timed out".into();
    }
    let e = e.without_url();
    let top = e.to_string();
    let mut cause: &dyn std::error::Error = &e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    let inner = cause.to_string();
    if inner == top { top } else { format!("{top} ({inner})") }
}

pub async fn send(rb: reqwest::RequestBuilder, secret: &str) -> Result<Response, ApiError> {
    let mut resp = rb.send().await.map_err(|e| ApiError::Network(scrub(&describe(e), secret)))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    if resp.content_length().is_some_and(|n| n as usize > MAX_BODY) {
        return Err(ApiError::Unexpected("response too large".into()));
    }
    // read incrementally so chunked responses are capped too
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| ApiError::Network(scrub(&describe(e), secret)))? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err(ApiError::Unexpected("response too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status == 200 && body.is_null() && !bytes.is_empty() {
        return Err(ApiError::Unexpected("not JSON".into()));
    }
    Ok(Response { status, headers, body })
}

/// Generic status mapping for providers that use plain HTTP semantics.
pub fn status_error(status: u16, message: String) -> ApiError {
    match status {
        404 => ApiError::NotFound,
        401 => ApiError::Unauthorized,
        429 => ApiError::Quota(message),
        402 | 403 => ApiError::Forbidden(message),
        400 | 405 | 409 | 413 | 415 | 422 => ApiError::BadRequest(message),
        s => ApiError::Server(s),
    }
}

/// Shorten provider-supplied text before it is displayed.
pub fn short(text: &str, max: usize) -> String {
    let t: String = text.chars().filter(|c| !c.is_control()).take(max).collect();
    if text.chars().count() > max {
        format!("{t}…")
    } else {
        t
    }
}

#[cfg(test)]
pub mod mock {
    //! Minimal one-request-per-connection HTTP/1.1 server for tests. It records every
    //! request (head and body) so tests can assert on what was — or was not — sent.
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct Seen {
        pub head: String,
        pub body: Vec<u8>,
    }

    impl Seen {
        pub fn first_line(&self) -> &str {
            self.head.lines().next().unwrap_or("")
        }
        pub fn header(&self, name: &str) -> Option<String> {
            self.head.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        }
    }

    pub struct Server {
        pub base: String,
        pub seen: Arc<Mutex<Vec<Seen>>>,
    }

    /// A canned response: status, extra headers, body.
    pub type Canned = (u16, Vec<(String, String)>, String);

    /// Serve canned responses in order. After they run out, further connections get 500.
    pub fn serve(responses: Vec<Canned>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            let mut queue = responses.into_iter();
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { break };
                let mut data = Vec::new();
                let mut buf = [0u8; 65536];
                // read the head
                let head_end = loop {
                    let n = match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => n,
                    };
                    data.extend_from_slice(&buf[..n]);
                    if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p + 4);
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&data[..head_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0);
                let mut body = data[head_end..].to_vec();
                while body.len() < len {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&buf[..n]),
                    }
                }
                log.lock().unwrap().push(Seen { head, body });
                let (status, headers, payload) = queue.next().unwrap_or((500, vec![], "{}".into()));
                let mut resp = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", payload.len());
                for (k, v) in headers {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n");
                resp.push_str(&payload);
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        Server { base, seen }
    }

    pub fn ok(body: &str) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], body.to_string())
    }
    pub fn status(code: u16, body: &str) -> (u16, Vec<(String, String)>, String) {
        (code, vec![], body.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_secrets_and_maps_statuses() {
        assert_eq!(scrub("key=abcdefgh123 failed", "abcdefgh123"), "key=•••••• failed");
        assert_eq!(status_error(404, String::new()), ApiError::NotFound);
        assert_eq!(status_error(429, "x".into()), ApiError::Quota("x".into()));
        assert_eq!(status_error(503, String::new()), ApiError::Server(503));
        assert_eq!(ApiError::Quota("Quota exceeded.".into()).message("VirusTotal"), "VirusTotal quota or rate limit reached (Quota exceeded). Try again later.");
        assert_eq!(short("abcdef", 3), "abc…");
    }

    #[tokio::test]
    async fn network_errors_do_not_leak_the_secret() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let secret = "s3cr3t-key-value-123";
        let c = client(Duration::from_secs(5)).unwrap();
        let err = send(c.get(format!("http://127.0.0.1:{port}/x?key={secret}")), secret).await.err().unwrap();
        assert!(matches!(err, ApiError::Network(_)));
        assert!(!err.message("Shodan").contains(secret));
    }
}
