//! Commands of the security utilities (see `sectools`). Utilities that contact a target (TLS
//! analysis, HTTP requests) need a project and pass the active scope gate; DNS intelligence is a
//! passive lookup through the system resolver; the secrets scanner and the port reference are local.

use rusqlite::params;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::commands::activity::log;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::redact::redact_text;
use crate::sectools::{containers, dns_intel, http, secrets, tls};
use crate::workspace::{assets, scope_gate};

/// Host and port of a TLS target ("host", "host:port", "[v6]:port" or a URL).
pub fn tls_target(raw: &str, port: Option<u16>) -> AppResult<(String, u16)> {
    let raw = raw.trim();
    let (host, p) = if raw.contains("://") {
        let u = url::Url::parse(raw).map_err(|_| validation("Not a valid URL"))?;
        (u.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_string(), u.port_or_known_default())
    } else if let Some(rest) = raw.strip_prefix('[') {
        let (h, p) = rest.split_once(']').ok_or_else(|| validation("Invalid IPv6 address"))?;
        (h.to_string(), p.strip_prefix(':').and_then(|x| x.parse().ok()))
    } else if raw.matches(':').count() == 1 {
        let (h, p) = raw.split_once(':').unwrap_or((raw, ""));
        (h.to_string(), Some(p.parse().map_err(|_| validation("Invalid port"))?))
    } else {
        (raw.to_string(), None)
    };
    let port = port.or(p).unwrap_or(443);
    if port == 0 {
        return Err(validation("Invalid port"));
    }
    match crate::scope::parse_target(&host) {
        Some(crate::scope::Target::Host(_)) | Some(crate::scope::Target::Ip(_)) => Ok((host.to_ascii_lowercase(), port)),
        _ => Err(validation("Enter a host name or IP address")),
    }
}

/// Analyzes the TLS service of an in-scope host and records its certificate as a project asset.
#[tauri::command]
pub async fn tls_analyze(db: State<'_, Db>, project_id: i64, target: String, port: Option<u16>) -> AppResult<tls::TlsReport> {
    let (host, port) = tls_target(&target, port)?;
    let entries = db.with(|c| {
        scope_gate::enforce(c, Some(project_id), std::slice::from_ref(&host), scope_gate::Mode::Active, "TLS analysis")?;
        crate::commands::projects::scope_entries(c, project_id)
    })?;
    let addrs = match scope_gate::resolve_vetted(&entries, &host, port).await {
        Ok(a) => a,
        Err(reason) => {
            db.with(|c| scope_gate::record_blocked(c, project_id, &host, &reason, "TLS analysis"))?;
            return Err(AppError::Scope(format!("TLS analysis was not started. {reason}")));
        }
    };
    let report = tls::analyze(&host, port, &addrs).await.map_err(AppError::Network)?;
    db.with(|c| {
        if let Some(leaf) = report.chain.first() {
            let input = assets::AssetInput {
                project_id,
                kind: "certificate".into(),
                value: leaf.sha256.clone(),
                source: "tls".into(),
                confidence: Some("high".into()),
                osint_entity_id: None,
                data: Some(serde_json::json!({
                    "certainty": "confirmed", "subject": leaf.subject, "issuer": leaf.issuer, "notAfter": leaf.not_after,
                    "names": leaf.sans.iter().take(20).collect::<Vec<_>>(), "seenOn": [format!("{host}:{port}")], "trusted": report.trusted,
                })),
            };
            assets::upsert_observation(c, &input, None)?;
        }
        let protocol = report.protocol.clone().unwrap_or_default();
        crate::workspace::timeline::record(c, project_id, "utility", &format!("TLS analysis: {host}:{port}"), &protocol, None, None)?;
        log(c, "utility", "TLS analysis", &format!("{host}:{port} ({protocol})"), Some("project"), Some(&project_id.to_string()), Some(project_id))
    })?;
    Ok(report)
}

/// DNS records and an e-mail/CAA/DNSSEC assessment for a public domain.
#[tauri::command]
pub async fn dns_intel(db: State<'_, Db>, project_id: Option<i64>, domain: String) -> AppResult<dns_intel::DnsIntel> {
    let domain = crate::osint::normalize::domain(&domain).map_err(|_| validation("Enter a domain name such as example.com"))?;
    db.with(|c| scope_gate::enforce(c, project_id, std::slice::from_ref(&domain), scope_gate::Mode::Passive, "DNS intelligence").map(|_| ()))?;
    let out = dns_intel::collect(&domain).await.map_err(AppError::Network)?;
    db.with(|c| log(c, "utility", "DNS intelligence", &domain, None, None, project_id))?;
    Ok(out)
}

/// The addresses a request may connect to: its host resolved and vetted (refusals are recorded).
async fn vetted_pin(db: &Db, project_id: i64, url: &url::Url, operation: &str) -> AppResult<Option<(String, Vec<std::net::SocketAddr>)>> {
    let entries = db.with(|c| crate::commands::projects::scope_entries(c, project_id))?;
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    match scope_gate::resolve_vetted(&entries, &host, port).await {
        Ok(addrs) => Ok((host.parse::<std::net::IpAddr>().is_err() && !host.starts_with('[')).then_some((host, addrs))),
        Err(reason) => {
            db.with(|c| scope_gate::record_blocked(c, project_id, &host, &reason, operation))?;
            Err(AppError::Scope(format!("{operation} was not sent. {reason}")))
        }
    }
}

/// Sends one request built by the analyst to an in-scope target (the URL, and the same path on any
/// Host header). With `follow_redirects`, each redirect is a new request that is checked the same
/// way before it is sent; a refused redirect ends the chain with its reason.
#[tauri::command]
pub async fn http_send(db: State<'_, Db>, input: http::HttpRequestInput) -> AppResult<http::HttpResponseOut> {
    send_checked(&db, input).await
}

/// [`http_send`] without the app state (tested directly).
pub(crate) async fn send_checked(db: &Db, input: http::HttpRequestInput) -> AppResult<http::HttpResponseOut> {
    let mut current = http::prepare(&input).map_err(validation)?;
    db.with(|c| scope_gate::enforce(c, Some(input.project_id), &current.targets, scope_gate::Mode::Active, "HTTP request").map(|_| ()))?;
    let mut pin = vetted_pin(db, input.project_id, &current.url, "HTTP request").await?;
    let first = format!("{} {}", current.method, redact_text(current.url.as_str()));
    // the project timeline shows the URL without its query
    let shown = format!("{} {}", current.method, http::label(&current.url));
    let mut body = input.body.clone();
    let mut hops: Vec<http::RedirectHop> = Vec::new();
    loop {
        let sent = current.clone();
        let mut out = http::send(current, body.clone(), input.insecure, pin).await.map_err(AppError::Network)?;
        let location = out.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone());
        let next = if input.follow_redirects { http::next_request(&sent, out.status, location.as_deref()) } else { None };
        let stop = |out: &mut http::HttpResponseOut, why: String| out.redirect_stopped = Some(why);
        match next {
            None => {}
            Some(http::Next::Stop(why)) => stop(&mut out, why),
            Some(http::Next::Follow { .. }) if hops.len() >= http::MAX_REDIRECTS => stop(&mut out, format!("More than {} redirects; the last one was not followed", http::MAX_REDIRECTS)),
            Some(http::Next::Follow { request, keep_body }) => {
                let to = http::label(&request.url);
                // the redirect target is checked exactly like a request the analyst typed
                let checked = db.with(|c| scope_gate::enforce(c, Some(input.project_id), &request.targets, scope_gate::Mode::Active, "HTTP redirect").map(|_| ()));
                let vetted = match checked {
                    Ok(()) => vetted_pin(db, input.project_id, &request.url, "HTTP redirect").await,
                    Err(e) => Err(e),
                };
                match vetted {
                    Ok(next_pin) => {
                        hops.push(http::RedirectHop { status: out.status, from: http::label(&sent.url), to });
                        current = *request;
                        pin = next_pin;
                        if !keep_body {
                            body.clear();
                        }
                        continue;
                    }
                    Err(e) => stop(&mut out, format!("The redirect to {to} was not followed: {}", e.to_string().trim_start_matches("HTTP redirect was not started. ").trim_start_matches("HTTP redirect was not sent. "))),
                }
            }
        }
        out.redirects = hops;
        let chain = if out.redirects.is_empty() { String::new() } else { format!(" after {}", crate::workspace::discovery::plural(out.redirects.len(), "redirect", "redirects")) };
        db.with(|c| {
            crate::workspace::timeline::record(c, input.project_id, "utility", &format!("HTTP request: {shown} → {}{chain}", out.status), out.redirect_stopped.as_deref().unwrap_or(""), None, None)?;
            log(c, "utility", "HTTP request", &format!("{first} → {}{chain}", out.status), Some("project"), Some(&input.project_id.to_string()), Some(input.project_id))
        })?;
        return Ok(out);
    }
}

#[tauri::command]
pub async fn leak_scan_text(text: String) -> AppResult<secrets::ScanResult> {
    if text.len() > 5 * 1024 * 1024 {
        return Err(validation("Paste at most 5 MB"));
    }
    let mut hits = Vec::new();
    secrets::scan_text("pasted text", &text, &mut hits, secrets::MAX_HITS);
    Ok(secrets::ScanResult { truncated: hits.len() >= secrets::MAX_HITS, hits, files_scanned: 1, files_skipped: 0 })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathScan {
    pub root: String,
    pub result: secrets::ScanResult,
}

/// Checks pasted text as a Dockerfile, Compose file or Kubernetes manifest (`kind`: auto,
/// dockerfile, compose, kubernetes). Nothing is contacted.
#[tauri::command]
pub async fn container_scan_text(text: String, kind: String) -> AppResult<containers::FileReport> {
    if text.len() > containers::MAX_TEXT {
        return Err(validation(format!("The text is larger than {} MB", containers::MAX_TEXT / 1024 / 1024)));
    }
    if !["auto", "dockerfile", "compose", "kubernetes"].contains(&kind.as_str()) {
        return Err(validation("Unknown file type"));
    }
    containers::analyze("pasted text", &text, &kind).ok_or_else(|| validation("This is not a Dockerfile, Compose file or Kubernetes manifest. Choose the type if it is one."))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerScan {
    pub root: String,
    pub result: containers::ScanResult,
}

/// Choose a file or folder (native dialog) and check the container configurations in it locally.
/// None when cancelled.
#[tauri::command]
pub async fn container_scan_pick(app: AppHandle, folder: bool) -> AppResult<Option<ContainerScan>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title(if folder { "Check a folder for container configurations" } else { "Check a container configuration" });
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    let send = move |p: Option<tauri_plugin_dialog::FilePath>| {
        let _ = tx.send(p.and_then(|f| f.into_path().ok()));
    };
    if folder {
        d.pick_folder(send);
    } else {
        d.pick_file(send);
    }
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let root = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string_lossy().to_string());
    let result = tauri::async_runtime::spawn_blocking(move || containers::scan_path(&path)).await.map_err(|e| AppError::Internal(format!("check failed: {e}")))?;
    Ok(Some(ContainerScan { root, result }))
}

/// Choose a file or folder (native dialog) and scan it locally. None when cancelled.
#[tauri::command]
pub async fn leak_scan_pick(app: AppHandle, folder: bool) -> AppResult<Option<PathScan>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title(if folder { "Scan a folder for secrets" } else { "Scan a file for secrets" });
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    let send = move |p: Option<tauri_plugin_dialog::FilePath>| {
        let _ = tx.send(p.and_then(|f| f.into_path().ok()));
    };
    if folder {
        d.pick_folder(send);
    } else {
        d.pick_file(send);
    }
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let root = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string_lossy().to_string());
    let result = tauri::async_runtime::spawn_blocking(move || secrets::scan_path(&path)).await.map_err(|e| AppError::Internal(format!("scan failed: {e}")))?;
    Ok(Some(PathScan { root, result }))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortSighting {
    pub project_id: i64,
    pub project: String,
    pub asset_id: i64,
    pub value: String,
    pub service: String,
    pub product: String,
    pub last_seen: String,
}

/// Where a port was seen as an open service in recorded assets (all projects).
#[tauri::command]
pub async fn services_by_port(db: State<'_, Db>, port: u16) -> AppResult<Vec<PortSighting>> {
    db.with(|c| {
        let mut st = c.prepare(
            "SELECT a.project_id, p.name, a.id, a.value, a.data, a.last_seen FROM assets a JOIN projects p ON p.id = a.project_id
             WHERE a.type = 'service' AND (a.value LIKE '%:' || ?1 || '/tcp' OR a.value LIKE '%:' || ?1 || '/udp') ORDER BY a.last_seen DESC LIMIT 500",
        )?;
        let rows = st
            .query_map(params![port], |r| {
                let data: serde_json::Value = serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default();
                Ok(PortSighting {
                    project_id: r.get(0)?,
                    project: r.get(1)?,
                    asset_id: r.get(2)?,
                    value: r.get(3)?,
                    service: data["service"].as_str().unwrap_or("").to_string(),
                    product: [data["product"].as_str().unwrap_or(""), data["version"].as_str().unwrap_or("")].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" "),
                    last_seen: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_targets_are_parsed() {
        assert_eq!(tls_target("https://App.Example.com:8443/x", None).unwrap(), ("app.example.com".into(), 8443));
        assert_eq!(tls_target("mail.example.com:465", None).unwrap(), ("mail.example.com".into(), 465));
        assert_eq!(tls_target("[2001:db8::1]:993", None).unwrap(), ("2001:db8::1".into(), 993));
        assert_eq!(tls_target("192.0.2.1", Some(8443)).unwrap(), ("192.0.2.1".into(), 8443));
        assert_eq!(tls_target("example.com", None).unwrap().1, 443);
        for bad in ["", "a b", "example.com:0", "example.com:http", "10.0.0.0/8"] {
            assert!(tls_target(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn active_utilities_refuse_out_of_scope_targets() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (1,'example.com','domain',1,'t')", [])?;
            let input = http::HttpRequestInput { project_id: 1, method: "GET".into(), url: "https://example.com/".into(), headers: vec![("Host".into(), "evil.example.net".into())], body: String::new(), insecure: false, follow_redirects: false };
            let p = http::prepare(&input).unwrap();
            assert!(scope_gate::enforce(c, Some(1), &p.targets, scope_gate::Mode::Active, "HTTP request").is_err(), "a Host header outside the scope is refused");
            let ok = http::prepare(&http::HttpRequestInput { headers: vec![], ..input }).unwrap();
            assert!(scope_gate::enforce(c, Some(1), &ok.targets, scope_gate::Mode::Active, "HTTP request").is_ok());
            Ok(())
        })
        .unwrap();
    }

    /// A local server: `/api/start` redirects to `/api/next`, which redirects outside the
    /// authorized path to `/admin`. Returns the port and the count of requests to `/admin`.
    async fn redirecting_server() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let admin = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = admin.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let resp = match path.as_str() {
                        "/api/start" => "HTTP/1.1 302 Found
Location: /api/next
Content-Length: 0
Connection: close

".to_string(),
                        "/api/next" => format!("HTTP/1.1 302 Found
Location: http://127.0.0.1:{port}/admin
Content-Length: 0
Connection: close

"),
                        _ => {
                            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            "HTTP/1.1 200 OK
Content-Length: 6
Connection: close

secret".to_string()
                        }
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (port, admin)
    }

    #[tokio::test]
    async fn every_redirect_is_checked_before_it_is_followed() {
        let (port, admin) = redirecting_server().await;
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (1, ?1, 'url', 1, 't')", [format!("http://127.0.0.1:{port}/api/")])?;
            Ok(())
        })
        .unwrap();
        let input = |follow: bool| http::HttpRequestInput { project_id: 1, method: "GET".into(), url: format!("http://127.0.0.1:{port}/api/start"), headers: vec![], body: String::new(), insecure: false, follow_redirects: follow };
        // not followed unless asked
        let out = send_checked(&db, input(false)).await.unwrap();
        assert_eq!((out.status, out.redirects.len(), out.redirect_stopped.is_none()), (302, 0, true));
        // followed inside the path, stopped at the hop that leaves it
        let out = send_checked(&db, input(true)).await.unwrap();
        assert_eq!(out.status, 302, "the response that asked for the refused redirect");
        assert_eq!(out.redirects, vec![http::RedirectHop { status: 302, from: format!("http://127.0.0.1:{port}/api/start"), to: format!("http://127.0.0.1:{port}/api/next") }]);
        let why = out.redirect_stopped.unwrap();
        assert!(why.contains("/admin was not followed") && why.contains("outside the authorized URLs"), "{why}");
        assert_eq!(admin.load(std::sync::atomic::Ordering::SeqCst), 0, "the refused URL was never requested");
        let blocked: i64 = db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM scope_events WHERE action = 'blocked' AND source = 'HTTP redirect'", [], |r| r.get(0))?)).unwrap();
        assert_eq!(blocked, 1, "the refused redirect is in the scope history");
        // requests sent to the target are on the project timeline, without their query
        let sent: Vec<(String, String)> = db
            .with(|c| Ok(c.prepare("SELECT title, detail FROM timeline_events WHERE type = 'utility' ORDER BY id")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?))
            .unwrap();
        assert!(sent.iter().any(|(t, d)| t.starts_with("HTTP request: GET http://127.0.0.1:") && t.contains("→ 302 after 1 redirect") && d.contains("was not followed")), "{sent:?}");
    }

    #[test]
    fn requests_in_path_scoped_projects_stay_inside_the_paths() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1,'P','active','t','t')", [])?;
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (1,'https://app.example.com/api/','url',1,'t')", [])?;
            let req = |url: &str, host: Option<&str>| http::HttpRequestInput { project_id: 1, method: "GET".into(), url: url.into(), headers: host.map(|h| vec![("Host".to_string(), h.to_string())]).unwrap_or_default(), body: String::new(), insecure: false, follow_redirects: false };
            let enforce = |i: &http::HttpRequestInput| scope_gate::enforce(c, Some(1), &http::prepare(i).unwrap().targets, scope_gate::Mode::Active, "HTTP request");
            assert!(enforce(&req("https://app.example.com/api/v1?x=1", None)).is_ok());
            assert!(enforce(&req("https://app.example.com/api/v1", Some("app.example.com"))).is_ok(), "the same virtual host");
            for (url, host) in [("https://app.example.com/login", None), ("https://app.example.com/api/v1", Some("admin.example.com")), ("https://app.example.com/api/v1", Some("app.example.com:8443"))] {
                let err = enforce(&req(url, host)).unwrap_err().to_string();
                assert!(err.contains("HTTP request was not sent") || err.contains("was not started"), "{url} {host:?}: {err}");
            }
            Ok(())
        })
        .unwrap();
    }
}
