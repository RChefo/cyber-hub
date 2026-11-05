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
use crate::sectools::{dns_intel, http, secrets, tls};
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
    db.with(|c| scope_gate::enforce(c, Some(project_id), std::slice::from_ref(&host), scope_gate::Mode::Active, "TLS analysis").map(|_| ()))?;
    let report = tls::analyze(&host, port).await.map_err(AppError::Network)?;
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
        log(c, "utility", "TLS analysis", &format!("{host}:{port} ({})", report.protocol.clone().unwrap_or_default()), Some("project"), Some(&project_id.to_string()), Some(project_id))
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

/// Sends one request built by the analyst to an in-scope target (URL host and any Host header).
#[tauri::command]
pub async fn http_send(db: State<'_, Db>, input: http::HttpRequestInput) -> AppResult<http::HttpResponseOut> {
    let prepared = http::prepare(&input).map_err(validation)?;
    db.with(|c| scope_gate::enforce(c, Some(input.project_id), &prepared.targets, scope_gate::Mode::Active, "HTTP request").map(|_| ()))?;
    let summary = format!("{} {}", prepared.method, redact_text(prepared.url.as_str()));
    let out = http::send(prepared, input.body.clone(), input.insecure).await.map_err(AppError::Network)?;
    db.with(|c| log(c, "utility", "HTTP request", &format!("{summary} → {}", out.status), Some("project"), Some(&input.project_id.to_string()), Some(input.project_id)))?;
    Ok(out)
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
            let input = http::HttpRequestInput { project_id: 1, method: "GET".into(), url: "https://example.com/".into(), headers: vec![("Host".into(), "evil.example.net".into())], body: String::new(), insecure: false };
            let p = http::prepare(&input).unwrap();
            assert!(scope_gate::enforce(c, Some(1), &p.targets, scope_gate::Mode::Active, "HTTP request").is_err(), "a Host header outside the scope is refused");
            let ok = http::prepare(&http::HttpRequestInput { headers: vec![], ..input }).unwrap();
            assert!(scope_gate::enforce(c, Some(1), &ok.targets, scope_gate::Mode::Active, "HTTP request").is_ok());
            Ok(())
        })
        .unwrap();
    }
}
