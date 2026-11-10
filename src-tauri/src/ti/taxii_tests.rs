//! TAXII 2.1 against a local mock server (127.0.0.1, accepted over HTTP in debug builds only).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::db::Db;

type Route = dyn Fn(&str, &HashMap<String, String>) -> (u16, Vec<(String, String)>, String) + Send + Sync;

/// A one-thread HTTP/1.1 server: every request is logged as "<path?query>|<accept>|<authorization>".
fn mock(route: Arc<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut first = String::new();
            if reader.read_line(&mut first).is_err() {
                continue;
            }
            let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut headers = HashMap::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            log2.lock().unwrap().push(format!("{target}|{}|{}", headers.get("accept").cloned().unwrap_or_default(), headers.get("authorization").cloned().unwrap_or_default()));
            let (status, extra, body) = route(&target, &headers);
            let mut head = format!("HTTP/1.1 {status} X\r\nContent-Type: {MEDIA}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
            for (k, v) in extra {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(body.as_bytes());
        }
    });
    (base, log)
}

fn ind(id: u32, pattern: &str, modified: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut o = json!({
        "type": "indicator", "spec_version": "2.1", "id": format!("indicator--00000000-0000-4000-8000-{id:012}"),
        "created": "2026-11-01T00:00:00Z", "modified": modified, "pattern": pattern, "pattern_type": "stix", "valid_from": "2026-11-01T00:00:00Z",
        "name": format!("Indicator {id}")
    });
    if let (Some(o), Some(e)) = (o.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    o
}

#[test]
fn urls_must_be_https_without_credentials() {
    assert_eq!(check_url("https://taxii.example.org/taxii2").unwrap().as_str(), "https://taxii.example.org/taxii2/");
    assert!(check_url("http://taxii.example.org/taxii2/").unwrap_err().contains("HTTPS"));
    assert!(check_url("http://127.0.0.1:9/taxii2/").is_ok(), "loopback over HTTP in debug builds (tests)");
    assert!(check_url("https://user:pw@taxii.example.org/taxii2/").unwrap_err().contains("no user name"));
    assert!(check_url("https://taxii.example.org/taxii2/?x=1").is_err());
    assert!(check_url("ftp://taxii.example.org/").is_err());
    assert!(check_url("not a url").is_err());
}

#[test]
fn only_simple_equality_patterns_are_read() {
    assert_eq!(pattern_values("[ipv4-addr:value = '8.8.4.4']").unwrap(), vec!["8.8.4.4"]);
    assert_eq!(pattern_values("[domain-name:value = 'evil.example.net'] OR [url:value = 'https://evil.example.net/a']").unwrap().len(), 2);
    assert_eq!(pattern_values("[file:hashes.'SHA-256' = 'aa'] OR [file:hashes.MD5 = 'bb']").unwrap(), vec!["aa", "bb"]);
    assert_eq!(pattern_values(r"[url:value = 'https://x.example.net/it\'s']").unwrap(), vec!["https://x.example.net/it's"]);
    for (p, why) in [
        ("[ipv4-addr:value = '1.2.3.4' AND ipv4-addr:value = '5.6.7.8']", "more than one term"),
        ("[ipv4-addr:value != '1.2.3.4']", "simple equality"),
        ("[file:name MATCHES '^x']", "equality"),
        ("[ipv4-addr:value = '1.2.3.4'] WITHIN 300 SECONDS", "OR"),
        ("[ipv4-addr:value = '1.2.3.4'] FOLLOWEDBY [ipv4-addr:value = '5.6.7.8']", "OR"),
        ("[process:name = 'x']", "not imported"),
        ("[ipv4-addr:value = '1.2.3.4", "closing quote"),
        ("ipv4-addr:value = '1.2.3.4'", "brackets"),
    ] {
        let e = pattern_values(p).unwrap_err();
        assert!(e.contains(why), "{p}: {e}");
    }
    let ok = indicator(&ind(1, "[ipv4-addr:value = '8.8.4.4']", "2026-11-02T00:00:00Z", json!({ "confidence": 80, "valid_until": "2026-12-31T00:00:00Z" }))).unwrap();
    assert_eq!((ok.confidence, ok.valid_until.as_deref(), ok.revoked), (Some(80), Some("2026-12-31"), false));
    assert!(indicator(&json!({ "type": "malware", "id": "malware--1" })).unwrap_err().contains("malware objects"));
    assert!(indicator(&ind(2, "alert tcp any any", "x", json!({ "pattern_type": "snort" }))).unwrap_err().contains("other than STIX"));
}

/// A server with one API root and one collection whose objects come in two pages.
fn feed_server(fail_second_page: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let route: Arc<Route> = Arc::new(move |target: &str, headers: &HashMap<String, String>| {
        let ok = |v: serde_json::Value| (200, vec![], v.to_string());
        if target == "/taxii2/" {
            return ok(json!({ "title": "Test feeds", "api_roots": ["/api1/", "https://elsewhere.example.org/api9/"] }));
        }
        if !headers.get("authorization").is_some_and(|a| a.starts_with("Basic ")) {
            return (401, vec![], json!({ "title": "Unauthorized", "description": "credentials s3cr3t-pass wrong" }).to_string());
        }
        if target == "/api1/collections/" {
            return ok(json!({ "collections": [
                { "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "title": "High-confidence C2", "can_read": true, "can_write": false },
                { "id": "../../etc", "title": "bad id", "can_read": true, "can_write": false }
            ] }));
        }
        if target.starts_with("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/") {
            if target.contains("next=p2") {
                if fail_second_page {
                    return (500, vec![], "{}".into());
                }
                return (200, vec![("X-TAXII-Date-Added-Last".into(), "2026-11-09T12:00:00.000Z".into())], json!({ "more": false, "objects": [
                    ind(3, "[url:value = 'https://phish.example.net/login']", "2026-11-09T00:00:00Z", json!({ "revoked": true })),
                    ind(4, "[ipv4-addr:value = '10.1.2.3']", "2026-11-09T00:00:00Z", json!({}))
                ] }).to_string());
            }
            if target.contains("added_after=2026-11-09T12") {
                // the next synchronization: a newer version of indicator 1
                return ok(json!({ "more": false, "objects": [ind(1, "[ipv4-addr:value = '8.8.4.4']", "2026-11-10T00:00:00Z", json!({ "confidence": 40 }))] }));
            }
            return (200, vec![("X-TAXII-Date-Added-Last".into(), "2026-11-09T10:00:00.000Z".into())], json!({ "more": true, "next": "p2", "objects": [
                ind(1, "[ipv4-addr:value = '8.8.4.4']", "2026-11-02T00:00:00Z", json!({ "confidence": 85, "valid_until": "2027-01-31T00:00:00Z" })),
                ind(2, "[domain-name:value = 'saved-by-analyst.example.net'] OR [domain-name:value = 'dismissed.example.net']", "2026-11-02T00:00:00Z", json!({ "confidence": 60 })),
                json!({ "type": "malware", "id": "malware--1", "name": "x" }),
                ind(5, "[ipv4-addr:value = '203.0.113.5' AND ipv4-addr:value = '203.0.113.6']", "2026-11-02T00:00:00Z", json!({}))
            ] }).to_string());
        }
        (404, vec![], json!({ "title": "Not found" }).to_string())
    });
    mock(route)
}

fn status_of(db: &Db, value: &str) -> (String, Option<i64>, String) {
    db.with(|c| Ok(c.query_row("SELECT status, confidence, source FROM ti_saved WHERE indicator = ?1", params![value], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?)).unwrap()
}

#[tokio::test]
async fn a_feed_is_discovered_synchronized_incrementally_and_never_overrides_the_analyst() {
    let (base, log) = feed_server(false);
    let db = Db::open_in_memory().unwrap();
    let sid = db
        .with(|c| server_save(c, &ServerInput { id: None, name: "Partner".into(), discovery_url: format!("{base}/taxii2/"), auth: "basic".into(), username: "analyst".into(), reliability: "B".into(), default_confidence: Some(50), ..Default::default() }))
        .unwrap();
    // the analyst's own records: one saved, one dismissed as a false positive
    db.with(|c| {
        c.execute("INSERT INTO ti_saved (kind, indicator, note, source, created_at, updated_at) VALUES ('domain', 'saved-by-analyst.example.net', 'from the incident', 'IR-42', 't', 't')", [])?;
        c.execute("INSERT INTO ti_saved (kind, indicator, status, created_at, updated_at) VALUES ('domain', 'dismissed.example.net', 'false_positive', 't', 't')", [])?;
        Ok(())
    })
    .unwrap();
    let srv = db.with(|c| server(c, sid)).unwrap();
    // without the stored credential, nothing is sent
    assert!(auth_of(&srv, None).unwrap_err().contains("Store credential"));
    let client = Client::new(auth_of(&srv, Some("s3cr3t-pass".into())).unwrap()).unwrap();
    let d = discover(&client, &check_url(&srv.discovery_url).unwrap()).await.unwrap();
    assert_eq!(d.api_roots, vec![format!("{base}/api1/")], "an API root on another host is not used");
    let cols = collections(&client, &check_url(&d.api_roots[0]).unwrap()).await.unwrap();
    assert_eq!(cols.len(), 1, "an invalid collection id is ignored");
    db.with(|c| record_discovery(c, sid, &d, &cols)).unwrap();
    let coll = db.with(|c| collections_of(c, sid)).unwrap().remove(0);

    let s1 = sync(&db, &client, coll.id).await.unwrap();
    assert_eq!((s1.status.as_str(), s1.pages, s1.objects), ("succeeded", 2, 6), "{s1:?}");
    assert_eq!((s1.added, s1.revoked, s1.sighted), (2, 1, 2), "{s1:?}");
    assert_eq!(s1.skipped, 3, "malware object, AND pattern, private address");
    // indicator 1: the feed's confidence and validity, the server's reliability, the feed as source
    assert_eq!(status_of(&db, "8.8.4.4"), ("active".into(), Some(85), "TAXII: Partner / High-confidence C2".into()));
    assert_eq!(status_of(&db, "https://phish.example.net/login").0, "revoked");
    // the analyst's records keep their fields; the feed's view is in their history
    assert_eq!(status_of(&db, "saved-by-analyst.example.net"), ("active".into(), None, "IR-42".into()));
    assert_eq!(status_of(&db, "dismissed.example.net").0, "false_positive");
    let hist: Vec<String> = db.with(|c| Ok(c.prepare("SELECT e.detail FROM ti_saved_events e JOIN ti_saved t ON t.id = e.saved_id WHERE t.indicator = 'saved-by-analyst.example.net'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)).unwrap();
    assert!(hist[0].contains("listed by TAXII: Partner") && hist[0].contains("confidence 60"), "{hist:?}");
    // requests: the TAXII media type, Basic credentials, no added_after the first time, next on page 2
    let reqs = log.lock().unwrap().clone();
    assert!(reqs.iter().all(|r| r.contains(MEDIA)), "{reqs:?}");
    let objects: Vec<&String> = reqs.iter().filter(|r| r.contains("/objects/")).collect();
    assert!(objects[0].contains("limit=500") && objects[0].contains("match%5Btype%5D=indicator") && !objects[0].contains("added_after"));
    assert!(objects[1].contains("next=p2") && objects[1].contains("|Basic "));
    // the next synchronization starts from the cursor, and a newer version updates the feed's own indicator
    assert_eq!(db.with(|c| collection(c, coll.id)).unwrap().added_after.as_deref(), Some("2026-11-09T12:00:00.000Z"));
    let s2 = sync(&db, &client, coll.id).await.unwrap();
    assert_eq!((s2.status.as_str(), s2.updated), ("succeeded", 1));
    assert_eq!(status_of(&db, "8.8.4.4").1, Some(40));
    assert!(log.lock().unwrap().last().unwrap().contains("added_after=2026-11-09T12"));
    assert_eq!(db.with(|c| syncs(c, coll.id)).unwrap().len(), 2, "the feed's history");
}

#[tokio::test]
async fn failures_are_reported_without_the_credential_and_keep_the_cursor_honest() {
    let (base, _) = feed_server(true);
    let db = Db::open_in_memory().unwrap();
    let sid = db.with(|c| server_save(c, &ServerInput { id: None, name: "P".into(), discovery_url: format!("{base}/taxii2/"), auth: "basic".into(), username: "a".into(), ..Default::default() })).unwrap();
    let srv = db.with(|c| server(c, sid)).unwrap();
    // wrong credentials: the error never repeats the secret, even when the server does
    let wrong = Client::new(Auth::Header { name: "X-Api-Key".into(), value: "s3cr3t-pass".into() }).unwrap();
    let e = collections(&wrong, &check_url(&format!("{base}/api1/")).unwrap()).await.unwrap_err();
    assert!(e.contains("wants credentials") && !e.contains("s3cr3t-pass") && e.contains("••••••"), "{e}");
    // a partial synchronization stores the first page and keeps the cursor at it
    let client = Client::new(auth_of(&srv, Some("s3cr3t-pass".into())).unwrap()).unwrap();
    let d = discover(&client, &check_url(&srv.discovery_url).unwrap()).await.unwrap();
    let cols = collections(&client, &check_url(&d.api_roots[0]).unwrap()).await.unwrap();
    db.with(|c| record_discovery(c, sid, &d, &cols)).unwrap();
    let coll = db.with(|c| collections_of(c, sid)).unwrap().remove(0);
    let s = sync(&db, &client, coll.id).await.unwrap();
    assert_eq!((s.status.as_str(), s.pages), ("partial", 1), "{s:?}");
    assert!(s.message.contains("HTTP 500"));
    let after = db.with(|c| collection(c, coll.id)).unwrap();
    assert_eq!((after.added_after.as_deref(), after.last_status.as_str()), (Some("2026-11-09T10:00:00.000Z"), "partial"));
    assert_eq!(status_of(&db, "8.8.4.4").0, "active", "the stored page is kept");
}

#[tokio::test]
async fn redirects_oversized_and_non_json_responses_are_refused() {
    let big = "x".repeat(MAX_BODY + 10);
    let route: Arc<Route> = Arc::new(move |target: &str, _| match target {
        "/redirect/" => (302, vec![("Location".into(), "https://attacker.example.org/steal".into())], String::new()),
        "/big/" => (200, vec![], big.clone()),
        "/html/" => (200, vec![], "<html>not taxii</html>".into()),
        _ => (406, vec![], String::new()),
    });
    let (base, log) = mock(route);
    let client = Client::new(Auth::Basic { username: "u".into(), password: "pw-123456".into() }).unwrap();
    let get = |p: &str| check_url(&format!("{base}{p}")).unwrap();
    assert!(client.get(&get("/redirect/")).await.unwrap_err().contains("redirects are not followed"));
    assert!(client.get(&get("/big/")).await.unwrap_err().contains("larger than"));
    assert!(client.get(&get("/html/")).await.unwrap_err().contains("not JSON"));
    assert!(client.get(&get("/other/")).await.unwrap_err().contains("does not speak TAXII 2.1"));
    assert!(!log.lock().unwrap().iter().any(|r| r.contains("steal")), "the redirect was not followed");
}

#[test]
fn servers_are_validated() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let base = ServerInput { name: "S".into(), discovery_url: "https://taxii.example.org/taxii2/".into(), auth: "none".into(), ..Default::default() };
        let id = server_save(c, &base)?;
        assert!(server_save(c, &base).unwrap_err().to_string().contains("already configured"));
        assert!(server_save(c, &ServerInput { discovery_url: "http://taxii.example.org/".into(), ..base.clone() }).is_err());
        assert!(server_save(c, &ServerInput { auth: "basic".into(), discovery_url: "https://b.example.org/".into(), ..base.clone() }).unwrap_err().to_string().contains("user name is required"));
        assert!(server_save(c, &ServerInput { auth: "header".into(), header_name: "Host".into(), discovery_url: "https://c.example.org/".into(), ..base.clone() }).is_err());
        assert!(server_save(c, &ServerInput { reliability: "G".into(), discovery_url: "https://d.example.org/".into(), ..base.clone() }).is_err());
        assert!(server_save(c, &ServerInput { default_confidence: Some(101), discovery_url: "https://e.example.org/".into(), ..base.clone() }).is_err());
        assert_eq!(secret_name(id), format!("taxii_{id}"));
        assert!(crate::commands::system::is_taxii_secret(&secret_name(id)));
        Ok(())
    })
    .unwrap();
}
