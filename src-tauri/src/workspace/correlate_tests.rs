//! Tests of the correlation rules: each rule's matches, what must not match, and decisions kept
//! across runs.

use super::*;
use crate::db::Db;
use crate::workspace::relations::{self, Filter};

fn exec(c: &Connection, sql: &str, p: &[&dyn rusqlite::ToSql]) -> i64 {
    c.execute(sql, p).unwrap();
    c.last_insert_rowid()
}

struct Fixture {
    p: i64,
    a: [i64; 4],
    v: [i64; 3],
    f: [i64; 8],
    e: [i64; 2],
    o: [i64; 3],
    doc1: i64,
    doc2: i64,
    spec: i64,
}

const SHA: &str = "4f2a8e1c0b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f";

fn fixture(c: &Connection) -> Fixture {
    let p = exec(c, "INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Acme', 'active', 't', 't')", &[]);
    let asset = |kind: &str, value: &str| exec(c, "INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (?1, ?2, ?3, ?3, 'manual', 't', 't', 't', 't')", &[&p, &kind, &value]);
    let a = [asset("http_service", "https://app.example.com"), asset("subdomain", "app.example.com"), asset("ip", "93.184.215.7"), asset("subdomain", "other.example.com")];
    let vuln = |cve: &str, asset: Option<i64>| exec(c, "INSERT INTO vulnerabilities (project_id, cve_id, asset_id, status, priority, priority_score, created_at, updated_at) VALUES (?1, ?2, ?3, 'open', 'p2', 7.0, 't', 't')", &[&p, &cve, &asset]);
    let v = [vuln("CVE-2021-41773", Some(a[0])), vuln("CVE-2021-41773", Some(a[3])), vuln("CVE-2021-23337", None)];
    let finding = |title: &str, target: &str, cve: &str, description: &str| {
        exec(c, "INSERT INTO findings (project_id, title, severity, status, affected_target, cve, description, created_at, updated_at) VALUES (?1, ?2, 'high', 'new', ?3, ?4, ?5, 't', 't')", &[&p, &title, &target, &cve, &description])
    };
    let f = [
        finding("Path traversal", "https://app.example.com/cgi-bin/x", "CVE-2021-41773", ""),
        finding("Apache 2.4.49 path traversal and RCE", "https://app.example.com/", "CVE-2021-41773", ""),
        finding("SSH weak ciphers", "93.184.215.7", "", ""),
        finding("Unrelated", "https://elsewhere.example.org/x", "", ""),
        finding("lodash prototype pollution", "pkg:npm/lodash@4.17.20", "CVE-2021-23337", ""),
        finding("Dropper found", "host-7", "", &format!("The file has SHA-256 {}.", SHA.to_uppercase())),
        finding("IDOR on users", "https://api.example.com/v1/users/42?x=1", "", ""),
        finding("IDOR on orders", "https://api.example.com/v1/users/42/orders", "", ""),
    ];
    let ev = |title: &str, sha: &str| exec(c, "INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (?1, 'file', ?2, 'user', ?3, 10, 'x', 't')", &[&p, &title, &sha]);
    let e = [ev("dropper.exe", SHA), ev("capture.pcap", &"9".repeat(64))];
    for fid in [f[2], f[5]] {
        crate::workspace::findings::link(c, fid, "evidence", e[1], "user").unwrap();
    }
    let inv = exec(c, "INSERT INTO osint_investigations (name, target_type, target_value, project_id, created_at, updated_at) VALUES ('Infra', 'domain', 'example.com', ?1, 't', 't')", &[&p]);
    let entity = |kind: &str, value: &str| exec(c, "INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3, ?3, 't', 't')", &[&inv, &kind, &value]);
    let o = [entity("domain", "app.example.com"), entity("file_hash", SHA), entity("domain", "unrelated.example.net")];
    let lock = |version: &str| {
        let doc = format!(r#"{{"name":"shop","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"shop"}},"node_modules/lodash":{{"version":"{version}","resolved":"https://registry.npmjs.org/lodash/-/lodash-{version}.tgz","integrity":"sha512-x"}}}}}}"#);
        crate::workspace::sbom::parse_file("package-lock.json", &doc).unwrap()
    };
    let doc1 = crate::workspace::sbom::store(c, p, "lock-1.json", "s1", None, &lock("4.17.20")).unwrap();
    let doc2 = crate::workspace::sbom::store(c, p, "lock-2.json", "s2", None, &lock("4.17.21")).unwrap();
    let osv = crate::workspace::sbom::Vuln { id: "GHSA-35jh-r3h4-6jhm".into(), aliases: vec!["CVE-2021-23337".into()], severity: "high".into(), components: vec![0], ..Default::default() };
    crate::workspace::sbom::save_lookup(c, doc1, &[osv]).unwrap();
    let spec = crate::workspace::apisec::parse(r#"{"openapi":"3.0.3","info":{"title":"Users","version":"1"},"servers":[{"url":"https://api.example.com/v1"}],
        "paths":{"/users":{"get":{"responses":{"200":{"description":"ok"}}}},"/users/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#)
    .unwrap();
    let spec = crate::workspace::apisec::store(c, p, "users.json", "u1", None, &spec).unwrap();
    Fixture { p, a, v, f, e, o, doc1, doc2, spec }
}

fn has(cands: &[Candidate], rule: &str, a: &Ref, b: &Ref, confidence: &str) -> bool {
    cands.iter().any(|x| x.rule == rule && ((x.a == *a && x.b == *b) || (x.a == *b && x.b == *a)) && x.confidence == confidence)
}

fn pairs(cands: &[Candidate], rule: &str) -> usize {
    cands.iter().filter(|x| x.rule == rule).count()
}

#[test]
fn every_rule_finds_its_matches_and_nothing_else() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let x = fixture(c);
        let cands = candidates(c, x.p)?;
        let (f, a, v, e, o) = (|i: usize| Ref::new("finding", x.f[i]), |i: usize| Ref::new("asset", x.a[i]), |i: usize| Ref::new("vulnerability", x.v[i]), |i: usize| Ref::new("evidence", x.e[i]), |i: usize| Ref::new("osint_entity", x.o[i]));

        // finding → asset: the web service by origin, the address exactly, never the bare name when the service matches
        assert!(has(&cands, "finding-asset", &f(0), &a(0), "high"));
        assert!(has(&cands, "finding-asset", &f(1), &a(0), "high"));
        assert!(has(&cands, "finding-asset", &f(2), &a(2), "high"));
        assert!(!cands.iter().any(|c| c.rule == "finding-asset" && c.a == f(0) && c.b == a(1)), "the more specific asset wins");
        assert!(!cands.iter().any(|c| c.rule == "finding-asset" && c.a == f(3)), "no asset for elsewhere.example.org");
        assert_eq!(cands.iter().find(|c| c.rule == "finding-asset" && c.a == f(2)).unwrap().matched[0].how, "exact");

        // CVE: the same host, or a vulnerability without an asset; never the same CVE on another host
        assert!(has(&cands, "finding-vulnerability", &f(0), &v(0), "high"));
        assert!(!cands.iter().any(|c| c.rule == "finding-vulnerability" && (c.a == v(1) || c.b == v(1))), "CVE-2021-41773 on other.example.com is another instance");
        assert!(has(&cands, "finding-vulnerability", &f(4), &v(2), "medium"));

        // packages: the OSV result's alias, the same version, the package in the newer lockfile
        let comp = |doc: i64| Ref::sub("sbom_component", doc, "0");
        assert!(has(&cands, "vulnerability-component", &v(2), &comp(x.doc1), "high"));
        assert!(!cands.iter().any(|c| c.rule == "vulnerability-component" && (c.b == comp(x.doc2))), "4.17.21 has no lookup result");
        assert!(cands.iter().any(|c| c.rule == "finding-component" && c.b == comp(x.doc1) && c.rel_type == "affects" && c.confidence == "high"));
        assert!(cands.iter().any(|c| c.rule == "finding-component" && c.b == comp(x.doc2) && c.rel_type == "corresponds_to" && c.reason.contains("4.17.21")));

        // hashes: evidence and entity, the finding naming the hash in capitals
        assert!(has(&cands, "hash", &e(0), &o(1), "high"));
        assert!(has(&cands, "hash", &f(5), &e(0), "high"));
        assert!(has(&cands, "hash", &f(5), &o(1), "high"));
        assert!(!cands.iter().any(|c| c.rule == "hash" && (c.a == e(1) || c.b == e(1))));

        // API endpoint: server + template; a longer path is another endpoint
        let ep = Ref::sub("api_endpoint", x.spec, "1");
        assert!(has(&cands, "finding-endpoint", &f(6), &ep, "high"), "{:?}", cands.iter().filter(|c| c.rule == "finding-endpoint").collect::<Vec<_>>());
        assert!(!cands.iter().any(|c| c.rule == "finding-endpoint" && c.a == f(7)));

        // OSINT: the entity's host is an asset's host; findings on that host
        assert!(has(&cands, "entity-asset", &a(0), &o(0), "high"));
        assert!(has(&cands, "entity-asset", &a(1), &o(0), "high"));
        assert!(!cands.iter().any(|c| c.a == o(2) || c.b == o(2)), "unrelated.example.net matches nothing");
        assert!(has(&cands, "finding-entity", &f(0), &o(0), "medium"));

        // shared evidence, duplicates by CVE on the same host
        assert!(has(&cands, "shared-evidence", &f(2), &f(5), "medium"));
        assert!(has(&cands, "duplicate", &f(0), &f(1), "high"));
        assert_eq!(pairs(&cands, "duplicate"), 1);
        // every candidate explains itself
        assert!(cands.iter().all(|c| !c.reason.is_empty() && !c.matched.is_empty()));
        Ok(())
    })
    .unwrap();
}

#[test]
fn runs_store_suggestions_and_keep_decisions() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let x = fixture(c);
        let first = run(c, x.p)?;
        assert!(first.stored.new >= 15, "{first:?}");
        assert_eq!(first.stored.decided, 0);
        assert!(first.by_rule.contains_key("hash") && first.by_rule.contains_key("duplicate"));
        let pending = relations::list(c, x.p, &Filter { review: Some("pending".into()), limit: Some(500), ..Default::default() })?;
        assert_eq!(pending.total as usize, first.stored.new);
        let find = |rule: &str| pending.items.iter().find(|r| r.rules.contains(&rule.to_string())).unwrap().id;
        relations::review(c, find("duplicate"), "reject", "different scanners, one issue each", "user")?;
        relations::review(c, find("shared-evidence"), "accept", "", "user")?;
        let second = run(c, x.p)?;
        assert_eq!(second.stored.new, 0);
        assert_eq!(second.stored.decided, 2, "{second:?}");
        assert_eq!(second.stored.updated, first.stored.new - 2);
        let summaries: Vec<String> = c.prepare("SELECT summary FROM relation_events WHERE action = 'correlated' ORDER BY id").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(summaries.len(), 2);
        assert!(summaries[1].contains("0 new suggestions") && summaries[1].contains("2 already decided"));
        Ok(())
    })
    .unwrap();
}

#[test]
fn large_groups_are_capped_and_archived_projects_refused() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = exec(c, "INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Big', 'active', 't', 't')", &[]);
        for i in 0..60 {
            exec(c, "INSERT INTO findings (project_id, title, severity, status, affected_target, cve, created_at, updated_at) VALUES (?1, ?2, 'high', 'new', 'https://big.example', 'CVE-2024-0001', 't', 't')", &[&p, &format!("Issue {i}")]);
        }
        assert_eq!(pairs(&candidates(c, p)?, "duplicate"), MAX_PAIRS_PER_GROUP, "one group yields at most {MAX_PAIRS_PER_GROUP} pairs");
        c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", params![p])?;
        assert!(run(c, p).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn api_endpoints_match_without_regard_to_case_and_through_parameters() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = exec(c, "INSERT INTO projects (name, status, created_at, updated_at) VALUES ('API', 'active', 't', 't')", &[]);
        let finding = |title: &str, target: &str| exec(c, "INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (?1, ?2, 'high', 'new', ?3, 't', 't')", &[&p, &title, &target]);
        let spec = crate::workspace::apisec::parse(
            r#"{"openapi":"3.0.3","info":{"title":"Reports","version":"1"},"servers":[{"url":"https://API.example.com/v2/"}],
            "paths":{"/Reports/{year}":{"get":{"responses":{"200":{"description":"ok"}}}},"/{tenant}/status":{"get":{"responses":{"200":{"description":"ok"}}}},"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        )
        .unwrap();
        let index = |path: &str| spec.endpoints.iter().position(|e| e.path == path).unwrap().to_string();
        let (reports, status) = (index("/Reports/{year}"), index("/{tenant}/status"));
        let s = crate::workspace::apisec::store(c, p, "reports.json", "r1", None, &spec).unwrap();
        let f1 = finding("Report export", "https://api.example.com/v2/reports/2024#top");
        let f2 = finding("Tenant status", "https://api.EXAMPLE.com/v2/acme/status");
        let f3 = finding("Elsewhere", "https://api.example.com.evil.test/v2/health");
        let f4 = finding("Other version", "https://api.example.com/v1/health");
        let cands = candidates(c, p)?;
        let hit = |f: i64| cands.iter().filter(|x| x.rule == "finding-endpoint" && x.a == Ref::new("finding", f)).map(|x| (x.b.sub.clone(), x.confidence)).collect::<Vec<_>>();
        assert_eq!(hit(f1), vec![(reports, "high")], "the path's case does not matter");
        assert_eq!(hit(f2), vec![(status, "high")], "a parameter as the first segment");
        assert!(hit(f3).is_empty() && hit(f4).is_empty(), "another host, another base path");
        assert!(cands.iter().filter(|x| x.rule == "finding-endpoint").all(|x| x.b.id == s));
        Ok(())
    })
    .unwrap();
}

/// Times a run over a large project: `cargo test --release correlation_at_scale -- --ignored --nocapture`.
#[test]
#[ignore = "timing"]
fn correlation_at_scale() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = exec(c, "INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Scale', 'active', 't', 't')", &[]);
        let tx = c.unchecked_transaction()?;
        for i in 0..20_000 {
            tx.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (?1, 'subdomain', ?2, ?2, 'scan', 't', 't', 't', 't')", params![p, format!("h{i}.example.com")])?;
        }
        for i in 0..10_000 {
            tx.execute(
                "INSERT INTO findings (project_id, title, severity, status, affected_target, cve, created_at, updated_at) VALUES (?1, ?2, 'medium', 'new', ?3, ?4, 't', 't')",
                params![p, format!("Issue {}", i % 300), format!("https://h{}.example.com/p{}", i % 20_000, i), format!("CVE-2024-{:04}", i % 500)],
            )?;
        }
        tx.commit()?;
        let start = std::time::Instant::now();
        let n = candidates(c, p)?.len();
        let found = start.elapsed();
        let report = run(c, p)?;
        println!("10,000 findings and 20,000 assets: {n} candidates in {found:?}; run (with storing) {} ms, {:?}", report.elapsed_ms, report.stored);
        Ok(())
    })
    .unwrap();
}
