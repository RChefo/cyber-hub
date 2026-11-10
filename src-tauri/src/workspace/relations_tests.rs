//! Tests of the relationship store: decisions, links, project isolation, archived projects,
//! deletion, related records and the graph.

use super::*;
use crate::db::Db;

fn project(c: &Connection, name: &str) -> i64 {
    c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES (?1, 'active', 't', 't')", params![name]).unwrap();
    c.last_insert_rowid()
}

fn finding(c: &Connection, p: i64, title: &str, target: &str) -> i64 {
    c.execute("INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (?1, ?2, 'high', 'new', ?3, 't', 't')", params![p, title, target]).unwrap();
    c.last_insert_rowid()
}

fn asset(c: &Connection, p: i64, kind: &str, value: &str) -> i64 {
    c.execute(
        "INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (?1, ?2, ?3, ?3, 'manual', 't', 't', 't', 't')",
        params![p, kind, value],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn evidence(c: &Connection, p: i64, title: &str, sha: &str) -> i64 {
    c.execute("INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (?1, 'file', ?2, 'user', ?3, 10, 'x.bin', 't')", params![p, title, sha]).unwrap();
    c.last_insert_rowid()
}

fn cand(a: Ref, b: Ref, rel_type: &'static str, rule: &'static str) -> Candidate {
    Candidate { a, b, rel_type, rule, reason: format!("{rule} matched"), matched: vec![Match { field_a: "x".into(), value_a: "1".into(), field_b: "y".into(), value_b: "1".into(), how: "exact".into() }], confidence: "high", origin: "derived" }
}

fn links(c: &Connection, f: i64) -> Vec<(String, i64)> {
    c.prepare("SELECT kind, ref_id FROM finding_links WHERE finding_id = ?1 ORDER BY id").unwrap().query_map(params![f], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

#[test]
fn decisions_are_kept_and_confirmed_links_become_finding_links() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c, "Web");
        let f = finding(c, p, "SQL injection", "https://app.example.com/login");
        let a = asset(c, p, "http_service", "https://app.example.com");
        let first = suggest(c, p, vec![cand(Ref::new("finding", f), Ref::new("asset", a), "affects", "finding-asset")], "correlation")?;
        assert_eq!((first.new, first.updated), (1, 0));
        let page = list(c, p, &Filter { review: Some("pending".into()), ..Default::default() })?;
        assert_eq!((page.total, page.pending), (1, 1));
        let r = &page.items[0];
        assert_eq!((r.origin.as_str(), r.verification.as_str(), r.a.label.as_str(), r.b.label.as_str()), ("derived", "inferred", "SQL injection", "https://app.example.com"));
        assert_eq!(r.rules, vec!["finding-asset"]);
        assert!(links(c, f).is_empty(), "a suggestion links nothing");

        let accepted = review(c, r.id, "accept", "seen in the proxy", "user")?;
        assert_eq!((accepted.verification.as_str(), accepted.review.as_str(), accepted.materialized), ("verified", "done", true));
        assert_eq!(links(c, f), vec![("asset".to_string(), a)], "accepting creates the finding link");
        // the rules run again: the decision stays, nothing new; the pair is now linked anyway
        let again = suggest(c, p, vec![cand(Ref::new("finding", f), Ref::new("asset", a), "affects", "finding-asset")], "correlation")?;
        assert_eq!((again.new, again.decided + again.linked), (0, 1));

        let rejected = review(c, r.id, "reject", "", "user")?;
        assert_eq!((rejected.verification.as_str(), rejected.materialized), ("rejected", false));
        assert!(links(c, f).is_empty(), "rejecting removes the link it created");
        let again = suggest(c, p, vec![cand(Ref::new("finding", f), Ref::new("asset", a), "affects", "finding-asset")], "correlation")?;
        assert_eq!((again.new, again.decided), (0, 1), "a rejected pair is not suggested again");

        review(c, r.id, "restore", "", "user")?;
        assert_eq!(get(c, r.id)?.review, "pending");
        review(c, r.id, "dismiss", "", "user")?;
        assert_eq!(list(c, p, &Filter::default())?.dismissed, 1);
        review(c, r.id, "reviewed", "", "user")?;
        assert_eq!((get(c, r.id)?.review.as_str(), get(c, r.id)?.verification.as_str()), ("done", "inferred"), "reviewed leaves it unconfirmed");
        assert!(review(c, r.id, "bogus", "", "user").is_err());

        let actions: Vec<String> = c.prepare("SELECT action FROM relation_events WHERE project_id = ?1 ORDER BY id").unwrap().query_map(params![p], |x| x.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(actions, vec!["accept", "reject", "restore", "dismiss", "reviewed"]);
        let timeline = crate::workspace::timeline::project_timeline(c, p, &["correlation".into()], None, 50)?;
        assert_eq!(timeline.len(), 5);
        assert!(timeline.iter().any(|e| e.title == "Accepted: SQL injection affects https://app.example.com" && e.detail == "seen in the proxy"));
        Ok(())
    })
    .unwrap();
}

#[test]
fn links_by_hand_are_checked_and_mcp_links_wait_for_review() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c, "Web");
        let other = project(c, "Other");
        let f = finding(c, p, "Malware dropper", "host-7");
        let e = evidence(c, p, "dropper.exe", &"a".repeat(64));
        let foreign = evidence(c, other, "other.exe", &"b".repeat(64));
        assert!(link(c, p, Ref::new("finding", f), Ref::new("evidence", foreign), "supported_by", "", "user").unwrap_err().to_string().contains("another project"));
        assert!(link(c, p, Ref::new("finding", f), Ref::new("finding", f), "related_to", "", "user").is_err(), "no self links");
        assert!(link(c, p, Ref::new("finding", f), Ref::new("evidence", 9999), "supported_by", "", "user").is_err(), "the record must exist");
        assert!(link(c, p, Ref::new("finding", f), Ref::new("widget", 1), "supported_by", "", "user").is_err(), "unknown kind");
        assert!(link(c, p, Ref::new("finding", f), Ref::new("evidence", e), "bogus", "", "user").is_err(), "unknown type");
        assert!(link(c, p, Ref::new("finding", f), Ref::technique("T9999.999"), "maps_to", "", "user").is_err(), "an ID the catalog does not know");
        let revoked = link(c, p, Ref::new("finding", f), Ref::technique("T1143"), "maps_to", "", "user")?;
        assert_eq!(revoked.b.label, "T1143 (revoked, now T1564.003)");

        let t = link(c, p, Ref::new("finding", f), Ref::technique("t1059.001"), "maps_to", "macro launched PowerShell", "user")?;
        assert_eq!((t.b.label.as_str(), t.origin.as_str(), t.verification.as_str()), ("T1059.001 PowerShell", "manual", "verified"));
        let ev = link(c, p, Ref::new("finding", f), Ref::new("evidence", e), "supported_by", "", "user")?;
        assert!(ev.materialized && links(c, f) == vec![("evidence".to_string(), e)]);
        unlink(c, ev.id, "wrong file", "user")?;
        assert!(get(c, ev.id).is_err(), "a link made by hand is deleted");
        assert!(links(c, f).is_empty(), "with the finding link it made");

        let proposal = link(c, p, Ref::new("evidence", e), Ref::new("finding", f), "related_to", "same campaign", "mcp:Claude Code")?;
        assert_eq!((proposal.origin.as_str(), proposal.verification.as_str(), proposal.review.as_str(), proposal.materialized), ("suggested", "inferred", "pending", false));
        assert_eq!((proposal.confidence.as_str(), proposal.created_by.as_str()), ("low", "mcp:Claude Code"), "an AI suggestion is low confidence and names its client");
        assert!(links(c, f).is_empty(), "a proposal links nothing until accepted");
        // symmetric types keep one order: the same pair the other way round is the same relationship
        let same = link(c, p, Ref::new("finding", f), Ref::new("evidence", e), "related_to", "", "mcp")?;
        assert_eq!(same.id, proposal.id);
        Ok(())
    })
    .unwrap();
}

#[test]
fn archived_projects_and_deleted_records() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c, "Old");
        let f = finding(c, p, "XSS", "https://a.example");
        let a = asset(c, p, "domain", "a.example");
        let g = finding(c, p, "CSRF", "https://a.example");
        suggest(c, p, vec![cand(Ref::new("finding", f), Ref::new("asset", a), "affects", "finding-asset"), cand(Ref::new("finding", g), Ref::new("finding", f), "related_to", "shared-evidence")], "correlation")?;
        let id = list(c, p, &Filter::default())?.items[0].id;
        review(c, id, "accept", "", "user")?;
        c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", params![p])?;
        assert!(suggest(c, p, vec![], "correlation").is_err());
        assert!(review(c, id, "reject", "", "user").is_err());
        assert!(link(c, p, Ref::new("finding", f), Ref::new("asset", a), "affects", "", "user").is_err());
        assert!(unlink(c, id, "", "user").is_err());
        assert_eq!(list(c, p, &Filter::default())?.total, 2, "reading still works");
        c.execute("UPDATE projects SET status = 'active' WHERE id = ?1", params![p])?;

        // deleting a record removes its relationships; the history keeps what was decided
        c.execute("DELETE FROM findings WHERE id = ?1", params![f])?;
        assert_eq!(list(c, p, &Filter::default())?.total, 0);
        let kept: (Option<i64>, String) = c.query_row("SELECT relation_id, summary FROM relation_events WHERE action = 'accept'", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        assert_eq!(kept.0, None);
        assert!(kept.1.contains("XSS"));
        assert!(list(c, p, &Filter { verification: Some("bogus".into()), ..Default::default() }).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn related_records_graph_paths_and_merged_entities() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c, "IR");
        let f = finding(c, p, "Beacon", "203.0.113.9");
        let a = asset(c, p, "ip", "203.0.113.9");
        let e = evidence(c, p, "pcap", &"c".repeat(64));
        c.execute(
            "INSERT INTO vulnerabilities (project_id, cve_id, asset_id, status, priority, priority_score, created_at, updated_at) VALUES (?1, 'CVE-2024-3400', ?2, 'open', 'p1', 9.0, 't', 't')",
            params![p, a],
        )?;
        let v = c.last_insert_rowid();
        crate::workspace::findings::link(c, f, "evidence", e, "user")?;
        let r = link(c, p, Ref::new("finding", f), Ref::new("asset", a), "affects", "", "user")?;
        assert!(r.materialized);

        let view = related(c, p, &Ref::new("asset", a), false)?;
        let vias: Vec<(&str, &str)> = view.related.iter().map(|x| (x.node.label.as_str(), x.via.as_str())).collect();
        assert!(vias.contains(&("Beacon", "affects (from the other side)")), "{vias:?}");
        assert!(vias.contains(&("CVE-2024-3400", "vulnerability of the asset")), "{vias:?}");
        assert!(!vias.contains(&("Beacon", "linked to the finding")), "the finding link the confirmed relationship made is shown once: {vias:?}");
        let fview = related(c, p, &Ref::new("finding", f), false)?;
        let ev = fview.related.iter().find(|x| x.node.r == Ref::new("evidence", e)).expect("evidence");
        assert_eq!((ev.via.as_str(), ev.origin.as_str()), ("finding link", "manual"));
        assert!(!fview.events.is_empty(), "the finding's timeline events come along");
        assert!(related(c, p, &Ref::new("vulnerability", v), false)?.related.iter().any(|x| x.node.r == Ref::new("asset", a)));

        let g = graph(c, p, &GraphFilter::default())?;
        assert_eq!(g.nodes.len(), 3, "finding, asset, evidence");
        assert!(g.edges.iter().any(|x| x.rel_type == "affects" && x.origin == "manual" && x.verification == "verified"));
        assert!(g.edges.iter().any(|x| x.rel_type == "linked" && x.target == format!("evidence:{e}")));
        assert_eq!(shortest_path(&g, &format!("asset:{a}"), &format!("evidence:{e}")), Some(vec![format!("asset:{a}"), format!("finding:{f}"), format!("evidence:{e}")]));
        assert_eq!(neighborhood(&g, &format!("asset:{a}"), 1).len(), 2);
        let json: Value = serde_json::from_str(&export_json("IR", "now", &g)).unwrap();
        assert_eq!(json["edges"].as_array().unwrap().len(), g.edges.len());
        assert!(json["edges"][0]["origin"].is_string() && json["edges"][0]["verification"].is_string());
        assert!(graph(c, p, &GraphFilter { kinds: vec!["widget".into()], ..Default::default() }).is_err());
        assert_eq!(graph(c, p, &GraphFilter { kinds: vec!["finding".into(), "asset".into()], ..Default::default() })?.edges.len(), 1, "the affects edge stands for the asset link it made");
        assert!(g.edges.iter().filter(|x| x.source == format!("finding:{f}") && x.target == format!("asset:{a}")).count() == 1, "one edge per pair");

        // merged OSINT entities keep their relationships
        c.execute("INSERT INTO osint_investigations (name, target_type, target_value, project_id, created_at, updated_at) VALUES ('C2','ip','203.0.113.9',?1,'t','t')", params![p])?;
        let inv = c.last_insert_rowid();
        let mut ids = Vec::new();
        for v in ["203.0.113.9", "203.0.113.11", "203.0.113.10"] {
            c.execute(
                "INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1, 'ip', ?2, ?2, ?2, 't', 't')",
                params![inv, v],
            )?;
            ids.push(c.last_insert_rowid());
        }
        let (keep, third, merge) = (ids[0], ids[1], ids[2]);
        link(c, p, Ref::new("evidence", e), Ref::new("osint_entity", merge), "corresponds_to", "", "user")?;
        // the merged entity was related to the kept one, and both to a third (stored in id order)
        link(c, p, Ref::new("osint_entity", keep), Ref::new("osint_entity", merge), "related_to", "", "user")?;
        link(c, p, Ref::new("osint_entity", keep), Ref::new("osint_entity", third), "related_to", "", "user")?;
        link(c, p, Ref::new("osint_entity", third), Ref::new("osint_entity", merge), "related_to", "", "user")?;
        crate::osint::store::entity_merge(c, keep, merge)?;
        let rel = related(c, p, &Ref::new("evidence", e), false)?;
        assert!(rel.related.iter().any(|x| x.node.r == Ref::new("osint_entity", keep)), "the relationship follows the kept entity");
        let pairs: Vec<(i64, i64)> = c
            .prepare("SELECT a_id, b_id FROM relations WHERE type = 'related_to' AND a_kind = 'osint_entity' AND b_kind = 'osint_entity'")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        assert_eq!(pairs, vec![(keep, third)], "no entity is related to itself, and the pair with the third entity is stored once, in order");
        Ok(())
    })
    .unwrap();
}

#[test]
fn concurrent_correlation_and_review_keep_one_row_per_pair() {
    let db = Db::open_in_memory().unwrap();
    let p = db
        .with(|c| {
            let p = project(c, "Concurrent");
            for i in 0..30 {
                finding(c, p, &format!("Issue {i}"), &format!("h{i}.example.com"));
                asset(c, p, "subdomain", &format!("h{i}.example.com"));
            }
            Ok(p)
        })
        .unwrap();
    // correlation from several threads while another accepts suggestions as they appear
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..5 {
                    db.with(|c| crate::workspace::correlate::run(c, p)).unwrap();
                }
            });
        }
        // at least 20 rounds, and on until something was accepted: under load the correlation
        // threads may not have suggested anything during the first rounds
        s.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let (mut rounds, mut accepted) = (0, 0);
            while rounds < 20 || (accepted == 0 && std::time::Instant::now() < deadline) {
                accepted += db
                    .with(|c| {
                        let pending = list(c, p, &Filter { review: Some("pending".into()), limit: Some(3), ..Default::default() })?.items;
                        for r in &pending {
                            review(c, r.id, "accept", "", "user")?;
                        }
                        Ok(pending.len())
                    })
                    .unwrap();
                rounds += 1;
                std::thread::yield_now();
            }
        });
    });
    db.with(|c| {
        let dupes: i64 = c.query_row(
            "SELECT COUNT(*) FROM (SELECT COUNT(*) AS n FROM relations GROUP BY project_id, type, a_kind, a_id, a_sub, b_kind, b_id, b_sub HAVING n > 1)",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(dupes, 0, "one relationship per pair and type");
        let (total, verified, pending): (i64, i64, i64) = c.query_row(
            "SELECT COUNT(*), SUM(verification = 'verified'), SUM(review = 'pending') FROM relations WHERE project_id = ?1",
            params![p],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        assert_eq!(total, 30, "one suggestion per finding and asset");
        assert!(verified > 0 && verified + pending == total, "decisions are kept: {verified} accepted, {pending} pending");
        let links: i64 = c.query_row("SELECT COUNT(*) FROM finding_links WHERE kind = 'asset'", [], |r| r.get(0))?;
        assert_eq!(links, verified, "each accepted suggestion made its finding link once");
        Ok(())
    })
    .unwrap();
}
