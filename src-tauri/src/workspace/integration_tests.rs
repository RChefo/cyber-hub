// SPDX-License-Identifier: Apache-2.0
//! Cross-module tests: one project followed through scope, discovery, vulnerabilities, findings,
//! evidence, workflows' records, analysis, timeline and reports, plus a volume check.

use rusqlite::params;
use serde_json::json;

use crate::db::Db;
use crate::workspace::discovery::{self, Batch, Certainty};
use crate::workspace::{analysis, assets, evidence, findings, report, timeline, vulns};

fn project(c: &rusqlite::Connection) -> i64 {
    c.execute("INSERT INTO projects (name, status, client, created_at, updated_at) VALUES ('Acme external','active','Acme Corp','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z')", []).unwrap();
    c.last_insert_rowid()
}

#[test]
fn a_project_flows_through_every_module() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c);
        crate::commands::projects::target_add(c, p, "*.example.com", "wildcard", true, "")?;
        crate::commands::projects::target_add(c, p, "93.184.215.0/24", "cidr", true, "")?;
        crate::commands::projects::target_add(c, p, "vpn.example.com", "domain", false, "Production VPN")?;

        // passive discovery recorded a name and its address; a scan confirmed a service
        let s1 = assets::start_snapshot(c, p, "passive", "passive", None, None)?;
        let mut b = Batch::default();
        let entries = crate::commands::projects::scope_entries(c, p)?;
        discovery::add_dns(&mut b, &entries, "app.example.com", &[("A".into(), vec!["93.184.215.7".into()])]);
        b.add("subdomain", "app.example.com", Certainty::Observed, json!({ "sources": ["crt.sh", "dns"], "resolves": true }));
        discovery::complete(c, p, s1, "passive", &b, ("completed", &[]), &|_| true)?;
        let s2 = assets::start_snapshot(c, p, "active", "nmap", None, None)?;
        let run = discovery::parse_nmap(
            r#"<nmaprun><host><status state="up"/><address addr="93.184.215.7" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>"#,
        )
        .map_err(crate::error::validation)?;
        discovery::complete(c, p, s2, "nmap", &discovery::nmap_batch(&run), ("completed", &[]), &|_| true)?;
        let service = assets::list(c, p, Some("service"), None, 10, 0)?.remove(0);

        // a vulnerability on the service, a finding from it, evidence linked to the finding
        let v = vulns::create(c, &vulns::VulnInput { project_id: p, cve_id: "CVE-2021-23017".into(), asset_id: Some(service.id), ..Default::default() }, None, None, "user")?;
        assert_eq!(v.exposure, "internet", "a public address is internet-facing");
        let fid = crate::commands::projects::finding_save(
            c,
            &crate::commands::projects::FindingInput { project_id: p, title: "nginx resolver off-by-one".into(), severity: "high".into(), status: "new".into(), affected_target: "https://app.example.com".into(), ..Default::default() },
            "user",
        )?;
        findings::link(c, fid, "vulnerability", v.id, "user")?;
        let ev = evidence::add_text(c, p, "Response headers", "Server: nginx/1.18.0", "", "user")?;
        findings::link(c, fid, "evidence", ev.id, "user")?;

        // analysis sees the chain and the correlation
        let paths = analysis::exposure_paths(c, p)?;
        let labels: Vec<&str> = paths[0].nodes.iter().map(|n| n.label.as_str()).collect();
        assert_eq!(labels, vec!["Internet", "app.example.com", "93.184.215.7", "93.184.215.7:443/tcp", "CVE-2021-23017 (P3)", "nginx resolver off-by-one"]);
        let ioc = analysis::correlate(c, p)?;
        assert!(ioc.iter().any(|i| i.value == "93.184.215.7" && i.sources >= 1));
        assert!(ioc.iter().any(|i| i.value == "app.example.com" && i.sightings.iter().any(|s| s.source == "finding")));

        // the timeline has every kind of event, the report everything that was selected
        timeline::record(c, p, "report", "Report exported (HTML)", "", None, None)?;
        let kinds: std::collections::BTreeSet<String> = timeline::project_timeline(c, p, &[], None, 500)?.into_iter().map(|e| e.kind).collect();
        for k in ["scope", "discovery", "vulnerability", "finding", "evidence", "report"] {
            assert!(kinds.contains(k), "{k} missing from the timeline: {kinds:?}");
        }
        let html = report::render(c, p, &report::ReportOptions::default(), "2026-11-05")?;
        for needle in ["Acme Corp", "nginx resolver off-by-one", "CVE-2021-23017", "93.184.215.7:443/tcp", "Response headers", "vpn.example.com"] {
            assert!(html.contains(needle), "{needle} missing from the report");
        }

        // deleting the project removes everything that belongs to it
        c.execute("DELETE FROM projects WHERE id = ?1", params![p])?;
        for t in ["assets", "asset_observations", "discovery_snapshots", "vulnerabilities", "vulnerability_events", "findings", "finding_events", "finding_links", "evidence", "scope_events", "timeline_events"] {
            let n: i64 = c.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))?;
            assert_eq!(n, 0, "{t} still has rows");
        }
        Ok(())
    })
    .unwrap();
}

/// Volume check: run with `cargo test --release -- --ignored volume --nocapture`.
#[test]
#[ignore]
fn volume() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c);
        c.execute_batch("BEGIN")?;
        for i in 0..20_000 {
            let ip = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256);
            c.execute(
                "INSERT INTO assets (project_id, type, value, key, source, data, first_seen, last_seen, created_at, updated_at) VALUES (?1,'ip',?2,?2,'passive','{\"names\":[\"h.example.com\"]}','t','t','t','t')",
                params![p, ip],
            )?;
            let aid = c.last_insert_rowid();
            if i % 10 == 0 {
                c.execute(
                    "INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (?1,'service',?2,?2,'nmap','t','t','t','t')",
                    params![p, format!("{ip}:443/tcp")],
                )?;
                let sid = c.last_insert_rowid();
                c.execute(
                    "INSERT INTO vulnerabilities (project_id, cve_id, asset_id, status, priority, priority_score, created_at, updated_at) VALUES (?1,?2,?3,'open','p2',9.0,'t','t')",
                    params![p, format!("CVE-2026-{:05}", i), sid],
                )?;
            }
            if i % 4 == 0 {
                c.execute("INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (?1,'F','low','new',?2,'t','t')", params![p, ip])?;
                let f = c.last_insert_rowid();
                c.execute("INSERT INTO finding_events (finding_id, project_id, kind, at) VALUES (?1, ?2, 'created', ?3)", params![f, p, format!("2026-11-01T00:{:02}:00Z", i % 60)])?;
                c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (?1,'asset',?2,'t')", params![f, aid])?;
            }
        }
        c.execute_batch("COMMIT")?;
        let time = |label: &str, f: &mut dyn FnMut() -> usize| {
            let t = std::time::Instant::now();
            let n = f();
            println!("{label}: {n} rows in {} ms", t.elapsed().as_millis());
        };
        time("assets list", &mut || assets::list(c, p, None, None, 5000, 0).unwrap().len());
        time("timeline", &mut || timeline::project_timeline(c, p, &[], None, 200).unwrap().len());
        time("correlation", &mut || analysis::correlate(c, p).unwrap().len());
        time("exposure paths", &mut || analysis::exposure_paths(c, p).unwrap().len());
        time("vulnerabilities", &mut || vulns::list(c, p).unwrap().len());
        time("report", &mut || report::render(c, p, &report::ReportOptions { include_assets: false, ..Default::default() }, "2026-11-05").unwrap().len());
        Ok(())
    })
    .unwrap();
}

#[test]
fn findings_keep_a_validated_cvss_vector_and_its_score() {
    use crate::commands::projects::{finding_get, finding_save, FindingInput};
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c);
        let input = |vector: &str| FindingInput { project_id: p, title: "RCE".into(), severity: "critical".into(), status: "new".into(), cvss_vector: vector.into(), ..Default::default() };
        // stored in canonical order, scored by the backend
        let id = finding_save(c, &input("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"), "user")?;
        let f = finding_get(c, id)?;
        assert_eq!((f.cvss_vector.as_str(), f.cvss_score), ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", Some(9.3)));
        // a broken vector is refused with the reason, and nothing changes
        let err = finding_save(c, &FindingInput { id: Some(id), ..input("CVSS:3.1/AV:N") }, "user").unwrap_err();
        assert!(err.to_string().contains("CVSS vector") && err.to_string().contains("missing"), "{err}");
        assert_eq!(finding_get(c, id)?.cvss_score, Some(9.3));
        // clearing the vector clears the score; the change is in the history
        finding_save(c, &FindingInput { id: Some(id), ..input("") }, "user")?;
        let f = finding_get(c, id)?;
        assert_eq!((f.cvss_vector.as_str(), f.cvss_score), ("", None));
        assert!(findings::history(c, id)?.iter().any(|e| e.note.contains("CVSS vector")));
        // reports show the score with its vector
        finding_save(c, &FindingInput { id: Some(id), ..input("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") }, "user")?;
        let html = report::render(c, p, &report::ReportOptions::default(), "2026-11-08")?;
        assert!(html.contains("CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"));
        let md = report::markdown(c, p, &report::ReportOptions::default(), "2026-11-08")?;
        assert!(md.contains("- **CVSS:** `9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`"), "{md}");
        Ok(())
    })
    .unwrap();
}

#[test]
fn the_report_states_checklist_coverage() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let p = project(c);
        let html = report::render(c, p, &report::ReportOptions::default(), "2026-11-08")?;
        assert!(!html.contains("Testing checklist"), "no checklist line without progress");
        crate::methodology::set(c, p, "WSTG-INFO-01", "passed", "", crate::methodology::Link::Keep, "user")?;
        crate::methodology::set(c, p, "WSTG-ATHN-01", "failed", "", crate::methodology::Link::Keep, "user")?;
        let html = report::render(c, p, &report::ReportOptions::default(), "2026-11-08")?;
        assert!(html.contains("OWASP Web Security Testing Guide: 2 of 115 tests have a result (1 passed, 1 failed, 0 not applicable); 0 in progress."));
        Ok(())
    })
    .unwrap();
}
