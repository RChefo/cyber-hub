//! Every path that can change a finding's or a vulnerability's status meets the risk acceptance
//! rule; acceptances are validated, expire without changing anything by themselves, renew,
//! revoke and keep their history.

use super::*;
use crate::db::Db;

fn day(offset: i64) -> String {
    (chrono::Utc::now().date_naive() + Duration::days(offset)).to_string()
}

fn draft(expires_in: i64) -> Draft {
    Draft {
        title: "Legacy TLS on the payment gateway".into(),
        justification: "The vendor appliance cannot be upgraded before the Q3 replacement; it is reachable only from the payment VLAN.".into(),
        compensating: "Network ACL; TLS inspection at the edge".into(),
        owner: "Head of payments".into(),
        approver: "CISO".into(),
        approved_at: day(0),
        expires_at: day(expires_in),
        review_at: None,
    }
}

fn finding(c: &Connection, project: i64, title: &str, status: &str) -> i64 {
    c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (?1, ?2, 'high', ?3, 't', 't')", params![project, title, status]).unwrap();
    c.last_insert_rowid()
}

fn vuln(c: &Connection, project: i64) -> i64 {
    c.execute("INSERT INTO vulnerabilities (project_id, cve_id, status, priority, priority_score, created_at, updated_at) VALUES (?1, 'CVE-2024-3094', 'open', 'p1', 9.0, 't', 't')", params![project]).unwrap();
    c.last_insert_rowid()
}

fn status(c: &Connection, id: i64) -> String {
    c.query_row("SELECT status FROM findings WHERE id = ?1", params![id], |r| r.get(0)).unwrap()
}

fn it(kind: &str, ref_id: i64) -> ItemRef {
    ItemRef { kind: kind.into(), ref_id, requirement: String::new() }
}

/// A change that makes a valid draft invalid.
type Change = Box<dyn Fn(&mut Draft)>;

fn setup() -> Db {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Acme', 'active', 't', 't'), (2, 'Other', 'active', 't', 't'), (3, 'Old', 'archived', 't', 't')", [])?;
        Ok(())
    })
    .unwrap();
    db
}

#[test]
fn no_path_makes_an_accepted_risk_without_an_acceptance() {
    let db = setup();
    db.with(|c| {
        let f = finding(c, 1, "Weak TLS", "confirmed");
        // a status change (the finding's status menu, imports, internal services)
        let err = crate::workspace::findings::set_status(c, f, "accepted_risk", "fine", "user").unwrap_err().to_string();
        assert!(err.contains("only through a risk acceptance"), "{err}");
        // the editor
        let mut input = crate::commands::projects::FindingInput { id: Some(f), project_id: 1, title: "Weak TLS".into(), severity: "high".into(), status: "accepted_risk".into(), ..Default::default() };
        assert!(crate::commands::projects::finding_write(c, &input, "user", false).unwrap_err().to_string().contains("only through a risk acceptance"));
        // a new finding, from the editor or an MCP client
        input.id = None;
        assert!(crate::commands::projects::finding_write(c, &input, "mcp", false).unwrap_err().to_string().contains("only through a risk acceptance"));
        // bulk changes report the finding instead of failing the others
        let g = finding(c, 1, "Verbose banner", "new");
        let r = crate::commands::vulns::bulk_status(c, &[f, g], "accepted_risk", "")?;
        assert!(r.changed.is_empty() && r.skipped.len() == 2 && r.skipped[0].1.contains("only through a risk acceptance"), "{:?}", r.skipped);
        assert_eq!((status(c, f), status(c, g)), ("confirmed".into(), "new".into()));
        // a vulnerability
        let v = vuln(c, 1);
        assert!(crate::workspace::vulns::set_status(c, v, "accepted_risk", "known", "user").unwrap_err().to_string().contains("only through a risk acceptance"));
        // imports never resolve or reopen an accepted risk: it is not an open status
        assert!(!crate::workspace::findings::OPEN_SQL.contains("accepted_risk"));
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_acceptance_covers_findings_vulnerabilities_and_asvs_exceptions() {
    let db = setup();
    db.with(|c| {
        let f = finding(c, 1, "Weak TLS", "confirmed");
        let g = finding(c, 1, "Old cipher suites", "in_remediation");
        let v = vuln(c, 1);
        let a = crate::workspace::asvs::create(c, 1, "Gateway", 1, "")?;
        let req = crate::workspace::asvs::CATALOG.requirements.iter().find(|r| r.level == 1).unwrap().id.to_string();
        crate::workspace::asvs::set_status(c, a, &req, "non_compliant", Some("TLS 1.0 still offered"), "user")?;
        let items = vec![it("finding", f), it("finding", g), it("vulnerability", v), ItemRef { kind: "asvs".into(), ref_id: a, requirement: req.clone() }];
        let id = create(c, 1, &draft(90), &items, "user")?;
        assert_eq!((status(c, f), status(c, g)), ("accepted_risk".into(), "accepted_risk".into()));
        let vs: String = c.query_row("SELECT status FROM vulnerabilities WHERE id = ?1", params![v], |r| r.get(0))?;
        assert_eq!(vs, "accepted_risk");
        let acc = get(c, id)?;
        assert_eq!((acc.standing.as_str(), acc.items.len()), ("active", 4));
        assert!(acc.items.iter().any(|i| i.kind == "asvs" && i.status == "non_compliant" && i.label == format!("ASVS {req}")));
        // the finding's own history says who accepted it, approved by whom, until when
        let hist = crate::workspace::findings::history(c, f)?;
        assert!(hist.iter().any(|e| e.to_status.as_deref() == Some("accepted_risk") && e.note.contains("approved by CISO") && e.note.contains(&day(90))), "{hist:?}");
        // a finding of another project, a resolved finding, a compliant requirement: refused
        let other = finding(c, 2, "Elsewhere", "new");
        assert!(create(c, 1, &draft(30), &[it("finding", other)], "user").unwrap_err().to_string().contains("not part of this project"));
        let fixed = finding(c, 1, "Fixed", "resolved");
        assert!(create(c, 1, &draft(30), &[it("finding", fixed)], "user").unwrap_err().to_string().contains("no risk left"));
        let req2 = crate::workspace::asvs::CATALOG.requirements.iter().filter(|r| r.level == 1).nth(1).unwrap().id.to_string();
        assert!(create(c, 1, &draft(30), &[ItemRef { kind: "asvs".into(), ref_id: a, requirement: req2 }], "user").unwrap_err().to_string().contains("non-compliant"));
        // an archived project
        let old = finding(c, 3, "Archived", "new");
        assert!(create(c, 3, &draft(30), &[it("finding", old)], "user").unwrap_err().to_string().contains("archived"));
        // the requirement met at last: its exception is released
        crate::workspace::asvs::set_status(c, a, &req, "compliant", None, "user")?;
        let acc = get(c, id)?;
        let ex = acc.items.iter().find(|i| i.kind == "asvs").unwrap();
        assert!(ex.removed_at.is_some() && ex.removed_reason.contains("now compliant"), "{ex:?}");
        Ok(())
    })
    .unwrap();
}

#[test]
fn acceptances_are_validated() {
    let db = setup();
    db.with(|c| {
        let f = finding(c, 1, "Weak TLS", "confirmed");
        let cases: Vec<(Change, &str)> = vec![
            (Box::new(|d| d.justification = "  ".into()), "justification is required"),
            (Box::new(|d| d.owner = String::new()), "risk owner is required"),
            (Box::new(|d| d.approver = String::new()), "approver is required"),
            (Box::new(|d| d.expires_at = day(0)), "after today"),
            (Box::new(|d| d.expires_at = day(-3)), "after today"),
            (Box::new(|d| d.expires_at = day(4 * 365)), "three years"),
            (Box::new(|d| d.approved_at = day(2)), "in the future"),
            (Box::new(|d| d.expires_at = "next spring".into()), "YYYY-MM-DD"),
            (Box::new(|d| d.review_at = Some(day(120))), "no later than the expiry"),
        ];
        for (change, words) in cases {
            let mut d = draft(90);
            change(&mut d);
            let err = create(c, 1, &d, &[it("finding", f)], "user").unwrap_err().to_string();
            assert!(err.contains(words), "{words}: {err}");
        }
        assert_eq!(status(c, f), "confirmed", "nothing changed on a refused acceptance");
        assert!(create(c, 1, &draft(90), &[], "user").is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn leaving_expiring_renewing_and_revoking() {
    let db = setup();
    db.with(|c| {
        let f = finding(c, 1, "Weak TLS", "confirmed");
        let g = finding(c, 1, "Old ciphers", "new");
        let v = vuln(c, 1);
        let id = create(c, 1, &draft(60), &[it("finding", f), it("finding", g), it("vulnerability", v)], "user")?;
        // a finding that leaves (reopened by the analyst) is released with the reason
        crate::workspace::findings::set_status(c, g, "reopened", "the vendor shipped a patch", "user")?;
        let acc = get(c, id)?;
        let left = acc.items.iter().find(|i| i.ref_id == g).unwrap();
        assert!(left.removed_at.is_some() && left.removed_reason.contains("reopened"));
        // and cannot come back as accepted without being covered again
        assert!(crate::workspace::findings::set_status(c, g, "accepted_risk", "", "user").is_err());
        // expiry is computed: nothing changes status by itself, everything is flagged
        c.execute("UPDATE risk_acceptances SET expires_at = ?2 WHERE id = ?1", params![id, day(-1)])?;
        assert_eq!(get(c, id)?.standing, "expired");
        assert_eq!(status(c, f), "accepted_risk");
        assert_eq!(summary(c, 1)?.expired, 1);
        assert_eq!(list(c, 1)?[0].id, id, "expired first");
        let err = crate::workspace::findings::set_status(c, g, "accepted_risk", "", "user").unwrap_err().to_string();
        assert!(err.contains("only through a risk acceptance"), "{err}");
        // renewed with a new approval
        let mut d = draft(120);
        d.approver = "CFO".into();
        d.review_at = Some(day(30));
        renew(c, id, &d, "user")?;
        let acc = get(c, id)?;
        assert_eq!((acc.standing.as_str(), acc.approver.as_str(), acc.expires_at.clone()), ("active", "CFO", day(120)));
        c.execute("UPDATE risk_acceptances SET review_at = ?2 WHERE id = ?1", params![id, day(0)])?;
        assert_eq!(get(c, id)?.standing, "review_due");
        // revoked: what it still covered is reopened, with the reason
        revoke(c, id, "the compensating ACL was removed", "user")?;
        assert_eq!(status(c, f), "reopened");
        let vs: String = c.query_row("SELECT status FROM vulnerabilities WHERE id = ?1", params![v], |r| r.get(0))?;
        assert_eq!(vs, "open");
        let acc = get(c, id)?;
        assert_eq!(acc.standing, "revoked");
        assert!(acc.items.iter().all(|i| i.removed_at.is_some()));
        assert!(revoke(c, id, "again", "user").is_err() && renew(c, id, &draft(30), "user").is_err());
        let actions: Vec<String> = history(c, id)?.into_iter().map(|e| e.action).collect();
        assert_eq!(actions, ["created", "item_added", "item_added", "item_added", "item_removed", "renewed", "revoked"]);
        Ok(())
    })
    .unwrap();
}

#[test]
fn moving_documenting_and_deleting_items() {
    let db = setup();
    db.with(|c| {
        // a finding marked accepted before risk acceptance records existed
        let legacy = finding(c, 1, "Accepted in 2025", "accepted_risk");
        assert_eq!(uncovered_findings(c, 1)?, vec![(legacy, "Accepted in 2025".to_string())]);
        let a = create(c, 1, &draft(30), &[it("finding", legacy)], "user")?;
        assert!(uncovered_findings(c, 1)?.is_empty(), "documented");
        assert_eq!(status(c, legacy), "accepted_risk");
        // covered by a second acceptance: it moves, and revoking the first leaves it accepted
        let b = create(c, 1, &draft(200), &[it("finding", legacy)], "user")?;
        assert!(get(c, a)?.items[0].removed_reason.contains(&format!("moved to acceptance #{b}")));
        revoke(c, a, "replaced", "user")?;
        assert_eq!(status(c, legacy), "accepted_risk");
        // a deleted finding leaves no item behind
        c.execute("DELETE FROM findings WHERE id = ?1", params![legacy])?;
        assert!(get(c, b)?.items.is_empty());
        // the editor moving a finding away from accepted releases it too
        let f = finding(c, 1, "Weak TLS", "new");
        create(c, 1, &draft(30), &[it("finding", f)], "user")?;
        let input = crate::commands::projects::FindingInput { id: Some(f), project_id: 1, title: "Weak TLS".into(), severity: "high".into(), status: "in_remediation".into(), ..Default::default() };
        crate::commands::projects::finding_write(c, &input, "user", false)?;
        assert!(cover(c, "finding", f, "")?.is_none());
        // a vulnerability verified as fixed is released
        let v = vuln(c, 1);
        let x = create(c, 1, &draft(30), &[it("vulnerability", v)], "user")?;
        crate::workspace::vulns::verify(c, v, "patched to 5.6.2", "user")?;
        assert!(get(c, x)?.items[0].removed_reason.contains("verified"));
        Ok(())
    })
    .unwrap();
}

fn wstg(test: &str) -> ItemRef {
    ItemRef { kind: "wstg".into(), ref_id: 1, requirement: test.into() }
}

fn check(c: &Connection, test: &str, status: &str, source: &str) -> AppResult<()> {
    crate::methodology::set(c, 1, test, status, "", crate::methodology::Link::Keep, source).map(|_| ())
}

fn test_status(c: &Connection, test: &str) -> String {
    c.query_row("SELECT status FROM checklist_items WHERE project_id = 1 AND test_id = ?1", params![test], |r| r.get(0)).unwrap()
}

/// Mission 6: a WSTG test that failed can have a documented exception. The test stays failed,
/// every path that changes its result ends the exception, and nothing marks it passed.
#[test]
fn a_failed_wstg_test_can_have_an_exception_that_never_passes_it() {
    let db = setup();
    db.with(|c| {
        // only a failed test of the bundled checklist, of this project, can be excepted
        check(c, "WSTG-ATHN-03", "passed", "user")?;
        let err = create(c, 1, &draft(60), &[wstg("WSTG-ATHN-03")], "user").unwrap_err().to_string();
        assert!(err.contains("a test that failed"), "{err}");
        let err = create(c, 1, &draft(60), &[wstg("WSTG-ATHN-04")], "user").unwrap_err().to_string();
        assert!(err.contains("a test that failed"), "not started is not failed: {err}");
        let err = create(c, 1, &draft(60), &[wstg("WSTG-NOPE-99")], "user").unwrap_err().to_string();
        assert!(err.contains("not a test of the bundled WSTG checklist"), "{err}");
        let other = ItemRef { kind: "wstg".into(), ref_id: 2, requirement: "WSTG-ATHN-03".into() };
        assert!(create(c, 1, &draft(60), &[other], "user").unwrap_err().to_string().contains("not part of this project"));

        check(c, "WSTG-ATHN-03", "failed", "user")?;
        check(c, "WSTG-SESS-02", "failed", "user")?;
        // the id is matched as the catalog spells it
        let id = create(c, 1, &draft(60), &[wstg("wstg-athn-03"), wstg("WSTG-SESS-02")], "user")?;
        assert_eq!(test_status(c, "WSTG-ATHN-03"), "failed", "an exception is not a pass");
        assert!(cover(c, "wstg", 1, "WSTG-ATHN-03")?.is_some_and(|(a, _, _)| a == id));
        let acc = get(c, id)?;
        let labels: Vec<(String, String)> = acc.items.iter().map(|i| (i.label.clone(), i.status.clone())).collect();
        assert_eq!(labels, [("WSTG-ATHN-03".to_string(), "failed".to_string()), ("WSTG-SESS-02".to_string(), "failed".to_string())]);
        assert!(crate::methodology::coverage(c, 1)?.failed == 2, "coverage still counts both as failed");

        // the analyst's retest (the UI path) ends one exception, with the reason
        check(c, "WSTG-ATHN-03", "passed", "user")?;
        let acc = get(c, id)?;
        let left = acc.items.iter().find(|i| i.requirement == "WSTG-ATHN-03").unwrap();
        assert!(left.removed_at.is_some() && left.removed_reason.contains("now passed"), "{}", left.removed_reason);
        // an MCP client's change goes through the same rule
        let set = crate::mcp::assessment::ChecklistSet { project_id: 1, test_id: "WSTG-SESS-02".into(), status: "not_applicable".into(), note: None, finding_id: None, unlink_finding: false };
        crate::mcp::assessment::set_checklist(c, &set)?;
        let acc = get(c, id)?;
        let left = acc.items.iter().find(|i| i.requirement == "WSTG-SESS-02").unwrap();
        assert!(left.removed_at.is_some() && left.removed_reason.contains("not applicable"), "{}", left.removed_reason);
        let sources: Vec<String> = history(c, id)?.into_iter().filter(|e| e.action == "item_removed").map(|e| e.source).collect();
        assert_eq!(sources, ["user", "mcp"]);
        // failing again does not bring the exception back: a new acceptance is needed
        check(c, "WSTG-ATHN-03", "failed", "user")?;
        assert!(cover(c, "wstg", 1, "WSTG-ATHN-03")?.is_none());
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_expired_or_revoked_wstg_exception_is_flagged_and_changes_no_result() {
    let db = setup();
    db.with(|c| {
        check(c, "WSTG-CRYP-01", "failed", "user")?;
        let id = create(c, 1, &draft(60), &[wstg("WSTG-CRYP-01")], "user")?;
        c.execute("UPDATE risk_acceptances SET expires_at = ?2 WHERE id = ?1", params![id, day(-1)])?;
        assert_eq!(get(c, id)?.standing, "expired");
        assert_eq!(summary(c, 1)?.expired, 1);
        assert_eq!(test_status(c, "WSTG-CRYP-01"), "failed", "expiry never changes a result");
        revoke(c, id, "the TLS migration slipped again", "user")?;
        assert_eq!(test_status(c, "WSTG-CRYP-01"), "failed", "revoking never changes a result either");
        assert!(get(c, id)?.items.iter().all(|i| i.removed_at.is_some()));
        // the report says what the exception is and is not
        let md = crate::workspace::report::markdown(c, 1, &crate::workspace::report::ReportOptions::default(), "2026-11-10")?;
        assert!(!md.contains("## Risk acceptances and exceptions"), "a revoked acceptance alone is not listed as a section");
        check(c, "WSTG-CRYP-02", "failed", "user")?;
        create(c, 1, &draft(30), &[wstg("WSTG-CRYP-02")], "user")?;
        let md = crate::workspace::report::markdown(c, 1, &crate::workspace::report::ReportOptions::default(), "2026-11-10")?;
        assert!(md.contains("## Risk acceptances and exceptions"), "{md}");
        assert!(md.contains("WSTG-CRYP-02 (test failed, exception)"));
        assert!(md.contains("excepted WSTG tests stay failed"));
        assert!(md.contains("One failed test has a documented exception and stays failed"));
        assert!(md.contains("1 revoked acceptance is not listed."));
        let html = crate::workspace::report::render(c, 1, &crate::workspace::report::ReportOptions::default(), "2026-11-10")?;
        assert!(html.contains("Risk acceptances and exceptions") && html.contains("WSTG-CRYP-02 (test failed, exception)"));
        Ok(())
    })
    .unwrap();
}

/// Migration 30 copied the items table: its triggers still drop the items of deleted records.
#[test]
fn the_items_table_keeps_its_triggers_after_migration_30() {
    let db = setup();
    db.with(|c| {
        let f = finding(c, 1, "Weak TLS", "confirmed");
        let id = create(c, 1, &draft(60), &[it("finding", f)], "user")?;
        c.execute("DELETE FROM findings WHERE id = ?1", params![f])?;
        let n: i64 = c.query_row("SELECT COUNT(*) FROM risk_acceptance_items WHERE acceptance_id = ?1", params![id], |r| r.get(0))?;
        assert_eq!(n, 0);
        let sql: String = c.query_row("SELECT sql FROM sqlite_master WHERE name = 'risk_acceptance_items'", [], |r| r.get(0))?;
        assert!(sql.contains("'wstg'"));
        let triggers: i64 = c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'risk_items_%'", [], |r| r.get(0))?;
        assert_eq!(triggers, 3);
        Ok(())
    })
    .unwrap();
}
