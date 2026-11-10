//! Tests of the detection library: versions, collections, tests with expectations, feedback,
//! project hits and their promotion, and ATT&CK coverage.

use super::*;
use crate::db::Db;
use crate::detection::events::{Event, Kind, Sample};

const RULE: &str = "title: Failed logon burst
id: 0f1e2d3c-4b5a-4968-8776-655443322110
status: test
tags:
    - attack.credential_access
    - attack.t1110.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: medium
";

fn ev(id: &str, user: &str) -> Event {
    Event { position: format!("record {user}"), time: "2026-11-09T10:00:00Z".into(), fields: vec![("Channel".into(), "Security".into()), ("EventID".into(), id.into()), ("Computer".into(), "DC01".into()), ("TargetUserName".into(), user.into())], text: String::new() }
}

fn sample(events: Vec<Event>) -> Sample {
    Sample { kind: Kind::Evtx, events, truncated: false, warnings: vec![] }
}

fn import(c: &Connection, text: &str) -> Imported {
    let checked = crate::detection::sigma::read(text).unwrap().remove(0);
    upsert_sigma(c, text, &checked, "rules.yml", "").unwrap()
}

#[test]
fn rules_are_versioned_organized_and_listed() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let a = import(c, RULE);
        assert_eq!((a.outcome, a.version, a.errors), ("added", 1, 0));
        assert_eq!(import(c, RULE).outcome, "unchanged", "the same content is the same version");
        let changed = RULE.replace("level: medium", "level: high");
        let b = import(c, &changed);
        assert_eq!((b.id, b.outcome, b.version), (a.id, "updated", 2), "the same id is a new version");
        let d = get(c, a.id)?;
        assert_eq!(d.versions.iter().map(|v| v.version).collect::<Vec<_>>(), vec![2, 1]);
        assert_eq!(version_content(c, a.id, 1)?, RULE);
        assert_eq!((d.summary.level.as_str(), d.summary.techniques.clone()), ("high", vec!["T1110.001".to_string()]));
        // a rule without an id is identified by its title and log source
        let noid = import(c, "title: Other\nlogsource:\n    product: linux\ndetection:\n    k:\n        - sudo\n    condition: k\n");
        assert_ne!(noid.id, a.id);
        // an invalid rule is kept with its problems, but cannot run
        let bad = import(c, "title: Broken\nlogsource:\n    product: windows\ndetection:\n    s:\n        F|frobnicate: x\n    condition: s\n");
        assert_eq!(bad.errors, 1);
        assert!(!get(c, bad.id)?.summary.runnable);
        assert_eq!(runnable(c, None)?.len(), 2, "only valid, enabled rules run");
        set_enabled(c, noid.id, false)?;
        assert_eq!(runnable(c, None)?.len(), 1);
        // collections and filters
        let col = collection_create(c, "Credential access", "")?;
        assert!(collection_create(c, "credential ACCESS", "").is_err(), "names are unique");
        collection_member(c, col, a.id, true)?;
        assert_eq!(runnable(c, Some(col))?.iter().map(|r| r.id).collect::<Vec<_>>(), vec![a.id]);
        assert_eq!(list(c, &ListFilter { collection: Some(col), ..Default::default() })?.total, 1);
        assert_eq!(list(c, &ListFilter { technique: Some("t1110.001".into()), ..Default::default() })?.items[0].id, a.id);
        assert_eq!(list(c, &ListFilter { text: Some("broken".into()), ..Default::default() })?.items[0].id, bad.id);
        assert_eq!(list(c, &ListFilter { enabled: Some(false), ..Default::default() })?.items[0].id, noid.id);
        assert_eq!(collections(c)?[0].rules, 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn tests_check_expectations_and_flag_broad_rules() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let a = import(c, RULE);
        let rule = compile(&stored(c, a.id)?)?;
        let spray: Vec<Event> = (0..30).map(|i| ev("4625", &format!("user{i}"))).collect();
        let r = run(&rule, &sample(spray.clone()));
        assert_eq!((r.events, r.in_source, r.matched), (30, 30, 30));
        assert!(r.notes.iter().any(|n| n.contains("too broad")), "{:?}", r.notes);
        assert_eq!(r.matches[0].explanation["selections"][0]["hits"][0]["field"], "EventID");
        let quiet = run(&rule, &sample(vec![ev("4624", "a"), ev("4634", "b")]));
        assert_eq!(quiet.matched, 0);
        // expectations make tests pass or fail
        let s1 = sample_add(c, "aa", "spray.evtx", "evtx", 10, 30)?;
        let s2 = sample_add(c, "bb", "normal.evtx", "evtx", 10, 2)?;
        assert_eq!(sample_add(c, "aa", "copy.evtx", "evtx", 10, 30)?, s1, "a sample is kept once per content");
        set_expect(c, a.id, s1, "match")?;
        set_expect(c, a.id, s2, "no_match")?;
        assert!(set_expect(c, a.id, s2, "maybe").is_err());
        assert_eq!(record_test(c, a.id, 1, s1, &r)?.passed, Some(true));
        assert_eq!(record_test(c, a.id, 1, s2, &quiet)?.passed, Some(true));
        assert!(coverage(c)?["T1110.001"][0].tested);
        // a new version that stops matching fails its regression test
        assert_eq!(record_test(c, a.id, 2, s1, &quiet)?.passed, Some(false));
        let d = get(c, a.id)?;
        assert_eq!((d.summary.tests_passed, d.summary.tests_failed), (1, 1));
        assert!(!coverage(c)?["T1110.001"][0].tested, "a failing sample makes the coverage untested");
        // a sample without expectation records a test that neither passes nor fails
        let s3 = sample_add(c, "cc", "other.json", "json", 1, 2)?;
        assert_eq!(record_test(c, a.id, 2, s3, &quiet)?.passed, None);
        Ok(())
    })
    .unwrap();
}

#[test]
fn hits_stay_leads_until_the_analyst_promotes_them() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't'), (2, 'Old', 'archived', 't', 't')", [])?;
        c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (7, 1, 'file', 'Security.evtx', 'user', 'ab', 10, 'Security.evtx', 't')", [])?;
        let a = import(c, RULE);
        let s = stored(c, a.id)?;
        let rule = compile(&s)?;
        let r = run(&rule, &sample(vec![ev("4625", "alice"), ev("4625", "bob"), ev("4624", "carol")]));
        assert_eq!(hits_store(c, 1, &s, 7, &r.matches)?, (2, 0));
        assert_eq!(hits_store(c, 1, &s, 7, &r.matches)?, (0, 2), "a second run adds no duplicate");
        let page = hits_list(c, 1, &HitFilter::default())?;
        assert_eq!((page.total, page.items[0].evidence.as_str(), page.counts["new"]), (2, "Security.evtx", 2));
        assert_eq!(hits_by_technique(c, 1)?["T1110.001"], 2);
        // a false positive is feedback on the rule
        hit_set(c, page.items[0].id, "false_positive", "service account")?;
        let d = get(c, a.id)?;
        assert_eq!((d.summary.false_positives, d.feedback[0].project.as_str(), d.feedback[0].note.as_str()), (1, "IR", "service account"));
        assert_eq!(hits_by_technique(c, 1)?["T1110.001"], 1, "false positives do not count");
        // promotion makes a finding under review, linked to the evidence
        let fid = hit_promote(c, page.items[1].id)?;
        let (title, status, severity, tags, conf): (String, String, String, String, String) =
            c.query_row("SELECT title, status, severity, tags, confidence FROM findings WHERE id = ?1", params![fid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        assert_eq!((title.as_str(), status.as_str(), severity.as_str(), conf.as_str()), ("Failed logon burst (DC01)", "under_review", "medium", "low"));
        assert!(tags.contains("T1110.001") && tags.contains("detection"));
        assert_eq!(crate::workspace::findings::links(c, fid)?.iter().map(|l| (l.kind.as_str(), l.ref_id)).collect::<Vec<_>>(), vec![("evidence", 7)]);
        assert_eq!(hit_promote(c, page.items[1].id)?, fid, "promoting twice is the same finding");
        assert!(hit_set(c, page.items[1].id, "dismissed", "").is_err(), "a promoted hit is changed through its finding");
        assert_eq!(get(c, a.id)?.projects[0].findings, 1);
        // archived projects take no decision; deleting the rule keeps the hits
        c.execute("INSERT INTO detection_hits (project_id, rule_id, rule_title, rule_version, position, created_at) VALUES (2, ?1, 'x', 1, 'line 1', 't')", params![a.id])?;
        let archived_hit = c.last_insert_rowid();
        assert!(hit_set(c, archived_hit, "dismissed", "").is_err());
        assert!(hit_promote(c, archived_hit).is_err());
        delete(c, a.id)?;
        assert_eq!(hits_list(c, 1, &HitFilter::default())?.total, 2);
        assert!(hits_list(c, 1, &HitFilter::default())?.items.iter().all(|h| h.rule_id.is_none()));
        assert_eq!(c.query_row("SELECT COUNT(*) FROM detection_rule_versions", [], |r| r.get::<_, i64>(0))?, 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn rule_files_split_into_documents() {
    let docs = documents("# header\ntitle: a\n---\n\n---\ntitle: b\n...\n");
    assert_eq!(docs.len(), 2);
    assert!(docs[0].contains("title: a") && docs[1].contains("title: b"));
}

const YARA: &str = r#"
private rule IsMz { condition: uint16(0) == 0x5A4D }
rule Demo_Dropper : dropper
{
    meta:
        description = "Dropper strings of the demo sample"
        author = "Cyber Hub tests"
        severity = "high"
        mitre_attack = "T1105"
    strings:
        $url = "http://evil.example/stage2" ascii wide
        $mutex = "Global\\DemoMutex"
    condition:
        IsMz and any of them
}
"#;

fn import_yara(c: &Connection, name: &str, text: &str) -> Imported {
    let checked = crate::detection::yara::check(text);
    upsert_yara(c, &yara_key(name), name, text, &checked, name, "").unwrap()
}

#[test]
fn yara_files_are_versioned_tested_and_promoted() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't')", [])?;
        c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (9, 1, 'file', 'invoice.exe', 'user', 'cd', 10, 'invoice.exe', 't')", [])?;
        let a = import_yara(c, "Dropper.yar", YARA);
        assert_eq!((a.outcome, a.title.as_str(), a.errors), ("added", "Demo_Dropper", 0));
        assert_eq!(import_yara(c, "dropper.yar", YARA).outcome, "unchanged", "the same file name and content");
        let b = import_yara(c, "dropper.yar", &YARA.replace("any of them", "all of them"));
        assert_eq!((b.id, b.outcome, b.version), (a.id, "updated", 2), "the same file name is a new version");
        let d = get(c, a.id)?;
        assert_eq!((d.summary.kind.as_str(), d.summary.level.as_str(), d.summary.logsource.as_str()), ("yara", "high", "files"));
        assert_eq!(d.summary.techniques, vec!["T1105"]);
        assert_eq!(d.meta["rules"].as_array().map(Vec::len), Some(2));
        // a file that does not compile is kept with its problem and cannot run
        let broken = import_yara(c, "broken.yar", "rule Broken { condition: $nothing }");
        assert_eq!((broken.title.as_str(), broken.errors), ("broken.yar", 1));
        assert!(!get(c, broken.id)?.summary.runnable);
        assert_eq!(list(c, &ListFilter { kind: Some("yara".into()), ..Default::default() })?.total, 2);
        assert_eq!(runnable(c, None)?.iter().map(|s| s.kind.as_str()).collect::<Vec<_>>(), vec!["yara"]);

        // a test on a file sample
        let s = stored(c, a.id)?;
        assert!(compile(&s).is_err(), "a YARA file is not a Sigma rule");
        let scanner = compile_yara(&s)?;
        let mut file = b"MZ\x90\x00".to_vec();
        file.extend_from_slice(b"..h\0t\0t\0p\0:\0/\0/\0e\0v\0i\0l\0.\0e\0x\0a\0m\0p\0l\0e\0/\0s\0t\0a\0g\0e\x002\0..Global\\DemoMutex");
        let r = yara_result(&crate::detection::yara::scan(&scanner, &file), "invoice.exe");
        assert_eq!((r.events, r.matched), (1, 1));
        assert_eq!(r.matches[0].position, "rule Demo_Dropper");
        assert_eq!(r.matches[0].explanation["strings"].as_array().map(Vec::len), Some(2), "all of them matched");
        let sid = sample_add(c, "ef", "invoice.exe", "file", file.len() as i64, 0)?;
        set_expect(c, a.id, sid, "match")?;
        assert_eq!(record_test(c, a.id, s.version, sid, &r)?.passed, Some(true));
        let clean = yara_result(&crate::detection::yara::scan(&scanner, b"MZ nothing here"), "clean.exe");
        assert_eq!(clean.matched, 0);

        // hits in a project, promoted to a finding linked to the file
        assert_eq!(hits_store(c, 1, &s, 9, &r.matches)?, (1, 0));
        assert_eq!(hits_store(c, 1, &s, 9, &r.matches)?, (0, 1), "the same rule on the same file is one hit");
        let hit = hits_list(c, 1, &HitFilter::default())?.items.remove(0);
        assert_eq!(hit.explanation["kind"], "yara");
        let fid = hit_promote(c, hit.id)?;
        let (title, status, tags, description, details): (String, String, String, String, String) =
            c.query_row("SELECT title, status, tags, description, technical_details FROM findings WHERE id = ?1", params![fid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        assert_eq!((title.as_str(), status.as_str()), ("YARA Demo_Dropper (invoice.exe)", "under_review"));
        assert!(tags.contains("yara") && tags.contains("T1105") && !tags.contains("sigma"), "{tags}");
        assert!(description.contains("$url matched 1 time, first at offset 0x6") && description.contains("SHA-256 cd"), "{description}");
        assert!(details.contains("version 2, rule Demo_Dropper"), "{details}");
        assert_eq!(crate::workspace::findings::links(c, fid)?.iter().map(|l| (l.kind.as_str(), l.ref_id)).collect::<Vec<_>>(), vec![("evidence", 9)]);

        // coverage counts YARA files that name techniques
        let cov = coverage(c)?;
        assert_eq!(cov["T1105"].iter().map(|x| (x.kind.as_str(), x.tested)).collect::<Vec<_>>(), vec![("yara", true)]);
        Ok(())
    })
    .unwrap();
}

#[test]
fn any_hit_can_be_reviewed_however_many_the_project_has() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't')", [])?;
        for i in 0..600 {
            c.execute("INSERT INTO detection_hits (project_id, rule_title, rule_version, rule_level, position, created_at) VALUES (1, 'r', 1, ?1, ?2, 't')", params![if i == 0 { "low" } else { "high" }, format!("record {i}")])?;
        }
        let first: i64 = c.query_row("SELECT MIN(id) FROM detection_hits", [], |r| r.get(0))?;
        assert!(!hits_list(c, 1, &HitFilter { limit: Some(500), ..Default::default() })?.items.iter().any(|h| h.id == first), "it is past the first page");
        hit_set(c, first, "dismissed", "noise")?;
        assert_eq!(hit(c, first)?.status, "dismissed");
        assert!(hit(c, 999_999).is_err());
        Ok(())
    })
    .unwrap();
}

/// The specification's complete example: a temporal_ordered correlation over an event_count
/// correlation and a detection rule, in one file of four documents.
const CHAIN: &str = "title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
level: high
tags:
    - attack.t1110
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Single failed login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Successful login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
";

fn login(id: &str, user: &str, second: u32) -> Event {
    Event {
        position: format!("record {id}-{user}-{second}"),
        time: format!("2026-11-09T10:{:02}:{:02}Z", second / 60, second % 60),
        fields: vec![("Channel".into(), "Security".into()), ("EventID".into(), id.into()), ("User".into(), user.into())],
        text: String::new(),
    }
}

fn import_file(c: &Connection, text: &str, source: &str) -> Vec<(Checked, Imported)> {
    documents(text)
        .iter()
        .map(|d| {
            let ch = crate::detection::sigma::read(d).unwrap().remove(0);
            let imp = upsert_sigma(c, d, &ch, source, "").unwrap();
            (ch, imp)
        })
        .collect()
}

#[test]
fn correlation_rules_resolve_in_the_library_and_their_hits_are_reviewable_leads() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't')", [])?;
        c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (7, 1, 'file', 'dc1-Security.evtx', 'user', 'ab', 10, 'a.evtx', 't'), (8, 1, 'file', 'dc2-Security.evtx', 'user', 'cd', 10, 'b.evtx', 't')", [])?;
        let docs = import_file(c, CHAIN, "mr_failed_then_success.yml");
        assert!(docs.iter().all(|(ch, imp)| ch.runnable() && imp.outcome == "added"), "{:?}", docs.iter().map(|(c, _)| &c.issues).collect::<Vec<_>>());
        // the base rules only run as part of the correlation (no generate: true)
        let mut disabled = disable_correlated(c, &docs)?;
        disabled.sort();
        assert_eq!(disabled, vec!["Multiple failed logons".to_string(), "Single failed login".to_string(), "Successful login".to_string()]);
        let runnable_ids: Vec<i64> = runnable(c, None)?.iter().map(|s| s.id).collect();
        assert_eq!(runnable_ids, vec![docs[0].1.id], "only the outer correlation runs; the inner one and the rules only through it");
        assert!(compile(&stored(c, docs[0].1.id)?).is_err(), "a correlation is not a detection rule");

        // ten failures on one domain controller, the success on another: one chain across files
        let outer = stored(c, docs[0].1.id)?;
        let mut tree = correlation_tree(c, &outer)?.expect("a correlation");
        tree.feed(&sample((0..10).map(|i| login("4625", "admin", i * 20)).collect()), 7, "dc1-Security.evtx");
        tree.feed(&sample(vec![login("4624", "admin", 240), login("4624", "guest", 250)]), 8, "dc2-Security.evtx");
        let run = finish_correlation(tree);
        assert_eq!(run.matched, 1, "{:?}", run.notes);
        let (evidence, m) = &run.matches[0];
        assert_eq!(*evidence, 8, "stored with the evidence of the window's last event");
        assert_eq!(m.position, "window 2026-11-09T10:03:00Z – 2026-11-09T10:04:00Z · User=admin");
        assert_eq!(m.explanation["events"][0]["sourceId"], 7);
        assert_eq!(hits_store(c, 1, &outer, *evidence, std::slice::from_ref(m))?, (1, 0));
        assert_eq!(hits_store(c, 1, &outer, *evidence, std::slice::from_ref(m))?, (0, 1), "a second run adds no duplicate");

        // promoted: a finding under review linked to both domain controllers' logs
        let hit_id = hits_list(c, 1, &HitFilter::default())?.items[0].id;
        let fid = hit_promote(c, hit_id)?;
        let (status, confidence, tags, description): (String, String, String, String) = c.query_row("SELECT status, confidence, tags, description FROM findings WHERE id = ?1", params![fid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        assert_eq!((status.as_str(), confidence.as_str()), ("under_review", "low"));
        assert!(tags.contains("correlation") && tags.contains("T1110"), "{tags}");
        assert!(description.contains("all 2 rules in order") && description.contains("multiple_failed_login: window") && description.contains("confirm each event"), "{description}");
        let linked: Vec<i64> = c.prepare("SELECT ref_id FROM finding_links WHERE finding_id = ?1 AND kind = 'evidence' ORDER BY ref_id")?.query_map(params![fid], |r| r.get(0))?.collect::<Result<_, _>>()?;
        assert_eq!(linked, vec![7, 8]);

        // as a test on one sample
        let tree = correlation_tree(c, &outer)?.unwrap();
        let mut events: Vec<Event> = (0..10).map(|i| login("4625", "root", i * 5)).collect();
        events.push(login("4624", "root", 100));
        let r = correlation_result(tree, &sample(events), 3, "burst.evtx");
        assert_eq!((r.matched, r.events), (1, 11));
        Ok(())
    })
    .unwrap();
}

#[test]
fn correlation_references_prefer_their_own_file_and_refuse_ambiguity() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let docs = import_file(c, CHAIN, "mr_failed_then_success.yml");
        // another file with its own rule named failed_login
        let other = "title: Failed login (other source)\nid: 11111111-2222-4333-8444-555555555555\nname: failed_login\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4771\n    condition: selection\n";
        import_file(c, other, "kerberos.yml");
        assert!(correlation_tree(c, &stored(c, docs[1].1.id)?)?.is_some(), "the correlation's own file wins");
        // a third file refers to the shared name: ambiguous
        let third = "title: Third\ncorrelation:\n    type: event_count\n    rules: [failed_login]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        gte: 3\n";
        let t = import_file(c, third, "third.yml");
        let err = correlation_tree(c, &stored(c, t[0].1.id)?).err().unwrap().to_string();
        assert!(err.contains("Several rules in the library are named 'failed_login'"), "{err}");
        // by id it is unambiguous, without regard to case
        let by_id = "title: By id\ncorrelation:\n    type: event_count\n    rules: [53BA33FD-3A50-4468-A5EF-C583635CFA92]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        gte: 3\n";
        let t = import_file(c, by_id, "by-id.yml");
        assert!(correlation_tree(c, &stored(c, t[0].1.id)?)?.is_some());
        let missing = "title: Missing\ncorrelation:\n    type: event_count\n    rules: [nowhere]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        gte: 3\n";
        let t = import_file(c, missing, "missing.yml");
        assert!(correlation_tree(c, &stored(c, t[0].1.id)?).err().unwrap().to_string().contains("No Sigma rule named or identified 'nowhere'"));
        // generate: true keeps the referenced rules running on their own
        let gen = CHAIN.replace("level: high\n", "level: high\ngenerate: true\n").replace("b180ead8", "c180ead8").replace("Correlation - Multiple", "Generated - Multiple");
        let db2 = Db::open_in_memory().unwrap();
        db2.with(|c2| {
            let docs = import_file(c2, &gen, "gen.yml");
            // the inner correlation (no generate) still disables its own rule; the outer keeps the inner one and the success rule running
            assert_eq!(disable_correlated(c2, &docs)?, vec!["Single failed login".to_string()]);
            Ok(())
        })?;
        Ok(())
    })
    .unwrap();
}
