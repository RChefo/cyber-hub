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
