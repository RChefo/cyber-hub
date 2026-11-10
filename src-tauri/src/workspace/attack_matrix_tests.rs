//! Tests of the ATT&CK matrix: what findings name, assessments, imported layers and the export.

use super::*;
use crate::db::Db;
use crate::workspace::relations::Ref;

fn layer(body: &str) -> Vec<u8> {
    body.as_bytes().to_vec()
}

#[test]
fn layers_are_read_by_the_specification_and_checked_against_the_catalog() {
    let l = parse_layer(&layer(
        r##"{"name":"SOC coverage","versions":{"attack":"14","navigator":"4.9.1","layer":"4.5"},"domain":"enterprise-attack","description":"Detections",
            "techniques":[
              {"techniqueID":"T1059.001","tactic":"execution","score":2,"color":"#31a354","comment":"Sigma: encoded PowerShell","enabled":true},
              {"techniqueID":"t1059.001","tactic":"defense-evasion","score":3,"comment":"EDR rule"},
              {"techniqueID":"T1143","score":1,"comment":"old ID"},
              {"techniqueID":"T9999","score":1},
              {"techniqueID":"not-an-id","score":1},
              {"techniqueID":"T1003","enabled":false,"color":"javascript:alert(1)"}
            ]}"##,
    ))
    .unwrap();
    assert_eq!(l.name, "SOC coverage");
    assert_eq!((l.layer_version.as_str(), l.attack_version.as_str(), l.navigator_version.as_str()), ("4.5", "14", "4.9.1"));
    let ps = &l.techniques["T1059.001"];
    assert_eq!((ps.score, ps.color.as_str(), ps.enabled), (Some(3.0), "#31a354", true), "one entry per technique: the highest score");
    assert_eq!(ps.comment, "Sigma: encoded PowerShell / EDR rule");
    assert_eq!(l.remapped.get("T1143").map(String::as_str), Some("T1564.003"), "a revoked ID counts for the technique that replaced it");
    assert!(l.techniques.contains_key("T1564.003") && !l.techniques.contains_key("T1143"));
    assert_eq!(l.unknown, vec!["T9999".to_string(), "not-an-id".to_string()], "unknown IDs are counted, never guessed");
    let cred = &l.techniques["T1003"];
    assert!(!cred.enabled && cred.color.is_empty(), "a disabled entry stays disabled, and only colors are kept as colors");
    assert!(l.warnings.iter().any(|w| w.contains("made for ATT&CK v14")), "{:?}", l.warnings);

    // older layer formats
    let old = parse_layer(&layer(r#"{"name":"v3","version":"3.0","domain":"mitre-enterprise","techniques":[{"techniqueID":"T1110","score":1}]}"#)).unwrap();
    assert_eq!((old.layer_version.as_str(), old.techniques.len()), ("3.0", 1));
    // other domains, other files
    for (bad, why) in [
        // a technique of another domain is not in this domain's catalog (Mission 6)
        (r#"{"name":"m","domain":"mobile-attack","techniques":[{"techniqueID":"T1059.001"}]}"#, "None of the layer's techniques is in ATT&CK Mobile"),
        (r#"{"name":"i","domain":"ics-attack","techniques":[{"techniqueID":"T1404"}]}"#, "None of the layer's techniques is in ATT&CK ICS"),
        (r#"{"name":"p","domain":"pre-attack","techniques":[{"techniqueID":"T1404"}]}"#, "Unknown layer domain"),
        (r#"{"name":"x","domain":"enterprise-attack"}"#, "no technique list"),
        (r#"{"name":"x","domain":"enterprise-attack","techniques":[{"techniqueID":"T9999"}]}"#, "None of the layer's techniques"),
        ("[1,2]", "JSON object"),
        ("not json", "not a JSON file"),
    ] {
        let e = parse_layer(&layer(bad)).unwrap_err();
        assert!(e.contains(why), "{bad}: {e}");
    }
    assert!(parse_layer(&vec![b' '; MAX_LAYER_BYTES + 1]).unwrap_err().contains("10 MB"));
}

#[test]
fn findings_assessments_and_layers_stay_apart() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('IR', 'active', 't', 't')", [])?;
        let p = c.last_insert_rowid();
        let finding = |title: &str, status: &str, tags: &str, technical: &str| -> i64 {
            c.execute(
                "INSERT INTO findings (project_id, title, severity, status, tags, technical_details, created_at, updated_at) VALUES (?1, ?2, 'high', ?3, ?4, ?5, 't', 't')",
                params![p, title, status, tags, technical],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        let f1 = finding("Injects code", "new", r#"["file","T1055"]"#, "");
        let f2 = finding("Encoded PowerShell", "confirmed", "[]", "Rule WIN-PS-ENC. MITRE ATT&CK: T1059.001.");
        finding("Dumps LSASS", "false_positive", r#"["T1003"]"#, "");
        c.execute("INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (?1, 'file', 'sample', 'user', ?2, 1, 's', 't')", params![p, "e".repeat(64)])?;
        let ev = c.last_insert_rowid();
        crate::workspace::findings::link(c, f1, "evidence", ev, "utility")?;
        relations::link(c, p, Ref::new("finding", f2), Ref::technique("t1105"), "related_to", "", "user")?;

        let m = matrix(c, p)?;
        let get = |m: &Matrix, id: &str| m.entries.iter().find(|e| e.id == id).cloned();
        let inj = get(&m, "T1055").expect("named by a finding");
        assert_eq!((inj.name.as_str(), inj.observed[0].finding_id, inj.observed[0].evidence), ("Process Injection", f1, 1));
        assert!(inj.tactics.contains(&"defense-evasion".to_string()) || inj.tactics.contains(&"privilege-escalation".to_string()), "{:?}", inj.tactics);
        assert_eq!(get(&m, "T1059.001").unwrap().parent.as_deref(), Some("T1059"));
        assert!(get(&m, "T1003").is_none(), "a false positive names nothing");
        assert_eq!(get(&m, "T1105").unwrap().linked.len(), 1, "a technique linked by hand is listed with the link");
        assert_eq!((m.counts.observed, m.counts.findings, m.counts.confirmed), (2, 2, 0), "naming is not confirming");

        // the analyst's assessments
        assess(c, p, "t1055", Some("confirmed"), "high", "Sandbox run shows injection into explorer.exe", "user")?;
        assess(c, p, "T1059.001", Some("hypothesis"), "medium", "", "user")?;
        assess(c, p, "T1003", Some("ruled_out"), "high", "LSASS access was the EDR", "user")?;
        assert!(assess(c, p, "T9999", Some("confirmed"), "high", "", "user").is_err(), "unknown techniques are refused");
        assert!(assess(c, p, "T1055", Some("certain"), "high", "", "user").is_err());
        assert!(assess(c, p, "T1055", Some("confirmed"), "absolute", "", "user").is_err());
        let revoked = assess(c, p, "T1143", Some("hypothesis"), "low", "", "user")?.unwrap();
        assert_eq!(revoked.attack_version, attack::catalog().version, "the assessment keeps the catalog version it was made with");
        assess(c, p, "T1143", None, "low", "", "user")?;
        let m = matrix(c, p)?;
        assert_eq!((m.counts.confirmed, m.counts.hypothesis, m.counts.ruled_out), (1, 1, 1));
        assert_eq!(get(&m, "T1003").unwrap().assessment.as_ref().map(|a| a.status.as_str()), Some("ruled_out"), "an assessment without findings is listed");
        let events: i64 = c.query_row("SELECT COUNT(*) FROM relation_events WHERE project_id = ?1 AND action = 'assessed'", params![p], |r| r.get(0))?;
        assert_eq!(events, 5, "each assessment and its removal is on the timeline");

        // an imported layer is an overlay
        let parsed = parse_layer(&layer(r#"{"name":"Coverage","versions":{"layer":"4.5","attack":"20"},"domain":"enterprise-attack","techniques":[{"techniqueID":"T1055","score":1},{"techniqueID":"T1110","score":2}]}"#)).unwrap();
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let lid = store_layer(c, p, "coverage.json", "abc", Some(ev), &parsed)?;
        assert!(store_layer(c, p, "coverage.json", "abc", None, &parsed).is_err(), "the same layer once per project");
        let m = matrix(c, p)?;
        assert_eq!(get(&m, "T1055").unwrap().layers[0].layer_id, lid);
        let brute = get(&m, "T1110").unwrap();
        assert!(brute.observed.is_empty() && brute.assessment.is_none() && brute.layers[0].mark.score == Some(2.0), "listed in a layer, observed nowhere");
        assert_eq!(m.counts.observed, 2, "a layer does not make a technique observed");
        assert_eq!(m.layers[0].techniques, 2);

        // the export: findings and assessments, not the imported layer
        let doc: Value = serde_json::from_str(&export_layer("IR", "now", &m).unwrap()).unwrap();
        assert_eq!(doc["versions"]["layer"], "4.5");
        assert_eq!(doc["versions"]["attack"], attack_major_of(attack::ENTERPRISE));
        assert_eq!(doc["domain"], "enterprise-attack");
        let t = |id: &str| doc["techniques"].as_array().unwrap().iter().find(|t| t["techniqueID"] == id).cloned();
        assert_eq!(t("T1055").unwrap()["color"], "#c62828");
        assert_eq!(t("T1059.001").unwrap()["color"], "#f9a825");
        assert_eq!(t("T1003").unwrap()["enabled"], false, "ruled out is disabled");
        assert!(t("T1110").is_none() && t("T1105").is_none(), "layer-only and link-only techniques are not exported as findings or assessments");
        assert!(t("T1059.001").unwrap()["comment"].as_str().unwrap().contains("leads, not confirmed"));

        // archived projects are read-only; deleting the layer keeps its evidence
        c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", params![p])?;
        assert!(assess(c, p, "T1055", None, "low", "", "user").is_err());
        assert!(delete_layer(c, lid).is_err());
        assert!(matrix(c, p).is_ok(), "an archived project can still be read");
        c.execute("UPDATE projects SET status = 'active' WHERE id = ?1", params![p])?;
        delete_layer(c, lid)?;
        assert!(layers(c, p)?.is_empty());
        assert_eq!(c.query_row("SELECT COUNT(*) FROM evidence WHERE id = ?1", params![ev], |r| r.get::<_, i64>(0))?, 1);

        // everything goes with its project
        c.execute("DELETE FROM projects WHERE id = ?1", params![p])?;
        for table in ["attack_assessments", "attack_layers"] {
            assert_eq!(c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))?, 0, "{table}");
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_empty_project_exports_nothing() {
    let m = Matrix { domain: attack::ENTERPRISE.into(), attack_version: "20.1".into(), attack_modified: String::new(), attack_retrieved: String::new(), entries: Vec::new(), layers: Vec::new(), counts: Counts::default() };
    assert!(export_layer("Empty", "now", &m).unwrap_err().contains("No technique"));
}

#[test]
fn detection_rules_are_coverage_and_their_matches_are_leads() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't')", [])?;
        c.execute("INSERT INTO findings (project_id, title, severity, status, tags, created_at, updated_at) VALUES (1, 'Injects code', 'high', 'new', '[\"T1055\"]', 't', 't')", [])?;
        let rule = "title: Password spraying\nid: 11111111-2222-4333-8444-555555555555\ntags: [attack.t1110.003]\nlogsource: {product: windows, service: security}\ndetection: {s: {EventID: 4625}, condition: s}\n";
        let checked = crate::detection::sigma::read(rule).unwrap().remove(0);
        let r = crate::workspace::detections::upsert_sigma(c, rule, &checked, "r.yml", "")?;
        c.execute("INSERT INTO detection_hits (project_id, rule_id, rule_title, rule_version, techniques, position, created_at) VALUES (1, ?1, 'Password spraying', 1, '[\"T1110.003\"]', 'record 9', 't')", params![r.id])?;
        let m = matrix(c, 1)?;
        let spray = m.entries.iter().find(|e| e.id == "T1110.003").expect("covered technique");
        assert_eq!((spray.rules.len(), spray.hits, spray.observed.len()), (1, 1, 0), "a rule and its match are not an observation");
        assert_eq!((m.counts.covered, m.counts.uncovered, m.counts.observed), (1, 1, 1), "T1055 is named by a finding without a rule");
        let layer: Value = serde_json::from_str(&export_coverage_layer("now", &m).unwrap()).unwrap();
        assert_eq!(layer["techniques"][0]["techniqueID"], "T1110.003");
        assert_eq!(layer["techniques"][0]["color"], "#c7e9c0", "untested coverage is light");
        crate::workspace::detections::set_enabled(c, r.id, false)?;
        let m = matrix(c, 1)?;
        assert_eq!(m.counts.covered, 0, "a disabled rule covers nothing");
        assert!(export_coverage_layer("now", &m).is_err());
        Ok(())
    })
    .unwrap();
}

/// Mission 6: Mobile and ICS are matrices of their own. Findings, assessments and layers land in
/// the domain whose catalog knows their technique; exports name their domain and version; sets of
/// different domains are never compared.
/// Mission 7 (#62): the matrix switch shows how many techniques of each domain have data.
#[test]
fn each_domain_counts_its_techniques_with_data() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Fleet', 'active', 't', 't')", [])?;
        assert_eq!(domain_counts(c, 1)?, vec![("enterprise-attack".to_string(), 0), ("mobile-attack".to_string(), 0), ("ics-attack".to_string(), 0)]);
        c.execute("INSERT INTO findings (id, project_id, title, severity, status, tags, created_at, updated_at) VALUES (1, 1, 'APK', 'high', 'confirmed', '[\"T1404\"]', 't', 't'), (2, 1, 'PowerShell', 'medium', 'confirmed', '[\"T1059.001\", \"T1003\"]', 't', 't')", [])?;
        assess(c, 1, "T0800", Some("hypothesis"), "low", "", "user")?;
        assert_eq!(domain_counts(c, 1)?, vec![("enterprise-attack".to_string(), 2), ("mobile-attack".to_string(), 1), ("ics-attack".to_string(), 1)]);
        Ok(())
    })
    .unwrap();
}

#[test]
fn mobile_and_ics_are_separate_matrices() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Fleet', 'active', 't', 't')", [])?;
        c.execute("INSERT INTO findings (id, project_id, title, severity, status, tags, created_at, updated_at) VALUES (1, 1, 'Sideloaded APK escalates', 'high', 'confirmed', '[\"T1404\"]', 't', 't'), (2, 1, 'PLC program changed', 'high', 'confirmed', '[\"T0889\"]', 't', 't'), (3, 1, 'PowerShell', 'medium', 'confirmed', '[\"T1059.001\"]', 't', 't')", [])?;
        assess(c, 1, "T1404", Some("confirmed"), "high", "seen in the MDM logs", "user")?;
        assess(c, 1, "T0800", Some("hypothesis"), "low", "", "user")?;
        let stored: Vec<(String, String)> = c.prepare("SELECT technique, domain FROM attack_assessments ORDER BY technique")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        assert_eq!(stored, [("T0800".to_string(), "ics-attack".to_string()), ("T1404".to_string(), "mobile-attack".to_string())]);

        let mobile = matrix_for(c, 1, "mobile-attack")?;
        let ids = |m: &Matrix| m.entries.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
        assert_eq!((mobile.domain.as_str(), ids(&mobile)), ("mobile-attack", vec!["T1404".to_string()]));
        let e = &mobile.entries[0];
        assert_eq!((e.observed.len(), e.assessment.as_ref().map(|a| a.status.as_str()), e.state.clone()), (1, Some("confirmed"), IdState::Current));
        assert!(!e.tactics.is_empty() && e.name == "Exploitation for Privilege Escalation");
        assert_eq!(ids(&matrix_for(c, 1, "ics-attack")?), ["T0800", "T0889"]);
        let enterprise = matrix(c, 1)?;
        assert_eq!((enterprise.domain.as_str(), ids(&enterprise)), ("enterprise-attack", vec!["T1059.001".to_string()]), "Enterprise keeps only its own");
        assert!(matrix_for(c, 1, "pre-attack").is_err());

        // a Mobile layer: read against the Mobile catalog, shown only in the Mobile matrix
        let l = parse_layer(&layer(r#"{"name":"Mobile threat profile","versions":{"attack":"20","layer":"4.5","navigator":"5.3.2"},"domain":"mobile-attack","techniques":[{"techniqueID":"T1404","score":5},{"techniqueID":"T1418","score":2},{"techniqueID":"T1059","score":9}]}"#)).unwrap();
        assert_eq!((l.domain.as_str(), l.techniques.len(), l.unknown.clone()), ("mobile-attack", 2, vec!["T1059".to_string()]), "an Enterprise ID is not a Mobile technique");
        let lid = store_layer(c, 1, "mobile.json", "ab", None, &l)?;
        assert_eq!(layers(c, 1)?[0].domain, "mobile-attack");
        assert!(matrix_for(c, 1, "mobile-attack")?.layers.iter().any(|x| x.id == lid));
        assert!(matrix(c, 1)?.layers.is_empty() && !matrix(c, 1)?.entries.iter().any(|e| e.id == "T1418"));

        // exports name their domain and version
        let out: serde_json::Value = serde_json::from_str(&export_layer("Fleet", "2026-11-10", &matrix_for(c, 1, "mobile-attack")?).unwrap()).unwrap();
        assert_eq!((out["domain"].as_str(), out["versions"]["attack"].as_str()), (Some("mobile-attack"), Some("20")));
        assert!(out["description"].as_str().unwrap().contains("ATT&CK Mobile v20.1"));

        // comparisons stay inside one domain
        let cmp = crate::workspace::attack_history::compare(c, 1, "mobile-attack", "observed", &format!("layer:{lid}"))?;
        assert_eq!((cmp.domain.as_str(), cmp.both.len(), cmp.only_b.len()), ("mobile-attack", 1, 1));
        let err = crate::workspace::attack_history::compare(c, 1, "enterprise-attack", "observed", &format!("layer:{lid}")).unwrap_err().to_string();
        assert!(err.contains("is for ATT&CK Mobile") && err.contains("cannot be compared with ATT&CK Enterprise"), "{err}");
        let snap = crate::workspace::attack_history::snapshot_take(c, "Enterprise coverage", "enterprise-attack")?;
        assert!(crate::workspace::attack_history::compare(c, 1, "ics-attack", &format!("snapshot:{snap}"), "observed").unwrap_err().to_string().contains("is for ATT&CK Enterprise"));
        assert_eq!(crate::workspace::attack_history::snapshots(c)?[0].domain, "enterprise-attack");

        // the findings layer stays Enterprise and says what it left out
        let findings = crate::commands::projects::findings_of(c, 1)?;
        let fl: serde_json::Value = serde_json::from_str(&crate::workspace::attack_layer::layer("Fleet", "2026-11-10", &findings).unwrap()).unwrap();
        let listed: Vec<&str> = fl["techniques"].as_array().unwrap().iter().map(|t| t["techniqueID"].as_str().unwrap()).collect();
        assert_eq!(listed, ["T1059.001"]);
        assert!(fl["description"].as_str().unwrap().contains("2 ATT&CK Mobile or ICS references are left out"));
        Ok(())
    })
    .unwrap();
}
