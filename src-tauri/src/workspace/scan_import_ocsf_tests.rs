//! Tests of the OCSF import. The fixtures follow the structure of Prowler 5's example outputs
//! (`examples/output/example_output_*.ocsf.json` in the Prowler repository).

use serde_json::{json, Value};

use super::super::{detect, import, not_reported, parse, preview, FileInfo, Format, Options};
use crate::db::Db;
use crate::workspace::findings as lifecycle;

/// A Prowler finding for an AWS resource.
fn aws(check: &str, status: &str, resource: &str, severity_id: u64) -> Value {
    let severity = ["Unknown", "Informational", "Low", "Medium", "High", "Critical"][severity_id as usize];
    json!({
        "message": format!("{check} on {resource}"),
        "metadata": { "event_code": check, "product": { "name": "Prowler", "uid": "prowler", "vendor_name": "Prowler", "version": "5.4.0" }, "profiles": ["cloud", "datetime"], "tenant_uid": "", "version": "1.4.0" },
        "severity_id": severity_id,
        "severity": severity,
        "status": "New",
        "status_code": status,
        "status_detail": format!("S3 Bucket {resource} has public access."),
        "status_id": 1,
        "unmapped": {
            "related_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "categories": ["internet-exposed"],
            "compliance": { "CIS-2.0": ["2.1.4"], "ISO27001-2013": ["A.9.1", "A.13.2"], "MITRE-ATTACK": ["T1530", "T1190", "TA0001"] },
            "notes": ""
        },
        "activity_name": "Create",
        "activity_id": 1,
        "finding_info": {
            "created_time": 1739539623,
            "desc": "Ensure that S3 buckets are not publicly accessible.",
            "product_uid": "prowler",
            "title": "Ensure there are no S3 buckets open to Everyone or Any AWS user.",
            "types": ["Data Protection"],
            "uid": format!("prowler-aws-{check}-123456789012-eu-west-1-{resource}"),
            "attacks": [{ "tactic": { "name": "Collection", "uid": "TA0009" }, "technique": { "name": "Data from Cloud Storage", "uid": "T1530" }, "version": "16.1" }]
        },
        "resources": [{
            "cloud_partition": "aws",
            "region": "eu-west-1",
            "data": { "details": "", "metadata": { "name": resource } },
            "group": { "name": "s3" },
            "labels": [],
            "name": resource,
            "type": "AwsS3Bucket",
            "uid": format!("arn:aws:s3:::{resource}")
        }],
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Detection Finding",
        "class_uid": 2004,
        "cloud": { "account": { "name": "production", "type": "AWS Account", "type_id": 10, "uid": "123456789012", "labels": [] }, "org": { "name": "", "uid": "" }, "provider": "aws", "region": "eu-west-1" },
        "remediation": {
            "desc": "Turn on S3 Block Public Access for the bucket.",
            "references": ["aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
        },
        "risk_details": "Anyone on the internet can read the bucket's objects.",
        "time": 1739539623,
        "type_uid": 200401,
        "type_name": "Detection Finding: Create"
    })
}

fn file(items: &[Value]) -> String {
    serde_json::to_string_pretty(&Value::Array(items.to_vec())).unwrap()
}

#[test]
fn prowler_failures_become_findings_and_other_results_are_counted() {
    let mut muted = aws("s3_bucket_public_access", "FAIL", "muted-bucket", 5);
    muted["status"] = json!("Suppressed");
    muted["status_id"] = json!(3);
    let text = file(&[
        aws("s3_bucket_public_access", "FAIL", "public-bucket", 5),
        aws("s3_bucket_default_encryption", "FAIL", "logs-bucket", 3),
        aws("s3_bucket_public_access", "PASS", "private-bucket", 5),
        aws("account_security_contact_information_is_registered", "MANUAL", "123456789012", 3),
        muted,
    ]);
    assert_eq!(detect(&text), Ok(Format::Ocsf));
    let p = parse(&text).unwrap();
    assert_eq!(p.tool, "Prowler");
    assert_eq!(p.findings.len(), 2);
    assert_eq!(p.passed.len(), 1);
    let f = &p.findings[0];
    assert_eq!((f.rule_id.as_str(), f.severity, f.confidence), ("s3_bucket_public_access", "critical", "high"));
    assert_eq!(f.title, "Ensure there are no S3 buckets open to Everyone or Any AWS user.");
    assert_eq!(f.target, "arn:aws:s3:::public-bucket");
    assert_eq!((f.host.as_deref(), f.network), (None, false), "a cloud resource is not a network target");
    assert_eq!(f.category, "Cloud configuration");
    assert!(f.description.starts_with("S3 Bucket public-bucket has public access.\n\nEnsure that S3 buckets"));
    assert!(f.description.ends_with("Risk: Anyone on the internet can read the bucket's objects."));
    assert!(f.remediation.starts_with("Turn on S3 Block Public Access"));
    assert!(f.remediation.contains("Commands and settings:\n- aws s3api put-public-access-block"));
    assert_eq!(f.references, vec!["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]);
    for line in ["Check: s3_bucket_public_access (Prowler 5.4.0)", "Provider: aws · Account: 123456789012 (production) · Region: eu-west-1", "Resource: AwsS3Bucket arn:aws:s3:::public-bucket · service s3", "Compliance: CIS-2.0 2.1.4 · ISO27001-2013 A.9.1, A.13.2 · MITRE-ATTACK T1530, T1190, TA0001", "MITRE ATT&CK: T1530 Data from Cloud Storage (Collection) · T1190"] {
        assert!(f.technical.contains(line), "{line} in {}", f.technical);
    }
    assert_eq!(f.tags, vec!["imported", "prowler", "aws", "s3", "t1530", "t1190"]);
    assert_eq!(p.findings[1].severity, "medium");
    assert_eq!(
        p.warnings,
        vec![
            "1 check passed; it is not imported, and resolves the finding of an earlier import for the same resource when you choose to",
            "1 check needs a manual review (MANUAL) and was skipped",
            "1 muted finding (suppressed in the scanner) was skipped",
        ]
    );
    assert!(!p.incomplete);
}

#[test]
fn kubernetes_findings_use_the_namespace_and_old_or_broken_files_are_handled() {
    let mut k8s = aws("apiserver_always_pull_images_plugin", "FAIL", "kube-apiserver-node1", 3);
    k8s.as_object_mut().unwrap().remove("cloud");
    k8s["metadata"]["profiles"] = json!(["container", "datetime"]);
    k8s["resources"] = json!([{ "group": { "name": "apiserver" }, "labels": [], "name": "kube-apiserver-node1", "namespace": "kube-system", "type": "KubernetesAPIServer", "uid": "a1b2c3" }]);
    let p = parse(&file(&[k8s])).unwrap();
    let f = &p.findings[0];
    assert_eq!((f.target.as_str(), f.category.as_str()), ("a1b2c3", "Container configuration"));
    assert!(f.technical.contains("Provider: kubernetes · Namespace: kube-system"), "{}", f.technical);
    assert!(f.tags.contains(&"kubernetes".to_string()));

    // Prowler's file of an interrupted scan: no closing bracket
    let whole = file(&[aws("s3_bucket_public_access", "FAIL", "a", 4), aws("s3_bucket_public_access", "FAIL", "b", 4)]);
    let cut = format!("{},", whole.trim_end().strip_suffix(']').unwrap().trim_end());
    assert_eq!(detect(&cut), Ok(Format::Ocsf));
    let p = parse(&cut).unwrap();
    assert_eq!(p.findings.len(), 2);
    assert!(p.incomplete);
    assert!(p.warnings[0].contains("without its closing bracket"));

    // OCSF 1.0 security findings of older Prowler versions
    let old = json!([{ "class_uid": 2001, "finding": { "title": "x", "uid": "y" }, "status": "FAIL" }]).to_string();
    assert_eq!(detect(&old), Ok(Format::Ocsf));
    assert!(parse(&old).unwrap_err().contains("Prowler 4 or later"));
    // a JSON list of something else is still refused
    assert!(detect(r#"[{"class_uid": 3002}]"#).unwrap_err().contains("Prowler (OCSF)"));
}

#[test]
fn a_passing_check_resolves_the_finding_of_an_earlier_import() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Cloud','active','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z')", []).unwrap();
        let p = c.last_insert_rowid();
        let info = |name: &'static str| FileInfo { file_name: name, sha256: "ab", evidence_id: None };
        // no scope entries are needed: cloud resources are not network targets
        let first = parse(&file(&[aws("s3_bucket_public_access", "FAIL", "a", 5), aws("s3_bucket_public_access", "FAIL", "b", 5)])).unwrap();
        let pv = preview(c, p, &first, Options::default())?;
        assert_eq!((pv.counts.new, pv.counts.out_of_scope), (2, 0));
        assert_eq!(import(c, p, &first, Options::default(), &info("monday.ocsf.json"))?.created, 2);
        let id_of = |c: &rusqlite::Connection, target: &str| -> i64 { c.query_row("SELECT id FROM findings WHERE affected_target = ?1", [target], |r| r.get(0)).unwrap() };
        let (a, b) = (id_of(c, "arn:aws:s3:::a"), id_of(c, "arn:aws:s3:::b"));

        // the bucket a was fixed: Prowler reports the check as passing; b still fails
        let second = parse(&file(&[aws("s3_bucket_public_access", "PASS", "a", 5), aws("s3_bucket_public_access", "FAIL", "b", 5)])).unwrap();
        let pv = preview(c, p, &second, Options::default())?;
        assert_eq!((pv.counts.new, pv.counts.seen_again, pv.not_reported_count, pv.not_reported_passed), (0, 1, 1, 1));
        assert_eq!(pv.not_reported[0].finding_id, Some(a));
        let r = import(c, p, &second, Options::default(), &info("tuesday.ocsf.json"))?;
        assert_eq!((r.not_reported, r.resolved, r.seen_again), (1, 0, 1));
        assert!(lifecycle::history(c, a)?.iter().any(|e| e.note == "The check passes for arn:aws:s3:::a in the Prowler import of tuesday.ocsf.json"));
        let r = import(c, p, &second, Options { resolve_missing: true, ..Default::default() }, &info("tuesday-again.ocsf.json"))?;
        assert_eq!(r.resolved, 1);
        assert_eq!(crate::commands::projects::finding_get(c, a)?.status, "resolved");
        assert!(lifecycle::history(c, a)?.iter().any(|e| e.note.starts_with("Verified by rescan: the check passes for arn:aws:s3:::a")));
        assert_eq!(crate::commands::projects::finding_get(c, b)?.status, "new");

        // a file without the bucket a says nothing about it: absence alone resolves nothing
        let third = parse(&file(&[aws("s3_bucket_public_access", "FAIL", "b", 5)])).unwrap();
        assert!(not_reported(c, p, &third)?.is_empty());
        Ok(())
    })
    .unwrap();
}

#[test]
fn cut_or_multibyte_files_never_panic() {
    // with panic = "abort" a parser panic would end the app
    let doc = file(&[aws("s3_bucket_public_access", "FAIL", "bücket-日本", 5), aws("s3_bucket_public_access", "PASS", "b", 5)]);
    for (i, _) in doc.char_indices().step_by(7) {
        let _ = detect(&doc[..i]);
        let _ = parse(&doc[..i]);
    }
    assert_eq!(parse(&doc).unwrap().findings[0].target, "arn:aws:s3:::bücket-日本");
}

/// Reads every `.json` file of `CYBERHUB_OCSF_DIR` (such as Prowler's example outputs) and prints
/// what the import would take from it.
#[test]
#[ignore = "reads a folder named by CYBERHUB_OCSF_DIR"]
fn files_of_a_folder_are_read() {
    let dir = std::env::var("CYBERHUB_OCSF_DIR").expect("CYBERHUB_OCSF_DIR");
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    names.sort();
    for path in names {
        let text = std::fs::read_to_string(&path).unwrap();
        let p = parse(&text).unwrap();
        println!("{}: {:?}, tool {}, {} findings, {} passed, warnings {:?}", path.display(), detect(&text), p.tool, p.findings.len(), p.passed.len(), p.warnings);
        for f in &p.findings {
            println!("  [{}] {} | {} | {} | tags {:?}", f.severity, f.title, f.target, f.category, f.tags);
            println!("    {}", f.technical.replace('\n', "\n    "));
        }
    }
}
