//! Timings of the heavy paths on generated data (Mission 5). Ignored in normal runs; run them in
//! an optimized build, one per process so the peak memory belongs to the test:
//! `cargo test --release --lib perf_ -- --ignored --nocapture --test-threads=1`.
//! Each prints `PERF <name> <milliseconds> ms <what>` and, on Linux, the process's peak memory.

use std::time::Instant;

use rusqlite::params;

use crate::db::Db;
use crate::detection::events::{Event, Kind, Sample};

fn peak_kb() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string()))
        .map(|k| format!(" peak {} MB", k.parse::<u64>().unwrap_or(0) / 1024))
        .unwrap_or_default()
}

fn report(name: &str, started: Instant, what: &str) {
    println!("PERF {name} {} ms {what}{}", started.elapsed().as_millis(), peak_kb());
}

fn events(n: usize) -> Sample {
    let events = (0..n)
        .map(|i| Event {
            position: format!("record {i}"),
            time: format!("2026-11-09T{:02}:{:02}:{:02}Z", (i / 3600) % 24, (i / 60) % 60, i % 60),
            fields: vec![
                ("Channel".into(), "Security".into()),
                ("EventID".into(), if i % 10 == 0 { "4625".into() } else { "4624".into() }),
                ("TargetUserName".into(), format!("user{}", i % 1000)),
                ("IpAddress".into(), format!("10.0.{}.{}", (i / 250) % 250, i % 250)),
                ("CommandLine".into(), format!("C:\\Windows\\System32\\cmd.exe /c echo {i}")),
            ],
            text: String::new(),
        })
        .collect();
    Sample { kind: Kind::Evtx, events, truncated: false, warnings: vec![] }
}

fn rule(i: usize) -> String {
    format!(
        "title: Rule {i}\nid: 00000000-0000-4000-8000-{i:012}\nlogsource:\n    product: windows\n    service: security\ndetection:\n    s:\n        EventID: 4625\n        CommandLine|contains|all: ['cmd.exe', 'echo {i}']\n    f:\n        TargetUserName|re: '^svc_'\n    condition: s and not f\n"
    )
}

#[test]
#[ignore = "timing"]
fn perf_sigma_rules_over_events() {
    let t = Instant::now();
    let rules: Vec<crate::detection::sigma::Rule> = (0..1000).map(|i| crate::detection::sigma::read(&rule(i)).unwrap().remove(0).rule.unwrap()).collect();
    report("sigma_compile", t, "1,000 rules");
    let sample = events(100_000);
    let t = Instant::now();
    let mut matched = 0;
    for r in rules.iter().take(50) {
        matched += crate::workspace::detections::run(r, &sample).matched;
    }
    report("sigma_evaluate", t, &format!("50 rules x 100,000 events ({matched} matches)"));
}

#[test]
#[ignore = "timing"]
fn perf_correlation() {
    let yaml = "title: Burst\ncorrelation:\n    type: event_count\n    rules: [failed]\n    group-by: [TargetUserName]\n    timespan: 10m\n    condition:\n        gte: 5\n";
    let corr = crate::detection::sigma::read(yaml).unwrap().remove(0).correlation.unwrap();
    let failed = "title: Failed\nname: failed\nlogsource:\n    product: windows\n    service: security\ndetection:\n    s:\n        EventID: 4625\n    condition: s\n";
    let mut resolve = |_: &str| -> Result<crate::detection::correlation::Resolved, String> {
        Ok(crate::detection::correlation::Resolved::Rule { title: "Failed".into(), rule: Box::new(crate::detection::sigma::read(failed).unwrap().remove(0).rule.unwrap()) })
    };
    let mut tree = crate::detection::correlation::Tree::build("root", corr, &mut resolve).unwrap();
    let sample = events(500_000);
    let t = Instant::now();
    tree.feed(&sample, 1, "s");
    let out = tree.finish();
    report("correlation_event_count", t, &format!("500,000 events, 1,000 groups ({} matches)", out.matched));
}

#[test]
#[ignore = "timing"]
fn perf_yara() {
    let mut text = String::from("import \"pe\"\n");
    for i in 0..100 {
        text.push_str(&format!("rule r{i} {{ strings: $a = \"marker{i}\" wide ascii nocase $b = {{ 4D 5A ?? 00 [2-8] 50 45 }} $c = /evil[0-9]{{2,4}}x{i}/ condition: any of them }}\n"));
    }
    let t = Instant::now();
    let checked = crate::detection::yara::check(&text);
    let scanner = checked.scanner.expect("compiles");
    report("yara_compile", t, "100 rules");
    let mut data = vec![0u8; 64 * 1024 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i.wrapping_mul(2_654_435_761) >> 13) as u8;
    }
    data[1_000_000..1_000_007].copy_from_slice(b"marker7");
    let t = Instant::now();
    let scan = crate::detection::yara::scan(&scanner, &data);
    report("yara_scan", t, &format!("64 MB ({} rules matched)", scan.matches.len()));
}

#[test]
#[ignore = "timing"]
fn perf_pcap_and_logs() {
    let frames = crate::sectools::pcap::tests::frames();
    let many: Vec<Vec<u8>> = (0..200_000).map(|i| frames[i % frames.len()].clone()).collect();
    let file = crate::sectools::pcap::tests::pcap_file(&many);
    let t = Instant::now();
    let r = crate::sectools::pcap::analyze(&file[..]).unwrap();
    report("pcap", t, &format!("{} packets, {} MB", r.packets, file.len() / 1024 / 1024));
    let mut log = String::new();
    for i in 0..1_000_000 {
        log.push_str(&format!("Nov  9 10:{:02}:{:02} host sshd[{}]: Failed password for invalid user u{} from 203.0.{}.{} port 5{:04} ssh2\n", (i / 60) % 60, i % 60, i % 9999, i % 500, (i / 250) % 250, i % 250, i % 10000));
    }
    let t = Instant::now();
    let r = crate::sectools::logs::analyze(log.as_bytes()).unwrap();
    report("auth_log", t, &format!("1,000,000 lines, {} MB ({} lines read)", log.len() / 1024 / 1024, r.lines));
}

#[test]
#[ignore = "timing"]
fn perf_sbom_and_lockfile() {
    let comps: Vec<String> = (0..20_000).map(|i| format!("{{\"type\":\"library\",\"name\":\"p{i}\",\"version\":\"1.{i}.0\",\"purl\":\"pkg:npm/p{i}@1.{i}.0\",\"bom-ref\":\"r{i}\"}}")).collect();
    let vulns: Vec<String> = (0..20_000).map(|i| format!("{{\"id\":\"CVE-2026-{i:05}\",\"ratings\":[{{\"score\":7.5}}],\"affects\":[{{\"ref\":\"r{}\"}}]}}", i % 20_000)).collect();
    let text = format!("{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"components\":[{}],\"vulnerabilities\":[{}]}}", comps.join(","), vulns.join(","));
    let t = Instant::now();
    let s = crate::workspace::sbom::parse(&text).unwrap();
    let merged = crate::workspace::sbom::merged(&s, &[]);
    report("sbom", t, &format!("{} components, {} vulnerabilities, {} MB", s.components.len(), merged.len(), text.len() / 1024 / 1024));
    let mut pkgs = String::from("{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{\"\":{}");
    for i in 0..20_000 {
        pkgs.push_str(&format!(",\"node_modules/p{i}\":{{\"version\":\"1.0.{i}\",\"resolved\":\"https://registry.npmjs.org/p{i}/-/p{i}-1.0.{i}.tgz\",\"integrity\":\"sha512-x\"}}"));
    }
    pkgs.push_str("}}");
    let t = Instant::now();
    let l = crate::workspace::lockfiles::parse("package-lock.json", &pkgs).unwrap().unwrap();
    report("package_lock", t, &format!("{} packages", l.components.len()));
}

#[test]
#[ignore = "timing"]
fn perf_large_project_queries() {
    let t = Instant::now();
    let db = Db::open_in_memory().unwrap();
    report("schema_init", t, &format!("fresh database to schema {}", db.schema_version().unwrap()));
    db.with(|c| {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Large', 'active', 't', 't')", [])?;
        let t = Instant::now();
        let tx = c.unchecked_transaction()?;
        for i in 0..50_000 {
            tx.execute(
                "INSERT INTO findings (project_id, title, severity, status, description, affected_target, tags, created_at, updated_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, '2026-11-09T10:00:00Z', 't')",
                params![format!("Finding {i} SQL injection in parameter q{i}"), ["critical", "high", "medium", "low", "info"][i % 5], ["new", "confirmed", "in_remediation", "resolved"][i % 4], format!("Description {i}"), format!("https://app{}.example.net/p{i}", i % 300), format!("[\"T10{:02}\"]", i % 90)],
            )?;
            if i % 5 == 0 {
                tx.execute("INSERT INTO timeline_events (project_id, type, title, detail, at) VALUES (1, 'finding', ?1, '', '2026-11-09T10:00:00Z')", params![format!("Recorded finding {i}")])?;
            }
        }
        tx.commit()?;
        report("insert_findings", t, "50,000 findings");
        let t = Instant::now();
        let all = crate::commands::projects::findings_of(c, 1)?;
        report("findings_list", t, &format!("{} findings", all.len()));
        let t = Instant::now();
        let hits = crate::workspace::search::search(c, &crate::workspace::search::Query { text: "parameter q4999".into(), ..Default::default() })?;
        report("global_search", t, &format!("{} hits", hits.len()));
        let t = Instant::now();
        let m = crate::workspace::attack_matrix::matrix(c, 1)?;
        report("attack_matrix", t, &format!("{} techniques", m.entries.len()));
        let t = Instant::now();
        let md = crate::workspace::report::markdown(c, 1, &Default::default(), "2026-11-10")?;
        report("report_markdown", t, &format!("{} KB", md.len() / 1024));
        let t = Instant::now();
        let a = crate::workspace::asvs::create(c, 1, "L3", 3, "")?;
        let v = crate::workspace::asvs::get(c, a)?;
        let g = crate::workspace::asvs_gaps::gaps(c, a)?;
        report("asvs_view_and_gaps", t, &format!("{} requirements, {} chapters", v.items.len(), g.chapters.len()));
        Ok(())
    })
    .unwrap();
}

/// Mission 7: the saved-indicator list at the TAXII ceiling (100,000 indicators from feeds): the
/// query and the JSON the page receives, measured before deciding whether it needs paging.
#[test]
#[ignore = "timing"]
fn perf_saved_indicators_at_the_taxii_ceiling() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        let t = Instant::now();
        let tx = c.unchecked_transaction()?;
        for i in 0..100_000 {
            tx.execute(
                "INSERT INTO ti_saved (kind, indicator, note, source, created_at, updated_at) VALUES ('domain', ?1, '', 'TAXII: Partner / C2', ?2, ?2)",
                params![format!("host{i}.c2.example.net"), format!("2026-11-{:02}T10:00:00Z", 1 + i % 28)],
            )?;
        }
        tx.commit()?;
        report("insert_saved_indicators", t, "100,000 saved indicators");
        let t = Instant::now();
        let list = crate::ti::lifecycle::list(c)?;
        report("saved_list_query", t, &format!("{} rows", list.len()));
        let t = Instant::now();
        let json = serde_json::to_vec(&list).unwrap();
        report("saved_list_json", t, &format!("{} KB for the whole list", json.len() / 1024));
        // what the page asks for since Mission 7: one page and the counts, with and without a search
        let t = Instant::now();
        let p = crate::ti::lifecycle::page(c, "", 100)?;
        let json = serde_json::to_vec(&p).unwrap();
        report("saved_page", t, &format!("{} rows of {}, {} KB sent to the page", p.items.len(), p.total, json.len() / 1024));
        let t = Instant::now();
        let p = crate::ti::lifecycle::page(c, "host9999", 100)?;
        report("saved_page_search", t, &format!("{} matching", p.matching));
        Ok(())
    })
    .unwrap();
}
