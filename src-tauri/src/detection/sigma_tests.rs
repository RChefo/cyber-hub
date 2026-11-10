//! Tests of the Sigma engine against the specification (v2.1.0) and its modifier appendix.

use super::*;

fn ev(fields: &[(&str, &str)]) -> Event {
    Event { position: "record 1".into(), time: String::new(), fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), text: String::new() }
}

fn line(t: &str) -> Event {
    Event { position: "line 1".into(), time: String::new(), fields: vec![("message".into(), t.into())], text: t.into() }
}

fn one(yaml: &str) -> Checked {
    let mut v = read(yaml).unwrap();
    assert_eq!(v.len(), 1);
    v.remove(0)
}

fn rule(yaml: &str) -> Rule {
    let c = one(yaml);
    c.rule.unwrap_or_else(|| panic!("not runnable: {:?}", c.issues))
}

const ENCODED_PS: &str = r#"
title: Encoded PowerShell command line
id: 2b6a0f4e-8d4e-4c0e-9a3b-0c6c1f0e7d11
status: test
description: A PowerShell command line with an encoded command
author: Cyber Hub tests
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1143
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\powershell.exe'
    selection_cli:
        CommandLine|windash|contains:
            - ' -enc '
            - ' -EncodedCommand '
    filter_admin:
        ParentImage|endswith: '\sccm-agent.exe'
    condition: all of selection_* and not filter_admin
falsepositives:
    - Administration scripts
level: high
"#;

#[test]
fn a_rule_is_read_with_its_metadata_and_attack_mapping() {
    let c = one(ENCODED_PS);
    let m = &c.meta;
    assert_eq!((m.title.as_str(), m.status.as_deref(), m.level.as_deref()), ("Encoded PowerShell command line", Some("test"), Some("high")));
    assert_eq!(m.logsource, LogSource { category: Some("process_creation".into()), product: Some("windows".into()), service: None });
    assert_eq!(m.techniques, vec!["T1059.001".to_string(), "T1564.003".to_string()], "a revoked technique counts for its replacement");
    assert_eq!(m.tactics, vec!["execution".to_string()]);
    assert!(c.issues.iter().any(|i| i.level == "warning" && i.message.contains("T1564.003")), "{:?}", c.issues);
    assert_eq!(c.errors(), 0);
    assert!(matches!(c.rule.as_ref().unwrap().source, SourceCheck::Windows { .. }));
}

#[test]
fn process_creation_matches_sysmon_and_security_events_and_explains_why() {
    let r = rule(ENCODED_PS);
    let sysmon = ev(&[("Channel", "Microsoft-Windows-Sysmon/Operational"), ("EventID", "1"), ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), ("CommandLine", "powershell.exe /enc SQBFAFgA"), ("ParentImage", "C:\\Windows\\explorer.exe")]);
    let x = r.evaluate(&sysmon).expect("windash: /enc is -enc");
    let names: Vec<(&str, bool)> = x.selections.iter().map(|s| (s.name.as_str(), s.matched)).collect();
    assert_eq!(names, vec![("filter_admin", false), ("selection_cli", true), ("selection_img", true)]);
    let cli = x.selections.iter().find(|s| s.name == "selection_cli").unwrap();
    assert_eq!(cli.hits[0].field, "CommandLine");
    assert!(cli.hits[0].condition.contains("windash|contains") && cli.hits[0].value.contains("/enc"), "{:?}", cli.hits);
    // Security 4688 names the image NewProcessName
    let security = ev(&[("Channel", "Security"), ("EventID", "4688"), ("NewProcessName", "C:\\x\\PowerShell.EXE"), ("CommandLine", "powershell -EncodedCommand AAA"), ("ParentProcessName", "C:\\cmd.exe")]);
    assert!(r.evaluate(&security).is_some(), "the 4688 field names are mapped, and values are case-insensitive");
    // the filter, another channel, another event ID
    let admin = ev(&[("Channel", "Microsoft-Windows-Sysmon/Operational"), ("EventID", "1"), ("Image", "c:\\powershell.exe"), ("CommandLine", "powershell -enc x"), ("ParentImage", "C:\\tools\\sccm-agent.exe")]);
    assert!(r.evaluate(&admin).is_none(), "the filter excludes it");
    let other_id = ev(&[("Channel", "Microsoft-Windows-Sysmon/Operational"), ("EventID", "3"), ("Image", "c:\\powershell.exe"), ("CommandLine", "powershell -enc x")]);
    assert!(r.evaluate(&other_id).is_none(), "network connections are not process creations");
    let no_dash = ev(&[("Channel", "Security"), ("EventID", "4688"), ("NewProcessName", "c:\\powershell.exe"), ("CommandLine", "powershell -version 2")]);
    assert!(r.evaluate(&no_dash).is_none());
}

#[test]
fn conditions_follow_the_specified_precedence() {
    let base = |cond: &str| {
        format!(
            "title: t\nlogsource:\n    product: windows\n    service: security\ndetection:\n    a:\n        F: a\n    b:\n        F: b\n    c:\n        G: c\n    sel_1:\n        H: 1\n    sel_2:\n        H: 2\n    _hidden:\n        Z: z\n    condition: {cond}\n"
        )
    };
    let e = |f: &str, g: &str, h: &str| ev(&[("Channel", "Security"), ("F", f), ("G", g), ("H", h)]);
    // or < and < not
    let r = rule(&base("a or b and not c"));
    assert!(r.evaluate(&e("a", "c", "")).is_some(), "a alone is enough: (a) or (b and not c)");
    assert!(r.evaluate(&e("b", "c", "")).is_none());
    assert!(r.evaluate(&e("b", "x", "")).is_some());
    let r = rule(&base("(a or b) and not c"));
    assert!(r.evaluate(&e("a", "c", "")).is_none());
    // x of
    let r = rule(&base("1 of sel_*"));
    assert!(r.evaluate(&e("", "", "2")).is_some());
    let r = rule(&base("all of sel_*"));
    assert!(r.evaluate(&e("", "", "2")).is_none());
    let r = rule(&base("2 of them"));
    assert!(r.evaluate(&e("a", "c", "")).is_some() && r.evaluate(&e("a", "x", "")).is_none());
    // `them` leaves out identifiers that start with an underscore
    let r = rule(&base("1 of them"));
    assert!(r.evaluate(&ev(&[("Channel", "Security"), ("Z", "z")])).is_none());
    // a list of conditions is ORed
    let r = rule(&base("['a', 'c']"));
    assert!(r.evaluate(&e("", "c", "")).is_some());
    assert!(glob("sel*", "selection") && glob("*_img", "selection_img") && !glob("sel?", "selection") && glob("a*b*c", "aXXbYc"));
}

#[test]
fn values_follow_the_modifier_appendix() {
    let r = |det: &str| rule(&format!("title: t\nlogsource:\n    category: test\ndetection:\n{det}\n    condition: s\n"));
    let e = |pairs: &[(&str, &str)]| ev(pairs);
    // wildcards, escapes and case
    // `\\` before a wildcard is a backslash; `\?` alone is a plain question mark
    let w = r("    s:\n        F: 'C:\\Win*\\\\?md.exe'");
    assert!(w.evaluate(&e(&[("F", "c:\\windows\\system32\\cmd.exe")])).is_some());
    let q = r("    s:\n        F: 'what\\?'");
    assert!(q.evaluate(&e(&[("F", "what?")])).is_some() && q.evaluate(&e(&[("F", "whatx")])).is_none());
    let esc = r("    s:\n        F: 'a\\*b'");
    assert!(esc.evaluate(&e(&[("F", "a*b")])).is_some() && esc.evaluate(&e(&[("F", "axxb")])).is_none(), "an escaped wildcard is a plain character");
    let cased = r("    s:\n        F|cased: Admin");
    assert!(cased.evaluate(&e(&[("F", "Admin")])).is_some() && cased.evaluate(&e(&[("F", "admin")])).is_none());
    // lists: OR, or AND with all
    let any = r("    s:\n        F|contains:\n            - x\n            - y");
    assert!(any.evaluate(&e(&[("F", "..y..")])).is_some());
    let all = r("    s:\n        F|contains|all:\n            - x\n            - y");
    assert!(all.evaluate(&e(&[("F", "..y..")])).is_none() && all.evaluate(&e(&[("F", "x.y")])).is_some());
    // regular expressions: case-sensitive unless |i
    let re = r("    s:\n        F|re: '^cmd\\.exe /c .*whoami$'");
    assert!(re.evaluate(&e(&[("F", "cmd.exe /c x & whoami")])).is_some() && re.evaluate(&e(&[("F", "CMD.exe /c whoami")])).is_none());
    let rei = r("    s:\n        F|re|i: '^cmd'");
    assert!(rei.evaluate(&e(&[("F", "CMD.exe")])).is_some());
    // numbers, CIDR, existence, null, field references, neq
    let gt = r("    s:\n        Size|gte: 1000");
    assert!(gt.evaluate(&e(&[("Size", "1024")])).is_some() && gt.evaluate(&e(&[("Size", "0x10")])).is_none() && gt.evaluate(&e(&[("Size", "big")])).is_none());
    let cidr = r("    s:\n        Ip|cidr:\n            - 10.0.0.0/8\n            - 'fd00::/8'");
    assert!(cidr.evaluate(&e(&[("Ip", "10.1.2.3")])).is_some() && cidr.evaluate(&e(&[("Ip", "fd12::1")])).is_some() && cidr.evaluate(&e(&[("Ip", "8.8.8.8")])).is_none());
    let exists = r("    s:\n        F|exists: false");
    assert!(exists.evaluate(&e(&[("G", "x")])).is_some() && exists.evaluate(&e(&[("F", "")])).is_none(), "an empty value still exists");
    let null = r("    s:\n        F: null");
    assert!(null.evaluate(&e(&[("G", "x")])).is_some() && null.evaluate(&e(&[("F", "x")])).is_none());
    let empty = r("    s:\n        F: ''");
    assert!(empty.evaluate(&e(&[("F", "")])).is_some() && empty.evaluate(&e(&[("G", "")])).is_none());
    let fref = r("    s:\n        SourceUser|fieldref: TargetUser");
    assert!(fref.evaluate(&e(&[("SourceUser", "Bob"), ("TargetUser", "bob")])).is_some() && fref.evaluate(&e(&[("SourceUser", "a"), ("TargetUser", "b")])).is_none());
    let neq = r("    s:\n        User|neq:\n            - SYSTEM\n            - LOCAL SERVICE");
    assert!(neq.evaluate(&e(&[("User", "alice")])).is_some() && neq.evaluate(&e(&[("User", "system")])).is_none());
}

#[test]
fn encoded_values_match_wherever_they_sit_in_the_encoding() {
    fn std_b64(b: &[u8]) -> String {
        b64(b)
    }
    let r = rule("title: t\nlogsource:\n    category: test\ndetection:\n    s:\n        CommandLine|base64offset|contains: 'Mimikatz'\n    condition: s\n");
    let w = rule("title: t\nlogsource:\n    category: test\ndetection:\n    s:\n        CommandLine|wide|base64offset|contains: 'Invoke-Mimikatz'\n    condition: s\n");
    for prefix in ["", "a", "ab", "abc", "abcd"] {
        let ascii = std_b64(format!("{prefix}Mimikatz and more").as_bytes());
        assert!(r.evaluate(&ev(&[("CommandLine", &format!("x {ascii} y"))])).is_some(), "ascii, {} bytes before", prefix.len());
        let utf16: Vec<u8> = format!("{prefix}IEX (Invoke-Mimikatz -DumpCreds)").encode_utf16().flat_map(u16::to_le_bytes).collect();
        let enc = std_b64(&utf16);
        assert!(w.evaluate(&ev(&[("CommandLine", &format!("powershell -enc {enc}"))])).is_some(), "UTF-16LE, {} characters before", prefix.len());
    }
    assert!(r.evaluate(&ev(&[("CommandLine", &std_b64(b"nothing to see"))])).is_none());
    let plain = rule("title: t\nlogsource:\n    category: test\ndetection:\n    s:\n        F|base64: 'cmd'\n    condition: s\n");
    assert!(plain.evaluate(&ev(&[("F", "Y21k")])).is_some());
    assert_eq!(b64(b"ab"), "YWI=");
}

#[test]
fn keywords_search_the_whole_event() {
    let r = rule("title: t\nlogsource:\n    product: linux\n    service: auth\ndetection:\n    keywords:\n        - 'Accepted password for root'\n        - 'session opened for user root'\n    condition: keywords\n");
    assert!(r.evaluate(&line("Nov  9 sshd[1]: Accepted password for root from 203.0.113.9")).is_some());
    assert!(r.evaluate(&line("Nov  9 sshd[1]: Accepted publickey for alice")).is_none());
    let all = rule("title: t\nlogsource:\n    product: linux\ndetection:\n    keywords:\n        '|all':\n            - 'sudo'\n            - 'COMMAND=/bin/bash'\n    condition: keywords\n");
    assert!(all.evaluate(&line("sudo: bob : COMMAND=/bin/bash")).is_some() && all.evaluate(&line("sudo: bob : COMMAND=/bin/ls")).is_none());
    // structured events are searched in all values
    assert!(r.evaluate(&ev(&[("msg", "Accepted password for root from x")])).is_some());
}

#[test]
fn log_sources_filter_events_and_unmapped_ones_are_said() {
    let sec = rule("title: t\nlogsource:\n    product: windows\n    service: security\ndetection:\n    s:\n        EventID: 4625\n    condition: s\n");
    assert!(sec.evaluate(&ev(&[("Channel", "Security"), ("EventID", "4625")])).is_some());
    assert!(sec.evaluate(&ev(&[("Channel", "System"), ("EventID", "4625")])).is_none(), "another channel");
    assert!(sec.evaluate(&ev(&[("EventID", "4625")])).is_some(), "events without a channel are not filtered");
    let c = one("title: t\nlogsource:\n    product: linux\n    service: auth\ndetection:\n    s: x\n    condition: s\n");
    assert!(c.issues.iter().any(|i| i.message.contains("'linux' has no channel mapping")));
    assert!(matches!(c.rule.unwrap().source, SourceCheck::Unmapped { .. }));
}

#[test]
fn what_cannot_be_evaluated_is_reported_never_ignored() {
    let cases = [
        ("    s:\n        Workstation|expand: '%Workstations%'\n    condition: s", "unsupported", "placeholders"),
        ("    s:\n        UtcTime|hour: 3\n    condition: s", "unsupported", "time modifier"),
        ("    s:\n        F: x\n    condition: s | count() by User > 5", "unsupported", "aggregations"),
        ("    s:\n        F|re: '(?<=a)b'\n    condition: s", "unsupported", "look-around"),
        ("    s:\n        F|frobnicate: x\n    condition: s", "error", "unknown modifier"),
        ("    s:\n        F|all: x\n    condition: s", "error", "'all' needs a list"),
        ("    s:\n        F: x\n    condition: s and missing", "error", "'missing'"),
        ("    s:\n        F: x\n    condition: s and (s", "error", "parenthesis"),
        ("    s:\n        F: [x, null]\n    condition: s", "error", "null cannot"),
        ("    s: {}\n    condition: s", "error", "empty map"),
        ("    s:\n        F|re: '('\n    condition: s", "error", "re:"),
        ("    s:\n        F|base64|contains|base64: x\n    condition: s", "error", "wildcards"),
    ];
    for (det, level, words) in cases {
        let c = one(&format!("title: t\nlogsource:\n    category: test\ndetection:\n{det}\n"));
        assert!(c.rule.is_none(), "{det}");
        assert!(c.issues.iter().any(|i| i.level == level && i.message.contains(words)), "{det}: {:?}", c.issues);
    }
    // correlation rules are checked by the correlation module: a count needs a condition, and
    // value_percentile is refused
    let corr = one("title: Many failed logons\ncorrelation:\n    type: event_count\n    rules: [a]\n    timespan: 5m\n");
    assert!(!corr.runnable() && corr.issues.iter().any(|i| i.level == "error" && i.message.contains("needs a condition")), "{:?}", corr.issues);
    let pct = one("title: Rare\ncorrelation:\n    type: value_percentile\n    rules: [a]\n    group-by: [Host]\n    timespan: 1d\n    condition:\n        field: Image\n        lte: 1\n");
    assert!(!pct.runnable() && pct.issues.iter().any(|i| i.level == "unsupported" && i.message.contains("percentile")));
    let warn = one("title: t\nid: not-a-uuid\nstatus: beta\ndate: 2026/11/09\ntags: [attack.T1059, attack.t9999]\nlogsource:\n    category: test\ndetection:\n    s:\n        F: x\n    unused:\n        G: y\n    condition: s\n");
    assert!(warn.rule.is_some(), "warnings do not stop a rule");
    for w in ["not a UUID", "Unknown status", "YYYY-MM-DD", "lower-case", "no ATT&CK Enterprise technique", "'unused' is not used"] {
        assert!(warn.issues.iter().any(|i| i.level == "warning" && i.message.contains(w)), "{w}: {:?}", warn.issues);
    }
    assert!(one("title: t\nlogsource: {}\n").issues.iter().any(|i| i.message.contains("no detection")));
    assert!(read("not: [valid").is_err() && read("").is_err() && read(&"x".repeat(MAX_RULE_BYTES + 1)).is_err());
    assert_eq!(read("- just\n- a list\n").unwrap()[0].issues[0].message, "A Sigma rule is a YAML mapping");
    assert_eq!(read("---\ntitle: a\nlogsource: {product: windows}\ndetection: {s: x, condition: s}\n---\ntitle: b\nlogsource: {product: windows}\ndetection: {s: y, condition: s}\n").unwrap().len(), 2, "one rule per document");
}

#[test]
fn damaged_rules_never_panic() {
    let cut: Vec<&str> = ENCODED_PS.char_indices().map(|(i, _)| &ENCODED_PS[..i]).step_by(7).collect();
    for part in cut {
        let _ = read(part);
    }
    for odd in ["title: ✓\ntags: [attack.té123]\nlogsource: {category: x}\ndetection: {s: {F: 'ünïcødé*'}, condition: s}", "title: t\nlogsource: {category: x}\ndetection: {s: {F|windash: '-'}, condition: s}", "detection: 5", "title: [1,2]"] {
        let r = read(odd);
        if let Ok(v) = r {
            for c in v {
                if let Some(rule) = c.rule {
                    let _ = rule.evaluate(&ev(&[("F", "ünïcødé x")]));
                }
            }
        }
    }
}

/// Prints the fields of the first events of each EVTX file in `CYBERHUB_EVTX_SAMPLES`:
/// `cargo test --lib evtx_sample_fields -- --ignored --nocapture`
#[test]
#[ignore = "needs EVTX samples"]
fn evtx_sample_fields() {
    let Ok(dir) = std::env::var("CYBERHUB_EVTX_SAMPLES") else { return };
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("evtx") {
            continue;
        }
        let s = crate::detection::events::read(std::fs::File::open(&p).unwrap()).unwrap();
        println!("== {} ({} events)", p.file_name().unwrap().to_string_lossy(), s.events.len());
        let mut seen = std::collections::BTreeSet::new();
        for e in &s.events {
            let key = format!("{} {}", e.get("Channel").unwrap_or(""), e.get("EventID").unwrap_or(""));
            if seen.insert(key.clone()) && seen.len() <= 4 {
                println!("  {key}: {}", e.fields.iter().map(|(k, v)| format!("{k}={}", v.chars().take(60).collect::<String>())).collect::<Vec<_>>().join(" | "));
            }
        }
    }
}

/// Runs rules written for these tests on the EVTX-ATTACK-SAMPLES files in `CYBERHUB_EVTX_SAMPLES`
/// with the rules in `CYBERHUB_SIGMA_RULES`:
/// `cargo test --lib sigma_rules_on_attack_samples -- --ignored --nocapture`
#[test]
#[ignore = "needs EVTX samples and rules"]
fn sigma_rules_on_attack_samples() {
    let (Ok(samples), Ok(rules)) = (std::env::var("CYBERHUB_EVTX_SAMPLES"), std::env::var("CYBERHUB_SIGMA_RULES")) else { return };
    let load = |f: &str| {
        let mut v = read(&std::fs::read_to_string(std::path::Path::new(&rules).join(f)).unwrap()).unwrap();
        let c = v.remove(0);
        assert!(c.issues.iter().all(|i| i.level == "warning"), "{f}: {:?}", c.issues);
        c.rule.unwrap()
    };
    let count = |r: &Rule, f: &str| {
        let s = crate::detection::events::read(std::fs::File::open(std::path::Path::new(&samples).join(f)).unwrap()).unwrap();
        s.events.iter().filter(|e| r.evaluate(e).is_some()).count()
    };
    let cleared = load("security_log_cleared.yml");
    let lsass = load("lsass_access.yml");
    let service = load("service_shell.yml");
    let cases = [
        (&cleared, "DE_1102_security_log_cleared.evtx", true),
        (&cleared, "DE_104_system_log_cleared.evtx", false),
        (&lsass, "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx", true),
        // this sample dumps notepad.exe, not LSASS: the rule must stay silent
        (&lsass, "sysmon_10_1_memdump_comsvcs_minidump.evtx", false),
        (&lsass, "DE_1102_security_log_cleared.evtx", false),
        (&service, "System_7045_namedpipe_privesc.evtx", true),
        (&service, "LM_Remote_Service02_7045.evtx", true),
        (&service, "DE_104_system_log_cleared.evtx", false),
    ];
    for (rule, file, want) in cases {
        let n = count(rule, file);
        println!("{file}: {n} matches");
        assert_eq!(n > 0, want, "{file}");
    }
}
