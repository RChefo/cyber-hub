use super::*;

fn compiled(text: &str) -> Checked {
    let c = check(text);
    assert!(c.scanner.is_some(), "{:?}", c.issues);
    c
}

const DEMO: &str = r#"
rule Demo_Loader : loader windows
{
    meta:
        description = "Loader strings seen in the demo sample"
        author = "Cyber Hub tests"
        severity = "High"
        mitre_attack = "T1059.001, T1105"
        reference = "https://example.org/demo"
        score = 70
    strings:
        $a = "powershell -enc" nocase
        $b = { 4D 5A 90 00 }
        $c = /https?:\/\/[a-z0-9.]+\/payload/
    condition:
        $b at 0 and ($a or $c)
}
"#;

#[test]
fn strings_match_with_offsets_and_the_metadata_is_read() {
    let c = compiled(DEMO);
    assert!(c.issues.is_empty(), "{:?}", c.issues);
    let m = &c.meta;
    assert_eq!((m.description.as_str(), m.author.as_str(), m.level.as_str()), ("Loader strings seen in the demo sample", "Cyber Hub tests", "high"));
    assert_eq!(m.techniques, vec!["T1059.001", "T1105"]);
    assert_eq!(m.references, vec!["https://example.org/demo"]);
    assert_eq!(m.tags, vec!["loader", "windows"]);
    assert_eq!(title(m), "Demo_Loader");
    assert!(m.rules[0].metas.contains(&("score".into(), "70".into())));

    let mut data = vec![0x4d, 0x5a, 0x90, 0x00];
    data.extend_from_slice(b"....POWERSHELL -ENC aGVsbG8= then http://evil.example/payload");
    let s = scan(c.scanner.as_ref().unwrap(), &data);
    assert!(!s.timed_out);
    assert_eq!(s.matches.len(), 1);
    let r = &s.matches[0];
    assert_eq!((r.rule.as_str(), r.tags.clone()), ("Demo_Loader", vec!["loader".to_string(), "windows".to_string()]));
    let ids: Vec<&str> = r.strings.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(ids, vec!["$a", "$b", "$c"]);
    assert_eq!((r.strings[0].matches[0].offset, r.strings[0].matches[0].text.as_str()), (8, "POWERSHELL -ENC"));
    assert_eq!((r.strings[1].matches[0].offset, r.strings[1].matches[0].hex.as_str()), (0, "4d5a9000"));
    assert_eq!(r.strings[2].matches[0].text, "http://evil.example/payload");
    let x = explanation(r);
    assert_eq!(x["kind"], "yara");
    assert_eq!(x["strings"][1]["matches"][0]["offset"], 0);

    // the same strings without the header do not satisfy the condition
    assert!(scan(c.scanner.as_ref().unwrap(), b"powershell -enc http://evil.example/payload").matches.is_empty());
}

#[test]
fn includes_are_refused_so_a_rule_reads_no_file() {
    let dir = std::env::temp_dir().join(format!("cyberhub-yara-include-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let other = dir.join("other.yar");
    std::fs::write(&other, "rule Other { condition: true }").unwrap();
    for target in [other.to_string_lossy().replace('\\', "/"), "../../../../etc/passwd".into(), "other.yar".into()] {
        let c = check(&format!("include \"{target}\"\nrule Main {{ condition: true }}"));
        assert!(c.scanner.is_none(), "{target}");
        assert!(c.issues.iter().any(|i| i.level == "error" && i.message.contains("includes are not allowed")), "{:?}", c.issues);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_rules_say_where_and_why() {
    let c = check("rule Broken\n{\n    strings:\n        $a = \"x\"\n    condition:\n        $a and $b\n}\n");
    assert!(c.scanner.is_none());
    assert_eq!(c.errors(), 1);
    assert!(c.issues[0].message.starts_with("Line 6, column"), "{:?}", c.issues);
    assert!(c.issues[0].message.contains("$b"), "{:?}", c.issues);

    let c = check("import \"cuckoo\"\nrule R { condition: true }");
    assert!(c.scanner.is_none());
    assert!(c.issues[0].message.contains("not cuckoo"), "{:?}", c.issues);
    assert_eq!(c.meta.imports, vec!["cuckoo"]);

    for damaged in ["", "rule", "rule {", "rule R { condition: }", "rule R { strings: $a = { 4D 5 } condition: $a }", "rule R { strings: $a = /(/ condition: $a }", "\u{0}\u{1}rule"] {
        let c = check(damaged);
        assert!(c.scanner.is_none() && c.errors() >= 1, "{damaged:?}: {:?}", c.issues);
    }
    let c = check("// nothing here\n");
    assert_eq!(c.issues[0].message, "The file holds no rule");

    assert!(check(&"a".repeat(MAX_RULE_BYTES + 1)).issues[0].message.contains("larger than"));

    // deep nesting is refused, not a stack overflow
    let deep = format!("rule R {{ condition: {}true{} }}", "(".repeat(5000), ")".repeat(5000));
    let c = check(&deep);
    assert!(c.scanner.is_none() && c.errors() == 1, "{:?}", c.issues);
    let not = format!("rule R {{ condition: {}true }}", "not ".repeat(5000));
    assert!(check(&not).scanner.is_none());
}

#[test]
fn private_and_global_rules_work_as_in_yara() {
    let c = compiled(
        r#"
private rule IsMz { condition: uint16(0) == 0x5A4D }
global rule Small { condition: filesize < 1KB }
rule Dropper { strings: $s = "dropper" condition: IsMz and $s }
"#,
    );
    assert_eq!(title(&c.meta), "Small and 1 more");
    assert!(c.meta.rules.iter().any(|r| r.name == "IsMz" && r.private));
    assert!(c.meta.rules.iter().any(|r| r.name == "Small" && r.global));
    let names = |data: &[u8]| scan(c.scanner.as_ref().unwrap(), data).matches.into_iter().map(|m| m.rule).collect::<Vec<_>>();
    assert_eq!(names(b"MZ dropper"), vec!["Small", "Dropper"], "a private rule is never reported");
    assert_eq!(names(b"PK dropper"), vec!["Small"]);
    let mut big = b"MZ dropper".to_vec();
    big.resize(2048, 0);
    assert!(names(&big).is_empty(), "a false global rule makes every rule false");

    let c = check("private rule Only { condition: true }");
    assert!(c.scanner.is_some());
    assert!(c.issues.iter().any(|i| i.message.contains("Every rule is private")));
}

#[test]
fn wide_xor_and_module_conditions() {
    let c = compiled("rule W { strings: $w = \"secret\" wide $x = \"key\" xor condition: $w and $x }");
    let mut data = b"..s\0e\0c\0r\0e\0t\0..".to_vec();
    data.extend(b"key".iter().map(|b| b ^ 0x20));
    let s = scan(c.scanner.as_ref().unwrap(), &data);
    let m = &s.matches[0];
    assert_eq!(m.strings[0].matches[0].text, "secret (UTF-16LE)");
    assert_eq!((m.strings[1].matches[0].text.as_str(), m.strings[1].matches[0].xor), ("KEY", Some(0x20)));
    assert_eq!(m.strings[0].matches[0].xor, None);

    let c = compiled("import \"hash\"\nrule H { condition: hash.sha256(0, filesize) == \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\" }");
    assert_eq!(c.meta.imports, vec!["hash"]);
    assert_eq!(scan(c.scanner.as_ref().unwrap(), b"hello").matches.len(), 1);
    assert!(scan(c.scanner.as_ref().unwrap(), b"hello!").matches.is_empty());
    let r = &scan(c.scanner.as_ref().unwrap(), b"hello").matches[0];
    assert!(r.strings.is_empty(), "a condition without strings explains itself by the rule");

    let c = compiled("import \"pe\"\nrule P { condition: pe.is_pe and pe.number_of_sections > 0 }");
    assert!(scan(c.scanner.as_ref().unwrap(), b"MZ but not a PE").matches.is_empty());
    #[cfg(windows)]
    {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(scan(c.scanner.as_ref().unwrap(), &me).matches.len(), 1, "the test program is a PE file");
    }
}

#[test]
fn matches_are_bounded_and_the_scan_has_a_time_limit() {
    let c = compiled("rule Many { strings: $a = \"A\" condition: #a > 10 }");
    let sc = c.scanner.as_ref().unwrap();
    assert_eq!(sc.scan_params().get_timeout_duration(), Some(&SCAN_TIMEOUT));
    let s = scan(sc, &vec![b'A'; 5000]);
    let st = &s.matches[0].strings[0];
    assert_eq!((st.count, st.matches.len()), (MATCHES_PER_STRING, KEPT_PER_STRING));

    let long = compiled("rule Long { strings: $a = { 41 [0-300] 42 } condition: $a }");
    let mut data = vec![b'A'];
    data.extend(vec![b'x'; 200]);
    data.push(b'B');
    let s = scan(long.scanner.as_ref().unwrap(), &data);
    let h = &s.matches[0].strings[0].matches[0];
    assert_eq!((h.length, h.hex.len() / 2), (202, MATCH_BYTES), "the length is real, the bytes kept are cut");
}

#[test]
fn a_library_runs_several_files_in_one_pass() {
    let same = "rule Same { strings: $a = \"abc\" condition: $a }";
    let lib = library(&[(1, same), (2, same), (3, "rule Broken {"), (4, "rule Other { condition: filesize > 100 }")]);
    assert_eq!(lib.failed.iter().map(|f| f.0).collect::<Vec<_>>(), vec![3]);
    let s = scan(&lib.scanner, b"xxabcxx");
    let mut ids: Vec<(i64, String)> = s.matches.iter().map(|m| (namespace_id(&m.namespace).unwrap(), m.rule.clone())).collect();
    ids.sort();
    assert_eq!(ids, vec![(1, "Same".to_string()), (2, "Same".to_string())]);
    assert_eq!(namespace_id("default"), None);
}

#[test]
fn helpers_read_plainly() {
    assert_eq!(plain("mem:3:7: error: unknown identifier \"x\""), "Line 3, column 7: unknown identifier \"x\"");
    assert_eq!(plain("something else"), "something else");
    assert_eq!(technique_ids("T1059.001, t1105; T12345 xT1000 T1027.0021"), vec!["T1059.001", "T1105"]);
    assert_eq!(preview(b"ab\x00\xff\n"), "ab\\x00\\xff\\n");
    assert_eq!(imports("import \"pe\"\n  import \"hash\"\n// import \"x\"\nimport \"pe\""), vec!["hash", "pe"]);
    assert_eq!(level_of("Moderate"), Some("medium"));
    let caps = capabilities();
    assert_eq!(caps["limits"]["scanSeconds"], 30);
}

/// boreal's parser recurses without a limit on chains of prefix operators, nested calls and
/// indexes, and chains of arithmetic, bitwise and comparison operators: 5,000 levels (300 for
/// calls) overflowed the stack and ended the process. Such rules are refused before boreal reads
/// them; a crash here would end the whole test run.
#[test]
fn deep_conditions_are_refused_before_they_reach_the_parser() {
    let n = 5000;
    let shapes = [
        ("not", format!("rule R {{ condition: {}true }}", "not ".repeat(n))),
        ("defined", format!("rule R {{ condition: {}true }}", "defined ".repeat(n))),
        ("minus", format!("rule R {{ condition: {}1 == 1 }}", "-".repeat(n))),
        ("tilde", format!("rule R {{ condition: {}1 == 1 }}", "~".repeat(n))),
        ("mixed", format!("rule R {{ condition: {}1 == 1 }}", "not -".repeat(n))),
        ("calls", format!("rule R {{ condition: {}0{} == 0 }}", "uint8(".repeat(n), ")".repeat(n))),
        ("indexes", format!("rule R {{ strings: $a = \"A\" condition: {}1{} > 0 }}", "@a[".repeat(n), "]".repeat(n))),
        ("plus", format!("rule R {{ condition: 1{} > 0 }}", " + 1".repeat(n))),
        ("bits", format!("rule R {{ condition: 1{} > 0 }}", " | 1".repeat(n))),
        ("compare", format!("rule R {{ condition: true{} }}", " == true".repeat(n))),
        ("parens", format!("rule R {{ condition: {}true{} }}", "(".repeat(n), ")".repeat(n))),
        ("in a comment-free tail", format!("rule R {{ condition: true }}\n// )\nrule S {{ condition: {}1 == 1 }}", "~".repeat(n))),
    ];
    for (name, text) in &shapes {
        let c = check(text);
        assert!(c.scanner.is_none(), "{name}");
        assert!(c.issues[0].message.contains("nests about"), "{name}: {:?}", c.issues);
        let lib = library(&[(7, text)]);
        assert_eq!(lib.failed.first().map(|f| f.0), Some(7), "{name}");
    }

    // what is skipped does not count: comments, strings, regular expressions, hex strings
    let skipped = format!(
        "rule S\n{{\n  meta:\n    note = \"{}\"\n  strings:\n    $h = {{ 41 ( 42 | 43{} ) 44 }}\n    $r = /a(b|c){}/\n  condition:\n    // {}\n    /* {} */\n    any of them\n}}\n",
        "(".repeat(500),
        " | 45".repeat(500),
        "|d".repeat(500),
        "not ".repeat(500),
        "~".repeat(500)
    );
    assert!(nesting(&skipped) < 10, "{}", nesting(&skipped));
    assert!(check(&skipped).scanner.is_some(), "{:?}", check(&skipped).issues);

    // long flat conditions, as generated rules have, are fine
    let flat = format!(
        "rule F {{ strings: {} condition: {} }}",
        (0..300).map(|i| format!("$s{i} = \"x{i}y\"")).collect::<Vec<_>>().join(" "),
        (0..300).map(|i| format!("#s{i} > 0")).collect::<Vec<_>>().join(" and ")
    );
    assert!(nesting(&flat) < 10);
    assert!(check(&flat).scanner.is_some());
    assert!(nesting(DEMO) < 10, "{}", nesting(DEMO));

    // between boreal's limit (40) and ours (64): boreal says why
    let c = check(&format!("rule R {{ condition: {}true }}", "not ".repeat(50)));
    assert!(c.issues[0].message.contains("too complex"), "{:?}", c.issues);
}


/// Compiles every rule file of a folder (`CYBERHUB_YARA_RULES`) and says how many compile, why
/// the others do not, and that no real rule is refused for nesting:
/// `cargo test --lib yara_rule_corpus -- --ignored --nocapture`.
#[test]
#[ignore]
fn yara_rule_corpus() {
    let Ok(dir) = std::env::var("CYBERHUB_YARA_RULES") else { return };
    let started = std::time::Instant::now();
    let (mut files, mut ok, mut rules) = (0, 0, 0);
    let mut failed: std::collections::BTreeMap<String, usize> = Default::default();
    let mut nested = Vec::new();
    let mut slowest = (std::time::Duration::ZERO, String::new());
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        files += 1;
        let Ok(text) = std::fs::read_to_string(&path) else {
            *failed.entry("not UTF-8 text".into()).or_default() += 1;
            continue;
        };
        let t = std::time::Instant::now();
        let c = check(&text);
        if t.elapsed() > slowest.0 {
            slowest = (t.elapsed(), path.display().to_string());
        }
        if c.scanner.is_some() {
            ok += 1;
            rules += c.meta.rules.len();
            continue;
        }
        let m = c.issues.iter().find(|i| i.level == "error").map(|i| i.message.clone()).unwrap_or_default();
        if m.contains("nests about") {
            nested.push(path.display().to_string());
        }
        let reason = m.split_once(": ").filter(|(head, _)| head.starts_with("Line ")).map(|(_, r)| r).unwrap_or(&m);
        let reason: String = reason.split('"').next().unwrap_or("").chars().take(60).collect();
        *failed.entry(reason).or_default() += 1;
    }
    eprintln!("CORPUS {dir}: {ok} of {files} files compile ({rules} rules) in {:.1?}; slowest {:.1?} {}", started.elapsed(), slowest.0, slowest.1);
    for (reason, n) in &failed {
        eprintln!("CORPUS   {n:4}  {reason}");
    }
    assert!(nested.is_empty(), "refused for nesting: {nested:?}");
}
