use super::*;
use crate::detection::events::{Event, Kind as SampleKind, Sample};
use crate::detection::sigma;

fn doc(yaml: &str) -> serde_json::Map<String, Value> {
    match crate::yaml::parse_documents(yaml).unwrap().remove(0) {
        Value::Object(o) => o,
        other => panic!("not a mapping: {other:?}"),
    }
}

fn corr(yaml: &str) -> Correlation {
    let (c, issues) = parse(&doc(yaml));
    c.unwrap_or_else(|| panic!("not valid: {issues:?}"))
}

fn errors(yaml: &str) -> Vec<String> {
    let (c, issues) = parse(&doc(yaml));
    assert!(c.is_none(), "expected a refusal");
    issues.into_iter().filter(|(l, _)| *l != "warning").map(|(_, m)| m).collect()
}

fn ev(time: &str, fields: &[(&str, &str)]) -> Event {
    Event { position: format!("record {time}"), time: time.into(), fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), text: String::new() }
}

fn sample(events: Vec<Event>) -> Sample {
    Sample { kind: SampleKind::Json, events, truncated: false, warnings: vec![] }
}

/// A detection rule from YAML (any log source: these events have no channel).
fn rule(yaml: &str) -> Box<sigma::Rule> {
    let mut v = sigma::read(yaml).unwrap();
    Box::new(v.remove(0).rule.expect("the rule compiles"))
}

const FAILED: &str = "title: Single failed login\nname: failed_login\nlogsource:\n  product: test\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\n";
const SUCCESS: &str = "title: Successful login\nname: successful_login\nlogsource:\n  product: test\ndetection:\n  selection:\n    EventID: 4624\n  condition: selection\n";

/// Resolves the names used in these tests.
fn resolver(extra: Vec<(&'static str, Correlation)>) -> impl FnMut(&str) -> Result<Resolved, String> {
    move |r: &str| match r {
        "failed_login" => Ok(Resolved::Rule { title: "Single failed login".into(), rule: rule(FAILED) }),
        "successful_login" => Ok(Resolved::Rule { title: "Successful login".into(), rule: rule(SUCCESS) }),
        other => extra
            .iter()
            .find(|(n, _)| *n == other)
            .map(|(n, c)| Resolved::Correlation { key: n.to_string(), title: n.to_string(), correlation: c.clone() })
            .ok_or_else(|| format!("No rule named '{other}' in the library")),
    }
}

fn run(c: Correlation, extra: Vec<(&'static str, Correlation)>, events: Vec<Event>) -> Outcome {
    let mut t = Tree::build("root", c, &mut resolver(extra)).unwrap();
    t.feed(&sample(events), 1, "Security.evtx");
    t.finish()
}

fn at(minute: u32, second: u32) -> String {
    let total = minute * 60 + second;
    format!("2026-11-09T10:{:02}:{:02}Z", total / 60, total % 60)
}

#[test]
fn the_specification_examples_are_read() {
    let c = corr("title: Many failed logins\nid: 0e95725d-7320-415d-80f7-004da920fc11\ncorrelation:\n    type: event_count\n    rules:\n        - 5638f7c0-ac70-491d-8465-2a65075e0d86\n    group-by:\n        - ComputerName\n    timespan: 1h\n    condition:\n        gte: 100\n");
    assert_eq!((c.kind, c.timespan, c.group_by.clone(), c.condition.clone()), (Kind::EventCount, 3600, vec!["ComputerName".to_string()], vec![(Op::Gte, 100.0)]));
    let c = corr("title: Failed login\ncorrelation:\n    type: value_count\n    rules:\n        - 5638f7c0-ac70-491d-8465-2a65075e0d86\n    group-by:\n        - ComputerName\n        - WorkstationName\n    timespan: 1d\n    condition:\n        field: User\n        gte: 100\n");
    assert_eq!((c.kind, c.timespan, c.fields.clone()), (Kind::ValueCount, 86_400, vec!["User".to_string()]));
    assert_eq!(c.condition_text(), "distinct User ≥ 100");
    let c = corr("title: Recon\ncorrelation:\n    type: temporal\n    rules:\n        - recon_cmd_a\n        - recon_cmd_b\n        - recon_cmd_c\n    group-by:\n        - ComputerName\n        - User\n    timespan: 5m\n");
    assert_eq!((c.kind, c.rules.len(), c.timespan, c.condition_text()), (Kind::Temporal, 3, 300, "all 3 rules".to_string()));
    let c = corr("title: Exfiltration\ncorrelation:\n    type: value_sum\n    rules:\n        - website_access\n    group-by:\n        - SourceIP\n        - User\n    timespan: 1h\n    condition:\n        field: bytes_sent\n        gt: 1000000\n");
    assert_eq!(c.condition_text(), "sum of bytes_sent > 1000000");
    let c = corr("title: Average\ncorrelation:\n    type: value_avg\n    rules:\n        - rule_a_id\n    group-by:\n        - SourceIP\n    timespan: 24h\n    condition:\n        field: BytesOut\n        gt: 500\n");
    assert_eq!((c.kind, c.timespan), (Kind::ValueAvg, 86_400));
    // a range
    let c = corr("title: Range\ncorrelation:\n    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: 90m\n    condition:\n        gt: 100\n        lte: 200\n");
    assert_eq!((c.timespan, c.condition_text()), (5400, "count > 100 and count ≤ 200".to_string()));
    // aliases, as in the specification's example
    let c = corr("title: Aliases\ncorrelation:\n    type: temporal\n    rules:\n        - internal_error\n        - new_network_connection\n    group-by:\n        - internal_ip\n        - remote_ip\n    timespan: 10s\n    aliases:\n        internal_ip:\n            internal_error: destination.ip\n            new_network_connection: source.ip\n        remote_ip:\n            internal_error: source.ip\n            new_network_connection: destination.ip\n");
    assert_eq!(c.aliases["internal_ip"]["internal_error"], "destination.ip");
    // generate, inside the section (pySigma) or at the top level (the specification's component list)
    assert!(corr("title: G\ncorrelation:\n    type: temporal\n    rules: [a, b]\n    group-by: [User]\n    timespan: 1m\n    generate: true\n").generate);
    assert!(corr("title: G\ngenerate: true\ncorrelation:\n    type: temporal\n    rules: [a, b]\n    group-by: [User]\n    timespan: 1m\n").generate);
}

#[test]
fn malformed_and_unsupported_correlations_are_refused_with_the_reason() {
    let base = |body: &str| format!("title: X\ncorrelation:\n{body}");
    assert!(errors(&base("    rules: [a]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 2\n")).iter().any(|e| e.contains("no type")));
    assert!(errors(&base("    type: event_counts\n    rules: [a]\n    timespan: 1h\n    condition:\n        gte: 2\n")).iter().any(|e| e.contains("Unknown correlation type")));
    let (c, issues) = parse(&doc(&base("    type: value_percentile\n    rules: [a]\n    group-by: [Host]\n    timespan: 24h\n    condition:\n        field: image\n        lte: 1\n")));
    assert!(c.is_none() && issues.iter().any(|(l, m)| *l == "unsupported" && m.contains("percentile")));
    for (span, why) in [("1H", "no unit"), ("1w", "no unit"), ("0m", "greater than zero"), ("32d", "31 days"), ("soon", "not a number")] {
        let e = errors(&base(&format!("    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: {span}\n    condition:\n        gte: 2\n")));
        assert!(e.iter().any(|m| m.contains(why)), "{span}: {e:?}");
    }
    assert!(errors(&base("    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: 1h\n")).iter().any(|e| e.contains("needs a condition")));
    assert!(errors(&base("    type: value_count\n    rules: [a]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 2\n")).iter().any(|e| e.contains("needs condition.field")));
    assert!(errors(&base("    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gt: 1\n        lt: 9\n        neq: 4\n")).iter().any(|e| e.contains("two for a range")));
    assert!(errors(&base("    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: 1h\n    condition:\n        above: 2\n")).iter().any(|e| e.contains("Unknown condition")));
    assert!(errors(&base("    type: event_count\n    rules: []\n    group-by: [User]\n    timespan: 1h\n    condition:\n        gte: 2\n")).iter().any(|e| e.contains("refers to no rules")));
    assert!(errors(&base("    type: event_count\n    rules: [a]\n    timespan: 1h\n    condition:\n        gte: many\n")).iter().any(|e| e.contains("must be a number")));
    // through the Sigma checker: valid correlations are runnable, a detection section is refused
    let ok = sigma::read(&base("    type: temporal\n    rules: [a, b]\n    group-by: [User]\n    timespan: 5m\n")).unwrap().remove(0);
    assert!(ok.runnable() && ok.rule.is_none() && ok.correlation.is_some(), "{:?}", ok.issues);
    let bad = sigma::read(&format!("{}detection:\n  sel:\n    a: 1\n  condition: sel\n", base("    type: temporal\n    rules: [a, b]\n    group-by: [User]\n    timespan: 5m\n"))).unwrap().remove(0);
    assert!(!bad.runnable());
}

#[test]
fn event_count_slides_across_clock_boundaries_and_counts_per_group() {
    let c = corr("title: Burst\ncorrelation:\n    type: event_count\n    rules: [failed_login]\n    group-by: [User]\n    timespan: 1m\n    condition:\n        gte: 3\n");
    // alice: 3 failures within 30 s, across the 10:00/10:01 boundary; bob: 3 failures over 3 minutes
    let events = vec![
        ev(&at(0, 50), &[("EventID", "4625"), ("User", "alice")]),
        ev(&at(1, 5), &[("EventID", "4625"), ("User", "alice")]),
        ev(&at(1, 20), &[("EventID", "4625"), ("User", "alice")]),
        ev(&at(0, 0), &[("EventID", "4625"), ("User", "bob")]),
        ev(&at(1, 30), &[("EventID", "4625"), ("User", "bob")]),
        ev(&at(3, 0), &[("EventID", "4625"), ("User", "bob")]),
        ev(&at(1, 0), &[("EventID", "4624"), ("User", "alice")]),
    ];
    let out = run(c.clone(), vec![], events);
    assert_eq!(out.matched, 1, "{out:?}");
    let f = &out.found[0];
    assert_eq!((f.group.clone(), f.value, f.total, f.first.as_str(), f.last.as_str()), (vec![("User".into(), "alice".into())], 3.0, 3, "2026-11-09T10:00:50Z", "2026-11-09T10:01:20Z"));
    assert_eq!(f.position(), "window 2026-11-09T10:00:50Z – 2026-11-09T10:01:20Z · User=alice");
    let x = f.explanation(&c, &["Single failed login".into()]);
    assert_eq!((x["kind"].as_str(), x["condition"].as_str(), x["events"].as_array().map(Vec::len)), (Some("correlation"), Some("count ≥ 3"), Some(3)));
    // a long burst: one match per window, extended while the condition holds
    let burst: Vec<Event> = (0..10).map(|i| ev(&at(5, i * 5), &[("EventID", "4625"), ("User", "carol")])).collect();
    let out = run(c, vec![], burst);
    assert_eq!((out.matched, out.found[0].value), (1, 10.0), "ten failures in 45 s are one window of 10");
}

#[test]
fn value_count_sum_and_average_measure_the_field() {
    let distinct = corr("title: Spray\ncorrelation:\n    type: value_count\n    rules: [failed_login]\n    group-by: [Host]\n    timespan: 10m\n    condition:\n        field: User\n        gte: 3\n");
    let events = |users: &[&str]| users.iter().enumerate().map(|(i, u)| ev(&at(0, i as u32), &[("EventID", "4625"), ("Host", "dc1"), ("User", u)])).collect::<Vec<_>>();
    assert_eq!(run(distinct.clone(), vec![], events(&["a", "a", "b", "a", "b"])).matched, 0, "two distinct users only");
    let out = run(distinct, vec![], events(&["a", "b", "a", "c"]));
    assert_eq!((out.matched, out.found[0].value), (1, 3.0));

    let sum = corr("title: Bytes\ncorrelation:\n    type: value_sum\n    rules: [failed_login]\n    group-by: [Host]\n    timespan: 1h\n    condition:\n        field: bytes\n        gt: 1000\n");
    let mut ev3 = vec![ev(&at(0, 1), &[("EventID", "4625"), ("Host", "h"), ("bytes", "600")]), ev(&at(0, 2), &[("EventID", "4625"), ("Host", "h"), ("bytes", "500")])];
    ev3.push(ev(&at(0, 3), &[("EventID", "4625"), ("Host", "h"), ("bytes", "lots")]));
    let out = run(sum, vec![], ev3.clone());
    assert_eq!((out.matched, out.found[0].value), (1, 1100.0));
    assert!(out.notes.iter().any(|n| n.contains("not a number")), "{:?}", out.notes);
    let avg = corr("title: Avg\ncorrelation:\n    type: value_avg\n    rules: [failed_login]\n    group-by: [Host]\n    timespan: 1h\n    condition:\n        field: bytes\n        gt: 560\n");
    assert_eq!(run(avg, vec![], ev3).matched, 0, "the average of 600 and 500 is 550");
}

#[test]
fn temporal_needs_every_rule_and_temporal_ordered_their_order() {
    let any = corr("title: Both\ncorrelation:\n    type: temporal\n    rules: [failed_login, successful_login]\n    group-by: [User]\n    timespan: 5m\n");
    let ordered = Correlation { kind: Kind::TemporalOrdered, ..any.clone() };
    let success_first = vec![ev(&at(0, 0), &[("EventID", "4624"), ("User", "u")]), ev(&at(1, 0), &[("EventID", "4625"), ("User", "u")])];
    assert_eq!(run(any.clone(), vec![], success_first.clone()).matched, 1, "any order");
    assert_eq!(run(ordered.clone(), vec![], success_first).matched, 0, "the success came first");
    let in_order = vec![ev(&at(0, 0), &[("EventID", "4625"), ("User", "u")]), ev(&at(4, 0), &[("EventID", "4624"), ("User", "u")])];
    assert_eq!(run(ordered.clone(), vec![], in_order).matched, 1);
    let too_late = vec![ev(&at(0, 0), &[("EventID", "4625"), ("User", "u")]), ev(&at(6, 0), &[("EventID", "4624"), ("User", "u")])];
    assert_eq!(run(ordered, vec![], too_late.clone()).matched, 0, "outside the 5 minutes");
    assert_eq!(run(any.clone(), vec![], too_late).matched, 0);
    let other_user = vec![ev(&at(0, 0), &[("EventID", "4625"), ("User", "u")]), ev(&at(1, 0), &[("EventID", "4624"), ("User", "v")])];
    assert_eq!(run(any, vec![], other_user).matched, 0, "different groups");
}

#[test]
fn the_specification_chain_finds_failed_logins_followed_by_a_success() {
    let many = corr("title: Multiple failed logons\nname: multiple_failed_login\ncorrelation:\n    type: event_count\n    rules:\n        - failed_login\n    group-by:\n        - User\n    timespan: 10m\n    condition:\n        gte: 10\n");
    let outer = corr("title: Correlation - Multiple Failed Logins Followed by Successful Login\ncorrelation:\n    type: temporal_ordered\n    rules:\n        - multiple_failed_login\n        - successful_login\n    group-by:\n        - User\n    timespan: 10m\n");
    let mut events: Vec<Event> = (0..12).map(|i| ev(&at(0, i * 10), &[("EventID", "4625"), ("User", "admin")])).collect();
    events.push(ev(&at(3, 0), &[("EventID", "4624"), ("User", "admin")]));
    // another user: nine failures then a success, which is not enough
    events.extend((0..9).map(|i| ev(&at(0, i), &[("EventID", "4625"), ("User", "guest")])));
    events.push(ev(&at(1, 0), &[("EventID", "4624"), ("User", "guest")]));
    let out = run(outer.clone(), vec![("multiple_failed_login", many.clone())], events.clone());
    assert_eq!(out.matched, 1, "{out:?}");
    let f = &out.found[0];
    assert_eq!(f.group, vec![("User".to_string(), "admin".to_string())]);
    assert_eq!(f.events.len(), 2, "the inner window and the success");
    assert!(f.events[0].position.starts_with("window 2026-11-09T10:00:00Z"), "{:?}", f.events[0]);
    // without the success there is nothing
    let no_success: Vec<Event> = events.into_iter().filter(|e| e.get("EventID") != Some("4624")).collect();
    assert_eq!(run(outer, vec![("multiple_failed_login", many)], no_success).matched, 0);
}

#[test]
fn aliases_group_different_fields_of_different_rules() {
    let err = "title: Internal error\nname: internal_error\nlogsource:\n  product: test\ndetection:\n  sel:\n    http.response.status_code: 500\n  condition: sel\n";
    let conn = "title: New connection\nname: new_network_connection\nlogsource:\n  product: test\ndetection:\n  sel:\n    event.category: network\n  condition: sel\n";
    let c = corr("title: Aliases\ncorrelation:\n    type: temporal\n    rules:\n        - internal_error\n        - new_network_connection\n    group-by:\n        - internal_ip\n        - remote_ip\n    timespan: 10s\n    aliases:\n        internal_ip:\n            internal_error: destination.ip\n            new_network_connection: source.ip\n        remote_ip:\n            internal_error: source.ip\n            new_network_connection: destination.ip\n");
    let mut resolve = |r: &str| -> Result<Resolved, String> {
        Ok(match r {
            "internal_error" => Resolved::Rule { title: "Internal error".into(), rule: rule(err) },
            _ => Resolved::Rule { title: "New connection".into(), rule: rule(conn) },
        })
    };
    let mut t = Tree::build("root", c.clone(), &mut resolve).unwrap();
    t.feed(
        &sample(vec![
            ev(&at(0, 0), &[("http.response.status_code", "500"), ("destination.ip", "10.0.0.5"), ("source.ip", "203.0.113.9")]),
            ev(&at(0, 4), &[("event.category", "network"), ("source.ip", "10.0.0.5"), ("destination.ip", "203.0.113.9")]),
            // the same addresses the wrong way round: not the same pair
            ev(&at(0, 6), &[("event.category", "network"), ("source.ip", "203.0.113.9"), ("destination.ip", "10.0.0.5")]),
        ]),
        7,
        "proxy.json",
    );
    let out = t.finish();
    assert_eq!(out.matched, 1, "{out:?}");
    assert_eq!(out.found[0].group, vec![("internal_ip".to_string(), "10.0.0.5".to_string()), ("remote_ip".to_string(), "203.0.113.9".to_string())]);
    assert_eq!(out.found[0].source_id(), 7);
}

#[test]
fn events_without_time_or_group_fields_take_no_part_and_say_so() {
    let c = corr("title: Burst\ncorrelation:\n    type: event_count\n    rules: [failed_login]\n    group-by: [User]\n    timespan: 1m\n    condition:\n        gte: 2\n");
    let out = run(c, vec![], vec![ev("", &[("EventID", "4625"), ("User", "a")]), ev("yesterday", &[("EventID", "4625"), ("User", "a")]), ev(&at(0, 0), &[("EventID", "4625")]), ev(&at(0, 1), &[("EventID", "4625"), ("User", "a")])]);
    assert_eq!(out.matched, 0);
    assert!(out.notes.iter().any(|n| n == "2 matching events without a usable time took no part"), "{:?}", out.notes);
    assert!(out.notes.iter().any(|n| n == "1 matching event without a group-by field took no part"), "{:?}", out.notes);
    // the time formats events come with
    for t in ["2026-11-09T10:00:00Z", "2026-11-09T12:00:00+02:00", "2026-11-09T10:00:00.1234567Z", "2026-11-09 10:00:00", "2026-11-09T10:00:00", "1794218400", "1794218400000"] {
        assert_eq!(epoch(t).map(|s| s.round() as i64), Some(1_794_218_400), "{t}");
    }
}

#[test]
fn references_are_resolved_cycles_refused_and_results_bounded() {
    let c = corr("title: X\ncorrelation:\n    type: temporal\n    rules: [failed_login, nowhere]\n    group-by: [User]\n    timespan: 1m\n");
    assert!(Tree::build("x", c, &mut resolver(vec![])).err().unwrap().contains("No rule named 'nowhere'"));
    let a = corr("title: A\ncorrelation:\n    type: event_count\n    rules: [b]\n    group-by: [User]\n    timespan: 1m\n    condition:\n        gte: 1\n");
    let b = corr("title: B\ncorrelation:\n    type: event_count\n    rules: [a]\n    group-by: [User]\n    timespan: 1m\n    condition:\n        gte: 1\n");
    let err = Tree::build("a", a.clone(), &mut resolver(vec![("a", a.clone()), ("b", b)])).err().unwrap();
    assert!(err.contains("refers to itself"), "{err}");
    // many groups and many matches: everything is counted, a bounded number listed
    let c = corr("title: Each\ncorrelation:\n    type: event_count\n    rules: [failed_login]\n    group-by: [User]\n    timespan: 1m\n    condition:\n        gte: 1\n");
    let events: Vec<Event> = (0..(MAX_FOUND + 50)).map(|i| ev(&at(0, 0), &[("EventID", "4625"), ("User", &format!("u{i}"))])).collect();
    let out = run(c, vec![], events);
    assert_eq!((out.matched, out.found.len()), (MAX_FOUND + 50, MAX_FOUND));
}
