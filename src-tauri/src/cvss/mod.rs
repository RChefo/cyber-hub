//! CVSS v3.1 and v4.0 vectors: validation, canonical form and scores (docs/DATA_MODEL.md#cvss).
//!
//! * **v3.1** follows the FIRST specification (section 7 and Appendix A, including its `Roundup`).
//! * **v3.0** vectors are scored with the 3.0 equations, as FIRST's 3.0 calculator does: `Roundup`
//!   is `ceil(x × 10) / 10`, and the modified impact of a changed scope is
//!   `7.52 × (MISS − 0.029) − 3.25 × (MISS − 0.02)^15`. 3.1 changed both, so about one in twenty
//!   3.0 vectors with environmental metrics would score differently under the 3.1 equations.
//! * Both are computed in the order of FIRST's calculators (`cvsscalc31.js`, `cvsscalc30.js`), so
//!   results round the same way.
//! * **v4.0** follows FIRST's reference calculator (`cvss_score.js`): macrovector equivalence
//!   classes, the macrovector lookup table (`v4_lookup.rs`, BSD-2-Clause), and interpolation by
//!   severity distance. The arithmetic is done in the same order as the reference so the results
//!   round the same way.
//!
//! Vectors are parsed strictly: the right prefix, every base metric once, known metrics and values
//! only. Metric order is not enforced on input (FIRST's own examples are not always in order); the
//! canonical form written back is in the specification's order without `X` values.

mod v4_lookup;

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cvss {
    /// "3.0", "3.1" or "4.0"
    pub version: &'static str,
    /// canonical vector
    pub vector: String,
    /// the score of everything in the vector (environmental, else temporal/threat, else base)
    pub score: f64,
    pub base_score: f64,
    /// qualitative rating of `score`: none, low, medium, high, critical
    pub rating: &'static str,
    /// what the score covers: v4.0 `CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE`; v3 `Base`,
    /// `Temporal`, `Environmental`
    pub label: &'static str,
}

/// Qualitative severity rating scale (the same for v3.x and v4.0).
pub fn rating(score: f64) -> &'static str {
    if score <= 0.0 {
        "none"
    } else if score < 4.0 {
        "low"
    } else if score < 7.0 {
        "medium"
    } else if score < 9.0 {
        "high"
    } else {
        "critical"
    }
}

/// Validates and scores a vector.
pub fn parse(vector: &str) -> Result<Cvss, String> {
    let v = vector.trim();
    if v.len() > 400 {
        return Err("The vector is too long".into());
    }
    if let Some(rest) = v.strip_prefix("CVSS:4.0/") {
        return v4(rest);
    }
    if let Some(rest) = v.strip_prefix("CVSS:3.1/") {
        return v3(rest, "3.1");
    }
    if let Some(rest) = v.strip_prefix("CVSS:3.0/") {
        return v3(rest, "3.0");
    }
    Err("Enter a CVSS 3.1 or 4.0 vector, starting with CVSS:3.1/ or CVSS:4.0/".into())
}

type Metrics = BTreeMap<&'static str, &'static str>;
type Spec = [(&'static str, &'static [&'static str])];

/// Metric → value, checked against `spec` (names, values, duplicates, required base metrics).
fn metrics(rest: &str, spec: &Spec, base: &[&str]) -> Result<Metrics, String> {
    let mut out: Metrics = BTreeMap::new();
    for part in rest.split('/') {
        let Some((k, val)) = part.split_once(':') else {
            return Err(format!("“{part}” is not a metric (write NAME:VALUE)"));
        };
        let Some((name, values)) = spec.iter().find(|(n, _)| *n == k) else {
            return Err(format!("{k} is not a metric of this CVSS version"));
        };
        let Some(value) = values.iter().find(|x| **x == val) else {
            return Err(format!("{val} is not a value of {k} (allowed: {})", values.join(", ")));
        };
        if out.insert(name, value).is_some() {
            return Err(format!("{k} appears more than once"));
        }
    }
    let missing: Vec<&str> = base.iter().filter(|b| !out.contains_key(*b)).copied().collect();
    if !missing.is_empty() {
        return Err(format!("Every base metric is required; missing: {}", missing.join(", ")));
    }
    Ok(out)
}

fn canonical(prefix: &str, spec: &Spec, base: &[&str], sel: &Metrics) -> String {
    let mut s = prefix.to_string();
    for (name, _) in spec {
        if let Some(v) = sel.get(name) {
            if base.contains(name) || *v != "X" {
                s.push('/');
                s.push_str(name);
                s.push(':');
                s.push_str(v);
            }
        }
    }
    s
}

/* ───────────────────────── v3.1 ───────────────────────── */

const V3: &Spec = &[
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "R"]),
    ("S", &["U", "C"]),
    ("C", &["H", "L", "N"]),
    ("I", &["H", "L", "N"]),
    ("A", &["H", "L", "N"]),
    ("E", &["X", "H", "F", "P", "U"]),
    ("RL", &["X", "U", "W", "T", "O"]),
    ("RC", &["X", "C", "R", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "R"]),
    ("MS", &["X", "U", "C"]),
    ("MC", &["X", "H", "L", "N"]),
    ("MI", &["X", "H", "L", "N"]),
    ("MA", &["X", "H", "L", "N"]),
];
const V3_BASE: &[&str] = &["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

/// `Roundup` of the CVSS v3.1 specification, Appendix A: the smallest number with one decimal
/// place that is equal to or higher than the input, computed in integers to avoid floating-point
/// artifacts.
pub fn roundup(x: f64) -> f64 {
    let i = (x * 100_000.0).round() as i64;
    if i % 10_000 == 0 {
        i as f64 / 100_000.0
    } else {
        ((i / 10_000) + 1) as f64 / 10.0
    }
}

/// `Roundup` of CVSS v3.0 as FIRST's 3.0 calculator computes it: `ceil(x × 10) / 10`.
fn roundup30(x: f64) -> f64 {
    (x * 10.0).ceil() / 10.0
}

fn w_av(v: &str) -> f64 {
    match v {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        _ => 0.2,
    }
}
fn w_ac(v: &str) -> f64 {
    if v == "L" {
        0.77
    } else {
        0.44
    }
}
fn w_pr(v: &str, changed: bool) -> f64 {
    match (v, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        (_, false) => 0.27,
        (_, true) => 0.5,
    }
}
fn w_ui(v: &str) -> f64 {
    if v == "N" {
        0.85
    } else {
        0.62
    }
}
fn w_cia(v: &str) -> f64 {
    match v {
        "H" => 0.56,
        "L" => 0.22,
        _ => 0.0,
    }
}
fn w_req(v: &str) -> f64 {
    match v {
        "H" => 1.5,
        "L" => 0.5,
        _ => 1.0,
    }
}
fn w_e(v: &str) -> f64 {
    match v {
        "F" => 0.97,
        "P" => 0.94,
        "U" => 0.91,
        _ => 1.0,
    }
}
fn w_rl(v: &str) -> f64 {
    match v {
        "W" => 0.97,
        "T" => 0.96,
        "O" => 0.95,
        _ => 1.0,
    }
}
fn w_rc(v: &str) -> f64 {
    match v {
        "R" => 0.96,
        "U" => 0.92,
        _ => 1.0,
    }
}

fn v3(rest: &str, version: &'static str) -> Result<Cvss, String> {
    let sel = metrics(rest, V3, V3_BASE)?;
    let g = |k: &str| sel.get(k).copied().unwrap_or("X");
    // a modified metric replaces its base metric unless it is X
    let eff = |k: &str| match sel.get(format!("M{k}").as_str()) {
        Some(&v) if v != "X" => v,
        _ => g(k),
    };

    let v30 = version == "3.0";
    let up: fn(f64) -> f64 = if v30 { roundup30 } else { roundup };

    let changed = g("S") == "C";
    let iss = 1.0 - ((1.0 - w_cia(g("C"))) * (1.0 - w_cia(g("I"))) * (1.0 - w_cia(g("A"))));
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    let exploitability = 8.22 * w_av(g("AV")) * w_ac(g("AC")) * w_pr(g("PR"), changed) * w_ui(g("UI"));
    let base = if impact <= 0.0 {
        0.0
    } else if changed {
        up((1.08 * (impact + exploitability)).min(10.0))
    } else {
        up((impact + exploitability).min(10.0))
    };

    // multiplied one weight at a time, in the calculators' order (floating point is not associative)
    let (e, rl, rc) = (w_e(g("E")), w_rl(g("RL")), w_rc(g("RC")));
    let has_temporal = ["E", "RL", "RC"].iter().any(|k| g(k) != "X");
    let has_env = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"].iter().any(|k| g(k) != "X");

    let (score, label) = if has_env {
        let mchanged = eff("S") == "C";
        let miss = (1.0 - ((1.0 - w_req(g("CR")) * w_cia(eff("C"))) * (1.0 - w_req(g("IR")) * w_cia(eff("I"))) * (1.0 - w_req(g("AR")) * w_cia(eff("A"))))).min(0.915);
        let mimpact = match (mchanged, v30) {
            (false, _) => 6.42 * miss,
            (true, true) => 7.52 * (miss - 0.029) - 3.25 * (miss - 0.02).powi(15),
            (true, false) => 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02).powi(13),
        };
        let mexpl = 8.22 * w_av(eff("AV")) * w_ac(eff("AC")) * w_pr(eff("PR"), mchanged) * w_ui(eff("UI"));
        let env = if mimpact <= 0.0 {
            0.0
        } else if mchanged {
            up(up((1.08 * (mimpact + mexpl)).min(10.0)) * e * rl * rc)
        } else {
            up(up((mimpact + mexpl).min(10.0)) * e * rl * rc)
        };
        (env, "Environmental")
    } else if has_temporal {
        (up(base * e * rl * rc), "Temporal")
    } else {
        (base, "Base")
    };
    let prefix = if version == "3.0" { "CVSS:3.0" } else { "CVSS:3.1" };
    Ok(Cvss { version, vector: canonical(prefix, V3, V3_BASE, &sel), score, base_score: base, rating: rating(score), label })
}

/* ───────────────────────── v4.0 ───────────────────────── */

const V4: &Spec = &[
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
    ("E", &["X", "A", "P", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];
const V4_BASE: &[&str] = &["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
const V4_ENV: &[&str] = &["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"];

/// The effective value of a metric (FIRST's `m()`): a modified metric replaces the base metric
/// unless it is X; E:X counts as A, and CR/IR/AR:X count as H.
fn m4<'a>(sel: &'a Metrics, k: &str) -> &'a str {
    let v = sel.get(k).copied().unwrap_or("X");
    if k == "E" && v == "X" {
        return "A";
    }
    if matches!(k, "CR" | "IR" | "AR") && v == "X" {
        return "H";
    }
    match sel.get(format!("M{k}").as_str()) {
        Some(&mv) if mv != "X" => mv,
        _ => v,
    }
}

/// Severity level of a metric value (distance from the most severe value), as in the reference.
fn level(k: &str, v: &str) -> f64 {
    match (k, v) {
        ("AV", "N") | ("PR", "N") | ("UI", "N") | ("AC", "L") | ("AT", "N") => 0.0,
        ("AV", "A") | ("PR", "L") | ("UI", "P") | ("AC", "H") | ("AT", "P") => 0.1,
        ("AV", "L") | ("PR", "H") | ("UI", "A") => 0.2,
        ("AV", "P") => 0.3,
        ("VC" | "VI" | "VA", "H") => 0.0,
        ("VC" | "VI" | "VA", "L") => 0.1,
        ("VC" | "VI" | "VA", "N") => 0.2,
        ("SC", "H") => 0.1,
        ("SC", "L") => 0.2,
        ("SC", "N") => 0.3,
        ("SI" | "SA", "S") => 0.0,
        ("SI" | "SA", "H") => 0.1,
        ("SI" | "SA", "L") => 0.2,
        ("SI" | "SA", "N") => 0.3,
        ("CR" | "IR" | "AR", "H") => 0.0,
        ("CR" | "IR" | "AR", "M") => 0.1,
        ("CR" | "IR" | "AR", "L") => 0.2,
        _ => 0.0,
    }
}

/// Highest-severity vectors of each equivalence class level (`MAX_COMPOSED` of the reference).
fn max_composed(eq: usize, l: u8, eq6: u8) -> &'static [&'static str] {
    match (eq, l, eq6) {
        (1, 0, _) => &["AV:N/PR:N/UI:N/"],
        (1, 1, _) => &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        (1, 2, _) => &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        (2, 0, _) => &["AC:L/AT:N/"],
        (2, 1, _) => &["AC:H/AT:N/", "AC:L/AT:P/"],
        (3, 0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        (3, 0, 1) => &["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        (3, 1, 0) => &["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
        (3, 1, 1) => &["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
        (3, 2, 1) => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        (4, 0, _) => &["SC:H/SI:S/SA:S/"],
        (4, 1, _) => &["SC:H/SI:H/SA:H/"],
        (4, 2, _) => &["SC:L/SI:L/SA:L/"],
        (5, 0, _) => &["E:A/"],
        (5, 1, _) => &["E:P/"],
        (5, 2, _) => &["E:U/"],
        _ => &[],
    }
}

/// Maximal severity distances in each class level (`MAX_SEVERITY` of the reference).
fn max_severity(eq: &str, l: u8, eq6: u8) -> f64 {
    let n: u8 = match (eq, l, eq6) {
        ("eq1", 0, _) => 1,
        ("eq1", 1, _) => 4,
        ("eq1", 2, _) => 5,
        ("eq2", 0, _) => 1,
        ("eq2", 1, _) => 2,
        ("eq3eq6", 0, 0) => 7,
        ("eq3eq6", 0, 1) => 6,
        ("eq3eq6", 1, 0) => 8,
        ("eq3eq6", 1, 1) => 8,
        ("eq3eq6", 2, 1) => 10,
        ("eq4", 0, _) => 6,
        ("eq4", 1, _) => 5,
        ("eq4", 2, _) => 4,
        _ => 1,
    };
    n as f64
}

fn lookup(eq: [u8; 6]) -> Option<f64> {
    let key: String = eq.iter().map(|d| char::from(b'0' + d)).collect();
    v4_lookup::LOOKUP.binary_search_by(|(k, _)| (*k).cmp(key.as_str())).ok().map(|i| v4_lookup::LOOKUP[i].1)
}

/// The six equivalence-class levels (the macrovector).
fn macrovector(s: &Metrics) -> [u8; 6] {
    let g = |k: &str| m4(s, k);
    let eq1 = if g("AV") == "N" && g("PR") == "N" && g("UI") == "N" {
        0
    } else if (g("AV") == "N" || g("PR") == "N" || g("UI") == "N") && g("AV") != "P" {
        1
    } else {
        2
    };
    let eq2 = if g("AC") == "L" && g("AT") == "N" { 0 } else { 1 };
    let eq3 = if g("VC") == "H" && g("VI") == "H" {
        0
    } else if g("VC") == "H" || g("VI") == "H" || g("VA") == "H" {
        1
    } else {
        2
    };
    let eq4 = if g("MSI") == "S" || g("MSA") == "S" {
        0
    } else if g("SC") == "H" || g("SI") == "H" || g("SA") == "H" {
        1
    } else {
        2
    };
    let eq5 = match g("E") {
        "A" => 0,
        "P" => 1,
        _ => 2,
    };
    let eq6 = if (g("CR") == "H" && g("VC") == "H") || (g("IR") == "H" && g("VI") == "H") || (g("AR") == "H" && g("VA") == "H") { 0 } else { 1 };
    [eq1, eq2, eq3, eq4, eq5, eq6]
}

fn value_in(metric: &str, vector: &str) -> &'static str {
    // the composed max vectors are static text: `AV:N/PR:N/…/`
    let needle = format!("{metric}:");
    let start = vector.split('/').find_map(|p| p.strip_prefix(needle.as_str())).unwrap_or("");
    match start {
        "N" => "N",
        "A" => "A",
        "L" => "L",
        "P" => "P",
        "H" => "H",
        "M" => "M",
        "S" => "S",
        "U" => "U",
        _ => "",
    }
}

/// The score of a v4.0 selection (FIRST's `cvss_score`).
fn v4_score(s: &Metrics) -> f64 {
    if ["VC", "VI", "VA", "SC", "SI", "SA"].iter().all(|k| m4(s, k) == "N") {
        return 0.0;
    }
    let [eq1, eq2, eq3, eq4, eq5, eq6] = macrovector(s);
    let Some(mut value) = lookup([eq1, eq2, eq3, eq4, eq5, eq6]) else { return 0.0 };
    let lower = |e: [u8; 6]| lookup(e).unwrap_or(f64::NAN);

    let score_eq1_next = lower([eq1 + 1, eq2, eq3, eq4, eq5, eq6]);
    let score_eq2_next = lower([eq1, eq2 + 1, eq3, eq4, eq5, eq6]);
    // EQ3 and EQ6 move together: 00 → the higher of 01 and 10, 01 → 11, 10 → 11, 11 → 21
    let score_eq3eq6_next = match (eq3, eq6) {
        (0 | 1, 1) => lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6]),
        (1, 0) => lower([eq1, eq2, eq3, eq4, eq5, eq6 + 1]),
        (0, 0) => {
            let left = lower([eq1, eq2, eq3, eq4, eq5, eq6 + 1]);
            let right = lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6]);
            if left > right {
                left
            } else {
                right
            }
        }
        _ => lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]),
    };
    let score_eq4_next = lower([eq1, eq2, eq3, eq4 + 1, eq5, eq6]);
    let score_eq5_next = lower([eq1, eq2, eq3, eq4, eq5 + 1, eq6]);

    // the first highest-severity vector of the macrovector that the selection does not exceed
    const DIST: [&str; 14] = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"];
    let mut d = [0.0f64; 14];
    'search: for a in max_composed(1, eq1, 0) {
        for b in max_composed(2, eq2, 0) {
            for c in max_composed(3, eq3, eq6) {
                for e4 in max_composed(4, eq4, 0) {
                    for e5 in max_composed(5, eq5, 0) {
                        let max_vector = format!("{a}{b}{c}{e4}{e5}");
                        for (i, k) in DIST.iter().enumerate() {
                            d[i] = level(k, m4(s, k)) - level(k, value_in(k, &max_vector));
                        }
                        if d.iter().all(|x| *x >= 0.0) {
                            break 'search;
                        }
                    }
                }
            }
        }
    }
    let [av, pr, ui, ac, at, vc, vi, va, sc, si, sa, cr, ir, ar] = d;
    let current_eq1 = av + pr + ui;
    let current_eq2 = ac + at;
    let current_eq3eq6 = vc + vi + va + cr + ir + ar;
    let current_eq4 = sc + si + sa;

    let step = 0.1;
    let available_eq1 = value - score_eq1_next;
    let available_eq2 = value - score_eq2_next;
    let available_eq3eq6 = value - score_eq3eq6_next;
    let available_eq4 = value - score_eq4_next;
    let available_eq5 = value - score_eq5_next;
    let max_eq1 = max_severity("eq1", eq1, 0) * step;
    let max_eq2 = max_severity("eq2", eq2, 0) * step;
    let max_eq3eq6 = max_severity("eq3eq6", eq3, eq6) * step;
    let max_eq4 = max_severity("eq4", eq4, 0) * step;

    let mut n_existing_lower = 0u32;
    let (mut n1, mut n2, mut n36, mut n4, mut n5) = (0.0, 0.0, 0.0, 0.0, 0.0);
    if !available_eq1.is_nan() {
        n_existing_lower += 1;
        n1 = available_eq1 * (current_eq1 / max_eq1);
    }
    if !available_eq2.is_nan() {
        n_existing_lower += 1;
        n2 = available_eq2 * (current_eq2 / max_eq2);
    }
    if !available_eq3eq6.is_nan() {
        n_existing_lower += 1;
        n36 = available_eq3eq6 * (current_eq3eq6 / max_eq3eq6);
    }
    if !available_eq4.is_nan() {
        n_existing_lower += 1;
        n4 = available_eq4 * (current_eq4 / max_eq4);
    }
    if !available_eq5.is_nan() {
        // the reference: every vector of an EQ5 level has the same severity, so the proportion is 0
        n_existing_lower += 1;
        n5 = available_eq5 * 0.0;
    }
    let mean_distance = if n_existing_lower == 0 { 0.0 } else { (n1 + n2 + n36 + n4 + n5) / n_existing_lower as f64 };
    value -= mean_distance;
    value = value.clamp(0.0, 10.0);
    // JavaScript's Math.round(value * 10) / 10 (the value is never negative here)
    (value * 10.0).round() / 10.0
}

fn v4(rest: &str) -> Result<Cvss, String> {
    let sel = metrics(rest, V4, V4_BASE)?;
    let score = v4_score(&sel);
    let base_only: Metrics = sel.iter().filter(|(k, _)| V4_BASE.contains(k)).map(|(k, v)| (*k, *v)).collect();
    let base_score = v4_score(&base_only);
    let threat = sel.get("E").is_some_and(|v| *v != "X");
    let env = V4_ENV.iter().any(|k| sel.get(k).is_some_and(|v| *v != "X"));
    let label = match (threat, env) {
        (false, false) => "CVSS-B",
        (true, false) => "CVSS-BT",
        (false, true) => "CVSS-BE",
        (true, true) => "CVSS-BTE",
    };
    Ok(Cvss { version: "4.0", vector: canonical("CVSS:4.0", V4, V4_BASE, &sel), score, base_score, rating: rating(score), label })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        parse(v).unwrap_or_else(|e| panic!("{v}: {e}")).score
    }

    #[test]
    fn v4_matches_firsts_published_examples() {
        // https://www.first.org/cvss/v4.0/examples (table values; see docs/DATA_MODEL.md#cvss)
        let cases = [
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
            ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9),
            ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2),
            ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L", 8.1),
            ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P", 9.7),
            ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MVC:N/MVI:N/MVA:N", 0.0),
        ];
        for (v, expected) in cases {
            assert_eq!(score(v), expected, "{v}");
        }
    }

    #[test]
    fn v4_labels_canonical_order_and_base_score() {
        let c = parse("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:P/PR:N/AT:P/AC:L/AV:N/E:U/S:X").unwrap();
        assert_eq!(c.vector, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", "spec order, X values dropped");
        assert_eq!((c.score, c.label, c.rating), (5.2, "CVSS-BT", "medium"));
        assert!(c.base_score > c.score, "the threat metric lowers the score: {c:?}");
        assert_eq!(parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H").unwrap().label, "CVSS-BE");
    }

    #[test]
    fn v31_matches_the_specification() {
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.3),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ];
        for (v, expected) in cases {
            assert_eq!(score(v), expected, "{v}");
        }
        // the 3.0 vector of the same base metrics scores the same
        assert_eq!(score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap().version, "3.0");
        // 3.0 keeps its own environmental equations (FIRST's 3.0 calculator: 9.0; 3.1: 9.1)
        let m = "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H/RC:C/AR:M/MPR:L/MUI:R/MC:H";
        assert_eq!(score(&format!("CVSS:3.0/{m}")), 9.0);
        assert_eq!(score(&format!("CVSS:3.1/{m}")), 9.1);
        // and its own Roundup: ceil(x × 10) / 10
        assert_eq!(roundup30(4.000_000_000_000_001), 4.1);
        assert_eq!(roundup(4.000_000_000_000_001), 4.0);
    }

    #[test]
    fn v31_temporal_and_environmental_scores() {
        // Log4Shell base 10.0; exploit code functional, official fix: 10.0 × 0.97 × 0.95 → 9.3 (rounded up)
        let t = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C").unwrap();
        assert_eq!((t.base_score, t.score, t.label), (10.0, 9.3, "Temporal"));
        // the environment removes the impact: no score
        let e = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N").unwrap();
        assert_eq!((e.score, e.label, e.rating), (0.0, "Environmental", "none"));
        // modified metrics equal to the base ones give the base score back
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M"), 9.8);
        assert_eq!(parse("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:X").unwrap().vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    }

    #[test]
    fn roundup_follows_appendix_a() {
        assert_eq!(roundup(4.02), 4.1);
        assert_eq!(roundup(4.0), 4.0);
        assert_eq!(roundup(4.000_000_1), 4.0, "floating-point noise does not round up");
    }

    #[test]
    fn invalid_vectors_are_refused_with_a_reason() {
        for (v, reason) in [
            ("AV:N/AC:L", "CVSS 3.1 or 4.0"),
            ("CVSS:2.0/AV:N", "CVSS 3.1 or 4.0"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "missing: A"),
            ("CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "more than once"),
            ("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "not a value of AV"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AT:N", "not a metric"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", "missing: SA"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N", "not a value of SI"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/", "not a metric"),
        ] {
            let err = parse(v).unwrap_err();
            assert!(err.contains(reason), "{v}: {err}");
        }
        assert_eq!(rating(0.1), "low");
        assert_eq!(rating(9.0), "critical");
        assert_eq!(rating(0.0), "none");
    }

    /// Lines of `vector<TAB>base score<TAB>score` (scripts/cvss-reference.mjs) that this scorer
    /// does not reproduce.
    fn reference_mismatches(tsv: &str) -> (usize, Vec<String>) {
        let mut checked = 0;
        let mut bad = Vec::new();
        for line in tsv.lines().filter(|l| !l.is_empty()) {
            let mut cols = line.split('\t');
            let (Some(vector), Some(base), Some(expected)) = (cols.next(), cols.next(), cols.next()) else {
                panic!("malformed reference line: {line}");
            };
            checked += 1;
            match parse(vector) {
                Ok(c) if format!("{:.1}", c.base_score) == base && format!("{:.1}", c.score) == expected => {}
                Ok(c) => bad.push(format!("{vector}: FIRST {base}/{expected}, here {:.1}/{:.1}", c.base_score, c.score)),
                Err(e) => bad.push(format!("{vector}: refused ({e})")),
            }
        }
        (checked, bad)
    }

    /// FIRST's calculators' scores for 484 vectors: one v4.0 vector per reachable macrovector,
    /// v3.1 vectors with temporal and environmental metrics, and v3.0 vectors whose 3.0 and 3.1
    /// scores differ. Generated by scripts/cvss-reference.mjs.
    #[test]
    fn matches_firsts_reference_calculators() {
        let (checked, bad) = reference_mismatches(include_str!("testdata/first_reference.tsv"));
        assert!(checked > 400, "{checked}");
        assert!(bad.is_empty(), "{} of {checked} differ:\n{}", bad.len(), bad.join("\n"));
    }

    /// The full comparison: every base vector of each version and 200,000 random vectors each.
    /// `CVSS_REFERENCE_DIR=<out dir of scripts/cvss-reference.mjs> cargo test cvss -- --ignored`
    #[test]
    #[ignore = "needs the output of scripts/cvss-reference.mjs"]
    fn matches_firsts_reference_calculators_exhaustively() {
        let dir = std::env::var("CVSS_REFERENCE_DIR").expect("set CVSS_REFERENCE_DIR");
        let mut report = Vec::new();
        for file in ["v40.tsv", "v31.tsv", "v30.tsv"] {
            let tsv = std::fs::read_to_string(std::path::Path::new(&dir).join(file)).expect(file);
            let (checked, bad) = reference_mismatches(&tsv);
            eprintln!("{file}: {checked} vectors, {} differ", bad.len());
            if !bad.is_empty() {
                report.push(format!("{file}: {} of {checked} differ, e.g.\n{}", bad.len(), bad[..bad.len().min(15)].join("\n")));
            }
        }
        assert!(report.is_empty(), "{}", report.join("\n"));
    }
}
