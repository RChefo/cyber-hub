//! OCSF Detection Findings (class 2004), as Prowler writes them with `-M json-ocsf`: a JSON array
//! with one finding per check and resource (docs/DATA_MODEL.md#scan-import).
//!
//! * `status_code` FAIL (or none, for other OCSF producers) is a finding. PASS is kept as proof that
//!   the check now passes on that resource, so a rescan can resolve the finding of an earlier
//!   import; MANUAL checks need a person and are skipped.
//! * A suppressed finding (`status_id` 3, Prowler's muted findings) is skipped like a suppressed
//!   SARIF result; a resolved one (4) counts as passing.
//! * Cloud resources are not network targets: no scope check, no assets. The fingerprint is the
//!   check, account, region (or namespace) and resource, so the same failure is recognized across
//!   scans.
//! * Prowler leaves the array without its closing bracket when a scan is interrupted; such a file is
//!   read as far as it goes and marked incomplete.

use serde_json::Value;

use super::{fingerprint, s, severity_word, strings, tool_tags, trunc, Format, ImportedFinding, Parsed};

/// OCSF class of detection findings.
const DETECTION_FINDING: u64 = 2004;
/// OCSF 1.0 security findings, which older Prowler versions wrote.
const SECURITY_FINDING: u64 = 2001;
/// Compliance frameworks and requirements listed per finding.
const MAX_FRAMEWORKS: usize = 12;
const MAX_REQUIREMENTS: usize = 8;

/// The OCSF class of a JSON value that looks like an OCSF finding.
pub(super) fn finding_class(v: &Value) -> Option<u64> {
    let class = v.get("class_uid").and_then(Value::as_u64)?;
    (class == DETECTION_FINDING || class == SECURITY_FINDING).then_some(class)
}

/// An array whose closing bracket is missing (`[{…},` or `[{…}`), closed.
pub(super) fn repair(text: &str) -> Option<Value> {
    let t = text.trim();
    if !t.starts_with('[') || t.ends_with(']') {
        return None;
    }
    let t = t.strip_suffix(',').unwrap_or(t);
    serde_json::from_str::<Value>(&format!("{t}]")).ok().filter(|v| v.as_array().and_then(|a| a.first()).is_some_and(|f| finding_class(f).is_some()))
}

fn severity(x: &Value) -> &'static str {
    match x.get("severity_id").and_then(Value::as_u64) {
        Some(5) | Some(6) => "critical",
        Some(4) => "high",
        Some(3) => "medium",
        Some(2) => "low",
        Some(1) => "info",
        _ => severity_word(&s(x, "severity")),
    }
}

/// `CIS-2.0 1.20, 1.21 · ISO27001-2013 A.12.4` (the first frameworks, the first requirements).
fn compliance(v: &Value) -> String {
    let Some(map) = v.as_object() else { return String::new() };
    let mut parts: Vec<String> = map
        .iter()
        .take(MAX_FRAMEWORKS)
        .map(|(k, reqs)| {
            let r = strings(Some(reqs));
            let more = if r.len() > MAX_REQUIREMENTS { format!(" and {} more", r.len() - MAX_REQUIREMENTS) } else { String::new() };
            format!("{k} {}{more}", r.into_iter().take(MAX_REQUIREMENTS).collect::<Vec<_>>().join(", "))
        })
        .collect();
    if map.len() > MAX_FRAMEWORKS {
        parts.push(format!("{} more frameworks", map.len() - MAX_FRAMEWORKS));
    }
    parts.join(" · ")
}

/// `(technique id, "T1078 Valid Accounts (Initial Access)")` of each ATT&CK entry: OCSF's
/// `finding_info.attacks`, then the technique IDs Prowler lists as `MITRE-ATTACK` compliance
/// requirements.
fn attacks(x: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    // duplicates are found through a set: a linear scan per entry was quadratic in the list
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for a in x["finding_info"].get("attacks").and_then(Value::as_array).into_iter().flatten() {
        let id = s(&a["technique"], "uid");
        if id.is_empty() || !seen.insert(id.clone()) {
            continue;
        }
        let name = s(&a["technique"], "name");
        let tactic = s(&a["tactic"], "name");
        let label = [id.clone(), name, if tactic.is_empty() { String::new() } else { format!("({tactic})") }].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ");
        out.push((id, label));
    }
    let technique = |t: &str| {
        let b = t.as_bytes();
        b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit) && (b.len() == 5 || (b.len() == 9 && b[5] == b'.' && b[6..].iter().all(u8::is_ascii_digit)))
    };
    for (k, reqs) in x["unmapped"]["compliance"].as_object().into_iter().flatten() {
        if !k.to_ascii_uppercase().starts_with("MITRE") {
            continue;
        }
        for id in strings(Some(reqs)) {
            if out.len() < 20 && technique(&id) && seen.insert(id.clone()) {
                out.push((id.clone(), id));
            }
        }
    }
    out
}

pub(super) fn parse(text: &str) -> Result<Parsed, String> {
    let (v, repaired) = match serde_json::from_str::<Value>(text) {
        Ok(v) => (v, false),
        Err(e) => match repair(text) {
            Some(v) => (v, true),
            None => return Err(format!("The OCSF file is not valid JSON: {e}")),
        },
    };
    let items: Vec<Value> = match v {
        Value::Array(a) => a,
        o @ Value::Object(_) => vec![o],
        _ => return Err("The OCSF file holds neither a list of findings nor one finding".into()),
    };
    if items.iter().any(|x| finding_class(x) == Some(SECURITY_FINDING)) && !items.iter().any(|x| finding_class(x) == Some(DETECTION_FINDING)) {
        return Err("This file holds OCSF 1.0 security findings (class 2001), written by older Prowler versions. Export the results again with Prowler 4 or later (-M json-ocsf), which writes detection findings.".into());
    }
    // the product is part of every item's fingerprint, details and tags: read once, bounded
    // (Mission 6: a long name was hashed and copied for each of thousands of items)
    let product = items.iter().map(|x| trunc(&s(&x["metadata"]["product"], "name"), 200)).find(|n| !n.is_empty()).unwrap_or_else(|| "OCSF".into());
    let mut p = Parsed::new(Format::Ocsf, &trunc(&product, 60));
    if repaired {
        p.incomplete = true;
        p.warnings.push("The file ends without its closing bracket, as Prowler leaves it when a scan is interrupted; the findings before the end were read".into());
    }
    let (mut passed, mut manual, mut muted, mut other) = (0usize, 0usize, 0usize, 0usize);
    for x in &items {
        if finding_class(x) != Some(DETECTION_FINDING) {
            other += 1;
            continue;
        }
        let info = &x["finding_info"];
        let res = x.get("resources").and_then(|r| r.get(0)).unwrap_or(&Value::Null);
        let check = Some(s(&x["metadata"], "event_code")).filter(|c| !c.is_empty()).unwrap_or_else(|| s(&info["analytic"], "uid"));
        let resource = Some(s(res, "uid")).filter(|u| !u.is_empty()).unwrap_or_else(|| s(res, "name"));
        let account = s(&x["cloud"]["account"], "uid");
        let namespace = s(res, "namespace");
        let region = [s(res, "region"), namespace.clone(), s(&x["cloud"], "region")].into_iter().find(|r| !r.is_empty()).unwrap_or_default();
        let fp = fingerprint(&["ocsf", &product, &check, &account, &region, &resource]);
        let code = s(x, "status_code").to_ascii_uppercase();
        let status_id = x.get("status_id").and_then(Value::as_u64);
        if code == "PASS" || status_id == Some(4) {
            passed += 1;
            p.passed.insert(fp);
            continue;
        }
        if code == "MANUAL" {
            manual += 1;
            continue;
        }
        if status_id == Some(3) {
            muted += 1;
            continue;
        }
        let container = !namespace.is_empty() || strings(x["metadata"].get("profiles")).iter().any(|pr| pr == "container");
        let provider = Some(s(&x["cloud"], "provider")).filter(|pr| !pr.is_empty()).unwrap_or_else(|| if container { "kubernetes".into() } else { String::new() });
        let service = s(&res["group"], "name");
        let detail = Some(s(x, "status_detail")).filter(|d| !d.is_empty()).unwrap_or_else(|| s(x, "message"));
        let title = [s(info, "title"), check.clone(), detail.clone()].into_iter().find(|t| !t.is_empty()).unwrap_or_default();
        let risk = s(x, "risk_details");
        let description = [detail.clone(), s(info, "desc"), if risk.is_empty() { String::new() } else { format!("Risk: {risk}") }].into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n\n");
        // references: URLs; anything else in them is a command or a setting to change
        let mut refs: Vec<String> = Vec::new();
        let mut commands: Vec<String> = Vec::new();
        let more = [s(&x["unmapped"], "related_url")].into_iter().chain(strings(x["unmapped"].get("additional_urls")));
        for r in strings(x["remediation"].get("references")).into_iter().chain(more) {
            if r.starts_with("https://") || r.starts_with("http://") {
                if refs.len() < 50 && !refs.contains(&r) {
                    refs.push(r);
                }
            } else if !r.is_empty() && commands.len() < 10 {
                commands.push(r);
            }
        }
        let fix = s(&x["remediation"], "desc");
        let remediation = if commands.is_empty() { fix } else { format!("{fix}\n\nCommands and settings:\n{}", commands.iter().map(|c| format!("- {}", trunc(c, 1_000))).collect::<Vec<_>>().join("\n")) };
        let techniques = attacks(x);
        let version = s(&x["metadata"]["product"], "version");
        let account_name = s(&x["cloud"]["account"], "name");
        let mut technical = vec![format!("Check: {check} ({product}{})", if version.is_empty() || version.starts_with('<') { String::new() } else { format!(" {version}") })];
        let place = [
            if provider.is_empty() { String::new() } else { format!("Provider: {provider}") },
            if account.is_empty() { String::new() } else if account_name.is_empty() { format!("Account: {account}") } else { format!("Account: {account} ({account_name})") },
            if namespace.is_empty() { if region.is_empty() { String::new() } else { format!("Region: {region}") } } else { format!("Namespace: {namespace}") },
        ];
        if place.iter().any(|x| !x.is_empty()) {
            technical.push(place.into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · "));
        }
        let kind = s(res, "type");
        technical.push(format!("Resource: {}{}{}", if kind.is_empty() { String::new() } else { format!("{kind} ") }, if resource.is_empty() { "(not named)".to_string() } else { resource.clone() }, if service.is_empty() { String::new() } else { format!(" · service {service}") }));
        let comp = compliance(&x["unmapped"]["compliance"]);
        if !comp.is_empty() {
            technical.push(format!("Compliance: {comp}"));
        }
        if !techniques.is_empty() {
            technical.push(format!("MITRE ATT&CK: {}", techniques.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join(" · ")));
        }
        let target = match (resource.is_empty(), account.is_empty()) {
            (false, _) => resource.clone(),
            (true, false) => format!("{provider} account {account}").trim().to_string(),
            (true, true) => check.clone(),
        };
        let extra = [provider.clone(), service].into_iter().chain(techniques.iter().map(|(id, _)| id.clone()));
        p.push_finding(ImportedFinding {
            rule_id: check.clone(),
            title: trunc(&title, 200),
            severity: severity(x),
            // a configuration check reads the setting itself
            confidence: "high",
            target: trunc(&target, 500),
            host: None,
            asset: None,
            description: trunc(&description, 50_000),
            remediation: trunc(&remediation, 50_000),
            technical: trunc(&technical.join("\n"), 50_000),
            references: refs,
            cve: String::new(),
            category: if container { "Container configuration".into() } else { "Cloud configuration".into() },
            tags: tool_tags(&product, extra),
            cvss: String::new(),
            fingerprint: fp,
            network: false,
        });
    }
    if passed > 0 {
        p.warnings.push(match passed {
            1 => "1 check passed; it is not imported, and resolves the finding of an earlier import for the same resource when you choose to".into(),
            n => format!("{n} checks passed; they are not imported, and resolve the findings of earlier imports for the same resources when you choose to"),
        });
    }
    if manual > 0 {
        p.warnings.push(match manual {
            1 => "1 check needs a manual review (MANUAL) and was skipped".into(),
            n => format!("{n} checks need a manual review (MANUAL) and were skipped"),
        });
    }
    if muted > 0 {
        p.warnings.push(match muted {
            1 => "1 muted finding (suppressed in the scanner) was skipped".into(),
            n => format!("{n} muted findings (suppressed in the scanner) were skipped"),
        });
    }
    if other > 0 {
        p.warnings.push(format!("{other} entries of the file are not OCSF detection findings and were skipped"));
    }
    Ok(p)
}

#[cfg(test)]
#[path = "scan_import_ocsf_tests.rs"]
mod tests;
