//! Findings as an ATT&CK Navigator layer (layer format 4.5, docs/DATA_MODEL.md#findings-export).
//!
//! The techniques come from the findings themselves: tags that are technique IDs (`T1059.001`,
//! as the log, file, Linux and Prowler triage write them) and IDs on lines of the technical
//! details that name ATT&CK. Each technique is colored by the highest severity of its findings and
//! scored with how many name it; its comment and metadata list them. False positives are left
//! out. The layer names no ATT&CK version, so the Navigator shows it on its current data.

use std::collections::BTreeMap;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};

use crate::commands::projects::Finding;

/// Navigator release the layer was checked with (layer format 4.5 needs 4.9.0 or later).
const NAVIGATOR: &str = "5.3.2";
const SEVERITIES: &[(&str, &str, &str)] = &[("critical", "Critical", "#c62828"), ("high", "High", "#ef6c00"), ("medium", "Medium", "#f9a825"), ("low", "Low", "#64b5f6"), ("info", "Informational", "#b0bec5")];
/// Findings listed in a technique's metadata.
const MAX_LISTED: usize = 25;

static ID: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[Tt]\d{4}(\.\d{3})?$").expect("technique tag"));
static IN_TEXT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bT\d{4}(\.\d{3})?\b").expect("technique"));

/// The ATT&CK technique IDs a finding names, upper-case and without repeats.
pub fn techniques_of(f: &Finding) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |id: &str| {
        let id = id.to_ascii_uppercase();
        if !out.contains(&id) {
            out.push(id);
        }
    };
    for t in f.tags.iter().filter(|t| ID.is_match(t.trim())) {
        push(t.trim());
    }
    for line in f.technical_details.lines().filter(|l| l.contains("ATT&CK")) {
        for m in IN_TEXT.find_iter(line) {
            push(m.as_str());
        }
    }
    out
}

fn rank(severity: &str) -> usize {
    SEVERITIES.iter().position(|(s, _, _)| *s == severity).unwrap_or(SEVERITIES.len() - 1)
}

/// The layer of the given findings, or an error when none of them names a technique.
pub fn layer(project: &str, generated: &str, findings: &[Finding]) -> Result<String, String> {
    let mut by: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    let mut named = 0usize;
    let mut skipped = 0usize;
    // an Enterprise layer: Mobile and ICS techniques are in their own matrices (Mission 6)
    let mut elsewhere = 0usize;
    for f in findings {
        if f.status == "false_positive" {
            skipped += 1;
            continue;
        }
        let (ids, other): (Vec<String>, Vec<String>) = techniques_of(f).into_iter().partition(|id| crate::workspace::attack::in_domain(id, crate::workspace::attack::ENTERPRISE));
        elsewhere += other.len();
        if !ids.is_empty() {
            named += 1;
        }
        for id in ids {
            by.entry(id).or_default().push(f);
        }
    }
    if by.is_empty() {
        return Err("None of these findings names an ATT&CK technique (as a tag such as T1059.001 or in its technical details)".into());
    }
    let mut used: Vec<usize> = Vec::new();
    let mut most = 1usize;
    let techniques: Vec<Value> = by
        .iter()
        .map(|(id, fs)| {
            let top = fs.iter().map(|f| rank(&f.severity)).min().unwrap_or(SEVERITIES.len() - 1);
            if !used.contains(&top) {
                used.push(top);
            }
            most = most.max(fs.len());
            let titles: Vec<&str> = fs.iter().take(5).map(|f| f.title.as_str()).collect();
            let more = if fs.len() > 5 { format!(" and {} more", fs.len() - 5) } else { String::new() };
            let metadata: Vec<Value> = fs.iter().take(MAX_LISTED).map(|f| json!({ "name": format!("Finding #{}", f.id), "value": format!("[{}, {}] {} · {}", f.severity, f.status.replace('_', " "), f.title, f.affected_target) })).collect();
            json!({
                "techniqueID": id,
                "score": fs.len(),
                "color": SEVERITIES[top].2,
                "comment": format!("{} {}: {}{more}", fs.len(), if fs.len() == 1 { "finding" } else { "findings" }, titles.join("; ")),
                "enabled": true,
                "metadata": metadata,
                "showSubtechniques": false,
            })
        })
        .collect();
    used.sort_unstable();
    let legend: Vec<Value> = used.iter().map(|i| json!({ "label": format!("Highest severity: {}", SEVERITIES[*i].1), "color": SEVERITIES[*i].2 })).collect();
    let description = format!(
        "ATT&CK techniques named by {named} {} of {project}, exported by Cyber Hub on {generated}. Color: the highest severity of a technique's findings; score: how many findings name it.{}",
        if named == 1 { "finding" } else { "findings" },
        match skipped {
            0 => String::new(),
            1 => " 1 false positive is left out.".to_string(),
            n => format!(" {n} false positives are left out."),
        }
    ) + &match elsewhere {
        0 => String::new(),
        n => format!(" {n} ATT&CK Mobile or ICS reference{} left out: export {} from the project's matrix in that domain.", if n == 1 { " is" } else { "s are" }, if n == 1 { "it" } else { "them" }),
    };
    let doc = json!({
        "name": format!("{project}: findings"),
        "versions": { "attack": crate::workspace::attack_matrix::attack_major_of(crate::workspace::attack::ENTERPRISE), "layer": "4.5", "navigator": NAVIGATOR },
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "layout": { "layout": "side", "showID": true, "showName": true, "expandedSubtechniques": "annotated" },
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": { "colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": most },
        "legendItems": legend,
        "metadata": [{ "name": "Project", "value": project }, { "name": "Exported", "value": generated }, { "name": "Source", "value": "Cyber Hub" }],
        "showTacticRowBackground": false,
        "selectTechniquesAcrossTactics": true,
        "selectSubtechniquesWithParent": false,
        "selectVisibleTechniques": false,
    });
    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: i64, title: &str, severity: &str, status: &str, tags: &[&str], technical: &str) -> Finding {
        Finding {
            id,
            project_id: 1,
            title: title.into(),
            severity: severity.into(),
            status: status.into(),
            category: String::new(),
            confidence: "medium".into(),
            description: String::new(),
            affected_target: "/etc/crontab".into(),
            cve: String::new(),
            evidence: Vec::new(),
            reproduction: String::new(),
            technical_details: technical.into(),
            remediation: String::new(),
            source: "user".into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            assignee: String::new(),
            due_date: None,
            created_at: String::new(),
            updated_at: String::new(),
            cvss_vector: String::new(),
            cvss_score: None,
        }
    }

    #[test]
    fn techniques_come_from_tags_and_attack_lines() {
        let f = finding(1, "x", "high", "new", &["linux", "T1053.003", "t1530", "T12"], "Check: s3 (Prowler)\nMITRE ATT&CK: T1530 Data from Cloud Storage (Collection) · T1190\nCompliance: CIS T9999 is not read here");
        assert_eq!(techniques_of(&f), vec!["T1053.003", "T1530", "T1190"]);
    }

    #[test]
    fn layers_follow_the_format_and_leave_false_positives_out() {
        let fs = vec![
            finding(7, "Cron job downloads a script and runs it", "high", "new", &["T1053.003"], ""),
            finding(8, "User cron jobs", "info", "resolved", &["T1053.003"], ""),
            finding(9, "Encoded PowerShell", "critical", "new", &["T1059.001", "T1027"], ""),
            finding(10, "Not a real one", "critical", "false_positive", &["T1003.001"], ""),
            finding(11, "No technique", "medium", "new", &[], ""),
        ];
        let v: Value = serde_json::from_str(&layer("Web01", "2026-11-09T19:00:00Z", &fs).unwrap()).unwrap();
        // required by the 4.5 format
        assert_eq!(v["versions"], json!({ "attack": "20", "layer": "4.5", "navigator": "5.3.2" }), "the ATT&CK version is named (Mission 6)");
        assert_eq!(v["domain"], "enterprise-attack");
        assert_eq!(v["name"], "Web01: findings");
        let ids: Vec<&str> = v["techniques"].as_array().unwrap().iter().map(|t| t["techniqueID"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["T1027", "T1053.003", "T1059.001"], "the false positive's technique is left out");
        let cron = &v["techniques"][1];
        assert_eq!((cron["score"].as_u64(), cron["color"].as_str()), (Some(2), Some("#ef6c00")), "two findings, the highest is high");
        assert_eq!(cron["comment"], "2 findings: Cron job downloads a script and runs it; User cron jobs");
        assert_eq!(cron["metadata"][1], json!({ "name": "Finding #8", "value": "[info, resolved] User cron jobs · /etc/crontab" }));
        assert!(v["gradient"]["maxValue"].as_u64().unwrap() > v["gradient"]["minValue"].as_u64().unwrap());
        assert_eq!(v["legendItems"].as_array().unwrap().iter().map(|l| l["label"].as_str().unwrap()).collect::<Vec<_>>(), vec!["Highest severity: Critical", "Highest severity: High"]);
        assert!(v["description"].as_str().unwrap().contains("named by 3 findings of Web01") && v["description"].as_str().unwrap().ends_with("1 false positive is left out."));
        assert!(layer("Web01", "now", &fs[4..]).unwrap_err().contains("names an ATT&CK technique"));
    }
}
