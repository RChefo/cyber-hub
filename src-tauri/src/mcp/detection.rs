//! MCP tools for detection engineering and ASVS assessments (docs/MCP.md): the rule library, a
//! project's detection hits with their explanations, ASVS assessments, and two writes that wait
//! for the user's approval (an ASVS status, a hit's review). Plain functions over the database,
//! like `assessment.rs`.
//!
//! A client never marks an ASVS requirement compliant: that is the analyst's call, made in
//! Cyber Hub. Values from logs and files (event fields, matched bytes) pass through the
//! credential redaction before they leave the app.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{validation, AppError, AppResult};
use crate::redact::redact_text;
use crate::workspace::{asvs, detections};

/// Rule content returned to a client, at most.
const MAX_CONTENT: usize = 64 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesQuery {
    pub kind: Option<String>,
    pub text: Option<String>,
    pub technique: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// The detection library: Sigma rules and YARA rule files, with whether they run and their tests.
pub fn rules(c: &Connection, q: &RulesQuery) -> AppResult<Value> {
    if q.kind.as_deref().is_some_and(|k| k != "sigma" && k != "yara") {
        return Err(validation("kind must be sigma or yara"));
    }
    let page = detections::list(c, &detections::ListFilter { kind: q.kind.clone(), text: q.text.clone(), technique: q.technique.clone(), enabled: q.enabled, limit: q.limit, offset: q.offset, ..Default::default() })?;
    Ok(json!({
        "total": page.total,
        "returned": page.items.len(),
        "note": "A rule describes what could be detected. Coverage is not evidence that a technique was used, and a match is a lead until the analyst confirms it.",
        "rules": page.items.iter().map(|r| json!({
            "id": r.id,
            "kind": r.kind,
            "title": r.title,
            "level": r.level,
            "status": r.status,
            "logsource": r.logsource,
            "techniques": r.techniques,
            "enabled": r.enabled,
            "runnable": r.runnable,
            "version": r.version,
            "problems": r.errors,
            "warnings": r.warnings,
            "testsPassing": r.tests_passed,
            "testsFailing": r.tests_failed,
            "falsePositives": r.false_positives,
            "openHits": r.hits,
        })).collect::<Vec<_>>(),
    }))
}

/// One rule: its content, the problems found when it was read, its versions, tests and feedback.
pub fn rule(c: &Connection, id: i64) -> AppResult<Value> {
    let d = detections::get(c, id)?;
    let truncated = d.content.len() > MAX_CONTENT;
    let mut content = d.content.clone();
    if truncated {
        let mut cut = MAX_CONTENT;
        while !content.is_char_boundary(cut) {
            cut -= 1;
        }
        content.truncate(cut);
    }
    Ok(json!({
        "id": d.summary.id,
        "kind": d.summary.kind,
        "title": d.summary.title,
        "level": d.summary.level,
        "techniques": d.summary.techniques,
        "enabled": d.summary.enabled,
        "runnable": d.summary.runnable,
        "version": d.summary.version,
        "content": content,
        "contentTruncated": truncated,
        "problems": d.issues,
        "metadata": d.meta,
        "versions": d.versions.iter().map(|v| json!({ "version": v.version, "note": v.note, "createdAt": v.created_at })).collect::<Vec<_>>(),
        "tests": d.samples.iter().map(|s| json!({
            "sample": s.file_name,
            "kind": s.kind,
            "expectation": s.expect,
            "last": s.last.as_ref().map(|t| json!({ "version": t.version, "matched": t.matched, "passed": t.passed, "ranAt": t.ran_at })),
        })).collect::<Vec<_>>(),
        "feedback": d.feedback.iter().map(|f| json!({ "verdict": f.verdict, "note": f.note, "project": f.project, "createdAt": f.created_at })).collect::<Vec<_>>(),
    }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HitsQuery {
    pub project_id: i64,
    pub status: Option<String>,
    pub rule_id: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// A project's risk register, redacted (justifications are free text the analyst wrote).
pub fn risk_view(c: &Connection, project_id: i64) -> AppResult<Value> {
    c.query_row("SELECT 1 FROM projects WHERE id = ?1", params![project_id], |_| Ok(())).optional()?.ok_or_else(|| AppError::NotFound(format!("project {project_id}")))?;
    let mut v = json!({
        "acceptances": crate::workspace::risk::list(c, project_id)?,
        "summary": crate::workspace::risk::summary(c, project_id)?,
        "acceptedWithoutRecord": crate::workspace::risk::uncovered_findings(c, project_id)?.into_iter().map(|(id, title)| json!({ "findingId": id, "title": title })).collect::<Vec<_>>(),
        "note": "An accepted risk is not remediated: it stays a risk, accepted by its owner until the expiry. Only the analyst records, renews or revokes an acceptance, in Cyber Hub.",
    });
    redact_value(&mut v);
    Ok(v)
}

/// Redacts every string of a JSON value (event fields, matched text) in place.
fn redact_value(v: &mut Value) {
    match v {
        Value::String(s) => *s = redact_text(s),
        Value::Array(a) => a.iter_mut().for_each(redact_value),
        Value::Object(o) => o.values_mut().for_each(redact_value),
        _ => {}
    }
}

/// A project's detection hits with why each matched; values from the logs and files are redacted.
pub fn hits(c: &Connection, q: &HitsQuery) -> AppResult<Value> {
    require_project(c, q.project_id)?;
    if q.status.as_deref().is_some_and(|s| !["new", "promoted", "false_positive", "dismissed"].contains(&s)) {
        return Err(validation("status must be new, promoted, false_positive or dismissed"));
    }
    let page = detections::hits_list(c, q.project_id, &detections::HitFilter { status: q.status.clone(), rule_id: q.rule_id, limit: q.limit, offset: q.offset })?;
    let hits: Vec<Value> = page
        .items
        .iter()
        .map(|h| {
            let mut event = h.event.clone();
            let mut explanation = h.explanation.clone();
            redact_value(&mut event);
            redact_value(&mut explanation);
            json!({
                "id": h.id,
                "kind": if h.explanation.get("kind").and_then(Value::as_str) == Some("yara") { "yara" } else { "sigma" },
                "ruleId": h.rule_id,
                "rule": h.rule_title,
                "ruleVersion": h.rule_version,
                "level": h.rule_level,
                "techniques": h.techniques,
                "evidenceId": h.evidence_id,
                "evidence": h.evidence,
                "position": h.position,
                "time": h.event_time,
                "status": h.status,
                "findingId": h.finding_id,
                "event": event,
                "explanation": explanation,
            })
        })
        .collect();
    Ok(json!({
        "projectId": q.project_id,
        "total": page.total,
        "counts": page.counts,
        "returned": hits.len(),
        "note": "A hit is a rule match, a lead: not a confirmed finding. Values from logs and files are redacted.",
        "hits": hits,
    }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsvsQuery {
    pub project_id: i64,
    pub assessment_id: Option<i64>,
    pub status: Option<String>,
    pub chapter: Option<String>,
    #[serde(default)]
    pub include_above_level: bool,
}

fn require_project(c: &Connection, id: i64) -> AppResult<String> {
    c.query_row("SELECT name FROM projects WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("project {id}")))
}

fn assessment_of(c: &Connection, project_id: i64, id: i64) -> AppResult<()> {
    let pid: Option<i64> = c.query_row("SELECT project_id FROM asvs_assessments WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
    match pid {
        Some(p) if p == project_id => Ok(()),
        _ => Err(AppError::NotFound(format!("ASVS assessment {id} of project {project_id}"))),
    }
}

/// A project's ASVS assessments, or one of them with its requirements (filtered), their notes,
/// links and the analyst's mappings, and recent changes.
pub fn asvs_view(c: &Connection, q: &AsvsQuery) -> AppResult<Value> {
    require_project(c, q.project_id)?;
    let cat = asvs::catalog();
    let attribution = format!("OWASP Application Security Verification Standard {} ({}), © OWASP Foundation, {}", cat.version, cat.source, cat.license);
    let Some(id) = q.assessment_id else {
        let list = asvs::list(c, q.project_id)?;
        return Ok(json!({ "projectId": q.project_id, "assessments": list, "attribution": attribution }));
    };
    assessment_of(c, q.project_id, id)?;
    if q.status.as_deref().is_some_and(|s| !asvs::STATUSES.contains(&s)) {
        return Err(validation("status must be not_assessed, compliant, non_compliant, not_applicable or needs_review"));
    }
    let v = asvs::get(c, id)?;
    let items: Vec<&asvs::Item> = v
        .items
        .iter()
        .filter(|i| (q.include_above_level || i.in_level) && q.status.as_deref().is_none_or(|s| i.status == s) && q.chapter.as_deref().is_none_or(|ch| i.requirement.chapter.eq_ignore_ascii_case(ch)))
        .collect();
    Ok(json!({
        "projectId": q.project_id,
        "assessment": v.summary,
        "returned": items.len(),
        "note": "A requirement is compliant only when the analyst marked it so in Cyber Hub; a requirement without a status is not assessed, whatever the findings. Mappings are the analyst's own: ASVS 5.0.0 publishes none.",
        "requirements": items,
        "recentChanges": v.history.iter().take(20).collect::<Vec<_>>(),
        "attribution": attribution,
    }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsvsSet {
    pub project_id: i64,
    pub assessment_id: i64,
    pub requirement: String,
    pub status: String,
    pub note: Option<String>,
}

/// What an approval shows for an ASVS status change, after the same checks the change makes.
/// A client may not mark a requirement compliant.
pub fn describe_asvs_set(c: &Connection, a: &AsvsSet) -> AppResult<(String, Vec<(String, String)>)> {
    let project = require_project(c, a.project_id)?;
    crate::commands::projects::refuse_archived_for_clients(c, a.project_id)?;
    assessment_of(c, a.project_id, a.assessment_id)?;
    if a.status == "compliant" {
        return Err(validation("Only the analyst marks a requirement compliant, in Cyber Hub; a client can set not_assessed, non_compliant, needs_review or not_applicable"));
    }
    if !asvs::STATUSES.contains(&a.status.as_str()) {
        return Err(validation("status must be not_assessed, non_compliant, needs_review or not_applicable"));
    }
    let r = asvs::requirement(&a.requirement).ok_or_else(|| validation(format!("{} is not an ASVS {} requirement", a.requirement.chars().take(20).collect::<String>(), asvs::catalog().version)))?;
    let current = c
        .query_row("SELECT status, note FROM asvs_results WHERE assessment_id = ?1 AND requirement = ?2", params![a.assessment_id, r.id], |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?)))
        .optional()?
        .unwrap_or_else(|| ("not_assessed".into(), String::new()));
    let mut details = vec![
        ("Requirement".to_string(), format!("{} (level {}): {}", r.id, r.level, r.text.chars().take(400).collect::<String>())),
        ("Status".to_string(), format!("{} → {}", current.0.replace('_', " "), a.status.replace('_', " "))),
    ];
    if let Some(n) = &a.note {
        let n = crate::util::clean("Note", n, 2000, false)?;
        details.push(("Note".to_string(), if n.is_empty() { "(empty: clears the note)".into() } else { format!("{}{}", n.chars().take(600).collect::<String>(), if current.1.is_empty() || current.1 == n { "" } else { " (replaces the existing note)" }) }));
    }
    Ok((project, details))
}

pub fn set_asvs(c: &Connection, a: &AsvsSet) -> AppResult<Value> {
    describe_asvs_set(c, a)?;
    let note = match &a.note {
        Some(n) => Some(crate::util::clean("Note", n, 2000, false)?),
        None => None,
    };
    asvs::set_status(c, a.assessment_id, &a.requirement, &a.status, note.as_deref(), "mcp")?;
    let v = asvs::get(c, a.assessment_id)?;
    let item = v.items.into_iter().find(|i| i.requirement.id.eq_ignore_ascii_case(&a.requirement));
    Ok(json!({ "assessmentId": a.assessment_id, "requirement": item, "counts": v.summary.counts }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HitReview {
    pub project_id: i64,
    pub hit_id: i64,
    /// false_positive, dismiss or promote
    pub action: String,
    pub note: Option<String>,
}

fn hit_project(c: &Connection, project_id: i64, hit_id: i64) -> AppResult<(String, String, String, String)> {
    let row: Option<(i64, String, String, String, String)> = c
        .query_row("SELECT project_id, rule_title, position, status, COALESCE((SELECT title FROM evidence WHERE id = h.evidence_id), '') FROM detection_hits h WHERE id = ?1", params![hit_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .optional()?;
    match row {
        Some((p, rule, pos, status, ev)) if p == project_id => Ok((rule, pos, status, ev)),
        _ => Err(AppError::NotFound(format!("detection hit {hit_id} of project {project_id}"))),
    }
}

/// What an approval shows for a hit's review.
pub fn describe_hit_review(c: &Connection, a: &HitReview) -> AppResult<(String, Vec<(String, String)>)> {
    let project = require_project(c, a.project_id)?;
    crate::commands::projects::refuse_archived_for_clients(c, a.project_id)?;
    let (rule, position, status, evidence) = hit_project(c, a.project_id, a.hit_id)?;
    let what = match a.action.as_str() {
        "false_positive" => "Mark it a false positive (recorded as feedback on the rule)",
        "dismiss" => "Dismiss it",
        "promote" => "Promote it to a finding under review, with low confidence, linked to its evidence",
        _ => return Err(validation("action must be false_positive, dismiss or promote")),
    };
    if status == "promoted" {
        return Err(validation("The hit was promoted already; change it through its finding"));
    }
    let mut details = vec![("Hit".to_string(), format!("#{} {rule} at {position}{}", a.hit_id, if evidence.is_empty() { String::new() } else { format!(" in {evidence}") })), ("Action".to_string(), what.to_string())];
    if let Some(n) = &a.note {
        details.push(("Note".to_string(), crate::util::clean("Note", n, 500, false)?));
    }
    Ok((project, details))
}

pub fn review_hit(c: &Connection, a: &HitReview) -> AppResult<Value> {
    describe_hit_review(c, a)?;
    let note = match &a.note {
        Some(n) => crate::util::clean("Note", n, 500, false)?,
        None => String::new(),
    };
    match a.action.as_str() {
        "promote" => {
            let fid = detections::hit_promote(c, a.hit_id)?;
            Ok(json!({ "hitId": a.hit_id, "status": "promoted", "findingId": fid, "findingStatus": "under_review" }))
        }
        "false_positive" => {
            detections::hit_set(c, a.hit_id, "false_positive", &note)?;
            Ok(json!({ "hitId": a.hit_id, "status": "false_positive" }))
        }
        _ => {
            detections::hit_set(c, a.hit_id, "dismissed", &note)?;
            Ok(json!({ "hitId": a.hit_id, "status": "dismissed" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn setup(c: &Connection) -> (i64, i64, i64) {
        c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Acme', 'active', 't', 't'), (2, 'Other', 'active', 't', 't'), (3, 'Old', 'archived', 't', 't')", []).unwrap();
        c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (5, 1, 'file', 'Security.evtx', 'user', 'ab', 10, 'Security.evtx', 't')", []).unwrap();
        let text = "title: Logon with a password in the command line\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    s:\n        CommandLine|contains: ' /p:'\n    condition: s\nlevel: high\n";
        let checked = crate::detection::sigma::read(text).unwrap().remove(0);
        let r = detections::upsert_sigma(c, text, &checked, "t.yml", "").unwrap();
        let s = detections::stored(c, r.id).unwrap();
        let m = detections::Match {
            position: "record 7".into(),
            time: "t".into(),
            label: "process".into(),
            fields: vec![("CommandLine".into(), "net use \\\\fs01 /user:admin /p:password=Hunter2!".into())],
            explanation: json!({ "selections": [{ "name": "s", "matched": true, "hits": [{ "field": "CommandLine", "condition": "contains", "value": "net use \\\\fs01 /user:admin /p:password=Hunter2!" }] }] }),
        };
        detections::hits_store(c, 1, &s, 5, &[m]).unwrap();
        let hit: i64 = c.query_row("SELECT id FROM detection_hits", [], |r| r.get(0)).unwrap();
        let aid = asvs::create(c, 1, "Portal", 1, "").unwrap();
        (r.id, hit, aid)
    }

    #[test]
    fn rules_and_hits_are_read_with_redacted_values() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let (rule_id, hit, _) = setup(c);
            let r = rules(c, &RulesQuery::default())?;
            assert_eq!((r["total"].as_i64(), r["rules"][0]["kind"].as_str()), (Some(1), Some("sigma")));
            assert!(rules(c, &RulesQuery { kind: Some("snort".into()), ..Default::default() }).is_err());
            let d = rule(c, rule_id)?;
            assert!(d["content"].as_str().unwrap().contains("CommandLine|contains"));
            let h = hits(c, &HitsQuery { project_id: 1, status: None, rule_id: None, limit: None, offset: None })?;
            assert_eq!(h["hits"][0]["id"].as_i64(), Some(hit));
            let text = h["hits"][0].to_string();
            assert!(!text.contains("Hunter2!"), "the password is redacted: {text}");
            assert!(hits(c, &HitsQuery { project_id: 99, status: None, rule_id: None, limit: None, offset: None }).is_err());
            assert_eq!(hits(c, &HitsQuery { project_id: 2, status: None, rule_id: None, limit: None, offset: None })?["total"], 0, "other projects' hits stay apart");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn asvs_is_read_and_changed_only_within_the_rules() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let (_, _, aid) = setup(c);
            let list = asvs_view(c, &AsvsQuery { project_id: 1, assessment_id: None, status: None, chapter: None, include_above_level: false })?;
            assert_eq!(list["assessments"].as_array().map(Vec::len), Some(1));
            assert!(asvs_view(c, &AsvsQuery { project_id: 2, assessment_id: Some(aid), status: None, chapter: None, include_above_level: false }).is_err(), "another project's assessment");
            let set = |status: &str| AsvsSet { project_id: 1, assessment_id: aid, requirement: "V1.2.1".into(), status: status.into(), note: Some("Encoder missing on the error page".into()) };
            let e = describe_asvs_set(c, &set("compliant")).unwrap_err().to_string();
            assert!(e.contains("Only the analyst marks a requirement compliant"), "{e}");
            assert!(set_asvs(c, &set("compliant")).is_err(), "also when carried out");
            assert!(describe_asvs_set(c, &AsvsSet { requirement: "V99.1.1".into(), ..set("needs_review") }).is_err());
            let (_, details) = describe_asvs_set(c, &set("non_compliant"))?;
            assert!(details.iter().any(|(k, v)| k == "Status" && v == "not assessed → non compliant"), "{details:?}");
            let v = set_asvs(c, &set("non_compliant"))?;
            assert_eq!((v["requirement"]["status"].as_str(), v["counts"]["nonCompliant"].as_i64()), (Some("non_compliant"), Some(1)));
            let actor: String = c.query_row("SELECT actor FROM asvs_history WHERE assessment_id = ?1", params![aid], |r| r.get(0))?;
            assert_eq!(actor, "mcp");
            let only = asvs_view(c, &AsvsQuery { project_id: 1, assessment_id: Some(aid), status: Some("non_compliant".into()), chapter: None, include_above_level: false })?;
            assert_eq!(only["returned"], 1);
            // archived projects are refused
            c.execute("UPDATE projects SET status = 'archived' WHERE id = 1", [])?;
            assert!(describe_asvs_set(c, &set("needs_review")).unwrap_err().to_string().contains("archived"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn hits_are_reviewed_within_their_project() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let (_, hit, _) = setup(c);
            let review = |project_id: i64, action: &str| HitReview { project_id, hit_id: hit, action: action.into(), note: Some("Admin script".into()) };
            assert!(describe_hit_review(c, &review(2, "dismiss")).is_err(), "a hit of another project");
            assert!(describe_hit_review(c, &review(1, "delete")).is_err());
            let (_, details) = describe_hit_review(c, &review(1, "promote"))?;
            assert!(details.iter().any(|(_, v)| v.contains("under review")), "{details:?}");
            let v = review_hit(c, &review(1, "promote"))?;
            let status: String = c.query_row("SELECT status FROM findings WHERE id = ?1", params![v["findingId"].as_i64().unwrap()], |r| r.get(0))?;
            assert_eq!(status, "under_review");
            assert!(describe_hit_review(c, &review(1, "dismiss")).unwrap_err().to_string().contains("promoted already"));
            Ok(())
        })
        .unwrap();
    }
}
