//! ASVS compliance views over an assessment (Mission 5): the gaps chapter by chapter with their
//! exceptions and the remediation state of the linked findings, compliant requirements that no
//! evidence supports, and the comparison of two assessments of a project.
//!
//! Nothing here sets a status: a gap is closed only by the analyst marking the requirement
//! compliant (or not applicable), an exception only covers it, and a comparison only reports.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use super::asvs::{get, Item, LinkedFinding, Summary, CATALOG};
use crate::error::{validation, AppError, AppResult};

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChapterGap {
    pub id: String,
    pub name: String,
    pub total: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    /// non-compliant requirements an active exception covers
    pub excepted: usize,
    pub needs_review: usize,
    pub not_assessed: usize,
    pub not_applicable: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionRef {
    pub id: i64,
    pub title: String,
    pub owner: String,
    pub approver: String,
    pub expires_at: String,
    /// active, review_due or expired
    pub standing: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub requirement: String,
    pub text: String,
    pub level: u8,
    pub chapter: String,
    pub exception: Option<ExceptionRef>,
    pub findings: Vec<LinkedFinding>,
    /// no finding recorded / N open / in remediation / fixed: reassess
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Gaps {
    pub summary: Summary,
    pub chapters: Vec<ChapterGap>,
    /// non-compliant requirements of the level, without exception first
    pub gaps: Vec<Gap>,
    /// compliant requirements with no evidence linked (the analyst's word only)
    pub without_evidence: Vec<String>,
    pub exceptions_expired: usize,
}

/// The exception (risk acceptance) that covers a requirement, active or expired, not revoked.
fn exception(c: &Connection, assessment: i64, requirement: &str) -> AppResult<Option<ExceptionRef>> {
    let today = chrono::Utc::now().date_naive().to_string();
    Ok(c
        .query_row(
            "SELECT a.id, a.title, a.owner, a.approver, a.expires_at, a.review_at, a.status FROM risk_acceptance_items i JOIN risk_acceptances a ON a.id = i.acceptance_id
             WHERE i.kind = 'asvs' AND i.ref_id = ?1 AND i.requirement = ?2 AND i.removed_at IS NULL AND a.status = 'active' ORDER BY a.expires_at DESC LIMIT 1",
            params![assessment, requirement],
            |r| {
                let expires: String = r.get(4)?;
                let review: Option<String> = r.get(5)?;
                let status: String = r.get(6)?;
                Ok(ExceptionRef { id: r.get(0)?, title: r.get(1)?, owner: r.get(2)?, approver: r.get(3)?, standing: super::risk::standing(&status, &expires, review.as_deref(), &today).into(), expires_at: expires })
            },
        )
        .optional()?)
}

fn remediation(findings: &[LinkedFinding]) -> String {
    if findings.is_empty() {
        return "no finding recorded".into();
    }
    let open = findings.iter().filter(|f| matches!(f.status.as_str(), "new" | "under_review" | "confirmed" | "reopened")).count();
    let fixing = findings.iter().filter(|f| f.status == "in_remediation").count();
    let done = findings.iter().filter(|f| matches!(f.status.as_str(), "resolved" | "false_positive")).count();
    if done == findings.len() {
        return "the linked findings are resolved: reassess the requirement".into();
    }
    let mut parts = Vec::new();
    if open > 0 {
        parts.push(format!("{open} open"));
    }
    if fixing > 0 {
        parts.push(format!("{fixing} in remediation"));
    }
    let accepted = findings.iter().filter(|f| f.status == "accepted_risk").count();
    if accepted > 0 {
        parts.push(format!("{accepted} accepted risk"));
    }
    if done > 0 {
        parts.push(format!("{done} resolved"));
    }
    parts.join(", ")
}

pub fn gaps(c: &Connection, id: i64) -> AppResult<Gaps> {
    let v = get(c, id)?;
    let in_level: Vec<&Item> = v.items.iter().filter(|i| i.in_level).collect();
    let mut chapters: BTreeMap<String, ChapterGap> = BTreeMap::new();
    let mut gaps = Vec::new();
    let mut without_evidence = Vec::new();
    let mut exceptions_expired = 0;
    for i in &in_level {
        let r = &i.requirement;
        let ch = chapters.entry(r.chapter.clone()).or_insert_with(|| ChapterGap {
            id: r.chapter.clone(),
            name: CATALOG.chapters.iter().find(|c| c.id == r.chapter).map(|c| c.name.clone()).unwrap_or_default(),
            ..Default::default()
        });
        ch.total += 1;
        match i.status.as_str() {
            "compliant" => {
                ch.compliant += 1;
                if i.evidence.is_empty() {
                    without_evidence.push(r.id.clone());
                }
            }
            "non_compliant" => {
                ch.non_compliant += 1;
                let ex = exception(c, id, &r.id)?;
                if ex.is_some() {
                    ch.excepted += 1;
                }
                if ex.as_ref().is_some_and(|e| e.standing == "expired") {
                    exceptions_expired += 1;
                }
                gaps.push(Gap { requirement: r.id.clone(), text: r.text.clone(), level: r.level, chapter: r.chapter.clone(), remediation: remediation(&i.findings), findings: i.findings.clone(), exception: ex });
            }
            "needs_review" => ch.needs_review += 1,
            "not_applicable" => ch.not_applicable += 1,
            _ => ch.not_assessed += 1,
        }
    }
    // gaps without an exception (or with an expired one) first, then by level and id
    gaps.sort_by_key(|g| (g.exception.as_ref().is_some_and(|e| e.standing != "expired"), g.level, g.requirement.clone()));
    let mut chapters: Vec<ChapterGap> = chapters.into_values().collect();
    chapters.sort_by_key(|c| CATALOG.chapters.iter().position(|x| x.id == c.id).unwrap_or(usize::MAX));
    Ok(Gaps { summary: v.summary, chapters, gaps, without_evidence, exceptions_expired })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub requirement: String,
    pub text: String,
    pub from: String,
    pub to: String,
    /// improved, regressed or changed (to or from not assessed)
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub from: Summary,
    pub to: Summary,
    pub improved: usize,
    pub regressed: usize,
    pub changed: usize,
    pub unchanged: usize,
    pub changes: Vec<Change>,
}

/// A status's standing for comparison: met (compliant or not applicable) above needs review
/// above non-compliant; not assessed has none.
fn score(s: &str) -> Option<u8> {
    match s {
        "compliant" | "not_applicable" => Some(2),
        "needs_review" => Some(1),
        "non_compliant" => Some(0),
        _ => None,
    }
}

/// How requirements moved between two assessments of the same project (for example before and
/// after remediation): every requirement within either assessment's level.
pub fn compare(c: &Connection, from_id: i64, to_id: i64) -> AppResult<Comparison> {
    if from_id == to_id {
        return Err(validation("Choose two different assessments"));
    }
    let a = get(c, from_id)?;
    let b = get(c, to_id)?;
    if a.summary.project_id != b.summary.project_id {
        return Err(AppError::Validation("Both assessments must belong to the same project".into()));
    }
    let level = a.summary.level.max(b.summary.level);
    let status_of = |items: &[Item], id: &str| items.iter().find(|i| i.requirement.id == id).map(|i| i.status.clone()).unwrap_or_else(|| "not_assessed".into());
    let mut out = Comparison { from: a.summary.clone(), to: b.summary.clone(), improved: 0, regressed: 0, changed: 0, unchanged: 0, changes: Vec::new() };
    for r in CATALOG.requirements.iter().filter(|r| r.level <= level) {
        let (from, to) = (status_of(&a.items, &r.id), status_of(&b.items, &r.id));
        if from == to {
            out.unchanged += 1;
            continue;
        }
        let direction = match (score(&from), score(&to)) {
            (Some(x), Some(y)) if y > x => "improved",
            (Some(x), Some(y)) if y < x => "regressed",
            _ => "changed",
        };
        match direction {
            "improved" => out.improved += 1,
            "regressed" => out.regressed += 1,
            _ => out.changed += 1,
        }
        out.changes.push(Change { requirement: r.id.clone(), text: r.text.clone(), from, to, direction: direction.into() });
    }
    let rank = |d: &str| match d {
        "regressed" => 0,
        "improved" => 1,
        _ => 2,
    };
    out.changes.sort_by_key(|x| rank(&x.direction));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::workspace::asvs::{create, set_status};

    fn day(offset: i64) -> String {
        (chrono::Utc::now().date_naive() + chrono::Duration::days(offset)).to_string()
    }

    #[test]
    fn gaps_exceptions_evidence_and_comparison() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Shop', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (5, 1, 'XSS', 'high', 'in_remediation', 't', 't')", [])?;
            c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (9, 1, 'text', 'Scan', 'user', '', 0, '', 't')", [])?;
            let l1: Vec<String> = CATALOG.requirements.iter().filter(|r| r.level == 1).take(4).map(|r| r.id.clone()).collect();
            let before = create(c, 1, "Before", 1, "")?;
            set_status(c, before, &l1[0], "non_compliant", None, "user")?;
            set_status(c, before, &l1[1], "non_compliant", None, "user")?;
            set_status(c, before, &l1[2], "compliant", None, "user")?;
            set_status(c, before, &l1[3], "compliant", None, "user")?;
            crate::workspace::asvs::link(c, before, &l1[0], "finding", 5, true)?;
            crate::workspace::asvs::link(c, before, &l1[3], "evidence", 9, true)?;
            let d = crate::workspace::risk::Draft { title: "Legacy login".into(), justification: "Replaced in Q3".into(), owner: "Product".into(), approver: "CISO".into(), approved_at: day(0), expires_at: day(60), ..Default::default() };
            crate::workspace::risk::create(c, 1, &d, &[crate::workspace::risk::ItemRef { kind: "asvs".into(), ref_id: before, requirement: l1[1].clone() }], "user")?;
            let g = gaps(c, before)?;
            assert_eq!(g.gaps.len(), 2);
            // the gap without an exception first, with its finding's remediation state
            assert_eq!((g.gaps[0].requirement.as_str(), g.gaps[0].exception.is_none(), g.gaps[0].remediation.as_str()), (l1[0].as_str(), true, "1 in remediation"));
            assert_eq!((g.gaps[1].exception.as_ref().map(|e| e.standing.as_str()), g.gaps[1].remediation.as_str()), (Some("active"), "no finding recorded"));
            let ch = g.chapters.iter().find(|x| x.id == CATALOG.requirements.iter().find(|r| r.id == l1[0]).unwrap().chapter).unwrap();
            assert!(ch.non_compliant >= 1 && ch.total >= ch.non_compliant);
            assert_eq!(g.chapters.iter().map(|x| x.excepted).sum::<usize>(), 1);
            assert_eq!(g.without_evidence, vec![l1[2].clone()], "compliant without evidence");
            // a reassessment after the fix
            let after = create(c, 1, "After", 1, "")?;
            set_status(c, after, &l1[0], "compliant", None, "user")?;
            set_status(c, after, &l1[1], "non_compliant", None, "user")?;
            set_status(c, after, &l1[2], "needs_review", None, "user")?;
            let cmp = compare(c, before, after)?;
            assert_eq!((cmp.improved, cmp.regressed, cmp.changed), (1, 1, 1), "{:?}", cmp.changes);
            assert_eq!(cmp.changes[0].direction, "regressed", "regressions first");
            assert!(compare(c, before, before).is_err());
            Ok(())
        })
        .unwrap();
    }
}
