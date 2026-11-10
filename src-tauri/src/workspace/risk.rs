//! Risk acceptance (Mission 5; docs/DATA_MODEL.md#risk-acceptance-schema-27).
//!
//! A risk acceptance records who accepted which risk, why, with which compensating controls,
//! who approved it and until when. It covers findings, vulnerabilities, ASVS requirements (an
//! exception for a requirement the project does not meet) and, since Mission 6, WSTG tests that
//! failed (an exception for a test result; the test stays failed).
//!
//! * A finding or a vulnerability becomes an accepted risk **only** through an active, unexpired
//!   acceptance that covers it. The checks sit where every status change goes through
//!   (`findings::set_status`, the finding editor's `finding_write`, `vulns::set_status`), so the
//!   editor, bulk changes, imports, MCP clients and internal services all meet them. MCP has no
//!   tool to create one: only the analyst records an acceptance, in the app.
//! * Accepting is not remediating: an accepted finding keeps its own status (`accepted_risk`),
//!   apart from open, in remediation, resolved and false positive, and reports list it as such.
//! * Expiry is computed when read. An expired acceptance changes nothing by itself: its items stay
//!   accepted and are flagged everywhere until it is renewed or revoked. A review date before the
//!   expiry flags it for review.
//! * Revoking reopens what it covered (findings `reopened`, vulnerabilities `open`); an item that
//!   leaves (fixed, reopened, deleted, requirement now met) is released with the reason. Every
//!   change is in the acceptance's history.

use chrono::{Duration, NaiveDate};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, now};

/// The longest an acceptance may last from its approval.
pub const MAX_DAYS: i64 = 3 * 366;

pub const NOT_COVERED: &str = "A finding becomes an accepted risk only through a risk acceptance: record who accepts it, why, who approved it and until when (Accept risk…)";
pub const VULN_NOT_COVERED: &str = "A vulnerability becomes an accepted risk only through a risk acceptance: record who accepts it, why, who approved it and until when (Accept risk…)";

fn today() -> String {
    chrono::Utc::now().date_naive().to_string()
}

fn date(field: &str, v: &str) -> AppResult<NaiveDate> {
    NaiveDate::parse_from_str(v.trim(), "%Y-%m-%d").map_err(|_| validation(format!("{field} must be a date (YYYY-MM-DD)")))
}

/// active, review_due (the review date has come), expired (past its expiry) or revoked.
pub fn standing(status: &str, expires_at: &str, review_at: Option<&str>, today: &str) -> &'static str {
    if status == "revoked" {
        "revoked"
    } else if expires_at < today {
        "expired"
    } else if review_at.is_some_and(|r| r <= today) {
        "review_due"
    } else {
        "active"
    }
}

/// What the analyst writes: the record's fields.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub title: String,
    pub justification: String,
    #[serde(default)]
    pub compensating: String,
    pub owner: String,
    pub approver: String,
    pub approved_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub review_at: Option<String>,
}

struct Clean {
    title: String,
    justification: String,
    compensating: String,
    owner: String,
    approver: String,
    approved_at: String,
    expires_at: String,
    review_at: Option<String>,
}

fn check(d: &Draft) -> AppResult<Clean> {
    let today = chrono::Utc::now().date_naive();
    let approved = date("The approval date", &d.approved_at)?;
    let expires = date("The expiry date", &d.expires_at)?;
    if approved > today {
        return Err(validation("The approval date cannot be in the future"));
    }
    if expires <= today {
        return Err(validation("The expiry date must be after today: an acceptance without a future expiry accepts nothing"));
    }
    if expires > approved + Duration::days(MAX_DAYS) {
        return Err(validation("An acceptance lasts at most three years from its approval; renew it when it ends"));
    }
    let review = match d.review_at.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        None => None,
        Some(r) => {
            let r = date("The review date", r)?;
            if r <= today || r > expires {
                return Err(validation("The review date must be after today and no later than the expiry"));
            }
            Some(r.to_string())
        }
    };
    Ok(Clean {
        title: clean("The title", &d.title, 200, true)?,
        justification: clean("The justification", &d.justification, 10_000, true)?,
        compensating: clean("Compensating controls", &d.compensating, 10_000, false)?,
        owner: clean("The risk owner", &d.owner, 200, true)?,
        approver: clean("The approver", &d.approver, 200, true)?,
        approved_at: approved.to_string(),
        expires_at: expires.to_string(),
        review_at: review,
    })
}

/// One thing an acceptance covers.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ItemRef {
    pub kind: String,
    pub ref_id: i64,
    #[serde(default)]
    pub requirement: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub kind: String,
    pub ref_id: i64,
    pub requirement: String,
    /// the finding's title, the vulnerability's CVE and title, or the ASVS requirement
    pub label: String,
    /// its status now (finding, vulnerability or requirement)
    pub status: String,
    pub added_at: String,
    pub removed_at: Option<String>,
    pub removed_reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Acceptance {
    pub id: i64,
    pub project_id: i64,
    pub title: String,
    pub justification: String,
    pub compensating: String,
    pub owner: String,
    pub approver: String,
    pub approved_at: String,
    pub expires_at: String,
    pub review_at: Option<String>,
    pub status: String,
    /// active, review_due, expired or revoked (computed today)
    pub standing: String,
    pub revoked_at: Option<String>,
    pub revoked_reason: String,
    pub created_at: String,
    pub updated_at: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub action: String,
    pub detail: String,
    pub source: String,
    pub at: String,
}

fn record(c: &Connection, id: i64, action: &str, detail: &str, source: &str) -> AppResult<()> {
    c.execute(
        "INSERT INTO risk_acceptance_events (acceptance_id, action, detail, source, at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, action, detail.chars().take(4000).collect::<String>(), source, now()],
    )?;
    Ok(())
}

/// The project, status and label of an item, or why it cannot be covered.
fn describe(c: &Connection, it: &ItemRef) -> AppResult<(i64, String, String)> {
    match it.kind.as_str() {
        "finding" => c
            .query_row("SELECT project_id, status, title FROM findings WHERE id = ?1", params![it.ref_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("finding {}", it.ref_id))),
        "vulnerability" => c
            .query_row("SELECT project_id, status, cve_id || CASE WHEN title = '' THEN '' ELSE ' · ' || title END FROM vulnerabilities WHERE id = ?1", params![it.ref_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("vulnerability {}", it.ref_id))),
        "asvs" => {
            let project: i64 = c.query_row("SELECT project_id FROM asvs_assessments WHERE id = ?1", params![it.ref_id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("ASVS assessment {}", it.ref_id)))?;
            let req = crate::workspace::asvs::requirement(&it.requirement).ok_or_else(|| validation(format!("{} is not an ASVS requirement", it.requirement)))?;
            let status: String = c
                .query_row("SELECT status FROM asvs_results WHERE assessment_id = ?1 AND requirement = ?2", params![it.ref_id, req.id], |r| r.get(0))
                .optional()?
                .unwrap_or_else(|| "not_assessed".into());
            Ok((project, status, format!("ASVS {}", req.id)))
        }
        // the checklist is per project: ref_id is the project, requirement the WSTG test
        "wstg" => {
            let exists: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM projects WHERE id = ?1)", params![it.ref_id], |r| r.get(0))?;
            if !exists {
                return Err(AppError::NotFound(format!("project {}", it.ref_id)));
            }
            let test = wstg_test(&it.requirement)?;
            let status: String = c
                .query_row("SELECT status FROM checklist_items WHERE project_id = ?1 AND test_id = ?2", params![it.ref_id, test], |r| r.get(0))
                .optional()?
                .unwrap_or_else(|| "not_started".into());
            Ok((it.ref_id, status, test))
        }
        other => Err(validation(format!("An acceptance covers findings, vulnerabilities, ASVS requirements or WSTG tests, not '{other}'"))),
    }
}

/// A WSTG test id of the bundled checklist, as the catalog spells it.
fn wstg_test(id: &str) -> AppResult<String> {
    let id = id.trim();
    crate::methodology::catalog()
        .categories
        .iter()
        .flat_map(|c| c.tests.iter())
        .find(|t| t.id.eq_ignore_ascii_case(id))
        .map(|t| t.id.clone())
        .ok_or_else(|| validation(format!("{} is not a test of the bundled WSTG checklist", id.chars().take(40).collect::<String>())))
}

/// The active, unexpired acceptance covering an item, if any: (id, expires_at).
pub fn cover(c: &Connection, kind: &str, ref_id: i64, requirement: &str) -> AppResult<Option<(i64, String, String)>> {
    Ok(c
        .query_row(
            "SELECT a.id, a.expires_at, a.status FROM risk_acceptance_items i JOIN risk_acceptances a ON a.id = i.acceptance_id
             WHERE i.kind = ?1 AND i.ref_id = ?2 AND i.requirement = ?3 AND i.removed_at IS NULL AND a.status = 'active'
             ORDER BY a.expires_at DESC LIMIT 1",
            params![kind, ref_id, requirement],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?)
}

/// Refuses unless an active, unexpired acceptance covers the item.
pub fn require_cover(c: &Connection, kind: &str, ref_id: i64) -> AppResult<()> {
    match cover(c, kind, ref_id, "")? {
        Some((id, expires, _)) if expires < today() => Err(validation(format!("The risk acceptance #{id} that covers it expired on {expires}: renew it first"))),
        Some(_) => Ok(()),
        None => Err(validation(if kind == "vulnerability" { VULN_NOT_COVERED } else { NOT_COVERED })),
    }
}

/// The item leaves every acceptance that still covers it, with the reason in their history.
pub fn release(c: &Connection, kind: &str, ref_id: i64, requirement: &str, why: &str, source: &str) -> AppResult<usize> {
    let ids: Vec<i64> = c
        .prepare("SELECT acceptance_id FROM risk_acceptance_items WHERE kind = ?1 AND ref_id = ?2 AND requirement = ?3 AND removed_at IS NULL")?
        .query_map(params![kind, ref_id, requirement], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let ts = now();
    for id in &ids {
        c.execute(
            "UPDATE risk_acceptance_items SET removed_at = ?5, removed_reason = ?4 WHERE acceptance_id = ?1 AND kind = ?2 AND ref_id = ?3 AND requirement = ?6",
            params![id, kind, ref_id, why, ts, requirement],
        )?;
        let label = match kind {
            "asvs" => format!("ASVS {requirement}"),
            "wstg" => requirement.to_string(),
            _ => format!("{kind} #{ref_id}"),
        };
        record(c, *id, "item_removed", &format!("{label}: {why}"), source)?;
    }
    Ok(ids.len())
}

fn acceptable(kind: &str, status: &str) -> Result<(), String> {
    match kind {
        "finding" if matches!(status, "resolved" | "false_positive") => Err(format!("it is {}: there is no risk left to accept", status.replace('_', " "))),
        "vulnerability" if matches!(status, "resolved" | "false_positive" | "mitigated") => Err(format!("it is {}: there is no risk left to accept", status.replace('_', " "))),
        "asvs" if status != "non_compliant" => Err("an exception is for a requirement assessed as non-compliant".into()),
        "wstg" if status != "failed" => Err("an exception is for a test that failed".into()),
        _ => Ok(()),
    }
}

fn note_for(id: i64, c: &Clean) -> String {
    format!("Risk accepted (#{id} “{}”): owner {}, approved by {} on {}, until {}", c.title, c.owner, c.approver, c.approved_at, c.expires_at)
}

/// Records an acceptance covering `items` (all of one open project) and makes each finding and
/// vulnerability an accepted risk. Items already covered by another acceptance move to this one.
pub fn create(c: &Connection, project_id: i64, d: &Draft, items: &[ItemRef], source: &str) -> AppResult<i64> {
    crate::workspace::relations::require_open(c, project_id)?;
    let f = check(d)?;
    if items.is_empty() || items.len() > 500 {
        return Err(validation("An acceptance covers 1 to 500 items"));
    }
    let tx = c.unchecked_transaction()?;
    let mut described = Vec::new();
    for it in items {
        let (project, status, label) = describe(&tx, it)?;
        if project != project_id {
            return Err(validation(format!("{label} is not part of this project")));
        }
        acceptable(&it.kind, &status).map_err(|why| validation(format!("{label} cannot be accepted: {why}")))?;
        described.push((it, status, label));
    }
    let ts = now();
    tx.execute(
        "INSERT INTO risk_acceptances (project_id, title, justification, compensating, owner, approver, approved_at, expires_at, review_at, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', ?10, ?10)",
        params![project_id, f.title, f.justification, f.compensating, f.owner, f.approver, f.approved_at, f.expires_at, f.review_at, ts],
    )?;
    let id = tx.last_insert_rowid();
    record(&tx, id, "created", &format!("{} item{}; owner {}, approved by {} on {}, until {}", items.len(), if items.len() == 1 { "" } else { "s" }, f.owner, f.approver, f.approved_at, f.expires_at), source)?;
    let note = note_for(id, &f);
    for (it, status, label) in described {
        let requirement = match it.kind.as_str() {
            "asvs" => crate::workspace::asvs::requirement(&it.requirement).map(|r| r.id.to_string()).unwrap_or_default(),
            "wstg" => wstg_test(&it.requirement)?,
            _ => String::new(),
        };
        release(&tx, &it.kind, it.ref_id, &requirement, &format!("moved to acceptance #{id}"), source)?;
        tx.execute(
            "INSERT INTO risk_acceptance_items (acceptance_id, kind, ref_id, requirement, added_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (acceptance_id, kind, ref_id, requirement) DO UPDATE SET removed_at = NULL, removed_reason = ''",
            params![id, it.kind, it.ref_id, requirement, ts],
        )?;
        record(&tx, id, "item_added", &label, source)?;
        match (it.kind.as_str(), status.as_str()) {
            // already marked accepted (before records existed, or under an expired acceptance)
            ("finding", "accepted_risk") => crate::workspace::findings::add_note(&tx, it.ref_id, &note, source)?,
            ("finding", _) => {
                crate::workspace::findings::set_status(&tx, it.ref_id, "accepted_risk", &note, source)?;
            }
            ("vulnerability", "accepted_risk") => {}
            ("vulnerability", _) => {
                crate::workspace::vulns::set_status(&tx, it.ref_id, "accepted_risk", &note, source)?;
            }
            _ => {}
        }
    }
    crate::workspace::timeline::record(&tx, project_id, "risk", &format!("Risk accepted: {}", f.title), &format!("{} item{}, until {}", items.len(), if items.len() == 1 { "" } else { "s" }, f.expires_at), None, None)?;
    tx.commit()?;
    Ok(id)
}

fn project_of(c: &Connection, id: i64) -> AppResult<(i64, String)> {
    c.query_row("SELECT project_id, status FROM risk_acceptances WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("risk acceptance {id}")))
}

/// A new approval and expiry (and optionally a new review date), keeping what it covers.
pub fn renew(c: &Connection, id: i64, d: &Draft, source: &str) -> AppResult<()> {
    let (project_id, status) = project_of(c, id)?;
    crate::workspace::relations::require_open(c, project_id)?;
    if status == "revoked" {
        return Err(validation("A revoked acceptance cannot be renewed; record a new one"));
    }
    let f = check(d)?;
    let tx = c.unchecked_transaction()?;
    tx.execute(
        "UPDATE risk_acceptances SET title = ?2, justification = ?3, compensating = ?4, owner = ?5, approver = ?6, approved_at = ?7, expires_at = ?8, review_at = ?9, updated_at = ?10 WHERE id = ?1",
        params![id, f.title, f.justification, f.compensating, f.owner, f.approver, f.approved_at, f.expires_at, f.review_at, now()],
    )?;
    record(&tx, id, "renewed", &format!("approved by {} on {}, until {}{}", f.approver, f.approved_at, f.expires_at, f.review_at.as_deref().map(|r| format!(", review on {r}")).unwrap_or_default()), source)?;
    tx.commit()?;
    Ok(())
}

/// Ends an acceptance: what it still covered is reopened (findings `reopened`, vulnerabilities
/// `open`; an ASVS requirement keeps its status and loses its exception).
pub fn revoke(c: &Connection, id: i64, reason: &str, source: &str) -> AppResult<()> {
    let (project_id, status) = project_of(c, id)?;
    crate::workspace::relations::require_open(c, project_id)?;
    if status == "revoked" {
        return Err(validation("The acceptance is already revoked"));
    }
    let reason = clean("The reason", reason, 4000, true)?;
    let tx = c.unchecked_transaction()?;
    let open: Vec<(String, i64, String)> = tx
        .prepare("SELECT kind, ref_id, requirement FROM risk_acceptance_items WHERE acceptance_id = ?1 AND removed_at IS NULL")?
        .query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let ts = now();
    tx.execute("UPDATE risk_acceptances SET status = 'revoked', revoked_at = ?2, revoked_reason = ?3, updated_at = ?2 WHERE id = ?1", params![id, ts, reason])?;
    tx.execute("UPDATE risk_acceptance_items SET removed_at = ?2, removed_reason = ?3 WHERE acceptance_id = ?1 AND removed_at IS NULL", params![id, ts, format!("revoked: {reason}")])?;
    record(&tx, id, "revoked", &reason, source)?;
    let note = format!("Risk acceptance #{id} revoked: {reason}");
    for (kind, ref_id, _) in open {
        // only what is still an accepted risk under no other acceptance reopens
        if cover(&tx, &kind, ref_id, "")?.is_some() {
            continue;
        }
        match kind.as_str() {
            "finding" => {
                let st: Option<String> = tx.query_row("SELECT status FROM findings WHERE id = ?1", params![ref_id], |r| r.get(0)).optional()?;
                if st.as_deref() == Some("accepted_risk") {
                    crate::workspace::findings::set_status(&tx, ref_id, "reopened", &note, source)?;
                }
            }
            "vulnerability" => {
                let st: Option<String> = tx.query_row("SELECT status FROM vulnerabilities WHERE id = ?1", params![ref_id], |r| r.get(0)).optional()?;
                if st.as_deref() == Some("accepted_risk") {
                    crate::workspace::vulns::set_status(&tx, ref_id, "open", &note, source)?;
                }
            }
            _ => {}
        }
    }
    crate::workspace::timeline::record(&tx, project_id, "risk", "Risk acceptance revoked", &reason, None, None)?;
    tx.commit()?;
    Ok(())
}

fn row(r: &rusqlite::Row, today: &str) -> rusqlite::Result<Acceptance> {
    let status: String = r.get(10)?;
    let expires: String = r.get(8)?;
    let review: Option<String> = r.get(9)?;
    Ok(Acceptance {
        id: r.get(0)?,
        project_id: r.get(1)?,
        title: r.get(2)?,
        justification: r.get(3)?,
        compensating: r.get(4)?,
        owner: r.get(5)?,
        approver: r.get(6)?,
        approved_at: r.get(7)?,
        standing: standing(&status, &expires, review.as_deref(), today).into(),
        expires_at: expires,
        review_at: review,
        status,
        revoked_at: r.get(11)?,
        revoked_reason: r.get(12)?,
        created_at: r.get(13)?,
        updated_at: r.get(14)?,
        items: Vec::new(),
    })
}

const COLS: &str = "id, project_id, title, justification, compensating, owner, approver, approved_at, expires_at, review_at, status, revoked_at, revoked_reason, created_at, updated_at";

fn items(c: &Connection, id: i64) -> AppResult<Vec<Item>> {
    let raw: Vec<(String, i64, String, String, Option<String>, String)> = c
        .prepare("SELECT kind, ref_id, requirement, added_at, removed_at, removed_reason FROM risk_acceptance_items WHERE acceptance_id = ?1 ORDER BY removed_at IS NOT NULL, kind, ref_id, requirement")?
        .query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
        .collect::<Result<_, _>>()?;
    raw.into_iter()
        .map(|(kind, ref_id, requirement, added_at, removed_at, removed_reason)| {
            let (status, label) = describe(c, &ItemRef { kind: kind.clone(), ref_id, requirement: requirement.clone() }).map(|(_, s, l)| (s, l)).unwrap_or_else(|_| ("deleted".into(), format!("{kind} #{ref_id}")));
            Ok(Item { kind, ref_id, requirement, label, status, added_at, removed_at, removed_reason })
        })
        .collect()
}

pub fn get(c: &Connection, id: i64) -> AppResult<Acceptance> {
    let today = today();
    let mut a = c.query_row(&format!("SELECT {COLS} FROM risk_acceptances WHERE id = ?1"), params![id], |r| row(r, &today)).optional()?.ok_or_else(|| AppError::NotFound(format!("risk acceptance {id}")))?;
    a.items = items(c, id)?;
    Ok(a)
}

/// A project's acceptances with what they cover: expired and due for review first, then active,
/// then revoked.
pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<Acceptance>> {
    let today = today();
    let mut all: Vec<Acceptance> = c
        .prepare(&format!("SELECT {COLS} FROM risk_acceptances WHERE project_id = ?1 ORDER BY expires_at, id"))?
        .query_map(params![project_id], |r| row(r, &today))?
        .collect::<Result<_, _>>()?;
    for a in &mut all {
        a.items = items(c, a.id)?;
    }
    let rank = |s: &str| match s {
        "expired" => 0,
        "review_due" => 1,
        "active" => 2,
        _ => 3,
    };
    all.sort_by_key(|a| (rank(&a.standing), a.expires_at.clone(), a.id));
    Ok(all)
}

pub fn history(c: &Connection, id: i64) -> AppResult<Vec<Event>> {
    Ok(c
        .prepare("SELECT action, detail, source, at FROM risk_acceptance_events WHERE acceptance_id = ?1 ORDER BY id")?
        .query_map(params![id], |r| Ok(Event { action: r.get(0)?, detail: r.get(1)?, source: r.get(2)?, at: r.get(3)? }))?
        .collect::<Result<_, _>>()?)
}

/// Findings marked as accepted risks that no acceptance covers (marked before records existed,
/// or whose acceptance ended): (id, title).
pub fn uncovered_findings(c: &Connection, project_id: i64) -> AppResult<Vec<(i64, String)>> {
    Ok(c
        .prepare(
            "SELECT f.id, f.title FROM findings f WHERE f.project_id = ?1 AND f.status = 'accepted_risk'
             AND NOT EXISTS (SELECT 1 FROM risk_acceptance_items i JOIN risk_acceptances a ON a.id = i.acceptance_id
                             WHERE i.kind = 'finding' AND i.ref_id = f.id AND i.removed_at IS NULL AND a.status = 'active')
             ORDER BY f.id",
        )?
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?)
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub active: usize,
    pub review_due: usize,
    pub expired: usize,
    pub revoked: usize,
    /// findings marked accepted that no active acceptance covers
    pub undocumented: usize,
}

pub fn summary(c: &Connection, project_id: i64) -> AppResult<Summary> {
    let mut s = Summary { undocumented: uncovered_findings(c, project_id)?.len(), ..Default::default() };
    let today = today();
    let rows: Vec<(String, String, Option<String>)> = c
        .prepare("SELECT status, expires_at, review_at FROM risk_acceptances WHERE project_id = ?1")?
        .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (status, expires, review) in rows {
        match standing(&status, &expires, review.as_deref(), &today) {
            "expired" => s.expired += 1,
            "review_due" => s.review_due += 1,
            "revoked" => s.revoked += 1,
            _ => s.active += 1,
        }
    }
    Ok(s)
}

#[cfg(test)]
#[path = "risk_tests.rs"]
mod tests;
