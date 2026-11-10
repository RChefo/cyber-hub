//! OWASP ASVS assessments (docs/DATA_MODEL.md#asvs-assessments-schema-25).
//!
//! The requirement list is the official ASVS 5.0.0 JSON (`catalog/asvs-5.0.0.json`, © OWASP
//! Foundation, CC BY-SA 4.0, unmodified). A project's assessment records, per requirement of its
//! level, the analyst's status (not assessed, compliant, non-compliant, not applicable, needs
//! review), a note, linked findings and evidence, and mappings the analyst defines to other
//! frameworks; every status change is kept. Nothing is ever marked compliant automatically: no
//! finding is not evidence of compliance. ASVS 5.0.0 publishes no CWE or NIST mapping, so every
//! mapping here is the analyst's.

use std::collections::BTreeMap;

use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::error::{validation, AppError, AppResult};
use crate::util::now;
use crate::workspace::relations;

pub const STATUSES: &[&str] = &["not_assessed", "compliant", "non_compliant", "not_applicable", "needs_review"];
pub const FRAMEWORKS: &[&str] = &["wstg", "api_top10", "cwe", "attack", "nist_800_53", "other"];
pub const SOURCE: &str = "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release";
pub const LICENSE: &str = "CC BY-SA 4.0";

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Requirement {
    /// `V1.2.1`
    pub id: String,
    pub chapter: String,
    pub section: String,
    pub text: String,
    /// the lowest verification level that includes it
    pub level: u8,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Chapter {
    pub id: String,
    pub name: String,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub name: String,
    pub version: String,
    pub source: &'static str,
    pub license: &'static str,
    pub chapters: Vec<Chapter>,
    pub requirements: Vec<Requirement>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string()
}

pub(crate) static CATALOG: Lazy<Catalog> = Lazy::new(|| {
    let doc: Value = serde_json::from_str(include_str!("../../catalog/asvs-5.0.0.json")).expect("catalog/asvs-5.0.0.json is valid JSON");
    let mut chapters = Vec::new();
    let mut requirements = Vec::new();
    for ch in doc["Requirements"].as_array().expect("chapters") {
        let mut sections = Vec::new();
        for sec in ch["Items"].as_array().expect("sections") {
            sections.push(Section { id: s(sec, "Shortcode"), name: s(sec, "Name") });
            for r in sec["Items"].as_array().expect("requirements") {
                requirements.push(Requirement {
                    id: s(r, "Shortcode"),
                    chapter: s(ch, "Shortcode"),
                    section: s(sec, "Shortcode"),
                    text: s(r, "Description"),
                    level: s(r, "L").parse().unwrap_or(3),
                });
            }
        }
        chapters.push(Chapter { id: s(ch, "Shortcode"), name: s(ch, "Name"), sections });
    }
    Catalog { name: s(&doc, "Name"), version: s(&doc, "Version"), source: SOURCE, license: LICENSE, chapters, requirements }
});

pub fn catalog() -> &'static Catalog {
    &CATALOG
}

pub fn requirement(id: &str) -> Option<&'static Requirement> {
    CATALOG.requirements.iter().find(|r| r.id.eq_ignore_ascii_case(id.trim()))
}

/* ───────────────────────── assessments ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// requirements of the assessment's level
    pub total: usize,
    pub not_assessed: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    pub not_applicable: usize,
    pub needs_review: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub version: String,
    pub level: u8,
    pub scope: String,
    pub counts: Counts,
    pub created_at: String,
    pub updated_at: String,
}

fn statuses(c: &Connection, id: i64) -> AppResult<BTreeMap<String, (String, String, String)>> {
    let mut st = c.prepare("SELECT requirement, status, note, updated_at FROM asvs_results WHERE assessment_id = ?1")?;
    let rows = st.query_map(params![id], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn counts(level: u8, st: &BTreeMap<String, (String, String, String)>) -> Counts {
    let mut n = Counts::default();
    for r in CATALOG.requirements.iter().filter(|r| r.level <= level) {
        n.total += 1;
        match st.get(&r.id).map(|x| x.0.as_str()).unwrap_or("not_assessed") {
            "compliant" => n.compliant += 1,
            "non_compliant" => n.non_compliant += 1,
            "not_applicable" => n.not_applicable += 1,
            "needs_review" => n.needs_review += 1,
            _ => n.not_assessed += 1,
        }
    }
    n
}

fn summary(c: &Connection, id: i64) -> AppResult<Summary> {
    let (project_id, name, version, level, scope, created_at, updated_at): (i64, String, String, u8, String, String, String) = c
        .query_row("SELECT project_id, name, version, level, scope, created_at, updated_at FROM asvs_assessments WHERE id = ?1", params![id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("ASVS assessment {id}")))?;
    let st = statuses(c, id)?;
    Ok(Summary { id, project_id, name, version, level, scope, counts: counts(level, &st), created_at, updated_at })
}

pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<Summary>> {
    let ids: Vec<i64> = c.prepare("SELECT id FROM asvs_assessments WHERE project_id = ?1 ORDER BY id")?.query_map(params![project_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    ids.into_iter().map(|id| summary(c, id)).collect()
}

fn check_level(level: u8) -> AppResult<()> {
    if (1..=3).contains(&level) {
        Ok(())
    } else {
        Err(validation("The verification level is 1, 2 or 3"))
    }
}

pub fn create(c: &Connection, project_id: i64, name: &str, level: u8, scope: &str) -> AppResult<i64> {
    relations::require_open(c, project_id)?;
    check_level(level)?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(validation("An assessment name has 1 to 200 characters"));
    }
    let ts = now();
    c.execute(
        "INSERT INTO asvs_assessments (project_id, name, version, level, scope, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![project_id, name, CATALOG.version, level, scope.trim().chars().take(2000).collect::<String>(), ts],
    )?;
    let id = c.last_insert_rowid();
    crate::workspace::timeline::record(c, project_id, "checklist", &format!("ASVS {} assessment started: {name}", CATALOG.version), &format!("level {level}"), None, None)?;
    Ok(id)
}

fn open_assessment(c: &Connection, id: i64) -> AppResult<i64> {
    let project_id: i64 = c.query_row("SELECT project_id FROM asvs_assessments WHERE id = ?1", params![id], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("ASVS assessment {id}")))?;
    relations::require_open(c, project_id)?;
    Ok(project_id)
}

pub fn update(c: &Connection, id: i64, name: Option<&str>, level: Option<u8>, scope: Option<&str>) -> AppResult<()> {
    open_assessment(c, id)?;
    if let Some(l) = level {
        check_level(l)?;
    }
    if let Some(n) = name {
        if n.trim().is_empty() || n.trim().chars().count() > 200 {
            return Err(validation("An assessment name has 1 to 200 characters"));
        }
    }
    c.execute(
        "UPDATE asvs_assessments SET name = COALESCE(?2, name), level = COALESCE(?3, level), scope = COALESCE(?4, scope), updated_at = ?5 WHERE id = ?1",
        params![id, name.map(str::trim), level, scope.map(|s| s.trim().chars().take(2000).collect::<String>()), now()],
    )?;
    Ok(())
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    open_assessment(c, id)?;
    c.execute("DELETE FROM asvs_assessments WHERE id = ?1", params![id])?;
    Ok(())
}

/// Sets a requirement's status and note; a change of status is kept in the history.
pub fn set_status(c: &Connection, id: i64, req: &str, status: &str, note: Option<&str>, actor: &str) -> AppResult<()> {
    open_assessment(c, id)?;
    let r = requirement(req).ok_or_else(|| validation(format!("{req} is not an ASVS {} requirement", CATALOG.version)))?;
    if !STATUSES.contains(&status) {
        return Err(validation("A status is not_assessed, compliant, non_compliant, not_applicable or needs_review"));
    }
    let tx = c.unchecked_transaction()?;
    let ts = now();
    let old: Option<(String, String)> = tx.query_row("SELECT status, note FROM asvs_results WHERE assessment_id = ?1 AND requirement = ?2", params![id, r.id], |x| Ok((x.get(0)?, x.get(1)?))).optional()?;
    let (old_status, old_note) = old.unwrap_or_else(|| ("not_assessed".into(), String::new()));
    let note = note.map(|n| n.trim().chars().take(5000).collect::<String>()).unwrap_or(old_note);
    tx.execute(
        "INSERT INTO asvs_results (assessment_id, requirement, status, note, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (assessment_id, requirement) DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = excluded.updated_at",
        params![id, r.id, status, note, ts],
    )?;
    if old_status != status {
        tx.execute("INSERT INTO asvs_history (assessment_id, requirement, from_status, to_status, note, actor, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![id, r.id, old_status, status, note, actor, ts])?;
        if status != "non_compliant" {
            crate::workspace::risk::release(&tx, "asvs", id, &r.id, &format!("the requirement is now {}", status.replace('_', " ")), actor)?;
        }
    }
    tx.execute("UPDATE asvs_assessments SET updated_at = ?2 WHERE id = ?1", params![id, ts])?;
    tx.commit()?;
    Ok(())
}

/// Links (or unlinks) a finding or evidence record of the same project to a requirement.
pub fn link(c: &Connection, id: i64, req: &str, kind: &str, ref_id: i64, linked: bool) -> AppResult<()> {
    let project_id = open_assessment(c, id)?;
    let r = requirement(req).ok_or_else(|| validation(format!("{req} is not an ASVS requirement")))?;
    let table = match kind {
        "finding" => "findings",
        "evidence" => "evidence",
        _ => return Err(validation("Link a finding or an evidence record")),
    };
    let owner: Option<i64> = c.query_row(&format!("SELECT project_id FROM {table} WHERE id = ?1"), params![ref_id], |x| x.get(0)).optional()?;
    if owner != Some(project_id) {
        return Err(validation(format!("{kind} #{ref_id} is not part of this project")));
    }
    if linked {
        c.execute("INSERT OR IGNORE INTO asvs_links (assessment_id, requirement, kind, ref_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)", params![id, r.id, kind, ref_id, now()])?;
    } else {
        c.execute("DELETE FROM asvs_links WHERE assessment_id = ?1 AND requirement = ?2 AND kind = ?3 AND ref_id = ?4", params![id, r.id, kind, ref_id])?;
    }
    Ok(())
}

pub fn mapping_add(c: &Connection, id: i64, req: &str, framework: &str, reference: &str, note: &str) -> AppResult<i64> {
    open_assessment(c, id)?;
    let r = requirement(req).ok_or_else(|| validation(format!("{req} is not an ASVS requirement")))?;
    if !FRAMEWORKS.contains(&framework) {
        return Err(validation("A mapping names wstg, api_top10, cwe, attack, nist_800_53 or other"));
    }
    let reference = reference.trim();
    if reference.is_empty() || reference.chars().count() > 120 {
        return Err(validation("A reference has 1 to 120 characters (for example WSTG-INPV-05, API1:2023, CWE-89, T1190, AC-3)"));
    }
    if framework == "attack" && crate::workspace::attack::id_state(reference) == crate::workspace::attack::IdState::Unknown {
        return Err(validation(format!("{reference} is not an ATT&CK Enterprise technique")));
    }
    c.execute(
        "INSERT OR IGNORE INTO asvs_mappings (assessment_id, requirement, framework, reference, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, r.id, framework, reference, note.trim().chars().take(1000).collect::<String>(), now()],
    )?;
    Ok(c.query_row("SELECT id FROM asvs_mappings WHERE assessment_id = ?1 AND requirement = ?2 AND framework = ?3 AND reference = ?4", params![id, r.id, framework, reference], |x| x.get(0))?)
}

pub fn mapping_delete(c: &Connection, mapping_id: i64) -> AppResult<()> {
    let id: i64 = c.query_row("SELECT assessment_id FROM asvs_mappings WHERE id = ?1", params![mapping_id], |x| x.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("mapping {mapping_id}")))?;
    open_assessment(c, id)?;
    c.execute("DELETE FROM asvs_mappings WHERE id = ?1", params![mapping_id])?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinkedFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinkedEvidence {
    pub id: i64,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Mapping {
    pub id: i64,
    pub framework: String,
    pub reference: String,
    pub note: String,
    /// always the analyst's: ASVS 5.0.0 publishes no mapping
    pub origin: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub requirement: Requirement,
    pub in_level: bool,
    pub status: String,
    pub note: String,
    pub updated_at: Option<String>,
    pub findings: Vec<LinkedFinding>,
    pub evidence: Vec<LinkedEvidence>,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct History {
    pub requirement: String,
    pub from_status: String,
    pub to_status: String,
    pub note: String,
    pub actor: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub summary: Summary,
    /// every requirement, those above the level marked out of level
    pub items: Vec<Item>,
    pub history: Vec<History>,
}

pub fn get(c: &Connection, id: i64) -> AppResult<View> {
    let summary = summary(c, id)?;
    let st = statuses(c, id)?;
    let mut findings: BTreeMap<String, Vec<LinkedFinding>> = BTreeMap::new();
    for row in c
        .prepare("SELECT l.requirement, f.id, f.title, f.severity, f.status FROM asvs_links l JOIN findings f ON f.id = l.ref_id WHERE l.assessment_id = ?1 AND l.kind = 'finding' ORDER BY f.id")?
        .query_map(params![id], |r| Ok((r.get::<_, String>(0)?, LinkedFinding { id: r.get(1)?, title: r.get(2)?, severity: r.get(3)?, status: r.get(4)? })))?
    {
        let (k, v) = row?;
        findings.entry(k).or_default().push(v);
    }
    let mut evidence: BTreeMap<String, Vec<LinkedEvidence>> = BTreeMap::new();
    for row in c
        .prepare("SELECT l.requirement, e.id, e.title FROM asvs_links l JOIN evidence e ON e.id = l.ref_id WHERE l.assessment_id = ?1 AND l.kind = 'evidence' ORDER BY e.id")?
        .query_map(params![id], |r| Ok((r.get::<_, String>(0)?, LinkedEvidence { id: r.get(1)?, title: r.get(2)? })))?
    {
        let (k, v) = row?;
        evidence.entry(k).or_default().push(v);
    }
    let mut mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    for row in c
        .prepare("SELECT requirement, id, framework, reference, note FROM asvs_mappings WHERE assessment_id = ?1 ORDER BY id")?
        .query_map(params![id], |r| Ok((r.get::<_, String>(0)?, Mapping { id: r.get(1)?, framework: r.get(2)?, reference: r.get(3)?, note: r.get(4)?, origin: "analyst" })))?
    {
        let (k, v) = row?;
        mappings.entry(k).or_default().push(v);
    }
    let items = CATALOG
        .requirements
        .iter()
        .map(|r| {
            let s = st.get(&r.id);
            Item {
                requirement: r.clone(),
                in_level: r.level <= summary.level,
                status: s.map(|x| x.0.clone()).unwrap_or_else(|| "not_assessed".into()),
                note: s.map(|x| x.1.clone()).unwrap_or_default(),
                updated_at: s.map(|x| x.2.clone()),
                findings: findings.remove(&r.id).unwrap_or_default(),
                evidence: evidence.remove(&r.id).unwrap_or_default(),
                mappings: mappings.remove(&r.id).unwrap_or_default(),
            }
        })
        .collect();
    let history = c
        .prepare("SELECT requirement, from_status, to_status, note, actor, at FROM asvs_history WHERE assessment_id = ?1 ORDER BY id DESC LIMIT 200")?
        .query_map(params![id], |r| Ok(History { requirement: r.get(0)?, from_status: r.get(1)?, to_status: r.get(2)?, note: r.get(3)?, actor: r.get(4)?, at: r.get(5)? }))?
        .collect::<Result<_, _>>()?;
    Ok(View { summary, items, history })
}

/// Records a finding for a requirement that is not met, linked to it. The status stays the
/// analyst's: recording a finding does not change it, and fixing the finding does not make the
/// requirement compliant.
pub fn record_finding(c: &Connection, id: i64, req: &str, severity: &str) -> AppResult<i64> {
    let project_id = open_assessment(c, id)?;
    let r = requirement(req).ok_or_else(|| validation(format!("{req} is not an ASVS requirement")))?;
    let note: String = c.query_row("SELECT note FROM asvs_results WHERE assessment_id = ?1 AND requirement = ?2", params![id, r.id], |x| x.get(0)).optional()?.unwrap_or_default();
    let chapter = CATALOG.chapters.iter().find(|ch| ch.id == r.chapter).map(|ch| ch.name.clone()).unwrap_or_default();
    let input = crate::commands::projects::FindingInput {
        project_id,
        title: format!("ASVS {}: requirement {} not met", CATALOG.version, r.id).chars().take(200).collect(),
        severity: severity.into(),
        status: "confirmed".into(),
        category: format!("ASVS {chapter}").chars().take(100).collect(),
        description: format!("{}\n\nRequirement v{}-{} (level {}) of the OWASP Application Security Verification Standard.{}", r.text, CATALOG.version, r.id.trim_start_matches('V'), r.level, if note.is_empty() { String::new() } else { format!("\n\nAssessment note: {note}") }),
        remediation: format!("Meet the requirement: {}", r.text.trim_start_matches("Verify that ")),
        tags: vec!["asvs".into(), r.id.clone(), format!("asvs-l{}", r.level)],
        ..Default::default()
    };
    let tx = c.unchecked_transaction()?;
    let fid = crate::commands::projects::finding_write(&tx, &input, "asvs", true)?;
    tx.execute("INSERT OR IGNORE INTO asvs_links (assessment_id, requirement, kind, ref_id, created_at) VALUES (?1, ?2, 'finding', ?3, ?4)", params![id, r.id, fid, now()])?;
    tx.commit()?;
    Ok(fid)
}

fn status_label(s: &str) -> &'static str {
    match s {
        "compliant" => "Compliant",
        "non_compliant" => "Non-compliant",
        "not_applicable" => "Not applicable",
        "needs_review" => "Needs review",
        _ => "Not assessed",
    }
}

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('<', "&lt;").replace('[', "\\[")
}

/// The assessment as a Markdown report: totals, then every requirement of the level by chapter
/// with its status, note, findings and evidence. It names the standard and its license.
pub fn report_markdown(c: &Connection, id: i64, project: &str, generated: &str) -> AppResult<String> {
    let v = get(c, id)?;
    let s = &v.summary;
    let n = &s.counts;
    let assessed = n.total - n.not_assessed;
    let mut out = format!(
        "# {} — ASVS {} assessment\n\nProject: {}  \nLevel: {}  \nGenerated: {}  \n{}\n## Summary\n\n| Status | Requirements |\n|---|---|\n| Compliant | {} |\n| Non-compliant | {} |\n| Needs review | {} |\n| Not applicable | {} |\n| Not assessed | {} |\n| **Total at level {}** | **{}** |\n\n{} of {} requirements assessed. A requirement is compliant only when the analyst said so; requirements without a status are not assessed, whatever the findings.\n",
        md(&s.name),
        s.version,
        md(project),
        s.level,
        generated,
        if s.scope.is_empty() { String::new() } else { format!("Scope: {}  \n", md(&s.scope)) },
        n.compliant,
        n.non_compliant,
        n.needs_review,
        n.not_applicable,
        n.not_assessed,
        s.level,
        n.total,
        assessed,
        n.total
    );
    // the gaps, with their exceptions and remediation, and what no evidence supports
    let g = super::asvs_gaps::gaps(c, id)?;
    if !g.gaps.is_empty() {
        out.push_str("\n## Gaps\n\nNon-compliant requirements of the level, those without an exception first. An exception (a recorded risk acceptance) covers a gap; it does not close it.\n\n| Requirement | Exception | Remediation of the linked findings |\n|---|---|---|\n");
        for gp in &g.gaps {
            let ex = gp
                .exception
                .as_ref()
                .map(|e| format!("#{} {}: owner {}, approved by {}, {} {}", e.id, md(&e.title), md(&e.owner), md(&e.approver), if e.standing == "expired" { "**expired** on" } else { "until" }, e.expires_at))
                .unwrap_or_else(|| "—".into());
            out.push_str(&format!("| {} {} | {} | {} |\n", gp.requirement, md(&gp.text), ex, md(&gp.remediation)));
        }
    }
    if !g.without_evidence.is_empty() {
        out.push_str(&format!(
            "\n{} compliant requirement{} {} no evidence linked ({}): compliant on the analyst's word.\n",
            g.without_evidence.len(),
            if g.without_evidence.len() == 1 { "" } else { "s" },
            if g.without_evidence.len() == 1 { "has" } else { "have" },
            g.without_evidence.join(", ")
        ));
    }
    for ch in &CATALOG.chapters {
        let items: Vec<&Item> = v.items.iter().filter(|i| i.in_level && i.requirement.chapter == ch.id).collect();
        if items.is_empty() {
            continue;
        }
        out.push_str(&format!("\n## {} {}\n\n| Requirement | Level | Status | Note | Findings | Evidence |\n|---|---|---|---|---|---|\n", ch.id, md(&ch.name)));
        for i in items {
            out.push_str(&format!(
                "| {} {} | {} | {} | {} | {} | {} |\n",
                i.requirement.id,
                md(&i.requirement.text),
                i.requirement.level,
                status_label(&i.status),
                md(&i.note),
                i.findings.iter().map(|f| format!("#{} {} ({})", f.id, md(&f.title), f.status.replace('_', " "))).collect::<Vec<_>>().join("; "),
                i.evidence.iter().map(|e| format!("#{} {}", e.id, md(&e.title))).collect::<Vec<_>>().join("; ")
            ));
        }
    }
    let mapped: Vec<String> = v.items.iter().flat_map(|i| i.mappings.iter().map(move |m| format!("| {} | {} | {} | {} |", i.requirement.id, m.framework, md(&m.reference), md(&m.note)))).collect();
    if !mapped.is_empty() {
        out.push_str("\n## Mappings defined by the analyst\n\nASVS 5.0.0 publishes no mapping to other frameworks; these are the analyst's.\n\n| Requirement | Framework | Reference | Note |\n|---|---|---|---|\n");
        out.push_str(&mapped.join("\n"));
        out.push('\n');
    }
    out.push_str(&format!("\n---\nRequirements: OWASP Application Security Verification Standard {} (<{}>), © OWASP Foundation, licensed under {}.\n", CATALOG.version, SOURCE, LICENSE));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn the_bundled_catalog_is_asvs_5_0_0() {
        let c = catalog();
        assert_eq!((c.version.as_str(), c.chapters.len(), c.requirements.len()), ("5.0.0", 17, 345));
        let by_level = |l: u8| c.requirements.iter().filter(|r| r.level == l).count();
        assert_eq!((by_level(1), by_level(2), by_level(3)), (70, 183, 92));
        assert_eq!(requirement("v1.2.1").unwrap().section, "V1.2");
        assert!(c.requirements.iter().all(|r| r.text.starts_with("Verify") || !r.text.is_empty()));
        let mut ids: Vec<&str> = c.requirements.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 345, "identifiers are unique");
    }

    #[test]
    fn assessments_record_statuses_links_and_history() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Shop', 'active', 't', 't'), (2, 'Other', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, created_at, updated_at) VALUES (5, 1, 'XSS', 'high', 'new', 't', 't'), (6, 2, 'Elsewhere', 'low', 'new', 't', 't')", [])?;
            c.execute("INSERT INTO evidence (id, project_id, kind, title, source, created_at) VALUES (8, 1, 'text', 'Request', 'user', 't')", [])?;
            assert!(create(c, 1, "Web shop", 4, "").is_err());
            let a = create(c, 1, "Web shop", 1, "https://shop.example.com")?;
            let s = &list(c, 1)?[0];
            assert_eq!((s.counts.total, s.counts.not_assessed, s.version.as_str()), (70, 70, "5.0.0"), "level 1 has 70 requirements, none assessed by itself");
            set_status(c, a, "V1.2.1", "non_compliant", Some("Output is not encoded in attributes"), "user")?;
            set_status(c, a, "v1.2.1", "non_compliant", None, "user")?;
            set_status(c, a, "V1.2.2", "compliant", None, "user")?;
            assert!(set_status(c, a, "V99.1.1", "compliant", None, "user").is_err());
            assert!(set_status(c, a, "V1.2.1", "perfect", None, "user").is_err());
            let v = get(c, a)?;
            let item = v.items.iter().find(|i| i.requirement.id == "V1.2.1").unwrap();
            assert_eq!((item.status.as_str(), item.note.as_str()), ("non_compliant", "Output is not encoded in attributes"), "the note stays when only the status is given");
            assert_eq!(v.history.len(), 2, "unchanged statuses add no history");
            assert_eq!((v.summary.counts.non_compliant, v.summary.counts.compliant), (1, 1));
            // links within the project only
            link(c, a, "V1.2.1", "finding", 5, true)?;
            link(c, a, "V1.2.1", "evidence", 8, true)?;
            assert!(link(c, a, "V1.2.1", "finding", 6, true).is_err(), "another project's finding");
            // a finding recorded for the requirement, linked to it; the status stays the analyst's
            let fid = record_finding(c, a, "V1.2.1", "high")?;
            let v = get(c, a)?;
            let item = v.items.iter().find(|i| i.requirement.id == "V1.2.1").unwrap();
            assert_eq!((item.findings.len(), item.evidence.len(), item.status.as_str()), (2, 1, "non_compliant"));
            let (tags, status): (String, String) = c.query_row("SELECT tags, status FROM findings WHERE id = ?1", params![fid], |r| Ok((r.get(0)?, r.get(1)?)))?;
            assert!(tags.contains("V1.2.1") && tags.contains("asvs") && status == "confirmed");
            // resolving the finding does not make the requirement compliant
            c.execute("UPDATE findings SET status = 'resolved' WHERE id = ?1", params![fid])?;
            assert_eq!(get(c, a)?.items.iter().find(|i| i.requirement.id == "V1.2.1").unwrap().status, "non_compliant");
            // mappings are the analyst's and checked where possible
            mapping_add(c, a, "V1.2.1", "wstg", "WSTG-CLNT-01", "")?;
            mapping_add(c, a, "V1.2.1", "cwe", "CWE-79", "")?;
            assert!(mapping_add(c, a, "V1.2.1", "attack", "T9999", "").is_err());
            assert!(mapping_add(c, a, "V1.2.1", "iso", "A.8.28", "").is_err());
            let m = get(c, a)?.items.into_iter().find(|i| i.requirement.id == "V1.2.1").unwrap().mappings;
            assert_eq!((m.len(), m[0].origin), (2, "analyst"));
            mapping_delete(c, m[0].id)?;
            // the level changes what counts
            update(c, a, None, Some(2), None)?;
            assert_eq!(list(c, 1)?[0].counts.total, 70 + 183);
            // the report
            let r = report_markdown(c, a, "Shop", "2026-11-10")?;
            for want in ["ASVS 5.0.0 assessment", "| Non-compliant | 1 |", "V1.2.1", "Output is not encoded in attributes", "CC BY-SA 4.0", "Mappings defined by the analyst", "CWE-79"] {
                assert!(r.contains(want), "{want}");
            }
            // deleted findings leave no link; archived projects are read-only
            c.execute("DELETE FROM findings WHERE id = 5", [])?;
            assert_eq!(get(c, a)?.items.iter().find(|i| i.requirement.id == "V1.2.1").unwrap().findings.len(), 1);
            c.execute("UPDATE projects SET status = 'archived' WHERE id = 1", [])?;
            assert!(set_status(c, a, "V1.2.2", "needs_review", None, "user").is_err());
            assert!(get(c, a).is_ok());
            c.execute("DELETE FROM projects WHERE id = 1", [])?;
            assert_eq!(c.query_row("SELECT COUNT(*) FROM asvs_results", [], |r| r.get::<_, i64>(0))?, 0);
            Ok(())
        })
        .unwrap();
    }
}
