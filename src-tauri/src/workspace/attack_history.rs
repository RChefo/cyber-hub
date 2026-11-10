//! ATT&CK over time (Mission 5): a technique's history in a project, snapshots of the detection
//! library's coverage, and the comparison of any two technique sets.
//!
//! The sets keep their meaning apart: what the project **observed** (findings that name the
//! technique and confirmed assessments), its **hypotheses**, the library's detection **coverage**
//! (enabled, runnable rules: what could be detected, not what happened), a coverage
//! **snapshot**, or an imported Navigator **layer** (someone else's view). A comparison only
//! reports differences; it never turns one kind into another.
//!
//! Since Mission 6 every set belongs to one ATT&CK domain (Enterprise, Mobile or ICS): snapshots
//! and layers record theirs, and two sets of different domains are not compared (their tactics,
//! IDs and versions differ; the same behaviour has a different ID in each).

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::attack;
use super::attack_layer::techniques_of;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub at: String,
    /// assessment, finding, detection or link
    pub kind: String,
    pub summary: String,
    pub actor: String,
    /// the finding, rule or relation it is about
    pub ref_id: Option<i64>,
}

/// Everything that happened about one technique in a project, oldest first: the analyst's
/// assessments, findings that name it, detection matches of rules mapped to it, and records
/// linked to it in the investigation.
pub fn technique_history(c: &Connection, project_id: i64, technique: &str) -> AppResult<Vec<HistoryEntry>> {
    let id = technique.trim().to_ascii_uppercase();
    let mut out = Vec::new();
    // assessments (recorded with the investigation's events)
    let mut st = c.prepare("SELECT at, summary, actor, note FROM relation_events WHERE project_id = ?1 AND action = 'assessed' AND (summary LIKE ?2 OR summary LIKE ?3) ORDER BY id")?;
    for row in st.query_map(params![project_id, format!("ATT&CK {id} %"), format!("Assessment removed: {id} %")], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))? {
        let (at, summary, actor, note) = row?;
        out.push(HistoryEntry { at, kind: "assessment".into(), summary: if note.is_empty() { summary } else { format!("{summary} — {note}") }, actor, ref_id: None });
    }
    // findings that name it (their creation, and their status now)
    for f in crate::commands::projects::findings_of(c, project_id)? {
        if techniques_of(&f).contains(&id) {
            out.push(HistoryEntry { at: f.created_at.clone(), kind: "finding".into(), summary: format!("Finding #{} “{}” names it (now {})", f.id, f.title, f.status.replace('_', " ")), actor: f.source.clone(), ref_id: Some(f.id) });
        }
    }
    // detection matches of rules mapped to it, per rule
    let mut st = c.prepare("SELECT rule_id, rule_title, MIN(created_at), COUNT(*), SUM(status = 'new') FROM detection_hits WHERE project_id = ?1 AND techniques LIKE ?2 GROUP BY rule_id, rule_title")?;
    for row in st.query_map(params![project_id, format!("%\"{id}\"%")], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)))? {
        let (rule, title, first, n, open) = row?;
        out.push(HistoryEntry { at: first, kind: "detection".into(), summary: format!("Detection rule “{title}” matched {n} time{} ({open} still to review)", if n == 1 { "" } else { "s" }), actor: "detection".into(), ref_id: rule });
    }
    // records linked to it in the investigation
    let mut st = c.prepare(
        "SELECT id, created_at, a_kind, a_id, b_kind, b_id, verification, origin FROM relations
         WHERE project_id = ?1 AND ((a_kind = 'technique' AND a_sub = ?2) OR (b_kind = 'technique' AND b_sub = ?2)) ORDER BY id",
    )?;
    let rows = st.query_map(params![project_id, id], |r| {
        let (ak, ai, bk, bi): (String, i64, String, i64) = (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
        // the other end of the link
        let (k, other) = if ak == "technique" { (bk, bi) } else { (ak, ai) };
        Ok(HistoryEntry { at: r.get(1)?, kind: "link".into(), summary: format!("Linked to {k} #{other} ({}, {})", r.get::<_, String>(6)?, r.get::<_, String>(7)?), actor: r.get(7)?, ref_id: Some(r.get(0)?) })
    })?;
    for e in rows {
        out.push(e?);
    }
    out.sort_by(|a, b| a.at.cmp(&b.at));
    Ok(out)
}

/* ───────────────────────── coverage snapshots ───────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CoveredBy {
    pub rule_id: i64,
    pub title: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: i64,
    /// the ATT&CK domain whose techniques it records
    pub domain: String,
    pub label: String,
    pub attack_version: String,
    pub taken_at: String,
    pub techniques: i64,
    pub rules: i64,
}

/// What the library covers now in a domain: technique → enabled, runnable rules.
fn coverage_now(c: &Connection, domain: &str) -> AppResult<BTreeMap<String, Vec<CoveredBy>>> {
    let mut out = BTreeMap::new();
    for (t, rules) in crate::workspace::detections::coverage(c)? {
        if !attack::in_domain(&t, domain) {
            continue;
        }
        let live: Vec<CoveredBy> = rules.into_iter().filter(|r| r.enabled && r.runnable).map(|r| CoveredBy { rule_id: r.rule_id, title: r.title, kind: r.kind }).collect();
        if !live.is_empty() {
            out.insert(t, live);
        }
    }
    Ok(out)
}

fn domain_or_err(domain: &str) -> AppResult<&'static str> {
    attack::parse_domain(domain).ok_or_else(|| validation("The ATT&CK domain is enterprise-attack, mobile-attack or ics-attack"))
}

/// Records the library's coverage of a domain now, to compare later (rules added, removed,
/// disabled), with that domain's catalog version.
pub fn snapshot_take(c: &Connection, label: &str, domain: &str) -> AppResult<i64> {
    let domain = domain_or_err(domain)?;
    let label = crate::util::clean("The label", label, 120, true)?;
    let cov = coverage_now(c, domain)?;
    let rules: BTreeSet<i64> = cov.values().flatten().map(|r| r.rule_id).collect();
    let version = attack::catalog_for(domain).map(|c| c.version.clone()).unwrap_or_default();
    c.execute(
        "INSERT INTO attack_coverage_snapshots (label, attack_version, taken_at, coverage, techniques, rules, domain) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![label, version, now(), serde_json::to_string(&cov).unwrap_or_else(|_| "{}".into()), cov.len() as i64, rules.len() as i64, domain],
    )?;
    Ok(c.last_insert_rowid())
}

pub fn snapshots(c: &Connection) -> AppResult<Vec<Snapshot>> {
    Ok(c
        .prepare("SELECT id, label, attack_version, taken_at, techniques, rules, domain FROM attack_coverage_snapshots ORDER BY id DESC")?
        .query_map([], |r| Ok(Snapshot { id: r.get(0)?, label: r.get(1)?, attack_version: r.get(2)?, taken_at: r.get(3)?, techniques: r.get(4)?, rules: r.get(5)?, domain: r.get(6)? }))?
        .collect::<Result<_, _>>()?)
}

pub fn snapshot_delete(c: &Connection, id: i64) -> AppResult<()> {
    if c.execute("DELETE FROM attack_coverage_snapshots WHERE id = ?1", params![id])? == 0 {
        return Err(AppError::NotFound(format!("coverage snapshot {id}")));
    }
    Ok(())
}

/* ───────────────────────── comparison ───────────────────────── */

/// A set of techniques with a short note for each (what put it there).
struct Set {
    label: String,
    kind: &'static str,
    items: BTreeMap<String, String>,
}

/// `observed`, `hypotheses`, `coverage`, `snapshot:<id>` or `layer:<id>` (a layer of the project),
/// in `domain`. A snapshot or a layer of another domain is refused.
fn side(c: &Connection, project_id: i64, domain: &'static str, spec: &str) -> AppResult<Set> {
    let m = || super::attack_matrix::matrix_for(c, project_id, domain);
    let other_domain = |what: &str, theirs: &str| {
        validation(format!(
            "{what} is for ATT&CK {}; it cannot be compared with ATT&CK {} sets (different tactics, IDs and versions). Compare it in the {} matrix.",
            attack::domain_label(theirs),
            attack::domain_label(domain),
            attack::domain_label(theirs)
        ))
    };
    match spec.split_once(':').unwrap_or((spec, "")) {
        ("observed", _) => {
            let mut items = BTreeMap::new();
            for e in m()?.entries {
                if !e.observed.is_empty() {
                    items.insert(e.id.clone(), format!("{} finding{}", e.observed.len(), if e.observed.len() == 1 { "" } else { "s" }));
                } else if e.assessment.as_ref().is_some_and(|a| a.status == "confirmed") {
                    items.insert(e.id.clone(), "confirmed by the analyst".into());
                }
            }
            Ok(Set { label: "Observed in the project".into(), kind: "observed", items })
        }
        ("hypotheses", _) => Ok(Set {
            label: "Hypotheses".into(),
            kind: "hypothesis",
            items: m()?.entries.into_iter().filter(|e| e.assessment.as_ref().is_some_and(|a| a.status == "hypothesis")).map(|e| (e.id, "hypothesis".into())).collect(),
        }),
        ("coverage", _) => Ok(Set {
            label: "Detection coverage now".into(),
            kind: "coverage",
            items: coverage_now(c, domain)?.into_iter().map(|(t, r)| (t, r.iter().map(|x| x.title.clone()).take(3).collect::<Vec<_>>().join("; "))).collect(),
        }),
        ("snapshot", id) => {
            let id: i64 = id.parse().map_err(|_| validation("Unknown snapshot"))?;
            let (label, taken, cov, theirs): (String, String, String, String) = c
                .query_row("SELECT label, taken_at, coverage, domain FROM attack_coverage_snapshots WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("coverage snapshot {id}")))?;
            if theirs != domain {
                return Err(other_domain(&format!("The snapshot “{label}”"), &theirs));
            }
            let cov: BTreeMap<String, Vec<CoveredBy>> = serde_json::from_str(&cov).unwrap_or_default();
            Ok(Set { label: format!("Coverage snapshot “{label}” ({})", taken.get(..10).unwrap_or(&taken)), kind: "coverage", items: cov.into_iter().map(|(t, r)| (t, r.iter().map(|x| x.title.clone()).take(3).collect::<Vec<_>>().join("; "))).collect() })
        }
        ("layer", id) => {
            let id: i64 = id.parse().map_err(|_| validation("Unknown layer"))?;
            let (name, owner, marks, theirs): (String, i64, String, String) = c
                .query_row("SELECT name, project_id, techniques, domain FROM attack_layers WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("layer {id}")))?;
            if owner != project_id {
                return Err(validation("The layer belongs to another project"));
            }
            if theirs != domain {
                return Err(other_domain(&format!("The layer “{name}”"), &theirs));
            }
            let marks: BTreeMap<String, super::attack_matrix::Mark> = serde_json::from_str(&marks).unwrap_or_default();
            Ok(Set {
                label: format!("Layer “{name}”"),
                kind: "layer",
                items: marks.into_iter().map(|(t, mk)| (t, mk.score.map(|s| format!("score {s}")).unwrap_or_default())).collect(),
            })
        }
        _ => Err(validation("Compare observed, hypotheses, coverage, a snapshot or a layer")),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Diffed {
    pub id: String,
    pub name: String,
    pub a: String,
    pub b: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    /// the ATT&CK domain both sets belong to
    pub domain: String,
    pub a_label: String,
    pub b_label: String,
    pub a_kind: String,
    pub b_kind: String,
    pub only_a: Vec<Diffed>,
    pub only_b: Vec<Diffed>,
    pub both: Vec<Diffed>,
    /// what the comparison means, in one sentence, so coverage is never read as activity
    pub reading: String,
}

fn name(domain: &str, id: &str) -> String {
    attack::technique_in(domain, id).map(|t| t.name.clone()).unwrap_or_else(|| "(not in the catalog)".into())
}

/// Two technique sets of one ATT&CK domain compared (Enterprise when `domain` is empty).
pub fn compare(c: &Connection, project_id: i64, domain: &str, a: &str, b: &str) -> AppResult<Comparison> {
    let domain = if domain.trim().is_empty() { attack::ENTERPRISE } else { domain_or_err(domain)? };
    if a == b {
        return Err(validation("Choose two different sets"));
    }
    let (x, y) = (side(c, project_id, domain, a)?, side(c, project_id, domain, b)?);
    let d = |id: &String| Diffed { id: id.clone(), name: name(domain, id), a: x.items.get(id).cloned().unwrap_or_default(), b: y.items.get(id).cloned().unwrap_or_default() };
    let only_a = x.items.keys().filter(|k| !y.items.contains_key(*k)).map(d).collect();
    let only_b = y.items.keys().filter(|k| !x.items.contains_key(*k)).map(d).collect();
    let both = x.items.keys().filter(|k| y.items.contains_key(*k)).map(d).collect();
    let reading = match (x.kind, y.kind) {
        ("observed", "coverage") | ("coverage", "observed") => "Observed techniques without coverage are detection gaps; coverage without observation says nothing about activity.",
        ("coverage", "coverage") => "Techniques in one coverage set only are rules added, removed or disabled between the two.",
        ("layer", _) | (_, "layer") => "A layer is someone else's view (a threat profile, a red-team plan): matching it shows overlap, not activity in this project.",
        _ => "Differences between two sets of techniques; each keeps its own meaning.",
    };
    Ok(Comparison { domain: domain.into(), a_label: x.label, b_label: y.label, a_kind: x.kind.into(), b_kind: y.kind.into(), only_a, only_b, both, reading: reading.into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn history_snapshots_and_comparisons_keep_their_meaning() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'IR', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO findings (id, project_id, title, severity, status, tags, created_at, updated_at) VALUES (4, 1, 'PowerShell download cradle', 'high', 'confirmed', '[\"T1059.001\"]', '2026-11-01T10:00:00Z', 't')", [])?;
            super::super::attack_matrix::assess(c, 1, "T1059.001", Some("confirmed"), "high", "seen in 4688 events", "user")?;
            super::super::attack_matrix::assess(c, 1, "T1003", Some("hypothesis"), "low", "", "user")?;
            let h = technique_history(c, 1, "t1059.001")?;
            assert_eq!(h.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), ["finding", "assessment"]);
            assert!(h[1].summary.contains("confirmed") && h[1].summary.contains("seen in 4688"), "{h:?}");
            // coverage: one rule for T1059.001
            let rule = "title: PS\nid: 0f1e2d3c-4b5a-4968-8776-655443322111\ntags: [attack.t1059.001]\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    s:\n        Image|endswith: '\\\\powershell.exe'\n    condition: s\n";
            let checked = crate::detection::sigma::read(rule).unwrap().remove(0);
            let r = crate::workspace::detections::upsert_sigma(c, rule, &checked, "r.yml", "")?;
            let snap = snapshot_take(c, "Before tuning", attack::ENTERPRISE)?;
            assert_eq!(snapshots(c)?[0].techniques, 1);
            // observed vs coverage: T1059.001 is covered; T1003 is only a hypothesis (not observed)
            let cmp = compare(c, 1, "", "observed", "coverage")?;
            assert_eq!((cmp.only_a.len(), cmp.both.len(), cmp.only_b.len()), (0, 1, 0));
            assert!(cmp.reading.contains("says nothing about activity"));
            assert_eq!(compare(c, 1, "", "hypotheses", "observed")?.only_a[0].id, "T1003");
            // the rule disabled: the snapshot still has it, coverage now does not
            crate::workspace::detections::set_enabled(c, r.id, false)?;
            let drift = compare(c, 1, attack::ENTERPRISE, &format!("snapshot:{snap}"), "coverage")?;
            assert_eq!(drift.only_a.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["T1059.001"]);
            assert!(drift.reading.contains("added, removed or disabled"));
            assert!(compare(c, 1, "", "coverage", "coverage").is_err() && compare(c, 1, "", "layer:99", "coverage").is_err());
            Ok(())
        })
        .unwrap();
    }
}
