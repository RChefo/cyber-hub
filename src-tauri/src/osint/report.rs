//! Markdown investigation reports and deterministic next-step suggestions.
//!
//! Both are computed only from stored data: no external service and no model is involved. Every
//! statement names the evidence or rule it comes from, and inferred or unreviewed material is
//! labelled as such.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{params, Connection};
use serde::Serialize;

use super::analysis::{self, Graph};
use super::ingest;
use super::model::{self, EntityType};
use super::providers;
use super::store::{self, EntityBrief, RelationshipBrief, TimelineQuery};
use crate::error::AppResult;

const MAX_ENTITY_ROWS: usize = 500;
const MAX_REL_ROWS: usize = 500;
const MAX_EVIDENCE_ROWS: usize = 300;
const MAX_TIMELINE_ROWS: usize = 200;
const ANALYSIS_LIMIT: usize = 20_000;

/// Escape a value for a Markdown table cell (and keep collected text from forming links/HTML).
pub fn cell(v: &str) -> String {
    let t: String = v.chars().filter(|c| !c.is_control() || *c == ' ').collect();
    let t = t.replace('\\', "\\\\").replace('|', "\\|").replace('<', "&lt;").replace('>', "&gt;").replace('[', "\\[").replace(']', "\\]").replace('`', "'");
    let t = t.trim();
    if t.is_empty() {
        "—".into()
    } else if t.chars().count() > 160 {
        format!("{}…", t.chars().take(160).collect::<String>())
    } else {
        t.to_string()
    }
}

/// A reference shown as a link: an http(s) URL with nothing that could end the link or the table
/// cell, or start other markup.
fn plain_url(r: &str) -> bool {
    (r.starts_with("https://") || r.starts_with("http://")) && !r.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '`' | '|' | '\\' | '"'))
}

fn type_label(t: &str) -> &'static str {
    EntityType::parse(t).map(|t| t.label()).unwrap_or("Other")
}

fn rel_label(t: &str) -> String {
    model::relationship_type(t).map(|r| r.label.to_string()).unwrap_or_else(|| t.replace('_', " ").to_lowercase())
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/* ───────────────────────── suggestions ───────────────────────── */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Suggestion {
    /// review_inferred | resolve_duplicates | corroborate | collect | review_flagged | connect_isolated
    pub kind: String,
    pub title: String,
    pub reason: String,
    pub entity_ids: Vec<i64>,
    pub relationship_ids: Vec<i64>,
    pub provider: Option<String>,
}

/// Providers that already completed for an entity value (any operation in the investigation).
fn completed_runs(c: &Connection, inv: i64) -> AppResult<HashSet<(String, String, String)>> {
    let mut st = c.prepare("SELECT provider, input_type, lower(input_value) FROM osint_operations WHERE investigation_id = ?1 AND status = 'completed'")?;
    let v = st.query_map(params![inv], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<HashSet<_>, _>>()?;
    Ok(v)
}

/// Deterministic gap analysis: what is unreviewed, weakly supported, duplicated or not yet
/// collected. Suggestions are proposals; nothing is changed.
pub fn suggestions(c: &Connection, inv: i64) -> AppResult<Vec<Suggestion>> {
    let investigation = store::investigation_get(c, inv)?;
    let (ents, rels) = store::investigation_graph(c, inv, ANALYSIS_LIMIT)?;
    let by_id: HashMap<i64, &EntityBrief> = ents.iter().map(|e| (e.id, e)).collect();
    let name = |id: i64| by_id.get(&id).map(|e| e.display_name.clone()).unwrap_or_else(|| format!("#{id}"));
    let mut out = vec![];

    let inferred: Vec<&RelationshipBrief> = rels.iter().filter(|r| r.verification == "inferred").collect();
    if !inferred.is_empty() {
        out.push(Suggestion {
            kind: "review_inferred".into(),
            title: format!("Review {}", plural(inferred.len(), "inferred relationship", "inferred relationships")),
            reason: "Inferred and suggested links come from correlation rules or proposals, not direct observation. Verify, dispute or reject each one before relying on it.".into(),
            entity_ids: vec![],
            relationship_ids: inferred.iter().take(200).map(|r| r.id).collect(),
            provider: None,
        });
    }

    for group in ingest::possible_duplicates(c, inv)?.into_iter().take(20) {
        let names: Vec<String> = group.iter().map(|id| name(*id)).collect();
        out.push(Suggestion {
            kind: "resolve_duplicates".into(),
            title: format!("Possible duplicates: {}", names.join(", ")),
            reason: "These entities differ only in formatting (case, punctuation or a trailing dot). They were not merged automatically; merge them if they are the same thing.".into(),
            entity_ids: group,
            relationship_ids: vec![],
            provider: None,
        });
    }

    let flagged: Vec<i64> = ents.iter().filter(|e| e.flagged && e.verification != "verified" && e.verification != "rejected").map(|e| e.id).collect();
    if !flagged.is_empty() {
        out.push(Suggestion {
            kind: "review_flagged".into(),
            title: format!("Review {} flagged by threat intelligence", plural(flagged.len(), "entity", "entities")),
            reason: "A provider reported these as malicious or suspicious. Provider verdicts differ and age quickly; confirm with the provider evidence before acting.".into(),
            entity_ids: flagged.into_iter().take(200).collect(),
            relationship_ids: vec![],
            provider: None,
        });
    }

    let weak: Vec<i64> = rels.iter().filter(|r| r.confidence == "low" && r.verification == "observed").map(|r| r.id).collect();
    if !weak.is_empty() {
        out.push(Suggestion {
            kind: "corroborate".into(),
            title: format!("Corroborate {} with low confidence", plural(weak.len(), "relationship", "relationships")),
            reason: "These relationships rest on a single source or on weak evidence. A second independent source raises confidence; analyst verification settles it.".into(),
            entity_ids: vec![],
            relationship_ids: weak.into_iter().take(200).collect(),
            provider: None,
        });
    }

    let g = Graph::new(&ents, &rels, false);
    let isolated = analysis::isolated(&g);
    if !isolated.is_empty() && ents.len() > 1 {
        out.push(Suggestion {
            kind: "connect_isolated".into(),
            title: format!("{} without relationships", plural(isolated.len(), "entity", "entities")),
            reason: "Isolated entities have no reviewed link to the rest of the investigation. Collect more data about them, link them manually with a note, or remove them if they are noise.".into(),
            entity_ids: isolated.into_iter().take(200).collect(),
            relationship_ids: vec![],
            provider: None,
        });
    }

    // collection gaps: providers that accept an entity's type and have not completed for it
    let runs = completed_runs(c, inv)?;
    let mut collect: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    let mut priority: Vec<&EntityBrief> = ents.iter().filter(|e| e.verification != "rejected").collect();
    // the target first, then the most connected
    let degree: HashMap<i64, usize> = rels.iter().filter(|r| r.verification != "rejected").fold(HashMap::new(), |mut m, r| {
        *m.entry(r.source).or_default() += 1;
        *m.entry(r.target).or_default() += 1;
        m
    });
    let target_key = (investigation.target_type.clone(), investigation.target_value.to_lowercase());
    priority.sort_by_key(|e| ((e.entity_type.clone(), e.value.to_lowercase()) != target_key, std::cmp::Reverse(degree.get(&e.id).copied().unwrap_or(0)), e.id));
    for e in priority.iter().take(300) {
        let Some(t) = EntityType::parse(&e.entity_type) else { continue };
        for p in providers::PROVIDERS {
            if !p.inputs.contains(&t) || (p.contacts_target && investigation.project_id.is_none()) {
                continue;
            }
            if runs.contains(&(p.id.to_string(), e.entity_type.clone(), e.value.to_lowercase())) {
                continue;
            }
            let list = collect.entry(p.id).or_default();
            if list.len() < 25 {
                list.push(e.id);
            }
        }
    }
    for (pid, ids) in collect {
        let Some(p) = providers::info(pid) else { continue };
        let first = ids.iter().take(3).map(|id| name(*id)).collect::<Vec<_>>().join(", ");
        let more = if ids.len() > 3 { format!(" and {} more", ids.len() - 3) } else { String::new() };
        let mut reason = format!("{} has not been run for {first}{more}. {}", p.name, p.description);
        if p.uses_threat_intel {
            reason.push_str(" Uses your configured threat-intelligence keys and their quotas.");
        }
        if p.contacts_target {
            reason.push_str(" Contacts the target directly and is limited to the linked project's scope.");
        }
        out.push(Suggestion { kind: "collect".into(), title: format!("Run {} on {}", p.name, plural(ids.len(), "entity", "entities")), reason, entity_ids: ids, relationship_ids: vec![], provider: Some(pid.to_string()) });
    }
    Ok(out)
}

/* ───────────────────────── report ───────────────────────── */

/// Markdown report of an investigation. `generated` is the date string printed in the header.
pub fn markdown(c: &Connection, inv: i64, generated: &str) -> AppResult<String> {
    let i = store::investigation_get(c, inv)?;
    let (ents, rels) = store::investigation_graph(c, inv, ANALYSIS_LIMIT)?;
    let by_id: HashMap<i64, &EntityBrief> = ents.iter().map(|e| (e.id, e)).collect();
    let name = |id: i64| by_id.get(&id).map(|e| cell(&e.display_name)).unwrap_or_else(|| format!("#{id}"));
    let ops = {
        let mut st = c.prepare("SELECT provider, input_type, input_value, status, requested_by, started_at, result_count, imported_count, message FROM osint_operations WHERE investigation_id = ?1 ORDER BY started_at, id")?;
        let v = st
            .query_map(params![inv], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?, r.get::<_, Option<String>>(8)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        v
    };
    let evidence = store::evidence_list(c, inv, MAX_EVIDENCE_ROWS)?;
    let mut l: Vec<String> = vec![];
    let one_line = |v: &str| v.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>();
    l.push(format!("# OSINT investigation: {}", one_line(i.name.trim()).replace('<', "&lt;").replace('[', "\\[")));
    l.push(String::new());
    l.push(format!("Generated {generated} by ExploitX from locally stored data. Status: {}.", i.status));
    l.push(String::new());

    // overview
    l.push("## Overview".into());
    l.push(String::new());
    l.push(format!("- **Target:** {} `{}`", type_label(&i.target_type), one_line(&i.target_value).replace('`', "'")));
    if let Some(p) = &i.project_name {
        l.push(format!("- **Linked project:** {}", cell(p)));
    }
    if !i.tags.is_empty() {
        l.push(format!("- **Tags:** {}", i.tags.iter().map(|t| cell(t)).collect::<Vec<_>>().join(", ")));
    }
    l.push(format!("- **Created:** {} · **Last updated:** {}", i.created_at.get(..10).unwrap_or(&i.created_at), i.updated_at.get(..10).unwrap_or(&i.updated_at)));
    if !i.authorization.trim().is_empty() {
        l.push(format!("- **Authorization / scope note:** {}", cell(&i.authorization)));
    }
    if !i.description.trim().is_empty() {
        l.push(String::new());
        // the description as written, but never markup: an imported graph sets it (Mission 7)
        l.push(crate::workspace::report::md_text(&i.description));
    }
    l.push(String::new());

    // executive summary
    let ver = |v: &str| rels.iter().filter(|r| r.verification == v).count();
    let ent_ver = |v: &str| ents.iter().filter(|e| e.verification == v).count();
    let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &ents {
        *by_type.entry(type_label(&e.entity_type)).or_default() += 1;
    }
    l.push("## Executive summary".into());
    l.push(String::new());
    l.push(format!(
        "The investigation holds {} and {}, supported by {} from {}.",
        plural(ents.len(), "entity", "entities"),
        plural(rels.len(), "relationship", "relationships"),
        plural(i.counts.evidence as usize, "evidence record", "evidence records"),
        plural(ops.len(), "collection operation", "collection operations")
    ));
    l.push(String::new());
    l.push(format!(
        "- Relationships: {} verified, {} observed, {} inferred (awaiting review), {} disputed, {} rejected.",
        ver("verified"),
        ver("observed"),
        ver("inferred"),
        ver("disputed"),
        ver("rejected")
    ));
    l.push(format!("- Entities: {} verified, {} disputed, {} rejected; {} flagged by threat intelligence.", ent_ver("verified"), ent_ver("disputed"), ent_ver("rejected"), ents.iter().filter(|e| e.flagged).count()));
    if !by_type.is_empty() {
        l.push(format!("- By type: {}.", by_type.iter().map(|(t, n)| format!("{t} {n}")).collect::<Vec<_>>().join(", ")));
    }
    l.push(String::new());
    l.push("Observed means a source reported it; verified means an analyst confirmed it. Inferred relationships come from correlation rules and are not facts until reviewed.".into());
    l.push(String::new());

    // methodology
    l.push("## Methodology and collection".into());
    l.push(String::new());
    if ops.is_empty() {
        l.push("No collection operations were recorded; data was entered manually or imported.".into());
    } else {
        l.push("| Started | Source | Input | Status | Results | Imported | Requested by |".into());
        l.push("| --- | --- | --- | --- | --- | --- | --- |".into());
        for (p, t, v, status, by, at, n, imported, msg) in &ops {
            let pname = providers::info(p).map(|x| x.name.to_string()).unwrap_or_else(|| p.replace("import:", "Import: "));
            let status = match msg {
                Some(m) if status != "completed" => format!("{status}: {}", m),
                _ => status.clone(),
            };
            l.push(format!("| {} | {} | {} `{}` | {} | {n} | {imported} | {} |", at.get(..16).unwrap_or(at), cell(&pname), type_label(t), v.replace('`', "'").replace('|', "\\|"), cell(&status), cell(by)));
        }
    }
    l.push(String::new());

    // sources
    let mut sources: BTreeMap<String, usize> = BTreeMap::new();
    for e in &evidence {
        *sources.entry(e.source.clone()).or_default() += 1;
    }
    l.push("## Sources".into());
    l.push(String::new());
    if sources.is_empty() {
        l.push("No evidence recorded.".into());
    } else {
        for (s, n) in &sources {
            let detail = providers::info(s).map(|p| format!(" — {} ({})", p.name, p.source_url)).unwrap_or_default();
            // an imported graph sets the source: shown as escaped text (Mission 7)
            l.push(format!("- {}{detail}: {}", cell(s), plural(*n, "evidence record", "evidence records")));
        }
        if i.counts.evidence as usize > evidence.len() {
            l.push(format!("- Counts cover the {} most recent of {} evidence records.", evidence.len(), i.counts.evidence));
        }
    }
    l.push(String::new());

    // entities
    l.push("## Entities".into());
    l.push(String::new());
    let mut sorted: Vec<&EntityBrief> = ents.iter().collect();
    sorted.sort_by(|a, b| a.entity_type.cmp(&b.entity_type).then(a.value.cmp(&b.value)));
    if sorted.is_empty() {
        l.push("No entities.".into());
    } else {
        l.push("| Type | Value | Verification | Confidence | Flagged |".into());
        l.push("| --- | --- | --- | --- | --- |".into());
        for e in sorted.iter().take(MAX_ENTITY_ROWS) {
            l.push(format!("| {} | {} | {} | {} | {} |", type_label(&e.entity_type), cell(&e.display_name), e.verification, e.confidence, if e.flagged { "yes" } else { "" }));
        }
        if sorted.len() > MAX_ENTITY_ROWS {
            l.push(String::new());
            l.push(format!("{} more entities are not listed; export the graph as CSV for the full list.", sorted.len() - MAX_ENTITY_ROWS));
        }
    }
    l.push(String::new());

    // relationships
    l.push("## Relationships".into());
    l.push(String::new());
    let mut rsorted: Vec<&RelationshipBrief> = rels.iter().filter(|r| r.verification != "rejected").collect();
    let rank = |v: &str| match v {
        "verified" => 0,
        "observed" => 1,
        "inferred" => 2,
        "disputed" => 3,
        _ => 4,
    };
    rsorted.sort_by(|a, b| rank(&a.verification).cmp(&rank(&b.verification)).then(a.rel_type.cmp(&b.rel_type)).then(a.id.cmp(&b.id)));
    if rsorted.is_empty() {
        l.push("No relationships.".into());
    } else {
        l.push("| Source | Relationship | Target | Status | Confidence | Origin |".into());
        l.push("| --- | --- | --- | --- | --- | --- |".into());
        for r in rsorted.iter().take(MAX_REL_ROWS) {
            l.push(format!("| {} | {} | {} | {} | {} | {} |", name(r.source), cell(&rel_label(&r.rel_type)), name(r.target), r.verification, r.confidence, r.origin));
        }
        if rsorted.len() > MAX_REL_ROWS {
            l.push(String::new());
            l.push(format!("{} more relationships are not listed.", rsorted.len() - MAX_REL_ROWS));
        }
    }
    l.push(String::new());

    // graph overview
    let g = Graph::new(&ents, &rels, false);
    let o = analysis::overview(&g);
    l.push("## Graph analysis".into());
    l.push(String::new());
    l.push(format!("Computed over reviewed and observed relationships ({}); inferred links are excluded.", o.relationships));
    l.push(String::new());
    l.push(format!("- Connected groups: {} (largest has {}).", o.components.iter().filter(|c| c.entities.len() > 1).count(), plural(o.components.first().map_or(0, |c| c.entities.len()), "entity", "entities")));
    l.push(format!("- Entities without relationships: {}.", o.isolated.len()));
    if !o.hubs.is_empty() {
        l.push("- Most connected entities (connectivity is not an indicator of maliciousness):".into());
        for h in o.hubs.iter().take(10) {
            l.push(format!("  - {} — {}", name(h.entity), plural(h.degree, "relationship", "relationships")));
        }
    }
    if !o.shared_infrastructure.is_empty() {
        l.push("- Shared infrastructure:".into());
        for s in o.shared_infrastructure.iter().take(10) {
            l.push(format!("  - {} via {} — {}", name(s.infrastructure), cell(&rel_label(&s.via)), cell(&s.note)));
        }
    }
    l.push(String::new());

    // confidence
    let conf = |v: &str| rels.iter().filter(|r| r.confidence == v && r.verification != "rejected").count();
    l.push("## Confidence".into());
    l.push(String::new());
    l.push(format!("Relationships by confidence: {} high, {} medium, {} low.", conf("high"), conf("medium"), conf("low")));
    l.push(String::new());
    l.push("Confidence is qualitative. High needs direct evidence from at least two independent sources or analyst verification; medium is direct evidence from one source or corroboration from several; low is a single weak or inferred signal. Each relationship stores the reason for its level.".into());
    l.push(String::new());

    // timeline
    let tl = store::timeline(c, inv, &TimelineQuery { limit: MAX_TIMELINE_ROWS as i64, ..Default::default() })?;
    l.push("## Timeline".into());
    l.push(String::new());
    if tl.items.is_empty() {
        l.push("No events.".into());
    } else {
        let mut items = tl.items.clone();
        items.reverse();
        for e in &items {
            l.push(format!("- {} — {}", e.at.get(..16).unwrap_or(&e.at).replace('T', " "), cell(&e.summary)));
        }
        if tl.total as usize > items.len() {
            l.push(format!("- … {} earlier events are not listed.", tl.total as usize - items.len()));
        }
    }
    l.push(String::new());

    // evidence
    l.push("## Evidence".into());
    l.push(String::new());
    if evidence.is_empty() {
        l.push("No evidence.".into());
    } else {
        l.push("| Collected | Source | Strength | Summary | Reference |".into());
        l.push("| --- | --- | --- | --- | --- |".into());
        for e in &evidence {
            // a link only when the whole reference is a plain URL; anything else is escaped text (Mission 7)
            let reference = e.reference.as_deref().map_or_else(|| "—".into(), |r| if plain_url(r) { format!("<{r}>") } else { cell(r) });
            l.push(format!("| {} | {} | {} | {} | {} |", e.collected_at.get(..16).unwrap_or(&e.collected_at).replace('T', " "), cell(&e.source), e.strength, cell(&e.summary), reference));
        }
    }
    l.push(String::new());

    // linked project findings
    if let Some(pid) = i.project_id {
        let mut st = c.prepare("SELECT title, severity, status, affected_target FROM findings WHERE project_id = ?1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id")?;
        let findings = st.query_map(params![pid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?.collect::<Result<Vec<_>, _>>()?;
        l.push("## Findings of the linked project".into());
        l.push(String::new());
        if findings.is_empty() {
            l.push("The linked project has no findings.".into());
        } else {
            l.push("| Title | Severity | Status | Affected |".into());
            l.push("| --- | --- | --- | --- |".into());
            for (t, s, st, a) in findings.iter().take(200) {
                l.push(format!("| {} | {s} | {st} | {} |", cell(t), cell(a)));
            }
        }
        l.push(String::new());
    }

    // limitations and recommendations
    l.push("## Limitations".into());
    l.push(String::new());
    l.push("- Public sources are incomplete and can be stale; absence of data is not evidence of absence.".into());
    l.push("- Shared hosting, DNS and certificate providers serve many unrelated customers, so shared infrastructure alone does not establish common ownership.".into());
    l.push("- Threat-intelligence verdicts are each provider's own assessment at collection time; they are not combined into a score.".into());
    if ver("inferred") > 0 {
        l.push(format!("- {} inferred relationships have not been reviewed.", ver("inferred")));
    }
    l.push(String::new());
    let sugg = suggestions(c, inv)?;
    l.push("## Recommended next steps".into());
    l.push(String::new());
    if sugg.is_empty() {
        l.push("No open review items or collection gaps were found.".into());
    } else {
        for s in sugg.iter().take(15) {
            l.push(format!("- **{}.** {}", cell(&s.title), cell(&s.reason)));
        }
    }
    if !i.notes.trim().is_empty() {
        l.push(String::new());
        l.push("## Analyst notes".into());
        l.push(String::new());
        // as written, but never markup: an imported graph sets them too (Mission 7)
        l.push(crate::workspace::report::md_text(&i.notes));
    }
    l.push(String::new());
    Ok(l.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::osint::ingest::tests::{ent, ev, rel, run};
    use crate::osint::ingest::{Observation, Origin};

    fn setup() -> (Db, i64) {
        let db = Db::open_in_memory().unwrap();
        let inv = db
            .with(|c| {
                let tx = c.unchecked_transaction()?;
                let id = store::investigation_create(&tx, &store::InvestigationInput { name: "Acme | <script>".into(), description: "Scope: public footprint.".into(), target_type: "domain".into(), target_value: "example.com".into(), tags: vec!["q4".into()], notes: String::new(), authorization: String::new(), project_id: None })?;
                tx.commit()?;
                Ok(id)
            })
            .unwrap();
        run(&db, inv, &Observation { evidence: ev("dns", "A records for example.com"), entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34"), ent(EntityType::Domain, "www.example.com")], relationships: vec![rel(0, 1, "RESOLVES_TO"), rel(2, 1, "RESOLVES_TO")] });
        let mut o = Observation { evidence: ev("manual", "note"), entities: vec![ent(EntityType::Organization, "Acme [Corp](javascript:x)"), ent(EntityType::Domain, "example.com")], relationships: vec![rel(1, 0, "OWNED_BY")] };
        o.relationships[0].origin = Origin::Inferred;
        run(&db, inv, &o);
        (db, inv)
    }

    /// Mission 7: fields an imported graph sets (the description, the notes, the target, an
    /// evidence record's source and reference) never become markup: a CommonMark parser finds no
    /// raw HTML and no image in the report.
    #[test]
    fn imported_fields_never_become_markup() {
        let (db, inv) = setup();
        db.with(|c| {
            c.execute(
                "UPDATE osint_investigations SET name = ?2, description = ?3, notes = ?4, target_value = ?5 WHERE id = ?1",
                rusqlite::params![
                    inv,
                    "Acme\n\n<img src=https://x.example/h.png>",
                    "\n\n<img src=https://x.example/d.png>",
                    "`a\nb` <img src=https://x.example/n.png> `c`\n\n![n](https://x.example/n2.png)",
                    "example.com\n\n<img src=https://x.example/t.png>"
                ],
            )?;
            c.execute("UPDATE osint_evidence SET source = 'a` <img src=https://x.example/s.png> `', reference = ?2 WHERE investigation_id = ?1 AND summary = 'note'", rusqlite::params![inv, "https://ok.example/\n![x](https://x.example/r.png)"])?;
            c.execute("UPDATE osint_evidence SET reference = 'https://ok.example/a`b<img src=https://x.example/q.png>' WHERE investigation_id = ?1 AND summary <> 'note'", [inv])?;
            Ok(())
        })
        .unwrap();
        let md = db.with(|c| markdown(c, inv, "2026-11-05")).unwrap();
        assert_eq!(crate::util::commonmark_markup(&md), Vec::<String>::new(), "{md}");
        // a plain URL stays a link
        assert!(plain_url("https://urlhaus.abuse.ch/host/x/") && !plain_url("https://a.example/\n![x](y)") && !plain_url("javascript:alert(1)"));
    }

    #[test]
    fn report_covers_sections_and_escapes_collected_text() {
        let (db, inv) = setup();
        let md = db.with(|c| markdown(c, inv, "2026-11-05")).unwrap();
        for h in ["## Overview", "## Executive summary", "## Methodology and collection", "## Sources", "## Entities", "## Relationships", "## Graph analysis", "## Confidence", "## Timeline", "## Evidence", "## Limitations", "## Recommended next steps"] {
            assert!(md.contains(h), "missing {h}");
        }
        assert!(md.contains("Acme \\| &lt;script&gt;"), "title cell text is escaped in tables: header keeps raw name only in the H1");
        assert!(!md.contains("[Corp](") && md.contains(r"\[Corp\]"), "collected text cannot form links");
        assert!(md.contains("inferred (awaiting review)") && !md.contains(" 0 inferred (awaiting review)"));
        assert!(md.contains("connectivity is not an indicator"));
    }

    #[test]
    fn suggestions_are_deterministic_and_reasoned() {
        let (db, inv) = setup();
        let a = db.with(|c| suggestions(c, inv)).unwrap();
        let b = db.with(|c| suggestions(c, inv)).unwrap();
        assert_eq!(a.iter().map(|s| s.title.clone()).collect::<Vec<_>>(), b.iter().map(|s| s.title.clone()).collect::<Vec<_>>());
        assert!(a.iter().any(|s| s.kind == "review_inferred" && !s.relationship_ids.is_empty()));
        let collect: Vec<&Suggestion> = a.iter().filter(|s| s.kind == "collect").collect();
        assert!(collect.iter().any(|s| s.provider.as_deref() == Some("crtsh")));
        assert!(!collect.iter().any(|s| s.provider.as_deref() == Some("http")), "target-contacting providers need a linked project");
        assert!(a.iter().all(|s| !s.reason.is_empty()));
    }
}
