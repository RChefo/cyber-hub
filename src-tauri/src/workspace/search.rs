//! Search over the records of one project or of every project (docs/DATA_MODEL.md#search):
//! findings, assets, vulnerabilities, evidence, OSINT entities of linked investigations, API
//! endpoints, SBOM components, tool runs, projects, and ATT&CK techniques. Results are references
//! the investigation layer understands, described the same way everywhere, ranked exact match
//! first, then prefix, then substring. Archived projects are searched only when asked.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use super::relations::{Describer, Node, Ref, KINDS};
use crate::error::{validation, AppResult};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    pub text: String,
    /// one project; none: every project
    #[serde(default)]
    pub project_id: Option<i64>,
    /// record kinds (and `project`); empty: all
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub include_archived: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub project_id: Option<i64>,
    pub project: String,
    pub archived: bool,
    pub node: Node,
    /// 3 exact, 2 prefix, 1 substring
    pub score: u8,
}

fn score(hay: &str, needle: &str) -> u8 {
    let h = hay.to_lowercase();
    if h == needle {
        3
    } else if h.starts_with(needle) {
        2
    } else if h.contains(needle) {
        1
    } else {
        0
    }
}

pub fn search(c: &Connection, q: &Query) -> AppResult<Vec<Hit>> {
    let needle = q.text.trim().to_lowercase();
    if needle.chars().count() < 2 {
        return Err(validation("Type at least two characters"));
    }
    if needle.len() > 200 {
        return Err(validation("The search text is too long"));
    }
    if let Some(k) = q.kinds.iter().find(|k| *k != "project" && !KINDS.contains(&k.as_str())) {
        return Err(validation(format!("Unknown record kind '{k}'")));
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let wants = |k: &str| q.kinds.is_empty() || q.kinds.iter().any(|x| x == k);
    let projects: Vec<(i64, String, String)> = c
        .prepare("SELECT id, name, status FROM projects WHERE (?1 IS NULL OR id = ?1) AND (?2 OR status <> 'archived' OR id = ?1) ORDER BY id")?
        .query_map(params![q.project_id, q.include_archived], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    if let Some(p) = q.project_id {
        if !projects.iter().any(|(id, _, _)| *id == p) {
            return Err(crate::error::AppError::NotFound(format!("project {p}")));
        }
    }
    let mut d = Describer::default();
    let mut hits: Vec<Hit> = Vec::new();
    let like = format!("%{}%", needle.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let per_kind = limit;

    for (pid, pname, status) in &projects {
        let archived = status == "archived";
        let add = |hits: &mut Vec<Hit>, d: &mut Describer, r: Ref, hay: &[String]| -> AppResult<()> {
            let s = hay.iter().map(|h| score(h, &needle)).max().unwrap_or(0);
            if s == 0 {
                return Ok(());
            }
            if let Some((_, node)) = d.lookup(c, &r)? {
                hits.push(Hit { project_id: Some(*pid), project: pname.clone(), archived, node, score: s });
            }
            Ok(())
        };
        if wants("project") && score(pname, &needle) > 0 {
            hits.push(Hit {
                project_id: Some(*pid),
                project: pname.clone(),
                archived,
                node: Node { r: Ref::new("project", *pid), key: format!("project:{pid}"), label: pname.clone(), detail: format!("project · {status}"), severity: None, flagged: false },
                score: score(pname, &needle),
            });
        }
        let rows = |sql: &str| -> AppResult<Vec<(i64, Vec<String>)>> {
            let mut st = c.prepare(sql)?;
            let out = st
                .query_map(params![pid, like, per_kind as i64], |r| {
                    let id: i64 = r.get(0)?;
                    let n = r.as_ref().column_count();
                    let mut hay = Vec::with_capacity(n - 1);
                    for i in 1..n {
                        hay.push(r.get::<_, Option<String>>(i)?.unwrap_or_default());
                    }
                    Ok((id, hay))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(out)
        };
        let esc = "ESCAPE '\\'";
        if wants("finding") {
            for (id, hay) in rows(&format!("SELECT id, title, affected_target, cve FROM findings WHERE project_id = ?1 AND (lower(title) LIKE ?2 {esc} OR lower(affected_target) LIKE ?2 {esc} OR lower(cve) LIKE ?2 {esc}) LIMIT ?3"))? {
                add(&mut hits, &mut d, Ref::new("finding", id), &hay)?;
            }
        }
        if wants("asset") {
            for (id, hay) in rows(&format!("SELECT id, value FROM assets WHERE project_id = ?1 AND lower(value) LIKE ?2 {esc} LIMIT ?3"))? {
                add(&mut hits, &mut d, Ref::new("asset", id), &hay)?;
            }
        }
        if wants("vulnerability") {
            for (id, hay) in rows(&format!("SELECT id, cve_id, title FROM vulnerabilities WHERE project_id = ?1 AND (lower(cve_id) LIKE ?2 {esc} OR lower(title) LIKE ?2 {esc}) LIMIT ?3"))? {
                add(&mut hits, &mut d, Ref::new("vulnerability", id), &hay)?;
            }
        }
        if wants("evidence") {
            for (id, hay) in rows(&format!("SELECT id, title, file_name, sha256 FROM evidence WHERE project_id = ?1 AND (lower(title) LIKE ?2 {esc} OR lower(file_name) LIKE ?2 {esc} OR lower(sha256) LIKE ?2 {esc}) LIMIT ?3"))? {
                add(&mut hits, &mut d, Ref::new("evidence", id), &hay)?;
            }
        }
        if wants("osint_entity") {
            for (id, hay) in rows(&format!(
                "SELECT e.id, e.value, e.display_name FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id
                 WHERE i.project_id = ?1 AND (lower(e.value) LIKE ?2 {esc} OR lower(e.display_name) LIKE ?2 {esc}) LIMIT ?3"
            ))? {
                add(&mut hits, &mut d, Ref::new("osint_entity", id), &hay)?;
            }
        }
        if wants("execution") {
            for (id, hay) in rows(&format!("SELECT id, tool_id, program FROM executions WHERE project_id = ?1 AND (lower(tool_id) LIKE ?2 {esc} OR lower(program) LIKE ?2 {esc}) ORDER BY id DESC LIMIT ?3"))? {
                add(&mut hits, &mut d, Ref::new("execution", id), &hay)?;
            }
        }
        if wants("api_endpoint") {
            let specs: Vec<i64> = c.prepare("SELECT id FROM api_specs WHERE project_id = ?1")?.query_map(params![pid], |r| r.get(0))?.collect::<Result<_, _>>()?;
            'specs: for spec in specs {
                let (_, doc) = super::apisec::get(c, spec)?;
                for (i, e) in doc.endpoints.iter().enumerate() {
                    let label = format!("{} {}", e.method, e.path);
                    if score(&label, &needle) > 0 || score(&e.path, &needle) > 0 || score(&e.operation_id, &needle) > 0 {
                        add(&mut hits, &mut d, Ref::sub("api_endpoint", spec, i.to_string()), &[label, e.path.clone(), e.operation_id.clone()])?;
                        if hits.len() > limit * 4 {
                            break 'specs;
                        }
                    }
                }
            }
        }
        if wants("sbom_component") {
            let docs: Vec<i64> = c.prepare("SELECT id FROM sbom_docs WHERE project_id = ?1")?.query_map(params![pid], |r| r.get(0))?.collect::<Result<_, _>>()?;
            'docs: for doc in docs {
                let (_, sbom, _) = super::sbom::get(c, doc)?;
                for (i, comp) in sbom.components.iter().enumerate() {
                    if score(&comp.label(), &needle) > 0 || score(&comp.purl, &needle) > 0 {
                        add(&mut hits, &mut d, Ref::sub("sbom_component", doc, i.to_string()), &[comp.label(), comp.purl.clone()])?;
                        if hits.len() > limit * 4 {
                            break 'docs;
                        }
                    }
                }
            }
        }
    }
    if wants("technique") {
        for t in &super::attack::catalog().techniques {
            let s = score(&t.id, &needle).max(score(&t.name, &needle));
            if s > 0 {
                if let Some((_, node)) = d.lookup(c, &Ref::technique(&t.id))? {
                    hits.push(Hit { project_id: None, project: String::new(), archived: false, node, score: s });
                }
            }
        }
    }
    hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.archived.cmp(&b.archived)).then(a.node.label.len().cmp(&b.node.label.len())).then(a.node.key.cmp(&b.node.key)));
    hits.truncate(limit);
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn search_ranks_and_respects_projects_and_archives() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute_batch(
                "INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Shop', 'active', 't', 't'), (2, 'Old shop', 'archived', 't', 't');
                 INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (1, 'SQL injection in search', 'high', 'new', 'https://shop.example/search', 't', 't');
                 INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (1, 'sql', 'low', 'new', '', 't', 't');
                 INSERT INTO findings (project_id, title, severity, status, affected_target, created_at, updated_at) VALUES (2, 'SQL injection, old', 'high', 'new', '', 't', 't');
                 INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (1, 'subdomain', 'sql.shop.example', 'sql.shop.example', 'x', 't', 't', 't', 't');",
            )?;
            let hits = search(c, &Query { text: "SQL".into(), ..Default::default() })?;
            let labels: Vec<&str> = hits.iter().map(|h| h.node.label.as_str()).collect();
            assert_eq!(labels[0], "sql", "an exact match first");
            assert!(labels.contains(&"SQL injection in search") && labels.contains(&"sql.shop.example"));
            assert!(!labels.contains(&"SQL injection, old"), "archived projects only when asked");
            let all = search(c, &Query { text: "sql".into(), include_archived: true, ..Default::default() })?;
            let old = all.iter().find(|h| h.node.label == "SQL injection, old").unwrap();
            assert!(old.archived && old.project == "Old shop");
            assert_eq!(search(c, &Query { text: "sql".into(), project_id: Some(2), kinds: vec!["finding".into()], ..Default::default() })?.len(), 1, "one project, even archived, when named");
            let t = search(c, &Query { text: "t1059.001".into(), kinds: vec!["technique".into()], ..Default::default() })?;
            assert_eq!(t[0].node.label, "T1059.001 PowerShell");
            let shops = search(c, &Query { text: "shop".into(), kinds: vec!["project".into()], include_archived: true, ..Default::default() })?;
            assert_eq!(shops.iter().map(|h| h.node.label.as_str()).collect::<Vec<_>>(), vec!["Shop", "Old shop"]);
            assert!(search(c, &Query { text: "s".into(), ..Default::default() }).is_err());
            assert!(search(c, &Query { text: "sql".into(), kinds: vec!["widget".into()], ..Default::default() }).is_err());
            assert!(search(c, &Query { text: "100%_".into(), ..Default::default() })?.is_empty(), "wildcards are literal");
            Ok(())
        })
        .unwrap();
    }
}
