//! The detection library (docs/DATA_MODEL.md#detection-engineering-schema-24): rules with their
//! versions, collections, test samples with expectations, test runs, analyst feedback, and per
//! project the matches of rules run on the project's evidence.
//!
//! A match is a lead, not a finding: it is kept as a detection hit until the analyst marks it a
//! false positive, dismisses it, or promotes it to a finding (status "under review"). Rules are
//! organization-wide; hits, feedback and findings belong to projects.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::detection::correlation::{Kind as CorrKind, Resolved, Tree};
use crate::detection::events::{Event, Sample};
use crate::detection::sigma::{self, Checked, Issue};
use crate::detection::yara;
use crate::error::{validation, AppError, AppResult};
use crate::util::now;

/// Matches kept per rule and sample in a test, and per rule and evidence file in a project run.
pub const MAX_MATCHES: usize = 200;
/// A rule matching more than this share of a sample (of at least 20 events) is flagged as broad.
const BROAD_SHARE: f64 = 0.5;

pub fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Splits a YAML stream into its documents (lines that are only `---` separate them).
pub fn documents(text: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    for line in text.lines() {
        if line.trim_end() == "---" {
            out.push(String::new());
        } else {
            let cur = out.last_mut().expect("one document");
            cur.push_str(line);
            cur.push('\n');
        }
    }
    out.into_iter().filter(|d| d.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))).collect()
}

fn sigma_key(c: &Checked) -> String {
    match &c.meta.id {
        Some(id) => id.to_ascii_lowercase(),
        None => format!("{}|{}", c.meta.title.to_lowercase(), c.meta.logsource.label()),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Imported {
    pub id: i64,
    pub title: String,
    /// added, updated (a new version) or unchanged
    pub outcome: &'static str,
    pub version: i64,
    pub errors: usize,
}

/// Adds a Sigma rule document, or a new version of the rule with the same id.
pub fn upsert_sigma(c: &Connection, content: &str, checked: &Checked, source: &str, note: &str) -> AppResult<Imported> {
    if checked.meta.title.trim().is_empty() {
        return Err(validation("A rule needs a title"));
    }
    let key = sigma_key(checked);
    let level = checked.meta.level.clone().unwrap_or_default();
    let status = checked.meta.status.clone().unwrap_or_default();
    let issues = serde_json::to_string(&checked.issues).unwrap_or_else(|_| "[]".into());
    let meta = serde_json::to_string(&checked.meta).unwrap_or_else(|_| "{}".into());
    let row = Fields {
        title: &checked.meta.title,
        status: &status,
        level: &level,
        description: &checked.meta.description,
        author: &checked.meta.author,
        logsource: &checked.meta.logsource.label(),
        techniques: &serde_json::to_string(&checked.meta.techniques).unwrap_or_default(),
        tags: &serde_json::to_string(&checked.meta.tags).unwrap_or_default(),
        meta: &meta,
        issues: &issues,
        runnable: checked.runnable(),
    };
    upsert(c, "sigma", &key, content, &row, source, note, checked.errors())
}

/// The library key of a YARA rule file: its file name. Importing a file of the same name again
/// records a new version when the content changed.
pub fn yara_key(file_name: &str) -> String {
    format!("file:{}", file_name.trim().to_lowercase())
}

/// Adds a YARA rule file, or a new version of the file with the same key. A file that does not
/// compile is kept with its problems and cannot run.
pub fn upsert_yara(c: &Connection, key: &str, file_name: &str, content: &str, checked: &yara::Checked, source: &str, note: &str) -> AppResult<Imported> {
    let m = &checked.meta;
    let title = if m.rules.is_empty() { file_name.trim().to_string() } else { yara::title(m) };
    if title.is_empty() {
        return Err(validation("A YARA file needs a name"));
    }
    let row = Fields {
        title: &title,
        status: "",
        level: &m.level,
        description: &m.description,
        author: &m.author,
        logsource: "files",
        techniques: &serde_json::to_string(&m.techniques).unwrap_or_default(),
        tags: &serde_json::to_string(&m.tags).unwrap_or_default(),
        meta: &serde_json::to_string(m).unwrap_or_else(|_| "{}".into()),
        issues: &serde_json::to_string(&checked.issues).unwrap_or_else(|_| "[]".into()),
        runnable: checked.scanner.is_some(),
    };
    upsert(c, "yara", key, content, &row, source, note, checked.errors())
}

/// The stored fields of a rule.
pub struct Fields<'a> {
    pub title: &'a str,
    pub status: &'a str,
    pub level: &'a str,
    pub description: &'a str,
    pub author: &'a str,
    pub logsource: &'a str,
    pub techniques: &'a str,
    pub tags: &'a str,
    pub meta: &'a str,
    pub issues: &'a str,
    pub runnable: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn upsert(c: &Connection, kind: &str, key: &str, content: &str, f: &Fields, source: &str, note: &str, errors: usize) -> AppResult<Imported> {
    let sha = sha256(content);
    let ts = now();
    let tx = c.unchecked_transaction()?;
    let existing: Option<(i64, String, i64)> = tx.query_row("SELECT id, sha256, version FROM detection_rules WHERE kind = ?1 AND rule_key = ?2", params![kind, key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
    let out = match existing {
        Some((id, old, version)) if old == sha => Imported { id, title: f.title.into(), outcome: "unchanged", version, errors },
        Some((id, _, version)) => {
            let v = version + 1;
            tx.execute(
                "UPDATE detection_rules SET title=?2, status=?3, level=?4, description=?5, author=?6, logsource=?7, techniques=?8, tags=?9, meta=?10, issues=?11, runnable=?12, content=?13, sha256=?14, version=?15, source=?16, updated_at=?17 WHERE id=?1",
                params![id, f.title, f.status, f.level, f.description, f.author, f.logsource, f.techniques, f.tags, f.meta, f.issues, f.runnable, content, sha, v, source, ts],
            )?;
            tx.execute("INSERT INTO detection_rule_versions (rule_id, version, content, sha256, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![id, v, content, sha, note.trim(), ts])?;
            Imported { id, title: f.title.into(), outcome: "updated", version: v, errors }
        }
        None => {
            tx.execute(
                "INSERT INTO detection_rules (kind, rule_key, title, status, level, description, author, logsource, techniques, tags, meta, issues, runnable, content, sha256, version, source, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 1, ?16, ?17, ?17)",
                params![kind, key, f.title, f.status, f.level, f.description, f.author, f.logsource, f.techniques, f.tags, f.meta, f.issues, f.runnable, content, sha, source, ts],
            )?;
            let id = tx.last_insert_rowid();
            tx.execute("INSERT INTO detection_rule_versions (rule_id, version, content, sha256, note, created_at) VALUES (?1, 1, ?2, ?3, ?4, ?5)", params![id, content, sha, if note.trim().is_empty() { "Imported" } else { note.trim() }, ts])?;
            Imported { id, title: f.title.into(), outcome: "added", version: 1, errors }
        }
    };
    tx.commit()?;
    Ok(out)
}

/* ───────────────────────── reading ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleSummary {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub level: String,
    pub logsource: String,
    pub techniques: Vec<String>,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub runnable: bool,
    pub version: i64,
    pub source: String,
    pub updated_at: String,
    pub errors: usize,
    pub warnings: usize,
    pub collections: Vec<i64>,
    /// the last test of each sample with an expectation: passing and failing samples
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub false_positives: i64,
    pub hits: i64,
}

const SUMMARY_COLS: &str = "r.id, r.kind, r.title, r.status, r.level, r.logsource, r.techniques, r.tags, r.enabled, r.runnable, r.version, r.source, r.updated_at, r.issues,
    (SELECT COUNT(*) FROM detection_feedback f WHERE f.rule_id = r.id AND f.verdict = 'false_positive'),
    (SELECT COUNT(*) FROM detection_hits h WHERE h.rule_id = r.id AND h.status IN ('new','promoted')),
    (SELECT group_concat(collection_id) FROM detection_collection_rules cr WHERE cr.rule_id = r.id)";

fn summary_row(r: &rusqlite::Row) -> rusqlite::Result<RuleSummary> {
    let issues: Vec<Issue> = serde_json::from_str(&r.get::<_, String>(13)?).unwrap_or_default();
    Ok(RuleSummary {
        id: r.get(0)?,
        kind: r.get(1)?,
        title: r.get(2)?,
        status: r.get(3)?,
        level: r.get(4)?,
        logsource: r.get(5)?,
        techniques: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
        tags: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
        enabled: r.get(8)?,
        runnable: r.get(9)?,
        version: r.get(10)?,
        source: r.get(11)?,
        updated_at: r.get(12)?,
        errors: issues.iter().filter(|i| i.level != "warning").count(),
        warnings: issues.iter().filter(|i| i.level == "warning").count(),
        false_positives: r.get(14)?,
        hits: r.get(15)?,
        collections: r.get::<_, Option<String>>(16)?.unwrap_or_default().split(',').filter_map(|x| x.parse().ok()).collect(),
        tests_passed: 0,
        tests_failed: 0,
    })
}

/// Passing and failing samples (the last test of each sample with an expectation).
fn test_state(c: &Connection, rule_id: i64) -> AppResult<(usize, usize)> {
    let mut st = c.prepare(
        "SELECT t.passed FROM detection_rule_samples s JOIN detection_tests t ON t.id = (SELECT MAX(id) FROM detection_tests WHERE rule_id = s.rule_id AND sample_id = s.sample_id)
         WHERE s.rule_id = ?1 AND s.expect <> 'none' AND t.passed IS NOT NULL",
    )?;
    let rows: Vec<bool> = st.query_map(params![rule_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok((rows.iter().filter(|p| **p).count(), rows.iter().filter(|p| !**p).count()))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFilter {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub technique: Option<String>,
    #[serde(default)]
    pub collection: Option<i64>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub items: Vec<RuleSummary>,
    pub total: i64,
}

pub fn list(c: &Connection, f: &ListFilter) -> AppResult<Page> {
    let text = f.text.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(|t| t.to_lowercase());
    let technique = f.technique.as_deref().map(|t| format!("\"{}\"", t.trim().to_ascii_uppercase()));
    let wheres = "(?1 IS NULL OR r.kind = ?1) AND (?2 IS NULL OR instr(lower(r.title || ' ' || r.description || ' ' || r.tags || ' ' || r.logsource), ?2) > 0)
        AND (?3 IS NULL OR r.enabled = ?3) AND (?4 IS NULL OR instr(r.techniques, ?4) > 0)
        AND (?5 IS NULL OR EXISTS (SELECT 1 FROM detection_collection_rules cr WHERE cr.rule_id = r.id AND cr.collection_id = ?5)) AND (?6 IS NULL OR r.level = ?6)";
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM detection_rules r WHERE {wheres}"), params![f.kind, text, f.enabled, technique, f.collection, f.level], |r| r.get(0))?;
    let limit = f.limit.unwrap_or(100).clamp(1, 500);
    let offset = f.offset.unwrap_or(0).max(0);
    let mut st = c.prepare(&format!(
        "SELECT {SUMMARY_COLS} FROM detection_rules r WHERE {wheres}
         ORDER BY CASE r.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, r.title LIMIT ?7 OFFSET ?8"
    ))?;
    let mut items: Vec<RuleSummary> = st.query_map(params![f.kind, text, f.enabled, technique, f.collection, f.level, limit, offset], summary_row)?.collect::<Result<_, _>>()?;
    for it in &mut items {
        (it.tests_passed, it.tests_failed) = test_state(c, it.id)?;
    }
    Ok(Page { items, total })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VersionRow {
    pub version: i64,
    pub sha256: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TestRow {
    pub id: i64,
    pub version: i64,
    pub sample_id: i64,
    pub expect: String,
    pub events: i64,
    pub matched: i64,
    pub passed: Option<bool>,
    pub ran_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleSample {
    pub sample_id: i64,
    pub file_name: String,
    pub kind: String,
    pub events: i64,
    pub sha256: String,
    pub expect: String,
    pub last: Option<TestRow>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Feedback {
    pub id: i64,
    pub project_id: Option<i64>,
    pub project: String,
    pub verdict: String,
    pub note: String,
    pub event: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectUse {
    pub project_id: i64,
    pub project: String,
    pub hits: i64,
    pub findings: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleDetail {
    pub summary: RuleSummary,
    pub content: String,
    pub meta: Value,
    pub issues: Vec<Issue>,
    pub versions: Vec<VersionRow>,
    pub samples: Vec<RuleSample>,
    pub feedback: Vec<Feedback>,
    pub projects: Vec<ProjectUse>,
}

fn test_row(r: &rusqlite::Row) -> rusqlite::Result<TestRow> {
    Ok(TestRow { id: r.get(0)?, version: r.get(1)?, sample_id: r.get(2)?, expect: r.get(3)?, events: r.get(4)?, matched: r.get(5)?, passed: r.get(6)?, ran_at: r.get(7)? })
}

pub fn get(c: &Connection, id: i64) -> AppResult<RuleDetail> {
    let mut summary = c.query_row(&format!("SELECT {SUMMARY_COLS} FROM detection_rules r WHERE r.id = ?1"), params![id], summary_row).optional()?.ok_or_else(|| AppError::NotFound(format!("detection rule {id}")))?;
    (summary.tests_passed, summary.tests_failed) = test_state(c, id)?;
    let (content, meta, issues): (String, String, String) = c.query_row("SELECT content, meta, issues FROM detection_rules WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let versions = c
        .prepare("SELECT version, sha256, note, created_at FROM detection_rule_versions WHERE rule_id = ?1 ORDER BY version DESC")?
        .query_map(params![id], |r| Ok(VersionRow { version: r.get(0)?, sha256: r.get(1)?, note: r.get(2)?, created_at: r.get(3)? }))?
        .collect::<Result<_, _>>()?;
    let mut samples: Vec<RuleSample> = c
        .prepare("SELECT s.id, s.file_name, s.kind, s.events, s.sha256, rs.expect FROM detection_rule_samples rs JOIN detection_samples s ON s.id = rs.sample_id WHERE rs.rule_id = ?1 ORDER BY s.id")?
        .query_map(params![id], |r| Ok(RuleSample { sample_id: r.get(0)?, file_name: r.get(1)?, kind: r.get(2)?, events: r.get(3)?, sha256: r.get(4)?, expect: r.get(5)?, last: None }))?
        .collect::<Result<_, _>>()?;
    for s in &mut samples {
        s.last = c
            .query_row("SELECT id, version, sample_id, expect, events, matched, passed, ran_at FROM detection_tests WHERE rule_id = ?1 AND sample_id = ?2 ORDER BY id DESC LIMIT 1", params![id, s.sample_id], test_row)
            .optional()?;
    }
    let feedback = c
        .prepare("SELECT f.id, f.project_id, COALESCE(p.name, ''), f.verdict, f.note, f.event, f.created_at FROM detection_feedback f LEFT JOIN projects p ON p.id = f.project_id WHERE f.rule_id = ?1 ORDER BY f.id DESC LIMIT 100")?
        .query_map(params![id], |r| Ok(Feedback { id: r.get(0)?, project_id: r.get(1)?, project: r.get(2)?, verdict: r.get(3)?, note: r.get(4)?, event: r.get(5)?, created_at: r.get(6)? }))?
        .collect::<Result<_, _>>()?;
    let projects = c
        .prepare("SELECT h.project_id, p.name, COUNT(*), COUNT(h.finding_id) FROM detection_hits h JOIN projects p ON p.id = h.project_id WHERE h.rule_id = ?1 AND h.status IN ('new','promoted') GROUP BY h.project_id ORDER BY 3 DESC")?
        .query_map(params![id], |r| Ok(ProjectUse { project_id: r.get(0)?, project: r.get(1)?, hits: r.get(2)?, findings: r.get(3)? }))?
        .collect::<Result<_, _>>()?;
    Ok(RuleDetail { summary, content, meta: serde_json::from_str(&meta).unwrap_or(Value::Null), issues: serde_json::from_str(&issues).unwrap_or_default(), versions, samples, feedback, projects })
}

pub fn version_content(c: &Connection, id: i64, version: i64) -> AppResult<String> {
    c.query_row("SELECT content FROM detection_rule_versions WHERE rule_id = ?1 AND version = ?2", params![id, version], |r| r.get(0)).optional()?.ok_or_else(|| AppError::NotFound(format!("version {version} of rule {id}")))
}

pub fn set_enabled(c: &Connection, id: i64, enabled: bool) -> AppResult<()> {
    if c.execute("UPDATE detection_rules SET enabled = ?2, updated_at = ?3 WHERE id = ?1", params![id, enabled, now()])? == 0 {
        return Err(AppError::NotFound(format!("detection rule {id}")));
    }
    Ok(())
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    c.execute("DELETE FROM detection_rules WHERE id = ?1", params![id])?;
    Ok(())
}

/* ───────────────────────── collections ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub rules: i64,
}

pub fn collections(c: &Connection) -> AppResult<Vec<Collection>> {
    Ok(c.prepare("SELECT id, name, description, (SELECT COUNT(*) FROM detection_collection_rules WHERE collection_id = c.id) FROM detection_collections c ORDER BY name")?
        .query_map([], |r| Ok(Collection { id: r.get(0)?, name: r.get(1)?, description: r.get(2)?, rules: r.get(3)? }))?
        .collect::<Result<_, _>>()?)
}

pub fn collection_create(c: &Connection, name: &str, description: &str) -> AppResult<i64> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(validation("A collection name has 1 to 100 characters"));
    }
    if c.query_row("SELECT 1 FROM detection_collections WHERE lower(name) = lower(?1)", params![name], |_| Ok(())).optional()?.is_some() {
        return Err(validation(format!("A collection named “{name}” exists")));
    }
    c.execute("INSERT INTO detection_collections (name, description, created_at) VALUES (?1, ?2, ?3)", params![name, description.trim().chars().take(2000).collect::<String>(), now()])?;
    Ok(c.last_insert_rowid())
}

pub fn collection_delete(c: &Connection, id: i64) -> AppResult<()> {
    c.execute("DELETE FROM detection_collections WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn collection_member(c: &Connection, collection_id: i64, rule_id: i64, member: bool) -> AppResult<()> {
    if member {
        c.execute("INSERT OR IGNORE INTO detection_collection_rules (collection_id, rule_id) VALUES (?1, ?2)", params![collection_id, rule_id])?;
    } else {
        c.execute("DELETE FROM detection_collection_rules WHERE collection_id = ?1 AND rule_id = ?2", params![collection_id, rule_id])?;
    }
    Ok(())
}

/* ───────────────────────── samples and tests ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SampleRow {
    pub id: i64,
    pub sha256: String,
    pub file_name: String,
    pub kind: String,
    pub size: i64,
    pub events: i64,
    pub added_at: String,
}

pub fn sample_add(c: &Connection, sha: &str, file_name: &str, kind: &str, size: i64, events: i64) -> AppResult<i64> {
    if let Some((id, old)) = c.query_row("SELECT id, kind FROM detection_samples WHERE sha256 = ?1", params![sha], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).optional()? {
        // the same file added again as a log: Sigma rules can use it too
        if old == "file" && kind != "file" {
            c.execute("UPDATE detection_samples SET kind = ?2, events = ?3 WHERE id = ?1", params![id, kind, events])?;
        }
        return Ok(id);
    }
    c.execute("INSERT INTO detection_samples (sha256, file_name, kind, size, events, added_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![sha, file_name, kind, size, events, now()])?;
    Ok(c.last_insert_rowid())
}

pub fn samples(c: &Connection) -> AppResult<Vec<SampleRow>> {
    Ok(c.prepare("SELECT id, sha256, file_name, kind, size, events, added_at FROM detection_samples ORDER BY id DESC")?
        .query_map([], |r| Ok(SampleRow { id: r.get(0)?, sha256: r.get(1)?, file_name: r.get(2)?, kind: r.get(3)?, size: r.get(4)?, events: r.get(5)?, added_at: r.get(6)? }))?
        .collect::<Result<_, _>>()?)
}

pub fn sample(c: &Connection, id: i64) -> AppResult<SampleRow> {
    c.query_row("SELECT id, sha256, file_name, kind, size, events, added_at FROM detection_samples WHERE id = ?1", params![id], |r| {
        Ok(SampleRow { id: r.get(0)?, sha256: r.get(1)?, file_name: r.get(2)?, kind: r.get(3)?, size: r.get(4)?, events: r.get(5)?, added_at: r.get(6)? })
    })
    .optional()?
    .ok_or_else(|| AppError::NotFound(format!("sample {id}")))
}

/// Records what a rule should do on a sample: match, not match, or nothing said.
pub fn set_expect(c: &Connection, rule_id: i64, sample_id: i64, expect: &str) -> AppResult<()> {
    if !["none", "match", "no_match"].contains(&expect) {
        return Err(validation("An expectation is none, match or no_match"));
    }
    c.execute(
        "INSERT INTO detection_rule_samples (rule_id, sample_id, expect) VALUES (?1, ?2, ?3) ON CONFLICT (rule_id, sample_id) DO UPDATE SET expect = excluded.expect",
        params![rule_id, sample_id, expect],
    )?;
    Ok(())
}

/// One matching event, as kept: its place, time, fields (cut) and the explanation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub position: String,
    pub time: String,
    pub label: String,
    pub fields: Vec<(String, String)>,
    /// a Sigma explanation (selections), or a YARA one (`"kind": "yara"`, strings and offsets)
    pub explanation: Value,
}

pub fn event_summary(ev: &Event) -> Vec<(String, String)> {
    ev.fields.iter().take(40).map(|(k, v)| (k.clone(), if v.chars().count() > 300 { format!("{}…", v.chars().take(300).collect::<String>()) } else { v.clone() })).collect()
}

/// What a rule did on a sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub events: usize,
    /// events in the rule's log source (all events when it is not mapped)
    pub in_source: usize,
    pub matched: usize,
    pub matches: Vec<Match>,
    /// notes for the analyst: an unmapped log source, a broad rule, a cut sample
    pub notes: Vec<String>,
}

/// Runs a compiled rule over a sample.
pub fn run(rule: &sigma::Rule, sample: &Sample) -> RunResult {
    let mut out = RunResult { events: sample.events.len(), in_source: 0, matched: 0, matches: Vec::new(), notes: sample.warnings.clone() };
    for ev in &sample.events {
        if rule.in_source(ev) {
            out.in_source += 1;
        }
        if let Some(x) = rule.evaluate(ev) {
            out.matched += 1;
            if out.matches.len() < MAX_MATCHES {
                out.matches.push(Match { position: ev.position.clone(), time: ev.time.clone(), label: ev.label(), fields: event_summary(ev), explanation: serde_json::to_value(&x).unwrap_or(Value::Null) });
            }
        }
    }
    if let sigma::SourceCheck::Unmapped { reason } = &rule.source {
        out.notes.push(format!("Log source: {reason}"));
    }
    if out.in_source >= 20 && out.matched as f64 / out.in_source as f64 > BROAD_SHARE {
        out.notes.push(format!("The rule matched {} of {} events of its log source ({:.0}%): it may be too broad to be useful", out.matched, out.in_source, 100.0 * out.matched as f64 / out.in_source as f64));
    }
    if sample.truncated {
        out.notes.push(format!("Only the first {} events of the sample were read", crate::detection::events::MAX_EVENTS));
    }
    if out.matched > MAX_MATCHES {
        out.notes.push(format!("{} matches; the first {MAX_MATCHES} are listed", out.matched));
    }
    out
}

/// What YARA rules did on one file: each rule that matched is a match, placed by its name.
pub fn yara_result(scan: &yara::Scan, file: &str) -> RunResult {
    let matches: Vec<Match> = scan
        .matches
        .iter()
        .map(|m| {
            let strings: usize = m.strings.iter().map(|s| s.count).sum();
            let mut fields = vec![("file".to_string(), file.to_string()), ("rule".to_string(), m.rule.clone())];
            if !m.tags.is_empty() {
                fields.push(("tags".into(), m.tags.join(", ")));
            }
            fields.extend(m.metas.iter().take(20).map(|(k, v)| (format!("meta.{k}"), v.chars().take(300).collect())));
            Match {
                position: format!("rule {}", m.rule),
                time: String::new(),
                label: if strings == 0 { format!("{} (its condition holds without strings)", m.rule) } else { format!("{} ({} string match{})", m.rule, strings, if strings == 1 { "" } else { "es" }) },
                fields,
                explanation: yara::explanation(m),
            }
        })
        .collect();
    let mut notes = Vec::new();
    if scan.timed_out {
        notes.push(format!("The scan stopped after {} s: rules that would have matched later are missing", yara::SCAN_TIMEOUT.as_secs()));
    }
    if scan.more > 0 {
        notes.push(format!("{} more rules matched; the first {} are listed", scan.more, matches.len()));
    }
    RunResult { events: 1, in_source: 1, matched: matches.len() + scan.more, matches, notes }
}

/// Stores a test run. A test passes when it does what the sample's expectation says.
pub fn record_test(c: &Connection, rule_id: i64, version: i64, sample_id: i64, r: &RunResult) -> AppResult<TestRow> {
    let expect: String = c.query_row("SELECT expect FROM detection_rule_samples WHERE rule_id = ?1 AND sample_id = ?2", params![rule_id, sample_id], |r| r.get(0)).optional()?.unwrap_or_else(|| "none".into());
    let passed = match expect.as_str() {
        "match" => Some(r.matched > 0),
        "no_match" => Some(r.matched == 0),
        _ => None,
    };
    if c.query_row("SELECT 1 FROM detection_rule_samples WHERE rule_id = ?1 AND sample_id = ?2", params![rule_id, sample_id], |_| Ok(())).optional()?.is_none() {
        set_expect(c, rule_id, sample_id, "none")?;
    }
    let keep = RunResult { matches: r.matches.iter().take(50).cloned().collect(), ..r.clone() };
    c.execute(
        "INSERT INTO detection_tests (rule_id, version, sample_id, expect, events, matched, passed, result, ran_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![rule_id, version, sample_id, expect, r.events as i64, r.matched as i64, passed, serde_json::to_string(&keep).unwrap_or_default(), now()],
    )?;
    let id = c.last_insert_rowid();
    Ok(c.query_row("SELECT id, version, sample_id, expect, events, matched, passed, ran_at FROM detection_tests WHERE id = ?1", params![id], test_row)?)
}

/// The stored rule for a run: its kind, id, version, title, level, techniques and content.
pub struct Stored {
    pub kind: String,
    pub id: i64,
    pub version: i64,
    pub title: String,
    pub level: String,
    pub techniques: Vec<String>,
    pub content: String,
}

pub fn stored(c: &Connection, id: i64) -> AppResult<Stored> {
    c.query_row("SELECT id, version, title, level, techniques, content, kind FROM detection_rules WHERE id = ?1", params![id], |r| {
        Ok(Stored { id: r.get(0)?, version: r.get(1)?, title: r.get(2)?, level: r.get(3)?, techniques: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(), content: r.get(5)?, kind: r.get(6)? })
    })
    .optional()?
    .ok_or_else(|| AppError::NotFound(format!("detection rule {id}")))
}

/// The enabled rules that can run, Sigma and YARA (of one collection when given).
pub fn runnable(c: &Connection, collection: Option<i64>) -> AppResult<Vec<Stored>> {
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM detection_rules r WHERE enabled = 1 AND runnable = 1 AND (?1 IS NULL OR EXISTS (SELECT 1 FROM detection_collection_rules cr WHERE cr.rule_id = r.id AND cr.collection_id = ?1)) ORDER BY id")?
        .query_map(params![collection], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    ids.into_iter().map(|id| stored(c, id)).collect()
}

/// Compiles a stored Sigma rule (it was valid when stored; a failure here means the content is
/// no longer runnable).
pub fn compile(s: &Stored) -> AppResult<sigma::Rule> {
    if s.kind != "sigma" {
        return Err(validation(format!("“{}” is not a Sigma rule", s.title)));
    }
    let mut v = sigma::read(&s.content).map_err(validation)?;
    let c = v.pop().ok_or_else(|| validation("The rule is empty"))?;
    c.rule.ok_or_else(|| validation(format!("“{}” cannot run: {}", s.title, c.issues.iter().filter(|i| i.level != "warning").map(|i| i.message.as_str()).collect::<Vec<_>>().join("; "))))
}

/* ───────────────────────── correlations ───────────────────────── */

fn read_one(content: &str) -> AppResult<Checked> {
    sigma::read(content).map_err(validation)?.pop().ok_or_else(|| validation("The rule is empty"))
}

/// The Sigma library entry a correlation refers to: by the `name` its file gives it, or by its
/// `id` (without regard to case). When several entries share a name, the one imported from the
/// correlation's own file wins; otherwise the reference is ambiguous and refused.
fn find_ref(c: &Connection, reference: &str, source: &str) -> AppResult<Stored> {
    let found: Vec<(i64, String)> = c
        .prepare("SELECT id, source FROM detection_rules WHERE kind = 'sigma' AND (json_extract(meta, '$.name') = ?1 OR lower(COALESCE(json_extract(meta, '$.id'), '')) = lower(?1)) ORDER BY id")?
        .query_map(params![reference.trim()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let id = match found.as_slice() {
        [] => return Err(validation(format!("No Sigma rule named or identified '{reference}' is in the library: import the rules it correlates"))),
        [(id, _)] => *id,
        many => {
            let same: Vec<i64> = many.iter().filter(|(_, s)| s == source).map(|(id, _)| *id).collect();
            match same.as_slice() {
                [id] => *id,
                _ => return Err(validation(format!("Several rules in the library are named '{reference}': refer to the rule by its id"))),
            }
        }
    };
    stored(c, id)
}

/// A correlation rule with everything it refers to, resolved in the library, or None for a
/// detection rule. The rules it refers to run as part of it even when they are disabled (a
/// correlation's rules are not run on their own unless it says `generate: true`).
pub fn correlation_tree(c: &Connection, s: &Stored) -> AppResult<Option<Tree>> {
    if s.kind != "sigma" {
        return Ok(None);
    }
    let Some(corr) = read_one(&s.content)?.correlation else {
        return Ok(None);
    };
    let source: String = c.query_row("SELECT source FROM detection_rules WHERE id = ?1", params![s.id], |r| r.get(0))?;
    let mut resolve = |r: &str| -> Result<Resolved, String> {
        let st = find_ref(c, r, &source).map_err(|e| e.to_string())?;
        let ch = read_one(&st.content).map_err(|e| e.to_string())?;
        if let Some(correlation) = ch.correlation {
            return Ok(Resolved::Correlation { key: format!("rule:{}", st.id), title: st.title, correlation });
        }
        match ch.rule {
            Some(rule) => Ok(Resolved::Rule { title: st.title, rule: Box::new(rule) }),
            None => Err(format!("“{}”, which it refers to, cannot run: {}", st.title, ch.issues.iter().filter(|i| i.level != "warning").map(|i| i.message.as_str()).collect::<Vec<_>>().join("; "))),
        }
    };
    Tree::build(&format!("rule:{}", s.id), corr, &mut resolve).map(Some).map_err(validation)
}

/// A finished correlation: every match with the evidence (or sample) of its last event.
pub struct CorrelationRun {
    pub matched: usize,
    pub matches: Vec<(i64, Match)>,
    pub notes: Vec<String>,
}

pub fn finish_correlation(tree: Tree) -> CorrelationRun {
    let corr = tree.correlation().clone();
    let titles = tree.titles().to_vec();
    let out = tree.finish();
    let measure = match corr.kind {
        CorrKind::EventCount => "events",
        CorrKind::ValueCount => "distinct values",
        CorrKind::ValueSum => "sum",
        CorrKind::ValueAvg => "average",
        CorrKind::Temporal | CorrKind::TemporalOrdered => "rules matched",
    };
    let matches = out
        .found
        .iter()
        .map(|f| {
            let group = f.group.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
            let mut fields: Vec<(String, String)> = f.group.clone();
            fields.push((measure.to_string(), format!("{}", f.value)));
            let label = format!("{} · {} event{} · {}", if group.is_empty() { "all events".to_string() } else { group }, f.total, if f.total == 1 { "" } else { "s" }, corr.condition_text());
            (f.source_id(), Match { position: f.position(), time: f.last.clone(), label, fields, explanation: f.explanation(&corr, &titles) })
        })
        .collect();
    CorrelationRun { matched: out.matched, matches, notes: out.notes }
}

/// A correlation run on one sample, as a test result.
pub fn correlation_result(mut tree: Tree, sample: &Sample, sample_id: i64, file_name: &str) -> RunResult {
    tree.feed(sample, sample_id, file_name);
    let r = finish_correlation(tree);
    let mut notes = sample.warnings.clone();
    notes.extend(r.notes);
    if sample.truncated {
        notes.push(format!("Only the first {} events of the sample were read", crate::detection::events::MAX_EVENTS));
    }
    if r.matched > MAX_MATCHES {
        notes.push(format!("{} matches; the first {MAX_MATCHES} are listed", r.matched));
    }
    RunResult { events: sample.events.len(), in_source: sample.events.len(), matched: r.matched, matches: r.matches.into_iter().take(MAX_MATCHES).map(|(_, m)| m).collect(), notes }
}

/// When a file's correlations refer to rules of the same file and do not say `generate: true`,
/// those rules only run as part of the correlation (the specification's default): the ones this
/// import added are disabled, inner correlations of a chain included (otherwise each would also
/// report its own matches). Returns their titles.
pub fn disable_correlated(c: &Connection, docs: &[(Checked, Imported)]) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for (corr, _) in docs.iter().filter(|(ch, _)| ch.correlation.as_ref().is_some_and(|c| !c.generate)) {
        let refs = &corr.correlation.as_ref().expect("filtered").rules;
        for (ch, imp) in docs {
            let named = ch.meta.name.as_ref().is_some_and(|n| refs.contains(n)) || ch.meta.id.as_ref().is_some_and(|id| refs.iter().any(|r| r.eq_ignore_ascii_case(id)));
            let itself = std::ptr::eq(ch, corr);
            if named && !itself && imp.outcome == "added" && !out.contains(&imp.title) {
                set_enabled(c, imp.id, false)?;
                out.push(imp.title.clone());
            }
        }
    }
    Ok(out)
}

/// Compiles a stored YARA rule file on its own.
pub fn compile_yara(s: &Stored) -> AppResult<boreal::Scanner> {
    if s.kind != "yara" {
        return Err(validation(format!("“{}” is not a YARA rule file", s.title)));
    }
    let c = yara::check(&s.content);
    c.scanner.ok_or_else(|| validation(format!("“{}” cannot run: {}", s.title, c.issues.iter().filter(|i| i.level == "error").map(|i| i.message.as_str()).collect::<Vec<_>>().join("; "))))
}

/* ───────────────────────── feedback ───────────────────────── */

pub fn feedback_add(c: &Connection, rule_id: i64, project_id: Option<i64>, verdict: &str, note: &str, event: &str) -> AppResult<i64> {
    if !["false_positive", "true_positive", "note"].contains(&verdict) {
        return Err(validation("Feedback is false_positive, true_positive or note"));
    }
    stored_exists(c, rule_id)?;
    c.execute(
        "INSERT INTO detection_feedback (rule_id, project_id, verdict, note, event, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![rule_id, project_id, verdict, note.trim().chars().take(4000).collect::<String>(), event.chars().take(4000).collect::<String>(), now()],
    )?;
    Ok(c.last_insert_rowid())
}

fn stored_exists(c: &Connection, id: i64) -> AppResult<()> {
    c.query_row("SELECT 1 FROM detection_rules WHERE id = ?1", params![id], |_| Ok(())).optional()?.ok_or_else(|| AppError::NotFound(format!("detection rule {id}")))
}

/* ───────────────────────── project hits ───────────────────────── */

/// Stores the matches of one rule on one evidence file of a project; returns (new, already known).
pub fn hits_store(c: &Connection, project_id: i64, rule: &Stored, evidence_id: i64, matches: &[Match]) -> AppResult<(usize, usize)> {
    let ts = now();
    let mut new = 0;
    let mut known = 0;
    for m in matches {
        let added = c.execute(
            "INSERT OR IGNORE INTO detection_hits (project_id, rule_id, rule_title, rule_version, rule_level, techniques, evidence_id, position, event_time, event, explanation, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                project_id,
                rule.id,
                rule.title,
                rule.version,
                rule.level,
                serde_json::to_string(&rule.techniques).unwrap_or_default(),
                evidence_id,
                m.position,
                m.time,
                serde_json::to_string(&json!({ "label": m.label, "fields": m.fields })).unwrap_or_default(),
                serde_json::to_string(&m.explanation).unwrap_or_default(),
                ts
            ],
        )?;
        if added == 1 {
            new += 1;
        } else {
            known += 1;
        }
    }
    Ok((new, known))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HitRow {
    pub id: i64,
    pub rule_id: Option<i64>,
    pub rule_title: String,
    pub rule_version: i64,
    pub rule_level: String,
    pub techniques: Vec<String>,
    pub evidence_id: Option<i64>,
    pub evidence: String,
    pub position: String,
    pub event_time: String,
    pub event: Value,
    pub explanation: Value,
    pub status: String,
    pub finding_id: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HitFilter {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub rule_id: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HitPage {
    pub items: Vec<HitRow>,
    pub total: i64,
    /// per status
    pub counts: BTreeMap<String, i64>,
}

const HIT_COLS: &str = "h.id, h.rule_id, h.rule_title, h.rule_version, h.rule_level, h.techniques, h.evidence_id, COALESCE(e.title, ''), h.position, h.event_time, h.event, h.explanation, h.status, h.finding_id, h.created_at";

fn hit_row(r: &rusqlite::Row) -> rusqlite::Result<HitRow> {
    Ok(HitRow {
        id: r.get(0)?,
        rule_id: r.get(1)?,
        rule_title: r.get(2)?,
        rule_version: r.get(3)?,
        rule_level: r.get(4)?,
        techniques: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        evidence_id: r.get(6)?,
        evidence: r.get(7)?,
        position: r.get(8)?,
        event_time: r.get(9)?,
        event: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or(Value::Null),
        explanation: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or(Value::Null),
        status: r.get(12)?,
        finding_id: r.get(13)?,
        created_at: r.get(14)?,
    })
}

pub fn hits_list(c: &Connection, project_id: i64, f: &HitFilter) -> AppResult<HitPage> {
    let wheres = "h.project_id = ?1 AND (?2 IS NULL OR h.status = ?2) AND (?3 IS NULL OR h.rule_id = ?3)";
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM detection_hits h WHERE {wheres}"), params![project_id, f.status, f.rule_id], |r| r.get(0))?;
    let mut st = c.prepare(&format!(
        "SELECT {HIT_COLS} FROM detection_hits h LEFT JOIN evidence e ON e.id = h.evidence_id WHERE {wheres}
         ORDER BY CASE h.rule_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, h.id LIMIT ?4 OFFSET ?5"
    ))?;
    let items = st.query_map(params![project_id, f.status, f.rule_id, f.limit.unwrap_or(100).clamp(1, 500), f.offset.unwrap_or(0).max(0)], hit_row)?.collect::<Result<_, _>>()?;
    let counts = c.prepare("SELECT status, COUNT(*) FROM detection_hits WHERE project_id = ?1 GROUP BY status")?.query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(HitPage { items, total, counts })
}

fn hit(c: &Connection, id: i64) -> AppResult<HitRow> {
    c.query_row(&format!("SELECT {HIT_COLS} FROM detection_hits h LEFT JOIN evidence e ON e.id = h.evidence_id WHERE h.id = ?1"), params![id], hit_row).optional()?.ok_or_else(|| AppError::NotFound(format!("detection hit {id}")))
}

/// Marks a hit a false positive (recorded as feedback on the rule), dismissed, or new again.
pub fn hit_set(c: &Connection, id: i64, status: &str, note: &str) -> AppResult<()> {
    if !["new", "false_positive", "dismissed"].contains(&status) {
        return Err(validation("A hit is new, false_positive or dismissed (promote it to make a finding)"));
    }
    let (project_id, rule_id, old, event): (i64, Option<i64>, String, String) =
        c.query_row("SELECT project_id, rule_id, status, event FROM detection_hits WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?.ok_or_else(|| AppError::NotFound(format!("detection hit {id}")))?;
    crate::workspace::relations::require_open(c, project_id)?;
    if old == "promoted" {
        return Err(validation("This hit became a finding; change the finding instead"));
    }
    let tx = c.unchecked_transaction()?;
    tx.execute("UPDATE detection_hits SET status = ?2 WHERE id = ?1", params![id, status])?;
    if status == "false_positive" && old != "false_positive" {
        if let Some(rule) = rule_id {
            feedback_add(&tx, rule, Some(project_id), "false_positive", note, &event)?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn finding_severity(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
}

/// Promotes a hit to a finding under review, linked to the evidence the event came from. The
/// rule's match is the lead; the analyst confirms or rejects the finding.
pub fn hit_promote(c: &Connection, id: i64) -> AppResult<i64> {
    let h = hit(c, id)?;
    let project_id: i64 = c.query_row("SELECT project_id FROM detection_hits WHERE id = ?1", params![id], |r| r.get(0))?;
    crate::workspace::relations::require_open(c, project_id)?;
    if let Some(f) = h.finding_id {
        return Ok(f);
    }
    match h.explanation.get("kind").and_then(Value::as_str) {
        Some("yara") => return promote_yara(c, id, project_id, &h),
        Some("correlation") => return promote_correlation(c, id, project_id, &h),
        _ => {}
    }
    let fields = h.event.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
    let get = |name: &str| fields.iter().find(|p| p.get(0).and_then(Value::as_str).is_some_and(|k| k.eq_ignore_ascii_case(name))).and_then(|p| p.get(1).and_then(Value::as_str)).map(str::to_string);
    let target = get("Computer").or_else(|| get("host.name")).or_else(|| get("Hostname")).unwrap_or_else(|| h.evidence.clone());
    let why: Vec<String> = h
        .explanation
        .get("selections")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter(|s| s.get("matched").and_then(Value::as_bool) == Some(true))
                .flat_map(|s| s.get("hits").and_then(Value::as_array).cloned().unwrap_or_default())
                .map(|x| format!("{} = {}", x.get("condition").and_then(Value::as_str).unwrap_or(""), x.get("value").and_then(Value::as_str).unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    let description = format!(
        "The detection rule “{}” (version {}) matched {} at {} in {}.\n\nWhy it matched:\n{}\n\nA detection match is a lead: confirm it from the evidence before treating it as adversary activity.",
        h.rule_title,
        h.rule_version,
        h.event.get("label").and_then(Value::as_str).unwrap_or("an event"),
        if h.event_time.is_empty() { h.position.clone() } else { format!("{} ({})", h.event_time, h.position) },
        if h.evidence.is_empty() { "the evidence".to_string() } else { h.evidence.clone() },
        why.iter().map(|w| format!("- {w}")).collect::<Vec<_>>().join("\n")
    );
    let mut tags = vec!["detection".to_string(), "sigma".to_string()];
    tags.extend(h.techniques.iter().cloned());
    let input = crate::commands::projects::FindingInput {
        project_id,
        title: format!("{} ({})", h.rule_title, target).chars().take(200).collect(),
        severity: finding_severity(&h.rule_level).into(),
        status: "under_review".into(),
        category: "Detection".into(),
        confidence: Some("low".into()),
        description,
        affected_target: target.chars().take(500).collect(),
        technical_details: format!("Sigma rule #{} “{}”, version {}.{}", h.rule_id.unwrap_or(0), h.rule_title, h.rule_version, if h.techniques.is_empty() { String::new() } else { format!(" MITRE ATT&CK: {}.", h.techniques.join(", ")) }),
        tags,
        ..Default::default()
    };
    let tx = c.unchecked_transaction()?;
    let fid = crate::commands::projects::finding_write(&tx, &input, "detection", true)?;
    if let Some(eid) = h.evidence_id {
        crate::workspace::findings::link(&tx, fid, "evidence", eid, "detection")?;
    }
    tx.execute("UPDATE detection_hits SET status = 'promoted', finding_id = ?2 WHERE id = ?1", params![id, fid])?;
    tx.commit()?;
    Ok(fid)
}

/// A correlation hit as a finding under review, linked to every evidence file whose events it
/// combined. The finding says what was counted and lists the events, so each can be checked.
fn promote_correlation(c: &Connection, id: i64, project_id: i64, h: &HitRow) -> AppResult<i64> {
    let x = &h.explanation;
    let s = |k: &str| x.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let group: Vec<String> = x
        .get("groupBy")
        .and_then(Value::as_array)
        .map(|g| g.iter().filter_map(|p| Some(format!("{}={}", p.get(0)?.as_str()?, p.get(1)?.as_str()?))).collect())
        .unwrap_or_default();
    let events = x.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
    let lines: Vec<String> = events
        .iter()
        .map(|e| {
            let f = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
            format!("- {}: {} at {} in {}", f("rule"), f("position"), f("time"), f("source"))
        })
        .collect();
    let mut sources: Vec<i64> = events.iter().filter_map(|e| e.get("sourceId").and_then(Value::as_i64)).collect();
    sources.extend(h.evidence_id);
    sources.sort_unstable();
    sources.dedup();
    let target = if group.is_empty() { h.evidence.clone() } else { group.join(", ") };
    let value = x.get("value").and_then(Value::as_f64).unwrap_or_default();
    let total = x.get("total").and_then(Value::as_u64).unwrap_or(events.len() as u64);
    let description = format!(
        "The correlation rule “{}” (version {}, {}) matched for {}: {} within {} (measured: {}).\n\nWindow: {} to {}.\n\nEvents combined ({} of {} listed):\n{}\n\nA correlation is a lead built from other rules' matches: confirm each event from the evidence before treating it as adversary activity.",
        h.rule_title,
        h.rule_version,
        s("type"),
        if target.is_empty() { "all events".to_string() } else { target.clone() },
        s("condition"),
        s("timespan"),
        value,
        s("first"),
        s("last"),
        events.len(),
        total,
        lines.join("\n")
    );
    let mut tags = vec!["detection".to_string(), "sigma".to_string(), "correlation".to_string()];
    tags.extend(h.techniques.iter().cloned());
    let input = crate::commands::projects::FindingInput {
        project_id,
        title: format!("{} ({})", h.rule_title, if target.is_empty() { "all events" } else { &target }).chars().take(200).collect(),
        severity: finding_severity(&h.rule_level).into(),
        status: "under_review".into(),
        category: "Detection".into(),
        confidence: Some("low".into()),
        description,
        affected_target: target.chars().take(500).collect(),
        technical_details: format!(
            "Sigma correlation rule #{} “{}”, version {}, type {}.{}",
            h.rule_id.unwrap_or(0),
            h.rule_title,
            h.rule_version,
            s("type"),
            if h.techniques.is_empty() { String::new() } else { format!(" MITRE ATT&CK: {}.", h.techniques.join(", ")) }
        ),
        tags,
        ..Default::default()
    };
    let tx = c.unchecked_transaction()?;
    let fid = crate::commands::projects::finding_write(&tx, &input, "detection", true)?;
    for eid in sources {
        // evidence removed since the run is skipped; the events stay listed in the description
        let here: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM evidence WHERE id = ?1 AND project_id = ?2)", params![eid, project_id], |r| r.get(0))?;
        if here {
            crate::workspace::findings::link(&tx, fid, "evidence", eid, "detection")?;
        }
    }
    tx.execute("UPDATE detection_hits SET status = 'promoted', finding_id = ?2 WHERE id = ?1", params![id, fid])?;
    tx.commit()?;
    Ok(fid)
}

/// A YARA hit as a finding under review, linked to the file it matched.
fn promote_yara(c: &Connection, id: i64, project_id: i64, h: &HitRow) -> AppResult<i64> {
    let x = &h.explanation;
    let rule = x.get("rule").and_then(Value::as_str).unwrap_or("");
    let sha: Option<String> = match h.evidence_id {
        Some(e) => c.query_row("SELECT sha256 FROM evidence WHERE id = ?1", params![e], |r| r.get(0)).optional()?.flatten(),
        None => None,
    };
    let why: Vec<String> = x
        .get("strings")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .map(|s| {
                    let first = s.get("matches").and_then(|m| m.get(0));
                    format!(
                        "{} matched {} time{}, first at offset {}: {}",
                        s.get("id").and_then(Value::as_str).unwrap_or("?"),
                        s.get("count").and_then(Value::as_u64).unwrap_or(0),
                        if s.get("count").and_then(Value::as_u64) == Some(1) { "" } else { "s" },
                        first.and_then(|m| m.get("offset")).and_then(Value::as_u64).map(|o| format!("0x{o:x}")).unwrap_or_default(),
                        first.and_then(|m| m.get("text")).and_then(Value::as_str).unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let file = if h.evidence.is_empty() { "the evidence file".to_string() } else { h.evidence.clone() };
    let description = format!(
        "The YARA rule {} of “{}” (version {}) matched {}{}.\n\nWhy it matched:\n{}\n\nA rule match is a lead: confirm it from the file before treating the file as malicious.",
        rule,
        h.rule_title,
        h.rule_version,
        file,
        sha.as_deref().map(|s| format!(" (SHA-256 {s})")).unwrap_or_default(),
        if why.is_empty() { "- its condition holds on the file's properties (no string was needed)".to_string() } else { why.iter().map(|w| format!("- {w}")).collect::<Vec<_>>().join("\n") }
    );
    let mut tags = vec!["detection".to_string(), "yara".to_string()];
    tags.extend(h.techniques.iter().cloned());
    let input = crate::commands::projects::FindingInput {
        project_id,
        title: format!("YARA {rule} ({file})").chars().take(200).collect(),
        severity: finding_severity(&h.rule_level).into(),
        status: "under_review".into(),
        category: "Detection".into(),
        confidence: Some("low".into()),
        description,
        affected_target: file.chars().take(500).collect(),
        technical_details: format!(
            "YARA rule file #{} “{}”, version {}, rule {}.{}",
            h.rule_id.unwrap_or(0),
            h.rule_title,
            h.rule_version,
            rule,
            if h.techniques.is_empty() { String::new() } else { format!(" MITRE ATT&CK: {}.", h.techniques.join(", ")) }
        ),
        tags,
        ..Default::default()
    };
    let tx = c.unchecked_transaction()?;
    let fid = crate::commands::projects::finding_write(&tx, &input, "detection", true)?;
    if let Some(eid) = h.evidence_id {
        crate::workspace::findings::link(&tx, fid, "evidence", eid, "detection")?;
    }
    tx.execute("UPDATE detection_hits SET status = 'promoted', finding_id = ?2 WHERE id = ?1", params![id, fid])?;
    tx.commit()?;
    Ok(fid)
}

/* ───────────────────────── ATT&CK coverage ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub rule_id: i64,
    /// sigma or yara
    pub kind: String,
    pub title: String,
    pub enabled: bool,
    pub runnable: bool,
    /// at least one sample with an expectation, and the last test of each passed
    pub tested: bool,
}

/// The library's rules (Sigma, and YARA files whose metadata names techniques) per ATT&CK
/// technique: detection coverage, which says nothing about whether a technique was used.
pub fn coverage(c: &Connection) -> AppResult<BTreeMap<String, Vec<Coverage>>> {
    let rows: Vec<(i64, String, String, String, bool, bool)> = c
        .prepare("SELECT id, kind, title, techniques, enabled, runnable FROM detection_rules WHERE techniques <> '[]'")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
        .collect::<Result<_, _>>()?;
    let mut out: BTreeMap<String, Vec<Coverage>> = BTreeMap::new();
    for (id, kind, title, techniques, enabled, runnable) in rows {
        let (passed, failed) = test_state(c, id)?;
        let tested = passed > 0 && failed == 0;
        for t in serde_json::from_str::<Vec<String>>(&techniques).unwrap_or_default() {
            out.entry(t).or_default().push(Coverage { rule_id: id, kind: kind.clone(), title: title.clone(), enabled, runnable, tested });
        }
    }
    Ok(out)
}

/// A project's open detection hits per ATT&CK technique (not false positives or dismissed).
pub fn hits_by_technique(c: &Connection, project_id: i64) -> AppResult<BTreeMap<String, i64>> {
    let rows: Vec<String> = c.prepare("SELECT techniques FROM detection_hits WHERE project_id = ?1 AND status IN ('new','promoted')")?.query_map(params![project_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut out = BTreeMap::new();
    for t in rows {
        for id in serde_json::from_str::<Vec<String>>(&t).unwrap_or_default() {
            *out.entry(id).or_insert(0) += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "detections_tests.rs"]
mod tests;
