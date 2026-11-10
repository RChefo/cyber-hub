//! API security commands (`workspace/apisec.rs`): import an API definition, Postman collection or
//! HAR capture into a project's inventory, read it with its checks and scope status, and record an
//! issue as a finding. Nothing here contacts a network.

use std::collections::BTreeMap;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::commands::activity;
use crate::commands::projects::scope_entries;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::scope::ScopeEntry;
use crate::workspace::apisec::{self, ApiSpec, Endpoint, Issue, SpecSummary};
use crate::workspace::evidence::{self, EvidenceStore};
use crate::workspace::{findings, scan_import, timeline};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointScope {
    /// the URL a request would use: the first absolute server and the path template
    pub url: String,
    pub in_scope: bool,
    /// why it is not in scope ("" when it is)
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiSpecView {
    pub summary: SpecSummary,
    pub spec: ApiSpec,
    pub issues: Vec<Issue>,
    /// one per endpoint, in the same order
    pub scope: Vec<EndpointScope>,
    /// issues already recorded as findings: issue id → finding id
    pub recorded: BTreeMap<String, i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedIssue {
    pub finding_id: i64,
    /// false when the issue had been recorded before
    pub created: bool,
}

/// `{id}` path parameters as plain text, so the URL can be checked like a request would be.
fn fill(path: &str) -> String {
    path.replace(['{', '}'], "")
}

fn endpoint_scope(entries: &[ScopeEntry], spec: &ApiSpec, e: &Endpoint) -> EndpointScope {
    let Some(server) = e.servers.iter().chain(spec.servers.iter()).find(|s| s.contains("://")) else {
        return EndpointScope { url: e.path.clone(), in_scope: false, reason: "The definition names no absolute server URL".into() };
    };
    let url = format!("{server}{}", e.path);
    match crate::scope::parse_target(&format!("{server}{}", fill(&e.path))) {
        None => EndpointScope { url, in_scope: false, reason: "Not a valid URL".into() },
        Some(t) => match crate::scope::check_target(entries, &t) {
            Ok(()) => EndpointScope { url, in_scope: true, reason: String::new() },
            Err(reason) => EndpointScope { url, in_scope: false, reason },
        },
    }
}

/// The finding an issue was recorded as, if any (same title and rule line in the same project).
pub(crate) fn recorded_finding(c: &Connection, input: &crate::commands::projects::FindingInput) -> AppResult<Option<i64>> {
    Ok(c.query_row(
        "SELECT id FROM findings WHERE project_id = ?1 AND title = ?2 AND technical_details = ?3 ORDER BY id LIMIT 1",
        params![input.project_id, input.title, input.technical_details],
        |r| r.get(0),
    )
    .optional()?)
}

pub(crate) fn view(c: &Connection, id: i64) -> AppResult<ApiSpecView> {
    let (summary, spec) = apisec::get(c, id)?;
    let entries = scope_entries(c, summary.project_id)?;
    let scope = spec.endpoints.iter().map(|e| endpoint_scope(&entries, &spec, e)).collect();
    let issues = apisec::audit(&spec);
    let mut recorded = BTreeMap::new();
    for i in issues.iter().filter(|i| i.kind == "issue") {
        if let Some(fid) = recorded_finding(c, &apisec::finding_for(&summary, &spec, i))? {
            recorded.insert(i.id.clone(), fid);
        }
    }
    Ok(ApiSpecView { summary, spec, issues, scope, recorded })
}

/// Records an issue of a definition as a finding, once. Tests are not findings.
pub(crate) fn record_issue(c: &Connection, spec_id: i64, issue_id: &str) -> AppResult<RecordedIssue> {
    let (summary, spec) = apisec::get(c, spec_id)?;
    let issue = apisec::audit(&spec).into_iter().find(|i| i.id == issue_id).ok_or_else(|| AppError::NotFound(format!("issue {issue_id}")))?;
    if issue.kind != "issue" {
        return Err(validation("A test is a list of endpoints to test, not a finding. Record a finding when a test shows a flaw."));
    }
    let input = apisec::finding_for(&summary, &spec, &issue);
    if let Some(finding_id) = recorded_finding(c, &input)? {
        return Ok(RecordedIssue { finding_id, created: false });
    }
    let tx = c.unchecked_transaction()?;
    let finding_id = crate::commands::projects::finding_write(&tx, &input, "api", true)?;
    if let Some(ev) = summary.evidence_id {
        findings::link(&tx, finding_id, "evidence", ev, "api")?;
    }
    tx.commit()?;
    Ok(RecordedIssue { finding_id, created: true })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiCompareView {
    pub old: SpecSummary,
    pub new: SpecSummary,
    pub comparison: apisec::compare::Comparison,
    /// issue id → finding id, for the issues already recorded
    pub recorded: BTreeMap<String, i64>,
}

/// Two definitions of the project, the older first.
fn compared(c: &Connection, old_id: i64, new_id: i64) -> AppResult<(SpecSummary, SpecSummary, apisec::ApiSpec, apisec::compare::Comparison)> {
    if old_id == new_id {
        return Err(validation("Choose two different definitions"));
    }
    let (old, old_spec) = apisec::get(c, old_id)?;
    let (new, new_spec) = apisec::get(c, new_id)?;
    if old.project_id != new.project_id {
        return Err(validation("Both definitions must belong to the same project"));
    }
    let name = format!("{} (imported {})", old.name, old.imported_at.get(..10).unwrap_or(&old.imported_at));
    let comparison = apisec::compare::compare(&old_spec, &new_spec, &name);
    Ok((old, new, new_spec, comparison))
}

pub(crate) fn compare_view(c: &Connection, old_id: i64, new_id: i64) -> AppResult<ApiCompareView> {
    let (old, new, new_spec, comparison) = compared(c, old_id, new_id)?;
    let mut recorded = BTreeMap::new();
    for i in comparison.issues.iter().filter(|i| i.kind == "issue") {
        if let Some(fid) = recorded_finding(c, &apisec::finding_for(&new, &new_spec, i))? {
            recorded.insert(i.id.clone(), fid);
        }
    }
    Ok(ApiCompareView { old, new, comparison, recorded })
}

/// Compares two definitions of the project: endpoints added, removed and changed.
#[tauri::command]
pub async fn api_spec_compare(db: State<'_, Db>, old_id: i64, new_id: i64) -> AppResult<ApiCompareView> {
    db.with(|c| compare_view(c, old_id, new_id))
}

/// Records an issue of a comparison as a finding, once, against the newer definition.
pub(crate) fn record_compared(c: &Connection, old_id: i64, new_id: i64, issue_id: &str) -> AppResult<RecordedIssue> {
    let (_, new, new_spec, comparison) = compared(c, old_id, new_id)?;
    let issue = comparison.issues.into_iter().find(|i| i.id == issue_id).ok_or_else(|| AppError::NotFound(format!("issue {issue_id}")))?;
    if issue.kind != "issue" {
        return Err(validation("A test is a list of endpoints to test, not a finding. Record a finding when a test shows a flaw."));
    }
    let input = apisec::finding_for(&new, &new_spec, &issue);
    if let Some(finding_id) = recorded_finding(c, &input)? {
        return Ok(RecordedIssue { finding_id, created: false });
    }
    let tx = c.unchecked_transaction()?;
    let finding_id = crate::commands::projects::finding_write(&tx, &input, "api", true)?;
    if let Some(ev) = new.evidence_id {
        findings::link(&tx, finding_id, "evidence", ev, "api")?;
    }
    tx.commit()?;
    Ok(RecordedIssue { finding_id, created: true })
}

#[tauri::command]
pub async fn api_compare_record(db: State<'_, Db>, old_id: i64, new_id: i64, issue_id: String) -> AppResult<RecordedIssue> {
    db.with(|c| record_compared(c, old_id, new_id, &issue_id))
}

/// Choose a file (native dialog) and add it to the project's API inventory. The file is kept in
/// the evidence vault. None when the dialog is cancelled.
#[tauri::command]
pub async fn api_spec_import(app: AppHandle, project_id: i64) -> AppResult<Option<SpecSummary>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    crate::commands::workspace::main_window_dialog(&app, "Import an API definition")
        .add_filter("API definitions, Postman collections, HAR", &["json", "yaml", "yml", "har"])
        .add_filter("All files", &["*"])
        .pick_file(move |f| {
            let _ = tx.send(f.and_then(|f| f.into_path().ok()));
        });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Option<SpecSummary>> {
        let meta = std::fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(validation("Choose a file"));
        }
        if meta.len() as usize > apisec::MAX_FILE_BYTES {
            return Err(validation(format!("The file is larger than {} MB", apisec::MAX_FILE_BYTES / 1024 / 1024)));
        }
        let bytes = crate::util::read_regular(&path, apisec::MAX_FILE_BYTES as u64)?;
        if bytes.len() > apisec::MAX_FILE_BYTES {
            return Err(validation("The file grew while it was read"));
        }
        let (text, _) = scan_import::decode_text(&bytes);
        let spec = apisec::parse(&text).map_err(AppError::Validation)?;
        if spec.endpoints.is_empty() {
            return Err(validation("The file describes no endpoints"));
        }
        let sha256: String = {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
        };
        let file_name: String = evidence::display_name(&path.to_string_lossy()).chars().take(200).collect();
        let db = handle.state::<Db>();
        let dup: Option<i64> = db.with(|c| Ok(c.query_row("SELECT id FROM api_specs WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?))?;
        if dup.is_some() {
            return Err(validation("This file is already in the project's API inventory"));
        }
        let store = handle.state::<Arc<EvidenceStore>>();
        let existed: Option<i64> = db.with(|c| {
            Ok(c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?)
        })?;
        let kind = match spec.format.as_str() {
            "har" => "HAR capture",
            "postman" => "Postman collection",
            _ => "API definition",
        };
        let rec = store.add_bytes(&db, project_id, &file_name, &bytes, (&format!("{kind}: {file_name}"), &format!("Imported into the API inventory ({}). SHA-256 {sha256}", spec.format)), "import")?;
        let stored = db.with(|c| {
            let tx = c.unchecked_transaction()?;
            let id = apisec::store(&tx, project_id, &file_name, &sha256, Some(rec.id), &spec)?;
            let prov = crate::workspace::evidence::Provenance { source_module: "api_inventory".into(), source_ref: format!("api_spec:{id}"), tool: kind.to_string(), ..Default::default() };
            crate::workspace::evidence::set_provenance(&tx, rec.id, &prov)?;
            let what = format!("{} endpoints from {file_name} ({kind})", spec.endpoints.len());
            timeline::record(&tx, project_id, "asset", &format!("API inventory: {}", if spec.title.is_empty() { &file_name } else { &spec.title }), &what, Some("api_spec"), Some(id))?;
            activity::log(&tx, "import", "API definition imported", &what, Some("project"), Some(&project_id.to_string()), Some(project_id))?;
            tx.commit()?;
            Ok(id)
        });
        let id = match stored {
            Ok(id) => id,
            Err(e) => {
                if existed.is_none() {
                    let _ = store.delete(&db, rec.id);
                }
                return Err(e);
            }
        };
        Ok(Some(db.with(|c| apisec::get(c, id))?.0))
    })
    .await
    .map_err(|e| AppError::Internal(format!("reading the API definition failed: {e}")))?
}

#[tauri::command]
pub async fn api_specs_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<SpecSummary>> {
    db.with(|c| apisec::list(c, project_id))
}

#[tauri::command]
pub async fn api_spec_get(db: State<'_, Db>, id: i64) -> AppResult<ApiSpecView> {
    db.with(|c| view(c, id))
}

/// Removes a definition from the inventory. Its file stays in the evidence vault, and findings
/// recorded from it stay.
#[tauri::command]
pub async fn api_spec_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        let (summary, _) = apisec::get(c, id)?;
        apisec::delete(c, id)?;
        activity::log(c, "import", "API definition removed", &summary.name, Some("project"), Some(&summary.project_id.to_string()), Some(summary.project_id))
    })
}

#[tauri::command]
pub async fn api_issue_record(db: State<'_, Db>, spec_id: i64, issue_id: String) -> AppResult<RecordedIssue> {
    db.with(|c| record_issue(c, spec_id, &issue_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_check_the_scope_per_endpoint_and_issues_are_recorded_once() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
            let pid = c.last_insert_rowid();
            // only the users collection is authorized, by path
            c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES (?1, 'https://api.shop.example/v1/users', 'url', 1, '', '2026-11-09T00:00:00Z')", params![pid])?;
            let spec = apisec::parse(
                "openapi: 3.0.0\ninfo: {title: Shop, version: '1'}\nservers: [{url: 'https://api.shop.example/v1'}]\ncomponents:\n  securitySchemes:\n    b: {type: http, scheme: bearer}\nsecurity: [{b: []}]\npaths:\n  /users/{id}:\n    delete:\n      security: []\n      responses: {'204': {description: ok}}\n  /orders:\n    get: {responses: {'200': {description: ok}}}\n",
            )
            .unwrap();
            let id = apisec::store(c, pid, "shop.yaml", "cd34", None, &spec)?;
            let v = view(c, id)?;
            let by_path: BTreeMap<&str, &EndpointScope> = v.spec.endpoints.iter().map(|e| e.path.as_str()).zip(v.scope.iter()).collect();
            assert!(by_path["/users/{id}"].in_scope, "{:?}", by_path["/users/{id}"]);
            assert_eq!(by_path["/users/{id}"].url, "https://api.shop.example/v1/users/{id}");
            assert!(!by_path["/orders"].in_scope && !by_path["/orders"].reason.is_empty());
            let issue = v.issues.iter().find(|i| i.rule == "API2-ANONYMOUS-WRITE").unwrap().id.clone();
            let first = record_issue(c, id, &issue)?;
            assert!(first.created);
            let again = record_issue(c, id, &issue)?;
            assert_eq!((again.finding_id, again.created), (first.finding_id, false), "recorded once");
            assert_eq!(view(c, id)?.recorded.get(&issue), Some(&first.finding_id));
            let test = v.issues.iter().find(|i| i.kind == "test").unwrap().id.clone();
            assert!(record_issue(c, id, &test).is_err(), "tests are not findings");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn comparisons_record_their_issues_once_and_refuse_tests() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
            let pid = c.last_insert_rowid();
            let v1 = apisec::parse(r#"{"openapi":"3.0.3","info":{"title":"Shop","version":"1"},"servers":[{"url":"https://api.shop.example"}],
                "components":{"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Key"}}},"security":[{"key":[]}],
                "paths":{"/orders":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#).unwrap();
            let v2 = apisec::parse(r#"{"openapi":"3.0.3","info":{"title":"Shop","version":"2"},"servers":[{"url":"https://api.shop.example"}],
                "components":{"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Key"}}},"security":[{"key":[]}],
                "paths":{"/orders":{"get":{"security":[],"responses":{"200":{"description":"ok"}}}},"/reports":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#).unwrap();
            let a = apisec::store(c, pid, "shop-v1.json", "a1", None, &v1)?;
            let b = apisec::store(c, pid, "shop-v2.json", "b2", None, &v2)?;
            assert!(compare_view(c, a, a).is_err(), "a definition is not compared with itself");
            let view = compare_view(c, a, b)?;
            assert_eq!((view.comparison.added.clone(), view.comparison.changed.len()), (vec!["GET /reports".to_string()], 1));
            assert!(view.recorded.is_empty());
            let lost = view.comparison.issues.iter().find(|i| i.rule == "CMP-AUTH-REMOVED").unwrap().id.clone();
            let first = record_compared(c, a, b, &lost)?;
            assert!(first.created);
            let again = record_compared(c, a, b, &lost)?;
            assert_eq!((again.finding_id, again.created), (first.finding_id, false), "recorded once");
            let f = crate::commands::projects::finding_get(c, first.finding_id)?;
            assert_eq!((f.severity.as_str(), f.affected_target.as_str()), ("high", "https://api.shop.example/orders"));
            assert!(f.description.starts_with("Compared with shop-v1.json (imported"), "{}", f.description);
            assert_eq!(compare_view(c, a, b)?.recorded.get(&lost), Some(&first.finding_id), "the view knows it is recorded");
            let test = view.comparison.issues.iter().find(|i| i.kind == "test").unwrap().id.clone();
            assert!(record_compared(c, a, b, &test).is_err(), "a test is not a finding");
            Ok(())
        })
        .unwrap();
    }
}
