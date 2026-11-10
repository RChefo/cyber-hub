//! Risk acceptance commands (`workspace/risk.rs`): a project's register, recording, renewing and
//! revoking acceptances. Recording one is the only way to make a finding or a vulnerability an
//! accepted risk; it happens here, in the app, never through MCP.

use serde::Serialize;
use tauri::State;

use crate::db::Db;
use crate::error::AppResult;
use crate::workspace::risk::{self, Acceptance, Draft, Event, ItemRef, Summary};

#[tauri::command]
pub async fn risk_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<Acceptance>> {
    db.with(|c| risk::list(c, project_id))
}

#[tauri::command]
pub async fn risk_get(db: State<'_, Db>, id: i64) -> AppResult<Acceptance> {
    db.with(|c| risk::get(c, id))
}

#[tauri::command]
pub async fn risk_history(db: State<'_, Db>, id: i64) -> AppResult<Vec<Event>> {
    db.with(|c| risk::history(c, id))
}

/// The register's state: counts by standing, and the findings marked accepted that no
/// acceptance covers (to be documented).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskOverview {
    pub summary: Summary,
    pub undocumented: Vec<(i64, String)>,
}

#[tauri::command]
pub async fn risk_overview(db: State<'_, Db>, project_id: i64) -> AppResult<RiskOverview> {
    db.with(|c| Ok(RiskOverview { summary: risk::summary(c, project_id)?, undocumented: risk::uncovered_findings(c, project_id)? }))
}

#[tauri::command]
pub async fn risk_accept(db: State<'_, Db>, project_id: i64, draft: Draft, items: Vec<ItemRef>) -> AppResult<i64> {
    db.with(|c| risk::create(c, project_id, &draft, &items, "user"))
}

#[tauri::command]
pub async fn risk_renew(db: State<'_, Db>, id: i64, draft: Draft) -> AppResult<()> {
    db.with(|c| risk::renew(c, id, &draft, "user"))
}

#[tauri::command]
pub async fn risk_revoke(db: State<'_, Db>, id: i64, reason: String) -> AppResult<()> {
    db.with(|c| risk::revoke(c, id, &reason, "user"))
}
