//! Analysis commands over stored data (see `workspace::analysis`); none of them contacts a network.

use tauri::State;

use crate::db::Db;
use crate::error::AppResult;
use crate::workspace::analysis::{self, ExposurePath, Indicator, RunDiff};
use crate::workspace::discovery::{self, SnapshotChanges};

#[tauri::command]
pub async fn ioc_correlation(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<Indicator>> {
    db.with(|c| analysis::correlate(c, project_id))
}

#[tauri::command]
pub async fn exposure_paths(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<ExposurePath>> {
    db.with(|c| analysis::exposure_paths(c, project_id))
}

#[tauri::command]
pub async fn discovery_compare(db: State<'_, Db>, from: i64, to: i64) -> AppResult<SnapshotChanges> {
    db.with(|c| discovery::compare(c, from, to))
}

#[tauri::command]
pub async fn runs_compare(db: State<'_, Db>, a: i64, b: i64) -> AppResult<RunDiff> {
    db.with(|c| analysis::compare_runs(c, a, b))
}
