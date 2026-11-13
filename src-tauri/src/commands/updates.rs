// SPDX-License-Identifier: Apache-2.0
//! Update Center commands. The updater plugin itself grants the web view nothing; these commands
//! are the only way the page reaches it (see `updates`).

use tauri::{AppHandle, State};

use crate::error::AppResult;
use crate::updates::{self, Status, Updates};

type Svc<'a> = State<'a, std::sync::Arc<Updates>>;

#[tauri::command]
pub async fn update_status(app: AppHandle, svc: Svc<'_>) -> AppResult<Status> {
    Ok(svc.status(&app))
}

#[tauri::command]
pub async fn update_check(app: AppHandle) -> AppResult<Status> {
    updates::check(&app, true).await
}

#[tauri::command]
pub async fn update_download(app: AppHandle) -> AppResult<Status> {
    updates::download(&app)
}

#[tauri::command]
pub async fn update_cancel(app: AppHandle) -> AppResult<Status> {
    updates::cancel(&app)
}

#[tauri::command]
pub async fn update_install(app: AppHandle) -> AppResult<Status> {
    updates::install(&app).await
}

#[tauri::command]
pub async fn update_restart(app: AppHandle) -> AppResult<()> {
    updates::restart(&app)
}

#[tauri::command]
pub async fn update_settings_set(app: AppHandle, svc: Svc<'_>, auto_check: bool, frequency_hours: u32) -> AppResult<Status> {
    svc.set_settings(&app, auto_check, frequency_hours)
}
