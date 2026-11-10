//! TAXII 2.1 feed commands (`ti/taxii.rs`). Every connection is started by the analyst and
//! confirmed in a native dialog that names the server; the web view never sees a credential (it
//! only learns whether one is stored).

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::ti::taxii::{self, Collection, Server, ServerInput, SyncRun};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    #[serde(flatten)]
    pub server: Server,
    /// a credential is stored for it (never its value)
    pub credential_stored: bool,
    /// the command that stores it
    pub credential_command: String,
    pub collections: Vec<Collection>,
}

fn view(c: &rusqlite::Connection, s: Server) -> AppResult<ServerView> {
    let stored = s.auth != "none" && crate::commands::system::read_secret(&taxii::secret_name(s.id)).is_some();
    Ok(ServerView { credential_command: format!("cyberhub-keys taxii-set {}", s.id), credential_stored: stored, collections: taxii::collections_of(c, s.id)?, server: s })
}

#[tauri::command]
pub async fn taxii_servers(db: State<'_, Db>) -> AppResult<Vec<ServerView>> {
    db.with(|c| taxii::servers(c)?.into_iter().map(|s| view(c, s)).collect())
}

#[tauri::command]
pub async fn taxii_server_save(db: State<'_, Db>, input: ServerInput) -> AppResult<i64> {
    db.with(|c| taxii::server_save(c, &input))
}

/// Removes a server and its collections. Indicators saved from it stay, with their source.
#[tauri::command]
pub async fn taxii_server_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        taxii::server(c, id)?;
        c.execute("DELETE FROM taxii_servers WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    })
}

#[tauri::command]
pub async fn taxii_syncs(db: State<'_, Db>, collection_id: i64) -> AppResult<Vec<SyncRun>> {
    db.with(|c| taxii::syncs(c, collection_id))
}

fn client_for(s: &Server) -> AppResult<taxii::Client> {
    let secret = if s.auth == "none" { None } else { crate::commands::system::read_secret(&taxii::secret_name(s.id)) };
    let auth = taxii::auth_of(s, secret).map_err(validation)?;
    taxii::Client::new(auth).map_err(AppError::Internal)
}

async fn confirm(app: &AppHandle, s: &Server, what: &str) -> AppResult<()> {
    let host = url::Url::parse(&s.discovery_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let ok = crate::confirm::native(app, "Connect to a TAXII server", format!("Cyber Hub will connect to {host} ({}) to {what}.\n\nOnly this server is contacted, over HTTPS{}. Continue?", s.discovery_url, if s.auth == "none" { "" } else { ", with its stored credential" }), "Connect").await;
    if ok {
        Ok(())
    } else {
        Err(validation("Not connected: the connection was not confirmed"))
    }
}

/// Lists the server's API roots and collections (after the analyst confirms the connection).
#[tauri::command]
pub async fn taxii_discover(app: AppHandle, id: i64) -> AppResult<ServerView> {
    let s = app.state::<Db>().with(|c| taxii::server(c, id))?;
    let discovery = taxii::check_url(&s.discovery_url).map_err(validation)?;
    let client = client_for(&s)?;
    confirm(&app, &s, "list its collections").await?;
    let d = taxii::discover(&client, &discovery).await.map_err(|e| validation(format!("Discovery failed: {e}")))?;
    let mut found = Vec::new();
    for root in d.api_roots.iter().take(10) {
        let root = taxii::check_url(root).map_err(validation)?;
        match taxii::collections(&client, &root).await {
            Ok(list) => found.extend(list),
            Err(e) => return Err(validation(format!("The collections of {root} could not be listed: {e}"))),
        }
    }
    let db = app.state::<Db>();
    db.with(|c| {
        taxii::record_discovery(c, id, &d, &found)?;
        view(c, taxii::server(c, id)?)
    })
}

/// Downloads a collection's new indicators (after the analyst confirms the connection).
#[tauri::command]
pub async fn taxii_sync(app: AppHandle, collection_id: i64) -> AppResult<SyncRun> {
    let (coll, s) = app.state::<Db>().with(|c| {
        let coll = taxii::collection(c, collection_id)?;
        Ok((coll.clone(), taxii::server(c, coll.server_id)?))
    })?;
    if !coll.can_read {
        return Err(validation("The server does not let these credentials read this collection"));
    }
    let client = client_for(&s)?;
    confirm(&app, &s, &format!("download new indicators of the collection “{}”", if coll.title.is_empty() { &coll.collection } else { &coll.title })).await?;
    let db = app.state::<Db>();
    let out = taxii::sync(&db, &client, collection_id).await?;
    let _ = db.with(|c| {
        crate::commands::activity::log(c, "ti", &format!("TAXII synchronization: {}", coll.title), &format!("{} added, {} updated, {} revoked, {} already known, {} skipped ({})", out.added, out.updated, out.revoked, out.sighted, out.skipped, out.status), None, None, None)
    });
    Ok(out)
}
