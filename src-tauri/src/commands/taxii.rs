//! TAXII 2.1 feed commands (`ti/taxii.rs`). Every connection is started by the analyst and
//! confirmed in a native dialog that names the server; the web view never sees a credential (it
//! only learns whether one is stored). Since Mission 6 the analyst types a server's credential
//! into a native OS dialog (`taxii_auth_prompt`), which stores it in the OS credential store; the
//! value never reaches the web view, in either direction.

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
    pub collections: Vec<Collection>,
}

fn view(c: &rusqlite::Connection, s: Server) -> AppResult<ServerView> {
    let stored = s.auth != "none" && stored(s.id);
    Ok(ServerView { credential_stored: stored, collections: taxii::collections_of(c, s.id)?, server: s })
}

/// Whether a credential is stored for the server (never its value).
fn stored(id: i64) -> bool {
    crate::commands::system::read_secret(&taxii::secret_name(id)).is_some()
}

/// Deletes the server's stored credential, if there is one (a computer without a credential store
/// has none, so this never fails there).
fn drop_credential(id: i64) -> AppResult<()> {
    if stored(id) {
        crate::commands::system::delete_taxii_secret(id)?;
    }
    Ok(())
}

/// The scheme, host and port a credential is sent to.
fn origin(url: &str) -> Option<String> {
    url::Url::parse(url).ok().map(|u| u.origin().ascii_serialization())
}

/// Whether an edit sends the server's credential somewhere else: another origin, or another kind
/// of authentication (a password sent as an API key). An address the save refuses moves nothing.
fn moves(old_url: &str, old_auth: &str, new_url: &str, new_auth: &str) -> bool {
    let new_origin = taxii::check_url(new_url).ok().map(|u| u.origin().ascii_serialization());
    new_origin.is_some() && (new_origin != origin(old_url) || new_auth != old_auth)
}

#[tauri::command]
pub async fn taxii_servers(db: State<'_, Db>) -> AppResult<Vec<ServerView>> {
    db.with(|c| taxii::servers(c)?.into_iter().map(|s| view(c, s)).collect())
}

#[tauri::command]
pub async fn taxii_server_save(db: State<'_, Db>, input: ServerInput) -> AppResult<i64> {
    // a stored credential never follows its server to another origin, or to another kind of
    // authentication (a password sent as an API key): it is deleted, and stored again by the analyst
    if let Some(id) = input.id {
        let before = db.with(|c| taxii::server(c, id))?;
        if moves(&before.discovery_url, &before.auth, &input.discovery_url, &input.auth) {
            drop_credential(id)?;
        }
    }
    db.with(|c| taxii::server_save(c, &input))
}

/// Removes a server, its collections and its stored credential. Indicators saved from it stay, with
/// their source.
#[tauri::command]
pub async fn taxii_server_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| taxii::server(c, id).map(|_| ()))?;
    drop_credential(id)?;
    db.with(|c| {
        c.execute("DELETE FROM taxii_servers WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    })
}

/// Asks for a TAXII server's password or API key in a native OS dialog (Windows' credential
/// dialog, a GTK dialog on Linux), never in the web view, and stores it in the OS credential store
/// in place of any earlier one. For HTTP Basic, the user name typed there becomes the server's.
/// Returns whether a credential is stored.
#[tauri::command]
pub async fn taxii_auth_prompt(app: AppHandle, id: i64) -> AppResult<bool> {
    let s = app.state::<Db>().with(|c| taxii::server(c, id))?;
    if s.auth == "none" {
        return Err(validation("This server is set to use no authentication"));
    }
    let host = url::Url::parse(&s.discovery_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let (what, user_label) = if s.auth == "basic" { ("the password", Some("User name")) } else { ("the API key", None) };
    let message = format!("Type {what} for the TAXII server “{}” ({host}). Cyber Hub stores it in this computer's credential store and sends it only to this server.{}", s.name, if s.auth == "header" { format!(" It goes in the {} header.", s.header_name) } else { String::new() });
    let handle = app.clone();
    // Windows' dialog always has a user name field: for an API key it shows the header's name
    let user = if s.auth == "basic" { s.username.clone() } else { s.header_name.clone() };
    let typed = tauri::async_runtime::spawn_blocking(move || crate::native_prompt::ask(&handle, "Store a TAXII credential", &message, user_label, &user))
        .await
        .map_err(|e| AppError::Internal(format!("the credential dialog failed: {e}")))?
        .map_err(validation)?;
    let Some(t) = typed else {
        return Ok(stored(id));
    };
    let secret = t.secret.trim();
    if secret.is_empty() || secret.len() > 4096 || secret.chars().any(char::is_control) {
        return Err(validation("Nothing was stored: the secret is empty, longer than 4 KB or contains control characters"));
    }
    let user = t.user.trim();
    if s.auth == "basic" && (user.is_empty() || user.len() > 200 || user.contains(':') || user.chars().any(char::is_control)) {
        return Err(validation("Nothing was stored: HTTP Basic needs a user name without ':' (at most 200 characters)"));
    }
    // the server may have been edited while the dialog was open: the secret is stored only for the
    // origin and the kind of authentication the dialog named
    let now = app.state::<Db>().with(|c| taxii::server(c, id))?;
    if origin(&now.discovery_url) != origin(&s.discovery_url) || now.auth != s.auth {
        return Err(validation("Nothing was stored: the server's address or authentication changed while the dialog was open"));
    }
    crate::commands::system::store_taxii_secret(id, secret)?;
    if s.auth == "basic" && user != now.username {
        app.state::<Db>().with(|c| {
            c.execute("UPDATE taxii_servers SET username = ?2, updated_at = ?3 WHERE id = ?1", rusqlite::params![id, user, crate::util::now()])?;
            Ok(())
        })?;
    }
    Ok(true)
}

/// Deletes a TAXII server's stored credential, after a native confirmation. Returns whether one
/// is still stored (false).
#[tauri::command]
pub async fn taxii_auth_forget(app: AppHandle, id: i64) -> AppResult<bool> {
    let s = app.state::<Db>().with(|c| taxii::server(c, id))?;
    if !crate::confirm::native(&app, "Forget a TAXII credential", format!("Delete the stored credential of the TAXII server “{}” from this computer's credential store?", s.name), "Delete").await {
        return Ok(stored(id));
    }
    drop_credential(id)?;
    Ok(false)
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

#[cfg(test)]
mod tests {
    use super::moves;

    /// A stored credential stays only while the server keeps its origin and its kind of
    /// authentication.
    #[test]
    fn a_credential_never_follows_its_server_elsewhere() {
        let url = "https://taxii.example.org/taxii2/";
        // the same origin: kept (another path, a trailing difference, the default port written out)
        assert!(!moves(url, "basic", url, "basic"));
        assert!(!moves(url, "basic", "https://taxii.example.org/other/taxii2/", "basic"));
        assert!(!moves(url, "basic", "https://TAXII.example.org:443/taxii2/", "basic"));
        // another host, port or kind of authentication: deleted
        assert!(moves(url, "basic", "https://attacker.example.net/taxii2/", "basic"));
        assert!(moves(url, "basic", "https://taxii.example.org:8443/taxii2/", "basic"));
        assert!(moves(url, "basic", "https://sub.taxii.example.org/taxii2/", "basic"));
        assert!(moves(url, "basic", url, "header"));
        assert!(moves(url, "header", url, "none"));
        // an address the save refuses changes nothing
        assert!(!moves(url, "basic", "http://taxii.example.org/taxii2/", "header"));
        assert!(!moves(url, "basic", "https://user:pw@taxii.example.org/taxii2/", "basic"));
        assert!(!moves(url, "basic", "not a url", "basic"));
    }
}
