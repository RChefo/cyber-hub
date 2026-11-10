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
    let stored = stored(&s);
    Ok(ServerView { credential_stored: stored, collections: taxii::collections_of(c, s.id)?, server: s })
}

/// Whether a credential is stored for the server as it is now: its number, origin, kind of
/// authentication and header (never its value).
fn stored(s: &Server) -> bool {
    taxii::server_secret_name(s).is_some_and(|name| crate::commands::system::read_secret(&name).is_some())
}

/// Deletes the server's stored credential, if there is one (a computer without a credential store
/// has none, so this never fails there).
fn drop_credential(s: &Server) -> AppResult<()> {
    crate::commands::system::delete_taxii_secret(s)
}

/// A server's credential changes one change at a time (Mission 7). The credential dialog checks
/// the server again once the analyst has answered, then writes the credential store. A removal, a
/// save that moves the server, or "Forget" landing between the two found nothing to delete, and
/// the write then left the credential in the store for a server that no longer had it (seen live:
/// a removal 150–200 ms after Store). Each holds this while it checks the server and changes the
/// store; nothing waits for the dialog itself.
static CREDENTIALS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
pub async fn taxii_servers(db: State<'_, Db>) -> AppResult<Vec<ServerView>> {
    db.with(|c| taxii::servers(c)?.into_iter().map(|s| view(c, s)).collect())
}

#[tauri::command]
pub async fn taxii_server_save(db: State<'_, Db>, input: ServerInput) -> AppResult<i64> {
    save_server(&db, input).await
}

async fn save_server(db: &Db, input: ServerInput) -> AppResult<i64> {
    let _changing = CREDENTIALS.lock().await;
    let before = match input.id {
        Some(id) => Some(db.with(|c| taxii::server(c, id))?),
        None => None,
    };
    let id = db.with(|c| taxii::server_save(c, &input))?;
    // a stored credential never follows its server to another origin, another kind of
    // authentication (a password sent as an API key) or another header: it is bound to them
    // (`secret_name`), so it can no longer be read, and it is deleted; the analyst stores it again
    if let Some(before) = before {
        let after = db.with(|c| taxii::server(c, id))?;
        if taxii::server_secret_name(&before) != taxii::server_secret_name(&after) {
            drop_credential(&before).map_err(|e| AppError::Secret(format!("The server was saved, but its earlier credential could not be deleted from the credential store: {e}")))?;
        }
    }
    Ok(id)
}

/// Removes a server, its collections and its stored credential. Indicators saved from it stay, with
/// their source.
#[tauri::command]
pub async fn taxii_server_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    remove_server(&db, id).await
}

async fn remove_server(db: &Db, id: i64) -> AppResult<()> {
    let _changing = CREDENTIALS.lock().await;
    let s = db.with(|c| taxii::server(c, id))?;
    drop_credential(&s)?;
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
        return Ok(stored(&s));
    };
    let secret = t.secret.trim();
    if secret.is_empty() || secret.len() > 4096 || secret.chars().any(char::is_control) {
        return Err(validation("Nothing was stored: the secret is empty, longer than 4 KB or contains control characters"));
    }
    let user = t.user.trim();
    if s.auth == "basic" && (user.is_empty() || user.len() > 200 || user.contains(':') || user.chars().any(char::is_control)) {
        return Err(validation("Nothing was stored: HTTP Basic needs a user name without ':' (at most 200 characters)"));
    }
    store_typed(&app.state::<Db>(), &s, secret, user).await
}

/// Stores a credential typed into the dialog, for the server as the dialog named it. The server
/// may have been removed or edited while the dialog was open: the secret is stored only for the
/// origin, the kind of authentication and the header the dialog named.
async fn store_typed(db: &Db, s: &Server, secret: &str, user: &str) -> AppResult<bool> {
    let _changing = CREDENTIALS.lock().await;
    let now = match db.with(|c| taxii::server(c, s.id)) {
        Err(AppError::NotFound(_)) => return Err(validation("Nothing was stored: the server was removed while the dialog was open")),
        other => other?,
    };
    if taxii::server_secret_name(&now) != taxii::server_secret_name(s) {
        return Err(validation("Nothing was stored: the server's address or authentication changed while the dialog was open"));
    }
    crate::commands::system::store_taxii_secret(s, secret)?;
    if s.auth == "basic" && user != now.username {
        db.with(|c| {
            c.execute("UPDATE taxii_servers SET username = ?2, updated_at = ?3 WHERE id = ?1", rusqlite::params![s.id, user, crate::util::now()])?;
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
        return Ok(stored(&s));
    }
    forget(&app.state::<Db>(), id).await
}

/// Deletes the server's credential as the server is now (it may have been edited while the
/// confirmation was open).
async fn forget(db: &Db, id: i64) -> AppResult<bool> {
    let _changing = CREDENTIALS.lock().await;
    let s = db.with(|c| taxii::server(c, id))?;
    drop_credential(&s)?;
    Ok(false)
}

#[tauri::command]
pub async fn taxii_syncs(db: State<'_, Db>, collection_id: i64) -> AppResult<Vec<SyncRun>> {
    db.with(|c| taxii::syncs(c, collection_id))
}

fn client_for(s: &Server) -> AppResult<taxii::Client> {
    let secret = taxii::server_secret_name(s).and_then(|name| crate::commands::system::read_secret(&name));
    let auth = taxii::auth_of(s, secret).map_err(validation)?;
    taxii::Client::new(auth).map_err(AppError::Internal)
}

async fn confirm(app: &AppHandle, s: &Server, what: &str) -> AppResult<()> {
    let host = url::Url::parse(&s.discovery_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let ok = crate::confirm::native(app, "Connect to a TAXII server", format!("Cyber Hub will connect to {host} ({}) to {what}.\n\nOnly this server is contacted, over HTTPS{}. Continue?", s.discovery_url, if s.auth == "none" { "" } else { ", with its stored credential" }), "Connect").await;
    if ok {
        Ok(())
    } else {
        Err(AppError::Cancelled("Not connected: the connection was not confirmed".into()))
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

/// The collections being synchronized now: one synchronization per collection at a time.
static SYNCING: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());

/// A collection's synchronization while it runs; it ends when this is dropped (Mission 7).
#[derive(Debug)]
struct Syncing(i64);

impl Syncing {
    /// Refuses a second synchronization of a collection while one runs: they would both move the
    /// same cursor.
    fn start(collection_id: i64) -> AppResult<Syncing> {
        let mut running = SYNCING.lock().map_err(|_| AppError::Internal("the synchronization list is unavailable".into()))?;
        if running.contains(&collection_id) {
            return Err(validation("This collection is already being synchronized; it continues if you leave the page"));
        }
        running.push(collection_id);
        Ok(Syncing(collection_id))
    }
}

impl Drop for Syncing {
    fn drop(&mut self) {
        if let Ok(mut running) = SYNCING.lock() {
            running.retain(|id| *id != self.0);
        }
    }
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
    // refused before asking: the collection must still be on the server's own origin, and only one
    // synchronization of it runs at a time
    taxii::collection_root(&s, &coll).map_err(validation)?;
    let _syncing = Syncing::start(collection_id)?;
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
    use super::{forget, remove_server, save_server, store_typed, Syncing, CREDENTIALS};
    use crate::db::Db;
    use crate::ti::taxii::{self, ServerInput};

    /// Whether the change is still waiting after 300 ms. It is then dropped, so it never reaches
    /// the credential store.
    async fn still_waiting<F: std::future::Future>(change: F) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(300), change).await.is_err()
    }

    /// Mission 7: a server's credential changes one change at a time. While a typed credential is
    /// being stored, removing the server, saving it elsewhere, "Forget" and another store wait,
    /// so whichever comes second sees what the first did; and a credential typed for a server
    /// that was moved or removed meanwhile is refused before the credential store is touched. Live
    /// on Debian, a removal 150–200 ms after Store left the new credential in the Secret Service
    /// (2 of 10 attempts) before this.
    #[tokio::test]
    async fn credential_changes_never_interleave() {
        let db = Db::open_in_memory().unwrap();
        let input = ServerInput { id: None, name: "Serialized".into(), discovery_url: "https://taxii.serialized.test/taxii2/".into(), auth: "basic".into(), username: "analyst".into(), reliability: "B".into(), default_confidence: Some(50), ..Default::default() };
        let first = save_server(&db, input.clone()).await.unwrap();
        // a number no real credential store holds a credential for: nothing here can reach one
        let id = 900_001;
        db.with(|c| {
            c.execute("UPDATE taxii_servers SET id = ?2 WHERE id = ?1", rusqlite::params![first, id])?;
            Ok(())
        })
        .unwrap();
        let s = db.with(|c| taxii::server(c, id)).unwrap();

        let storing = CREDENTIALS.lock().await;
        assert!(still_waiting(remove_server(&db, id)).await, "a removal waits for the credential being stored");
        let moved = ServerInput { id: Some(id), discovery_url: "https://elsewhere.serialized.test/taxii2/".into(), ..input.clone() };
        assert!(still_waiting(save_server(&db, moved)).await, "a save that moves the server waits");
        assert!(still_waiting(forget(&db, id)).await, "Forget waits");
        assert!(still_waiting(store_typed(&db, &s, "QA-typed-value", "analyst")).await, "another store waits");
        drop(storing);
        assert_eq!(db.with(|c| taxii::server(c, id)).unwrap().discovery_url, s.discovery_url, "nothing changed while they waited");

        db.with(|c| {
            c.execute("UPDATE taxii_servers SET discovery_url = 'https://moved.serialized.test/taxii2/' WHERE id = ?1", [id])?;
            Ok(())
        })
        .unwrap();
        let err = store_typed(&db, &s, "QA-typed-value", "analyst").await.unwrap_err().to_string();
        assert!(err.contains("changed while the dialog was open"), "{err}");
        db.with(|c| {
            c.execute("DELETE FROM taxii_servers WHERE id = ?1", [id])?;
            Ok(())
        })
        .unwrap();
        let err = store_typed(&db, &s, "QA-typed-value", "analyst").await.unwrap_err().to_string();
        assert!(err.contains("removed while the dialog was open"), "{err}");
    }

    /// Mission 7: one synchronization per collection at a time; another collection is not held up,
    /// and the collection is free again when the synchronization ends, however it ends.
    #[test]
    fn a_collection_is_synchronized_once_at_a_time() {
        let first = Syncing::start(9001).unwrap();
        assert!(Syncing::start(9001).unwrap_err().to_string().contains("already being synchronized"));
        let other = Syncing::start(9002).unwrap();
        drop(first);
        let again = Syncing::start(9001).unwrap();
        drop((other, again));
    }
}
