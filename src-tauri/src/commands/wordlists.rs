//! Wordlist management. Files are indexed by reference (large lists stay where they
//! are) or copied into the managed directory inside the app data folder.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::commands::activity::log;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, now, one_of};

const CATEGORIES: &[&str] =
    &["general", "directories", "subdomains", "passwords", "usernames", "parameters", "fuzzing", "api", "custom"];
const MAX_COUNT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Wordlist {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub category: String,
    pub size_bytes: i64,
    pub line_count: Option<i64>,
    pub managed: bool,
    pub exists: bool,
    pub added_at: String,
    pub modified_at: Option<String>,
}

pub fn managed_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = crate::util::data_dir(app)?.join("wordlists");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Whether Cyber Hub may touch an indexed path (Mission 7). On Windows, never a network or device
/// path: even checking that it exists makes Windows connect to the host with the user's
/// credentials, and a restored database could name one.
fn touchable(path: &str) -> bool {
    !(cfg!(windows) && crate::util::is_network_or_device_path(path))
}

/// The file of an indexed wordlist, when it may be read (Mission 7): a touchable path, and for a
/// managed copy, a file still inside the managed folder (checked on the canonical path, so a link
/// cannot lead out of it).
fn readable_path(app: &AppHandle, path: &str, managed: bool) -> AppResult<PathBuf> {
    if !touchable(path) {
        return Err(validation("Network and device paths are not opened"));
    }
    let p = PathBuf::from(path);
    if managed {
        let dir = managed_dir(app)?.canonicalize()?;
        let canon = p.canonicalize()?;
        if !canon.starts_with(&dir) {
            return Err(validation("This wordlist is marked as a managed copy but is not in the managed folder"));
        }
        return Ok(canon);
    }
    Ok(p)
}

fn count_lines(path: &Path) -> Option<i64> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_COUNT_BYTES {
        return None;
    }
    let mut reader = BufReader::with_capacity(1 << 20, crate::util::open_regular(path).ok()?);
    let mut buf = vec![0u8; 1 << 20];
    let mut count = 0i64;
    let mut last = b'\n';
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        count += buf[..n].iter().filter(|b| **b == b'\n').count() as i64;
        last = buf[n - 1];
    }
    if last != b'\n' && meta.len() > 0 {
        count += 1;
    }
    Some(count)
}

fn modified(path: &Path) -> Option<String> {
    let t = std::fs::metadata(path).ok()?.modified().ok()?;
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn guess_category(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("subdomain") || n.contains("dns") {
        "subdomains"
    } else if n.contains("pass") || n.contains("rockyou") {
        "passwords"
    } else if n.contains("user") || n.contains("names") {
        "usernames"
    } else if n.contains("param") {
        "parameters"
    } else if n.contains("api") {
        "api"
    } else if n.contains("dir") || n.contains("content") || n.contains("common") || n.contains("raft") {
        "directories"
    } else if n.contains("fuzz") {
        "fuzzing"
    } else {
        "general"
    }
}

fn index_file(db: &Db, path: &Path, category: Option<&str>, managed: bool) -> AppResult<i64> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(validation("Not a regular file"));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let category = match category {
        Some(c) => one_of("Category", c, CATEGORIES)?,
        None => guess_category(&name).to_string(),
    };
    let lines = count_lines(path);
    let path_str = path.to_string_lossy().to_string();
    db.with(|c| {
        c.execute(
            "INSERT INTO wordlists (name, path, category, size_bytes, line_count, managed, added_at, modified_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(path) DO UPDATE SET size_bytes=excluded.size_bytes, line_count=excluded.line_count, modified_at=excluded.modified_at",
            params![name, path_str, category, meta.len() as i64, lines, managed as i64, now(), modified(path)],
        )?;
        let id: i64 = c.query_row("SELECT id FROM wordlists WHERE path=?1", params![path_str], |r| r.get(0))?;
        log(c, "wordlist", &format!("Indexed wordlist {name}"), &path_str, Some("wordlist"), Some(&id.to_string()), None)?;
        Ok(id)
    })
}

#[tauri::command]
pub async fn wordlists_list(db: State<'_, Db>) -> AppResult<Vec<Wordlist>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, name, path, category, size_bytes, line_count, managed, added_at, modified_at FROM wordlists ORDER BY name COLLATE NOCASE",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let path: String = r.get(2)?;
                Ok(Wordlist {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    exists: touchable(&path) && Path::new(&path).is_file(),
                    path,
                    category: r.get(3)?,
                    size_bytes: r.get(4)?,
                    line_count: r.get(5)?,
                    managed: r.get::<_, i64>(6)? != 0,
                    added_at: r.get(7)?,
                    modified_at: r.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/* ─────────────── native dialogs (paths never come from the web view) ─────────────── */

async fn pick_files(app: &AppHandle) -> Vec<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Add wordlists");
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.pick_files(move |files| {
        let paths = files.unwrap_or_default().into_iter().filter_map(|f| f.into_path().ok()).collect::<Vec<_>>();
        let _ = tx.send(paths);
    });
    rx.await.unwrap_or_default()
}

async fn pick_folder(app: &AppHandle) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Choose a wordlist folder");
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.pick_folder(move |f| {
        let _ = tx.send(f.and_then(|p| p.into_path().ok()));
    });
    rx.await.ok().flatten()
}

async fn save_file(app: &AppHandle, suggested: &str) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut d = app.dialog().file().set_title("Export wordlist").set_file_name(suggested);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d.save_file(move |f| {
        let _ = tx.send(f.and_then(|p| p.into_path().ok()));
    });
    rx.await.ok().flatten()
}

const DIR_PREF: &str = "wordlists.directory";

fn extra_dir(db: &Db) -> AppResult<Option<PathBuf>> {
    db.with(|c| {
        let v: Option<String> =
            c.query_row("SELECT value FROM user_preferences WHERE key=?1", params![DIR_PREF], |r| r.get(0)).optional()?;
        Ok(v.and_then(|raw| serde_json::from_str::<String>(&raw).ok()).filter(|s| !s.is_empty()).map(PathBuf::from))
    })
}

fn set_extra_dir(db: &Db, dir: Option<&Path>) -> AppResult<()> {
    let value = serde_json::to_string(&dir.map(|d| d.to_string_lossy().to_string()).unwrap_or_default())?;
    db.with(|c| {
        c.execute(
            "INSERT INTO user_preferences (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![DIR_PREF, value, now()],
        )?;
        Ok(())
    })
}

/// Choose the extra wordlist folder with the native folder picker. Returns the chosen path.
#[tauri::command]
pub async fn wordlists_choose_directory(app: AppHandle, db: State<'_, Db>) -> AppResult<Option<String>> {
    let Some(dir) = pick_folder(&app).await else { return Ok(None) };
    if !dir.is_dir() {
        return Err(validation("The selected folder does not exist"));
    }
    set_extra_dir(&db, Some(&dir))?;
    Ok(Some(dir.to_string_lossy().to_string()))
}

#[tauri::command]
pub async fn wordlists_clear_directory(db: State<'_, Db>) -> AppResult<()> {
    set_extra_dir(&db, None)
}

/// Add files chosen in the native file picker. `copy` copies them into the managed directory.
/// Returns the ids of the indexed wordlists (empty when the dialog was cancelled).
#[tauri::command]
pub async fn wordlists_pick(app: AppHandle, copy: bool, category: Option<String>) -> AppResult<Vec<i64>> {
    let paths = pick_files(&app).await;
    if paths.len() > 200 {
        return Err(validation("Select at most 200 files"));
    }
    let dir = managed_dir(&app)?;
    let mut ids = Vec::new();
    for src in paths {
        if !src.is_file() {
            return Err(validation(format!("Not a file: {}", src.display())));
        }
        let target = if copy {
            let name = src.file_name().ok_or_else(|| validation("Invalid file name"))?;
            let mut dest = dir.join(name);
            let mut i = 1;
            while dest.exists() {
                dest = dir.join(format!("{}-{i}", name.to_string_lossy()));
                i += 1;
            }
            let (s, d) = (src.clone(), dest.clone());
            tauri::async_runtime::spawn_blocking(move || std::fs::copy(s, d))
                .await
                .map_err(|e| AppError::Internal(e.to_string()))??;
            dest
        } else {
            src
        };
        // counting lines reads up to 512 MB: keep it off the async runtime
        let (app2, category) = (app.clone(), category.clone());
        let id = tauri::async_runtime::spawn_blocking(move || index_file(&app2.state::<Db>(), &target, category.as_deref(), copy))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
        ids.push(id);
    }
    Ok(ids)
}

/// Index every file in the managed directory and the extra folder chosen in Settings.
#[tauri::command]
pub async fn wordlists_scan(app: AppHandle, db: State<'_, Db>) -> AppResult<usize> {
    let mut dirs = vec![(managed_dir(&app)?, true)];
    if let Some(p) = extra_dir(&db)? {
        if !p.is_dir() {
            return Err(validation(format!("The wordlist folder {} no longer exists; choose it again in Settings", p.display())));
        }
        dirs.push((p, false));
    }
    // indexing counts lines of every file: run it off the async runtime
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<usize> {
        let db = app2.state::<Db>();
        let mut count = 0;
        for (dir, managed) in dirs {
            for entry in std::fs::read_dir(&dir)?.flatten().take(5000) {
                let p = entry.path();
                if p.is_file() {
                    index_file(&db, &p, None, managed)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
}

#[tauri::command]
pub async fn wordlist_update(db: State<'_, Db>, id: i64, name: String, category: String) -> AppResult<()> {
    let name = clean("Name", &name, 200, true)?;
    let category = one_of("Category", &category, CATEGORIES)?;
    db.with(|c| {
        c.execute("UPDATE wordlists SET name=?2, category=?3 WHERE id=?1", params![id, name, category])?;
        Ok(())
    })
}

/// Remove from the index. Managed copies may also be deleted from disk; files that
/// were indexed by reference are never deleted.
#[tauri::command]
pub async fn wordlist_remove(app: AppHandle, db: State<'_, Db>, id: i64, delete_file: bool) -> AppResult<()> {
    let row: Option<(String, bool)> = db.with(|c| {
        Ok(c.query_row("SELECT path, managed FROM wordlists WHERE id=?1", params![id], |r| {
            Ok((r.get(0)?, r.get::<_, i64>(1)? != 0))
        })
        .optional()?)
    })?;
    let (path, managed) = row.ok_or_else(|| AppError::NotFound(format!("wordlist {id}")))?;
    if delete_file {
        if !managed {
            return Err(validation("Only copies in the managed directory can be deleted from disk"));
        }
        let p = PathBuf::from(&path);
        let dir = managed_dir(&app)?.canonicalize()?;
        if p.exists() {
            let canon = p.canonicalize()?;
            if !canon.starts_with(&dir) {
                return Err(validation("Refusing to delete a file outside the managed directory"));
            }
            std::fs::remove_file(canon)?;
        }
    }
    db.with(|c| {
        c.execute("DELETE FROM wordlists WHERE id=?1", params![id])?;
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WordlistPreview {
    pub lines: Vec<String>,
    pub scanned_lines: i64,
    pub truncated: bool,
}

/// Preview lines (optionally filtered by a substring). Reads at most 64 MB.
#[tauri::command]
pub async fn wordlist_preview(app: AppHandle, db: State<'_, Db>, id: i64, filter: Option<String>, limit: Option<usize>) -> AppResult<WordlistPreview> {
    let (path, managed): (String, bool) = db.with(|c| {
        c.query_row("SELECT path, managed FROM wordlists WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("wordlist {id}")))
    })?;
    let path = readable_path(&app, &path, managed)?;
    let limit = limit.unwrap_or(500).clamp(1, 5000);
    let filter = filter.map(|f| f.to_lowercase()).filter(|f| !f.is_empty());
    tauri::async_runtime::spawn_blocking(move || -> AppResult<WordlistPreview> {
        // the indexed path may have been replaced by a pipe or device since: never block on it
        let file = crate::util::open_regular(&path).map_err(|_| validation("The wordlist is no longer a regular file"))?;
        let reader = BufReader::new(file.take(64 * 1024 * 1024));
        let mut lines = Vec::new();
        let mut scanned = 0i64;
        let mut truncated = false;
        for line in reader.split(b'\n') {
            let raw = line?;
            scanned += 1;
            let text = String::from_utf8_lossy(&raw).trim_end_matches('\r').to_string();
            let keep = filter.as_ref().map(|f| text.to_lowercase().contains(f)).unwrap_or(true);
            if keep {
                if lines.len() >= limit {
                    truncated = true;
                    break;
                }
                lines.push(text.chars().take(500).collect());
            }
        }
        Ok(WordlistPreview { lines, scanned_lines: scanned, truncated })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
}

/// Export (copy) a wordlist to a destination chosen in the native save dialog.
/// Returns the number of bytes written, or None when the dialog was cancelled.
#[tauri::command]
pub async fn wordlist_export(app: AppHandle, db: State<'_, Db>, id: i64) -> AppResult<Option<u64>> {
    let (path, name, managed): (String, String, bool) = db.with(|c| {
        c.query_row("SELECT path, name, managed FROM wordlists WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("wordlist {id}")))
    })?;
    let src = readable_path(&app, &path, managed)?;
    if !src.is_file() {
        return Err(validation(format!("{} no longer exists", src.display())));
    }
    let Some(dest) = save_file(&app, &name).await else { return Ok(None) };
    if dest.is_dir() {
        return Err(validation("Destination must be a file path"));
    }
    if let (Ok(a), Ok(b)) = (src.canonicalize(), dest.canonicalize()) {
        if a == b {
            return Err(validation("Destination is the source file"));
        }
    }
    let bytes = tauri::async_runtime::spawn_blocking(move || std::fs::copy(src, dest))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Some(bytes))
}

#[tauri::command]
pub async fn wordlists_dir(app: AppHandle) -> AppResult<String> {
    Ok(managed_dir(&app)?.to_string_lossy().to_string())
}

#[cfg(test)]
mod path_tests {
    /// Mission 7: on Windows, a wordlist's network or device path is never touched, not even to
    /// check that it exists.
    #[test]
    fn network_paths_are_never_touched_on_windows() {
        assert!(super::touchable("/usr/share/wordlists/rockyou.txt") && super::touchable(r"C:\lists\a.txt"));
        assert_eq!(super::touchable(r"\\203.0.113.5\share\a.txt"), !cfg!(windows));
        assert_eq!(super::touchable("//203.0.113.5/share/a.txt"), !cfg!(windows));
    }
}
