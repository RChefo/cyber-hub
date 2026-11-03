//! Local SQLite storage. All persistence goes through this module; the frontend
//! never receives raw SQL access.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{AppError, AppResult};

pub struct Db {
    conn: Mutex<Connection>,
}

/// Ordered list of migrations. Never edit a shipped migration — append a new one.
const MIGRATIONS: &[&str] = &[
    // 1 — initial schema
    r#"
    CREATE TABLE user_preferences (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE favorites (
        kind TEXT NOT NULL,
        item_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (kind, item_id)
    );

    CREATE TABLE tool_categories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        sort_order INTEGER NOT NULL
    );

    CREATE TABLE tools (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category_id TEXT NOT NULL REFERENCES tool_categories(id),
        catalog_version INTEGER NOT NULL
    );

    CREATE TABLE tool_installations (
        tool_id TEXT PRIMARY KEY REFERENCES tools(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK (status IN ('installed','not_installed','dependency_missing','installation_failed','unsupported_os')),
        path TEXT,
        version TEXT,
        missing_dependencies TEXT NOT NULL DEFAULT '[]',
        message TEXT,
        checked_at TEXT NOT NULL
    );

    CREATE TABLE resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );

    CREATE TABLE resource_visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_key TEXT NOT NULL,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        visited_at TEXT NOT NULL
    );
    CREATE INDEX idx_resource_visits_time ON resource_visits(visited_at DESC);

    CREATE TABLE projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL CHECK (status IN ('planning','active','paused','completed','archived')),
        scope_notes TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        start_date TEXT,
        end_date TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE project_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        value TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('domain','wildcard','ip','cidr','url')),
        in_scope INTEGER NOT NULL DEFAULT 1,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE (project_id, value)
    );

    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
        status TEXT NOT NULL CHECK (status IN ('open','confirmed','reported','resolved','false_positive')),
        description TEXT NOT NULL DEFAULT '',
        affected_target TEXT NOT NULL DEFAULT '',
        cve TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX idx_findings_project ON findings(project_id);

    CREATE TABLE command_categories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL
    );
    INSERT INTO command_categories (id, name) VALUES
        ('general','General'), ('network','Network'), ('web','Web'), ('recon','Recon'),
        ('password','Password Auditing'), ('forensics','Forensics'), ('system','System');

    CREATE TABLE commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        command TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        category_id TEXT NOT NULL DEFAULT 'general' REFERENCES command_categories(id),
        os TEXT NOT NULL DEFAULT 'any' CHECK (os IN ('any','windows','macos','linux')),
        tags TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE command_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command TEXT NOT NULL,
        source TEXT NOT NULL,
        tool_id TEXT,
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_command_history_time ON command_history(created_at DESC);

    CREATE TABLE saved_dorks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        query TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'custom',
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE dork_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE payloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        payload TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        context TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL
    );

    CREATE TABLE wordlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        path TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL DEFAULT 'general',
        size_bytes INTEGER NOT NULL,
        line_count INTEGER,
        managed INTEGER NOT NULL DEFAULT 0,
        added_at TEXT NOT NULL,
        modified_at TEXT
    );

    CREATE TABLE activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        ref_kind TEXT,
        ref_id TEXT,
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_activity_time ON activity_logs(created_at DESC);

    CREATE TABLE executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('run','install')),
        program TEXT NOT NULL,
        args TEXT NOT NULL,
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','cancelled','error')),
        exit_code INTEGER,
        output TEXT NOT NULL DEFAULT '',
        truncated INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE INDEX idx_executions_time ON executions(started_at DESC);

    CREATE TABLE cve_cache (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    );

    CREATE TABLE cve_search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        result_count INTEGER NOT NULL,
        live INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        done INTEGER NOT NULL DEFAULT 0,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        due_date TEXT,
        created_at TEXT NOT NULL
    );
    "#,
];

impl Db {
    pub fn open(path: &Path) -> AppResult<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> AppResult<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> AppResult<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
        )?;
        let db = Db { conn: Mutex::new(conn) };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> AppResult<()> {
        self.with(|conn| {
            let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            for (idx, sql) in MIGRATIONS.iter().enumerate() {
                let version = (idx + 1) as i64;
                if version > current {
                    let tx = conn.unchecked_transaction()?;
                    tx.execute_batch(sql)?;
                    tx.execute_batch(&format!("PRAGMA user_version = {version}"))?;
                    tx.commit()?;
                }
            }
            Ok(())
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".into()))?;
        f(&guard)
    }

    pub fn schema_version(&self) -> AppResult<i64> {
        self.with(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_cleanly() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
        // re-running is a no-op
        db.migrate().unwrap();
        let fk: i64 = db.with(|c| Ok(c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?)).unwrap();
        assert_eq!(fk, 1);
    }
}
