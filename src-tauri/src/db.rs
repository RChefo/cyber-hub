//! Local SQLite storage. All persistence goes through this module; the frontend
//! never receives raw SQL access.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{AppError, AppResult};

/// History tables that are trimmed to their newest rows (table, rows kept). Several of them
/// are written by lookups that MCP clients may make without an approval, so they must not grow
/// without bound.
pub const HISTORY_LIMITS: &[(&str, i64)] = &[("activity_logs", 5000), ("cve_search_history", 500), ("command_history", 2000), ("dork_history", 500)];

/// Lookup caches (keyed by indicator or CVE ID) trimmed at startup to their most recently fetched
/// entries, so distinct lookups cannot grow the database without bound.
const CACHE_LIMITS: &[(&str, i64)] = &[("vt_cache", 5000), ("ti_cache", 10000), ("cve_cache", 20000), ("osint_source_cache", 5000)];

/// Keep the newest rows of a history table listed in [`HISTORY_LIMITS`]; other names are ignored.
pub fn trim_history(c: &Connection, table: &str) -> rusqlite::Result<usize> {
    let Some(&(table, keep)) = HISTORY_LIMITS.iter().find(|(t, _)| *t == table) else {
        debug_assert!(false, "{table} is not a history table");
        return Ok(0);
    };
    c.execute(&format!("DELETE FROM {table} WHERE id <= (SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?1)"), [keep])
}

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
    // 2 — VirusTotal reputation cache (also serves as lookup history)
    r#"
    CREATE TABLE vt_cache (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('ip','domain','url','file')),
        indicator TEXT NOT NULL,
        data TEXT,
        not_found INTEGER NOT NULL DEFAULT 0,
        fetched_at TEXT NOT NULL
    );
    CREATE INDEX idx_vt_cache_time ON vt_cache(fetched_at DESC);
    "#,
    // 3 — threat-intelligence providers: per-provider cache, search history, saved indicators,
    //     provider enablement
    r#"
    CREATE TABLE ti_cache (
        provider TEXT NOT NULL,
        indicator_key TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('ip','domain','url','file')),
        indicator TEXT NOT NULL,
        found INTEGER NOT NULL,
        data TEXT NOT NULL,
        quota TEXT,
        fetched_at TEXT NOT NULL,
        PRIMARY KEY (provider, indicator_key)
    );
    CREATE TABLE ti_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK (kind IN ('ip','domain','url','file')),
        indicator TEXT NOT NULL,
        summary TEXT NOT NULL,
        searched_at TEXT NOT NULL
    );
    CREATE INDEX idx_ti_history_time ON ti_history(searched_at DESC);
    CREATE TABLE ti_saved (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK (kind IN ('ip','domain','url','file')),
        indicator TEXT NOT NULL UNIQUE,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE ti_provider_settings (
        provider TEXT PRIMARY KEY,
        enabled INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    );
    "#,
    // 4 — MCP audit log (one row per MCP tool call; arguments are redacted)
    r#"
    CREATE TABLE mcp_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        client TEXT NOT NULL,
        connection INTEGER NOT NULL,
        tool TEXT NOT NULL,
        arguments TEXT NOT NULL,
        project_id INTEGER,
        approval TEXT NOT NULL,
        approval_id TEXT,
        execution_id INTEGER,
        result TEXT NOT NULL,
        message TEXT NOT NULL DEFAULT '',
        duration_ms INTEGER NOT NULL
    );
    CREATE INDEX idx_mcp_audit_time ON mcp_audit(id DESC);
    "#,
    // 5 — permission category that applied to each MCP call (NULL for unknown tools)
    r#"
    ALTER TABLE mcp_audit ADD COLUMN category TEXT;
    "#,
    // 6 — per-project run history and project deletion (ON DELETE SET NULL) look runs up by project
    r#"
    CREATE INDEX idx_executions_project ON executions(project_id, id DESC);
    "#,
    // 7 — OSINT workspace: investigations, entities, relationships, evidence, discovery
    // operations, timeline, saved graphs (membership + presentation) and graph versions
    r#"
    CREATE TABLE osint_investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        target_type TEXT NOT NULL,
        target_value TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','closed')),
        tags TEXT NOT NULL DEFAULT '[]',
        notes TEXT NOT NULL DEFAULT '',
        authorization TEXT NOT NULL DEFAULT '',
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_opened_at TEXT
    );

    CREATE TABLE osint_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        match_key TEXT NOT NULL,
        display_name TEXT NOT NULL,
        aliases TEXT NOT NULL DEFAULT '[]',
        metadata TEXT NOT NULL DEFAULT '{}',
        confidence TEXT NOT NULL DEFAULT 'medium',
        verification TEXT NOT NULL DEFAULT 'observed',
        flagged INTEGER NOT NULL DEFAULT 0,
        notes TEXT NOT NULL DEFAULT '',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE (investigation_id, type, match_key)
    );
    CREATE INDEX idx_osint_entities_type ON osint_entities(investigation_id, type);

    CREATE TABLE osint_relationships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        source_id INTEGER NOT NULL REFERENCES osint_entities(id) ON DELETE CASCADE,
        target_id INTEGER NOT NULL REFERENCES osint_entities(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        directed INTEGER NOT NULL DEFAULT 1,
        origin TEXT NOT NULL CHECK (origin IN ('observed','derived','inferred','manual','suggested')),
        confidence TEXT NOT NULL DEFAULT 'medium',
        confidence_reason TEXT NOT NULL DEFAULT '',
        verification TEXT NOT NULL DEFAULT 'observed',
        metadata TEXT NOT NULL DEFAULT '{}',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE (investigation_id, source_id, target_id, type)
    );
    CREATE INDEX idx_osint_rel_source ON osint_relationships(source_id);
    CREATE INDEX idx_osint_rel_target ON osint_relationships(target_id);
    CREATE INDEX idx_osint_rel_investigation ON osint_relationships(investigation_id, type);

    CREATE TABLE osint_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        input_type TEXT NOT NULL,
        input_value TEXT NOT NULL,
        input_entity_id INTEGER REFERENCES osint_entities(id) ON DELETE SET NULL,
        status TEXT NOT NULL CHECK (status IN ('running','completed','failed','cancelled')),
        requested_by TEXT NOT NULL DEFAULT 'user',
        started_at TEXT NOT NULL,
        finished_at TEXT,
        result_count INTEGER NOT NULL DEFAULT 0,
        message TEXT,
        results TEXT,
        imported_at TEXT,
        imported_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_osint_ops ON osint_operations(investigation_id, id DESC);

    CREATE TABLE osint_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        source TEXT NOT NULL,
        reference TEXT,
        observed_at TEXT NOT NULL,
        collected_at TEXT NOT NULL,
        operation_id INTEGER REFERENCES osint_operations(id) ON DELETE SET NULL,
        execution_id INTEGER REFERENCES executions(id) ON DELETE SET NULL,
        summary TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}',
        strength TEXT NOT NULL CHECK (strength IN ('direct','corroborating','weak')),
        fingerprint TEXT NOT NULL,
        UNIQUE (investigation_id, fingerprint)
    );
    CREATE TABLE osint_entity_evidence (
        entity_id INTEGER NOT NULL REFERENCES osint_entities(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES osint_evidence(id) ON DELETE CASCADE,
        PRIMARY KEY (entity_id, evidence_id)
    );
    CREATE INDEX idx_osint_ee_evidence ON osint_entity_evidence(evidence_id);
    CREATE TABLE osint_relationship_evidence (
        relationship_id INTEGER NOT NULL REFERENCES osint_relationships(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES osint_evidence(id) ON DELETE CASCADE,
        strength TEXT NOT NULL,
        PRIMARY KEY (relationship_id, evidence_id)
    );
    CREATE INDEX idx_osint_re_evidence ON osint_relationship_evidence(evidence_id);

    CREATE TABLE osint_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        at TEXT NOT NULL,
        kind TEXT NOT NULL,
        summary TEXT NOT NULL,
        source TEXT,
        entity_id INTEGER REFERENCES osint_entities(id) ON DELETE SET NULL,
        relationship_id INTEGER REFERENCES osint_relationships(id) ON DELETE SET NULL,
        operation_id INTEGER REFERENCES osint_operations(id) ON DELETE SET NULL,
        graph_id INTEGER,
        data TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_osint_events ON osint_events(investigation_id, at DESC);
    CREATE INDEX idx_osint_events_entity ON osint_events(entity_id);

    CREATE TABLE osint_graphs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        follow_new INTEGER NOT NULL DEFAULT 1,
        revision INTEGER NOT NULL DEFAULT 1,
        workspace TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_opened_at TEXT
    );
    CREATE INDEX idx_osint_graphs ON osint_graphs(investigation_id);
    CREATE TABLE osint_graph_nodes (
        graph_id INTEGER NOT NULL REFERENCES osint_graphs(id) ON DELETE CASCADE,
        entity_id INTEGER NOT NULL REFERENCES osint_entities(id) ON DELETE CASCADE,
        x REAL,
        y REAL,
        pinned INTEGER NOT NULL DEFAULT 0,
        hidden INTEGER NOT NULL DEFAULT 0,
        group_id TEXT,
        PRIMARY KEY (graph_id, entity_id)
    );
    CREATE INDEX idx_osint_graph_nodes_entity ON osint_graph_nodes(entity_id);
    CREATE TABLE osint_graph_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        graph_id INTEGER NOT NULL REFERENCES osint_graphs(id) ON DELETE CASCADE,
        number INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('save','manual','restore','import','created')),
        label TEXT NOT NULL DEFAULT '',
        content_hash TEXT NOT NULL,
        snapshot TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '{}',
        UNIQUE (graph_id, number)
    );

    CREATE TABLE osint_entity_merges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER NOT NULL REFERENCES osint_investigations(id) ON DELETE CASCADE,
        kept_id INTEGER NOT NULL,
        merged_id INTEGER NOT NULL,
        merged_type TEXT NOT NULL,
        merged_value TEXT NOT NULL,
        merged_at TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE osint_source_cache (
        provider TEXT NOT NULL,
        query_key TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (provider, query_key)
    );
    "#,
    // 8: graph state revision for optimistic concurrency. `revision` also changes when
    // collected entities join a graph automatically; `state_revision` changes only when the
    // presentation state is written (save, restore), so only conflicting edits are refused.
    r#"
    ALTER TABLE osint_graphs ADD COLUMN state_revision INTEGER NOT NULL DEFAULT 0;
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
        db.with(|c| {
            for (table, _) in HISTORY_LIMITS {
                trim_history(c, table)?;
            }
            for (table, keep) in CACHE_LIMITS {
                c.execute(&format!("DELETE FROM {table} WHERE rowid NOT IN (SELECT rowid FROM {table} ORDER BY fetched_at DESC LIMIT ?1)"), [keep])?;
            }
            // Only one instance runs at a time, so a run still marked as running was interrupted
            // (crash or power loss); record that instead of showing it as running forever.
            c.execute("UPDATE executions SET status = 'error', finished_at = COALESCE(finished_at, ?1) WHERE status = 'running'", [crate::util::now()])?;
            Ok(())
        })?;
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
    fn databases_from_the_previous_schema_are_upgraded_in_place() {
        // a database as the previous release left it (schema 7) with an investigation and a graph
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for (i, sql) in MIGRATIONS.iter().take(7).enumerate() {
            conn.execute_batch(sql).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {}", i + 1)).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO osint_investigations (id, name, description, target_type, target_value, status, tags, notes, authorization, created_at, updated_at)
               VALUES (1, 'Old', '', 'domain', 'example.com', 'active', '[]', '', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO osint_graphs (id, investigation_id, name, description, follow_new, revision, workspace, created_at, updated_at)
               VALUES (1, 1, 'Main graph', '', 1, 3, '{}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
        let (rev, state): (i64, i64) = db.with(|c| Ok(c.query_row("SELECT revision, state_revision FROM osint_graphs WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))?)).unwrap();
        assert_eq!((rev, state), (3, 0), "existing graphs keep their data and start at state revision 0");
    }

    #[test]
    fn reopening_marks_interrupted_runs_and_indexes_runs_by_project() {
        let path = std::env::temp_dir().join(format!("cyberhub-dbtest-{}-{}.db", std::process::id(), crate::util::now().replace(':', "")));
        {
            let db = Db::open(&path).unwrap();
            db.with(|c| {
                c.execute("INSERT INTO executions (tool_id, kind, program, args, status, started_at) VALUES ('nmap','run','nmap','[]','running','t')", [])?;
                c.execute("INSERT INTO executions (tool_id, kind, program, args, status, started_at, finished_at) VALUES ('nmap','run','nmap','[]','succeeded','t','t2')", [])?;
                let idx: i64 = c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_executions_project'", [], |r| r.get(0))?;
                assert_eq!(idx, 1);
                Ok(())
            })
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let rows: Vec<(String, Option<String>)> = db
            .with(|c| {
                let mut st = c.prepare("SELECT status, finished_at FROM executions ORDER BY id")?;
                let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
                Ok(v)
            })
            .unwrap();
        drop(db);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        assert_eq!(rows[0].0, "error", "an interrupted run is not shown as running forever");
        assert!(rows[0].1.is_some());
        assert_eq!(rows[1], ("succeeded".to_string(), Some("t2".to_string())), "finished runs are untouched");
    }

    #[test]
    fn history_tables_keep_only_their_newest_rows() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            for i in 0..520 {
                c.execute("INSERT INTO cve_search_history (query, result_count, live, created_at) VALUES (?1, 0, 0, 't')", [format!("q{i}")])?;
            }
            assert_eq!(trim_history(c, "cve_search_history")?, 20);
            let n: i64 = c.query_row("SELECT COUNT(*) FROM cve_search_history", [], |r| r.get(0))?;
            assert_eq!(n, 500);
            let first: String = c.query_row("SELECT query FROM cve_search_history ORDER BY id LIMIT 1", [], |r| r.get(0))?;
            assert_eq!(first, "q20", "the oldest rows are removed");
            // a second trim removes nothing
            assert_eq!(trim_history(c, "cve_search_history")?, 0);
            Ok(())
        })
        .unwrap();
    }

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
