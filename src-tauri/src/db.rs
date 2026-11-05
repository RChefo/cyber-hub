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
const CACHE_LIMITS: &[(&str, i64)] = &[("vt_cache", 5000), ("ti_cache", 10000), ("cve_cache", 20000), ("osint_source_cache", 5000), ("epss_cache", 20000)];

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
    // 9: shared data foundation (docs/DATA_MODEL.md): findings lifecycle and history, finding
    // links, scope audit, assets with observations and discovery snapshots, evidence registry,
    // project timeline. Existing findings keep their ids and data; old statuses are mapped
    // (open → new, reported → confirmed, the latter recorded in the finding's history).
    r#"
    CREATE TABLE findings_v9 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
        status TEXT NOT NULL CHECK (status IN ('new','under_review','confirmed','accepted_risk','in_remediation','resolved','reopened','false_positive')),
        category TEXT NOT NULL DEFAULT '',
        confidence TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
        description TEXT NOT NULL DEFAULT '',
        affected_target TEXT NOT NULL DEFAULT '',
        cve TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '[]',
        reproduction TEXT NOT NULL DEFAULT '',
        technical_details TEXT NOT NULL DEFAULT '',
        remediation TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'manual',
        tags TEXT NOT NULL DEFAULT '[]',
        assignee TEXT NOT NULL DEFAULT '',
        due_date TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    INSERT INTO findings_v9 (id, project_id, title, severity, status, description, affected_target, cve, evidence, created_at, updated_at)
        SELECT id, project_id, title, severity,
               CASE status WHEN 'open' THEN 'new' WHEN 'reported' THEN 'confirmed' ELSE status END,
               description, affected_target, cve, evidence, created_at, updated_at
        FROM findings;
    CREATE TEMP TABLE finding_status_v8 AS SELECT id, status FROM findings;
    DROP TABLE findings;
    ALTER TABLE findings_v9 RENAME TO findings;
    CREATE INDEX idx_findings_project ON findings(project_id, status);

    CREATE TABLE finding_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('created','status','updated','note','link','unlink','migrated')),
        from_status TEXT,
        to_status TEXT,
        note TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'user',
        at TEXT NOT NULL
    );
    CREATE INDEX idx_finding_events ON finding_events(finding_id, id);
    INSERT INTO finding_events (finding_id, project_id, kind, to_status, note, source, at)
        SELECT f.id, f.project_id, 'created', f.status, 'Recorded before finding history existed', 'migration', f.created_at FROM findings f;
    INSERT INTO finding_events (finding_id, project_id, kind, from_status, to_status, note, source, at)
        SELECT f.id, f.project_id, 'migrated', 'reported', 'confirmed', 'The status “Reported” of earlier versions is now “Confirmed”', 'migration',
               strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
        FROM findings f JOIN finding_status_v8 o ON o.id = f.id WHERE o.status = 'reported';
    DROP TABLE finding_status_v8;

    CREATE TABLE finding_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('asset','vulnerability','osint_entity','execution','evidence')),
        ref_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (finding_id, kind, ref_id)
    );
    CREATE INDEX idx_finding_links_ref ON finding_links(kind, ref_id);

    CREATE TABLE scope_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        action TEXT NOT NULL CHECK (action IN ('added','updated','removed','blocked')),
        value TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT '',
        in_scope INTEGER,
        note TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'user',
        at TEXT NOT NULL
    );
    CREATE INDEX idx_scope_events ON scope_events(project_id, id DESC);
    INSERT INTO scope_events (project_id, action, value, kind, in_scope, note, source, at)
        SELECT project_id, 'added', value, kind, in_scope, note, 'migration', created_at FROM project_targets;

    CREATE TABLE discovery_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        mode TEXT NOT NULL CHECK (mode IN ('passive','active','manual')),
        source TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('running','completed','partial','failed','cancelled')),
        operation_id INTEGER REFERENCES osint_operations(id) ON DELETE SET NULL,
        execution_id INTEGER REFERENCES executions(id) ON DELETE SET NULL,
        note TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE INDEX idx_discovery_snapshots ON discovery_snapshots(project_id, id DESC);

    CREATE TABLE assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        type TEXT NOT NULL CHECK (type IN ('domain','subdomain','ip','dns_record','service','http_service','certificate','technology','endpoint')),
        value TEXT NOT NULL,
        key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','not_observed','retired')),
        confidence TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
        source TEXT NOT NULL,
        osint_entity_id INTEGER REFERENCES osint_entities(id) ON DELETE SET NULL,
        data TEXT NOT NULL DEFAULT '{}',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (project_id, type, key)
    );
    CREATE INDEX idx_assets_project ON assets(project_id, type, status);
    CREATE TABLE asset_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        snapshot_id INTEGER REFERENCES discovery_snapshots(id) ON DELETE SET NULL,
        observed_at TEXT NOT NULL,
        source TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}',
        fingerprint TEXT NOT NULL
    );
    CREATE INDEX idx_asset_observations ON asset_observations(asset_id, id DESC);
    CREATE INDEX idx_asset_observations_snapshot ON asset_observations(snapshot_id);

    CREATE TABLE evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('file','text','execution','osint_evidence')),
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'user',
        sha256 TEXT,
        size INTEGER,
        file_name TEXT,
        content TEXT,
        execution_id INTEGER REFERENCES executions(id) ON DELETE SET NULL,
        osint_evidence_id INTEGER REFERENCES osint_evidence(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_evidence_project ON evidence(project_id, id DESC);
    CREATE UNIQUE INDEX idx_evidence_file ON evidence(project_id, sha256) WHERE kind = 'file';
    CREATE UNIQUE INDEX idx_evidence_execution ON evidence(project_id, execution_id) WHERE kind = 'execution';
    CREATE UNIQUE INDEX idx_evidence_osint ON evidence(project_id, osint_evidence_id) WHERE kind = 'osint_evidence';

    CREATE TABLE timeline_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        ref_kind TEXT,
        ref_id INTEGER,
        at TEXT NOT NULL
    );
    CREATE INDEX idx_timeline_events ON timeline_events(project_id, at DESC);
    "#,
    // 10: vulnerability management (docs/DATA_MODEL.md): vulnerabilities per project (CVE, optional
    // asset), transparent priority with its reasons, remediation and verification, append-only
    // history, and the optional EPSS score cache.
    r#"
    CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        cve_id TEXT NOT NULL,
        asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
        title TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','triaged','in_remediation','mitigated','resolved','accepted_risk','false_positive')),
        cvss_score REAL,
        cvss_version TEXT,
        cvss_vector TEXT,
        kev INTEGER NOT NULL DEFAULT 0,
        epss REAL,
        epss_percentile REAL,
        epss_date TEXT,
        exploit_known INTEGER NOT NULL DEFAULT 0,
        exposure TEXT NOT NULL DEFAULT 'unknown' CHECK (exposure IN ('internet','internal','unknown')),
        criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low','medium','high')),
        priority TEXT NOT NULL CHECK (priority IN ('p1','p2','p3','p4')),
        priority_score REAL NOT NULL,
        priority_reasons TEXT NOT NULL DEFAULT '[]',
        remediation TEXT NOT NULL DEFAULT '',
        remediation_owner TEXT NOT NULL DEFAULT '',
        remediation_due TEXT,
        verified_at TEXT,
        verification_note TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX idx_vulnerabilities_unique ON vulnerabilities(project_id, cve_id, COALESCE(asset_id, 0));
    CREATE INDEX idx_vulnerabilities_project ON vulnerabilities(project_id, status, priority);
    CREATE INDEX idx_vulnerabilities_asset ON vulnerabilities(asset_id);
    CREATE TABLE vulnerability_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('created','status','priority','remediation','verification','note','updated')),
        from_value TEXT,
        to_value TEXT,
        note TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'user',
        at TEXT NOT NULL
    );
    CREATE INDEX idx_vulnerability_events ON vulnerability_events(vulnerability_id, id);
    CREATE INDEX idx_vulnerability_events_project ON vulnerability_events(project_id, at);
    CREATE TABLE epss_cache (
        cve_id TEXT PRIMARY KEY,
        epss REAL NOT NULL,
        percentile REAL NOT NULL,
        score_date TEXT NOT NULL,
        fetched_at TEXT NOT NULL
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
            // likewise discovery runs: nothing found by an interrupted run is treated as removed
            c.execute(
                "UPDATE discovery_snapshots SET status = 'failed', note = 'Interrupted: Cyber Hub was closed while it ran', finished_at = COALESCE(finished_at, ?1) WHERE status = 'running'",
                [crate::util::now()],
            )?;
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

    /// A database as release 0.1 left it (schema 8): a project with scope entries, a tool run and
    /// a finding in every status of that release.
    fn schema8_with_data() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for (i, sql) in MIGRATIONS.iter().take(8).enumerate() {
            conn.execute_batch(sql).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {}", i + 1)).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (7, 'Acme', 'active', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z');
             INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES
               (7, 'example.com', 'domain', 1, '', '2026-01-01T00:00:00Z'),
               (7, 'vpn.example.com', 'domain', 0, 'Production VPN', '2026-01-01T00:01:00Z');
             INSERT INTO executions (id, tool_id, kind, program, args, project_id, status, started_at) VALUES (3, 'nmap', 'run', 'nmap', '[]', 7, 'succeeded', '2026-01-03T00:00:00Z');
             INSERT INTO findings (id, project_id, title, severity, status, description, affected_target, cve, evidence, created_at, updated_at) VALUES
               (11, 7, 'Open',     'high',     'open',           'd1', 'a.example.com', '',               '[{\"label\":\"Request\",\"reference\":\"req.txt\"}]', '2026-01-04T00:00:00Z', '2026-01-04T00:00:00Z'),
               (12, 7, 'Conf',     'critical', 'confirmed',      'd2', 'b.example.com', 'CVE-2021-44228', '[]', '2026-01-05T00:00:00Z', '2026-01-05T00:00:00Z'),
               (13, 7, 'Reported', 'medium',   'reported',       'd3', '',              '',               '[]', '2026-01-06T00:00:00Z', '2026-01-06T00:00:00Z'),
               (14, 7, 'Fixed',    'low',      'resolved',       '',   '',              '',               '[]', '2026-01-07T00:00:00Z', '2026-01-07T00:00:00Z'),
               (15, 7, 'FP',       'info',     'false_positive', '',   '',              '',               '[]', '2026-01-08T00:00:00Z', '2026-01-08T00:00:00Z');",
        )
        .unwrap();
        conn
    }

    fn count(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn findings_and_scope_of_release_0_1_survive_the_upgrade_with_history() {
        let db = Db::init(schema8_with_data()).unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
        db.with(|c| {
            // every column as text: id, title, severity, status, description, affected_target, cve,
            // evidence, created_at, updated_at, source, confidence
            let mut st = c.prepare("SELECT CAST(id AS TEXT), title, severity, status, description, affected_target, cve, evidence, created_at, updated_at, source, confidence FROM findings ORDER BY id")?;
            let rows: Vec<Vec<String>> = st.query_map([], |r| (0..12).map(|i| r.get::<_, String>(i)).collect())?.collect::<Result<_, _>>()?;
            let statuses: Vec<(&str, &str)> = rows.iter().map(|r| (r[0].as_str(), r[3].as_str())).collect();
            assert_eq!(statuses, vec![("11", "new"), ("12", "confirmed"), ("13", "confirmed"), ("14", "resolved"), ("15", "false_positive")], "ids are kept and old statuses are mapped");
            assert_eq!((rows[0][4].as_str(), rows[0][5].as_str(), rows[0][7].as_str()), ("d1", "a.example.com", "[{\"label\":\"Request\",\"reference\":\"req.txt\"}]"));
            assert_eq!((rows[1][6].as_str(), rows[1][2].as_str()), ("CVE-2021-44228", "critical"));
            assert_eq!((rows[2][8].as_str(), rows[2][9].as_str()), ("2026-01-06T00:00:00Z", "2026-01-06T00:00:00Z"), "timestamps are untouched");
            assert!(rows.iter().all(|r| r[10] == "manual" && r[11] == "medium"), "new columns get neutral defaults");

            assert_eq!(count(c, "SELECT COUNT(*) FROM finding_events WHERE kind = 'created' AND source = 'migration'"), 5);
            let created_at: String = c.query_row("SELECT at FROM finding_events WHERE finding_id = 13 AND kind = 'created'", [], |r| r.get(0))?;
            assert_eq!(created_at, "2026-01-06T00:00:00Z", "history starts when the finding was recorded");
            let migrated: (i64, String, String) = c.query_row("SELECT finding_id, from_status, to_status FROM finding_events WHERE kind = 'migrated'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            assert_eq!(migrated, (13, "reported".into(), "confirmed".into()), "only the renamed status is recorded as migrated");

            let scope: Vec<(String, i64)> = c.prepare("SELECT value, in_scope FROM scope_events WHERE action = 'added' AND source = 'migration' ORDER BY id")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            assert_eq!(scope, vec![("example.com".into(), 1), ("vpn.example.com".into(), 0)]);
            assert_eq!(count(c, "SELECT COUNT(*) FROM project_targets"), 2, "scope entries are kept");

            assert_eq!(count(c, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
            let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            assert_eq!(integrity, "ok");
            assert_eq!(count(c, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('findings_v9', 'finding_status_v8')"), 0, "no temporary tables are left");
            assert_eq!(count(c, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_findings_project'"), 1);
            // the rebuilt table still cascades with its project
            c.execute("DELETE FROM projects WHERE id = 7", [])?;
            assert_eq!(count(c, "SELECT COUNT(*) FROM findings") + count(c, "SELECT COUNT(*) FROM finding_events") + count(c, "SELECT COUNT(*) FROM scope_events"), 0);
            Ok(())
        })
        .unwrap();
        // running the migrations again changes nothing
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
    }

    #[test]
    fn a_failed_upgrade_leaves_the_previous_database_untouched_and_can_be_retried() {
        let conn = schema8_with_data();
        // something the migration does not expect (here: a table it is about to create)
        conn.execute_batch("CREATE TABLE timeline_events (x INTEGER);").unwrap();
        let before: Vec<(i64, String)> = conn.prepare("SELECT id, status FROM findings ORDER BY id").unwrap().query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
        let db = Db { conn: Mutex::new(conn) };
        assert!(db.migrate().is_err());
        assert_eq!(db.schema_version().unwrap(), 8, "the version is not advanced");
        db.with(|c| {
            let after: Vec<(i64, String)> = c.prepare("SELECT id, status FROM findings ORDER BY id")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            assert_eq!(after, before, "findings keep their data and old statuses");
            assert_eq!(count(c, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('findings_v9', 'finding_events', 'assets', 'evidence')"), 0, "nothing of the failed upgrade remains");
            c.execute_batch("DROP TABLE timeline_events;")?;
            Ok(())
        })
        .unwrap();
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
        db.with(|c| {
            assert_eq!(count(c, "SELECT COUNT(*) FROM findings WHERE status IN ('open', 'reported')"), 0);
            assert_eq!(count(c, "SELECT COUNT(*) FROM findings"), 5);
            Ok(())
        })
        .unwrap();
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
