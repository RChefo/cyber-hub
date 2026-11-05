//! Project asset inventory: one record per real asset (normalized key), with every observation kept
//! for change detection. Assets link to OSINT entities instead of duplicating them.

use std::net::IpAddr;
use std::str::FromStr;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{validation, AppError, AppResult};
use crate::osint::normalize;
use crate::util::now;

pub const TYPES: &[&str] = &["domain", "subdomain", "ip", "dns_record", "service", "http_service", "certificate", "technology", "endpoint"];
pub const STATUSES: &[&str] = &["active", "not_observed", "retired"];
const CONFIDENCES: &[&str] = &["low", "medium", "high"];
const DNS_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA"];

/// Runs `f` inside a savepoint (works whether or not a transaction is already open).
pub fn with_savepoint<T>(c: &Connection, f: impl FnOnce() -> AppResult<T>) -> AppResult<T> {
    c.execute_batch("SAVEPOINT cyberhub_sp")?;
    match f() {
        Ok(v) => {
            c.execute_batch("RELEASE cyberhub_sp")?;
            Ok(v)
        }
        Err(e) => {
            let _ = c.execute_batch("ROLLBACK TO cyberhub_sp; RELEASE cyberhub_sp");
            Err(e)
        }
    }
}

/// Normalized display value and uniqueness key of an asset, or why the value is not valid.
pub fn normalize_asset(kind: &str, raw: &str) -> Result<(String, String), String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2000 || raw.chars().any(|c| c.is_control()) {
        return Err("The value is empty, too long or contains control characters".into());
    }
    match kind {
        "domain" | "subdomain" => {
            let d = normalize::domain(raw)?;
            Ok((d.clone(), d))
        }
        "ip" => {
            let ip = normalize::ip(raw)?;
            Ok((ip.clone(), ip))
        }
        "service" => {
            // ip:port/proto, [v6]:port/proto
            let (addr, proto) = raw.rsplit_once('/').unwrap_or((raw, "tcp"));
            let proto = proto.to_ascii_lowercase();
            if proto != "tcp" && proto != "udp" {
                return Err("The protocol must be tcp or udp".into());
            }
            let (host, port) = addr.rsplit_once(':').ok_or("Use address:port/protocol, e.g. 192.0.2.10:443/tcp")?;
            let port: u16 = port.parse().map_err(|_| "Invalid port")?;
            if port == 0 {
                return Err("Invalid port".into());
            }
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let host = match IpAddr::from_str(host) {
                Ok(ip) => normalize::ip(&ip.to_string())?,
                Err(_) => normalize::domain(host)?,
            };
            let shown = if host.contains(':') { format!("[{host}]:{port}/{proto}") } else { format!("{host}:{port}/{proto}") };
            Ok((shown.clone(), shown))
        }
        "http_service" | "endpoint" => {
            let u = url::Url::parse(raw).map_err(|_| "Not a valid URL")?;
            if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
                return Err("Use an http or https URL with a host".into());
            }
            if !u.username().is_empty() || u.password().is_some() {
                return Err("URLs with credentials are not stored as assets".into());
            }
            let origin = u.origin().ascii_serialization();
            if kind == "http_service" {
                return Ok((origin.clone(), origin));
            }
            let mut v = u.clone();
            v.set_fragment(None);
            let s = v.to_string();
            Ok((s.clone(), s))
        }
        "dns_record" => {
            // name TYPE value
            let mut parts = raw.split_whitespace();
            let (Some(name), Some(rtype)) = (parts.next(), parts.next()) else {
                return Err("Use name, type and value, e.g. example.com A 192.0.2.10".into());
            };
            let value = parts.collect::<Vec<_>>().join(" ");
            let rtype = rtype.to_ascii_uppercase();
            if !DNS_TYPES.contains(&rtype.as_str()) || value.is_empty() {
                return Err(format!("Supported record types: {}", DNS_TYPES.join(", ")));
            }
            let name = normalize::domain(name)?;
            let value = if matches!(rtype.as_str(), "CNAME" | "NS" | "PTR") { normalize::domain(&value)? } else { value.trim_end_matches('.').to_string() };
            let shown = format!("{name} {rtype} {value}");
            Ok((shown.clone(), shown.to_ascii_lowercase()))
        }
        "certificate" => {
            let hex: String = raw.chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Use the certificate's SHA-256 fingerprint".into());
            }
            Ok((hex.clone(), hex))
        }
        "technology" => {
            let v: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
            if v.len() > 200 {
                return Err("Technology names are limited to 200 characters".into());
            }
            Ok((v.clone(), v.to_ascii_lowercase()))
        }
        _ => Err(format!("Unknown asset type '{kind}'")),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: i64,
    pub project_id: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub status: String,
    pub confidence: String,
    pub source: String,
    pub osint_entity_id: Option<i64>,
    pub data: serde_json::Value,
    pub first_seen: String,
    pub last_seen: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetInput {
    pub project_id: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub source: String,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub osint_entity_id: Option<i64>,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

const COLS: &str = "id, project_id, type, value, status, confidence, source, osint_entity_id, data, first_seen, last_seen, updated_at";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Asset> {
    Ok(Asset {
        id: r.get(0)?,
        project_id: r.get(1)?,
        kind: r.get(2)?,
        value: r.get(3)?,
        status: r.get(4)?,
        confidence: r.get(5)?,
        source: r.get(6)?,
        osint_entity_id: r.get(7)?,
        data: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or(serde_json::Value::Null),
        first_seen: r.get(9)?,
        last_seen: r.get(10)?,
        updated_at: r.get(11)?,
    })
}

pub fn get(c: &Connection, id: i64) -> AppResult<Asset> {
    c.query_row(&format!("SELECT {COLS} FROM assets WHERE id = ?1"), params![id], row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("asset {id}")))
}

pub fn list(c: &Connection, project_id: i64, kind: Option<&str>, status: Option<&str>, limit: i64, offset: i64) -> AppResult<Vec<Asset>> {
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM assets WHERE project_id = ?1 AND (?2 IS NULL OR type = ?2) AND (?3 IS NULL OR status = ?3)
         ORDER BY type, value LIMIT ?4 OFFSET ?5"
    ))?;
    let rows = st.query_map(params![project_id, kind, status, limit.clamp(1, 5000), offset.max(0)], row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn fingerprint(data: &serde_json::Value) -> String {
    Sha256::digest(data.to_string().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Creates or refreshes an asset and records the observation. Returns the asset and whether it
/// is new. Within a snapshot every observation is kept (change detection compares snapshots);
/// outside one, an identical observation is not repeated.
pub fn upsert_observation(c: &Connection, input: &AssetInput, snapshot_id: Option<i64>) -> AppResult<(Asset, bool)> {
    if !TYPES.contains(&input.kind.as_str()) {
        return Err(validation(format!("Unknown asset type '{}'", input.kind)));
    }
    let (value, key) = normalize_asset(&input.kind, &input.value).map_err(validation)?;
    let confidence = input.confidence.clone().unwrap_or_else(|| "medium".into());
    if !CONFIDENCES.contains(&confidence.as_str()) {
        return Err(validation("Confidence must be low, medium or high"));
    }
    let source: String = input.source.trim().chars().take(100).collect();
    if source.is_empty() {
        return Err(validation("Every asset needs a discovery source"));
    }
    let data = input.data.clone().unwrap_or_else(|| serde_json::json!({}));
    if data.to_string().len() > 64 * 1024 {
        return Err(validation("Asset data is limited to 64 KB"));
    }
    if let Some(entity) = input.osint_entity_id {
        let owner: Option<Option<i64>> = c
            .query_row("SELECT i.project_id FROM osint_entities e JOIN osint_investigations i ON i.id = e.investigation_id WHERE e.id = ?1", params![entity], |r| r.get(0))
            .optional()?;
        if owner.flatten() != Some(input.project_id) {
            return Err(validation("The OSINT entity belongs to an investigation of another project (or of none)"));
        }
    }
    if let Some(s) = snapshot_id {
        let owner: Option<i64> = c.query_row("SELECT project_id FROM discovery_snapshots WHERE id = ?1", params![s], |r| r.get(0)).optional()?;
        if owner != Some(input.project_id) {
            return Err(validation("The discovery snapshot belongs to another project"));
        }
    }
    with_savepoint(c, || {
        let ts = now();
        let existing: Option<i64> = c
            .query_row("SELECT id FROM assets WHERE project_id = ?1 AND type = ?2 AND key = ?3", params![input.project_id, input.kind, key], |r| r.get(0))
            .optional()?;
        let created = existing.is_none();
        let id = match existing {
            Some(id) => {
                c.execute(
                    "UPDATE assets SET last_seen = ?2, updated_at = ?2, status = CASE status WHEN 'retired' THEN 'retired' ELSE 'active' END,
                         osint_entity_id = COALESCE(?3, osint_entity_id), data = ?4,
                         confidence = CASE WHEN ?5 = 'high' OR (?5 = 'medium' AND confidence = 'low') THEN ?5 ELSE confidence END
                     WHERE id = ?1",
                    params![id, ts, input.osint_entity_id, data.to_string(), confidence],
                )?;
                id
            }
            None => {
                c.execute(
                    "INSERT INTO assets (project_id, type, value, key, status, confidence, source, osint_entity_id, data, first_seen, last_seen, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9, ?9, ?9, ?9)",
                    params![input.project_id, input.kind, value, key, confidence, source, input.osint_entity_id, data.to_string(), ts],
                )?;
                c.last_insert_rowid()
            }
        };
        let fp = fingerprint(&data);
        let last_fp: Option<String> = c.query_row("SELECT fingerprint FROM asset_observations WHERE asset_id = ?1 ORDER BY id DESC LIMIT 1", params![id], |r| r.get(0)).optional()?;
        if snapshot_id.is_some() || last_fp.as_deref() != Some(fp.as_str()) {
            c.execute(
                "INSERT INTO asset_observations (asset_id, snapshot_id, observed_at, source, data, fingerprint) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, snapshot_id, ts, source, data.to_string(), fp],
            )?;
        }
        Ok((get(c, id)?, created))
    })
}

pub fn set_status(c: &Connection, id: i64, status: &str) -> AppResult<Asset> {
    if !STATUSES.contains(&status) {
        return Err(validation("Status must be active, not_observed or retired"));
    }
    if c.execute("UPDATE assets SET status = ?2, updated_at = ?3 WHERE id = ?1", params![id, status, now()])? == 0 {
        return Err(AppError::NotFound(format!("asset {id}")));
    }
    get(c, id)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub id: i64,
    pub snapshot_id: Option<i64>,
    pub observed_at: String,
    pub source: String,
    pub data: serde_json::Value,
}

pub fn observations(c: &Connection, asset_id: i64, limit: i64) -> AppResult<Vec<Observation>> {
    let mut st = c.prepare("SELECT id, snapshot_id, observed_at, source, data FROM asset_observations WHERE asset_id = ?1 ORDER BY id DESC LIMIT ?2")?;
    let rows = st
        .query_map(params![asset_id, limit.clamp(1, 1000)], |r| {
            Ok(Observation { id: r.get(0)?, snapshot_id: r.get(1)?, observed_at: r.get(2)?, source: r.get(3)?, data: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(serde_json::Value::Null) })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/* ───────────────────────── discovery snapshots ───────────────────────── */

// Snapshots group the observations of one discovery run (asset discovery, next phase).
#[cfg_attr(not(test), allow(dead_code))]
pub fn start_snapshot(c: &Connection, project_id: i64, mode: &str, source: &str, operation_id: Option<i64>, execution_id: Option<i64>) -> AppResult<i64> {
    if !matches!(mode, "passive" | "active" | "manual") {
        return Err(validation("Mode must be passive, active or manual"));
    }
    c.execute(
        "INSERT INTO discovery_snapshots (project_id, mode, source, status, operation_id, execution_id, started_at) VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6)",
        params![project_id, mode, source.chars().take(100).collect::<String>(), operation_id, execution_id, now()],
    )?;
    Ok(c.last_insert_rowid())
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn finish_snapshot(c: &Connection, id: i64, status: &str, note: &str) -> AppResult<()> {
    if !matches!(status, "completed" | "partial" | "failed" | "cancelled") {
        return Err(validation("Invalid snapshot status"));
    }
    let n = c.execute(
        "UPDATE discovery_snapshots SET status = ?2, note = ?3, finished_at = ?4 WHERE id = ?1 AND status = 'running'",
        params![id, status, note.chars().take(2000).collect::<String>(), now()],
    )?;
    if n == 0 {
        return Err(validation("The snapshot is not running"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn project(db: &Db) -> i64 {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            Ok(c.last_insert_rowid())
        })
        .unwrap()
    }
    fn input(p: i64, kind: &str, value: &str) -> AssetInput {
        AssetInput { project_id: p, kind: kind.into(), value: value.into(), source: "test".into(), confidence: None, osint_entity_id: None, data: None }
    }

    #[test]
    fn values_are_normalized_so_one_asset_is_stored_once() {
        assert_eq!(normalize_asset("domain", "WWW.Example.COM.").unwrap().1, "www.example.com");
        assert_eq!(normalize_asset("ip", "::ffff:192.0.2.1").unwrap().1, normalize::ip("::ffff:192.0.2.1").unwrap());
        assert_eq!(normalize_asset("service", "192.0.2.10:443").unwrap().1, "192.0.2.10:443/tcp");
        assert_eq!(normalize_asset("service", "[2001:db8::1]:53/UDP").unwrap().1, "[2001:db8::1]:53/udp");
        assert_eq!(normalize_asset("http_service", "HTTPS://Example.com:443/login?x=1").unwrap().1, "https://example.com");
        assert_eq!(normalize_asset("endpoint", "https://example.com/a#frag").unwrap().1, "https://example.com/a");
        assert_eq!(normalize_asset("dns_record", "Example.com. cname WWW.Example.net.").unwrap().1, "example.com cname www.example.net");
        assert_eq!(normalize_asset("certificate", &format!("{}AB", "AB:".repeat(31))).unwrap().1, "ab".repeat(32));
        for (k, v) in [("service", "192.0.2.10:0/tcp"), ("service", "192.0.2.10:443/icmp"), ("http_service", "ftp://x.example"), ("endpoint", "https://user:pw@example.com/"), ("dns_record", "example.com BOGUS x"), ("certificate", "abc"), ("ip", "999.1.1.1"), ("domain", "a b"), ("nonsense", "x"), ("domain", "x\u{0}y")] {
            assert!(normalize_asset(k, v).is_err(), "{k} {v} must be refused");
        }
    }

    #[test]
    fn observations_are_kept_and_assets_never_duplicated() {
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        db.with(|c| {
            let (a, created) = upsert_observation(c, &input(p, "domain", "Example.com"), None)?;
            assert!(created);
            let (b, created) = upsert_observation(c, &input(p, "domain", "example.COM."), None)?;
            assert!(!created);
            assert_eq!(a.id, b.id);
            assert_eq!(observations(c, a.id, 10)?.len(), 1, "an identical observation outside a snapshot is not repeated");
            let s1 = start_snapshot(c, p, "passive", "dns", None, None)?;
            upsert_observation(c, &AssetInput { data: Some(serde_json::json!({"a": ["192.0.2.1"]})), ..input(p, "domain", "example.com") }, Some(s1))?;
            finish_snapshot(c, s1, "completed", "")?;
            assert!(finish_snapshot(c, s1, "completed", "").is_err(), "a finished snapshot cannot be finished again");
            let s2 = start_snapshot(c, p, "passive", "dns", None, None)?;
            upsert_observation(c, &AssetInput { data: Some(serde_json::json!({"a": ["192.0.2.2"]})), ..input(p, "domain", "example.com") }, Some(s2))?;
            let obs = observations(c, a.id, 10)?;
            assert_eq!(obs.len(), 3);
            assert_eq!(obs[0].data["a"][0], "192.0.2.2", "newest first, history preserved");
            // a retired asset stays retired when seen again; a not-observed one becomes active
            set_status(c, a.id, "not_observed")?;
            assert_eq!(upsert_observation(c, &input(p, "domain", "example.com"), None)?.0.status, "active");
            set_status(c, a.id, "retired")?;
            assert_eq!(upsert_observation(c, &input(p, "domain", "example.com"), None)?.0.status, "retired");
            assert!(set_status(c, a.id, "deleted").is_err());
            // confidence only goes up
            assert_eq!(upsert_observation(c, &AssetInput { confidence: Some("high".into()), ..input(p, "ip", "192.0.2.1") }, None)?.0.confidence, "high");
            assert_eq!(upsert_observation(c, &AssetInput { confidence: Some("low".into()), ..input(p, "ip", "192.0.2.1") }, None)?.0.confidence, "high");
            assert_eq!(list(c, p, Some("domain"), None, 100, 0)?.len(), 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn references_must_belong_to_the_same_project_and_failures_change_nothing() {
        let db = Db::open_in_memory().unwrap();
        let (p1, p2) = (project(&db), project(&db));
        db.with(|c| {
            c.execute("INSERT INTO osint_investigations (name, target_type, target_value, project_id, created_at, updated_at) VALUES ('I','domain','example.com',?1,'t','t')", params![p1])?;
            let inv = c.last_insert_rowid();
            c.execute("INSERT INTO osint_entities (investigation_id, type, value, match_key, display_name, first_seen, last_seen) VALUES (?1,'domain','example.com','example.com','example.com','t','t')", params![inv])?;
            let entity = c.last_insert_rowid();
            assert!(upsert_observation(c, &AssetInput { osint_entity_id: Some(entity), ..input(p1, "domain", "example.com") }, None).is_ok());
            assert!(upsert_observation(c, &AssetInput { osint_entity_id: Some(entity), ..input(p2, "domain", "example.com") }, None).is_err());
            let s = start_snapshot(c, p1, "active", "nmap", None, None)?;
            assert!(upsert_observation(c, &input(p2, "ip", "192.0.2.1"), Some(s)).is_err(), "a snapshot of another project");
            assert!(upsert_observation(c, &AssetInput { source: " ".into(), ..input(p1, "ip", "192.0.2.1") }, None).is_err());
            assert_eq!(list(c, p2, None, None, 100, 0)?.len(), 0, "nothing was written for refused input");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn concurrent_upserts_of_the_same_asset_create_one_record() {
        let db = std::sync::Arc::new(Db::open_in_memory().unwrap());
        let p = project(&db);
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let db = db.clone();
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        db.with(|c| upsert_observation(c, &AssetInput { data: Some(serde_json::json!({"thread": i})), ..input(p, "subdomain", "api.example.com") }, None)).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        db.with(|c| {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM assets WHERE project_id = ?1", params![p], |r| r.get(0))?;
            assert_eq!(n, 1);
            Ok(())
        })
        .unwrap();
    }
}
