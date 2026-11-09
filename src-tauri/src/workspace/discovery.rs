//! Attack-surface discovery. Three sources fill the asset inventory, each run grouped in a
//! discovery snapshot:
//!
//! * `passive`: certificate transparency (crt.sh) and DNS for the project's in-scope domains.
//!   Only public sources are asked; nothing is sent to the targets.
//! * `http`: an HTTP(S) request to in-scope hosts (active, natively confirmed).
//! * `nmap`: a service scan through the normal tool execution path (active, natively confirmed,
//!   scope-checked again), read from Nmap's XML output.
//!
//! Every recorded item carries a certainty: `confirmed` (the target itself answered), `observed`
//! (a source reported it and DNS corroborates it), `possible` (a single unverified report, such as
//! a certificate name that does not resolve). Comparing a snapshot with the previous one of the
//! same source classifies changes; items missing from a run that did not complete are
//! `incomplete`, never removed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::scope::{self, ScopeEntry, Target};
use crate::workspace::assets::{self, AssetInput};

pub const MAX_ROOTS: usize = 20;
pub const MAX_NAMES: usize = 300;
pub const MAX_HTTP_HOSTS: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Certainty {
    Incomplete,
    Possible,
    Observed,
    Confirmed,
}

impl Certainty {
    pub fn as_str(self) -> &'static str {
        match self {
            Certainty::Confirmed => "confirmed",
            Certainty::Observed => "observed",
            Certainty::Possible => "possible",
            Certainty::Incomplete => "incomplete",
        }
    }
    fn parse(s: &str) -> Certainty {
        match s {
            "confirmed" => Certainty::Confirmed,
            "observed" => Certainty::Observed,
            "incomplete" => Certainty::Incomplete,
            _ => Certainty::Possible,
        }
    }
    fn confidence(self) -> &'static str {
        match self {
            Certainty::Confirmed => "high",
            Certainty::Observed => "medium",
            _ => "low",
        }
    }
}

/* ───────────────────────── collected items ───────────────────────── */

struct Item {
    kind: &'static str,
    value: String,
    certainty: Certainty,
    data: Map<String, Value>,
}

/// Items found by one run, merged by asset (type and normalized key) before anything is written.
#[derive(Default)]
pub struct Batch {
    items: BTreeMap<(&'static str, String), Item>,
    /// values that are not valid assets (reported, not stored)
    pub invalid: usize,
}

/// Keys whose values are lists that grow across reports (sources, names, hosts).
const LIST_KEYS: &[&str] = &["sources", "names", "seenOn", "versions", "addresses"];

impl Batch {
    pub fn add(&mut self, kind: &'static str, value: &str, certainty: Certainty, data: Value) {
        let Ok((shown, key)) = assets::normalize_asset(kind, value) else {
            self.invalid += 1;
            return;
        };
        let item = self.items.entry((kind, key)).or_insert_with(|| Item { kind, value: shown, certainty, data: Map::new() });
        item.certainty = item.certainty.max(certainty);
        if let Value::Object(m) = data {
            for (k, v) in m {
                if LIST_KEYS.contains(&k.as_str()) {
                    let list = item.data.entry(k).or_insert_with(|| json!([]));
                    if let (Value::Array(have), Value::Array(new)) = (list, v) {
                        for x in new {
                            if !have.contains(&x) && have.len() < 50 {
                                have.push(x);
                            }
                        }
                    }
                } else {
                    item.data.insert(k, v);
                }
            }
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecordStats {
    pub new: usize,
    pub seen: usize,
}

/// Writes a batch as observations of `snapshot_id` (one savepoint: all or nothing).
pub fn record(c: &Connection, project_id: i64, snapshot_id: i64, source: &str, batch: &Batch) -> AppResult<RecordStats> {
    assets::with_savepoint(c, || {
        let mut stats = RecordStats::default();
        for item in batch.items.values() {
            let mut data = item.data.clone();
            data.insert("certainty".into(), json!(item.certainty.as_str()));
            let input = AssetInput {
                project_id,
                kind: item.kind.into(),
                value: item.value.clone(),
                source: source.into(),
                confidence: Some(item.certainty.confidence().into()),
                osint_entity_id: None,
                data: Some(Value::Object(data)),
            };
            let (_, created) = assets::upsert_observation(c, &input, Some(snapshot_id))?;
            if created {
                stats.new += 1;
            } else {
                stats.seen += 1;
            }
        }
        Ok(stats)
    })
}

/// Marks assets as not observed when a *completed* run of the same source no longer saw them.
/// `covers` limits this to what the run actually looked at (types, hosts).
pub fn mark_missing(c: &Connection, project_id: i64, snapshot_id: i64, source: &str, covers: &dyn Fn(&assets::Asset) -> bool) -> AppResult<usize> {
    let ids: Vec<i64> = c
        .prepare(
            "SELECT a.id FROM assets a WHERE a.project_id = ?1 AND a.status = 'active'
               AND EXISTS (SELECT 1 FROM asset_observations o JOIN discovery_snapshots s ON s.id = o.snapshot_id WHERE o.asset_id = a.id AND s.source = ?2 AND s.id <> ?3)
               AND NOT EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id = a.id AND o.snapshot_id = ?3)",
        )?
        .query_map(params![project_id, source, snapshot_id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut n = 0;
    for id in ids {
        if covers(&assets::get(c, id)?) {
            assets::set_status(c, id, "not_observed")?;
            n += 1;
        }
    }
    Ok(n)
}

/// Ends a snapshot: records the batch, marks missing assets for a completed run, and stores a
/// short summary. Returns the summary.
pub fn complete(c: &Connection, project_id: i64, snapshot_id: i64, source: &str, batch: &Batch, (status, problems): (&str, &[String]), covers: &dyn Fn(&assets::Asset) -> bool) -> AppResult<String> {
    assets::with_savepoint(c, || {
        let stats = record(c, project_id, snapshot_id, source, batch)?;
        let missing = if status == "completed" { mark_missing(c, project_id, snapshot_id, source, covers)? } else { 0 };
        let mut note = format!("{} ({} new), {} no longer observed", plural(stats.new + stats.seen, "asset", "assets"), stats.new, missing);
        if batch.invalid > 0 {
            note.push_str(&format!("; {} not recorded (not a valid asset)", plural(batch.invalid, "value", "values")));
        }
        for p in problems.iter().take(5) {
            note.push_str("; ");
            note.push_str(p);
        }
        if problems.len() > 5 {
            note.push_str(&format!("; {} more problems", problems.len() - 5));
        }
        assets::finish_snapshot(c, snapshot_id, status, &note)?;
        Ok(note)
    })
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/* ───────────────────────── snapshots and changes ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: i64,
    pub mode: String,
    pub source: String,
    pub status: String,
    pub note: String,
    pub execution_id: Option<i64>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub assets: i64,
}

const SNAP_COLS: &str = "s.id, s.mode, s.source, s.status, s.note, s.execution_id, s.started_at, s.finished_at,
    (SELECT COUNT(DISTINCT o.asset_id) FROM asset_observations o WHERE o.snapshot_id = s.id)";

fn snap_row(r: &rusqlite::Row) -> rusqlite::Result<Snapshot> {
    Ok(Snapshot { id: r.get(0)?, mode: r.get(1)?, source: r.get(2)?, status: r.get(3)?, note: r.get(4)?, execution_id: r.get(5)?, started_at: r.get(6)?, finished_at: r.get(7)?, assets: r.get(8)? })
}

pub fn snapshots(c: &Connection, project_id: i64, limit: i64) -> AppResult<Vec<Snapshot>> {
    let mut st = c.prepare(&format!("SELECT {SNAP_COLS} FROM discovery_snapshots s WHERE s.project_id = ?1 ORDER BY s.id DESC LIMIT ?2"))?;
    let rows = st.query_map(params![project_id, limit.clamp(1, 500)], snap_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn snapshot(c: &Connection, id: i64) -> AppResult<Snapshot> {
    c.query_row(&format!("SELECT {SNAP_COLS} FROM discovery_snapshots s WHERE s.id = ?1"), params![id], snap_row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("discovery snapshot {id}")))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// added, changed or missing
    pub change: &'static str,
    pub asset_id: i64,
    #[serde(rename = "assetType")]
    pub asset_type: String,
    pub value: String,
    pub certainty: Certainty,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotChanges {
    pub snapshot: Snapshot,
    /// the earlier run of the same source it is compared with (None for the first run)
    pub previous: Option<i64>,
    pub changes: Vec<Change>,
}

/// Latest observation per asset in a snapshot: (fingerprint, certainty).
fn observed_in(c: &Connection, snapshot_id: i64) -> AppResult<BTreeMap<i64, (String, Certainty)>> {
    let mut st = c.prepare("SELECT asset_id, fingerprint, data FROM asset_observations WHERE snapshot_id = ?1 ORDER BY id")?;
    let mut out = BTreeMap::new();
    for row in st.query_map(params![snapshot_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, fp, data) = row?;
        let certainty = serde_json::from_str::<Value>(&data).ok().and_then(|v| v.get("certainty").and_then(Value::as_str).map(Certainty::parse)).unwrap_or(Certainty::Possible);
        out.insert(id, (fp, certainty));
    }
    Ok(out)
}

/// Compares a snapshot with the previous finished run of the same source in the same project.
pub fn changes(c: &Connection, snapshot_id: i64) -> AppResult<SnapshotChanges> {
    let snap = snapshot(c, snapshot_id)?;
    let project_id: i64 = c.query_row("SELECT project_id FROM discovery_snapshots WHERE id = ?1", params![snapshot_id], |r| r.get(0))?;
    let previous: Option<i64> = c
        .query_row(
            "SELECT id FROM discovery_snapshots WHERE project_id = ?1 AND source = ?2 AND id < ?3 AND status IN ('completed','partial') ORDER BY id DESC LIMIT 1",
            params![project_id, snap.source, snapshot_id],
            |r| r.get(0),
        )
        .optional()?;
    diff(c, previous, snap)
}

/// Compares any two runs of the same project and source (`from` the older one).
pub fn compare(c: &Connection, from: i64, to: i64) -> AppResult<SnapshotChanges> {
    let owner = |id: i64| -> AppResult<(i64, String)> {
        c.query_row("SELECT project_id, source FROM discovery_snapshots WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("discovery snapshot {id}")))
    };
    let (a, b) = (owner(from)?, owner(to)?);
    if a.0 != b.0 || a.1 != b.1 {
        return Err(validation("Only runs of the same kind in the same project can be compared"));
    }
    diff(c, Some(from), snapshot(c, to)?)
}

fn diff(c: &Connection, previous: Option<i64>, snap: Snapshot) -> AppResult<SnapshotChanges> {
    let cur = observed_in(c, snap.id)?;
    let prev = match previous {
        Some(p) => observed_in(c, p)?,
        None => BTreeMap::new(),
    };
    let mut out = Vec::new();
    let mut push = |change: &'static str, id: i64, certainty: Certainty| -> AppResult<()> {
        let (t, v): (String, String) = c.query_row("SELECT type, value FROM assets WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        out.push(Change { change, asset_id: id, asset_type: t, value: v, certainty });
        Ok(())
    };
    for (id, (fp, certainty)) in &cur {
        match prev.get(id) {
            None => push("added", *id, *certainty)?,
            Some((pfp, _)) if pfp != fp => push("changed", *id, *certainty)?,
            _ => {}
        }
    }
    // absence is never proof: a finished run makes removal possible, an unfinished one says nothing
    let absent = if snap.status == "completed" { Certainty::Possible } else { Certainty::Incomplete };
    for id in prev.keys().filter(|id| !cur.contains_key(id)) {
        if c.query_row("SELECT 1 FROM assets WHERE id = ?1", params![id], |_| Ok(())).optional()?.is_some() {
            push("missing", *id, absent)?;
        }
    }
    Ok(SnapshotChanges { snapshot: snap, previous, changes: out })
}

/* ───────────────────────── passive: certificate transparency and DNS ───────────────────────── */

/// Domains to ask public sources about: in-scope domains, wildcard bases and URL hosts.
pub fn passive_roots(entries: &[ScopeEntry]) -> Vec<String> {
    let mut roots = BTreeSet::new();
    for e in entries.iter().filter(|e| e.in_scope) {
        // URL entries authorize paths, not hosts: they are no roots for name discovery
        let host = match e.kind.as_str() {
            "domain" => Some(e.value.clone()),
            "wildcard" => e.value.strip_prefix("*.").map(str::to_string),
            _ => None,
        };
        if let Some(h) = host.and_then(|h| crate::osint::normalize::domain(&h).ok()) {
            roots.insert(h);
        }
    }
    roots.into_iter().take(MAX_ROOTS).collect()
}

/// Whether a name or address found by discovery may be recorded: authorized as a host. An excluded
/// URL path does not keep its host out of the inventory (recording contacts nothing).
fn in_scope(entries: &[ScopeEntry], raw: &str) -> bool {
    scope::parse_target(raw).is_some_and(|t| scope::check_target_with(entries, &t, false).is_ok())
}

/// DNS answers for one name, mapped to items. Returns whether the name resolves.
pub fn add_dns(batch: &mut Batch, entries: &[ScopeEntry], name: &str, answers: &[(String, Vec<String>)]) -> bool {
    let mut resolves = false;
    for (rtype, values) in answers {
        for raw in values {
            let host = raw.split_whitespace().last().unwrap_or("").trim_end_matches('.').to_string();
            // a null MX ("0 .") means the domain receives no mail: nothing to record
            if host.is_empty() {
                continue;
            }
            match rtype.as_str() {
                "A" | "AAAA" => {
                    resolves = true;
                    let ip_in_scope = scope::parse_target(&host).is_some_and(|t| matches!(t, Target::Ip(_)) && scope::check_target(entries, &t).is_ok());
                    let non_public = host.parse().is_ok_and(|ip| crate::ti::indicator::is_non_public(&ip));
                    batch.add("ip", &host, Certainty::Observed, json!({ "names": [name], "inScope": ip_in_scope, "nonPublic": non_public }));
                    batch.add("dns_record", &format!("{name} {rtype} {host}"), Certainty::Observed, json!({}));
                }
                "CNAME" => {
                    resolves = true;
                    batch.add("dns_record", &format!("{name} CNAME {host}"), Certainty::Observed, json!({}));
                }
                "MX" | "NS" => batch.add("dns_record", &format!("{name} {rtype} {host}"), Certainty::Observed, json!({})),
                _ => {}
            }
        }
    }
    resolves
}

/// Progress reported while a discovery runs.
pub type Progress = Arc<dyn Fn(String) + Send + Sync>;

/// Runs passive discovery. Returns the batch, problems, and how many names were outside the scope.
pub async fn passive_collect(db: &Db, entries: &[ScopeEntry], roots: &[String], cancel: &AtomicBool, progress: Progress) -> (Batch, Vec<String>, usize) {
    let mut batch = Batch::default();
    let mut problems = Vec::new();
    // name → sources
    let mut names: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for root in roots {
        names.entry(root.clone()).or_default().insert("scope");
    }
    let mut outside: BTreeSet<String> = BTreeSet::new();
    for root in roots {
        if cancel.load(Ordering::Relaxed) {
            return (batch, vec!["Cancelled".into()], outside.len());
        }
        progress(format!("Certificate transparency for {root}"));
        match crate::osint::providers::crtsh::run(db, root, false).await {
            Ok(out) => {
                for o in &out.observations {
                    for e in o.entities.iter().filter(|e| e.entity_type == crate::osint::model::EntityType::Domain) {
                        let n = e.value.trim_start_matches("*.").to_string();
                        if !(n == *root || n.ends_with(&format!(".{root}"))) {
                            continue;
                        }
                        if in_scope(entries, &n) {
                            names.entry(n).or_default().insert("crt.sh");
                        } else {
                            outside.insert(n);
                        }
                    }
                }
            }
            Err(e) => problems.push(format!("crt.sh for {root}: {}", e.message())),
        }
    }
    if names.len() > MAX_NAMES {
        problems.push(format!("{} names found; the first {MAX_NAMES} were checked", names.len()));
    }
    let list: Vec<(String, BTreeSet<&'static str>)> = names.into_iter().take(MAX_NAMES).collect();
    progress(format!("Resolving {} names", list.len()));
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let mut set = tokio::task::JoinSet::new();
    for (i, (name, _)) in list.iter().enumerate() {
        let (name, sem) = (name.clone(), sem.clone());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            (i, crate::osint::providers::dns::query_domain(&name).await)
        });
    }
    let mut answers: BTreeMap<usize, Vec<(String, Vec<String>)>> = BTreeMap::new();
    while let Some(res) = set.join_next().await {
        if cancel.load(Ordering::Relaxed) {
            set.abort_all();
            problems.push("Cancelled".into());
            break;
        }
        match res {
            Ok((i, Ok(a))) => {
                answers.insert(i, a);
            }
            Ok((i, Err(e))) => problems.push(format!("DNS for {}: {}", list[i].0, e.message())),
            Err(_) => {}
        }
    }
    let root_set: BTreeSet<&String> = roots.iter().collect();
    for (i, (name, sources)) in list.iter().enumerate() {
        let resolves = answers.get(&i).is_some_and(|a| add_dns(&mut batch, entries, name, a));
        let kind = if root_set.contains(name) { "domain" } else { "subdomain" };
        let mut src: Vec<&str> = sources.iter().copied().collect();
        if resolves {
            src.push("dns");
        }
        // a name only in certificate logs that does not resolve is a possibility, not a host
        let certainty = if resolves { Certainty::Observed } else { Certainty::Possible };
        batch.add(kind, name, certainty, json!({ "sources": src, "resolves": resolves }));
    }
    (batch, problems, outside.len())
}

/* ───────────────────────── active: HTTP probe ───────────────────────── */

fn http_client_builder(insecure: bool) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // straight to the vetted addresses: a system proxy would resolve names itself
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(6))
        .user_agent("Cyber Hub attack surface check")
        .danger_accept_invalid_certs(insecure)
}

/// Text of the first `<title>` in (the start of) an HTML body.
pub fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open_end = start + lower[start..].find('>')? + 1;
    let end = open_end + lower[open_end..].find("</title")?;
    let t: String = body[open_end..end].split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then(|| t.chars().take(200).collect())
}

async fn probe_one(verified: &reqwest::Client, insecure: &reqwest::Client, origin: &str) -> Result<(u16, Vec<(String, String)>, Option<String>, Option<bool>), String> {
    let https = origin.starts_with("https://");
    let (resp, trusted) = match verified.get(origin).send().await {
        Ok(r) => (r, https.then_some(true)),
        Err(e) if https && crate::updates::is_certificate_error(&e) => (insecure.get(origin).send().await.map_err(|e| e.to_string())?, Some(false)),
        Err(e) => return Err(if e.is_timeout() { "no answer (timeout)".into() } else if e.is_connect() { "connection refused or unreachable".into() } else { e.to_string() }),
    };
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())).collect();
    // read at most 64 KB of the page for its title
    let mut body = Vec::new();
    let mut resp = resp;
    while body.len() < 64 * 1024 {
        match resp.chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    let title = html_title(&String::from_utf8_lossy(&body));
    Ok((status, headers, title, trusted))
}

/// Requests `/` over HTTPS and HTTP on each host. Hosts must already be scope-checked; each name
/// is resolved and vetted ([`scope_gate::resolve_vetted`]) and the requests go only to the vetted
/// addresses. Hosts refused by that check are reported as problems.
pub async fn http_collect(hosts: &[String], entries: &[ScopeEntry], cancel: &AtomicBool, progress: Progress) -> AppResult<(Batch, Vec<String>, BTreeSet<String>)> {
    let mut batch = Batch::default();
    let mut problems = Vec::new();
    let mut probed = BTreeSet::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(6));
    let mut set = tokio::task::JoinSet::new();
    for host in hosts.iter().take(MAX_HTTP_HOSTS) {
        let (sem, host, entries) = (sem.clone(), host.clone(), entries.to_vec());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let addrs = match crate::workspace::scope_gate::resolve_vetted(&entries, &host, 443).await {
                Ok(a) => a,
                Err(reason) => return (host, Err(reason)),
            };
            let named = host.parse::<std::net::IpAddr>().is_err();
            let client = |insecure: bool| -> Result<reqwest::Client, String> {
                let mut b = http_client_builder(insecure);
                if named {
                    b = b.resolve_to_addrs(&host, &addrs);
                }
                b.build().map_err(|e| e.to_string())
            };
            let (v, i) = match (client(false), client(true)) {
                (Ok(v), Ok(i)) => (v, i),
                (Err(e), _) | (_, Err(e)) => return (host, Err(e)),
            };
            let shown = if host.contains(':') { format!("[{host}]") } else { host.clone() };
            let mut results = Vec::new();
            for scheme in ["https", "http"] {
                let origin = format!("{scheme}://{shown}");
                let r = probe_one(&v, &i, &origin).await;
                results.push((origin, r));
            }
            (host, Ok(results))
        });
    }
    progress(format!("Checking {} hosts over HTTP and HTTPS", hosts.len().min(MAX_HTTP_HOSTS)));
    while let Some(res) = set.join_next().await {
        if cancel.load(Ordering::Relaxed) {
            set.abort_all();
            problems.push("Cancelled".into());
            break;
        }
        let Ok((host, outcome)) = res else { continue };
        let results = match outcome {
            Ok(r) => r,
            // a name that points at an unauthorized internal address is refused and reported
            Err(reason) if reason.contains("authorized scope") => {
                problems.push(reason);
                continue;
            }
            // a name that does not resolve (common for names from certificate logs) is not a problem
            Err(_) => continue,
        };
        probed.insert(host.clone());
        for (origin, r) in results {
            // no answer on one scheme is normal (many hosts serve only HTTPS) and not a problem
            let Ok((status, headers, title, trusted)) = r else { continue };
            let header = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
            let mut data = json!({ "status": status, "server": header("server"), "title": title, "location": header("location") });
            if let Some(t) = trusted {
                data["tlsTrusted"] = json!(t);
            }
            batch.add("http_service", &origin, Certainty::Confirmed, data);
            for (k, v) in &headers {
                for tech in crate::osint::providers::web::technologies(k, v) {
                    batch.add("technology", &tech, Certainty::Confirmed, json!({ "seenOn": [origin.clone()] }));
                }
            }
        }
    }
    Ok((batch, problems, probed))
}

/// Host part of an http_service origin.
pub fn origin_host(origin: &str) -> Option<String> {
    url::Url::parse(origin).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string()))
}

/* ───────────────────────── active: Nmap service scan ───────────────────────── */

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NmapPort {
    pub proto: String,
    pub port: u16,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NmapHost {
    pub address: String,
    pub hostnames: Vec<String>,
    pub up: bool,
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NmapRun {
    pub hosts: Vec<NmapHost>,
    /// `<finished exit="success">` was present: the scan ran to its end
    pub finished: bool,
}

/// Reads Nmap's XML output (`-oX -`). Truncated documents yield what was complete.
pub fn parse_nmap(xml: &str) -> Result<NmapRun, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut run = NmapRun::default();
    let mut host: Option<NmapHost> = None;
    let mut port: Option<NmapPort> = None;
    let mut saw_root = false;
    // a read error means a truncated document: keep what was read
    while let Ok(ev) = reader.read_event() {
        match ev {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) => {
                let mut attrs: BTreeMap<String, String> = BTreeMap::new();
                for a in e.attributes().flatten() {
                    if let Ok(v) = a.normalized_value(quick_xml::XmlVersion::default()) {
                        attrs.insert(a.key.local_name().into_inner().to_string(), v.to_string());
                    }
                }
                let get = |k: &str| attrs.get(k).cloned().unwrap_or_default();
                match e.local_name().into_inner() {
                    "nmaprun" => saw_root = true,
                    "host" => host = Some(NmapHost::default()),
                    "status" => {
                        if let Some(h) = host.as_mut() {
                            h.up = get("state") == "up";
                        }
                    }
                    "address" if matches!(get("addrtype").as_str(), "ipv4" | "ipv6") => {
                        if let Some(h) = host.as_mut() {
                            h.address = get("addr");
                        }
                    }
                    "hostname" => {
                        if let Some(h) = host.as_mut() {
                            let n = get("name");
                            // bounded: names are copied into every service of the host
                            if !n.is_empty() && h.hostnames.len() < 50 && !h.hostnames.contains(&n) {
                                h.hostnames.push(n);
                            }
                        }
                    }
                    "port" => port = Some(NmapPort { proto: get("protocol"), port: get("portid").parse().unwrap_or(0), ..Default::default() }),
                    "state" => {
                        if let Some(p) = port.as_mut() {
                            p.state = get("state");
                        }
                    }
                    "service" => {
                        if let Some(p) = port.as_mut() {
                            p.service = get("name");
                            p.product = get("product");
                            p.version = get("version");
                        }
                    }
                    "finished" => run.finished = get("exit") == "success",
                    _ => {}
                }
                // an empty <port/> has no children
                if matches!(ev, Event::Empty(_)) && e.local_name().into_inner() == "port" {
                    if let (Some(p), Some(h)) = (port.take(), host.as_mut()) {
                        h.ports.push(p);
                    }
                }
            }
            Event::End(ref e) => match e.local_name().into_inner() {
                "port" => {
                    if let (Some(p), Some(h)) = (port.take(), host.as_mut()) {
                        h.ports.push(p);
                    }
                }
                "host" => {
                    if let Some(h) = host.take() {
                        if !h.address.is_empty() {
                            run.hosts.push(h);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    if !saw_root {
        return Err("The run produced no Nmap XML output".into());
    }
    Ok(run)
}

/// Stored run output → the XML Nmap wrote to standard output (stderr lines are prefixed).
pub fn xml_from_output(output: &str) -> String {
    output.lines().filter(|l| !l.starts_with("[stderr] ")).collect::<Vec<_>>().join("\n")
}

/// Items from a scan: up hosts (confirmed), open ports as services, products as technologies.
pub fn nmap_batch(run: &NmapRun) -> Batch {
    let mut batch = Batch::default();
    for h in run.hosts.iter().filter(|h| h.up) {
        batch.add("ip", &h.address, Certainty::Confirmed, json!({ "names": h.hostnames }));
        for p in h.ports.iter().filter(|p| p.state == "open" && p.port > 0) {
            let host = if h.address.contains(':') { format!("[{}]", h.address) } else { h.address.clone() };
            let version = [p.product.as_str(), p.version.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ");
            batch.add("service", &format!("{host}:{}/{}", p.port, p.proto), Certainty::Confirmed, json!({ "service": p.service, "product": p.product, "version": p.version, "names": h.hostnames }));
            if !p.product.is_empty() {
                batch.add("technology", &p.product, Certainty::Confirmed, json!({ "seenOn": [format!("{host}:{}/{}", p.port, p.proto)], "versions": if version.is_empty() { json!([]) } else { json!([version]) } }));
            }
        }
    }
    batch
}

/// Addresses of the hosts that answered (their missing ports may be marked as not observed).
pub fn up_hosts(run: &NmapRun) -> BTreeSet<String> {
    run.hosts.iter().filter(|h| h.up).filter_map(|h| crate::osint::normalize::ip(&h.address).ok()).collect()
}

/// Host part of a service key (`192.0.2.1:443/tcp`, `[2001:db8::1]:53/udp`).
pub fn service_host(value: &str) -> Option<String> {
    let addr = value.rsplit_once('/')?.0;
    let host = addr.rsplit_once(':')?.0;
    crate::osint::normalize::ip(host.trim_start_matches('[').trim_end_matches(']')).ok()
}

/// Arguments for a service scan profile. `-oX -` writes XML to standard output, which the run
/// stores; nothing is written to disk.
pub fn nmap_args(profile: &str, targets: &[String]) -> AppResult<Vec<String>> {
    let mut args: Vec<String> = match profile {
        // the 100 most common ports
        "quick" => vec!["-sV".into(), "-T3".into(), "-F".into()],
        // Nmap's default 1,000 ports
        "standard" => vec!["-sV".into(), "-T3".into()],
        _ => return Err(validation("The scan profile must be quick or standard")),
    };
    args.extend(["-oX".to_string(), "-".to_string()]);
    args.extend(targets.iter().cloned());
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(v: &[(&str, bool)]) -> Vec<ScopeEntry> {
        v.iter()
            .map(|(x, s)| {
                let (value, kind) = scope::classify(x).unwrap();
                ScopeEntry { value, kind: kind.into(), in_scope: *s }
            })
            .collect()
    }

    fn project(db: &Db) -> i64 {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P','active','t','t')", [])?;
            Ok(c.last_insert_rowid())
        })
        .unwrap()
    }

    #[test]
    fn passive_roots_come_from_in_scope_domains_only() {
        let e = entries(&[("example.com", true), ("*.corp.example.net", true), ("https://app.example.org/login", true), ("10.0.0.0/24", true), ("secret.example.com", false)]);
        assert_eq!(passive_roots(&e), vec!["corp.example.net", "example.com"], "a URL entry authorizes paths, never name discovery for its host");
    }

    #[test]
    fn names_whose_host_has_an_excluded_path_are_still_recorded() {
        let e = entries(&[("*.example.com", true), ("https://app.example.com/admin", false), ("secret.example.com", false)]);
        assert!(in_scope(&e, "app.example.com"), "recording a name contacts nothing; only the path is excluded");
        assert!(!in_scope(&e, "secret.example.com") && !in_scope(&e, "example.org"));
    }

    #[test]
    fn dns_answers_become_names_addresses_and_records() {
        let e = entries(&[("example.com", true), ("93.184.215.0/24", true)]);
        let mut b = Batch::default();
        let resolves = add_dns(
            &mut b,
            &e,
            "www.example.com",
            &[("A".into(), vec!["93.184.215.14".into()]), ("AAAA".into(), vec![]), ("CNAME".into(), vec!["edge.example.net.".into()]), ("MX".into(), vec!["10 mail.example.com.".into()])],
        );
        assert!(resolves);
        add_dns(&mut b, &e, "api.example.com", &[("A".into(), vec!["93.184.215.14".into(), "10.1.2.3".into()])]);
        let ip = &b.items[&("ip", "93.184.215.14".to_string())];
        assert_eq!(ip.data["names"], json!(["www.example.com", "api.example.com"]), "reports about one address are merged");
        assert_eq!(ip.data["inScope"], json!(true));
        assert_eq!(b.items[&("ip", "10.1.2.3".to_string())].data["nonPublic"], json!(true));
        assert!(b.items.contains_key(&("dns_record", "www.example.com mx mail.example.com".to_string())));
        assert!(!add_dns(&mut Batch::default(), &e, "gone.example.com", &[("A".into(), vec![])]));
        let mut nomail = Batch::default();
        add_dns(&mut nomail, &e, "example.com", &[("MX".into(), vec!["0 .".into()])]);
        assert_eq!((nomail.len(), nomail.invalid), (0, 0), "a null MX is skipped, not counted as invalid");
        assert_eq!(plural(1, "asset", "assets"), "1 asset");
    }

    #[test]
    fn nmap_xml_is_read_into_hosts_and_open_services() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">
            <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/>
              <hostnames><hostname name="www.example.com" type="user"/></hostnames>
              <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port>
                     <port protocol="tcp" portid="22"><state state="filtered"/><service name="ssh"/></port>
                     <port protocol="udp" portid="53"><state state="open"/></port></ports></host>
            <host><status state="down"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
            <runstats><finished time="1" exit="success"/></runstats></nmaprun>"#;
        let run = parse_nmap(xml).unwrap();
        assert!(run.finished);
        assert_eq!(run.hosts.len(), 2);
        assert_eq!(run.hosts[0].address, "192.0.2.10");
        assert_eq!(run.hosts[0].ports.len(), 3);
        let b = nmap_batch(&run);
        let keys: Vec<String> = b.items.keys().map(|(t, k)| format!("{t}:{k}")).collect();
        assert_eq!(keys, vec!["ip:192.0.2.10", "service:192.0.2.10:443/tcp", "service:192.0.2.10:53/udp", "technology:nginx"]);
        assert_eq!(up_hosts(&run), BTreeSet::from(["192.0.2.10".to_string()]));
        assert_eq!(service_host("[2001:db8::1]:53/udp").as_deref(), Some("2001:db8::1"));

        let cut = &xml[..xml.find("<host><status state=\"down\"").unwrap()];
        let partial = parse_nmap(cut).unwrap();
        assert!(!partial.finished, "a truncated scan is not finished");
        assert_eq!(partial.hosts.len(), 1);
        assert!(parse_nmap("Starting Nmap 7.95\nFailed to resolve").is_err());
        assert_eq!(xml_from_output("<a>\n[stderr] warning\n</a>"), "<a>\n</a>");
    }

    #[test]
    fn scan_arguments_are_fixed_profiles() {
        assert_eq!(nmap_args("quick", &["192.0.2.0/28".into()]).unwrap(), vec!["-sV", "-T3", "-F", "-oX", "-", "192.0.2.0/28"]);
        assert!(nmap_args("--script=evil", &[]).is_err());
        // the execution engine accepts the arguments and finds exactly the targets
        let e = entries(&[("192.0.2.0/24", true), ("example.com", true)]);
        let targets = vec!["192.0.2.0/28".to_string(), "example.com".to_string()];
        let res = crate::targets::resolve(&nmap_args("standard", &targets).unwrap(), &targets, &e, None).unwrap();
        assert_eq!(res.checked.len(), 2, "{:?}", res.checked);
        assert!(crate::targets::resolve(&nmap_args("quick", &["example.org".into()]).unwrap(), &["example.org".into()], &e, None).is_err());
    }

    #[test]
    fn titles_are_read_from_html() {
        assert_eq!(html_title("<html><head><TITLE>\n  Sign in |  Acme </title>").as_deref(), Some("Sign in | Acme"));
        assert_eq!(html_title("<title></title>"), None);
        assert_eq!(html_title("no html"), None);
    }

    #[test]
    fn snapshots_classify_changes_and_mark_only_what_a_complete_run_covered() {
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        db.with(|c| {
            let covers_all = |_: &assets::Asset| true;
            // run 1: two names
            let s1 = assets::start_snapshot(c, p, "passive", "passive", None, None)?;
            let mut b = Batch::default();
            b.add("subdomain", "a.example.com", Certainty::Observed, json!({ "sources": ["crt.sh"] }));
            b.add("subdomain", "b.example.com", Certainty::Possible, json!({}));
            complete(c, p, s1, "passive", &b, ("completed", &[]), &covers_all)?;
            let ch = changes(c, s1)?;
            assert_eq!(ch.previous, None);
            assert_eq!(ch.changes.iter().map(|x| (x.change, x.value.as_str(), x.certainty)).collect::<Vec<_>>(), vec![("added", "a.example.com", Certainty::Observed), ("added", "b.example.com", Certainty::Possible)]);

            // a manual asset is never marked by discovery
            assets::upsert_observation(c, &AssetInput { project_id: p, kind: "subdomain".into(), value: "manual.example.com".into(), source: "manual".into(), confidence: None, osint_entity_id: None, data: None }, None)?;

            // run 2 (partial): b is missing, a changed → b is incomplete, nothing is marked
            let s2 = assets::start_snapshot(c, p, "passive", "passive", None, None)?;
            let mut b2 = Batch::default();
            b2.add("subdomain", "a.example.com", Certainty::Observed, json!({ "sources": ["crt.sh", "dns"] }));
            complete(c, p, s2, "passive", &b2, ("partial", &["crt.sh unavailable".into()]), &covers_all)?;
            let ch = changes(c, s2)?;
            assert_eq!(ch.previous, Some(s1));
            assert_eq!(ch.changes.iter().map(|x| (x.change, x.value.as_str(), x.certainty)).collect::<Vec<_>>(), vec![("changed", "a.example.com", Certainty::Observed), ("missing", "b.example.com", Certainty::Incomplete)]);
            let status = |v: &str| -> AppResult<String> { Ok(c.query_row("SELECT status FROM assets WHERE value = ?1", params![v], |r| r.get(0))?) };
            assert_eq!(status("b.example.com")?, "active", "an unfinished run removes nothing");
            assert!(snapshot(c, s2)?.note.contains("crt.sh unavailable"));

            // run 3 (completed): b still missing → possible removal, marked not observed
            let s3 = assets::start_snapshot(c, p, "passive", "passive", None, None)?;
            complete(c, p, s3, "passive", &b2, ("completed", &[]), &covers_all)?;
            let ch = changes(c, s3)?;
            assert_eq!(ch.previous, Some(s2));
            assert!(ch.changes.is_empty(), "compared with the previous run, nothing changed");
            assert_eq!(status("b.example.com")?, "not_observed");
            assert_eq!(status("manual.example.com")?, "active");
            assert_eq!(snapshots(c, p, 10)?.len(), 3);
            // any two runs of the same kind can be compared; run 1 against run 3 shows the dropped name
            let ch = compare(c, s1, s3)?;
            assert_eq!(ch.changes.iter().map(|x| (x.change, x.value.as_str())).collect::<Vec<_>>(), vec![("changed", "a.example.com"), ("missing", "b.example.com")]);

            // another source never marks passive assets
            let s4 = assets::start_snapshot(c, p, "active", "http", None, None)?;
            complete(c, p, s4, "http", &Batch::default(), ("completed", &[]), &covers_all)?;
            assert!(compare(c, s1, s4).is_err(), "different kinds of runs are not compared");
            assert_eq!(status("a.example.com")?, "active");
            Ok(())
        })
        .unwrap();
    }
}
