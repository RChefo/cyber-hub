//! TAXII 2.1 feeds (OASIS TAXII 2.1, 2021-06-10) of STIX 2.1 indicators (Mission 5;
//! docs/PROVIDERS.md#taxii-21-feeds).
//!
//! * **Off until asked.** A server does nothing until the analyst adds it. Every connection
//!   (discovery, collection list, synchronization) is started by the analyst and confirmed in a
//!   native dialog that names the server; nothing synchronizes in the background.
//! * **Transport.** HTTPS only (plain HTTP is accepted for 127.0.0.1 or localhost in debug
//!   builds, for tests). No user name or password in the URL. Redirects are not followed, so
//!   credentials never travel to another host. Every request has a timeout, every response body
//!   a size limit, and every synchronization a page and object budget. Errors never contain the
//!   credential.
//! * **Credentials** (HTTP Basic, which TAXII 2.1 clients must support, or an API-key header) are
//!   typed by the analyst into a native OS dialog (`native_prompt`: Windows' credential dialog, a
//!   GTK dialog on Linux) and kept in the OS credential store; `cyberhub-keys taxii-set` still
//!   stores them from a terminal. The web view never reads or writes them. A stored credential is
//!   bound to its server's number, origin, kind of authentication and header (`secret_name`), so
//!   it is never read for anything else, and it is deleted when one of them changes or the server
//!   is removed. Collections are synchronized only while their API root is on the server's own
//!   origin (`collection_root`, Mission 7).
//! * **What is imported.** STIX `indicator` objects whose pattern is a simple equality (or an OR
//!   of equalities) on an IPv4/IPv6 address, a domain name, a URL or a file hash. Other objects and
//!   patterns are counted and skipped with the reason; nothing is guessed. Indicators become saved
//!   indicators (with the lifecycle of Mission 4: source, reliability, confidence, validity,
//!   revocation, history). **A feed never creates a finding.**
//! * **Conflicts.** The analyst's record wins: a value already saved by the analyst or by another
//!   feed keeps its fields, and the feed's sighting is added to its history. A false positive is
//!   never changed by a feed. A feed updates only its own indicators, and only with a newer
//!   `modified`; its revocation revokes them.
//! * **Incremental.** Each collection keeps `X-TAXII-Date-Added-Last` as its `added_after` cursor;
//!   `next` continues a page set as the specification describes.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::AppResult;
use crate::ti::indicator;
use crate::ti::lifecycle;
use crate::util::now;

pub const MEDIA: &str = "application/taxii+json;version=2.1";
/// One response body.
pub const MAX_BODY: usize = 16 * 1024 * 1024;
/// Objects asked for per page.
pub const PAGE_LIMIT: u32 = 500;
/// Pages and objects per synchronization; the cursor lets the next one continue.
pub const MAX_PAGES: usize = 200;
pub const MAX_OBJECTS: usize = 100_000;
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The credential store entry of a server: `taxii_<number>_<fingerprint>`. The fingerprint (16
/// hex digits of SHA-256) covers where and how the credential is sent: the discovery URL's origin,
/// the kind of authentication and, for an API key, the header's name (in any case). A credential
/// is therefore only read for the server, origin and header it was stored for: not after an edit,
/// and not when a restored database, or another data folder of the same user, names another
/// server under the same number (Mission 7). `None` without authentication or for an address the
/// app refuses.
pub fn secret_name(server_id: i64, discovery_url: &str, auth: &str, header_name: &str) -> Option<String> {
    if !matches!(auth, "basic" | "header") {
        return None;
    }
    let origin = check_url(discovery_url).ok()?.origin().ascii_serialization();
    let header = if auth == "header" { header_name.trim().to_ascii_lowercase() } else { String::new() };
    let digest = Sha256::digest(format!("{origin}\n{auth}\n{header}").as_bytes());
    let fingerprint: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    Some(format!("taxii_{server_id}_{fingerprint}"))
}

/// The credential store entry of a stored server (see `secret_name`).
pub fn server_secret_name(s: &Server) -> Option<String> {
    secret_name(s.id, &s.discovery_url, &s.auth, &s.header_name)
}

/// A TAXII URL: https, or http to 127.0.0.1/localhost in debug builds; no credentials, query or
/// fragment; ends with `/` as TAXII URLs do.
pub fn check_url(raw: &str) -> Result<Url, String> {
    let mut u = Url::parse(raw.trim()).map_err(|_| "This is not a valid URL".to_string())?;
    let loopback = matches!(u.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"));
    match u.scheme() {
        "https" => {}
        "http" if loopback && cfg!(debug_assertions) => {}
        _ => return Err("TAXII 2.1 uses HTTPS: the URL must start with https://".into()),
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("Put no user name or password in the URL: store the credential with Store credential… on the server's card".into());
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err("A TAXII URL has no query or fragment".into());
    }
    if u.host_str().is_none_or(str::is_empty) {
        return Err("The URL has no host".into());
    }
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Auth {
    None,
    Basic { username: String, password: String },
    Header { name: String, value: String },
}

pub struct Client {
    http: reqwest::Client,
    auth: Auth,
}

fn scrub(text: &str, auth: &Auth) -> String {
    match auth {
        Auth::Basic { password, .. } => crate::ti::http::scrub(text, password),
        Auth::Header { value, .. } => crate::ti::http::scrub(text, value),
        Auth::None => text.to_string(),
    }
}

impl Client {
    pub fn new(auth: Auth) -> Result<Client, String> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("CyberHub/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Client { http, auth })
    }

    /// GET a TAXII resource: the JSON body and the response headers.
    pub async fn get(&self, url: &Url) -> Result<(Value, HeaderMap), String> {
        let mut rb = self.http.get(url.clone()).header(ACCEPT, HeaderValue::from_static(MEDIA));
        rb = match &self.auth {
            Auth::None => rb,
            Auth::Basic { username, password } => rb.basic_auth(username, Some(password)),
            Auth::Header { name, value } => rb.header(name.as_str(), value.as_str()),
        };
        let mut resp = rb.send().await.map_err(|e| {
            let e = e.without_url();
            scrub(&if e.is_timeout() { "the server did not answer in time".to_string() } else { e.to_string() }, &self.auth)
        })?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        if resp.content_length().is_some_and(|n| n as usize > MAX_BODY) {
            return Err(format!("the response is larger than {} MB", MAX_BODY / 1024 / 1024));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| scrub(&e.without_url().to_string(), &self.auth))? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(format!("the response is larger than {} MB", MAX_BODY / 1024 / 1024));
            }
            body.extend_from_slice(&chunk);
        }
        let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            // the TAXII error message resource, when the server sends one
            let detail = [json.get("title").and_then(Value::as_str), json.get("description").and_then(Value::as_str)].into_iter().flatten().collect::<Vec<_>>().join(": ");
            let what = match status {
                300..=399 => "the server redirected the request (redirects are not followed, so credentials stay with this server)".to_string(),
                401 => "the server wants credentials, or refused them (store or replace the server's credential)".into(),
                403 => "the credentials do not give access to this resource".into(),
                404 => "not found (or not visible with these credentials)".into(),
                406 => "the server does not speak TAXII 2.1 (it refused application/taxii+json;version=2.1)".into(),
                _ => format!("HTTP {status}"),
            };
            let detail: String = scrub(&detail, &self.auth).chars().take(300).collect();
            return Err(if detail.is_empty() { what } else { format!("{what} ({detail})") });
        }
        if json.is_null() {
            return Err("the response is not JSON".into());
        }
        Ok((json, headers))
    }
}

/* ───────────────────────── resources ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Discovery {
    pub title: String,
    pub description: String,
    pub default: Option<String>,
    /// absolute API root URLs
    pub api_roots: Vec<String>,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").chars().take(1000).collect()
}

/// An API root URL as the discovery resource gives it: absolute https, or relative to the
/// discovery URL (starting with a single `/`).
fn api_root(base: &Url, raw: &str) -> Option<Url> {
    let joined = if raw.starts_with('/') && !raw.starts_with("//") { base.join(raw).ok()? } else { Url::parse(raw).ok()? };
    let u = check_url(joined.as_str()).ok()?;
    // an absolute API root on another host is allowed by the specification, but the server's
    // credentials are never sent there
    (u.origin() == base.origin()).then_some(u)
}

/// A collection's API root, checked again before anything is sent to it: it must still be on the
/// server's own origin (scheme, host and port). A server edited to another origin keeps none of
/// its collections (`server_save`), and a restored database cannot point a collection, and with
/// it the server's credential, at another host (Mission 7).
pub fn collection_root(srv: &Server, coll: &Collection) -> Result<Url, String> {
    let base = check_url(&srv.discovery_url)?;
    let root = check_url(&coll.api_root)?;
    if root.origin() != base.origin() {
        return Err(format!(
            "The collection's API root ({}) is not on the server's address ({}): list the server's collections again",
            root.origin().ascii_serialization(),
            base.origin().ascii_serialization()
        ));
    }
    Ok(root)
}

pub async fn discover(client: &Client, discovery: &Url) -> Result<Discovery, String> {
    let (v, _) = client.get(discovery).await?;
    let mut roots = Vec::new();
    for r in v.get("api_roots").and_then(Value::as_array).into_iter().flatten().take(50) {
        if let Some(u) = r.as_str().and_then(|s| api_root(discovery, s)) {
            roots.push(u.to_string());
        }
    }
    Ok(Discovery { title: text(&v, "title"), description: text(&v, "description"), default: v.get("default").and_then(Value::as_str).and_then(|s| api_root(discovery, s)).map(|u| u.to_string()), api_roots: roots })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CollectionInfo {
    pub api_root: String,
    pub id: String,
    pub title: String,
    pub description: String,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Vec<String>,
}

fn collection_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub async fn collections(client: &Client, root: &Url) -> Result<Vec<CollectionInfo>, String> {
    let (v, _) = client.get(&root.join("collections/").map_err(|e| e.to_string())?).await?;
    let mut out = Vec::new();
    for c in v.get("collections").and_then(Value::as_array).into_iter().flatten().take(500) {
        let id = text(c, "id");
        if !collection_id_ok(&id) {
            continue;
        }
        out.push(CollectionInfo {
            api_root: root.to_string(),
            title: text(c, "title"),
            description: text(c, "description"),
            can_read: c.get("can_read").and_then(Value::as_bool).unwrap_or(false),
            can_write: c.get("can_write").and_then(Value::as_bool).unwrap_or(false),
            media_types: c.get("media_types").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).take(20).collect()).unwrap_or_else(|| vec!["application/stix+json".into()]),
            id,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Page {
    pub objects: Vec<Value>,
    pub more: bool,
    pub next: Option<String>,
    pub date_added_last: Option<String>,
}

pub async fn objects_page(client: &Client, root: &Url, collection: &str, added_after: Option<&str>, next: Option<&str>) -> Result<Page, String> {
    if !collection_id_ok(collection) {
        return Err("the collection id is not valid".into());
    }
    let mut u = root.join(&format!("collections/{collection}/objects/")).map_err(|e| e.to_string())?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("limit", &PAGE_LIMIT.to_string());
        q.append_pair("match[type]", "indicator");
        if let Some(a) = added_after {
            q.append_pair("added_after", a);
        }
        if let Some(n) = next {
            q.append_pair("next", n);
        }
    }
    let (v, headers) = client.get(&u).await?;
    let header = |name: &str| headers.get(name).and_then(|h| h.to_str().ok()).map(|s| s.chars().take(64).collect::<String>());
    Ok(Page {
        objects: v.get("objects").and_then(Value::as_array).cloned().unwrap_or_default(),
        more: v.get("more").and_then(Value::as_bool).unwrap_or(false),
        next: v.get("next").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 1024).map(str::to_string),
        date_added_last: header("X-TAXII-Date-Added-Last"),
    })
}

/* ───────────────────────── STIX indicators ───────────────────────── */

/// The values of a STIX pattern made of equality comparisons on observable values, joined by
/// OR: `[ipv4-addr:value = '198.51.100.7']`, `[file:hashes.'SHA-256' = '…'] OR [url:value = '…']`.
/// Anything else (AND, other operators, qualifiers, other properties) is refused with the reason.
pub fn pattern_values(pattern: &str) -> Result<Vec<String>, String> {
    let p = pattern.trim();
    if p.len() > 10_000 {
        return Err("the pattern is too long".into());
    }
    let mut out = Vec::new();
    let mut rest = p;
    loop {
        rest = rest.trim_start();
        let Some(body) = rest.strip_prefix('[') else {
            return Err("not a comparison in brackets".into());
        };
        // the value is quoted; find the closing quote (\' escapes a quote, \\ a backslash)
        let eq = body.find('=').ok_or("not an equality")?;
        let (lhs, after) = body.split_at(eq);
        let lhs = lhs.trim();
        let after = after[1..].trim_start();
        if lhs.ends_with('!') || lhs.contains(" AND ") || lhs.contains(" OR ") {
            return Err("not a simple equality".into());
        }
        let path = match lhs {
            "ipv4-addr:value" | "ipv6-addr:value" | "domain-name:value" | "url:value" => lhs,
            "file:hashes.'SHA-256'" | "file:hashes.SHA256" | "file:hashes.'SHA-1'" | "file:hashes.SHA1" | "file:hashes.MD5" | "file:hashes.'MD5'" => "file:hashes",
            other => return Err(format!("the property {} is not imported", other.chars().take(60).collect::<String>())),
        };
        let Some(q) = after.strip_prefix('\'') else {
            return Err("the value is not a quoted string".into());
        };
        let mut value = String::new();
        let mut chars = q.char_indices();
        let mut end = None;
        while let Some((i, ch)) = chars.next() {
            match ch {
                '\\' => match chars.next() {
                    Some((_, e)) => value.push(e),
                    None => break,
                },
                '\'' => {
                    end = Some(i);
                    break;
                }
                c => value.push(c),
            }
        }
        let end = end.ok_or("the value has no closing quote")?;
        let tail = q[end + 1..].trim_start();
        let Some(tail) = tail.strip_prefix(']') else {
            return Err("the comparison has more than one term".into());
        };
        let _ = path;
        out.push(value);
        let tail = tail.trim_start();
        if tail.is_empty() {
            break;
        }
        match tail.strip_prefix("OR") {
            Some(t) if t.starts_with([' ', '[']) => rest = t,
            _ => return Err("observation expressions other than OR (AND, FOLLOWEDBY, qualifiers) are not imported".into()),
        }
        if out.len() > 100 {
            return Err("the pattern has more than 100 values".into());
        }
    }
    Ok(out)
}

/// A STIX indicator as Cyber Hub keeps it.
#[derive(Debug, Clone, PartialEq)]
pub struct StixIndicator {
    pub id: String,
    pub name: String,
    pub values: Vec<String>,
    pub confidence: Option<i64>,
    /// YYYY-MM-DD
    pub valid_until: Option<String>,
    pub revoked: bool,
    pub modified: String,
}

/// An `indicator` object, or why it is skipped.
pub fn indicator(obj: &Value) -> Result<StixIndicator, String> {
    if obj.get("type").and_then(Value::as_str) != Some("indicator") {
        return Err(format!("{} objects are not imported", obj.get("type").and_then(Value::as_str).unwrap_or("untyped").chars().take(40).collect::<String>()));
    }
    let id = text(obj, "id");
    if !id.starts_with("indicator--") || id.len() > 100 {
        return Err("the indicator has no valid id".into());
    }
    if obj.get("pattern_type").and_then(Value::as_str).is_some_and(|t| t != "stix") {
        return Err("patterns other than STIX (Snort, YARA, Sigma…) are not imported".into());
    }
    let pattern = obj.get("pattern").and_then(Value::as_str).ok_or("the indicator has no pattern")?;
    let values = pattern_values(pattern)?;
    let date = |k: &str| {
        obj.get(k).and_then(Value::as_str).and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc).date_naive().to_string())
    };
    Ok(StixIndicator {
        name: text(obj, "name").chars().take(200).collect(),
        values,
        confidence: obj.get("confidence").and_then(Value::as_i64).filter(|c| (0..=100).contains(c)),
        valid_until: date("valid_until"),
        revoked: obj.get("revoked").and_then(Value::as_bool).unwrap_or(false),
        modified: text(obj, "modified").chars().take(40).collect(),
        id,
    })
}

/* ───────────────────────── storing ───────────────────────── */

/// The feed a synchronization stores into.
pub struct Feed {
    /// `taxii:<collection row id>`
    pub reference: String,
    /// "TAXII: <server> / <collection>"
    pub label: String,
    pub reliability: String,
    pub default_confidence: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Stored {
    pub added: usize,
    pub updated: usize,
    pub revoked: usize,
    /// already saved by the analyst or another feed: recorded as a sighting
    pub sighted: usize,
    pub skipped: usize,
    pub reasons: BTreeMap<String, usize>,
}

impl Stored {
    fn skip(&mut self, why: impl Into<String>) {
        self.skipped += 1;
        *self.reasons.entry(why.into()).or_default() += 1;
    }
}

/// Stores one page's objects as saved indicators (in one transaction).
pub fn store(c: &Connection, feed: &Feed, objects: &[Value], out: &mut Stored) -> AppResult<()> {
    let tx = c.unchecked_transaction()?;
    for obj in objects {
        let ind = match indicator(obj) {
            Ok(i) => i,
            Err(why) => {
                out.skip(why);
                continue;
            }
        };
        for raw in &ind.values {
            let Ok(found) = indicator::detect(raw) else {
                out.skip("not a public IP address, domain, URL or file hash");
                continue;
            };
            let value = found.value.clone();
            let confidence = ind.confidence.or(feed.default_confidence);
            let ts = now();
            let existing = lifecycle::find(&tx, &value)?;
            let own: Option<(String, String)> = match &existing {
                Some(s) => tx.query_row("SELECT feed_object, feed_modified FROM ti_saved WHERE id = ?1 AND feed_ref = ?2", params![s.id, feed.reference], |r| Ok((r.get(0)?, r.get(1)?))).optional()?,
                None => None,
            };
            match (existing, own) {
                (None, _) => {
                    let status = if ind.revoked { "revoked" } else { "active" };
                    tx.execute(
                        "INSERT INTO ti_saved (kind, indicator, note, source, reliability, confidence, status, valid_until, created_at, updated_at, feed_ref, feed_object, feed_modified)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12)",
                        params![found.kind.as_str(), value, ind.name, feed.label, feed.reliability, confidence, status, ind.valid_until, ts, feed.reference, ind.id, ind.modified],
                    )?;
                    lifecycle::record(&tx, tx.last_insert_rowid(), "saved", &format!("from {} ({})", feed.label, ind.id))?;
                    out.added += 1;
                    if ind.revoked {
                        out.revoked += 1;
                    }
                }
                // the feed's own indicator: a newer version updates it, never a false positive
                (Some(s), Some((object, modified))) if object == ind.id => {
                    if ind.modified <= modified {
                        continue;
                    }
                    let status = if s.status == "false_positive" { "false_positive" } else if ind.revoked { "revoked" } else { "active" };
                    tx.execute(
                        "UPDATE ti_saved SET confidence = ?2, valid_until = ?3, status = ?4, feed_modified = ?5, updated_at = ?6 WHERE id = ?1",
                        params![s.id, confidence, ind.valid_until, status, ind.modified, ts],
                    )?;
                    let detail = if ind.revoked && s.status != "revoked" && status == "revoked" { format!("revoked by {}", feed.label) } else { format!("updated by {} (version {})", feed.label, ind.modified) };
                    lifecycle::record(&tx, s.id, "updated", &detail)?;
                    if status == "revoked" && s.status != "revoked" {
                        out.revoked += 1;
                    }
                    out.updated += 1;
                }
                // the analyst's record, or another feed's: the feed's view goes to the history
                (Some(s), _) => {
                    let seen = format!(
                        "listed by {}{}{}{}",
                        feed.label,
                        confidence.map(|c| format!(", confidence {c}")).unwrap_or_default(),
                        ind.valid_until.as_deref().map(|v| format!(", valid until {v}")).unwrap_or_default(),
                        if ind.revoked { ", revoked there" } else { "" }
                    );
                    let last: Option<String> = tx.query_row("SELECT detail FROM ti_saved_events WHERE saved_id = ?1 ORDER BY id DESC LIMIT 1", params![s.id], |r| r.get(0)).optional()?;
                    if last.as_deref() != Some(seen.as_str()) {
                        lifecycle::record(&tx, s.id, "sighting", &seen)?;
                    }
                    out.sighted += 1;
                }
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/* ───────────────────────── servers, collections and synchronization ───────────────────────── */

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub discovery_url: String,
    pub auth: String,
    pub username: String,
    pub header_name: String,
    pub reliability: String,
    pub default_confidence: Option<i64>,
    pub title: String,
    pub discovered_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: i64,
    pub server_id: i64,
    pub api_root: String,
    pub collection: String,
    pub title: String,
    pub description: String,
    pub can_read: bool,
    /// the incremental cursor (X-TAXII-Date-Added-Last of the last stored page)
    pub added_after: Option<String>,
    pub last_sync_at: Option<String>,
    /// succeeded, partial, failed, or empty before the first synchronization
    pub last_status: String,
    pub last_error: String,
    /// indicators saved from this collection
    pub indicators: i64,
    /// when the synchronization that is running now started (Mission 7)
    pub running_since: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncRun {
    pub id: i64,
    pub collection_id: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub pages: i64,
    pub objects: i64,
    pub added: i64,
    pub updated: i64,
    pub revoked: i64,
    pub sighted: i64,
    pub skipped: i64,
    pub message: String,
}

const SERVER_COLS: &str = "id, name, discovery_url, auth, username, header_name, reliability, default_confidence, title, discovered_at, created_at, updated_at";

fn server_row(r: &rusqlite::Row) -> rusqlite::Result<Server> {
    Ok(Server {
        id: r.get(0)?,
        name: r.get(1)?,
        discovery_url: r.get(2)?,
        auth: r.get(3)?,
        username: r.get(4)?,
        header_name: r.get(5)?,
        reliability: r.get(6)?,
        default_confidence: r.get(7)?,
        title: r.get(8)?,
        discovered_at: r.get(9)?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
    })
}

pub fn servers(c: &Connection) -> AppResult<Vec<Server>> {
    Ok(c.prepare(&format!("SELECT {SERVER_COLS} FROM taxii_servers ORDER BY name, id"))?.query_map([], server_row)?.collect::<Result<_, _>>()?)
}

pub fn server(c: &Connection, id: i64) -> AppResult<Server> {
    c.query_row(&format!("SELECT {SERVER_COLS} FROM taxii_servers WHERE id = ?1"), params![id], server_row).optional()?.ok_or_else(|| crate::error::AppError::NotFound(format!("TAXII server {id}")))
}

/// What the analyst sets about a server (never its credential).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInput {
    pub id: Option<i64>,
    pub name: String,
    pub discovery_url: String,
    pub auth: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub header_name: String,
    #[serde(default)]
    pub reliability: String,
    #[serde(default)]
    pub default_confidence: Option<i64>,
}

pub fn server_save(c: &Connection, input: &ServerInput) -> AppResult<i64> {
    use crate::error::validation;
    let name = crate::util::clean("The name", &input.name, 120, true)?;
    let url = check_url(&input.discovery_url).map_err(validation)?;
    if !matches!(input.auth.as_str(), "none" | "basic" | "header") {
        return Err(validation("Authentication is none, basic or header"));
    }
    let username = crate::util::clean("The user name", &input.username, 200, input.auth == "basic")?;
    let header_name = crate::util::clean("The header name", &input.header_name, 100, input.auth == "header")?;
    if input.auth == "header" && !header_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(validation("A header name has letters, digits, - and _ only"));
    }
    if input.auth == "header" && matches!(header_name.to_ascii_lowercase().as_str(), "host" | "accept" | "content-length" | "connection" | "cookie") {
        return Err(validation("That header cannot carry a credential"));
    }
    if !["", "A", "B", "C", "D", "E", "F"].contains(&input.reliability.as_str()) {
        return Err(validation("Reliability is A to F"));
    }
    if input.default_confidence.is_some_and(|v| !(0..=100).contains(&v)) {
        return Err(validation("Confidence is a number from 0 to 100"));
    }
    let ts = now();
    match input.id {
        Some(id) => {
            server(c, id)?;
            let tx = c.unchecked_transaction()?;
            tx.execute(
                "UPDATE taxii_servers SET name = ?2, discovery_url = ?3, auth = ?4, username = ?5, header_name = ?6, reliability = ?7, default_confidence = ?8, updated_at = ?9 WHERE id = ?1",
                params![id, name, url.as_str(), input.auth, username, header_name, input.reliability, input.default_confidence, ts],
            )?;
            // collections live on the server's origin: those of an origin it left are removed (with
            // their synchronization history; indicators saved from them stay, with their source)
            let roots: Vec<(i64, String)> = tx.prepare("SELECT id, api_root FROM taxii_collections WHERE server_id = ?1")?.query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            for (cid, root) in roots {
                if check_url(&root).map_or(true, |r| r.origin() != url.origin()) {
                    tx.execute("DELETE FROM taxii_collections WHERE id = ?1", params![cid])?;
                }
            }
            tx.commit()?;
            Ok(id)
        }
        None => {
            c.execute(
                "INSERT INTO taxii_servers (name, discovery_url, auth, username, header_name, reliability, default_confidence, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                params![name, url.as_str(), input.auth, username, header_name, input.reliability, input.default_confidence, ts],
            )
            .map_err(|e| if e.to_string().contains("UNIQUE") { validation("This discovery URL is already configured") } else { e.into() })?;
            Ok(c.last_insert_rowid())
        }
    }
}

const COLLECTION_COLS: &str = "c.id, c.server_id, c.api_root, c.collection, c.title, c.description, c.can_read, c.added_after, c.last_sync_at, c.last_status, c.last_error,
    (SELECT COUNT(*) FROM ti_saved t WHERE t.feed_ref = 'taxii:' || c.id),
    (SELECT s.started_at FROM taxii_syncs s WHERE s.collection_id = c.id AND s.status = 'running' ORDER BY s.id DESC LIMIT 1)";

fn collection_row(r: &rusqlite::Row) -> rusqlite::Result<Collection> {
    Ok(Collection {
        id: r.get(0)?,
        server_id: r.get(1)?,
        api_root: r.get(2)?,
        collection: r.get(3)?,
        title: r.get(4)?,
        description: r.get(5)?,
        can_read: r.get(6)?,
        added_after: r.get(7)?,
        last_sync_at: r.get(8)?,
        last_status: r.get(9)?,
        last_error: r.get(10)?,
        indicators: r.get(11)?,
        running_since: r.get(12)?,
    })
}

pub fn collections_of(c: &Connection, server_id: i64) -> AppResult<Vec<Collection>> {
    Ok(c.prepare(&format!("SELECT {COLLECTION_COLS} FROM taxii_collections c WHERE c.server_id = ?1 ORDER BY c.title, c.id"))?.query_map(params![server_id], collection_row)?.collect::<Result<_, _>>()?)
}

pub fn collection(c: &Connection, id: i64) -> AppResult<Collection> {
    c.query_row(&format!("SELECT {COLLECTION_COLS} FROM taxii_collections c WHERE c.id = ?1"), params![id], collection_row).optional()?.ok_or_else(|| crate::error::AppError::NotFound(format!("TAXII collection {id}")))
}

/// Records what a discovery found: the server's title and its collections (known ones keep their
/// cursor and history).
pub fn record_discovery(c: &Connection, server_id: i64, d: &Discovery, found: &[CollectionInfo]) -> AppResult<()> {
    let ts = now();
    let tx = c.unchecked_transaction()?;
    tx.execute("UPDATE taxii_servers SET title = ?2, discovered_at = ?3 WHERE id = ?1", params![server_id, d.title, ts])?;
    for f in found {
        tx.execute(
            "INSERT INTO taxii_collections (server_id, api_root, collection, title, description, can_read, media_types, discovered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (server_id, api_root, collection) DO UPDATE SET title = excluded.title, description = excluded.description, can_read = excluded.can_read, media_types = excluded.media_types",
            params![server_id, f.api_root, f.id, f.title, f.description, f.can_read, serde_json::to_string(&f.media_types).unwrap_or_default(), ts],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn syncs(c: &Connection, collection_id: i64) -> AppResult<Vec<SyncRun>> {
    Ok(c
        .prepare("SELECT id, collection_id, started_at, finished_at, status, pages, objects, added, updated, revoked, sighted, skipped, message FROM taxii_syncs WHERE collection_id = ?1 ORDER BY id DESC LIMIT 50")?
        .query_map(params![collection_id], |r| {
            Ok(SyncRun {
                id: r.get(0)?,
                collection_id: r.get(1)?,
                started_at: r.get(2)?,
                finished_at: r.get(3)?,
                status: r.get(4)?,
                pages: r.get(5)?,
                objects: r.get(6)?,
                added: r.get(7)?,
                updated: r.get(8)?,
                revoked: r.get(9)?,
                sighted: r.get(10)?,
                skipped: r.get(11)?,
                message: r.get(12)?,
            })
        })?
        .collect::<Result<_, _>>()?)
}

/// The credential of a server from the OS credential store (never shown to the web view).
pub fn auth_of(s: &Server, secret: Option<String>) -> Result<Auth, String> {
    match s.auth.as_str() {
        "basic" => Ok(Auth::Basic { username: s.username.clone(), password: secret.ok_or("No password is stored for this server: use Store credential… on its card")? }),
        "header" => Ok(Auth::Header { name: s.header_name.clone(), value: secret.ok_or("No API key is stored for this server: use Store credential… on its card")? }),
        _ => Ok(Auth::None),
    }
}

/// Downloads a collection's new indicators (from its cursor), stores them page by page, and
/// records the synchronization. The cursor advances only past pages that were stored, so an
/// interrupted or failed synchronization is continued by the next one.
pub async fn sync(db: &crate::db::Db, client: &Client, collection_id: i64) -> AppResult<SyncRun> {
    let (coll, srv) = db.with(|c| {
        let coll = collection(c, collection_id)?;
        let srv = server(c, coll.server_id)?;
        Ok((coll, srv))
    })?;
    let root = collection_root(&srv, &coll).map_err(crate::error::validation)?;
    let feed = Feed {
        reference: format!("taxii:{}", coll.id),
        label: format!("TAXII: {} / {}", srv.name, if coll.title.is_empty() { coll.collection.as_str() } else { coll.title.as_str() }),
        reliability: srv.reliability.clone(),
        default_confidence: srv.default_confidence,
    };
    let started = now();
    let sync_id = db.with(|c| {
        c.execute("INSERT INTO taxii_syncs (collection_id, started_at, status) VALUES (?1, ?2, 'running')", params![coll.id, started])?;
        Ok(c.last_insert_rowid())
    })?;
    let mut stored = Stored::default();
    let (mut pages, mut objects) = (0usize, 0usize);
    let original = coll.added_after.clone();
    let mut added_after = original.clone();
    let mut cursor = original.clone();
    let mut next: Option<String> = None;
    let mut error: Option<String> = None;
    let mut complete = false;
    loop {
        if pages >= MAX_PAGES || objects >= MAX_OBJECTS {
            break;
        }
        let page = match objects_page(client, &root, &coll.collection, added_after.as_deref(), next.as_deref()).await {
            Ok(p) => p,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        pages += 1;
        objects += page.objects.len();
        db.with(|c| store(c, &feed, &page.objects, &mut stored))?;
        if page.date_added_last.is_some() {
            cursor = page.date_added_last.clone();
        }
        if !page.more {
            complete = true;
            break;
        }
        match page.next {
            Some(n) => next = Some(n),
            // more without next: continue from the last object's date (§3.5)
            None => {
                if page.date_added_last.is_none() || page.date_added_last == added_after {
                    error = Some("the server says there is more but gives no way to continue".into());
                    break;
                }
                added_after = page.date_added_last.clone();
                next = None;
            }
        }
    }
    let status = match (&error, complete) {
        (None, true) => "succeeded",
        (Some(_), _) if pages == 0 => "failed",
        _ => "partial",
    };
    let message = match (&error, complete) {
        (Some(e), _) => e.clone(),
        (None, false) => format!("Stopped after {pages} pages and {objects} objects; the next synchronization continues"),
        _ => String::new(),
    };
    let finished = now();
    db.with(|c| {
        c.execute(
            "UPDATE taxii_syncs SET finished_at = ?2, status = ?3, pages = ?4, objects = ?5, added = ?6, updated = ?7, revoked = ?8, sighted = ?9, skipped = ?10, message = ?11 WHERE id = ?1",
            params![sync_id, finished, status, pages as i64, objects as i64, stored.added as i64, stored.updated as i64, stored.revoked as i64, stored.sighted as i64, stored.skipped as i64, message],
        )?;
        c.execute(
            "UPDATE taxii_collections SET added_after = ?2, last_sync_at = ?3, last_status = ?4, last_error = ?5 WHERE id = ?1",
            params![coll.id, cursor, finished, status, error.clone().unwrap_or_default()],
        )?;
        Ok(())
    })?;
    db.with(|c| Ok(syncs(c, coll.id)?.into_iter().find(|s| s.id == sync_id).expect("the synchronization just recorded")))
}

#[cfg(test)]
#[path = "taxii_tests.rs"]
mod tests;
