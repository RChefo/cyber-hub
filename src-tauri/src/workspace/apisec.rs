//! API security (docs/DATA_MODEL.md#api-security-schema-20): the endpoints an API definition
//! describes, and checks of the definition against the OWASP API Security Top 10 (2023).
//!
//! Formats: OpenAPI 3.0 and 3.1 and Swagger 2.0 (JSON or YAML), Postman collections (v2.0, v2.1)
//! and HAR captures from a browser or proxy. Reading a file contacts nothing.
//!
//! * **Names, never values.** The inventory keeps parameter and body field names and the names of
//!   authentication schemes. Tokens, cookies, passwords and example values stay in the file, whose
//!   copy is kept in the evidence vault.
//! * **Issues and tests.** An *issue* is a property of the definition itself (a write operation
//!   that allows anonymous calls, an API key in the query string, a cleartext server). A *test*
//!   lists endpoints worth testing for a class of flaw that no definition can show (object
//!   identifiers for BOLA, URL parameters for SSRF). Only issues become findings.
//! * External `$ref`s are not fetched; local ones are followed, at most 16 hops.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{validation, AppError, AppResult};

pub const MAX_FILE_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_ENDPOINTS: usize = 5_000;
const METHODS: [&str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
const MAX_FIELDS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Param {
    pub name: String,
    /// path, query, header, cookie or form
    pub location: String,
    #[serde(default)]
    pub required: bool,
    /// string, integer, number, boolean, array, object, or empty when not declared
    #[serde(default)]
    pub kind: String,
    /// a maximum, maximum length, item limit or list of allowed values is declared
    #[serde(default)]
    pub bounded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub operation_id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub params: Vec<Param>,
    /// request body media types
    #[serde(default)]
    pub body_types: Vec<String>,
    /// request body property names (top level, and of the items of an array body)
    #[serde(default)]
    pub body_fields: Vec<String>,
    /// the alternatives that authorize a call, each a list of schemes that must all be met
    #[serde(default)]
    pub auth: Vec<Vec<String>>,
    /// anonymous calls are allowed: no requirement, or an empty alternative (`{}`)
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub servers: Vec<String>,
    /// documented (or, in a capture, observed) response codes
    #[serde(default)]
    pub responses: Vec<String>,
    /// requests seen in a capture (HAR); 0 for definitions
    #[serde(default)]
    pub seen: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Scheme {
    pub name: String,
    /// apiKey, http, oauth2, openIdConnect, mutualTLS; for collections and captures the kind seen
    /// (bearer, basic, apikey, cookie, header…)
    pub kind: String,
    /// http: basic, bearer or digest; apiKey: header, query or cookie
    #[serde(default)]
    pub detail: String,
    /// apiKey: the parameter or header name
    #[serde(default)]
    pub param: String,
    /// OAuth 2.0 flows: implicit, password, clientCredentials, authorizationCode
    #[serde(default)]
    pub flows: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiSpec {
    /// openapi-3.0, openapi-3.1, swagger-2.0, postman or har
    pub format: String,
    pub title: String,
    pub version: String,
    pub servers: Vec<String>,
    pub schemes: Vec<Scheme>,
    /// at least one operation requires authentication (a capture: carried credentials)
    pub auth_applied: bool,
    pub endpoints: Vec<Endpoint>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    /// stable within a definition: the rule, and the endpoint for per-endpoint issues
    pub id: String,
    pub rule: String,
    /// "API2:2023"
    pub owasp: String,
    pub category: String,
    pub severity: String,
    /// issue (a property of the definition) or test (endpoints to test)
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub endpoints: Vec<String>,
    pub recommendation: String,
}

/* ───────────────────────────── reading ───────────────────────────── */

/// Reads a definition, collection or capture. JSON is detected by its first character, anything
/// else is read as YAML.
pub fn parse(text: &str) -> Result<ApiSpec, String> {
    let body = text.trim_start_matches('\u{feff}').trim_start();
    let root: Value = if body.starts_with('{') || body.starts_with('[') {
        serde_json::from_str(body).map_err(|e| format!("not valid JSON: {e}"))?
    } else {
        crate::yaml::parse_one(body)?
    };
    let mut spec = if let Some(v) = root.get("openapi") {
        let v = text_of(Some(v));
        if !v.starts_with("3.") {
            return Err(format!("OpenAPI {v} is not supported; OpenAPI 3.0 and 3.1, and Swagger 2.0 are"));
        }
        openapi(&root, &v)
    } else if root.get("swagger").is_some_and(|v| v.as_str() == Some("2.0") || v.as_f64() == Some(2.0)) {
        swagger(&root)
    } else if root.pointer("/info/schema").and_then(Value::as_str).is_some_and(|s| s.contains("postman")) || (root.get("item").is_some() && root.get("info").is_some()) {
        postman(&root)
    } else if root.pointer("/log/entries").is_some() {
        har(&root)
    } else {
        return Err("This is not an OpenAPI or Swagger definition, a Postman collection or a HAR capture".into());
    };
    if spec.endpoints.len() > MAX_ENDPOINTS {
        spec.warnings.push(format!("Only the first {MAX_ENDPOINTS} of {} endpoints were kept", spec.endpoints.len()));
        spec.endpoints.truncate(MAX_ENDPOINTS);
    }
    spec.endpoints.sort_by(|a, b| (a.path.as_str(), method_rank(&a.method)).cmp(&(b.path.as_str(), method_rank(&b.method))));
    spec.servers.dedup();
    spec.auth_applied = spec.endpoints.iter().any(|e| !e.auth.is_empty());
    Ok(spec)
}

fn method_rank(m: &str) -> usize {
    METHODS.iter().position(|x| x.eq_ignore_ascii_case(m)).unwrap_or(METHODS.len())
}

fn text_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn short(s: &str, n: usize) -> String {
    let line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
    line.chars().take(n).collect()
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().map(|x| text_of(Some(x))).filter(|s| !s.is_empty()).take(50).collect()).unwrap_or_default()
}

/// Follows local `$ref`s (`#/components/...`), at most 16 hops; an external or broken reference
/// is returned as it is.
fn deref<'a>(root: &'a Value, mut v: &'a Value) -> &'a Value {
    for _ in 0..16 {
        match v.get("$ref").and_then(Value::as_str) {
            Some(r) if r.starts_with("#/") => match root.pointer(&r[1..]) {
                Some(t) => v = t,
                None => return v,
            },
            _ => return v,
        }
    }
    v
}

/// A server URL without a trailing slash; `{variables}` take their default.
fn server_url(url: &str, vars: Option<&Value>) -> String {
    let mut u = url.trim().to_string();
    if let Some(vars) = vars.and_then(Value::as_object) {
        for (k, v) in vars {
            let d = text_of(v.get("default"));
            u = u.replace(&format!("{{{k}}}"), &d);
        }
    }
    u.trim_end_matches('/').to_string()
}

fn servers3(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|list| list.iter().map(|s| server_url(&text_of(s.get("url")), s.get("variables"))).filter(|s| !s.is_empty()).take(20).collect())
        .unwrap_or_default()
}

/// `{name: [scopes]}` alternatives → (alternatives, anonymous allowed)
fn security(v: Option<&Value>) -> (Vec<Vec<String>>, bool) {
    let Some(list) = v.and_then(Value::as_array) else { return (Vec::new(), true) };
    let mut alternatives = Vec::new();
    let mut anonymous = list.is_empty();
    for req in list {
        match req.as_object() {
            Some(o) if !o.is_empty() => alternatives.push(o.keys().cloned().collect()),
            _ => anonymous = true,
        }
    }
    (alternatives, anonymous)
}

fn bounded(schema: &Value) -> bool {
    ["maximum", "exclusiveMaximum", "maxLength", "maxItems", "enum", "const"].iter().any(|k| schema.get(k).is_some()) || schema.get("type").and_then(Value::as_str) == Some("boolean")
}

/// Schemas visited for one request body. A schema whose `allOf` lists itself 50 times would
/// otherwise be visited 50^8 times within the depth limit.
const MAX_SCHEMA_VISITS: usize = 2_000;

/// The property names of a request body schema (allOf/oneOf/anyOf combined; the items of an array).
fn body_fields(root: &Value, schema: Option<&Value>, out: &mut Vec<String>, depth: usize) {
    let mut budget = MAX_SCHEMA_VISITS;
    body_fields_in(root, schema, out, depth, &mut budget);
}

fn body_fields_in(root: &Value, schema: Option<&Value>, out: &mut Vec<String>, depth: usize, budget: &mut usize) {
    let Some(schema) = schema else { return };
    if depth > 8 || out.len() >= MAX_FIELDS || *budget == 0 {
        return;
    }
    *budget -= 1;
    let s = deref(root, schema);
    if let Some(props) = s.get("properties").and_then(Value::as_object) {
        for k in props.keys() {
            if !out.contains(k) && out.len() < MAX_FIELDS {
                out.push(k.clone());
            }
        }
    }
    for combo in ["allOf", "oneOf", "anyOf"] {
        if let Some(list) = s.get(combo).and_then(Value::as_array) {
            for sub in list {
                body_fields_in(root, Some(sub), out, depth + 1, budget);
            }
        }
    }
    if s.get("type").and_then(Value::as_str) == Some("array") {
        body_fields_in(root, s.get("items"), out, depth + 1, budget);
    }
}

/// Parameters of an operation: path-level ones overridden by operation-level ones (same name and
/// location). Swagger 2.0 `in: body` parameters give their schema back instead.
fn parameters<'a>(root: &'a Value, path_level: Option<&'a Value>, op_level: Option<&'a Value>) -> (Vec<Param>, Vec<&'a Value>) {
    let mut by_key: BTreeMap<(String, String), Param> = BTreeMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    let mut bodies = Vec::new();
    for list in [path_level, op_level].into_iter().flatten() {
        for p in list.as_array().into_iter().flatten() {
            let p = deref(root, p);
            let name = text_of(p.get("name"));
            let location = text_of(p.get("in"));
            if location == "body" {
                if let Some(s) = p.get("schema") {
                    bodies.push(s);
                }
                continue;
            }
            if name.is_empty() {
                continue;
            }
            let schema = p.get("schema").map(|s| deref(root, s)).unwrap_or(p);
            let param = Param {
                location: if location == "formData" { "form".into() } else { location.clone() },
                required: location == "path" || p.get("required").and_then(Value::as_bool).unwrap_or(false),
                kind: text_of(schema.get("type")),
                bounded: bounded(schema),
                name: name.clone(),
            };
            let key = (name, param.location.clone());
            if !by_key.contains_key(&key) {
                order.push(key.clone());
            }
            by_key.insert(key, param);
        }
    }
    (order.into_iter().filter_map(|k| by_key.remove(&k)).collect(), bodies)
}

/// `{name}` segments of a path template that no parameter declares (definitions often omit them).
fn template_params(path: &str, params: &mut Vec<Param>) {
    for seg in path.split('/') {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')).filter(|n| !n.is_empty()) {
            if !params.iter().any(|p| p.location == "path" && p.name == name) {
                params.push(Param { name: name.to_string(), location: "path".into(), required: true, ..Default::default() });
            }
        }
    }
}

fn openapi(root: &Value, version: &str) -> ApiSpec {
    let mut spec = ApiSpec {
        format: if version.starts_with("3.1") { "openapi-3.1" } else { "openapi-3.0" }.into(),
        title: text_of(root.pointer("/info/title")),
        version: text_of(root.pointer("/info/version")),
        servers: servers3(root.get("servers")),
        ..Default::default()
    };
    if let Some(defs) = root.pointer("/components/securitySchemes").and_then(Value::as_object) {
        for (name, s) in defs {
            let s = deref(root, s);
            let kind = text_of(s.get("type"));
            spec.schemes.push(Scheme {
                name: name.clone(),
                detail: match kind.as_str() {
                    "http" => text_of(s.get("scheme")).to_ascii_lowercase(),
                    "apiKey" => text_of(s.get("in")),
                    _ => String::new(),
                },
                param: if kind == "apiKey" { text_of(s.get("name")) } else { String::new() },
                flows: s.get("flows").and_then(Value::as_object).map(|f| f.keys().cloned().collect()).unwrap_or_default(),
                kind,
            });
        }
    }
    let global = root.get("security");
    let mut external = BTreeSet::new();
    for (path, item) in root.get("paths").and_then(Value::as_object).into_iter().flatten() {
        let item = deref(root, item);
        let path_servers = item.get("servers").map(|s| servers3(Some(s))).filter(|s| !s.is_empty());
        for m in METHODS {
            let Some(op) = item.get(m) else { continue };
            let op = deref(root, op);
            let (mut params, _) = parameters(root, item.get("parameters"), op.get("parameters"));
            template_params(path, &mut params);
            let mut e = Endpoint {
                method: m.to_ascii_uppercase(),
                path: path.clone(),
                operation_id: text_of(op.get("operationId")),
                summary: short(&text_of(op.get("summary").or(op.get("description"))), 200),
                tags: strings(op.get("tags")),
                deprecated: op.get("deprecated").and_then(Value::as_bool).unwrap_or(false),
                params,
                servers: op.get("servers").map(|s| servers3(Some(s))).filter(|s| !s.is_empty()).or_else(|| path_servers.clone()).unwrap_or_else(|| spec.servers.clone()),
                responses: op.get("responses").and_then(Value::as_object).map(|r| r.keys().take(30).cloned().collect()).unwrap_or_default(),
                ..Default::default()
            };
            if let Some(body) = op.get("requestBody").map(|b| deref(root, b)) {
                for (ctype, media) in body.get("content").and_then(Value::as_object).into_iter().flatten() {
                    e.body_types.push(ctype.clone());
                    body_fields(root, media.get("schema"), &mut e.body_fields, 0);
                }
            }
            (e.auth, e.anonymous) = security(op.get("security").or(global));
            for r in [op.get("requestBody"), op.get("$ref")].into_iter().flatten() {
                if let Some(x) = r.get("$ref").and_then(Value::as_str).filter(|x| !x.starts_with("#/")) {
                    external.insert(x.to_string());
                }
            }
            spec.endpoints.push(e);
        }
    }
    if !external.is_empty() {
        spec.warnings.push(format!("{} external references were not followed (for example {})", external.len(), external.iter().next().cloned().unwrap_or_default()));
    }
    spec
}

fn swagger(root: &Value) -> ApiSpec {
    let host = text_of(root.get("host"));
    let base = text_of(root.get("basePath"));
    let schemes = strings(root.get("schemes"));
    let mut servers: Vec<String> = Vec::new();
    if host.is_empty() {
        if !base.is_empty() {
            servers.push(base.trim_end_matches('/').to_string());
        }
    } else {
        for s in if schemes.is_empty() { vec!["https".to_string()] } else { schemes } {
            servers.push(format!("{s}://{host}{}", base.trim_end_matches('/')));
        }
    }
    let mut spec = ApiSpec {
        format: "swagger-2.0".into(),
        title: text_of(root.pointer("/info/title")),
        version: text_of(root.pointer("/info/version")),
        servers,
        ..Default::default()
    };
    for (name, s) in root.get("securityDefinitions").and_then(Value::as_object).into_iter().flatten() {
        let kind = text_of(s.get("type"));
        let flow = match text_of(s.get("flow")).as_str() {
            "application" => "clientCredentials".to_string(),
            "accessCode" => "authorizationCode".to_string(),
            other => other.to_string(),
        };
        spec.schemes.push(Scheme {
            name: name.clone(),
            kind: if kind == "basic" { "http".into() } else { kind.clone() },
            detail: match kind.as_str() {
                "basic" => "basic".into(),
                "apiKey" => text_of(s.get("in")),
                _ => String::new(),
            },
            param: if kind == "apiKey" { text_of(s.get("name")) } else { String::new() },
            flows: if flow.is_empty() { Vec::new() } else { vec![flow] },
        });
    }
    let global = root.get("security");
    let consumes = strings(root.get("consumes"));
    for (path, item) in root.get("paths").and_then(Value::as_object).into_iter().flatten() {
        for m in METHODS {
            let Some(op) = item.get(m) else { continue };
            let (mut params, bodies) = parameters(root, item.get("parameters"), op.get("parameters"));
            template_params(path, &mut params);
            let has_form = params.iter().any(|p| p.location == "form");
            let mut e = Endpoint {
                method: m.to_ascii_uppercase(),
                path: path.clone(),
                operation_id: text_of(op.get("operationId")),
                summary: short(&text_of(op.get("summary").or(op.get("description"))), 200),
                tags: strings(op.get("tags")),
                deprecated: op.get("deprecated").and_then(Value::as_bool).unwrap_or(false),
                params,
                servers: spec.servers.clone(),
                responses: op.get("responses").and_then(Value::as_object).map(|r| r.keys().take(30).cloned().collect()).unwrap_or_default(),
                ..Default::default()
            };
            if !bodies.is_empty() || has_form {
                let op_consumes = strings(op.get("consumes"));
                e.body_types = if op_consumes.is_empty() { consumes.clone() } else { op_consumes };
                for b in bodies {
                    body_fields(root, Some(b), &mut e.body_fields, 0);
                }
            }
            (e.auth, e.anonymous) = security(op.get("security").or(global));
            spec.endpoints.push(e);
        }
    }
    spec
}

/* ─────────────── Postman collections ─────────────── */

/// A substituted value. Variables that expand into each other (`a` = `{{a}}{{a}}…`) grow
/// without end; past this size the text is left as written.
const MAX_SUBSTITUTED: usize = 64 * 1024;

/// `{{name}}` replaced by the collection's variables (unknown ones are left as they are).
fn substitute(s: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = s.to_string();
    for _ in 0..4 {
        let mut changed = false;
        for (k, v) in vars {
            let pat = format!("{{{{{k}}}}}");
            let n = out.matches(&pat).count();
            if n == 0 {
                continue;
            }
            // the size is known before anything is allocated
            if out.len() + n * v.len() > MAX_SUBSTITUTED {
                return s.to_string();
            }
            out = out.replace(&pat, v);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    out
}

/// `:id` and `{{id}}` path segments as `{id}`.
fn template_path(segments: &[String]) -> String {
    let parts: Vec<String> = segments
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(n) = s.strip_prefix(':') {
                format!("{{{n}}}")
            } else if s.starts_with("{{") && s.ends_with("}}") && s.len() > 4 {
                format!("{{{}}}", &s[2..s.len() - 2])
            } else {
                s.clone()
            }
        })
        .collect();
    format!("/{}", parts.join("/"))
}

/// An attribute of a Postman auth block, in the v2.1 list form or the v2.0 object form.
fn auth_attr(block: &Value, kind: &str, attr: &str) -> String {
    match block.get(kind) {
        Some(Value::Array(list)) => list.iter().find(|x| text_of(x.get("key")) == attr).map(|x| text_of(x.get("value"))).unwrap_or_default(),
        Some(Value::Object(o)) => text_of(o.get(attr)),
        _ => String::new(),
    }
}

fn postman_scheme(block: &Value) -> Option<Scheme> {
    let kind = text_of(block.get("type"));
    if kind.is_empty() || kind == "noauth" || kind == "inherit" {
        return None;
    }
    let mut s = Scheme { name: kind.clone(), kind: kind.clone(), ..Default::default() };
    match kind.as_str() {
        "apikey" => {
            s.detail = match auth_attr(block, "apikey", "in").as_str() {
                "query" => "query".into(),
                _ => "header".into(),
            };
            s.param = auth_attr(block, "apikey", "key");
            s.name = format!("apikey ({})", s.detail);
        }
        "basic" | "digest" | "bearer" => s.detail = kind.clone(),
        "oauth2" => {
            let flow = match auth_attr(block, "oauth2", "grant_type").as_str() {
                "implicit" => "implicit",
                "password_credentials" => "password",
                "client_credentials" => "clientCredentials",
                "" => "",
                _ => "authorizationCode",
            };
            if !flow.is_empty() {
                s.flows = vec![flow.to_string()];
                s.name = format!("oauth2 ({flow})");
            }
        }
        _ => {}
    }
    Some(s)
}

fn postman(root: &Value) -> ApiSpec {
    let mut spec = ApiSpec { format: "postman".into(), title: text_of(root.pointer("/info/name")), ..Default::default() };
    spec.version = match root.pointer("/info/version") {
        Some(Value::Object(o)) => format!("{}.{}.{}", text_of(o.get("major")), text_of(o.get("minor")), text_of(o.get("patch"))),
        v => text_of(v),
    };
    let vars: BTreeMap<String, String> = root
        .get("variable")
        .and_then(Value::as_array)
        .map(|l| l.iter().map(|v| (text_of(v.get("key")), text_of(v.get("value")))).filter(|(k, _)| !k.is_empty()).collect())
        .unwrap_or_default();
    let mut found: BTreeMap<(String, String), Endpoint> = BTreeMap::new();
    let mut schemes: BTreeMap<String, Scheme> = BTreeMap::new();
    let mut servers = BTreeSet::new();
    walk_postman(root.get("item"), root.get("auth"), &vars, &mut found, &mut schemes, &mut servers, 0, &mut spec.warnings);
    spec.endpoints = found.into_values().collect();
    spec.schemes = schemes.into_values().collect();
    spec.servers = servers.into_iter().collect();
    spec
}

#[allow(clippy::too_many_arguments)]
fn walk_postman(
    items: Option<&Value>,
    inherited: Option<&Value>,
    vars: &BTreeMap<String, String>,
    found: &mut BTreeMap<(String, String), Endpoint>,
    schemes: &mut BTreeMap<String, Scheme>,
    servers: &mut BTreeSet<String>,
    depth: usize,
    warnings: &mut Vec<String>,
) {
    if depth > 32 {
        warnings.push("Folders nested deeper than 32 levels were skipped".into());
        return;
    }
    for item in items.and_then(Value::as_array).into_iter().flatten() {
        let auth = item.get("auth").or(inherited);
        if item.get("item").is_some() {
            walk_postman(item.get("item"), auth, vars, found, schemes, servers, depth + 1, warnings);
            continue;
        }
        let Some(req) = item.get("request") else { continue };
        let (method, url) = match req {
            Value::String(u) => ("GET".to_string(), Value::String(u.clone())),
            _ => (text_of(req.get("method")).to_ascii_uppercase(), req.get("url").cloned().unwrap_or(Value::Null)),
        };
        let method = if method.is_empty() { "GET".to_string() } else { method };
        let (server, path, query) = postman_url(&url, vars);
        if !server.is_empty() {
            servers.insert(server.clone());
        }
        let key = (method.clone(), path.clone());
        let e = found.entry(key).or_insert_with(|| Endpoint { method: method.clone(), path: path.clone(), summary: short(&text_of(item.get("name")), 200), ..Default::default() });
        push_unique(&mut e.servers, server);
        // at most MAX_FIELDS parameters per endpoint, as for HAR (Mission 6: a URL with tens of
        // thousands of query names took a linear search per name)
        for q in query {
            if e.params.len() < MAX_FIELDS && !e.params.iter().any(|p| p.name == q && p.location == "query") {
                e.params.push(Param { name: q, location: "query".into(), ..Default::default() });
            }
        }
        for seg in path.split('/').filter(|s| s.starts_with('{') && s.ends_with('}') && s.len() > 2) {
            let name = seg[1..seg.len() - 1].to_string();
            if e.params.len() < MAX_FIELDS && !e.params.iter().any(|p| p.name == name && p.location == "path") {
                e.params.push(Param { name, location: "path".into(), required: true, ..Default::default() });
            }
        }
        let request_auth = req.get("auth").or(auth);
        let mut alternative = Vec::new();
        if let Some(s) = request_auth.and_then(postman_scheme) {
            alternative.push(s.name.clone());
            schemes.entry(s.name.clone()).or_insert(s);
        }
        let headers: Vec<(String, String)> = req
            .get("header")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter(|h| !h.get("disabled").and_then(Value::as_bool).unwrap_or(false)).map(|h| (text_of(h.get("key")), text_of(h.get("value")))).collect())
            .unwrap_or_default();
        for (name, value) in &headers {
            if let Some(s) = credential_header(name, value) {
                if !alternative.contains(&s.name) {
                    alternative.push(s.name.clone());
                }
                schemes.entry(s.name.clone()).or_insert(s);
            }
        }
        if alternative.is_empty() {
            e.anonymous = true;
        } else if e.auth.len() < MAX_FIELDS && !e.auth.contains(&alternative) {
            e.auth.push(alternative);
        }
        if let Some(body) = req.get("body") {
            let ctype = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone());
            match text_of(body.get("mode")).as_str() {
                "raw" => {
                    let lang = text_of(body.pointer("/options/raw/language"));
                    let t = ctype.unwrap_or_else(|| if lang == "json" { "application/json".into() } else { "text/plain".into() });
                    push_unique(&mut e.body_types, t);
                    json_fields(&text_of(body.get("raw")), &mut e.body_fields);
                }
                mode @ ("urlencoded" | "formdata") => {
                    push_unique(&mut e.body_types, if mode == "urlencoded" { "application/x-www-form-urlencoded".into() } else { "multipart/form-data".into() });
                    for f in body.get(mode).and_then(Value::as_array).into_iter().flatten() {
                        let n = text_of(f.get("key"));
                        if !n.is_empty() && e.params.len() < MAX_FIELDS && !e.params.iter().any(|p| p.name == n && p.location == "form") {
                            e.params.push(Param { name: n, location: "form".into(), ..Default::default() });
                        }
                    }
                }
                "graphql" => push_unique(&mut e.body_types, "application/graphql".into()),
                _ => {}
            }
        }
    }
}

/// Adds `s` once, keeping at most MAX_FIELDS values (servers, body fields, media types,
/// responses of one endpoint), so each check stays a short search.
fn push_unique(v: &mut Vec<String>, s: String) {
    if !s.is_empty() && v.len() < MAX_FIELDS && !v.contains(&s) {
        v.push(s);
    }
}

/// The top-level keys of a JSON body (a body with `{{variables}}` is read with a pattern instead).
fn json_fields(raw: &str, out: &mut Vec<String>) {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(o)) => o.keys().take(MAX_FIELDS).for_each(|k| push_unique(out, k.clone())),
        Ok(Value::Array(a)) => {
            if let Some(Value::Object(o)) = a.first() {
                o.keys().take(MAX_FIELDS).for_each(|k| push_unique(out, k.clone()));
            }
        }
        Ok(_) => {}
        Err(_) => {
            static KEY: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r#""([A-Za-z_][A-Za-z0-9_.\-]{0,63})"\s*:"#).expect("valid pattern"));
            for c in KEY.captures_iter(raw).take(MAX_FIELDS) {
                push_unique(out, c[1].to_string());
            }
        }
    }
}

/// The server, the path template and the query parameter names of a Postman URL.
fn postman_url(url: &Value, vars: &BTreeMap<String, String>) -> (String, String, Vec<String>) {
    let mut query = Vec::new();
    match url {
        Value::String(raw) => {
            let raw = substitute(raw, vars);
            let (no_query, q) = raw.split_once('?').unwrap_or((raw.as_str(), ""));
            for pair in q.split('&').filter(|p| !p.is_empty()) {
                let name = pair.split('=').next().unwrap_or("").to_string();
                if !name.is_empty() {
                    query.push(name);
                }
            }
            let (server, path) = match no_query.split_once("://") {
                Some((scheme, rest)) => {
                    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
                    (format!("{scheme}://{host}"), path.to_string())
                }
                None => match no_query.split_once('/') {
                    Some((host, path)) if host.starts_with("{{") || host.contains('.') => (host.to_string(), path.to_string()),
                    _ => (String::new(), no_query.trim_start_matches('/').to_string()),
                },
            };
            let segments: Vec<String> = path.split('/').map(str::to_string).collect();
            (server, template_path(&segments), query)
        }
        Value::Object(o) => {
            let host = match o.get("host") {
                Some(Value::Array(parts)) => parts.iter().map(|p| text_of(Some(p))).collect::<Vec<_>>().join("."),
                v => text_of(v),
            };
            let host = substitute(&host, vars);
            let protocol = substitute(&text_of(o.get("protocol")), vars);
            let port = substitute(&text_of(o.get("port")), vars);
            let server = if host.is_empty() {
                String::new()
            } else if host.contains("://") {
                host.trim_end_matches('/').to_string()
            } else {
                format!("{}://{host}{}", if protocol.is_empty() { "https" } else { protocol.as_str() }, if port.is_empty() { String::new() } else { format!(":{port}") })
            };
            let segments: Vec<String> = match o.get("path") {
                Some(Value::Array(parts)) => parts.iter().map(|p| text_of(Some(p)).trim_matches('/').to_string()).collect(),
                v => text_of(v).split('/').map(str::to_string).collect(),
            };
            for q in o.get("query").and_then(Value::as_array).into_iter().flatten() {
                if !q.get("disabled").and_then(Value::as_bool).unwrap_or(false) {
                    let k = text_of(q.get("key"));
                    if !k.is_empty() {
                        query.push(k);
                    }
                }
            }
            if o.get("host").is_none() && o.get("path").is_none() {
                return postman_url(&Value::String(text_of(o.get("raw"))), vars);
            }
            (server, template_path(&segments), query)
        }
        _ => (String::new(), "/".into(), query),
    }
}

/// A header that carries credentials, as a scheme (the value is only used to name its type).
fn credential_header(name: &str, value: &str) -> Option<Scheme> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "authorization" | "proxy-authorization" => {
            let word = value.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            let detail = match word.as_str() {
                "basic" | "bearer" | "digest" | "ntlm" | "negotiate" => word,
                _ => "custom".into(),
            };
            Some(Scheme { name: format!("Authorization: {detail}"), kind: "http".into(), detail, ..Default::default() })
        }
        "cookie" => Some(Scheme { name: "cookie".into(), kind: "cookie".into(), ..Default::default() }),
        "x-api-key" | "api-key" | "apikey" | "x-auth-token" | "x-access-token" | "x-csrf-token" | "x-amz-security-token" => {
            Some(Scheme { name: format!("header: {name}"), kind: "apiKey".into(), detail: "header".into(), param: name.to_string(), ..Default::default() })
        }
        _ => None,
    }
}

/* ─────────────── HAR captures ─────────────── */

const STATIC_EXT: &[&str] = &[
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav",
];

/// A path segment that is a value rather than a name: a number, a UUID, a long hex or token, an
/// e-mail address.
fn value_segment(s: &str) -> Option<&'static str> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return Some("id");
    }
    let hex = s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    if hex && s.len() == 36 && s.matches('-').count() == 4 {
        return Some("id");
    }
    if hex && s.len() >= 16 && s.bytes().any(|b| b.is_ascii_digit()) {
        return Some("id");
    }
    if s.contains('@') && s.contains('.') {
        return Some("email");
    }
    if s.len() >= 24 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && s.bytes().any(|b| b.is_ascii_digit()) && s.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Some("token");
    }
    None
}

fn har(root: &Value) -> ApiSpec {
    let mut spec = ApiSpec { format: "har".into(), title: "HAR capture".into(), ..Default::default() };
    if let Some(c) = root.pointer("/log/creator") {
        spec.version = format!("{} {}", text_of(c.get("name")), text_of(c.get("version"))).trim().to_string();
    }
    let mut found: BTreeMap<(String, String), Endpoint> = BTreeMap::new();
    let mut schemes: BTreeMap<String, Scheme> = BTreeMap::new();
    let mut servers = BTreeSet::new();
    let (mut skipped, mut other) = (0usize, 0usize);
    for entry in root.pointer("/log/entries").and_then(Value::as_array).into_iter().flatten() {
        let req = entry.get("request").unwrap_or(&Value::Null);
        let Ok(url) = url::Url::parse(&text_of(req.get("url"))) else {
            other += 1;
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            other += 1;
            continue;
        }
        let resource = text_of(entry.get("_resourceType")).to_ascii_lowercase();
        let mime = text_of(entry.pointer("/response/content/mimeType")).to_ascii_lowercase();
        let lower_path = url.path().to_ascii_lowercase();
        if matches!(resource.as_str(), "image" | "stylesheet" | "script" | "font" | "media" | "manifest")
            || STATIC_EXT.iter().any(|x| lower_path.ends_with(x))
            || ["image/", "font/", "text/css", "javascript", "video/", "audio/"].iter().any(|m| mime.contains(m))
        {
            skipped += 1;
            continue;
        }
        let origin = url.origin().ascii_serialization();
        servers.insert(origin.clone());
        let mut path_params = Vec::new();
        let segments: Vec<String> = url
            .path_segments()
            .map(|s| {
                s.map(|seg| match value_segment(seg) {
                    Some(kind) => {
                        path_params.push(kind);
                        format!("{{{kind}}}")
                    }
                    None => seg.to_string(),
                })
                .collect()
            })
            .unwrap_or_default();
        let path = template_path(&segments);
        let method = text_of(req.get("method")).to_ascii_uppercase();
        let e = found.entry((method.clone(), path.clone())).or_insert_with(|| Endpoint { method, path, ..Default::default() });
        e.seen = e.seen.saturating_add(1);
        push_unique(&mut e.servers, origin);
        for kind in path_params {
            if !e.params.iter().any(|p| p.name == kind && p.location == "path") {
                e.params.push(Param { name: kind.into(), location: "path".into(), required: true, ..Default::default() });
            }
        }
        for (name, _) in url.query_pairs() {
            if !e.params.iter().any(|p| p.name == name && p.location == "query") && e.params.len() < MAX_FIELDS {
                e.params.push(Param { name: name.to_string(), location: "query".into(), ..Default::default() });
            }
        }
        let mut alternative = Vec::new();
        for h in req.get("headers").and_then(Value::as_array).into_iter().flatten() {
            if let Some(s) = credential_header(&text_of(h.get("name")), &text_of(h.get("value"))) {
                push_unique(&mut alternative, s.name.clone());
                schemes.entry(s.name.clone()).or_insert(s);
            }
        }
        if alternative.is_empty() {
            e.anonymous = true;
        } else if e.auth.len() < MAX_FIELDS && !e.auth.contains(&alternative) {
            e.auth.push(alternative);
        }
        let status = text_of(entry.pointer("/response/status"));
        if !status.is_empty() && status != "0" {
            push_unique(&mut e.responses, status);
        }
        if let Some(post) = req.get("postData") {
            let mime = text_of(post.get("mimeType"));
            let mime = mime.split(';').next().unwrap_or("").trim().to_string();
            push_unique(&mut e.body_types, mime.clone());
            if mime.contains("json") {
                json_fields(&text_of(post.get("text")), &mut e.body_fields);
            } else if mime.contains("x-www-form-urlencoded") {
                let names: Vec<String> = match post.get("params").and_then(Value::as_array) {
                    Some(list) => list.iter().map(|p| text_of(p.get("name"))).collect(),
                    None => text_of(post.get("text")).split('&').map(|p| p.split('=').next().unwrap_or("").to_string()).collect(),
                };
                for n in names.into_iter().filter(|n| !n.is_empty()) {
                    if !e.params.iter().any(|p| p.name == n && p.location == "form") && e.params.len() < MAX_FIELDS {
                        e.params.push(Param { name: n, location: "form".into(), ..Default::default() });
                    }
                }
            }
        }
    }
    if skipped > 0 {
        spec.warnings.push(format!("{skipped} requests for images, scripts, styles, fonts and media were left out"));
    }
    if other > 0 {
        spec.warnings.push(format!("{other} entries without an http or https URL were left out"));
    }
    spec.endpoints = found.into_values().collect();
    spec.schemes = schemes.into_values().collect();
    spec.servers = servers.into_iter().collect();
    spec
}

/* ───────────────────────────── checks ───────────────────────────── */

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

fn is_write(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn label(e: &Endpoint) -> String {
    format!("{} {}", e.method, e.path)
}

fn sensitive_name(name: &str) -> bool {
    let n = norm(name);
    const EXACT: &[&str] = &["pwd", "pass", "key", "auth", "sid", "jwt", "otp", "pin", "ssn", "cvv", "cvc", "session", "authorization", "code"];
    const PART: &[&str] = &["password", "passwd", "secret", "token", "apikey", "sessionid", "creditcard", "cardnumber", "privatekey", "accesskey"];
    EXACT.contains(&n.as_str()) || PART.iter().any(|p| n.contains(p))
}

fn object_id_name(name: &str) -> bool {
    let n = norm(name);
    n.ends_with("id") || n.ends_with("uuid") || n.ends_with("guid") || n.ends_with("number") || ["username", "email", "handle", "slug", "key", "ref", "reference", "token"].contains(&n.as_str())
}

fn url_like(name: &str) -> bool {
    let n = norm(name);
    const EXACT: &[&str] = &[
        "url", "uri", "link", "href", "src", "callback", "webhook", "redirect", "return", "returnto", "next", "continue", "dest", "destination", "target", "feed", "proxy", "host", "domain", "endpoint",
        "server", "image", "imageurl", "avatar", "site", "website", "fetch", "load",
    ];
    EXACT.contains(&n.as_str()) || n.ends_with("url") || n.ends_with("uri") || n.ends_with("webhook") || n.ends_with("callback")
}

fn privileged_field(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "role", "roles", "admin", "isadmin", "staff", "isstaff", "superuser", "issuperuser", "permissions", "permission", "privileges", "privilege", "scopes", "owner", "ownerid", "tenantid",
        "balance", "credit", "credits", "verified", "isverified", "emailverified", "approved", "isapproved", "plan", "tier", "accountstatus", "groups",
    ];
    NAMES.contains(&norm(name).as_str())
}

fn page_size(p: &Param) -> bool {
    const NAMES: &[&str] = &["limit", "size", "pagesize", "perpage", "count", "max", "maxresults", "top", "take", "first", "last", "rows", "batchsize", "pagelimit"];
    (p.location == "query" || p.location == "form") && NAMES.contains(&norm(&p.name).as_str()) && !p.bounded && matches!(p.kind.as_str(), "" | "integer" | "number")
}

fn privileged_path(path: &str) -> bool {
    const SEGMENTS: &[&str] = &["internal", "debug", "actuator", "management", "manage", "console", "ops", "superuser", "sudo", "backoffice", "staff", "private", "jolokia", "heapdump", "env", "metrics", "system"];
    path.split('/').map(|s| s.to_ascii_lowercase()).any(|s| s.starts_with("admin") || SEGMENTS.contains(&s.trim_start_matches('_')))
}

fn sensitive_flow(path: &str) -> bool {
    const WORDS: &[&str] = &[
        "login", "signin", "logon", "token", "oauth", "otp", "mfa", "2fa", "verify", "verification", "password", "reset", "forgot", "register", "signup", "checkout", "purchase", "payment", "pay",
        "transfer", "withdraw", "redeem", "coupon", "voucher", "vote", "invite", "sms",
    ];
    path.split('/').map(norm).any(|s| WORDS.iter().any(|w| s == *w || (w.len() > 4 && s.contains(w))))
}

fn host_of(server: &str) -> Option<String> {
    url::Url::parse(server).ok().and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase()))
}

fn loopback(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn non_production(host: &str) -> bool {
    const LABELS: &[&str] = &["dev", "develop", "development", "test", "testing", "qa", "uat", "stage", "staging", "stg", "sandbox", "preprod", "preproduction", "local", "localhost", "internal", "intranet"];
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    host.split(['.', '-']).any(|l| LABELS.contains(&l))
}

struct Rule {
    rule: &'static str,
    owasp: &'static str,
    category: &'static str,
}

const API1: (&str, &str) = ("API1:2023", "Broken Object Level Authorization");
const API2: (&str, &str) = ("API2:2023", "Broken Authentication");
const API3: (&str, &str) = ("API3:2023", "Broken Object Property Level Authorization");
const API4: (&str, &str) = ("API4:2023", "Unrestricted Resource Consumption");
const API5: (&str, &str) = ("API5:2023", "Broken Function Level Authorization");
const API6: (&str, &str) = ("API6:2023", "Unrestricted Access to Sensitive Business Flows");
const API7: (&str, &str) = ("API7:2023", "Server Side Request Forgery");
const API8: (&str, &str) = ("API8:2023", "Security Misconfiguration");
const API9: (&str, &str) = ("API9:2023", "Improper Inventory Management");

fn rule(rule: &'static str, (owasp, category): (&'static str, &'static str)) -> Rule {
    Rule { rule, owasp, category }
}

#[allow(clippy::too_many_arguments)]
fn push(out: &mut Vec<Issue>, r: Rule, severity: &str, kind: &str, key: &str, title: String, detail: String, endpoints: Vec<String>, recommendation: &str) {
    out.push(Issue {
        id: if key.is_empty() { r.rule.to_string() } else { format!("{}:{key}", r.rule) },
        rule: r.rule.into(),
        owasp: r.owasp.into(),
        category: r.category.into(),
        severity: severity.into(),
        kind: kind.into(),
        title,
        detail,
        endpoints,
        recommendation: recommendation.into(),
    });
}

fn severity_rank(s: &str) -> usize {
    ["critical", "high", "medium", "low", "info"].iter().position(|x| *x == s).unwrap_or(5)
}

/// The checks of a definition: issues first (most severe first), then tests.
pub fn audit(spec: &ApiSpec) -> Vec<Issue> {
    let mut out = Vec::new();
    let capture = spec.format == "har" || spec.format == "postman";
    let defined = !capture;

    // ── authentication
    if defined && spec.schemes.is_empty() && !spec.endpoints.is_empty() {
        push(&mut out, rule("API2-NO-AUTH-DEFINED", API2), "medium", "issue", "", "The definition declares no authentication".into(),
            "No security scheme is declared, so the definition does not say how any operation is protected. Either the API is meant to be public or its authentication is undocumented, which keeps it out of reviews and tests.".into(),
            Vec::new(), "Declare the security schemes and apply them with security, globally or per operation. Mark public operations explicitly with security: [].");
    }
    if defined && !spec.schemes.is_empty() && !spec.auth_applied {
        push(&mut out, rule("API2-AUTH-NOT-APPLIED", API2), "medium", "issue", "", "Security schemes are declared but no operation requires one".into(),
            format!("The definition declares {} but applies none of them, so every operation is documented as callable without credentials.", plural(spec.schemes.len(), "security scheme")),
            Vec::new(), "Apply the schemes with a global security requirement and opt public operations out explicitly.");
    }
    if spec.auth_applied {
        for e in spec.endpoints.iter().filter(|e| is_write(&e.method) && e.anonymous) {
            let (severity, how) = if defined { ("high", "allows calls without credentials (no security requirement, or an empty alternative {})") } else { ("medium", "was sent without credentials") };
            push(&mut out, rule("API2-ANONYMOUS-WRITE", API2), severity, "issue", &label(e), format!("Anonymous {} {}", e.method, e.path),
                format!("{} changes data and {how}, while other operations of this API require authentication.", label(e)),
                vec![label(e)], "Require authentication for every operation that changes data, unless it is public on purpose (then document why).");
        }
    }
    for s in &spec.schemes {
        if s.detail == "basic" {
            push(&mut out, rule("API2-BASIC-AUTH", API2), "medium", "issue", &s.name, format!("HTTP Basic authentication ({})", s.name),
                "Basic authentication sends the reusable password with every request, has no expiry or scope, and is easy to brute-force without extra controls.".into(),
                Vec::new(), "Use short-lived tokens (OAuth 2.0 or OpenID Connect) and keep Basic only for machine accounts behind TLS, rate limits and lockout.");
        }
        if s.kind.eq_ignore_ascii_case("apikey") && s.detail == "query" {
            push(&mut out, rule("API2-KEY-IN-QUERY", API2), "medium", "issue", &s.name, format!("API key in the query string ({})", if s.param.is_empty() { &s.name } else { &s.param }),
                "A key in the URL ends up in server, proxy and browser logs, in the Referer header and in shared links.".into(),
                Vec::new(), "Send the key in a header (for example X-API-Key or Authorization) and rotate keys that have appeared in URLs.");
        }
        for f in s.flows.iter().filter(|f| *f == "implicit" || *f == "password") {
            push(&mut out, rule("API2-LEGACY-OAUTH-FLOW", API2), "medium", "issue", &format!("{}:{f}", s.name), format!("OAuth 2.0 {} flow ({})", if f == "implicit" { "implicit" } else { "resource owner password" }, s.name),
                format!("The {f} flow is deprecated by the OAuth 2.0 Security Best Current Practice (RFC 9700): {}.", if f == "implicit" { "tokens are returned in the URL fragment and can leak or be injected" } else { "the client handles the user's password, which defeats delegation and MFA" }),
                Vec::new(), "Use the authorization code flow with PKCE, or the client credentials flow for machine-to-machine calls.");
        }
    }

    // ── transport and URLs
    let mut all_servers: BTreeSet<String> = spec.servers.iter().cloned().collect();
    for e in &spec.endpoints {
        all_servers.extend(e.servers.iter().cloned());
    }
    let cleartext: Vec<String> = all_servers.iter().filter(|s| s.to_ascii_lowercase().starts_with("http://") && host_of(s).is_some_and(|h| !loopback(&h))).cloned().collect();
    if !cleartext.is_empty() {
        let carries = !spec.schemes.is_empty() || spec.auth_applied;
        push(&mut out, rule("API8-CLEARTEXT", API8), if carries { "high" } else { "medium" }, "issue", "", "API served over cleartext HTTP".into(),
            format!("{} {} {} plain HTTP{}: requests and responses can be read and changed on the network.", plural(cleartext.len(), "server"), cleartext.join(", "), if cleartext.len() == 1 { "uses" } else { "use" }, if carries { ", including credentials" } else { "" }),
            Vec::new(), "Serve the API only over HTTPS, redirect or refuse HTTP, and send HSTS.");
    }
    let sensitive: Vec<String> = spec
        .endpoints
        .iter()
        .filter_map(|e| {
            let names: Vec<&str> = e.params.iter().filter(|p| p.location == "query" && sensitive_name(&p.name)).map(|p| p.name.as_str()).collect();
            (!names.is_empty()).then(|| format!("{} ({})", label(e), names.join(", ")))
        })
        .collect();
    if !sensitive.is_empty() {
        push(&mut out, rule("API8-SECRET-IN-QUERY", API8), "medium", "issue", "", "Credentials or secrets in query strings".into(),
            format!("{} take passwords, tokens, keys or similar values in the URL, where logs, proxies and the Referer header keep them.", plural(sensitive.len(), "endpoint")),
            sensitive, "Move these values to headers or the request body, and treat values that were sent in URLs as exposed.");
    }

    // ── resource consumption
    let unbounded: Vec<String> = spec
        .endpoints
        .iter()
        .filter_map(|e| {
            let names: Vec<&str> = e.params.iter().filter(|p| page_size(p)).map(|p| p.name.as_str()).collect();
            (!names.is_empty()).then(|| format!("{} ({})", label(e), names.join(", ")))
        })
        .collect();
    if defined && !unbounded.is_empty() {
        push(&mut out, rule("API4-UNBOUNDED-PAGE", API4), "low", "issue", "", "Page sizes without a maximum".into(),
            format!("{} accept a page size or count with no declared maximum, so one request can ask for every record.", plural(unbounded.len(), "endpoint")),
            unbounded, "Declare maximum for page sizes and counts, and enforce it on the server.");
    }

    // ── inventory
    let deprecated: Vec<String> = spec.endpoints.iter().filter(|e| e.deprecated).map(label).collect();
    if !deprecated.is_empty() {
        push(&mut out, rule("API9-DEPRECATED", API9), "low", "issue", "", "Deprecated operations are still published".into(),
            format!("{} are marked deprecated but still documented, and probably still served. Old versions tend to miss newer security controls.", plural(deprecated.len(), "operation")),
            deprecated, "Set a retirement date, monitor their use, and remove them from the gateway when it passes.");
    }
    let nonprod: Vec<String> = all_servers.iter().filter(|s| host_of(s).is_some_and(|h| non_production(&h))).cloned().collect();
    if !nonprod.is_empty() {
        push(&mut out, rule("API9-NON-PRODUCTION-SERVER", API9), "low", "issue", "", "Non-production servers in the API inventory".into(),
            format!("The definition names development, test, staging or internal servers: {}. These are often less protected and should not be reachable from outside.", nonprod.join(", ")),
            Vec::new(), "Publish separate definitions per environment, and check that non-production APIs are not exposed or use production data.");
    }
    let versions: BTreeSet<String> = all_servers
        .iter()
        .flat_map(|s| s.split('/').map(str::to_string).collect::<Vec<_>>())
        .chain(spec.endpoints.iter().flat_map(|e| e.path.split('/').map(str::to_string).collect::<Vec<_>>()))
        .filter(|seg| seg.len() >= 2 && seg.starts_with(['v', 'V']) && seg[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.') && seg.as_bytes()[1].is_ascii_digit())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if versions.len() > 1 {
        push(&mut out, rule("API9-SEVERAL-VERSIONS", API9), "info", "test", "", format!("Several API versions are exposed ({})", versions.iter().cloned().collect::<Vec<_>>().join(", ")),
            "Older versions often lack the authorization checks of newer ones. Call the same operation through every version and compare.".into(),
            Vec::new(), "Retire old versions, or apply the same controls to every version that is still served.");
    }

    // ── tests: what a definition cannot show
    let ids: Vec<String> = spec
        .endpoints
        .iter()
        .filter_map(|e| {
            let names: Vec<&str> = e.params.iter().filter(|p| p.location == "path" && object_id_name(&p.name)).map(|p| p.name.as_str()).collect();
            (!names.is_empty()).then(|| format!("{} ({})", label(e), names.join(", ")))
        })
        .collect();
    if !ids.is_empty() {
        push(&mut out, rule("API1-OBJECT-IDS", API1), "info", "test", "", "Test object-level authorization".into(),
            format!("{} take an object identifier in the path. Call each with another user's identifier and expect a refusal.", plural(ids.len(), "endpoint")),
            ids, "Check on the server, for every request, that the caller may access the object the identifier names.");
    }
    let privileged: Vec<String> = spec.endpoints.iter().filter(|e| privileged_path(&e.path)).map(label).collect();
    if !privileged.is_empty() {
        push(&mut out, rule("API5-PRIVILEGED-PATHS", API5), "info", "test", "", "Test function-level authorization".into(),
            format!("{} look administrative or internal. Call them with an ordinary user's credentials and without credentials.", plural(privileged.len(), "endpoint")),
            privileged, "Deny by default and grant administrative functions by role, checked on the server.");
    }
    let assign: Vec<String> = spec
        .endpoints
        .iter()
        .filter(|e| is_write(&e.method))
        .filter_map(|e| {
            let names: Vec<&str> = e.body_fields.iter().filter(|f| privileged_field(f)).map(String::as_str).collect();
            (!names.is_empty()).then(|| format!("{} ({})", label(e), names.join(", ")))
        })
        .collect();
    if !assign.is_empty() {
        push(&mut out, rule("API3-PRIVILEGED-FIELDS", API3), "info", "test", "", "Test mass assignment of privileged properties".into(),
            format!("{} accept properties such as roles, ownership or balances. Send them as an ordinary user and check that they are ignored.", plural(assign.len(), "endpoint")),
            assign, "Accept only the properties a caller may change (an allow-list per operation), never bind requests to internal objects directly.");
    }
    let urls: Vec<String> = spec
        .endpoints
        .iter()
        .filter_map(|e| {
            let mut names: Vec<&str> = e.params.iter().filter(|p| p.location != "header" && url_like(&p.name)).map(|p| p.name.as_str()).collect();
            names.extend(e.body_fields.iter().filter(|f| url_like(f)).map(String::as_str));
            (!names.is_empty()).then(|| format!("{} ({})", label(e), names.join(", ")))
        })
        .collect();
    if !urls.is_empty() {
        push(&mut out, rule("API7-URL-INPUTS", API7), "info", "test", "", "Test server-side request forgery".into(),
            format!("{} take a URL, host or callback. Point them at internal addresses and cloud metadata endpoints and watch for requests or errors.", plural(urls.len(), "endpoint")),
            urls, "Allow-list destinations, resolve and check addresses on the server, block internal ranges, and do not return fetched content verbatim.");
    }
    let flows: Vec<String> = spec.endpoints.iter().filter(|e| sensitive_flow(&e.path) && (capture || !e.responses.iter().any(|r| r == "429"))).map(label).collect();
    if !flows.is_empty() {
        push(&mut out, rule("API6-SENSITIVE-FLOWS", API6), "info", "test", "", "Test rate limits on sensitive flows".into(),
            format!("{} handle logins, tokens, passwords, payments or similar flows{}. Repeat them quickly and look for throttling or lockout.", plural(flows.len(), "endpoint"), if capture { "" } else { " and document no 429 response" }),
            flows, "Rate-limit and monitor these flows per account and per client, and document the limits (429 with Retry-After).");
    }
    out.sort_by(|a, b| (a.kind != "issue", severity_rank(&a.severity), a.title.as_str()).cmp(&(b.kind != "issue", severity_rank(&b.severity), b.title.as_str())));
    out
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/* ───────────────────────────── storage ───────────────────────────── */

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SpecSummary {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub format: String,
    pub title: String,
    pub version: String,
    pub endpoints: usize,
    pub sha256: String,
    pub evidence_id: Option<i64>,
    pub imported_at: String,
    /// issues per severity: critical, high, medium, low, info
    pub issues: [usize; 5],
    pub tests: usize,
}

fn summarize(id: i64, project_id: i64, name: String, sha256: String, evidence_id: Option<i64>, imported_at: String, spec: &ApiSpec) -> SpecSummary {
    let mut issues = [0usize; 5];
    let mut tests = 0;
    for i in audit(spec) {
        if i.kind == "issue" {
            issues[severity_rank(&i.severity).min(4)] += 1;
        } else {
            tests += 1;
        }
    }
    SpecSummary { id, project_id, name, format: spec.format.clone(), title: spec.title.clone(), version: spec.version.clone(), endpoints: spec.endpoints.len(), sha256, evidence_id, imported_at, issues, tests }
}

/// Stores a read definition for a project. The same file twice in a project is refused.
pub fn store(c: &Connection, project_id: i64, name: &str, sha256: &str, evidence_id: Option<i64>, spec: &ApiSpec) -> AppResult<i64> {
    let dup: Option<i64> = c.query_row("SELECT id FROM api_specs WHERE project_id = ?1 AND sha256 = ?2", params![project_id, sha256], |r| r.get(0)).optional()?;
    if dup.is_some() {
        return Err(validation("This file is already in the project's API inventory"));
    }
    let doc = serde_json::to_string(spec).map_err(|e| AppError::Internal(e.to_string()))?;
    c.execute(
        "INSERT INTO api_specs (project_id, name, format, title, version, endpoints, sha256, evidence_id, doc, imported_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![project_id, name, spec.format, spec.title, spec.version, spec.endpoints.len() as i64, sha256, evidence_id, doc, crate::util::now()],
    )?;
    Ok(c.last_insert_rowid())
}

type Row = (i64, i64, String, String, Option<i64>, String, String);

fn load(c: &Connection, sql: &str, p: impl rusqlite::Params) -> AppResult<Vec<(SpecSummary, ApiSpec)>> {
    let mut st = c.prepare(sql)?;
    let rows: Vec<Row> = st.query_map(p, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?.collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(id, project_id, name, sha256, evidence_id, imported_at, doc)| {
            let spec: ApiSpec = serde_json::from_str(&doc).map_err(|e| AppError::Internal(format!("stored API definition {id} cannot be read: {e}")))?;
            Ok((summarize(id, project_id, name, sha256, evidence_id, imported_at, &spec), spec))
        })
        .collect()
}

const COLS: &str = "id, project_id, name, sha256, evidence_id, imported_at, doc";

pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<SpecSummary>> {
    Ok(load(c, &format!("SELECT {COLS} FROM api_specs WHERE project_id = ?1 ORDER BY id DESC"), params![project_id])?.into_iter().map(|(s, _)| s).collect())
}

pub fn get(c: &Connection, id: i64) -> AppResult<(SpecSummary, ApiSpec)> {
    load(c, &format!("SELECT {COLS} FROM api_specs WHERE id = ?1"), params![id])?.into_iter().next().ok_or_else(|| AppError::NotFound(format!("API definition {id}")))
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    if c.execute("DELETE FROM api_specs WHERE id = ?1", params![id])? == 0 {
        return Err(AppError::NotFound(format!("API definition {id}")));
    }
    Ok(())
}

/// The finding an issue becomes. Its target is the first endpoint's URL on the first server.
pub fn finding_for(summary: &SpecSummary, spec: &ApiSpec, issue: &Issue) -> crate::commands::projects::FindingInput {
    let api = if spec.title.is_empty() { summary.name.clone() } else { spec.title.clone() };
    let target = issue
        .endpoints
        .first()
        .and_then(|ep| {
            let (method, rest) = ep.split_once(' ')?;
            let path = rest.split(" (").next().unwrap_or(rest);
            let e = spec.endpoints.iter().find(|e| e.method == method && e.path == path)?;
            let server = e.servers.iter().chain(spec.servers.iter()).find(|s| s.contains("://"))?;
            Some(format!("{server}{path}"))
        })
        .or_else(|| spec.servers.iter().find(|s| s.contains("://")).cloned())
        .unwrap_or_else(|| format!("{api} API"));
    let mut description = format!("{}\n\nAPI: {api}", issue.detail);
    if !spec.version.is_empty() {
        description.push_str(&format!(" (version {})", spec.version));
    }
    if !issue.endpoints.is_empty() {
        let shown: Vec<String> = issue.endpoints.iter().take(50).map(|e| format!("- {e}")).collect();
        description.push_str(&format!("\n\nAffected endpoints:\n{}", shown.join("\n")));
        if issue.endpoints.len() > 50 {
            description.push_str(&format!("\n- … and {} more", issue.endpoints.len() - 50));
        }
    }
    crate::commands::projects::FindingInput {
        id: None,
        project_id: summary.project_id,
        title: issue.title.chars().take(200).collect(),
        severity: issue.severity.clone(),
        status: "new".into(),
        category: format!("{} {}", issue.owasp, issue.category),
        confidence: Some(if spec.format == "har" || spec.format == "postman" { "medium" } else { "high" }.into()),
        description,
        affected_target: target,
        cve: String::new(),
        evidence: Vec::new(),
        reproduction: String::new(),
        technical_details: format!("Rule {} on {} ({}, SHA-256 {}).", issue.rule, summary.name, summary.format, summary.sha256),
        remediation: issue.recommendation.clone(),
        tags: vec!["api-security".into(), issue.owasp.clone()],
        assignee: String::new(),
        due_date: None,
        cvss_vector: String::new(),
    }
}

#[path = "apisec_compare.rs"]
pub mod compare;

#[cfg(test)]
#[path = "apisec_tests.rs"]
mod tests;
