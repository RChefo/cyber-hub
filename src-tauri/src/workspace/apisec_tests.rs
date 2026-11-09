use super::*;
use crate::db::Db;

const OPENAPI: &str = r#"
openapi: 3.0.3
info:
  title: Shop API
  version: "2.1"
servers:
  - url: https://api.shop.example/v1
  - url: http://staging.shop.example/{base}
    variables:
      base:
        default: v1
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
    basicAuth: {type: http, scheme: Basic}
    keyQuery: {type: apiKey, in: query, name: api_key}
    legacy:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: https://auth.shop.example/authorize
          scopes: {}
  parameters:
    Limit:
      name: limit
      in: query
      schema: {type: integer}
  schemas:
    User:
      type: object
      properties:
        name: {type: string}
        role: {type: string}
        avatar_url: {type: string}
security:
  - bearerAuth: []
paths:
  /users:
    get:
      summary: List users
      parameters:
        - $ref: '#/components/parameters/Limit'
      responses:
        '200': {description: ok}
    post:
      summary: Create user
      security: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/User'
      responses:
        '201': {description: created}
  /users/{userId}:
    parameters:
      - {name: userId, in: path, required: true, schema: {type: string}}
    get:
      responses: {'200': {description: ok}}
    delete:
      deprecated: true
      responses: {'204': {description: gone}}
  /login:
    post:
      parameters:
        - {name: password, in: query, schema: {type: string}}
      responses: {'200': {description: ok}}
  /admin/stats:
    get:
      security:
        - {}
        - bearerAuth: []
      responses: {'200': {description: ok}}
"#;

const SWAGGER: &str = r#"{"swagger":"2.0","info":{"title":"Legacy","version":"1"},"host":"legacy.example.com","basePath":"/api","schemes":["http","https"],
 "securityDefinitions":{"basic":{"type":"basic"},"oauth":{"type":"oauth2","flow":"password","tokenUrl":"https://legacy.example.com/token","scopes":{}}},
 "security":[{"basic":[]}],
 "consumes":["application/json"],
 "paths":{"/orders/{orderId}":{"put":{"parameters":[{"name":"orderId","in":"path","required":true,"type":"integer"},{"name":"body","in":"body","schema":{"type":"object","properties":{"owner":{"type":"string"},"total":{"type":"number"}}}}],"responses":{"200":{"description":"ok"}}}},
 "/v2/orders":{"get":{"parameters":[{"name":"limit","in":"query","type":"integer","maximum":100}],"responses":{"200":{"description":"ok"}}}}}}"#;

const POSTMAN: &str = r#"{"info":{"name":"Pets","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
 "variable":[{"key":"baseUrl","value":"https://pets.example.com"}],
 "auth":{"type":"bearer","bearer":[{"key":"token","value":"secret-token-value"}]},
 "item":[
  {"name":"Folder","item":[
    {"name":"Get pet","request":{"method":"GET","url":{"raw":"{{baseUrl}}/pets/:petId?fields=name","host":["{{baseUrl}}"],"path":["pets",":petId"],"query":[{"key":"fields","value":"name"}]}}},
    {"name":"Public search","request":{"auth":{"type":"noauth"},"method":"POST","url":"{{baseUrl}}/pets/search?token=abc123","body":{"mode":"raw","raw":"{\"callback_url\": \"{{cb}}\", \"query\": \"x\"}","options":{"raw":{"language":"json"}}}}}
  ]},
  {"name":"Key","request":{"auth":{"type":"apikey","apikey":[{"key":"in","value":"query"},{"key":"key","value":"api_key"},{"key":"value","value":"k-9a8b7c"}]},"method":"GET","url":"https://pets.example.com/stats"}}
 ]}"#;

const HAR: &str = r#"{"log":{"creator":{"name":"Firefox","version":"130"},"entries":[
 {"request":{"method":"GET","url":"https://app.example.com/api/users/12345/orders?limit=50","headers":[{"name":"Authorization","value":"Bearer eyJhbGciOi.secret-part"}]},"response":{"status":200,"content":{"mimeType":"application/json"}}},
 {"request":{"method":"GET","url":"https://app.example.com/api/users/987/orders","headers":[{"name":"Authorization","value":"Bearer eyJhbGciOi.secret-part"}]},"response":{"status":403,"content":{"mimeType":"application/json"}}},
 {"request":{"method":"POST","url":"http://app.example.com/api/feedback","headers":[{"name":"Content-Type","value":"application/json"}],"postData":{"mimeType":"application/json; charset=utf-8","text":"{\"message\":\"hi\",\"redirect\":\"https://x.example\"}"}},"response":{"status":201,"content":{"mimeType":"application/json"}}},
 {"request":{"method":"GET","url":"https://app.example.com/static/app.js","headers":[]},"response":{"status":200,"content":{"mimeType":"application/javascript"}}}
]}}"#;

fn rules(spec: &ApiSpec) -> Vec<(String, String, String)> {
    audit(spec).into_iter().map(|i| (i.rule, i.severity, i.kind)).collect()
}

fn has(spec: &ApiSpec, rule: &str, severity: &str) -> bool {
    audit(spec).iter().any(|i| i.rule == rule && i.severity == severity)
}

#[test]
fn openapi_3_definitions_become_an_inventory() {
    let spec = parse(OPENAPI).unwrap();
    assert_eq!((spec.format.as_str(), spec.title.as_str(), spec.version.as_str()), ("openapi-3.0", "Shop API", "2.1"));
    assert_eq!(spec.servers, vec!["https://api.shop.example/v1", "http://staging.shop.example/v1"], "server variables take their default");
    let labels: Vec<String> = spec.endpoints.iter().map(label).collect();
    assert_eq!(labels, vec!["GET /admin/stats", "POST /login", "GET /users", "POST /users", "GET /users/{userId}", "DELETE /users/{userId}"]);
    let get_users = &spec.endpoints[2];
    assert_eq!(get_users.params, vec![Param { name: "limit".into(), location: "query".into(), required: false, kind: "integer".into(), bounded: false }], "parameter $ref followed");
    assert_eq!((get_users.auth.clone(), get_users.anonymous), (vec![vec!["bearerAuth".to_string()]], false), "global security applies");
    let post_users = &spec.endpoints[3];
    assert!(post_users.anonymous && post_users.auth.is_empty(), "security: [] opts out");
    assert_eq!(post_users.body_fields, vec!["avatar_url", "name", "role"], "request body schema $ref followed");
    assert!(spec.endpoints[0].anonymous && spec.endpoints[0].auth == vec![vec!["bearerAuth".to_string()]], "an empty alternative allows anonymous calls");
    assert!(spec.endpoints[5].deprecated);
    assert_eq!(spec.endpoints[4].params[0].name, "userId", "path-level parameters apply to each operation");
    let basic = spec.schemes.iter().find(|s| s.name == "basicAuth").unwrap();
    assert_eq!(basic.detail, "basic", "scheme names are case-insensitive");
}

#[test]
fn openapi_checks_map_to_the_owasp_api_top_10() {
    let spec = parse(OPENAPI).unwrap();
    let issues = audit(&spec);
    let anon = issues.iter().find(|i| i.rule == "API2-ANONYMOUS-WRITE").unwrap();
    assert_eq!((anon.severity.as_str(), anon.owasp.as_str(), anon.endpoints.clone()), ("high", "API2:2023", vec!["POST /users".to_string()]));
    assert!(has(&spec, "API2-BASIC-AUTH", "medium"));
    assert!(has(&spec, "API2-KEY-IN-QUERY", "medium"));
    assert!(has(&spec, "API2-LEGACY-OAUTH-FLOW", "medium"));
    let cleartext = issues.iter().find(|i| i.rule == "API8-CLEARTEXT").unwrap();
    assert!(cleartext.severity == "high" && cleartext.detail.contains("http://staging.shop.example/v1"), "{cleartext:?}");
    assert_eq!(issues.iter().find(|i| i.rule == "API8-SECRET-IN-QUERY").unwrap().endpoints, vec!["POST /login (password)"]);
    assert_eq!(issues.iter().find(|i| i.rule == "API4-UNBOUNDED-PAGE").unwrap().endpoints, vec!["GET /users (limit)"]);
    assert_eq!(issues.iter().find(|i| i.rule == "API9-DEPRECATED").unwrap().endpoints, vec!["DELETE /users/{userId}"]);
    assert!(has(&spec, "API9-NON-PRODUCTION-SERVER", "low"));
    // tests: what only testing can show
    let tests: Vec<&Issue> = issues.iter().filter(|i| i.kind == "test").collect();
    let test_rules: Vec<&str> = tests.iter().map(|i| i.rule.as_str()).collect();
    for r in ["API1-OBJECT-IDS", "API5-PRIVILEGED-PATHS", "API3-PRIVILEGED-FIELDS", "API7-URL-INPUTS", "API6-SENSITIVE-FLOWS"] {
        assert!(test_rules.contains(&r), "{r} in {test_rules:?}");
    }
    assert_eq!(tests.iter().find(|i| i.rule == "API1-OBJECT-IDS").unwrap().endpoints, vec!["GET /users/{userId} (userId)", "DELETE /users/{userId} (userId)"]);
    assert_eq!(tests.iter().find(|i| i.rule == "API3-PRIVILEGED-FIELDS").unwrap().endpoints, vec!["POST /users (role)"]);
    assert_eq!(tests.iter().find(|i| i.rule == "API7-URL-INPUTS").unwrap().endpoints, vec!["POST /users (avatar_url)"]);
    assert!(!test_rules.contains(&"API9-SEVERAL-VERSIONS"), "one version only");
    // issues come first, most severe first
    let first_test = issues.iter().position(|i| i.kind == "test").unwrap();
    assert!(issues[..first_test].iter().all(|i| i.kind == "issue") && issues[first_test..].iter().all(|i| i.kind == "test"));
    assert!(issues[..first_test].windows(2).all(|w| severity_rank(&w[0].severity) <= severity_rank(&w[1].severity)));
    // ids are unique within a definition
    let ids: BTreeSet<&str> = issues.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids.len(), issues.len());
}

#[test]
fn swagger_2_definitions_are_read() {
    let spec = parse(SWAGGER).unwrap();
    assert_eq!(spec.format, "swagger-2.0");
    assert_eq!(spec.servers, vec!["http://legacy.example.com/api", "https://legacy.example.com/api"]);
    let put = spec.endpoints.iter().find(|e| e.method == "PUT").unwrap();
    assert_eq!((put.body_types.clone(), put.body_fields.clone()), (vec!["application/json".to_string()], vec!["owner".to_string(), "total".to_string()]));
    assert_eq!(put.auth, vec![vec!["basic".to_string()]]);
    let get = spec.endpoints.iter().find(|e| e.method == "GET").unwrap();
    assert!(get.params[0].bounded, "maximum on a Swagger 2.0 parameter");
    let r = rules(&spec);
    assert!(r.contains(&("API2-BASIC-AUTH".into(), "medium".into(), "issue".into())));
    assert!(r.contains(&("API2-LEGACY-OAUTH-FLOW".into(), "medium".into(), "issue".into())), "password flow: {r:?}");
    assert!(r.contains(&("API8-CLEARTEXT".into(), "high".into(), "issue".into())));
    assert!(!r.iter().any(|x| x.0 == "API4-UNBOUNDED-PAGE"), "the limit is bounded");
    assert!(r.iter().any(|x| x.0 == "API3-PRIVILEGED-FIELDS"), "owner in a write body");
}

#[test]
fn postman_collections_keep_names_and_drop_values() {
    let spec = parse(POSTMAN).unwrap();
    assert_eq!((spec.format.as_str(), spec.title.as_str()), ("postman", "Pets"));
    assert_eq!(spec.servers, vec!["https://pets.example.com"]);
    let labels: Vec<String> = spec.endpoints.iter().map(label).collect();
    assert_eq!(labels, vec!["POST /pets/search", "GET /pets/{petId}", "GET /stats"], "sorted by path");
    let pet = &spec.endpoints[1];
    assert_eq!(pet.auth, vec![vec!["bearer".to_string()]], "collection auth is inherited through the folder");
    assert!(pet.params.iter().any(|p| p.name == "petId" && p.location == "path") && pet.params.iter().any(|p| p.name == "fields"));
    let search = &spec.endpoints[0];
    assert!(search.anonymous && search.auth.is_empty(), "noauth");
    assert_eq!(search.body_fields, vec!["callback_url", "query"], "a JSON body with variables is read by pattern");
    assert_eq!(spec.endpoints[2].auth, vec![vec!["apikey (query)".to_string()]]);
    let doc = serde_json::to_string(&spec).unwrap();
    for secret in ["secret-token-value", "abc123", "k-9a8b7c"] {
        assert!(!doc.contains(secret), "{secret} must not be stored");
    }
    let r = rules(&spec);
    assert!(r.contains(&("API2-ANONYMOUS-WRITE".into(), "medium".into(), "issue".into())), "{r:?}");
    assert!(r.iter().any(|x| x.0 == "API2-KEY-IN-QUERY"));
    assert!(r.iter().any(|x| x.0 == "API8-SECRET-IN-QUERY"), "token in the query string");
    assert!(r.iter().any(|x| x.0 == "API7-URL-INPUTS"));
    assert!(!r.iter().any(|x| x.0 == "API2-NO-AUTH-DEFINED"), "collections are not definitions");
}

#[test]
fn har_captures_are_grouped_into_endpoints() {
    let spec = parse(HAR).unwrap();
    assert_eq!(spec.format, "har");
    assert_eq!(spec.servers, vec!["http://app.example.com", "https://app.example.com"]);
    let labels: Vec<String> = spec.endpoints.iter().map(label).collect();
    assert_eq!(labels, vec!["POST /api/feedback", "GET /api/users/{id}/orders"], "numeric segments become {{id}}; scripts are left out");
    let orders = &spec.endpoints[1];
    assert_eq!((orders.seen, orders.responses.clone()), (2, vec!["200".to_string(), "403".to_string()]));
    assert_eq!(orders.auth, vec![vec!["Authorization: bearer".to_string()]]);
    assert!(!orders.anonymous);
    let feedback = &spec.endpoints[0];
    assert!(feedback.anonymous);
    assert_eq!((feedback.body_types.clone(), feedback.body_fields.clone()), (vec!["application/json".to_string()], vec!["message".to_string(), "redirect".to_string()]));
    assert!(spec.warnings.iter().any(|w| w.contains("1 requests for images")), "{:?}", spec.warnings);
    assert!(!serde_json::to_string(&spec).unwrap().contains("secret-part"), "header values are never kept");
    let r = rules(&spec);
    assert!(r.contains(&("API2-ANONYMOUS-WRITE".into(), "medium".into(), "issue".into())));
    assert!(r.contains(&("API8-CLEARTEXT".into(), "high".into(), "issue".into())));
    assert!(r.iter().any(|x| x.0 == "API1-OBJECT-IDS") && r.iter().any(|x| x.0 == "API7-URL-INPUTS"));
}

#[test]
fn other_files_and_limits() {
    assert!(parse(r#"{"hello": "world"}"#).unwrap_err().contains("not an OpenAPI"));
    assert!(parse("openapi: '2.0'\npaths: {}\n").unwrap_err().contains("not supported"));
    assert!(parse("openapi: 3.0.0\npaths: [1, 2\n").unwrap_err().contains("YAML"));
    assert!(parse("{ not json").unwrap_err().contains("JSON"));
    let mut paths = serde_json::Map::new();
    for i in 0..(MAX_ENDPOINTS + 1) {
        paths.insert(format!("/r{i}"), serde_json::json!({"get": {"responses": {"200": {"description": "ok"}}}}));
    }
    let big = serde_json::json!({"openapi": "3.1.0", "info": {"title": "Big", "version": "1"}, "paths": paths}).to_string();
    let spec = parse(&big).unwrap();
    assert_eq!((spec.format.as_str(), spec.endpoints.len()), ("openapi-3.1", MAX_ENDPOINTS));
    assert!(spec.warnings[0].contains("Only the first"));
    // no authentication anywhere: one definition-level issue, not one per write operation
    let open = parse("openapi: 3.0.0\ninfo: {title: Open, version: '1'}\npaths:\n  /notes:\n    post: {responses: {'200': {description: ok}}}\n").unwrap();
    let r = rules(&open);
    assert!(r.iter().any(|x| x.0 == "API2-NO-AUTH-DEFINED") && !r.iter().any(|x| x.0 == "API2-ANONYMOUS-WRITE"), "{r:?}");
}

#[test]
fn definitions_are_stored_listed_and_become_findings() {
    let db = Db::open_in_memory().unwrap();
    db.with(|c| {
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Shop', 'active', '2026-11-09T00:00:00Z', '2026-11-09T00:00:00Z')", [])?;
        let pid = c.last_insert_rowid();
        let spec = parse(OPENAPI).unwrap();
        let id = store(c, pid, "shop.yaml", "ab12", None, &spec)?;
        assert!(store(c, pid, "copy.yaml", "ab12", None, &spec).is_err(), "the same file twice");
        let listed = list(c, pid)?;
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0].endpoints, listed[0].issues[1] >= 2, listed[0].tests), (6, true, 5));
        let (summary, back) = get(c, id)?;
        assert_eq!(back, spec);
        let issue = audit(&back).into_iter().find(|i| i.rule == "API2-ANONYMOUS-WRITE").unwrap();
        let input = finding_for(&summary, &back, &issue);
        assert_eq!(input.affected_target, "https://api.shop.example/v1/users");
        assert_eq!((input.severity.as_str(), input.status.as_str()), ("high", "new"));
        assert!(input.tags.contains(&"API2:2023".to_string()) && input.description.contains("Affected endpoints:\n- POST /users"));
        let fid = crate::commands::projects::finding_write(c, &input, "api", false)?;
        assert!(fid > 0);
        delete(c, id)?;
        assert!(list(c, pid)?.is_empty());
        assert!(delete(c, id).is_err());
        Ok(())
    })
    .unwrap();
}
