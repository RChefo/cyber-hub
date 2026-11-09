use super::*;
use crate::workspace::apisec::parse;

/// Version 1: every operation needs the bearer token.
const V1: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Shop", "version": "1.0" },
  "servers": [{ "url": "https://api.shop.example/v1" }],
  "components": { "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer" } } },
  "security": [{ "bearer": [] }],
  "paths": {
    "/users/{id}": {
      "get": { "parameters": [{ "name": "id", "in": "path", "required": true }], "responses": { "200": { "description": "ok" } } },
      "patch": { "parameters": [{ "name": "id", "in": "path", "required": true }],
        "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "email": { "type": "string" } } } } } },
        "responses": { "200": { "description": "ok" } } }
    },
    "/orders": { "get": { "responses": { "200": { "description": "ok" } } } },
    "/legacy/export": { "get": { "responses": { "200": { "description": "ok" } } } }
  }
}"#;

/// Version 2: an orders endpoint lost its security, a field and a public endpoint were added,
/// legacy export was dropped, and a plain-HTTP server appeared.
const V2: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Shop", "version": "2.0" },
  "servers": [{ "url": "https://api.shop.example/v1" }, { "url": "http://staging.shop.example/v1" }],
  "components": { "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer" } } },
  "security": [{ "bearer": [] }],
  "paths": {
    "/users/{userId}": {
      "get": { "parameters": [{ "name": "userId", "in": "path", "required": true }], "responses": { "200": { "description": "ok" } } },
      "patch": { "parameters": [{ "name": "userId", "in": "path", "required": true }],
        "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "email": { "type": "string" }, "role": { "type": "string" } } } } } },
        "responses": { "200": { "description": "ok" } } }
    },
    "/orders": { "get": { "security": [], "responses": { "200": { "description": "ok" } } } },
    "/coupons/{code}": { "get": { "security": [], "parameters": [{ "name": "code", "in": "path", "required": true }], "responses": { "200": { "description": "ok" } } } },
    "/reports": { "post": { "responses": { "201": { "description": "created" } } } }
  }
}"#;

#[test]
fn endpoints_added_removed_and_changed() {
    let (old, new) = (parse(V1).unwrap(), parse(V2).unwrap());
    let c = compare(&old, &new, "shop-v1.json");
    assert_eq!(c.added, vec!["GET /coupons/{code}", "POST /reports"]);
    assert_eq!(c.removed, vec!["GET /legacy/export"]);
    assert_eq!(c.unchanged, 1, "GET /users/{{id}} and /users/{{userId}} are the same endpoint: {:?}", c.changed);
    let changed: Vec<&str> = c.changed.iter().map(|x| x.endpoint.as_str()).collect();
    assert_eq!(changed, vec!["GET /orders", "PATCH /users/{userId}"]);
    assert!(c.changed[0].details[0].starts_with("authentication removed (was bearer"), "{:?}", c.changed[0].details);
    assert!(c.changed[1].details.iter().any(|d| d == "request fields added: role"), "{:?}", c.changed[1].details);
    assert_eq!(c.servers_added, vec!["http://staging.shop.example/v1"]);
    assert!(c.servers_removed.is_empty());
}

#[test]
fn security_relevant_changes_become_issues() {
    let (old, new) = (parse(V1).unwrap(), parse(V2).unwrap());
    let c = compare(&old, &new, "shop-v1.json");
    let by = |id: &str| c.issues.iter().find(|i| i.rule == id).unwrap_or_else(|| panic!("{id} in {:?}", c.issues.iter().map(|i| &i.rule).collect::<Vec<_>>()));
    let lost = by("CMP-AUTH-REMOVED");
    assert_eq!((lost.severity.as_str(), lost.owasp.as_str(), lost.kind.as_str()), ("high", "API2:2023", "issue"));
    assert_eq!(lost.endpoints, vec!["GET /orders"]);
    assert!(lost.detail.starts_with("Compared with shop-v1.json (version 1.0)."), "{}", lost.detail);
    assert_eq!(by("CMP-NEW-ANONYMOUS").endpoints, vec!["GET /coupons/{code}"]);
    assert_eq!(by("CMP-NEW-HTTP-SERVER").severity, "medium");
    assert_eq!((by("CMP-REMOVED").severity.as_str(), by("CMP-REMOVED").owasp.as_str()), ("low", "API9:2023"));
    let fields = by("CMP-NEW-FIELDS");
    assert_eq!((fields.kind.as_str(), fields.endpoints.clone()), ("test", vec!["PATCH /users/{userId} (role)".to_string()]));
    assert_eq!(by("CMP-NEW-ENDPOINTS").kind, "test");

    // the same definition twice: nothing to report
    let same = compare(&old, &old, "shop-v1.json");
    assert!(same.added.is_empty() && same.removed.is_empty() && same.changed.is_empty() && same.issues.is_empty());
    assert_eq!(same.unchanged, 4);
}

#[test]
fn paths_normalize_parameter_names_and_trailing_slashes() {
    assert_eq!(normalize("/users/{id}/orders/{orderId}/"), "/users/{}/orders/{}");
    assert_eq!(normalize("/"), "/");
    assert_eq!(normalize(""), "/");
}
