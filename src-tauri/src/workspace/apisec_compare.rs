// SPDX-License-Identifier: Apache-2.0
//! Two definitions of the same API compared (docs/DATA_MODEL.md, "API security"): endpoints
//! added, removed and changed, and the changes that matter for security as issues mapped to the
//! OWASP API Security Top 10 (2023). Endpoints match by method and path; the names of path
//! parameters do not matter (`/users/{id}` and `/users/{userId}` are the same endpoint).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{push, rule, ApiSpec, Endpoint, Issue, API2, API3, API8, API9};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// "POST /users" in the newer definition
    pub endpoint: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<Change>,
    pub unchanged: usize,
    pub servers_added: Vec<String>,
    pub servers_removed: Vec<String>,
    pub issues: Vec<Issue>,
}

fn normalize(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    let p = if trimmed.is_empty() { "/" } else { trimmed };
    p.split('/').map(|s| if s.starts_with('{') && s.ends_with('}') { "{}" } else { s }).collect::<Vec<_>>().join("/")
}

fn key(e: &Endpoint) -> String {
    format!("{} {}", e.method.to_ascii_uppercase(), normalize(&e.path))
}

fn label(e: &Endpoint) -> String {
    format!("{} {}", e.method.to_ascii_uppercase(), e.path)
}

fn auth_text(e: &Endpoint) -> String {
    if e.anonymous || e.auth.is_empty() {
        "none".into()
    } else {
        e.auth.iter().map(|a| a.join(" + ")).collect::<Vec<_>>().join(" or ")
    }
}

fn servers(spec: &ApiSpec) -> BTreeSet<String> {
    spec.servers.iter().chain(spec.endpoints.iter().flat_map(|e| e.servers.iter())).cloned().collect()
}

fn diff<'a>(old: &'a [String], new: &'a [String]) -> (Vec<&'a String>, Vec<&'a String>) {
    (new.iter().filter(|x| !old.contains(x)).collect(), old.iter().filter(|x| !new.contains(x)).collect())
}

/// What changed for one endpoint present in both; empty when nothing did.
fn changes(o: &Endpoint, n: &Endpoint) -> Vec<String> {
    let mut out = Vec::new();
    match (o.anonymous, n.anonymous) {
        (false, true) => out.push(format!("authentication removed (was {})", auth_text(o))),
        (true, false) => out.push(format!("authentication added ({})", auth_text(n))),
        _ if auth_text(o) != auth_text(n) => out.push(format!("authentication changed: {} → {}", auth_text(o), auth_text(n))),
        _ => {}
    }
    // path parameters are part of the endpoint's key, compared by position, not by name
    let pname = |e: &Endpoint| e.params.iter().filter(|p| p.location != "path").map(|p| format!("{} ({}){}", p.name, p.location, if p.required { ", required" } else { "" })).collect::<Vec<_>>();
    let (pa, pr) = (pname(o), pname(n));
    let (added, removed) = diff(&pa, &pr);
    if !added.is_empty() {
        out.push(format!("parameters added: {}", added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !removed.is_empty() {
        out.push(format!("parameters removed: {}", removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    let (fa, fr) = diff(&o.body_fields, &n.body_fields);
    if !fa.is_empty() {
        out.push(format!("request fields added: {}", fa.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !fr.is_empty() {
        out.push(format!("request fields removed: {}", fr.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !o.deprecated && n.deprecated {
        out.push("now deprecated".into());
    }
    let (ra, rr) = diff(&o.responses, &n.responses);
    if !ra.is_empty() || !rr.is_empty() {
        out.push(format!("responses: {}{}", if ra.is_empty() { String::new() } else { format!("+{}", ra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", +")) }, if rr.is_empty() { String::new() } else { format!(" -{}", rr.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", -")) }));
    }
    out
}

/// `old` and `new` are two imports of the same API; `old_name` names the older one in issues.
pub fn compare(old: &ApiSpec, new: &ApiSpec, old_name: &str) -> Comparison {
    let olds: BTreeMap<String, &Endpoint> = old.endpoints.iter().map(|e| (key(e), e)).collect();
    let news: BTreeMap<String, &Endpoint> = new.endpoints.iter().map(|e| (key(e), e)).collect();
    let mut c = Comparison::default();
    let mut lost_auth = Vec::new();
    let mut new_fields = Vec::new();
    for (k, n) in &news {
        match olds.get(k) {
            None => c.added.push(label(n)),
            Some(o) => {
                let details = changes(o, n);
                if details.is_empty() {
                    c.unchanged += 1;
                    continue;
                }
                if !o.anonymous && n.anonymous {
                    lost_auth.push(label(n));
                }
                if matches!(n.method.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH") && n.body_fields.iter().any(|f| !o.body_fields.contains(f)) {
                    let added: Vec<&String> = n.body_fields.iter().filter(|f| !o.body_fields.contains(f)).collect();
                    new_fields.push(format!("{} ({})", label(n), added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
                }
                c.changed.push(Change { endpoint: label(n), details });
            }
        }
    }
    c.removed = olds.iter().filter(|(k, _)| !news.contains_key(*k)).map(|(_, e)| label(e)).collect();
    let (so, sn) = (servers(old), servers(new));
    c.servers_added = sn.difference(&so).cloned().collect();
    c.servers_removed = so.difference(&sn).cloned().collect();

    let against = format!("Compared with {old_name}{}.", if old.version.is_empty() { String::new() } else { format!(" (version {})", old.version) });
    let out = &mut c.issues;
    if !lost_auth.is_empty() {
        push(out, rule("CMP-AUTH-REMOVED", API2), "high", "issue", "", format!("Endpoints lost their authentication ({})", lost_auth.len()),
            format!("{against} These endpoints required authentication before and accept anonymous requests in the newer definition."),
            lost_auth.clone(), "Confirm the change was intended; if not, restore the security requirement, and test the endpoints without credentials.");
    }
    let protected_api = new.auth_applied || new.endpoints.iter().any(|e| !e.anonymous);
    let anonymous_new: Vec<String> = news.iter().filter(|(k, n)| !olds.contains_key(*k) && n.anonymous).map(|(_, n)| label(n)).collect();
    if protected_api && !anonymous_new.is_empty() {
        push(out, rule("CMP-NEW-ANONYMOUS", API2), "medium", "issue", "", format!("New endpoints without authentication ({})", anonymous_new.len()),
            format!("{against} The API requires authentication elsewhere, but these new endpoints do not."),
            anonymous_new, "Check that each is meant to be public, and test them without credentials.");
    }
    let plain: Vec<String> = c.servers_added.iter().filter(|s| s.starts_with("http://")).cloned().collect();
    if !plain.is_empty() {
        push(out, rule("CMP-NEW-HTTP-SERVER", API8), "medium", "issue", "", "New server over plain HTTP".into(),
            format!("{against} The newer definition adds {}, which carries credentials and data unencrypted.", plain.join(", ")),
            plain.clone(), "Serve the API over HTTPS only, and redirect or refuse HTTP.");
    }
    if !c.removed.is_empty() {
        push(out, rule("CMP-REMOVED", API9), "low", "issue", "", format!("Endpoints removed from the definition ({})", c.removed.len()),
            format!("{against} Endpoints dropped from a definition often stay reachable in the deployment, unmaintained and outside later tests."),
            c.removed.clone(), "Check that these endpoints are gone from every server and gateway, not only from the definition.");
    }
    if !new_fields.is_empty() {
        push(out, rule("CMP-NEW-FIELDS", API3), "info", "test", "", format!("New request fields to test for mass assignment ({})", new_fields.len()),
            format!("{against} Write operations accept new fields; test that a client cannot set properties it should not (for example roles, prices or owners)."),
            new_fields, "Send each new field as a low-privileged user and check whether it is accepted.");
    }
    if !c.added.is_empty() {
        push(out, rule("CMP-NEW-ENDPOINTS", API9), "info", "test", "", format!("New endpoints to test ({})", c.added.len()),
            format!("{against} These endpoints did not exist in the older definition; they have had no security testing yet."),
            c.added.clone(), "Add them to the test plan: authentication, object and function level authorization, input validation.");
    }
    c
}

#[cfg(test)]
#[path = "apisec_compare_tests.rs"]
mod tests;
