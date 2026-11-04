//! GitHub public data through the REST API without authentication: repository search (name,
//! description, README) and public user profiles. Code search requires a token and is not used.

use serde_json::{json, Value};

use super::{ent, get_json, Builder, Error, Output};
use crate::db::Db;
use crate::osint::ingest::EvidenceInput;
use crate::osint::model::{EntityType, Strength};

const API: &str = "https://api.github.com";
const MAX_REPOS: usize = 30;

/// Search query text for an entity; quoting keeps dots and @ literal.
pub fn search_query(t: EntityType, value: &str) -> Option<String> {
    let v = value.replace('"', "");
    match t {
        EntityType::Domain | EntityType::Email | EntityType::Organization => Some(format!("\"{v}\" in:name,description,readme")),
        _ => None,
    }
}

fn reference_type(t: EntityType) -> &'static str {
    match t {
        EntityType::Domain => "REFERENCES_DOMAIN",
        EntityType::Email => "REFERENCES_EMAIL",
        EntityType::Ip => "REFERENCES_IP",
        _ => "MENTIONS",
    }
}

pub fn parse_search(t: EntityType, value: &str, url: &str, body: &Value) -> Result<Output, Error> {
    let items = body.get("items").and_then(Value::as_array).ok_or_else(|| Error::Invalid("GitHub returned an unexpected search document".into()))?;
    let total = body.get("total_count").and_then(Value::as_i64).unwrap_or(items.len() as i64);
    let mut b = Builder::default();
    let me = b.add(ent(t, value));
    let mut lines = vec![];
    for it in items.iter().take(MAX_REPOS) {
        let (Some(full), Some(html)) = (it.get("full_name").and_then(Value::as_str), it.get("html_url").and_then(Value::as_str)) else { continue };
        let mut repo = ent(EntityType::Repository, format!("github.com/{full}"));
        for (k, f) in [("description", "description"), ("url", "html_url"), ("language", "language"), ("updated", "pushed_at"), ("created", "created_at")] {
            if let Some(v) = it.get(f).and_then(Value::as_str) {
                repo.metadata.insert(k.into(), json!(v.chars().take(300).collect::<String>()));
            }
        }
        if let Some(s) = it.get("stargazers_count").and_then(Value::as_i64) {
            repo.metadata.insert("stars".into(), json!(s));
        }
        let r = b.add(repo);
        // the search engine matched the value in the repository's name, description or README
        b.rel(r, me, reference_type(t), Strength::Corroborating);
        if let Some(owner) = it.get("owner").and_then(|o| o.get("login")).and_then(Value::as_str) {
            let kind = it.get("owner").and_then(|o| o.get("type")).and_then(Value::as_str).unwrap_or("User");
            let mut u = ent(EntityType::Username, format!("github:{owner}"));
            u.metadata.insert("accountType".into(), json!(kind));
            let ui = b.add(u);
            b.rel(r, ui, "MAINTAINED_BY", Strength::Direct);
        }
        lines.push(format!("{full} — {html}"));
    }
    let n = lines.len();
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "github".into(),
        reference: Some(url.into()),
        observed_at: None,
        summary: format!("GitHub repository search for {value}: {total} result{} (showing {n}). A match means the text appears in the repository name, description or README.\n{}", if total == 1 { "" } else { "s" }, lines.join("\n")),
        data: json!({ "total": total }),
        strength: Strength::Corroborating,
        operation_id: None,
        execution_id: None,
    });
    Ok(Output { observations: if n > 0 { vec![obs] } else { vec![] }, summary: format!("{n} public repositor{} mention {value} ({total} in total)", if n == 1 { "y" } else { "ies" }), rate_note: None, from_cache: false })
}

pub fn parse_user(handle: &str, user: &Value, repos: &Value) -> Result<Output, Error> {
    let login = user.get("login").and_then(Value::as_str).ok_or_else(|| Error::Invalid("GitHub returned an unexpected user document".into()))?;
    let html = user.get("html_url").and_then(Value::as_str).unwrap_or("");
    let mut b = Builder::default();
    let mut u = ent(EntityType::Username, format!("github:{login}"));
    for (k, f) in [("name", "name"), ("bio", "bio"), ("created", "created_at"), ("accountType", "type")] {
        if let Some(v) = user.get(f).and_then(Value::as_str) {
            u.metadata.insert(k.into(), json!(v.chars().take(300).collect::<String>()));
        }
    }
    let me = b.add(u);
    let mut facts = vec![];
    if !html.is_empty() {
        let p = b.add(ent(EntityType::Profile, html));
        b.rel(me, p, "HAS_PROFILE", Strength::Direct);
    }
    if let Some(c) = user.get("company").and_then(Value::as_str).map(|s| s.trim().trim_start_matches('@')).filter(|s| !s.is_empty()) {
        let o = b.add(ent(EntityType::Organization, c));
        b.rel(me, o, "ASSOCIATED_WITH", Strength::Corroborating);
        facts.push(format!("company (self-declared): {c}"));
    }
    if let Some(blog) = user.get("blog").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let url = if blog.contains("://") { blog.to_string() } else { format!("https://{blog}") };
        if crate::osint::normalize::normalize(EntityType::Url, &url).is_ok() {
            let w = b.add(ent(EntityType::Url, url));
            b.rel(me, w, "LINKS_TO", Strength::Corroborating);
            facts.push(format!("website: {blog}"));
        }
    }
    if let Some(e) = user.get("email").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let em = b.add(ent(EntityType::Email, e));
        b.rel(em, me, "USES_USERNAME", Strength::Corroborating);
        facts.push(format!("public email: {e}"));
    }
    if let Some(l) = user.get("location").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        let loc = b.add(ent(EntityType::Location, l));
        b.rel(me, loc, "LOCATED_IN", Strength::Weak);
        facts.push(format!("location (self-declared): {l}"));
    }
    let mut repo_names = vec![];
    for r in repos.as_array().into_iter().flatten().take(MAX_REPOS) {
        if let Some(full) = r.get("full_name").and_then(Value::as_str) {
            let ri = b.add(ent(EntityType::Repository, format!("github.com/{full}")));
            b.rel(ri, me, "MAINTAINED_BY", Strength::Direct);
            repo_names.push(full.to_string());
        }
    }
    let obs = b.finish(EvidenceInput {
        kind: "provider_response".into(),
        source: "github".into(),
        reference: Some(if html.is_empty() { format!("https://github.com/{handle}") } else { html.to_string() }),
        observed_at: None,
        summary: format!("GitHub public profile of {login}. Profile fields are self-declared.\n{}\nrepositories: {}", facts.join("\n"), repo_names.join(", ")),
        data: json!({ "publicRepos": user.get("public_repos"), "followers": user.get("followers") }),
        strength: Strength::Direct,
        operation_id: None,
        execution_id: None,
    });
    Ok(Output { observations: vec![obs], summary: format!("GitHub profile {login} with {} public repositor{}", repo_names.len(), if repo_names.len() == 1 { "y" } else { "ies" }), rate_note: None, from_cache: false })
}

fn status_error(status: u16) -> Error {
    match status {
        403 | 429 => Error::RateLimited(60),
        404 => Error::Invalid("Not found on GitHub".into()),
        422 => Error::Invalid("GitHub refused the search query".into()),
        s => Error::Network(format!("GitHub returned HTTP {s}")),
    }
}

pub async fn run(db: &Db, t: EntityType, value: &str, refresh: bool) -> Result<Output, Error> {
    let client = super::client(20)?;
    if t == EntityType::Username {
        let (platform, handle) = value.split_once(':').unwrap_or(("unknown", value));
        if platform != "github" {
            return Err(Error::Unsupported("Only GitHub usernames (github:<name>) can be looked up here".into()));
        }
        if handle.is_empty() || !handle.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::Invalid("Invalid GitHub username".into()));
        }
        let key = format!("user:{}", handle.to_ascii_lowercase());
        let cached = if refresh { None } else { super::cache_get(db, "github", &key, 6) };
        let (user, repos, rate, from_cache) = match cached {
            Some(v) => (v["user"].clone(), v["repos"].clone(), None, true),
            None => {
                let (s1, user, rate) = get_json(&client, &format!("{API}/users/{handle}"), "application/vnd.github+json").await?;
                if s1 != 200 {
                    return if s1 == 404 { Ok(Output { summary: format!("No GitHub user {handle}"), ..Default::default() }) } else { Err(status_error(s1)) };
                }
                let (s2, repos, _) = get_json(&client, &format!("{API}/users/{handle}/repos?per_page=30&sort=pushed"), "application/vnd.github+json").await?;
                let repos = if s2 == 200 { repos } else { json!([]) };
                super::cache_put(db, "github", &key, &json!({ "user": user, "repos": repos }));
                (user, repos, rate, false)
            }
        };
        let mut out = parse_user(handle, &user, &repos)?;
        out.rate_note = rate;
        out.from_cache = from_cache;
        return Ok(out);
    }
    let q = search_query(t, value).ok_or_else(|| Error::Unsupported("GitHub search supports domains, emails, organizations and GitHub usernames".into()))?;
    let url = format!("{API}/search/repositories?q={}&per_page={MAX_REPOS}", url::form_urlencoded::byte_serialize(q.as_bytes()).collect::<String>());
    let (body, rate, from_cache) = match if refresh { None } else { super::cache_get(db, "github", &url, 6) } {
        Some(v) => (v, None, true),
        None => {
            let (status, body, rate) = get_json(&client, &url, "application/vnd.github+json").await?;
            if status != 200 {
                return Err(status_error(status));
            }
            super::cache_put(db, "github", &url, &body);
            (body, rate, false)
        }
    };
    // the evidence points at the API request that was actually made
    let mut out = parse_search(t, value, &url, &body)?;
    out.rate_note = rate;
    out.from_cache = from_cache;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_repository_search_and_profiles() {
        let body = json!({ "total_count": 2, "items": [
            { "full_name": "acme/site", "html_url": "https://github.com/acme/site", "description": "Website for example.com", "owner": { "login": "acme", "type": "Organization" }, "stargazers_count": 3 },
            { "full_name": "bob/notes", "html_url": "https://github.com/bob/notes", "owner": { "login": "bob", "type": "User" } }
        ]});
        let out = parse_search(EntityType::Domain, "example.com", "u", &body).unwrap();
        let o = &out.observations[0];
        assert_eq!(o.entities.iter().filter(|e| e.entity_type == EntityType::Repository).count(), 2);
        assert_eq!(o.relationships.iter().filter(|r| r.rel_type == "REFERENCES_DOMAIN").count(), 2);
        assert!(o.relationships.iter().filter(|r| r.rel_type == "REFERENCES_DOMAIN").all(|r| r.strength == Strength::Corroborating));
        assert!(o.evidence.summary.contains("name, description or README"));
        assert!(parse_search(EntityType::Domain, "x", "u", &json!({})).is_err());
        assert!(parse_search(EntityType::Domain, "x", "u", &json!({ "total_count": 0, "items": [] })).unwrap().observations.is_empty());

        let user = json!({ "login": "octocat", "html_url": "https://github.com/octocat", "company": "@github", "blog": "github.blog", "location": "San Francisco", "email": null, "type": "User" });
        let repos = json!([{ "full_name": "octocat/Hello-World" }]);
        let out = parse_user("octocat", &user, &repos).unwrap();
        let rels: Vec<&str> = out.observations[0].relationships.iter().map(|r| r.rel_type.as_str()).collect();
        assert_eq!(rels, vec!["HAS_PROFILE", "ASSOCIATED_WITH", "LINKS_TO", "LOCATED_IN", "MAINTAINED_BY"]);
        assert!(out.observations[0].evidence.summary.contains("self-declared"));
        assert_eq!(search_query(EntityType::Domain, "ex\"ample.com").unwrap(), "\"example.com\" in:name,description,readme");
    }
}
