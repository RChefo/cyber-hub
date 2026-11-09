//! One entry point for scope decisions of new operations (assets, workflows, utilities, monitors).
//!
//! * **Active** operations contact the target. They need an active project whose authorized scope
//!   covers every target; exclusions always win (`scope.rs`). Blocked attempts are recorded in the
//!   project's scope history.
//! * **Passive** operations only ask public sources about a target. They never accept private,
//!   loopback, link-local or internal names (they would leak or be meaningless), and when a project
//!   is given they respect its explicit exclusions.
//!
//! Tool runs keep their own, stricter path (`targets.rs`: arguments and target files, snapshots);
//! both use the same scope engine and the same rules.

use std::net::IpAddr;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::commands::projects::scope_entries;
use crate::error::{AppError, AppResult};
use crate::scope::{self, ScopeEntry, Target};
use crate::ti::indicator::{is_internal_domain, is_non_public};
use crate::util::now;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Passive,
    Active,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub target: String,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub mode: Mode,
    pub verdicts: Vec<Verdict>,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        !self.verdicts.is_empty() && self.verdicts.iter().all(|v| v.allowed)
    }
    pub fn blocked(&self) -> Vec<&Verdict> {
        self.verdicts.iter().filter(|v| !v.allowed).collect()
    }
}

/// At most this many targets are judged per decision.
pub const MAX_TARGETS: usize = 500;
/// Refused active attempts kept per project in the scope history.
pub const MAX_BLOCKED_EVENTS: i64 = 2000;

fn public_problem(t: &Target) -> Option<String> {
    let label = scope::target_label(t);
    match t {
        // a URL is judged by its host
        Target::Url(w) => public_problem(&w.host),
        Target::Host(h) if is_internal_domain(h) => Some(format!("{label} is an internal or single-label name; it is not sent to public sources")),
        Target::Ip(ip) if is_non_public(ip) => Some(format!("{label} is a private, loopback, link-local or reserved address; it is not sent to public sources")),
        Target::Net(n) if is_non_public(&n.network()) => Some(format!("{label} is a private or reserved range; it is not sent to public sources")),
        Target::Range(a, b) if is_non_public(a) || is_non_public(b) => Some(format!("{label} contains private or reserved addresses")),
        _ => None,
    }
}

/// Judges targets without side effects. `project_id` is required for active operations.
pub fn decide(c: &Connection, project_id: Option<i64>, targets: &[String], mode: Mode) -> AppResult<Decision> {
    let mut verdicts = Vec::new();
    let project = match project_id {
        Some(id) => Some(
            c.query_row("SELECT status FROM projects WHERE id = ?1", params![id], |r| r.get::<_, String>(0))
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("project {id}")))?,
        ),
        None => None,
    };
    let entries = match project_id {
        Some(id) => scope_entries(c, id)?,
        None => Vec::new(),
    };
    for raw in targets.iter().take(MAX_TARGETS) {
        let parsed = scope::parse_target(raw.trim());
        // what is shown and recorded: a URL without credentials, query or fragment; anything else
        // redacted and cut
        let target = match &parsed {
            Some(t @ Target::Url(_)) => scope::target_label(t),
            _ => crate::redact::redact_text(raw.trim()).chars().take(255).collect(),
        };
        let v = |allowed: bool, reason: String| Verdict { target: target.clone(), allowed, reason };
        let Some(t) = parsed else {
            verdicts.push(v(false, "Not a recognizable host, IP address, network or URL".into()));
            continue;
        };
        match mode {
            Mode::Active => {
                let Some(status) = project.as_deref() else {
                    verdicts.push(v(false, "Operations that contact a target need a project with an authorized scope".into()));
                    continue;
                };
                if status != "active" {
                    verdicts.push(v(false, format!("The project is {status}; operations that contact a target need an active project")));
                    continue;
                }
                if !entries.iter().any(|e| e.in_scope) {
                    verdicts.push(v(false, "The project has no authorized scope entries".into()));
                    continue;
                }
                match scope::check_target(&entries, &t) {
                    Ok(()) => verdicts.push(v(true, "In the authorized scope".into())),
                    Err(reason) => verdicts.push(v(false, reason)),
                }
            }
            Mode::Passive => {
                if let Some(problem) = public_problem(&t) {
                    verdicts.push(v(false, problem));
                } else if let Some(reason) = scope::exclusion(&entries, &t, false) {
                    // an excluded URL path does not stop lookups about its host: they do not reach paths
                    verdicts.push(v(false, reason));
                } else {
                    verdicts.push(v(true, "Public lookup".into()));
                }
            }
        }
    }
    if verdicts.is_empty() {
        verdicts.push(Verdict { target: String::new(), allowed: false, reason: "No target was given".into() });
    }
    Ok(Decision { mode, verdicts })
}

/// Like [`decide`], but refuses with a clear error when any target is blocked, and records blocked
/// active attempts in the project's scope history (they are audit-relevant).
pub fn enforce(c: &Connection, project_id: Option<i64>, targets: &[String], mode: Mode, operation: &str) -> AppResult<Decision> {
    let d = decide(c, project_id, targets, mode)?;
    if d.allowed() {
        return Ok(d);
    }
    let blocked = d.blocked();
    if let (Mode::Active, Some(pid)) = (mode, project_id) {
        for b in blocked.iter().take(50) {
            record_blocked(c, pid, &b.target, &b.reason, operation)?;
        }
    }
    let list = blocked.iter().map(|b| if b.target.is_empty() { b.reason.clone() } else { format!("{}: {}", b.target, b.reason) }).collect::<Vec<_>>().join("; ");
    Err(AppError::Scope(format!("{operation} was not started. {list}")))
}

/// Operations on hosts (service and port scans): URLs are refused before the scope check, because a
/// URL entry would authorize the URL but never its host, and these tools contact the host.
pub fn refuse_urls(targets: &[String], operation: &str) -> AppResult<()> {
    if let Some(t) = targets.iter().find(|t| matches!(scope::parse_target(t), Some(Target::Url(_)))) {
        return Err(AppError::Scope(format!(
            "{operation} was not started. {} is a URL; a {} works on host names, addresses and networks. Give the host instead: it must be in the scope as a host, domain or address range, because a URL in the scope authorizes only requests to its paths.",
            t.chars().take(200).collect::<String>(),
            operation.to_lowercase()
        )));
    }
    Ok(())
}

/// A refusal identical to one recorded within this many minutes (same target, reason and
/// operation) is counted on that entry instead of adding a row.
pub const REPEAT_WINDOW_MINUTES: i64 = 10;

/// Records a refused active attempt in the project's scope history (bounded, see [`enforce`]).
/// Repeats of the same refusal are counted, so retried requests cannot flood the history.
pub fn record_blocked(c: &Connection, project_id: i64, target: &str, reason: &str, operation: &str) -> AppResult<()> {
    let value: String = target.chars().take(255).collect();
    let note: String = reason.chars().take(500).collect();
    let source: String = operation.chars().take(100).collect();
    let ts = now();
    let since = (chrono::Utc::now() - chrono::Duration::minutes(REPEAT_WINDOW_MINUTES)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let recent: Option<i64> = c
        .query_row(
            "SELECT id FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND value = ?2 AND note = ?3 AND source = ?4 AND at >= ?5 ORDER BY id DESC LIMIT 1",
            params![project_id, value, note, source, since],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = recent {
        c.execute("UPDATE scope_events SET repeats = repeats + 1, at = ?2 WHERE id = ?1", params![id, ts])?;
        return Ok(());
    }
    c.execute(
        "INSERT INTO scope_events (project_id, action, value, kind, in_scope, note, source, at) VALUES (?1, 'blocked', ?2, '', NULL, ?3, ?4, ?5)",
        params![project_id, value, note, source, ts],
    )?;
    // refused attempts are kept, but only the newest ones: the history cannot be flooded
    c.execute(
        "DELETE FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND id NOT IN
           (SELECT id FROM scope_events WHERE project_id = ?1 AND action = 'blocked' ORDER BY id DESC LIMIT ?2)",
        params![project_id, MAX_BLOCKED_EVENTS],
    )?;
    Ok(())
}

/// Checks the addresses an in-scope name resolves to. Public addresses are accepted (the scope is
/// name-based); a private, loopback, link-local or reserved address is accepted only when that
/// address is itself in the authorized scope. A name therefore cannot be pointed at internal
/// systems (DNS rebinding, SSRF-style redirection) unless the analyst authorized them.
pub fn vet_addresses(entries: &[ScopeEntry], host: &str, addrs: &[IpAddr]) -> Result<(), String> {
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve to any address"));
    }
    let refused: Vec<String> = addrs
        .iter()
        .map(|ip| ip.to_canonical())
        .filter(|ip| is_non_public(ip) && scope::check_target(entries, &Target::Ip(*ip)).is_err())
        .map(|ip| ip.to_string())
        .collect();
    if refused.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{host} resolves to {}: a private, loopback, link-local or reserved address that is not in the authorized scope. Add the address or its range to the scope if it is part of the engagement.",
            refused.join(", ")
        ))
    }
}

/// Resolves a host for an active operation and vets the result. The caller connects only to the
/// returned addresses, so the name cannot resolve differently between the check and the
/// connection. Address literals are returned as they are (the scope gate already checked them).
pub async fn resolve_vetted(entries: &[ScopeEntry], host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip.to_canonical(), port)]);
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(std::time::Duration::from_secs(8), tokio::net::lookup_host((bare, port)))
        .await
        .map_err(|_| format!("{host} could not be resolved in time"))?
        .map_err(|e| format!("{host} could not be resolved: {e}"))?
        .map(|a| std::net::SocketAddr::new(a.ip().to_canonical(), a.port()))
        .collect();
    vet_addresses(entries, host, &addrs.iter().map(|a| a.ip()).collect::<Vec<_>>())?;
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn setup(status: &str, targets: &[(&str, bool)]) -> (Db, i64) {
        let db = Db::open_in_memory().unwrap();
        let id = db
            .with(|c| {
                c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P', ?1, 't', 't')", params![status])?;
                let id = c.last_insert_rowid();
                for (v, in_scope) in targets {
                    let (value, kind) = scope::classify(v)?;
                    c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, created_at) VALUES (?1, ?2, ?3, ?4, 't')", params![id, value, kind, *in_scope as i64])?;
                }
                Ok(id)
            })
            .unwrap();
        (db, id)
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn active_operations_need_an_active_project_and_in_scope_targets() {
        let (db, p) = setup("active", &[("*.example.com", true), ("10.0.0.0/24", true), ("admin.example.com", false)]);
        db.with(|c| {
            let d = decide(c, Some(p), &s(&["www.example.com", "10.0.0.5", "https://api.example.com/x"]), Mode::Active)?;
            assert!(d.allowed(), "{d:?}");
            let d = decide(c, Some(p), &s(&["admin.example.com", "example.org", "10.0.1.1", "not a host!"]), Mode::Active)?;
            assert_eq!(d.verdicts.iter().filter(|v| v.allowed).count(), 0);
            assert!(d.verdicts[0].reason.contains("explicitly excluded"));
            assert!(decide(c, None, &s(&["www.example.com"]), Mode::Active)?.verdicts[0].reason.contains("need a project"));
            assert!(!decide(c, Some(p), &[], Mode::Active)?.allowed(), "no target is never allowed");
            Ok(())
        })
        .unwrap();
        for status in ["planning", "paused", "completed", "archived"] {
            let (db, p) = setup(status, &[("example.com", true)]);
            db.with(|c| {
                assert!(decide(c, Some(p), &s(&["example.com"]), Mode::Active)?.verdicts[0].reason.contains(status));
                Ok(())
            })
            .unwrap();
        }
        let (db, p) = setup("active", &[("example.com", false)]);
        db.with(|c| {
            assert!(decide(c, Some(p), &s(&["www.example.com"]), Mode::Active)?.verdicts[0].reason.contains("no authorized scope"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn scope_bypass_attempts_are_refused() {
        let (db, p) = setup("active", &[("example.com", true), ("192.0.2.0/24", true)]);
        db.with(|c| {
            for t in [
                "example.com.evil.net",
                "evil.net/example.com",
                "https://example.com@evil.net/",
                "http://2130706433/",
                "http://[::ffff:127.0.0.1]/",
                "192.0.2.0/23",
                "www.example.com",
                "localhost",
            ] {
                assert!(!decide(c, Some(p), &s(&[t]), Mode::Active)?.allowed(), "{t} must be refused");
            }
            assert!(decide(c, Some(p), &s(&["http://EXAMPLE.com./path", "192.0.2.17"]), Mode::Active)?.allowed());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn passive_lookups_refuse_private_and_internal_targets_and_respect_exclusions() {
        let (db, p) = setup("planning", &[("secret.example.com", false)]);
        db.with(|c| {
            for t in ["10.1.2.3", "127.0.0.1", "169.254.169.254", "fd00::1", "intranet", "printer.local", "corp.internal", "10.0.0.0/8"] {
                assert!(!decide(c, None, &s(&[t]), Mode::Passive)?.allowed(), "{t} must not go to public sources");
            }
            assert!(decide(c, None, &s(&["example.com", "93.184.215.14"]), Mode::Passive)?.allowed());
            assert!(!decide(c, Some(p), &s(&["secret.example.com"]), Mode::Passive)?.allowed(), "exclusions apply to passive lookups too");
            assert!(decide(c, Some(p), &s(&["www.example.com"]), Mode::Passive)?.allowed(), "passive lookups do not need the project to be active");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn names_resolving_to_internal_addresses_need_those_addresses_in_scope() {
        let entries = |v: &[(&str, bool)]| -> Vec<ScopeEntry> {
            v.iter()
                .map(|(x, s)| {
                    let (value, kind) = scope::classify(x).unwrap();
                    ScopeEntry { value, kind: kind.into(), in_scope: *s }
                })
                .collect()
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let web = entries(&[("*.example.com", true)]);
        assert!(vet_addresses(&web, "app.example.com", &[ip("93.184.215.14")]).is_ok(), "public addresses of in-scope names are fine");
        for internal in ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fd00::5", "::ffff:192.168.1.1", "100.64.0.1"] {
            let err = vet_addresses(&web, "app.example.com", &[ip("93.184.215.14"), ip(internal)]).unwrap_err();
            assert!(err.contains("not in the authorized scope"), "{internal}: {err}");
        }
        let internal = entries(&[("*.corp.example.com", true), ("10.20.0.0/16", true), ("10.20.9.9", false)]);
        assert!(vet_addresses(&internal, "intranet.corp.example.com", &[ip("10.20.1.5")]).is_ok(), "authorized internal ranges are allowed");
        assert!(vet_addresses(&internal, "intranet.corp.example.com", &[ip("10.20.9.9")]).is_err(), "excluded addresses stay refused");
        assert!(vet_addresses(&internal, "x.corp.example.com", &[]).is_err());
    }

    #[tokio::test]
    async fn resolution_is_vetted_and_literals_pass_through() {
        let none: Vec<ScopeEntry> = vec![];
        // localhost resolves to loopback, which is not authorized here
        assert!(resolve_vetted(&none, "localhost", 80).await.is_err());
        let lo = vec![ScopeEntry { value: "127.0.0.0/8".into(), kind: "cidr".into(), in_scope: true }, ScopeEntry { value: "::1".into(), kind: "ip".into(), in_scope: true }];
        assert!(resolve_vetted(&lo, "localhost", 80).await.is_ok());
        let lit = resolve_vetted(&none, "[2001:db8::1]", 443).await.unwrap();
        assert_eq!(lit[0].to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn path_level_scopes_authorize_urls_never_hosts() {
        let (db, p) = setup("active", &[("https://app.example.com/api/", true)]);
        db.with(|c| {
            assert!(decide(c, Some(p), &s(&["https://app.example.com/api/x?id=1"]), Mode::Active)?.allowed());
            let d = decide(c, Some(p), &s(&["app.example.com", "https://app.example.com/", "http://app.example.com/api/x"]), Mode::Active)?;
            assert!(d.verdicts.iter().all(|v| !v.allowed), "{d:?}");
            assert!(d.verdicts[0].reason.contains("specific URLs"), "{}", d.verdicts[0].reason);
            assert!(d.verdicts[1].reason.contains("outside the authorized URLs"), "{}", d.verdicts[1].reason);
            // host operations refuse URLs before the scope check, with a reason
            let err = refuse_urls(&s(&["10.0.0.5", "https://app.example.com/api/"]), "Service scan").unwrap_err().to_string();
            assert!(err.contains("works on host names") && err.contains("only requests to its paths"), "{err}");
            assert!(refuse_urls(&s(&["app.example.com", "10.0.0.0/24", "[2001:db8::1]:443"]), "Service scan").is_ok());
            Ok(())
        })
        .unwrap();
        // passive lookups judge a URL by its host
        let (db, p) = setup("planning", &[("*.example.com", true), ("https://app.example.com/admin", false)]);
        db.with(|c| {
            for t in ["http://10.0.0.1/", "https://intranet/x", "http://127.0.0.1:8080/", "https://[fd00::1]/"] {
                assert!(!decide(c, None, &s(&[t]), Mode::Passive)?.allowed(), "{t}");
            }
            assert!(decide(c, Some(p), &s(&["app.example.com"]), Mode::Passive)?.allowed(), "an excluded path does not stop lookups about its host");
            assert!(!decide(c, Some(p), &s(&["https://app.example.com/admin/x"]), Mode::Passive)?.allowed());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn blocked_active_attempts_are_audited() {
        let (db, p) = setup("active", &[("example.com", true)]);
        db.with(|c| {
            let err = enforce(c, Some(p), &s(&["example.org", "example.com"]), Mode::Active, "TLS analysis").unwrap_err();
            assert!(matches!(err, AppError::Scope(_)));
            assert!(err.to_string().contains("example.org"));
            let n: i64 = c.query_row("SELECT COUNT(*) FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND source = 'TLS analysis'", params![p], |r| r.get(0))?;
            assert_eq!(n, 1, "only the blocked target is recorded");
            assert!(enforce(c, Some(p), &s(&["example.com"]), Mode::Active, "TLS analysis").is_ok());
            let huge = "x".repeat(10_000) + ".example.org";
            let _ = enforce(c, Some(p), &[huge], Mode::Active, "TLS analysis");
            let stored: i64 = c.query_row("SELECT MAX(length(value)) FROM scope_events WHERE action = 'blocked'", [], |r| r.get(0))?;
            assert!(stored <= 255, "stored values are bounded");
            // the same refusal retried is counted on one entry, a different one gets its own
            let rows = |c: &Connection| -> AppResult<(i64, i64)> {
                Ok(c.query_row("SELECT COUNT(*), COALESCE(MAX(repeats), 0) FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND value = 'example.org'", params![p], |r| Ok((r.get(0)?, r.get(1)?)))?)
            };
            for _ in 0..25 {
                let _ = enforce(c, Some(p), &s(&["example.org"]), Mode::Active, "TLS analysis");
            }
            assert_eq!(rows(c)?, (1, 25), "one entry, 25 repeats");
            let _ = enforce(c, Some(p), &s(&["example.org"]), Mode::Active, "HTTP request");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND value = 'example.org'", params![p], |r| r.get::<_, i64>(0))?, 2, "another operation is another entry");
            // an old refusal is not reused
            c.execute("UPDATE scope_events SET at = '2020-01-01T00:00:00Z' WHERE project_id = ?1 AND value = 'example.org'", params![p])?;
            let _ = enforce(c, Some(p), &s(&["example.org"]), Mode::Active, "TLS analysis");
            assert_eq!(c.query_row("SELECT COUNT(*) FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND value = 'example.org'", params![p], |r| r.get::<_, i64>(0))?, 3);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn refusals_are_shown_and_recorded_without_credentials_or_queries() {
        let (db, p) = setup("active", &[("example.com", true)]);
        db.with(|c| {
            let err = enforce(c, Some(p), &s(&["https://user:hunter2@evil.example.net/x?token=abc#frag"]), Mode::Active, "HTTP request").unwrap_err().to_string();
            assert!(!err.contains("hunter2") && !err.contains("token=abc"), "{err}");
            let v: String = c.query_row("SELECT value FROM scope_events WHERE project_id = ?1 AND action = 'blocked'", params![p], |r| r.get(0))?;
            assert_eq!(v, "https://evil.example.net/x");
            // a value that is not a target is redacted before it is shown or recorded
            let err = enforce(c, Some(p), &s(&["password=hunter2 evil"]), Mode::Active, "HTTP request").unwrap_err().to_string();
            assert!(!err.contains("hunter2"), "{err}");
            let leaked: i64 = c.query_row("SELECT COUNT(*) FROM scope_events WHERE project_id = ?1 AND (value LIKE '%hunter2%' OR note LIKE '%hunter2%')", params![p], |r| r.get(0))?;
            assert_eq!(leaked, 0);
            Ok(())
        })
        .unwrap();
    }
}
