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
        Target::Host(h) if is_internal_domain(h) => Some(format!("{label} is an internal or single-label name; it is not sent to public sources")),
        Target::Ip(ip) if is_non_public(ip) => Some(format!("{label} is a private, loopback, link-local or reserved address; it is not sent to public sources")),
        Target::Net(n) if is_non_public(&n.network()) => Some(format!("{label} is a private or reserved range; it is not sent to public sources")),
        Target::Range(a, b) if is_non_public(a) || is_non_public(b) => Some(format!("{label} contains private or reserved addresses")),
        _ => None,
    }
}

fn excluded(entries: &[ScopeEntry], t: &Target) -> bool {
    let only_exclusions: Vec<ScopeEntry> = entries.iter().filter(|e| !e.in_scope).cloned().collect();
    // with no in-scope entries, check_target fails only for an explicit exclusion when the
    // exclusion matches; distinguish the two reasons by testing against exclusions alone
    !only_exclusions.is_empty() && scope::check_target(&only_exclusions, t).err().is_some_and(|r| r.contains("explicitly excluded"))
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
        let target = raw.trim().to_string();
        let v = |allowed: bool, reason: String| Verdict { target: target.clone(), allowed, reason };
        let Some(t) = scope::parse_target(&target) else {
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
                } else if excluded(&entries, &t) {
                    verdicts.push(v(false, format!("{} is explicitly excluded from the project scope", scope::target_label(&t))));
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
            c.execute(
                "INSERT INTO scope_events (project_id, action, value, kind, in_scope, note, source, at) VALUES (?1, 'blocked', ?2, '', NULL, ?3, ?4, ?5)",
                params![pid, b.target.chars().take(255).collect::<String>(), b.reason.chars().take(500).collect::<String>(), operation.chars().take(100).collect::<String>(), now()],
            )?;
        }
        // refused attempts are kept, but only the newest ones: the history cannot be flooded
        c.execute(
            "DELETE FROM scope_events WHERE project_id = ?1 AND action = 'blocked' AND id NOT IN
               (SELECT id FROM scope_events WHERE project_id = ?1 AND action = 'blocked' ORDER BY id DESC LIMIT ?2)",
            params![pid, MAX_BLOCKED_EVENTS],
        )?;
    }
    let list = blocked.iter().map(|b| if b.target.is_empty() { b.reason.clone() } else { format!("{}: {}", b.target, b.reason) }).collect::<Vec<_>>().join("; ");
    Err(AppError::Scope(format!("{operation} was not started. {list}")))
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
            Ok(())
        })
        .unwrap();
    }
}
