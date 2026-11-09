//! Remediation groups (docs/DATA_MODEL.md#remediation-groups): findings that one fix addresses,
//! across the modules that reported them. A group is explained by what its findings share: the
//! same CVE, the same package (package URL without its version), the same check reported on
//! several targets, or the same remediation text. Nothing is merged, closed or changed: groups are
//! computed from the findings as they are, and a fix counts as verified only when a rescan
//! resolved the finding (the import's explicit rule), never because another tool did not report it.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::AppResult;

const MAX_GROUPS: usize = 200;
const MAX_MEMBERS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub target: String,
    /// resolved by a rescan that no longer reported it
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// cve, package, check or fix
    pub kind: &'static str,
    pub key: String,
    pub label: String,
    /// why the findings are together
    pub reason: String,
    /// the remediation most of them give
    pub fix: String,
    pub severity: String,
    pub open: usize,
    pub resolved: usize,
    pub verified: usize,
    pub targets: usize,
    pub findings: Vec<Member>,
}

fn rank(severity: &str) -> usize {
    ["critical", "high", "medium", "low", "info"].iter().position(|s| *s == severity).unwrap_or(5)
}

/// `pkg:npm/lodash` of `pkg:npm/lodash@4.17.20?x=y`.
fn package(target: &str) -> Option<String> {
    let t = target.trim();
    if !t.to_ascii_lowercase().starts_with("pkg:") {
        return None;
    }
    let base = t.split(['?', '#']).next().unwrap_or(t);
    let base = match base.rfind('@') {
        Some(i) if i > 4 => &base[..i],
        _ => base,
    };
    Some(base.to_ascii_lowercase())
}

/// A title without a trailing target in parentheses (`… (drop.exe)`).
fn without_target(title: &str) -> &str {
    let t = title.trim();
    match (t.ends_with(')'), t.rfind(" (")) {
        (true, Some(i)) if i > 0 => &t[..i],
        _ => t,
    }
}

/// The check behind a title, for comparing.
fn check(title: &str) -> String {
    without_target(title).split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

fn fix_key(remediation: &str) -> Option<String> {
    let k = remediation.split_whitespace().collect::<Vec<_>>().join(" ").trim_end_matches('.').to_lowercase();
    (k.chars().count() >= 20).then_some(k)
}

/// The project's remediation groups, largest open work first. False positives are left out.
pub fn groups(c: &Connection, project_id: i64) -> AppResult<Vec<Group>> {
    let mut st = c.prepare(
        "SELECT f.id, f.title, f.severity, f.status, f.affected_target, f.cve, f.remediation,
                EXISTS (SELECT 1 FROM finding_events e WHERE e.finding_id = f.id AND e.kind = 'status' AND e.to_status = 'resolved' AND e.note LIKE 'Verified by rescan%')
         FROM findings f WHERE f.project_id = ?1 AND f.status <> 'false_positive' ORDER BY f.id",
    )?;
    let rows: Vec<(Member, String, String)> = st
        .query_map(params![project_id], |r| {
            Ok((
                Member { id: r.get(0)?, title: r.get(1)?, severity: r.get(2)?, status: r.get(3)?, target: r.get(4)?, verified: r.get::<_, bool>(7)? && r.get::<_, String>(3)? == "resolved" },
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    // (kind, key) → members (indexes into rows); BTreeMap keeps the output stable
    let mut by: BTreeMap<(&'static str, String), Vec<usize>> = BTreeMap::new();
    for (i, (m, cve, remediation)) in rows.iter().enumerate() {
        let cve = cve.trim().to_ascii_uppercase();
        if cve.starts_with("CVE-") {
            by.entry(("cve", cve)).or_default().push(i);
        }
        if let Some(p) = package(&m.target) {
            by.entry(("package", p)).or_default().push(i);
        }
        let k = check(&m.title);
        if !k.is_empty() {
            by.entry(("check", k)).or_default().push(i);
        }
        if let Some(k) = fix_key(remediation) {
            by.entry(("fix", k)).or_default().push(i);
        }
    }
    let mut out: Vec<Group> = Vec::new();
    let mut seen: BTreeSet<Vec<i64>> = BTreeSet::new();
    // the most specific explanation first, so a set of findings is listed once
    for kind in ["cve", "package", "check", "fix"] {
        for ((k, key), idx) in by.iter().filter(|((k, _), _)| *k == kind) {
            let members: Vec<&Member> = idx.iter().map(|i| &rows[*i].0).collect();
            let targets: BTreeSet<&str> = members.iter().map(|m| m.target.trim()).filter(|t| !t.is_empty()).collect();
            // a check is a group when it was reported on several targets
            if members.len() < 2 || (*k == "check" && targets.len() < 2) {
                continue;
            }
            let ids: Vec<i64> = members.iter().map(|m| m.id).collect();
            if !seen.insert(ids) {
                continue;
            }
            let mut fixes: BTreeMap<String, usize> = BTreeMap::new();
            for i in idx {
                let r = rows[*i].2.trim();
                if !r.is_empty() {
                    *fixes.entry(r.to_string()).or_default() += 1;
                }
            }
            let fix = fixes.iter().max_by_key(|(_, n)| **n).map(|(f, _)| f.clone()).unwrap_or_default();
            let open = members.iter().filter(|m| crate::workspace::findings::OPEN_SQL.contains(&format!("'{}'", m.status))).count();
            let resolved = members.iter().filter(|m| m.status == "resolved").count();
            let verified = members.iter().filter(|m| m.verified).count();
            let severity = members.iter().map(|m| m.severity.as_str()).min_by_key(|s| rank(s)).unwrap_or("info").to_string();
            let (label, reason) = match *k {
                "cve" => (key.clone(), format!("{} findings name {key}", members.len())),
                "package" => (key.clone(), format!("{} findings are about the package {key}", members.len())),
                "check" => (without_target(&members[0].title).to_string(), format!("The same check on {} targets", targets.len())),
                _ => (fix.chars().take(90).collect(), format!("{} findings give the same remediation", members.len())),
            };
            out.push(Group {
                kind: k,
                key: key.clone(),
                label,
                reason,
                fix,
                severity,
                open,
                resolved,
                verified,
                targets: targets.len(),
                findings: members.into_iter().take(MAX_MEMBERS).cloned().collect(),
            });
        }
    }
    out.sort_by(|a, b| (b.open > 0).cmp(&(a.open > 0)).then(rank(&a.severity).cmp(&rank(&b.severity))).then(b.open.cmp(&a.open)).then(b.findings.len().cmp(&a.findings.len())));
    out.truncate(MAX_GROUPS);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn findings_that_one_fix_addresses_are_grouped_and_explained() {
        assert_eq!(package("pkg:npm/lodash@4.17.20?x=1").as_deref(), Some("pkg:npm/lodash"));
        assert_eq!(package("pkg:npm/%40babel/core@7.0.0").as_deref(), Some("pkg:npm/%40babel/core"));
        assert_eq!(package("https://example.com"), None);
        assert_eq!(check("Can inject code into other processes (drop.exe)"), "can inject code into other processes");
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'P', 'active', 't', 't'), (2, 'Q', 'active', 't', 't')", [])?;
            let f = |p: i64, title: &str, sev: &str, status: &str, target: &str, cve: &str, fix: &str| -> i64 {
                c.execute(
                    "INSERT INTO findings (project_id, title, severity, status, affected_target, cve, remediation, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 't', 't')",
                    params![p, title, sev, status, target, cve, fix],
                )
                .unwrap();
                c.last_insert_rowid()
            };
            let a = f(1, "Apache path traversal", "critical", "new", "https://a.example.com/", "CVE-2021-41773", "Upgrade Apache httpd to 2.4.51 or later.");
            let b = f(1, "Path traversal (Nuclei)", "high", "resolved", "https://b.example.com/", "cve-2021-41773", "Upgrade Apache httpd to 2.4.51 or later");
            c.execute("INSERT INTO finding_events (finding_id, project_id, kind, from_status, to_status, note, source, at) VALUES (?1, 1, 'status', 'new', 'resolved', 'Verified by rescan: Nuclei results', 'import', 't')", params![b])?;
            f(1, "lodash prototype pollution", "high", "new", "pkg:npm/lodash@4.17.20", "CVE-2021-23337", "Upgrade lodash to 4.17.21.");
            f(1, "lodash command injection", "medium", "confirmed", "pkg:npm/lodash@4.17.15", "CVE-2020-8203", "Upgrade lodash to 4.17.21.");
            f(1, "Missing HSTS header (a.example.com)", "low", "new", "https://a.example.com/", "", "");
            f(1, "Missing HSTS header (b.example.com)", "low", "new", "https://b.example.com/", "", "");
            f(1, "Missing HSTS header (b.example.com)", "low", "false_positive", "https://c.example.com/", "", "");
            f(1, "Lonely", "info", "new", "x", "", "Nothing else gives this remediation text.");
            f(2, "Apache path traversal", "critical", "new", "https://z.example.com/", "CVE-2021-41773", "Upgrade Apache httpd to 2.4.51 or later.");

            let g = groups(c, 1)?;
            let by = |kind: &str| g.iter().filter(|x| x.kind == kind).collect::<Vec<_>>();
            let cve = by("cve");
            assert_eq!(cve.len(), 1, "CVE case is ignored; another project's finding is not in it");
            assert_eq!((cve[0].findings.iter().map(|m| m.id).collect::<Vec<_>>(), cve[0].open, cve[0].resolved, cve[0].verified), (vec![a, b], 1, 1, 1));
            assert_eq!((cve[0].severity.as_str(), cve[0].fix.as_str()), ("critical", "Upgrade Apache httpd to 2.4.51 or later."));
            let pkg = by("package");
            assert_eq!((pkg.len(), pkg[0].key.as_str(), pkg[0].findings.len()), (1, "pkg:npm/lodash", 2), "versions do not split a package");
            let checks = by("check");
            assert_eq!((checks.len(), checks[0].targets, checks[0].findings.len()), (1, 2, 2), "the same check on two targets; the false positive is left out");
            assert_eq!(checks[0].label, "Missing HSTS header", "the label names the check, not one target");
            assert!(by("fix").is_empty(), "the same findings already grouped by CVE or package are listed once");
            assert!(!g.iter().any(|x| x.findings.iter().any(|m| m.title == "Lonely")));
            assert_eq!(g[0].kind, "cve", "open critical work first");
            Ok(())
        })
        .unwrap();
    }
}
