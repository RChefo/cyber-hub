// SPDX-License-Identifier: Apache-2.0
//! Two SBOMs or lockfiles of the same software compared (docs/DATA_MODEL.md#sbom-comparison):
//! components added, removed, upgraded and downgraded, the vulnerabilities that came or went, and
//! the changes that matter for the supply chain.
//!
//! Components match by ecosystem, group and name; a package can appear in several versions (npm
//! lockfiles). Vulnerabilities are compared only when both sides have the same kind of data (both
//! checked on OSV.dev, or neither), so a missing lookup never shows as a fix.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{registry_of, severity_rank, Component, Issue, Sbom, SbomSummary, Vuln};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// "npm lodash"
    pub component: String,
    pub from: String,
    pub to: String,
    /// upgraded, downgraded or changed (versions that do not compare)
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnDelta {
    pub id: String,
    pub severity: String,
    /// "name@version"
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<Change>,
    pub unchanged: usize,
    /// both sides have the same kind of vulnerability data, so the lists below mean something
    pub vulns_compared: bool,
    pub vulns_new: Vec<VulnDelta>,
    pub vulns_fixed: Vec<VulnDelta>,
    pub issues: Vec<Issue>,
}

fn key(c: &Component) -> String {
    format!("{}|{}|{}", c.ecosystem, c.group, c.name).to_lowercase()
}

fn display(c: &Component) -> String {
    let name = if c.group.is_empty() { c.name.clone() } else { format!("{}/{}", c.group, c.name) };
    if c.ecosystem.is_empty() {
        name
    } else {
        format!("{} {name}", c.ecosystem)
    }
}

/// Orders two versions: numbers numerically, `1.0.0-rc1` before `1.0.0`. None when they do not
/// compare (commit hashes, dates against numbers).
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering::*;
    let parts = |v: &str| -> Vec<String> { v.trim().trim_start_matches(['v', 'V']).split(['.', '-', '+', '_']).filter(|p| !p.is_empty()).map(str::to_string).collect() };
    let (pa, pb) = (parts(a), parts(b));
    if pa.is_empty() || pb.is_empty() || !pa[0].chars().all(|c| c.is_ascii_digit()) || !pb[0].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    for i in 0..pa.len().max(pb.len()) {
        match (pa.get(i), pb.get(i)) {
            (Some(x), Some(y)) => {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(n), Ok(m)) => n.cmp(&m),
                    // a pre-release word against a number: the number is the later version
                    (Ok(_), Err(_)) => Greater,
                    (Err(_), Ok(_)) => Less,
                    (Err(_), Err(_)) => x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()),
                };
                if o != Equal {
                    return Some(o);
                }
            }
            // 1.0.0-rc1 is before 1.0.0, 1.0.0.1 after it
            (Some(x), None) => return Some(if x.parse::<u64>().is_ok() { Greater } else { Less }),
            (None, Some(y)) => return Some(if y.parse::<u64>().is_ok() { Less } else { Greater }),
            (None, None) => break,
        }
    }
    Some(Equal)
}

/// (vulnerability id, component name) → severity and affected labels.
fn vuln_map(sbom: &Sbom, vulns: &[Vuln]) -> BTreeMap<(String, String), (String, BTreeSet<String>)> {
    let mut out: BTreeMap<(String, String), (String, BTreeSet<String>)> = BTreeMap::new();
    for v in vulns {
        for &i in &v.components {
            let Some(c) = sbom.components.get(i) else { continue };
            let e = out.entry((v.id.clone(), key(c))).or_insert_with(|| (v.severity.clone(), BTreeSet::new()));
            e.1.insert(c.label());
        }
    }
    out
}

fn deltas(from: &BTreeMap<(String, String), (String, BTreeSet<String>)>, without: &BTreeMap<(String, String), (String, BTreeSet<String>)>) -> Vec<VulnDelta> {
    let mut by_id: BTreeMap<String, VulnDelta> = BTreeMap::new();
    for ((id, k), (sev, labels)) in from {
        if without.contains_key(&(id.clone(), k.clone())) {
            continue;
        }
        let d = by_id.entry(id.clone()).or_insert_with(|| VulnDelta { id: id.clone(), severity: sev.clone(), components: Vec::new() });
        d.components.extend(labels.iter().cloned());
    }
    let mut out: Vec<VulnDelta> = by_id.into_values().collect();
    out.sort_by_key(|d| (severity_rank(&d.severity), d.id.clone()));
    out
}

/// The part of a package key after the ecosystem: group and name.
fn name_part(key: &str) -> &str {
    key.split_once('|').map_or(key, |(_, rest)| rest)
}

/// Where a package comes from: its registry, or for Git and URL dependencies the host (or the
/// scheme, for `file:` and the like) of the address the lockfile resolves.
fn source_of(format: &str, c: &Component) -> Option<String> {
    registry_of(format, c).or_else(|| {
        let r = c.resolved.trim();
        if r.is_empty() {
            return None;
        }
        let host = url::Url::parse(r.trim_start_matches("git+")).ok().and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        Some(host.unwrap_or_else(|| r.split(':').next().unwrap_or(r).to_ascii_lowercase()))
    })
}

fn by_package(s: &Sbom) -> BTreeMap<String, Vec<&Component>> {
    let mut m: BTreeMap<String, Vec<&Component>> = BTreeMap::new();
    for c in &s.components {
        m.entry(key(c)).or_default().push(c);
    }
    m
}

/// The latest of a package's versions (several in npm lockfiles).
fn newest<'a>(set: &BTreeSet<&'a str>) -> &'a str {
    set.iter().copied().max_by(|x, y| compare_versions(x, y).unwrap_or(std::cmp::Ordering::Equal)).unwrap_or("")
}

const LICENSE_ORDER: [&str; 5] = ["permissive", "weak-copyleft", "copyleft", "network-copyleft", "restricted"];

/// Compares an older and a newer SBOM with their looked-up vulnerabilities. `checked` says for
/// each side whether it was looked up on OSV.dev.
pub fn compare(old: &Sbom, old_vulns: &[Vuln], old_checked: bool, new: &Sbom, new_vulns: &[Vuln], new_checked: bool) -> Comparison {
    let (a, b) = (by_package(old), by_package(new));
    // a package that moved to a Git or URL source has no ecosystem any more: it matches the one
    // earlier package of its name that is otherwise unmatched
    let mut matched: BTreeSet<&str> = BTreeSet::new();
    let mut pairs: Vec<(&str, Option<&str>)> = Vec::new();
    for k in b.keys() {
        if a.contains_key(k) {
            matched.insert(k.as_str());
            pairs.push((k.as_str(), Some(k.as_str())));
        }
    }
    for k in b.keys().filter(|k| !a.contains_key(*k)) {
        let same: Vec<&str> = a.keys().map(String::as_str).filter(|o| !matched.contains(o) && !b.contains_key(*o) && name_part(o) == name_part(k)).collect();
        if same.len() == 1 {
            matched.insert(same[0]);
            pairs.push((k.as_str(), Some(same[0])));
        } else {
            pairs.push((k.as_str(), None));
        }
    }
    pairs.sort();
    let mut out = Comparison::default();
    let (mut downgraded, mut sources, mut contents, mut licenses): (Vec<String>, Vec<String>, Vec<String>, Vec<String>) = Default::default();
    let mut riskiest = 0usize;
    for (k, old_key) in pairs {
        let news = &b[k];
        let Some(olds) = old_key.and_then(|o| a.get(o)) else {
            out.added.extend(news.iter().map(|c| c.label()));
            continue;
        };
        let name = display(if news[0].ecosystem.is_empty() { olds[0] } else { news[0] });
        let ov: BTreeSet<&str> = olds.iter().map(|c| c.version.as_str()).collect();
        let nv: BTreeSet<&str> = news.iter().map(|c| c.version.as_str()).collect();
        if ov == nv {
            out.unchanged += 1;
        } else {
            let (from, to) = (ov.iter().copied().collect::<Vec<_>>().join(", "), nv.iter().copied().collect::<Vec<_>>().join(", "));
            // one version each (most SBOMs): upgraded or downgraded; several: compare the newest
            let direction = match compare_versions(newest(&ov), newest(&nv)) {
                Some(std::cmp::Ordering::Less) => "upgraded",
                Some(std::cmp::Ordering::Greater) => "downgraded",
                _ => "changed",
            };
            if direction == "downgraded" {
                downgraded.push(format!("{name} {from} → {to}"));
            }
            out.changed.push(Change { component: name.clone(), from, to, direction: direction.into() });
        }
        // the same package from another registry, Git repository or address
        let source = |cs: &Vec<&Component>, s: &Sbom| cs.iter().filter_map(|c| source_of(&s.format, c)).collect::<BTreeSet<String>>();
        let (os, ns) = (source(olds, old), source(news, new));
        if !os.is_empty() && !ns.is_empty() && os.is_disjoint(&ns) {
            sources.push(format!("{name}: {} → {}", os.into_iter().collect::<Vec<_>>().join(", "), ns.into_iter().collect::<Vec<_>>().join(", ")));
        }
        // the same version with other content
        for n in news {
            if let Some(o) = olds.iter().find(|o| o.version == n.version && !o.version.is_empty()) {
                if !o.hashes.is_empty() && !n.hashes.is_empty() && !o.hashes.iter().any(|h| n.hashes.contains(h)) {
                    contents.push(n.label());
                }
            }
        }
        let rank = |r: &str| LICENSE_ORDER.iter().position(|x| *x == r);
        let (or, nr) = (olds.iter().filter_map(|c| rank(&c.license_risk)).max(), news.iter().filter_map(|c| rank(&c.license_risk)).max());
        if let (Some(o), Some(n)) = (or, nr) {
            if n > o && n >= 2 {
                riskiest = riskiest.max(n);
                licenses.push(format!("{name}: {} → {} ({})", LICENSE_ORDER[o], LICENSE_ORDER[n], news[0].licenses.join(" OR ")));
            }
        }
    }
    for (k, olds) in &a {
        if !matched.contains(k.as_str()) {
            out.removed.extend(olds.iter().map(|c| c.label()));
        }
    }
    out.vulns_compared = old_checked == new_checked;
    if out.vulns_compared {
        let (va, vb) = (vuln_map(old, &super::merged(old, old_vulns)), vuln_map(new, &super::merged(new, new_vulns)));
        out.vulns_new = deltas(&vb, &va);
        out.vulns_fixed = deltas(&va, &vb);
    }
    let issue = |id: &str, area: &str, severity: &str, title: &str, detail: String, components: Vec<String>, recommendation: &str| Issue { id: id.into(), area: area.into(), severity: severity.into(), title: title.into(), detail, components, recommendation: recommendation.into() };
    if !out.vulns_new.is_empty() {
        let top = out.vulns_new.iter().map(|d| d.severity.as_str()).min_by_key(|s| severity_rank(s)).unwrap_or("medium");
        let listed = out.vulns_new.iter().flat_map(|d| d.components.iter().map(move |c| format!("{c} ({})", d.id))).collect();
        out.issues.push(issue("SBOM-CMP-NEW-VULNS", "supply-chain", if top == "unknown" { "medium" } else { top }, "Vulnerabilities new in the newer version", format!("{} known {} affect components of the newer SBOM and not the older one: they came with new components or version changes.", out.vulns_new.len(), if out.vulns_new.len() == 1 { "vulnerability" } else { "vulnerabilities" }), listed, "Move the affected components to fixed versions before the release, or record why each one does not apply (VEX)."));
    }
    if !sources.is_empty() {
        out.issues.push(issue("SBOM-CMP-SOURCE-CHANGED", "supply-chain", "high", "Packages now come from another source", format!("{} now {} from another registry, Git repository or address than in the older version. Dependency confusion and hijacked packages look like this; so does a deliberate mirror change.", plural(sources.len(), "package"), if sources.len() == 1 { "comes" } else { "come" }), sources, "Confirm each new source with the team; pin the registry (scopes, index URLs) and the package hashes."));
    }
    if !contents.is_empty() {
        out.issues.push(issue("SBOM-CMP-CONTENT-CHANGED", "supply-chain", "high", "Same version, different content", format!("{} the same version with other hashes than in the older version: the published file changed, or it came from another build.", if contents.len() == 1 { "1 package has".to_string() } else { format!("{} packages have", contents.len()) }), contents, "Compare the files from both sources; a version should never change once published. Report a republished package to its registry."));
    }
    if !downgraded.is_empty() {
        out.issues.push(issue("SBOM-CMP-DOWNGRADE", "supply-chain", "medium", "Components downgraded", format!("{} went back to an earlier version, which can bring back fixed vulnerabilities.", plural(downgraded.len(), "component")), downgraded, "Check why each one was downgraded and that the earlier version has no known vulnerability."));
    }
    if !licenses.is_empty() {
        out.issues.push(issue("SBOM-CMP-LICENSE", "license", if riskiest >= 3 { "medium" } else { "low" }, "Licenses changed to stricter terms", format!("{} changed to a license with more obligations.", plural(licenses.len(), "component")), licenses, "Have the license changes reviewed before shipping the newer version."));
    }
    out
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// The finding of a comparison issue: titled with both versions and keyed by both files' hashes,
/// so each comparison records it once.
pub fn finding(old: &SbomSummary, new: &SbomSummary, new_sbom: &Sbom, issue: &Issue) -> crate::commands::projects::FindingInput {
    let label = |s: &SbomSummary| if s.subject.is_empty() { s.name.clone() } else { s.subject.clone() };
    let mut f = super::issue_finding(new, new_sbom, issue);
    f.title = format!("{} ({} → {})", issue.title, label(old), label(new)).chars().take(200).collect();
    f.category = if issue.area == "license" { "License compliance".into() } else { "Supply chain".into() };
    f.technical_details = format!("Check {} comparing {} (SHA-256 {}) with {} (SHA-256 {}).", issue.id, old.name, old.sha256, new.name, new.sha256);
    f.tags = vec!["sbom".into(), "comparison".into(), issue.area.clone()];
    f
}

#[cfg(test)]
#[path = "sbom_compare_tests.rs"]
mod tests;
