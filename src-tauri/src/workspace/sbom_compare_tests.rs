// SPDX-License-Identifier: Apache-2.0
//! Tests of the SBOM comparison, with lockfiles read by the importer.

use std::cmp::Ordering::*;

use super::*;
use crate::workspace::sbom::parse_file;

fn lock(packages: &[(&str, &str, &str, &str, &str)]) -> Sbom {
    // name, version, resolved URL, integrity, license
    let mut pk = serde_json::Map::new();
    pk.insert("".into(), serde_json::json!({ "name": "shop", "version": "1.0.0" }));
    for (name, version, resolved, integrity, license) in packages {
        pk.insert(format!("node_modules/{name}"), serde_json::json!({ "version": version, "resolved": resolved, "integrity": integrity, "license": license }));
    }
    let doc = serde_json::json!({ "name": "shop", "version": "1.0.0", "lockfileVersion": 3, "packages": pk });
    parse_file("package-lock.json", &doc.to_string()).unwrap()
}

#[test]
fn versions_compare_like_package_managers() {
    assert_eq!(compare_versions("4.17.20", "4.17.21"), Some(Less));
    assert_eq!(compare_versions("10.0.0", "9.9.9"), Some(Greater));
    assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), Some(Less));
    assert_eq!(compare_versions("v2.0", "2.0.0"), Some(Less), "2.0 < 2.0.0 is fine for ordering upgrades");
    assert_eq!(compare_versions("1.2.3", "1.2.3"), Some(Equal));
    assert_eq!(compare_versions("a1b2c3d", "1.0.0"), None);
}

#[test]
fn components_sources_contents_and_licenses() {
    let npm = |n: &str, v: &str| format!("https://registry.npmjs.org/{n}/-/{n}-{v}.tgz");
    let old = lock(&[
        ("lodash", "4.17.20", &npm("lodash", "4.17.20"), "sha512-AAA", "MIT"),
        ("left-pad", "1.3.0", &npm("left-pad", "1.3.0"), "sha512-BBB", "WTFPL"),
        ("express", "4.18.2", &npm("express", "4.18.2"), "sha512-CCC", "MIT"),
        ("colors", "1.4.0", &npm("colors", "1.4.0"), "sha512-DDD", "MIT"),
        ("chart", "2.0.0", &npm("chart", "2.0.0"), "sha512-EEE", "MIT"),
        ("gone", "1.0.0", &npm("gone", "1.0.0"), "sha512-FFF", "MIT"),
    ]);
    let new = lock(&[
        ("lodash", "4.17.21", &npm("lodash", "4.17.21"), "sha512-AAB", "MIT"),
        ("left-pad", "1.3.0", &npm("left-pad", "1.3.0"), "sha512-BBB", "WTFPL"),
        ("express", "4.17.1", &npm("express", "4.17.1"), "sha512-CCD", "MIT"),
        ("colors", "1.4.0", "https://evil.example/colors-1.4.0.tgz", "sha512-ZZZ", "MIT"),
        ("chart", "2.0.0", &npm("chart", "2.0.0"), "sha512-EEE", "AGPL-3.0-only"),
        ("fresh", "0.1.0", &npm("fresh", "0.1.0"), "sha512-GGG", "MIT"),
    ]);
    let c = compare(&old, &[], false, &new, &[], false);
    assert_eq!(c.added, vec!["fresh@0.1.0"]);
    assert_eq!(c.removed, vec!["gone@1.0.0"]);
    assert_eq!(c.changed.iter().map(|x| (x.component.as_str(), x.from.as_str(), x.to.as_str(), x.direction.as_str())).collect::<Vec<_>>(), vec![("npm express", "4.18.2", "4.17.1", "downgraded"), ("npm lodash", "4.17.20", "4.17.21", "upgraded")]);
    assert_eq!(c.unchanged, 3);
    let ids: Vec<(&str, &str)> = c.issues.iter().map(|i| (i.id.as_str(), i.severity.as_str())).collect();
    assert_eq!(ids, vec![("SBOM-CMP-SOURCE-CHANGED", "high"), ("SBOM-CMP-CONTENT-CHANGED", "high"), ("SBOM-CMP-DOWNGRADE", "medium"), ("SBOM-CMP-LICENSE", "medium")]);
    assert_eq!(c.issues[0].components, vec!["npm colors: registry.npmjs.org → evil.example"]);
    assert_eq!(c.issues[1].components, vec!["colors@1.4.0"], "only an identical version with other hashes counts");
    assert_eq!(c.issues[2].components, vec!["npm express 4.18.2 → 4.17.1"]);
    assert_eq!(c.issues[3].components, vec!["npm chart: permissive → network-copyleft (AGPL-3.0-only)"]);
}

#[test]
fn vulnerabilities_are_compared_only_with_the_same_data() {
    let old = lock(&[("lodash", "4.17.20", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "sha512-A", "MIT"), ("minimist", "1.2.5", "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz", "sha512-B", "MIT")]);
    let new = lock(&[("lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "sha512-C", "MIT"), ("minimist", "1.2.5", "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz", "sha512-B", "MIT"), ("tar", "4.4.1", "https://registry.npmjs.org/tar/-/tar-4.4.1.tgz", "sha512-D", "ISC")]);
    let idx = |s: &Sbom, n: &str| s.components.iter().position(|c| c.name == n).unwrap();
    let v = |id: &str, sev: &str, comps: Vec<usize>| Vuln { id: id.into(), severity: sev.into(), components: comps, ..Default::default() };
    let old_v = vec![v("GHSA-lodash", "high", vec![idx(&old, "lodash")]), v("GHSA-minimist", "critical", vec![idx(&old, "minimist")])];
    let new_v = vec![v("GHSA-minimist", "critical", vec![idx(&new, "minimist")]), v("GHSA-tar", "high", vec![idx(&new, "tar")])];
    let c = compare(&old, &old_v, true, &new, &new_v, true);
    assert!(c.vulns_compared);
    assert_eq!(c.vulns_new.iter().map(|d| (d.id.as_str(), d.components.clone())).collect::<Vec<_>>(), vec![("GHSA-tar", vec!["tar@4.4.1".to_string()])]);
    assert_eq!(c.vulns_fixed.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), vec!["GHSA-lodash"]);
    assert_eq!(c.issues[0].id, "SBOM-CMP-NEW-VULNS");
    assert_eq!((c.issues[0].severity.as_str(), c.issues[0].components.clone()), ("high", vec!["tar@4.4.1 (GHSA-tar)".to_string()]));
    // the newer one was not looked up: nothing is called fixed
    let c = compare(&old, &old_v, true, &new, &[], false);
    assert!(!c.vulns_compared && c.vulns_fixed.is_empty() && c.vulns_new.is_empty());
    assert!(c.issues.iter().all(|i| i.id != "SBOM-CMP-NEW-VULNS"));
}
