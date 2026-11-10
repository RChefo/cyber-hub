//! The CI workflows stay deterministic (Mission 5): they parse, every action is pinned to a
//! commit, the container image to a digest, the toolchains to exact versions, and the checks the
//! project relies on are there.

fn pinned_uses(name: &str, text: &str) {
    for line in text.lines() {
        let t = line.trim().trim_start_matches("- ");
        let Some(target) = t.strip_prefix("uses: ") else { continue };
        let (action, rest) = target.split_once('@').unwrap_or_else(|| panic!("{name}: {target} has no version"));
        let sha = rest.split_whitespace().next().unwrap_or_default();
        assert!(sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "{name}: {action}@{sha} is not pinned to a commit");
    }
}

#[test]
fn workflows_parse_and_pin_every_action_by_commit() {
    let ci = include_str!("../../.github/workflows/ci.yml");
    let release = include_str!("../../.github/workflows/release.yml");
    for (name, text) in [("ci.yml", ci), ("release.yml", release)] {
        let doc = crate::yaml::parse_one(text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(doc.get("jobs").and_then(|j| j.as_object()).is_some_and(|j| !j.is_empty()), "{name} has jobs");
        pinned_uses(name, text);
    }
    let doc = crate::yaml::parse_one(ci).unwrap();
    let jobs = doc["jobs"].as_object().unwrap();
    for job in ["verify", "debian", "audit", "msrv"] {
        assert!(jobs.contains_key(job), "ci.yml has the {job} job");
    }
    // exact versions, never a floating toolchain
    let rust = doc["env"]["RUST_VERSION"].as_str().unwrap_or_default();
    assert!(rust.split('.').count() == 3 && rust.split('.').all(|p| p.parse::<u32>().is_ok()), "RUST_VERSION {rust}");
    assert!(!ci.contains("toolchain: stable"));
    assert!(ci.contains("toolchain: 1.90.0"), "the minimum Rust version is checked");
    assert!(ci.contains("container: rust@sha256:"), "the Debian image is pinned by digest");
    // the checks
    for check in ["cargo clippy --locked --all-targets -- -D warnings", "cargo test --locked", "npx tsc --noEmit", "npx vitest run", "npm audit", "cargo audit", "gitleaks git", "sha256sum -c", "./actionlint"] {
        assert!(ci.contains(check), "ci.yml runs {check}");
    }
}

/// Mission 6: the release workflow uses the same exact toolchains as CI, grants the least it can,
/// and cannot publish anything by accident.
#[test]
fn the_release_workflow_is_pinned_least_privileged_and_publishes_only_on_explicit_conditions() {
    let ci = include_str!("../../.github/workflows/ci.yml");
    let release = include_str!("../../.github/workflows/release.yml");
    let ci_doc = crate::yaml::parse_one(ci).unwrap();
    let doc = crate::yaml::parse_one(release).unwrap();
    for key in ["RUST_VERSION", "NODE_VERSION"] {
        let v = doc["env"][key].as_str().unwrap_or_default();
        assert!(v.split('.').count() == 3 && v.split('.').all(|p| p.parse::<u32>().is_ok()), "release.yml {key} is {v}");
        assert_eq!(Some(v), ci_doc["env"][key].as_str(), "release.yml and ci.yml use the same {key}");
    }
    for (name, text) in [("ci.yml", ci), ("release.yml", release)] {
        assert!(!text.contains("toolchain: stable") && !text.contains("toolchain: nightly"), "{name}: a floating Rust toolchain");
        for line in text.lines() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("node-version:") {
                assert_eq!(v.trim(), "${{ env.NODE_VERSION }}", "{name}: node-version {v}");
            }
            if t.contains("cargo install") {
                assert!(t.contains("--locked") && t.contains("--version"), "{name}: unpinned tool: {t}");
            }
            if let Some(r) = t.strip_prefix("runs-on:").or_else(|| t.strip_prefix("os: [")) {
                assert!(!r.contains("latest"), "{name}: floating runner image {r}");
            }
        }
        let parsed = crate::yaml::parse_one(text).unwrap();
        for (job, def) in parsed["jobs"].as_object().unwrap() {
            assert!(def.get("timeout-minutes").is_some(), "{name}: {job} has no timeout");
        }
    }
    // least privilege, and never from a pull request
    assert_eq!(doc["permissions"], serde_json::json!({}), "release.yml grants nothing at the top level");
    assert!(doc["on"].get("pull_request").is_none() && doc["on"].get("pull_request_target").is_none());
    let jobs = doc["jobs"].as_object().unwrap();
    for (job, def) in jobs {
        assert!(def.get("permissions").is_some(), "release.yml: {job} states its permissions");
        let body = def.to_string();
        if body.contains("secrets.") {
            assert_eq!(def["environment"], "release", "{job} reads secrets outside the protected environment");
        }
        if job != "validate" {
            // nothing is built, signed or uploaded unless the owner switched publishing on
            assert_eq!(def["if"], "vars.RELEASE_PUBLISHING == 'enabled'", "{job} runs without the release switch");
        }
    }
    assert_eq!(jobs["validate"]["permissions"], serde_json::json!({ "contents": "read" }));
    assert_eq!(jobs["build"]["permissions"], serde_json::json!({ "contents": "read" }));
    // every upload is a draft; the one step that makes it public needs a manual run that confirms the tag
    assert!(release.contains("gh release create \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft"));
    assert_eq!(release.matches("--draft=false").count(), 1);
    let steps = jobs["publish"]["steps"].as_array().unwrap();
    let public: Vec<_> = steps.iter().filter(|s| s["run"].as_str().is_some_and(|r| r.contains("--draft=false"))).collect();
    assert_eq!(public.len(), 1);
    assert_eq!(public[0]["if"], "github.event_name == 'workflow_dispatch' && inputs.draft == false && inputs.confirm == inputs.tag");
}
