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
    for check in ["cargo clippy --locked --all-targets -- -D warnings", "cargo test --locked", "npx tsc --noEmit", "npx vitest run", "npm audit", "cargo audit", "gitleaks git", "sha256sum -c"] {
        assert!(ci.contains(check), "ci.yml runs {check}");
    }
}
