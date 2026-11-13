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
    for job in ["verify", "debian", "audit", "msrv", "checks"] {
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
    // Mission 7: no expression is expanded inside a shell script (template injection); values reach
    // scripts through `env:` only
    for (name, text) in [("ci.yml", ci), ("release.yml", release)] {
        let parsed = crate::yaml::parse_one(text).unwrap();
        for (job, def) in parsed["jobs"].as_object().unwrap() {
            for step in def["steps"].as_array().into_iter().flatten() {
                if let Some(run) = step["run"].as_str() {
                    assert!(!run.contains("${{"), "{name}: {job}: an expression inside a run script: {run}");
                }
            }
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
            // nothing is built, signed or uploaded unless the owner switched publishing on and
            // started the run by hand: a tag push only validates (Mission 7)
            assert_eq!(def["if"], "vars.RELEASE_PUBLISHING == 'enabled' && github.event_name == 'workflow_dispatch'", "{job} runs without the release switch or a manual run");
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

/// The keys GitHub Actions accepts at each level of a workflow (workflow syntax reference).
const TOP_KEYS: &[&str] = &["name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs"];
const JOB_KEYS: &[&str] = &["name", "needs", "runs-on", "permissions", "environment", "concurrency", "outputs", "env", "defaults", "if", "steps", "timeout-minutes", "strategy", "continue-on-error", "container", "services"];
const STEP_KEYS: &[&str] = &["id", "name", "if", "uses", "with", "run", "shell", "env", "working-directory", "continue-on-error", "timeout-minutes"];
/// The contexts an expression may read.
const CONTEXTS: &[&str] = &["github", "env", "vars", "secrets", "inputs", "needs", "matrix", "steps", "runner", "job", "strategy"];

/// The roots of the property paths in an expression (`github.ref_name` → `github`), skipping
/// string literals and function names.
fn expression_roots(expr: &str) -> Vec<String> {
    let mut roots = Vec::new();
    let b = expr.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' => {
                i += 1;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-') {
                    i += 1;
                }
                let after_dot = start > 0 && b[start - 1] == b'.';
                if !after_dot && i < b.len() && (b[i] == b'.' || b[i] == b'[') {
                    roots.push(expr[start..i].to_string());
                }
            }
            _ => i += 1,
        }
    }
    roots
}

/// Every expression of a workflow: `${{ … }}` anywhere, and the implicit ones in `if:`.
fn expressions(text: &str, doc: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = text.split("${{").skip(1).map(|s| s.split("}}").next().unwrap_or_default().to_string()).collect();
    for def in doc["jobs"].as_object().unwrap().values() {
        out.extend(def["if"].as_str().map(String::from));
        for step in def["steps"].as_array().into_iter().flatten() {
            out.extend(step["if"].as_str().map(String::from));
        }
    }
    out
}

/// Mission 8: a static validation of the workflows in place of actionlint, which could not run
/// locally (CI still runs it): only keys GitHub knows at each level, every step one action or one
/// script, and expressions that read known contexts only.
#[test]
fn workflows_use_only_known_keys_steps_and_contexts() {
    for (name, text) in [("ci.yml", include_str!("../../.github/workflows/ci.yml")), ("release.yml", include_str!("../../.github/workflows/release.yml"))] {
        let doc = crate::yaml::parse_one(text).unwrap();
        for key in doc.as_object().unwrap().keys() {
            assert!(TOP_KEYS.contains(&key.as_str()), "{name}: unknown top-level key {key}");
        }
        for (job, def) in doc["jobs"].as_object().unwrap() {
            for key in def.as_object().unwrap().keys() {
                assert!(JOB_KEYS.contains(&key.as_str()), "{name}: {job}: unknown key {key}");
            }
            assert!(def.get("runs-on").is_some(), "{name}: {job} has no runner");
            for (n, step) in def["steps"].as_array().unwrap().iter().enumerate() {
                for key in step.as_object().unwrap().keys() {
                    assert!(STEP_KEYS.contains(&key.as_str()), "{name}: {job} step {n}: unknown key {key}");
                }
                let (uses, run) = (step.get("uses").is_some(), step.get("run").is_some());
                assert!(uses != run, "{name}: {job} step {n} is one action or one script");
                if uses {
                    assert!(step.get("shell").is_none() && step.get("working-directory").is_none(), "{name}: {job} step {n}: script keys on an action");
                } else {
                    assert!(step.get("with").is_none(), "{name}: {job} step {n}: `with` on a script");
                }
            }
        }
        for expr in expressions(text, &doc) {
            for root in expression_roots(&expr) {
                assert!(CONTEXTS.contains(&root.as_str()), "{name}: unknown context {root} in `{expr}`");
            }
        }
    }
    assert_eq!(expression_roots("github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name"), ["github", "inputs", "github"]);
    assert_eq!(expression_roots("needs.validate.outputs.sha"), ["needs"]);
    assert_eq!(expression_roots("contains('a.b', x.y)"), ["x"]);
}

/// Mission 8: verification and release stay apart. CI reads no secret, writes nothing and never
/// runs for `pull_request_target`; checkouts keep no credentials; downloads are checked against
/// pinned hashes; the release runs only for stable version tags or by hand, without caches, with
/// its secrets only in the protected environment, and names on its release the commit it built.
#[test]
fn verification_and_release_stay_apart_and_the_release_names_the_commit_it_built() {
    let ci = include_str!("../../.github/workflows/ci.yml");
    let release = include_str!("../../.github/workflows/release.yml");
    let ci_doc = crate::yaml::parse_one(ci).unwrap();
    let doc = crate::yaml::parse_one(release).unwrap();
    // CI: verification only
    // (keys come back sorted)
    let triggers: Vec<&str> = ci_doc["on"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(triggers, ["pull_request", "push"]);
    // every pull request runs CI; pushes only on the long-lived branches and tags, so a branch with
    // a pull request (Dependabot's too) is not checked twice (Mission 12)
    assert_eq!(ci_doc["on"]["pull_request"], serde_json::Value::Null);
    assert_eq!(ci_doc["on"]["push"], serde_json::json!({ "branches": ["main", "release/**"], "tags": ["v*"] }));
    assert!(!ci.contains("secrets.") && !ci.contains("write") && !ci.contains("environment:"), "ci.yml reads no secret and writes nothing");
    assert_eq!(ci_doc["permissions"], serde_json::json!({ "contents": "read" }));
    for text in [ci, release] {
        for trigger in ["pull_request_target", "workflow_run", "issue_comment"] {
            assert!(!text.contains(trigger), "{trigger}");
        }
    }
    // both: no credentials left in a checkout, and every download checked
    for (name, text) in [("ci.yml", ci), ("release.yml", release)] {
        let parsed = crate::yaml::parse_one(text).unwrap();
        for (job, def) in parsed["jobs"].as_object().unwrap() {
            for step in def["steps"].as_array().unwrap() {
                if step["uses"].as_str().is_some_and(|u| u.starts_with("actions/checkout@")) {
                    assert_eq!(step["with"]["persist-credentials"], false, "{name}: {job}: a checkout keeps its credentials");
                }
                if let Some(run) = step["run"].as_str() {
                    if run.contains("curl ") {
                        assert!(run.contains("sha256sum -c"), "{name}: {job}: a download without a pinned hash: {run}");
                    }
                }
            }
        }
    }
    // release: stable version tags or a manual run, nothing from pull requests, no caches
    let on = doc["on"].as_object().unwrap();
    assert_eq!(on.keys().map(String::as_str).collect::<Vec<_>>(), ["push", "workflow_dispatch"]);
    assert_eq!(on["push"], serde_json::json!({ "tags": ["v*.*.*"] }));
    let inputs = &on["workflow_dispatch"]["inputs"];
    assert_eq!(inputs["tag"]["required"], true);
    assert_eq!(inputs["draft"]["default"], true, "a manual run stops at a draft unless asked otherwise");
    assert_eq!(inputs["confirm"]["default"], "");
    // a stable version, or a release candidate of one (Mission 11); no other pre-release
    const TAG_RE: &str = r#"^v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))(-rc\.([1-9][0-9]*))?$"#;
    assert!(release.contains(&format!("[[ \"$TAG\" =~ {TAG_RE} ]]")), "the tag check");
    let re = regex::Regex::new(TAG_RE).unwrap();
    for (tag, version, candidate) in [("v0.1.0", "0.1.0", ""), ("v0.1.0-rc.2", "0.1.0", "2"), ("v10.20.30-rc.11", "10.20.30", "11")] {
        let c = re.captures(tag).unwrap_or_else(|| panic!("{tag} is accepted"));
        assert_eq!((&c[1], c.get(6).map_or("", |m| m.as_str())), (version, candidate), "{tag}");
    }
    for tag in ["v0.1.0-rc.0", "v0.1.0-rc.01", "v0.1.0-rc2", "v0.1.0-beta.1", "v0.1.0-rc.1.1", "v01.0.0", "0.1.0", "v0.1", "v0.1.0 "] {
        assert!(!re.is_match(tag), "{tag} is refused");
    }
    for cache in ["cache:", "rust-cache", "actions/cache"] {
        assert!(!release.contains(cache), "release.yml uses a cache: {cache}");
    }
    let jobs = doc["jobs"].as_object().unwrap();
    assert!(jobs["validate"].get("environment").is_none() && !jobs["validate"].to_string().contains("secrets."));
    assert_eq!(jobs["build"]["environment"], "release");
    assert_eq!(jobs["publish"]["environment"], "release");
    assert_eq!(jobs["build"]["needs"], "validate");
    assert_eq!(jobs["publish"]["needs"], serde_json::json!(["validate", "build"]));
    // the build checks out the validated commit, and the release names it: the tag is checked
    // before the draft is created and again before it becomes public (Mission 8)
    assert_eq!(jobs["build"]["steps"][0]["with"]["ref"], "${{ needs.validate.outputs.sha }}");
    assert_eq!(jobs["publish"]["env"]["SHA"], "${{ needs.validate.outputs.sha }}");
    let steps = jobs["publish"]["steps"].as_array().unwrap();
    let position = |name: &str| steps.iter().position(|s| s["name"] == name).unwrap_or_else(|| panic!("publish has the step {name}"));
    let check = position("The tag still names the built commit");
    assert!(check < position("Upload to a draft release"), "the tag is checked before the draft is created");
    for step in [&steps[check], &steps[position("Publish the release")]] {
        let run = step["run"].as_str().unwrap();
        assert!(run.contains("git/ref/tags/$TAG") && run.contains("!= \"$SHA\""), "{run}");
    }
    let publish = steps[position("Publish the release")]["run"].as_str().unwrap();
    assert!(publish.find("!= \"$SHA\"").unwrap() < publish.find("--draft=false").unwrap(), "checked before it becomes public");
    // a release candidate's draft is a pre-release, never the "latest" release of the update feed,
    // and is never made public (Mission 11)
    assert_eq!(jobs["validate"]["outputs"]["candidate"], "${{ steps.version.outputs.candidate }}");
    assert_eq!(jobs["publish"]["env"]["CANDIDATE"], "${{ needs.validate.outputs.candidate }}");
    let upload = steps[position("Upload to a draft release")]["run"].as_str().unwrap();
    assert!(upload.contains("if [ -n \"$CANDIDATE\" ]; then") && upload.contains("--draft --prerelease --verify-tag"), "{upload}");
    let refused = publish.find("if [ -n \"$CANDIDATE\" ]").expect("the publish step refuses a release candidate");
    assert!(refused < publish.find("--draft=false").unwrap(), "refused before anything is made public");
}

/// Mission 8: every run script parses as bash (the shell of the Linux jobs and of the Windows
/// steps that name it); a syntax error would only show on the first run on GitHub.
#[cfg(unix)]
#[test]
fn run_scripts_are_valid_bash() {
    for (name, text) in [("ci.yml", include_str!("../../.github/workflows/ci.yml")), ("release.yml", include_str!("../../.github/workflows/release.yml"))] {
        let doc = crate::yaml::parse_one(text).unwrap();
        for (job, def) in doc["jobs"].as_object().unwrap() {
            for step in def["steps"].as_array().unwrap() {
                let Some(run) = step["run"].as_str() else { continue };
                let out = std::process::Command::new("bash").args(["-n", "-c", run]).output().expect("bash");
                assert!(out.status.success(), "{name}: {job}: {}\n{run}", String::from_utf8_lossy(&out.stderr));
            }
        }
    }
}

/// Mission 11: after a real uninstall, the NSIS uninstaller forgets the install folder (Tauri's MSI
/// looks there and installed into the removed per-user folder), and removes nothing else: no
/// files, no other registry values, and nothing when an update runs it.
#[test]
fn the_nsis_uninstaller_forgets_the_install_folder_and_nothing_else() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(conf["bundle"]["windows"]["nsis"]["installerHooks"], "windows/installer-hooks.nsh");
    let hooks = include_str!("../windows/installer-hooks.nsh");
    let code: Vec<&str> = hooks.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(';')).collect();
    assert_eq!(
        code,
        [
            "!macro NSIS_HOOK_POSTUNINSTALL",
            "${If} $UpdateMode <> 1",
            r#"DeleteRegValue SHCTX "${MANUPRODUCTKEY}" """#,
            r#"DeleteRegKey /ifempty SHCTX "${MANUPRODUCTKEY}""#,
            r#"DeleteRegKey /ifempty SHCTX "${MANUKEY}""#,
            "${EndIf}",
            "!macroend",
        ]
    );
}

/// Mission 11: what identifies an installed copy on Windows stays the same, so that a new version
/// upgrades the old one instead of installing next to it. The MSI's upgrade code is derived from
/// the product name. The publisher, unset and so "cyberhub" (the identifier's second part), names
/// the NSIS key that holds the install folder (HKCU\Software\cyberhub\Cyber Hub), read by the next
/// NSIS installer to find and remove the old copy and by the MSI to choose its folder. The
/// identifier names the data folder. Changing any of them needs a migration; see
/// docs/release/RELEASE_READINESS.md, "Publisher identity".
#[test]
fn the_windows_install_identity_stays_the_same() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(conf["productName"], "Cyber Hub");
    assert_eq!(conf["identifier"], "dev.cyberhub.workstation");
    assert!(conf["bundle"].get("publisher").is_none(), "the publisher stays the derived \"cyberhub\"");
    assert!(conf["bundle"]["windows"].get("wix").is_none(), "no upgrade code or template override");
    assert!(conf.get("mainBinaryName").is_none(), "the binary stays cyber-hub.exe");
}

/// Mission 13: the product is called ExploitX, while the package identity above stays "Cyber Hub"
/// (install folders, registry keys, MSI upgrade code, package and binary names, the MCP server's
/// path). What people see says ExploitX where the identity allows it: the window title, the Linux
/// desktop entry's name (its file, Exec, Icon and StartupWMClass stay, so docks still match the
/// window) and the package descriptions. docs/brand/NAME_MIGRATION.md lists what keeps the old name.
#[test]
fn the_product_shows_the_exploitx_name_without_changing_the_package_identity() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(conf["app"]["windows"][0]["title"], "ExploitX");
    assert!(conf["bundle"]["shortDescription"].as_str().is_some_and(|d| !d.contains("Cyber Hub")));
    assert!(conf["bundle"]["longDescription"].as_str().is_some_and(|d| d.starts_with("ExploitX ")));
    for format in ["deb", "rpm"] {
        assert_eq!(conf["bundle"]["linux"][format]["desktopTemplate"], "linux/exploitx.desktop.hbs", "{format}");
    }
    let desktop = include_str!("../linux/exploitx.desktop.hbs");
    for line in ["Name=ExploitX", "Exec={{exec}}", "StartupWMClass={{exec}}", "Icon={{icon}}", "Categories={{categories}}", "Type=Application"] {
        assert!(desktop.lines().any(|l| l == line), "the desktop entry has {line}");
    }
    assert_eq!(conf["bundle"]["windows"]["nsis"]["installerIcon"], "icons/icon.ico", "the installer shows the ExploitX icon");
    assert!(include_str!("../../index.html").contains("<title>ExploitX</title>"));
}

/// Mission 14: every package carries the full third-party license texts. `scripts/licenses.mjs
/// notices` generates the file from what ships (CI checks it is current); Tauri bundles it as a
/// resource (next to the app on Windows, under /usr/lib/<product>/ on Linux, inside the AppImage),
/// and the deb and rpm also install it where their users look for licenses.
#[test]
fn third_party_licenses_are_bundled_with_every_package() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(conf["bundle"]["resources"]["resources/THIRD_PARTY_LICENSES.txt"], "THIRD_PARTY_LICENSES.txt");
    assert_eq!(conf["bundle"]["linux"]["deb"]["files"]["/usr/share/doc/cyber-hub/THIRD_PARTY_LICENSES.txt"], "resources/THIRD_PARTY_LICENSES.txt");
    assert_eq!(conf["bundle"]["linux"]["rpm"]["files"]["/usr/share/licenses/cyber-hub/THIRD_PARTY_LICENSES.txt"], "resources/THIRD_PARTY_LICENSES.txt");
    let notices = include_str!("../resources/THIRD_PARTY_LICENSES.txt");
    assert!(notices.starts_with("ExploitX ") && notices.contains("Generated by `node scripts/licenses.mjs notices`"));
    for section in ["1. Rust crates compiled into ExploitX", "2. JavaScript packages bundled", "4. Native libraries", "5. License texts", "6. THIRD_PARTY_NOTICES.md"] {
        assert!(notices.contains(section), "{section}");
    }
    // a few crates that certainly ship, with their texts
    for krate in ["\n  tauri ", "\n  rusqlite ", "\n  reqwest ", "\n  serde "] {
        assert!(notices.contains(krate), "{krate}");
    }
    assert!(notices.len() > 500_000, "the license texts are reproduced in full");
}

/// Mission 14: the AppImage bundles LGPL and GPL libraries of the build system. The Linux build
/// collects their copyright files into the AppImage and their Debian source packages into a release
/// asset before `tauri build`, and every build checks its signed packages for the notices before
/// they are uploaded. The source archive is not an update artifact: unsigned, covered by SHA256SUMS.
#[test]
fn the_release_ships_the_notices_and_the_appimage_library_sources() {
    let release = include_str!("../../.github/workflows/release.yml");
    let doc = crate::yaml::parse_one(release).unwrap();
    let steps = doc["jobs"]["build"]["steps"].as_array().unwrap();
    let position = |name: &str| steps.iter().position(|s| s["name"].as_str().is_some_and(|n| n.starts_with(name))).unwrap_or_else(|| panic!("build has the step {name}"));
    let collect = position("Licenses and corresponding source of the AppImage's libraries");
    let build = position("Build and sign");
    let artifacts = position("Collect signed artifacts");
    let check = position("Every package carries the third-party notices");
    let upload = steps.iter().position(|s| s["uses"].as_str().is_some_and(|u| u.starts_with("actions/upload-artifact@"))).unwrap();
    assert!(collect < build && build < artifacts && artifacts < check && check < upload, "collected before the build, checked before the upload");
    assert_eq!(steps[collect]["if"], "runner.os == 'Linux'");
    let run = steps[collect]["run"].as_str().unwrap();
    assert!(run.contains("deb-src http://archive.ubuntu.com/ubuntu $codename-updates") && run.contains("deb-src http://security.ubuntu.com/ubuntu $codename-security"), "{run}");
    assert!(run.contains("bash scripts/appimage-licenses.sh \"$RUNNER_TEMP/appimage-licenses\"") && run.contains("--sources \"release-sources/ExploitX-AppImage-library-sources_${VERSION}.tar\"") && run.contains("--tauri-config \"$RUNNER_TEMP/appimage-files.json\""), "{run}");
    // `. /etc/os-release` in the step's own shell would overwrite VERSION
    assert!(run.contains("codename=$(. /etc/os-release && echo \"$VERSION_CODENAME\")"), "{run}");
    let run = steps[build]["run"].as_str().unwrap();
    assert!(run.contains("if [ \"$RUNNER_OS\" = Linux ]; then config+=(--config \"$RUNNER_TEMP/appimage-files.json\"); fi") && run.contains("npx tauri build --ci --bundles \"$BUNDLES\" \"${config[@]}\""), "{run}");
    let run = steps[artifacts]["run"].as_str().unwrap();
    assert!(run.find("was not signed").unwrap() < run.find("cp release-sources/* release-assets/").unwrap(), "the signature check covers the packages, then the unsigned source archive joins them");
    assert_eq!(steps[check]["run"], "node scripts/check-package-notices.mjs release-assets");
    assert!(steps[check].get("if").is_none(), "both platforms check their packages");
    // the archive is not mistaken for an update artifact (scripts/updater-manifest.mjs patterns)
    for pattern in ["_x64-setup\\.exe$", "\\.msi$", "_amd64\\.AppImage$", "_amd64\\.deb$", "\\.x86_64\\.rpm$"] {
        assert!(!regex::Regex::new(pattern).unwrap().is_match("ExploitX-AppImage-library-sources_0.1.0.tar"), "{pattern}");
    }
    // CI installs the npm packages, without running their scripts, before the notices check reads them
    let ci = include_str!("../../.github/workflows/ci.yml");
    let ci_doc = crate::yaml::parse_one(ci).unwrap();
    let runs: Vec<&str> = ci_doc["jobs"]["checks"]["steps"].as_array().unwrap().iter().filter_map(|s| s["run"].as_str()).collect();
    let install = runs.iter().position(|r| r.starts_with("npm ci --ignore-scripts")).expect("the checks job installs the npm packages");
    let licenses = runs.iter().position(|r| r.contains("node scripts/licenses.mjs check")).unwrap();
    assert!(install < licenses);
}

/// Mission 12: the repository is public. A release run's build artifacts could be downloaded by any
/// signed-in GitHub user, which would make a private draft's binaries public, so they live one day
/// and the publish job deletes them once the draft holds the files. CI also checks dependency
/// licenses, documentation links and pull request titles, the title reaching its script as data.
#[test]
fn public_repository_release_artifacts_are_short_lived_and_ci_checks_licenses_links_and_titles() {
    let release = include_str!("../../.github/workflows/release.yml");
    let doc = crate::yaml::parse_one(release).unwrap();
    let jobs = doc["jobs"].as_object().unwrap();
    let upload = jobs["build"]["steps"].as_array().unwrap().iter().find(|s| s["uses"].as_str().is_some_and(|u| u.starts_with("actions/upload-artifact@"))).expect("the build uploads its bundles");
    let days = &upload["with"]["retention-days"];
    assert_eq!(days.as_u64().or_else(|| days.as_str().and_then(|s| s.parse().ok())), Some(1), "build artifacts live one day");
    assert_eq!(jobs["publish"]["permissions"], serde_json::json!({ "contents": "write", "actions": "write" }));
    let steps = jobs["publish"]["steps"].as_array().unwrap();
    let position = |name: &str| steps.iter().position(|s| s["name"].as_str().is_some_and(|n| n.starts_with(name))).unwrap_or_else(|| panic!("publish has the step {name}"));
    let delete = position("Delete this run's build artifacts");
    assert!(delete > position("Check GitHub's asset digests"), "artifacts go only after the draft is verified");
    let run = steps[delete]["run"].as_str().unwrap();
    assert!(run.contains("actions/runs/$GITHUB_RUN_ID/artifacts") && run.contains("-X DELETE") && run.contains("startswith(\"bundles-\")"), "{run}");
    // CI: the repository checks
    let ci = include_str!("../../.github/workflows/ci.yml");
    let ci_doc = crate::yaml::parse_one(ci).unwrap();
    let checks = &ci_doc["jobs"]["checks"];
    assert_eq!(checks["name"], "Repository checks");
    let runs: Vec<&str> = checks["steps"].as_array().unwrap().iter().filter_map(|s| s["run"].as_str()).collect();
    for cmd in ["node scripts/licenses.mjs check", "node scripts/check-links.mjs"] {
        assert!(runs.iter().any(|r| r.contains(cmd)), "CI runs {cmd}");
    }
    let title = checks["steps"].as_array().unwrap().iter().find(|s| s["name"].as_str().is_some_and(|n| n.starts_with("Pull request title"))).expect("a title check");
    assert_eq!(title["if"], "github.event_name == 'pull_request'");
    assert_eq!(title["env"]["TITLE"], "${{ github.event.pull_request.title }}");
    assert!(!title["run"].as_str().unwrap().contains("${{"), "the title is never expanded into the script");
}
