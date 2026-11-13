// SPDX-License-Identifier: Apache-2.0
//! Dependency lockfiles read as SBOM components (docs/DATA_MODEL.md, "SBOM analysis"): the exact
//! versions a project resolves, with package URLs for the OSV.dev check. Recognised by file name;
//! nothing is contacted. Packages that belong to the project itself (workspace members, path and
//! editable packages) are left out. Formats: npm (package-lock.json, npm-shrinkwrap.json), Yarn
//! classic and Berry, pnpm (lockfile versions 5 to 9), Cargo, Poetry, uv, Pipfile.lock, pinned
//! requirements.txt, Composer, Bundler, Go modules (go.mod), NuGet and Gradle lockfiles.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::sbom::{Component, Sbom, MAX_COMPONENTS};

/// The lockfile kind of a file name ("npm", "cargo", …), or None for anything else.
pub fn kind_of(file_name: &str) -> Option<&'static str> {
    let name = file_name.rsplit(['/', '\\']).next().unwrap_or(file_name).to_ascii_lowercase();
    Some(match name.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => "npm",
        "yarn.lock" => "yarn",
        "pnpm-lock.yaml" | "pnpm-lock.yml" => "pnpm",
        "cargo.lock" => "cargo",
        "poetry.lock" => "poetry",
        "uv.lock" => "uv",
        "pipfile.lock" => "pipfile",
        "composer.lock" => "composer",
        "gemfile.lock" | "gems.locked" => "gemfile",
        "go.mod" => "gomod",
        "packages.lock.json" => "nuget",
        "gradle.lockfile" | "buildscript-gradle.lockfile" => "gradle",
        n if n.ends_with(".txt") && n.contains("requirements") => "requirements",
        _ => return None,
    })
}

/// Formats whose registry packages normally carry a hash (`LOCK-NO-INTEGRITY` applies to them).
pub const HASHED: &[&str] = &["lockfile-npm", "lockfile-yarn", "lockfile-pnpm", "lockfile-cargo", "lockfile-poetry", "lockfile-uv", "lockfile-pipfile", "lockfile-nuget"];

/// A lockfile, when the file name is one; the components are not yet finished (see `sbom::parse_file`).
pub fn parse(file_name: &str, text: &str) -> Option<Result<Sbom, String>> {
    let kind = kind_of(file_name)?;
    let body = text.trim_start_matches('\u{feff}');
    let mut out = Out::new(kind);
    let parsed = match kind {
        "npm" => npm(body, &mut out),
        "yarn" => yarn(body, &mut out),
        "pnpm" => pnpm(body, &mut out),
        "cargo" => cargo(body, &mut out),
        "poetry" => poetry(body, &mut out),
        "uv" => uv(body, &mut out),
        "pipfile" => pipfile(body, &mut out),
        "requirements" => requirements(body, &mut out),
        "composer" => composer(body, &mut out),
        "gemfile" => gemfile(body, &mut out),
        "gomod" => gomod(body, &mut out),
        "nuget" => nuget(body, &mut out),
        _ => gradle(body, &mut out),
    };
    Some(parsed.map(|()| out.finish()))
}

/* ───────────────────────────── building ───────────────────────────── */

struct Out {
    sbom: Sbom,
    seen: BTreeSet<String>,
    local: usize,
    full: bool,
}

impl Out {
    fn new(kind: &str) -> Self {
        let tool = match kind {
            "gomod" => "go",
            "requirements" | "pipfile" => "pip",
            "gemfile" => "bundler",
            k => k,
        };
        Out { sbom: Sbom { format: format!("lockfile-{kind}"), tools: vec![tool.to_string()], ..Default::default() }, seen: BTreeSet::new(), local: 0, full: false }
    }

    fn push(&mut self, c: Component) {
        let key = format!("{}|{}|{}|{}", c.purl, c.name, c.version, c.resolved);
        if !self.seen.insert(key) {
            return;
        }
        if self.sbom.components.len() >= MAX_COMPONENTS {
            self.full = true;
            return;
        }
        self.sbom.components.push(c);
    }

    fn finish(mut self) -> Sbom {
        match self.local {
            0 => {}
            1 => self.sbom.warnings.push("1 of the project's own packages (a workspace member, path or editable package) is left out".into()),
            n => self.sbom.warnings.push(format!("{n} of the project's own packages (workspace members, path or editable packages) are left out")),
        }
        if self.full {
            self.sbom.warnings.push(format!("Only the first {MAX_COMPONENTS} packages were kept"));
        }
        if !self.sbom.components.is_empty() && self.sbom.components.iter().all(|c| c.licenses.is_empty()) {
            self.sbom.warnings.push("This lockfile records no licenses, so licenses are not checked".into());
        }
        self.sbom
    }
}

/// Percent-encoding of one package URL segment (unreserved characters stay).
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// PEP 503 normalized Python project name.
fn pep503(name: &str) -> String {
    let mut out = String::new();
    for ch in name.trim().chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

/// A package from a registry, with its package URL. `name` may carry a namespace (`@scope/name`,
/// `vendor/name`, `group:artifact`, a Go module path).
fn registry(ecosystem: &str, name: &str, version: &str) -> Component {
    let path = match ecosystem {
        "npm" => match name.strip_prefix('@').and_then(|n| n.split_once('/')) {
            Some((scope, n)) => format!("%40{}/{}", enc(scope), enc(n)),
            None => enc(name),
        },
        "pypi" => enc(&pep503(name)),
        "maven" => match name.split_once(':') {
            Some((g, a)) => format!("{}/{}", enc(g), enc(a)),
            None => enc(name),
        },
        "golang" | "composer" => name.split('/').map(enc).collect::<Vec<_>>().join("/"),
        _ => enc(name),
    };
    // Maven: the group goes to its own field, as for SBOM components
    let (group, shown) = match (ecosystem, name.split_once(':')) {
        ("maven", Some((g, a))) => (g.to_string(), a.to_string()),
        _ => (String::new(), name.to_string()),
    };
    Component {
        name: shown,
        group,
        version: version.to_string(),
        purl: if version.is_empty() { String::new() } else { format!("pkg:{ecosystem}/{path}@{}", enc(version)) },
        kind: "library".into(),
        ..Default::default()
    }
}

/// A package from Git, a URL or a local path: no package URL, so no OSV match.
fn elsewhere(name: &str, version: &str, origin: &str) -> Component {
    Component { name: name.to_string(), version: version.to_string(), resolved: origin.to_string(), kind: "library".into(), ..Default::default() }
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn flag(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true))) || matches!(v, Some(Value::String(s)) if s == "true")
}

fn json(body: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|e| format!("not valid JSON: {e}"))
}

fn toml_doc(body: &str) -> Result<toml::Table, String> {
    body.parse::<toml::Table>().map_err(|e| format!("not valid TOML: {}", e.message()))
}

fn tstr(v: Option<&toml::Value>) -> String {
    match v {
        Some(toml::Value::String(s)) => s.trim().to_string(),
        Some(toml::Value::Integer(i)) => i.to_string(),
        Some(toml::Value::Float(f)) => f.to_string(),
        _ => String::new(),
    }
}

/// `@scope/name@range` or `name@range` → the name (Yarn and pnpm keys, Yarn resolutions).
fn spec_name(spec: &str) -> (&str, &str) {
    let at = if let Some(rest) = spec.strip_prefix('@') { rest.find('@').map(|i| i + 1) } else { spec.find('@') };
    match at {
        Some(i) => (&spec[..i], &spec[i + 1..]),
        None => (spec, ""),
    }
}

/// Whether an npm `resolved` value points somewhere other than a registry tarball.
fn npm_elsewhere(resolved: &str) -> bool {
    let r = resolved.to_ascii_lowercase();
    r.starts_with("git") || r.starts_with("github:") || r.starts_with("file:") || r.starts_with("link:") || ((r.starts_with("http://") || r.starts_with("https://")) && !r.contains("/-/"))
}

fn npm_component(name: &str, version: &str, resolved: &str) -> Component {
    let mut c = if npm_elsewhere(resolved) || version.starts_with("file:") || version.starts_with("git") { elsewhere(name, version, resolved) } else { registry("npm", name, version) };
    if c.resolved.is_empty() {
        c.resolved = resolved.to_string();
    }
    c
}

/* ───────────────────────────── JavaScript ───────────────────────────── */

fn npm(body: &str, out: &mut Out) -> Result<(), String> {
    let root = json(body)?;
    out.sbom.spec_version = text(root.get("lockfileVersion"));
    let (name, version) = (text(root.get("name")), text(root.get("version")));
    out.sbom.subject = if version.is_empty() { name } else { format!("{name}@{version}") };
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        let top = packages.get("");
        let mut direct = BTreeSet::new();
        for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            direct.extend(top.and_then(|t| t.get(k)).and_then(Value::as_object).into_iter().flat_map(|m| m.keys().cloned()));
        }
        out.sbom.relationships = top.is_some();
        for (path, p) in packages {
            let Some(at) = path.rfind("node_modules/") else {
                if !path.is_empty() {
                    out.local += 1; // a workspace member
                }
                continue;
            };
            if flag(p.get("link")) {
                continue;
            }
            let key_name = &path[at + "node_modules/".len()..];
            let name = p.get("name").and_then(Value::as_str).unwrap_or(key_name);
            let version = text(p.get("version"));
            if version.is_empty() {
                continue;
            }
            let mut c = npm_component(name, &version, &text(p.get("resolved")));
            c.dev = flag(p.get("dev"));
            c.direct = at == 0 && direct.contains(key_name);
            let integrity = text(p.get("integrity"));
            if !integrity.is_empty() {
                c.hashes.push(integrity);
            }
            match p.get("license") {
                Some(Value::String(l)) if !l.is_empty() => c.licenses.push(l.clone()),
                Some(Value::Object(o)) => c.licenses.extend(o.get("type").and_then(Value::as_str).map(String::from)),
                _ => {}
            }
            out.push(c);
        }
    } else if let Some(deps) = root.get("dependencies").and_then(Value::as_object) {
        npm_v1(deps, 0, out);
    } else {
        return Err("This package-lock.json has neither packages nor dependencies".into());
    }
    Ok(())
}

/// lockfileVersion 1: a tree of `dependencies`.
fn npm_v1(deps: &serde_json::Map<String, Value>, depth: usize, out: &mut Out) {
    if depth > 64 {
        return;
    }
    for (name, d) in deps {
        let version = text(d.get("version"));
        if !version.is_empty() {
            let mut c = npm_component(name, &version, &text(d.get("resolved")));
            c.dev = flag(d.get("dev"));
            let integrity = text(d.get("integrity"));
            if !integrity.is_empty() {
                c.hashes.push(integrity);
            }
            out.push(c);
        }
        if let Some(nested) = d.get("dependencies").and_then(Value::as_object) {
            npm_v1(nested, depth + 1, out);
        }
    }
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"')
}

fn yarn(body: &str, out: &mut Out) -> Result<(), String> {
    if body.lines().any(|l| l.starts_with("__metadata:")) {
        return yarn_berry(body, out);
    }
    out.sbom.spec_version = "1".into();
    let mut cur: Option<(String, BTreeMap<String, String>)> = None;
    let flush = |cur: &mut Option<(String, BTreeMap<String, String>)>, out: &mut Out| {
        if let Some((name, f)) = cur.take() {
            let version = f.get("version").cloned().unwrap_or_default();
            if !version.is_empty() {
                let resolved = f.get("resolved").cloned().unwrap_or_default();
                let mut c = npm_component(&name, &version, &resolved);
                c.hashes.extend(f.get("integrity").filter(|i| !i.is_empty()).cloned());
                out.push(c);
            }
        }
    };
    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            flush(&mut cur, out);
            let first = line.trim_end().trim_end_matches(':').split(", ").next().unwrap_or("");
            let (name, _) = spec_name(unquote(first));
            cur = Some((name.to_string(), BTreeMap::new()));
        } else if let (Some((_, fields)), Some(rest)) = (cur.as_mut(), line.strip_prefix("  ")) {
            if !rest.starts_with(' ') {
                if let Some((k, v)) = rest.split_once(' ') {
                    fields.insert(k.to_string(), unquote(v).to_string());
                }
            }
        }
    }
    flush(&mut cur, out);
    if out.sbom.components.is_empty() {
        return Err("No packages found in this yarn.lock".into());
    }
    Ok(())
}

fn yarn_berry(body: &str, out: &mut Out) -> Result<(), String> {
    let root = crate::yaml::parse_one(body)?;
    let map = root.as_object().ok_or("This yarn.lock is not a mapping")?;
    out.sbom.spec_version = map.get("__metadata").map(|m| text(m.get("version"))).unwrap_or_default();
    for (key, p) in map {
        if key == "__metadata" {
            continue;
        }
        let resolution = text(p.get("resolution"));
        let (name, rest) = spec_name(&resolution);
        let (protocol, value) = rest.split_once(':').unwrap_or(("", rest));
        let mut c = match protocol {
            "npm" => registry("npm", name, value),
            "workspace" | "link" | "portal" | "file" => {
                out.local += 1;
                continue;
            }
            "patch" => {
                // patch:name@npm%3A1.2.3#… : the patched registry package
                let inner = value.split('#').next().unwrap_or("").replace("%3A", ":");
                match spec_name(&inner).1.strip_prefix("npm:") {
                    Some(v) => registry("npm", name, v),
                    None => elsewhere(name, &text(p.get("version")), &resolution),
                }
            }
            _ => elsewhere(name, &text(p.get("version")), &resolution),
        };
        if c.version.is_empty() {
            continue;
        }
        let checksum = text(p.get("checksum"));
        if !checksum.is_empty() {
            c.hashes.push(checksum);
        }
        out.push(c);
    }
    Ok(())
}

/// pnpm package keys: `/name/1.0.0_peer` (v5), `/name@1.0.0(peer)` (v6), `name@1.0.0(peer)` (v9).
fn pnpm_key(key: &str) -> Option<(String, String)> {
    let k = key.trim_start_matches('/');
    let k = k.split('(').next().unwrap_or(k);
    let (name, version) = spec_name(k);
    let slashes = name.matches('/').count();
    if !version.is_empty() && !version.contains('/') && slashes == usize::from(name.starts_with('@')) {
        return Some((name.to_string(), version.to_string()));
    }
    let parts: Vec<&str> = k.split('/').collect();
    let (name, version) = match (k.starts_with('@'), parts.len()) {
        (true, n) if n >= 3 => (format!("{}/{}", parts[0], parts[1]), parts[2]),
        (false, n) if n >= 2 => (parts[0].to_string(), parts[1]),
        _ => return None,
    };
    Some((name, version.split('_').next().unwrap_or(version).to_string()))
}

fn pnpm(body: &str, out: &mut Out) -> Result<(), String> {
    let root = crate::yaml::parse_one(body)?;
    out.sbom.spec_version = text(root.get("lockfileVersion"));
    // direct dependencies, from the importers (workspaces) or the root (single project, v5)
    let mut direct: BTreeMap<String, bool> = BTreeMap::new();
    let importers: Vec<&Value> = match root.get("importers").and_then(Value::as_object) {
        Some(m) => m.values().collect(),
        None => vec![&root],
    };
    if root.get("importers").and_then(Value::as_object).is_some_and(|m| m.len() > 1) {
        out.local += root["importers"].as_object().map_or(0, |m| m.len() - 1);
    }
    for imp in &importers {
        for (field, dev) in [("dependencies", false), ("optionalDependencies", false), ("devDependencies", true)] {
            for name in imp.get(field).and_then(Value::as_object).into_iter().flat_map(|m| m.keys()) {
                let e = direct.entry(name.clone()).or_insert(dev);
                *e = *e && dev;
            }
        }
    }
    out.sbom.relationships = !direct.is_empty();
    let packages = root.get("packages").and_then(Value::as_object).ok_or("This pnpm-lock.yaml has no packages")?;
    for (key, p) in packages {
        let Some((key_name, key_version)) = pnpm_key(key) else { continue };
        let name = p.get("name").and_then(Value::as_str).map(String::from).unwrap_or(key_name);
        let version = p.get("version").and_then(Value::as_str).map(String::from).unwrap_or(key_version);
        let res = p.get("resolution");
        let tarball = text(res.and_then(|r| r.get("tarball")));
        let mut c = if res.and_then(|r| r.get("directory")).is_some() {
            out.local += 1;
            continue;
        } else if res.and_then(|r| r.get("repo")).is_some() || text(res.and_then(|r| r.get("type"))) == "git" {
            elsewhere(&name, &version, &text(res.and_then(|r| r.get("repo"))))
        } else if !tarball.is_empty() && npm_elsewhere(&tarball) {
            elsewhere(&name, &version, &tarball)
        } else {
            let mut c = registry("npm", &name, &version);
            c.resolved = tarball;
            c
        };
        c.hashes.extend(Some(text(res.and_then(|r| r.get("integrity")))).filter(|i| !i.is_empty()));
        c.direct = direct.contains_key(&name);
        c.dev = flag(p.get("dev")) || direct.get(&name).copied().unwrap_or(false);
        out.push(c);
    }
    Ok(())
}

/* ───────────────────────────── Rust, Python ───────────────────────────── */

fn crates_io(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index" || source == "sparse+https://index.crates.io/"
}

fn cargo(body: &str, out: &mut Out) -> Result<(), String> {
    let doc = toml_doc(body)?;
    out.sbom.spec_version = tstr(doc.get("version"));
    let packages = doc.get("package").and_then(toml::Value::as_array).ok_or("This Cargo.lock lists no packages")?;
    let mut direct = BTreeSet::new();
    for p in packages.iter().filter(|p| p.get("source").is_none()) {
        if out.sbom.subject.is_empty() {
            out.sbom.subject = tstr(p.get("name"));
        }
        for d in p.get("dependencies").and_then(toml::Value::as_array).into_iter().flatten() {
            direct.insert(tstr(Some(d)).split(' ').next().unwrap_or("").to_string());
        }
    }
    out.sbom.relationships = !direct.is_empty();
    for p in packages {
        let (name, version, source) = (tstr(p.get("name")), tstr(p.get("version")), tstr(p.get("source")));
        if source.is_empty() {
            out.local += 1;
            continue;
        }
        let mut c = if source.starts_with("registry+") || source.starts_with("sparse+") { registry("cargo", &name, &version) } else { elsewhere(&name, &version, &source) };
        c.resolved = if crates_io(&source) { "crates.io".into() } else { source };
        let checksum = tstr(p.get("checksum"));
        if !checksum.is_empty() {
            c.hashes.push(format!("SHA-256:{checksum}"));
        }
        c.direct = direct.contains(&name);
        out.push(c);
    }
    Ok(())
}

fn poetry(body: &str, out: &mut Out) -> Result<(), String> {
    let doc = toml_doc(body)?;
    out.sbom.spec_version = tstr(doc.get("metadata").and_then(|m| m.get("lock-version")));
    for p in doc.get("package").and_then(toml::Value::as_array).into_iter().flatten() {
        let (name, version) = (tstr(p.get("name")), tstr(p.get("version")));
        let source = p.get("source");
        let kind = tstr(source.and_then(|s| s.get("type")));
        let url = tstr(source.and_then(|s| s.get("url")));
        let mut c = match kind.as_str() {
            "directory" | "file" => {
                out.local += 1;
                continue;
            }
            "git" | "url" => elsewhere(&name, &version, &url),
            _ => {
                let mut c = registry("pypi", &name, &version);
                c.resolved = if url.is_empty() { "pypi.org".into() } else { url };
                c
            }
        };
        c.dev = tstr(p.get("category")) == "dev";
        c.hashes.extend(p.get("files").and_then(toml::Value::as_array).and_then(|f| f.first()).map(|f| tstr(f.get("hash"))).filter(|h| !h.is_empty()));
        out.push(c);
    }
    Ok(())
}

fn uv(body: &str, out: &mut Out) -> Result<(), String> {
    let doc = toml_doc(body)?;
    out.sbom.spec_version = tstr(doc.get("version"));
    let packages = doc.get("package").and_then(toml::Value::as_array).ok_or("This uv.lock lists no packages")?;
    let names = |list: Option<&toml::Value>| -> Vec<String> { list.and_then(toml::Value::as_array).into_iter().flatten().map(|d| pep503(&tstr(d.get("name")))).collect() };
    let (mut direct, mut dev) = (BTreeSet::new(), BTreeSet::new());
    for p in packages.iter() {
        let source = p.get("source");
        if ["virtual", "editable"].iter().any(|k| source.and_then(|s| s.get(*k)).is_some_and(|v| tstr(Some(v)) == ".")) {
            out.sbom.subject = tstr(p.get("name"));
            direct.extend(names(p.get("dependencies")));
            for group in p.get("dev-dependencies").and_then(toml::Value::as_table).into_iter().flat_map(|t| t.values()) {
                dev.extend(names(Some(group)));
            }
        }
    }
    out.sbom.relationships = !direct.is_empty() || !dev.is_empty();
    for p in packages {
        let (name, version) = (tstr(p.get("name")), tstr(p.get("version")));
        let source = p.get("source");
        let get = |k: &str| tstr(source.and_then(|s| s.get(k)));
        let mut c = if !get("registry").is_empty() {
            let mut c = registry("pypi", &name, &version);
            c.resolved = get("registry");
            c
        } else if !get("git").is_empty() || !get("url").is_empty() {
            elsewhere(&name, &version, &format!("{}{}", get("git"), get("url")))
        } else {
            out.local += 1;
            continue;
        };
        let hash = tstr(p.get("sdist").and_then(|s| s.get("hash")));
        let hash = if hash.is_empty() { tstr(p.get("wheels").and_then(toml::Value::as_array).and_then(|w| w.first()).and_then(|w| w.get("hash"))) } else { hash };
        c.hashes.extend(Some(hash).filter(|h| !h.is_empty()));
        let key = pep503(&name);
        c.direct = direct.contains(&key) || dev.contains(&key);
        c.dev = dev.contains(&key) && !direct.contains(&key);
        out.push(c);
    }
    Ok(())
}

fn pipfile(body: &str, out: &mut Out) -> Result<(), String> {
    let root = json(body)?;
    let meta = root.get("_meta");
    out.sbom.spec_version = text(meta.and_then(|m| m.get("pipfile-spec")));
    let sources: BTreeMap<String, String> = meta.and_then(|m| m.get("sources")).and_then(Value::as_array).into_iter().flatten().map(|s| (text(s.get("name")), text(s.get("url")))).collect();
    out.sbom.sources = sources.values().cloned().collect();
    for (section, dev) in [("default", false), ("develop", true)] {
        for (name, p) in root.get(section).and_then(Value::as_object).into_iter().flatten() {
            let version = text(p.get("version")).trim_start_matches("==").to_string();
            let mut c = if p.get("path").is_some() || p.get("file").is_some() || (flag(p.get("editable")) && p.get("git").is_none()) {
                out.local += 1;
                continue;
            } else if p.get("git").is_some() {
                elsewhere(name, &text(p.get("ref")), &text(p.get("git")))
            } else {
                let mut c = registry("pypi", name, &version);
                c.resolved = sources.get(&text(p.get("index"))).cloned().unwrap_or_else(|| "pypi.org".into());
                c
            };
            c.dev = dev;
            c.hashes.extend(p.get("hashes").and_then(Value::as_array).and_then(|h| h.first()).map(|h| text(Some(h))));
            out.push(c);
        }
    }
    Ok(())
}

fn requirements(body: &str, out: &mut Out) -> Result<(), String> {
    let joined = body.replace("\\\r\n", " ").replace("\\\n", " ");
    let (mut unpinned, mut included) = (0usize, 0usize);
    for raw in joined.lines() {
        let line = raw.split(" #").next().unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("");
        let option_value = |w: &mut std::str::SplitWhitespace| -> String { first.split_once('=').map(|(_, v)| v.to_string()).unwrap_or_else(|| w.next().unwrap_or("").to_string()) };
        match first.split('=').next().unwrap_or("") {
            "-i" | "--index-url" => {
                out.sbom.sources.push(format!("index-url {}", option_value(&mut words)));
                continue;
            }
            "--extra-index-url" => {
                out.sbom.sources.push(format!("extra-index-url {}", option_value(&mut words)));
                continue;
            }
            "-r" | "--requirement" | "-c" | "--constraint" => {
                included += 1;
                continue;
            }
            "-e" | "--editable" => {
                let target = option_value(&mut words);
                let egg = target.split("#egg=").nth(1).unwrap_or("").split('&').next().unwrap_or("").to_string();
                if target.starts_with("git+") || target.contains("://") {
                    out.push(elsewhere(if egg.is_empty() { &target } else { &egg }, "", &target));
                } else {
                    out.local += 1;
                }
                continue;
            }
            o if o.starts_with('-') => continue,
            _ => {}
        }
        let req = line.split(';').next().unwrap_or(line).split(" --").next().unwrap_or(line).trim();
        if let Some((name, url)) = req.split_once(" @ ") {
            out.push(elsewhere(name.split('[').next().unwrap_or(name).trim(), "", url.trim()));
            continue;
        }
        let pinned = req.split_once("===").or_else(|| req.split_once("=="));
        match pinned {
            Some((name, version)) if !version.contains(['*', ',', '<', '>', '!', '~']) => {
                let name = name.split('[').next().unwrap_or(name).trim();
                let mut c = registry("pypi", name, version.trim());
                c.resolved = "pypi.org".into();
                out.push(c);
            }
            _ => unpinned += 1,
        }
    }
    match unpinned {
        0 => {}
        1 => out.sbom.warnings.push("1 requirement is not pinned to one version (==) and was left out; a lockfile or pip freeze output lists exact versions".into()),
        n => out.sbom.warnings.push(format!("{n} requirements are not pinned to one version (==) and were left out; a lockfile or pip freeze output lists exact versions")),
    }
    match included {
        0 => {}
        1 => out.sbom.warnings.push("1 included requirement or constraint file (-r, -c) was not read; import it separately".into()),
        n => out.sbom.warnings.push(format!("{n} included requirement or constraint files (-r, -c) were not read; import them separately")),
    }
    Ok(())
}

/* ───────────────────────────── PHP, Ruby, Go, .NET, Java ───────────────────────────── */

fn composer(body: &str, out: &mut Out) -> Result<(), String> {
    let root = json(body)?;
    for (section, dev) in [("packages", false), ("packages-dev", true)] {
        for p in root.get(section).and_then(Value::as_array).into_iter().flatten() {
            let name = text(p.get("name"));
            let raw = text(p.get("version"));
            if text(p.get("dist").and_then(|d| d.get("type"))) == "path" {
                out.local += 1;
                continue;
            }
            let version = match raw.strip_prefix('v') {
                Some(v) if v.starts_with(|c: char| c.is_ascii_digit()) => v.to_string(),
                _ => raw.clone(),
            };
            let mut c = if version.starts_with("dev-") { elsewhere(&name, &version, &text(p.get("source").and_then(|s| s.get("url")))) } else { registry("composer", &name, &version) };
            c.dev = dev;
            if c.resolved.is_empty() {
                c.resolved = text(p.get("dist").and_then(|d| d.get("url")));
            }
            c.licenses.extend(p.get("license").and_then(Value::as_array).into_iter().flatten().map(|l| text(Some(l))).filter(|l| !l.is_empty()));
            out.push(c);
        }
    }
    if out.sbom.components.is_empty() {
        return Err("This composer.lock lists no packages".into());
    }
    Ok(())
}

fn gemfile(body: &str, out: &mut Out) -> Result<(), String> {
    let (mut section, mut remote) = (String::new(), String::new());
    let mut direct = BTreeSet::new();
    let mut checksums: BTreeMap<String, String> = BTreeMap::new();
    let mut specs: Vec<(String, String, String, String)> = Vec::new(); // section, remote, name, version
    for line in body.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            section = line.trim().to_string();
            remote.clear();
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        match (section.as_str(), indent) {
            ("GEM" | "GIT" | "PATH", 2) => {
                if let Some(r) = t.strip_prefix("remote:") {
                    // copied into every spec of the section, so bounded
                    remote = r.trim().chars().take(2_048).collect();
                    if section == "GEM" {
                        out.sbom.sources.push(remote.clone());
                    }
                }
            }
            ("GEM" | "GIT" | "PATH", 4) => {
                if let Some((name, rest)) = t.split_once(" (") {
                    specs.push((section.clone(), remote.clone(), name.to_string(), rest.trim_end_matches(')').to_string()));
                }
            }
            ("DEPENDENCIES", 2) => {
                direct.insert(t.split([' ', '!']).next().unwrap_or("").to_string());
            }
            ("CHECKSUMS", 2) => {
                if let Some((spec, sum)) = t.split_once(") ") {
                    checksums.insert(format!("{spec})"), sum.to_string());
                }
            }
            _ => {}
        }
    }
    out.sbom.relationships = !direct.is_empty();
    for (section, remote, name, full) in specs {
        // "1.13.10-x86_64-linux": the platform after the version
        let version = full.split('-').next().unwrap_or(&full).to_string();
        let mut c = match section.as_str() {
            "PATH" => {
                out.local += 1;
                continue;
            }
            "GIT" => elsewhere(&name, &version, &remote),
            _ => {
                let mut c = registry("gem", &name, &version);
                c.resolved = remote.clone();
                c
            }
        };
        c.hashes.extend(checksums.get(&format!("{name} ({full})")).cloned());
        c.direct = direct.contains(&name);
        out.push(c);
    }
    if out.sbom.components.is_empty() {
        return Err("No gems found in this Gemfile.lock".into());
    }
    Ok(())
}

fn gomod(body: &str, out: &mut Out) -> Result<(), String> {
    let mut requires: Vec<(String, String, bool)> = Vec::new();
    let mut replaces: BTreeMap<String, (String, String)> = BTreeMap::new(); // "path" or "path@version" → (new path, new version)
    let mut block = "";
    for raw in body.lines() {
        let (code, comment) = raw.split_once("//").unwrap_or((raw, ""));
        let line = code.trim();
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = "";
            continue;
        }
        let (directive, rest) = match line.split_once(char::is_whitespace) {
            Some((d, r)) if block.is_empty() => (d, r.trim()),
            _ if !block.is_empty() => (block, line),
            _ => (line, ""),
        };
        if rest == "(" {
            block = match directive {
                "require" => "require",
                "replace" => "replace",
                _ => "other",
            };
            continue;
        }
        match directive {
            "module" => out.sbom.subject = rest.trim_matches('"').to_string(),
            "require" => {
                let mut w = rest.split_whitespace();
                if let (Some(path), Some(version)) = (w.next(), w.next()) {
                    requires.push((path.to_string(), version.to_string(), comment.trim() == "indirect"));
                }
            }
            "replace" => {
                if let Some((old, new)) = rest.split_once("=>") {
                    let mut o = old.split_whitespace();
                    let mut n = new.split_whitespace();
                    let key = match (o.next(), o.next()) {
                        (Some(p), Some(v)) => format!("{p}@{v}"),
                        (Some(p), None) => p.to_string(),
                        _ => continue,
                    };
                    replaces.insert(key, (n.next().unwrap_or("").to_string(), n.next().unwrap_or("").to_string()));
                }
            }
            _ => {}
        }
    }
    out.sbom.relationships = true;
    for (path, version, indirect) in requires {
        let replaced = replaces.get(&format!("{path}@{version}")).or_else(|| replaces.get(&path));
        let mut c = match replaced {
            Some((target, _)) if target.starts_with('.') || target.starts_with('/') || target.contains('\\') => elsewhere(&path, &version, &format!("replaced by {target}")),
            Some((target, v)) if !v.is_empty() => {
                let mut c = registry("golang", target, v);
                c.resolved = format!("replaces {path}@{version}");
                c
            }
            _ => registry("golang", &path, &version),
        };
        c.direct = !indirect;
        out.push(c);
    }
    if out.sbom.components.is_empty() {
        return Err("This go.mod requires no modules".into());
    }
    Ok(())
}

fn nuget(body: &str, out: &mut Out) -> Result<(), String> {
    let root = json(body)?;
    out.sbom.spec_version = text(root.get("version"));
    let frameworks = root.get("dependencies").and_then(Value::as_object).ok_or("This packages.lock.json has no dependencies")?;
    out.sbom.relationships = true;
    for deps in frameworks.values().filter_map(Value::as_object) {
        for (name, d) in deps {
            let kind = text(d.get("type"));
            if kind.eq_ignore_ascii_case("project") {
                out.local += 1;
                continue;
            }
            let mut c = registry("nuget", name, &text(d.get("resolved")));
            c.direct = kind.eq_ignore_ascii_case("direct");
            c.hashes.extend(Some(text(d.get("contentHash"))).filter(|h| !h.is_empty()));
            out.push(c);
        }
    }
    Ok(())
}

fn gradle(body: &str, out: &mut Out) -> Result<(), String> {
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        let (coords, configs) = line.split_once('=').unwrap_or((line, ""));
        let parts: Vec<&str> = coords.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        let mut c = registry("maven", &format!("{}:{}", parts[0], parts[1]), parts[2]);
        c.dev = !configs.is_empty() && configs.split(',').all(|k| k.to_ascii_lowercase().contains("test"));
        out.push(c);
    }
    if out.sbom.components.is_empty() {
        return Err("No dependencies found in this Gradle lockfile".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "lockfiles_tests.rs"]
mod tests;
