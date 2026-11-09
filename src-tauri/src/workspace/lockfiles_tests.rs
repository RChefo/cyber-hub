use super::*;
use crate::workspace::sbom::{audit, parse_file, Issue};

fn read(name: &str, text: &str) -> Sbom {
    parse_file(name, text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn find<'a>(s: &'a Sbom, name: &str) -> &'a Component {
    s.components.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("{name} not in {:?}", s.components.iter().map(|c| c.label()).collect::<Vec<_>>()))
}

fn ids(issues: &[Issue]) -> Vec<&str> {
    issues.iter().map(|i| i.id.as_str()).collect()
}

#[test]
fn file_names_pick_the_parser() {
    assert_eq!(kind_of("C:\\repo\\package-lock.json"), Some("npm"));
    assert_eq!(kind_of("web/pnpm-lock.yaml"), Some("pnpm"));
    assert_eq!(kind_of("requirements-dev.txt"), Some("requirements"));
    assert_eq!(kind_of("Gemfile.lock"), Some("gemfile"));
    assert_eq!(kind_of("bom.json"), None);
    assert_eq!(kind_of("notes.txt"), None);
    // anything else is read as an SBOM
    let cdx = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"x","version":"1","purl":"pkg:npm/x@1"}]}"#;
    assert_eq!(read("bom.json", cdx).format, "cyclonedx-json");
}

const NPM_V3: &str = r#"{
  "name": "shop", "version": "1.2.0", "lockfileVersion": 3,
  "packages": {
    "": { "name": "shop", "dependencies": { "lodash": "^4.17.20", "@babel/core": "7.12.3", "forked": "github:me/forked" }, "devDependencies": { "minimist": "1.2.5" } },
    "node_modules/lodash": { "version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "integrity": "sha512-abc", "license": "MIT" },
    "node_modules/@babel/core": { "version": "7.12.3", "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.12.3.tgz", "integrity": "sha512-def" },
    "node_modules/minimist": { "version": "1.2.5", "resolved": "http://npm.internal.example/minimist/-/minimist-1.2.5.tgz", "dev": true },
    "node_modules/forked": { "version": "2.0.0", "resolved": "git+ssh://git@github.com/me/forked.git#0123abcd" },
    "node_modules/@babel/core/node_modules/semver": { "version": "5.7.1", "resolved": "https://registry.npmjs.org/semver/-/semver-5.7.1.tgz", "integrity": "sha512-ghi" },
    "node_modules/aliased": { "name": "real-name", "version": "3.0.0", "resolved": "https://registry.npmjs.org/real-name/-/real-name-3.0.0.tgz", "integrity": "sha512-jkl" },
    "packages/ui": { "name": "@shop/ui", "version": "0.0.1" },
    "node_modules/@shop/ui": { "resolved": "packages/ui", "link": true }
  }
}"#;

#[test]
fn npm_lockfiles_give_package_urls_flags_and_supply_chain_issues() {
    let s = read("package-lock.json", NPM_V3);
    assert_eq!((s.format.as_str(), s.spec_version.as_str(), s.subject.as_str()), ("lockfile-npm", "3", "shop@1.2.0"));
    assert_eq!(s.components.len(), 6, "the workspace member and its link are left out");
    let lodash = find(&s, "lodash");
    assert_eq!((lodash.purl.as_str(), lodash.ecosystem.as_str(), lodash.direct, lodash.dev), ("pkg:npm/lodash@4.17.20", "npm", true, false));
    assert_eq!((lodash.licenses.clone(), lodash.license_risk.as_str()), (vec!["MIT".to_string()], "permissive"));
    assert_eq!(find(&s, "@babel/core").purl, "pkg:npm/%40babel/core@7.12.3");
    let semver = find(&s, "semver");
    assert!(!semver.direct, "nested under @babel/core");
    assert!(find(&s, "minimist").dev && find(&s, "minimist").direct);
    assert_eq!(find(&s, "real-name").purl, "pkg:npm/real-name@3.0.0", "an alias is checked under its real name");
    let forked = find(&s, "forked");
    assert!(forked.purl.is_empty() && forked.resolved.starts_with("git+ssh://"));
    assert!(s.warnings.iter().any(|w| w.starts_with("1 of the project's own packages")), "{:?}", s.warnings);

    let issues = audit(&s);
    let got = ids(&issues);
    for id in ["LOCK-HTTP", "LOCK-NO-INTEGRITY", "LOCK-NON-REGISTRY", "LOCK-MIXED-REGISTRIES"] {
        assert!(got.contains(&id), "{id} in {got:?}");
    }
    for id in ["SBOM-NO-SUPPLIER", "SBOM-NO-AUTHOR", "SBOM-NO-RELATIONSHIPS", "SBOM-NO-IDENTIFIER"] {
        assert!(!got.contains(&id), "{id}: a lockfile is not an SBOM");
    }
    let issue = |id: &str| issues.iter().find(|i| i.id == id).unwrap();
    assert_eq!(issue("LOCK-HTTP").components, vec!["minimist@1.2.5"]);
    assert_eq!(issue("LOCK-NO-INTEGRITY").components, vec!["minimist@1.2.5"]);
    assert_eq!(issue("LOCK-MIXED-REGISTRIES").components, vec!["npm.internal.example", "registry.npmjs.org"]);
    assert_eq!(issue("LOCK-HTTP").severity, "high");
    assert!(issue("LOCK-NON-REGISTRY").components.contains(&"forked@2.0.0".to_string()));
}

#[test]
fn npm_v1_trees_and_yarn_lockfiles() {
    let v1 = r#"{"name":"old","lockfileVersion":1,"dependencies":{
        "a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha1-x","dependencies":{
            "b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz","integrity":"sha1-y","dev":true}}},
        "b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz","integrity":"sha1-y"}}}"#;
    let s = read("npm-shrinkwrap.json", v1);
    assert_eq!(s.components.iter().map(Component::label).collect::<Vec<_>>(), vec!["a@1.0.0", "b@2.0.0"], "nested copies of the same version count once");

    let classic = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.10.4\":\n  version \"7.12.13\"\n  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dad\"\n  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==\n  dependencies:\n    \"@babel/highlight\" \"^7.12.13\"\n\nlodash@^4.17.20:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679\"\n  integrity sha512-v2kD\n\nold-thing@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/old-thing/-/old-thing-1.0.0.tgz#123\"\n";
    let y = read("yarn.lock", classic);
    assert_eq!((y.format.as_str(), y.components.len()), ("lockfile-yarn", 3));
    assert_eq!(find(&y, "@babel/code-frame").purl, "pkg:npm/%40babel/code-frame@7.12.13");
    let issues = audit(&y);
    assert_eq!(issues.iter().find(|i| i.id == "LOCK-NO-INTEGRITY").map(|i| i.components.clone()), Some(vec!["old-thing@1.0.0".to_string()]));
    assert!(!ids(&issues).contains(&"LOCK-MIXED-REGISTRIES"), "registry.yarnpkg.com is the npm registry");

    let berry = "__metadata:\n  version: 6\n  cacheKey: 8\n\n\"lodash@npm:^4.17.20\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n  checksum: eb835a2e51d381e561e508ce932ea50a8e5a68f4ebdd771ea240d3048244a8d13658acbd502cd4829768c56f2e16bdd4340b9ea141297d472517b83868e677f7\n  languageName: node\n  linkType: hard\n\n\"shop@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"shop@workspace:.\"\n  languageName: unknown\n  linkType: soft\n\n\"left-pad@patch:left-pad@npm%3A1.3.0#~/.yarn/patches/left-pad.patch::version=1.3.0&hash=abc\":\n  version: 1.3.0\n  resolution: \"left-pad@patch:left-pad@npm%3A1.3.0#~/.yarn/patches/left-pad.patch::version=1.3.0&hash=abc\"\n  checksum: 1\n  languageName: node\n  linkType: hard\n";
    let b = read("yarn.lock", berry);
    assert_eq!(b.spec_version, "6");
    assert_eq!(b.components.iter().map(|c| c.purl.as_str()).collect::<Vec<_>>(), vec!["pkg:npm/left-pad@1.3.0", "pkg:npm/lodash@4.17.21"]);
    assert!(b.warnings.iter().any(|w| w.starts_with("1 of the project's own packages")));
}

#[test]
fn pnpm_keys_of_every_lockfile_version() {
    assert_eq!(pnpm_key("/lodash/4.17.21"), Some(("lodash".into(), "4.17.21".into())));
    assert_eq!(pnpm_key("/@babel/core/7.12.3_@babel+x@1.0.0"), Some(("@babel/core".into(), "7.12.3".into())));
    assert_eq!(pnpm_key("/foo/1.0.0_bar@2.0.0"), Some(("foo".into(), "1.0.0".into())));
    assert_eq!(pnpm_key("/@babel/core@7.12.3(supports-color@8.1.1)"), Some(("@babel/core".into(), "7.12.3".into())));
    assert_eq!(pnpm_key("lodash@4.17.21"), Some(("lodash".into(), "4.17.21".into())));
    let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.20\n        version: 4.17.20\n    devDependencies:\n      minimist:\n        specifier: 1.2.5\n        version: 1.2.5\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==}\n\n  minimist@1.2.5:\n    resolution: {integrity: sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==}\n\n  private-lib@1.0.0:\n    resolution: {integrity: sha512-xyz, tarball: https://npm.internal.example/private-lib/-/private-lib-1.0.0.tgz}\n\n  forked@2.0.0:\n    resolution: {type: git, repo: https://github.com/me/forked, commit: 0123abcd}\n";
    let s = read("pnpm-lock.yaml", v9);
    assert_eq!((s.spec_version.as_str(), s.components.len()), ("9.0", 4));
    let minimist = find(&s, "minimist");
    assert!(minimist.direct && minimist.dev && minimist.purl == "pkg:npm/minimist@1.2.5");
    assert!(!find(&s, "private-lib").direct);
    assert!(find(&s, "forked").purl.is_empty());
    let issues = audit(&s);
    assert_eq!(issues.iter().find(|i| i.id == "LOCK-MIXED-REGISTRIES").map(|i| i.components.clone()), Some(vec!["npm.internal.example".to_string(), "registry.npmjs.org".to_string()]), "the default registry has no tarball address in pnpm");
}

#[test]
fn rust_and_python_lockfiles() {
    let cargo_lock = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n \"tokio 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"\n\n[[package]]\nname = \"patched\"\nversion = \"0.3.0\"\nsource = \"git+https://github.com/me/patched?branch=main#0123abcd\"\n";
    let c = read("Cargo.lock", cargo_lock);
    assert_eq!((c.format.as_str(), c.subject.as_str(), c.components.len()), ("lockfile-cargo", "app", 3));
    let serde = find(&c, "serde");
    assert_eq!((serde.purl.as_str(), serde.direct, serde.hashes.len()), ("pkg:cargo/serde@1.0.200", true, 1));
    assert!(find(&c, "tokio").direct, "a dependency written with its version and source");
    assert!(find(&c, "patched").purl.is_empty());
    let got = audit(&c);
    assert_eq!(got.iter().find(|i| i.id == "LOCK-NO-INTEGRITY").map(|i| i.components.clone()), Some(vec!["tokio@1.0.0".to_string()]));
    assert!(!ids(&got).contains(&"LOCK-MIXED-REGISTRIES"), "the git index and the sparse index are both crates.io");

    let poetry = "[[package]]\nname = \"Django\"\nversion = \"3.2.0\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.6\"\nfiles = [\n    {file = \"Django-3.2-py3-none-any.whl\", hash = \"sha256:0604e84c4fb698a5e53e5857b5aea945b2f19a18f25f10b8748dbdf935788927\"},\n]\n\n[[package]]\nname = \"pytest\"\nversion = \"6.2.2\"\ncategory = \"dev\"\nfiles = []\n\n[[package]]\nname = \"internal-tool\"\nversion = \"0.1.0\"\nfiles = []\n\n[package.source]\ntype = \"git\"\nurl = \"https://git.example/internal-tool.git\"\nreference = \"main\"\n\n[metadata]\nlock-version = \"2.0\"\n";
    let p = read("poetry.lock", poetry);
    assert_eq!(find(&p, "Django").purl, "pkg:pypi/django@3.2.0", "PEP 503 names");
    assert!(find(&p, "pytest").dev);
    assert!(find(&p, "internal-tool").purl.is_empty());

    let uv_lock = "version = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n    { name = \"requests\" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = \"pytest\" },\n]\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/r.tar.gz\", hash = \"sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1\" }\n\n[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [\n    { url = \"https://files.pythonhosted.org/p.whl\", hash = \"sha256:50fb9cbe836c3f20f0dfa99c565201fb75dc54c8d76373cd1bde06b06657bdb6\" },\n]\n";
    let u = read("uv.lock", uv_lock);
    assert_eq!((u.subject.as_str(), u.components.len()), ("demo", 2));
    assert!(find(&u, "requests").direct && !find(&u, "requests").dev);
    assert!(find(&u, "pytest").dev);
    assert!(audit(&u).iter().all(|i| i.id != "LOCK-NO-INTEGRITY"));

    let pipfile = r#"{"_meta":{"pipfile-spec":6,"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},
        "default":{"requests":{"hashes":["sha256:abc"],"index":"pypi","version":"==2.25.1"},"mylib":{"editable":true,"path":"."}},
        "develop":{"black":{"hashes":["sha256:def"],"version":"==22.3.0"},"tool":{"git":"https://github.com/me/tool.git","ref":"0123abcd"}}}"#;
    let pf = read("Pipfile.lock", pipfile);
    assert_eq!(find(&pf, "requests").purl, "pkg:pypi/requests@2.25.1");
    assert!(find(&pf, "black").dev && find(&pf, "tool").purl.is_empty());

    let reqs = "--index-url https://pypi.org/simple\n--extra-index-url https://pkgs.internal.example/simple\n-r base.txt\nDjango==3.2.0 \\\n    --hash=sha256:0604e84c\nrequests[security]>=2.0\nurllib3===1.26.4 ; python_version >= \"3.6\"\nflask\n-e git+https://github.com/me/tool.git#egg=tool\nmylib @ https://example.com/mylib-1.0.tar.gz\n# a comment\n";
    let r = read("requirements.txt", reqs);
    assert_eq!(r.components.iter().map(|c| c.label()).collect::<Vec<_>>(), vec!["Django@3.2.0", "urllib3@1.26.4", "tool", "mylib"], "names as written");
    assert_eq!(find(&r, "Django").purl, "pkg:pypi/django@3.2.0", "the package URL is normalized");
    assert!(r.warnings.iter().any(|w| w.starts_with("2 requirements are not pinned")), "{:?}", r.warnings);
    assert!(r.warnings.iter().any(|w| w.starts_with("1 included requirement")));
    let issues = audit(&r);
    assert!(ids(&issues).contains(&"LOCK-EXTRA-INDEX"));
    assert_eq!(issues.iter().find(|i| i.id == "LOCK-EXTRA-INDEX").unwrap().severity, "medium");
}

#[test]
fn php_ruby_go_dotnet_and_java_lockfiles() {
    let composer = r#"{"content-hash":"x","packages":[
        {"name":"symfony/http-kernel","version":"v5.4.3","dist":{"type":"zip","url":"https://api.github.com/repos/symfony/http-kernel/zipball/abc","shasum":""},"license":["MIT"]},
        {"name":"acme/branch","version":"dev-main","source":{"type":"git","url":"https://github.com/acme/branch.git"}},
        {"name":"acme/local","version":"1.0.0","dist":{"type":"path","url":"../local"}}],
        "packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0","license":["BSD-3-Clause"]}]}"#;
    let c = read("composer.lock", composer);
    assert_eq!(find(&c, "symfony/http-kernel").purl, "pkg:composer/symfony/http-kernel@5.4.3");
    assert!(find(&c, "acme/branch").purl.is_empty(), "a branch is not a version");
    assert!(find(&c, "phpunit/phpunit").dev);
    assert_eq!(c.components.len(), 3);

    let gemfile = "GIT\n  remote: https://github.com/me/forked-gem.git\n  revision: 0123abcd\n  specs:\n    forked-gem (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.10-x86_64-linux)\n      racc (~> 1.4)\n    racc (1.6.2)\n    rails (7.0.4)\n\nPATH\n  remote: .\n  specs:\n    myapp (0.1.0)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  forked-gem!\n  rails (~> 7.0)\n\nCHECKSUMS\n  racc (1.6.2) sha256=58d26b3666382396fea84d33dc0639b7ee8d704156a52ceb180c15886c3d8ad1\n\nBUNDLED WITH\n   2.5.6\n";
    let g = read("Gemfile.lock", gemfile);
    assert_eq!(find(&g, "nokogiri").purl, "pkg:gem/nokogiri@1.13.10", "the platform is not part of the version");
    assert!(find(&g, "rails").direct && !find(&g, "racc").direct);
    assert_eq!(find(&g, "racc").hashes.len(), 1);
    assert!(find(&g, "forked-gem").purl.is_empty());
    assert_eq!(g.components.len(), 4);

    let gomod = "module example.com/shop\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/old/lib v1.0.0\n\texample.com/local v0.0.0\n)\n\nrequire github.com/single/dep v0.2.0+incompatible\n\nreplace github.com/old/lib => github.com/new/lib v1.1.0\n\nreplace example.com/local => ../local\n";
    let m = read("go.mod", gomod);
    assert_eq!(m.subject, "example.com/shop");
    assert_eq!(find(&m, "github.com/gin-gonic/gin").purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.0");
    assert!(!find(&m, "golang.org/x/net").direct);
    assert_eq!(find(&m, "github.com/new/lib").purl, "pkg:golang/github.com/new/lib@v1.1.0", "the replacement is what gets built");
    assert!(find(&m, "example.com/local").purl.is_empty());
    assert_eq!(find(&m, "github.com/single/dep").purl, "pkg:golang/github.com/single/dep@v0.2.0%2Bincompatible");

    let nuget = r#"{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A=="},"System.Text.Json":{"type":"Transitive","resolved":"4.7.2","contentHash":"x"},"Shop.Core":{"type":"Project"}},
        "net7.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1","contentHash":"ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A=="}}}}"#;
    let n = read("packages.lock.json", nuget);
    assert_eq!(n.components.len(), 2, "one entry per package across target frameworks");
    assert!(find(&n, "Newtonsoft.Json").direct);

    let gradle = "# This is a Gradle generated file for dependency locking.\ncom.fasterxml.jackson.core:jackson-databind:2.13.0=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n";
    let gl = read("gradle.lockfile", gradle);
    let jackson = find(&gl, "jackson-databind");
    assert_eq!((jackson.group.as_str(), jackson.purl.as_str(), jackson.label()), ("com.fasterxml.jackson.core", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "com.fasterxml.jackson.core/jackson-databind@2.13.0".to_string()));
    assert!(find(&gl, "junit").dev);
}

#[test]
fn damaged_lockfiles_are_refused_with_a_reason() {
    assert!(parse_file("package-lock.json", "{not json").unwrap_err().contains("not valid JSON"));
    assert!(parse_file("Cargo.lock", "[[package]\nname=").unwrap_err().contains("not valid TOML"));
    assert!(parse_file("go.mod", "module x\n").is_err());
    assert!(parse_file("yarn.lock", "# yarn lockfile v1\n").is_err());
}

/// Cyber Hub's own lockfiles: real files with hundreds of packages.
#[test]
fn the_repository_lockfiles_parse() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let c = read("Cargo.lock", &cargo_lock);
    assert!(c.components.len() > 300, "{} crates", c.components.len());
    assert!(c.components.iter().all(|x| x.purl.starts_with("pkg:cargo/") && x.ecosystem == "cargo"));
    assert!(c.components.iter().any(|x| x.name == "serde" && x.direct));
    assert!(audit(&c).iter().all(|i| i.id != "LOCK-HTTP" && i.id != "LOCK-NO-INTEGRITY"), "every crates.io package has a checksum");
    if let Ok(npm_lock) = std::fs::read_to_string(root.join("../package-lock.json")) {
        let n = read("package-lock.json", &npm_lock);
        assert!(n.components.len() > 100, "{} packages", n.components.len());
        assert!(n.components.iter().all(|x| !x.purl.is_empty()), "every package comes from the registry");
        assert!(n.components.iter().any(|x| x.name == "react" && x.direct && !x.dev));
        assert!(n.components.iter().any(|x| x.dev));
    }
}
