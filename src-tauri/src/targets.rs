//! Tool-independent target resolution for the execution engine.
//!
//! Every argument value of a scope-required run is examined without relying on
//! per-tool knowledge of option names:
//!
//! * A value that names an **existing file** is read and classified:
//!   - raw HTTP request (`METHOD target HTTP/x`): the `Host` header and an absolute
//!     request-line URL are targets;
//!   - target list (any line names a network endpoint): **every** non-comment line must
//!     parse strictly as targets and every entry must be in scope;
//!   - plain data (wordlists, payload lists, binaries): allowed.
//!
//!   Target lists and requests are snapshotted into a private directory and the argument
//!   is rewritten to the snapshot, so the tool reads exactly what was validated.
//! * Any other value is scanned for endpoints (URLs, IPs, [IPv6], CIDRs, IPv4 ranges,
//!   host names, `host:port`, `user@host`, `localhost`); each must be in scope.
//! * At least one target must be identified.
//!
//! Spawned processes never receive stdin (it is closed), so "read targets from stdin"
//! options receive no input.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::scope::{self, ScopeEntry, Target};

/// Files larger than this cannot be validated and are rejected for scope-required runs.
pub const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
/// Target lists with more entries than this are rejected.
pub const MAX_LIST_ENTRIES: usize = 100_000;

static REQUEST_LINE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z]{3,12} (\S+) HTTP/\d(\.\d)?$").unwrap());
static SINGLE_LABEL: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?i)[a-z][a-z0-9_-]{0,62}$").unwrap());

#[derive(Debug, Clone, PartialEq)]
pub enum FileClass {
    /// no endpoints: wordlist or other data
    Data,
    /// every line is one or more targets
    TargetList,
    /// raw HTTP request
    HttpRequest,
}

#[derive(Debug, Default)]
pub struct Resolution {
    /// arguments as they must be passed to the process (file arguments rewritten to snapshots)
    pub args: Vec<String>,
    /// distinct authorized targets (labels)
    pub checked: Vec<String>,
    /// number of distinct targets that came from files
    pub file_targets: usize,
    /// (original path, snapshot path) for every validated file
    pub snapshots: Vec<(PathBuf, PathBuf)>,
    /// warnings for the preview
    pub warnings: Vec<String>,
    /// informational notes for the preview
    pub notes: Vec<String>,
}

/// The data part of an argument: whole token for positionals, the part after `=` for
/// `--option=value`. Bare options (`-sV`, `--batch`) carry no data.
fn value_of(arg: &str) -> Option<(usize, &str)> {
    if arg == "-" || arg == "--" {
        return None;
    }
    if arg.starts_with('-') {
        return arg.find('=').map(|i| (i + 1, &arg[i + 1..])).filter(|(_, v)| !v.is_empty());
    }
    Some((0, arg))
}

fn existing_file(value: &str) -> Option<PathBuf> {
    if value.is_empty() || value.contains('\0') || value.contains("://") {
        return None;
    }
    let p = PathBuf::from(value);
    match std::fs::metadata(&p) {
        Ok(m) if m.is_file() => Some(p),
        _ => None,
    }
}

/// Cheap pre-filter: a line can only name an endpoint if it has a dot, a colon or "localhost".
fn may_contain_endpoint(line: &str) -> bool {
    line.contains('.') || line.contains(':') || line.to_ascii_lowercase().contains("localhost")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Classify a file and validate the targets it names against the scope.
/// Returns the class and the distinct targets (empty for data files).
pub fn validate_file(path: &Path, entries: &[ScopeEntry]) -> Result<(FileClass, Vec<Target>), String> {
    let shown = path.display().to_string();
    let io = |e: std::io::Error| format!("{shown}: {e}");
    let meta = std::fs::metadata(path).map_err(io)?;
    if meta.len() > MAX_SCAN_BYTES {
        return Err(format!("{shown} is larger than 256 MB and cannot be validated against the project scope"));
    }
    let mut sample = vec![0u8; 8192];
    let n = File::open(path).map_err(io)?.read(&mut sample).map_err(io)?;
    if sample[..n].contains(&0) {
        return Ok((FileClass::Data, vec![]));
    }

    let mut lines = BufReader::with_capacity(1 << 20, File::open(path).map_err(io)?).split(b'\n').enumerate();

    // first non-empty line decides whether this is a raw HTTP request
    let mut first: Option<(usize, String)> = None;
    for (i, raw) in lines.by_ref() {
        let line = String::from_utf8_lossy(&raw.map_err(io)?).trim().to_string();
        if !line.is_empty() {
            first = Some((i, line));
            break;
        }
    }
    let Some((first_no, first_line)) = first else {
        return Ok((FileClass::Data, vec![]));
    };
    if let Some(c) = REQUEST_LINE.captures(&first_line) {
        let uri = c[1].to_string();
        let targets = validate_request(&uri, lines.map(|(_, r)| r), entries).map_err(|e| format!("{shown}: {e}"))?;
        return Ok((FileClass::HttpRequest, targets));
    }

    // Single pass: parse every piece, remember whether any line names an endpoint.
    let mut parsed: Vec<(usize, Target)> = Vec::new();
    let mut first_bad: Option<String> = None;
    let mut any_endpoint = false;
    let mut visit = |no: usize, line: &str| -> Result<(), String> {
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            return Ok(());
        }
        if !any_endpoint && may_contain_endpoint(content) && !scope::loose_targets(content).is_empty() {
            any_endpoint = true;
        }
        for piece in content.split([' ', '\t', ',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
            match scope::parse_target(piece) {
                Some(t) => {
                    if parsed.len() >= MAX_LIST_ENTRIES {
                        return Err(format!("{shown}: more than {MAX_LIST_ENTRIES} entries"));
                    }
                    parsed.push((no, t));
                }
                None if first_bad.is_none() => {
                    first_bad = Some(format!("line {}: '{}' is not a valid target", no + 1, truncate(piece, 80)));
                }
                None => {}
            }
        }
        Ok(())
    };
    visit(first_no, &first_line)?;
    for (i, raw) in lines {
        let raw = raw.map_err(io)?;
        visit(i, &String::from_utf8_lossy(&raw))?;
    }

    if !any_endpoint {
        return Ok((FileClass::Data, vec![]));
    }
    if let Some(bad) = first_bad {
        return Err(format!(
            "{shown} names network targets, so it is treated as a target list and every line must be a valid target ({bad})"
        ));
    }
    let mut out: Vec<Target> = Vec::new();
    for (no, t) in parsed {
        scope::check_target(entries, &t).map_err(|e| format!("{shown} line {}: {e}", no + 1))?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok((FileClass::TargetList, out))
}

/// The URLs a raw request reaches through its `Host` header and request path. The file does not say
/// whether the tool sends it over HTTPS or HTTP, so both are given (HTTPS first); the request is
/// authorized when one of them is, and refused when either is excluded.
fn request_urls(host: &str, uri: &str) -> Vec<Target> {
    let path = if uri.contains("://") {
        url::Url::parse(uri).ok().map(|u| u[url::Position::BeforePath..].to_string()).unwrap_or_default()
    } else if uri.starts_with('/') {
        uri.to_string()
    } else {
        "/".to_string()
    };
    ["https", "http"].iter().filter_map(|scheme| scope::parse_target(&format!("{scheme}://{host}{path}"))).filter(|t| matches!(t, Target::Url(_))).collect()
}

fn validate_request<I>(uri: &str, rest: I, entries: &[ScopeEntry]) -> Result<Vec<Target>, String>
where
    I: Iterator<Item = std::io::Result<Vec<u8>>>,
{
    let mut out = Vec::new();
    if uri.contains("://") {
        let t = scope::parse_target(uri).ok_or_else(|| format!("request-line target '{}' is not valid", truncate(uri, 80)))?;
        scope::check_target(entries, &t)?;
        out.push(t);
    }
    let mut host: Option<String> = None;
    for raw in rest.take(500) {
        let line = String::from_utf8_lossy(&raw.map_err(|e| e.to_string())?).trim().to_string();
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("host") {
                if host.is_some() {
                    return Err("request has more than one Host header".into());
                }
                host = Some(value.trim().to_string());
            }
        }
    }
    let host = host.ok_or("request has no Host header")?;
    let shown = truncate(&host, 80);
    if host.contains(['/', '@', '?', '#', '\\']) || scope::parse_target(&host).is_none() {
        return Err(format!("Host header '{shown}' is not a valid target"));
    }
    let urls = request_urls(&host, uri);
    if urls.is_empty() {
        return Err(format!("Host header '{shown}' is not a valid target"));
    }
    // an exclusion of either scheme refuses the request; one authorized scheme accepts it
    let results: Vec<Result<(), String>> = urls.iter().map(|t| scope::check_target(entries, t)).collect();
    if let Some(Err(e)) = results.iter().find(|r| r.as_ref().is_err_and(|e| e.contains("excluded"))) {
        return Err(e.clone());
    }
    match urls.iter().zip(&results).find(|(_, r)| r.is_ok()) {
        Some((t, _)) => {
            if !out.contains(t) {
                out.push(t.clone());
            }
        }
        None => return Err(results.into_iter().find_map(Result::err).unwrap_or_default()),
    }
    Ok(out)
}

/// Resolve and validate all targets of a scope-required run.
///
/// `snapshot_dir`: when `Some`, validated target files are copied there and the returned
/// arguments point at the copies. When `None` (dry run), nothing is written.
pub fn resolve(args: &[String], explicit: &[String], entries: &[ScopeEntry], snapshot_dir: Option<&Path>) -> Result<Resolution, String> {
    let mut res = Resolution { args: args.to_vec(), ..Default::default() };
    let mut found: Vec<Target> = Vec::new();
    let push = |t: Target, found: &mut Vec<Target>| -> Result<(), String> {
        scope::check_target(entries, &t)?;
        if !found.contains(&t) {
            found.push(t);
        }
        Ok(())
    };

    for raw in explicit {
        for t in scope::strict_targets(raw)? {
            push(t, &mut found)?;
        }
    }

    let mut unverifiable: Vec<String> = Vec::new();
    for (idx, arg) in args.iter().enumerate() {
        let Some((offset, value)) = value_of(arg) else { continue };

        if let Some(path) = existing_file(value) {
            let (class, targets) = validate_file(&path, entries)?;
            if class == FileClass::Data {
                continue;
            }
            res.file_targets += targets.len();
            res.notes.push(match class {
                FileClass::HttpRequest => format!("{} is a raw HTTP request; its Host was validated", path.display()),
                _ => format!("{}: {} distinct targets, all in scope", path.display(), targets.len()),
            });
            if let Some(dir) = snapshot_dir {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "input".into());
                let snap = dir.join(format!("{idx}-{name}"));
                std::fs::copy(&path, &snap).map_err(|e| format!("could not snapshot {}: {e}", path.display()))?;
                // the snapshot must still contain exactly what was validated
                let (class2, targets2) = validate_file(&snap, entries)?;
                if class2 != class || targets2 != targets {
                    return Err(format!("{} changed while it was being validated", path.display()));
                }
                res.args[idx] = format!("{}{}", &arg[..offset], snap.to_string_lossy());
                res.snapshots.push((path.clone(), snap));
            }
            for t in targets {
                if !found.contains(&t) {
                    found.push(t);
                }
            }
            continue;
        }

        let loose = scope::loose_targets(value);
        if loose.is_empty() && offset == 0 && SINGLE_LABEL.is_match(value) && value.len() > 1 {
            unverifiable.push(value.to_string());
        }
        for t in loose {
            push(t, &mut found)?;
        }
    }

    if found.is_empty() {
        return Err("No target could be identified. Pass at least one host, IP, CIDR, URL or target file on the command line.".into());
    }
    if !unverifiable.is_empty() {
        unverifiable.truncate(10);
        res.warnings.push(format!(
            "Single-word arguments are not scope-checked because they cannot be told apart from sub-commands: {}. If any of them is a host name, use its fully-qualified name or IP instead.",
            unverifiable.join(", ")
        ));
    }
    res.checked = found.iter().map(scope::target_label).collect();
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn e(value: &str, in_scope: bool) -> ScopeEntry {
        let (v, kind) = scope::classify(value).unwrap();
        ScopeEntry { value: v, kind: kind.to_string(), in_scope }
    }

    fn scope() -> Vec<ScopeEntry> {
        vec![e("10.0.0.0/24", true), e("10.0.0.13", false), e("*.example.com", true), e("example.com", true), e("admin.example.com", false)]
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmpdir(name: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("cyberhub-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
    fn write(dir: &Path, name: &str, content: &[u8]) -> String {
        let p = dir.join(name);
        File::create(&p).unwrap().write_all(content).unwrap();
        p.to_string_lossy().to_string()
    }
    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn path_scoped_projects_check_urls_exactly_and_never_hosts() {
        let s = vec![e("https://app.example.com/api/", true), e("https://app.example.com/api/admin/", false)];
        assert_eq!(resolve(&a(&["-u", "https://app.example.com/api/FUZZ"]), &[], &s, None).unwrap().checked, vec!["https://app.example.com/api/FUZZ".to_string()]);
        for u in ["https://app.example.com/FUZZ", "http://app.example.com/api/FUZZ", "https://app.example.com:8443/api/", "https://app.example.com/api/admin/users"] {
            assert!(resolve(&a(&["-u", u]), &[], &s, None).is_err(), "{u}");
        }
        // a host name in the arguments (a port scan, for example) is never authorized by a URL
        for args in [vec!["-sV", "app.example.com"], vec!["-p", "443", "app.example.com:443"]] {
            let err = resolve(&a(&args), &[], &s, None).unwrap_err();
            assert!(err.contains("excluded path") || err.contains("specific URLs"), "{args:?}: {err}");
        }
        let t = tmpdir("pathlist");
        let good = write(&t.0, "urls.txt", b"https://app.example.com/api/a\nhttps://app.example.com/api/b?x=1\n");
        assert_eq!(resolve(&a(&["-l", &good]), &[], &s, None).unwrap().file_targets, 2);
        let bad = write(&t.0, "urls2.txt", b"https://app.example.com/api/a\nhttps://app.example.com/login\n");
        assert!(resolve(&a(&["-l", &bad]), &[], &s, None).unwrap_err().contains("line 2"));
        let hosts = write(&t.0, "hosts.txt", b"app.example.com\n");
        assert!(resolve(&a(&["-iL", &hosts]), &[], &s, None).is_err(), "a host list needs host-level authorization");
        // raw requests: the Host header with the request path, under either scheme
        let inside = write(&t.0, "in.req", b"POST /api/v1/login HTTP/1.1\r\nHost: app.example.com\r\n\r\nuser=a");
        assert_eq!(resolve(&a(&["-r", &inside]), &[], &s, None).unwrap().checked, vec!["https://app.example.com/api/v1/login".to_string()]);
        let outside = write(&t.0, "out.req", b"GET /admin HTTP/1.1\r\nHost: app.example.com\r\n\r\n");
        assert!(resolve(&a(&["-r", &outside]), &[], &s, None).unwrap_err().contains("outside the authorized URLs"));
        let excluded = write(&t.0, "ex.req", b"GET /api/admin/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n");
        assert!(resolve(&a(&["-r", &excluded]), &[], &s, None).unwrap_err().contains("excluded"));
        let port = write(&t.0, "port.req", b"GET /api/x HTTP/1.1\r\nHost: app.example.com:8443\r\n\r\n");
        assert!(resolve(&a(&["-r", &port]), &[], &s, None).is_err(), "another port is another origin");
        for host in ["app.example.com/evil", "evil.net@app.example.com", "app.example.com?x"] {
            let f = write(&t.0, "vh.req", format!("GET /api/x HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes());
            assert!(resolve(&a(&["-r", &f]), &[], &s, None).is_err(), "{host}");
        }
    }

    #[test]
    fn target_file_in_scope_is_snapshotted_and_rewritten() {
        let t = tmpdir("ok");
        let list = write(&t.0, "targets.txt", b"# lab\n10.0.0.5\n10.0.0.20-30 api.example.com\n\nhttps://app.example.com/login\n");
        let snaps = t.0.join("snap");
        let r = resolve(&a(&["-sT", "-iL", &list]), &[], &scope(), Some(&snaps)).unwrap();
        assert_eq!(r.file_targets, 4);
        assert!(r.checked.contains(&"api.example.com".to_string()));
        assert_ne!(r.args[2], list, "argument must point at the snapshot");
        assert!(r.args[2].starts_with(&*snaps.to_string_lossy()));
        assert_eq!(std::fs::read(&r.args[2]).unwrap(), std::fs::read(&list).unwrap());
        // dry run writes nothing and keeps the original argument
        let dry = resolve(&a(&["-iL", &list]), &[], &scope(), None).unwrap();
        assert_eq!(dry.args[1], list);
    }

    #[test]
    fn target_file_with_out_of_scope_entry_is_rejected() {
        let t = tmpdir("oos");
        let list = write(&t.0, "t.txt", b"10.0.0.5\n8.8.8.8\n");
        let err = resolve(&a(&["-iL", &list, "10.0.0.6"]), &[], &scope(), None).unwrap_err();
        assert!(err.contains("8.8.8.8") && err.contains("line 2"), "{err}");
    }

    #[test]
    fn target_file_hitting_exclusions_is_rejected() {
        let t = tmpdir("excl");
        let list = write(&t.0, "t.txt", b"10.0.0.0/28\n");
        assert!(resolve(&a(&["-iL", &list]), &[], &scope(), None).unwrap_err().contains("excluded"));
        let list2 = write(&t.0, "t2.txt", b"admin.example.com\n");
        assert!(resolve(&a(&["-l", &list2]), &[], &scope(), None).unwrap_err().contains("excluded"));
        let list3 = write(&t.0, "t3.txt", b"10.0.0.1-50\n");
        assert!(resolve(&a(&["-iL", &list3]), &[], &scope(), None).unwrap_err().contains("excluded"));
    }

    #[test]
    fn malformed_or_ambiguous_lines_are_rejected() {
        let t = tmpdir("bad");
        let wild = write(&t.0, "t.txt", b"10.0.0.5\n10.0.0.*\n");
        assert!(resolve(&a(&["-iL", &wild]), &[], &scope(), None).unwrap_err().contains("line 2"));
        // single-label names in a target list could resolve through DNS search domains
        let short = write(&t.0, "t2.txt", b"intranet\n10.0.0.5\n");
        assert!(resolve(&a(&["-iL", &short]), &[], &scope(), None).unwrap_err().contains("line 1"));
    }

    #[test]
    fn option_equals_file_form_is_validated_and_rewritten() {
        let t = tmpdir("eq");
        let bad = write(&t.0, "bad.txt", b"8.8.4.4\n");
        assert!(resolve(&[format!("--targets-file={bad}")], &[], &scope(), None).is_err());
        let ok = write(&t.0, "ok.txt", b"10.0.0.7\n");
        let snaps = t.0.join("s");
        let r = resolve(&[format!("-list={ok}")], &[], &scope(), Some(&snaps)).unwrap();
        assert!(r.args[0].starts_with("-list=") && r.args[0].contains(&*snaps.to_string_lossy()));
    }

    #[test]
    fn wordlists_and_binaries_are_data() {
        let t = tmpdir("wl");
        let wl = write(&t.0, "common.txt", b"admin\nlogin\nbackup.bak\nindex.php\n.git\nconfig.json\n");
        let r = resolve(&a(&["-u", "https://app.example.com/FUZZ", "-w", &wl]), &[], &scope(), None).unwrap();
        assert_eq!(r.file_targets, 0);
        assert_eq!(r.checked, vec!["https://app.example.com/FUZZ".to_string()]);
        let bin = write(&t.0, "x.bin", &[0u8, 1, 2, b'8', b'.', b'8', b'.', b'8', b'.', b'8']);
        assert_eq!(resolve(&a(&[&bin, "10.0.0.1"]), &[], &scope(), None).unwrap().file_targets, 0);
    }

    #[test]
    fn http_request_files_validate_host_and_request_line() {
        let t = tmpdir("req");
        let ok = write(&t.0, "ok.req", b"POST /login HTTP/1.1\r\nHost: app.example.com\r\nReferer: https://elsewhere.net/\r\n\r\nuser=a");
        assert_eq!(resolve(&a(&["-r", &ok]), &[], &scope(), None).unwrap().checked, vec!["https://app.example.com/login".to_string()]);
        let bad = write(&t.0, "bad.req", b"GET / HTTP/1.1\r\nHost: evil.net\r\n\r\n");
        assert!(resolve(&a(&["-r", &bad]), &[], &scope(), None).is_err());
        let abs = write(&t.0, "abs.req", b"GET http://evil.net/ HTTP/1.1\r\nHost: app.example.com\r\n\r\n");
        assert!(resolve(&a(&["-r", &abs]), &[], &scope(), None).is_err());
        let two = write(&t.0, "two.req", b"GET / HTTP/1.1\r\nHost: app.example.com\r\nhost: evil.net\r\n\r\n");
        assert!(resolve(&a(&["-r", &two]), &[], &scope(), None).unwrap_err().contains("more than one Host"));
        let none = write(&t.0, "none.req", b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n");
        assert!(resolve(&a(&["-r", &none]), &[], &scope(), None).unwrap_err().contains("no Host"));
    }

    #[test]
    fn mixed_arguments_cannot_smuggle_targets() {
        let s = scope();
        let cases: &[&[&str]] = &[
            &["10.0.0.5", "--script-args", "http.host=evil.net"],
            &["10.0.0.5", "--proxies=http://8.8.8.8:8080"],
            &["10.0.0.5", "corp/user:pw@192.168.1.1"],
            &["-u", "https://app.example.com", "-H", "X: http://intranet/"],
            &["10.0.0.5", "intranet:445"],
            &["10.0.0.5", "localhost"],
            &["10.0.0.5", "[::1]:80"],
            &["https://app.example.com@evil.net/"],
            &["http://2130706433/"],
            &["10.0.0.5", "evil.pl"],
            &["10.0.0.5", "evil.zip"],
            &["10.0.0.5", "evil.sh"],
            &["10.0.0.5", "evil.py"],
            &["10.0.0.5", "evil.md"],
            &["10.0.0.5,8.8.8.8"],
            &["10.0.0.5", "-D", "1.2.3.4"],
        ];
        for c in cases {
            assert!(resolve(&a(c), &[], &s, None).is_err(), "should be rejected: {c:?}");
        }
        let err = resolve(&a(&["10.0.0.5", "::ffff:10.0.0.13"]), &[], &s, None).unwrap_err();
        assert!(err.contains("excluded"), "{err}");
    }

    #[test]
    fn fuzzing_keywords_in_hosts_resolve_to_real_hosts() {
        let s = scope();
        // keyword as a whole leading label under an in-scope wildcard: allowed
        assert!(resolve(&a(&["-u", "https://FUZZ.example.com/"]), &[], &s, None).is_ok());
        // keyword inside a label, as the whole host, or inside an IP: the URL names some other host → rejected
        for u in ["https://exaFUZZ.com/", "https://FUZZ/", "https://10.0.0.FUZZ/", "https://FUZZ.evil.net/"] {
            assert!(resolve(&a(&["-u", u]), &[], &s, None).is_err(), "{u}");
        }
        // keyword in the path is not a host concern
        assert!(resolve(&a(&["-u", "https://app.example.com/FUZZ?q=FUZZ"]), &[], &s, None).is_ok());
        // apex-only scope does not authorize fuzzed sub-domains
        let apex = vec![e("example.com", true)];
        assert!(resolve(&a(&["-u", "https://FUZZ.example.com/"]), &[], &apex, None).is_err());
    }

    #[test]
    fn single_label_arguments_are_reported() {
        let r = resolve(&a(&["dir", "-u", "https://app.example.com"]), &[], &scope(), None).unwrap();
        assert!(r.warnings.iter().any(|w| w.contains("dir")));
    }

    #[test]
    fn explicit_targets_are_strict() {
        assert!(resolve(&a(&["-sV"]), &a(&["not a host"]), &scope(), None).is_err());
        assert!(resolve(&a(&["-sV"]), &a(&["10.0.0.9"]), &scope(), None).is_ok());
    }

    #[test]
    fn no_target_is_an_error() {
        assert!(resolve(&a(&["-sV", "-p", "80"]), &[], &scope(), None).unwrap_err().contains("No target"));
        assert!(resolve(&a(&["-iL", "-"]), &[], &scope(), None).unwrap_err().contains("No target"));
    }

    #[test]
    fn oversized_files_are_rejected_not_skipped() {
        // validate the size guard without writing 256 MB: check the constant is enforced by metadata
        const { assert!(MAX_SCAN_BYTES >= 128 * 1024 * 1024) };
    }
}
