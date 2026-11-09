//! Whether an external tool follows HTTP redirects in a run, from its options.
//!
//! A run whose URLs are authorized only by path (URL scope entries), or that sit on a host with an
//! excluded path, is refused when the tool would follow redirects: a redirect can lead outside the
//! authorized paths or into the excluded one, and Cyber Hub cannot check where an external tool's
//! redirects go. Cyber Hub's own HTTP client checks every redirect itself (`sectools::http`).
//!
//! The options and defaults come from each tool's own help text or source (checked in November
//! 2026). A tool without an entry is not known to follow redirects: its runs keep the warning that
//! the tool decides which further paths it requests.

/// How a tool treats redirects when no option says otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Follow {
    /// follows only when an option turns it on
    Off,
    /// follows unless an option turns it off
    On,
    /// always follows; no option turns it off
    Always,
}

struct Policy {
    tool: &'static str,
    default: Follow,
    /// options that turn following on (names without leading dashes)
    enable: &'static [&'static str],
    /// options that turn it off
    disable: &'static [&'static str],
    /// short options the tool lets the analyst bundle (`-kr`): letters that turn following on
    bundled: &'static [char],
    /// unique prefixes of the option names are accepted too (Perl and Ruby option parsers)
    prefixes: bool,
    /// an option whose value decides (name, values that turn following off)
    value: Option<(&'static str, &'static [&'static str])>,
    /// how to run the tool without following redirects
    off: &'static str,
}

const POLICIES: &[Policy] = &[
    // ffuf: `-r  Follow redirects (default: false)`
    Policy { tool: "ffuf", default: Follow::Off, enable: &["r"], disable: &[], bundled: &[], prefixes: false, value: None, off: "leave out -r" },
    // gobuster: `follow-redirect` (alias `r`), default false
    Policy { tool: "gobuster", default: Follow::Off, enable: &["r", "follow-redirect"], disable: &[], bundled: &[], prefixes: false, value: None, off: "leave out -r / --follow-redirect" },
    // feroxbuster (clap, short options can be bundled): `-r, --redirects  Allow client to follow redirects`
    Policy { tool: "feroxbuster", default: Follow::Off, enable: &["r", "redirects"], disable: &[], bundled: &['r'], prefixes: false, value: None, off: "leave out -r / --redirects" },
    // httpx: `-fr, -follow-redirects`, `-fhr, -follow-host-redirects` (same host, other paths)
    Policy {
        tool: "httpx",
        default: Follow::Off,
        enable: &["fr", "follow-redirects", "fhr", "follow-host-redirects"],
        disable: &[],
        bundled: &[],
        prefixes: false,
        value: None,
        off: "leave out -fr and -fhr",
    },
    // dalfox (clap): `-F, --follow-redirects`
    Policy { tool: "dalfox", default: Follow::Off, enable: &["F", "follow-redirects"], disable: &[], bundled: &['F'], prefixes: false, value: None, off: "leave out -F / --follow-redirects" },
    // nikto (Getopt::Long, unique prefixes such as `-f`): `-followredirects`
    Policy { tool: "nikto", default: Follow::Off, enable: &["followredirects"], disable: &[], bundled: &[], prefixes: true, value: None, off: "leave out -followredirects" },
    // nuclei: templates may follow redirects on their own; `-dr, -disable-redirects` stops it
    Policy {
        tool: "nuclei",
        default: Follow::On,
        enable: &["fr", "follow-redirects", "fhr", "follow-host-redirects"],
        disable: &["dr", "disable-redirects"],
        bundled: &[],
        prefixes: false,
        value: None,
        off: "add -dr (-disable-redirects) and leave out -fr and -fhr",
    },
    // katana: `-dr, -disable-redirects  disable following redirects (default false)`
    Policy { tool: "katana", default: Follow::On, enable: &[], disable: &["dr", "disable-redirects"], bundled: &[], prefixes: false, value: None, off: "add -dr (-disable-redirects)" },
    // sqlmap: asks "Do you want to follow? [Y/n]" with the default Y (runs have no input); `--ignore-redirects`
    Policy { tool: "sqlmap", default: Follow::On, enable: &[], disable: &["ignore-redirects"], bundled: &[], prefixes: false, value: None, off: "add --ignore-redirects" },
    // whatweb: `--follow-redirect=WHEN` … `Default: always`
    Policy {
        tool: "whatweb",
        default: Follow::On,
        enable: &[],
        disable: &[],
        bundled: &[],
        prefixes: true,
        value: Some(("follow-redirect", &["never"])),
        off: "add --follow-redirect=never",
    },
    // wpscan: the target's own redirect is always requested (`--ignore-main-redirect` only
    // decides what is scanned afterwards)
    Policy { tool: "wpscan", default: Follow::Always, enable: &[], disable: &[], bundled: &[], prefixes: false, value: None, off: "" },
    // CeWL: the spider queues every redirect location; no option turns it off
    Policy { tool: "cewl", default: Follow::Always, enable: &[], disable: &[], bundled: &[], prefixes: false, value: None, off: "" },
];

/// An argument's option name and its attached value: `--follow-redirect=never` → (`follow-redirect`, Some(`never`)).
fn option(arg: &str) -> Option<(&str, Option<&str>)> {
    let rest = arg.strip_prefix('-')?;
    let rest = rest.strip_prefix('-').unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    Some(match rest.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    })
}

fn named(name: &str, names: &[&str], prefixes: bool) -> bool {
    names.iter().any(|n| *n == name || (prefixes && !name.is_empty() && n.starts_with(name)))
}

/// An attached value that turns a boolean option off (`-fr=false`).
fn falsy(v: Option<&str>) -> bool {
    v.is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
}

/// Why the run follows redirects, if it does; None for tools without a known policy.
pub fn follows(tool_id: &str, args: &[String]) -> Option<String> {
    let p = POLICIES.iter().find(|p| p.tool == tool_id)?;
    if p.default == Follow::Always {
        return Some(format!("{} always follows redirects and has no option to turn that off", p.tool));
    }
    let mut enabled: Option<String> = None;
    let mut disabled = false;
    for (i, arg) in args.iter().enumerate() {
        // bundled short options (`-kr`): letters only, so a value such as `-uhttps://…` is not read as one
        if !p.bundled.is_empty() && !arg.starts_with("--") && arg.len() > 2 && arg[1..].chars().all(|c| c.is_ascii_alphabetic()) {
            if let Some(c) = arg[1..].chars().find(|c| p.bundled.contains(c)) {
                enabled.get_or_insert_with(|| format!("-{c} in {arg}"));
            }
        }
        let Some((name, attached)) = option(arg) else { continue };
        if named(name, p.enable, p.prefixes) && !falsy(attached) {
            enabled.get_or_insert_with(|| arg.clone());
        }
        if named(name, p.disable, p.prefixes) && !falsy(attached) {
            disabled = true;
        }
        if let Some((vname, offs)) = p.value {
            if named(name, &[vname], p.prefixes) {
                let value = attached.map(str::to_string).or_else(|| args.get(i + 1).cloned()).unwrap_or_default();
                if offs.contains(&value.to_ascii_lowercase().as_str()) {
                    disabled = true;
                } else {
                    enabled.get_or_insert_with(|| if attached.is_some() { arg.clone() } else { format!("{arg} {value}") });
                }
            }
        }
    }
    match (enabled, p.default) {
        (Some(opt), _) => Some(format!("{opt} makes {} follow redirects", p.tool)),
        (None, Follow::On) if !disabled => Some(format!("{} follows redirects unless told not to ({})", p.tool, p.off)),
        _ => None,
    }
}

/// How to run the tool without following redirects ("" when it cannot be done).
pub fn how_to_stop(tool_id: &str) -> &'static str {
    POLICIES.iter().find(|p| p.tool == tool_id).map_or("", |p| p.off)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redirect_options_are_read_per_tool() {
        // tools that follow only when told to
        for (tool, on, off) in [
            ("ffuf", vec!["-u", "https://app.example.com/api/FUZZ", "-r"], vec!["-u", "https://app.example.com/api/FUZZ", "-mr", "x"]),
            ("gobuster", vec!["dir", "-u", "https://app.example.com/api/", "--follow-redirect"], vec!["dir", "-u", "https://app.example.com/api/"]),
            ("gobuster", vec!["dir", "-u", "https://app.example.com/api/", "-r"], vec!["dir", "-u", "https://app.example.com/api/", "--follow-redirect=false"]),
            ("feroxbuster", vec!["-u", "https://app.example.com/api/", "-kr"], vec!["-u", "https://app.example.com/api/", "-k"]),
            ("feroxbuster", vec!["-u", "https://app.example.com/api/", "--redirects"], vec!["-uhttps://redirect.example.com/api/"]),
            ("httpx", vec!["-u", "https://app.example.com/api/", "-fhr"], vec!["-u", "https://app.example.com/api/", "-maxr", "3"]),
            ("httpx", vec!["-u", "https://app.example.com/api/", "--follow-redirects"], vec!["-u", "https://app.example.com/api/", "-fr=false"]),
            ("dalfox", vec!["url", "https://app.example.com/api/?q=1", "-F"], vec!["url", "https://app.example.com/api/?q=1"]),
            ("nikto", vec!["-h", "https://app.example.com/api/", "-f"], vec!["-h", "https://app.example.com/api/", "-Format", "htm"]),
            ("nikto", vec!["-h", "https://app.example.com/api/", "-followredirects"], vec!["-h", "https://app.example.com/api/"]),
        ] {
            assert!(follows(tool, &a(&on)).is_some(), "{tool} {on:?}");
            assert!(follows(tool, &a(&off)).is_none(), "{tool} {off:?}");
        }
        // tools that follow unless told not to
        for (tool, on, off) in [
            ("nuclei", vec!["-u", "https://app.example.com/api/"], vec!["-u", "https://app.example.com/api/", "-dr"]),
            ("nuclei", vec!["-u", "https://app.example.com/api/", "-dr", "-fr"], vec!["-u", "https://app.example.com/api/", "--disable-redirects"]),
            ("katana", vec!["-u", "https://app.example.com/api/"], vec!["-u", "https://app.example.com/api/", "-disable-redirects"]),
            ("sqlmap", vec!["-u", "https://app.example.com/api/?id=1", "--batch"], vec!["-u", "https://app.example.com/api/?id=1", "--batch", "--ignore-redirects"]),
            ("whatweb", vec!["https://app.example.com/api/"], vec!["https://app.example.com/api/", "--follow-redirect=never"]),
            ("whatweb", vec!["https://app.example.com/api/", "--follow-redirect", "same-site"], vec!["--follow-redirect", "never", "https://app.example.com/api/"]),
        ] {
            assert!(follows(tool, &a(&on)).is_some(), "{tool} {on:?}");
            assert!(follows(tool, &a(&off)).is_none(), "{tool} {off:?}");
        }
        // tools that always follow
        for tool in ["wpscan", "cewl"] {
            assert!(follows(tool, &a(&["--url", "https://app.example.com/"])).unwrap().contains("always follows"));
        }
        // unknown tools: no claim either way
        assert!(follows("nmap", &a(&["-sV", "-r", "10.0.0.5"])).is_none());
        assert_eq!(how_to_stop("katana"), "add -dr (-disable-redirects)");
        assert!(follows("ffuf", &a(&["-r"])).unwrap().contains("-r makes ffuf follow redirects"));
    }
}
