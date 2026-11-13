//! Whether an external tool follows HTTP redirects in a run, from its options.
//!
//! A run whose URLs are authorized only by path (URL scope entries), or that sit on a host with an
//! excluded path, is refused when the tool would follow redirects: a redirect can lead outside the
//! authorized paths or into the excluded one, and ExploitX cannot check where an external tool's
//! redirects go. ExploitX's own HTTP client checks every redirect itself (`sectools::http`).
//!
//! The options and defaults come from each tool's own help text or source (checked in November
//! 2026). A tool without an entry is not known to follow redirects: its runs keep the warning that
//! the tool decides which further paths it requests.
//!
//! A file of options can turn redirects on where ExploitX cannot see it. Such runs are refused when
//! an option loads one ([`option_file`]); the files a tool reads on its own are named in a warning
//! ([`own_option_files`]), because ExploitX does not read them.

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
    // httpx: `-fr, -follow-redirects`, `-fhr, -follow-host-redirects` (same host, other paths); the
    // headless browser of `-ss, -screenshot` follows redirects itself (`-fr` does not apply to it)
    Policy {
        tool: "httpx",
        default: Follow::Off,
        enable: &["fr", "follow-redirects", "fhr", "follow-host-redirects", "ss", "screenshot"],
        disable: &[],
        bundled: &[],
        prefixes: false,
        value: None,
        off: "leave out -fr, -fhr and -ss (-screenshot)",
    },
    // dalfox (clap): `-F, --follow-redirects`
    Policy { tool: "dalfox", default: Follow::Off, enable: &["F", "follow-redirects"], disable: &[], bundled: &['F'], prefixes: false, value: None, off: "leave out -F / --follow-redirects" },
    // nikto (Getopt::Long, unique prefixes such as `-f`): `-followredirects`
    Policy { tool: "nikto", default: Follow::Off, enable: &["followredirects"], disable: &[], bundled: &[], prefixes: true, value: None, off: "leave out -followredirects" },
    // nuclei: templates may follow redirects on their own; `-dr, -disable-redirects` stops it for
    // HTTP templates, but the browser of headless templates (`-headless`) follows redirects itself
    Policy {
        tool: "nuclei",
        default: Follow::On,
        enable: &["fr", "follow-redirects", "fhr", "follow-host-redirects", "headless"],
        disable: &["dr", "disable-redirects"],
        bundled: &[],
        prefixes: false,
        value: None,
        off: "add -dr (-disable-redirects) and leave out -fr, -fhr and -headless",
    },
    // katana: `-dr, -disable-redirects  disable following redirects (default false)`; its headless
    // engine (`-hl, -headless`) leaves redirects to the browser, the hybrid one (`-hh`) honours `-dr`
    Policy {
        tool: "katana",
        default: Follow::On,
        enable: &["hl", "headless"],
        disable: &["dr", "disable-redirects"],
        bundled: &[],
        prefixes: false,
        value: None,
        off: "add -dr (-disable-redirects) and leave out -hl (-headless)",
    },
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
        // (strip_prefix, not a byte slice: an argument starting with a multi-byte character must not panic)
        let short = arg.strip_prefix('-').filter(|rest| !p.bundled.is_empty() && !rest.starts_with('-') && rest.len() > 1 && rest.chars().all(|c| c.is_ascii_alphabetic()));
        if let Some(rest) = short {
            if let Some(c) = rest.chars().find(|c| p.bundled.contains(c)) {
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

/// Files of options: a tool can turn on redirects in one, where ExploitX cannot see it. The options
/// that load a file named on the command line, and the files the tool reads on its own (from each
/// tool's source, November 2026). Command-line options take precedence over these files in every
/// tool listed, but a file can still turn on an option the command line leaves out.
struct OptionFiles {
    tool: &'static str,
    /// options that load a file of options (names without leading dashes)
    options: &'static [&'static str],
    /// unique prefixes of the option names are accepted too
    prefixes: bool,
    /// the files the tool reads on its own, as shown to the analyst ("" when it reads none)
    own: &'static str,
}

const OPTION_FILES: &[OptionFiles] = &[
    // `-config`; ffufrc in $XDG_CONFIG_HOME/ffuf (~/.config/ffuf), else ~/.ffufrc (`followredirects`)
    OptionFiles { tool: "ffuf", options: &["config"], prefixes: false, own: "ffufrc (in its configuration folder such as ~/.config/ffuf, or ~/.ffufrc)" },
    // `--resume-from` loads a saved scan's whole configuration; ferox-config.toml (`redirects`) is
    // read from /etc/feroxbuster, the user's configuration folder, the program's folder and the
    // working folder
    OptionFiles {
        tool: "feroxbuster",
        options: &["resume-from"],
        prefixes: false,
        own: "ferox-config.toml (in /etc/feroxbuster, its configuration folder such as ~/.config/feroxbuster, or next to the program)",
    },
    // goflags: `-config`, and config.yaml in the user's configuration folder (created on first use)
    OptionFiles { tool: "httpx", options: &["config"], prefixes: false, own: "config.yaml in its configuration folder (such as ~/.config/httpx)" },
    OptionFiles { tool: "katana", options: &["config"], prefixes: false, own: "config.yaml in its configuration folder (such as ~/.config/katana)" },
    // also `-tp, -profile` (a template profile is a file of options) and, in recent versions,
    // /etc/nuclei/config.yaml
    OptionFiles {
        tool: "nuclei",
        options: &["config", "tp", "profile"],
        prefixes: false,
        own: "config.yaml in its configuration folders (such as ~/.config/nuclei and /etc/nuclei)",
    },
    // `--config`, and config.toml or config.json in $XDG_CONFIG_HOME/dalfox or ~/.config/dalfox
    OptionFiles { tool: "dalfox", options: &["config"], prefixes: false, own: "config.toml or config.json in its configuration folder (such as ~/.config/dalfox)" },
    // `-config`; nikto.conf next to the program, in the home folder or in /etc, whose CLIOPTS
    // adds command-line options
    OptionFiles { tool: "nikto", options: &["config"], prefixes: true, own: "nikto.conf (next to the program, in your home folder or in /etc), whose CLIOPTS adds options" },
    // `-c` loads options from an INI file; sqlmap reads none on its own
    OptionFiles { tool: "sqlmap", options: &["c"], prefixes: false, own: "" },
];

/// The argument that loads a file of options ExploitX cannot read, if any.
pub fn option_file(tool_id: &str, args: &[String]) -> Option<String> {
    let f = OPTION_FILES.iter().find(|f| f.tool == tool_id)?;
    args.iter()
        .find(|arg| {
            // the attached value of a one-letter option: `-cFILE`, `-c=FILE` (sqlmap)
            let attached = f.options.iter().any(|o| o.len() == 1 && !arg.starts_with("--") && arg.len() > 2 && arg.strip_prefix('-').is_some_and(|r| r.starts_with(o)));
            attached || option(arg).is_some_and(|(name, _)| named(name, f.options, f.prefixes))
        })
        .cloned()
}

/// The files of options the tool reads on its own ("" when none is known).
pub fn own_option_files(tool_id: &str) -> &'static str {
    OPTION_FILES.iter().find(|f| f.tool == tool_id).map_or("", |f| f.own)
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
        assert_eq!(how_to_stop("katana"), "add -dr (-disable-redirects) and leave out -hl (-headless)");
        assert!(follows("ffuf", &a(&["-r"])).unwrap().contains("-r makes ffuf follow redirects"));
    }

    #[test]
    fn browser_modes_follow_redirects_whatever_the_redirect_options_say() {
        // the browser follows redirects itself: -dr, or leaving out -fr, does not stop it
        assert!(follows("nuclei", &a(&["-u", "https://app.example.com/api/", "-dr", "-headless"])).unwrap().contains("-headless"));
        assert!(follows("httpx", &a(&["-u", "https://app.example.com/api/", "-ss"])).unwrap().contains("-ss"));
        assert!(follows("httpx", &a(&["-u", "https://app.example.com/api/", "-screenshot"])).is_some());
        assert!(follows("katana", &a(&["-u", "https://app.example.com/api/", "-dr", "-hl"])).is_some());
        // katana's hybrid engine honours -dr
        assert!(follows("katana", &a(&["-u", "https://app.example.com/api/", "-dr", "-hh"])).is_none());
    }

    #[test]
    fn options_that_load_a_file_of_options_are_found() {
        for (tool, args) in [
            ("ffuf", vec!["-u", "https://app.example.com/api/FUZZ", "-config", "my.ffufrc"]),
            ("ffuf", vec!["-u", "https://app.example.com/api/FUZZ", "--config=my.ffufrc"]),
            ("feroxbuster", vec!["--resume-from", "ferox-1606586780.state"]),
            ("httpx", vec!["-u", "https://app.example.com/api/", "-config", "httpx.yaml"]),
            ("katana", vec!["-u", "https://app.example.com/api/", "-dr", "-config=katana.yaml"]),
            ("nuclei", vec!["-u", "https://app.example.com/api/", "-dr", "-config", "nuclei.yaml"]),
            ("nuclei", vec!["-u", "https://app.example.com/api/", "-dr", "-tp", "profile.yaml"]),
            ("nuclei", vec!["-u", "https://app.example.com/api/", "-dr", "--profile", "profile.yaml"]),
            ("dalfox", vec!["url", "https://app.example.com/api/?q=1", "--config", "dalfox.toml"]),
            ("nikto", vec!["-h", "https://app.example.com/api/", "-config", "nikto.conf"]),
            ("nikto", vec!["-h", "https://app.example.com/api/", "-conf", "nikto.conf"]),
            ("sqlmap", vec!["-u", "https://app.example.com/api/?id=1", "-c", "sqlmap.conf"]),
            ("sqlmap", vec!["-u", "https://app.example.com/api/?id=1", "-csqlmap.conf"]),
            ("sqlmap", vec!["-u", "https://app.example.com/api/?id=1", "-c=sqlmap.conf"]),
        ] {
            assert!(option_file(tool, &a(&args)).is_some(), "{tool} {args:?}");
        }
        for (tool, args) in [
            // -c is the concurrency of nuclei and katana; sqlmap's long options are not -c
            ("nuclei", vec!["-u", "https://app.example.com/api/", "-dr", "-c", "10"]),
            ("katana", vec!["-u", "https://app.example.com/api/", "-dr", "-c", "10"]),
            ("sqlmap", vec!["-u", "https://app.example.com/api/?id=1", "--crawl", "2", "--csrf-token", "t"]),
            ("nikto", vec!["-h", "https://app.example.com/api/", "-Cgidirs", "all"]),
            ("ffuf", vec!["-u", "https://app.example.com/api/FUZZ", "-w", "config"]),
            // tools without such options
            ("gobuster", vec!["dir", "-u", "https://app.example.com/api/", "--config", "x"]),
            ("whatweb", vec!["https://app.example.com/api/", "--follow-redirect=never"]),
        ] {
            assert!(option_file(tool, &a(&args)).is_none(), "{tool} {args:?}");
        }
        assert!(own_option_files("ffuf").contains("ffufrc"));
        assert!(own_option_files("nikto").contains("CLIOPTS"));
        assert_eq!(own_option_files("sqlmap"), "");
        assert_eq!(own_option_files("gobuster"), "");
    }

    #[test]
    fn arguments_starting_with_multibyte_characters_are_not_options() {
        // `é1` used to be sliced at its second byte, inside the character, and panic
        assert_eq!(follows("feroxbuster", &a(&["-u", "https://app.example.com/api/", "é1"])), None);
        assert_eq!(follows("dalfox", &a(&["url", "https://app.example.com/", "€F"])), None);
        assert!(follows("feroxbuster", &a(&["-kr", "-u", "https://app.example.com/"])).is_some(), "bundled short options are still read");
    }
}
