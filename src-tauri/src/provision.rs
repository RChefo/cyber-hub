//! `cyberhub-keys` — developer-only credential provisioning and diagnostics.
//!
//! Compiled only with the `provisioning` Cargo feature, so it is not part of the application
//! binary, `tauri build` output or installers. It writes credentials into the same OS
//! credential store entries the app reads (service `dev.cyberhub.workstation`), and reports
//! sanitized status and connectivity. It never prints a credential.
//!
//! Keys are accepted only through a hidden prompt, standard input, or a local secrets file
//! that git ignores. They are never accepted as command-line arguments (shell history and
//! process listings would expose them).

use std::io::{BufRead, IsTerminal};
use std::path::Path;
use std::time::Duration;

use crate::commands::system::{delete_secret, secret_configured, store_secret, NVD_KEY};
use crate::ti::http::{self, ApiError};
use crate::ti::{KeyId, ProviderId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cred {
    Ti(KeyId),
    Nvd,
    Anthropic,
}

impl Cred {
    pub const ALL: [Cred; 7] = [Cred::Ti(KeyId::Virustotal), Cred::Ti(KeyId::Abuseipdb), Cred::Ti(KeyId::Otx), Cred::Ti(KeyId::Abusech), Cred::Ti(KeyId::Shodan), Cred::Nvd, Cred::Anthropic];

    pub fn parse(s: &str) -> Option<Cred> {
        if s == "nvd" {
            return Some(Cred::Nvd);
        }
        if s == "anthropic" {
            return Some(Cred::Anthropic);
        }
        KeyId::parse(s).map(Cred::Ti)
    }
    pub fn id(self) -> &'static str {
        match self {
            Cred::Ti(k) => k.as_str(),
            Cred::Nvd => "nvd",
            Cred::Anthropic => "anthropic",
        }
    }
    pub fn secret_name(self) -> &'static str {
        match self {
            Cred::Ti(k) => k.secret_name(),
            Cred::Nvd => NVD_KEY,
            Cred::Anthropic => crate::commands::assistant::ANTHROPIC_KEY,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Cred::Ti(k) => k.label(),
            Cred::Nvd => "NVD API key",
            Cred::Anthropic => "Anthropic API key",
        }
    }
    pub fn used_by(self) -> String {
        match self {
            Cred::Ti(k) => k.providers().into_iter().map(ProviderId::name).collect::<Vec<_>>().join(", "),
            Cred::Nvd => "Vulnerability Intel (optional; raises the NVD rate limit)".into(),
            Cred::Anthropic => "Project assistant (Projects → Assistant)".into(),
        }
    }
    pub fn check_format(self, key: &str) -> Result<(), String> {
        match self {
            Cred::Ti(k) => k.check_format(key),
            Cred::Nvd => {
                if (8..=256).contains(&key.len()) && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    Ok(())
                } else {
                    Err("This does not look like an NVD API key.".into())
                }
            }
            Cred::Anthropic => {
                if key.starts_with("sk-ant-") && (20..=400).contains(&key.len()) && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    Ok(())
                } else {
                    Err("This does not look like an Anthropic API key (sk-ant-…).".into())
                }
            }
        }
    }
}

/// Parse a local secrets file: `id = value` per line; `#` comments and blank lines ignored;
/// optional surrounding quotes. Every id must be known and appear once.
pub fn parse_secrets(text: &str) -> Result<Vec<(Cred, String)>, String> {
    let mut out: Vec<(Cred, String)> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (id, value) = line.split_once('=').ok_or_else(|| format!("line {}: expected `id = value`", n + 1))?;
        let cred = Cred::parse(id.trim()).ok_or_else(|| format!("line {}: unknown credential id `{}`", n + 1, id.trim()))?;
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        if value.is_empty() {
            continue; // placeholder lines in the template
        }
        if out.iter().any(|(c, _)| *c == cred) {
            return Err(format!("line {}: `{}` appears twice", n + 1, cred.id()));
        }
        out.push((cred, value));
    }
    Ok(out)
}

fn client() -> Result<reqwest::Client, String> {
    http::client(Duration::from_secs(20))
}

/// One read-only request with a fixed public probe. Returns sanitized quota/plan text.
async fn probe(cred: Cred, key: &str) -> Result<Option<String>, String> {
    let c = client()?;
    match cred {
        Cred::Ti(k) => {
            let name = match k {
                KeyId::Abusech => "abuse.ch",
                _ => k.providers()[0].name(),
            };
            crate::ti::probe(k, &c, key).await.map_err(|e: ApiError| http::scrub(&e.message(name), key))
        }
        Cred::Nvd => {
            let rb = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0").query(&[("cveId", "CVE-2021-44228")]).header("apiKey", key);
            let resp = http::send(rb, key).await.map_err(|e| http::scrub(&e.message("NVD"), key))?;
            match resp.status {
                200 => Ok(None),
                s => Err(format!("NVD answered HTTP {s}; the key was not accepted or the service is unavailable.")),
            }
        }
        Cred::Anthropic => {
            // listing models is read-only and uses no tokens
            let rb = c.get("https://api.anthropic.com/v1/models").header("x-api-key", key).header("anthropic-version", crate::commands::assistant::API_VERSION);
            let resp = http::send(rb, key).await.map_err(|e| http::scrub(&e.message("Anthropic"), key))?;
            match resp.status {
                200 => Ok(None),
                s => Err(format!("Anthropic answered HTTP {s}; the key was not accepted or the service is unavailable.")),
            }
        }
    }
}

fn usage() -> &'static str {
    "cyberhub-keys — developer-only credential provisioning for Cyber Hub

USAGE
  cyberhub-keys status                  Show which credentials are configured (never their values)
  cyberhub-keys test [ID|all]           Check connectivity with one read-only request; show quota
  cyberhub-keys set ID [--no-verify]    Store one credential; the value is read from a hidden
                                        prompt or from standard input (never from arguments)
  cyberhub-keys import FILE [--no-verify] [--allow-unignored]
                                        Store every credential listed in a local secrets file
  cyberhub-keys remove ID|all           Delete stored credentials
  cyberhub-keys taxii-set SERVER_ID     Store a TAXII server's password or API key (the server's
                                        number, shown in Threat Intel → TAXII feeds)
  cyberhub-keys taxii-remove SERVER_ID  Delete it

IDS
  virustotal, abuseipdb, otx, abusech (URLhaus, MalwareBazaar, ThreatFox), shodan, nvd,
  anthropic (project assistant)

Credentials are stored in the OS credential store of the current user. See docs/PROVISIONING.md."
}

/// Entry point for the `cyberhub-keys` binary. Returns the process exit code.
pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let result = rt.block_on(run(&args));
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn select(arg: Option<&String>) -> Result<Vec<Cred>, String> {
    match arg.map(String::as_str) {
        None | Some("all") => Ok(Cred::ALL.to_vec()),
        Some(id) => Cred::parse(id).map(|c| vec![c]).ok_or_else(|| format!("unknown credential id `{id}`")),
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let flags: Vec<&str> = args.iter().filter(|a| a.starts_with("--")).map(String::as_str).collect();
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let verify = !flags.contains(&"--no-verify");
    match pos.first().map(|s| s.as_str()) {
        Some("status") => {
            for c in Cred::ALL {
                let state = if secret_configured(c.secret_name()) { "configured" } else { "not configured" };
                println!("{:<11} {:<15} {}", c.id(), state, c.used_by());
            }
            Ok(())
        }
        Some("test") => {
            for c in select(pos.get(1).copied())? {
                let Some(key) = crate::commands::system::read_secret(c.secret_name()) else {
                    println!("{:<11} not configured", c.id());
                    continue;
                };
                match probe(c, &key).await {
                    Ok(q) => println!("{:<11} ok{}", c.id(), q.map(|q| format!(" · {q}")).unwrap_or_default()),
                    Err(e) => println!("{:<11} FAILED · {e}", c.id()),
                }
            }
            Ok(())
        }
        Some("set") => {
            let id = pos.get(1).ok_or("set needs a credential id")?;
            if pos.len() > 2 {
                return Err("do not pass credentials as arguments; they end up in shell history. Run `set ID` and paste the value at the prompt, or pipe it on standard input.".into());
            }
            let cred = Cred::parse(id).ok_or_else(|| format!("unknown credential id `{id}`"))?;
            let value = read_value(cred)?;
            store(cred, &value, verify).await
        }
        Some("import") => {
            let file = pos.get(1).ok_or("import needs a file path")?;
            let path = Path::new(file.as_str());
            if !flags.contains(&"--allow-unignored") && tracked_by_git(path) {
                return Err(format!("{} is inside a git working tree and not ignored by git. Move it outside the repository or add it to .gitignore (or pass --allow-unignored).", path.display()));
            }
            let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let entries = parse_secrets(&text)?;
            if entries.is_empty() {
                return Err("the file contains no credentials".into());
            }
            for (cred, value) in entries {
                store(cred, &value, verify).await?;
            }
            println!("Done. Delete or protect the secrets file if you no longer need it.");
            Ok(())
        }
        Some("taxii-set") => {
            let id = pos.get(1).ok_or("taxii-set needs the server's number")?;
            if pos.len() > 2 {
                return Err("do not pass credentials as arguments; they end up in shell history".into());
            }
            let name = format!("taxii_{id}");
            if !crate::commands::system::is_taxii_secret(&name) {
                return Err(format!("`{id}` is not a server number"));
            }
            let value = if std::io::stdin().is_terminal() {
                rpassword::prompt_password("TAXII password or API key (input hidden): ").map_err(|e| e.to_string())?
            } else {
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
                line
            };
            let value = value.trim();
            if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                return Err("the value is empty, too long or has control characters".into());
            }
            store_secret(&name, value).map_err(|e| e.to_string())?;
            println!("{name} stored (it is tested when the server is next used)");
            Ok(())
        }
        Some("taxii-remove") => {
            let id = pos.get(1).ok_or("taxii-remove needs the server's number")?;
            let name = format!("taxii_{id}");
            if !crate::commands::system::is_taxii_secret(&name) {
                return Err(format!("`{id}` is not a server number"));
            }
            delete_secret(&name).map_err(|e| e.to_string())?;
            println!("{name} removed");
            Ok(())
        }
        Some("remove") => {
            let which = pos.get(1).ok_or("remove needs a credential id or `all`")?;
            for c in select(Some(which))? {
                delete_secret(c.secret_name()).map_err(|e| e.to_string())?;
                println!("{:<11} removed", c.id());
            }
            Ok(())
        }
        _ => {
            println!("{}", usage());
            Ok(())
        }
    }
}

fn read_value(cred: Cred) -> Result<String, String> {
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{} (input hidden): ", cred.label())).map_err(|e| e.to_string())?
    } else {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
        line
    };
    Ok(value.trim().to_string())
}

async fn store(cred: Cred, value: &str, verify: bool) -> Result<(), String> {
    cred.check_format(value).map_err(|e| format!("{}: {e}", cred.id()))?;
    if verify {
        let quota = probe(cred, value).await.map_err(|e| format!("{}: not stored — {e}", cred.id()))?;
        store_secret(cred.secret_name(), value).map_err(|e| e.to_string())?;
        println!("{:<11} verified and stored{}", cred.id(), quota.map(|q| format!(" · {q}")).unwrap_or_default());
    } else {
        store_secret(cred.secret_name(), value).map_err(|e| e.to_string())?;
        println!("{:<11} stored (not verified)", cred.id());
    }
    Ok(())
}

/// True when the path is inside a git working tree and git does not ignore it.
fn tracked_by_git(path: &Path) -> bool {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let out = std::process::Command::new("git").arg("-C").arg(dir).arg("check-ignore").arg("-q").arg(path.file_name().unwrap_or_default()).output();
    // exit 0: ignored; 1: not ignored; 128: not a repository or git error
    matches!(out.map(|o| o.status.code()), Ok(Some(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_secrets_file_format() {
        let text = "# Cyber Hub credentials\nvirustotal = \"aaaa\"\n\nshodan=bbbb\nabuseipdb =\n";
        let v = parse_secrets(text).unwrap();
        assert_eq!(v, vec![(Cred::Ti(KeyId::Virustotal), "aaaa".to_string()), (Cred::Ti(KeyId::Shodan), "bbbb".to_string())]);
        assert!(parse_secrets("nope = x").unwrap_err().contains("unknown credential id"));
        assert!(parse_secrets("shodan = a\nshodan = b").unwrap_err().contains("twice"));
        assert!(parse_secrets("just a line").is_err());
    }

    #[test]
    fn ids_and_formats() {
        for c in Cred::ALL {
            assert_eq!(Cred::parse(c.id()), Some(c));
        }
        assert!(Cred::Nvd.check_format("0123abcd-0123-abcd-0123-0123456789ab").is_ok());
        assert!(Cred::Nvd.check_format("bad key").is_err());
    }

    #[test]
    fn credentials_are_refused_as_arguments() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let err = rt.block_on(run(&["set".into(), "shodan".into(), "SECRETVALUE123".into()])).unwrap_err();
        assert!(err.contains("do not pass credentials as arguments") && !err.contains("SECRETVALUE123"));
    }

    #[test]
    fn the_secrets_template_is_ignored_by_git() {
        // the documented local secrets file location must never be committable
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(!tracked_by_git(&root.join("secrets.local.env")));
    }
}
