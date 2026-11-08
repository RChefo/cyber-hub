//! Finding library (docs/DATA_MODEL.md#finding-library-schema-14): reusable write-ups that are
//! applied when a finding is recorded, and by scan imports for findings whose tool rule matches a
//! template's import rule (`nessus:57582`, `zap:10038`, …). Templates belong to the workstation, not
//! to a project, so they carry over between engagements. The library can be exported to and
//! imported from a JSON file.

use std::collections::HashMap;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, now};

pub const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
/// Formats an import rule can name (the scan importer's formats).
pub const RULE_FORMATS: &[&str] = &["nmap", "nuclei", "nessus", "burp", "zap", "sarif", "openvas"];
pub const MAX_TEMPLATES: usize = 2_000;
pub const MAX_LIBRARY_FILE: usize = 5 * 1024 * 1024;
const FILE_FORMAT: &str = "cyberhub-finding-templates";

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingTemplate {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub rules: Vec<String>,
    pub use_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateInput {
    #[serde(default)]
    pub id: Option<i64>,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
}

const COLS: &str = "id, title, severity, category, description, remediation, refs, tags, rules, use_count, created_at, updated_at";

fn list_of(s: String) -> Vec<String> {
    serde_json::from_str(&s).unwrap_or_default()
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<FindingTemplate> {
    Ok(FindingTemplate {
        id: r.get(0)?,
        title: r.get(1)?,
        severity: r.get(2)?,
        category: r.get(3)?,
        description: r.get(4)?,
        remediation: r.get(5)?,
        references: list_of(r.get(6)?),
        tags: list_of(r.get(7)?),
        rules: list_of(r.get(8)?),
        use_count: r.get(9)?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
    })
}

pub fn list(c: &Connection) -> AppResult<Vec<FindingTemplate>> {
    let mut stmt = c.prepare(&format!("SELECT {COLS} FROM finding_templates ORDER BY use_count DESC, title COLLATE NOCASE"))?;
    let rows = stmt.query_map([], row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn get(c: &Connection, id: i64) -> AppResult<FindingTemplate> {
    c.query_row(&format!("SELECT {COLS} FROM finding_templates WHERE id = ?1"), params![id], row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("finding template {id}")))
}

/// `format:rule` in its stored form (lower-case format, rule as written), or why it is not valid.
pub fn normalize_rule(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let Some((format, rule)) = raw.split_once(':') else {
        return Err(format!("“{raw}” is not an import rule; write format:rule, for example nessus:57582"));
    };
    let format = format.trim().to_lowercase();
    let rule = rule.trim();
    if !RULE_FORMATS.contains(&format.as_str()) {
        return Err(format!("“{format}” is not an import format ({})", RULE_FORMATS.join(", ")));
    }
    if rule.is_empty() || rule.chars().count() > 200 || rule.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("The rule in “{raw}” must be 1–200 characters without spaces"));
    }
    Ok(format!("{format}:{rule}"))
}

/// Key used to look a rule up (rules match case-insensitively).
pub fn rule_key(format: &str, rule: &str) -> String {
    format!("{}:{}", format.trim().to_lowercase(), rule.trim().to_lowercase())
}

struct Clean {
    title: String,
    severity: String,
    category: String,
    description: String,
    remediation: String,
    refs: String,
    tags: String,
    rules: Vec<String>,
}

fn dedup_clean(field: &str, items: &[String], max_items: usize, max_len: usize) -> AppResult<Vec<String>> {
    // checked first: deduplication below is quadratic in the number of entries
    if items.len() > max_items * 4 {
        return Err(validation(format!("At most {max_items} entries in {}", field.to_lowercase())));
    }
    let mut out: Vec<String> = Vec::new();
    for i in items {
        let v = clean(field, i, max_len, false)?;
        if !v.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&v)) {
            out.push(v);
        }
    }
    if out.len() > max_items {
        return Err(validation(format!("At most {max_items} entries in {}", field.to_lowercase())));
    }
    Ok(out)
}

fn clean_input(input: &TemplateInput) -> AppResult<Clean> {
    let severity = input.severity.trim().to_lowercase();
    if !SEVERITIES.contains(&severity.as_str()) {
        return Err(validation("Severity must be critical, high, medium, low or info"));
    }
    if input.rules.len() > 200 {
        return Err(validation("At most 50 import rules"));
    }
    let mut rules: Vec<String> = Vec::new();
    for r in input.rules.iter().filter(|r| !r.trim().is_empty()) {
        let n = normalize_rule(r).map_err(validation)?;
        if !rules.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
            rules.push(n);
        }
    }
    if rules.len() > 50 {
        return Err(validation("At most 50 import rules"));
    }
    Ok(Clean {
        title: clean("Title", &input.title, 200, true)?,
        severity,
        category: clean("Category", &input.category, 100, false)?,
        description: clean("Description", &input.description, 50_000, false)?,
        remediation: clean("Remediation", &input.remediation, 50_000, false)?,
        refs: serde_json::to_string(&dedup_clean("References", &input.references, 30, 2000)?)?,
        tags: serde_json::to_string(&dedup_clean("Tags", &input.tags, 20, 40)?)?,
        rules,
    })
}

/// The template (other than `except`) that already uses one of `rules`.
fn rule_owner(c: &Connection, rules: &[String], except: Option<i64>) -> AppResult<Option<(String, String)>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let wanted: Vec<String> = rules.iter().map(|r| r.to_lowercase()).collect();
    for t in list(c)? {
        if Some(t.id) == except {
            continue;
        }
        if let Some(r) = t.rules.iter().find(|r| wanted.contains(&r.to_lowercase())) {
            return Ok(Some((r.clone(), t.title)));
        }
    }
    Ok(None)
}

/// Creates or updates a template. Titles are unique (case-insensitive), and an import rule can
/// belong to one template only.
pub fn save(c: &Connection, input: &TemplateInput) -> AppResult<i64> {
    let t = clean_input(input)?;
    let taken: Option<i64> = c.query_row("SELECT id FROM finding_templates WHERE title = ?1 COLLATE NOCASE", params![t.title], |r| r.get(0)).optional()?;
    if taken.is_some() && taken != input.id {
        return Err(validation(format!("A template named “{}” already exists", t.title)));
    }
    if let Some((rule, owner)) = rule_owner(c, &t.rules, input.id)? {
        return Err(validation(format!("The import rule {rule} already belongs to the template “{owner}”")));
    }
    let rules = serde_json::to_string(&t.rules)?;
    let ts = now();
    match input.id {
        Some(id) => {
            get(c, id)?;
            c.execute(
                "UPDATE finding_templates SET title=?2, severity=?3, category=?4, description=?5, remediation=?6, refs=?7, tags=?8, rules=?9, updated_at=?10 WHERE id=?1",
                params![id, t.title, t.severity, t.category, t.description, t.remediation, t.refs, t.tags, rules, ts],
            )?;
            Ok(id)
        }
        None => {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM finding_templates", [], |r| r.get(0))?;
            if n as usize >= MAX_TEMPLATES {
                return Err(validation(format!("The library holds at most {MAX_TEMPLATES} templates")));
            }
            c.execute(
                "INSERT INTO finding_templates (title, severity, category, description, remediation, refs, tags, rules, use_count, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?9)",
                params![t.title, t.severity, t.category, t.description, t.remediation, t.refs, t.tags, rules, ts],
            )?;
            Ok(c.last_insert_rowid())
        }
    }
}

pub fn delete(c: &Connection, id: i64) -> AppResult<()> {
    if c.execute("DELETE FROM finding_templates WHERE id = ?1", params![id])? == 0 {
        return Err(AppError::NotFound(format!("finding template {id}")));
    }
    Ok(())
}

pub fn mark_used(c: &Connection, id: i64) -> AppResult<()> {
    c.execute("UPDATE finding_templates SET use_count = use_count + 1 WHERE id = ?1", params![id])?;
    Ok(())
}

/// Templates by import rule key (see [`rule_key`]).
pub fn by_rule(c: &Connection) -> AppResult<HashMap<String, FindingTemplate>> {
    let mut map = HashMap::new();
    for t in list(c)? {
        for r in &t.rules {
            if let Some((f, rule)) = r.split_once(':') {
                map.entry(rule_key(f, rule)).or_insert_with(|| t.clone());
            }
        }
    }
    Ok(map)
}

/* ───────────────────────── library file ───────────────────────── */

pub fn export_json(c: &Connection) -> AppResult<String> {
    let templates: Vec<Value> = list(c)?
        .into_iter()
        .map(|t| json!({ "title": t.title, "severity": t.severity, "category": t.category, "description": t.description, "remediation": t.remediation, "references": t.references, "tags": t.tags, "rules": t.rules }))
        .collect();
    Ok(serde_json::to_string_pretty(&json!({ "format": FILE_FORMAT, "version": 1, "exportedAt": now(), "templates": templates }))?)
}

#[derive(Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryImport {
    pub created: usize,
    /// a template with the same title exists; it was left as it is
    pub skipped: Vec<String>,
    /// entries that were not valid, with the reason
    pub invalid: Vec<String>,
}

/// Adds the templates of a library file. Existing titles are never overwritten. All or nothing
/// for the valid entries (one savepoint).
pub fn import_json(c: &Connection, text: &str) -> AppResult<LibraryImport> {
    if text.len() > MAX_LIBRARY_FILE {
        return Err(validation("The library file is larger than 5 MB"));
    }
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| validation(format!("The file is not valid JSON: {e}")))?;
    if v.get("format").and_then(Value::as_str) != Some(FILE_FORMAT) {
        return Err(validation("This is not a Cyber Hub finding library file"));
    }
    let entries = v.get("templates").and_then(Value::as_array).ok_or_else(|| validation("The file has no templates"))?;
    if entries.len() > MAX_TEMPLATES {
        return Err(validation(format!("The file has more than {MAX_TEMPLATES} templates")));
    }
    crate::workspace::assets::with_savepoint(c, || {
        let mut out = LibraryImport::default();
        for (i, e) in entries.iter().enumerate() {
            let input: TemplateInput = match serde_json::from_value(json!({
                "title": e.get("title").cloned().unwrap_or(Value::Null),
                "severity": e.get("severity").cloned().unwrap_or(Value::Null),
                "category": e.get("category").cloned().unwrap_or(json!("")),
                "description": e.get("description").cloned().unwrap_or(json!("")),
                "remediation": e.get("remediation").cloned().unwrap_or(json!("")),
                "references": e.get("references").cloned().unwrap_or(json!([])),
                "tags": e.get("tags").cloned().unwrap_or(json!([])),
                "rules": e.get("rules").cloned().unwrap_or(json!([])),
            })) {
                Ok(x) => x,
                Err(_) => {
                    out.invalid.push(format!("Entry {}: missing or mistyped fields", i + 1));
                    continue;
                }
            };
            let title = input.title.trim().to_string();
            let exists: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM finding_templates WHERE title = ?1 COLLATE NOCASE)", params![title], |r| r.get(0))?;
            if exists {
                out.skipped.push(title);
                continue;
            }
            match save(c, &input) {
                Ok(_) => out.created += 1,
                Err(AppError::Validation(m)) => out.invalid.push(format!("“{}”: {m}", title.chars().take(80).collect::<String>())),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    })
}

/* ───────────────────────── starter templates ───────────────────────── */

struct Starter {
    title: &'static str,
    severity: &'static str,
    category: &'static str,
    description: &'static str,
    remediation: &'static str,
    references: &'static [&'static str],
    rules: &'static [&'static str],
}

const STARTERS: &[Starter] = &[
    Starter {
        title: "SQL injection",
        severity: "high",
        category: "Injection",
        description: "User-supplied input reaches a database query without being separated from the query's code. An attacker can change what the query does: read or modify data they are not allowed to see, bypass authentication, and depending on the database and its privileges, run commands on the server.",
        remediation: "Use parameterized queries (prepared statements) or a safe query builder for every query that includes input. Do not build queries by concatenating strings. Run the application's database account with the least privileges it needs. Verify the fix by repeating the original request and confirming the input is treated as data.",
        references: &["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/89.html"],
        rules: &["zap:40018", "burp:1049088"],
    },
    Starter {
        title: "Reflected cross-site scripting",
        severity: "medium",
        category: "Injection",
        description: "The application includes input from the request in its response without encoding it for the context it appears in. A crafted link can make a victim's browser run script in the application's origin, with access to the victim's session and to everything the victim can do in the application.",
        remediation: "Encode output for its context (HTML body, attribute, JavaScript, URL) using the framework's templating, and validate input against what is expected. Add a restrictive Content-Security-Policy as a second layer. Verify by repeating the payload and confirming it is rendered as text.",
        references: &["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/79.html"],
        rules: &["zap:40012", "burp:2097920"],
    },
    Starter {
        title: "Content-Security-Policy header not set",
        severity: "low",
        category: "Security misconfiguration",
        description: "Responses do not include a Content-Security-Policy header. The policy limits where scripts, styles and other resources may be loaded from, and so reduces the impact of cross-site scripting and content injection. Without it the browser applies no such limits.",
        remediation: "Define a Content-Security-Policy that allows only the sources the application needs, starting from default-src 'self', and avoid 'unsafe-inline' for scripts. Roll it out in report-only mode first to find violations.",
        references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
        rules: &["zap:10038"],
    },
    Starter {
        title: "Missing protection against clickjacking",
        severity: "low",
        category: "Security misconfiguration",
        description: "Pages can be embedded in frames on other sites because responses set neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive. An attacker can overlay the framed page and trick users into clicking controls they cannot see.",
        remediation: "Send Content-Security-Policy: frame-ancestors 'none' (or the specific origins that may frame the application), and X-Frame-Options: DENY for older browsers.",
        references: &["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
        rules: &["zap:10020"],
    },
    Starter {
        title: "Strict-Transport-Security header not set",
        severity: "low",
        category: "Transport security",
        description: "The HTTPS site does not send a Strict-Transport-Security header. Browsers may therefore still make the first request over plain HTTP, where an attacker on the network can intercept or redirect it.",
        remediation: "Send Strict-Transport-Security with a max-age of at least one year (max-age=31536000) on all HTTPS responses, and includeSubDomains once every subdomain supports HTTPS.",
        references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
        rules: &["zap:10035"],
    },
    Starter {
        title: "X-Content-Type-Options header missing",
        severity: "info",
        category: "Security misconfiguration",
        description: "Responses do not include X-Content-Type-Options: nosniff. Some browsers may then guess the content type of a response and treat, for example, an uploaded text file as script or HTML.",
        remediation: "Send X-Content-Type-Options: nosniff on all responses, and set an accurate Content-Type for every response.",
        references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        rules: &["zap:10021"],
    },
    Starter {
        title: "TLS certificate is not trusted",
        severity: "medium",
        category: "Transport security",
        description: "The service presents a certificate that clients cannot validate: it is self-signed or not issued by a trusted authority. Users and clients learn to accept certificate warnings, which removes the protection against interception by an attacker who presents their own certificate.",
        remediation: "Install a certificate issued by a trusted public authority (or by the organization's internal authority, deployed to all clients) that matches the host name and is within its validity period.",
        references: &["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
        rules: &["nessus:57582", "nessus:51192"],
    },
    Starter {
        title: "Deprecated TLS protocol versions enabled",
        severity: "medium",
        category: "Transport security",
        description: "The service accepts TLS 1.0 or TLS 1.1. Both versions are deprecated (RFC 8996) and lack modern cipher suites and protections. Supporting them lets clients and attackers negotiate weaker connections.",
        remediation: "Disable TLS 1.0 and 1.1 and allow only TLS 1.2 and TLS 1.3 with modern cipher suites. Check that the clients that need the service support TLS 1.2 or later.",
        references: &["https://www.rfc-editor.org/rfc/rfc8996", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
        rules: &["nessus:104743"],
    },
    Starter {
        title: "SSH server allows CBC-mode ciphers",
        severity: "low",
        category: "Transport security",
        description: "The SSH server offers ciphers in cipher-block-chaining (CBC) mode. CBC modes in SSH have known weaknesses that can allow an attacker in a privileged network position to recover small amounts of plaintext under certain conditions.",
        remediation: "Remove CBC ciphers from the server configuration and allow only modern authenticated ciphers (for OpenSSH, chacha20-poly1305 and the AES-GCM or AES-CTR ciphers). Restart the service and confirm the offered list.",
        references: &["https://www.openssh.com/manual.html"],
        rules: &["nessus:70658"],
    },
    Starter {
        title: "SMB signing not required",
        severity: "medium",
        category: "Network security",
        description: "The host accepts SMB connections without requiring message signing. An attacker on the network can relay authentication attempts to this host (NTLM relay) or tamper with SMB traffic.",
        remediation: "Require SMB signing on servers and clients (Group Policy: \"Microsoft network server: Digitally sign communications (always)\"). Test with dependent systems before enforcing it everywhere.",
        references: &["https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing"],
        rules: &["nessus:57608"],
    },
    Starter {
        title: "Directory listing enabled",
        severity: "low",
        category: "Information disclosure",
        description: "The web server lists the contents of directories that have no index page. Visitors can browse files that were not meant to be linked, such as backups, configuration files or source code.",
        remediation: "Disable directory listing in the web server configuration, and remove files from the web root that should not be served.",
        references: &["https://cwe.mitre.org/data/definitions/548.html"],
        rules: &["zap:0"],
    },
    Starter {
        title: "Software with known vulnerabilities",
        severity: "medium",
        category: "Vulnerable components",
        description: "The service runs a version of a component with publicly known vulnerabilities. The CVEs, their scores and whether they are known to be exploited are listed with this finding. Public exploit code often exists for such issues.",
        remediation: "Update the component to a supported version that fixes the listed vulnerabilities, and keep it covered by the regular patch process. Where an update is not possible yet, apply the vendor's mitigations and restrict network access to the service.",
        references: &["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        rules: &[],
    },
    Starter {
        title: "Default or weak credentials",
        severity: "high",
        category: "Authentication",
        description: "An account accepts a default, well-known or easily guessed password. Anyone who tries the common credentials for the product gains the account's access.",
        remediation: "Change the password to a unique, strong one, or disable the account. Require a password change on first use for every product that ships with default credentials, and add rate limiting or lockout to the login.",
        references: &["https://cwe.mitre.org/data/definitions/1392.html"],
        rules: &[],
    },
    Starter {
        title: "Insecure direct object reference",
        severity: "high",
        category: "Access control",
        description: "The application uses an identifier from the request (for example an account or document number) to access a record without checking that the current user may access it. Changing the identifier gives access to other users' data.",
        remediation: "Check on the server, for every request, that the authenticated user is allowed to access the requested object. Do not rely on identifiers being hard to guess.",
        references: &["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/639.html"],
        rules: &[],
    },
];

/// Adds the starter templates whose titles are not in the library yet; returns how many.
pub fn add_starters(c: &Connection) -> AppResult<usize> {
    crate::workspace::assets::with_savepoint(c, || {
        let mut n = 0;
        for s in STARTERS {
            let exists: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM finding_templates WHERE title = ?1 COLLATE NOCASE)", params![s.title], |r| r.get(0))?;
            if exists {
                continue;
            }
            // a rule another template already claims is left out rather than failing the set
            let mut rules: Vec<String> = s.rules.iter().map(|r| r.to_string()).collect();
            while let Some((taken, _)) = rule_owner(c, &rules, None)? {
                rules.retain(|r| !r.eq_ignore_ascii_case(&taken));
            }
            save(
                c,
                &TemplateInput {
                    id: None,
                    title: s.title.into(),
                    severity: s.severity.into(),
                    category: s.category.into(),
                    description: s.description.into(),
                    remediation: s.remediation.into(),
                    references: s.references.iter().map(|r| r.to_string()).collect(),
                    tags: vec![],
                    rules,
                },
            )?;
            n += 1;
        }
        Ok(n)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn input(title: &str, rules: &[&str]) -> TemplateInput {
        TemplateInput { title: title.into(), severity: "Medium".into(), rules: rules.iter().map(|r| r.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn templates_are_validated_and_unique() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let id = save(c, &TemplateInput { references: vec!["https://a".into(), "https://A".into(), " ".into()], tags: vec!["web".into()], ..input("Weak TLS", &["Nessus:104743", "nessus:104743"]) })?;
            let t = get(c, id)?;
            assert_eq!((t.severity.as_str(), t.rules.clone(), t.references.len()), ("medium", vec!["nessus:104743".to_string()], 1), "normalized and deduplicated");
            assert!(save(c, &input("weak tls", &[])).unwrap_err().to_string().contains("already exists"), "titles are unique without regard to case");
            assert!(save(c, &input("Other", &["NESSUS:104743"])).unwrap_err().to_string().contains("already belongs"), "a rule has one owner");
            assert!(save(c, &input("Bad rule", &["qualys:1"])).is_err());
            assert!(save(c, &input("Bad rule", &["nessus"])).is_err());
            assert!(save(c, &input("Bad rule", &["nessus:a b"])).is_err());
            assert!(save(c, &TemplateInput { severity: "urgent".into(), ..input("Sev", &[]) }).is_err());
            // updating keeps the title and rules it already owns
            save(c, &TemplateInput { id: Some(id), remediation: "Disable TLS 1.0".into(), ..input("Weak TLS", &["nessus:104743"]) })?;
            assert_eq!(get(c, id)?.remediation, "Disable TLS 1.0");
            mark_used(c, id)?;
            assert_eq!(get(c, id)?.use_count, 1);
            assert_eq!(by_rule(c)?.get("nessus:104743").map(|t| t.id), Some(id));
            delete(c, id)?;
            assert!(get(c, id).is_err());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn the_library_file_round_trips_without_overwriting() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            assert_eq!(add_starters(c)?, STARTERS.len());
            assert_eq!(add_starters(c)?, 0, "starters are added once");
            let file = export_json(c)?;
            let other = Db::open_in_memory().unwrap();
            other.with(|o| {
                save(o, &TemplateInput { description: "mine".into(), ..input("SQL injection", &[]) })?;
                let r = import_json(o, &file)?;
                assert_eq!(r.created, STARTERS.len() - 1);
                assert_eq!(r.skipped, vec!["SQL injection".to_string()]);
                let mine = list(o)?.into_iter().find(|t| t.title == "SQL injection").unwrap();
                assert_eq!(mine.description, "mine", "an existing template is not overwritten");
                assert!(mine.rules.is_empty());
                // the starters' rules other than the skipped template's arrived
                assert!(by_rule(o)?.contains_key("zap:10038"));
                assert!(!by_rule(o)?.contains_key("zap:40018"));
                Ok(())
            })?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn bad_library_files_are_refused_or_reported() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            assert!(import_json(c, "not json").is_err());
            assert!(import_json(c, r#"{"templates":[]}"#).unwrap_err().to_string().contains("not a Cyber Hub"));
            let r = import_json(c, r#"{"format":"cyberhub-finding-templates","version":1,"templates":[{"title":"A","severity":"high"},{"title":"B","severity":"nope"},{"severity":"low"},{"title":"C","severity":"low","rules":["zap:1","bogus"]}]}"#)?;
            assert_eq!(r.created, 1);
            assert_eq!(r.invalid.len(), 3, "{:?}", r.invalid);
            assert_eq!(list(c)?.len(), 1);
            Ok(())
        })
        .unwrap();
    }
}
