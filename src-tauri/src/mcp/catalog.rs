//! The MCP tool catalogue: names, descriptions, input schemas and the permission category
//! each tool belongs to. Shared by the stdio server (advertises tools) and the in-app bridge
//! (enforces the category's policy).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// What a tool can do, which decides the approval policy that applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Reads local Cyber Hub data or cached results. Always allowed.
    Read,
    /// Sends an indicator or query to an external service (VirusTotal, threat-intel
    /// providers, NVD). Allow, ask or deny.
    ExternalLookup,
    /// Writes local data (findings, saved indicators). Ask or deny.
    LocalWrite,
    /// Starts a security tool. Ask or deny; the native confirmation always follows.
    RunTools,
    /// Uploads a file to VirusTotal. Ask or deny; native file picker and confirmation follow.
    FileUpload,
    /// Writes a report file through the native save dialog. Ask or deny.
    Export,
}

impl Category {
    pub const ALL: [Category; 6] = [Category::Read, Category::ExternalLookup, Category::LocalWrite, Category::RunTools, Category::FileUpload, Category::Export];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Read => "read",
            Category::ExternalLookup => "external_lookup",
            Category::LocalWrite => "local_write",
            Category::RunTools => "run_tools",
            Category::FileUpload => "file_upload",
            Category::Export => "export",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Read => "Read local data",
            Category::ExternalLookup => "External lookups (VirusTotal, threat intelligence, NVD)",
            Category::LocalWrite => "Create findings and save indicators",
            Category::RunTools => "Run security tools",
            Category::FileUpload => "Upload files to VirusTotal",
            Category::Export => "Export reports",
        }
    }

    /// Policies a user may choose for this category.
    pub fn allowed_policies(self) -> &'static [Policy] {
        match self {
            Category::Read => &[Policy::Allow],
            Category::ExternalLookup => &[Policy::Allow, Policy::Ask, Policy::Deny],
            _ => &[Policy::Ask, Policy::Deny],
        }
    }

    pub fn default_policy(self) -> Policy {
        match self {
            Category::Read => Policy::Allow,
            _ => Policy::Ask,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// run without asking
    Allow,
    /// ask the user in Cyber Hub every time
    Ask,
    /// refuse
    Deny,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "allow" => Some(Policy::Allow),
            "ask" => Some(Policy::Ask),
            "deny" => Some(Policy::Deny),
            _ => None,
        }
    }
}

pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub group: &'static str,
    pub description: &'static str,
    pub category: Category,
    /// JSON Schema of the arguments (an object schema)
    pub schema: fn() -> Value,
}

fn obj(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false })
}
fn none() -> Value {
    obj(json!({}), &[])
}
fn project_id() -> Value {
    json!({ "type": "integer", "minimum": 1, "description": "Cyber Hub project ID (from cyberhub_list_projects)" })
}
fn run_id() -> Value {
    json!({ "type": "integer", "minimum": 1, "description": "Run (execution) ID" })
}
fn indicator() -> Value {
    json!({ "type": "string", "minLength": 1, "maxLength": 2048, "description": "Public IP address, domain, http(s) URL, or MD5/SHA-1/SHA-256 hash. Private and internal values are refused." })
}
fn hash() -> Value {
    json!({ "type": "string", "pattern": "^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", "description": "MD5, SHA-1 or SHA-256 hash" })
}
fn exec_args() -> Value {
    obj(
        json!({
            "tool_id": { "type": "string", "maxLength": 64, "description": "Catalog tool ID (from cyberhub_list_tools)" },
            "project_id": project_id(),
            "args": { "type": "array", "maxItems": 256, "items": { "type": "string", "maxLength": 4096 }, "description": "Command-line arguments, one per item (no shell; pipes and redirection have no effect)" }
        }),
        &["tool_id", "args"],
    )
}

pub const SERVER_INSTRUCTIONS: &str = "Cyber Hub is a local security workstation. Use the discovery tools first \
(cyberhub_get_status, cyberhub_list_tools, cyberhub_list_projects). Security tools may only target assets inside an \
active project's authorized scope: check with cyberhub_get_project_scope / cyberhub_validate_target and \
cyberhub_preview_run before cyberhub_run_tool. Runs, file uploads, exports, local writes and (by default) external \
lookups require approval by the human user inside Cyber Hub; a tool may return status \"awaiting_approval\" with an \
approvalId to poll with cyberhub_get_approval_status. Never attempt to test targets that are out of scope.";

pub static TOOLS: &[ToolSpec] = &[
    // ── discovery
    ToolSpec { name: "cyberhub_get_status", title: "Cyber Hub status", group: "discovery", category: Category::Read,
        description: "Status of the running Cyber Hub app: version, provider availability, installed tool count, running processes, pending approvals and the active MCP permission policy.", schema: none },
    ToolSpec { name: "cyberhub_list_modules", title: "List modules", group: "discovery", category: Category::Read,
        description: "Cyber Hub modules and which MCP tools cover each one.", schema: none },
    ToolSpec { name: "cyberhub_list_tools", title: "List security tools", group: "discovery", category: Category::Read,
        description: "Security tools in the Cyber Hub catalog with category, kind, whether they require project scope, and local installation status.",
        schema: || obj(json!({
            "category": { "type": "string", "maxLength": 64, "description": "Only this catalog category" },
            "installed_only": { "type": "boolean", "description": "Only tools detected on this machine" }
        }), &[]) },
    ToolSpec { name: "cyberhub_get_tool_details", title: "Tool details", group: "discovery", category: Category::Read,
        description: "Details for one catalog tool: description, documentation link, example commands, scope requirement and detection status.",
        schema: || obj(json!({ "tool_id": { "type": "string", "maxLength": 64 } }), &["tool_id"]) },
    ToolSpec { name: "cyberhub_list_supported_providers", title: "List intelligence providers", group: "discovery", category: Category::Read,
        description: "Threat-intelligence and vulnerability providers, whether each is configured and enabled, and its last observed availability. Credentials are never returned.", schema: none },
    // ── projects and scope
    ToolSpec { name: "cyberhub_list_projects", title: "List projects", group: "projects", category: Category::Read,
        description: "Assessment projects with status, target and finding counts.", schema: none },
    ToolSpec { name: "cyberhub_get_project", title: "Get project", group: "projects", category: Category::Read,
        description: "One project with description, rules of engagement, notes and scope entries.",
        schema: || obj(json!({ "project_id": project_id() }), &["project_id"]) },
    ToolSpec { name: "cyberhub_get_project_scope", title: "Get project scope", group: "projects", category: Category::Read,
        description: "The authorized scope of a project as stored in Cyber Hub: in-scope and excluded targets plus rules of engagement.",
        schema: || obj(json!({ "project_id": project_id() }), &["project_id"]) },
    ToolSpec { name: "cyberhub_validate_target", title: "Validate targets against scope", group: "projects", category: Category::Read,
        description: "Check targets (hosts, IPs, CIDRs, URLs) against a project's scope, including exclusions. Uses the same scope engine as tool runs.",
        schema: || obj(json!({ "project_id": project_id(), "targets": { "type": "array", "minItems": 1, "maxItems": 50, "items": { "type": "string", "maxLength": 2048 } } }), &["project_id", "targets"]) },
    ToolSpec { name: "cyberhub_list_findings", title: "List findings", group: "projects", category: Category::Read,
        description: "Findings, optionally for one project.",
        schema: || obj(json!({ "project_id": project_id() }), &[]) },
    ToolSpec { name: "cyberhub_create_finding", title: "Create finding", group: "projects", category: Category::LocalWrite,
        description: "Create a finding in a project. Requires the user's approval in Cyber Hub.",
        schema: || obj(json!({
            "project_id": project_id(),
            "title": { "type": "string", "minLength": 1, "maxLength": 300 },
            "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
            "status": { "type": "string", "enum": ["open", "confirmed", "reported", "resolved", "false_positive"] },
            "description": { "type": "string", "maxLength": 20000 },
            "affected_target": { "type": "string", "maxLength": 500 },
            "cve": { "type": "string", "maxLength": 32 }
        }), &["project_id", "title", "severity"]) },
    // ── execution
    ToolSpec { name: "cyberhub_preview_run", title: "Preview a tool run", group: "execution", category: Category::Read,
        description: "Validate a planned run without starting anything: resolved program, arguments (credentials redacted), every target found in the arguments and target files checked against the project scope, warnings and notes.",
        schema: exec_args },
    ToolSpec { name: "cyberhub_run_tool", title: "Run a security tool", group: "execution", category: Category::RunTools,
        description: "Start a catalog tool inside a project's scope through Cyber Hub's execution engine. Requires approval in Cyber Hub and the native confirmation dialog. Returns a run ID.",
        schema: exec_args },
    ToolSpec { name: "cyberhub_get_run_status", title: "Run status", group: "execution", category: Category::Read,
        description: "Status, exit code and timing of a run.", schema: || obj(json!({ "run_id": run_id() }), &["run_id"]) },
    ToolSpec { name: "cyberhub_get_run_output", title: "Run output", group: "execution", category: Category::Read,
        description: "The last lines of a run's output (live while running; stored and redacted after it ends).",
        schema: || obj(json!({ "run_id": run_id(), "tail_lines": { "type": "integer", "minimum": 1, "maximum": 2000 } }), &["run_id"]) },
    ToolSpec { name: "cyberhub_cancel_run", title: "Cancel a run", group: "execution", category: Category::Read,
        description: "Cancel a running tool; the whole process tree is terminated.", schema: || obj(json!({ "run_id": run_id() }), &["run_id"]) },
    ToolSpec { name: "cyberhub_list_runs", title: "List runs", group: "execution", category: Category::Read,
        description: "Recent tool runs and installations.",
        schema: || obj(json!({ "limit": { "type": "integer", "minimum": 1, "maximum": 200 }, "project_id": project_id() }), &[]) },
    // ── VirusTotal
    ToolSpec { name: "cyberhub_vt_lookup", title: "VirusTotal lookup", group: "virustotal", category: Category::ExternalLookup,
        description: "VirusTotal reputation of an IP, domain, URL or file hash (sends the indicator to VirusTotal; never uploads anything).",
        schema: || obj(json!({ "indicator": indicator(), "refresh": { "type": "boolean" } }), &["indicator"]) },
    ToolSpec { name: "cyberhub_vt_lookup_hash", title: "VirusTotal hash lookup", group: "virustotal", category: Category::ExternalLookup,
        description: "VirusTotal report for a file hash. Sends only the hash; never uploads a file.",
        schema: || obj(json!({ "hash": hash(), "refresh": { "type": "boolean" } }), &["hash"]) },
    ToolSpec { name: "cyberhub_vt_upload_file", title: "Upload a file to VirusTotal", group: "virustotal", category: Category::FileUpload,
        description: "Ask the user to choose a file in Cyber Hub's native file picker and, after the public-sharing warning and native confirmation, upload it for analysis. The AI client cannot choose the file. Optionally pass the SHA-256 you expect; a different file is refused.",
        schema: || obj(json!({ "expected_sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" } }), &[]) },
    ToolSpec { name: "cyberhub_vt_get_analysis", title: "VirusTotal analysis status", group: "virustotal", category: Category::ExternalLookup,
        description: "Status of a VirusTotal analysis started by an upload.",
        schema: || obj(json!({ "analysis_id": { "type": "string", "minLength": 1, "maxLength": 256 } }), &["analysis_id"]) },
    ToolSpec { name: "cyberhub_vt_get_report", title: "Cached VirusTotal report", group: "virustotal", category: Category::Read,
        description: "The locally cached VirusTotal report for a hash, IP, domain or URL (no network request).",
        schema: || obj(json!({ "indicator": indicator() }), &["indicator"]) },
    // ── threat intelligence
    ToolSpec { name: "cyberhub_threat_intel_lookup", title: "Threat intelligence lookup", group: "threat_intel", category: Category::ExternalLookup,
        description: "Look up an indicator across configured providers. Each provider's verdict, scores and source link are kept in its own terms; no combined score is computed.",
        schema: || obj(json!({ "indicator": indicator(), "providers": { "type": "array", "maxItems": 7, "items": { "type": "string", "enum": ["virustotal", "abuseipdb", "otx", "urlhaus", "malwarebazaar", "threatfox", "shodan"] } }, "refresh": { "type": "boolean" } }), &["indicator"]) },
    ToolSpec { name: "cyberhub_threat_intel_compare", title: "Compare providers", group: "threat_intel", category: Category::ExternalLookup,
        description: "Side-by-side comparison of provider results for one indicator (verdicts, scores, families, categories, timestamps), each in the provider's own wording.",
        schema: || obj(json!({ "indicator": indicator(), "providers": { "type": "array", "maxItems": 7, "items": { "type": "string" } } }), &["indicator"]) },
    ToolSpec { name: "cyberhub_get_saved_indicators", title: "Saved indicators", group: "threat_intel", category: Category::Read,
        description: "Indicators the user saved in Threat Intel.", schema: none },
    ToolSpec { name: "cyberhub_save_indicator", title: "Save indicator", group: "threat_intel", category: Category::LocalWrite,
        description: "Save an indicator with an optional note. Requires approval in Cyber Hub.",
        schema: || obj(json!({ "indicator": indicator(), "note": { "type": "string", "maxLength": 500 } }), &["indicator"]) },
    // ── vulnerability intelligence
    ToolSpec { name: "cyberhub_lookup_cve", title: "Look up a CVE", group: "vulnerabilities", category: Category::Read,
        description: "A CVE from the local cache; with live=true it is fetched from NVD when not cached (external lookup).",
        schema: || obj(json!({ "cve_id": { "type": "string", "pattern": "^(?i)CVE-[0-9]{4}-[0-9]{4,}$" }, "live": { "type": "boolean" } }), &["cve_id"]) },
    ToolSpec { name: "cyberhub_search_vulnerabilities", title: "Search vulnerabilities", group: "vulnerabilities", category: Category::Read,
        description: "Keyword or CVE ID search in the local CVE cache, or live in NVD with live=true (external lookup).",
        schema: || obj(json!({ "query": { "type": "string", "minLength": 2, "maxLength": 200 }, "live": { "type": "boolean" } }), &["query"]) },
    ToolSpec { name: "cyberhub_get_vulnerability_details", title: "Vulnerability details", group: "vulnerabilities", category: Category::Read,
        description: "Full cached record of a CVE: CVSS vectors, CWEs, affected products, references and the CISA KEV flag.",
        schema: || obj(json!({ "cve_id": { "type": "string", "pattern": "^(?i)CVE-[0-9]{4}-[0-9]{4,}$" } }), &["cve_id"]) },
    // ── reports and history
    ToolSpec { name: "cyberhub_generate_report", title: "Generate project report", group: "reports", category: Category::Read,
        description: "Markdown assessment report for a project (scope, findings, notes), generated from local data and returned as text.",
        schema: || obj(json!({ "project_id": project_id() }), &["project_id"]) },
    ToolSpec { name: "cyberhub_export_report", title: "Export a report file", group: "reports", category: Category::Export,
        description: "Save a project report or a threat-intelligence report to a file. Requires approval; the user chooses the location in a native save dialog.",
        schema: || obj(json!({
            "kind": { "type": "string", "enum": ["project", "threat_intel"] },
            "project_id": project_id(),
            "indicator": indicator(),
            "format": { "type": "string", "enum": ["md", "json"] }
        }), &["kind"]) },
    ToolSpec { name: "cyberhub_get_activity", title: "Recent activity", group: "reports", category: Category::Read,
        description: "Recent activity log entries (runs, lookups, findings, uploads).",
        schema: || obj(json!({ "limit": { "type": "integer", "minimum": 1, "maximum": 500 }, "kind": { "type": "string", "maxLength": 40 } }), &[]) },
    ToolSpec { name: "cyberhub_get_run_details", title: "Run details", group: "reports", category: Category::Read,
        description: "Full record of a run: tool, redacted arguments, project, status, exit code, timing and the beginning of its stored output.",
        schema: || obj(json!({ "run_id": run_id() }), &["run_id"]) },
    // ── approvals
    ToolSpec { name: "cyberhub_get_approval_status", title: "Approval status", group: "approvals", category: Category::Read,
        description: "Status of a request that is waiting for the user's approval in Cyber Hub, and its result once decided.",
        schema: || obj(json!({ "approval_id": { "type": "string", "minLength": 8, "maxLength": 64 } }), &["approval_id"]) },
];

pub fn tool(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == name)
}

/// Category for a specific call (some tools only reach the network when asked to).
pub fn effective_category(spec: &ToolSpec, args: &Value) -> Category {
    match spec.name {
        "cyberhub_lookup_cve" | "cyberhub_search_vulnerabilities" if args.get("live").and_then(Value::as_bool) == Some(true) => Category::ExternalLookup,
        _ => spec.category,
    }
}

/// Read-only resources and the read tool that serves each.
pub static RESOURCES: &[(&str, &str, &str, &str)] = &[
    ("cyberhub://status", "status", "Cyber Hub status", "cyberhub_get_status"),
    ("cyberhub://projects", "projects", "Projects", "cyberhub_list_projects"),
    ("cyberhub://tools", "tools", "Security tool catalog and detection status", "cyberhub_list_tools"),
    ("cyberhub://providers", "providers", "Intelligence providers and availability", "cyberhub_list_supported_providers"),
    ("cyberhub://runs/recent", "recent-runs", "Recent tool runs", "cyberhub_list_runs"),
    ("cyberhub://findings", "findings", "Findings across projects", "cyberhub_list_findings"),
];

pub const SCOPE_TEMPLATE: &str = "cyberhub://project/{project_id}/scope";

/// Resolve a resource URI to (read tool, arguments). Only read tools are reachable.
pub fn resource_call(uri: &str) -> Option<(&'static str, Value)> {
    if let Some((_, _, _, tool)) = RESOURCES.iter().find(|r| r.0 == uri) {
        return Some((tool, json!({})));
    }
    let id = uri.strip_prefix("cyberhub://project/")?.strip_suffix("/scope")?;
    let id: i64 = id.parse().ok().filter(|n| *n > 0)?;
    Some(("cyberhub_get_project_scope", json!({ "project_id": id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_unique_valid_and_schemas_are_objects() {
        let mut names = std::collections::HashSet::new();
        for t in TOOLS {
            assert!(names.insert(t.name), "duplicate {}", t.name);
            assert!(t.name.len() <= 64 && t.name.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{}", t.name);
            let s = (t.schema)();
            assert_eq!(s["type"], "object", "{}", t.name);
            assert_eq!(s["additionalProperties"], false, "{}", t.name);
            for r in s["required"].as_array().unwrap() {
                assert!(s["properties"].get(r.as_str().unwrap()).is_some(), "{} requires an undefined property", t.name);
            }
        }
        assert_eq!(TOOLS.len(), 34);
    }

    #[test]
    fn sensitive_tools_are_not_read_only() {
        for (name, cat) in [
            ("cyberhub_run_tool", Category::RunTools),
            ("cyberhub_vt_upload_file", Category::FileUpload),
            ("cyberhub_create_finding", Category::LocalWrite),
            ("cyberhub_save_indicator", Category::LocalWrite),
            ("cyberhub_export_report", Category::Export),
            ("cyberhub_threat_intel_lookup", Category::ExternalLookup),
        ] {
            assert_eq!(tool(name).unwrap().category, cat, "{name}");
        }
        let cve = tool("cyberhub_lookup_cve").unwrap();
        assert_eq!(effective_category(cve, &json!({"cve_id": "CVE-2021-44228"})), Category::Read);
        assert_eq!(effective_category(cve, &json!({"cve_id": "CVE-2021-44228", "live": true})), Category::ExternalLookup);
    }

    #[test]
    fn policies_per_category() {
        assert_eq!(Category::Read.allowed_policies(), &[Policy::Allow]);
        assert!(!Category::RunTools.allowed_policies().contains(&Policy::Allow), "runs always need approval");
        assert!(!Category::FileUpload.allowed_policies().contains(&Policy::Allow), "uploads always need approval");
        assert!(Category::ExternalLookup.allowed_policies().contains(&Policy::Allow));
        for c in Category::ALL {
            assert!(c.allowed_policies().contains(&c.default_policy()));
            assert_eq!(Category::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn resources_map_only_to_read_tools() {
        for r in RESOURCES {
            assert_eq!(tool(r.3).unwrap().category, Category::Read);
        }
        assert_eq!(resource_call("cyberhub://project/7/scope").unwrap().1, json!({"project_id": 7}));
        assert!(resource_call("cyberhub://project/../scope").is_none());
        assert!(resource_call("cyberhub://project/0/scope").is_none());
        assert!(resource_call("file:///etc/passwd").is_none());
    }
}
