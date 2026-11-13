//! Built-in MCP prompts. They guide an AI client through ExploitX's tools and always require
//! working inside an authorized project scope. None of them encourages testing anything the
//! user is not authorized to test.

pub struct PromptSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// (argument, description, required)
    pub arguments: &'static [(&'static str, &'static str, bool)],
    pub template: &'static str,
}

const RULES: &str = "Rules you must follow:\n\
- Only act inside the authorized scope stored in ExploitX. Read it with cyberhub_get_project_scope and check targets with cyberhub_validate_target before planning anything.\n\
- If a target is out of scope, excluded, or the project is not active, stop and tell the user. Never try to work around scope checks.\n\
- Preview every run with cyberhub_preview_run and explain it before calling cyberhub_run_tool. The user approves runs in ExploitX; never claim an approval you did not receive.\n\
- Prefer the least intrusive option and conservative rates. Do not run denial-of-service, brute-force or exploitation tooling unless the rules of engagement explicitly allow it.\n\
- Report provider verdicts in each provider's own terms; never invent a combined score.";

pub static PROMPTS: &[PromptSpec] = &[
    PromptSpec {
        name: "network_reconnaissance",
        title: "Network reconnaissance",
        description: "Plan and run authorized network discovery for an ExploitX project.",
        arguments: &[("project_id", "ExploitX project ID", true), ("focus", "Optional focus, e.g. 'web ports' or a subnet inside scope", false)],
        template: "Perform authorized network reconnaissance for ExploitX project {project_id}. Focus: {focus}.\n\n\
Steps: 1) cyberhub_get_project_scope and summarize what is in scope and excluded. 2) cyberhub_list_tools with installed_only=true to see what is available. \
3) Propose a minimal plan (e.g. host discovery, then a limited service scan) and validate every target with cyberhub_validate_target. \
4) For each step, call cyberhub_preview_run, show the plan to the user, then cyberhub_run_tool. 5) Follow with cyberhub_get_run_status / cyberhub_get_run_output and summarize results. \
6) Offer to record notable issues with cyberhub_create_finding.\n\n{rules}",
    },
    PromptSpec {
        name: "web_application_assessment",
        title: "Web application assessment",
        description: "Assess an in-scope web application with ExploitX's catalog tools.",
        arguments: &[("project_id", "ExploitX project ID", true), ("url", "Base URL of the application (must be in scope)", true)],
        template: "Assess the web application {url} for ExploitX project {project_id}.\n\n\
First confirm {url} is in scope with cyberhub_validate_target. Check which web tools are installed (cyberhub_list_tools, category web). \
Start with passive and low-impact checks (headers, technology fingerprinting, content discovery with small wordlists and low rates). \
Preview each run, explain it, and only then request it. Record confirmed issues as findings with evidence references: \
look for a matching write-up with cyberhub_list_finding_templates, score CVSS vectors with cyberhub_score_cvss, and keep the \
project's OWASP WSTG checklist current (cyberhub_get_checklist, cyberhub_set_checklist_item).\n\n{rules}",
    },
    PromptSpec {
        name: "threat_intelligence_investigation",
        title: "Threat intelligence investigation",
        description: "Investigate an indicator across the configured intelligence providers.",
        arguments: &[("indicator", "IP address, domain, URL or hash", true)],
        template: "Investigate the indicator {indicator} with ExploitX.\n\n\
1) cyberhub_list_supported_providers to see which providers are configured. 2) cyberhub_threat_intel_lookup for {indicator}. \
3) Summarize which providers have records, their verdicts in their own words, scores with their scales, malware families, categories and first/last seen dates, with the source link for each. \
4) Look at related indicators and ask the user before pivoting to any of them. 5) Offer to save the indicator (cyberhub_save_indicator) or export a report (cyberhub_export_report). \
Do not combine provider scores into one number. Lookups send the indicator to external services; the user may need to approve them in ExploitX.",
    },
    PromptSpec {
        name: "malware_hash_investigation",
        title: "Malware hash investigation",
        description: "Investigate a file hash without uploading anything.",
        arguments: &[("hash", "MD5, SHA-1 or SHA-256", true)],
        template: "Investigate the file hash {hash}.\n\n\
Use cyberhub_vt_get_report for a cached result, then cyberhub_vt_lookup_hash and cyberhub_threat_intel_lookup (MalwareBazaar, ThreatFox, URLhaus, OTX). \
Summarize detections, malware family names per provider, first/last seen, and related URLs or hosts. \
Never upload a file unless the user explicitly asks for it; uploads are public submissions and require the user to pick the file and confirm in ExploitX.",
    },
    PromptSpec {
        name: "vulnerability_assessment",
        title: "Vulnerability assessment",
        description: "Relate discovered services to known vulnerabilities for a project.",
        arguments: &[("project_id", "ExploitX project ID", true), ("product", "Optional product or CPE keyword to research", false)],
        template: "Assess known vulnerabilities for ExploitX project {project_id} (product focus: {product}).\n\n\
Review recent runs (cyberhub_list_runs, cyberhub_get_run_output) for identified services and versions. Search vulnerabilities with cyberhub_search_vulnerabilities \
(local cache first; live NVD searches may need approval) and read details with cyberhub_get_vulnerability_details. \
Prioritize by CVSS and the CISA KEV flag, and state clearly when a version match is uncertain. Only verify vulnerabilities actively if the rules of engagement allow it.\n\n{rules}",
    },
    PromptSpec {
        name: "security_report_generation",
        title: "Security report generation",
        description: "Draft an assessment report from a project's scope, findings and runs.",
        arguments: &[("project_id", "ExploitX project ID", true)],
        template: "Prepare a security assessment report for ExploitX project {project_id}.\n\n\
Use cyberhub_generate_report for the base report, cyberhub_list_findings for details, cyberhub_list_runs / cyberhub_get_run_details for evidence \
and cyberhub_get_checklist for the testing coverage. \
Write an executive summary, a findings table sorted by severity, and remediation guidance. Only state facts supported by ExploitX data. \
Saving the report to a file (cyberhub_export_report) asks the user to approve and choose a location.

{rules}",
    },
];

pub fn prompt(name: &str) -> Option<&'static PromptSpec> {
    PROMPTS.iter().find(|p| p.name == name)
}

/// Fill a prompt template. Argument values are length-capped and stripped of control
/// characters; missing optional arguments become "not specified".
pub fn render(p: &PromptSpec, args: &std::collections::HashMap<String, String>) -> Result<String, String> {
    let mut text = p.template.replace("{rules}", RULES);
    for (name, _, required) in p.arguments {
        let v = args.get(*name).map(|s| s.chars().filter(|c| !c.is_control()).take(500).collect::<String>()).filter(|s| !s.trim().is_empty());
        let v = match (v, required) {
            (Some(v), _) => v,
            (None, true) => return Err(format!("missing required argument `{name}`")),
            (None, false) => "not specified".into(),
        };
        text = text.replace(&format!("{{{name}}}"), &v);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_render_and_require_scope() {
        let mut a = std::collections::HashMap::new();
        a.insert("project_id".to_string(), "3".to_string());
        let t = render(prompt("network_reconnaissance").unwrap(), &a).unwrap();
        assert!(t.contains("project 3") && t.contains("Focus: not specified") && t.contains("cyberhub_validate_target") && t.contains("Never try to work around scope"));
        assert!(render(prompt("web_application_assessment").unwrap(), &a).is_err(), "url is required");
        for p in PROMPTS {
            // every prompt that works on a project carries the scope rules
            if p.arguments.iter().any(|(n, _, _)| *n == "project_id") {
                assert!(p.template.contains("{rules}"), "{}", p.name);
            }
            let mut args = std::collections::HashMap::new();
            for (n, _, _) in p.arguments {
                args.insert(n.to_string(), "x".to_string());
            }
            let text = render(p, &args).unwrap();
            assert!(!text.contains('{'), "unfilled placeholder in {}", p.name);
            assert!(!text.to_lowercase().contains("bypass"), "{}", p.name);
        }
        assert_eq!(PROMPTS.len(), 6);
    }
}
