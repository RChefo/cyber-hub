// SPDX-License-Identifier: Apache-2.0
//! AWS IAM policy analysis (docs/UTILITIES.md, "Cloud and infrastructure-as-code checks"): one
//! policy document at a time, as written. Identity policies are checked for administrator access,
//! service-wide wildcards and the privilege-escalation methods Rhino Security Labs catalogued;
//! resource and trust policies for public access, cross-account trust without an external ID and
//! OpenID Connect trust (GitHub Actions) without a subject condition. Effective permissions,
//! which also depend on other policies, boundaries and SCPs, are not computed.

use serde_json::Value;

use super::containers::Issue;

const RHINO: &str = "Rhino Security Labs: AWS IAM privilege escalation methods";
const AWS_GUIDE: &str = "AWS IAM User Guide: security best practices";

/// Rhino Security Labs' privilege-escalation methods: a name and every action it needs.
const ESCALATIONS: &[(&str, &[&str])] = &[
    ("create a new version of a policy", &["iam:CreatePolicyVersion"]),
    ("set an older policy version as the default", &["iam:SetDefaultPolicyVersion"]),
    ("start an EC2 instance with a more privileged instance profile", &["iam:PassRole", "ec2:RunInstances"]),
    ("create access keys for other users", &["iam:CreateAccessKey"]),
    ("create a console password for another user", &["iam:CreateLoginProfile"]),
    ("change another user's console password", &["iam:UpdateLoginProfile"]),
    ("attach any managed policy to a user", &["iam:AttachUserPolicy"]),
    ("attach any managed policy to a group", &["iam:AttachGroupPolicy"]),
    ("attach any managed policy to a role", &["iam:AttachRolePolicy"]),
    ("write an inline policy for a user", &["iam:PutUserPolicy"]),
    ("write an inline policy for a group", &["iam:PutGroupPolicy"]),
    ("write an inline policy for a role", &["iam:PutRolePolicy"]),
    ("add a user to a more privileged group", &["iam:AddUserToGroup"]),
    ("rewrite a role's trust policy and assume the role", &["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"]),
    ("run a new Lambda function with a more privileged role", &["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),
    ("run a new Lambda function with a more privileged role, invoked from elsewhere", &["iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"]),
    ("run a new Lambda function with a more privileged role from an event source", &["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"]),
    ("replace the code of an existing Lambda function", &["lambda:UpdateFunctionCode"]),
    ("add a layer to an existing Lambda function", &["lambda:UpdateFunctionConfiguration"]),
    ("create a Glue development endpoint with a more privileged role", &["iam:PassRole", "glue:CreateDevEndpoint"]),
    ("take over an existing Glue development endpoint", &["glue:UpdateDevEndpoint"]),
    ("create a CloudFormation stack with a more privileged role", &["iam:PassRole", "cloudformation:CreateStack"]),
    ("create a Data Pipeline with a more privileged role", &["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"]),
    ("create a CodeStar project from a template", &["codestar:CreateProjectFromTemplate"]),
    ("create a CodeStar project with a more privileged role", &["codestar:CreateProject", "iam:PassRole"]),
    ("create a CodeStar project and add a team member", &["codestar:CreateProject", "codestar:AssociateTeamMember"]),
    ("start a SageMaker notebook with a more privileged role", &["sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl", "iam:PassRole"]),
    ("open an existing SageMaker notebook", &["sagemaker:CreatePresignedNotebookInstanceUrl"]),
];

/// Services whose full access (`service:*` on every resource) is an administrator in disguise.
const SENSITIVE_SERVICES: &[&str] = &["iam", "sts", "kms", "secretsmanager", "ssm", "organizations", "s3", "ec2", "lambda", "cloudtrail", "logs"];

/// Condition keys that narrow a public principal to an account, organization, network or source.
const NARROWING: &[&str] = &[
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip",
    "aws:resourceorgid", "aws:userid", "aws:principalservicename",
];

#[derive(Debug, Clone)]
struct Statement {
    index: usize,
    sid: String,
    allow: bool,
    /// Action, or NotAction when `not_action`
    actions: Vec<String>,
    not_action: bool,
    resources: Vec<String>,
    not_resource: bool,
    principal: Option<Value>,
    condition: Option<Value>,
}

impl Statement {
    fn label(&self) -> String {
        if self.sid.is_empty() {
            format!("statement {}", self.index + 1)
        } else {
            format!("statement {} ({})", self.index + 1, self.sid)
        }
    }
    fn any_resource(&self) -> bool {
        !self.not_resource && self.resources.iter().any(|r| r == "*")
    }
    fn conditioned(&self) -> bool {
        self.condition.as_ref().is_some_and(|c| c.as_object().is_some_and(|o| !o.is_empty()))
    }
    /// Whether the statement names `action` (with wildcards, ignoring case).
    fn covers(&self, action: &str) -> bool {
        let hit = self.actions.iter().any(|p| glob(p, action));
        if self.not_action {
            !hit
        } else {
            hit
        }
    }
    fn condition_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if let Some(Value::Object(ops)) = &self.condition {
            for inner in ops.values() {
                if let Value::Object(m) = inner {
                    keys.extend(m.keys().map(|k| k.to_ascii_lowercase()));
                }
            }
        }
        keys
    }
    fn condition_values(&self, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(Value::Object(ops)) = &self.condition {
            for inner in ops.values() {
                if let Value::Object(m) = inner {
                    for (k, v) in m {
                        if k.eq_ignore_ascii_case(key) {
                            out.extend(strings(v));
                        }
                    }
                }
            }
        }
        out
    }
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

/// IAM wildcard matching: `*` any run of characters, `?` one character, case-insensitive.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn statements(doc: &Value) -> Vec<Statement> {
    let list: Vec<&Value> = match doc.get("Statement") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v @ Value::Object(_)) => vec![v],
        _ => Vec::new(),
    };
    list.into_iter()
        .take(1000)
        .enumerate()
        .map(|(index, s)| {
            let (actions, not_action) = match (s.get("Action"), s.get("NotAction")) {
                (Some(a), _) => (strings(a), false),
                (None, Some(n)) => (strings(n), true),
                _ => (Vec::new(), false),
            };
            let (resources, not_resource) = match (s.get("Resource"), s.get("NotResource")) {
                (Some(r), _) => (strings(r), false),
                (None, Some(n)) => (strings(n), true),
                // trust policies have no Resource
                _ => (vec!["*".to_string()], false),
            };
            Statement {
                index,
                sid: s.get("Sid").and_then(Value::as_str).unwrap_or("").to_string(),
                allow: s.get("Effect").and_then(Value::as_str).is_some_and(|e| e.eq_ignore_ascii_case("allow")),
                actions,
                not_action,
                resources,
                not_resource,
                principal: s.get("Principal").or_else(|| s.get("NotPrincipal")).cloned(),
                condition: s.get("Condition").cloned(),
            }
        })
        .collect()
}

/// Whether the document is an IAM policy (`Statement` with Effect).
pub fn is_policy(doc: &Value) -> bool {
    doc.get("Statement").is_some_and(|s| match s {
        Value::Array(a) => a.iter().any(|x| x.get("Effect").is_some()),
        Value::Object(o) => o.contains_key("Effect"),
        _ => false,
    })
}

/// The statement that allows `action` on any resource without a condition, unless an
/// unconditional Deny covers it.
fn allowed<'a>(stmts: &'a [Statement], action: &str) -> Option<&'a Statement> {
    let denied = stmts.iter().any(|s| !s.allow && s.covers(action) && s.any_resource() && !s.conditioned());
    if denied {
        return None;
    }
    stmts.iter().find(|s| s.allow && s.principal.is_none() && s.covers(action) && !s.conditioned())
}

fn public_principal(p: &Value) -> bool {
    match p {
        Value::String(s) => s == "*",
        Value::Object(o) => o.get("AWS").is_some_and(|a| strings(a).iter().any(|x| x == "*")),
        _ => false,
    }
}

fn aws_accounts(p: &Value) -> Vec<String> {
    let list = match p {
        Value::Object(o) => o.get("AWS").map(strings).unwrap_or_default(),
        _ => Vec::new(),
    };
    list.into_iter()
        .filter_map(|a| {
            if a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit()) {
                return Some(a);
            }
            let parts: Vec<&str> = a.split(':').collect();
            (parts.len() >= 6 && parts[0] == "arn" && parts[2] == "iam").then(|| parts[4].to_string())
        })
        .filter(|a| !a.is_empty())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn issue(out: &mut Vec<Issue>, rule: &str, severity: &str, title: &str, location: String, detail: String, remediation: &str, reference: &str) {
    out.push(Issue { rule: rule.into(), severity: severity.into(), title: title.into(), location, detail, remediation: remediation.into(), reference: reference.into() });
}

/// Checks one policy document. `label` names it in the issues ("Role app-deployer", "policy.json").
/// `own_account`, when known, keeps trust in the same account from being reported as cross-account.
pub fn check(label: &str, doc: &Value, own_account: Option<&str>) -> Vec<Issue> {
    let stmts = statements(doc);
    let mut out = Vec::new();
    let at = |s: &Statement| format!("{label} › {}", s.label());
    for s in stmts.iter().filter(|s| s.allow && s.principal.is_none()) {
        if s.not_action {
            issue(&mut out, "IAM-NOT-ACTION", "high", "Allow with NotAction", at(s), format!("The statement allows every action except {}, including actions added to AWS later.", s.actions.join(", ")), "List the allowed actions instead of excluding some.", AWS_GUIDE);
        } else if s.actions.iter().any(|a| a == "*") && s.any_resource() && !s.conditioned() {
            issue(&mut out, "IAM-FULL-ADMIN", "critical", "Full administrator access", at(s), "The statement allows every action on every resource (\"Action\": \"*\", \"Resource\": \"*\").".into(), "Grant only the actions and resources the identity needs; keep administrator access for a few break-glass roles.", AWS_GUIDE);
        } else if s.any_resource() && !s.conditioned() {
            let broad: Vec<&str> = s.actions.iter().filter_map(|a| a.strip_suffix(":*")).filter(|svc| SENSITIVE_SERVICES.contains(&svc.to_ascii_lowercase().as_str())).collect();
            if !broad.is_empty() {
                issue(&mut out, "IAM-SERVICE-ADMIN", "high", "Every action of a sensitive service", at(s), format!("The statement allows all of {} on every resource; full IAM, STS, KMS or Secrets Manager access is administrator access in practice.", broad.iter().map(|b| format!("{b}:*")).collect::<Vec<_>>().join(", ")), "List the specific actions needed, and limit the resources.", AWS_GUIDE);
            }
        }
        if s.not_resource {
            issue(&mut out, "IAM-NOT-RESOURCE", "medium", "Allow with NotResource", at(s), format!("The statement allows its actions on every resource except {}, including resources created later.", s.resources.join(", ")), "List the resources instead of excluding some.", AWS_GUIDE);
        }
    }
    // privilege escalation: every action of a method allowed (not only through `*`, reported above)
    if !out.iter().any(|i| i.rule == "IAM-FULL-ADMIN") {
        let methods: Vec<&str> = ESCALATIONS.iter().filter(|(_, needs)| needs.iter().all(|a| allowed(&stmts, a).is_some())).map(|(name, _)| *name).collect();
        if !methods.is_empty() {
            let by: Vec<String> = ESCALATIONS
                .iter()
                .filter(|(n, _)| methods.contains(n))
                .flat_map(|(_, needs)| needs.iter().filter_map(|a| allowed(&stmts, a).map(|s| s.label())))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            issue(&mut out, "IAM-PRIVILEGE-ESCALATION", "high", "Permissions that lead to more privileges", format!("{label} › {}", by.join(", ")),
                format!("The policy allows ways to gain more privileges than it grants: {}.", methods.join("; ")),
                "Remove these actions, or limit them to specific resources and add conditions (for example iam:PassedToService for iam:PassRole).", RHINO);
        }
        if let Some(s) = allowed(&stmts, "sts:AssumeRole").filter(|s| s.any_resource()) {
            issue(&mut out, "IAM-ASSUME-ANY-ROLE", "medium", "Can assume any role", at(s), "sts:AssumeRole is allowed on every resource: every role that trusts this account can be assumed.".into(), "List the role ARNs that may be assumed.", AWS_GUIDE);
        }
    }
    // resource and trust policies
    for s in stmts.iter().filter(|s| s.allow) {
        let Some(p) = &s.principal else { continue };
        let keys = s.condition_keys();
        let narrowed = keys.iter().any(|k| NARROWING.contains(&k.as_str()));
        if public_principal(p) && !narrowed {
            let trust = s.actions.iter().any(|a| glob(a, "sts:AssumeRole"));
            issue(&mut out, "IAM-PUBLIC", "critical", if trust { "Role can be assumed by anyone" } else { "Resource open to anyone" }, at(s),
                format!("The statement allows {} to any principal (\"*\"), with no condition that limits the account, organization, network or source.", if s.actions.is_empty() { "access".to_string() } else { s.actions.join(", ") }),
                "Name the accounts or principals that need access, or add a condition such as aws:PrincipalOrgID or aws:SourceArn.", AWS_GUIDE);
            continue;
        }
        let federated = p.get("Federated").map(strings).unwrap_or_default();
        if federated.iter().any(|f| f.contains("token.actions.githubusercontent.com") || f.contains("oidc-provider/")) && s.actions.iter().any(|a| glob(a, "sts:AssumeRoleWithWebIdentity")) {
            let subs: Vec<String> = keys.iter().filter(|k| k.ends_with(":sub")).flat_map(|k| s.condition_values(k)).collect();
            // "*" or "repo:*" admit every subject; "repo:org/*" or a full subject narrow it
            let open = subs.is_empty() || subs.iter().any(|v| v == "*" || (v.ends_with(":*") && v.matches(':').count() <= 1));
            if open {
                issue(&mut out, "IAM-OIDC-ANY-SUBJECT", "high", "Web identity trust without a subject condition", at(s),
                    format!("{} can assume the role with a token from {} without a condition on the token's subject (sub), so any repository or workload of that provider can.", if subs.is_empty() { "Anyone" } else { "Almost anyone" }, federated.join(", ")),
                    "Add a StringEquals or StringLike condition on the provider's sub claim naming your repository and branch or environment (for GitHub, token.actions.githubusercontent.com:sub).", "GitHub Docs: configuring OpenID Connect in Amazon Web Services");
            }
        }
        let accounts: Vec<String> = aws_accounts(p).into_iter().filter(|a| own_account != Some(a.as_str())).collect();
        if !accounts.is_empty() && s.actions.iter().any(|a| glob(a, "sts:AssumeRole")) && !keys.iter().any(|k| k == "sts:externalid") && !narrowed {
            issue(&mut out, "IAM-CROSS-ACCOUNT-NO-EXTERNAL-ID", "low", "Cross-account trust without an external ID", at(s),
                format!("Account {} can assume the role without an sts:ExternalId condition; when the trusted account is a third party, this allows the confused deputy problem.", accounts.join(", ")),
                "For roles assumed by third parties, require the external ID they gave you.", "AWS IAM User Guide: the confused deputy problem");
        }
    }
    out
}

#[cfg(test)]
#[path = "iam_tests.rs"]
mod tests;
