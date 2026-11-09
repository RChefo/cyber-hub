//! Cloud infrastructure as code (docs/UTILITIES.md, "Cloud and infrastructure-as-code checks"):
//! Terraform (HCL, JSON configuration and `terraform show -json` plans), AWS CloudFormation (JSON,
//! YAML) and IAM policy documents (single policies, AWS CLI output and the output of
//! `aws iam get-account-authorization-details`) are read locally and checked for AWS
//! misconfigurations. Policies go through `iam.rs`. Values that are references, variables or
//! functions are not resolved: a setting that is not written literally is not reported.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::containers::{FileReport, Issue, ScanResult};
use super::iam;

pub const MAX_FILES: usize = 2_000;
pub const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_TEXT: usize = 50 * 1024 * 1024;
const MAX_VISITED: usize = 50_000;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".terraform", "vendor", "target", "dist", ".venv", "venv", "__pycache__", ".idea"];

const CIS: &str = "CIS AWS Foundations Benchmark";

#[allow(clippy::too_many_arguments)]
fn issue(out: &mut Vec<Issue>, rule: &str, severity: &str, title: &str, location: &str, detail: String, remediation: &str, reference: &str) {
    out.push(Issue { rule: rule.into(), severity: severity.into(), title: title.into(), location: location.into(), detail, remediation: remediation.into(), reference: reference.into() });
}

/* ───────────────────────────── values ───────────────────────────── */

/// A nested block or property: an object, or the objects of an array (Terraform writes blocks as arrays).
fn blocks<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    match v.get(key) {
        Some(Value::Array(a)) => a.iter().filter(|x| x.is_object()).collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => Vec::new(),
    }
}

fn text(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// A boolean setting: written as true or false, missing (the provider's default applies), or
/// unknown (a reference, variable or function that is not resolved here, and so not reported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setting {
    On,
    Off,
    Missing,
    Unknown,
}

fn setting(v: &Value, key: &str) -> Setting {
    match v.get(key) {
        None | Some(Value::Null) => Setting::Missing,
        Some(Value::Bool(true)) => Setting::On,
        Some(Value::Bool(false)) => Setting::Off,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Setting::On,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => Setting::Off,
        _ => Setting::Unknown,
    }
}

/// Off, or missing where the default is off.
fn off(v: &Value, key: &str) -> bool {
    matches!(setting(v, key), Setting::Off | Setting::Missing)
}

fn list(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn port(v: &Value, key: &str) -> Option<i64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A policy given as an object, a JSON string or a heredoc.
fn policy(v: Option<&Value>) -> Option<Value> {
    match v? {
        o @ Value::Object(_) => Some(o.clone()),
        Value::String(s) => serde_json::from_str::<Value>(s.trim()).ok().filter(Value::is_object),
        _ => None,
    }
}

fn check_policy(out: &mut Vec<Issue>, label: &str, doc: Option<&Value>) {
    if let Some(p) = policy(doc) {
        if iam::is_policy(&p) {
            out.extend(iam::check(label, &p, None));
        }
    }
}

/* ───────────────────────────── shared checks ───────────────────────────── */

const ADMIN_PORTS: &[(i64, &str)] = &[(22, "SSH"), (23, "Telnet"), (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM over TLS")];
const DATA_PORTS: &[(i64, &str)] = &[
    (1433, "SQL Server"), (1521, "Oracle"), (2375, "Docker API"), (2376, "Docker API"), (3306, "MySQL"), (5432, "PostgreSQL"), (5601, "Kibana"), (5984, "CouchDB"), (6379, "Redis"), (9042, "Cassandra"),
    (9092, "Kafka"), (9200, "Elasticsearch"), (9300, "Elasticsearch"), (11211, "Memcached"), (27017, "MongoDB"), (2181, "ZooKeeper"),
];

/// An ingress rule from anywhere: the CIDR, protocol and port range decide the severity.
fn open_ingress(out: &mut Vec<Issue>, location: &str, cidrs: &[String], protocol: &str, from: Option<i64>, to: Option<i64>) {
    let open: Vec<&String> = cidrs.iter().filter(|c| c.as_str() == "0.0.0.0/0" || c.as_str() == "::/0").collect();
    if open.is_empty() {
        return;
    }
    let all_protocols = matches!(protocol, "-1" | "all");
    let (from, to) = (from.unwrap_or(0), to.unwrap_or(65535));
    let (from, to) = if all_protocols || (from <= 0 && to >= 65535) { (0, 65535) } else { (from.min(to), from.max(to)) };
    let within = |p: i64| from <= p && p <= to;
    let src = open.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(" and ");
    if all_protocols || (from == 0 && to == 65535) {
        issue(out, "AWS-SG-ALL-OPEN", "critical", "All ports open to the internet", location, format!("Ingress from {src} on every port{}.", if all_protocols { " and protocol" } else { "" }), "Allow only the ports the service needs, from the addresses that need them.", CIS);
        return;
    }
    let admin: Vec<String> = ADMIN_PORTS.iter().filter(|(p, _)| within(*p)).map(|(p, n)| format!("{p} ({n})")).collect();
    let data: Vec<String> = DATA_PORTS.iter().filter(|(p, _)| within(*p)).map(|(p, n)| format!("{p} ({n})")).collect();
    let range = if from == to { from.to_string() } else { format!("{from}-{to}") };
    if !admin.is_empty() {
        issue(out, "AWS-SG-ADMIN-OPEN", "high", "Remote administration open to the internet", location, format!("Ingress from {src} on {range}, which includes {}.", admin.join(", ")), "Reach administration ports through a VPN, a bastion or Systems Manager Session Manager; never from 0.0.0.0/0.", &format!("{CIS}: no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"));
    }
    if !data.is_empty() {
        issue(out, "AWS-SG-DATA-OPEN", "high", "Database or data service open to the internet", location, format!("Ingress from {src} on {range}, which includes {}.", data.join(", ")), "Keep data stores in private subnets and allow only the application's security group.", "AWS documentation: security group rules");
    }
    // a web port on its own is the usual public service
    let web = from == to && (from == 80 || from == 443);
    if admin.is_empty() && data.is_empty() && !web {
        issue(out, "AWS-SG-PORT-OPEN", "low", "Port open to the internet", location, format!("Ingress from {src} on {range}."), "Check that this port is meant to be public.", "AWS documentation: security group rules");
    }
}

fn admin_policy_attached(out: &mut Vec<Issue>, location: &str, arns: &[String]) {
    if arns.iter().any(|a| a.ends_with(":policy/AdministratorAccess")) {
        issue(out, "AWS-IAM-ADMIN-ATTACHED", "high", "AdministratorAccess attached", location, "The AWS managed policy AdministratorAccess (every action on every resource) is attached.".into(), "Attach a policy with the permissions the identity needs.", &format!("{CIS}: IAM policies that allow full \"*:*\" administrative privileges are not attached"));
    }
}

/* ───────────────────────────── Terraform ───────────────────────────── */

fn expr_json(e: &hcl::Expression) -> Value {
    use hcl::{Expression as E, ObjectKey, TemplateExpr};
    match e {
        E::Null => Value::Null,
        E::Bool(b) => Value::Bool(*b),
        E::Number(n) => serde_json::to_value(n).unwrap_or(Value::Null),
        E::String(s) => Value::String(s.clone()),
        E::Array(a) => Value::Array(a.iter().map(expr_json).collect()),
        E::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let key = match k {
                        ObjectKey::Identifier(i) => i.as_str().to_string(),
                        ObjectKey::Expression(E::String(s)) => s.clone(),
                        ObjectKey::Expression(other) => other.to_string(),
                        _ => String::new(),
                    };
                    (key, expr_json(v))
                })
                .collect(),
        ),
        E::TemplateExpr(t) => match t.as_ref() {
            TemplateExpr::QuotedString(s) => Value::String(s.clone()),
            TemplateExpr::Heredoc(h) => Value::String(h.template.clone()),
        },
        // jsonencode({…}) of literal values is the policy itself
        E::FuncCall(f) if f.name.name.as_str() == "jsonencode" && f.args.len() == 1 => expr_json(&f.args[0]),
        E::Parenthesis(inner) => expr_json(inner),
        other => Value::String(format!("${{{other}}}")),
    }
}

/// An HCL body as Terraform's JSON configuration: labelled blocks nest by label, repeated
/// unlabelled blocks become arrays.
fn body_json(body: &hcl::Body, depth: usize) -> Value {
    let mut map = Map::new();
    if depth > 32 {
        return Value::Object(map);
    }
    for a in body.attributes() {
        map.insert(a.key().to_string(), expr_json(a.expr()));
    }
    for b in body.blocks() {
        let inner = body_json(b.body(), depth + 1);
        let labels: Vec<&str> = b.labels().iter().map(|l| l.as_str()).collect();
        if labels.is_empty() {
            match map.entry(b.identifier().to_string()).or_insert_with(|| Value::Array(Vec::new())) {
                Value::Array(a) => a.push(inner),
                other => *other = Value::Array(vec![inner]),
            }
            continue;
        }
        let mut node = map.entry(b.identifier().to_string()).or_insert_with(|| Value::Object(Map::new()));
        for (i, label) in labels.iter().enumerate() {
            if !node.is_object() {
                *node = Value::Object(Map::new());
            }
            let obj = node.as_object_mut().expect("object");
            if i + 1 == labels.len() {
                obj.insert(label.to_string(), inner.clone());
                break;
            }
            node = obj.entry(label.to_string()).or_insert_with(|| Value::Object(Map::new()));
        }
    }
    Value::Object(map)
}

/// (mode, type, name, attributes) of every resource and data source in a configuration.
fn config_resources(root: &Value) -> Vec<(String, String, String, Value)> {
    let mut out = Vec::new();
    for (mode, key) in [("managed", "resource"), ("data", "data")] {
        for (ty, by_name) in root.get(key).and_then(Value::as_object).into_iter().flatten() {
            for (name, attrs) in by_name.as_object().into_iter().flatten() {
                // the JSON syntax also allows an array of bodies
                let attrs = match attrs {
                    Value::Array(a) => a.first().cloned().unwrap_or(Value::Null),
                    o => o.clone(),
                };
                out.push((mode.to_string(), ty.clone(), name.clone(), attrs));
            }
        }
    }
    out
}

/// Resources of a plan (`terraform show -json`): planned values, and data sources read during the plan.
fn plan_resources(root: &Value) -> Vec<(String, String, String, Value)> {
    fn walk(module: &Value, out: &mut Vec<(String, String, String, Value)>, depth: usize) {
        if depth > 32 {
            return;
        }
        for r in module.get("resources").and_then(Value::as_array).into_iter().flatten() {
            let address = text(r, "address");
            out.push((text(r, "mode"), text(r, "type"), if address.is_empty() { text(r, "name") } else { address }, r.get("values").cloned().unwrap_or(Value::Null)));
        }
        for child in module.get("child_modules").and_then(Value::as_array).into_iter().flatten() {
            walk(child, out, depth + 1);
        }
    }
    let mut out = Vec::new();
    if let Some(m) = root.pointer("/planned_values/root_module") {
        walk(m, &mut out, 0);
    }
    if let Some(m) = root.pointer("/prior_state/values/root_module") {
        let mut prior = Vec::new();
        walk(m, &mut prior, 0);
        out.extend(prior.into_iter().filter(|r| r.0 == "data"));
    }
    out
}

/// `data "aws_iam_policy_document"` as a policy (statement blocks with actions, resources,
/// principals and conditions), or its rendered `json` in a plan.
fn policy_document(attrs: &Value) -> Option<Value> {
    if let Some(p) = policy(attrs.get("json")) {
        return Some(p);
    }
    let mut statements = Vec::new();
    for s in blocks(attrs, "statement") {
        let mut st = Map::new();
        st.insert("Effect".into(), Value::String(match text(s, "effect").as_str() { "" => "Allow".into(), e => e.to_string() }));
        for (from, to) in [("actions", "Action"), ("not_actions", "NotAction"), ("resources", "Resource"), ("not_resources", "NotResource")] {
            let v = list(s, from);
            if !v.is_empty() {
                st.insert(to.into(), Value::from(v));
            }
        }
        for (from, to) in [("principals", "Principal"), ("not_principals", "NotPrincipal")] {
            let mut principal = Map::new();
            for p in blocks(s, from) {
                let ids = list(p, "identifiers");
                let ty = text(p, "type");
                if ty == "*" {
                    principal.clear();
                    st.insert(to.into(), Value::String("*".into()));
                    break;
                }
                principal.insert(ty, Value::from(ids));
            }
            if !principal.is_empty() {
                st.insert(to.into(), Value::Object(principal));
            }
        }
        let mut cond = Map::new();
        for c in blocks(s, "condition") {
            let op = cond.entry(text(c, "test")).or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(m) = op {
                m.insert(text(c, "variable"), Value::from(list(c, "values")));
            }
        }
        if !cond.is_empty() {
            st.insert("Condition".into(), Value::Object(cond));
        }
        statements.push(Value::Object(st));
    }
    (!statements.is_empty()).then(|| serde_json::json!({ "Version": "2012-10-17", "Statement": statements }))
}

fn terraform_checks(resources: &[(String, String, String, Value)]) -> Vec<Issue> {
    let mut out = Vec::new();
    for (mode, ty, name, a) in resources {
        let at = if name.contains('.') { name.clone() } else { format!("{}{ty}.{name}", if mode == "data" { "data." } else { "" }) };
        let at = at.as_str();
        match (mode.as_str(), ty.as_str()) {
            ("data", "aws_iam_policy_document") => {
                if let Some(p) = policy_document(a) {
                    out.extend(iam::check(at, &p, None));
                }
            }
            ("data", _) => {}
            (_, "aws_s3_bucket" | "aws_s3_bucket_acl") => {
                let acl = text(a, "acl");
                if matches!(acl.as_str(), "public-read" | "public-read-write" | "authenticated-read") {
                    issue(&mut out, "AWS-S3-PUBLIC-ACL", if acl == "public-read-write" { "critical" } else { "high" }, "Bucket ACL grants public access", at, format!("The bucket ACL is {acl}: {}.", if acl == "authenticated-read" { "any AWS account can read it" } else { "anyone on the internet can list and read it" }), "Use the private ACL (or disable ACLs with BucketOwnerEnforced) and grant access through policies.", &format!("{CIS}: S3 buckets are configured with Block public access"));
                }
                check_policy(&mut out, at, a.get("policy"));
            }
            (_, "aws_s3_bucket_public_access_block" | "aws_s3_account_public_access_block") => {
                let disabled: Vec<&str> = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"].into_iter().filter(|k| off(a, k)).collect();
                if !disabled.is_empty() {
                    issue(&mut out, "AWS-S3-PUBLIC-ACCESS-BLOCK", "medium", "Block public access not fully on", at, format!("{} {} not set to true, so public ACLs or policies can take effect.", disabled.join(", "), if disabled.len() == 1 { "is" } else { "are" }), "Set all four settings to true unless the bucket is meant to be public.", &format!("{CIS}: S3 buckets are configured with Block public access"));
                }
            }
            (_, "aws_s3_bucket_policy" | "aws_sqs_queue_policy" | "aws_sns_topic_policy" | "aws_ecr_repository_policy" | "aws_glacier_vault_lock") => check_policy(&mut out, at, a.get("policy")),
            (_, "aws_elasticsearch_domain_policy" | "aws_opensearch_domain_policy" | "aws_elasticsearch_domain" | "aws_opensearch_domain") => check_policy(&mut out, at, a.get("access_policies")),
            (_, "aws_security_group") => {
                for rule in blocks(a, "ingress") {
                    let cidrs = [list(rule, "cidr_blocks"), list(rule, "ipv6_cidr_blocks")].concat();
                    open_ingress(&mut out, at, &cidrs, &text(rule, "protocol"), port(rule, "from_port"), port(rule, "to_port"));
                }
            }
            (_, "aws_security_group_rule") if text(a, "type") == "ingress" => {
                let cidrs = [list(a, "cidr_blocks"), list(a, "ipv6_cidr_blocks")].concat();
                open_ingress(&mut out, at, &cidrs, &text(a, "protocol"), port(a, "from_port"), port(a, "to_port"));
            }
            (_, "aws_vpc_security_group_ingress_rule") => {
                let cidrs = [list(a, "cidr_ipv4"), list(a, "cidr_ipv6")].concat();
                open_ingress(&mut out, at, &cidrs, &text(a, "ip_protocol"), port(a, "from_port"), port(a, "to_port"));
            }
            (_, "aws_db_instance" | "aws_rds_cluster" | "aws_rds_cluster_instance" | "aws_redshift_cluster") => {
                if setting(a, "publicly_accessible") == Setting::On {
                    issue(&mut out, "AWS-DB-PUBLIC", "high", "Database reachable from the internet", at, "publicly_accessible is true: the database gets a public address.".into(), "Set publicly_accessible to false and reach the database from inside the VPC.", &format!("{CIS}: public access is not given to RDS instances"));
                }
                if ty != "aws_rds_cluster_instance" && off(a, "storage_encrypted") && off(a, "encrypted") {
                    issue(&mut out, "AWS-DB-UNENCRYPTED", "medium", "Database storage not encrypted", at, "storage_encrypted is not true.".into(), "Set storage_encrypted = true (it cannot be changed later without a snapshot copy).", &format!("{CIS}: encryption is enabled for RDS instances"));
                }
            }
            (_, "aws_instance" | "aws_launch_template" | "aws_launch_configuration") => {
                let tokens: Vec<String> = blocks(a, "metadata_options").iter().map(|m| text(m, "http_tokens")).collect();
                if !tokens.iter().any(|t| t == "required") {
                    issue(&mut out, "AWS-IMDSV1", "medium", "Instance metadata service v1 allowed", at, "http_tokens is not \"required\", so IMDSv1 answers simple GET requests; an SSRF in an application on the instance can then steal its role credentials.".into(), "Add metadata_options { http_tokens = \"required\" }.", &format!("{CIS}: EC2 Metadata Service only allows IMDSv2"));
                }
            }
            (_, "aws_ebs_volume") if off(a, "encrypted") => {
                issue(&mut out, "AWS-EBS-UNENCRYPTED", "low", "EBS volume not encrypted", at, "encrypted is not true (unless EBS encryption by default is on for the account).".into(), "Set encrypted = true, or turn on EBS encryption by default.", &format!("{CIS}: EBS volume encryption is enabled in all regions"));
            }
            (_, "aws_iam_policy" | "aws_iam_role_policy" | "aws_iam_user_policy" | "aws_iam_group_policy") => check_policy(&mut out, at, a.get("policy")),
            (_, "aws_iam_role") => {
                check_policy(&mut out, &format!("{at} trust policy"), a.get("assume_role_policy"));
                for p in blocks(a, "inline_policy") {
                    check_policy(&mut out, &format!("{at} inline policy {}", text(p, "name")), p.get("policy"));
                }
                admin_policy_attached(&mut out, at, &list(a, "managed_policy_arns"));
            }
            (_, "aws_iam_role_policy_attachment" | "aws_iam_user_policy_attachment" | "aws_iam_group_policy_attachment" | "aws_iam_policy_attachment") => admin_policy_attached(&mut out, at, &list(a, "policy_arn")),
            (_, "aws_iam_access_key") => {
                issue(&mut out, "AWS-ACCESS-KEY-IN-STATE", "medium", "Access key created by Terraform", at, "The secret of an aws_iam_access_key is stored in the Terraform state (encrypted only with a pgp_key), and long-lived keys are easy to leak.".into(), "Prefer roles and temporary credentials; if a key is unavoidable, set pgp_key and protect the state.", "Terraform AWS provider documentation: aws_iam_access_key");
            }
            (_, "aws_cloudtrail") => {
                if setting(a, "enable_logging") == Setting::Off {
                    issue(&mut out, "AWS-CLOUDTRAIL-OFF", "high", "CloudTrail logging turned off", at, "enable_logging is false.".into(), "Turn logging on.", &format!("{CIS}: CloudTrail is enabled in all regions"));
                }
                if off(a, "is_multi_region_trail") {
                    issue(&mut out, "AWS-CLOUDTRAIL-ONE-REGION", "low", "CloudTrail trail covers one region", at, "is_multi_region_trail is not true: activity in other regions is not recorded by this trail.".into(), "Set is_multi_region_trail = true.", &format!("{CIS}: CloudTrail is enabled in all regions"));
                }
                if off(a, "enable_log_file_validation") {
                    issue(&mut out, "AWS-CLOUDTRAIL-NO-VALIDATION", "low", "CloudTrail log file validation off", at, "enable_log_file_validation is not true, so changed or deleted log files cannot be detected.".into(), "Set enable_log_file_validation = true.", &format!("{CIS}: CloudTrail log file validation is enabled"));
                }
            }
            (_, "aws_kms_key") => {
                let symmetric = matches!(text(a, "customer_master_key_spec").as_str(), "" | "SYMMETRIC_DEFAULT");
                if symmetric && off(a, "enable_key_rotation") {
                    issue(&mut out, "AWS-KMS-NO-ROTATION", "low", "KMS key rotation off", at, "enable_key_rotation is not true.".into(), "Set enable_key_rotation = true.", &format!("{CIS}: rotation for customer-created symmetric CMKs is enabled"));
                }
                check_policy(&mut out, at, a.get("policy"));
            }
            (_, "aws_lambda_function_url") if text(a, "authorization_type") == "NONE" => {
                issue(&mut out, "AWS-LAMBDA-PUBLIC-URL", "high", "Lambda function URL without authentication", at, "authorization_type is NONE: anyone who knows the URL can invoke the function.".into(), "Use AWS_IAM, or authenticate inside the function and say so in the code.", "AWS Lambda documentation: function URLs");
            }
            (_, "aws_lambda_permission") if text(a, "principal") == "*" && text(a, "source_arn").is_empty() && text(a, "source_account").is_empty() && text(a, "principal_org_id").is_empty() => {
                issue(&mut out, "AWS-LAMBDA-PUBLIC-INVOKE", "critical", "Lambda function invocable by anyone", at, "The permission grants the function to principal \"*\" without a source ARN, account or organization.".into(), "Name the principal, or add source_arn or source_account.", "AWS Lambda documentation: resource-based policies");
            }
            (_, "aws_lb_listener" | "aws_alb_listener") if text(a, "protocol") == "HTTP" => {
                let redirects = blocks(a, "default_action").iter().any(|d| text(d, "type") == "redirect");
                if !redirects {
                    issue(&mut out, "AWS-LB-HTTP", "medium", "Load balancer serves plain HTTP", at, "The listener uses HTTP and does not redirect to HTTPS.".into(), "Redirect HTTP to HTTPS, and serve the application on an HTTPS listener.", "AWS Elastic Load Balancing documentation");
                }
            }
            (_, "aws_eks_cluster") => {
                for vpc in blocks(a, "vpc_config") {
                    let public = matches!(setting(vpc, "endpoint_public_access"), Setting::On | Setting::Missing);
                    let cidrs = list(vpc, "public_access_cidrs");
                    if public && (cidrs.is_empty() || cidrs.iter().any(|c| c == "0.0.0.0/0")) {
                        issue(&mut out, "AWS-EKS-PUBLIC-ENDPOINT", "medium", "Kubernetes API endpoint open to the internet", at, "The cluster's public endpoint is on (the default) and accepts connections from any address.".into(), "Turn the public endpoint off, or limit public_access_cidrs to known addresses.", "Amazon EKS best practices guide");
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/* ───────────────────────────── CloudFormation ───────────────────────────── */

fn cloudformation(root: &Value) -> Vec<Issue> {
    let mut out = Vec::new();
    for (name, r) in root.get("Resources").and_then(Value::as_object).into_iter().flatten() {
        let ty = text(r, "Type");
        let p = r.get("Properties").cloned().unwrap_or(Value::Null);
        let at = format!("{name} ({ty})");
        let at = at.as_str();
        match ty.as_str() {
            "AWS::S3::Bucket" => {
                let acl = text(&p, "AccessControl");
                if matches!(acl.as_str(), "PublicRead" | "PublicReadWrite" | "AuthenticatedRead") {
                    issue(&mut out, "AWS-S3-PUBLIC-ACL", if acl == "PublicReadWrite" { "critical" } else { "high" }, "Bucket ACL grants public access", at, format!("AccessControl is {acl}."), "Use Private (or BucketOwnerEnforced ownership) and grant access through policies.", &format!("{CIS}: S3 buckets are configured with Block public access"));
                }
                if let Some(b) = p.get("PublicAccessBlockConfiguration") {
                    let disabled: Vec<&str> = ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"].into_iter().filter(|k| off(b, k)).collect();
                    if !disabled.is_empty() {
                        issue(&mut out, "AWS-S3-PUBLIC-ACCESS-BLOCK", "medium", "Block public access not fully on", at, format!("{} {} not true.", disabled.join(", "), if disabled.len() == 1 { "is" } else { "are" }), "Set all four settings to true unless the bucket is meant to be public.", &format!("{CIS}: S3 buckets are configured with Block public access"));
                    }
                }
            }
            "AWS::S3::BucketPolicy" | "AWS::SQS::QueuePolicy" | "AWS::SNS::TopicPolicy" => check_policy(&mut out, at, p.get("PolicyDocument")),
            "AWS::ECR::Repository" => check_policy(&mut out, at, p.get("RepositoryPolicyText")),
            "AWS::OpenSearchService::Domain" | "AWS::Elasticsearch::Domain" => check_policy(&mut out, at, p.get("AccessPolicies")),
            "AWS::EC2::SecurityGroup" => {
                for rule in blocks(&p, "SecurityGroupIngress") {
                    let cidrs = [list(rule, "CidrIp"), list(rule, "CidrIpv6")].concat();
                    open_ingress(&mut out, at, &cidrs, &text(rule, "IpProtocol"), port(rule, "FromPort"), port(rule, "ToPort"));
                }
            }
            "AWS::EC2::SecurityGroupIngress" => {
                let cidrs = [list(&p, "CidrIp"), list(&p, "CidrIpv6")].concat();
                open_ingress(&mut out, at, &cidrs, &text(&p, "IpProtocol"), port(&p, "FromPort"), port(&p, "ToPort"));
            }
            "AWS::RDS::DBInstance" | "AWS::RDS::DBCluster" | "AWS::Redshift::Cluster" => {
                if setting(&p, "PubliclyAccessible") == Setting::On {
                    issue(&mut out, "AWS-DB-PUBLIC", "high", "Database reachable from the internet", at, "PubliclyAccessible is true.".into(), "Set PubliclyAccessible to false and reach the database from inside the VPC.", &format!("{CIS}: public access is not given to RDS instances"));
                }
                let unencrypted = off(&p, "StorageEncrypted") && off(&p, "Encrypted");
                // an Aurora instance takes its encryption from the cluster
                let aurora_member = ty == "AWS::RDS::DBInstance" && !text(&p, "DBClusterIdentifier").is_empty();
                if unencrypted && !aurora_member {
                    issue(&mut out, "AWS-DB-UNENCRYPTED", "medium", "Database storage not encrypted", at, "StorageEncrypted is not true.".into(), "Set StorageEncrypted to true.", &format!("{CIS}: encryption is enabled for RDS instances"));
                }
            }
            "AWS::EC2::LaunchTemplate" => {
                let tokens = p.pointer("/LaunchTemplateData/MetadataOptions/HttpTokens").and_then(Value::as_str).unwrap_or("");
                if tokens != "required" {
                    issue(&mut out, "AWS-IMDSV1", "medium", "Instance metadata service v1 allowed", at, "HttpTokens is not \"required\", so IMDSv1 answers; an SSRF in an application on the instance can steal its role credentials.".into(), "Set LaunchTemplateData.MetadataOptions.HttpTokens to required.", &format!("{CIS}: EC2 Metadata Service only allows IMDSv2"));
                }
            }
            "AWS::EC2::Volume" if off(&p, "Encrypted") => {
                issue(&mut out, "AWS-EBS-UNENCRYPTED", "low", "EBS volume not encrypted", at, "Encrypted is not true (unless EBS encryption by default is on for the account).".into(), "Set Encrypted to true, or turn on EBS encryption by default.", &format!("{CIS}: EBS volume encryption is enabled in all regions"));
            }
            "AWS::IAM::Role" | "AWS::IAM::User" | "AWS::IAM::Group" => {
                check_policy(&mut out, &format!("{name} trust policy"), p.get("AssumeRolePolicyDocument"));
                for pol in blocks(&p, "Policies") {
                    check_policy(&mut out, &format!("{name} policy {}", text(pol, "PolicyName")), pol.get("PolicyDocument"));
                }
                admin_policy_attached(&mut out, at, &list(&p, "ManagedPolicyArns"));
            }
            "AWS::IAM::Policy" | "AWS::IAM::ManagedPolicy" => check_policy(&mut out, at, p.get("PolicyDocument")),
            "AWS::IAM::AccessKey" => {
                issue(&mut out, "AWS-ACCESS-KEY-IN-TEMPLATE", "medium", "Access key created by the template", at, "A long-lived access key is created; its secret ends up in the stack outputs or wherever the template passes it.".into(), "Prefer roles and temporary credentials.", AWS_IAM_GUIDE);
            }
            "AWS::CloudTrail::Trail" => {
                if setting(&p, "IsLogging") == Setting::Off {
                    issue(&mut out, "AWS-CLOUDTRAIL-OFF", "high", "CloudTrail logging turned off", at, "IsLogging is false.".into(), "Turn logging on.", &format!("{CIS}: CloudTrail is enabled in all regions"));
                }
                if off(&p, "IsMultiRegionTrail") {
                    issue(&mut out, "AWS-CLOUDTRAIL-ONE-REGION", "low", "CloudTrail trail covers one region", at, "IsMultiRegionTrail is not true.".into(), "Set IsMultiRegionTrail to true.", &format!("{CIS}: CloudTrail is enabled in all regions"));
                }
                if off(&p, "EnableLogFileValidation") {
                    issue(&mut out, "AWS-CLOUDTRAIL-NO-VALIDATION", "low", "CloudTrail log file validation off", at, "EnableLogFileValidation is not true.".into(), "Set EnableLogFileValidation to true.", &format!("{CIS}: CloudTrail log file validation is enabled"));
                }
            }
            "AWS::KMS::Key" => {
                let symmetric = matches!(text(&p, "KeySpec").as_str(), "" | "SYMMETRIC_DEFAULT");
                if symmetric && off(&p, "EnableKeyRotation") {
                    issue(&mut out, "AWS-KMS-NO-ROTATION", "low", "KMS key rotation off", at, "EnableKeyRotation is not true.".into(), "Set EnableKeyRotation to true.", &format!("{CIS}: rotation for customer-created symmetric CMKs is enabled"));
                }
                check_policy(&mut out, at, p.get("KeyPolicy"));
            }
            "AWS::Lambda::Url" if text(&p, "AuthType") == "NONE" => {
                issue(&mut out, "AWS-LAMBDA-PUBLIC-URL", "high", "Lambda function URL without authentication", at, "AuthType is NONE: anyone who knows the URL can invoke the function.".into(), "Use AWS_IAM, or authenticate inside the function.", "AWS Lambda documentation: function URLs");
            }
            "AWS::Lambda::Permission" if text(&p, "Principal") == "*" && text(&p, "SourceArn").is_empty() && text(&p, "SourceAccount").is_empty() && text(&p, "PrincipalOrgID").is_empty() => {
                issue(&mut out, "AWS-LAMBDA-PUBLIC-INVOKE", "critical", "Lambda function invocable by anyone", at, "The permission grants the function to principal \"*\" without a source ARN, account or organization.".into(), "Name the principal, or add SourceArn or SourceAccount.", "AWS Lambda documentation: resource-based policies");
            }
            "AWS::ElasticLoadBalancingV2::Listener" if text(&p, "Protocol") == "HTTP" => {
                let redirects = blocks(&p, "DefaultActions").iter().any(|d| text(d, "Type") == "redirect");
                if !redirects {
                    issue(&mut out, "AWS-LB-HTTP", "medium", "Load balancer serves plain HTTP", at, "The listener uses HTTP and does not redirect to HTTPS.".into(), "Redirect HTTP to HTTPS.", "AWS Elastic Load Balancing documentation");
                }
            }
            "AWS::EKS::Cluster" => {
                let vpc = p.get("ResourcesVpcConfig").cloned().unwrap_or(Value::Null);
                let public = matches!(setting(&vpc, "EndpointPublicAccess"), Setting::On | Setting::Missing);
                let cidrs = list(&vpc, "PublicAccessCidrs");
                if public && (cidrs.is_empty() || cidrs.iter().any(|c| c == "0.0.0.0/0")) {
                    issue(&mut out, "AWS-EKS-PUBLIC-ENDPOINT", "medium", "Kubernetes API endpoint open to the internet", at, "The cluster's public endpoint is on (the default) and accepts connections from any address.".into(), "Turn the public endpoint off, or limit PublicAccessCidrs.", "Amazon EKS best practices guide");
                }
            }
            _ => {}
        }
    }
    out
}

const AWS_IAM_GUIDE: &str = "AWS IAM User Guide: security best practices";

/* ───────────────────────────── IAM documents ───────────────────────────── */

/// A policy document that the API returned URL-encoded, or as an object.
fn document(v: Option<&Value>) -> Option<Value> {
    match v? {
        o @ Value::Object(_) => Some(o.clone()),
        Value::String(s) => {
            let decoded = url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default();
            serde_json::from_str(&decoded).ok().or_else(|| serde_json::from_str(s).ok())
        }
        _ => None,
    }
}

/// `aws iam get-account-authorization-details`: users, groups, roles and customer managed policies.
fn account_details(root: &Value) -> Vec<Issue> {
    let mut out = Vec::new();
    let account = root
        .pointer("/RoleDetailList/0/Arn")
        .or_else(|| root.pointer("/UserDetailList/0/Arn"))
        .and_then(Value::as_str)
        .and_then(|arn| arn.split(':').nth(4))
        .map(String::from);
    let check = |out: &mut Vec<Issue>, label: String, doc: Option<Value>| {
        if let Some(d) = doc.filter(iam::is_policy) {
            out.extend(iam::check(&label, &d, account.as_deref()));
        }
    };
    for (list_key, kind, inline_key) in [("UserDetailList", "User", "UserPolicyList"), ("GroupDetailList", "Group", "GroupPolicyList"), ("RoleDetailList", "Role", "RolePolicyList")] {
        for item in root.get(list_key).and_then(Value::as_array).into_iter().flatten() {
            let name = [text(item, "UserName"), text(item, "GroupName"), text(item, "RoleName")].into_iter().find(|n| !n.is_empty()).unwrap_or_default();
            for p in item.get(inline_key).and_then(Value::as_array).into_iter().flatten() {
                check(&mut out, format!("{kind} {name} inline policy {}", text(p, "PolicyName")), document(p.get("PolicyDocument")));
            }
            if kind == "Role" {
                check(&mut out, format!("Role {name} trust policy"), document(item.get("AssumeRolePolicyDocument")));
            }
            let attached: Vec<String> = item.get("AttachedManagedPolicies").and_then(Value::as_array).into_iter().flatten().map(|m| text(m, "PolicyArn")).collect();
            admin_policy_attached(&mut out, &format!("{kind} {name}"), &attached);
        }
    }
    for p in root.get("Policies").and_then(Value::as_array).into_iter().flatten() {
        let default = p.get("PolicyVersionList").and_then(Value::as_array).into_iter().flatten().find(|v| setting(v, "IsDefaultVersion") == Setting::On);
        if let Some(v) = default {
            check(&mut out, format!("Policy {}", text(p, "PolicyName")), document(v.get("Document")));
        }
    }
    out
}

/* ───────────────────────────── files ───────────────────────────── */

fn name_of(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_ascii_lowercase()
}

fn rank(s: &str) -> usize {
    ["critical", "high", "medium", "low", "info"].iter().position(|x| *x == s).unwrap_or(5)
}

/// What a parsed JSON or YAML document is.
fn kind_of(v: &Value) -> Option<&'static str> {
    if v.get("format_version").is_some() && (v.get("planned_values").is_some() || v.get("resource_changes").is_some()) {
        return Some("terraform-plan");
    }
    if v.get("Resources").and_then(Value::as_object).is_some_and(|r| r.values().any(|x| x.get("Type").and_then(Value::as_str).is_some_and(|t| t.starts_with("AWS::")))) {
        return Some("cloudformation");
    }
    if ["UserDetailList", "RoleDetailList", "GroupDetailList"].iter().any(|k| v.get(*k).is_some()) || v.get("Policies").and_then(Value::as_array).is_some_and(|p| p.iter().any(|x| x.get("PolicyVersionList").is_some())) {
        return Some("iam-account");
    }
    if iam::is_policy(v) || cli_policy(v).is_some() {
        return Some("iam-policy");
    }
    if v.get("resource").and_then(Value::as_object).is_some_and(|r| r.keys().any(|k| k.starts_with("aws_"))) || v.get("data").and_then(Value::as_object).is_some_and(|r| r.keys().any(|k| k.starts_with("aws_"))) {
        return Some("terraform");
    }
    None
}

/// Policies in AWS CLI output: get-policy-version, get-role, get-role-policy and the like.
fn cli_policy(v: &Value) -> Option<(String, Value)> {
    for (pointer, label) in [("/PolicyVersion/Document", "policy version"), ("/Role/AssumeRolePolicyDocument", "trust policy"), ("/PolicyDocument", "policy"), ("/Policy", "resource policy")] {
        if let Some(d) = document(v.pointer(pointer)).filter(iam::is_policy) {
            return Some((label.to_string(), d));
        }
    }
    None
}

fn check_doc(kind: &str, file: &str, v: &Value) -> Vec<Issue> {
    match kind {
        "terraform-plan" => terraform_checks(&plan_resources(v)),
        "terraform" => terraform_checks(&config_resources(v)),
        "cloudformation" => cloudformation(v),
        "iam-account" => account_details(v),
        _ => {
            if iam::is_policy(v) {
                iam::check(file, v, None)
            } else if let Some((label, d)) = cli_policy(v) {
                iam::check(&format!("{file} {label}"), &d, None)
            } else {
                Vec::new()
            }
        }
    }
}

/// Checks one file's text. `hint`: auto, terraform, cloudformation or iam. None when the file is
/// not cloud configuration (only for auto).
pub fn analyze(file: &str, text_in: &str, hint: &str) -> Option<FileReport> {
    let name = name_of(file);
    let body = text_in.trim_start_matches('\u{feff}');
    let mut report = FileReport { file: file.to_string(), ..Default::default() };
    let trimmed = body.trim_start();
    if (hint == "terraform" && !trimmed.starts_with('{')) || (hint == "auto" && name.ends_with(".tf")) {
        report.kind = "terraform".into();
        match hcl::parse(body) {
            Ok(b) => report.issues = terraform_checks(&config_resources(&body_json(&b, 0))),
            Err(e) => report.error = format!("not valid HCL: {}", e.to_string().lines().next().unwrap_or("")),
        }
    } else {
        let parsed = if trimmed.starts_with('{') || trimmed.starts_with('[') { serde_json::from_str::<Value>(body).map_err(|e| format!("not valid JSON: {e}")) } else { crate::yaml::parse_one(body) };
        let v = match parsed {
            Ok(v) => v,
            Err(e) => {
                if hint == "auto" {
                    return None;
                }
                report.kind = hint.into();
                report.error = e;
                return Some(report);
            }
        };
        let kind = match (hint, kind_of(&v)) {
            (_, Some(k)) => k,
            ("cloudformation", None) | ("terraform", None) | ("iam", None) => {
                report.kind = hint.into();
                report.error = match hint {
                    "cloudformation" => "No AWS resources found (a CloudFormation template has Resources with AWS:: types)".into(),
                    "iam" => "No policy statements found".into(),
                    _ => "No Terraform resources found".into(),
                };
                return Some(report);
            }
            _ => return None,
        };
        report.kind = kind.into();
        report.issues = check_doc(kind, file, &v);
    }
    report.issues.sort_by_key(|i| rank(&i.severity));
    Some(report)
}

/// Scans a file or a folder tree for cloud configuration (symbolic links are not followed).
pub fn scan_path(root: &Path) -> ScanResult {
    let mut res = ScanResult::default();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(p) = stack.pop() {
        visited += 1;
        if visited > MAX_VISITED || res.files.len() >= MAX_FILES {
            res.truncated = true;
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if p != root && p.file_name().is_some_and(|n| SKIP_DIRS.contains(&n.to_string_lossy().as_ref())) {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&p) {
                let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                stack.extend(entries.into_iter().rev());
            }
            continue;
        }
        res.files_seen += 1;
        let name = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        let candidate = [".tf", ".json", ".yaml", ".yml", ".template"].iter().any(|e| name.ends_with(e)) || p == root;
        if !candidate || meta.len() > MAX_FILE_BYTES || name == "package.json" || name == "package-lock.json" || name.ends_with(".tfstate") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&p) else { continue };
        if bytes.iter().take(8192).any(|b| *b == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let shown = match p.strip_prefix(root).ok().filter(|r| !r.as_os_str().is_empty()) {
            Some(rel) => rel.to_string_lossy().replace('\\', "/"),
            None => p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.to_string_lossy().to_string()),
        };
        if let Some(r) = analyze(&shown, &text, "auto") {
            res.files.push(r);
        }
    }
    res
}

#[cfg(test)]
#[path = "iac_tests.rs"]
mod tests;
