//! Kubernetes RBAC: the rules of a Role or ClusterRole that open a way to more privileges, and who
//! receives them through RoleBindings and ClusterRoleBindings. The list follows the Kubernetes
//! documentation "Role Based Access Control Good Practices"; matching follows the API server's
//! (`*` for every verb or resource, `*/<subresource>`, exact names otherwise).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{issue, strings, Issue};

const GOOD_PRACTICES: &str = "Kubernetes documentation: RBAC good practices";
/// bindings to the API server's own defaults (`system:public-info-viewer` and the like) are left alone
const SYSTEM_PREFIX: &str = "system:";
/// RBAC objects kept from a folder scan for the bindings pass
pub(super) const MAX_OBJECTS: usize = 20_000;

/// A permission that leads to more privileges.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Danger {
    pub rule: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    /// what it allows, inside a sentence ("read Secrets")
    pub what: &'static str,
    pub detail: String,
    pub remediation: &'static str,
    pub reference: &'static str,
}

pub(super) fn is_rbac(doc: &Value) -> bool {
    matches!(doc.get("kind").and_then(Value::as_str), Some("Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding"))
}

fn has_verb(verbs: &[String], wanted: &[&str]) -> bool {
    verbs.iter().any(|v| v == "*" || wanted.contains(&v.as_str()))
}

/// `wanted` is `resource` or `resource/subresource`
fn has_resource(resources: &[String], wanted: &[&str]) -> bool {
    resources.iter().any(|r| {
        r == "*" || wanted.contains(&r.as_str()) || wanted.iter().any(|w| w.split_once('/').is_some_and(|(_, sub)| r.strip_prefix("*/") == Some(sub)))
    })
}

/// A rule without apiGroups is malformed for resources; it is read as matching, to stay on the safe side.
fn has_group(groups: &[String], wanted: &[&str], present: bool) -> bool {
    !present || groups.iter().any(|g| g == "*" || wanted.contains(&g.as_str()))
}

const WORKLOADS: &[&str] = &["pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs", "replicationcontrollers"];

/// The dangerous permissions one rule grants. A rule with a wildcard reports only the wildcard.
fn rule_dangers(rule: &Value) -> Vec<Danger> {
    let verbs = strings(rule.get("verbs"));
    let resources = strings(rule.get("resources"));
    let groups = strings(rule.get("apiGroups"));
    let grouped = rule.get("apiGroups").is_some();
    let names = strings(rule.get("resourceNames"));
    if resources.is_empty() {
        return Vec::new(); // nonResourceURLs only
    }
    let mut out = Vec::new();
    let mut add = |rule: &'static str, severity: &'static str, title: &'static str, what: &'static str, detail: String, remediation: &'static str, reference: &'static str| {
        out.push(Danger { rule, severity, title, what, detail, remediation, reference });
    };
    if verbs.iter().any(|v| v == "*") || resources.iter().any(|r| r == "*") {
        let everything = verbs.iter().any(|v| v == "*") && resources.iter().any(|r| r == "*") && groups.iter().any(|g| g == "*");
        add(
            "K8S-RBAC-WILDCARD",
            if everything { "critical" } else { "high" },
            "Wildcard RBAC permissions",
            if everything { "do everything (all verbs on all resources)" } else { "use wildcard permissions" },
            format!("A rule grants {} on {}: everything, including resources added later.", verbs.join(", "), resources.join(", ")),
            "List the exact verbs and resources the subject needs.",
            GOOD_PRACTICES,
        );
        return out;
    }
    let core = |wanted: &[&str]| has_group(&groups, wanted, grouped);
    // get on named Secrets only (resourceNames) is the narrow form this check recommends
    if core(&[""]) && has_resource(&resources, &["secrets"]) && has_verb(&verbs, &["get", "list", "watch"]) && (names.is_empty() || has_verb(&verbs, &["list", "watch"])) {
        add("K8S-RBAC-SECRETS", "medium", "Read access to Secrets", "read Secrets", "The role can read Secrets, which often hold credentials for other systems; list and watch reveal their contents as well as get does.".into(), "Limit it to named Secrets (resourceNames), or remove list and watch.", GOOD_PRACTICES);
    }
    if core(&["rbac.authorization.k8s.io"]) && has_resource(&resources, &["roles", "clusterroles"]) {
        if has_verb(&verbs, &["escalate"]) {
            add("K8S-RBAC-ESCALATE", "high", "Can raise its own permissions (escalate)", "grant permissions they do not hold (escalate)", "The escalate verb on roles lets the subject create or change roles with permissions it does not have, which lifts the API server's protection against privilege escalation.".into(), "Remove escalate; leave role changes to administrators.", GOOD_PRACTICES);
        }
        if has_verb(&verbs, &["bind"]) {
            add("K8S-RBAC-BIND", "high", "Can bind roles it does not hold (bind)", "bind roles they do not hold (bind)", "The bind verb lets the subject create bindings to roles whose permissions it does not have, for itself or for others.".into(), "Remove bind, or limit it with resourceNames to the roles the subject may hand out.", GOOD_PRACTICES);
        }
    }
    if core(&["", "authentication.k8s.io"]) && has_resource(&resources, &["users", "groups", "serviceaccounts", "uids", "userextras"]) && has_verb(&verbs, &["impersonate"]) {
        // the built-in edit role, for example, impersonates service accounts only
        let what = if has_resource(&resources, &["users", "groups", "uids", "userextras"]) { "impersonate users, groups or service accounts" } else { "impersonate service accounts" };
        add("K8S-RBAC-IMPERSONATE", "high", "Can impersonate other identities", what, "Impersonation gives the subject the rights of whoever it impersonates, for example a member of system:masters, which bypasses RBAC entirely.".into(), "Remove impersonate, or limit it with resourceNames to the identities that are needed.", GOOD_PRACTICES);
    }
    if core(&[""]) && has_resource(&resources, &["nodes/proxy"]) && has_verb(&verbs, &["get", "create", "update", "patch"]) {
        add("K8S-RBAC-NODES-PROXY", "high", "Access to the Kubelet API (nodes/proxy)", "use the Kubelet API (nodes/proxy)", "nodes/proxy reaches the Kubelet API, which can run commands in the pods of a node; this access bypasses audit logging and admission control, and get on nodes/proxy is not read-only.".into(), "Remove nodes/proxy; give monitoring tools the metrics endpoints they need instead.", GOOD_PRACTICES);
    }
    if core(&["certificates.k8s.io"]) && has_resource(&resources, &["certificatesigningrequests/approval"]) && has_verb(&verbs, &["update", "patch"]) {
        add("K8S-RBAC-CSR-APPROVE", "high", "Can approve certificate requests", "approve certificate signing requests", "Approving CertificateSigningRequests for the kubernetes.io/kube-apiserver-client signer issues client certificates for any name, including Kubernetes system components.".into(), "Leave certificate approval to the controller manager or to administrators.", GOOD_PRACTICES);
    }
    if core(&[""]) && has_resource(&resources, &["serviceaccounts/token"]) && has_verb(&verbs, &["create"]) {
        add("K8S-RBAC-TOKEN", "high", "Can issue service account tokens", "issue service account tokens (serviceaccounts/token)", "create on serviceaccounts/token issues tokens for existing service accounts, and with them their rights.".into(), "Remove it, or limit it with resourceNames to the service accounts the subject manages.", GOOD_PRACTICES);
    }
    if core(&["admissionregistration.k8s.io"]) && has_resource(&resources, &["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]) && has_verb(&verbs, &["create", "update", "patch"]) {
        add("K8S-RBAC-WEBHOOKS", "high", "Controls admission webhooks", "change admission webhook configurations", "Whoever controls webhook configurations can have every object admitted to the cluster sent to a server of their choice, and with a mutating webhook changed (for example to add a container).".into(), "Keep webhook configurations to cluster administrators.", GOOD_PRACTICES);
    }
    if core(&[""]) && has_resource(&resources, &["persistentvolumes"]) && has_verb(&verbs, &["create"]) {
        add("K8S-RBAC-PV-CREATE", "high", "Can create PersistentVolumes", "create PersistentVolumes (hostPath)", "Creating PersistentVolumes includes hostPath volumes, which give pods access to the node's file system.".into(), "Let only trusted operators and the control plane create PersistentVolumes; workloads claim storage with PersistentVolumeClaims.", GOOD_PRACTICES);
    }
    if core(&["", "apps", "extensions", "batch"]) && has_resource(&resources, WORKLOADS) && has_verb(&verbs, &["create"]) {
        add("K8S-RBAC-WORKLOADS", "medium", "Can create workloads", "create pods or workloads", "Creating pods, directly or through Deployments, Jobs and other workloads, gives access to the namespace's Secrets, ConfigMaps and volumes and runs code as any service account of the namespace; where privileged pods are allowed, it reaches the node.".into(), "Grant workload creation to deployment pipelines and namespace owners, and enforce Pod Security admission.", GOOD_PRACTICES);
    }
    if core(&[""]) && has_resource(&resources, &["pods/exec", "pods/attach"]) && has_verb(&verbs, &["create", "get"]) {
        add("K8S-RBAC-EXEC", "medium", "Can run commands in pods (pods/exec)", "run commands in pods (pods/exec)", "exec and attach give the subject a shell in running pods, with their service account tokens and mounted secrets.".into(), "Keep exec for break-glass access; use logs and metrics for day-to-day work.", "Microsoft threat matrix for Kubernetes: Exec into container");
    }
    if core(&[""]) && has_resource(&resources, &["namespaces"]) && has_verb(&verbs, &["patch", "update"]) {
        add("K8S-RBAC-NAMESPACE", "medium", "Can change namespaces", "change namespace labels", "patch or update on namespaces changes their labels, for example to relax the Pod Security admission level of a namespace.".into(), "Keep namespace changes to cluster administrators.", GOOD_PRACTICES);
    }
    out
}

fn rank(severity: &str) -> usize {
    ["critical", "high", "medium", "low", "info"].iter().position(|s| *s == severity).unwrap_or(5)
}

/// The dangers of a set of rules, one per kind, the most severe first.
fn dangers(rules: &[Value]) -> Vec<Danger> {
    let mut by_rule: BTreeMap<&'static str, Danger> = BTreeMap::new();
    for d in rules.iter().flat_map(rule_dangers) {
        match by_rule.get(d.rule) {
            Some(prev) if rank(prev.severity) <= rank(d.severity) => {}
            _ => {
                by_rule.insert(d.rule, d);
            }
        }
    }
    let mut out: Vec<Danger> = by_rule.into_values().collect();
    out.sort_by_key(|d| rank(d.severity));
    out
}

/// One issue per kind of danger in a Role or ClusterRole.
pub(super) fn role_issues(out: &mut Vec<Issue>, label: &str, doc: &Value) {
    let rules: Vec<Value> = doc.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
    for d in dangers(&rules) {
        issue(out, d.rule, d.severity, d.title, label.to_string(), d.detail, d.remediation, d.reference);
    }
}

/// The default user-facing ClusterRoles, as far as their dangers go (Kubernetes documentation,
/// "Using RBAC Authorization": admin and edit can read Secrets, run pods as any service account
/// of the namespace and exec into pods; view cannot read Secrets).
fn builtin(name: &str) -> Option<Vec<Value>> {
    let edit = || {
        vec![
            json!({ "apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"] }),
            json!({ "apiGroups": ["", "apps", "batch"], "resources": ["pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"], "verbs": ["create", "update", "patch", "delete"] }),
            json!({ "apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create", "get"] }),
            json!({ "apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"] }),
        ]
    };
    match name {
        "cluster-admin" => Some(vec![json!({ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] })]),
        "admin" | "edit" => Some(edit()),
        "view" => Some(Vec::new()),
        _ => None,
    }
}

fn label_of(doc: &Value) -> String {
    let kind = doc.get("kind").and_then(Value::as_str).unwrap_or("");
    let name = doc.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("?");
    match doc.pointer("/metadata/namespace").and_then(Value::as_str) {
        Some(ns) => format!("{kind} {ns}/{name}"),
        None => format!("{kind} {name}"),
    }
}

/// Who a subject stands for, when that is more than one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Audience {
    Anonymous,
    AllUsers,
    AllServiceAccounts,
    DefaultServiceAccount,
}

fn audience(subject: &Value) -> Option<Audience> {
    let kind = subject.get("kind").and_then(Value::as_str).unwrap_or("");
    let name = subject.get("name").and_then(Value::as_str).unwrap_or("");
    match (kind, name) {
        ("Group", "system:unauthenticated") | ("User", "system:anonymous") => Some(Audience::Anonymous),
        ("Group", "system:authenticated") => Some(Audience::AllUsers),
        ("Group", n) if n == "system:serviceaccounts" || n.starts_with("system:serviceaccounts:") => Some(Audience::AllServiceAccounts),
        ("ServiceAccount", "default") => Some(Audience::DefaultServiceAccount),
        _ => None,
    }
}

fn subject_name(subject: &Value, binding_ns: &str) -> String {
    let kind = subject.get("kind").and_then(Value::as_str).unwrap_or("");
    let name = subject.get("name").and_then(Value::as_str).unwrap_or("?");
    match (kind, subject.get("namespace").and_then(Value::as_str)) {
        ("ServiceAccount", Some(ns)) => format!("service account {ns}/{name}"),
        ("ServiceAccount", None) => format!("service account {binding_ns}/{name}"),
        ("Group", _) => format!("group {name}"),
        _ => format!("user {name}"),
    }
}

/// Bindings that give dangerous rights (or any rights, for anonymous users) to many identities at
/// once. `objects` are RBAC objects with the index of their file; roles are looked up among them
/// and among the default roles. The issues come back with the binding's file index.
pub(super) fn binding_issues(objects: &[(usize, &Value)]) -> Vec<(usize, Issue)> {
    let mut cluster_roles: BTreeMap<&str, &Value> = BTreeMap::new();
    let mut roles: BTreeMap<(&str, &str), &Value> = BTreeMap::new();
    for (_, d) in objects {
        let name = d.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("");
        match d.get("kind").and_then(Value::as_str) {
            Some("ClusterRole") => {
                cluster_roles.insert(name, d);
            }
            Some("Role") => {
                roles.insert((d.pointer("/metadata/namespace").and_then(Value::as_str).unwrap_or(""), name), d);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (file, b) in objects {
        let kind = b.get("kind").and_then(Value::as_str).unwrap_or("");
        if kind != "RoleBinding" && kind != "ClusterRoleBinding" {
            continue;
        }
        let name = b.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("");
        let role_kind = b.pointer("/roleRef/kind").and_then(Value::as_str).unwrap_or("");
        let role_name = b.pointer("/roleRef/name").and_then(Value::as_str).unwrap_or("");
        // the API server's own bindings, and cluster-admin (reported for every binding already)
        if name.starts_with(SYSTEM_PREFIX) || role_name.starts_with(SYSTEM_PREFIX) || role_name == "cluster-admin" {
            continue;
        }
        let ns = b.pointer("/metadata/namespace").and_then(Value::as_str).unwrap_or("");
        let rules: Option<Vec<Value>> = match role_kind {
            "ClusterRole" => cluster_roles.get(role_name).map(|r| r.get("rules").and_then(Value::as_array).cloned().unwrap_or_default()).or_else(|| builtin(role_name)),
            "Role" => roles.get(&(ns, role_name)).or_else(|| roles.get(&("", role_name))).map(|r| r.get("rules").and_then(Value::as_array).cloned().unwrap_or_default()),
            _ => None,
        };
        let found = rules.is_some();
        let found_dangers = dangers(&rules.unwrap_or_default());
        let scope = if kind == "ClusterRoleBinding" { "across the cluster".to_string() } else if ns.is_empty() { "in its namespace".to_string() } else { format!("in namespace {ns}") };
        let role = format!("{role_kind} {role_name}");
        let allows = if found_dangers.is_empty() { String::new() } else { format!(" It allows them to {}.", found_dangers.iter().map(|d| d.what).collect::<Vec<_>>().join("; ")) };
        let worst = found_dangers.first().map(|d| d.severity);
        let mut groups: BTreeMap<Audience, Vec<String>> = BTreeMap::new();
        for s in b.get("subjects").and_then(Value::as_array).into_iter().flatten() {
            if let Some(a) = audience(s) {
                groups.entry(a).or_default().push(subject_name(s, if ns.is_empty() { "?" } else { ns }));
            }
        }
        let label = label_of(b);
        for (aud, who) in groups {
            let who = who.join(", ");
            let (rule, severity, title, why) = match aud {
                Audience::Anonymous => (
                    "K8S-RBAC-ANONYMOUS",
                    if worst.is_some() { "critical" } else { "high" },
                    "Rights for anonymous users",
                    "anyone who can reach the API server, without credentials",
                ),
                Audience::AllUsers | Audience::AllServiceAccounts if worst.is_some() => (
                    "K8S-RBAC-BROAD",
                    if matches!(worst, Some("critical" | "high")) { "critical" } else { "high" },
                    if aud == Audience::AllUsers { "Dangerous rights for every authenticated user" } else { "Dangerous rights for every service account" },
                    if aud == Audience::AllUsers { "every user and service account that can authenticate" } else { "every service account, and so every pod that runs with one" },
                ),
                Audience::DefaultServiceAccount if worst.is_some() => (
                    "K8S-RBAC-DEFAULT-SA",
                    worst.unwrap_or("medium"),
                    "Dangerous rights for a default service account",
                    "every pod of the namespace that does not name another service account",
                ),
                _ => continue,
            };
            let unknown = if found { "" } else { " The role is not in the scanned files, so what it allows is not known here." };
            let mut issues = Vec::new();
            issue(
                &mut issues,
                rule,
                severity,
                title,
                label.clone(),
                format!("Gives {role} to {who} {scope}: {why}.{allows}{unknown}"),
                "Bind the role to the specific users, groups or service accounts that need it; give workloads their own service accounts.",
                GOOD_PRACTICES,
            );
            out.extend(issues.into_iter().map(|i| (*file, i)));
        }
    }
    out
}
