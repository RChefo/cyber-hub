//! Container and Kubernetes configuration checks (docs/UTILITIES.md): Dockerfiles, Compose files
//! and Kubernetes manifests are read locally and checked against the Kubernetes Pod Security
//! Standards (baseline and restricted) and the recommendations of the CIS Docker Benchmark.
//! Nothing is contacted, built or run. References name the recommendation, not a section number,
//! because the numbering changes between benchmark versions. RBAC objects are checked for the
//! ways to more privileges the Kubernetes RBAC good practices list (`containers_rbac.rs`).

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

#[path = "containers_rbac.rs"]
mod rbac;

pub const MAX_FILES: usize = 2_000;
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
pub const MAX_TEXT: usize = 5 * 1024 * 1024;
const MAX_VISITED: usize = 50_000;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "venv", "__pycache__", ".idea", ".gradle", "vendor", ".terraform", "dist", "build"];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub rule: String,
    /// critical, high, medium, low or info
    pub severity: String,
    pub title: String,
    /// "line 12" in a Dockerfile, "service web" in Compose, "Deployment shop/web › container app"
    pub location: String,
    pub detail: String,
    pub remediation: String,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub file: String,
    /// dockerfile, compose or kubernetes
    pub kind: String,
    pub issues: Vec<Issue>,
    /// why the file could not be read ("" when it was)
    pub error: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub files: Vec<FileReport>,
    /// files looked at (container configurations or not)
    pub files_seen: usize,
    pub truncated: bool,
}

#[allow(clippy::too_many_arguments)]
fn issue(out: &mut Vec<Issue>, rule: &str, severity: &str, title: &str, location: String, detail: String, remediation: &str, reference: &str) {
    out.push(Issue { rule: rule.into(), severity: severity.into(), title: title.into(), location, detail, remediation: remediation.into(), reference: reference.into() });
}

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

/// A variable name that suggests a secret.
fn secret_name(name: &str) -> bool {
    let n = norm(name);
    ["password", "passwd", "secret", "token", "apikey", "accesskey", "privatekey", "credential", "clientsecret"].iter().any(|p| n.contains(p)) || n.ends_with("pwd")
}

/// A literal value (not empty, not a variable reference such as `$X` or `${X}`).
fn literal(v: &str) -> bool {
    let t = v.trim().trim_matches(['"', '\'']);
    !t.is_empty() && !t.starts_with('$')
}

/// The tag problem of an image reference: None when it is pinned (a tag other than latest, or a
/// digest), or not checkable (a variable, `scratch`).
fn unpinned(image: &str) -> Option<&'static str> {
    let i = image.trim();
    if i.is_empty() || i.contains('$') || i.contains("{{") || i == "scratch" || i.contains("@sha256:") {
        return None;
    }
    let last = i.rsplit('/').next().unwrap_or(i);
    match last.split_once(':') {
        None => Some("has no tag, so it means latest"),
        Some((_, "latest")) => Some("uses the latest tag"),
        Some(_) => None,
    }
}

/* ───────────────────────────── Dockerfile ───────────────────────────── */

/// Instructions with the line they start on (continuations joined, comments dropped).
fn instructions(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if current.is_none() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if current.is_some() && trimmed.starts_with('#') {
            continue;
        }
        let (start, mut acc) = current.take().unwrap_or((i + 1, String::new()));
        let (body, more) = match line.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (line, false),
        };
        if !acc.is_empty() {
            acc.push(' ');
        }
        acc.push_str(body.trim());
        if more {
            current = Some((start, acc));
        } else {
            let (word, rest) = acc.split_once(char::is_whitespace).unwrap_or((acc.as_str(), ""));
            out.push((start, word.to_ascii_uppercase(), rest.trim().to_string()));
        }
    }
    if let Some((start, acc)) = current {
        let (word, rest) = acc.split_once(char::is_whitespace).unwrap_or((acc.as_str(), ""));
        out.push((start, word.to_ascii_uppercase(), rest.trim().to_string()));
    }
    out
}

const CIS_USER: &str = "CIS Docker Benchmark: Ensure that a user for the container has been created";
const CIS_SECRETS: &str = "CIS Docker Benchmark: Ensure secrets are not stored in Dockerfiles";

pub fn dockerfile(text: &str) -> Vec<Issue> {
    static PIPE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b").expect("valid pattern"));
    static NO_TLS: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)(\bcurl\b[^;&|]*\s(-k|--insecure)\b|--no-check-certificate|--trusted-host|strict-ssl\s+false|GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|sslverify\s*=\s*(0|false))").expect("valid pattern")
    });
    static CHMOD: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| regex::Regex::new(r"\bchmod\s+(-R\s+)?0?777\b").expect("valid pattern"));
    let mut out = Vec::new();
    let ins = instructions(text);
    // stages: (alias, index of its FROM, base image)
    let mut stages: Vec<(String, usize, String)> = Vec::new();
    for (idx, (line, word, args)) in ins.iter().enumerate() {
        let at = format!("line {line}");
        match word.as_str() {
            "FROM" => {
                let parts: Vec<&str> = args.split_whitespace().filter(|p| !p.starts_with("--")).collect();
                let image = parts.first().copied().unwrap_or("");
                let earlier_stage = stages.iter().any(|(a, _, _)| !a.is_empty() && a.eq_ignore_ascii_case(image));
                let alias = parts.iter().position(|p| p.eq_ignore_ascii_case("as")).and_then(|i| parts.get(i + 1)).map(|a| a.to_ascii_lowercase()).unwrap_or_default();
                stages.push((alias, idx, image.to_ascii_lowercase()));
                if !earlier_stage {
                    if let Some(why) = unpinned(image) {
                        issue(&mut out, "DF-UNPINNED-BASE", "medium", "Base image not pinned", at, format!("FROM {image} {why}: builds pick up whatever the tag points to that day, including untested or compromised images."), "Pin a specific version tag, or better a digest (image@sha256:…), and update it on purpose.", "CIS Docker Benchmark: Ensure images are scanned and rebuilt to include security patches");
                    }
                }
            }
            "RUN" => {
                if PIPE.is_match(args) {
                    issue(&mut out, "DF-PIPE-TO-SHELL", "high", "Downloaded script piped into a shell", at.clone(), "A script fetched with curl or wget is run directly: whatever the server returns at build time is executed, unchecked.".into(), "Download the file, verify its checksum or signature, then run it.", "CIS Docker Benchmark: Ensure verified packages are only installed");
                }
                if NO_TLS.is_match(args) {
                    issue(&mut out, "DF-TLS-DISABLED", "medium", "Certificate checks turned off", at.clone(), "A download or package manager runs with TLS verification disabled, so a network attacker can change what is installed.".into(), "Remove the option and install the needed CA certificates instead.", "CIS Docker Benchmark: Ensure verified packages are only installed");
                }
                if CHMOD.is_match(args) {
                    issue(&mut out, "DF-WORLD-WRITABLE", "medium", "World-writable permissions", at.clone(), "chmod 777 lets any user in the container change these files, including code that later runs with more privileges.".into(), "Grant only the permissions needed, to the user that needs them.", "CIS Docker Benchmark: Ensure setuid and setgid permissions are removed");
                }
                if args.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == "sudo") {
                    issue(&mut out, "DF-SUDO", "low", "sudo in the build", at, "sudo in a Dockerfile usually means the image ships sudo, which gives an attacker in the container an easy way to root.".into(), "Run the step as root before switching to an unprivileged USER, and do not install sudo.", CIS_USER);
                }
            }
            "ADD" => {
                let src = args.split_whitespace().find(|p| !p.starts_with("--")).unwrap_or("");
                let lower = src.to_ascii_lowercase();
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    issue(&mut out, "DF-ADD-URL", "medium", "ADD downloads a remote file", at, format!("ADD {src} fetches a file at build time without any integrity check."), "Download with curl or wget and verify a checksum, or use ADD --checksum=sha256:… where your builder supports it.", "CIS Docker Benchmark: Ensure that COPY is used instead of ADD in Dockerfiles");
                } else if ![".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tbz2", ".txz"].iter().any(|x| lower.ends_with(x)) {
                    issue(&mut out, "DF-ADD-NOT-COPY", "low", "ADD used where COPY is enough", at, format!("ADD {src} also unpacks archives and fetches URLs; COPY does only what is meant."), "Use COPY for local files.", "CIS Docker Benchmark: Ensure that COPY is used instead of ADD in Dockerfiles");
                }
            }
            "ENV" | "ARG" => {
                // ENV a=b c=d, ENV a b, ARG a=default, ARG a
                let pairs: Vec<(String, String)> = if args.contains('=') {
                    args.split_whitespace().filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect()
                } else {
                    let (k, v) = args.split_once(char::is_whitespace).unwrap_or((args.as_str(), ""));
                    vec![(k.to_string(), v.to_string())]
                };
                for (k, v) in pairs.into_iter().filter(|(k, _)| secret_name(k)) {
                    if word == "ENV" && literal(&v) {
                        issue(&mut out, "DF-SECRET-ENV", "high", "Secret stored in the image", at.clone(), format!("ENV {k} is set to a literal value: it stays in the image's layers and metadata, readable by anyone who can pull the image."), "Pass secrets at run time (an orchestrator secret or a mounted file), or use a BuildKit secret mount for the build.", CIS_SECRETS);
                    } else if word == "ARG" {
                        issue(&mut out, "DF-SECRET-ARG", if literal(&v) { "high" } else { "medium" }, "Secret passed as a build argument", at.clone(), format!("ARG {k} ends up in the image history (docker history) together with its value."), "Use a BuildKit secret mount (RUN --mount=type=secret) instead of a build argument.", CIS_SECRETS);
                    }
                }
            }
            "EXPOSE" => {
                if args.split_whitespace().any(|p| p.split('/').next() == Some("22")) {
                    issue(&mut out, "DF-SSH", "medium", "SSH port exposed", at, "Port 22 suggests an SSH server in the container: one more service and set of credentials to protect.".into(), "Use docker exec or kubectl exec for access instead of SSH inside containers.", "CIS Docker Benchmark: Ensure sshd is not run within containers");
                }
            }
            _ => {}
        }
    }
    if let Some(last) = stages.last() {
        let from = last.1;
        let final_stage = &ins[from..];
        // the user in effect: the last USER of the stage, else of the stage it is built FROM
        let mut user: Option<(usize, String)> = None;
        let mut base = last.2.clone();
        let mut cursor = stages.len() - 1;
        for _ in 0..stages.len() {
            let (_, start, image) = &stages[cursor];
            let end = stages.get(cursor + 1).map(|s| s.1).unwrap_or(ins.len());
            if let Some((line, _, a)) = ins[*start..end].iter().rev().find(|(_, w, _)| w == "USER") {
                user = Some((*line, a.split(':').next().unwrap_or("").trim().to_string()));
                break;
            }
            base = image.clone();
            match stages[..cursor].iter().rposition(|(a, _, _)| !a.is_empty() && *a == *image) {
                Some(prev) => cursor = prev,
                None => break,
            }
        }
        let own_user = base == "scratch" || base.contains("distroless") || base.contains("nonroot") || base.contains("chainguard");
        match user {
            None if !own_user => issue(&mut out, "DF-ROOT", "high", "The container runs as root", format!("line {}", final_stage[0].0), "The final stage sets no USER, so processes run as root inside the container unless the base image sets a non-root user; a breakout or a mounted volume then acts as root.".into(), "Create an unprivileged user and add USER <name> (or a numeric UID) to the final stage.", CIS_USER),
            Some((line, u)) if u == "root" || u == "0" => issue(&mut out, "DF-ROOT", "high", "The container runs as root", format!("line {line}"), "The last USER in effect for the final stage is root.".into(), "Switch to an unprivileged user at the end of the final stage.", CIS_USER),
            _ => {}
        }
        let image = base.as_str();
        if image != "scratch" && !final_stage.iter().any(|(_, w, _)| w == "HEALTHCHECK") && !ins.iter().any(|(_, w, a)| w == "HEALTHCHECK" && !a.eq_ignore_ascii_case("NONE")) {
            issue(&mut out, "DF-NO-HEALTHCHECK", "low", "No health check", format!("line {}", final_stage[0].0), "Without HEALTHCHECK the runtime cannot tell a hung container from a working one.".into(), "Add a HEALTHCHECK, or rely on the orchestrator's probes and say so.", "CIS Docker Benchmark: Ensure that HEALTHCHECK instructions have been added to container images");
        }
    }
    out
}

/* ───────────────────────────── Compose ───────────────────────────── */

const SENSITIVE_MOUNTS: &[&str] = &["/", "/etc", "/proc", "/sys", "/boot", "/root", "/dev", "/var/lib/docker", "/var/lib/kubelet", "/run", "/var/run"];
const RISKY_CAPS: &[&str] = &["SYS_ADMIN", "ALL", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN", "BPF", "PERFMON", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE"];
/// Container ports that should not be published on every interface.
const INTERNAL_PORTS: &[(u32, &str)] = &[
    (2375, "the Docker API without TLS"), (2376, "the Docker API"), (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"), (9200, "Elasticsearch"), (9300, "Elasticsearch transport"),
    (5984, "CouchDB"), (11211, "Memcached"), (8086, "InfluxDB"), (15672, "the RabbitMQ management UI"), (5601, "Kibana"), (8500, "Consul"), (2379, "etcd"), (10250, "the kubelet API"), (1433, "SQL Server"), (1521, "Oracle"),
];

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string).or_else(|| x.as_u64().map(|n| n.to_string()))).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn flag(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1"),
        _ => false,
    }
}

fn mount_issue(out: &mut Vec<Issue>, source: &str, location: String, reference_ps: bool) {
    let s = source.trim_end_matches('/');
    let s = if s.is_empty() { "/" } else { s };
    let reference = if reference_ps { "Pod Security Standards (baseline): HostPath volumes" } else { "CIS Docker Benchmark: Ensure sensitive host system directories are not mounted on containers" };
    if s.ends_with("docker.sock") || s.ends_with("containerd.sock") || s.ends_with("crio.sock") {
        issue(out, "MOUNT-RUNTIME-SOCKET", "critical", "Container runtime socket mounted", location, format!("{source} gives the container control of the container runtime, which is root on the host."), "Do not mount the runtime socket; use a narrowly scoped API proxy if a tool really needs it.", if reference_ps { reference } else { "CIS Docker Benchmark: Ensure that the Docker socket is not mounted inside any containers" });
    } else if SENSITIVE_MOUNTS.contains(&s) || s.starts_with("/etc/") || s.starts_with("/proc/") || s.starts_with("/sys/") {
        issue(out, "MOUNT-SENSITIVE-HOST-PATH", "high", "Sensitive host directory mounted", location, format!("{source} from the host is mounted into the container, which can read or change the host through it."), "Mount only the application's own data directories, read-only where possible.", reference);
    } else if reference_ps {
        issue(out, "K8S-HOSTPATH", "medium", "Host path mounted", location, format!("{source} from the node is mounted into the pod; hostPath volumes are not allowed by the baseline policy."), "Use a persistent volume, ConfigMap, Secret or emptyDir instead of hostPath.", reference);
    }
}

pub fn compose(doc: &Value) -> Vec<Issue> {
    let mut out = Vec::new();
    let Some(services) = doc.get("services").and_then(Value::as_object) else { return out };
    for (name, svc) in services {
        let at = || format!("service {name}");
        if flag(svc.get("privileged")) {
            issue(&mut out, "CMP-PRIVILEGED", "high", "Privileged container", at(), "privileged: true gives the container all capabilities and the host's devices: it is effectively root on the host.".into(), "Remove privileged and add only the specific capabilities the service needs.", "CIS Docker Benchmark: Ensure that privileged containers are not used");
        }
        for (key, sev, what) in [("network_mode", "medium", "network"), ("pid", "high", "process"), ("ipc", "medium", "IPC"), ("userns_mode", "medium", "user")] {
            if svc.get(key).and_then(Value::as_str) == Some("host") {
                issue(&mut out, &format!("CMP-HOST-{}", key.to_ascii_uppercase()), sev, &format!("Shares the host's {what} namespace"), at(), format!("{key}: host removes the isolation of the host's {what} namespace from this container."), "Remove the setting; publish ports or share specific resources instead.", "CIS Docker Benchmark: Ensure that the host's namespaces are not shared");
            }
        }
        for v in svc.get("volumes").and_then(Value::as_array).into_iter().flatten() {
            let source = match v {
                Value::String(s) => s.split(':').next().unwrap_or("").to_string(),
                Value::Object(o) if o.get("type").and_then(Value::as_str).unwrap_or("bind") == "bind" => o.get("source").and_then(Value::as_str).unwrap_or("").to_string(),
                _ => String::new(),
            };
            if source.starts_with('/') {
                mount_issue(&mut out, &source, at(), false);
            }
        }
        for cap in strings(svc.get("cap_add")) {
            let c = cap.to_ascii_uppercase().trim_start_matches("CAP_").to_string();
            if RISKY_CAPS.contains(&c.as_str()) {
                issue(&mut out, "CMP-CAPABILITY", if c == "SYS_ADMIN" || c == "ALL" { "high" } else { "medium" }, &format!("Powerful capability added ({c})"), at(), format!("cap_add {c} grants kernel privileges that are commonly used to break out of containers."), "Drop the capability, or add only the narrow one the service needs.", "CIS Docker Benchmark: Ensure that Linux kernel capabilities are restricted within containers");
            }
        }
        for opt in strings(svc.get("security_opt")) {
            let o = opt.to_ascii_lowercase().replace('=', ":");
            if o == "seccomp:unconfined" || o == "apparmor:unconfined" || o == "label:disable" {
                issue(&mut out, "CMP-PROFILE-DISABLED", "high", "Kernel security profile turned off", at(), format!("security_opt {opt} removes a layer that limits what the container can ask of the kernel."), "Keep the default seccomp and AppArmor/SELinux profiles, or write a custom profile.", "CIS Docker Benchmark: Ensure that the default seccomp profile is not disabled");
            }
        }
        if svc.get("devices").and_then(Value::as_array).is_some_and(|d| !d.is_empty()) {
            issue(&mut out, "CMP-DEVICES", "medium", "Host devices passed in", at(), "devices gives the container direct access to host devices.".into(), "Pass only the devices the service needs, read-only where possible.", "CIS Docker Benchmark: Ensure that host devices are not directly exposed to containers");
        }
        let env: Vec<(String, String)> = match svc.get("environment") {
            Some(Value::Object(o)) => o.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| if v.is_null() { String::new() } else { v.to_string() }))).collect(),
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(|e| e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).unwrap_or((e.to_string(), String::new()))).collect(),
            _ => Vec::new(),
        };
        for (k, _) in env.into_iter().filter(|(k, v)| secret_name(k) && literal(v)) {
            issue(&mut out, "CMP-SECRET-ENV", "high", "Secret written into the Compose file", at(), format!("environment {k} has a literal value in the file, which ends up in version control and in docker inspect."), "Use Compose secrets, an env file kept out of version control, or ${VARIABLE} substitution.", "CIS Docker Benchmark: Ensure secrets are not stored in Dockerfiles");
        }
        for p in svc.get("ports").and_then(Value::as_array).into_iter().flatten() {
            let (host_ip, target) = match p {
                Value::String(s) => {
                    let parts: Vec<&str> = s.split(':').collect();
                    let target = parts.last().and_then(|t| t.split('/').next()).and_then(|t| t.split('-').next()).and_then(|t| t.parse::<u32>().ok());
                    (if parts.len() >= 3 { parts[0].trim_matches(['[', ']']).to_string() } else { String::new() }, if parts.len() >= 2 { target } else { None })
                }
                Value::Number(_) => (String::new(), None),
                Value::Object(o) => (o.get("host_ip").and_then(Value::as_str).unwrap_or("").to_string(), o.get("published").and(o.get("target")).and_then(|t| t.as_u64().map(|n| n as u32).or_else(|| t.as_str().and_then(|s| s.parse().ok())))),
                _ => (String::new(), None),
            };
            let all = host_ip.is_empty() || host_ip == "0.0.0.0" || host_ip == "::";
            if let (true, Some(t)) = (all, target) {
                if let Some((_, what)) = INTERNAL_PORTS.iter().find(|(port, _)| *port == t) {
                    issue(&mut out, "CMP-PORT-ALL-INTERFACES", if t == 2375 { "high" } else { "medium" }, &format!("{what} published on every interface"), at(), format!("Port {t} ({what}) is published without a host address, so it is reachable from every network the host is on."), "Bind it to 127.0.0.1 (\"127.0.0.1:port:port\"), or keep it on an internal network without publishing it.", "CIS Docker Benchmark: Ensure that incoming container traffic is bound to a specific host interface");
                }
            }
        }
        if svc.get("build").is_none() {
            if let Some(image) = svc.get("image").and_then(Value::as_str) {
                if let Some(why) = unpinned(image) {
                    issue(&mut out, "CMP-UNPINNED-IMAGE", "low", "Image not pinned", at(), format!("{image} {why}, so each pull can bring a different image."), "Pin a version tag or a digest.", "CIS Docker Benchmark: Ensure images are scanned and rebuilt to include security patches");
                }
            }
        }
        if let Some(u) = svc.get("user").and_then(|u| u.as_str().map(str::to_string).or_else(|| u.as_u64().map(|n| n.to_string()))) {
            if u == "root" || u == "0" || u.starts_with("0:") || u.starts_with("root:") {
                issue(&mut out, "CMP-ROOT-USER", "medium", "Runs as root", at(), format!("user: {u} runs the service as root inside the container."), "Run the service as an unprivileged user.", CIS_USER);
            }
        }
    }
    out
}

/* ───────────────────────────── Kubernetes ───────────────────────────── */

const BASELINE_CAPS: &[&str] = &["AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"];
const PSS_BASELINE: &str = "Pod Security Standards (baseline)";
const PSS_RESTRICTED: &str = "Pod Security Standards (restricted)";

/// The pod template of a workload, with the workload's label.
fn pod_spec<'a>(doc: &'a Value, kind: &str) -> Option<&'a Value> {
    match kind {
        "Pod" => doc.get("spec"),
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "ReplicationController" | "Job" => doc.pointer("/spec/template/spec"),
        "CronJob" => doc.pointer("/spec/jobTemplate/spec/template/spec"),
        _ => None,
    }
}

fn workload(out: &mut Vec<Issue>, label: &str, spec: &Value) {
    for (key, what) in [("hostNetwork", "network"), ("hostPID", "process"), ("hostIPC", "IPC")] {
        if flag(spec.get(key)) {
            issue(out, "K8S-HOST-NAMESPACE", "high", &format!("Shares the node's {what} namespace"), label.to_string(), format!("{key}: true lets the pod see and reach the node's {what} namespace."), &format!("Remove {key}."), &format!("{PSS_BASELINE}: Host Namespaces"));
        }
    }
    for v in spec.get("volumes").and_then(Value::as_array).into_iter().flatten() {
        if let Some(path) = v.pointer("/hostPath/path").and_then(Value::as_str) {
            mount_issue(out, path, format!("{label} › volume {}", v.get("name").and_then(Value::as_str).unwrap_or("?")), true);
        }
    }
    let pod_ctx = spec.get("securityContext");
    let pod_non_root = pod_ctx.and_then(|c| c.get("runAsNonRoot")).and_then(Value::as_bool);
    let pod_user = pod_ctx.and_then(|c| c.get("runAsUser")).and_then(Value::as_i64);
    let pod_seccomp = pod_ctx.and_then(|c| c.pointer("/seccompProfile/type")).and_then(Value::as_str);
    if !matches!(spec.get("automountServiceAccountToken"), Some(Value::Bool(false))) {
        issue(out, "K8S-SA-TOKEN", "info", "Service account token mounted", label.to_string(), "The pod gets an API token by default; if the workload never calls the Kubernetes API, an attacker in it still can.".into(), "Set automountServiceAccountToken: false unless the pod needs the API.", "Kubernetes documentation: service account tokens");
    }
    for group in ["initContainers", "containers", "ephemeralContainers"] {
        for c in spec.get(group).and_then(Value::as_array).into_iter().flatten() {
            let at = format!("{label} › container {}", c.get("name").and_then(Value::as_str).unwrap_or("?"));
            let ctx = c.get("securityContext");
            let get = |k: &str| ctx.and_then(|x| x.get(k));
            if flag(get("privileged")) {
                issue(out, "K8S-PRIVILEGED", "critical", "Privileged container", at.clone(), "privileged: true gives the container the node's devices and all capabilities: it is effectively root on the node.".into(), "Remove privileged and add only the specific capabilities needed.", &format!("{PSS_BASELINE}: Privileged Containers"));
            }
            let added: Vec<String> = ctx.and_then(|x| x.pointer("/capabilities/add")).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(|s| s.to_ascii_uppercase().trim_start_matches("CAP_").to_string()).collect();
            for cap in added.iter().filter(|c| !BASELINE_CAPS.contains(&c.as_str())) {
                issue(out, "K8S-CAPABILITY", if cap == "SYS_ADMIN" || cap == "ALL" { "high" } else { "medium" }, &format!("Capability beyond the baseline ({cap})"), at.clone(), format!("capabilities.add {cap} is not allowed by the baseline policy and widens what the container can do to the kernel."), "Remove the capability, or move the workload to a namespace where this exception is reviewed.", &format!("{PSS_BASELINE}: Capabilities"));
            }
            if ctx.and_then(|x| x.pointer("/capabilities/drop")).and_then(Value::as_array).is_none_or(|d| !d.iter().any(|x| x.as_str().is_some_and(|s| s.eq_ignore_ascii_case("ALL")))) {
                issue(out, "K8S-CAPS-NOT-DROPPED", "low", "Capabilities not dropped", at.clone(), "The restricted policy requires dropping ALL capabilities (NET_BIND_SERVICE may be added back).".into(), "Add capabilities: {drop: [ALL]} to the container's securityContext.", &format!("{PSS_RESTRICTED}: Capabilities"));
            }
            if get("procMount").and_then(Value::as_str) == Some("Unmasked") {
                issue(out, "K8S-PROC-MOUNT", "high", "Unmasked /proc", at.clone(), "procMount: Unmasked exposes kernel information that is normally hidden from containers.".into(), "Remove procMount or set it to Default.", &format!("{PSS_BASELINE}: /proc Mount Type"));
            }
            let seccomp = get("seccompProfile").and_then(|s| s.get("type")).and_then(Value::as_str).or(pod_seccomp);
            match seccomp {
                Some("Unconfined") => issue(out, "K8S-SECCOMP-UNCONFINED", "high", "Seccomp turned off", at.clone(), "seccompProfile Unconfined lets the container make any system call.".into(), "Use RuntimeDefault (or a Localhost profile).", &format!("{PSS_BASELINE}: Seccomp")),
                Some("RuntimeDefault") | Some("Localhost") => {}
                _ => issue(out, "K8S-SECCOMP-MISSING", "low", "No seccomp profile", at.clone(), "The restricted policy requires a seccomp profile; without one, the container may run unconfined.".into(), "Set seccompProfile: {type: RuntimeDefault} on the pod or container.", &format!("{PSS_RESTRICTED}: Seccomp")),
            }
            if !matches!(get("allowPrivilegeEscalation"), Some(Value::Bool(false))) {
                issue(out, "K8S-PRIVILEGE-ESCALATION", "medium", "Privilege escalation allowed", at.clone(), "allowPrivilegeEscalation is not false, so a process can gain more privileges than its parent (setuid binaries).".into(), "Set allowPrivilegeEscalation: false.", &format!("{PSS_RESTRICTED}: Privilege Escalation"));
            }
            let user = get("runAsUser").and_then(Value::as_i64).or(pod_user);
            let non_root = get("runAsNonRoot").and_then(Value::as_bool).or(pod_non_root);
            if user == Some(0) {
                issue(out, "K8S-RUN-AS-ROOT", "high", "Runs as root", at.clone(), "runAsUser: 0 runs the container as root.".into(), "Run as a non-zero UID and set runAsNonRoot: true.", &format!("{PSS_RESTRICTED}: Running as Non-root user"));
            } else if non_root != Some(true) {
                issue(out, "K8S-RUN-AS-ROOT", "medium", "May run as root", at.clone(), "runAsNonRoot is not true, so the container runs as root if its image does.".into(), "Set runAsNonRoot: true (and a non-zero runAsUser).", &format!("{PSS_RESTRICTED}: Running as Non-root"));
            }
            if !flag(get("readOnlyRootFilesystem")) {
                issue(out, "K8S-WRITABLE-ROOT", "low", "Writable root file system", at.clone(), "An attacker in the container can change its files and drop tools.".into(), "Set readOnlyRootFilesystem: true and mount emptyDir volumes where the application writes.", "Kubernetes security hardening (not part of the Pod Security Standards)");
            }
            for p in c.get("ports").and_then(Value::as_array).into_iter().flatten() {
                if p.get("hostPort").and_then(Value::as_u64).is_some_and(|n| n > 0) {
                    issue(out, "K8S-HOST-PORT", "medium", "Host port used", at.clone(), format!("hostPort {} opens the port on the node itself, outside Services and network policies.", p.get("hostPort").and_then(Value::as_u64).unwrap_or(0)), "Expose the port through a Service instead.", &format!("{PSS_BASELINE}: HostPorts"));
                }
            }
            if c.pointer("/resources/limits").and_then(Value::as_object).is_none_or(|l| l.is_empty()) {
                issue(out, "K8S-NO-LIMITS", "low", "No resource limits", at.clone(), "Without CPU and memory limits one container can starve the others on its node.".into(), "Set resources.limits (and requests).", "Kubernetes security hardening (not part of the Pod Security Standards)");
            }
            if let Some(image) = c.get("image").and_then(Value::as_str) {
                if let Some(why) = unpinned(image) {
                    issue(out, "K8S-UNPINNED-IMAGE", "medium", "Image not pinned", at.clone(), format!("{image} {why}: every node may run a different image."), "Use a version tag or a digest.", "Kubernetes documentation: container images");
                }
            }
            for e in c.get("env").and_then(Value::as_array).into_iter().flatten() {
                let name = e.get("name").and_then(Value::as_str).unwrap_or("");
                if secret_name(name) && e.get("value").and_then(Value::as_str).is_some_and(literal) {
                    issue(out, "K8S-SECRET-ENV", "high", "Secret written into the manifest", at.clone(), format!("env {name} has a literal value in the manifest, readable by anyone who can read the workload."), "Store it in a Secret and use valueFrom.secretKeyRef (or a mounted secret volume).", "Kubernetes documentation: good practices for Secrets");
                }
            }
        }
    }
}

/// The documents, with the items of a `List` (from `kubectl get -o yaml`) in place of the list.
fn flatten(docs: &[Value]) -> Vec<&Value> {
    let mut all: Vec<&Value> = Vec::new();
    for d in docs {
        if d.get("kind").and_then(Value::as_str) == Some("List") {
            all.extend(d.get("items").and_then(Value::as_array).into_iter().flatten());
        } else {
            all.push(d);
        }
    }
    all
}

/// Kubernetes manifests, with the bindings checked against the roles of the same documents (the
/// app goes through [`analyze`] and [`scan_path`]).
#[cfg(test)]
pub fn kubernetes(docs: &[Value]) -> Vec<Issue> {
    kubernetes_with(docs, true)
}

/// `bindings`: whether to check RoleBindings here (a folder scan checks them across files).
fn kubernetes_with(docs: &[Value], bindings: bool) -> Vec<Issue> {
    let mut out = Vec::new();
    let all = flatten(docs);
    if bindings {
        let objects: Vec<(usize, &Value)> = all.iter().filter(|d| rbac::is_rbac(d)).map(|d| (0, *d)).collect();
        out.extend(rbac::binding_issues(&objects).into_iter().map(|(_, i)| i));
    }
    for d in all {
        let kind = d.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = d.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("?");
        let label = match d.pointer("/metadata/namespace").and_then(Value::as_str) {
            Some(ns) => format!("{kind} {ns}/{name}"),
            None => format!("{kind} {name}"),
        };
        if let Some(spec) = pod_spec(d, kind) {
            workload(&mut out, &label, spec);
        }
        match kind {
            "Role" | "ClusterRole" => rbac::role_issues(&mut out, &label, d),
            "ClusterRoleBinding" | "RoleBinding" if d.pointer("/roleRef/name").and_then(Value::as_str) == Some("cluster-admin") => {
                let subjects: Vec<String> = d.get("subjects").and_then(Value::as_array).into_iter().flatten().map(|s| format!("{} {}", s.get("kind").and_then(Value::as_str).unwrap_or(""), s.get("name").and_then(Value::as_str).unwrap_or(""))).collect();
                let broad = subjects.iter().any(|s| s.contains("system:authenticated") || s.contains("system:unauthenticated") || s.starts_with("ServiceAccount"));
                issue(&mut out, "K8S-CLUSTER-ADMIN", if broad { "critical" } else { "high" }, "cluster-admin granted", label.clone(), format!("{kind} gives cluster-admin to {}.", subjects.join(", ")), "Grant a role with only the permissions needed; keep cluster-admin for break-glass accounts.", "Kubernetes documentation: RBAC good practices");
            }
            "Service" => {
                let ty = d.pointer("/spec/type").and_then(Value::as_str).unwrap_or("ClusterIP");
                if ty == "LoadBalancer" || ty == "NodePort" {
                    issue(&mut out, "K8S-EXPOSED-SERVICE", "info", &format!("Service exposed outside the cluster ({ty})"), label.clone(), "Check that this exposure is intended and that the service authenticates its clients.".into(), "Use ClusterIP with an ingress that enforces TLS and authentication, or restrict loadBalancerSourceRanges.", "Kubernetes documentation: Services");
                }
            }
            _ => {}
        }
    }
    out
}

/* ───────────────────────────── files ───────────────────────────── */

fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_ascii_lowercase()
}

fn dockerfile_name(name: &str) -> bool {
    name == "dockerfile" || name == "containerfile" || name.starts_with("dockerfile.") || name.ends_with(".dockerfile") || name.starts_with("containerfile.")
}

fn rank(s: &str) -> usize {
    ["critical", "high", "medium", "low", "info"].iter().position(|x| *x == s).unwrap_or(5)
}

/// Checks one file's text. `hint` is dockerfile, compose, kubernetes or auto. None when the file
/// is not a container configuration (only for auto).
pub fn analyze(file: &str, text: &str, hint: &str) -> Option<FileReport> {
    analyze_with(file, text, hint, true).map(|(report, _)| report)
}

/// [`analyze`], also returning a Kubernetes file's RBAC objects. `bindings`: whether to check the
/// bindings against the roles of this file alone.
fn analyze_with(file: &str, text: &str, hint: &str, bindings: bool) -> Option<(FileReport, Vec<Value>)> {
    let name = file_name(file);
    let body = text.trim_start_matches('\u{feff}');
    let looks_docker = body.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).is_some_and(|l| {
        let w = l.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
        w == "FROM" || w == "ARG"
    });
    let mut report = FileReport { file: file.to_string(), ..Default::default() };
    let mut rbac_objects = Vec::new();
    if hint == "dockerfile" || (hint == "auto" && (dockerfile_name(&name) || (looks_docker && !name.ends_with(".yml") && !name.ends_with(".yaml") && !name.ends_with(".json")))) {
        report.kind = "dockerfile".into();
        report.issues = dockerfile(body);
    } else {
        let docs = if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
            serde_json::from_str::<Value>(body).map(|v| vec![v]).map_err(|e| format!("not valid JSON: {e}"))
        } else {
            crate::yaml::parse_documents(body)
        };
        let docs = match docs {
            Ok(d) => d,
            Err(e) => {
                if hint == "auto" && !(body.contains("apiVersion") || body.contains("services")) {
                    return None;
                }
                report.kind = if hint == "auto" { "unknown".into() } else { hint.into() };
                report.error = if body.contains("{{") { format!("{e} (a Helm chart or other template must be rendered first, for example with helm template)") } else { e };
                return Some((report, Vec::new()));
            }
        };
        let k8s = docs.iter().any(|d| d.get("apiVersion").is_some() && d.get("kind").is_some());
        let compose_doc = docs.iter().find(|d| d.get("services").is_some_and(Value::is_object));
        if hint == "kubernetes" || (hint == "auto" && k8s) {
            report.kind = "kubernetes".into();
            report.issues = kubernetes_with(&docs, bindings);
            rbac_objects = flatten(&docs).into_iter().filter(|d| rbac::is_rbac(d)).cloned().collect();
        } else if hint == "compose" || (hint == "auto" && compose_doc.is_some()) {
            report.kind = "compose".into();
            report.issues = compose_doc.map(compose).unwrap_or_default();
        } else {
            return None;
        }
    }
    report.issues.sort_by_key(|i| rank(&i.severity));
    Some((report, rbac_objects))
}

/// Scans a file or a folder tree for container configurations (symbolic links are not followed).
/// RoleBindings are checked against the roles of every file, since a role and its binding are
/// often kept apart; their issues go to the binding's file.
pub fn scan_path(root: &Path) -> ScanResult {
    let mut res = ScanResult::default();
    let mut rbac_objects: Vec<(usize, Value)> = Vec::new();
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
        let candidate = dockerfile_name(&name) || name.ends_with(".yml") || name.ends_with(".yaml") || name.ends_with(".json") || p == root;
        if !candidate || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&p) else { continue };
        if bytes.iter().take(8192).any(|b| *b == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let shown = match p.strip_prefix(root).ok().filter(|r| !r.as_os_str().is_empty()) {
            Some(rel) => rel.to_string_lossy().replace('\\', "/"),
            // a single file: its name
            None => p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.to_string_lossy().to_string()),
        };
        if let Some((r, objects)) = analyze_with(&shown, &text, "auto", false) {
            let room = rbac::MAX_OBJECTS.saturating_sub(rbac_objects.len());
            rbac_objects.extend(objects.into_iter().take(room).map(|o| (res.files.len(), o)));
            res.files.push(r);
        }
    }
    let objects: Vec<(usize, &Value)> = rbac_objects.iter().map(|(i, o)| (*i, o)).collect();
    for (i, found) in rbac::binding_issues(&objects) {
        res.files[i].issues.push(found);
    }
    for f in &mut res.files {
        f.issues.sort_by_key(|i| rank(&i.severity));
    }
    res
}

#[cfg(test)]
#[path = "containers_tests.rs"]
mod tests;
