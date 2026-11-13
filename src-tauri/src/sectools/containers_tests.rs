// SPDX-License-Identifier: Apache-2.0
use super::*;

fn rules(issues: &[Issue]) -> Vec<&str> {
    issues.iter().map(|i| i.rule.as_str()).collect()
}

const BAD_DOCKERFILE: &str = r#"# build
FROM node
ARG API_TOKEN
ENV DB_PASSWORD=hunter2 MODE=prod
RUN apt-get update && \
    curl -fsSL https://get.example.com/install.sh | bash
RUN curl -k https://example.com/x.tgz -o /tmp/x.tgz && chmod -R 777 /app && sudo ls
ADD https://example.com/tool.bin /usr/local/bin/tool
ADD app.js /app/
EXPOSE 22 8080
CMD ["node", "/app/app.js"]
"#;

#[test]
fn an_insecure_dockerfile_is_reported_line_by_line() {
    let issues = dockerfile(BAD_DOCKERFILE);
    let r = rules(&issues);
    for rule in ["DF-UNPINNED-BASE", "DF-SECRET-ARG", "DF-SECRET-ENV", "DF-PIPE-TO-SHELL", "DF-TLS-DISABLED", "DF-WORLD-WRITABLE", "DF-SUDO", "DF-ADD-URL", "DF-ADD-NOT-COPY", "DF-SSH", "DF-ROOT", "DF-NO-HEALTHCHECK"] {
        assert!(r.contains(&rule), "{rule} in {r:?}");
    }
    let at = |rule: &str| issues.iter().find(|i| i.rule == rule).unwrap().location.clone();
    assert_eq!(at("DF-PIPE-TO-SHELL"), "line 5", "a continued instruction is reported at its first line");
    assert_eq!(at("DF-SECRET-ENV"), "line 4");
    assert_eq!(at("DF-ROOT"), "line 2");
    assert_eq!(issues.iter().filter(|i| i.rule == "DF-SECRET-ENV").count(), 1, "MODE is not a secret");
    assert_eq!(issues.iter().find(|i| i.rule == "DF-SECRET-ARG").unwrap().severity, "medium", "no default value");
}

#[test]
fn a_hardened_dockerfile_passes() {
    let good = "FROM node:20.11-alpine@sha256:0123abcd AS build\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nENV DB_PASSWORD=${DB_PASSWORD}\nUSER node\nHEALTHCHECK CMD wget -qO- http://localhost:8080/health || exit 1\nCMD [\"node\", \"server.js\"]\n";
    assert_eq!(dockerfile(good), vec![]);
    // the final stage inherits USER from the stage it is built from; stage names are not images
    let staged = "FROM golang:1.22 AS base\nUSER builder\nHEALTHCHECK NONE\nFROM base AS final\nCOPY --from=base /out /app\nHEALTHCHECK CMD [\"/app\", \"-check\"]\n";
    let r = rules(&dockerfile(staged)).into_iter().map(str::to_string).collect::<Vec<_>>();
    assert!(!r.contains(&"DF-ROOT".to_string()) && !r.contains(&"DF-UNPINNED-BASE".to_string()), "{r:?}");
    let distroless = "FROM golang:1.22 AS build\nRUN go build -o /out ./...\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /out /app\n";
    assert!(!rules(&dockerfile(distroless)).contains(&"DF-ROOT"), "distroless nonroot images set their own user");
    assert!(rules(&dockerfile("FROM alpine:3.20\nUSER root\nHEALTHCHECK CMD true\n")).contains(&"DF-ROOT"));
}

const COMPOSE: &str = r#"
x-base: &base
  privileged: true
services:
  web:
    <<: *base
    image: nginx:latest
    network_mode: host
    pid: host
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host/etc:ro
      - ./site:/usr/share/nginx/html
    cap_add: [SYS_ADMIN, NET_BIND_SERVICE]
    security_opt: ["seccomp:unconfined"]
    devices: ["/dev/sda:/dev/sda"]
    environment:
      DB_PASSWORD: hunter2
      API_URL: https://api.example.com
  db:
    image: postgres:16.2
    ports: ["5432:5432", "127.0.0.1:6379:6379"]
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
  docker:
    build: .
    ports:
      - target: 2375
        published: 2375
"#;

#[test]
fn compose_files_are_checked_per_service() {
    let doc = crate::yaml::parse_one(COMPOSE).unwrap();
    let issues = compose(&doc);
    let web: Vec<&str> = issues.iter().filter(|i| i.location == "service web").map(|i| i.rule.as_str()).collect();
    for rule in ["CMP-PRIVILEGED", "CMP-HOST-NETWORK_MODE", "CMP-HOST-PID", "MOUNT-RUNTIME-SOCKET", "MOUNT-SENSITIVE-HOST-PATH", "CMP-CAPABILITY", "CMP-PROFILE-DISABLED", "CMP-DEVICES", "CMP-SECRET-ENV", "CMP-UNPINNED-IMAGE", "CMP-ROOT-USER"] {
        assert!(web.contains(&rule), "{rule} in {web:?}");
    }
    assert_eq!(issues.iter().filter(|i| i.rule == "CMP-CAPABILITY").count(), 1, "NET_BIND_SERVICE is fine");
    assert_eq!(issues.iter().find(|i| i.rule == "MOUNT-RUNTIME-SOCKET").unwrap().severity, "critical");
    let db: Vec<&Issue> = issues.iter().filter(|i| i.location == "service db").collect();
    assert_eq!(db.len(), 1, "only PostgreSQL on every interface; Redis is bound to localhost and the password is a variable: {db:?}");
    assert!(db[0].title.contains("PostgreSQL"));
    let docker = issues.iter().find(|i| i.location == "service docker").unwrap();
    assert_eq!((docker.rule.as_str(), docker.severity.as_str()), ("CMP-PORT-ALL-INTERFACES", "high"), "the Docker API without TLS");
}

const K8S: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: sock
          hostPath: {path: /var/run/docker.sock}
        - name: data
          hostPath: {path: /srv/data}
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
            capabilities: {add: [NET_ADMIN]}
          ports: [{containerPort: 80, hostPort: 80}]
          env:
            - {name: DB_PASSWORD, value: hunter2}
            - name: API_KEY
              valueFrom: {secretKeyRef: {name: api, key: key}}
---
apiVersion: v1
kind: Pod
metadata: {name: hardened}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: registry.example.com/app:1.4.2
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources: {limits: {cpu: 500m, memory: 256Mi}}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: report}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          securityContext: {runAsUser: 0}
          containers: [{name: job, image: "busybox:1.36"}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: open}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:authenticated", apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec: {type: LoadBalancer, ports: [{port: 80}]}
"#;

#[test]
fn kubernetes_manifests_follow_the_pod_security_standards() {
    let docs = crate::yaml::parse_documents(K8S).unwrap();
    let issues = kubernetes(&docs);
    let web: Vec<&str> = issues.iter().filter(|i| i.location.starts_with("Deployment shop/web")).map(|i| i.rule.as_str()).collect();
    for rule in ["K8S-HOST-NAMESPACE", "MOUNT-RUNTIME-SOCKET", "K8S-HOSTPATH", "K8S-PRIVILEGED", "K8S-CAPABILITY", "K8S-HOST-PORT", "K8S-SECRET-ENV", "K8S-UNPINNED-IMAGE", "K8S-NO-LIMITS", "K8S-RUN-AS-ROOT", "K8S-PRIVILEGE-ESCALATION", "K8S-SECCOMP-MISSING"] {
        assert!(web.contains(&rule), "{rule} in {web:?}");
    }
    assert_eq!(issues.iter().filter(|i| i.rule == "K8S-SECRET-ENV").count(), 1, "secretKeyRef is the right way");
    assert!(issues.iter().any(|i| i.location == "Deployment shop/web › container app" && i.rule == "K8S-PRIVILEGED" && i.severity == "critical"));
    let hardened: Vec<&Issue> = issues.iter().filter(|i| i.location.starts_with("Pod hardened")).collect();
    assert!(hardened.is_empty(), "a pod that meets the restricted policy has no issues: {hardened:?}");
    let cron = issues.iter().find(|i| i.location.starts_with("CronJob report") && i.rule == "K8S-RUN-AS-ROOT").unwrap();
    assert_eq!(cron.severity, "high", "runAsUser 0 from the pod's security context");
    assert!(rules(&issues).contains(&"K8S-RBAC-WILDCARD"));
    assert_eq!(issues.iter().find(|i| i.rule == "K8S-CLUSTER-ADMIN").unwrap().severity, "critical");
    assert!(rules(&issues).contains(&"K8S-EXPOSED-SERVICE"));
    // a List from kubectl get -o json is read item by item
    let list = serde_json::json!({"apiVersion": "v1", "kind": "List", "items": [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": {"hostPID": true, "containers": [{"name": "c", "image": "x:1"}]}}]});
    assert!(kubernetes(&[list]).iter().any(|i| i.rule == "K8S-HOST-NAMESPACE"));
}

#[test]
fn files_are_recognised_by_name_and_content() {
    assert_eq!(analyze("svc/Dockerfile.prod", "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n", "auto").unwrap().kind, "dockerfile");
    assert_eq!(analyze("pasted", "# comment\nFROM alpine:3.20\n", "auto").unwrap().kind, "dockerfile");
    assert_eq!(analyze("deploy.yaml", K8S, "auto").unwrap().kind, "kubernetes");
    assert_eq!(analyze("docker-compose.yml", COMPOSE, "auto").unwrap().kind, "compose");
    assert!(analyze(".github/workflows/ci.yml", "name: CI\non: [push]\njobs: {}\n", "auto").is_none(), "other YAML is not a container configuration");
    let helm = analyze("templates/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }\n  labels: [\n", "auto").unwrap();
    assert!(helm.error.contains("helm template"), "{}", helm.error);
    let forced = analyze("x.txt", "services:\n  a: {privileged: true}\n", "compose").unwrap();
    assert_eq!((forced.kind.as_str(), forced.issues.len()), ("compose", 1));
    // issues come most severe first
    let r = analyze("Dockerfile", BAD_DOCKERFILE, "auto").unwrap();
    assert!(r.issues.windows(2).all(|w| rank(&w[0].severity) <= rank(&w[1].severity)));
}

#[test]
fn folders_are_scanned_without_vendored_trees() {
    let dir = std::env::temp_dir().join(format!("cyberhub-containers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("k8s")).unwrap();
    std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
    std::fs::write(dir.join("Dockerfile"), BAD_DOCKERFILE).unwrap();
    std::fs::write(dir.join("docker-compose.yml"), COMPOSE).unwrap();
    std::fs::write(dir.join("k8s/deploy.yaml"), K8S).unwrap();
    std::fs::write(dir.join("node_modules/pkg/Dockerfile"), "FROM node\n").unwrap();
    std::fs::write(dir.join("notes.yml"), "title: not a container file\n").unwrap();
    let res = scan_path(&dir);
    let files: Vec<&str> = res.files.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(files, vec!["Dockerfile", "docker-compose.yml", "k8s/deploy.yaml"]);
    assert_eq!(res.files_seen, 4, "node_modules is not entered");
    assert!(!res.truncated);
    let single = scan_path(&dir.join("Dockerfile"));
    assert_eq!(single.files.len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

const ESCALATOR: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: escalator}
rules:
- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [escalate, bind]}
- {apiGroups: [""], resources: [users, groups], verbs: [impersonate]}
- {apiGroups: [""], resources: [nodes/proxy], verbs: [get]}
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests/approval], verbs: [update]}
- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create]}
- {apiGroups: [admissionregistration.k8s.io], resources: [mutatingwebhookconfigurations], verbs: [patch]}
- {apiGroups: [""], resources: [persistentvolumes], verbs: [create]}
- {apiGroups: [apps], resources: [deployments], verbs: [create]}
- {apiGroups: [""], resources: ["*/exec"], verbs: [create]}
- {apiGroups: [""], resources: [namespaces], verbs: [patch]}
- {apiGroups: [""], resources: [secrets], verbs: [list]}
- {apiGroups: [""], resources: [secrets], verbs: [watch]}
"#;

#[test]
fn rbac_rules_that_lead_to_more_privileges_are_named() {
    let docs = crate::yaml::parse_documents(ESCALATOR).unwrap();
    let issues = kubernetes(&docs);
    let mut found: Vec<&str> = rules(&issues);
    found.sort_unstable();
    let mut want = vec![
        "K8S-RBAC-BIND",
        "K8S-RBAC-CSR-APPROVE",
        "K8S-RBAC-ESCALATE",
        "K8S-RBAC-EXEC",
        "K8S-RBAC-IMPERSONATE",
        "K8S-RBAC-NAMESPACE",
        "K8S-RBAC-NODES-PROXY",
        "K8S-RBAC-PV-CREATE",
        "K8S-RBAC-SECRETS",
        "K8S-RBAC-TOKEN",
        "K8S-RBAC-WEBHOOKS",
        "K8S-RBAC-WORKLOADS",
    ];
    want.sort_unstable();
    assert_eq!(found, want, "one issue per kind of danger, */exec included");
    assert!(issues.iter().all(|i| i.location == "ClusterRole escalator"));
    assert_eq!(issues[0].severity, "high", "sorted, most severe first");

    let narrow = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: shop}
rules:
- {apiGroups: [""], resources: [configmaps, pods, pods/log], verbs: [get, list, watch]}
- {apiGroups: [""], resources: [secrets], resourceNames: [app-tls], verbs: [get]}
- {apiGroups: [example.com], resources: [pods], verbs: [create]}
- {nonResourceURLs: ["/healthz"], verbs: [get]}
"#;
    let none = kubernetes(&crate::yaml::parse_documents(narrow).unwrap());
    assert!(none.is_empty(), "read-only rules, one named Secret and another API group's pods: {none:?}");

    let wild = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: wild}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: pods-all, namespace: shop}
rules: [{apiGroups: [""], resources: [pods], verbs: ["*"]}]
"#;
    let w = kubernetes(&crate::yaml::parse_documents(wild).unwrap());
    let got: Vec<(&str, &str, &str)> = w.iter().map(|i| (i.location.as_str(), i.rule.as_str(), i.severity.as_str())).collect();
    assert_eq!(got, vec![("ClusterRole wild", "K8S-RBAC-WILDCARD", "critical"), ("Role shop/pods-all", "K8S-RBAC-WILDCARD", "high")]);
}

const BINDINGS: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: all-service-accounts}
roleRef: {kind: ClusterRole, name: escalator, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:serviceaccounts", apiGroup: rbac.authorization.k8s.io}, {kind: User, name: alice}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ci-edit, namespace: shop}
roleRef: {kind: ClusterRole, name: edit, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: default, namespace: shop}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: anon-read}
roleRef: {kind: ClusterRole, name: reader-cluster, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:unauthenticated", apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: "system:public-info-viewer"}
roleRef: {kind: ClusterRole, name: "system:public-info-viewer", apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:unauthenticated", apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: everyone-views, namespace: shop}
roleRef: {kind: ClusterRole, name: view, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:authenticated", apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: deployer, namespace: shop}
rules: [{apiGroups: [apps], resources: [deployments], verbs: [create, update]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: shop-accounts-deploy, namespace: shop}
roleRef: {kind: Role, name: deployer, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:serviceaccounts:shop", apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admins}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:authenticated", apiGroup: rbac.authorization.k8s.io}]
"#;

#[test]
fn bindings_that_reach_many_identities_are_reported() {
    let text = format!("{ESCALATOR}---\n{BINDINGS}");
    let issues = kubernetes(&crate::yaml::parse_documents(&text).unwrap());
    let binding = |loc: &str| issues.iter().filter(|i| i.location == loc && i.rule != "K8S-CLUSTER-ADMIN").map(|i| (i.rule.as_str(), i.severity.as_str())).collect::<Vec<_>>();
    let detail = |loc: &str| issues.iter().find(|i| i.location == loc).map(|i| i.detail.clone()).unwrap_or_default();
    assert_eq!(binding("ClusterRoleBinding all-service-accounts"), vec![("K8S-RBAC-BROAD", "critical")], "alice alone would not be reported");
    let d = detail("ClusterRoleBinding all-service-accounts");
    assert!(d.contains("across the cluster") && d.contains("grant permissions they do not hold (escalate)") && !d.contains("alice"), "{d}");
    assert_eq!(binding("RoleBinding shop/ci-edit"), vec![("K8S-RBAC-DEFAULT-SA", "high")], "the built-in edit role reads Secrets and impersonates service accounts");
    let edit = detail("RoleBinding shop/ci-edit");
    assert!(edit.contains("service account shop/default in namespace shop") && edit.contains("impersonate service accounts;"), "{edit}");
    assert_eq!(binding("ClusterRoleBinding anon-read"), vec![("K8S-RBAC-ANONYMOUS", "high")]);
    assert!(detail("ClusterRoleBinding anon-read").contains("not in the scanned files"));
    assert!(binding("ClusterRoleBinding system:public-info-viewer").is_empty(), "the API server's own bindings are left alone");
    assert!(binding("RoleBinding shop/everyone-views").is_empty(), "view grants nothing dangerous");
    assert_eq!(binding("RoleBinding shop/shop-accounts-deploy"), vec![("K8S-RBAC-BROAD", "high")], "a namespaced Role is found in the binding's namespace");
    assert!(binding("ClusterRoleBinding admins").is_empty(), "cluster-admin is reported once, by K8S-CLUSTER-ADMIN");
    assert_eq!(issues.iter().filter(|i| i.rule == "K8S-CLUSTER-ADMIN").count(), 1);
}

#[test]
fn folder_scans_match_bindings_to_roles_in_other_files() {
    let dir = std::env::temp_dir().join(format!("cyberhub-rbac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rbac")).unwrap();
    std::fs::write(dir.join("rbac/role.yaml"), ESCALATOR).unwrap();
    let binding = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: all-service-accounts}
roleRef: {kind: ClusterRole, name: escalator, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:serviceaccounts", apiGroup: rbac.authorization.k8s.io}]
"#;
    std::fs::write(dir.join("rbac/binding.yaml"), binding).unwrap();
    let res = scan_path(&dir);
    let of = |name: &str| res.files.iter().find(|f| f.file == name).unwrap();
    assert_eq!(rules(&of("rbac/binding.yaml").issues), vec!["K8S-RBAC-BROAD"], "found through the role in role.yaml, reported once");
    assert_eq!(of("rbac/binding.yaml").issues[0].severity, "critical");
    assert!(!rules(&of("rbac/role.yaml").issues).contains(&"K8S-RBAC-BROAD"));
    assert_eq!(of("rbac/role.yaml").issues.len(), 12);
    // the binding file alone: the role is unknown, and only anonymous access would be reported
    assert!(analyze("binding.yaml", binding, "auto").unwrap().issues.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}
