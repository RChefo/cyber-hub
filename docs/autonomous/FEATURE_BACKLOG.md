# Feature backlog

The evidence is in [../research/CYBER_HUB_MARKET_RESEARCH.md](../research/CYBER_HUB_MARKET_RESEARCH.md).

## Scoring model

Each criterion is rated from 1 to 5, where 5 is best:

| Criterion | Meaning | Weight |
|---|---|---|
| D | demand (strength and independence of the evidence) | 3 |
| W | workflow impact | 2 |
| F | fit with Cyber Hub and reuse of existing infrastructure | 2 |
| R | security risk; 5 = low risk | 1 |
| C | implementation and maintenance cost; 5 = cheap | 1 |
| T | testability | 1 |

**Score = 3D + 2W + 2F + R + C + T**, with a maximum of 50.

Deferred or rejected items say why.

## Prioritized backlog

| # | Feature | D | W | F | R | C | T | Score | Status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Scanner-output import with dedup, scope check, evidence link | 5 | 5 | 5 | 4 | 3 | 5 | 47 | **Done** (`b51615a`) |
| 2 | Finding templates: library; apply when recording; save a finding as a template; apply to matching imported findings | 5 | 5 | 4 | 5 | 4 | 5 | 47 | **Done** (`95c8eac`) |
| 3 | Fix verification by rescan: findings of earlier imports not reported again on covered hosts | 3 | 4 | 5 | 4 | 4 | 5 | 40 | **Done** (`0e201f5`) |
| 4 | CVSS 3.1 and 4.0 calculator on findings: vector, score, suggested severity | 4 | 3 | 4 | 5 | 3 | 5 | 39 | **Done** (`edad2bf`) |
| 5 | IOC extraction, defang and refang utility; STIX 2.1 export of project indicators | 3 | 3 | 4 | 5 | 4 | 5 | 37 | **Done** (`38599a1`) |
| 6 | OpenVAS / Greenbone XML import | 3 | 3 | 5 | 4 | 3 | 5 | 37 | **Done** (`99fe5ed`) |
| 7 | Findings export: CSV and JSON | 2 | 3 | 5 | 5 | 5 | 5 | 37 | **Done** (`0337e18`) |
| 8 | Bulk edit of tags and assignee on findings | 2 | 3 | 5 | 5 | 5 | 5 | 37 | **Done** (`0337e18`) |
| 9 | Methodology checklists (OWASP WSTG) with coverage per project | 3 | 4 | 3 | 5 | 3 | 4 | 35 | **Done** (`9c4ee92`) |
| 13 | More import formats (competitor trackers: CSV mapping, Qualys, Nmap greppable) | 3 | 3 | 5 | 4 | 3 | 5 | 38 | **Done** for CSV with a column mapping (`53dac93`), which covers Qualys, Nessus and Greenbone CSV exports and spreadsheets |
| 14 | MCP access to the new features (CVSS, library, checklist) | 2 | 3 | 5 | 4 | 4 | 5 | 34 | **Done** (`aaa7d0a`) |
| 10 | Notes on assets and vulnerabilities | 3 | 3 | 3 | 5 | 3 | 4 | 33 | Deferred: finding history notes and project notes cover part of it |
| 11 | Path-level scope rules | 4 | 3 | 3 | 3 | 2 | 4 | 33 | **Done** (`80f34de`, review fixes `8355745`): URL entries authorize paths only, never hosts; redirects rechecked per hop; schema 19 keeps old URL exclusions at host level |
| 12 | User-facing database backup and restore | 2 | 3 | 4 | 3 | 3 | 4 | 30 | **Done**: on-demand checked backup (`4a320a8`); restore in the app with a restart-time swap that keeps the previous database and its evidence (`2eb4209`) |
| 15 | Evidence integrity: verify stored files and text, checked exports | 3 | 3 | 5 | 5 | 4 | 5 | 39 | **Done** (`aa4d17d`) |
| 16 | Cross-module reference integrity (assets, runs, OSINT, timeline, reports) | 3 | 4 | 5 | 4 | 3 | 5 | 40 | **Done** (`96fe970`, `d26f799`, `ce76bfa`) |
| 17 | Vulnerability records from imported CVEs | 3 | 3 | 4 | 4 | 3 | 4 | 35 | **Done**: optional at import, linked to the finding and its asset, no network during the import |
| — | Jira or ticketing integration | 2 | 2 | 1 | 3 | 2 | 2 | — | Rejected: needs external accounts and credentials, and does not fit local-first |
| — | Collaborative or multi-user editing | 2 | 2 | 1 | 2 | 1 | 2 | — | Rejected: needs server infrastructure |

## Second research round (2026-11-09): new capability areas

The owner named six areas; none existed in Cyber Hub (code search: no API definition import, request history, SBOM, container configuration, packet capture or log parsing, and no SARIF export). Evidence, without invented figures:

* **API security.** The OWASP API Security Top 10 (2023) is the reference list of API risks. OpenAPI is the standard description format, and browsers' developer tools and proxies (Burp Suite, OWASP ZAP) export HAR, the usual starting point when no definition exists.
* **Repeater.** Burp Suite's Repeater and ZAP's request editor are core manual-testing workflows: edit a raw request, resend it, compare responses. Cyber Hub's request builder sends one request and keeps nothing.
* **SBOM.** US Executive Order 14028 and the NTIA minimum elements made SBOMs a delivery requirement; CycloneDX (ECMA-424) and SPDX (ISO/IEC 5962) are the formats, and OSV.dev offers an open vulnerability database queried by package URL.
* **Container and Kubernetes configuration.** The Kubernetes Pod Security Standards and the CIS Docker and Kubernetes benchmarks define the checks; tools such as hadolint, kube-linter and Checkov show the demand.
* **Packet captures and logs.** Wireshark and Zeek are the standard tools; an engagement workstation needs a quick offline triage tied to the project (hosts, names, cleartext credentials, attack patterns), not a replacement for them.
* **Interoperability.** SARIF 2.1.0 is an OASIS standard that code-scanning platforms such as GitHub ingest.

| # | Feature | D | W | F | R | C | T | Score | Status |
|---|---|---|---|---|---|---|---|---|---|
| 18 | API inventory from OpenAPI, Swagger, Postman and HAR, with OWASP API Top 10 (2023) checks, a test plan and scope per endpoint | 5 | 4 | 5 | 5 | 3 | 5 | 46 | **Done** (this round) |
| 19 | Repeater: raw requests, history, resend and response comparison in the HTTP request builder | 4 | 4 | 5 | 4 | 4 | 4 | 42 | **Done** (this round) |
| 20 | SBOM analysis: CycloneDX and SPDX components, known vulnerabilities from OSV, license risks | 5 | 4 | 4 | 4 | 3 | 5 | 43 | **Done** (this round) |
| 21 | Container and Kubernetes configuration checks (Dockerfile, Compose, manifests) | 4 | 3 | 4 | 5 | 3 | 5 | 39 | **Done** (this round) |
| 22 | Packet capture triage (pcap, pcapng): hosts, DNS, HTTP, TLS server names, cleartext credentials | 3 | 3 | 4 | 4 | 2 | 4 | 33 | **Done** (this round) |
| 23 | Log triage: web access and SSH authentication logs (attack patterns, brute force) | 3 | 3 | 4 | 5 | 3 | 5 | 36 | **Done** (this round) |
| 24 | SARIF 2.1.0 export of findings | 3 | 3 | 5 | 5 | 5 | 5 | 40 | **Done** (this round) |

## Third research round (2026-11-09): depth in the named areas

With items 18 to 24 done, the next gaps were looked for inside the same six areas rather than in new ones.

* **Kubernetes RBAC.** The container checks covered wildcards, Secrets and cluster-admin only. The Kubernetes documentation ("Role Based Access Control Good Practices") lists further privilege-escalation paths: escalate, bind, impersonate, nodes/proxy, CSR approval, token requests, admission webhooks, PersistentVolume and workload creation, namespace changes. Dedicated tools (rbac-tool, KubiScan) show that people need to know who receives such rights; a role and its binding are usually kept in separate files.
* **SARIF round trip.** Cyber Hub's SARIF import ignored `suppressions`, so results dismissed in another tool (or exported from Cyber Hub as false positives) came back as new findings.

| # | Feature | D | W | F | R | C | T | Score | Status |
|---|---|---|---|---|---|---|---|---|---|
| 25 | Kubernetes RBAC escalation paths, with bindings resolved across files and the built-in roles | 4 | 3 | 5 | 5 | 4 | 5 | 42 | **Done** (this round) |
| 26 | SARIF import skips suppressed results | 3 | 3 | 5 | 5 | 5 | 5 | 40 | **Done** (`d776c58`) |

## Mission 2 (2026-11-09T16:31Z): research and ranking

### What exists, checked in the code

Security Utilities has 26 tools (including the JWT inspector with `alg: none` and lifetime checks, the HTTP header analyzer, container and RBAC checks, packet capture and log triage for web and SSH logs). Projects have 16 tabs (scope, attack surface, APIs, components, vulnerabilities, findings, the WSTG checklist, analysis, assistant, automation, timeline, evidence, report, notes, commands). A code search found **none** of the following: Windows event logs (EVTX), cloud infrastructure as code (Terraform, CloudFormation), IAM policy analysis, dependency lockfiles, PE or ELF analysis, OWASP ASVS, OAuth or OIDC configuration review, ATT&CK technique mapping, persistence artifacts. `imphash` and `yara` appear only as fields of abuse.ch lookups.

### Sources and findings

Numbers are GitHub stars and crates.io downloads read through their APIs on 2026-11-09.

* **Windows event logs.** Chainsaw (WithSecure, Rust, 3,714 stars), Hayabusa (Yamato Security, 3,447) and DeepBlueCLI (SANS, 2,444) exist because responders need a fast first pass over EVTX files before a SIEM is available ([Chainsaw](https://labs.withsecure.com/tools/chainsaw), [SANS ISC diary 2022-09-19](https://isc.sans.edu/diary.html?date=2022-09-19), [Black Hills: Hayabusa and SOF-ELK](https://www.blackhillsinfosec.com/wrangling-windows-event-logs-with-hayabusa-sof-elk-part-2/)). Chainsaw is built on the `evtx` crate (Apache-2.0, 345,872 downloads). Cyber Hub's log triage reads web and SSH logs only.
* **Infrastructure as code.** Checkov (9,146 stars), tfsec (7,061) and KICS (2,731) check Terraform and CloudFormation before deployment; practitioner guides name public S3 buckets, open security groups and missing encryption as the core findings ([HackerOne: AWS security configuration review](https://www.hackerone.com/blog/aws-security-configuration-review-and-best-practices)). Cyber Hub checks containers and Kubernetes, not cloud resources. The `hcl-rs` crate (MIT/Apache-2.0, 3.4 million downloads) parses HCL.
* **IAM policies.** Rhino Security Labs catalogued the IAM privilege-escalation methods (iam:CreatePolicyVersion, iam:PassRole with ec2:RunInstances or lambda:CreateFunction, and others) ([research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), [catalog](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation)); Cloudsplaining (2,260 stars), PMapper (1,591), Parliament (1,127) and Pacu's `iam__privesc_scan` show the need to find them in policies.
* **Dependency lockfiles.** OSV-Scanner (Google, 11,470 stars) reads lockfiles (package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, poetry.lock, uv.lock, composer.lock, Gemfile.lock, go.mod and others) and checks them against OSV ([supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles)). Cyber Hub's SBOM analysis already queries OSV, but only for SBOM files, which many projects do not produce.
* **Static binary triage.** Detect It Easy (11,924 stars) and capa (Mandiant, 6,313) answer "what is this file and what can it do" without running it; the `goblin` crate (MIT, 87 million downloads) parses PE, ELF and Mach-O. Cyber Hub can hash a file and look it up (VirusTotal, abuse.ch) but cannot look inside it.
* **Verification standards.** OWASP ASVS 5.0.0 (May 2025; 3,773 stars; CC BY-SA 4.0) is published with CSV and JSON requirement lists ([OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)). Cyber Hub has the WSTG checklist only.
* **OAuth.** RFC 9700 (BCP 240, January 2025) says the implicit and the resource owner password grants must not be used and recommends the authorization code grant with PKCE ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)).
* **Linux artifacts.** The Unix-like Artifacts Collector (UAC, 1,509 stars) collects the files a responder reads for persistence (cron, systemd units, authorized_keys, shell profiles); reading them is manual.
* A Reddit search for practitioner threads on cloud reviews returned mostly vendor blogs; it is not counted as evidence.

### Scoring model for this mission

Each criterion is rated from 1 to 5, where 5 is best: D demand (×3), U professional usefulness (×2), N novelty compared with Cyber Hub (×2), I integration with projects, findings, evidence and reports (×2), F feasibility (×1), R security risk, 5 = low (×1), T testability (×1), M maintenance cost, 5 = cheap (×1). **Score = 3D + 2U + 2N + 2I + F + R + T + M**, at most 65.

| # | Candidate | D | U | N | I | F | R | T | M | Score | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 27 | Dependency lockfiles into the SBOM analysis (npm, pnpm, yarn, Cargo, Python, Composer, Ruby, Go, NuGet), with the OSV check | 5 | 5 | 4 | 5 | 4 | 5 | 5 | 4 | 61 | **Done** (Mission 2) |
| 28 | Windows event log (EVTX) triage with ATT&CK-mapped detections | 5 | 5 | 5 | 4 | 4 | 4 | 4 | 4 | 59 | **Done** (Mission 2) |
| 29 | AWS IAM policy analysis: privilege escalation, wildcards, public and cross-account access | 4 | 5 | 5 | 4 | 5 | 5 | 5 | 4 | 59 | **Done** (Mission 2) |
| 30 | Infrastructure-as-code checks: Terraform (HCL and plan JSON) and CloudFormation | 5 | 5 | 5 | 5 | 3 | 4 | 4 | 3 | 59 | **Done** (Mission 2) |
| 31 | Static PE and ELF triage: imports as capabilities, sections and entropy, strings and indicators | 4 | 4 | 5 | 4 | 4 | 4 | 4 | 4 | 54 | **Done** (Mission 2) |
| 32 | Prowler results (OCSF JSON) import | 4 | 4 | 4 | 5 | 4 | 5 | 4 | 3 | 54 | **Done** (Mission 2) |
| 33 | OWASP ASVS 5.0 checklist next to WSTG | 4 | 4 | 4 | 5 | 3 | 5 | 4 | 3 | 53 | Candidate |
| 34 | API definition comparison: new, removed and changed endpoints, lost authentication | 3 | 4 | 4 | 4 | 5 | 5 | 5 | 5 | 53 | **Done** (Mission 2) |
| 35 | Linux persistence triage from collected files | 3 | 4 | 5 | 4 | 4 | 5 | 5 | 4 | 53 | **Done** (Mission 2) |
| 36 | OAuth 2.0 and OpenID Connect configuration review (RFC 9700) | 3 | 4 | 5 | 3 | 5 | 5 | 5 | 4 | 52 | **Done** (Mission 2) |
| 37 | SBOM comparison between versions | 3 | 3 | 4 | 4 | 5 | 5 | 5 | 5 | 51 | Candidate |
| 38 | ATT&CK technique view and Navigator layer per project | 3 | 4 | 4 | 5 | 3 | 5 | 4 | 3 | 50 | Candidate |
| 39 | Request collections, variables and authentication profiles in the repeater | 4 | 4 | 4 | 4 | 2 | 4 | 3 | 3 | 48 | Deferred: large interface work for the gain |
| 40 | YARA matching | 4 | 4 | 5 | 4 | 1 | 3 | 4 | 2 | 48 | Deferred: the Rust engine (yara-x) brings a WebAssembly runtime; libyara needs a C toolchain |

