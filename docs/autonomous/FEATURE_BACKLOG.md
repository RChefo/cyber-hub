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
| 33 | OWASP ASVS 5.0 checklist next to WSTG | 4 | 4 | 4 | 5 | 3 | 5 | 4 | 3 | 53 | **Done** in Mission 4 as 43 (`8150748`) |
| 34 | API definition comparison: new, removed and changed endpoints, lost authentication | 3 | 4 | 4 | 4 | 5 | 5 | 5 | 5 | 53 | **Done** (Mission 2) |
| 35 | Linux persistence triage from collected files | 3 | 4 | 5 | 4 | 4 | 5 | 5 | 4 | 53 | **Done** (Mission 2) |
| 36 | OAuth 2.0 and OpenID Connect configuration review (RFC 9700) | 3 | 4 | 5 | 3 | 5 | 5 | 5 | 4 | 52 | **Done** (Mission 2) |
| 37 | SBOM comparison between versions | 3 | 3 | 4 | 4 | 5 | 5 | 5 | 5 | 51 | **Done** (Mission 2) |
| 38 | ATT&CK technique view and Navigator layer per project | 3 | 4 | 4 | 5 | 3 | 5 | 4 | 3 | 50 | **Done** in part (Mission 2): Navigator layer export of the listed findings; no matrix view inside Cyber Hub |
| 39 | Request collections, variables and authentication profiles in the repeater | 4 | 4 | 4 | 4 | 2 | 4 | 3 | 3 | 48 | Deferred: large interface work for the gain |
| 40 | YARA matching | 4 | 4 | 5 | 4 | 1 | 3 | 4 | 2 | 48 | **Done** in Mission 4 as 42 (`4fa4a1a`): boreal, a YARA engine in Rust without JIT or C, removed the obstacle |


## Mission 3 (2026-11-09T20:10Z): the integration layer

The brief's sections and what was built for each. "Done" means implemented, tested and checked in the real app.

| Brief | Requirement | Status |
|---|---|---|
| §2, §5 | One model of relationships between records with provenance (observed, imported, derived, inferred, analyst, suggested), explainable suggestions, accept, reject, dismiss, mark reviewed, link and unlink by hand, decision history | **Done** (`7b1a842`) |
| §3 | Correlation rules for file, API, cloud and supply-chain investigations: hashes, URLs and hosts, CVEs, package URLs, API paths, OSINT entities, shared evidence, duplicates | **Done** (`7b1a842`); cloud audits correlate through their findings and assets |
| §4 | Investigation workspace: review queue, relationships, record panel, graph, ATT&CK, timeline, evidence, reports | **Done** (`7b1a842`, `e3eeeca`) |
| §6 | Evidence provenance and integrity: module, record, tool and version, collection time, derived records, verification state; original files kept | **Done** (`7b1a842`, `24258c2`, `f08a6bb`) |
| §7 | Timeline filters (type, record, text, dates), day grouping, record navigation, CSV and JSON export, collection time apart from event time | **Done** (`7b1a842`); severity is not a timeline attribute |
| §8 | Graph on the OSINT engine: neighbourhood, shortest path, filters (origin, kind, confidence, pending and rejected, date), export with provenance | **Done** (`7b1a842`) |
| §9 | Playbooks with progress, cancellation, time limits, retry, history, evidence and confirmations, on built-in steps only | **Done** (`6dc7f63`) |
| §10 | ATT&CK matrix: findings' techniques, assessments, layers with gaps, import and export, version tracking | **Done** (`e3eeeca`) |
| §11 | Findings across modules: duplicates (correlation rule), related findings (record panel), remediation groups with rescan verification | **Done** (`7b1a842`, `ab4a9db`); cross-project search through the palette and MCP |
| §12 | MCP and assistant on retrieved data; suggestions labelled; approval for writes; nothing sent without the existing confirmation | **Done** (`f0ab1d5`) |
| §13 | Global search across projects and techniques, archived projects only on request | **Done** (`7b1a842`, `3c761db`) |
| §14 | A finding recorded from a utility is persisted with project, source and severity, linked to its evidence, on the timeline and in the investigation, and exported in reports | **Done** (`24258c2`, `f08a6bb`) |
| §15 | Tests: correlation, wrong relationships, duplicates, provenance, integrity, timeline, deletion and archival, cancellation, migration, project isolation, MCP permissions, scale, concurrency | **Done**; see the commits' tests |

### Deferred, with reasons

* **A graph across projects.** Projects are the unit of authorization and scope; a cross-project graph needs its own rules for what may be shown together.
* **Correlation by interpretation** (the same actor behind several hosts, renamed packages, redirects). Rules stay exact so every suggestion can be explained by matched values.
* **OWASP ASVS 5.0 checklist** (candidate 33 of Mission 2). Still not started.

## Mission 4 (2026-11-09T23:21Z): detection engineering, threat hunting and compliance

### Sources consulted during the mission

Every source below was read during this mission, through a fetch, a search or a public API call. Repository numbers are from GitHub's API on 2026-11-09 (stars, forks, last push, licence).

* **Sigma.** SigmaHQ's rules specification (v2.1.0, 2025-08-02) and its modifier appendix, read from the `sigma-specification` repository: the rule format, the condition grammar, and the modifier semantics the engine follows (`detection/sigma.rs`). Repository signals:

  | Repository | Stars | Forks | Last push | Licence |
  |---|---|---|---|---|
  | SigmaHQ/sigma | 11,452 | 2,931 | 2026-11-09 | Detection Rule License |
  | SigmaHQ/pySigma | 606 | 163 | 2026-11-09 | LGPL-2.1 |
  | SigmaHQ/sigma-cli | 221 | 55 | 2026-10-28 | LGPL-2.1 |
  | wagga40/Zircolite (Sigma on EVTX, JSON) | 875 | 121 | 2026-11-02 | |
  | Yamato-Security/hayabusa (Sigma-based EVTX triage) | 3,448 | 305 | 2026-11-09 | AGPL-3.0 |

  The base64offset offsets and the Windows log-source mappings follow pySigma's behaviour as known before this mission; its code was not fetched again.
* **YARA.** The YARA documentation ("Writing YARA rules") for the language. Repository signals:

  | Repository | Stars | Forks | Last push | Licence |
  |---|---|---|---|---|
  | VirusTotal/yara | 10,016 | 1,595 | 2026-10-27 | BSD-3-Clause |
  | VirusTotal/yara-x | 1,358 | 163 | 2026-11-09 | BSD-3-Clause |
  | Neo23x0/signature-base | 3,064 | 683 | 2026-11-06 | Detection Rule License |
  | YARAHQ/yara-forge | 353 | 37 | 2026-11-08 | GPL-3.0 |

  * **boreal (chosen engine):** checked on crates.io (1.4.0 of 2026-10-16, MIT OR Apache-2.0, MSRV 1.85, 67,577 downloads with 17,872 recent, regular releases) and in its README (claims compatibility with YARA 4.5.5 and protection against untrusted rules and inputs).
  * **boreal's documentation (docs.rs):** `CompilerParams` (`disable_includes`, condition depth, strings per rule), `ScanParams` (timeout, matches per string, match length), `Compiler` and `Scanner`.
  * **boreal's code:** its source was read before use. There is no build script; its file reads are only for includes and `scan_file`, neither used; the memory-map and process scanners are behind features left off; its `unsafe` blocks were reviewed.
* **YARA compatibility corpora** (downloaded for local tests only, not bundled): Neo23x0's signature-base (753 rule files) and Yara-Rules/rules (566).
* **ASVS.** OWASP ASVS 5.0.0's GitHub release (`v5.0.0_release`) through the API and its assets. The official JSON is bundled unmodified (SHA-256 recorded in THIRD_PARTY_NOTICES.md), under CC BY-SA 4.0. OWASP/ASVS: 3,773 stars, 851 forks, last push 2026-11-04. The 5.0.0 JSON maps no requirement to CWE or NIST, so mappings are the analyst's.
* **ATT&CK.** mitre-attack/attack-navigator: 2,506 stars, last push 2026-11-04. The bundled Enterprise 20.1 catalog (Mission 3) supplied revocations such as T1070.001 → T1685.005.
* **Test data reused from Mission 2:** EVTX-ATTACK-SAMPLES files for the Sigma tests on real logs.
* **Known without a fetch in this mission**, and named as such:
  * the STIX 2.1 indicator properties (`confidence`, `valid_until` later than `valid_from`, `revoked`);
  * the Admiralty source-reliability scale;
  * the beacon and DNS-tunnel heuristics, which are Cyber Hub's own, documented with their thresholds in docs/UTILITIES.md.
* **Not counted as evidence:** WithSecureLabs/chainsaw and mitre/d3fend-ontology returned no data from the API.

### Candidates and ranking

The Mission 2 scoring model: D demand (×3), U professional usefulness (×2), N novelty for Cyber Hub (×2), I integration (×2), F feasibility, R security risk (5 = low), T testability, M maintenance; maximum 65. Demand for 44 to 52 is the brief's own request and the practice it names, not a measured signal, so D stays at 3 or below for them.

| # | Candidate | D | U | N | I | F | R | T | M | Score | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 41 | Sigma detection engineering: library, validation, versions, collections, tests with expectations, project runs, explanations, ATT&CK coverage | 5 | 5 | 5 | 5 | 3 | 4 | 5 | 3 | 60 | **Done** (`e4a3987`) |
| 42 | YARA rules for files: library, tests on file samples, project runs, File Triage scan | 5 | 5 | 5 | 5 | 3 | 3 | 4 | 3 | 58 | **Done** (`4fa4a1a`) |
| 43 | OWASP ASVS 5.0 assessments: levels, statuses only the analyst sets, evidence and finding links, history, analyst mappings, report | 4 | 4 | 4 | 5 | 4 | 5 | 5 | 4 | 56 | **Done** (`8150748`) |
| 44 | Network hunting leads in captures: beacon-like timing, DNS tunneling, TXT volume, generated domains | 3 | 4 | 4 | 4 | 5 | 5 | 5 | 5 | 53 | **Done** (`ef862c3`) |
| 45 | Indicator lifecycle: source and reliability, confidence, validity, revoked and false positive, history, STIX fields | 3 | 4 | 4 | 4 | 5 | 5 | 5 | 5 | 53 | **Done** (`d8c8cbb`) |
| 46 | MCP tools for detections, hits and ASVS, with approvals | 3 | 4 | 3 | 5 | 5 | 4 | 5 | 4 | 51 | **Done** (`285e439`) |
| 47 | Risk acceptance records and exceptions for findings (justification, approver, expiry) | 3 | 4 | 3 | 5 | 3 | 5 | 4 | 3 | 48 | Deferred: every path that sets a finding's status (editor, bulk change, MCP, imports, reports) would have to require and show the record |
| 48 | Host hunting analytics beyond rules (process chains, logon anomalies, Linux authentication) | 3 | 4 | 3 | 4 | 2 | 5 | 3 | 3 | 44 | Partly covered by Sigma rules on logs and the existing EVTX, Linux and SSH triage; dedicated analytics deferred |
| 49 | Sigma correlation rules and aggregations (counts and time windows) | 3 | 4 | 4 | 4 | 2 | 4 | 3 | 2 | 44 | Deferred: needs a time-window engine; refused with the reason today |
| 50 | Assessment comparison and remediation metrics | 3 | 3 | 3 | 4 | 3 | 5 | 4 | 3 | 44 | Deferred |
| 51 | TAXII 2.1 feeds and indicator import | 3 | 3 | 4 | 3 | 2 | 2 | 3 | 2 | 38 | Deferred: network feeds need their own confirmation and provenance design |
| 52 | ATT&CK Mobile and ICS matrices | 2 | 2 | 3 | 2 | 2 | 5 | 3 | 2 | 32 | Deferred: the brief asks for proper data and tests first |

## Mission 5 (2026-11-10T10:14Z): hardening, Linux compatibility and feature completion

The brief set the order itself: Linux first, then parser security, database migrations, Sigma, risk acceptance, TAXII, compliance, ATT&CK and performance. No new ranking was made; the table records where the open Mission 4 items and the brief's new work ended.

### Sources consulted during the mission

* **Sigma correlation rules specification v2.1.0 (2025-08-02)**, read from SigmaHQ's `sigma-specification` repository:
  * the six correlation types;
  * `rules`, `group-by`, `timespan`, `condition`, field `aliases` and `generate`;
  * chaining, and the rule that only the outermost correlation carries metadata.

  `value_percentile` is listed but its percentile is not defined, so Cyber Hub refuses it.
* **TAXII 2.1, OASIS Standard (10 June 2021)**:
  * the media type and Accept header;
  * discovery, API roots and collections;
  * the objects endpoint with `added_after`, `next` and `limit`;
  * the `X-TAXII-Date-Added-First` and `-Last` headers;
  * the HTTPS requirement.

  The copy that was read was truncated: the conformance section and "Add Objects" were not visible. Cyber Hub only reads from servers, so it does not use "Add Objects".
* **Known without a fetch in this mission**, and named as such: STIX 2.1 indicator patterning, beyond the equality comparisons that are imported; and the ATT&CK Navigator layer format, already implemented in Mission 3.

### Status

| # | Item | Status |
|---|---|---|
| 47 | Risk acceptance records and exceptions | **Done** (`e6869ed`). Every path that sets *accepted risk* (status menus, the editor, bulk changes, imports, internal services) requires a covering record. MCP can only read the register |
| 48 | Host hunting analytics beyond rules | Deferred. It was not in the Mission 5 brief; Sigma rules, now with correlations, cover counted and ordered logon patterns |
| 49 | Sigma correlation rules and aggregations | **Done** (`0c8084f`, fixed in `91b064a`): all types except `value_percentile`, which is refused with the reason |
| 50 | Assessment comparison and remediation metrics | **Done for ASVS** (`e6869ed`): gaps by chapter with exceptions and the remediation state of linked findings, compliant requirements without evidence, and comparison of two assessments |
| 51 | TAXII 2.1 feeds and indicator import | **Done** (`3573c2f`). Only on request, each connection confirmed, indicators only, never findings |
| 52 | ATT&CK Mobile and ICS matrices | Deferred: no official Mobile or ICS data is bundled, and the brief forbids them without it |
| 53 | ATT&CK technique history and comparison of technique sets, with coverage snapshots | **Done** (`24045f0`) |
| 54 | Parser hardening: review of every untrusted-input parser, a hostile-input sweep, fuzzing | **Done** (`6acf43e`, `3336d6b`). Smaller amplifications remain open (SECURITY.md, "Parser safety") |
| 55 | Upgrade validation from every schema version, with failures and kills | **Done** (`ff3e5f5`) |
| 56 | CI: pinned toolchains and actions, clippy, Debian 12, audits, secret scanning | **Done** (`7206810`). Not run on GitHub, because the repository has not been pushed |
| 57 | TAXII credentials entered in the app, not only provisioned | Deferred. Credentials are stored only with `cyberhub-keys taxii-set`, so the web view never handles them |
| 58 | A cloud-resource asset type for cloud findings | Deferred. The cloud workflow used a domain asset (MISSION_REPORT.md, "Mission 5") |

## Mission 6 (2026-11-10T14:05Z): product completion and release readiness

The brief named the work itself (parser performance, WSTG exceptions, TAXII credentials, ATT&CK Mobile and ICS, host hunting, cloud resources, a real MCP client, Linux desktops, CI and release, an integration review, regression and documentation). No new ranking was made; the table records where each item ended.

### Sources consulted during the mission

* **MITRE ATT&CK STIX data**, release 20.1, from the `mitre-attack/attack-stix-data` repository: `mobile-attack-20.1.json` and `ics-attack-20.1.json` retrieved 2026-11-10 (SHA-256 beginning `632e2ec40848394f` and `3f6448369f9135ad`); `enterprise-attack-20.1.json` (retrieved 2026-11-09) was fetched again and matched (`539a843a7b53ed97…`). Licence: the ATT&CK Terms of Use (THIRD_PARTY_NOTICES.md).
* **ATT&CK Navigator layer format 4.5** (the `domain` and `versions` fields), already implemented in Mission 3.
* **rmcp 3.9.0 source** (`service.rs`): a `notifications/cancelled` cancels the request's token and drops its answer, but stops nothing the handler does not watch. This is how the MCP cancellation gap was found.
* **Claude Code 2.1.319** as a genuine MCP client: its tool timeout (`MCP_TOOL_TIMEOUT`) sends `notifications/cancelled`, and its stream-json input keeps one session over several turns.
* **Known without a fetch in this mission**, and named as such: the Win32 credential UI (`CredUIPromptForWindowsCredentialsW`, `CredPackAuthenticationBufferW`, `CredUnPackAuthenticationBufferW`), GTK 3 dialogs, Windows logon types (4624), the OCSF 1.x Detection Finding fields that Prowler writes, and GitHub Actions' pinning and permissions model. The action SHAs were checked with `git ls-remote`.
* **EVTX-ATTACK-SAMPLES**, the public sample corpus already used in Mission 2, for the process-chain patterns.

### Status

| # | Item | Status |
|---|---|---|
| 48 | Host hunting analytics beyond rules | **Done for Windows event logs** (`b5c845d`, `05500c5`): process chains (six patterns) and logons per account. Linux chains deferred (item 64) |
| 52 | ATT&CK Mobile and ICS matrices | **Done** (`020ad01`, `92100da`) from the official 20.1 data |
| 54 | The smaller parser amplifications | **Done** (`1f64034`): host duplication in Nessus, Burp and OpenVAS, SARIF, OCSF, OSINT evidence IDs, CSP matching and five more |
| 57 | TAXII credentials entered in the app | **Done** (`2eb6185`, `bfa6107`): typed into a native OS dialog, never into the web view. Typing into Windows' dialog could not be automated (item 66) |
| 58 | A cloud-resource asset type | **Done** (`d0e706e`, `1a93038`) |
| 59 | Exceptions for failed WSTG tests, and acceptances in reports | **Done** (`c270a1e`, `c8b0bdc`, `2a60d9f`) |
| 60 | A pinned release workflow that publishes only on explicit conditions | **Done** (`9d89831`). Never run on GitHub |
| 61 | MCP: client cancellations reach the app; credentials masked in results | **Done** (`ea60e88`, `57d3c48`), found with Claude Code |
| 62 | Per-matrix counts in the ATT&CK switch (review finding 11) | Deferred: needs counts per domain from the backend; small |
| 63 | One "record as findings" bar for a log's detections and chains (review finding 15) | Deferred: small, no data at risk |
| 64 | Process chains from Linux audit logs | Deferred: auditd records name a parent's process ID but not its program, so a parent started before the log cannot be recognised |
| 65 | GNOME Shell and Plasma sessions, desktop portals, a GPU, a physical HiDPI screen | Not tested: containers ran the compositors (Mutter, KWin) without the shells; needs a VM or hardware |
| 66 | Typing into Windows' credential dialog | Manual check: the dialog runs at a higher integrity level, which blocks synthetic input (MISSION_REPORT.md, "Mission 6") |
| 67 | A smaller minimum window size for scaled screens | Open: the minimum (1100 × 700 logical pixels) is larger than a 1920 × 1080 screen at 150 % or 200 % scaling (found in the HiDPI run). The layout below that width needs design and testing first |

## Mission 7 (2026-11-10): final hardening and release preparation

The brief named the work: high-DPI and the minimum window, Linux desktops, the Windows TAXII credential dialog, the two deferred usability items and a product-wide usability review, a full security review, release-workflow validation, regression, performance, upgrade safety, a manual release checklist and documentation. No new capability was ranked.

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 62 | Per-matrix counts in the ATT&CK switch | **Done** (`a18c157`), with state words in the cells |
| 63 | One "record as findings" bar for a log's detections and chains | **Done** (`b135d5b`) |
| 65 | GNOME Shell and Plasma sessions, portals, a GPU, a physical HiDPI screen | **Partly**: KWin with XWayland now works in the containers (Xwayland's glamor crashed on the GPU-less output; software rendering works). HiDPI and the minimum window were checked on virtual screens. The full sessions, portals, a login keyring and a physical screen are on the release checklist (`docs/release/RELEASE_READINESS.md`, M2–M7) |
| 66 | Typing into Windows' credential dialog | **Procedure written** (`docs/release/TAXII_CREDENTIAL_TEST.md`, `1e5d4dd`); needs a person (release checklist M1) |
| 67 | A smaller minimum window size for scaled screens | **Done** (`e9b5da1`): 800 × 480, sized to the monitor's work area |

### Deferred from the Mission 7 usability review

Each is larger than a focused fix, and none puts data at risk.

| # | Item | Why deferred |
|---|---|---|
| 68 | Back navigation (a route stack, a Back control, Alt+Left), and work that survives a pivot (the IOC extractor's text, a triage result) | Needs a navigation model across all pages |
| 69 | Sightings and exposure-path nodes that open their records and look indicators up | Each record kind needs its target; the types already carry `refKind` and `refId` |
| 70 | "Open" lands on the record itself (asset, evidence, vulnerability, API, component, ATT&CK technique), Open for OSINT entities, the linked project in an OSINT investigation | A focus parameter per tab, as findings already have |
| 71 | A run's project and outputs on the Runs page, and project run rows that open the run | A `run` route parameter and related-records links |
| 72 | Selecting a graph node by keyboard | Graph interaction design |
| 73 | Project tabs in workflow order, and triage tools named where they are found | Information architecture; affects every project |
| 74 | Global search for OSINT investigations, detection rules and saved indicators, its errors shown, and activity items that open their records | Search index and navigation targets |
| 75 | Arabic and right-to-left layout | Not supported: strings are not externalized (no i18n library) and about 150 places use left/right utilities |

### Recorded as limitations (SECURITY.md)

* Process starts without a native dialog (GUI tools, a terminal, version probes) and a project's status changed by a compromised page: accepted risks.
* Copied command lines are exact in POSIX shells; in PowerShell a word with a quote character arrives split. A platform-specific copy would need the history to keep the argument list.

## Mission 8 (2026-11-11): release validation and final readiness

The brief named release-validation work, not features: the manual tests (M1–M7), the first GitHub run (M8), signing (M9), the release-candidate procedure (M10), the accepted risks, the final regression and the release documents. No feature was added.

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 65 | GNOME Shell and Plasma sessions, portals, a GPU, a physical HiDPI screen | **Procedures written** (`docs/release/MANUAL_VALIDATION.md`, M2–M7). There was no such environment here: the VMs on this machine are Kali Linux (Xfce) and an inaccessible entry, and the screens run at 100 %. So these items are owner tasks |
| 66 | Typing into Windows' credential dialog | **Partly automated.** Everything but the dialog ran on Windows with the real Credential Manager, 16/16. Steps 2, 3 and 9 of `TAXII_CREDENTIAL_TEST.md` need a person |

### Accepted risks reviewed

| Risk | Outcome |
|---|---|
| GUI tools and a terminal start without a native dialog | **Fixed** (`fb1f323`): both ask first |
| Version probes start without a dialog | **Still accepted.** Fixed catalog flags; the ProjectDiscovery tools probe with `-duc`, so nothing is contacted; a test keeps the flag |
| A compromised page reopens an ended project | **Fixed** (`d3c654f`): reopening asks natively, with a compare-and-set |
| Copied commands in PowerShell | **Narrowed** (`8fe5ab5`): a word with a quote and nothing else special is double-quoted and arrives whole |

### Deferred, with reasons

| # | Item | Why deferred |
|---|---|---|
| 76 | Exact PowerShell copies of every word: keep the argument list with the command history and offer a copy per shell | Needs a schema change (migration 33) for the stored argument list. That is not a change for a release-validation mission; the remaining case (a quote with `$`, a backtick, `"`, `\` or `!`) is rare and runs nothing else |
| 77 | The real-window layout probe in the repository | **Done once, outside the repository**: a variant of `scripts/qa/layout-probe.mjs` measured the real window at 800 × 480 on Windows, 37/37. Adding it to `scripts/qa` (an option to skip emulation) is small; M5 does not block |
| 78 | A portal check in a container (`xdg-desktop-portal` with `GTK_USE_PORTAL=1`) | Would only be a substitute for M6, which does not block unsandboxed packages |
| 79 | Build provenance attestations for release artifacts (`actions/attest-build-provenance`) | Needs `id-token` and `attestations` permissions and a run on GitHub to test; recommended after the first release |

## Mission 9 (2026-11-11): autonomous end-to-end release execution

The brief authorized the repository, CI, VMs, signing with existing credentials, and the release-candidate build and its tests. No feature was added. Three defects found in real desktop sessions were fixed.

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 65 | GNOME Shell and Plasma sessions, portals, a physical HiDPI screen | **Sessions done** in disposable VMs: GNOME 46 and Plasma 5.27, Wayland, X11 and XWayland, with the development build (`docs/release/MANUAL_VALIDATION.md`, "Mission 9"). A physical HiDPI screen is still missing |
| 66 | Typing into Windows' credential dialog | **Still manual.** The Windows 11 VM hung in Windows Setup under VirtualBox with Hyper-V. A host-keyboard M1 run is prepared for Windows Sandbox |
| 78 | A portal check | **Done in real sessions:** GNOME (Wayland, Xorg) and Plasma Wayland, with `dbus-monitor` evidence |

### Fixed in Mission 9

| # | Item | Commit |
|---|---|---|
| 80 | Checking whether a credential exists unlocked the keyring and, for the TAXII list, held the database | `63d2cd6` |
| 81 | An interrupted restore left a copy of the backup in the data folder | `ed99331` |
| 82 | The command palette ranked pages above a project whose name starts with the query | `810e024` |
| 83 | Data folders at earlier schemas for the installer upgrade test (`write_upgrade_fixtures`) | `5ad2ad1` |

### Open, with reasons

| # | Item | Why open |
|---|---|---|
| 84 | Store the update-signing secrets in the `release` environment | The owner's step: the assistant session may not write secrets |
| 85 | An Authenticode certificate and its CI signing and verification | A purchase and an identity validation (`SIGNING_SETUP.md`) |
| 86 | Plasma with KWallet serving the Secret Service | Needs KWallet's interactive first-run setup; the GNOME Keyring of the Debian test VM did not serve its login collection |
| 87 | The desktop harness of Mission 9 (VM agent, AT-SPI helper, `qa-desktop.mjs`) in `scripts/qa/` | It lives in `E:\CyberHubQA\desk`. Worth adding with a short guide once the candidate exists, so the package tests can reuse it |
| 88 | Two GitHub Actions runs that never started | The next push ran normally. Check the account's usage only if it recurs |
| 89 | Third-party GitHub Apps with access to all repositories | An account setting: limit them to the repositories that need them |

## Mission 10 (2026-11-11 and 12): release-candidate completion

The brief asked for the remaining blockers to be resolved, and for the candidate to be built, validated and drafted privately once the signing prerequisites were in place. They were not in place, so no candidate was built. No feature was added and no code changed; the tests found no defect in Cyber Hub.

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 65 | A physical HiDPI screen | **Still open.** Virtual scaling at 100, 125, 150 and 200 % passes on GNOME Wayland and Windows 11 (`docs/release/MANUAL_VALIDATION.md`, "Mission 10") |
| 66 | Typing into Windows' credential dialog | **Done:** M1, 17/17, in a disposable Windows 11 VM, typed through the VM's keyboard |
| 84 | Store the update-signing secrets in the `release` environment | **Half done:** the key is stored (2026-11-11 22:13Z). The password is the owner's step: the session's permission classifier refused the command |
| 85 | An Authenticode certificate and its CI signing and verification | **Open.** The comparison now covers SmartScreen, identity, renewal and cost (`SIGNING_SETUP.md`). Nothing was bought |
| 86 | Plasma with KWallet serving the Secret Service | **Done:** M7 steps 1–7 pass on Plasma X11 with KWallet, and with GNOME Keyring |
| 87 | The desktop harness in `scripts/qa/` | **Open**, now with the Windows harness too (item 93) |
| 89 | Third-party GitHub Apps with access to all repositories | **Open.** Their permissions are recorded in `GITHUB_FIRST_RUN.md`, "Mission 10" |

### Open, with reasons

| # | Item | Why open |
|---|---|---|
| 90 | A switch that lets the release workflow build a draft candidate without also allowing publication | The build job runs only while `RELEASE_PUBLISHING` is `enabled`, the same variable that allows publishing. A run still stops at a draft unless *draft* is unchecked and the tag is typed again, but a separate switch would let the owner authorize a candidate alone. The owner's call |
| 91 | Sharper text at fractional scales on GNOME | GTK 3, and so WebKitGTK 4.1, has whole-number scales only: at 125 and 150 % the page renders at 2 and Mutter scales it down. Only a GTK 4 WebKitGTK would change that. A physical screen should judge whether it matters (M4) |
| 92 | Windows: another program can size the window below its minimum | `SetWindowPos` from another process is not limited by the minimum tracking size, which Windows applies to sizing by the user (a corner drag stops at 800 × 480 at every scale). It could be enforced in `WM_WINDOWPOSCHANGING`, which tao does not handle. No user action produces it; low priority |
| 93 | The Windows harness (M1 typing, the early-click checker, the HiDPI driver) | It lives in `E:\CyberHubQA\win-share` and `desk`. Add it with item 87 |
| 94 | Dependabot alert: `minimatch` 10.2.6 in `website/` (GHSA-g3hv-75wg-m249, medium, a denial of service through glob patterns) | It comes with the website's ESLint and typescript-eslint, development only, and is not part of the app. npm's suggested fix downgrades both a major version. Update them once they depend on `minimatch` 11.0.1 or later, or override `minimatch` after checking ESLint still works. The other Dependabot alert, `glib` below 0.20, is the unsound iterator already allowed in cargo audit and named in the release notes (Tauri's GTK 3 stack) |

## Mission 10, continued (2026-11-12): the release candidate

The owner authorized the password secret and the draft builds. The candidate was built and is a private draft (MISSION_REPORT.md, "Mission 10, continued"). Its tests found two release-pipeline defects, both fixed, and three issues recorded below.

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 84 | Store the update-signing secrets in the `release` environment | **Done.** The password was stored at 13:47:49Z, without the byte-order mark that broke the first copy, and the builds sign with both secrets |
| 85 | An Authenticode certificate and its CI signing and verification | **Open, now the main blocker for Windows.** SmartScreen ("Unknown publisher") and the MSI's UAC prompt ("unknown publisher") were seen on the candidate |
| 87, 93 | The QA harnesses in the repository | **Open.** Mission 10 added a CDP driver for installed Windows builds, UI Automation clicks, and Linux package and AppImage sequences. Gaps it hit: GTK's and Windows' "replace it?" prompts, Plasma's screen lock, Debian's `x-terminal-emulator`, and long lines typed into Win+R |
| 90 | A switch that builds a draft without allowing publication | **Open.** The owner allowed `RELEASE_PUBLISHING` for the draft runs; the variable was set only during each run |

### Fixed

| What | Commit |
|---|---|
| The update manifest refused 0.1.0's release notes (25,720 characters; the app shows 20,000), so the first complete run uploaded nothing. `generate` now shortens notes at a paragraph and links the full notes on the release page; `validate` still enforces the limit | `598b1f9` |
| The documented password command stored a UTF-8 byte-order mark in front of the password when the console used UTF-8 | `add894e` |

### New

| # | Item | Why open |
|---|---|---|
| 95 | **Cyber Hub refuses to start without CA certificates** | `VtState::new()` and `TiState::new()` build reqwest clients during setup. On a system with no CA certificates (bare Ubuntu 24.04 and Debian 12 containers, `--no-install-recommends`), `build()` fails and the start-up error says only "builder error"; with `ca-certificates` it starts. Desktops have the certificates. Fix: build those clients when first used (or start and report the network features as unavailable), name the cause in the message, and declare `ca-certificates` in the deb and rpm (`bundle.linux.deb.depends`). Low; decide before publishing |
| 96 | **The MSI installs into the NSIS folder after an NSIS install was removed** | The NSIS uninstaller leaves `HKCU\Software\cyberhub\Cyber Hub` (`(Default)` is the install folder). Tauri's MSI template reads that key to follow an NSIS install, so the per-machine MSI went to `C:\Users\<user>\AppData\Local\Cyber Hub\`. Options: clean the key in the NSIS uninstaller (a template hook), or document it. An MSI on a machine that never had the NSIS version was not tested |
| 97 | **Windows lists the publisher as "cyberhub"** | No `bundle.publisher` is set, so Tauri derives it from the identifier. Set it, for example to the certificate's subject, when Authenticode is added |
| 98 | **Test an update end to end after publication** | The feed is `releases/latest` of the repository. Before publication every package correctly reports that no update manifest is published. Check 0.1.0 against the published feed, then a 0.1.1 update signed with the same key |

## Mission 11 (2026-11-12): final release hardening and the second release candidate

The CA-certificate start-up and the MSI folder are fixed, the publisher name is decided (kept), the release workflow builds release candidates under their own tags, and the HiDPI audit found and fixed two front-end defects. Details: MISSION_REPORT.md, "Mission 11".

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 95 | Start-up without CA certificates | **Done** (`1c98af4`). The two start-up clients are built on first use (`tls_trust::LazyClient`), every client is built through `tls_trust::build`, and a client that cannot be built says that no CA certificates were found and what to install. Verification is unchanged: no client exists, so nothing is sent. A failure is not remembered, so installing the certificates is enough. Checked on bare Ubuntu 24.04 and Debian 12 images without `ca-certificates`, and in GUI containers with the certificates hidden and given back. **Not done, on purpose:** declaring `ca-certificates` as a package dependency. Cyber Hub is local-first, and a hard dependency would make an offline `apt install ./…deb` fail on a minimal system; every desktop installs the package, and the message names it |
| 96 | The MSI installs into the NSIS folder after an NSIS uninstall | **Done** (`1aed064`). An `NSIS_HOOK_POSTUNINSTALL` hook deletes the folder value after a real uninstall; an update keeps it. Tested in the Windows 11 VM: the MSI now goes to Program Files. **Limit:** a machine whose earlier copy was removed by an older uninstaller (only the first candidate, in QA VMs) keeps the stale value until the next NSIS uninstall |
| 97 | Windows lists the publisher as "cyberhub" | **Decided: unchanged for 0.1.0.** The value is part of the NSIS install identity (`HKCU\Software\<publisher>\Cyber Hub` holds the folder that the next installer reads), so changing it breaks a manual NSIS upgrade from a build with the old value: the reinstall page cannot find the old copy's folder. The exe's CompanyName, the NSIS Publisher and the MSI Manufacturer all say "cyberhub" consistently; the deb's Maintainer is Cargo.toml's "Cyber Hub contributors". A test now pins the identity. Choosing another value is the owner's decision **before the first public release**, after which it should never change; Authenticode's certificate subject is shown by SmartScreen and UAC independently of it |
| 90 | A switch that builds a draft without allowing publication | **Partly addressed.** A release candidate's tag (`vX.Y.Z-rc.N`) can never be published by the workflow, so enabling `RELEASE_PUBLISHING` for a candidate run cannot publish anything. A stable tag's run still depends on the *draft* box and the typed confirmation |

### Fixed

| What | Commit |
|---|---|
| No start without CA certificates ("builder error"); every network feature now says what to install | `1c98af4` |
| The MSI installed into the removed NSIS copy's per-user folder | `1aed064` |
| A second candidate of the same version needed the `v0.1.0` tag moved: the workflow now builds `vX.Y.Z-rc.N` tags as draft pre-releases and refuses to publish them | `00939e1` |
| The Projects page scrolled sideways just above the `lg` width when a project had dates (the row's details could not shrink) | `4d1a902` |
| The ASVS section failed to render when its history held a status the app does not know | `7e62a10` |
| Shellcheck SC2129 in the release workflow (found by CI's actionlint) | `44a0384` |
| The 0.1.0 notes read as if the Windows files were signed; they now state the signing, CA-certificate and scaling limits | `f049e08` |

### New

| # | Item | Why open |
|---|---|---|
| 99 | **The repository is public** | GitHub reports `RChefo/cyber-hub` as public (checked 2026-11-12T18:13Z); it was private at 00:06Z the same day, and no session on this machine changed it. Drafts stay hidden (an anonymous listing shows no release), but the source, the tags, the documentation and the Actions logs are public. The owner should confirm it is intended. If it is: turn on secret scanning and push protection (free for public repositories), consider required reviewers on the `release` environment (available for public repositories on GitHub Free), and consider requiring approval for all outside contributors' workflow runs |
| 100 | **Run actionlint before pushing a workflow change** | CI's pinned actionlint 1.7.7 with shellcheck runs locally in an `ubuntu:24.04` container (download, check the SHA-256, run). Mission 11's first push failed on a shellcheck style rule that the Rust workflow tests cannot see |
| 101 | **The final 0.1.0 release path** | The second candidate is the draft pre-release of `v0.1.0-rc.2`; the first is still the draft of `v0.1.0` (tag on `add894e`). To release 0.1.0, the owner deletes the first draft, moves `v0.1.0` to the validated commit (`git tag -f` and a forced tag push, a rewrite of a public tag to be done knowingly) or chooses a later version, builds the stable draft, checks it like the candidate, and publishes it. The stable build is a new build of the same commit, so its checksums differ from the candidate's |
| 102 | **"Installer Language" stays in `HKCU\Software\cyberhub\Cyber Hub`** | Tauri's NSIS installer writes it, and its uninstaller removes it only with *Delete the application data*. Harmless: the MSI reads only the folder value and `InstallDir`. Left as Tauri does it |

## Mission 12 (2026-11-13): open-source readiness

The owner decided that Cyber Hub stays public and becomes an open-source project. Mission 12 audited and secured the public repository, researched licenses (none applied: the owner selects one), audited third-party licenses, and added contributor documentation, community templates and repository checks. Details: MISSION_REPORT.md, "Mission 12".

### Status of earlier items

| # | Item | Status |
|---|---|---|
| 99 | The repository is public | **Decided by the owner: public, permanently.** Secret scanning, push protection, Dependabot security updates, private vulnerability reporting, branch and tag rulesets, approval of every outside contributor's workflow run, and the owner as required reviewer of the `release` environment are on (`docs/governance/REPOSITORY_SECURITY.md`). The third-party GitHub Apps remain the owner's account setting (item 109) |
| 100 | Run actionlint before pushing a workflow change | **Done** for Mission 12's changes (CI's pinned actionlint 1.7.7 with shellcheck, locally, no issue); documented in CONTRIBUTING.md |
| 101 | The final 0.1.0 release path | Unchanged; the tag ruleset now also blocks moving `v*` tags except for administrators, deliberately |

### Done

| What | Where |
|---|---|
| Public-repository security audit: gitleaks over every commit of every ref, the suppressed findings confirmed as fixtures, no signing key or env file ever committed, deleted files and identities checked | `docs/governance/REPOSITORY_SECURITY.md` |
| Free GitHub security features turned on, rulesets, `release` reviewer, outside-contributor approval | GitHub settings, 2026-11-13 |
| License comparison (MIT, Apache-2.0, GPL-3.0, AGPL-3.0) with a recommendation (Apache-2.0) | `docs/governance/LICENSE_COMPARISON.md`; no LICENSE committed |
| Third-party license audit: 649 crates, 457 npm packages, copied components, assets, data, the AppImage's native libraries | `docs/governance/THIRD_PARTY_LICENSE_AUDIT.md`, `docs/governance/third-party/` |
| A dependency license policy enforced in CI; Markdown link check; pull request title check | `scripts/licenses.mjs`, `scripts/license-policy.json`, `scripts/check-links.mjs`, CI job "Repository checks" |
| Release build artifacts were downloadable by any signed-in user for 7 days; now one day, and deleted after the draft upload | `.github/workflows/release.yml` |
| Notices for copied components, fonts and icons; license notes in the copied files' headers | `THIRD_PARTY_NOTICES.md`, `src/components/vendor/`, `website/src/components/ui/` |
| README, CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1), SECURITY, SUPPORT, development guide, documentation index | Repository root, `docs/README.md`, `docs/governance/DEVELOPMENT_GUIDE.md` |
| Issue forms (bug, feature, question), pull request template, CODEOWNERS, Dependabot version updates, 8 labels | `.github/` |
| "Repository checks" required by the default-branch ruleset; CI runs once per pull request instead of twice (`07b5912`) | Ruleset 27194018, `.github/workflows/ci.yml` |

### New

| # | Item | Why open |
|---|---|---|
| 103 | **Select the project license** | Owner decision. Recommended: Apache-2.0 (or GPL-3.0-or-later if preventing closed forks matters more). Then the steps in LICENSE_COMPARISON.md, "Applying the license" |
| 104 | **Replace the React Bits components** | `CountUp`, `BranchedMenu` (app) and `OrbitImages` (website) are under MIT + Commons Clause, which is not open source and blocks a repository-wide OSI license unless they are excluded. Replacing visible UI is the owner's decision |
| 105 | **Replace the website's Ink Orbit component or obtain permission** | Its source repository has no license |
| 106 | **The AppImage's bundled LGPL libraries and GPL-2.0-or-later `libjbig`** | A source offer is needed before public AppImage distribution, or `libjbig` and the TIFF loader removed, or Linux limited to deb and rpm. Owner decision; possibly legal advice |
| 107 | **Ship third-party license texts and NOTICE contents with the installers** | MIT, BSD, ISC, Apache-2.0 (ECharts, moka, tlsh2), OFL and the data licenses require them with binaries; extend `scripts/licenses.mjs` to generate the file and bundle it; needs a new candidate build |
| 108 | **The six release-run artifacts of the first and second candidates** | Downloadable by any signed-in GitHub user until 2026-11-19. Deleting them is the owner's call (Mission 12 was not authorized to delete repository content): `gh api -X DELETE repos/RChefo/cyber-hub/actions/artifacts/<id>` for each `bundles-*` artifact of runs 43231095560, 43242424304 and 43288379505 |
| 109 | **Limit the eight third-party GitHub Apps** to the repositories they serve | Account-wide setting; several have administration or workflow write access; none is used here |
| 110 | **Commit e-mail privacy** | Commits carry a personal e-mail address; turn on GitHub's e-mail privacy so future commits use the no-reply address. History is not rewritten |
| 111 | **A contact for Code of Conduct reports** | CODE_OF_CONDUCT.md points to GitHub's content reporting and the owner's profile until the owner publishes a private address |
| 112 | **Discussions, social preview, website URL** | Discussions are off (the owner decides whether to moderate a forum); the social preview image needs the web interface; there is no deployed website to link |
| 113 | **Provider credentials for external users** | Keys can be added only with the developer tool `cyberhub-keys` or the OS credential tools; a user-facing path would be a product change |
| 114 | **Lightswind's license file and the app icons' authorship** | Lightswind declares MIT only in npm metadata; the icons' origin is not recorded. Low |
| 115 | **Review Dependabot's first pull requests (#1–#8)** | Grouped minor and patch updates, plus majors for `getrandom`, `hmac`, `sha1`, `sha2` and the website's TypeScript 7, which may need code changes. Each needs CI green and a review; none was merged in Mission 12 |
| 94 (update) | glib and minimatch alerts | Dependabot's automatic security updates end in `security_update_not_possible`: glib's fix (0.20) is out of reach under GTK 0.18 and Tauri; minimatch's would downgrade other dependencies. GitHub shows those runs as failed. Unchanged otherwise |

## Mission 13 (2026-11-13): ExploitX

The owner renamed the product ExploitX (official website exploitx.net) and moved the website to RChefo/ExploitX-Web. Details: MISSION_REPORT.md, "Mission 13"; the identity in docs/brand/.

### Done

| What | Where |
|---|---|
| Brand strategy, the Convergence symbol, wordmark, lockups, colour, type, icon and illustration rules | `docs/brand/`, `design/brand/` |
| Editable SVG logos, PNG exports, Windows ICO and Linux icons, favicons, social images, illustrations | `design/brand/` (ASSET_CATALOG.md) |
| Design tokens shared by the app and the website | `design/brand/build/tokens.mjs` → `tokens.css`; `src/styles/index.css` |
| The desktop app rebranded (theme, logo, icons, texts, window title, Linux menu entry, installer icon) with the package identity kept and pinned by tests | `src/`, `src-tauri/`, `ci_tests.rs` |
| The website rebranded, canonical exploitx.net, and moved to its own repository with its history | RChefo/ExploitX-Web (`8c7fe0d`) |
| The name inventory and the name and domain research | `docs/brand/NAME_MIGRATION.md`, `BRAND_NAME_RESEARCH.md` |

### New

| # | Item | Why open |
|---|---|---|
| 116 | **The package identity** | Windows installer, Start menu, *Apps & features* and the executable's details still say "Cyber Hub", because they derive from `productName`, which the brief keeps. Owner decision: keep it, or migrate before the first public release (NAME_MIGRATION.md lists the steps and tests) |
| 117 | **Rebuild the release under ExploitX** | The drafts of `v0.1.0` and `v0.1.0-rc.2` are Cyber Hub builds; a new candidate needs a new tag, updated notes and an authorized run |
| 118 | **Clear the name** | Serious prior uses: the Chennai club and CTF "ExploitX" (exploitx.org), an "ExploitX" game-software shop (exploitx.io, expired), a CTF team, ExploitX Defence; EXPLOIT marks in Italy, Australia, the UK. Attorney review; confirm and lock exploitx.net |
| 119 | **The website live** | Host, DNS, HTTPS and the build variables (RChefo/ExploitX-Web README, "Deployment"); upload the GitHub social preview |
| 120 | **Windows VM checks of the rebranded installers** | Install, upgrade from RC2, uninstall, data kept, Start menu and taskbar icons; GNOME and KDE menu entries in real sessions |
| 121 | **Keep the website's copies in step** | Tokens, logo geometry, favicons, `og.png`, screenshots and the package patterns are copied into RChefo/ExploitX-Web (its docs/BRAND.md); sync when they change |
| 122 | **Installer wizard artwork** | NSIS header and sidebar images and WiX banners in the ExploitX style (display only); not done |
