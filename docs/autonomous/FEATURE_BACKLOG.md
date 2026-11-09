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
| 24 | SARIF 2.1.0 export of findings | 3 | 3 | 5 | 5 | 5 | 5 | 40 | Planned |
