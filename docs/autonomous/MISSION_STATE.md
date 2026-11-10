# Mission state: autonomous research and development mission

This file lets a new session resume the mission accurately. Times are UTC and measured with `date -u`.

| Item | Value |
|---|---|
| Mission start | 2026-11-08T21:31:01Z |
| Branch | `release/v0.1.0` |
| HEAD at start | `092e092` (plus 27 uncommitted QA-audit paths) |
| Current phase | **Complete** (Mission 7, 2026-11-10T18:40Z–2026-11-11: final hardening and release preparation: a full security review with every finding fixed and regression-tested or accepted, native-confirmation hardening, the minimum window and HiDPI, KWin with XWayland diagnosed, the Windows TAXII credential procedure, a manual-run-only release workflow, start errors shown natively, saved indicators paged, a TAXII credential race found in testing and fixed, and the release-readiness checklist (docs/release/), schema unchanged at 32; engineering checks pass, the release is not ready (checklist items M1–M4 and M7–M10), see MISSION_REPORT.md "Mission 7". Mission 6, 2026-11-10T14:05Z–18:31Z: exceptions for failed WSTG tests, the remaining parser amplifications, TAXII credentials typed into a native dialog, ATT&CK Mobile and ICS, process chains and logons, cloud-resource assets, validation with Claude Code as an MCP client and the two MCP fixes it led to, the compositors of GNOME and KDE and HiDPI on Linux, a release workflow that publishes only on explicit conditions, and an integration review, schema 29 → 32, see MISSION_REPORT.md "Mission 6". Mission 5, 2026-11-10T10:14:43Z–2026-11-10T14:08Z: Linux compatibility on Ubuntu 24.04 and Debian 12 including a real Wayland compositor, parser hardening with a hostile-input sweep and fuzzing, upgrade validation from every schema, Sigma correlation rules, risk acceptance, TAXII 2.1, ASVS gaps and comparison, ATT&CK history and comparison, release-profile timings and a pinned CI workflow, schema 26 → 29, see MISSION_REPORT.md "Mission 5". Mission 4, 2026-11-09T23:21:37Z–2026-11-10T01:56Z: detection engineering (Sigma, YARA), hunting leads, ASVS 5.0.0, indicator lifecycle and MCP tools, schema 23 → 26, see MISSION_REPORT.md "Mission 4". Mission 3, 2026-11-09T20:10:11Z–22:35Z: the unified investigation layer, schema 21 → 23, see MISSION_REPORT.md "Mission 3". Mission 2, 2026-11-09T16:31:14Z–19:55Z: ten research-driven capabilities, schema unchanged at 21, see MISSION_REPORT.md "Mission 2". Feature expansion round 2026-11-09T13:31Z–16:30Z: seven new capabilities in the six areas the owner named, schema 21; it comes after RC0, which does not cover it. RC0 release-candidate validation 2026-11-09T12:16Z–13:30Z: **ready for a release-candidate build**, not yet for final release authorization. Fourth segment 2026-11-09T11:28:28Z–12:20Z: final pre-release hardening. Earlier segments: 2026-11-08T21:31:01Z–23:43Z, 2026-11-09T06:32:12Z–08:07Z and 08:51:44Z–11:05Z). See [MISSION_REPORT.md](MISSION_REPORT.md) |

## Baseline (2026-11-08T21:31Z–21:45Z)

* Repository: Tauri 2, Rust, React 19, HeroUI v3, SQLite schema 12, 19 command modules.
* Pre-existing uncommitted QA-audit work re-verified, then committed as `676c23d`:
  * Rust: 257 passed, 1 ignored; clippy `-D warnings` clean.
  * Frontend: tsc clean, vitest 197 passed (30 files).
* Capabilities confirmed **absent** by code search:
  * scanner-output import (Nuclei, Burp, ZAP, SARIF; Nmap only from Cyber Hub's own runs);
  * finding templates;
  * a CVSS calculator for findings;
  * methodology checklists with coverage;
  * IOC extraction, defang and refang;
  * STIX export;
  * user-facing backup and restore.

## Research

See [../research/CYBER_HUB_MARKET_RESEARCH.md](../research/CYBER_HUB_MARKET_RESEARCH.md). All three research tracks are complete (community demand, competitor features, format specifications).

## Backlog

See [FEATURE_BACKLOG.md](FEATURE_BACKLOG.md).

## Completed features

1. Scanner-output import (`b51615a`)
2. Finding library with import rules (`95c8eac`)
3. Fix verification by rescan (`0e201f5`)
4. CVSS 4.0/3.1 on findings with a calculator (`edad2bf`)
5. IOC extractor, defang and refang, STIX 2.1 export (`38599a1`)
6. Greenbone/OpenVAS import (`99fe5ed`)
7. Findings CSV/JSON export (`0337e18`)
8. Bulk tag and assignee edit (`0337e18`)
9. OWASP WSTG checklist (`9c4ee92`)
10. On-demand database backup (`4a320a8`)
11. Security review fixes (`c3f26af`, `da545e8`, `bd6d73e`)
12. CVSS 3.0 scoring fixed after a 709,160-vector comparison with FIRST's calculators (`b46a075`)
13. Database restore in the app (`2eb4209`)
14. MCP tools for CVSS, the finding library and the checklist (`aaa7d0a`)
15. Clippy 0.1.99 lints fixed (`7fb4008`)
16. CSV findings import with a column mapping (`53dac93`)
17. Second review's fixes: CSV detection panic, redaction gaps, MCP approval checks (`9d6dba6`)
18. Path-level scope: URL entries authorize paths, never hosts; redirects rechecked per hop; repeated refusals counted (schema 18) (`80f34de`)
19. Imported files in UTF-16 or Windows-1252 (`e326ace`)
20. Review fixes for the path-level scope: whole-token URL reading, ambiguous forms, loose path matching, raw requests under both schemes, no system proxy; schema 19 keeps old URL exclusions at host level (`8355745`)
21. Cross-module references: tool runs as evidence, asset deletion with vulnerabilities, run history, OSINT links, atomic finding creation (`96fe970`)
22. Timeline paging without gaps; reports leave out notes and closed findings (`d26f799`)
23. Evidence verification and checked exports; MCP duplicate-finding warning (`aa4d17d`)
24. MCP clients kept out of archived projects; project status history (`ce76bfa`)
25. Requests sent to targets and asset status on the timeline (`7e74883`)
26. Imported CVEs tracked as vulnerabilities on request (`6860814`)
27. SQLite 3.54.1 and rmcp 3.9.0 for two new advisories; MSRV 1.89 (`0641a0e`)
28. Redirects of external tools need host-level authorization (`e43f3cb`)
29. Checklist links can be removed; checklist history on the timeline (`c4c80c8`)
30. Project deletion refused during active work; atomic end-of-run records (`a1e78ca`)
31. Guarded rebuild mode for migrations of referenced tables (`223491c`)
32. HTML and Markdown reports from one model (`ca685c0`)
33. Release notes and upgrade guidance (`d6a192e`)
34. API inventory from OpenAPI, Swagger, Postman and HAR, with OWASP API Security Top 10 (2023) checks and a test plan (schema 20) (`e36a9a3`)
35. Repeater in the HTTP request builder: raw requests, history, resend, response comparison, cURL (`3b9ad54`)
36. SBOM analysis: CycloneDX and SPDX, license risk, NTIA minimum elements, VEX, OSV.dev lookups on request (schema 21) (`9b32276`)
37. Container and Kubernetes configuration checks (Pod Security Standards, CIS Docker Benchmark) (`eff1b18`)
38. Packet capture triage (pcap, pcapng) and log triage (web access, SSH) (`6074b5f`)
39. SARIF 2.1.0 export of findings (`8a8f588`)
40. SARIF import skips suppressed results (`d776c58`)
41. Findings filters in their own row (`31615cc`)
42. Kubernetes RBAC escalation paths, with bindings resolved across files (`914f50a`)
43. Dependency lockfiles (13 formats) as SBOMs, with supply-chain checks (`4835950`)
44. Windows event log (EVTX) triage with 35 ATT&CK-mapped detections (`4d78bfd`)
45. Cloud and IaC checks: Terraform, CloudFormation, AWS IAM policies and escalation methods (`b35fafa`)
46. PE and ELF file triage without running the file (`f9d7594`)
47. API definition comparison (`25bb7a2`)
48. OAuth and OpenID Connect metadata review against RFC 9700 (`b77ddd2`)
49. Prowler (OCSF) import, with passing checks resolving earlier findings (`afd290c`)
50. Linux persistence triage of images and UAC collections (`2116f34`)
51. ATT&CK Navigator layer export of the findings' techniques (`cd8b0b7`)
52. SBOM and lockfile comparison between versions (`54d6534`)
53. Cut-input tests for the lockfile and IaC readers (`a7b0368`)
54. Investigation layer: relationships, correlation and review, record panel, graph, timeline filters and export, evidence provenance, record search (schema 22) (`7b1a842`)
55. Utility results recorded with their evidence and provenance (`24258c2`)
56. ATT&CK matrix with assessments and Navigator layers (schema 23) (`e3eeeca`)
57. Record search in the command palette (`3c761db`)
58. MCP tools for the investigation layer; assistant context and AI-suggestion labels (`f0ab1d5`)
59. Investigation playbooks on the workflow engine (`6dc7f63`)
60. Evidence provenance in reports (`f08a6bb`)
61. Remediation groups (`ab4a9db`)
62. Concurrency test of correlation and review (`54576dd`)
63. Sigma detection engineering: library, tests, project hits, ATT&CK coverage (`e4a3987`)
64. The concurrency test made reliable under full-suite load (`2d26fa2`)
65. OWASP ASVS 5.0.0 assessments (`8150748`)
66. YARA rules on boreal, in the library, project runs and File Triage (`4fa4a1a`)
67. Hunting leads in packet captures (`ef862c3`)
68. Indicator lifecycle (`d8c8cbb`)
69. MCP tools for detections and ASVS (`285e439`)
70. Clippy 1.99 lints found by the Linux runs (`4d9b12f`)
71. Upgrades from every schema version, with injected failures and kills (`ff3e5f5`)
72. Sigma correlation rules (`0c8084f`; chained imports fixed in `91b064a`)
73. Parser hardening and the hostile-input sweep (`6acf43e`)
74. Risk acceptances, ASVS exceptions and compliance gaps (`e6869ed`)
75. Coverage-guided fuzzing and the YAML key bound it led to (`3336d6b`)
76. TAXII 2.1 feeds (`3573c2f`)
77. ATT&CK technique history, comparison and coverage snapshots (`24045f0`)
78. Timing tests for an optimized build (`d23ddf3`)
79. A pinned CI workflow with clippy, Debian 12, audits and secret scanning (`7206810`)
80. A pinned release workflow that publishes only on explicit conditions (`9d89831`)
81. Exceptions for failed WSTG tests, and acceptances in reports (`c270a1e`)
82. The remaining parser amplifications (`1f64034`)
83. Process chains and logons per account in Windows event logs (`b5c845d`)
84. ATT&CK Mobile and ICS matrices (`020ad01`)
85. Cloud-resource assets from configuration audits (`d0e706e`)
86. TAXII credentials typed into a native OS dialog (`2eb6185`)
87. MCP: client cancellations reach the app (`ea60e88`); credentials masked in results (`57d3c48`)
88. Integration review fixes (`c8b0bdc`, `05500c5`, `92100da`, `1a93038`, `bfa6107`, `2a60d9f`)
89. The secret scan's fixture marker (`b002e0e`)

## Tests executed

See [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md).

## Known failures

None. At the end of Mission 6:
* **Windows 11** (at `2a60d9f`; `b002e0e` changed only comments): 593 Rust tests (27 ignored) and 291 frontend tests in 53 files; clippy, also with `fuzzing`, and tsc clean; cargo audit 0 vulnerabilities in 651 crates (the same 8 allowed warnings); npm audit 0; gitleaks over 149 commits: no leaks.
* **Ubuntu 24.04.5 and Debian 12** (at `b002e0e`): tsc, 53 frontend test files, clippy, 593 Rust tests (27 ignored) and npm audit pass; `cargo +1.90.0 check --all-targets` passes on Ubuntu.
* **Real app:** Windows end-to-end 23/23; Claude Code and a scripted MCP client 18/18; on each distribution the Mission 6 features 25/25 and the GUI regression 71/71; on Ubuntu, Mutter 5/5, KWin 5/5 and HiDPI 7/7.
* **Not run:** GitHub Actions (nothing pushed), installers, signing, a release build; typing into Windows' credential dialog (needs a person).

At `91b064a` (Mission 5):
* **Windows 11:**
  * 568 Rust tests (16 ignored, six of them the timing tests) and 281 frontend tests in 50 files;
  * clippy, also with the `fuzzing` feature, and tsc are clean;
  * cargo audit: 0 vulnerabilities in 651 crates, the same 8 allowed warnings; npm audit: 0;
  * gitleaks over the whole history (132 commits before this report) and the changed documents: no leaks.
* **Ubuntu 24.04.5 and Debian 12:** tsc, 50 frontend test files, clippy, 568 Rust tests (16 ignored) and npm audit pass. `cargo +1.90.0 check --all-targets` passes on Ubuntu. The GUI regression is 71/71 on each distribution (Debian on a re-run, see MISSION_REPORT.md).
* **Real app:**
  * end-to-end on Windows 48/48 and screens 10/10;
  * the Mission 5 features on Linux 18/18 per distribution;
  * WSLg Wayland 4/4 and XWayland 6/6 per distribution.
* **Not run:** GitHub Actions (nothing pushed), installers, signing and a release build of the app.

At `285e439` (Mission 4, Windows 11): 522 Rust tests (10 ignored) and 276 frontend tests in 49 files; clippy, tsc, cargo audit (0 vulnerabilities in 651 crates, 8 allowed warnings), npm audit (0) and gitleaks over the mission's 7 commits are clean; `cargo +1.90.0 check --all-targets` passes; every new capability passed its check in the real app (121 of 121). **Not run for Mission 4:** the Linux suites and Linux GUI checks.

At `54576dd` (Mission 3, Windows 11): 482 Rust tests (7 ignored) and 264 frontend tests in 47 files; clippy, tsc, cargo audit (0 vulnerabilities in 640 crates, 8 allowed warnings), npm audit (0) and gitleaks over the mission's 9 commits are clean; `cargo +1.90.0 check --locked --all-targets` passes; every new capability passed its check in the real app (112 of 112). **Not run for Mission 3:** the Linux suites and Linux GUI checks.

At `a7b0368` (Mission 2, Windows 11): 459 Rust tests (6 ignored) and 258 frontend tests in 45 files; `cargo clippy --all-targets -- -D warnings`, tsc, cargo audit (0 vulnerabilities in 640 crates, 8 allowed warnings), npm audit (0) and gitleaks over the mission's commits are clean; `cargo +1.90.0 check --locked --all-targets` passes; every new capability passed its check in the real app (174 of 174). **Not run for Mission 2:** the Linux suites and Linux GUI checks.

At `914f50a` (feature expansion round, Windows 11): 405 Rust tests (3 ignored) and 243 frontend tests in 41 files; clippy, tsc, cargo audit (0 vulnerabilities, 8 allowed warnings), npm audit (0) and gitleaks over the round's 9 commits are clean; `cargo +1.90.0 check --locked --all-targets` passes with the declared minimum Rust version; every new capability passed its check in the real app (125 of 125). **Not run for this round:** the Linux suites and Linux GUI checks.

The final results at `d6a192e`:
* **Windows:** 362 Rust tests (366 with provisioning) and 224 frontend tests.
* **Ubuntu 24.04.5 and Debian 12:** 362 Rust tests and all 36 frontend test files.
* **Static checks:** clippy, tsc, the build, npm audit, cargo audit (Windows) and gitleaks are clean.
* **Real GUI:** 69 of 69 checks on Ubuntu and on Debian; the Windows smoke and 7 feature checks passed.

## Commits during the mission

| Commit | Subject |
|---|---|
| `676c23d` | fix(qa): harden active utilities against DNS rebinding and fix issues from the final QA audit |
| `b51615a` | feat(findings): import Nmap, Nuclei, Nessus, Burp, ZAP and SARIF results |
| `95c8eac` | feat(library): add a finding library with templates and import rules |
| `0e201f5` | feat(findings): verify fixes when a rescan no longer reports a finding |
| `efe8605` | docs(research): add market research, scored backlog and mission state |
| `edad2bf` | feat(findings): add CVSS 4.0 and 3.1 vectors and a calculator to findings |
| `38599a1` | feat(intel): add an IOC extractor, defang and refang, and STIX 2.1 export |
| `3883ea5` | docs(mission): record features 4 and 5 in the mission log |
| `99fe5ed` | feat(findings): import Greenbone/OpenVAS reports |
| `0337e18` | feat(findings): export findings as CSV or JSON and edit tags in bulk |
| `21ed6f2` | docs(mission): record features 6 to 8 in the mission log |
| `9c4ee92` | feat(projects): add an OWASP WSTG testing checklist with coverage |
| `e4985ba` | test(findings): use an obviously fake value in the redaction fixture |
| `4a320a8` | feat(settings): back up the database on demand with an integrity check |
| `5afdcdc`, `9f1045d` | docs: test counts and mission pointers |
| `6764014` | docs(mission): record feature 9, the backup and the final verification |
| `c3f26af` | fix(security): harden scan import, redaction and IOC extraction |
| `da545e8` | test(security): mark made-up secret fixtures for the secret scanner |
| `bd6d73e` | fix(findings): count skipped Nuclei lines in singular and plural |
| `2afa5bd` | docs(mission): add the mission report and final verification results |
| `b46a075` | fix(cvss): score CVSS 3.0 vectors with the 3.0 equations |
| `2eb4209` | feat(settings): restore a database backup in the app |
| `3602269` | docs(mission): record the CVSS comparison and the database restore |
| `aaa7d0a` | feat(mcp): expose CVSS scoring, the finding library and the WSTG checklist |
| `7fb4008` | fix(osint): resolve the lints reported by clippy 0.1.99 |
| `53dac93` | feat(findings): import findings from CSV files with a column mapping |
| `04114e8` | docs(mission): record the MCP tools, Linux clippy and the CSV import |
| `9d6dba6` | fix(security): harden the CSV import and the new MCP approvals |
| `80f34de` | feat(scope): authorize URL entries per path, never their host |
| `e326ace` | fix(findings): read imported files saved as UTF-16 or Windows-1252 |
| `8355745` | fix(scope): close path-scope bypasses found in review |
| `96fe970` | fix(workspace): keep cross-module references consistent |
| `d26f799` | fix(reports): page the timeline without gaps and keep notes out of reports |
| `aa4d17d` | feat(evidence): verify stored evidence against its SHA-256 |
| `ce76bfa` | fix(mcp): keep MCP clients out of archived projects |
| `7e74883` | feat(timeline): record requests sent to targets and asset status changes |
| `6860814` | feat(findings): track imported CVEs as vulnerabilities on request |
| `0641a0e` | fix(deps): upgrade the bundled SQLite and rmcp for new advisories |
| `dcba30b` | docs(mission): report the third segment and its final verification |
| `e43f3cb` | feat(scope): refuse tool runs that follow redirects on path-only URLs |
| `c4c80c8` | feat(checklist): remove checklist finding links and record every change |
| `a1e78ca` | fix(projects): keep run history when a project is deleted during a run |
| `223491c` | fix(db): add a guarded rebuild mode for referenced tables in migrations |
| `ca685c0` | feat(reports): build HTML and Markdown reports from one model |
| `d6a192e` | docs(release): prepare the 0.1.0 release notes and upgrade guidance |
| `4361d36` | docs(mission): report the final pre-release hardening and its regression |
| `2ad9a1c` | fix(build): declare Rust 1.90, the minimum the locked Tauri crates need |
| `ae673e5` | fix(scope): cover browser modes and option files in the redirect rule |
| `f90ab22` | docs(release): correct the 0.1.0 notes against the code |
| `164e10f` | docs(mission): report the RC0 release candidate validation |
| `e36a9a3` | feat(api): add an API inventory with OWASP API Top 10 checks |
| `3b9ad54` | feat(utilities): turn the HTTP request builder into a repeater |
| `9b32276` | feat(sbom): analyze SBOMs for vulnerable components and license risks |
| `eff1b18` | feat(utilities): check Dockerfiles, Compose files and Kubernetes manifests |
| `6074b5f` | feat(utilities): triage packet captures and server logs |
| `8a8f588` | feat(findings): export findings as SARIF 2.1.0 |
| `d776c58` | fix(import): skip suppressed SARIF results |
| `31615cc` | fix(findings): give the findings filters their own row |
| `914f50a` | feat(utilities): find Kubernetes RBAC escalation paths |
| `7d17b22` | docs(mission): report the feature expansion round |
| `c3a79c1` | docs(mission): research and rank the mission 2 candidates |
| `4835950` | feat(sbom): analyze dependency lockfiles with supply-chain checks |
| `4d78bfd` | feat(utilities): triage Windows event logs with ATT&CK-mapped detections |
| `b35fafa` | feat(utilities): check cloud infrastructure as code and IAM policies |
| `f9d7594` | feat(utilities): triage PE and ELF files without running them |
| `25bb7a2` | feat(api): compare API definitions to find endpoint changes |
| `b77ddd2` | feat(utilities): review OAuth and OpenID Connect server metadata |
| `afd290c` | feat(import): import Prowler cloud audits as OCSF findings |
| `2116f34` | feat(utilities): triage Linux persistence in images and collections |
| `cd8b0b7` | feat(findings): export ATT&CK techniques as a Navigator layer |
| `54d6534` | feat(sbom): compare two SBOM or lockfile versions |
| `a7b0368` | test(parsers): feed cut and multibyte input to lockfile and IaC readers |
| `9abfbad` | docs(mission): report mission 2 |
| `8b99a05` | docs(mission): correct the mission 2 end time |
| `7b1a842` | feat(investigation): correlate records across modules with reviewed relationships |
| `24258c2` | feat(utilities): record triage results with their evidence and provenance |
| `e3eeeca` | feat(attack): add a project ATT&CK matrix with assessments and layers |
| `3c761db` | feat(search): find project records from the command palette |
| `f0ab1d5` | feat(mcp): expose the investigation layer to MCP clients and the assistant |
| `6dc7f63` | feat(workflows): add investigation playbooks built on workflow steps |
| `f08a6bb` | feat(reports): show evidence provenance in the evidence register |
| `ab4a9db` | feat(findings): group findings by the fix that addresses them |
| `54576dd` | test(investigation): run correlation and reviews from several threads |
| `2d23aba` | docs(mission): report mission 3 |
| `ddaac03` | docs(mission): correct the mission 3 commit count |
| `e4a3987` | feat(detections): add a Sigma detection engineering workspace |
| `2d26fa2` | test(investigation): keep reviewing until correlation has suggested something |
| `8150748` | feat(asvs): assess projects against OWASP ASVS 5.0.0 |
| `4fa4a1a` | feat(detections): run YARA rules on files with boreal |
| `ef862c3` | feat(hunting): report beacon-like timing and DNS patterns in captures |
| `d8c8cbb` | feat(intel): track saved indicators' source, confidence and validity |
| `285e439` | feat(mcp): expose detections and ASVS assessments to MCP clients |
| `0f51cd2` | docs(mission): report mission 4 |
| `4d9b12f` | fix(lint): satisfy clippy 1.99 found by the Linux runs |
| `ff3e5f5` | test(db): upgrade every schema version with data, failures and kills |
| `0c8084f` | feat(detections): evaluate Sigma correlation rules |
| `6acf43e` | fix(security): stop crafted files and peers from crashing or exhausting the app |
| `e6869ed` | feat(risk): record risk acceptances and ASVS exceptions, with compliance gaps |
| `3336d6b` | fix(security): bound YAML keys after fuzzing found an exponential blow-up |
| `3573c2f` | feat(intel): import STIX indicators from TAXII 2.1 feeds |
| `24045f0` | feat(attack): track techniques over time and compare technique sets |
| `d23ddf3` | test(perf): time the heavy paths on generated data |
| `7206810` | ci: pin the verification workflow and add clippy, audits, Debian and secret scanning |
| `91b064a` | fix(detections): import a chain's inner correlations disabled too |
| `9d89831` | ci: pin the release workflow and publish only on explicit conditions |
| `c270a1e` | feat(risk): record exceptions for failed WSTG tests and list acceptances in reports |
| `1f64034` | perf(import): remove the amplifications left open by the parser review |
| `b5c845d` | feat(hunting): link process creations into chains and summarize logons per account |
| `020ad01` | feat(attack): add the ATT&CK Mobile and ICS matrices |
| `d0e706e` | feat(assets): record cloud resources from configuration audits |
| `2eb6185` | feat(intel): store TAXII credentials typed into a native OS dialog |
| `ea60e88` | fix(mcp): cancel a waiting approval when the client cancels its call |
| `57d3c48` | fix(mcp): mask credential-like values in what clients receive |
| `c8b0bdc` | fix(risk): ask before a result ends an exception and fit the register to the report options |
| `05500c5` | fix(hunting): keep flagged chains visible and distinct in event log triage |
| `92100da` | fix(attack): keep each matrix's layers, snapshots and exports apart in the UI |
| `1a93038` | fix(assets): show where a cloud resource is and what relates to it |
| `bfa6107` | fix(intel): say when a kept TAXII password was typed for another user name |
| `2a60d9f` | fix(risk): render the confirmation that guards an exception |
| `b002e0e` | test(mcp): mark the made-up key ID in the redaction test for the secret scan |

## Next action

**After Mission 7 (2026-11-11), the owner decides:**
1. Review the work (MISSION_REPORT.md, "Mission 7"). No migration (schema 32). One test-only crate was added (`pulldown-cmark` 0.13.6, a dev-dependency). The TAXII credential entry name changed: credentials stored by earlier development builds have to be stored again.
2. Run or delegate the manual release checklist (docs/release/RELEASE_READINESS.md):
   * M1, the Windows TAXII credential dialog (TAXII_CREDENTIAL_TEST.md);
   * M2–M7, Linux desktop sessions, physical HiDPI, portals, a login keyring.
3. Push a branch so that `ci.yml` runs on GitHub for the first time (M8). `release.yml` builds and signs only in a manual run with `RELEASE_PUBLISHING` enabled.
4. Set up signing (M9), then authorize the one release build and validate its installers (M10).
5. Next candidates (FEATURE_BACKLOG.md, "Mission 7"): items 68–75.

**After Mission 6 (2026-11-10T18:31Z), the owner decides:**
1. Review the work (MISSION_REPORT.md, "Mission 6"). It adds migrations 30–32; a backup is taken before each, every earlier schema is upgraded in the tests, and 32 rebuilds `assets` keeping every row and id. No crate is added to `Cargo.lock`.
2. Push a branch so that `ci.yml` runs on GitHub for the first time (PLATFORMS.md, "First run of the workflows"). Only the owner can authorize this. `release.yml` publishes nothing until `RELEASE_PUBLISHING` is `enabled` and a manual dispatch confirms the tag.
3. Before any release:
   * set up signing;
   * authorize and validate one release-candidate build (installers, upgrade from a copy of a real database, uninstall, updates);
   * do the manual checks: typing into Windows' credential dialog, a GNOME and a Plasma session, a physical HiDPI screen.
4. Next candidates (FEATURE_BACKLOG.md, "Mission 6"): items 62–64 and 67.

**After Mission 5 (2026-11-10T14:08Z), the owner decides:**
1. Review the capabilities and fixes (MISSION_REPORT.md, "Mission 5"). They add migrations 27–29, which only add data; backups are taken before each, and every earlier schema version is upgraded in the tests. No application dependency is added.
2. Push a branch to let `ci.yml` run on GitHub for the first time. Only the owner can authorize this.
3. Before any release:
   * repeat the RC0 checks on a release-candidate build;
   * pin `release.yml`'s toolchain as `ci.yml` is;
   * set up signing.
4. Next candidates (FEATURE_BACKLOG.md, "Mission 5"):
   * the smaller parser amplifications in SECURITY.md;
   * TAXII credentials entered in the app;
   * a cloud-resource asset type;
   * host hunting analytics.

**After Mission 4 (2026-11-10T01:56Z), the owner decides:**
1. Review the six capabilities (MISSION_REPORT.md, "Mission 4"). They add migrations 24–26 (backups are taken before each) and one dependency, `boreal` 1.4.0 with its crates.
2. A release that includes Missions 2–4 needs the RC0 checks repeated for the new code, above all the Linux suites and GUI checks, which were not run.
3. Next candidates (FEATURE_BACKLOG.md, "Mission 4"): 47 risk acceptance records, then 48 host hunting analytics and 49 Sigma aggregations.

**After Mission 3 (2026-11-09T22:35Z), the owner decides:**
1. Review the investigation layer (MISSION_REPORT.md, "Mission 3"). It adds migrations 22 and 23 (backups are taken before each) and no dependency.
2. A release that includes Missions 2 and 3 needs the RC0 checks repeated for the new code, above all the Linux suites and GUI checks, which were not run.

**After Mission 2 (2026-11-09T19:55Z), the owner decides:**
1. Review the ten new capabilities (MISSION_REPORT.md, "Mission 2"). They add three dependencies (`toml` 1, `hcl-rs` 0.20 with `kstring` pinned at 2.0.2, `goblin` 0.10) and no migration.
2. A release that includes Mission 2 needs the RC0 checks repeated for the new code, above all the Linux suites and GUI checks, which were not run.
3. Next candidates (FEATURE_BACKLOG.md): 33, the OWASP ASVS 5.0 checklist next to WSTG. It needs the CC BY-SA requirement catalog with attribution, a schema migration for per-project status (to be rehearsed on a disposable copy) and the checklist UI generalized to two catalogs. Also an ATT&CK matrix view inside Cyber Hub (the rest of 38), and 39 and 40 as deferred.

**After the feature expansion round (2026-11-09T16:30Z), the owner decides:**
1. Review the seven new capabilities (MISSION_REPORT.md, "Feature expansion round"). They add schemas 20 and 21 and one dependency (yaml-rust2 0.13).
2. RC0 validated `ae673e5` and `f90ab22`, before this round. A release candidate built from `914f50a` or later needs the RC0 checks repeated for the new code: the Linux suites and GUI checks, the upgrade rehearsal to schema 21 and the restore rehearsal. The owner asked not to start that audit in this round.
3. The RC0 release blockers below still apply.

**After RC0 (2026-11-09T13:30Z), the owner decides:**
1. Set up Authenticode signing as `docs/SIGNING.md` describes (release blocker), preferably before the release-candidate build.
2. Authorize the release-candidate build, then validate its installers: install, upgrade from a copy of a real database, uninstall, a first start of the release build, and an update through a staging feed.
3. Review the version and `docs/releases/0.1.0.md`, which is published as written.

Code candidates that are not blocking (MISSION_REPORT.md, "Technical debt"): remove partial restore copies at start, record refused tool runs in the scope history, read known option-file formats, pin the release toolchain.

Second segment (from 2026-11-09T06:32Z), in this order:
1. ~~Verify CVSS scoring against FIRST's reference calculators~~: done (`b46a075`); it found and fixed CVSS 3.0 scoring.
2. ~~Restore from a backup inside the app~~: done (`2eb4209`); backlog item 12 is complete.
3. ~~Expose the new capabilities through MCP~~: done (`aaa7d0a`), 49 tools.
4. ~~More import formats~~: generic CSV import with a column mapping done (`53dac93`).
5. ~~Clippy on Linux~~: done; three lints from clippy 0.1.99 fixed (`7fb4008`).
6. ~~Independent review of `aaa7d0a`, `53dac93` and `b46a075`~~: done; fixes in `9d6dba6`.
7. ~~Performance at the import limits, final regression on Windows and Linux, report~~: done.

Third segment (from 2026-11-09T08:51Z): all done.
1. Path-level scope (`80f34de`), its independent review and fixes (`8355745`).
2. Linux GUI verification of every listed area, on Ubuntu 24.04.5 and Debian 12.
3. Reliability: encodings (`e326ace`), evidence integrity (`aa4d17d`), atomic finding creation (`96fe970`).
4. Cross-module audit and fixes (`96fe970`, `d26f799`, `ce76bfa`, `7e74883`).
5. Imported CVEs as vulnerabilities (`6860814`).
6. Two new dependency advisories (`0641a0e`).

The remaining candidates and the owner's decisions are in MISSION_REPORT.md ("Remaining release blockers"):
* refusing redirect flags of external tools on path-only scopes;
* one report model for HTML and Markdown;
* notes on assets;
* a foreign-key-off migration mode.

Release steps (installers, signing) need the owner's authorization.

## Resume instruction

1. Read this file, `FEATURE_BACKLOG.md` and `IMPLEMENTATION_LOG.md`.
2. Run `git log --oneline -15` and `git status`.
3. Continue with the first backlog item that is not marked done. Verify each change with these commands:

   ```
   cargo test
   cargo clippy --all-targets -- -D warnings
   npx tsc -b --noEmit
   npx vitest run
   ```

4. Never build installers or publish anything.
