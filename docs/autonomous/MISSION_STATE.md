# Mission state: autonomous research and development mission

This file lets a new session resume the mission accurately. Times are UTC and measured with `date -u`.

| Item | Value |
|---|---|
| Mission start | 2026-11-08T21:31:01Z |
| Branch | `release/v0.1.0` |
| HEAD at start | `092e092` (plus 27 uncommitted QA-audit paths) |
| Current phase | **Complete** (Mission 2, 2026-11-09T16:31:14Z–20:05Z: ten research-driven capabilities, schema unchanged at 21, see MISSION_REPORT.md "Mission 2". Feature expansion round 2026-11-09T13:31Z–16:30Z: seven new capabilities in the six areas the owner named, schema 21; it comes after RC0, which does not cover it. RC0 release-candidate validation 2026-11-09T12:16Z–13:30Z: **ready for a release-candidate build**, not yet for final release authorization. Fourth segment 2026-11-09T11:28:28Z–12:20Z: final pre-release hardening. Earlier segments: 2026-11-08T21:31:01Z–23:43Z, 2026-11-09T06:32:12Z–08:07Z and 08:51:44Z–11:05Z). See [MISSION_REPORT.md](MISSION_REPORT.md) |

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

## Tests executed

See [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md).

## Known failures

None. At `a7b0368` (Mission 2, Windows 11): 459 Rust tests (6 ignored) and 258 frontend tests in 45 files; `cargo clippy --all-targets -- -D warnings`, tsc, cargo audit (0 vulnerabilities in 640 crates, 8 allowed warnings), npm audit (0) and gitleaks over the mission's commits are clean; `cargo +1.90.0 check --locked --all-targets` passes; every new capability passed its check in the real app (174 of 174). **Not run for Mission 2:** the Linux suites and Linux GUI checks.

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
| (this report) | docs(mission): report mission 2 |

## Next action

**After Mission 2 (2026-11-09T20:05Z), the owner decides:**
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
