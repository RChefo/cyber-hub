# Mission state: autonomous research and development mission

This file lets a new session resume the mission accurately. Times are UTC and measured with `date -u`.

| Item | Value |
|---|---|
| Mission start | 2026-11-08T21:31:01Z |
| Branch | `release/v0.1.0` |
| HEAD at start | `092e092` (plus 27 uncommitted QA-audit paths) |
| Current phase | **Complete** (third segment 2026-11-09T08:51:44Z–11:05Z: path-level scope, Linux GUI, reliability and cross-module audits. Earlier segments: 2026-11-08T21:31:01Z–23:43Z and 2026-11-09T06:32:12Z–08:07Z). See [MISSION_REPORT.md](MISSION_REPORT.md) |

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

## Tests executed

See [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md).

## Known failures

None. The final results at `0641a0e`:
* **Windows:** 351 Rust tests (355 with provisioning) and 224 frontend tests.
* **Ubuntu 24.04.5 and Debian 12:** 351 Rust tests and all 36 frontend test files.
* **Static checks:** clippy (0.1.94 and 0.1.99), tsc, the build, the audits and gitleaks are clean.
* **Real GUI:** 62 of 62 checks on Ubuntu and on Debian; the Windows smoke covered every page and project tab.

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

## Next action

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
