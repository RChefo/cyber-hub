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
| 11 | Path-level scope rules | 4 | 3 | 3 | 3 | 2 | 4 | 33 | Deferred: changes the security-critical scope engine; needs its own design and review |
| 12 | User-facing database backup and restore | 2 | 3 | 4 | 3 | 3 | 4 | 30 | **Done**: on-demand checked backup (`4a320a8`); restore in the app with a restart-time swap that keeps the previous database and its evidence (`2eb4209`) |
| — | Jira or ticketing integration | 2 | 2 | 1 | 3 | 2 | 2 | — | Rejected: needs external accounts and credentials, and does not fit local-first |
| — | Collaborative or multi-user editing | 2 | 2 | 1 | 2 | 1 | 2 | — | Rejected: needs server infrastructure |
