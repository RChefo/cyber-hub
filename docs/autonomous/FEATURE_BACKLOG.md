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
| 4 | CVSS 3.1 and 4.0 calculator on findings: vector, score, suggested severity | 4 | 3 | 4 | 5 | 3 | 5 | 39 | Next |
| 5 | IOC extraction, defang and refang utility; STIX 2.1 export of project indicators | 3 | 3 | 4 | 5 | 4 | 5 | 37 | Planned |
| 6 | OpenVAS / Greenbone XML import | 3 | 3 | 5 | 4 | 3 | 5 | 37 | Planned (small) |
| 7 | Findings export: CSV and JSON | 2 | 3 | 5 | 5 | 5 | 5 | 37 | Planned (small) |
| 8 | Bulk edit of tags and assignee on findings | 2 | 3 | 5 | 5 | 5 | 5 | 37 | Planned (small) |
| 9 | Methodology checklists (OWASP WSTG) with coverage per project | 3 | 4 | 3 | 5 | 3 | 4 | 35 | Planned |
| 10 | Notes on assets and vulnerabilities | 3 | 3 | 3 | 5 | 3 | 4 | 33 | Deferred: finding history notes and project notes cover part of it |
| 11 | Path-level scope rules | 4 | 3 | 3 | 3 | 2 | 4 | 33 | Deferred: changes the security-critical scope engine; needs its own design and review |
| 12 | User-facing database backup and restore | 2 | 3 | 4 | 3 | 3 | 4 | 30 | Deferred: restoring while running needs a restart-time swap; upgrade backups already exist |
| — | Jira or ticketing integration | 2 | 2 | 1 | 3 | 2 | 2 | — | Rejected: needs external accounts and credentials, and does not fit local-first |
| — | Collaborative or multi-user editing | 2 | 2 | 1 | 2 | 1 | 2 | — | Rejected: needs server infrastructure |
