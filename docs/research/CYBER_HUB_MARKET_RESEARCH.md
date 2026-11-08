# Cyber Hub market and user-demand research

* **Research date.** 2026-11-08.
* **Method.** Three research tracks ran in parallel with live web access:
  1. **Community demand:** Reddit, Hacker News and practitioner blogs.
  2. **Competitive products:** 18 tools. The source was public documentation, plus GitHub issues and discussions retrieved through the GitHub API and ranked by reactions.
  3. **Technical formats and standards:** used for implementation and listed in section 6.

  Every link below was opened or returned by a search during the research. Nothing was taken from memory.

**Limitations.**
* reddit.com and old.reddit.com refused automated access. Reddit threads were read through `reddit.sentinel-team.org` snapshots. These show the reddit.com permalinks given below, but they capture only part of each comment thread, and point counts are as of the snapshot.
* There were no relevant r/bugbounty, r/netsec or r/sysadmin results, so bug-bounty evidence rests mostly on blogs.
* Several Reddit threads are posts by people building tools, and some replies look like vendors or bots. These are marked where it matters.
* Reaction counts are a snapshot of open GitHub issues only.
* Vendor figures that appeared only in search snippets (for example Cyver's report-time numbers) are left out.

**How to read the evidence:**
* **User statement:** what practitioners wrote, paraphrased or quoted in under 25 words.
* **Competitive observation:** what a product documents or ships.
* **Technical finding:** from specifications.
* **Hypothesis:** our own engineering judgement.

## 1. Repeated complaints and requests (community)

Themes are ranked by how many independent sources raised them.

| # | Theme | Confidence | Evidence (user statements) |
|---|---|---|---|
| 1 | Report writing and documentation take most of the time. Consistent, client-specific write-ups are the hard part, not the formatting. | High | "90% of the work is in the documentation" (188 pts) and "80% fighting with Microsoft Word formatting": [r/cybersecurity 1skawmu](https://reddit.com/r/cybersecurity/comments/1skawmu/whats_something_about_pentesting_that_isnt/). About 3–4 h per 5-day test *with a knowledge base of default findings*: [r/cybersecurity 1qr9qoy](https://reddit.com/r/cybersecurity/comments/1qr9qoy/how_much_time_do_you_actually_spend_writing/). "30+% is writing reports": [HN 34577532](https://news.ycombinator.com/item?id=34577532); estimates disputed between 40 % and 50 %: [HN 33945818](https://news.ycombinator.com/item?id=33945818). "90% boilerplate": [HN 30674491](https://news.ycombinator.com/item?id=30674491). SOC case documentation "eating more time than actual triage": [r/cybersecurity 1sywuwj](https://reddit.com/r/cybersecurity/comments/1sywuwj/daily_soc_analyst_pain_points/). |
| 2 | Notes and context are scattered across Obsidian, spreadsheets, text files and chat, with no single searchable place per engagement or case. | High | "duct tape … until I'm juggling multiple assessments or need to find something from 6 months ago": [r/AskNetsec 1pch8ds](https://reddit.com/r/AskNetsec/comments/1pch8ds/pentesting_organization/). "the analyst ends up being the integration layer": [r/AskNetsec 1tibs14](https://reddit.com/r/AskNetsec/comments/1tibs14/is_your_investigation_context_still_scattered/). An OSINT newcomer tracks cases in Notepad: [r/OSINT 1t620fn](https://reddit.com/r/OSINT/comments/1t620fn/whats_everyone_using_to_track_thier_osint_caes/). Students: [r/tryhackme 1rz5rfx](https://reddit.com/r/tryhackme/comments/1rz5rfx/how_do_you_organize_your_hackingcybersecurity/). |
| 3 | Scanners are noisy and give no context for prioritization. Users distrust CVSS on its own and want KEV first, then EPSS plus asset criticality. Pentest reports padded with scanner output are criticized. | High | "400+ open findings with no idea what to fix first": [r/cybersecurity 1safq3a](https://reddit.com/r/cybersecurity/comments/1safq3a/we_set_up_vulnerability_scanning_and_now_we_have/). About 20k alerts a week from Splunk and Qualys; replies recommend KEV, EPSS and SSVC: [r/AskNetsec 1swvxgf](https://reddit.com/r/AskNetsec/comments/1swvxgf/anyone_figured_out_how_to_prioritize/). 847 SAST/SCA/DAST findings with no context: [r/ExperiencedDevs 1qu6gw1](https://reddit.com/r/ExperiencedDevs/comments/1qu6gw1/how_do_you_prioritize_800_sastscadast/). "a vuln scan with a nicer PDF": [r/cybersecurity 1tdz9ko](https://reddit.com/r/cybersecurity/comments/1tdz9ko/most_pentest_reports_i_review_are_padded_with/). |
| 4 | Confidentiality of client data. Local or self-hosted tools are preferred, and AI makes the concern sharper. | Medium | Privacy is the most common question about an AI reporting SaaS: [r/Pentesting 1s7uud3](https://reddit.com/r/Pentesting/comments/1s7uud3/looking_for_beta_testers_for_our_pentesting/). Using LLMs without exposing client data: [r/Pentesting 1sjkdzu](https://reddit.com/r/Pentesting/comments/1sjkdzu/what_is_your_current_workflow/). A local, no-cloud report generator: [r/Pentesting 1reozfw](https://reddit.com/r/Pentesting/comments/1reozfw/report_generator_wip/). TCM Security on trusting third-party note services: [tcm-sec.com](https://tcm-sec.com/the-best-apps-for-keeping-notes-pros-cons/). |
| 5 | SOC enrichment fatigue: pivoting across VirusTotal, AbuseIPDB, Shodan and URLScan tabs. Inconsistent defang conventions are documented. | Medium (enrichment), low (defang) | "it's context switching": [r/cybersecurity_help 1shhaau](https://reddit.com/r/cybersecurity_help/comments/1shhaau/soc_analysts_what_sources_do_you_actually_use_for/). Defang variants break refanging: [IETF draft-grimminck-safe-ioc-sharing-02](https://www.ietf.org/archive/id/draft-grimminck-safe-ioc-sharing-02.html). |
| 6 | Getting scanner output (Nessus, Nmap, Burp, Nuclei) into one place you can query. The request dates back to at least 2007. | Medium | Nuclei import requested and not in core: [sysreptor#584](https://github.com/Syslifters/sysreptor/issues/584); more importers requested: [sysreptor#371](https://github.com/Syslifters/sysreptor/issues/371). "a dozen output files in different formats that you need to manually consolidate": [r/Pentesting 1s6xxc9](https://reddit.com/r/Pentesting/comments/1s6xxc9/building_a_recon_automator_for_pentesting/). Loading big scans into a database so testers can mark ports reviewed: [r/Pentesting 1sllx9i](https://reddit.com/r/Pentesting/comments/1sllx9i/do_other_pentest_teams_struggle_with_this_as_well/). Merging Nessus, Nmap and WebInspect (2007): [seclists](https://seclists.org/basics/2007/May/529). |
| 7 | Recon overload: deduplication and "what is new since the last run". | Medium (mostly blogs) | [Vidoc blog](https://blog.vidocsecurity.com/blog/why-good-recon-is-hard-and-how-we-make-it-easy); hakluke moved from text files to Postgres: [Detectify Labs](https://labs.detectify.com/2021/11/30/hakluke-creating-the-perfect-bug-bounty-automation/); git history as change detection: [Bugcrowd](https://www.bugcrowd.com/resources/levelup/implementing-recon-over-time/); [ProjectDiscovery](https://projectdiscovery.io/blog/building-one-shot-recon/). |
| 8 | Evidence: timestamped command logs and screenshots, for example when a client blames the tester for account lockouts. | Medium | [TrustedSec workflow improvements](https://trustedsec.com/blog/workflow-improvements-for-pentesters); a vendor pitch about terminal screenshots: [HN 44564451](https://news.ycombinator.com/item?id=44564451). |
| 9 | Methodology checklists and test-coverage tracking. Few complaints, many home-built tools. | Low–medium | A YAML checklist tool: [r/Pentesting 1rvo5kj](https://reddit.com/r/Pentesting/comments/1rvo5kj/i_created_a_new_dynamic_pentesting_checklist_tool/); coverage tracked in spreadsheets: [r/AskNetsec 1pch8ds](https://reddit.com/r/AskNetsec/comments/1pch8ds/pentesting_organization/). |
| 10 | Retests and remediation verification. | Low | "We retest our findings after they are marked as complete": [r/Pentesting 1s8ojvg](https://reddit.com/r/Pentesting/comments/1s8ojvg/best_practice_for_corporate_pentest_teams/). Keep reproduction notes because retests come later, and clients sometimes claim fixes that were not made: [PentesterLab](https://pentesterlab.com/blog/retesting). |

## 2. Competitive observations

Products are research references only. No code, assets or interface was copied.

| Product | Relevant capabilities | Requested features with evidence |
|---|---|---|
| Dradis | Methodology checklists, Issue Library, Rules Engine, CVSS v4/DREAD/ATT&CK calculators, Remediation Tracker; about 20 importers plus a CSV importer ([integrations](https://dradis.com/integrations/)) | (no open CE issues) |
| Faraday | Vulnerability KB templates, automatic merge of duplicates, 80+ tool plugins including SARIF and Nuclei ([faraday_plugins](https://github.com/infobyte/faraday_plugins)) | SARIF [#422](https://github.com/infobyte/faraday/issues/422) and Nuclei [#468](https://github.com/infobyte/faraday/issues/468), both delivered |
| Ghostwriter | Finding and observation libraries, oplog linked to evidence, CVSS v4 calculator ([wiki](https://www.ghostwriter.wiki/)) | Retesting and custom statuses [#242](https://github.com/GhostManager/Ghostwriter/issues/242); bulk actions [#616](https://github.com/GhostManager/Ghostwriter/issues/616) |
| SysReptor | Multilingual finding templates, CVSS 4.0, retest statuses, notes; scan import through the reptor CLI and a Pro plugin ([docs](https://docs.sysreptor.com/)) | Nuclei import [#584](https://github.com/Syslifters/sysreptor/issues/584); a hosts/targets database [#449](https://github.com/Syslifters/sysreptor/issues/449); moving a finding with its images [#524](https://github.com/Syslifters/sysreptor/issues/524); templates [#653](https://github.com/Syslifters/sysreptor/issues/653) |
| PwnDoc / PwnDoc-ng | CVSS v3/v4, retest and multi-audit workflows ([pwndoc](https://github.com/pwndoc/pwndoc)) | CVSS 4.0 [pwndoc-ng#279](https://github.com/pwndoc-ng/pwndoc-ng/issues/279) (11 reactions) and [#267](https://github.com/pwndoc-ng/pwndoc-ng/issues/267) (7); templates [pwndoc-ng#412](https://github.com/pwndoc-ng/pwndoc-ng/issues/412), [pwndoc#485](https://github.com/pwndoc/pwndoc/issues/485); retest [pwndoc#501](https://github.com/pwndoc/pwndoc/issues/501) |
| Caido | Findings with a dedupe key; workflows ([documentation repo](https://github.com/caido/documentation)) | Path-level scope [#642](https://github.com/caido/caido/issues/642) (66); compare requests and responses [#164](https://github.com/caido/caido/issues/164) (24); project notes [#214](https://github.com/caido/caido/issues/214) (18) |
| OWASP ZAP | Automation framework; reports in many formats including SARIF ([report generation](https://www.zaproxy.org/docs/desktop/addons/report-generation/)) | Apply context and exclusions on import [#8021](https://github.com/zaproxy/zaproxy/issues/8021) |
| Greenbone / OpenVAS | Overrides for false positives; delta reports (new, gone, same, changed); remediation tickets verified automatically by a rescan ([GSM manual](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html)) | n/a |
| MISP / OpenCTI | Freetext IOC import, warninglists, STIX export ([MISP features](https://www.misp-project.org/features/), [OpenCTI import](https://docs.opencti.io/latest/usage/import-files/)) | Create an event from freetext [MISP#3656](https://github.com/MISP/MISP/issues/3656); exclusion lists [OpenCTI#7285](https://github.com/OpenCTI-Platform/opencti/issues/7285) |
| CyberChef | Defang/Fang URL and IP, Extract IPs/URLs/domains/hashes ([repo](https://github.com/gchq/CyberChef)) | Desktop app [#1074](https://github.com/gchq/CyberChef/issues/1074), CLI [#1046](https://github.com/gchq/CyberChef/issues/1046) |
| TheHive | Task templates, case timeline ([docs](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/case-timelines/view-case-timeline/)) | Task library [#1191](https://github.com/TheHive-Project/TheHive/issues/1191); case notes [#1041](https://github.com/TheHive-Project/TheHive/issues/1041) (TheHive 4, archived repository) |
| Nuclei / ProjectDiscovery | `-report-db` deduplication, `-redact`; the cloud version has retest and regression scans ([OSS vs cloud](https://docs.projectdiscovery.io/cloud/ossvscloud)) | weak signal |
| Trivy, BloodHound CE, SpiderFoot, Recon-ng | SARIF output (Trivy); attack-path graph (BloodHound); correlation rules (SpiderFoot); workspaces (Recon-ng) | KEV flag idea [trivy#10706](https://github.com/aquasecurity/trivy/discussions/10706); notes on owned objects [BloodHound#237](https://github.com/SpecterOps/BloodHound/issues/237) |

## 3. Existing Cyber Hub coverage (verified in the code, 2026-11-08)

* **Covered:**
  * projects with scope engine and exclusions;
  * assets with discovery snapshots and change comparison (theme 7);
  * findings lifecycle with history;
  * vulnerabilities with transparent KEV/EPSS/exposure/criticality priority (theme 3);
  * evidence vault with SHA-256 (theme 8);
  * tool runs with redacted, timestamped output (theme 8);
  * timeline;
  * HTML/Markdown reports;
  * workflows;
  * OSINT graph;
  * threat intelligence across 7 providers in one search (theme 5);
  * IOC correlation over project data;
  * local-first storage with no telemetry (theme 4);
  * a Claude assistant with credential redaction.
* **Absent:**
  * import of other tools' output (theme 6);
  * finding templates (theme 1);
  * a CVSS calculator for findings;
  * methodology checklists (theme 9);
  * IOC extraction and defang/refang (theme 5);
  * STIX export;
  * verification of fixes by a rescan (theme 10).

## 4. Product gaps and approaches

| Gap | Approach in Cyber Hub (hypothesis) | Security implications | Complexity | Expected value | Confidence |
|---|---|---|---|---|---|
| Scanner-output import (Nmap, Nuclei, Nessus, Burp, ZAP, SARIF) | Parse locally into findings and assets, check scope, deduplicate by fingerprint across imports, keep false-positive decisions, store the file as evidence | Untrusted XML/JSON: no entity expansion (XXE), size and count limits, redaction of copied text, scope gate for every target | Medium-high | High (themes 3, 6) | High |
| Finding templates | A local library of reusable write-ups (description, remediation, references, CWE, severity). Apply when recording a finding; save a finding as a template; apply automatically to imported findings that match a rule | Plain text only; escaped in reports as now | Medium | High (theme 1) | High |
| Fix verification by rescan | When a later import of the same tool covers the same hosts and no longer reports a finding, list it as "not reported again". It can be resolved with a verification note | Must not resolve findings whose host the new file did not cover | Medium | Medium (theme 10) | Medium |
| CVSS 3.1 and 4.0 calculator on findings | A vector field on findings, a calculator dialog, the computed score and a suggested severity | Pure computation; must follow the FIRST specification exactly | Medium | Medium | High |
| IOC extraction, defang/refang, STIX 2.1 export | A utility that extracts indicators from pasted text (refanging first), defangs for sharing, sends to Threat Intel, and exports a STIX 2.1 bundle of a project's indicators | Local only; exports through native dialogs | Low-medium | Medium (theme 5) | Medium |
| Methodology checklists | OWASP WSTG-based checklist per project with status per test | License of WSTG content (CC BY-SA 4.0) must be respected | Medium | Medium (theme 9) | Medium |
| Notes on any entity | Already partly present (project notes, finding history notes) | — | — | Low-medium | — |

## 5. Prioritization

The scored backlog is in [../autonomous/FEATURE_BACKLOG.md](../autonomous/FEATURE_BACKLOG.md).

## 6. Technical findings

Format and standard details used for the implementation are recorded with the code and in [DATA_MODEL.md](../DATA_MODEL.md). The specification research that backs them is summarized in the backlog entries.

## 7. Sources examined

**Community:**
* reddit.com threads listed in section 1;
* the snapshots read at `reddit.sentinel-team.org/posts/<id>/snapshots/...` for ids 1qr9qoy, 1skawmu, 1s7uud3, 1tdz9ko, 1s6xxc9, 1s8ojvg, 1qor7af, 1pch8ds, 1rz5rfx, 1s3upsl, 1sywuwj, 1re6kdc, 1tibs14, 1shhaau, 1sllx9i, 1s6qldx, 1swvxgf, 1s1eq9d, 1safq3a, 1qu6gw1, 1sjkdzu, 1reozfw, 1rvo5kj, 1t620fn, 1rdzz39 and 1s03xnk;
* Hacker News items 33945818, 34577532, 30674491 and 44564451;
* trustedsec.com, tcm-sec.com, blog.vidocsecurity.com, labs.detectify.com, bugcrowd.com, projectdiscovery.io, pentesterlab.com, seclists.org and the IETF draft above.

**Competitive:**
* dradis.com: integrations, CE and the remediation add-on;
* github.com/infobyte/faraday and faraday_plugins, docs.faradaysec.com;
* ghostwriter.wiki and the Ghostwriter changelog;
* docs.sysreptor.com, including the CLI and plugins pages, and the sysreptor scanimport plugin source;
* github.com/pwndoc/pwndoc and pwndoc-ng;
* github.com/caido/documentation;
* zaproxy.org: report generation, automation framework, import/export;
* portswigger.net: Organizer and scan reporting;
* github.com/smicallef/spiderfoot and the Recon-ng wiki;
* docs.opencti.io: import and export;
* docs.strangebee.com: TheHive case reports and timelines;
* misp-project.org features;
* github.com/gchq/CyberChef;
* trivy.dev: reporting and VEX;
* docs.projectdiscovery.io;
* bloodhound.specterops.io;
* docs.greenbone.net reports.

All issue and discussion links are given inline.
