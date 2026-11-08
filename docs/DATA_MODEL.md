# Project data model (schema 16)

Migration 9 adds the shared data layer that the attack-surface, vulnerability, workflow, analysis and engagement features build on. It changes no existing data except finding statuses (see the mapping below). The logic lives in `src-tauri/src/workspace/`. The Tauri commands are in `commands/workspace.rs` (plus the finding commands in `commands/projects.rs`).

```
projects ─┬─ project_targets ── scope_events          (scope and its audit trail)
          ├─ findings ─┬─ finding_events             (lifecycle and change history)
          │            └─ finding_links ──▶ assets | executions | evidence | osint_entities
          ├─ assets ── asset_observations ──▶ discovery_snapshots
          ├─ evidence ──▶ executions | osint_evidence | <app data>/evidence/<ab>/<sha256>
          └─ timeline_events                         (events with no table of their own)
```

Every table has a `project_id` foreign key that cascades when the project is deleted. Links to records in other tables are set to `NULL` when that record is deleted (for example a run, an OSINT entity or a snapshot), so the referring row survives.

## Findings

| Field | Notes |
|---|---|
| `status` | `new`, `under_review`, `confirmed`, `accepted_risk`, `in_remediation`, `resolved`, `reopened`, `false_positive` |
| `category`, `confidence` (`low`/`medium`/`high`), `reproduction`, `technical_details`, `remediation` | added in schema 9; empty / `medium` for existing findings |
| `source` | who recorded it: `user`, `mcp`, `osint`; `manual` for findings recorded before schema 9 |
| `tags` (JSON list, ≤ 20, deduplicated), `assignee`, `due_date` (`YYYY-MM-DD`) | stored now; edited in the Findings Manager (phase 3) |
| `evidence` | the free-form `{label, reference}` list of earlier versions, kept as it is |

**Open** findings are those with status `new`, `under_review`, `confirmed`, `in_remediation` or `reopened` (`OPEN_SQL` in the backend, `OPEN_FINDING_STATUSES` in `src/lib/findings.ts`). Project counts, the dashboard and the overview use this definition.

**Lifecycle rule.** Any status can change to any other, except that `reopened` is only possible from a closed status (`resolved`, `false_positive`, `accepted_risk`). An unchanged status is not a change.

**Older clients.** The status names `open` and `reported` of release 0.1 are still accepted on input and stored as `new` and `confirmed`. MCP clients and saved forms keep working. Fields added in schema 9 are optional on input.

**History** (`finding_events`, append-only): `created`, `status` (from → to, with an optional reason), `updated` (the names of the changed fields), `note`, `link`/`unlink`, and `migrated`. Each event records its `source`. Saving a finding without changes records nothing. Deleting a finding deletes its history and adds a "Finding deleted" entry to the project timeline.

**Links** (`finding_links`, unique per finding, kind and record) point to an asset, a tool run, an evidence record or an OSINT entity. The linked record must belong to the finding's own project. For an OSINT entity, that means its investigation is linked to the same project. `vulnerability` is reserved for phase 3 and refused until then. Deleting an asset or an evidence record removes its links. A link whose record was deleted in another way shows as missing (`label: null`) instead of failing.

## Scope history

`project_target_add` and `project_target_delete` write `scope_events` in the same transaction as the change:

* `added`, `updated` (scope flag or note changed), and `removed`; re-adding an unchanged entry records nothing.
* `blocked`: an active operation refused by the scope gate, with the reason and the operation name.

Existing scope entries were recorded as `added` (source `migration`) with their original creation time.

## Scope gate

`workspace::scope_gate` is the single scope decision for new operations:

* **Active** (the operation contacts the target): needs a project with status `active`, at least one in-scope entry, and every target inside the scope. Exclusions always win. The same `scope.rs` engine as tool runs is used, so the same bypass protections apply: look-alike hosts, user-info URLs, numeric and IPv4-mapped addresses, and ranges wider than the scope.
* **Passive** (only public sources are asked): private, loopback, link-local and reserved addresses and internal or single-label names are refused, and the project's explicit exclusions are respected. The project does not need to be active.

`decide` explains a decision without side effects (command `scope_decide`). `enforce` refuses with a `scope` error and records blocked active attempts. Tool runs keep their own stricter path (`targets.rs`: arguments and target files, snapshots).

## Assets

One row per real asset: `UNIQUE(project_id, type, key)`, where `key` is the normalized value.

| Type | Normalized key |
|---|---|
| `domain`, `subdomain` | lower-case ASCII (IDNA) name without trailing dot (`osint/normalize.rs`) |
| `ip` | canonical address (IPv4-mapped IPv6 becomes IPv4) |
| `service` | `host:port/proto` (`tcp` default, `udp`), IPv6 in brackets |
| `http_service` | origin (`scheme://host[:port]`) |
| `endpoint` | URL without fragment; URLs with credentials are refused |
| `dns_record` | `name TYPE value` (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA) |
| `certificate` | SHA-256 fingerprint, 64 hex digits |
| `technology` | name (case-insensitive) |

The status is `active`, `not_observed` or `retired`. *Not observed* never means deleted. Seeing a `not_observed` asset again makes it active; a `retired` asset stays retired. Confidence only rises. Each refresh records an observation (`asset_observations`, with a fingerprint of the data). Within a discovery snapshot every observation is kept, so snapshots can be compared. Outside a snapshot, an identical consecutive observation is not repeated. Assets reference OSINT entities by id instead of copying them. Upserts run in a savepoint, and the unique key guarantees one record even under concurrent writers.

`discovery_snapshots` group the observations of one discovery run (`passive`, `active`, `manual`). They record their status (`running` → `completed`, `partial`, `failed`, `cancelled`) and their operation or run.

## Attack surface discovery

Projects → *Attack surface* fills the asset inventory from three kinds of runs. Each run is one discovery snapshot; the code is `workspace/discovery.rs` and `commands/discovery.rs`.

| Run | What it does | Contacts the target | Gate |
|---|---|---|---|
| Passive discovery (`passive`) | certificate transparency (crt.sh, cached 24 h) for every in-scope domain, wildcard base and URL host (at most 20), then DNS (A, AAAA, CNAME, NS, MX) for the names found (at most 300) | no | scope gate, passive: internal names are never sent; names outside the scope (or excluded) are counted and not recorded |
| Web services check (`http`) | `GET /` over HTTPS and HTTP on in-scope hosts (at most 100); no redirects followed, no credentials, at most 64 KB read for the title; an untrusted certificate is retried and recorded as such | yes | scope gate, active; native confirmation listing the hosts |
| Service scan (`nmap`) | `nmap -sV -T3 [-F] -oX - <targets>` through the normal tool execution path (scope check of every argument, native confirmation of the exact command, process tree, stored output); the XML on standard output is parsed when the run ends | yes | scope gate, active, then the execution engine's own checks |

One background run (passive or web check) per project runs at a time and can be cancelled. Progress is reported through the `asm-changed` event. A run interrupted by closing Cyber Hub is marked failed at the next start.

**Certainty.** Every recorded item carries one: `confirmed` (the target answered: an HTTP response, a host up or an open port), `observed` (a public source reported it and DNS corroborates it), `possible` (a single unverified report, for example a certificate name that does not resolve). Asset confidence follows it (high, medium, low) and only rises.

**Changes.** A run is compared with the previous finished or partial run of the same kind: items are *new*, *changed* (their recorded data differs) or *missing*. A missing item is `possible` after a completed run and `incomplete` after a partial, failed or cancelled run.

**Not observed.** Only a *completed* run marks assets as not observed, and only those it covered:
* passive runs cover names, addresses and DNS records that an earlier passive run recorded;
* web checks cover the web services of the hosts they checked;
* service scans cover the services of hosts that were up.

Assets recorded by hand are never marked. Nothing is deleted.

**Results.**
* Passive runs record names, addresses and DNS records. Addresses are flagged `inScope` and `nonPublic`, so the inventory shows when a name points outside the authorized scope.
* Web checks record web services (status, title, server, certificate trust) and technologies announced in the headers that name software (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-Varnish`, `Via`). Before November 2026 other headers were parsed too, so older inventories can hold entries such as `GMT` or `text/html`; the comparison of the next web check lists them as missing, but their status stays active (web checks only decide about web services), so retire them by hand.
* Service scans record addresses, open services (service, product, version) and products as technologies.

## Vulnerabilities (schema 10)

`vulnerabilities` tracks a CVE per project, optionally for one asset. There is one record per project, CVE and asset; the same CVE without an asset is a separate record. Projects → *Vulnerabilities*; the code is `workspace/vulns.rs` and `commands/vulns.rs`.

* **Data sources.** CVSS and the CISA KEV flag come from the NVD record: the local CVE cache first, otherwise one NVD lookup. EPSS comes from FIRST.org (`api.first.org/data/v1/epss`, only CVE IDs are sent, cached 24 h in `epss_cache`). It can be turned off with *Use EPSS*, stored as `epss.enabled`. Missing data never blocks tracking; the priority states what was missing.
* **Priority** is computed only from these factors, and every factor is stored with its contribution:

  | Factor | Contribution |
  |---|---|
  | CVSS base score (newest version, NVD's own first) | the score; 5.0 when unknown |
  | Listed in CISA KEV, or exploitation known (analyst) | +2 (not both) |
  | EPSS probability | +2 at ≥ 50 %, +1 at ≥ 10 %, +0.5 at ≥ 1 %; stated as not available otherwise |
  | Exposure | internet +1, unknown +0.5, internal 0 |
  | Asset criticality | high +1, medium 0, low −1 |

  P1 from 11, P2 from 8.5, P3 from 6, otherwise P4. Exposure defaults from the asset: private addresses are internal, public names and addresses internet-facing. A changed level is recorded in the history with its reasons.
* **Lifecycle.** `open`, `triaged`, `in_remediation` (these need work), `mitigated`, `resolved`, `accepted_risk`, `false_positive`. Accepting a risk or dismissing a vulnerability needs a written reason.
* **Remediation.** Each vulnerability has a plan, an owner and a due date; an open vulnerability past its due date is shown as overdue.
* **Verification.** Recording how a fix was confirmed sets `verified_at` and the status `resolved`. Reopening clears the verification.
* **History** (`vulnerability_events`, append-only): `created`, `status`, `priority`, `remediation`, `verification`, `updated`. It appears on the project timeline (`vulnerability`, and `remediation` for plans and verifications).
* **Findings.**
  * *Create finding* records a finding with the CVE, severity from CVSS, the priority reasons and the remediation, linked to the vulnerability and its asset.
  * Finding links of kind `vulnerability` are now accepted (same project only).
  * Deleting a vulnerability removes its links and leaves a timeline entry.
* **Updating scores** re-reads the CVE cache (at most 5 NVD lookups for CVEs without a record) and EPSS for open vulnerabilities, then recomputes priorities.

## Findings manager

Projects → *Findings* provides:
* search (title, target, CVE, category, assignee, description) and filters by tag, severity and status;
* tags, assignee and due date in the editor;
* history and links per finding, with notes;
* bulk status changes. `findings_bulk_status` changes each selected finding on its own with the lifecycle rule, records every change, and reports the findings it left unchanged instead of failing.

## Engagement workspace (schema 12)

* **Engagement details.** Projects have engagement details: client, engagement type, written authorization reference, objectives, methodology and contacts. Existing projects get empty values. The project form edits them, the overview shows them (with a warning when no authorization reference is recorded), and both reports include them. Every save of a project carries the fields, so editing notes or the status never clears them.
* **Scope manager.** The Scope tab adds a *Test targets* panel (the scope gate's decision for active or passive use, without contacting anything) and the scope history (additions, changes, removals and refused active operations).
* **Evidence vault.** The Evidence tab manages the evidence registry:
  * add files (native dialog), text notes and tool runs;
  * view notes, save copies of files, delete;
  * link evidence to findings.

  The free-form references kept in findings are listed below the vault.
* **Timeline tab.** The project timeline is grouped by day, can be filtered by event type, and pages back through older events.
* **Report builder.** The Report tab produces an HTML report with a live preview (sandboxed frame).
  * Options: title, author, classification, executive summary, minimum severity, closed findings, and sections (scope, findings, vulnerabilities, assets, evidence register, timeline).
  * Content: per finding, the description, reproduction, technical details, remediation and evidence, including the SHA-256 of linked files.
  * Output: *Print or save as PDF* uses the system web view's print dialog (decision 3; no PDF library). *Save as HTML* writes the file through a native save dialog. *Keep a copy in the evidence* stores the HTML as text evidence.
  * Safety: the backend escapes all content, and the document has its own Content-Security-Policy (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'`). The print frame may not run scripts.
  * Exports, prints and saved copies appear on the timeline (`report`). The Markdown report (header button, MCP) is unchanged apart from the engagement details.

## Scan import (schema 13)

Projects → *Findings* → *Import results* reads the output of other tools into the project (`workspace/scan_import.rs`, commands in `commands/workspace.rs`). Reading a file never contacts anything.

| Format | Recognized by | Findings | Assets |
|---|---|---|---|
| Nmap XML (`-oX`) | `<nmaprun>` root | none | up hosts, their names, open ports as services, products as technologies |
| Nuclei (`-jsonl`, or the JSON list of `-json-export`) | `template-id` field | one per template, matcher and location; `info.severity`, CVE and CWE from `info.classification`, references, remediation, extracted values | web service (origin), address, technology for `tech` templates |
| Nessus v2 (`.nessus`) | `<NessusClientData_v2>` root | one per plugin, host and port; `severity` 0–4, synopsis and description, solution, `see_also`, CVEs, plugin output | address, name (`host-fqdn`), services |
| Burp Suite issue export (XML) | `<issues>` root | one per issue; severity, confidence (Certain/Firm/Tentative), detail and background, remediation, CWE, references, the request line | web service, address |
| OWASP ZAP JSON report | `site` list | one per alert and site, with up to 25 instances; risk code, confidence, CWE, references | web service |
| Greenbone / OpenVAS report (GMP XML) | `<report>` root with `<results>` | one per NVT, host and port; `threat` High/Medium/Low/Critical, Log as informational, False Positive and Debug skipped; results with a quality of detection below 70 % left out (Greenbone's default filter); summary, insight and impact from the NVT tags, the result text, solution, CVEs, URL references, CVSS vector from `severities` | address, name, services |
| SARIF 2.1.0 | `version` 2.1.x and `runs` | one per result; `security-severity` mapped like GitHub code scanning (≥ 9 critical, ≥ 7 high, ≥ 4 medium, > 0 low), otherwise `level` (error high, warning medium, note low) | none (source-code locations have no network target) |

* **Flow.** The file (at most 50 MB, 10,000 findings, 20,000 asset values) is chosen in a native dialog, read and previewed. The preview says what each finding would do: new, already recorded, resolved and reported again, dismissed earlier, outside the scope, or informational (not imported unless selected). Nothing is written until *Import* is pressed. The preview can be used once.
* **Scope.** Every network target is checked against the project scope with the scope engine. Findings and assets outside it are counted and their hosts listed; they are not recorded. A project without in-scope entries records no network results. SARIF results have no network target and are always imported.
* **Deduplication.** `finding_fingerprints` keeps one fingerprint per imported finding (SHA-256 of tool, rule and location; SARIF's `partialFingerprints` when present). A finding reported again is not duplicated: the sighting is added to its history and to `times_seen`. A resolved finding can be reopened (*Reopen resolved findings*, on by default in the preview). A finding marked as a false positive or an accepted risk stays as it is. Repeated results inside one file are merged.
* **Fix verification by rescan (schema 15).** Each fingerprint records the host its finding is about. When a later file of the **same tool** covers a host (it has results or assets for it) but no longer reports an open finding that an earlier import recorded there, the preview lists the finding under *no longer reported*. By default each such finding only gets a history note. *Resolve … this rescan no longer reports* sets them to `resolved` with the note "Verified by rescan". This follows the delta reports of vulnerability scanners. The analyst decides, because a rescan with a narrower policy can also miss a finding. The following findings are never listed: findings on hosts the file does not cover; findings imported before schema 15 (their fingerprints have no host until they are seen again); source-code findings (SARIF); findings that are resolved, accepted or dismissed; and findings from other tools.
* **Records.** New findings have status `new`, source `import`, the tags `imported` and the tool, and the scanner's confidence. They link to the imported file (stored as file evidence with its SHA-256) and to their asset (web service, service or address) when it is in the inventory. Assets are recorded as one discovery snapshot (`manual`, source `import:<format>`); an import never marks other assets as no longer observed. `scan_imports` records each import (format, tool, file name, SHA-256, evidence, snapshot, summary). The timeline and the activity log get one entry per import.
* **What is not copied.** Request and response bodies (Burp, Nuclei), curl commands and cookies stay only in the stored file. Copied text (plugin output, extracted values, evidence strings, the request line) passes through the secret redaction used for tool output. HTML in scanner descriptions becomes plain text.
* **Archived projects** cannot receive imports.

## Finding library (schema 14)

The *Finding Library* page (Workspace group) keeps reusable write-ups in `finding_templates` (`workspace/templates.rs`). Templates belong to the workstation, not to a project, so they carry over between engagements.

| Field | Notes |
|---|---|
| `title` | required, ≤ 200 characters, unique without regard to case |
| `severity`, `category` | as for findings |
| `description`, `remediation` | ≤ 50,000 characters each |
| `refs` | JSON list of ≤ 30 references (URLs or citations), deduplicated |
| `tags` | JSON list of ≤ 20 tags |
| `rules` | JSON list of ≤ 50 import rules `format:rule` (`nmap`, `nuclei`, `nessus`, `burp`, `zap`, `sarif`, `openvas` (the NVT OID); the rule as the tool names it: Nessus plugin ID, ZAP plugin ID, Burp issue type, Nuclei template ID, SARIF rule ID). A rule belongs to one template; rules match without regard to case. |
| `use_count` | how often a finding was written from the template |

* **Recording a finding.** *Start from a template* fills the title, severity, category, description, remediation, references and tags. Fields the template leaves empty keep what was typed. The target, reproduction steps and evidence of the instance are added by hand.
* **Saving a finding as a template** copies its write-up (title, severity, category, description, remediation, URL references, tags) into a new template. Instance details stay with the finding.
* **Scan imports.** A new imported finding whose rule matches a template's import rule is written from the template: its title, severity, category, description and remediation replace the scanner's, references are merged, and tags are added. The finding's target, CVEs and the scanner's evidence (technical details) stay. The finding's history notes the template and rule. The preview counts these findings and lists them, and *Write matching findings from your finding library templates* turns this off for one import. Findings already recorded are never rewritten.
* **Starter templates.** *Add starter templates* adds 14 common findings with import rules for OWASP ZAP, Burp Suite and Nessus: SQL injection, reflected XSS, missing CSP, HSTS, X-Content-Type-Options and clickjacking protection, untrusted certificates, deprecated TLS, SSH CBC ciphers, SMB signing, directory listing, vulnerable components, default credentials and IDOR. It never overwrites a template with the same title. A rule that another template already owns is left out.
* **Library files.** *Export* writes `{"format":"cyberhub-finding-templates","version":1,"templates":[…]}` through a native save dialog. *Import* reads such a file (≤ 5 MB, ≤ 2,000 templates) through a native open dialog. It adds templates whose titles are new, never overwrites existing ones, and reports invalid entries with the reason. The valid entries are added in one savepoint.

## CVSS (schema 16)

Findings can carry a CVSS vector (`findings.cvss_vector`). The backend computes `findings.cvss_score` from it whenever the finding is saved; the web view never supplies a score. The code is in `src-tauri/src/cvss/`.

* **Versions.**
  * **CVSS 4.0** follows FIRST's reference calculator: macrovector equivalence classes, the lookup table (BSD-2-Clause, see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)), and interpolation by severity distance. The arithmetic runs in the reference's order and is rounded like `Math.round`.
  * **CVSS 3.1** follows the specification, including Appendix A's `Roundup`.
  * **CVSS 3.0** vectors are scored with the 3.1 equations. Base scores are the same; 3.1 changed rounding edge cases and the environmental modified impact.
* **Validation.**
  * Every base metric must be present once, and only known metrics and values are accepted.
  * Any order is accepted on input, because FIRST's own examples are not always in order.
  * The stored vector is canonical: specification order, without `X` values.
  * An invalid vector is refused with the reason, and the finding is not saved.
* **Score.** The score covers everything in the vector. For 4.0 the label is `CVSS-B`, `-BT`, `-BE` or `-BTE`; for 3.x it is base, temporal or environmental. The base score is also shown. The qualitative rating uses the standard bands: none 0.0, low 0.1–3.9, medium 4.0–6.9, high 7.0–8.9, critical 9.0–10.0.
* **Severity.** A finding's severity stays the analyst's choice. The form offers *Set severity to …* when it differs from the rating.
* **Calculator.** The finding form has a calculator for the base metrics (and Exploit Maturity for 4.0). It keeps environmental and supplemental metrics that were typed into the vector.
* **Imports.** Nuclei's `classification.cvss-metrics` and Nessus' `cvss4_vector` (else `cvss3_vector`) become the finding's vector when they are valid. Invalid vectors are ignored, but the reported text stays in the description or technical details.
* **Reports.** The HTML and Markdown reports show the score together with its vector, as FIRST asks.
* **Tests.** Tests cover all eight CVSS 4.0 examples in the table of FIRST's examples page, and CVSS 3.1 vectors from the specification's comparisons. Four captions on that page disagree with its own table (CVE-2023-48228, CVE-2016-5729, CVE-2015-2890, CVE-2018-3652); the table values are the calculator's.

## Analysis

Projects → *Analysis* works on stored data only; nothing is contacted (`workspace/analysis.rs`).

* **Exposure paths.** Chains from the network entry through name, address and service or web service to each open vulnerability that has an asset, and on to the findings linked to it. Asset-linked findings without a vulnerability get their own paths. Paths are ranked by vulnerability priority (findings by severity). Names come from DNS records and the address asset's data, and the entry comes from the vulnerability's exposure.
* **Indicator correlation.** Every address, domain (URL hosts included), e-mail and file hash of the project is listed with where it appears: assets, scope entries, finding targets, entities of OSINT investigations linked to the project, and saved indicators. The list includes the verdicts already in the threat-intelligence cache. Indicators are *flagged* when a provider reported them as malicious or suspicious, or an OSINT entity is flagged. Nothing is looked up; new lookups stay on the Threat Intel page with its own rules. The data is computed on demand, not copied into a new table.
* **Run comparison.**
  * Any two discovery runs of the same kind in the same project are compared asset by asset (new, changed, missing, with certainty).
  * Two tool runs are compared line by line on their stored, redacted output: a longest-common-subsequence diff of at most 4,000 lines each, with unchanged stretches reduced to two lines of context. Free text is compared only as text; no meaning is inferred from it.

The project assistant is described in [ASSISTANT.md](ASSISTANT.md).

## Evidence

`evidence` is a registry of four kinds:

| Kind | Content |
|---|---|
| `file` | copied into the store; `sha256`, `size`, `file_name` (display only) |
| `text` | up to 1 MB of text in `content` |
| `execution` | a reference to a tool run of the same project |
| `osint_evidence` | a reference to OSINT evidence of an investigation linked to the same project |

References are never duplicated: there are unique indexes per project for the file hash, the run and the OSINT evidence.

**Store.** Files are content-addressed under `<app data>/evidence/<first two hex digits>/<sha256>`. The backend opens the native file dialog (the web view never supplies a path). It streams the file into `evidence/incoming` while hashing it, enforces the 256 MB limit while reading, and then renames it into place. The original file name is only a label: it never becomes part of a path. Folders that are symbolic links are refused; on Unix the folders are `0700`. A stored file is removed when the last record that refers to it is deleted. At startup, `incoming` and files that no record refers to are removed (this covers interrupted copies and deleted projects). Files are exported through a native save dialog.

## Timeline

`project_timeline` is a query, not a copy. It merges `timeline_events` with tool runs, finding history, scope history, evidence, events of linked OSINT investigations and discovery snapshots. Results are newest first, can be filtered by type (`execution`, `finding`, `scope`, `evidence`, `investigation`, `discovery`, `asset`, `workflow`, `remediation`, `report`, `note`), and are paged by time (`before`).

## Migration 9

* **Findings.** The table is rebuilt (new table, copy, drop, rename) inside the migration transaction. Ids, text, evidence and timestamps are kept, and statuses are mapped:

  | Release 0.1 | Schema 9 |
  |---|---|
  | `open` | `new` |
  | `confirmed` | `confirmed` |
  | `reported` | `confirmed` (with a `migrated` history event) |
  | `resolved` | `resolved` |
  | `false_positive` | `false_positive` |

* **Backfill.** Every existing finding gets a `created` event dated at its creation, and every scope entry an `added` event.
* **Failure.** Migrations run in one transaction. A failure leaves schema 8 and its data untouched, and the next start retries.
* **Tests.** `db.rs` covers a populated schema-8 database, an injected failure followed by a retry, `PRAGMA foreign_key_check`, `integrity_check`, and cascades after the rebuild.
* **Downgrade.** Not supported: release 0.1 cannot write findings to a schema-9 database. The updater never offers downgrades.
