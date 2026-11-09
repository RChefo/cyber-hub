# Project data model (schema 21)

Migration 9 adds the shared data layer that the attack-surface, vulnerability, workflow, analysis and engagement features build on. It changes no existing data except finding statuses (see the mapping below). The logic lives in `src-tauri/src/workspace/`. The Tauri commands are in `commands/workspace.rs` (plus the finding commands in `commands/projects.rs`).

```
projects ─┬─ project_targets ── scope_events          (scope and its audit trail)
          ├─ findings ─┬─ finding_events             (lifecycle and change history)
          │            └─ finding_links ──▶ assets | executions | evidence | osint_entities
          ├─ assets ── asset_observations ──▶ discovery_snapshots
          ├─ evidence ──▶ executions | osint_evidence | <app data>/evidence/<ab>/<sha256>
          └─ timeline_events                         (events with no table of their own)
```

Project records (findings, scope, assets, vulnerabilities, evidence, snapshots, timeline, workflows) have a `project_id` foreign key that cascades when the project is deleted. Tool runs, command history, activity entries and OSINT investigations are not project records: they survive with an empty `project_id`. Columns that refer to a record in another table (a run, an OSINT entity, a snapshot) are set to `NULL` when that record is deleted, so the referring row survives.

What happens to references when a record goes:
* **Project deleted:** refused while a tool run, workflow run or discovery is still running for it, because their results would have nowhere to go. Otherwise one transaction removes everything the project owns. Tool runs and activity entries stay without a project. Evidence files that no other project uses are removed at once, unless a database restore is being sorted (the start-up sweep handles them then). A run whose project is gone when it ends is still recorded, with an activity entry that says so.
* **Asset deleted:** its finding links are removed. Its vulnerabilities are kept for the whole project, each with a history entry; when the same CVE is also tracked for the whole project, the deletion is refused instead, because the two records cannot be merged.
* **Run history cleared:** only finished runs that nothing refers to are removed. Runs that evidence, a finding link, OSINT evidence or a discovery snapshot refers to are kept with their output.
* **OSINT entity deleted:** finding links to it are removed. **Merged:** finding links, the asset it was observed as, and its events move to the kept entity.
* **Investigation deleted:** finding links to its entities are removed, and the linked project's timeline records the deletion.
* **Investigation linked elsewhere:** refused while the linked project still refers to it (finding links to its entities, evidence records of its evidence, assets observed from its entities); otherwise both the investigation and the previous project record the change.

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

**Links** (`finding_links`, unique per finding, kind and record) point to an asset, a vulnerability, a tool run, an evidence record or an OSINT entity. The linked record must belong to the finding's own project. For an OSINT entity, that means its investigation is linked to the same project. Deleting an asset, a vulnerability, an evidence record or an OSINT entity removes its links. A link whose record was deleted in another way shows as missing (`label: null`) instead of failing.

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
* bulk edits of tags and the assignee (*Edit tags or assignee* on a selection). `findings_bulk_edit` adds tags and removes them (matched without regard to case; at most 20 per finding), sets or clears the assignee, saves each finding on its own so that its history records what changed, and reports findings left unchanged;
* export (*Export* → CSV or JSON) of the findings currently listed, in the order shown, through a native save dialog. The backend reads them from the database (`workspace/findings_export.rs`).
  * **CSV** follows RFC 4180 (every field quoted, CRLF line ends) with a UTF-8 byte-order mark, and has 21 columns including the CVSS score and vector and the references. Finding text can come from scanners and so from the assessed systems, so cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading apostrophe and are not read as formulas (CSV injection).
  * **JSON** is `{"format":"cyberhub-findings","version":1,"project":…,"exportedAt":…,"findings":[…]}` with the full finding records.
  * The project timeline records the export.

## Engagement workspace (schema 12)

* **Engagement details.** Projects have engagement details: client, engagement type, written authorization reference, objectives, methodology and contacts. Existing projects get empty values. The project form edits them, the overview shows them (with a warning when no authorization reference is recorded), and both reports include them. Every save of a project carries the fields, so editing notes or the status never clears them.
* **Scope manager.** The Scope tab adds a *Test targets* panel (the scope gate's decision for active or passive use, without contacting anything) and the scope history (additions, changes, removals and refused active operations).
* **Evidence vault.** The Evidence tab manages the evidence registry:
  * add files (native dialog), text notes and tool runs;
  * view notes, save copies of files, delete;
  * link evidence to findings;
  * *Verify* checks every stored file and text against the SHA-256 recorded when it was added, and records the result on the timeline.
* **Tool runs as evidence** are named after their tool and run number when no title is given.

  The free-form references kept in findings are listed below the vault.
* **Timeline tab.** The project timeline is grouped by day, can be filtered by event type, and pages back through older events.
* **Report builder.** The Report tab produces an HTML report with a live preview (sandboxed frame).
  * Options: title, author, classification, executive summary, minimum severity, closed findings, and sections (scope, findings, vulnerabilities, assets, evidence register, timeline).
  * Content: per finding, the description, reproduction, technical details, remediation and evidence, including the SHA-256 of linked files.
  * Output: *Print or save as PDF* uses the system web view's print dialog (decision 3; no PDF library). *Save as HTML* writes the file through a native save dialog. *Keep a copy in the evidence* stores the HTML as text evidence.
  * Safety: the backend escapes all content, and the document has its own Content-Security-Policy (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'`). The print frame may not run scripts.
  * Exports, prints and saved copies appear on the timeline (`report`). The Markdown report (header button, MCP, the workflow `save_report` step) and the HTML report are built from the same data, with the same sections, order and terms:
  1. classification, title and engagement details;
  2. Executive summary: the analyst's summary or the project description, key figures, objectives, methodology, checklist coverage;
  3. Scope, with the rules of engagement;
  4. Findings: open findings only, each with its severity, CVSS vector, CVE, texts and evidence (references, and linked records with their SHA-256). Closed findings and findings below the minimum severity are counted, not listed.
  5. Vulnerabilities;
  6. Assets;
  7. Evidence register;
  8. Timeline (optional).

  Neither format ever includes the project's internal notes or contacts. The Markdown report uses the HTML report's default options. Free text keeps its Markdown formatting, but a `<` that could open HTML outside code is escaped, so imported text cannot become markup in a viewer. Exports and workflow copies appear on the timeline.

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
| CSV with a header row | none of the above, and a first line with at least two named columns separated by commas, semicolons or tabs | one per row, with the columns chosen in the preview (see [CSV findings](#csv-findings)) | addresses and names of the targets |

* **Flow.** The file (at most 50 MB, 10,000 findings, 20,000 asset values) is chosen in a native dialog, read and previewed. The preview says what each finding would do: new, already recorded, resolved and reported again, dismissed earlier, outside the scope, or informational (not imported unless selected). Nothing is written until *Import* is pressed. The preview can be used once.
* **Scope.** Every network target is checked against the project scope with the scope engine, on the value that is stored (a Nuclei finding on its `matched-at` target, each asset on its own host, a Burp address as an address). Findings and assets outside it are counted and their hosts listed; they are not recorded. A network finding whose host cannot be read (for example an invalid port) counts as outside the scope. A project without in-scope entries records no network results. SARIF results with a URL location (DAST tools) are scope-checked like network findings; results with source-code locations have no network target and are always imported.
* **Deduplication.** `finding_fingerprints` keeps one fingerprint per imported finding (SHA-256 of tool, rule and location; SARIF's `partialFingerprints` when present). A finding reported again is not duplicated: the sighting is added to its history and to `times_seen`. A resolved finding can be reopened (*Reopen resolved findings*, on by default in the preview). A finding marked as a false positive or an accepted risk stays as it is. Repeated results inside one file are merged.
* **Fix verification by rescan (schema 15).** Each fingerprint records the host its finding is about. When a later file of the **same tool** covers a host (it has results or assets for it) but no longer reports an open finding that an earlier import recorded there, the preview lists the finding under *no longer reported*. By default each such finding only gets a history note. *Resolve … this rescan no longer reports* sets them to `resolved` with the note "Verified by rescan". This follows the delta reports of vulnerability scanners. The analyst decides, because a rescan with a narrower policy can also miss a finding. Nothing is listed when the file was not read completely (limits reached, a document that breaks off, skipped lines, an unfinished Nmap scan); the preview says so. The following findings are never listed: findings on hosts the file does not cover; findings imported before schema 15 (their fingerprints have no host until they are seen again); source-code findings (SARIF); findings that are resolved, accepted or dismissed; and findings from other tools.
* **Records.** New findings have status `new`, source `import`, the tags `imported` and the tool, and the scanner's confidence. They link to the imported file (stored as file evidence with its SHA-256) and to their asset (web service, service or address) when it is in the inventory. Assets are recorded as one discovery snapshot (`manual`, source `import:<format>`); an import never marks other assets as no longer observed. `scan_imports` records each import (format, tool, file name, SHA-256, evidence, snapshot, summary). The timeline and the activity log get one entry per import.
* **CVEs as vulnerabilities (optional).** *Track N CVEs as vulnerabilities* is off by default.
  * When it is on, each CVE of a new or re-reported finding becomes a vulnerability (source `import`). The vulnerability is tracked for the finding's asset when the asset is in the inventory, otherwise for the project, and it is linked to the finding.
  * A CVE that is already tracked for that asset is linked, not duplicated. Dismissed findings are skipped.
  * Limits: 20 CVEs per finding and 500 per import. The summary says how many were left out.
  * Priorities use the cached NVD record and EPSS, so the import never goes to the network. *Vulnerabilities → Refresh* fetches the rest.
* **What is not copied.** Request and response bodies (Burp, Nuclei), curl commands and cookies stay only in the stored file.
  * **Redaction.** Every copied field (title, target, description, remediation, technical details) passes through the secret redaction used for tool output. It covers credentials in URLs, headers, `key=value` and `key: value` pairs, JWTs, PEM private keys (also cut off), AWS key IDs, and GitHub and Slack tokens.
  * **Cleaning.** Control characters are removed and fields are cut to their limits, so one odd record cannot fail an import whose preview succeeded.
  * **HTML.** HTML in scanner descriptions becomes plain text.
* **Archived projects** cannot receive imports, and MCP clients cannot record findings or checklist results in them (checked when the approval is shown and again when it is carried out). A project's status changes are recorded on its timeline and in the activity log.

### CSV findings

A CSV file can come from a spreadsheet or from a scanner's CSV export (Nessus, Qualys, Greenbone and others). The code is in `workspace/scan_import_csv.rs`.

**Reading the file.** The file is read as RFC 4180:
* quoted values may contain delimiters, `""` and line breaks;
* CRLF or LF line ends; blank lines are skipped; a UTF-8 BOM is ignored;
* the delimiter is whichever of comma, semicolon and tab splits the header row into at least two columns and the next rows into as many, under the same quoting rules (then the most columns; a comma wins a tie);
* at most 200 columns and 50,000 characters per cell are kept.

A file that ends inside a quoted value keeps the rows before it and is marked as not read completely.

**Columns.** The preview shows the eleven fields and the column each one is read from: title (required), severity, target, port, description, remediation, CVE, CVSS, rule ID, references and technical details. The columns are suggested from the header names; for example *Name* or *Title*, *Risk* or *Severity*, *Host*, *IP* or *URL*, *Plugin ID* or *QID*, *Solution*, *See Also*, and *Plugin Output* or *Results*. Changing a column reads the file again (`scan_import_remap`) and refreshes the preview.

**Values:**
* **Severity** is read per column:
  * words (critical, high, medium or moderate, low, info, none, log);
  * whole numbers 1 to 5 as levels, as Qualys uses them (5 critical, 4 high, 3 medium, 2 low, 1 informational);
  * numbers with decimals, or above 5, as CVSS scores (≥ 9 critical, ≥ 7 high, ≥ 4 medium, > 0 low). A decimal comma is accepted.
  * Without a severity column, a valid CVSS vector or score decides. Otherwise the finding is informational, and the preview says so.
* **Target.** A port column is joined to a plain host or address (`host:port`). URLs and values with a port stay as they are.
* **CVE.** CVE values are split on commas, semicolons and spaces.
* **References.** Only http(s) URLs are kept.
* **CVSS.** A valid CVSS vector is scored. Any other value goes into the technical details.

**Scope and copied text.** As for the other formats, rows whose target is outside the scope are not recorded. When a target column is chosen, a row with an empty or unreadable target also counts as outside the scope. Without a target column, findings are recorded without a target (there is nothing to check), and the preview warns about it. Every copied value is redacted and cleaned, rule IDs and references included, and so are the header names and sample values the preview shows.

**Deduplication and fixes.** The fingerprint is the rule ID (or the title when there is none) and the target, so the same rows are recognized in a later file. **A CSV file never verifies fixes**: exports are often filtered by severity or host, so a finding that a CSV file does not list proves nothing. Library templates do not apply to CSV rows, because a rule ID in a CSV file does not say which scanner it belongs to.

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
  * **CVSS 3.0** vectors are scored with the 3.0 equations, as FIRST's 3.0 calculator does: `Roundup` is `ceil(x × 10) / 10`, and a changed scope's modified impact is `7.52 × (MISS − 0.029) − 3.25 × (MISS − 0.02)^15`. 3.1 changed both; under the 3.1 equations about one in twenty 3.0 vectors with environmental metrics would score differently.
  * Both 3.x versions multiply in the order of FIRST's calculators, so results round the same way.
* **Validation.**
  * Every base metric must be present once, and only known metrics and values are accepted.
  * Any order is accepted on input, because FIRST's own examples are not always in order.
  * The stored vector is canonical: specification order, without `X` values.
  * An invalid vector is refused with the reason, and the finding is not saved.
* **Score.** The score covers everything in the vector. For 4.0 the label is `CVSS-B`, `-BT`, `-BE` or `-BTE`; for 3.x it is base, temporal or environmental. The base score is also shown. The qualitative rating uses the standard bands: none 0.0, low 0.1–3.9, medium 4.0–6.9, high 7.0–8.9, critical 9.0–10.0.
* **Severity.** A finding's severity stays the analyst's choice. The form offers *Set severity to …* when it differs from the rating.
* **Calculator.** The finding form has a calculator for the base metrics (and Exploit Maturity for 4.0). It keeps environmental and supplemental metrics that were typed into the vector. A 3.0 vector changed in the calculator is written as a 3.1 vector, the current 3.x version.
* **Imports.** Nuclei's `classification.cvss-metrics` and Nessus' `cvss4_vector` (else `cvss3_vector`) become the finding's vector when they are valid. Invalid vectors are ignored, but the reported text stays in the description or technical details.
* **Reports.** The HTML and Markdown reports show the score together with its vector, as FIRST asks.
* **Tests.**
  * **Reference comparison.** [`scripts/cvss-reference.mjs`](../scripts/cvss-reference.mjs) scores vectors with FIRST's own calculators: the v4.0 reference calculator (`cvss_score.js`, commit `c5b0d40`) and the scripts of FIRST's 3.1 and 3.0 calculator pages.
    * It covers every base vector of each version (104,976 for 4.0, 2,592 each for 3.1 and 3.0) and 200,000 seeded random vectors per version with threat or temporal, environmental and supplemental metrics.
    * All 709,160 vectors score the same here, in both the base score and the score.
    * The regular test suite checks a 484-vector subset (`src-tauri/src/cvss/testdata/first_reference.tsv`): one 4.0 vector for each of the 263 macrovectors the sample reaches, random 3.1 vectors, and 3.0 vectors whose 3.0 and 3.1 scores differ.
    * The full comparison is an ignored test: `CVSS_REFERENCE_DIR=<out dir> cargo test cvss -- --ignored`.
  * **Published examples.** All eight CVSS 4.0 examples in the table of FIRST's examples page, and CVSS 3.1 vectors from the specification's comparisons. Four captions on that page disagree with its own table (CVE-2023-48228, CVE-2016-5729, CVE-2015-2890, CVE-2018-3652); the table values are the calculator's.

## Scope upgrade (schema 19)

Migration 19 changes data only. URL exclusions recorded before URL entries became path-level (schema 18) excluded their whole host. The upgrade therefore excludes that host:
* an in-scope entry with the same value becomes an exclusion;
* otherwise a `domain` or `ip` exclusion is added;
* both get a note naming the URL entry and a `scope_events` row with source `upgrade`.

Existing exclusions and in-scope URL entries are left as they are. See [UPGRADE.md](UPGRADE.md).

## Scope history (schema 18)

`scope_events.repeats` (default 0) counts further identical refusals: same target, reason and operation within 10 minutes. These are counted on one entry instead of adding rows, so retried requests cannot flood the history. The scope history and the project timeline show "N attempts". The scope semantics, including path-level URL entries, are in [SECURITY.md](SECURITY.md#path-level-scope).

## Methodology checklist (schema 17)

Projects → *Checklist* tracks the engagement's coverage of the **OWASP Web Security Testing Guide**. The app bundles the WSTG checklist (`src-tauri/src/methodology/wstg.json`): 115 tests in 13 categories, from the WSTG repository at commit `8f7da50`, retrieved 2026-11-08. It keeps only test IDs, names, objectives and reference links. The data is CC BY-SA 4.0; the tab and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) give the attribution. Reference links are limited to `wstg.owasp.org` and open in the browser only when clicked.

* **Records.** `checklist_items` keeps one row per project and test: status (`not_started`, `in_progress`, `passed`, `failed`, `not_applicable`), a note of up to 2,000 characters, and optionally the finding the test led to (same project only; it stays empty if the finding is deleted). Tests without a row are not started.
* **Finding links.** A link stays until it is changed or removed: *Unlink* in the tab, `unlink` in the app's API, `unlink_finding` through MCP (with approval; archived projects are refused). A finding and an unlink in one request are refused, and the finding itself is never deleted.
* **History.** Every change is recorded on the project timeline (type `checklist`): status, note, link and unlink, and whether the analyst or an MCP client made it.
* **Coverage.** The tab shows how many tests have a result (passed, failed or not applicable) out of the whole catalog, with counts per status. Tests can be filtered by status and searched by ID, name, objective or note.
* **Findings.** *Record finding* on a failed test opens the finding form with the test's name, category, the note and the test objectives, a reference to the WSTG page, and the tags `wstg` and the test ID. Saving links the finding to the test.
* **Report.** The HTML report states the coverage under the engagement details (tests with a result, per status), once at least one test has a status.
* **Versions.** WSTG test IDs can change between guide versions. The bundled version is recorded in the data file, so a later update can map the IDs.

## API security (schema 20)

Projects → *APIs* keeps an inventory of the endpoints that API definitions describe, and checks each definition against the OWASP API Security Top 10 (2023). The code is `workspace/apisec.rs` and `commands/apisec.rs`; nothing here contacts a network.

* **Files.** OpenAPI 3.0 and 3.1 and Swagger 2.0 (JSON or YAML), Postman collections (v2.0 and v2.1) and HAR captures, at most 25 MB. YAML is read with limits (128 levels, one million values with aliases expanded) so a file built to expand itself is refused. Local `$ref`s are followed; external ones are not fetched and are named in a warning. A capture keeps API calls only: images, scripts, styles, fonts and media are left out, and path segments that are values (numbers, UUIDs, long hex or tokens, e-mail addresses) become `{id}`, `{token}` or `{email}`.
* **Records.** `api_specs` keeps one row per imported file: name, format, title, version, endpoint count, the file's SHA-256, the evidence record of the file, and `doc`, the normalized inventory as JSON. The same file twice in a project is refused. Deleting a definition keeps its file in the evidence vault and the findings recorded from it.
* **Names, never values.** The inventory keeps methods, paths, parameter and body field names, tags, response codes and the names of authentication schemes. Tokens, cookies, passwords and example values stay in the file only.
* **Authentication.** Each endpoint lists the alternatives that authorize it (each a set of schemes) and whether anonymous calls are allowed: no requirement, or an empty alternative `{}`. Postman auth is inherited through folders; in a capture, credentials are recognised by header (`Authorization`, cookies, API-key headers) without keeping their values.
* **Scope.** Every endpoint's URL (the first absolute server and the path, parameters as their names) is checked against the project's scope, with the same rules as the HTTP request builder. Only in-scope endpoints open in the builder, which checks the request again when it is sent.
* **Issues** are properties of the definition: anonymous write operations of an API that otherwise requires authentication, a definition without authentication or with schemes that no operation uses, HTTP Basic, API keys in the query string, the OAuth implicit and password flows, cleartext servers, secrets in query strings, page sizes without a maximum, deprecated operations and non-production servers. *Record finding* creates the finding once (title, severity, OWASP category and tag, the endpoints, the recommendation, and the definition's file as evidence).
* **Tests** list endpoints to test for what no definition can show: object identifiers in paths (BOLA), administrative paths (function-level authorization), privileged body properties (mass assignment), URL and callback inputs (SSRF), sensitive flows without a documented 429 (rate limits), and several API versions. They are not findings.

## SBOM analysis (schema 21)

Projects → *Components* reads software bills of materials and reports the known vulnerabilities, licenses and completeness of the components they list. The code is `workspace/sbom.rs` and `commands/sbom.rs`.

* **Files.** CycloneDX 1.2–1.6 as JSON or XML, SPDX 2.2 and 2.3 as JSON or tag-value; at most 50 MB and 20,000 components (nested CycloneDX components included). SPDX 3.0 (JSON-LD) and SPDX RDF are refused with a message. XML is read without DTD processing: only the predefined and numeric entities are expanded, so an external entity stays literal text.
* **Records.** `sbom_docs` keeps one row per imported file: name, format, the described software, the component count, the file's SHA-256 and evidence record, `doc` (the components and the vulnerabilities the file states, as JSON), `vulns` (the last OSV.dev result) and `checked_at`. The same file twice in a project is refused; deleting an SBOM keeps its file in the evidence vault and its findings.
* **Components** keep name, group, version, package URL, CPE, type, ecosystem (the package URL type), licenses, supplier, up to four hashes, and whether they are direct dependencies of the described software (CycloneDX `dependencies`, SPDX `DEPENDS_ON`/`CONTAINS` relationships).
* **Licenses** are classified from SPDX identifiers and expressions as permissive, weak copyleft, copyleft, network copyleft, restricted (non-commercial, no-derivatives and source-available terms) or unknown. In an expression, OR takes the most permissive choice and AND (or several license entries) the most restrictive.
* **Known vulnerabilities.** The file's own `vulnerabilities` (CycloneDX) are shown with their VEX analysis; `not_affected` and `false_positive` are hidden unless asked. *Check on OSV.dev* sends one batch query per 1,000 package URLs (only components with a package URL and a version; the others are counted as not checked), then fetches each vulnerability record. Severity comes from the GitHub advisory rating, else from the highest CVSS vector, scored with Cyber Hub's own CVSS code; fixed versions come from the ranges of the affected package. A vulnerability the file states and OSV.dev knows under the same id or alias is shown once.
* **Checks.** Network-copyleft and restricted licenses (medium), copyleft licenses, unknown licenses, components without a version or without a package URL or CPE (low), and missing suppliers, relationships, author or timestamp, and packages in several versions (info).
* **Findings.** Each vulnerability of each component, and each check, can be recorded once as a finding: severity (unrated vulnerabilities become medium), CVE, CVSS vector, the package URL as target, the fixed versions as remediation, the tags `sbom` and the ecosystem, and the SBOM file as evidence.

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

**Store.** Files are content-addressed under `<app data>/evidence/<first two hex digits>/<sha256>`. The backend opens the native file dialog (the web view never supplies a path). It streams the file into `evidence/incoming` while hashing it, enforces the 256 MB limit while reading, and then renames it into place. The original file name is only a label: it never becomes part of a path. Folders that are symbolic links are refused; on Unix the folders are `0700`. A stored file is removed when the last record that refers to it is deleted. At startup, `incoming` and files that no record refers to are removed (this covers interrupted copies and deleted projects). A file is placed and registered, and a deleted record's file removed, while the database is locked, so a deletion and a new record of the same content cannot interleave.

**Integrity.**
* `text` records keep the SHA-256 and size of their content.
* A file is exported through a native save dialog. The copy is hashed while it is written, and a copy that does not match the recorded SHA-256 is removed and refused.
* *Verify* (Evidence tab) reports stored files that are missing, unreadable or changed, and text whose content no longer matches. References (runs, OSINT evidence) hold no copy and are counted separately. Each check is recorded on the project timeline, and so is each deletion.

## Timeline

`project_timeline` is a query, not a copy. It merges `timeline_events` with tool runs, finding history, scope history, evidence, events of linked OSINT investigations and discovery snapshots. Results are newest first, can be filtered by type (`execution`, `finding`, `vulnerability`, `scope`, `evidence`, `investigation`, `discovery`, `asset`, `workflow`, `remediation`, `report`, `note`, `utility`, `checklist`), and are paged with each event's `cursor` (time, source and row, so events of the same second are never skipped; a plain time is still accepted as `before`). `utility` events are HTTP requests (URL without its query, status, redirects) and TLS analyses sent from the assessment utilities. Asset status changes and project status changes (`note`) are recorded too.

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
