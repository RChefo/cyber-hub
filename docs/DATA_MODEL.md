# Project data model (schema 26)

Migration 9 adds the shared data layer that the attack-surface, vulnerability, workflow, analysis and engagement features build on. It changes no existing data except finding statuses (see the mapping below). The logic lives in `src-tauri/src/workspace/`. The Tauri commands are in `commands/workspace.rs` (plus the finding commands in `commands/projects.rs`).

```
projects ─┬─ project_targets ── scope_events          (scope and its audit trail)
          ├─ findings ─┬─ finding_events             (lifecycle and change history)
          │            └─ finding_links ──▶ assets | executions | evidence | osint_entities
          ├─ assets ── asset_observations ──▶ discovery_snapshots
          ├─ evidence ──▶ executions | osint_evidence | <app data>/evidence/<ab>/<sha256>
          ├─ relations ── relation_events            (relationships between records, decisions)
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
* export (*Export* → CSV, JSON, SARIF or ATT&CK Navigator layer) of the findings currently listed, in the order shown, through a native save dialog. The backend reads them from the database (`workspace/findings_export.rs`, `workspace/attack_layer.rs`).
  * **CSV** follows RFC 4180 (every field quoted, CRLF line ends) with a UTF-8 byte-order mark, and has 21 columns including the CVSS score and vector and the references. Finding text can come from scanners and so from the assessed systems, so cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading apostrophe and are not read as formulas (CSV injection).
  * **JSON** is `{"format":"cyberhub-findings","version":1,"project":…,"exportedAt":…,"findings":[…]}` with the full finding records.
  * **SARIF 2.1.0** (OASIS) is for code-scanning platforms such as GitHub and for vulnerability managers that read SARIF. A finding is an analyst's judgement rather than a scanner rule, so each finding gets its own rule (`cyberhub/finding/<id>`) with the title, the description and the remediation as help text.
    * `level`: critical and high are `error`, medium is `warning`, low and informational are `note`.
    * `security-severity` (the score GitHub ranks alerts by): the CVSS score, or else 9.5, 8.0, 5.5, 3.0 or 0.0 for the severity. The rule's `tags` start with `security`, followed by the category and the finding's tags.
    * Location: a URL or a file path (a relative path, an absolute Windows path as a `file:` URI, or a bare file name such as `Dockerfile` or `docker-compose.yml`) is a physical location; a host, an address, a package URL or free text is a logical location.
    * `partialFingerprints` holds the finding ID, so the same finding stays the same alert across exports; the status, confidence, CVE and CVSS vector are result properties. False positives and accepted risks are exported as suppressed results (`suppressions`, status `accepted`).
    * `automationDetails.id` is `cyberhub/<project>/`, so exports of different projects do not replace each other in GitHub.
    * Exports pass the OASIS SARIF 2.1.0 JSON schema, and Cyber Hub's SARIF import reads them back with their titles, severities and file locations.
  * **ATT&CK Navigator layer** (layer format 4.5, `<project>-attack-layer.json`, domain `enterprise-attack`) maps the techniques the findings name: tags that are technique IDs (`T1053.003`, as the log, file, Linux and Prowler triage record them; any case) and IDs on lines of the technical details that mention ATT&CK. Each technique is colored by the highest severity of its findings (with a legend) and scored with the number of findings that name it; its comment lists the first titles and its metadata up to 25 findings with severity, status and target. False positives are left out, and the description says how many. The layer names no ATT&CK version, so the Navigator uses its current data; sub-techniques with findings are expanded. A list without any technique is refused with an explanation. Checked by loading an export into the ATT&CK Navigator 5.3.2.
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
  7. Evidence register (with each record's source: module, tool and version, collection time, the record it was derived from);
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
| SARIF 2.1.0 | `version` 2.1.x and `runs` | one per result; `security-severity` mapped like GitHub code scanning (≥ 9 critical, ≥ 7 high, ≥ 4 medium, > 0 low), otherwise `level` (error high, warning medium, note low). Results of kind `pass` or `notApplicable` and suppressed results (a suppression with status `accepted`, or without a status as ESLint writes in-source suppressions) are skipped with a warning | none (source-code locations have no network target) |
| OCSF detection findings (Prowler `-M json-ocsf`) | a JSON list (or one object) with `class_uid` 2004 | one per check and resource (`workspace/scan_import_ocsf.rs`): `status_code` FAIL, or none for other OCSF producers. `severity_id` 1–5 (informational to critical); the check title; the result (`status_detail`), check description and risk; the remediation, with commands that are not URLs listed apart; URL references; the check, provider, account, region or Kubernetes namespace, resource type and ID, service, compliance requirements and MITRE ATT&CK techniques (from `finding_info.attacks` or Prowler's `MITRE-ATTACK` compliance entries) in the technical details; category *Cloud configuration* (*Container configuration* for Kubernetes). PASS results and resolved findings (`status_id` 4) are not imported but prove a fix (below); MANUAL checks and muted findings (`status_id` 3, suppressed) are skipped with a warning. A file without its closing bracket, as Prowler leaves it when a scan is interrupted, is read as far as it goes and marked incomplete. OCSF 1.0 security findings (class 2001, older Prowler versions) are refused with advice to export again | none (cloud resources are not network targets and need no scope) |
| CSV with a header row | none of the above, and a first line with at least two named columns separated by commas, semicolons or tabs | one per row, with the columns chosen in the preview (see [CSV findings](#csv-findings)) | addresses and names of the targets |

* **Flow.** The file (at most 50 MB, 10,000 findings, 20,000 asset values) is chosen in a native dialog, read and previewed. The preview says what each finding would do: new, already recorded, resolved and reported again, dismissed earlier, outside the scope, or informational (not imported unless selected). Nothing is written until *Import* is pressed. The preview can be used once.
* **Scope.** Every network target is checked against the project scope with the scope engine, on the value that is stored (a Nuclei finding on its `matched-at` target, each asset on its own host, a Burp address as an address). Findings and assets outside it are counted and their hosts listed; they are not recorded. A network finding whose host cannot be read (for example an invalid port) counts as outside the scope. A project without in-scope entries records no network results. SARIF results with a URL location (DAST tools) are scope-checked like network findings; results with source-code locations have no network target and are always imported.
* **Deduplication.** `finding_fingerprints` keeps one fingerprint per imported finding (SHA-256 of tool, rule and location; SARIF's `partialFingerprints` when present). A finding reported again is not duplicated: the sighting is added to its history and to `times_seen`. A resolved finding can be reopened (*Reopen resolved findings*, on by default in the preview). A finding marked as a false positive or an accepted risk stays as it is. Repeated results inside one file are merged.
* **Fix verification by rescan (schema 15).** Each fingerprint records the host its finding is about. When a later file of the **same tool** covers a host (it has results or assets for it) but no longer reports an open finding that an earlier import recorded there, the preview lists the finding under *no longer reported*. By default each such finding only gets a history note. *Resolve … this rescan no longer reports* sets them to `resolved` with the note "Verified by rescan". This follows the delta reports of vulnerability scanners. The analyst decides, because a rescan with a narrower policy can also miss a finding. Nothing is listed when the file was not read completely (limits reached, a document that breaks off, skipped lines, an unfinished Nmap scan); the preview says so. **Passing checks (OCSF).** A Prowler file reports checks that pass, not only failures: an open finding of an earlier import of the same tool whose check and resource (the same fingerprint) the file reports as PASS is listed too, as proof rather than absence, also when the file was not read completely; the preview explains it, and the note reads "the check passes for … in the Prowler import of …". A Prowler file that merely leaves out a resource proves nothing. The following findings are never listed: findings on hosts the file does not cover; findings imported before schema 15 (their fingerprints have no host until they are seen again); source-code findings (SARIF); findings that are resolved, accepted or dismissed; and findings from other tools.
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
| `rules` | JSON list of ≤ 50 import rules `format:rule` (`nmap`, `nuclei`, `nessus`, `burp`, `zap`, `sarif`, `openvas` (the NVT OID), `ocsf` (the Prowler check ID)); the rule as the tool names it: Nessus plugin ID, ZAP plugin ID, Burp issue type, Nuclei template ID, SARIF rule ID). A rule belongs to one template; rules match without regard to case. |
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
* **Comparison** (*Compare definitions*, with two or more imports; `workspace/apisec_compare.rs`): an older and a newer import, by default the last two. Endpoints match by method and path, and path parameter names do not matter (`/users/{id}` is `/users/{userId}`). It lists endpoints added, removed and changed (authentication removed, added or changed, query, header and cookie parameters, request fields, deprecation, response codes) and the servers added and removed. Issues: endpoints that lost their authentication (high, API2), new endpoints without authentication in an API that requires it elsewhere (medium, API2), a new plain-HTTP server (medium, API8) and endpoints removed from the definition, which often stay reachable (low, API9); tests: new request fields of write operations to check for mass assignment (API3) and new endpoints (API9). Issues are recorded once, against the newer definition, with its evidence.

## SBOM analysis (schema 21)

Projects → *Components* reads software bills of materials and dependency lockfiles and reports the known vulnerabilities, licenses and completeness of the components they list. The code is `workspace/sbom.rs`, `workspace/lockfiles.rs` and `commands/sbom.rs`.

* **Files.** CycloneDX 1.2–1.6 as JSON or XML, SPDX 2.2 and 2.3 as JSON or tag-value; at most 50 MB and 20,000 components (nested CycloneDX components included). SPDX 3.0 (JSON-LD) and SPDX RDF are refused with a message. XML is read without DTD processing: only the predefined and numeric entities are expanded, so an external entity stays literal text.
* **Lockfiles** are recognised by their file name (`workspace/lockfiles.rs`): npm `package-lock.json` and `npm-shrinkwrap.json` (lockfile versions 1–3), Yarn `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (versions 5–9), `Cargo.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` (exact `==` pins only; other lines are counted in a warning, and `-r`/`-c` files are not followed), `composer.lock`, `Gemfile.lock`, `go.mod` (with its `replace` directives), NuGet `packages.lock.json` and Gradle `gradle.lockfile`. Registry packages get a package URL (npm scopes encoded, Python names normalized as in PEP 503, Maven groups in their own field); packages from Git, a URL or a local path keep where they come from (`resolved`) and no package URL, so they are not looked up. The project's own packages (workspace members, path and editable packages) are left out and counted. Each component records whether it is a development dependency (`dev`) and, where the lockfile tells, a direct one. The format is stored as `lockfile-<kind>`; the indexes a requirements, Pipfile or Gemfile names are kept in `sources`.
* **Records.** `sbom_docs` keeps one row per imported file: name, format, the described software, the component count, the file's SHA-256 and evidence record, `doc` (the components and the vulnerabilities the file states, as JSON), `vulns` (the last OSV.dev result) and `checked_at`. The same file twice in a project is refused; deleting an SBOM keeps its file in the evidence vault and its findings.
* **Components** keep name, group, version, package URL, CPE, type, ecosystem (the package URL type), licenses, supplier, up to four hashes, and whether they are direct dependencies of the described software (CycloneDX `dependencies`, SPDX `DEPENDS_ON`/`CONTAINS` relationships).
* **Licenses** are classified from SPDX identifiers and expressions as permissive, weak copyleft, copyleft, network copyleft, restricted (non-commercial, no-derivatives and source-available terms) or unknown. In an expression, OR takes the most permissive choice and AND (or several license entries) the most restrictive.
* **Known vulnerabilities.** The file's own `vulnerabilities` (CycloneDX) are shown with their VEX analysis; `not_affected` and `false_positive` are hidden unless asked. *Check on OSV.dev* sends one batch query per 1,000 package URLs (only components with a package URL and a version; the others are counted as not checked), then fetches each vulnerability record. Severity comes from the GitHub advisory rating, else from the highest CVSS vector, scored with Cyber Hub's own CVSS code; fixed versions come from the ranges of the affected package. A vulnerability the file states and OSV.dev knows under the same id or alias is shown once.
* **Checks.** Network-copyleft and restricted licenses (medium), copyleft licenses, unknown licenses, components without a version or without a package URL or CPE (low), and missing suppliers, relationships, author or timestamp, and packages in several versions (info). A lockfile is not an SBOM: the supplier, relationship, author and identifier checks do not apply, and licenses are checked only when the format records them (npm 7 and later, Composer). Lockfiles get supply-chain checks instead: packages downloaded over plain HTTP (high); registry packages without an integrity hash in formats that record one (medium); `--extra-index-url` in requirements files, which lets pip install a same-named public package (dependency confusion, medium); dependencies from Git, URLs or local paths (low); and packages from more than one registry (low; the npm and Yarn registry addresses, and crates.io's Git and sparse indexes, count as one).
* **Findings.** Each vulnerability of each component, and each check, can be recorded once as a finding: severity (unrated vulnerabilities become medium), CVE, CVSS vector, the package URL as target, the fixed versions as remediation, the tags `sbom` and the ecosystem, and the SBOM file as evidence.

### SBOM comparison

With two or more SBOMs or lockfiles in a project, *Compare versions* compares an older and a newer one, by default the last two imports (`workspace/sbom_compare.rs`); nothing is stored. Components match by ecosystem, group and name; a package that moved to a Git or URL source (which has no ecosystem) matches the one earlier package of its name that is otherwise unmatched. A package may appear in several versions (npm). The result lists components added and removed and the version changes, each upgraded, downgraded or changed (versions that do not compare, such as commit hashes); versions compare numerically, with pre-releases before their release (`1.0.0-rc.1` < `1.0.0`). Vulnerabilities (the files' own and the OSV.dev results) are compared only when both sides have the same kind of data, both checked on OSV.dev or neither, so a missing lookup is never shown as a fix; the panel says which data it compared.

* **SBOM-CMP-NEW-VULNS** (the highest severity among them; unrated is medium): vulnerabilities of the newer version that the older did not have.
* **SBOM-CMP-SOURCE-CHANGED** (high): a package now comes from another registry, Git host or address (the registry of lockfiles, or the host of the resolved address), as dependency confusion and hijacked packages do.
* **SBOM-CMP-CONTENT-CHANGED** (high): the same version with hashes that share nothing with the older ones: the published file changed or came from another build.
* **SBOM-CMP-DOWNGRADE** (medium): components that went back to an earlier version.
* **SBOM-CMP-LICENSE** (medium for network copyleft or restricted, otherwise low): licenses that moved to a stricter class (copyleft or more).

Each issue can be recorded once as a finding (category *Supply chain*, or *License compliance*), titled with both versions and keyed by both files' SHA-256, linked to the newer file's evidence record.

## Investigation layer (schema 22)

Projects → *Investigation* connects the results of the modules: which findings concern which assets, vulnerabilities, evidence, OSINT entities, API endpoints, SBOM components and ATT&CK techniques, how that is known, and what the analyst decided. The project stays the investigation: nothing here copies a record, and every relationship refers to the records where they are. The code is `workspace/relations.rs`, `workspace/correlate.rs`, `workspace/search.rs`, `workspace/attack.rs` and `commands/investigation.rs`; nothing here contacts a network.

**References.** A relationship joins two records, each given by its kind, its row id and, for records inside another one, its place there:

| Kind | Reference | Key |
|---|---|---|
| `finding`, `asset`, `vulnerability`, `evidence`, `osint_entity`, `execution` | the row id | `finding:12` |
| `api_endpoint` | the API definition and the endpoint's index in it | `api_endpoint:3:5` |
| `sbom_component` | the SBOM and the component's index in it | `sbom_component:2:14` |
| `technique` | the ATT&CK technique ID | `technique:T1059.001` |

A reference is checked when a relationship is made: the record must exist in the same project (an OSINT entity in an investigation linked to the project), and a technique must be in the bundled ATT&CK catalog. Revoked and deprecated techniques are accepted and labelled as such ("T1143 (revoked, now T1564.003)"); unknown IDs are refused.

**`relations`** keeps one row per pair and type in a project:

* `type`: `affects`, `supported_by` and `maps_to` have a direction; `corresponds_to`, `related_to`, `possible_duplicate` and `associated_with` do not, and store their two records in a fixed order so a pair is kept once.
* `origin`, how it was established: `observed`, `imported`, `derived` (computed from stored values by a correlation rule), `inferred`, `manual` (the analyst) or `suggested`. The values are those of OSINT relationships, plus `imported`.
* `verification`, whether it is a fact: `observed`, `verified`, `inferred`, `disputed` or `rejected`. A suggestion is `inferred` until the analyst decides; nothing becomes `verified` without the analyst.
* `review`: `pending`, `done` or `dismissed`.
* `confidence` (high, medium, low), `rules` (the rules that found it), `reason` (one sentence), `matched` (the fields and values that matched, and whether exactly or after normalizing), `created_by`, `note`, and the times it was made, changed and reviewed.

**Decisions.**
* *Accept* makes it `verified`. Between a finding and an asset, vulnerability, evidence record, OSINT entity or tool run, it also creates the finding link (source `correlation`), which reports and the evidence chain read; between an asset and an OSINT entity it records the entity on the asset when the asset has none. The relationship remembers what it created (`materialized`).
* *Reject* makes it `rejected` and removes what accepting created. Correlation never suggests a rejected pair again.
* *Dismiss* takes it out of the queue without deciding; *Mark reviewed* keeps it as it is; *Restore* puts a decided suggestion back in the queue and removes what it created.
* *Link* (by hand) creates a `manual`, `verified` relationship, and the finding link where one applies. *Remove* deletes a link made by hand; a relationship a rule found is kept as `rejected` instead, so it is not suggested again.
* Every decision is kept in `relation_events` (action, sentence, note, who, when), which the timeline shows as `correlation` events. Decisions are refused in archived projects.

**Deletion.** Triggers remove the relationships of a record when it is deleted (findings, assets, vulnerabilities, evidence, OSINT entities, tool runs, and the API definitions and SBOMs whose endpoints and components they refer to); their history stays. When OSINT entities are merged, relationships move to the kept entity; a pair that already exists for it keeps the kept entity's decision, and a relationship between the two merged entities is removed.

### Correlation

*Correlate* runs the rules below over the project's records and stores what they find as suggestions. Rules compare exact or normalized values (URLs, web origins, hosts and addresses, CVE IDs, package URLs, file hashes, API paths); nothing is matched by similarity of text, and no two records are ever merged. Each side is indexed once, so a run is linear in the number of records.

| Rule | Relationship | Confidence |
|---|---|---|
| `finding-asset` | the finding's affected target is an asset: the same value, else the same web origin, else the same host or address (the most specific match only; at most five assets per finding) | high; medium for a host match |
| `finding-vulnerability` | the finding names the CVE of a tracked vulnerability on the same host | high; medium for a vulnerability without an asset |
| `vulnerability-component` | the vulnerability's CVE is a known vulnerability of an SBOM component (the SBOM's own data or its OSV.dev result, aliases included) | high |
| `finding-component` | the finding's target is the package URL of an SBOM component | high for the same version; medium (corresponds to) for another version |
| `hash` | a file hash written in a finding (SHA-256, SHA-1 or MD5) is the SHA-256 of an evidence file or a file-hash entity of a linked investigation; an evidence file's SHA-256 is such an entity | high |
| `finding-endpoint` | the finding's URL (without query and fragment, in any case) is a server of an API definition followed by an endpoint's path, a parameter standing for one path segment | high for one endpoint, medium for several |
| `entity-asset` | an entity of a linked OSINT investigation is the host or address of an asset | high |
| `finding-entity` | the finding's target is on the host of an entity of a linked investigation | medium |
| `shared-evidence` | two findings are linked to the same evidence record | medium |
| `duplicate` | two findings name the same CVE on the same host (high), or have the same title on the same target (medium) | as stated |

* A pair already joined by a finding link is not suggested. A pair the analyst decided keeps the decision; one still pending is updated (rules, matches, the higher confidence).
* Groups are capped so one large group cannot flood the queue: 50 pairs per group of findings that share something, and 5,000 pending suggestions per project. The report says how many were found per rule and how many were not stored.
* Each run is recorded in `relation_events` with its counts and duration. Correlation is refused in archived projects.

**Related records.** The record panel (any finding, asset, vulnerability, evidence record, entity, endpoint, component or technique) lists, with how each is known: its relationships (rejected ones only on request), finding links, the structural links that already exist (an asset's vulnerabilities and OSINT entity, the evidence an API definition or SBOM came from, the evidence a record was derived from) and the record's timeline events. A finding link that a verified relationship created is listed once, as the relationship.

**Graph.** The investigation graph draws records as nodes and relationships and finding links as edges, each edge with its type, origin, verification, confidence and rules. Filters: pending and rejected suggestions (off by default), minimum confidence, origins, record kinds, a start date, and the neighbourhood of one record (1–6 steps). It is capped at 1,500 edges by default (at most 5,000), and says when it was cut. A shortest path between two records follows the same filters. The graph exports as JSON (format `cyberhub-investigation-graph`, with every edge's provenance), SVG or PNG through a native save dialog; each export is recorded on the timeline. The graph reuses the OSINT workspace's drawing and layout code.

**Search** (`records_search`) finds projects, findings, assets, vulnerabilities, evidence, OSINT entities, tool runs, API endpoints, SBOM components and ATT&CK techniques by text, in one project or across projects. Exact matches rank before prefixes and prefixes before substrings; the wildcards of SQL `LIKE` in the text are matched literally. Archived projects are searched only when asked for, or when named. At most 200 results (50 by default). The command palette (`Ctrl/⌘ + K`) searches the records of every open project as you type (from two characters, debounced): a finding opens in its project's Findings tab, any other record opens its related records in the Investigation tab. The search reads the tables at that moment, so a deleted record is never offered.

**ATT&CK catalog.** `catalog/attack-enterprise.json` is a compact copy of MITRE ATT&CK Enterprise 20.1 (tactics in matrix order, techniques and sub-techniques with their tactics and platforms, the revoked IDs with their replacements, the deprecated IDs), built by `scripts/attack-catalog.mjs` from MITRE's STIX bundle and bundled with the application. It records the source URL, the bundle's SHA-256 and when it was retrieved; the MITRE notice is in `THIRD_PARTY_NOTICES.md`.

### Utility results

`utility_record` records what a security utility found in a project, in one transaction: the analysed file in the evidence vault (`source_module` `file_triage`, `pcap_triage`, `log_triage` or `evtx_triage`; the tool and Cyber Hub's version), the analysis as text evidence with `derived_from` set to the file, the selected findings (source `utility`, each title once per project) linked to the file, a `utility` timeline event that refers to the file, and an activity entry. The OAuth review and pasted logs have no file: their findings are linked to the analysis. The file is named by a token from the analysis, never by a path from the web view, and must still have the SHA-256 that was analysed; a file larger than the vault takes (256 MB) is refused with a message, and the findings can be recorded without it. The same analysis recorded again is kept once. A failure leaves nothing behind (a file this call copied is removed). Files analysed by the file triage are indicators of the project: their SHA-256 appears in *Analysis* with any cached threat-intelligence verdict.

**Evidence provenance.** Evidence records gain `source_module` (the module that produced them, such as `scan_import`, `api_inventory` or `sbom`), `source_ref` (the record there, such as `sbom_doc:7`), `tool` and `tool_version`, `collected_at` (when the source says it was collected, such as an SBOM's creation time, kept apart from when Cyber Hub stored it), `derived_from` (the evidence it was derived from), `verification` (`unverified`, `intact`, `damaged`, `missing`) and `verified_at`. Imports of scan results, API definitions and SBOMs and recorded utility results fill them; provenance that a record already has is never overwritten, so the same file added again keeps where it first came from. *Verify* stores each stored record's result.

### Remediation groups

Projects → *Findings* → *Remediation groups* (`workspace/remediation.rs`, `remediation_groups`) lists findings that one fix addresses, whichever module reported them, so work is planned per fix rather than per finding. A group is explained by what its findings share: the same CVE (case ignored), the same package (the package URL without its version, so `lodash@4.17.15` and `lodash@4.17.20` are one package), the same check reported on at least two targets (the title without a trailing target in parentheses), or the same remediation text (at least 20 characters, spacing, case and a final period ignored). A set of findings is listed once, under its most specific explanation (CVE, then package, then check, then remediation). Each group shows the remediation most of its findings give, the highest severity, and how many findings are open, resolved, and resolved as verified by a rescan; groups with open work and higher severity come first. False positives are left out. Nothing is merged, closed or changed: a fix counts as verified only when a rescan by the same tool resolved the finding (see [Scan import](#scan-import-schema-13)), never because another tool did not report it.

## ATT&CK matrix (schema 23)

Projects → *Investigation* → *ATT&CK* shows the techniques of a project in ATT&CK Enterprise's matrix (tactics in MITRE's order, sub-techniques under their parent; by default only techniques with data, or the whole matrix). The code is `workspace/attack_matrix.rs` and `commands/attack.rs`. Three kinds of statement are kept apart because they mean different things:

* **Named by findings.** The technique IDs findings name (tags such as `T1059.001`, as the file, log, event log, Linux and cloud triage write them, and IDs on technical-detail lines that mention ATT&CK), with each finding's severity, status, confidence and number of evidence records. False positives name nothing. These are leads from the tools, not confirmed adversary activity, and the view says so.
* **Assessments** (`attack_assessments`): the analyst marks a technique *confirmed*, a *hypothesis* or *ruled out*, with a confidence (low, medium, high), a note, who and when, and the ATT&CK version it was assessed against. Only an assessment confirms a technique. Unknown technique IDs are refused; revoked and deprecated ones are accepted and labelled. Every change, and its removal, is kept in `relation_events` and shown on the timeline. Records linked to a technique by hand (see the investigation layer) are listed with it.
* **Imported layers** (`attack_layers`): ATT&CK Navigator layers from elsewhere, typically detection coverage, are an overlay. They never make a technique observed. With a layer shown, techniques that findings name or the analyst confirmed or suspects but the layer does not list (or lists disabled) are marked as gaps.

**Layer import.** A JSON file chosen in a native dialog (at most 10 MB and 20,000 entries), read as the Navigator's layer format specifies: format 4.x, and the older 2.x and 3.x files (`version`, domain `mitre-enterprise`). Only the Enterprise domain is accepted; Mobile and ICS layers are refused with a message. The layer's name, description, format, Navigator and ATT&CK versions are kept; a layer made for another ATT&CK version than the bundled catalog is said so. Entries are merged per technique (a layer may list a technique once per tactic: the highest score, the comments joined, enabled if any entry is); colors are kept only when they are hexadecimal colors. Technique IDs are checked against the catalog: revoked IDs count for the technique that replaced them and are listed as mapped, deprecated ones are kept with a warning, unknown ones are listed and left out, never guessed. The file is kept in the evidence vault (`source_module` `attack_layer`, the Navigator version as the tool), the same file is refused twice in a project, and removing a layer keeps its file.

**Layer export.** The project's techniques as a Navigator layer (format 4.5, domain `enterprise-attack`, `versions.attack` the catalog's major version), through a native save dialog: techniques named by findings and assessed techniques, colored by state (confirmed, named by findings, hypothesis, ruled out), scored with the number of findings, with the assessment and the findings in the comment and metadata; ruled-out techniques are disabled. Imported layers are not exported. The export is recorded on the timeline. The Findings tab's export of a filtered list of findings stays as it was.

## Detection engineering (schema 24)

*Detections* (sidebar) keeps a library of Sigma rules (for logs) and YARA rules (for files); projects run them on their evidence, and File Triage scans the file it analysed. The engines are `detection/sigma.rs` and `detection/yara.rs`, with events in `detection/events.rs`, the library in `workspace/detections.rs` and the commands in `commands/detections.rs`. Nothing contacts a network, and nothing in a rule or a sample is executed.

**Sigma support** follows SigmaHQ's specification v2.1.0 (2025-08-02) and its modifier appendix.
* **Read and checked:** every document of a YAML file is a rule; title, id, status, level, description, author, dates, references, tags, false positives, fields and logsource are kept. Problems are listed with a level: *error* (the rule is invalid: no title, logsource, detection or condition, an identifier the condition names but the detection lacks, an unknown modifier, an invalid regular expression, `all` with one value, `null` in a list, an empty map, more than 5,000 values), *unsupported* (valid Sigma that Cyber Hub cannot evaluate) and *warning* (an id that is not a UUID, an unknown status or level, a date not in YYYY-MM-DD, tags with capitals or spaces, unused search identifiers, `all of them`, a log source without a channel mapping). Rules with an error or an unsupported feature are kept but cannot run.
* **ATT&CK:** `attack.tNNNN[.NNN]` tags are checked against the bundled catalog: a revoked ID counts for the technique that replaced it, with a warning (ATT&CK v20 revoked, for example, T1070.001 for T1685.005); an unknown ID is a warning. `attack.<tactic>` tags are kept as tactics.
* **Detection:** maps are ANDed, lists of values ORed (ANDed with `all`), lists of maps ORed, keyword lists searched in every value of an event (or the line of a text log), with `'|all'` for all keywords. Values compare case-insensitively; `*` and `?` are wildcards, `\*`, `\?` and `\\` the plain characters, and other backslashes plain backslashes. `null` matches an absent field, `''` an empty one.
* **Modifiers:** contains, startswith, endswith, all, exists, cased, re (case-sensitive; `|i`, `|m`, `|s`), base64, base64offset (pySigma's three offsets), utf16le, wide, utf16be, utf16, windash (`-` and `/` at the start of an option match the five dashes Windows accepts), cidr (IPv4 and IPv6), lt, lte, gt, gte, neq and fieldref. Regular expressions run on the `regex` crate (linear time, a 1 MB size limit).
* **Conditions:** and, or, not, parentheses with the specified precedence, `1 of`, `all of`, `N of` (at least N), `them` (identifiers starting with `_` left out), patterns with `*`; a list of conditions is ORed.
* **Refused with the reason:** placeholders (`expand`, which the specification says a tool without values must reject), the time modifiers, aggregations (`| count() …`), correlation rules, rule collections with `action`, look-around and back-references in regular expressions.
* **Log sources:** for Windows, the services `security`, `system`, `application`, `sysmon`, `powershell`, `powershell-classic`, `taskscheduler`, `wmi`, `windefend`, `bits-client`, `codeintegrity-operational`, `firewall-as`, `dns-server`, `ntlm`, `openssh`, `terminalservices-localsessionmanager`, `printservice-operational` and `smbclient-security` filter events by channel, and the categories `process_creation` (Sysmon 1 and Security 4688, whose `NewProcessName`, `ParentProcessName` and `SubjectUserName` stand for `Image`, `ParentImage` and `User`), `network_connection`, `process_access`, `image_load`, `file_event`, the registry categories, `dns_query`, `pipe_created`, `wmi_event`, `ps_script`, `ps_module` and the others Sysmon defines filter by channel and event ID, after pySigma's Windows pipeline. Other log sources (Linux, cloud) run against every event, and the result says so. Events without a channel (JSON without one, text logs) are not filtered.

**YARA support** runs on boreal 1.4 (`detection/yara.rs`), a YARA 4.5 evaluator written in Rust, without a C library or a JIT compiler.
* **A library entry is a rule file:** its rules are compiled together, so private and global rules work as in YARA. The entry's title is the file's only public rule, or the first with the number of others. Its level comes from a `severity`, `level` or `threat_level` meta when that is critical, high, medium, low or informational. Techniques come from metas whose name mentions MITRE, ATT&CK, technique or TTP and from tags, checked against the bundled catalog like Sigma tags. Description, author, references and tags are kept.
* **Supported:** text, hex and regular-expression strings with their modifiers, conditions, and the modules time, math, string, hash, pe, elf, macho, dotnet and dex.
* **Refused:** `include`, so a rule never reads a file. Also absent: the console, magic and cuckoo modules, and external variables (LOKI's and THOR's `filename` and `filepath` would be meaningless for a copied file and would mislead path-based rules). Authenticode signatures are read, never verified.
* **Limits:** rule files of 2 MB and 1,000 strings per rule; boreal's limits on condition depth (40) and on nesting in strings, regular expressions and hex strings. Conditions nesting deeper than 64 levels are refused before boreal reads them: brackets, prefix operators and chains of operators other than `and` and `or` count. boreal's parser recurses on such chains without a limit, and a crafted rule of a few kilobytes would otherwise overflow the stack and end the app. Rules also compile on a thread with a 16 MB stack.
* **Scans:** files of up to 256 MB, read whole into memory and never opened by another program. A scan stops after 30 seconds and says so. boreal counts up to 1,000 matches per string, and the first 10 are kept with their offset, length, 64 bytes as text and hexadecimal, and the xor key.
* **Compatibility:** checked on two public collections compiled one file at a time.
  * Neo23x0's signature-base: 736 of 753 files compile (5,257 rules). The others use LOKI's external variables (13) or hold no rule (4).
  * Yara-Rules: 496 of 566 files compile (5,182 rules). The others import modules that are not available (androguard 46, cuckoo 2), are index files of includes (12), use external variables (7), hold no rule (2) or are too large (1).
  * No real rule was refused for nesting.

**Events** come from EVTX files (Cyber Hub's own reader; system fields as Sigma names them: `EventID`, `Channel`, `Provider_Name`, `Computer`, `Level`, `UserID`; hexadecimal values as Windows renders them, `0x1010` rather than `0x00001010`), JSON and JSON Lines (flattened with dots, each leaf also reachable by its own name unless two leaves share it; a single wrapper such as CloudTrail's `{"Records": [...]}` is unwrapped) and text logs (one event per line, as `message`; a file whose first bytes hold a NUL byte is binary or UTF-16 and is not read as a log). At most 500,000 events and 256 MB per file; values are cut at 32 KB.

**Library** (`detection_rules`, `detection_rule_versions`): one row per Sigma rule, identified by its Sigma id (or by title and log source without one), and one row per YARA rule file, identified by its file name (a file written in the app is named after its first rule; editing an entry keeps its name). Importing a rule with a known id, or a YARA file of a known name, with different content makes a new version; the same content is unchanged. The import tells the kinds apart by extension (`.yml`, `.yaml`; `.yar`, `.yara`), otherwise by the content. Every version is kept with its note, and two versions compare line by line. Rules can be enabled or disabled, grouped in collections (`detection_collections`), exported as `.yml` or `.yar` files (a collection into a folder; existing files are never overwritten), and receive feedback (`detection_feedback`: false positive, true positive, note).

**Tests:** samples (`detection_samples`) are copied into `<app data>/detection-samples/<sha256>`, hashed while copied: logs (EVTX, JSON, text) for Sigma rules, and with *Add file sample…* any file (kind `file`) for YARA rules, which run on every sample. A Sigma rule refuses a file sample. Adding a file sample again as a log makes it a log sample. A test runs the rule's current version on a sample and keeps the result (`detection_tests`: version, events, matches, the first matches with their explanation). The analyst says what a rule should do on each sample (`detection_rule_samples.expect`: match, no match, or nothing): a test passes when the rule does it. *Re-test all samples* runs the current version on every sample it was tested on and shows the previous result next to each, so a change that breaks a rule is seen at once. A rule matching more than half of the events of its log source (in a sample of at least 20) is flagged as probably too broad. A rule counts as **tested** when it has at least one sample with an expectation and the last test of each passed.

**Explanations:** every Sigma match lists the search identifiers the condition uses, whether each matched, and for each matching field its condition and the event's value; filters that did not match are listed too. Every YARA match names its rule, tags and metas, and each string that matched with its count and first matches (offset, bytes as text and hexadecimal, xor key); a rule whose condition holds without strings (file size, header values, modules) says so.

**Projects** (*Investigation* → *Detections*): the enabled rules (of a collection when chosen) run on file evidence of the project: Sigma rules on the files that read as logs, YARA rules on every file, all YARA files of the run in one pass. A YARA match is placed by its rule's name, so a rule matches a file once per version. Matches are kept as **detection hits** (`detection_hits`: rule, version, level, techniques, evidence, the event's place and time, its fields, the explanation), at most 200 per rule and file, never twice. A hit is a lead: the analyst promotes it to a finding (status *under review*, confidence low, category Detection, tags `detection`, `sigma` or `yara` and the techniques, linked to the evidence; the rule and version are in its technical details, and a YARA finding names the matched strings and the file's SHA-256), marks it a false positive (recorded as feedback on the rule, with the project), or dismisses it. Each run is a `detection` event on the timeline. Archived projects take no run or decision.

**File Triage** (Security Utilities): *Scan with YARA rules* scans the analysed file with the library's enabled YARA rules (or one collection's). The file must still have the SHA-256 that was analysed. Matches are shown with their strings; the analyst records the chosen ones as findings (under review, confidence low, tags `detection`, `yara` and the techniques) in a project, where the file and the analysis go into the evidence vault and the findings are linked to the file. Nothing is recorded by the scan itself.

**ATT&CK:** the matrix shows the library's coverage (enabled Sigma rules and YARA files that can run, per technique, and whether they are tested) as an overlay apart from what findings name and from the analyst's assessments; techniques that findings name or the analyst confirmed or suspects without a rule are marked as gaps. A project's open detection hits are counted per technique as leads. The coverage exports as a Navigator layer (format 4.5): score the number of rules, dark green when every rule is tested.

## ASVS assessments (schema 25)

Projects → *ASVS* assesses an application against the **OWASP Application Security Verification Standard 5.0.0**. The app bundles the standard's official JSON release unmodified (`src-tauri/catalog/asvs-5.0.0.json`; 17 chapters, 345 requirements: 70 at level 1, 183 at level 2, 92 at level 3). It is CC BY-SA 4.0: the tab, the report and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) give the attribution. The logic is in `workspace/asvs.rs` and the commands in `commands/asvs.rs`. Nothing contacts a network.

* **Assessments** (`asvs_assessments`): a project can hold several, each with a name, the ASVS version, a level (1, 2 or 3) and a scope. The level can change at any time. The requirements up to the level are counted; the others keep their statuses but are shown only on request and are not counted. Archived projects cannot start or change an assessment.
* **Statuses** (`asvs_results`): *not assessed* (no row), *compliant*, *non-compliant*, *needs review* or *not applicable*, each with a note. **Only the analyst sets a status.** Nothing is derived from findings, scans or the absence of findings. Recording a finding does not change a status, and neither does fixing one. Progress is the share of the level's requirements that have a status.
* **History** (`asvs_history`): every status change, with the previous and the new status, the note and who made it.
* **Links** (`asvs_links`): findings and evidence of the same project. When a finding or an evidence record is deleted, triggers remove its links.
* **Mappings** (`asvs_mappings`): the ASVS 5.0.0 release data maps no requirement to another framework, so every mapping is the analyst's own: OWASP WSTG, OWASP API Security Top 10, CWE, ATT&CK (checked against the bundled catalog), NIST SP 800-53 or other. The tab and the report label them as the analyst's.
* **Findings:** *Record a finding* on a non-compliant or needs-review requirement creates a confirmed finding linked to the requirement:
  * the title is "ASVS 5.0.0: requirement V… not met", and the category is the chapter;
  * the description holds the requirement text and the note;
  * the tags are `asvs`, the requirement ID and `asvs-l<level>`, and the source is `asvs`.
* **Report:** *Export report* writes Markdown through a native save dialog. It has the totals per status, then every requirement of the level by chapter, with its status, note, findings and evidence. It also lists the analyst's mappings and ends with the attribution. It states that a requirement without a status is not assessed, whatever the findings.
* **Timeline:** starting an assessment is recorded as `checklist`, and an export as `report`.

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
* *Verify* (Evidence tab) reports stored files that are missing, unreadable or changed, and text whose content no longer matches. References (runs, OSINT evidence) hold no copy and are counted separately. Each check is recorded on the project timeline, and so is each deletion. From schema 22 each stored record also keeps the result of its last check (`verification`, `verified_at`), and records keep their provenance (see [Investigation layer](#investigation-layer-schema-22)).

## Timeline

`project_timeline` is a query, not a copy. It merges `timeline_events` with tool runs, finding history, scope history, evidence, events of linked OSINT investigations and discovery snapshots. Results are newest first, can be filtered by type (`execution`, `finding`, `vulnerability`, `scope`, `evidence`, `investigation`, `discovery`, `asset`, `workflow`, `remediation`, `report`, `note`, `utility`, `checklist`), and are paged with each event's `cursor` (time, source and row, so events of the same second are never skipped; a plain time is still accepted as `before`). `utility` events are HTTP requests (URL without its query, status, redirects) and TLS analyses sent from the assessment utilities. Asset status changes and project status changes (`note`) are recorded too.

From schema 22 (`timeline_query`, the *Timeline* tab):
* `correlation` events are the investigation layer's history: correlation runs and every decision on a relationship.
* Events can also be limited to one record (a finding, asset, evidence record, vulnerability or tool run, as from a record panel's *Timeline* button), to text in the title or detail, and to a date range (the end date is included).
* Each event keeps its own time. An evidence record whose source collected it at another time (an SBOM's creation time, for instance) also shows that time as `observedAt`, so the time an event happened and the time Cyber Hub recorded it are not confused.
* The filtered timeline exports as CSV or JSON (at most 10,000 events) through a native save dialog.

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
