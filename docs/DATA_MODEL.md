# Project data model (schema 9)

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
* Web checks record web services (status, title, server, certificate trust) and technologies seen in headers.
* Service scans record addresses, open services (service, product, version) and products as technologies.

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
