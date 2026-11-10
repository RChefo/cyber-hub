# Threat-intelligence providers

Cyber Hub queries each provider from the Rust backend with credentials provisioned by the application owner and kept in the OS credential store ([PROVISIONING.md](PROVISIONING.md)). End users do not manage keys. Every provider is optional and can be turned off in Settings → Threat intelligence providers, which also shows read-only availability. Requirements below are taken from each provider's public API documentation (checked November 2026); plans and limits can change, so check the provider before relying on them.

## Integrated

| Provider | Indicator types | Endpoint used | Authentication | Documented access / limits | What it adds |
|---|---|---|---|---|---|
| **VirusTotal** (API v3) | IP, domain, URL, MD5/SHA-1/SHA-256 | `GET /ip_addresses`, `/domains`, `/urls/{id}`, `/files/{hash}`; uploads: `POST /files` (≤ 32 MB), `GET /files/upload_url` + one-time URL (≤ 650 MB); `GET /analyses/{id}` | `x-apikey` header | Free community key: 4 requests/minute plus daily/monthly caps. Submitted files and queried indicators can become part of the VirusTotal dataset. | Multi-engine verdicts, reputation, file analysis |
| **AbuseIPDB** (APIv2) | IP | `GET /check?maxAgeInDays=90&verbose` | `Key` header | Free account: 1,000 checks/day; remaining quota is returned in `X-RateLimit-*` headers and shown after each lookup. | Abuse confidence score, report categories, ISP / usage type, recent reports |
| **AlienVault OTX** (DirectConnect v1) | IP (v4/v6), domain/hostname, URL, file hash | `GET /indicators/{type}/{indicator}/general` | `X-OTX-API-KEY` header | Free account key. No published request limit; Cyber Hub stays under 30/minute. | Community pulses referencing the indicator, malware families, adversaries, ATT&CK IDs |
| **URLhaus** (abuse.ch) | URL, host (domain/IP), payload MD5/SHA-256 | `POST /v1/url/`, `/v1/host/`, `/v1/payload/` | `Auth-Key` header (free abuse.ch account) | Free under fair use; commercial use may require a paid abuse.ch / Spamhaus subscription. | Malware distribution URLs, online status, payloads served |
| **MalwareBazaar** (abuse.ch) | MD5/SHA-1/SHA-256 | `POST /api/v1/` `query=get_info` | same abuse.ch `Auth-Key` | Same as URLhaus. | Known malware samples: family, file metadata, ClamAV / vendor intelligence, YARA matches |
| **ThreatFox** (abuse.ch) | IP (matches `ip:port` IOCs), domain, URL, MD5/SHA-256 | `POST /api/v1/` `search_ioc` / `search_hash` | same abuse.ch `Auth-Key` | Same as URLhaus. IOCs older than six months are expired by ThreatFox. | IOC → malware family mapping (C2 servers, payload delivery), confidence level |
| **Shodan** | IP | `GET /shodan/host/{ip}`, `GET /api-info` | `key` query parameter (required by the API) | Every account has a key; host lookups do not consume query credits; all plans are limited to 1 request/second. | Open ports, service banners, hostnames, CVE tags from service metadata |

ThreatFox was not in the original list. It was added because it uses the same free abuse.ch key as URLhaus and MalwareBazaar and is the abuse.ch source that maps IPs, domains and URLs to malware families.

## Deferred

| Candidate | Reason |
|---|---|
| **VirusTotal private scanning** | Requires a Private Scanning licence. It could not be tested without one, and a public upload must never be presented as private, so only the standard public submission is implemented and labelled as public. |
| **Shodan InternetDB** (keyless) | Free for non-commercial use only ("If you're using the InternetDB API to make money then you need an enterprise license"), and data is refreshed weekly. The keyed Shodan host API covers the same data with clearer terms. |
| **GreyNoise Community API** | Useful for separating Internet background scanners from targeted activity, but it was not evaluated against its current terms in this release. |
| Reporting / submitting to providers (AbuseIPDB report, URLhaus submission, ThreatFox submission) | Out of scope by design: Cyber Hub never reports, submits or blocks anything at a provider. Any such action would need its own explicit confirmation. |

## How results are shown

* Every provider result keeps the provider's own verdict wording and scores. Scores from different providers are never converted or combined.
* A coarse colour bucket (malicious / suspicious / benign / informational / no verdict) is used only for sorting and colour. The mapping for each provider is documented in its parser (`src-tauri/src/ti/*.rs`) and shown on each result card.
* The summary lists which providers reported what. It is a grouping, not a score.
* Each result shows its source (live or cache), retrieval time and a link to the provider's own page.

## Saved indicators

*Saved indicators* on the Threat Intel page keep each indicator with its lifecycle (`src-tauri/src/ti/lifecycle.rs`; schema 26). *Edit* on an indicator changes the following, and every change is recorded in its history (`ti_saved_events`):

* **Source** (up to 300 characters): the report, feed, case or colleague the indicator came from. The time it was saved is its collection time.
* **Source reliability** on the Admiralty scale: A completely reliable, B usually reliable, C fairly reliable, D not usually reliable, E unreliable, F cannot be judged; or not judged.
* **Confidence** from 0 to 100, as in STIX 2.1, read as none (0), low (1–29), medium (30–69) or high (70–100).
* **Valid until**, a date. Past it the indicator reads as *expired*. Expiry is computed when the list is read, so nothing has to run for indicators to age.
* **Status:** active, revoked (no longer valid), or false positive.

Expired, revoked and false-positive indicators stay saved for the record, but are not presented as current intelligence:
* The Analysis tab says where each saved indicator stands, for example "expired 2026-10-31: no longer current" or "marked a false positive".
* An analyst's false positive outweighs a provider's cached verdict: the indicator is no longer flagged, and the verdict stays visible.
* An expired or revoked save hides no provider verdict.

Saved intelligence never flags an indicator by itself.

## TAXII 2.1 feeds

*Threat Intel → TAXII feeds* imports STIX 2.1 indicators from TAXII 2.1 servers (OASIS TAXII Version 2.1, 2021-06-10) that the analyst adds. The client is in `ti/taxii.rs`, the commands in `commands/taxii.rs`, and the data in schema 28 (`taxii_servers`, `taxii_collections`, `taxii_syncs`, and the feed columns of `ti_saved`).

* **Nothing connects until asked.** A server is added with a name, its discovery URL, how it authenticates, a source reliability (A–F) and a confidence to use when an indicator gives none. *Discover* lists its API roots and collections. *Sync* downloads one collection's new indicators. Each connection is confirmed in a native dialog that names the server, and nothing synchronizes in the background.
* **Transport:**
  * HTTPS only. Plain HTTP is accepted for 127.0.0.1 or localhost in debug builds, for tests.
  * No user name or password in the URL, and redirects are not followed, so credentials never reach another host.
  * An API root on another host than the discovery URL is not used.
  * Requests ask for `application/taxii+json;version=2.1` and time out after 30 s.
  * Responses are capped at 16 MB, and a synchronization at 200 pages and 100,000 objects; the next synchronization continues.
  * Errors are mapped (credentials refused, no access, not found, not TAXII 2.1, redirect refused) and never contain the credential, even when the server echoes it.
* **Credentials** (HTTP Basic, which TAXII 2.1 clients must support, or an API key in a named header) are the analyst's own, so they are entered in the app, but never in the web view:
  * *Store credential…* on the server's card opens a dialog of the operating system (Windows' credential dialog, a GTK dialog on Linux). The value goes from that dialog straight to the OS credential store; the web view can open the dialog but never reads or sends the value. For HTTP Basic the dialog also asks for the user name, which becomes the server's.
  * *Replace credential…* rotates it, *Forget credential…* deletes it after a native confirmation, and *Discover* tests the connection with it.
  * A stored credential is bound to the server's number, origin (scheme, host and port), kind of authentication and, for an API key, header (Mission 7). It is never read for anything else: not after an edit, and not when a restored database or another data folder names another server under the same number. It is deleted when one of those changes or the server is removed, and the dialog stores nothing if the server changed while it was open, so a credential never follows a server elsewhere.
  * A collection is synchronized only while its API root is on the server's own origin. Editing a server's origin removes the collections of the old one (their indicators stay, with their source); *Discover* lists the new server's.
  * `cyberhub-keys taxii-set <server number> <discovery URL> basic|header [header]` still stores one from a terminal ([PROVISIONING.md](PROVISIONING.md)).
  * The app reads it only to connect; the web view only learns whether one is stored.
* **Incremental synchronization.** Objects are requested 500 at a time (`match[type]=indicator`), following `next`, or `added_after` from `X-TAXII-Date-Added-Last` when the server gives no `next` (§3.5). The collection keeps the last stored page's `X-TAXII-Date-Added-Last` as its cursor. A failure keeps the pages already stored and the cursor at the last one, so the next synchronization continues from there. Every synchronization is recorded: pages, objects, added, updated, revoked, already saved, skipped and the message. The collection shows its last status (health).
* **What is imported:** `indicator` objects whose STIX pattern is an equality, or an OR of equalities, on `ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value`, `url:value` or a file hash (MD5, SHA-1, SHA-256), with a value Cyber Hub accepts as a public indicator.
  * Other objects (malware, reports, relationships, observables), other pattern types (Snort, YARA, Sigma), AND, FOLLOWEDBY, other operators and qualifiers, and private addresses are skipped and counted with the reason. Nothing is approximated.
  * Each indicator becomes a saved indicator ([Saved indicators](#saved-indicators)): the feed as its source, the server's reliability, its STIX confidence (or the server's default), `valid_until` as its validity, `revoked` as its status, the STIX id and `modified` as its provenance. The history says it came from the feed.
* **Conflicts:** the analyst's record wins.
  * A value already saved by the analyst, or by another feed, keeps its fields, and the feed's view (confidence, validity, revocation) is added to its history as a sighting.
  * A false positive is never changed by a feed.
  * A feed updates only its own indicators, and only with a newer `modified`: confidence, validity, and revocation, which revokes the saved indicator.
* **A feed never creates a finding.** Its indicators are leads: Analysis can show them as sightings, while expired, revoked and false-positive indicators are not presented as current.
* **Tests** (`ti/taxii_tests.rs`, a local mock server):
  * discovery, collections, two pages through `next`, and the cursor on the next synchronization;
  * the media type and Basic credentials;
  * the analyst's and false-positive records left unchanged, revocation, and newer versions;
  * partial synchronizations, refused redirects, oversized and non-JSON responses, and credential scrubbing.

  The pattern and object readers are also in the hostile-input sweep.

## STIX 2.1 export

*Saved indicators* → *STIX 2.1* writes every saved indicator as a STIX 2.1 `indicator` in one `bundle`, through a native save dialog (`src-tauri/src/ti/stix.rs`).

* **Patterns.** `[ipv4-addr:value = '…']`, `[ipv6-addr:value = '…']`, `[domain-name:value = '…']`, `[url:value = '…']`, and `[file:hashes.MD5 / 'SHA-1' / 'SHA-256' / 'SHA-512' = '…']` by hash length. String literals escape only `\` and `'`, as the patterning language requires. A hash of another length is reported and left out.
* **Identifiers.** Indicator IDs are UUIDv5 values derived from the indicator (a fixed Cyber Hub namespace), so exporting the same indicator again gives the same ID and an importing platform updates one object. The bundle ID is a random UUIDv4. `created`, `modified` and `valid_from` are the time the indicator was saved, in UTC with milliseconds.
* **Content.** The description is the analyst's note. No provider verdicts are claimed: `indicator_types` and labels are left out, so the bundle states only what the analyst saved.
* **Lifecycle.** The analyst's confidence becomes `confidence`. *Valid until* becomes `valid_until` (the end of that day, UTC). Revoked indicators and false positives get `revoked: true`, and a false positive says so in its description. The source becomes an external reference whose description gives its reliability. An indicator whose validity ended before it was saved is not exported and is named in the result, since STIX requires `valid_until` to be later than `valid_from`.

