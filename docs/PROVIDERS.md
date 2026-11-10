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

## STIX 2.1 export

*Saved indicators* → *STIX 2.1* writes every saved indicator as a STIX 2.1 `indicator` in one `bundle`, through a native save dialog (`src-tauri/src/ti/stix.rs`).

* **Patterns.** `[ipv4-addr:value = '…']`, `[ipv6-addr:value = '…']`, `[domain-name:value = '…']`, `[url:value = '…']`, and `[file:hashes.MD5 / 'SHA-1' / 'SHA-256' / 'SHA-512' = '…']` by hash length. String literals escape only `\` and `'`, as the patterning language requires. A hash of another length is reported and left out.
* **Identifiers.** Indicator IDs are UUIDv5 values derived from the indicator (a fixed Cyber Hub namespace), so exporting the same indicator again gives the same ID and an importing platform updates one object. The bundle ID is a random UUIDv4. `created`, `modified` and `valid_from` are the time the indicator was saved, in UTC with milliseconds.
* **Content.** The description is the analyst's note. No provider verdicts are claimed: `indicator_types` and labels are left out, so the bundle states only what the analyst saved.
* **Lifecycle.** The analyst's confidence becomes `confidence`. *Valid until* becomes `valid_until` (the end of that day, UTC). Revoked indicators and false positives get `revoked: true`, and a false positive says so in its description. The source becomes an external reference whose description gives its reliability. An indicator whose validity ended before it was saved is not exported and is named in the result, since STIX requires `valid_until` to be later than `valid_from`.

