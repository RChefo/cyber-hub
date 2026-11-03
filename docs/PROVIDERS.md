# Threat-intelligence providers

Cyber Hub queries each provider from the Rust backend with the user's own key, stored in the OS credential store. Every provider is optional and can be turned off in Settings → Threat intelligence providers. Requirements below are taken from each provider's public API documentation (checked November 2026); plans and limits can change, so check the provider before relying on them.

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
