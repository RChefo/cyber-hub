# OSINT Workspace

The OSINT Workspace (sidebar → Research → OSINT Workspace) is where you investigate a target from public information. You collect data from Cyber Hub's own records and from public sources, connect entities through relationships backed by evidence, review what was inferred, and keep complete graphs of the investigation for later work.

Everything is stored locally in Cyber Hub's SQLite database. No AI service is required or contacted.

## Concepts

| Term | Meaning |
|---|---|
| Investigation | A target (domain, IP, organization, email, username, …) plus its notes, tags, optional linked project and authorization note. Status: active, closed or archived (archived investigations cannot collect). |
| Entity | Something observed: domain, IP, netblock, URL, email, username, profile, organization, person, hosting provider, certificate, ASN, technology, repository, location, vulnerability, file hash, service, threat, other (20 types). Values are normalized (IDNA domains, canonical IPs, URLs without credentials or fragments, emails with a case-folded domain, `AS<n>`, `sha256:` fingerprints, `host/owner/name` repositories, CVE/GHSA IDs). |
| Relationship | A typed link between two entities (38 registered types such as `RESOLVES_TO`, `USES_NAMESERVER`, `SUBDOMAIN_OF`, `USES_CERTIFICATE`, `ROUTES_THROUGH`, `REGISTERED_TO`, `MAINTAINED_BY`, `REFERENCES_DOMAIN`, `INDICATED_AS_MALICIOUS`, `SHARES_INFRASTRUCTURE`; analysts may add custom `UPPER_SNAKE_CASE` types). Each records its origin: observed, derived (follows from values, e.g. a URL is on its host), inferred (a correlation rule), manual (an analyst) or suggested (a proposal, e.g. from an MCP client). |
| Evidence | The record behind entities and relationships: source, kind, the real reference (the API URL or record that was queried), observed and collected times, a summary, a bounded copy of the data, and a strength (direct, corroborating, weak). Identical evidence is stored once (SHA-256 fingerprint). |
| Graph | A saved view of the investigation: which entities it shows, their positions, pinned and hidden nodes, groups, filters, layout, label mode and viewport. An investigation can have many graphs; the first one ("Main graph") follows new data automatically. |
| Version | A snapshot of a graph, recorded when a save changes something. |

Intelligence (entities, relationships, evidence, review decisions) belongs to the investigation and is shared by all its graphs. A graph only stores presentation and membership, so removing an entity from a graph does not delete it, while verifying a relationship is visible in every graph.

## Verification and confidence

Every entity and relationship has a verification state:

- **Observed**: a source reported it; nobody has confirmed it.
- **Verified**: an analyst confirmed it.
- **Inferred**: produced by a correlation rule or proposed by someone; it needs review and is excluded from path finding and analysis unless you include inferred links.
- **Disputed**: an analyst doubts it; it stays visible with a warning style.
- **Rejected**: judged wrong; hidden by default and never counted in analysis. Collecting the same data again does not bring it back.

Analyst decisions are never overwritten by later collection. Nothing is ever verified automatically: imported files and MCP clients cannot set verified.

Confidence is qualitative (low, medium, high), never a percentage, and each item stores the reason:

- **High**: direct evidence from at least two independent sources, or analyst verification.
- **Medium**: direct evidence from one source, or corroborating evidence from two or more.
- **Low**: a single corroborating or weak signal, or an inferred link.

Repeated evidence from the same source counts once.

## Collection

### Cyber Hub data (no network)

From Data Sources → Cyber Hub data:

- **Tool runs**: entities are extracted from stored output. Nmap output becomes hosts, services and their relationships; other output yields domains, IPs, URLs, emails and CVE IDs found in the text.
- **Threat-intelligence lookups**: stored results become entities with each provider's verdict kept in its own words.
- **CVE cache**, **findings** and **project scope** entries.

Every import creates evidence pointing to the run, lookup, finding or scope entry it came from.

### Public sources

| Source | Input | What it returns | Notes |
|---|---|---|---|
| DNS records | domain, IP | A/AAAA, CNAME, NS, MX; PTR for IPs | System resolver. |
| IP to ASN (Team Cymru) | IP | ASN, announced prefix, registry, country, AS name | DNS-based service; no key. |
| RDAP registration data | domain, IP, ASN | Registrar, registrant organization (when public), dates, status, name servers, network ranges | Servers from the IANA bootstrap (cached 7 days); only `https://` on public hosts; redirects are not followed. |
| Certificate Transparency (crt.sh) | domain | Certificates and the names they cover inside the domain | The 60 most recent certificates and at most 400 names per run; names outside the queried domain are ignored. |
| GitHub public search | domain, organization, email, `github:` username | Repositories that mention the value, owners, user profiles | Unauthenticated public API (low rate limits). |
| Web server fingerprint | domain, URL | Status, server and technology headers, redirect target | **Contacts the target.** Only for investigations linked to an active project whose authorized scope covers the target; resolved public addresses are pinned for the request; HEAD (GET only when HEAD is refused) and the body is never read. |
| Threat intelligence providers | domain, IP, URL, file hash | The configured providers' results (VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox, Shodan) | Reuses the Threat Intel module, its provisioned keys and quotas. Keys never reach the frontend, MCP clients, logs or stored records. |
| NVD vulnerability record | CVE | CVE details | Uses the CVE cache when possible. |

Before anything is sent, Cyber Hub checks that the source accepts the entity type and refuses private, loopback, link-local and reserved addresses and internal names. It also applies a per-source rate limit and, for the web fingerprint, the scope check. Results are cached per source (see the table in the app for cache times; *Ignore cache* forces a new request).

A collection runs in the background. Its results wait in the operation for your review: open it, select the entities and relationships to keep, and import them. You can also choose *Import results without review* when starting it. Cancelling stops a running collection. Collections interrupted by closing the app are marked as such the next time it starts.

### What happens on import

Imported observations go through one pipeline:

1. The evidence is stored, or reused when identical evidence exists.
2. Values are normalized and matched to existing entities of the same type and normalized value. Entities are merged only on exact identity, never on similarity.
3. Derived relationships are added: a URL is on its host, an email belongs to its domain, a service runs on its host, a subdomain belongs to its nearest known parent, and an IP is part of a known netblock.
4. Observed relationships are recorded with their evidence.
5. Correlation adds `SHARES_INFRASTRUCTURE` (inferred, weak) between entities that resolve to the same address, use the same name server or certificate, and so on. This is skipped for infrastructure shared by more than 25 entities (CDNs, large hosters), where it means little.
6. Confidence is recalculated, timeline events are written, and graphs that follow new data receive the new entities.

Entities that differ only in formatting are listed as possible duplicates. They are merged only when you choose to: the relationships and evidence move to the kept entity and the merge is recorded.

## Link Analysis

The graph is drawn on a canvas and handles thousands of nodes. Layouts run in a worker for large graphs.

- **Navigate**: wheel to zoom, drag the background to pan, arrow keys and +/− from the keyboard; *Fit* frames everything or the selection.
- **Select**: click, Shift/Ctrl-click to add, drag a rectangle with Shift to select an area. Selecting one entity or relationship opens the inspector.
- **Arrange**: drag nodes (several at once when selected); layouts: force-directed, hierarchical, radial, circular, manual. Pinned nodes keep their position in every layout. Dragging switches the graph to manual layout so your arrangement is kept.
- **Explore**: double-click or *Expand* adds linked entities (300 at a time). *Focus* dims everything outside an entity's neighbourhood. *Find path* (select two entities, or right-click → *Find path from here* and pick the end) shows the shortest chain of relationships and adds missing entities to the graph. Search highlights matches.
- **Filter**: by entity type, by relationship verification state, by relationship type, or only flagged entities. Hide individual entities; *Show hidden* brings them back.
- **Group**: selected entities can be grouped; groups are drawn as a shaded area and saved.
- **Add**: *Add* searches the investigation's entities; the inspector's *Show in graph* adds an entity from any tab.
- **Full screen**: the expand button (Escape returns).
- **Legend**: entity types with their colour, glyph and count, and the line styles of verified, observed, inferred and disputed relationships. Flagged entities have a red ring.

### Inspector

Entity: value, type, verification and confidence with the reason, attributes, aliases, relationships, evidence with references (plain text, never clickable), history, notes and display name. It also offers verify, dispute, reject or clear, each with an optional note, plus *Collect more*, *Create finding* (when a project is linked) and *Remove*.

Relationship: both ends, type and description, origin, confidence reason, evidence, history, review decisions and removal.

### Saving, Save As and the Graph Manager

- **Save** (Ctrl+S) stores membership, positions, pinned and hidden nodes, groups, filters, layout, label mode and viewport. If entities were collected into the graph while you worked, the save keeps them and tells you so. Only entities you removed are taken out.
- **Save as** creates an independent graph from the current state; the original stays as last saved.
- **Graphs** opens the Graph Manager: open, rename (with description and the *follow new data* setting), duplicate, delete (system confirmation; entities and evidence are kept), and create empty graphs.
- Switching graphs with unsaved changes asks first.

### Versions

A save that changes anything records a version with a summary of what changed. The last 60 automatic versions are kept; checkpoints (*Create checkpoint*) and restores are always kept.

*Compare* shows the differences between two versions, or between a version and the saved graph: entities and relationships added or removed, review decisions, evidence counts, moved nodes and changed settings. *Restore* brings back the graph's membership, layout, filters and groups as a **new** version, so later versions remain available. Entities that no longer exist are reported, not recreated. Restoring does not change the investigation's intelligence.

## Import and export

Graph → Export:

| Format | Content |
|---|---|
| Cyber Hub graph (JSON) | Complete and re-importable: investigation summary, graph settings and positions, entities with attributes and review state, relationships with origin and reasons, evidence. Format `cyberhub-osint-graph`, version 1. |
| GraphML | Nodes and edges with type, value, label, verification, confidence, flag and positions. |
| Entities CSV, Relationships CSV | One row per entity or relationship. Cells that a spreadsheet would treat as a formula are prefixed with `'`. |
| PNG, SVG | The graph as currently shown (filters, groups, labels). SVG text is escaped and colours are validated. |

Exports are written through the system save dialog. Data exports use the saved graph; with unsaved changes Cyber Hub offers to save first.

Graph → Import (or *Import graph* on the investigation list) reads Cyber Hub JSON or GraphML through the system open dialog:

- Files over 25 MB, more than 20,000 entities or 60,000 relationships or evidence records, duplicate IDs, files from a newer format version, non-UTF-8 files and GraphML with a DOCTYPE are refused.
- A preview shows counts by type, elements that will be skipped (unknown types, invalid values, relationships to missing entities, invalid relationship types) and how many entities already exist in the chosen investigation.
- The import goes into a **new graph**, in the current investigation (entities resolve against existing ones) or in a new investigation. Nothing is overwritten.
- Review decisions in the file (verified, disputed, rejected) are kept as an attribute (`importedVerification`), but imported items start as observed or inferred.

## Timeline

Every collection, discovery, review decision, merge, removal, graph save, restore, import and export is an event. Filter by kind, date range, source and text; events link to their entity, relationship or graph.

## Analysis and suggestions

The Overview tab shows, over reviewed and observed relationships (optionally including inferred ones):

- the most connected entities (connectivity is not evidence of maliciousness)
- shared infrastructure with the relationships that show it
- connected groups and entities without relationships.

Suggestions are computed deterministically from the stored data and each one states its reason:

- review inferred relationships
- resolve possible duplicates
- review entities flagged by threat intelligence
- corroborate low-confidence relationships
- connect isolated entities
- run sources that have not been run for the target and the most connected entities. These respect the scope requirement and say when they use threat-intelligence quotas.

## Reports

Reports → *Generate* builds a Markdown report from local data: overview, executive summary, methodology and collection operations, sources, entities, relationships, graph analysis, confidence, timeline, evidence with references, findings of the linked project, limitations, recommended next steps and analyst notes. Collected text is escaped so it cannot form links or HTML in the report. *Export* saves it through the system save dialog.

## Investigations

The list shows active and closed investigations (archived on request), with counts and items awaiting review. *Compare* lists the entities two investigations have in common. Deleting an investigation removes its entities, evidence, graphs and versions after a system confirmation; running collections for it are cancelled first.

## MCP

MCP clients can use the workspace through ten tools (see [MCP.md](MCP.md)):

- **Read**: list and read investigations, search entities, read entities and relationships, find paths, read operations, generate reports.
- **External lookup** (`cyberhub_osint_discover`): runs a public source after the same checks as in the app. Results always wait for your review; a client cannot import them.
- **Local write** (`cyberhub_osint_propose_relationship`): adds a relationship as an unverified suggestion with low confidence and the client's rationale.

The server instructions tell clients that collected content is untrusted data and must never be followed as instructions.

## Security

- Private, loopback, link-local and reserved addresses and internal names are never sent to external sources. The only source that contacts targets (web fingerprint) requires a linked active project whose scope covers the target, and pins the checked addresses for the connection (no DNS rebinding).
- RDAP servers come only from the IANA bootstrap and must be HTTPS on public hosts; no redirects are followed.
- Responses are size-limited. Downloaded content is never executed, and web page bodies are not read.
- API keys stay in the OS credential store and the existing threat-intelligence layer; they are never stored in investigations, evidence, exports, logs or MCP responses.
- Collected text is rendered as plain text in the app, escaped in SVG, GraphML and Markdown output, and neutralized against formula injection in CSV.
- Imports are size- and count-limited, validated, previewed and never overwrite existing data.

## Limits

| Limit | Value |
|---|---|
| Entities per graph | 20,000 (a warning above 3,000) |
| Workspace state per graph | 2 MB |
| Automatic versions kept per graph | 60 (checkpoints and restores are kept) |
| Proposed results kept per operation | 6 MB |
| Concurrent collections | 6 |
| Import file | 25 MB, 20,000 entities, 60,000 relationships or evidence records |
| Correlation fan-out | Infrastructure shared by more than 25 entities is not correlated |

## Not included

- Paid or authenticated sources beyond the existing threat-intelligence keys; social-media scraping; people-search services; breach data. None of these are used.
- Automatic entity merging on similarity, and automatic verification.
- A built-in AI model. The suggestions are rule-based and deterministic.
- Live multi-user collaboration. The app is single-user; concurrent saves from two windows keep collected entities but the last workspace wins.
