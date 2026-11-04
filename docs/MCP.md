# MCP integration

Cyber Hub can be used by AI clients that speak the [Model Context Protocol](https://modelcontextprotocol.io), such as Claude Code and Claude Desktop. The client can discover tools, read projects and scope, preview and request tool runs, query threat intelligence, VirusTotal and CVE data, and generate reports. Every sensitive operation is decided by **you, inside Cyber Hub**.

## Architecture

```
MCP client (Claude Code, Claude Desktop, …)
   │  stdio, MCP JSON-RPC
   ▼
cyberhub-mcp            separate executable, started by the client; no credentials, no business logic
   │  TCP 127.0.0.1 (loopback only), mutual HMAC authentication, 4 MiB frames
   ▼
Cyber Hub app           policy · approvals · audit log
   └─ existing services: scope engine, execution engine (start_execution), native confirmations,
      VirusTotal / threat-intel providers, NVD, projects, findings, reports, SQLite
```

* **`cyberhub-mcp`** is built from the same code base (`src-tauri/src/bin/cyberhub-mcp.rs`, `src-tauri/src/mcp/server.rs`) on the official Rust SDK `rmcp`. It speaks MCP over stdio (stdout carries only protocol messages; diagnostics go to stderr). It forwards tool calls and resource reads to the running app and serves prompts itself.
* **The bridge** (`mcp/bridge.rs`, `mcp/proto.rs`) runs inside the Cyber Hub app only while **Settings → Integrations → MCP → Allow MCP clients** is on. It listens on `127.0.0.1` on a random port and writes `bridge.json` (port) and `bridge.key` (a fresh 256-bit key per session) to `<app data>/mcp/`. Both sides prove knowledge of the key before any request (HMAC-SHA256 challenge/response). A process without the key can neither use the bridge nor pose as Cyber Hub. The files are removed when MCP is turned off or the app exits.
* **Operations** (`mcp/ops.rs`) call the same functions as the GUI. A run requested through MCP goes through `start_execution`: the same validation, scope engine (exclusions included), target-file snapshots, native confirmation dialog and process-tree management as a run you start yourself. There is no second execution path.
* **Cyber Hub must be running.** Without it, tools return "Cyber Hub is not running or MCP is turned off".

## Tools (34)

| Group | Tools | Permission category |
|---|---|---|
| Discovery | `cyberhub_get_status`, `cyberhub_list_modules`, `cyberhub_list_tools`, `cyberhub_get_tool_details`, `cyberhub_list_supported_providers` | read |
| Projects and scope | `cyberhub_list_projects`, `cyberhub_get_project`, `cyberhub_get_project_scope`, `cyberhub_validate_target`, `cyberhub_list_findings` | read |
| | `cyberhub_create_finding` | local write |
| Execution | `cyberhub_preview_run`, `cyberhub_get_run_status`, `cyberhub_get_run_output`, `cyberhub_cancel_run`, `cyberhub_list_runs` | read |
| | `cyberhub_run_tool` | run tools |
| VirusTotal | `cyberhub_vt_lookup`, `cyberhub_vt_lookup_hash`, `cyberhub_vt_get_analysis` | external lookup |
| | `cyberhub_vt_get_report` (cache only) | read |
| | `cyberhub_vt_upload_file` | file upload |
| Threat intelligence | `cyberhub_threat_intel_lookup`, `cyberhub_threat_intel_compare` | external lookup |
| | `cyberhub_get_saved_indicators` | read |
| | `cyberhub_save_indicator` | local write |
| Vulnerability intelligence | `cyberhub_lookup_cve`, `cyberhub_search_vulnerabilities` (external lookup with `live: true`), `cyberhub_get_vulnerability_details` | read |
| Reports and history | `cyberhub_generate_report`, `cyberhub_get_activity`, `cyberhub_get_run_details` | read |
| | `cyberhub_export_report` | export |
| Approvals | `cyberhub_get_approval_status` | read |

Arguments are JSON objects with strict schemas; unknown fields are rejected, and every value is validated again in Rust. `cyberhub_run_tool` takes a catalog tool ID, a project and an argument list. No shell is involved (pipes and redirection have no effect), and the program is always the detected catalog executable. Arguments that refer to local files (target lists such as `-iL`, wordlists, request or configuration files) are refused for MCP clients; pass targets directly, or start file-based runs in Cyber Hub. `cyberhub_cancel_run` stops only runs started through MCP. Threat-intelligence results keep each provider's own verdict and scores; there is no combined score.

## Resources

`cyberhub://status`, `cyberhub://projects`, `cyberhub://tools`, `cyberhub://providers`, `cyberhub://runs/recent`, `cyberhub://findings`, and the template `cyberhub://project/{project_id}/scope`. Each is served by the corresponding read-only tool; no other URI (for example `file://`) is accepted.

## Prompts

`network_reconnaissance`, `web_application_assessment`, `threat_intelligence_investigation`, `malware_hash_investigation`, `vulnerability_assessment`, `security_report_generation`. They tell the AI to work only inside the stored project scope, to validate targets and preview runs first, to prefer low-impact options, and never to work around scope checks or claim approvals it did not receive.

## Permissions and approvals

Settings → Integrations → MCP → **What MCP clients may do**:

| Category | Choices | Default |
|---|---|---|
| Read local data | Allow (fixed) | Allow |
| External lookups (VirusTotal, threat intelligence, live NVD) | Allow · Ask me · Block | Ask me |
| Create findings and save indicators | Ask me · Block | Ask me |
| Run security tools | Ask me · Block | Ask me |
| Upload files to VirusTotal | Ask me · Block | Ask me |
| Export reports | Ask me · Block | Ask me |

**Ask me** works as follows:

1. Cyber Hub validates the request first. Invalid arguments, unknown projects and out-of-scope or excluded targets are refused without asking you.
2. A dialog opens in Cyber Hub, and its taskbar entry flashes if it is in the background. The dialog shows the client name (as reported by the client), the operation, and details such as program, arguments, project and authorized targets.
3. Only you can approve, in Cyber Hub's own window. The decision commands are not reachable through the bridge, so an MCP client cannot approve its own request or change its permissions.
4. **Runs** then show the usual native "Confirm tool execution" dialog, which names the requesting client. **Uploads** open the native file picker, where you choose the file; an optional `expected_sha256` must match. Then the usual public-upload warning and native confirmation follow. **Exports** use the native save dialog.
5. If you have not decided within 50 seconds, the tool returns `status: "awaiting_approval"` with an `approvalId` that the client can poll with `cyberhub_get_approval_status`. Requests expire after 3 minutes and are cancelled if the client disconnects. At most 20 can wait at once, 5 per client connection.

When several requests are waiting, they are shown one at a time. Approve is disabled for a second whenever a new request comes to the front.

Turning MCP off disconnects every client and cancels pending requests.

### Audit log

Every MCP tool call is recorded, including refused and unknown ones (Settings → Integrations → MCP → Recent requests, table `mcp_audit`, last 1,000 entries):

* time, client (self-reported) and connection number;
* tool and arguments, with credentials redacted and capped at 1,000 characters;
* project and approval outcome (`not_required`, `approved`, `denied`, `expired`, `cancelled`, `pending`, `denied_by_policy`);
* approval ID, run ID, result, error message (redacted), and duration. An approved request is recorded with its final result, even if you decide after the client stopped waiting.

## Connecting a client

Build the server once (it is placed next to the Cyber Hub executable):

```sh
cd src-tauri
cargo build --release --bin cyberhub-mcp     # or without --release for development
```

Then turn on **Settings → Integrations → MCP → Allow MCP clients**. The panel shows the exact executable path and copy buttons for the snippets below, filled with that path.

### Claude Code

```sh
claude mcp add --transport stdio --scope user cyberhub -- "<path to>/cyberhub-mcp(.exe)"
```

Or, per project, in `.mcp.json`:

```json
{ "mcpServers": { "cyberhub": { "type": "stdio", "command": "<path to cyberhub-mcp>", "args": [] } } }
```

* **Verify:** `claude mcp list` (shows ✓ Connected) or `/mcp` inside Claude Code, which lists the `cyberhub` tools.
* **Remove:** `claude mcp remove cyberhub -s user`.

### Claude Desktop

Add to `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\claude_desktop_config.json`, macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`), merging with any existing `mcpServers`, then restart Claude Desktop:

```json
{ "mcpServers": { "cyberhub": { "command": "<path to cyberhub-mcp>", "args": [] } } }
```

* **Verify:** the tools menu in a new chat lists the `cyberhub` tools.
* **Remove:** delete the `cyberhub` entry and restart Claude Desktop.

The configuration contains only the executable path. It carries no keys, tokens or environment variables.

## Security notes and limitations

* **Credentials:** MCP clients never receive API keys. Provider requests are made by the app with credentials it reads from the OS credential store. `cyberhub-mcp` never touches them, and the provisioning tool is not part of it ([PROVISIONING.md](PROVISIONING.md)).
* **Same-user trust:** the bridge key file is readable by your OS account. Any program running as you can read it, connect to the bridge, and make requests that are then subject to your policy and approvals. That is the same trust level as that program clicking in Cyber Hub's window. Other OS users cannot read the key.
* **Client names are self-reported** and are shown as such. They are never used for authorization.
* **Local files:** MCP clients cannot pass file paths. Runs that need target lists or other input files are started in Cyber Hub. Tool outputs show program file names and `<local file>` instead of absolute paths.
* **Bridge frames** are authenticated by the handshake, not individually; the loopback connection is trusted for its lifetime.
* **Live output** of a run is available through MCP for runs started through MCP. The stored, redacted output is available for every run once it ends.
* **Approved operations continue if the client disconnects.** Requests that are still waiting are cancelled.
* **Installed builds:** the current installer configuration bundles only the Cyber Hub app. `cyberhub-mcp` must be built and placed next to `cyber-hub(.exe)` (or bundled as a Tauri sidecar in a future installer).
* **Platforms:** Windows was tested end to end with a scripted MCP client and with Claude Code; Claude Desktop was not available for testing. Linux builds and passes the unit tests in a container; macOS was not built or tested.

## Troubleshooting

| Symptom | Check |
|---|---|
| Tools return "Cyber Hub is not running or MCP is turned off" | Start Cyber Hub and turn on Settings → Integrations → MCP. |
| "could not authenticate the Cyber Hub app" | Restart Cyber Hub (it writes a new key); make sure `cyberhub-mcp` and the app come from the same build. |
| A tool returns `awaiting_approval` | Approve or decline in Cyber Hub, then poll `cyberhub_get_approval_status`. |
| "… is turned off for MCP clients" | The category is set to Block in Settings → Integrations → MCP. |
| The client name shows "unknown MCP client" | The client sent no `clientInfo`; this is display-only. |
| Nothing appears in Recent requests | The client did not reach the app (see the first row). |
| "Arguments that refer to local files … are not accepted" | Pass targets directly, or start the file-based run in Cyber Hub. |
| "Only runs started through MCP can be cancelled" | Cancel that run in Cyber Hub. |
