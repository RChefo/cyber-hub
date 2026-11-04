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
* **The bridge** (`mcp/bridge.rs`, `mcp/proto.rs`) runs inside the Cyber Hub app only while **Allow MCP clients** is on (MCP page in the sidebar). It listens on `127.0.0.1` on a random port and writes `bridge.json` (port) and `bridge.key` (a fresh 256-bit key per session) to `<app data>/mcp/`. Both sides prove knowledge of the key before any request (HMAC-SHA256 challenge/response). A process without the key can neither use the bridge nor pose as Cyber Hub. The files are removed when MCP is turned off or the app exits.
* **Operations** (`mcp/ops.rs`) call the same functions as the GUI. A run requested through MCP goes through `start_execution`: the same validation, scope engine (exclusions included), target-file snapshots, native confirmation dialog and process-tree management as a run you start yourself. There is no second execution path.
* **Cyber Hub must be running.** Without it, tools return "Cyber Hub is not running or MCP is turned off".

## The MCP page

MCP has its own page in the sidebar (Integrations → MCP). The switch at the top turns MCP on or off. The sections are:

| Section | Shows |
|---|---|
| Overview | Server state, transport (STDIO), local bridge address, connected clients, catalog size, waiting approvals, recent activity |
| Approvals | The Approval Center: every waiting request with the client, action, project, target, the checks Cyber Hub ran, and time left; Approve and Decline; recent decisions from the audit log |
| Clients | Connected clients (from the running bridge) and clients seen before (from the audit log), with self-reported name and version, last activity, request counts and the latest result |
| Tools | All 34 tools from the server catalog, grouped as below, with permission category, whether they ask you under the current policy, availability and parameters |
| Resources & prompts | The resources, the scope template and the prompts, with their parameters |
| Permissions | The policy for each category (below) |
| Activity | The audit log, filterable by client, permission category and status, with redacted arguments per entry |
| Connect | Executable path, Claude Code and Claude Desktop setup with copy buttons, verification and troubleshooting |

The page reads everything from the app: the catalog comes from the same definitions `cyberhub-mcp` advertises, and clients and activity come from the bridge and the `mcp_audit` table. MCP settings are no longer in Settings.

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

MCP page → **Permissions**:

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
2. The request appears in the Approval Center (MCP page → Approvals), and Cyber Hub's taskbar entry flashes if it is in the background. On any other page or section, a dialog shows it instead. Both show the client name (as reported by the client), the operation, the checks that passed, and details such as program, arguments, project and authorized targets.
3. Only you can approve, in Cyber Hub's own window. The decision commands are not reachable through the bridge, so an MCP client cannot approve its own request or change its permissions.
4. **Runs** then show the usual native "Confirm tool execution" dialog, which names the requesting client. **Uploads** open the native file picker, where you choose the file; an optional `expected_sha256` must match. Then the usual public-upload warning and native confirmation follow. **Exports** use the native save dialog.
5. If you have not decided within 50 seconds, the tool returns `status: "awaiting_approval"` with an `approvalId` that the client can poll with `cyberhub_get_approval_status`. Requests expire after 3 minutes and are cancelled if the client disconnects. At most 20 can wait at once, 5 per client connection.

Approve is disabled for a second whenever the waiting requests change (in the dialog: a new request comes to the front; in the Approval Center: a request is added, decided or expires), so a click aimed at one request cannot approve another. A request whose time is up shows as expired and cannot be approved.

Turning MCP off disconnects every client and cancels pending requests.

### Audit log

Every MCP tool call is recorded, including refused and unknown ones (MCP page → Activity, table `mcp_audit`, last 1,000 entries):

* time, client (self-reported) and connection number;
* tool and arguments, with credentials redacted and capped at 1,000 characters;
* permission category that applied (for example, a CVE lookup with `live: true` counts as an external lookup);
* project and approval outcome (`not_required`, `approved`, `denied`, `expired`, `cancelled`, `pending`, `denied_by_policy`);
* approval ID, run ID, result, error message (redacted), and duration. An approved request is recorded with its final result, even if you decide after the client stopped waiting.

## Connecting a client

`cyberhub-mcp` is set up to be installed with Cyber Hub as a Tauri sidecar, in the same folder as the Cyber Hub executable. Cyber Hub is still in development and no installer is built yet; these are the paths the packaging will use:

| Platform | Installed path |
|---|---|
| Windows (MSI) | `C:\Program Files\Cyber Hub\cyberhub-mcp.exe` (or the folder chosen during setup) |
| Windows (NSIS setup, per user) | `%LOCALAPPDATA%\Cyber Hub\cyberhub-mcp.exe` (or the folder chosen during setup) |
| Linux (.deb, .rpm) | `/usr/bin/cyberhub-mcp` |
| Linux (AppImage) | inside the AppImage's temporary mount; see the limitation below |

Cyber Hub finds it next to its own executable and never uses the working directory or PATH. The **Connect** section shows the path actually in use. During development, `cargo build --bin cyberhub-mcp` puts it next to the debug app in `src-tauri/target/debug`.

Then turn on **Allow MCP clients** on the MCP page. Its **Connect** section shows the exact executable path and copy buttons for the snippets below, filled with that path.

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

Claude Desktop is available for Windows. Add to `%APPDATA%\Claude\claude_desktop_config.json`, merging with any existing `mcpServers`, then restart Claude Desktop:

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
* **Unscoped tools:** tools that are not target-based scanners in the catalog (for example OpenSSL, hashcat, tshark) are not scope-checked. Their approval shows a warning saying so, and the native confirmation repeats it. Approval details and the native confirmation show the arguments exactly as the client sent them, unredacted, so nothing can be hidden from you; the audit log stores them redacted.
* **Working folder:** tools run in a private folder in Cyber Hub's app data (`work`), so a relative file name in an argument never reads from or writes to the installation folder.
* **Audit retention:** the newest 1,000 ordinary entries are kept. Entries tied to an approval or a run are kept separately (newest 5,000), so a client cannot push the record of approved actions out by flooding cheap calls.
* **Clients share one trust level:** every client on the bridge holds the same key. A client can read the output of any run if it knows the run ID, and the client name is self-reported. Approval IDs are random 96-bit values that are never listed to clients.
* **Approved runs keep running after the client disconnects,** and `cyberhub_cancel_run` can stop any run started through MCP, whichever client started it. A native confirmation that is still open stays open until you answer it.
* **Installed builds (packaging deferred):** `cyberhub-mcp` is configured as a Tauri sidecar (`bundle.externalBin`). `tauri build` runs `scripts/build-sidecar.mjs` first, which compiles it for the target platform (without the provisioning feature) and stages it as `src-tauri/binaries/cyberhub-mcp-<target triple>`. Installers containing the sidecar have not been built yet. The bundling was checked through the configuration and an equivalent release layout in a folder with spaces in its path, not through a real installer.
* **AppImage:** the sidecar runs from the AppImage's temporary mount, whose path changes on every start, so client configurations break after a restart. The MCP page warns about this. Use the .deb or .rpm package for MCP.
* **Uninstalling:** the uninstallers remove `cyberhub-mcp` with the app. If an MCP client is still running it, close that client first, because a running executable cannot be deleted on Windows. Client configurations (Claude Code, Claude Desktop) are not changed by the uninstaller; remove the `cyberhub` entry there. The bridge key and info files exist only while MCP is on and Cyber Hub is running; they are deleted when MCP is turned off or the app exits, and any left by a crash are removed at the next start. App data, including the audit log, is kept unless you delete it (the Windows NSIS uninstaller offers to).
* **Platforms:** Windows was tested end to end with a scripted MCP client and with Claude Code, including an installed-style layout in a folder with spaces; Claude Desktop was not available for testing. On Linux (Debian 12 and Ubuntu 24.04 containers, virtual display) the MCP page, the bridge files' permissions (0600 in a 0700 folder), discovery, approvals with the native GTK dialog, declines and turning MCP off were tested with a scripted client; Claude Code was not tested on Linux. macOS is not supported.

## Troubleshooting

| Symptom | Check |
|---|---|
| Tools return "Cyber Hub is not running or MCP is turned off" | Start Cyber Hub and turn on MCP on the MCP page. |
| "could not authenticate the Cyber Hub app" | Restart Cyber Hub (it writes a new key); make sure `cyberhub-mcp` and the app come from the same build. |
| A tool returns `awaiting_approval` | Approve or decline in the Approval Center, then poll `cyberhub_get_approval_status`. |
| "… is turned off for MCP clients" | The category is set to Block under MCP page → Permissions. |
| The client name shows "unknown MCP client" | The client sent no `clientInfo`; this is display-only. |
| Nothing appears under MCP page → Activity | The client did not reach the app (see the first row). |
| "Arguments that refer to local files … are not accepted" | Pass targets directly, or start the file-based run in Cyber Hub. |
| "Only runs started through MCP can be cancelled" | Cancel that run in Cyber Hub. |
| "cyberhub-mcp is missing from the Cyber Hub installation folder" | Reinstall Cyber Hub. |
| The client fails to start the server after Cyber Hub was updated or moved | Copy the setup command again from the MCP page → Connect; the path may have changed. |
