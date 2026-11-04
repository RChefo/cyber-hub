# Credential provisioning (application owner only)

Cyber Hub's provider integrations (VirusTotal, AbuseIPDB, AlienVault OTX, the abuse.ch services URLhaus / MalwareBazaar / ThreatFox, Shodan) and the optional NVD key use credentials that the **application owner** provisions. End users never see, enter, validate, replace or remove credentials, and the app has no screen or IPC command for doing so.

## How it works

* Credentials live in the **OS credential store** of the user account that runs Cyber Hub (Windows Credential Manager, macOS Keychain, Linux Secret Service), under the service name `dev.cyberhub.workstation`:

  | ID | Credential store entry | Used by |
  |---|---|---|
  | `virustotal` | `virustotal_api_key` | VirusTotal lookups and file analysis |
  | `abuseipdb` | `abuseipdb_api_key` | AbuseIPDB |
  | `otx` | `otx_api_key` | AlienVault OTX |
  | `abusech` | `abusech_auth_key` | URLhaus, MalwareBazaar, ThreatFox |
  | `shodan` | `shodan_api_key` | Shodan |
  | `nvd` | `nvd_api_key` | Vulnerability Intel (optional; raises the NVD rate limit) |

* The app's Rust backend reads an entry only inside the function that calls that provider. The web view only learns whether each provider is **configured**, never the value.
* Credentials are written with **`cyberhub-keys`**, a developer-only command-line tool. It is compiled only with the Cargo feature `provisioning`, so it is not part of the application binary, `tauri build` output or the installers.
* No credential is ever placed in source code, the JavaScript bundle, configuration files, environment variables or installer resources.

## Build the tool

```sh
cd src-tauri
cargo build --release --features provisioning --bin cyberhub-keys
# → target/release/cyberhub-keys(.exe)
```

During development you can also run it directly: `cargo run --features provisioning --bin cyberhub-keys -- status`.

## Provision credentials

Run the tool **as the same OS user that runs Cyber Hub**, on that machine.

### From a local secrets file

1. Copy `src-tauri/secrets.example.env` to `src-tauri/secrets.local.env`, or to any location outside the repository. `secrets.local.*`, `*.secrets` and `*.secrets.env` are ignored by git.
2. Fill in the values you have (empty lines are skipped):

   ```
   virustotal = <64 hex characters>
   abuseipdb  = …
   otx        = …
   abusech    = …
   shodan     = …
   nvd        = …
   ```

3. Import, then delete the file:

   ```sh
   cyberhub-keys import src-tauri/secrets.local.env
   ```

The tool refuses to import a file inside a git working tree unless git ignores it (`--allow-unignored` overrides this). Each value is format-checked and verified with one read-only request before it is stored (`--no-verify` skips the request, for offline provisioning).

### One credential at a time

```sh
cyberhub-keys set shodan            # hidden prompt
cyberhub-keys set shodan < key.txt  # or from standard input
```

Credentials are never accepted as command-line arguments, because those end up in shell history and process listings.

## Diagnostics

```sh
cyberhub-keys status        # configured / not configured per credential (values never shown)
cyberhub-keys test          # one read-only request per configured credential, with quota/plan
cyberhub-keys test shodan
cyberhub-keys remove otx    # or: remove all
```

`test` uses fixed public probes only (VirusTotal and AbuseIPDB `8.8.8.8`; OTX subscribed pulses; abuse.ch the EICAR test hash; Shodan `/api-info`; NVD `CVE-2021-44228`). Output is sanitized and never contains a credential.

Inside the app, Settings → Threat intelligence providers shows each provider's read-only availability: Not configured, Turned off, Available, Rate limited, Credentials rejected or Last request failed. It also shows the quota a provider reported with its last real request since the app started.

## Important limits of this model

* **Per machine and per user account.** The OS credential store is local, so every machine (and user account) that should have working integrations must be provisioned with `cyberhub-keys`. An installer distributed to other people contains no credentials; on their machines every provider shows **Not configured**.
* **The local user can read their own credential store.** Anyone who can run programs as that OS user can read the entries with OS tools. Provisioning your keys on someone else's machine therefore gives that person access to them. Cyber Hub only guarantees that the keys are not exposed through the app (UI, IPC, logs, history, database, exports or error messages).
* **Shared keys and quotas.** Every provisioned machine uses your provider accounts and quotas, and is subject to each provider's terms (several free tiers are for non-commercial use only).
* **Giving end users working integrations without handing them your keys** requires a server you operate: an API gateway that holds the keys, authenticates installations and enforces rate limits. Cyber Hub would then call your gateway instead of the providers. That is not implemented.

## MCP clients

MCP clients ([MCP.md](MCP.md)) never receive credentials and cannot provision, test or remove them. `cyberhub-mcp` holds no credentials and does not include the provisioning tool; provider requests made on behalf of an MCP client are performed by the Cyber Hub app with the provisioned credentials, after the user's policy and approvals allow them.

## Development and tests

* Automated tests never use real credentials or real provider APIs: they use local mock servers and fake constants.
* Debug builds can point every provider at a local mock (`CYBERHUB_MOCK_API_BASE=http://127.0.0.1:<port>`). The `cyberhub-keys` tool honours it in debug builds, which is useful for testing provisioning without real keys. The override is compiled out of release builds.
