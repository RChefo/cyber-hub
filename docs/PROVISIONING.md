# Credential provisioning (application owner only)

ExploitX's provider integrations (VirusTotal, AbuseIPDB, AlienVault OTX, the abuse.ch services URLhaus / MalwareBazaar / ThreatFox, Shodan) and the optional NVD key use credentials that the **application owner** provisions. End users never see, enter, validate, replace or remove these credentials, and the app has no screen or IPC command for doing so. (TAXII servers are the analyst's own: their credential is typed into a native dialog in the app; see [TAXII servers](#taxii-servers).)

## How it works

* Credentials live in the **OS credential store** of the user account that runs ExploitX (Windows Credential Manager, Linux Secret Service), under the service name `dev.cyberhub.workstation`:

  | ID | Credential store entry | Used by |
  |---|---|---|
  | `virustotal` | `virustotal_api_key` | VirusTotal lookups and file analysis |
  | `abuseipdb` | `abuseipdb_api_key` | AbuseIPDB |
  | `otx` | `otx_api_key` | AlienVault OTX |
  | `abusech` | `abusech_auth_key` | URLhaus, MalwareBazaar, ThreatFox |
  | `shodan` | `shodan_api_key` | Shodan |
  | `nvd` | `nvd_api_key` | Vulnerability Intel (optional; raises the NVD rate limit) |
  | `anthropic` | `anthropic_api_key` | Project assistant (Claude, Anthropic Messages API); `test` lists models, which uses no tokens |

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

Run the tool **as the same OS user that runs ExploitX**, on that machine.

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
   anthropic  = …
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

### TAXII servers

A TAXII server's password (HTTP Basic) or API key (a header) belongs to the analyst, not to the application owner, so it is normally entered in the app: *Threat Intel → TAXII feeds → Store credential…* opens a dialog of the operating system (Windows' credential dialog, a GTK dialog on Linux) that the web view cannot read, and stores the value in the credential store ([PROVIDERS.md](PROVIDERS.md#taxii-21-feeds)). The tool does the same from a terminal, with the number the server shows in that list, its discovery URL and its authentication exactly as set in the app:

```sh
cyberhub-keys taxii-set 3 https://taxii.example.org/taxii2/ basic                 # hidden prompt
cyberhub-keys taxii-set 4 https://feeds.example.net/taxii2/ header X-Api-Key
cyberhub-keys taxii-remove 3 https://taxii.example.org/taxii2/ basic
```

The entry is `taxii_<number>_<fingerprint>` in the same credential store. The fingerprint covers the URL's origin, the kind of authentication and the header's name, so the app uses the credential only while the server keeps them; after an edit it shows no stored credential and asks for one again. The user name is a setting of the server in the app; only the secret is stored here. Entries stored by earlier versions as `taxii_<number>` are no longer read; they are deleted when the server is removed, its credential is forgotten, or its address or authentication changes.

## Diagnostics

```sh
cyberhub-keys status        # configured / not configured per credential (values never shown)
cyberhub-keys test          # one read-only request per configured credential, with quota/plan
cyberhub-keys test shodan
cyberhub-keys remove otx    # or: remove all
```

`test` uses fixed public probes only (VirusTotal and AbuseIPDB `8.8.8.8`; OTX subscribed pulses; abuse.ch the EICAR test hash; Shodan `/api-info`; NVD `CVE-2021-44228`). Output is sanitized and never contains a credential.

Inside the app, Settings → Threat intelligence providers shows each provider's read-only availability: Not configured, Turned off, Available, Rate limited, Credentials rejected or Last request failed. It also shows the quota a provider reported with its last real request since the app started.

## Platform notes

* **Windows:** entries are stored in Credential Manager (verified with the tool and the app).
* **Linux:** entries are stored through the Secret Service D-Bus API in the default collection (verified with GNOME Keyring on Debian 12: `import`, `status`, the app reading the keys for lookups, `remove all`). The collection must exist and be unlocked, which a desktop login keyring provides. In a minimal session without a default collection the tool fails with "Secret Service: no result found" and stores nothing (seen in an Ubuntu 24.04 container). KWallet's Secret Service bridge was not tested.
* **TAXII credential dialog:** on Windows it is the system's credential dialog (`CredUIPromptForWindowsCredentials`, generic credentials, never saved by Windows itself); on Linux a GTK dialog of the app's own process. Storing then needs the same credential store as the tool: on Linux a Secret Service with an unlocked default collection.
* macOS is not supported.

## Important limits of this model

* **Per machine and per user account.** The OS credential store is local, so every machine (and user account) that should have working integrations must be provisioned with `cyberhub-keys`. An installer distributed to other people contains no credentials; on their machines every provider shows **Not configured**.
* **The local user can read their own credential store.** Anyone who can run programs as that OS user can read the entries with OS tools. Provisioning your keys on someone else's machine therefore gives that person access to them. ExploitX only guarantees that the keys are not exposed through the app (UI, IPC, logs, history, database, exports or error messages).
* **Shared keys and quotas.** Every provisioned machine uses your provider accounts and quotas, and is subject to each provider's terms (several free tiers are for non-commercial use only).
* **Giving end users working integrations without handing them your keys** requires a server you operate: an API gateway that holds the keys, authenticates installations and enforces rate limits. ExploitX would then call your gateway instead of the providers. That is not implemented.

## MCP clients

MCP clients ([MCP.md](MCP.md)) never receive credentials and cannot provision, test or remove them. `cyberhub-mcp` holds no credentials and does not include the provisioning tool; provider requests made on behalf of an MCP client are performed by the ExploitX app with the provisioned credentials, after the user's policy and approvals allow them.

## Development and tests

* Automated tests never use real credentials or real provider APIs: they use local mock servers and fake constants.
* Debug builds can point every provider at a local mock (`CYBERHUB_MOCK_API_BASE=http://127.0.0.1:<port>`). The `cyberhub-keys` tool honours it in debug builds, which is useful for testing provisioning without real keys. The override is compiled out of release builds.
