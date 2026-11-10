# TAXII credentials on Windows: manual test procedure

**Status:** written in Mission 7, **not yet performed.** Fill in the results table at the end when you run it.

Windows' credential dialog (CredUI) runs at a higher integrity level than other programs, so Windows' UI isolation (UIPI) stops a test script from typing into it. This test therefore needs a person.

On Linux, the same flows run automatically against the GTK dialog in the Mission 6 and Mission 7 GUI phases, including a check that no copy of a credential reaches the disk. See MISSION_REPORT.md for those results.

**Use only the throwaway values below. Never type a real or production credential into this test.**

## What you need

* A Windows 11 computer or VM where you can install Node.js 22 and build the repository (`npm ci` works).
* The repository at the release-candidate commit.
* About 45 minutes.

### Test values

These are accepted only by the local test server.

| What | Value |
|---|---|
| HTTP Basic user name | `qa-analyst` |
| Password | `QA-only-not-a-real-secret-7f3a` |
| Rotated password | `QA-rotated-secret-55e1` |
| API key (header `X-API-Key`) | `QA-only-api-key-91c2` |

## Preparation

1. **Start a development build with its own data folder.** It must never be your real profile. Debug builds accept plain HTTP to 127.0.0.1 for TAXII; release builds require HTTPS, which is why this test uses a development build.

   ```powershell
   $env:CYBERHUB_DATA_DIR = "$env:TEMP\cyberhub-taxii-test"
   npm run tauri dev
   ```

2. **Start two test servers in two other terminals.** Port 18557 stands in for "the server moved".

   ```powershell
   node scripts/qa/taxii-mock.mjs --port 18556 --log "$env:TEMP\taxii-18556.log"
   node scripts/qa/taxii-mock.mjs --port 18557 --log "$env:TEMP\taxii-18557.log"
   ```

   Each request is logged with whether a credential arrived and which test value it matched. The value itself is never logged.

3. **Note the credential store before you start.** Cyber Hub's entries are generic credentials whose names contain `taxii_` and `dev.cyberhub.workstation`.

   ```powershell
   cmdkey /list | Select-String -SimpleMatch "taxii_"
   ```

   You should get no output.

## Steps

Record every observation in the table at the end. Screenshots are the evidence for dialogs; log lines are the evidence for what a server received.

| # | Do | Expected |
|---|---|---|
| 1 | *Threat Intel → TAXII feeds → Add a server*: name `QA feed`, URL `http://127.0.0.1:18556/taxii2/`, *HTTP Basic*, user name `analyst-initial`. Save. | The card says no credential is stored. Both server logs are empty. `cmdkey /list` shows no `taxii_` entry. |
| 2 | *Store credential…* | Windows' credential dialog opens, titled *Store a TAXII credential*. Its message names the server and `127.0.0.1`. The user name field shows `analyst-initial`. |
| 3 | Type user name `qa-analyst` and the password; confirm. | The dialog closes, the card shows a stored credential, and the server's user name is now `qa-analyst`. `cmdkey /list` shows one entry named `taxii_1_` followed by 16 hex digits. The password never appears in the window. |
| 4 | *Discover*. In the native confirmation, try Enter at once. | The confirmation *Connect to a TAXII server* names `127.0.0.1`. Cancel is the default, *Connect* is disabled for about a second, and Enter at once closes it without connecting: an information toast says it was not connected. The log of 18556 has no new line. |
| 5 | *Discover* again and press *Connect* after the delay. | *QA collection* is listed. The log of 18556 shows `/api1/collections/ credential: basic user=qa-analyst matches the test password`. |
| 6 | *Sync* on *QA collection*, then *Connect*. | A green toast says *Feed synchronized*, with 3 added. *Saved indicators* lists `198.51.100.23`, `c2.example.net` and `https://phish.example.org/login`, from the feed. The log shows the objects request with the matching password. |
| 7 | *Sync* again and press *Cancel* in the confirmation. | An information toast (not an error) says it was not connected. No new log line. |
| 8 | *Replace credential…*, type the rotated password. *Discover*. | The log shows `matches the test rotated password`. `cmdkey /list` still shows one entry for the server. |
| 9 | *Replace credential…*, then *Cancel* (try Escape and the window's close button as well). | Nothing changes. The next *Discover* still uses the rotated password. |
| 10 | **Leak check, with a credential stored and used.** Run the commands under *Leak check* below. Then export: *Project → Report → Save as HTML…* and *Save as Markdown…*, the saved indicators as STIX, and a database backup (*Settings → Back up*). Search those files the same way. | No file contains any of the three test values. |
| 11 | *Edit*: URL `http://127.0.0.1:18557/taxii2/` (another port, so another origin). | Before saving, the form warns that saving deletes the stored credential and removes the collection listed for the old address. |
| 12 | Save, then *Discover*. | The card shows no stored credential and the collection is gone. `cmdkey /list` shows no `taxii_` entry. Discover is refused before anything is sent (no password is stored for this server), so neither log gets a line. **The old credential never followed the server.** |
| 13 | *Edit*: back to `http://127.0.0.1:18556/taxii2/`. Save. | No credential is stored; the earlier one is not reused. |
| 14 | *Edit*: *API key in a header*, header `X-API-Key`. Save. *Store credential…*: type the API key. *Discover*, *Connect*. | The dialog asks for the API key; its user field shows the header name. 18556's log shows `x-api-key matches the test API key`. |
| 15 | *Edit*: header name `X-Other-Key`. | The form warns that saving deletes the stored credential (*sent in another header*). After saving, no credential is stored. |
| 16 | *Store credential…* again (password or key, as set), then *Forget credential…*. In the native confirmation, try a click at once, then *Delete* after the delay. | The early click does nothing; *Delete* removes it. The card shows no stored credential and `cmdkey /list` shows no `taxii_` entry. |
| 17 | *Store credential…* again, then *Remove* the server. | The in-app confirmation mentions the stored credential. The server and its `cmdkey` entry are gone, and saved indicators stay. |

### Leak check (step 10)

A credential must exist only in Windows Credential Manager. Search the test data folder, including the database, its write-ahead log and its logs:

```powershell
$values = "QA-only-not-a-real-secret-7f3a", "QA-rotated-secret-55e1", "QA-only-api-key-91c2"
Get-ChildItem -Recurse -File "$env:CYBERHUB_DATA_DIR" | Select-String -SimpleMatch -Pattern $values | Select-Object Path, LineNumber
```

The output must be empty. Run the same search on the exported HTML, Markdown and STIX files and on the backup.

Also check these:

* *Dashboard → activity*: *TAXII synchronization* entries contain counts, never a credential.
* *MCP* (optional): enable it, connect a client, and call `cyberhub_get_status` and `cyberhub_list_supported_providers`. MCP has no TAXII tool, and no answer contains a test value. *MCP → Activity and audit* shows the calls without one either.
* *Diagnostics*: the developer tool reports only whether credentials are configured. If you built it (`cargo build --features provisioning --bin cyberhub-keys`), run `cyberhub-keys status`: no test value appears.

## Cleanup

1. Remove the server in the app if it still exists, and stop the test servers and the development build.
2. Delete `$env:TEMP\cyberhub-taxii-test` and the two server logs.
3. Check that `cmdkey /list | Select-String -SimpleMatch "taxii_"` prints nothing. If an entry is left, delete it with `cmdkey /delete:<the target name it lists>`.

## Results

| # | Observed | Pass / fail | Evidence |
|---|---|---|---|
| 1–17 | | | |
| Leak check | | | |
| Cleanup | | | |

Tester, date, Windows build, commit: ____________________
