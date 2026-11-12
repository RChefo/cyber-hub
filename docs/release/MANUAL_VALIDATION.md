# Manual validation: M1–M7

These are the release-candidate checks that need a person, real hardware or a real desktop session. Mission 8 prepared them. **Mission 9 ran M2, M3, M6 and M7 in real GNOME and Plasma sessions of disposable VMs, with the development build** (results below, in *Mission 9: real desktop sessions*). What remains is in that section and in `RELEASE_READINESS.md`. Record each result in `RELEASE_READINESS.md` (manual checklist) with its evidence.

What was verified without a person, and where, is listed under *Already verified automatically* for each item. A container or an emulator is never counted as the real environment: a check run there is PARTIAL at most.

## Before any test

### Which build

| Items | Build | Why |
|---|---|---|
| M1 | Development build (`npm run tauri dev`) with an isolated data folder | TAXII over plain HTTP to `127.0.0.1` exists only in debug builds; the local test server speaks HTTP |
| M2–M7 | The release-candidate installers from the draft release (`RELEASE_CANDIDATE_PROCEDURE.md`) | These items check what users install |

### Protect your real data

Release builds keep their data in the same folder as development builds (the identifier is `dev.cyberhub.workstation` for both), and **they ignore `CYBERHUB_DATA_DIR`**:

* Windows: `%APPDATA%\dev.cyberhub.workstation`
* Linux: `~/.local/share/dev.cyberhub.workstation`

An installed release candidate opens and **upgrades** whatever database it finds there. Before installing one, do one of the following:

* use a VM, a spare computer or a separate operating-system account that has no Cyber Hub data (recommended);
* or copy your data folder somewhere else, then move it out of the way, and move it back after the test.

Never point a test at your real database.

### Test data

Create a project named `RC validation`, with these scope entries:

* `example.com` and `*.example.com` (public: no dialog);
* `192.0.2.0/24` (documentation space, which Cyber Hub treats as non-public: adding it shows a native dialog).

For the import checks, save this as `rc-nmap.xml`. It names only a documentation address. The `<runstats>` element marks a finished scan; without it the preview warns that the scan did not finish (the Mission 8 version of this file lacked it, Mission 9 corrected it):

```xml
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.0.2.10" start="1700000000" version="7.94">
  <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port></ports>
  </host>
  <runstats><finished time="1700000060" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
```

No check below contacts a real target. Do not run tools against hosts you are not authorized to test.

### Evidence

Keep one folder per item, `evidence/M<n>/<date>/`, with:

* screenshots (the whole screen, so the scale and the session are visible);
* the commands you ran and their output;
* the operating system's version, the desktop's version and the session type. On Linux, `echo $XDG_SESSION_TYPE $XDG_CURRENT_DESKTOP` and `gnome-shell --version` or `plasmashell --version` give them;
* the scale and the screen resolution;
* the build: installer file name and its SHA-256.

## M1: TAXII credentials in Windows' credential dialog

**Environment:** Windows 11, development build, isolated data folder, the local test servers (`scripts/qa/taxii-mock.mjs`).

**Steps, expected results and evidence:** `docs/release/TAXII_CREDENTIAL_TEST.md`, steps 1–17, the leak check and the cleanup. Its preparation step 3 tells you when **not** to run the test in your own Windows account.

**Pass:** every step as expected, the leak check finds nothing, and the cleanup leaves no `taxii_` entry. **Fail:** any test value outside Credential Manager, a credential sent to the wrong server, or an entry left behind.

**Already verified automatically (Mission 8, Windows):** everything except steps 2, 3 and 9 (16 of 16 checks, `cyberhub-keys` storing the values instead of the dialog). The person confirms what only the dialog can show:

* it appears for *Store credential…*;
* it names the server and `127.0.0.1`;
* it pre-fills the user name;
* it never shows the password;
* typing into it stores the credential;
* Cancel, Escape and the close button store nothing.

## M2: a full GNOME Shell session

**Environment:** Ubuntu 24.04 LTS desktop, on hardware or in a VM with 3D acceleration, logged in as a normal user. Use two sessions in turn, chosen with the gear icon on the login screen:

* *Ubuntu*: GNOME on Wayland, the default; Cyber Hub runs as a Wayland client;
* *Ubuntu on Xorg*.

In the Wayland session, also run the app once through **XWayland**: `GDK_BACKEND=x11 cyber-hub`.

**Install:** `sudo apt install ./Cyber.Hub_0.1.0_amd64.deb`. Then check that `/usr/bin/cyber-hub` and `/usr/bin/cyberhub-mcp` exist. Run the AppImage once too: `chmod +x Cyber.Hub_0.1.0_amd64.AppImage`, then start it.

| # | Do | Expected |
|---|---|---|
| 1 | Start Cyber Hub from the app grid | The window opens fully on the screen, at most 1440 × 900 or 94 % of the work area, with the title bar controls working. `stat -c %a ~/.local/share/dev.cyberhub.workstation` prints `700` |
| 2 | Open every page in the sidebar, then every tab of `RC validation` | Each page renders. No blank page, no error toast, no text cut off |
| 3 | Press `Ctrl+K`, type `RC`, press Enter. Then press Tab from the top of a page | The palette opens and finds the project. The first Tab shows *Skip to content*, and focus moves through the page visibly |
| 4 | Add the scope entry `192.0.2.0/24`. When the native dialog appears, press Enter at once | The dialog belongs to the Cyber Hub window, above it. Enter at once **cancels** (Cancel is the default), and the entry is not added |
| 5 | Add it again; wait one second, then click the approving button | The approving button works only after about a second; the entry is added |
| 6 | Click the terminal button in the top bar, then **Cancel**; click it again and approve | First nothing opens. Then a terminal opens in your home folder, empty |
| 7 | *Projects → RC validation → Findings → Import results → Choose file*, then choose `rc-nmap.xml` in the file dialog | The file dialog opens. The preview shows *Nmap* (Nmap XML), 0 findings and 3 assets (the host, its service and the software), with no warning: an open port alone is not a finding. *Import* commits it |
| 8 | *Report*: *Save as HTML…*, then *Save as Markdown…* | The save dialog proposes a file name; both files are written and open in a browser or editor |
| 9 | *Settings → Local data → Back up*, saving to your home folder; then *Restore* from that file and accept the restart | Both dialogs work. After the restart the restore notice appears, and the project, the finding and the scope are still there |
| 10 | Maximize, restore and minimize; drag the window to the second screen if there is one; try to drag it smaller than 800 × 480 | Every control works. The window stops shrinking at the minimum size (800 × 480 logical pixels) |
| 11 | Log out while Cyber Hub is open; log in and start it again | No error at start. The data is all there, and `cyber-hub` is not left running from the earlier session (`pgrep -a cyber-hub` before starting) |
| 12 | Close the window | `pgrep -a cyber-hub` prints nothing within 20 s |

**Evidence:**

* a screenshot of each step's result, per session;
* the output of `pgrep` and `stat`;
* the import preview;
* the restore notice.

**Pass:** every step as expected in both sessions and under XWayland. **Fail:** any of these:

* a step differs;
* a page does not render;
* a dialog opens behind the window or cannot be used with the keyboard;
* Enter approves a native confirmation at once;
* data is lost after a restore or a log-out.

**Already verified automatically:**

* Mutter as a native Wayland compositor in a container: 5/5;
* the same flows under Xvfb with Openbox on Ubuntu 24.04 and Debian 12: the dialogs, file choosers, backup, restore and restart.

The real session, with GNOME Shell, its panels, a GPU and log-out, was never tested.

## M3: a full KDE Plasma session

**Environment:** Kubuntu 24.04, or Debian 12 with KDE Plasma, on hardware or in a VM with 3D acceleration. Use two sessions:

* *Plasma (Wayland)*;
* *Plasma (X11)*.

In the Wayland session, also run `GDK_BACKEND=x11 cyber-hub` once. This is the real-hardware counterpart of the container's KWin-with-XWayland test (see below).

**Before you start:** credentials go through the Secret Service, and Plasma provides it only through KWallet when that is set up to do so. Check:

```bash
busctl --user list | grep -i org.freedesktop.secrets
```

* **If a provider is listed:** go on.
* **If none is listed:** do step 13 first, then enable KDE Wallet (*System Settings → KDE Wallet*) or install `gnome-keyring`, and log in again.

**Steps:** steps 1–12 of M2, in both sessions and under XWayland, plus:

| # | Do | Expected |
|---|---|---|
| 13 | With no Secret Service provider, try *Store credential…* on a TAXII server (M7, step 2) | An error toast says the credential could not be stored (record its exact text). Nothing else breaks, and nothing is written to disk |

**Evidence and pass/fail:** as M2.

**Already verified automatically:**

* KWin as a native Wayland compositor in a container: 5/5;
* KWin with XWayland in a container, with software rendering: 7/7, including the GTK credential dialog (into GNOME Keyring) and the file chooser.

Plasma itself, KWallet, a GPU and log-out were never tested.

### The KWin XWayland crash (Mission 6, explained in Mission 7)

* **What happened.** In Mission 6 the container session of KWin with XWayland crashed before Cyber Hub started.
* **What the evidence shows.**
  * Mission 7 reproduced it without Cyber Hub, with a diagnostic script kept among the QA harness files outside the repository: Xwayland segfaulted before any X client connected, even a plain `xdpyinfo`.
  * The crash is in Xwayland's GPU path (glamor) on KWin's virtual output, which has no GPU.
  * With `XWAYLAND_NO_GLAMOR=1` (software rendering), Xwayland, the X11 clients and Cyber Hub ran normally, and the desktop checks passed 7 of 7.
  * The Mission 8 regression repeated the run (MISSION_REPORT.md, "Mission 8").
* **Conclusion.** This is an environment fault of GPU-less containers, not of Cyber Hub. Cyber Hub sets no rendering option, and nothing was changed in the product, because there is no evidence of a fault on real hardware.
* **On real hardware**, step "XWayland" of M3 is the check. If Xwayland crashes there, save `journalctl --user -b | grep -i -A5 xwayland`, and compare with and without `XWAYLAND_NO_GLAMOR=1` before changing anything.

## M4: physical high-DPI screens

**Environment:**

* Windows 11 on a physical screen of 1920 × 1080 or more, at 100 %, 125 %, 150 % and 200 % (*Settings → System → Display → Scale*). If there are two screens with different scales, test across them too.
* Ubuntu 24.04 GNOME, on Wayland:
  * 100 % and 200 %;
  * the fractional scales 125 % and 150 %, after `gsettings set org.gnome.mutter experimental-features "['scale-monitor-framebuffer']"` and logging in again.
* Plasma at 125 %, 150 % and 200 % (*System Settings → Display*).

Changing the scale changes your desktop; set it back afterwards.

**Steps at each scale:**

1. Start Cyber Hub. Note the first window's size and position.
2. Open these, and type a few lines into each text box:
   * the dashboard;
   * *Projects → RC validation*: every tab;
   * the finding form (*New finding*);
   * the ATT&CK matrix;
   * the OSINT graph.
3. Trigger a native confirmation (M2 step 4) and a file dialog (M2 step 7).
4. Resize the window with the mouse to the minimum.
5. With two screens of different scales, drag the window from one to the other.

**Expected:**

* text and icons are sharp, not blurred;
* nothing is cut off or overlaps;
* the first window fits on the screen;
* the native dialogs are readable and fit;
* the minimum holds at 800 × 480 logical pixels;
* after moving between screens, the window re-lays out at the new scale within a second.

**Evidence:** a full-screen screenshot of each step at each scale, with the scale setting visible or named in the file name.

**Pass:** every scale as expected. **Fail:** a blurred window at a fractional scale, content that cannot be reached, a dialog that does not fit, or a window that opens partly off the screen.

**Already verified automatically:** emulated only.

* Windows: DevTools device emulation of every page at 100–200 % and 800 × 480 (`scripts/qa/layout-probe.mjs`).
* Linux: `GDK_SCALE=2` on a virtual 1920 × 1080 screen, 5/5.

No physical HiDPI screen was used. This machine's screens are at 100 %.

## M5: the minimum window on a real screen

**Environment:** any physical screen from M4, with the window at its minimum (800 × 480 logical pixels).

**Steps:**

1. Use the sidebar, which shows icons only below 1024 pixels.
2. Open *Projects*, then a project and each of its tabs.
3. Open a record panel (a finding) and a dialog (*New finding*).
4. Do all of it with the keyboard alone, then with the mouse.

**Expected:** everything can be reached by scrolling the page, never by scrolling sideways. Dialogs fit or scroll inside themselves.

**Evidence:** screenshots of each view.

**Pass:** nothing is unreachable. This item does not block the release.

**Already verified automatically:**

* emulated at 800 × 480 on Windows;
* the minimum enforced by the window manager, and the pages fitting at 800 × 480 on Linux (Xvfb, Openbox), 3/3 per distribution;
* **in a real window (Mission 8):** on Windows, the application window was resized to 800 × 480 on a physical 1920 × 1080 screen at 100 %. Every page, every project tab and the finding form passed, 37/37, with screenshots. That window was resized by a program, which Windows lets go below the minimum; resizing with the mouse, HiDPI scales and Linux sessions remain for this test.

## M6: desktop portals and the native file chooser

**How it works.** Cyber Hub's file dialogs are GTK's `GtkFileChooserNative` (Tauri's dialog plugin with its default GTK backend):

* **Outside a sandbox** (DEB, RPM, AppImage), it shows GTK's own file chooser.
* **Through the XDG desktop portal**, it shows the desktop's own chooser, such as KDE's. This happens inside a Flatpak or Snap sandbox, or when `GTK_USE_PORTAL=1` is set.

**Environment:** the M2 and M3 sessions.

**Steps:**

1. In a terminal, run `dbus-monitor --session "interface='org.freedesktop.portal.FileChooser'"`.
2. In another terminal, run `GTK_USE_PORTAL=1 cyber-hub`.
3. Import `rc-nmap.xml` (Open), save a report (Save), back up (Save) and add an evidence file (Open).
4. Run Cyber Hub again without the variable, and repeat one Open.

**Expected:**

* **With the variable:** each dialog is the desktop's own (on Plasma, KDE's), the monitor prints an `OpenFile` or `SaveFile` call for each, and the files are read and written.
* **Without it:** GTK's chooser, and no portal call.

**Evidence:** screenshots of both kinds of dialog, and the monitor's output.

**Pass:** as expected. This item blocks the release only if Cyber Hub is shipped sandboxed (Flatpak or Snap), which is not planned.

**Already verified automatically:** nothing. The containers had no portal service.

## M7: a real login keyring

**Environment:**

* GNOME: GNOME Keyring, with its login keyring unlocked when you log in;
* Plasma: KWallet serving the Secret Service, or `gnome-keyring`.

Use the M2 and M3 sessions.

| # | Do | Expected |
|---|---|---|
| 1 | *Threat Intel → TAXII feeds → Add a server*: `https://taxii.example.invalid/taxii2/`, HTTP Basic, user `qa-analyst`. **Do not press Discover**: the address does not exist and nothing is contacted | The card says no credential is stored |
| 2 | *Store credential…*; type the password `QA-only-not-a-real-secret-7f3a`; confirm | The GTK dialog belongs to the window; the card shows a stored credential |
| 3 | `secret-tool search --all service dev.cyberhub.workstation \| grep -E "^(label\|attribute)"` | One entry, `username = taxii_<n>_<16 hex>`. Do not copy the `secret` line into evidence |
| 4 | Quit Cyber Hub and start it again; then log out and in, and start it again | The card still shows a stored credential each time, with no unlock prompt after the login |
| 5 | Lock the keyring (*Passwords and Keys* on GNOME, *KDE Wallet* on Plasma); then *Replace credential…* | The desktop asks to unlock it once; after unlocking, the replacement is stored. If you cancel the unlock, a clear error appears, nothing is stored, and no prompt loops |
| 6 | *Forget credential…*, approving the native dialog after the delay | The card shows no credential; step 3's search finds nothing |
| 7 | Remove the server | Nothing of it is left in the keyring |

**Evidence:** screenshots, and the output of step 3 with the `secret` lines removed.

**Pass:** every step as expected in both desktops. **Fail:** any of these:

* the credential is not kept across a restart or a login;
* an unlock prompt loops;
* the value appears anywhere but the keyring.

**Already verified automatically:**

* GNOME Keyring in containers, unlocked by a script, not by a login, on Ubuntu 24.04 and Debian 12: store, rotate, cancel, forget, deletion on every change, no copy on disk, 16/16;
* the Mission 7 race fix, with 0 of 17 removals right after Store leaving a credential behind.

## Mission 9: real desktop sessions (2026-11-11)

**Environments.** Disposable VirtualBox 7.2.6 VMs on the owner's Windows 11 machine, created for the test and NAT-only:
* **Ubuntu 24.04.5** (kernel 6.8): GNOME Shell 46.0, GDM 46.2. Three sessions: *Ubuntu* (Wayland), *Ubuntu on Xorg*, and XWayland (`GDK_BACKEND=x11` in the Wayland session).
* **Debian 12.**
  * Desktop: KDE Plasma 5.27.5, KWin 5.27.5, SDDM.
  * Sessions: *Plasma (Wayland)*, *Plasma (X11)*, and XWayland.
  * Credential stores: GNOME Keyring 42.1 provides the Secret Service; KWallet 5 is installed beside it.

Each session started with a password login at GDM or SDDM, typed on the VM's virtual keyboard, so PAM unlocked the login keyring as it does for a person. Screens are 1280 × 800 at 100 %; rendering is in software (no 3D acceleration).

**Build.** The development build (debug profile, frontend embedded) of the fixed code, built in the Ubuntu 24.04 and Debian 12 images. It is the same code as the release candidate, **but not its packages**. Not covered yet:
* the deb, AppImage and rpm themselves;
* the desktop entry and the app-grid launcher;
* `/usr/bin` paths;
* the data folder of an installed copy.

Those wait for the candidate (`RELEASE_CANDIDATE_PROCEDURE.md`).

**How it was driven.**
* **The page:** through WebDriver (`tauri-driver` with WebKitWebDriver).
* **Native GTK dialogs:** read and answered through AT-SPI, which works on Wayland and X11 alike.
* **Real key presses:** on the VM's virtual keyboard: Return at once on a confirmation, Ctrl+L and typed paths in file choosers, Alt+F4, the login password.
* **Screenshots:** full-screen, from VirtualBox. MISSION_REPORT.md, "Mission 9", says where the screenshots and logs are kept.
* **Limitations:** KDE's portal dialogs are Qt windows, which AT-SPI did not list, so they were typed into blind and judged by screenshots and results. GNOME's portal chooser (GTK 4) completes paths inline while keys arrive, so on Xorg its path was set through AT-SPI.

| Item | Result | Evidence folder |
|---|---|---|
| M2: GNOME | **PASS.** Wayland: all 12 steps. Xorg: steps 1–8, the backup of step 9, 10 and 12. XWayland: steps 1–6, 10 and 12. Details below the table | `M2-gnome-wayland*`, `M2-gnome-xorg`, `M2-gnome-xwayland` |
| M3: Plasma | **PASS** for M2's steps 1–6, 10 and 12 in Plasma Wayland, X11 and XWayland. In Wayland also the import, both reports and the backup (7, 8, 9's backup), and step 11. Details below the table. **Credentials:** see M7 | `M3-kde-*` |
| M6: portals | **PASS.** Details below the table | `M6-*` |
| M7: login keyring, GNOME | **PASS** for steps 1–7 in the Wayland session. Details below the table | `M7-gnome-wayland*` |
| M7: Plasma | **Not usable in this Debian configuration.** Details below the table. KWallet as the Secret Service was not tried: it needs KWallet's interactive first-run setup. **Open** | `M3-kde-wayland` |
| M4, M5 | Not tested again: physical HiDPI screens were not available | |

**M2 in GNOME** (every step in Wayland; the subsets above in Xorg and XWayland):
* **Window:** the first window fills GNOME's work area beside the dock (1214 × 768 of 1280 × 800); Mutter enlarges windows that nearly fill it. The data folder is `700`.
* **Pages:** all 17 pages and 19 project tabs render without an error.
* **Keyboard:** Ctrl+K "RC" + Return opens the project, after the palette fix of Mission 9.
* **Confirmations:** a real Return at once cancels (Cancel is the default and has the focus), a click in the first second does nothing, and approving after the delay adds the scope entry.
* **Terminal:** it asks first; approving opens gnome-terminal.
* **Files:** the GTK file chooser imports, both reports save, and the backup saves.
* **Restore:** chosen, checked and applied. Cyber Hub restarts itself into the restored database ("Database restored" in the activity) and keeps the previous one in `backups/before-restore-<time>/`.
* **Window controls:** maximize, restore and minimize work; the minimum is 800 × 480 and the page fits.
* **Log-out:** logging out with Cyber Hub open leaves no process, and the data is there after logging in again.
* **Closing:** Alt+F4 ends the process in about 0.5 s.

**M3 in Plasma:**
* **Window:** the first window is exactly 94 % of the work area (1203 × 752), as specified.
* **Confirmations:** the dialogs have KWin's title bar.
* **Terminal:** it opens Konsole in the home folder (`x-terminal-emulator`).
* **XWayland:** it ran under the real KWin with no crash: the Mission 6 container crash does not occur here.
* **Log-out:** logging out with Cyber Hub open leaves no process, and the data is kept.

**M6 (portals):**
* **With `GTK_USE_PORTAL=1`:** one Open and one Save each reached `org.freedesktop.portal.FileChooser` (`OpenFile`, `SaveFile`, recorded with `dbus-monitor`). They went to the desktop's own chooser: GNOME's GTK 4 chooser in Wayland and Xorg, and KDE's "… — Portal" dialog in Plasma Wayland. The files were read and written.
* **Without the variable:** GTK's chooser inside Cyber Hub, and no portal call.

**M7 in GNOME (Wayland session):**
* **Steps 1–3:** the GTK dialog names the server and host, shows the user name and hides the password. The typed password is stored as one entry, `taxii_1_<16 hex>`.
* **Step 4:** the credential is still stored after a restart and after logging out and in, with no unlock prompt.
* **Step 5, unlocking:** with the keyring locked, *Replace* makes GNOME Shell ask "Authentication required" once; after the login password, the replacement is stored.
* **Step 5, cancelling:** cancelling that prompt gives a clear error ("Secret Service: unlock prompt was dismissed"), nothing is stored, and no prompt follows.
* **Step 6:** Forget, after the delay, leaves nothing.
* **Step 7:** removing the server leaves nothing.

**M7 in Plasma (this Debian configuration):** GNOME Keyring lists a `login` collection that it does not serve. `secret-tool store` hangs, and Cyber Hub's Store fails at once, with nothing stored and nothing else affected, with: "Secure storage error: Platform secure storage failure: DBus error: Object does not exist at path “/org/freedesktop/secrets/collection/login”". That is the behaviour step 13 asks for.

**Found and fixed in these sessions (with tests):**
* the palette ranking (`810e024`);
* a partial restore copy left in the data folder (`ed99331`);
* a locked keyring that raised an unlock prompt and held the database while the TAXII list was shown, and then showed a stored credential as missing (`63d2cd6`).

**Not done, and why:**
* **M1:** the Windows 11 VM's setup hung under VirtualBox with Hyper-V active: no disk write after 20:23Z, a black screen.
* **M4:** no physical HiDPI screen.
* **Packaging checks:** need the release candidate, which needs the update-signing secrets.

## Mission 10: Windows, KWallet and virtual HiDPI (2026-11-11 and 12)

**Environments.**
* **A new Windows VM, `chqa-win11b`.**
  * Windows 11 Enterprise Evaluation 26H2, build 26300.9457 (the registry's `ProductName` still says "Windows 10", as on every Windows 11).
  * Local user `tester`, NAT only, Guest Additions 7.2.6, WebView2 157.0.4341.46.
  * Settings that let it install under VirtualBox with Hyper-V: 2 vCPUs, no paravirtualization, an emulated TSC.
  * Its Credential Manager held no `taxii_` entry; the test stops if it finds one.
* **The Mission 9 Linux VMs:** Ubuntu 24.04.5 with GNOME 46 (Wayland) and Debian 12 with Plasma 5.27.5 (X11).

**Build.** Not the packages: development builds of the final code (`63d2cd6`). On Windows: debug profile with the frontend embedded (`--features tauri/custom-protocol`). On Linux: Mission 9's builds.

| Item | Result | Evidence folder (`E:\CyberHubQA\evidence\`) |
|---|---|---|
| M1: Windows credential dialog | **PASS, 17/17**, every credential typed into Windows' own dialog (run 3, 2026-11-12T00:04–00:07Z) | `M1-windows` (screenshots), `M1-windows\run1`–`run3` (logs) |
| M7: Plasma with GNOME Keyring | **PASS**, steps 1–7, Plasma X11 | `M7-kde-x11-gnomekeyring` |
| M7: Plasma with KWallet as the Secret Service | **PASS**, steps 1–7 with KWallet's own prompt, Plasma X11 | `M7-kde-kwallet`, `M7-kde-kwallet-2` |
| M4: virtual HiDPI, GNOME Wayland | **PASS, 5/5 at each of 100, 125, 150 and 200 %** (virtual, not a physical screen) | `M4-virtual-gnome` |
| M4: virtual HiDPI, Windows 11 | **PASS, 5/5 at each of 100, 125, 150 and 200 %** (virtual) | `M4-virtual-windows` |
| M5: the minimum window | **PASS** at the same four scales: GNOME by a window resize, Windows by a mouse drag | as M4 |

**How M1 ran.** It followed `TAXII_CREDENTIAL_TEST.md`, all 17 steps, inside the VM:
* `m1-vm.mjs` drove the app through WebView2's DevTools protocol, with the local test servers on `127.0.0.1:18556` and `:18557` and a data folder in the VM's temporary folder.
* Windows' credential dialog runs above the test's integrity level, so the host typed into it through the VM's virtual keyboard (`typist.mjs`), with a screenshot before and after each dialog.

What it showed:
* **Store.** The "Store a TAXII credential" dialog (Windows Security) names the server and its host. The typed user name and password become one entry, `taxii_<id>_<16 hex>`, with the password masked. Opening the dialog again shows the user name and an empty password: a stored secret is never shown.
* **Discover and Sync.** Both ask natively first, and declining sends nothing. Approving sends the stored credential to that server only: the test server confirmed the typed password, then the rotated password, then the API key in its header.
* **Cancel, Escape and the close box** store nothing, and the earlier password stays in use.
* **Deletion.** Moving the server to another origin or another header deletes the credential. So do Forget (after the delay) and Remove, whose confirmation names the credential.
* **No leaks.** No test value appears in the data folder, the STIX export, the backup, diagnostics, the activity or MCP results.
* **At the end:** no `taxii_` entry is left in the VM's Credential Manager.

**Step 16 in runs 1 and 2: a harness error, not the app.** Runs 1 and 2 passed 16 of 17. Step 16 checks that a click on Delete before its one-second delay does nothing.
* Run 1 sent the "early" click only after two PowerShell helpers had started, seconds after the dialog opened, when Delete was already enabled. The click therefore approved the deletion, which is correct.
* Run 2's new clicker looked the button up by a control ID that task-dialog buttons do not carry (they all have 0), so it never clicked.
* Run 3's clicker waits for the dialog before it opens, and finds the button by its label:
  * found 13 ms after the dialog appeared, with Delete disabled;
  * a click at 59 ms left the dialog open;
  * Delete was enabled at 993 ms;
  * a click at 1,105 ms deleted the credential.

**M7 in Plasma.**
* **GNOME Keyring.** After a fresh boot, `secret-tool` stores and reads back, and Cyber Hub's steps 1–7 pass. Mission 9's failure (a `login` collection that was listed but not served) was the state of that session, not a Plasma incompatibility.
* **KWallet.** GNOME Keyring was removed. `kwalletd5` (KDE Frameworks 5.103) then served `org.freedesktop.secrets` (`apiEnabled=true`), and `pam_kwallet5` opened `kdewallet` at login. `secret-tool` works against it, and Cyber Hub's steps 1–7 pass.
  * Step 5 needs the wallet closed first. In the first attempt there was no prompt: the Secret Service *Lock* call failed with "Can't lock object", and the wallet opened silently through `pam_kwallet5`'s login.
  * With the wallet closed first, KWallet's own "KDE Wallet Service" password prompt appeared. After the password, the replacement was stored. Cancelling gave a clear error, stored nothing, and no prompt followed.

**M4: virtual HiDPI (not a physical screen).**
* **GNOME 46 Wayland**, 2560 × 1600, set through Mutter's `DisplayConfig` with `scale-monitor-framebuffer`. The scales were 100, 125, 150 (Mutter's 1.5023) and 200 %. At each:
  * the page's screen is the logical one (2560 × 1600 divided by the scale);
  * the first window fits; at 200 % it is sized to the work area, 1214 × 768;
  * six pages lay out without sideways scrolling;
  * the native confirmation has Cancel as the default, with the focus, and Authorize disabled at first;
  * the 800 × 480 minimum holds;
  * the page reports no error.

  `devicePixelRatio` is 1 at 100 %, **2 at 125 and 150 %**, and 2 at 200 %. GTK 3, and so WebKitGTK, has whole-number scales only: it renders at the next one and Mutter scales the window down, which can soften text at fractional scales. A physical screen is needed to judge that.
* **Windows 11**, 2560 × 1600, scales set as Settings sets them. At each:
  * `devicePixelRatio` and the window's DPI equal the scale (1, 1.25, 1.5 and 2; 96 to 192 DPI);
  * the page's screen is 2560 × 1600 divided by the scale;
  * the first window's visible frame lies inside the work area; at 200 % it is sized to 94 % of it, 1203 × 707 logical pixels;
  * six pages lay out without sideways scrolling;
  * the native confirmation opens with Cancel as the default, and Cancel answers it;
  * a mouse drag of the window's corner toward 300 × 200 pixels stops at 800 × 480 logical pixels: 800 × 480, 1000 × 600, 1200 × 720 and 1600 × 960 physical.
* **Windows, an observation:** a resize sent by another program (`SetWindowPos`) is not limited by the minimum, because Windows applies a window's minimum tracking size to sizing by the user only. No user action produces it (FEATURE_BACKLOG.md, item 92).
* **Not verified:** sharpness on a physical panel, mixed-DPI monitors, Plasma's scaling.

**VM problems met: the environment, not Cyber Hub.**
* **VirtualBox on Hyper-V:** resuming a saved state crashed a VM process, and VBoxSVC then hung. Only cold boots are safe.
* **Ubuntu:** its boot stalls in the btrfs RAID6 benchmark with 2 vCPUs.
* **Windows:** the first VM hung in setup. In the second, the host's display-mode hint was not applied, so the mode was set from inside the session.
* **Debian:** Plasma's power management suspended the guest after about 40 idle minutes, and its e1000 network adapter hung on resume. Toggling the virtual link reset it.

**Not done:** the packages (deb, AppImage, rpm, NSIS, MSI), because no release candidate exists.

## Results

Record each item's result, date, tester, environment and evidence folder in `RELEASE_READINESS.md` (*Manual release-candidate checklist*).
