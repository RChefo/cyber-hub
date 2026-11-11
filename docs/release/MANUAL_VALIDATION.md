# Manual validation: M1–M7

These are the release-candidate checks that need a person, real hardware or a real desktop session. Mission 8 prepared them. **None has been performed.** Record each result in `RELEASE_READINESS.md` (manual checklist) with its evidence.

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

For the import checks, save this as `rc-nmap.xml`. It names only a documentation address:

```xml
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.0.2.10" start="1700000000" version="7.94">
  <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port></ports>
  </host>
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
| 7 | *Projects → RC validation → Findings → Import results*, then choose `rc-nmap.xml` in the file dialog | The file dialog opens, the preview names `192.0.2.10:443`, and the import commits |
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

## Results

Record each item's result, date, tester, environment and evidence folder in `RELEASE_READINESS.md` (*Manual release-candidate checklist*).
