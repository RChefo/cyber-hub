# ExploitX brand guidelines

How to present ExploitX: the name, the positioning, the voice, and the rules for the logo. The visual system is described in [VISUAL_IDENTITY.md](VISUAL_IDENTITY.md), its tokens in [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md), the files in [ASSET_CATALOG.md](ASSET_CATALOG.md).

Since Mission 13 (2026-11-13) the product is **ExploitX**. It was formerly Cyber Hub. The official website is **https://exploitx.net**. The source repository is `RChefo/ExploitX`; the owner renamed it from `RChefo/cyber-hub`, which GitHub redirects (observed 2026-11-13, Mission 14).

## Name

* Always **ExploitX**: one word, capital E, capital X.
* Not:
  * "Exploit X", "Exploit-X", "EXPLOITX", "exploitX";
  * Exploitx;
  * XploitX.
* In running text, the name stands alone ("ExploitX finds…"), without "the".
* The possessive is "ExploitX's".
* The article is "an ExploitX project", because the name starts with a vowel sound.
* Lowercase `exploitx` only where a system requires it: a domain, a handle, a package.
* **Technical names keep the old identifiers on purpose.** These are `cyberhub-mcp`, `cyberhub_*` tool names, `dev.cyberhub.workstation`, `CYBERHUB_DATA_DIR` and the Windows install folder "Cyber Hub". They are not branding, and documentation shows them exactly as they are ([NAME_MIGRATION.md](NAME_MIGRATION.md)).

## Positioning

**ExploitX — cybersecurity intelligence and security research platform.**

ExploitX is a local-first desktop platform where the whole of security work meets:
* security testing with scoped tool runs;
* OSINT investigations;
* threat and vulnerability intelligence;
* detection engineering (Sigma and YARA);
* findings, evidence, ATT&CK mapping and reports;
* MCP integration.

It is more than a penetration testing utility or a scanner. Present it as the workspace that connects these pieces.

| Element | Text |
|---|---|
| Descriptor (always next to the name in first mentions, metadata, store listings) | Cybersecurity intelligence & security research platform |
| Headline | From first signal to final report. |
| One-sentence description | ExploitX brings security testing, OSINT investigations, threat and vulnerability intelligence, detection engineering and reporting into one desktop platform. |
| Proof points (true today, keep them true) | Tool runs stay inside the authorized scope · every run and install needs a native confirmation · projects, findings and evidence stay on your machine · no account, no telemetry · Windows 10/11 and Linux, x64 |

**What the name means.**
* *Exploit* is the craft: finding the weakness, the attack path, the proof.
* *X* is the unknown the work starts from, and the point where everything meets. The symbol draws that point (see VISUAL_IDENTITY.md).

Use the meaning to explain the brand. Do not use it as a slogan.

## Personality and voice

Intelligent, technical, confident, precise, modern, professional, security-focused, developer-friendly, trustworthy.

| Do | Don't |
|---|---|
| Say what the product does, with the real capability ("checks every target against the project's scope") | Inflate it ("military-grade", "unbreakable", "AI-powered security") |
| Write for practitioners: name the protocol, the format, the standard (Sigma, STIX 2.1, CVSS 4.0, ATT&CK) | Explain what an exploit is |
| Be direct about limits (unsigned installers, no macOS) | Promise outcomes ("stops every attack", "guaranteed compliance") |
| Use the active voice and short sentences | Use hacker slang, leetspeak, skulls, hoodies, "h4ck" |
| Show real screens with demo data | Invent numbers, customers, downloads, certifications, partners |

**Offensive-security wording.**
* ExploitX supports *authorized* testing. Say "authorized", "in scope" and "assessment".
* Never suggest unauthorized use, evasion or anything that targets people.

## Logo

The logo has three parts: the **symbol** (Convergence), the **wordmark** "ExploitX", and the **lockups** that combine them.

| Version | File | Use |
|---|---|---|
| Horizontal (default) | `design/brand/logo-horizontal.svg` (dark backgrounds), `logo-light.svg` (light) | Headers, documents, README, website |
| Primary, stacked | `logo-primary.svg`, `logo-primary-light.svg` | Hero areas, splash, About, square spaces |
| Compact | `logo-compact.svg`, `logo-compact-light.svg` | Under 24 px high. The X's tips close and the symbol's gap closes, so it stays crisp |
| Symbol | `logo-symbol.svg`, `logo-symbol-light.svg`, `logo-symbol-small.svg` | Avatars, favicons, collapsed navigation, where the name appears nearby |
| Monochrome | `logo-monochrome.svg`, `logo-monochrome-stacked.svg`, `logo-symbol-monochrome.svg` | One-colour printing, engraving, embossing, single-colour UIs (`currentColor`) |
| Application icon | `app-icon.svg` (48 px and up), `app-icon-small.svg` (16–32 px) | The desktop app, installers, favicons |

**Colour versions.**
* **On dark:** the operator's chevron in Ultraviolet 500 `#7C6AFF`, the target's chevron and the wordmark in Bone `#F2F4F7`.
* **On light:** Ultraviolet 700 `#5240E0` and Ink `#0B0D12`.
* **One colour only:** everything in Ink, Bone or `currentColor`.

**Clear space.**
* Keep half the symbol's height free on every side. The SVG files include it.
* In a lockup, the space between symbol and wordmark is 0.62 cap heights. Never change it.

**Minimum sizes.**

| Version | Minimum |
|---|---|
| Horizontal lockup | 96 px wide on screen, 25 mm in print. Below 24 px high, use the compact version |
| Symbol | 16 px. Use `logo-symbol-small.svg` or the small app icon up to 24 px |
| Wordmark alone | 12 px cap height |

**Backgrounds.**
* Night `#0A0B10` and the dark surfaces are the home of the brand.
* On white or light grey, use the light versions.
* On photographs or busy screens, put the logo on a solid Night or white panel.

**Never:**
* stretch, rotate, skew or redraw the logo;
* change the letter spacing;
* retype the wordmark in a font;
* swap the chevrons' colours (the left one is always Ultraviolet);
* colour the right chevron Ultraviolet too, except in the monochrome versions;
* add outlines, shadows, glows, bevels, gradients or textures to the logo;
* put the logo inside a shield, padlock, circuit board or crosshair;
* use the old Cyber Hub shield, or combine the two names in one lockup;
* animate the symbol's chevrons apart for decoration (a single, meaningful reveal on the website is the exception).

## Imagery

* **Screenshots:**
  * real screens of the app with demo data, captured at 2× (`docs/WEBSITE.md`);
  * the machine's host name and personal paths replaced;
  * never retouched to show features that do not exist.
* **Illustrations:**
  * the style in `design/brand/illustrations/`: hairlines, one Ultraviolet signal, no text;
  * no stock photos of hackers, padlocks, binary rain or globes.
* **Social images:** compose them from the logo, one line of text and a real screenshot (`design/brand/social/`).

## Applying the brand to the website (exploitx.net)

* **Canonical address:** `https://exploitx.net`.
* **Metadata:** every page title ends with "ExploitX" or starts with it, and descriptions use the descriptor.
* **Layout:**
  * one primary call to action per view;
  * Ultraviolet only for that action, links and the brand's highlights;
  * headings in Archivo, text in IBM Plex Sans.
* **Motion:**
  * one orchestrated moment (the hero) and quiet reveals;
  * everything off with `prefers-reduced-motion`.
* **Truthful content:**
  * no release versions, download links, numbers or claims that the product does not have;
  * the download page shows packages only when a release is published.
