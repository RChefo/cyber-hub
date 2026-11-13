# ExploitX asset catalog

Every brand file, its format and what it is for. All paths are relative to the repository root. Usage rules are in [BRAND_GUIDELINES.md](BRAND_GUIDELINES.md).

## Sources and how to rebuild

| File | What |
|---|---|
| `design/brand/build/brand.mjs` | The geometry: symbol, wordmark X, lockups, application icon. No dependencies |
| `design/brand/build/tokens.mjs` | The design tokens |
| `design/brand/build/wordmark.json` | Outlines of "Exploit" (Archivo SemiBold, OFL-1.1), extracted once by `extract-wordmark.mjs` |
| `design/brand/build/build.mjs` | Writes every SVG below, `tokens.json`, `tokens.css`, and `logoData.ts` for the app and the website |
| `design/brand/build/export.mjs` | PNG, ICO and favicon exports (headless Chrome); `--tauri` also refreshes `src-tauri/icons/` |
| `design/brand/build/social.mjs` | Social and marketing images, composed from the logo, the brand fonts and real screenshots |
| `design/brand/build/illustrations.mjs` | The three example feature illustrations |
| `design/brand/exploration/*.html` | The exploration boards: symbol directions, accent colours, wordmark typefaces (VISUAL_IDENTITY.md) |

To rebuild everything:

```bash
node design/brand/build/build.mjs
node design/brand/build/export.mjs --tauri
node design/brand/build/illustrations.mjs
node design/brand/build/social.mjs
```

Set `CHROME` if Chrome is not in a standard place. `npm ci` must have run first: `social.mjs` reads the fonts from `node_modules`.

## Logos (vector, editable)

All files are in `design/brand/`. SVG with a transparent background and clear space included; filled paths only (no font needed); a `<title>` for accessibility.

| File | Content | Background |
|---|---|---|
| `logo-primary.svg` | Stacked lockup: symbol above wordmark (the primary logo) | Dark |
| `logo-primary-light.svg` | Stacked lockup | Light |
| `logo-horizontal.svg` | Horizontal lockup (the default) | Dark |
| `logo-dark.svg` | Horizontal lockup, explicitly for dark backgrounds (same as `logo-horizontal.svg`) | Dark |
| `logo-light.svg` | Horizontal lockup | Light |
| `logo-compact.svg`, `logo-compact-light.svg` | Horizontal lockup tuned for under 24 px high: the symbol's gap and the X's gap are closed | Dark / light |
| `logo-monochrome.svg`, `logo-monochrome-stacked.svg` | One colour (`currentColor`: black when used as a file, the text colour when inlined) | Any |
| `logo-symbol.svg` | Symbol, Ultraviolet and Bone | Dark |
| `logo-symbol-light.svg` | Symbol, Ultraviolet 700 and Ink | Light |
| `logo-symbol-small.svg` | Symbol without the hairline gap, for 24 px and smaller | Dark |
| `logo-symbol-monochrome.svg` | Symbol in one colour (`currentColor`) | Any |
| `logo-wordmark.svg`, `logo-wordmark-light.svg` | "ExploitX" alone | Dark / light |
| `brand-preview.svg` | The whole identity on one board (its labels use the brand fonts when installed; `png/brand-preview.png` is the rendered board) | — |

## Logos (raster, transparent PNG)

`design/brand/png/`:
* **Horizontal lockups:** `logo-horizontal`, `-dark`, `-light`, `-compact`, `-monochrome`, `-wordmark`, `-wordmark-light`. Each at 480, 960 (`@2x`) and 1920 (`@4x`) px wide.
* **Stacked lockups:** `logo-primary`, `-primary-light`, `-monochrome-stacked`. Each at 400 and 800 (`@2x`) px wide.
* **Symbols:** `logo-symbol`, `-symbol-light`, `-symbol-monochrome`. Each at 64, 256 and 1024 px.

## Application icons

| File | Format | Use |
|---|---|---|
| `design/brand/app-icon.svg` | SVG, 1024 units | The master for 48 px and up: the symbol on a rounded Night tile with a faint glow and edge |
| `design/brand/app-icon-small.svg` | SVG | The master for 16–32 px: a larger mark, no gap, no glow |
| `design/brand/png/app-icon-{16,20,24,32,40,48,64,128,256,512,1024}.png` | PNG | Every size; up to 48 px from the small master |
| `design/brand/icons/windows/exploitx.ico` | ICO (PNG entries 16–256) | Windows; copied to `src-tauri/icons/icon.ico` (the executable's icon, the installers, the taskbar) |
| `design/brand/icons/linux/hicolor/<size>/apps/exploitx.png` | PNG, 16–512 | Linux icon theme layout, for packagers |
| `src-tauri/icons/*` | PNG, ICO, ICNS | What Tauri bundles (`bundle.icon` in `tauri.conf.json`). On Linux the packages install them as `cyber-hub.png` (the package's identity) |

## Favicons and web

| File | Use |
|---|---|
| `design/brand/favicon.svg` → `website/public/favicon.svg`, `public/logo.svg` (the app) | Modern browsers |
| `design/brand/icons/favicon/favicon.ico` → `website/public/favicon.ico` | Legacy browsers (16, 32, 48) |
| `design/brand/icons/favicon/apple-touch-icon.png` → `website/public/` | iOS home screen (180 px, opaque) |
| `design/brand/icons/favicon/icon-192.png`, `icon-512.png` → `website/public/` | `site.webmanifest` |
| `design/brand/social/website-og.png` → `website/public/og.png` | Open Graph and Twitter image of exploitx.net (1200 × 630) |

## Social and marketing (PNG; built from real screenshots with demo data)

| File | Size | Use |
|---|---|---|
| `design/brand/social/github-social-preview.png` | 1280 × 640 | GitHub repository social preview. The owner uploads it under Settings → General → Social preview: GitHub's API cannot set it |
| `design/brand/social/website-og.png` | 1200 × 630 | Website social sharing (also `website/public/og.png`) |
| `design/brand/social/avatar.png` | 1024 × 1024 | Square avatar (organisation, social profiles); safe inside a circle crop |
| `design/brand/social/banner.png` | 1500 × 500 | Wide banner (X, LinkedIn); the lower-left corner stays clear for a profile picture |
| `design/brand/social/announcement.png` | 1200 × 675 | Rename announcement ("Cyber Hub is now ExploitX") |
| `design/brand/social/desktop-promo.png` | 1920 × 1080 | Desktop application promotional visual (presentations, website, release posts) |

Nothing here was published. Posting any of these is the owner's decision.

## Illustrations

`design/brand/illustrations/investigate.svg`, `detect.svg` and `report.svg` (480 × 320, SVG) are the feature illustration style; see VISUAL_IDENTITY.md for the rules.

## Screenshots

`website/src/assets/screens/*.webp` (2880 × 1800) are real screenshots of the rebranded app with demo data in a disposable data folder, captured in Mission 13. The machine's host name is replaced with `ws-01`. They are used by the website and the social images.

## Fonts (not in `design/brand`; bundled through npm)

| Typeface | Package | Licence |
|---|---|---|
| Archivo (variable) | `@fontsource-variable/archivo` | OFL-1.1 |
| IBM Plex Sans | `@fontsource/ibm-plex-sans` | OFL-1.1 |
| JetBrains Mono (variable) | `@fontsource-variable/jetbrains-mono` | OFL-1.1 |
