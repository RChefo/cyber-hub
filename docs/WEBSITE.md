# Website

The public website (landing page and download page) lives in `website/`. It is a separate project with its own `package.json`, so it never affects the desktop app's build, tests or dependencies. It is built and verified locally only: **it has not been deployed**, no domain is configured, and nothing has been published.

## Architecture

| | |
|---|---|
| Stack | Vite 8, React 19, TypeScript 6 (typescript-eslint does not support TypeScript 7 yet; the desktop app keeps 7), Tailwind CSS 4, GSAP 3 (`gsap`, `ScrollTrigger`, `@gsap/react`) |
| Pages | Four static HTML entry points, each with its own title, description, Open Graph and Twitter metadata: `index.html` (landing page), `download/index.html` (download page), `download/archive/index.html` (version archive) and `changelog/index.html` (changelog). Built as a multi-page app, so each page is a real document for search engines and link previews. |
| Content | `src/content.ts`: every capability, number and screenshot on the landing page. Only features that exist in the app are listed; numbers are counted from the app's catalogs (70 tools in 14 categories, 7 command builders, 7 threat-intelligence sources, 44 MCP tools). |
| Screenshots | `src/assets/screens/*.webp`: real screenshots of the desktop app (2880×1800), captured from the running app with demo data in an isolated data folder. The machine's host name was replaced with `ws-01` in the dashboard text before capture; nothing else was edited. |
| Release data | One model for every release view: `src/lib/releases.ts` (model, parsing, versions, changelog, archive, verification helpers), `src/lib/releaseStore.ts` (the shared request and cache), `src/lib/platform.ts` (OS detection and recommendation), `src/components/release.tsx` (shared release UI). See [Release metadata](#release-metadata). |
| Animation | GSAP only (plus the self-contained React Bits / InkOrbit components below). `src/lib/motion.ts` registers ScrollTrigger and `useGSAP`; every animation is created inside `gsap.matchMedia()` so it is skipped when the visitor prefers reduced motion, and parallax runs only on screens ≥ 1024 px. `useGSAP` scopes and reverts tweens and ScrollTriggers when a component unmounts. |
| Components | `src/components/Chrome.tsx` (navigation: Home, Features, Changelog, Documentation when a repository is configured, Download; footer), `src/components/ui/` (shadcn-style folder for UI components: `ink-orbit-features.tsx`, React Bits `OrbitImages.jsx`/`.css`), `src/home/Home.tsx`, `src/download/Download.tsx`. The `@/` alias points to `src/`. |
| Fonts | IBM Plex Sans and JetBrains Mono, self-hosted through `@fontsource` (no third-party font requests). |

### Landing page

Hero (headline, CTAs, the real dashboard and OSINT graph; the graph is uncovered by a single scan-line reveal), verified numbers (counters), two feature spreads (OSINT graph close-up cropped from the real screenshot, Command Center with a real generated command), an index of the other modules, "How it fits together" (`InkOrbitFeatures`, adapted: data sources instead of drawn people, a fixed report label instead of a counter that keeps increasing, the dashboard chart labelled as sample values, Cyber Hub colours), a tabbed screenshot showcase (arrow-key navigation), the security model, platforms (Windows 10/11 x64, Linux x64; macOS not supported), a closing call to action with the real screens orbiting it (React Bits `OrbitImages`, unmodified), and the footer.

### Changelog (`/changelog/`)

Every published release, newest first, as an editorial timeline: version, date, channel tag (*Latest stable*, *Stable*, *Pre-release*), the release's summary line, the categories it contains, expandable details grouped by the release author's own `##` headings, and links to the release on GitHub and to its downloads in the archive. Filters by category (only categories that occur are offered) and, only when pre-releases exist, a switch to include them. Loading, empty, error (with retry) and not-configured states.

The landing page shows a compact preview: the latest stable version, its date and summary, three to five highlights taken round-robin from Security, Features, Improvements and Fixes, and *View full changelog*.

### Version archive (`/download/archive/`)

Every published release, newest first, filterable by platform (Windows, Linux), by channel (only when pre-releases exist) and by version search. Each entry shows version, date, channel, summary, platforms and package types; *Details and downloads* opens the packages with sizes, SHA-256 checksums (copyable) and download links, `SHA256SUMS.txt`, the GitHub release page and the full notes. Older stable releases carry a warning that they may lack later fixes, including security fixes, and that nothing guarantees a clean update from them; pre-releases carry a testing warning. `#v<version>` opens and scrolls to a release (the changelog links there). Releases whose packages are gone stay listed without download actions.

### Download page

Release facts (version, date, status, platforms) of the latest stable release; the detected platform with a recommendation ("Windows detected. We recommend the Windows x64 installer.", *Recommended for your device* on the suggested package) and a platform switch that always works; only the package formats the release actually contains, each with a one-line explanation of when to choose it; a download button only for an existing file (never started without a click); a **Verify your download** panel (file name, package, platform and architecture, version, size, the full SHA-256 with a copy button, `Get-FileHash`/`sha256sum` commands with the real file name, and an explanation of the updater signature); installation steps per format; the latest release notes; links to the changelog and the archive; system requirements taken from the app's documentation (no hardware minimums are claimed). Download progress is left to the browser (no fake progress).

## Release metadata

### Source and model

All release views read one request: `GET <api>/repos/<owner>/<repo>/releases?per_page=100` (GitHub REST API), the same releases that host the desktop updater's `latest.json`. `releaseStore.ts` shares one in-flight request between every component of a page and caches the normalized answer in `sessionStorage` for 15 minutes; errors are never cached. The landing page (preview and footer), each page's views and the archive therefore cost one API call per page load at most.

```
Release        version · tag · name · publishedAt · notes · channel (stable | prerelease)
               htmlUrl · assets[] · checksumsUrl (SHA256SUMS.txt) · hasUpdateManifest (latest.json)
ReleaseAsset   name · os (windows | linux) · arch (x64) · format (nsis | msi | appimage | deb | rpm)
               downloadUrl · size · sha256 (or null) · signatureUrl (the .sig, or null)
```

Normalization rules:

* drafts are dropped (the API does not show them to visitors anyway); a release whose tag is not `v<semver>` is dropped;
* a release is a pre-release when GitHub flags it or its tag has a semver pre-release part (`v0.3.0-beta.1`);
* releases are ordered by semantic-version precedence; the **latest stable** is the highest stable version (what the updater offers);
* an asset is offered only if its URL is `https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`, its upload is complete, its size is known and its name matches a package pattern; the patterns are the updater manifest tool's (a test fails if they diverge);
* `.sig` files become the asset's `signatureUrl`, `SHA256SUMS.txt` the release's `checksumsUrl`; `latest.json` is not offered for download;
* the release page link is always `https://github.com/<owner>/<repo>/releases/tag/<tag>`;
* release notes are parsed into data (headings, lists, inline code, bold, https links) and rendered as React elements; no HTML from a release body is inserted. Categories (Features, Improvements, Fixes, Security, Other) come only from the author's `##` headings.

States everywhere: not configured (no repository), loading (skeletons), no release yet, error (rate limit, HTTP error, unreadable answer, offline; with *Try again* and a link to the releases page), ready. With only pre-releases published, the download page says so and points to the archive.

### Checksums and signatures

* **SHA-256 checksum.** The checksum shown for a file is GitHub's own per-asset digest (`digest: "sha256:…"` in the API, computed by GitHub when the file is uploaded). It arrives with the release list, so there is no extra request and no cross-origin download. Only 64-hex values are accepted. The release workflow (`.github/workflows/release.yml`, step *Check GitHub's asset digests against SHA256SUMS.txt*) compares every uploaded file's digest with the `SHA256SUMS.txt` it generated and keeps the release a draft on any mismatch, so the displayed value is the published one. When an asset has no digest, the page says so and links `SHA256SUMS.txt` (or says that no checksum was published). The page never computes a checksum and never labels a file "verified": the visitor hashes their own download with the commands shown.
* **Updater signature.** Each package's `.sig` (minisign, Tauri updater) is linked when published. It is verified by the installed app with the public key compiled into it when it installs an update (see UPDATER.md); the website does not verify it and says so.

### OS detection

`platform.ts` reads the user agent and, where the browser offers them, User-Agent Client Hints (`platform`, and `architecture`/`bitness` through `getHighEntropyValues`). Limitations: browsers can hide or freeze these values; the architecture is reported only when the browser says it (unknown is treated as unknown, ARM gets an "x64 only" note); Linux distributions are rarely named in user agents (Firefox on Ubuntu or Fedora does), so the Linux suggestion is the AppImage unless a distribution is named; macOS and mobile visitors are told Cyber Hub runs on Windows and Linux and can still download for another computer. Detection only preselects: the platform switch and every package remain available, and nothing downloads without a click.

## Environment variables

Build-time, all optional and public (they end up in the bundle; never put secrets here):

| Variable | Purpose | Unset |
|---|---|---|
| `VITE_GITHUB_REPOSITORY` | `owner/repo` that publishes Cyber Hub releases. Enables the release data (changelog, archive, downloads) and the Documentation, GitHub and *Releases on GitHub* links (`/tree/HEAD/docs`, the repository, `/releases`). | No release data (the pages show their "no release" states); those external links are hidden (no broken links). |
| `VITE_SITE_URL` | The production origin, e.g. `https://cyberhub.example` (https only). Enables canonical URLs, `og:url`, `og:image`/`twitter:image` (`/og.png`, see below) and `sitemap.xml`; `robots.txt` then references the sitemap. | None of these are emitted; `robots.txt` allows everything. |
| `VITE_RELEASES_API_BASE` | Overrides the GitHub API origin, for local testing against a mock (only `https://…`, `http://127.0.0.1` or `http://localhost` are accepted). | `https://api.github.com` |

Production builds add a Content-Security-Policy meta tag: scripts, styles, images and fonts from the site itself only, network requests only to the site and the releases API origin, no framing.

## Development

```bash
cd website
npm install
npm run dev          # http://localhost:5173
npm run typecheck
npm run lint
npm test             # release model, store and caching, changelog, archive, verification, OS detection, notes, updater parity
npm run build        # → website/dist
npm run preview      # serve the build
```

To see the release pages with data before a release exists, run a local mock of the GitHub API that serves a fixture for `/repos/<owner>/<repo>/releases` (an array of releases with `digest` fields on the assets) (with `Access-Control-Allow-Origin: *`) and build with `VITE_GITHUB_REPOSITORY=<owner>/<repo> VITE_RELEASES_API_BASE=http://127.0.0.1:<port>`. The fixture's asset URLs must use the `https://github.com/<owner>/<repo>/releases/download/<tag>/` prefix.

## Updating content

* Capabilities, numbers, principles and showcase screens: `src/content.ts`. Keep numbers in step with the app's catalogs.
* Screenshots: capture the running app at 1440×900 with a device scale factor of 2, as WebP, with demo data in a separate data folder (run `npx tauri dev --config '{"identifier":"dev.cyberhub.workstation.screenshots"}'` so the developer's own data never appears), and replace the files in `src/assets/screens/` (keep 2880×1800 or update `SHOT` in `content.ts`).
* Installation steps and requirements: `src/download/Download.tsx`.
* Release notes come from the GitHub release body; group them with `##` headings such as "New features", "Bug fixes" and "Security" (the page uses the author's headings and never invents categories).

## Connecting the production domain

1. Choose the domain (not done; requires the owner's approval).
2. Build with `VITE_SITE_URL=https://<domain>` and `VITE_GITHUB_REPOSITORY=<owner>/<repo>`.
3. Add an Open Graph image at `website/public/og.png` (1200×630; not created yet) before relying on link previews.
4. Check `dist/robots.txt`, `dist/sitemap.xml` and the canonical tags in both pages.

## Deployment

`website/dist` is a static site (four HTML pages and hashed assets) that any static host can serve (for example GitHub Pages, Cloudflare Pages or Netlify). Serve `/download/`, `/download/archive/` and `/changelog/` from their `index.html`; send `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`) as an HTTP header, because that directive is ignored in the page's `<meta>` policy; set long cache lifetimes for `/assets/*` (hashed names) and short ones for the HTML. Deploying, buying a domain and announcing the site need the owner's explicit approval and have not been done.

## Known limitations

* Not deployed; no domain; no Open Graph image file yet (`og.png`).
* No release exists, so the live site shows only the "no release yet" states; the ready, pre-release, empty, rate-limit and retry states of every release page were verified against a local mock of the GitHub API.
* GitHub per-asset digests are documented by GitHub for assets uploaded since 2025; if a digest is missing, the page falls back to linking `SHA256SUMS.txt`. The workflow's digest check has not run yet (the workflow has never run).
* The release list reads one API page (100 releases).
* No Privacy Policy or License link: neither document exists in the repository (the app's privacy behaviour is described in SECURITY.md).
* GitHub's unauthenticated API allows 60 requests per hour per IP; the 15-minute cache and the error state with a direct link cover heavy use.
* `npm audit` reports moderate advisories in development-only lint tooling (`minimatch` via eslint/typescript-eslint); nothing shipped to visitors is affected.
