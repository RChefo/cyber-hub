# Website

The public website (landing page and download page) lives in `website/`. It is a separate project with its own `package.json`, so it never affects the desktop app's build, tests or dependencies. It is built and verified locally only: **it has not been deployed**, no domain is configured, and nothing has been published.

## Architecture

| | |
|---|---|
| Stack | Vite 8, React 19, TypeScript 6 (typescript-eslint does not support TypeScript 7 yet; the desktop app keeps 7), Tailwind CSS 4, GSAP 3 (`gsap`, `ScrollTrigger`, `@gsap/react`) |
| Pages | Two static HTML entry points: `index.html` (landing page) and `download/index.html` (download page), each with its own title, description, Open Graph and Twitter metadata. Built as a multi-page app, so each page is a real document for search engines and link previews. |
| Content | `src/content.ts`: every capability, number and screenshot on the landing page. Only features that exist in the app are listed; numbers are counted from the app's catalogs (70 tools in 14 categories, 7 command builders, 7 threat-intelligence sources, 44 MCP tools). |
| Screenshots | `src/assets/screens/*.webp`: real screenshots of the desktop app (2880×1800), captured from the running app with demo data in an isolated data folder. The machine's host name was replaced with `ws-01` in the dashboard text before capture; nothing else was edited. |
| Release data | `src/lib/releases.ts` + `src/lib/useRelease.ts` (see below). |
| Animation | GSAP only (plus the self-contained React Bits / InkOrbit components below). `src/lib/motion.ts` registers ScrollTrigger and `useGSAP`; every animation is created inside `gsap.matchMedia()` so it is skipped when the visitor prefers reduced motion, and parallax runs only on screens ≥ 1024 px. `useGSAP` scopes and reverts tweens and ScrollTriggers when a component unmounts. |
| Components | `src/components/Chrome.tsx` (navigation, footer, logo), `src/components/ui/` (shadcn-style folder for UI components: `ink-orbit-features.tsx`, React Bits `OrbitImages.jsx`/`.css`), `src/home/Home.tsx`, `src/download/Download.tsx`. The `@/` alias points to `src/`. |
| Fonts | IBM Plex Sans and JetBrains Mono, self-hosted through `@fontsource` (no third-party font requests). |

### Landing page

Hero (headline, CTAs, the real dashboard and OSINT graph; the graph is uncovered by a single scan-line reveal), verified numbers (counters), two feature spreads (OSINT graph close-up cropped from the real screenshot, Command Center with a real generated command), an index of the other modules, "How it fits together" (`InkOrbitFeatures`, adapted: data sources instead of drawn people, a fixed report label instead of a counter that keeps increasing, the dashboard chart labelled as sample values, Cyber Hub colours), a tabbed screenshot showcase (arrow-key navigation), the security model, platforms (Windows 10/11 x64, Linux x64; macOS not supported), a closing call to action with the real screens orbiting it (React Bits `OrbitImages`, unmodified), and the footer.

### Download page

Release facts (version, date, status, platforms) from the release data; a platform switch (Windows / Linux, preselected from the visitor's OS but always changeable; macOS visitors are told it is not supported); package formats per platform with sizes, a download button only for packages that exist in the release, a "not available" label for the others; SHA-256 checksums link when the release has `SHA256SUMS.txt`; installation steps per format; release notes; system requirements taken from the app's documentation (no hardware minimums are claimed). Download progress is left to the browser (no fake progress).

## Release metadata

The download page reads `GET https://api.github.com/repos/<owner>/<repo>/releases/latest`, the same GitHub releases the desktop updater reads `latest.json` from (see UPDATER.md):

* `releases/latest` never returns drafts or pre-releases, and the parser also refuses them, so unpublished artifacts are never shown;
* only assets whose URL starts with `https://github.com/<owner>/<repo>/releases/download/<tag>/`, whose upload is complete and whose size is known are offered; `.sig` files and `latest.json` are not offered;
* package types are recognized with the same file-name patterns as `scripts/updater-manifest.mjs` (a test fails if they diverge);
* answers are cached for 15 minutes per browser session; errors are not cached;
* states: not configured, loading, no release yet, error (rate limit, HTTP error, offline; with *Try again* and a link to the releases page), ready;
* release notes are parsed into data (headings, lists, inline code, bold, https links) and rendered as React elements; no HTML from the release body is ever inserted.

Until a repository is configured and a release is published, both pages say "No public release yet" and show no download button.

## Environment variables

Build-time, all optional and public (they end up in the bundle; never put secrets here):

| Variable | Purpose | Unset |
|---|---|---|
| `VITE_GITHUB_REPOSITORY` | `owner/repo` that publishes Cyber Hub releases. Enables the release data and the Documentation, Changelog and GitHub links (`/tree/HEAD/docs`, `/releases`, the repository). | No release data; those links are hidden (no broken links). |
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
npm test             # release parsing, caching, link and OS detection, notes rendering, updater parity
npm run build        # → website/dist
npm run preview      # serve the build
```

To see the download page with a release before one exists, run a local mock of the GitHub API that serves a fixture for `/repos/<owner>/<repo>/releases/latest` (with `Access-Control-Allow-Origin: *`) and build with `VITE_GITHUB_REPOSITORY=<owner>/<repo> VITE_RELEASES_API_BASE=http://127.0.0.1:<port>`. The fixture's asset URLs must use the `https://github.com/<owner>/<repo>/releases/download/<tag>/` prefix.

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

`website/dist` is a static site (two HTML pages and hashed assets) that any static host can serve (for example GitHub Pages, Cloudflare Pages or Netlify). Serve `/download/` from `download/index.html`; set long cache lifetimes for `/assets/*` (hashed names) and short ones for the HTML. Deploying, buying a domain and announcing the site need the owner's explicit approval and have not been done.

## Known limitations

* Not deployed; no domain; no Open Graph image file yet (`og.png`).
* No release exists, so the live download experience shows only the "No public release yet" state; the ready, rate-limit and retry states were verified against a local mock of the GitHub API.
* No Privacy Policy or License link: neither document exists in the repository (the app's privacy behaviour is described in SECURITY.md).
* GitHub's unauthenticated API allows 60 requests per hour per IP; the 15-minute cache and the error state with a direct link cover heavy use.
* `npm audit` reports moderate advisories in development-only lint tooling (`minimatch` via eslint/typescript-eslint); nothing shipped to visitors is affected.
