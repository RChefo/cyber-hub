# Website

The ExploitX website (exploitx.net: landing page, downloads, version archive, changelog) has its own repository since Mission 13 (2026-11-13): [RChefo/ExploitX-Web](https://github.com/RChefo/ExploitX-Web). Its README and `docs/WEBSITE.md` describe the architecture, development, environment variables and deployment. It is not deployed yet.

Until then it lived in this repository's `website/` folder; that history stays here, and the new repository was created from it with `git subtree split`, so it carries the same commits.

## Which repository owns what

| Component | Repository |
|---|---|
| Desktop app, backend, MCP server, installers, release workflow and update feed | RChefo/cyber-hub (this one) |
| Brand sources: logos, icons, tokens, social images, screenshots (`design/brand/`), brand documentation (`docs/brand/`) | RChefo/cyber-hub |
| Website: pages, components, styles, SEO, favicons and Open Graph image as deployed | RChefo/ExploitX-Web |

## How the two stay in step

* **Brand:** the website keeps copies of the tokens, the logo geometry, the favicons, the Open Graph image and the screenshots. Its `docs/BRAND.md` lists each file and its source in `design/brand/`. Rebuild here (docs/brand/ASSET_CATALOG.md), then copy.
* **Releases:** the website reads this repository's GitHub releases (`VITE_GITHUB_REPOSITORY=RChefo/cyber-hub`): versions, notes, packages, SHA-256 digests and signatures. Nothing is copied by hand.
* **Package names:** the website's download patterns (`src/lib/releases.ts` there) must match `ARTIFACTS` in `scripts/updater-manifest.mjs` here. The website's test holds a copy of that list; change both together.
* **Release titles:** new drafts are titled "ExploitX X.Y.Z"; the website also accepts the former "Cyber Hub X.Y.Z".
