# ExploitX brand sources

The ExploitX identity: logos, application icons, favicons, design tokens, social images and illustrations, with the scripts that build them.

* Rules and reasoning: [docs/brand/](../../docs/brand/BRAND_GUIDELINES.md).
* Every file and its use: [docs/brand/ASSET_CATALOG.md](../../docs/brand/ASSET_CATALOG.md).
* Rebuild: `node design/brand/build/build.mjs`, then `export.mjs --tauri`, `illustrations.mjs` and `social.mjs` (see the catalog).

Edit the geometry in `build/brand.mjs` and the tokens in `build/tokens.mjs`, never the generated files.
