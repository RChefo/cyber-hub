## Summary

<!-- What does this change, and why? Link the issue it addresses (Fixes #123). -->

## Changes

<!-- The important changes, as a short list. -->

## Testing

<!-- How you verified it: the checks below, new or changed tests, and manual steps (platform, build). -->

- [ ] `npx tsc --noEmit -p tsconfig.json` and `npx vitest run`
- [ ] `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` (in `src-tauri/`)
- [ ] `node scripts/licenses.mjs check` and `node scripts/check-links.mjs`
- [ ] New or changed behaviour has tests (a bug fix has a test that fails without it)

## Checklist

- [ ] The title is a Conventional Commit, for example `fix(osint): keep graph positions after an import`
- [ ] Documentation is updated where behaviour changed
- [ ] Database changes add a migration at the end of `MIGRATIONS` and pass the upgrade tests (CONTRIBUTING.md, "Database changes")
- [ ] Security-sensitive areas (confirmations, scope, IPC, credentials, MCP, updater, TLS, parsers) are named below, with their abuse-case tests
- [ ] New dependencies are justified, and their licenses pass the policy
- [ ] No credentials, personal data or target data in code, tests, fixtures or screenshots

<!-- Security vulnerabilities are reported privately, not in pull requests: see SECURITY.md. -->
