# Release notes

The release workflow (`.github/workflows/release.yml`) publishes `docs/releases/<version>.md` as the notes of the GitHub release and of the update manifest. The full release process, including signing, is in [UPDATER.md](../UPDATER.md).

## Before a release

The owner decides each step; none is automated by this repository.

1. **Version.** Choose it. If it is not 0.1.0, rename `0.1.0.md`.
2. **Notes.** Review them against [UPGRADE.md](../UPGRADE.md) and [SECURITY.md](../SECURITY.md), and remove anything that does not apply to the published build. The notes are published as written.
3. **Checks.** Run them locally on the release commit:

   ```
   npx tsc -b --noEmit
   npx vitest run
   npm run build
   cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
   npm audit
   cd src-tauri && cargo audit
   ```

   Rust 1.89 or later is required.
4. **Upgrade test.** Upgrade a copy of a real database from the previous release, never the original. Check the pre-upgrade backup in `backups/`, the schema-19 notes in each project's scope history, and a restore of that backup.
5. **Signing and publishing.** These need the signing keys and the owner's authorization, as described in [UPDATER.md](../UPDATER.md) and [SIGNING.md](../SIGNING.md).
