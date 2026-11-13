# Standard license texts

The standard texts of the licenses in the permissive, attribution and source-obligation categories of `scripts/license-policy.json`, one file per SPDX identifier, unmodified from the SPDX License List 3.26.0:

`https://raw.githubusercontent.com/spdx/license-list-data/v3.26.0/text/<identifier>.txt` (retrieved 2026-11-13)

`scripts/licenses.mjs notices` uses them only for a dependency that publishes **no** license file of its own: its entry in `src-tauri/resources/THIRD_PARTY_LICENSES.txt` then carries the standard text of its declared license, the copyright holders the package names, and the note "standard text; the package includes no license file". A dependency's own license file always takes precedence.

When the notices need a license that has no file here, the generator stops with "add scripts/license-texts/<id>.txt": fetch it from the same tag of the SPDX License List, unmodified, and record the date above.
