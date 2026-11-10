# Third-party notices

## CVSS v4.0 calculator data

`src-tauri/src/cvss/v4_lookup.rs` contains the macrovector lookup table of FIRST's CVSS v4.0 calculator. It was generated from `cvss_lookup.js` of <https://github.com/FIRSTdotorg/cvss-v4-calculator>, which is identical to the table in Red Hat's `cvss40.js`. The scoring code in `src-tauri/src/cvss/mod.rs` follows the reference calculator's algorithm and the maximal-vector tables `MAX_COMPOSED` and `MAX_SEVERITY`.

CVSS is owned by FIRST and used by permission. Cyber Hub always shows a CVSS score together with its vector.

```
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of
   conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## OWASP Web Security Testing Guide checklist

`src-tauri/src/methodology/wstg.json` is adapted from the checklist of the OWASP Web Security Testing Guide (<https://github.com/OWASP/wstg>, `checklists/checklist.json`, commit `8f7da50ddfda9bc6929ca312eff9c9cb9a68ccc7`, retrieved 2026-11-08). Only test IDs, names, objectives and reference links are kept.

* **Original work:** © OWASP Foundation and the WSTG contributors, licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (<https://creativecommons.org/licenses/by-sa/4.0/>).
* **This adaptation:** the data file is distributed under the same license, CC BY-SA 4.0.
* **Shown in the app:** the Checklist tab names the source, commit and license.

## MITRE ATT&CK

`src-tauri/catalog/attack-enterprise.json` is a compact catalog of the Enterprise ATT&CK tactics and techniques (IDs, names, tactics, platforms, parents, revoked and deprecated IDs), built by `scripts/attack-catalog.mjs` from MITRE's STIX 2.1 bundle (<https://github.com/mitre-attack/attack-stix-data>, `enterprise-attack-20.1.json`, retrieved 2026-11-09; the file's SHA-256 is recorded in the catalog).

* **Notice:** © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
* **License:** MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
* **Shown in the app:** the ATT&CK view names the ATT&CK version and this notice.

## OWASP Application Security Verification Standard 5.0.0

`src-tauri/catalog/asvs-5.0.0.json` is the requirement list of the OWASP Application Security Verification Standard 5.0.0 exactly as the project publishes it (release `v5.0.0_release`, asset `OWASP_Application_Security_Verification_Standard_5.0.0_en.json`, <https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release>, retrieved 2026-11-10, SHA-256 `bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`). It is not modified.

* **Original work:** © OWASP Foundation and the ASVS contributors, licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (<https://creativecommons.org/licenses/by-sa/4.0/>).
* **Shown in the app:** the ASVS tab and the assessment report name the standard, its version and this license.
