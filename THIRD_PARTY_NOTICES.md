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
