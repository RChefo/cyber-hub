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

`src-tauri/catalog/attack-enterprise.json`, `attack-mobile.json` and `attack-ics.json` are compact catalogs of the Enterprise, Mobile and ICS ATT&CK tactics and techniques (IDs, names, tactics, platforms, parents, revoked and deprecated IDs). `scripts/attack-catalog.mjs` built them from MITRE's STIX 2.1 bundles at <https://github.com/mitre-attack/attack-stix-data>:
* `enterprise-attack-20.1.json`, retrieved 2026-11-09;
* `mobile-attack-20.1.json` and `ics-attack-20.1.json`, retrieved 2026-11-10 (Mission 6).

Each catalog records the SHA-256 of its source file. The Enterprise catalog regenerated from its bundle is identical, byte for byte, to the one bundled before.

* **Notice:** © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
* **License:** MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
* **Shown in the app:** the ATT&CK view names the ATT&CK version and this notice.

## OWASP Application Security Verification Standard 5.0.0

`src-tauri/catalog/asvs-5.0.0.json` is the requirement list of the OWASP Application Security Verification Standard 5.0.0 exactly as the project publishes it (release `v5.0.0_release`, asset `OWASP_Application_Security_Verification_Standard_5.0.0_en.json`, <https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release>, retrieved 2026-11-10, SHA-256 `bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`). It is not modified.

* **Original work:** © OWASP Foundation and the ASVS contributors, licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (<https://creativecommons.org/licenses/by-sa/4.0/>).
* **Shown in the app:** the ASVS tab and the assessment report name the standard, its version and this license.

## User-interface components copied into this repository (Mission 12)

These files were copied or adapted from other projects. Each carries a source note at its top. They keep their own licenses, below.

| Files | Source | License |
|---|---|---|
| `src/components/vendor/shadcn/chart.tsx` | shadcn/ui, <https://ui.shadcn.com> | MIT, Copyright (c) 2023 shadcn |
| `src/components/vendor/untitledui/FeaturedIcon.tsx` | Untitled UI React, <https://github.com/untitleduico/react> | MIT, Copyright (c) 2025 Untitled UI |
| `src/components/vendor/evilcharts/echarts-chart.tsx` | EvilCharts, <https://github.com/legions-developer/evilcharts> | MIT, Copyright (c) 2026 Gurbinder |
| `src/components/vendor/lightswind/DotPattern.tsx` | Lightswind, <https://lightswind.com> (npm package `lightswind` 3.2.5, author @codewithmuhilan) | MIT, as declared in the package metadata; the package publishes no license file and no copyright line |
| `src/components/vendor/reactbits/BranchedMenu.tsx`, `BranchedMenu.css`, `CountUp.tsx`; `website/src/components/ui/OrbitImages.jsx`, `OrbitImages.css` | React Bits, <https://github.com/DavidHDev/react-bits> | **MIT + Commons Clause License Condition v1.0**, Copyright (c) 2026 David Haz: **not an open-source license**, see below |
| `website/src/components/ui/ink-orbit-features.tsx` (website only) | Ink Orbit by Kedhareswer Naidu, <https://github.com/Kedhareswer/21stdev-my-components> | **No license found** (checked 2026-11-13): see `docs/governance/THIRD_PARTY_LICENSE_AUDIT.md` |

**The MIT License** (shadcn/ui, Untitled UI React, EvilCharts, Lightswind), with each project's copyright line above:

```
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
```

**React Bits.** The React Bits files may be used and distributed only as part of an application, website or product. Their license forbids selling, sublicensing or redistributing the components themselves. They are therefore **not covered by any license Cyber Hub adopts for its own code**; see `docs/governance/THIRD_PARTY_LICENSE_AUDIT.md`. The license, as published in the React Bits repository (retrieved 2026-11-13):

```
MIT + Commons Clause License Condition v1.0

Copyright (c) 2026 David Haz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, and distribute the Software **as part of an application, website, or product**, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

## Commons Clause Restriction

You may use this Software, including for any commercial purpose, **so long as you do not sell, sublicense, or redistribute the components themselves-whether alone, in a bundle, or as a ported version.**

The same restriction covers the React Bits tools (Background Studio, Texture Lab, Shape Magic, Center Stage, Sound Lab and any tools added later) and the sounds in the sound library. **You may not sell, sublicense, or redistribute the tools or the sounds themselves, or offer the tools or a substantially similar copy of them as a hosted service-whether alone, in a bundle, or as a ported version.**

What you make with the tools is yours to use. You can use exported code, images, videos, and audio files in any personal or commercial application, website, or product, including paid ones. **You may not sell or redistribute the exports on their own, either individually or as the product itself, such as a sound, texture, background, or template pack.**

## No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Fonts, icons and libraries bundled into the app's interface (Mission 12)

* **IBM Plex Sans** (`@fontsource/ibm-plex-sans`): Copyright 2019 IBM Corp. All rights reserved. SIL Open Font License 1.1.
* **JetBrains Mono** (`@fontsource-variable/jetbrains-mono`): Copyright 2020 The JetBrains Mono Project Authors (<https://github.com/JetBrains/JetBrainsMono>). SIL Open Font License 1.1.
* **Lucide icons** (`lucide-react`): ISC License, below.
* **Apache ECharts** (`echarts`): Apache License 2.0. Its NOTICE file reads: "Apache ECharts. Copyright 2017-2026 The Apache Software Foundation. This product includes software developed at The Apache Software Foundation (https://www.apache.org/)."

Every other dependency, with its license, is listed in `docs/governance/third-party/`. Shipping those license texts with the installers is an open item (`docs/governance/THIRD_PARTY_LICENSE_AUDIT.md`).

**Lucide** (ISC License):

```
ISC License

Copyright (c) 2026 Lucide Icons and Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

---

The following Lucide icons are derived from the Feather project:

airplay, alert-circle, alert-octagon, alert-triangle, aperture, arrow-down-circle, arrow-down-left, arrow-down-right, arrow-down, arrow-left-circle, arrow-left, arrow-right-circle, arrow-right, arrow-up-circle, arrow-up-left, arrow-up-right, arrow-up, at-sign, calendar, cast, check, chevron-down, chevron-left, chevron-right, chevron-up, chevrons-down, chevrons-left, chevrons-right, chevrons-up, circle, clipboard, clock, code, columns, command, compass, corner-down-left, corner-down-right, corner-left-down, corner-left-up, corner-right-down, corner-right-up, corner-up-left, corner-up-right, crosshair, database, divide-circle, divide-square, dollar-sign, download, external-link, feather, frown, hash, headphones, help-circle, info, italic, key, layout, life-buoy, link-2, link, loader, lock, log-in, log-out, maximize, meh, minimize, minimize-2, minus-circle, minus-square, minus, monitor, moon, more-horizontal, more-vertical, move, music, navigation-2, navigation, octagon, pause-circle, percent, plus-circle, plus-square, plus, power, radio, rss, search, server, share, shopping-bag, sidebar, smartphone, smile, square, table-2, tablet, target, terminal, trash-2, trash, triangle, tv, type, upload, x-circle, x-octagon, x-square, x, zoom-in, zoom-out

The MIT License (MIT) (for the icons listed above)

Copyright (c) 2013-present Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**SIL Open Font License 1.1** (IBM Plex Sans, JetBrains Mono):

```
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```
