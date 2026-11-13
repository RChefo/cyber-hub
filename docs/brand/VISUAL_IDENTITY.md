# ExploitX visual identity

What the identity is made of, how it was chosen, and how each part is constructed. Usage rules: [BRAND_GUIDELINES.md](BRAND_GUIDELINES.md). Tokens: [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md). Files: [ASSET_CATALOG.md](ASSET_CATALOG.md).

## How it was chosen (Mission 13)

Four symbol directions were drawn as real vector sketches and judged at 256, 64, 32 and 16 px on dark and light backgrounds. The board is `design/brand/exploration/directions.html`.

| Direction | Idea | Verdict |
|---|---|---|
| **A. Convergence** | Two chevrons meet at one point: the operator's input reaching the target | **Selected.** Reads as an X at every size: the hairline gap closes at small sizes, where it becomes a solid X. Distinct from the common X marks (crossed strokes, thin-and-thick strokes). A meaning that holds for the whole platform, not only for offence |
| B. Escape | An X cut out of a tile, with one arm leaving it (a sandbox escape) | Rejected: at icon sizes the tile and arm read as a magnifying glass, the universal "search" icon |
| C. Fault | One stroke crosses a boundary and comes out displaced | Rejected: reads as a "broken" or glitch X (a hacker cliché) and sits close to the X (Twitter) mark |
| D. Graph | Four observations joined through one node | Rejected: a generic "network" or drone icon, forgettable at small sizes |

Five accent colours were compared on the symbol, a primary button, a focus ring, a navigation item, links and the severity scale, on dark and light backgrounds. The board is `design/brand/exploration/palettes.html`.

| Candidate | Verdict |
|---|---|
| **Ultraviolet `#7C6AFF`** | **Selected.** Calm and premium. Legible on dark and light (with the 700 shade). No clash with any severity colour. The idea of light beyond the visible, which shows what is hidden, fits security research |
| Signal lime `#C8F03C` | The most striking, but it is the "neon hacker" look the brief rules out, close to Hack The Box's signature lime, and nearly invisible on white. **Kept as a sparing accent** |
| Ember `#FF6B3D` | Rejected: confused with the High severity orange |
| Ion aqua `#2FE3CF` | Rejected: the stock "cyber" colour; weak on white; close to success green |

Seven open-licence typefaces were set as "ExploitX". The board is `design/brand/exploration/wordmarks.html`.

| Typeface | Verdict |
|---|---|
| **Archivo SemiBold** | **Selected.** Engineered, slightly wide, confident without shouting; excellent numerals (tabular figures) for dashboards |
| Sora, Manrope | Too friendly and geometric for the subject |
| Space Grotesk | Distinctive, but quirky letterforms (the `t`, the `p`) date quickly |
| Geist, Instrument Sans | Clean, but strongly associated with other developer brands |
| IBM Plex Sans | Kept as the interface typeface, too corporate (IBM) for the logotype |

A trial that used the full symbol as the wordmark's final X was rejected: at small sizes it read as "Exploit><". The wordmark's X is therefore its own letter, built like the symbol at the letters' weight.

## Symbol: Convergence

* **Construction:** two chevrons on a 64-unit grid. The mark spans x 6–58 and y 8–56, centred on (32, 32).
  * The left chevron ">" is the operator, in Ultraviolet: points (6,8) (20,8) (31,32) (20,56) (6,56) (17,32).
  * The right chevron "<" is the target, in Bone on dark or Ink on light. It is the mirror image across x = 32.
* **Arms:** 14 units wide horizontally, with flat horizontal ends.
* **Tips:** they stop 2 units apart. That hairline is the point of exploitation, the unknown "X". It is visible from about 48 px up; below that it closes and the mark reads as a solid X.
* **Small sizes:** for 24 px and smaller there is a version without the gap (`logo-symbol-small.svg`, `SYMBOL.leftSmall/rightSmall`), so the tips meet on whole pixels instead of blurring.
* **Meaning:** input and target, offence and defence, many signals and one finding, converging on one point. The idea is broad enough for the whole platform (OSINT, intelligence, detection, reports), not only exploitation.

## Wordmark

* **"Exploit":** Archivo SemiBold (600), converted to outlines. Tracking is −0.012 em, and the font's kerning is kept.
  * Archivo by Omnibus-Type is under the SIL Open Font License 1.1, which allows using its glyphs in a logo.
  * The outlines are in `design/brand/build/wordmark.json`, extracted by `extract-wordmark.mjs`.
* **"X":** drawn, not typed: two chevrons meeting at a hairline, the symbol's construction at the letters' stem weight.
  * Each arm is 1.18 stems wide horizontally; the gap is 0.2 stem.
  * The compact version (under 16 px cap height) has no gap and 1.26-stem arms.
* **Capitalisation:** exactly `ExploitX`.
* **Lockups:** the symbol is 1.3 cap heights tall and centred on the capitals; the gap between symbol and wordmark is 0.62 cap heights. The stacked lockup uses a 2.6-cap-height symbol, 0.8 cap heights above the wordmark.

## Colour

* **Dark-first.**
  * **Brand colours:** Ultraviolet and Bone on Night.
  * **Graphite neutrals,** tinted very slightly towards Ultraviolet so surfaces and accent belong together.
  * **Surfaces are told apart by fill and shadow, never by outlines.** The app's long-standing no-borders rule continues.
* **Ultraviolet roles:**
  * **500 `#7C6AFF`:** the brand colour, for the symbol, focus rings and highlights on dark.
  * **600 `#6A57F5`:** solid fills that carry white text (4.9:1).
  * **700 `#5240E0`:** text and marks on light backgrounds (5.9:1 on white).
  * **300 and 400:** soft text and links on dark.
* **Signal `#C8F03C`:** an accent used sparingly, at most one highlight per view (for example a live state on the website). It never carries meaning such as success or a severity.
* **Severity colours:** they keep their established meanings, and every severity is shown with its name.
* **Data visualisation:** its own categorical and sequential palettes (see DESIGN_SYSTEM.md).
* **Contrast (WCAG):** values measured during the mission:

  | Pair | Contrast |
  |---|---|
  | Text `#ECEEF4` on Night | 16.95:1 |
  | Muted text `#8B92A5` on a surface | 5.8:1 |
  | Ultraviolet 500 on Night | 5.0:1 |
  | White on Ultraviolet 600 | 4.9:1 |
  | Critical `#E5484D` on a surface | 4.6:1 |
  | Medium `#F2C94C` on a surface | 11.4:1 |

## Typography

| Role | Typeface | Where |
|---|---|---|
| Display and headings | **Archivo** (variable, `wdth` 106, weight 600) | Page titles, key figures (`Stat`), website headings, social images |
| Interface and text | **IBM Plex Sans** 400/500/600 | Everything else in the app and on the website. Chosen for dense tables and long technical text; proven at 100–200 % scaling in earlier missions |
| Technical | **JetBrains Mono** (variable) | Commands, identifiers, hashes, code. Ligatures off, so `--` never becomes a dash |

* **Numbers:** tabular figures (`.tabular`) wherever numbers line up: tables, counters, timestamps.
* **Licences:** all three typefaces are under the SIL Open Font License 1.1. They are bundled through `@fontsource` packages and listed in THIRD_PARTY_NOTICES.md, and the licence policy check accepts OFL-1.1.

## Iconography

* **One family: Lucide** (ISC licence), as before. Outline icons with a 1.75 px stroke at 17 px in navigation and 1.5–2 px elsewhere, with round caps and joins.
* **Keep the established meanings** of existing actions; do not swap icons for decoration.
* **No second icon set,** and no filled icons next to outline ones, except status dots.
* **The symbol is the only brand glyph.** It is never used as an action icon.
* **Severity and status:** colour plus text, or plus a glyph, never colour alone.

## Illustration style

`design/brand/illustrations/` has three examples (investigate, detect, report).

* A Surface tile with a faint Ultraviolet glow.
* Hairline structure in Bone at 20–60 % opacity.
* **One** element in Ultraviolet that carries the idea (the signal), often the symbol at the point where things converge.
* Severity colours only where the drawing is about severity.
* No text, no people, no stock security metaphors (padlocks, shields, binary, globes).

## Background device: the convergence field

* **What it is:** two fans of hairlines that meet at one focal point, at 6–8 % opacity. It echoes the symbol at a large scale.
* **Where:** social images and large brand surfaces only. Never behind dense UI or text blocks.
