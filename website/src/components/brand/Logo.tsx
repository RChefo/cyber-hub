import { SYMBOL, WORDMARK } from "./logoData";

/** The ExploitX symbol: the operator's chevron in Ultraviolet, the target's in the current colour. */
export function BrandSymbol({ height = 24, className = "", label }: { height?: number; className?: string; label?: string }) {
  const tiny = height <= 24;
  return (
    <svg
      viewBox={SYMBOL.viewBox}
      height={height}
      width={(height * 52) / 48}
      className={`shrink-0 ${className}`}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <path d={tiny ? SYMBOL.leftSmall : SYMBOL.left} fill="var(--ex-uv-500)" />
      <path d={tiny ? SYMBOL.rightSmall : SYMBOL.right} fill="currentColor" />
    </svg>
  );
}

/** The "ExploitX" logotype at a cap height in px, in the current colour. */
export function Wordmark({ capHeight = 14, className = "" }: { capHeight?: number; className?: string }) {
  const tiny = capHeight < 16;
  const w = tiny ? WORDMARK.widthCompact : WORDMARK.width;
  const h = WORDMARK.capHeight + WORDMARK.descender;
  const s = capHeight / WORDMARK.capHeight;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} height={h * s} width={w * s} className={`shrink-0 ${className}`} aria-hidden="true">
      <path d={tiny ? WORDMARK.dCompact : WORDMARK.d} transform={`translate(${WORDMARK.shift} 0)`} fill="currentColor" />
    </svg>
  );
}

/** Horizontal lockup (symbol 1.3 cap heights, gap 0.62 cap heights), named "ExploitX" for assistive technology. */
export function Logo({ capHeight = 14, className = "" }: { capHeight?: number; className?: string }) {
  return (
    <span role="img" aria-label="ExploitX" className={`inline-flex items-start ${className}`} style={{ gap: capHeight * 0.62 }}>
      <BrandSymbol height={capHeight * 1.3} />
      <span className="inline-flex" style={{ paddingTop: capHeight * 0.15 }}>
        <Wordmark capHeight={capHeight} />
      </span>
    </span>
  );
}
