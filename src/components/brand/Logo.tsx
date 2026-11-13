import { cn } from "@/lib/utils";
import { SYMBOL, WORDMARK } from "./logoData";

/**
 * The ExploitX symbol: the operator's chevron in Ultraviolet, the target's in the current text
 * colour. `small` drops the hairline gap for sizes of 24 px and below (docs/brand/BRAND_GUIDELINES.md).
 */
export function BrandSymbol({ height = 24, small, className, label }: { height?: number; small?: boolean; className?: string; label?: string }) {
  const tiny = small ?? height <= 24;
  return (
    <svg
      viewBox={SYMBOL.viewBox}
      height={height}
      width={(height * 52) / 48}
      className={cn("shrink-0", className)}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <path d={tiny ? SYMBOL.leftSmall : SYMBOL.left} fill="var(--ex-uv-500)" />
      <path d={tiny ? SYMBOL.rightSmall : SYMBOL.right} fill="currentColor" />
    </svg>
  );
}

/** The "ExploitX" logotype at a given cap height (px), in the current text colour. */
export function Wordmark({ capHeight = 12, compact, className }: { capHeight?: number; compact?: boolean; className?: string }) {
  const tiny = compact ?? capHeight < 16;
  const w = tiny ? WORDMARK.widthCompact : WORDMARK.width;
  const h = WORDMARK.capHeight + WORDMARK.descender;
  const scale = capHeight / WORDMARK.capHeight;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} height={h * scale} width={w * scale} className={cn("shrink-0", className)} aria-hidden>
      <path d={tiny ? WORDMARK.dCompact : WORDMARK.d} transform={`translate(${WORDMARK.shift} 0)`} fill="currentColor" />
    </svg>
  );
}

/** Horizontal lockup: symbol, then the logotype; the symbol is 1.3 cap heights, centred on the caps. */
export function Logo({ capHeight = 12, className }: { capHeight?: number; className?: string }) {
  return (
    <span role="img" aria-label="ExploitX" className={cn("inline-flex items-start", className)} style={{ gap: capHeight * 0.62 }}>
      <BrandSymbol height={capHeight * 1.3} className="relative" />
      <span style={{ paddingTop: capHeight * 0.15 }} className="inline-flex">
        <Wordmark capHeight={capHeight} />
      </span>
    </span>
  );
}
