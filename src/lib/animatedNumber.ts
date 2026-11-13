// SPDX-License-Identifier: Apache-2.0
// Pure helpers of AnimatedNumber (src/components/ui/AnimatedNumber.tsx), Mission 14. Original code; it replaces
// the React Bits CountUp component, whose MIT + Commons Clause license is not an open-source license.

/** Ease-out cubic: fast at the start, settling at the end. `t` is clamped to 0..1. */
export function easeOutCubic(t: number): number {
  const c = Math.min(1, Math.max(0, t));
  return 1 - (1 - c) ** 3;
}

/** The value shown `elapsed` ms into an animation from `from` to `to` lasting `duration` ms. */
export function frameValue(from: number, to: number, elapsed: number, duration: number, decimals = 0): number {
  if (!(duration > 0) || elapsed >= duration) return to;
  const v = from + (to - from) * easeOutCubic(elapsed / duration);
  const f = 10 ** decimals;
  return Math.round(v * f) / f;
}

const FORMATS = new Map<number, Intl.NumberFormat>();

/** "1,234" or "12.5": grouped, a fixed number of decimals. Non-finite values show as an em dash. */
export function formatCount(value: number, decimals = 0): string {
  if (!Number.isFinite(value)) return "—";
  let f = FORMATS.get(decimals);
  if (!f) {
    f = new Intl.NumberFormat("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
    FORMATS.set(decimals, f);
  }
  return f.format(value);
}
