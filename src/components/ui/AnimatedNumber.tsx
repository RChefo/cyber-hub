// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { formatCount, frameValue } from "@/lib/animatedNumber";

const reducedMotion = () => typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;

/**
 * A number that counts to its value (Mission 14; original code that replaces the React Bits CountUp).
 *
 * * Counts from the previously shown value, so a refresh animates only the difference; the first
 *   render counts up from `from` (0).
 * * Assistive technology reads the final value once: the moving digits are hidden from it.
 * * With `prefers-reduced-motion`, the value is shown at once.
 */
export function AnimatedNumber({ value, duration = 600, from = 0, decimals = 0, className }: { value: number; duration?: number; from?: number; decimals?: number; className?: string }) {
  const [shown, setShown] = useState(() => (reducedMotion() ? value : from));
  const shownRef = useRef(shown);
  shownRef.current = shown;

  useEffect(() => {
    if (reducedMotion() || duration <= 0) {
      setShown(value);
      return;
    }
    const start = shownRef.current;
    if (start === value) return;
    let raf = 0;
    const t0 = performance.now();
    const step = (now: number) => {
      const next = frameValue(start, value, now - t0, duration, decimals);
      setShown(next);
      if (next !== value) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value, duration, decimals]);

  return (
    <span className={className}>
      <span aria-hidden="true">{formatCount(shown, decimals)}</span>
      <span className="sr-only">{formatCount(value, decimals)}</span>
    </span>
  );
}
