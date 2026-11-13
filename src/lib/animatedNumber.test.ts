// SPDX-License-Identifier: Apache-2.0
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AnimatedNumber } from "@/components/ui/AnimatedNumber";
import { easeOutCubic, formatCount, frameValue } from "./animatedNumber";

describe("AnimatedNumber (replaces the React Bits CountUp, Mission 14)", () => {
  it("eases out and clamps", () => {
    expect(easeOutCubic(0)).toBe(0);
    expect(easeOutCubic(1)).toBe(1);
    expect(easeOutCubic(-1)).toBe(0);
    expect(easeOutCubic(2)).toBe(1);
    expect(easeOutCubic(0.5)).toBeCloseTo(0.875);
    // monotonic
    let prev = -1;
    for (let t = 0; t <= 1; t += 0.05) {
      const v = easeOutCubic(t);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
  });

  it("starts at the start value, ends exactly on the target and rounds to the decimals", () => {
    expect(frameValue(0, 42, 0, 600)).toBe(0);
    expect(frameValue(0, 42, 600, 600)).toBe(42);
    expect(frameValue(0, 42, 10_000, 600)).toBe(42);
    expect(Number.isInteger(frameValue(0, 42, 123, 600))).toBe(true);
    expect(frameValue(10, 4, 300, 600)).toBeLessThan(10); // counts down too
    expect(frameValue(0, 1, 300, 600, 2)).toBeCloseTo(0.88, 2);
    expect(frameValue(0, 5, 0, 0)).toBe(5); // no duration: the value at once
  });

  it("formats with grouping and fixed decimals", () => {
    expect(formatCount(1234)).toBe("1,234");
    expect(formatCount(7)).toBe("7");
    expect(formatCount(12.345, 1)).toBe("12.3");
    expect(formatCount(Number.NaN)).toBe("—");
  });

  it("gives assistive technology the final value once and hides the moving digits", () => {
    const html = renderToStaticMarkup(createElement(AnimatedNumber, { value: 1234 }));
    expect(html).toContain('<span aria-hidden="true">0</span>'); // the first frame counts up from 0
    expect(html).toContain('<span class="sr-only">1,234</span>');
    const decimal = renderToStaticMarkup(createElement(AnimatedNumber, { value: 3.5, from: 3.5, decimals: 1 }));
    expect(decimal).toContain('<span aria-hidden="true">3.5</span>');
  });
});
