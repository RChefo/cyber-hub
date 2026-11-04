import { describe, expect, it } from "vitest";
import { dragRegionFor } from "./dragRegion";

describe("dragRegionFor", () => {
  it("uses Tauri's built-in drag region on Windows", () => {
    expect(dragRegionFor(false)).toEqual({ "data-tauri-drag-region": "" });
  });

  it("uses press-and-move dragging plus double-click maximize on Linux", () => {
    const p = dragRegionFor(true);
    expect(p["data-tauri-drag-region"]).toBeUndefined();
    expect(typeof p.onMouseDown).toBe("function");
    expect(typeof p.onDoubleClick).toBe("function");
  });

  it("ignores presses on child elements, other buttons and the second press of a double-click", () => {
    const { onMouseDown } = dragRegionFor(true);
    let prevented = 0;
    const ev = (over: Record<string, unknown>) =>
      ({ button: 0, detail: 1, target: 1, currentTarget: 1, screenX: 0, screenY: 0, preventDefault: () => prevented++, ...over }) as never;
    onMouseDown?.(ev({ target: 2 }));
    onMouseDown?.(ev({ button: 2 }));
    onMouseDown?.(ev({ detail: 2 }));
    expect(prevented).toBe(0);
  });
});
