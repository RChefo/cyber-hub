// SPDX-License-Identifier: Apache-2.0
import type { HTMLAttributes, MouseEvent } from "react";

/**
 * Props for empty areas that move the frameless window (top bar, sidebar header).
 *
 * Windows uses Tauri's built-in `data-tauri-drag-region` (drag on press, double-click toggles
 * maximize). On Linux that script starts a window-manager move on the first press, and the
 * window manager can still be in that move when the second press of a double-click asks to
 * maximize, so the request is dropped (seen with Openbox). There the move starts only once the
 * pointer actually moves with the button held, and a double-click toggles maximize directly.
 * As with the built-in attribute, only presses on the element itself count, not on its children.
 */
export type DragRegionProps = Pick<HTMLAttributes<HTMLElement>, "onMouseDown" | "onDoubleClick"> & { "data-tauri-drag-region"?: string };

const MOVE_THRESHOLD_PX = 4;

async function currentWindow() {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  return getCurrentWindow();
}

function onMouseDown(e: MouseEvent<HTMLElement>) {
  if (e.button !== 0 || e.detail > 1 || e.target !== e.currentTarget) return;
  e.preventDefault(); // no text selection while dragging
  const { screenX: x0, screenY: y0 } = e;
  const move = (m: globalThis.MouseEvent) => {
    if ((m.buttons & 1) === 0) return stop();
    if (Math.abs(m.screenX - x0) + Math.abs(m.screenY - y0) < MOVE_THRESHOLD_PX) return;
    stop();
    void currentWindow().then((w) => w.startDragging()).catch(() => undefined);
  };
  const stop = () => {
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", stop);
  };
  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", stop);
}

function onDoubleClick(e: MouseEvent<HTMLElement>) {
  if (e.button !== 0 || e.target !== e.currentTarget) return;
  void currentWindow().then((w) => w.toggleMaximize()).catch(() => undefined);
}

export function dragRegionFor(linux: boolean): DragRegionProps {
  return linux ? { onMouseDown, onDoubleClick } : { "data-tauri-drag-region": "" };
}

const IS_LINUX = typeof navigator !== "undefined" && /\blinux\b/i.test(navigator.userAgent) && !/android/i.test(navigator.userAgent);

/** Spread on an element: `<header {...dragRegion()}>`. */
export const dragRegion = (): DragRegionProps => dragRegionFor(IS_LINUX);
