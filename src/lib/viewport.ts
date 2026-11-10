import { useSyncExternalStore } from "react";

/** Below this window width (logical pixels) the sidebar shows icons only, whatever the preference:
 * at 150 % or 200 % scaling a 1920 × 1080 screen is only 1280 or 960 pixels wide, and labels
 * would take a quarter of it (Mission 7). */
export const COMPACT_SIDEBAR_BELOW = 1024;

/** Whether the sidebar shows icons only: the user's choice, or a window too narrow for labels. */
export function sidebarCollapsed(windowWidth: number, preferCollapsed: boolean): boolean {
  return preferCollapsed || windowWidth < COMPACT_SIDEBAR_BELOW;
}

const NARROW = `(max-width: ${COMPACT_SIDEBAR_BELOW - 0.02}px)`;

function subscribe(onChange: () => void) {
  const mq = typeof window !== "undefined" ? window.matchMedia?.(NARROW) : undefined;
  mq?.addEventListener("change", onChange);
  return () => mq?.removeEventListener("change", onChange);
}

/** The window's width class, updated when the window is resized or moved to another screen. */
export function useNarrowWindow(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => (typeof window !== "undefined" ? (window.matchMedia?.(NARROW).matches ?? false) : false),
    () => false,
  );
}
