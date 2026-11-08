import { useEffect, useState } from "react";

/** Rows rendered per step in long lists (thousands of rows would block the window). */
export const SHOW_STEP = 200;

/** The first `limit` items, and how many are not shown. */
export function limitList<T>(items: T[], limit: number): { visible: T[]; hidden: number } {
  return items.length > limit ? { visible: items.slice(0, limit), hidden: items.length - limit } : { visible: items, hidden: 0 };
}

/**
 * Renders a long list in steps of `step` rows. The limit goes back to one step whenever `resetKey`
 * changes (for example a new filter or search), so a narrowed list starts at the top again.
 */
export function useShowMore<T>(items: T[], resetKey: unknown, step = SHOW_STEP) {
  const [limit, setLimit] = useState(step);
  useEffect(() => setLimit(step), [resetKey, step]);
  const { visible, hidden } = limitList(items, limit);
  return { visible, hidden, more: () => setLimit((l) => l + step), step };
}
