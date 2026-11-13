// SPDX-License-Identifier: Apache-2.0
// Pure helpers of NavTree (src/components/ui/NavTree.tsx), Mission 14. Original code; it replaces the React
// Bits BranchedMenu component, whose MIT + Commons Clause license is not an open-source license.

/** Where focus goes from row `current` of `count` focusable rows for a navigation key, or null to ignore the key. */
export function nextFocus(current: number, count: number, key: string): number | null {
  if (count <= 0) return null;
  switch (key) {
    case "ArrowDown":
      return current < 0 ? 0 : (current + 1) % count;
    case "ArrowUp":
      return current < 0 ? count - 1 : (current - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

/** The groups that start open: all of them unless `openGroups` lists some; the group of the active item always does. */
export function initialOpen(groups: { children: { value: string }[] }[], active: string | undefined, openGroups?: number[]): Set<number> {
  const open = new Set(openGroups ?? groups.map((_, i) => i));
  groups.forEach((g, i) => {
    if (active && g.children.some((c) => c.value === active)) open.add(i);
  });
  return open;
}
