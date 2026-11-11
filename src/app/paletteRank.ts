/** Ranking of the command palette's results (Ctrl+K). */

export interface Rankable {
  group: string;
  title: string;
  /** lower-case text searched besides the title */
  haystack: string;
}

/** The order of groups whose best matches are equally strong. */
export const GROUP_ORDER = ["Pages", "Tools", "Projects", "Records", "Commands", "Resources", "Dorks", "Payloads", "Wordlists", "Utilities"];

/** At most this many results per group. */
export const PER_GROUP = 6;

/** Every term must match: a title that starts with it counts most, then a title that contains it,
 *  then the rest of the item's text. 0 when a term matches nothing. */
export function score(item: Rankable, terms: string[]): number {
  let s = 0;
  const title = item.title.toLowerCase();
  for (const t of terms) {
    if (title.startsWith(t)) s += 6;
    else if (title.includes(t)) s += 4;
    else if (item.haystack.includes(t)) s += 1;
    else return 0;
  }
  return s;
}

/** Orders the matches for a query. Each group keeps its strongest matches (at most PER_GROUP), and
 *  the groups are ordered by their best match, so a project whose name starts with the query comes
 *  before a page that only mentions it (Mission 9: "RC" found "Cyber Resources" before the project
 *  "RC validation"). Equally strong groups keep GROUP_ORDER. `matched` adds groups found elsewhere
 *  (the backend's record search) with a fixed score. */
export function rank<T extends Rankable>(items: T[], query: string, matched: { group: string; items: T[]; score: number }[] = []): T[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  const groups = new Map<string, { best: number; items: T[] }>();
  const scored = items
    .map((i) => ({ i, s: score(i, terms) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s);
  for (const { i, s } of scored) {
    const g = groups.get(i.group) ?? { best: s, items: [] };
    if (g.items.length < PER_GROUP) g.items.push(i);
    groups.set(i.group, g);
  }
  for (const m of matched) if (m.items.length) groups.set(m.group, { best: m.score, items: m.items });
  const order = (g: string) => {
    const k = GROUP_ORDER.indexOf(g);
    return k < 0 ? GROUP_ORDER.length : k;
  };
  return [...groups.entries()].sort(([ga, a], [gb, b]) => b.best - a.best || order(ga) - order(gb)).flatMap(([, g]) => g.items);
}
