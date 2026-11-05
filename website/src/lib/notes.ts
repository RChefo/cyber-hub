// A deliberately small Markdown subset for release notes, parsed into data (never HTML), so text
// from a release body cannot inject markup or scripts into the page.

export type Inline = { t: "text"; v: string } | { t: "code"; v: string } | { t: "strong"; v: string } | { t: "link"; v: string; href: string };
export type Block = { t: "heading"; level: 2 | 3; v: Inline[] } | { t: "list"; items: Inline[][] } | { t: "para"; v: Inline[] };
export interface NotesSection {
  title: string | null;
  blocks: Block[];
}

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\((https:\/\/[^\s)]+)\))/g;

export function parseInline(s: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of s.matchAll(INLINE)) {
    if (m.index > last) out.push({ t: "text", v: s.slice(last, m.index) });
    if (m[1]) out.push({ t: "code", v: m[1].slice(1, -1) });
    else if (m[2]) out.push({ t: "strong", v: m[2].slice(2, -2) });
    else if (m[3]) out.push({ t: "link", v: m[3].slice(1, m[3].indexOf("]")), href: m[4] });
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push({ t: "text", v: s.slice(last) });
  return out;
}

export function parseNotes(md: string): Block[] {
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: Inline[][] | null = null;
  const flush = () => {
    if (para.length) blocks.push({ t: "para", v: parseInline(para.join(" ")) });
    para = [];
    if (list) blocks.push({ t: "list", items: list });
    list = null;
  };
  for (const raw of md.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trimEnd();
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    const li = /^\s*[-*]\s+(.*)$/.exec(line);
    if (!line.trim()) flush();
    else if (h) {
      flush();
      blocks.push({ t: "heading", level: h[1].length <= 2 ? 2 : 3, v: parseInline(h[2].trim()) });
    } else if (li) {
      if (para.length) {
        blocks.push({ t: "para", v: parseInline(para.join(" ")) });
        para = [];
      }
      (list ??= []).push(parseInline(li[1]));
    } else {
      if (list) {
        blocks.push({ t: "list", items: list });
        list = null;
      }
      para.push(line.trim());
    }
  }
  flush();
  return blocks;
}

const text = (v: Inline[]) => v.map((i) => i.v).join("");

/** Groups notes by their level-2 headings ("New features", "Bug fixes", "Security", …) as written
 *  by the release author. Nothing is categorized automatically. */
export function sections(blocks: Block[]): NotesSection[] {
  const out: NotesSection[] = [];
  let cur: NotesSection = { title: null, blocks: [] };
  for (const b of blocks) {
    if (b.t === "heading" && b.level === 2) {
      if (cur.title !== null || cur.blocks.length) out.push(cur);
      cur = { title: text(b.v), blocks: [] };
    } else cur.blocks.push(b);
  }
  if (cur.title !== null || cur.blocks.length) out.push(cur);
  return out;
}
