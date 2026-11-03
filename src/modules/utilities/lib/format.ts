/** JSON / XML / HTML formatting helpers (pure, local). */

export class FormatError extends Error {
  line?: number;
  column?: number;
  constructor(message: string, line?: number, column?: number) {
    super(message);
    this.line = line;
    this.column = column;
  }
}

function lineCol(text: string, pos: number): { line: number; column: number } {
  const before = text.slice(0, pos);
  const line = before.split("\n").length;
  return { line, column: pos - before.lastIndexOf("\n") };
}

export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    const msg = (e as Error).message;
    const pos = msg.match(/position (\d+)/)?.[1];
    const lc = msg.match(/line (\d+) column (\d+)/);
    if (lc) throw new FormatError(msg, Number(lc[1]), Number(lc[2]));
    if (pos) {
      const { line, column } = lineCol(text, Number(pos));
      throw new FormatError(msg, line, column);
    }
    throw new FormatError(msg);
  }
}

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.keys(v as object)
        .sort()
        .map((k) => [k, sortDeep((v as Record<string, unknown>)[k])]),
    );
  }
  return v;
}

export function formatJson(text: string, opts: { indent: 0 | 2 | 4 | "tab"; sortKeys?: boolean }): string {
  let value = parseJson(text);
  if (opts.sortKeys) value = sortDeep(value);
  if (opts.indent === 0) return JSON.stringify(value);
  return JSON.stringify(value, null, opts.indent === "tab" ? "\t" : opts.indent);
}

export function formatXml(text: string, indent = 2): string {
  const doc = new DOMParser().parseFromString(text.trim(), "application/xml");
  const err = doc.getElementsByTagName("parsererror")[0];
  if (err) throw new FormatError((err.textContent || "Invalid XML").replace(/\s+/g, " ").trim());
  const pad = (n: number) => " ".repeat(n * indent);
  const lines: string[] = [];
  const walk = (node: Node, depth: number) => {
    switch (node.nodeType) {
      case Node.ELEMENT_NODE: {
        const el = node as Element;
        const attrs = Array.from(el.attributes)
          .map((a) => ` ${a.name}="${a.value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;")}"`)
          .join("");
        const children = Array.from(el.childNodes).filter((c) => !(c.nodeType === Node.TEXT_NODE && !c.textContent?.trim()));
        if (!children.length) lines.push(`${pad(depth)}<${el.tagName}${attrs}/>`);
        else if (children.length === 1 && children[0].nodeType === Node.TEXT_NODE)
          lines.push(`${pad(depth)}<${el.tagName}${attrs}>${escapeXmlText(children[0].textContent!.trim())}</${el.tagName}>`);
        else {
          lines.push(`${pad(depth)}<${el.tagName}${attrs}>`);
          children.forEach((c) => walk(c, depth + 1));
          lines.push(`${pad(depth)}</${el.tagName}>`);
        }
        break;
      }
      case Node.TEXT_NODE:
        lines.push(`${pad(depth)}${escapeXmlText(node.textContent!.trim())}`);
        break;
      case Node.CDATA_SECTION_NODE:
        lines.push(`${pad(depth)}<![CDATA[${node.textContent}]]>`);
        break;
      case Node.COMMENT_NODE:
        lines.push(`${pad(depth)}<!--${node.textContent}-->`);
        break;
      case Node.PROCESSING_INSTRUCTION_NODE: {
        const pi = node as ProcessingInstruction;
        lines.push(`${pad(depth)}<?${pi.target} ${pi.data}?>`);
        break;
      }
    }
  };
  const decl = text.trim().match(/^<\?xml[^?]*\?>/)?.[0];
  if (decl) lines.push(decl);
  Array.from(doc.childNodes).forEach((n) => {
    if (n.nodeType === Node.DOCUMENT_TYPE_NODE) lines.push(`<!DOCTYPE ${(n as DocumentType).name}>`);
    else walk(n, 0);
  });
  return lines.join("\n");
}

function escapeXmlText(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
const RAW = new Set(["script", "style", "pre", "textarea"]);

/** Indent HTML using a lightweight tokenizer. Content is never executed or parsed into a live DOM. */
export function formatHtml(html: string, indent = 2): string {
  const tokens = html.match(/<!--[\s\S]*?-->|<![^>]*>|<\/?[a-zA-Z][^>]*>|[^<]+|</g) ?? [];
  const out: string[] = [];
  let depth = 0;
  let raw: string | null = null;
  let rawBuf = "";
  const pad = () => " ".repeat(Math.max(depth, 0) * indent);
  for (const tok of tokens) {
    if (raw) {
      if (new RegExp(`^</${raw}\\s*>$`, "i").test(tok)) {
        if (rawBuf.trim()) out.push(rawBuf.replace(/^\n+|\s+$/g, "").replace(/^/gm, " ".repeat((depth + 1) * indent)));
        out.push(`${pad()}${tok}`);
        raw = null;
        rawBuf = "";
      } else rawBuf += tok;
      continue;
    }
    if (tok.startsWith("<!--") || tok.startsWith("<!")) {
      out.push(pad() + tok.trim());
    } else if (tok.startsWith("</")) {
      depth--;
      out.push(pad() + tok.trim());
    } else if (tok.startsWith("<") && tok.length > 1) {
      const name = tok.match(/^<([a-zA-Z][\w:-]*)/)?.[1].toLowerCase() ?? "";
      out.push(pad() + tok.trim());
      if (RAW.has(name) && !tok.endsWith("/>")) raw = name;
      if (!VOID.has(name) && !tok.endsWith("/>")) depth++;
      if (raw) depth--; // raw content is emitted at depth+1 explicitly
    } else {
      const text = tok.replace(/\s+/g, " ").trim();
      if (text) out.push(pad() + text);
    }
  }
  return out.join("\n");
}
