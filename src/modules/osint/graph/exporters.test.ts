import { describe, expect, it } from "vitest";
import { exportSvg, xmlEscape } from "./exporters";
import { THEME } from "./style";
import type { GraphEdge, GraphGroup, GraphNode, Positions, Verification } from "./types";

const node = (id: string, label: string, extra: Partial<GraphNode> = {}): GraphNode => ({
  id,
  label,
  type: "domain",
  color: "#4c8dff",
  glyph: "D",
  verification: "observed",
  ...extra,
});
const edge = (id: string, source: string, target: string, extra: Partial<GraphEdge> = {}): GraphEdge => ({
  id,
  source,
  target,
  type: "resolves_to",
  label: "",
  color: "#8a93a3",
  directed: true,
  verification: "observed",
  ...extra,
});

const count = (s: string, needle: string) => s.split(needle).length - 1;

describe("xmlEscape", () => {
  it("escapes markup characters and strips characters XML forbids", () => {
    expect(xmlEscape(`<a href="x">'&'</a>`)).toBe("&lt;a href=&quot;x&quot;&gt;&apos;&amp;&apos;&lt;/a&gt;");
    expect(xmlEscape("ok\u0000\u0007\u001Fdone")).toBe("okdone");
    expect(xmlEscape("tab\tnl\n")).toBe("tab\tnl\n");
    expect(xmlEscape("lone \uD800 surrogate")).toBe("lone  surrogate");
    expect(xmlEscape("emoji 😀")).toBe("emoji 😀");
  });
});

describe("exportSvg", () => {
  const nodes = [
    node("n1", `<script>alert("x")</script>`),
    node("n2", `Tom & Jerry's "LLC"`, { verification: "verified", flagged: true }),
    node("n3", "plain", { verification: "rejected", glyph: "<>" }),
    node("n4", "no position"),
  ];
  const positions: Positions = new Map([
    ["n1", { x: 0, y: 0 }],
    ["n2", { x: 200, y: 50 }],
    ["n3", { x: -150, y: 120 }],
  ]);
  const edges = [
    edge("e1", "n1", "n2", { label: "</text><script>bad()</script>" }),
    edge("e2", "n2", "n1", { verification: "disputed" }),
    edge("e3", "n1", "n3", { directed: false, verification: "inferred" }),
    edge("e4", "n1", "n4"), // endpoint without a position: skipped
  ];

  it("produces a standalone SVG document", () => {
    const svg = exportSvg(nodes, edges, positions);
    expect(svg.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true);
    expect(svg.trimEnd().endsWith("</svg>")).toBe(true);
    expect(count(svg, "<svg")).toBe(1);
  });

  it("escapes all untrusted text", () => {
    const svg = exportSvg(nodes, edges, positions);
    expect(svg).not.toContain("<script");
    expect(svg).not.toContain("</script");
    expect(svg).toContain("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
    expect(svg).toContain("Tom &amp; Jerry&apos;s &quot;LLC&quot;");
    expect(svg).toContain("&lt;/text&gt;&lt;script&gt;bad()&lt;/script&gt;");
    expect(svg).toContain(">&lt;&gt;</text>"); // glyph
    // No raw ampersand that is not the start of an entity.
    expect(/&(?!amp;|lt;|gt;|quot;|apos;)/.test(svg)).toBe(false);
  });

  it("emits one element per drawable node and edge", () => {
    const svg = exportSvg(nodes, edges, positions);
    expect(count(svg, 'class="node"')).toBe(3);
    expect(count(svg, 'class="node-body"')).toBe(3);
    expect(count(svg, 'class="node-flag"')).toBe(1);
    expect(count(svg, 'class="edge"')).toBe(3);
    expect(count(svg, 'class="node-label"')).toBe(3);
    expect(count(svg, 'class="edge-label"')).toBe(1);
  });

  it("uses markers for directed edges only, with dash styles per verification", () => {
    const svg = exportSvg(nodes, edges, positions);
    expect(count(svg, "marker-end=")).toBe(2);
    expect(count(svg, "<marker ")).toBe(2); // observed grey + disputed warning colour
    expect(svg).toContain('stroke-dasharray="6 4"'); // inferred
    expect(svg).toContain(`stroke="${THEME.warning}"`); // disputed uses the warning colour
    expect(svg).toContain('stroke-linecap="round"'); // dotted
    // Parallel A→B / B→A edges are drawn as curves.
    expect(count(svg, " Q")).toBeGreaterThanOrEqual(2);
  });

  it("frames the drawing in the viewBox with padding", () => {
    const svg = exportSvg(nodes, edges, positions, { padding: 40 });
    const m = /viewBox="([-\d.]+) ([-\d.]+) ([-\d.]+) ([-\d.]+)"/.exec(svg);
    expect(m).not.toBeNull();
    const [x, y, w, h] = m!.slice(1).map(Number);
    for (const p of positions.values()) {
      expect(p.x - 16).toBeGreaterThanOrEqual(x + 40 - 1e-6);
      expect(p.x + 16).toBeLessThanOrEqual(x + w - 40 + 1e-6);
      expect(p.y - 16).toBeGreaterThanOrEqual(y + 40 - 1e-6);
      expect(p.y + 16).toBeLessThanOrEqual(y + h - 40 + 1e-6);
    }
    expect(svg).toContain(`width="${Math.round(w)}"`);
  });

  it("honours explicit size, background, groups, pins and label toggles", () => {
    const groups: GraphGroup[] = [{ id: "g1", label: "Infra <core>", color: "#3fb68b", nodeIds: ["n1", "n2"] }];
    const svg = exportSvg(nodes, edges, positions, {
      width: 800,
      height: 600,
      background: "#0b0d10",
      groups,
      pinned: new Set(["n1"]),
      showLabels: false,
    });
    expect(svg).toContain('width="800" height="600"');
    expect(svg).toContain('fill="#0b0d10"');
    expect(count(svg, 'class="group"')).toBe(1);
    expect(svg).toContain("Infra &lt;core&gt;");
    expect(count(svg, 'class="node-pin"')).toBe(1);
    expect(count(svg, 'class="node-label"')).toBe(0);
    expect(count(svg, 'class="edge-label"')).toBe(0);
  });

  it("neutralises hostile colours", () => {
    const evil = [node("x", "x", { color: `red" onload="alert(1)` }), node("y", "y", { color: "url(javascript:alert(1))" })];
    const pos: Positions = new Map([
      ["x", { x: 0, y: 0 }],
      ["y", { x: 100, y: 0 }],
    ]);
    const svg = exportSvg(evil, [edge("e", "x", "y", { color: "expression(alert(1))" })], pos);
    expect(svg).not.toContain("onload");
    expect(svg).not.toContain("javascript");
    expect(svg).not.toContain("expression");
  });

  it("handles an empty graph", () => {
    const svg = exportSvg([], [], new Map());
    expect(svg).toContain("<svg");
    expect(count(svg, 'class="node"')).toBe(0);
  });

  it("renders every verification state", () => {
    const states: Verification[] = ["observed", "verified", "inferred", "disputed", "rejected"];
    const ns = states.map((v, i) => node(`s${i}`, v, { verification: v }));
    const pos: Positions = new Map(states.map((_, i) => [`s${i}`, { x: i * 100, y: 0 }]));
    const svg = exportSvg(ns, [], pos);
    expect(count(svg, 'class="node-body"')).toBe(5);
    expect(svg).toContain(`stroke="${THEME.success}"`); // verified ring
    expect(svg).toContain('fill-opacity="0.4"'); // rejected body
  });
});
