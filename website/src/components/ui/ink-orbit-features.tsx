// InkOrbitFeatures: a bento of three live diagrams (flow through a hub into a stack of reports,
// a hub that reaches one tool at a time, a chart you can scrub). Based on the features section of
// ink-orbit-saas-template (Ink Orbit by Kedhareswer Naidu on 21st.dev, source repository
// https://github.com/Kedhareswer/21stdev-my-components). No license was found for it (Mission 12):
// see docs/governance/THIRD_PARTY_LICENSE_AUDIT.md before reusing or redistributing this file.
//
// Adapted for the Cyber Hub website, which may only show what the product really does:
// - the flow diagram's left cluster shows data sources (props) instead of drawn portraits of people;
// - the report stack shows a fixed label instead of a counter that keeps increasing;
// - the hub glyph is the Cyber Hub shield, and the hub chip shows the whole brand name;
// - the integrations status text and the chart labels come from props; the forecast marker is
//   optional (Cyber Hub makes no forecasts);
// - colours and fonts follow the host page (dark theme tokens are overridable with CSS variables).
// No dependencies besides React, no assets.

import React from "react";

export type InkFeatureCopy = { title: string; description: string };
export type InkSource = { label: string; name: string };
export type InkFeatures = {
  tag: string;
  /** `*word*` sets a word in the muted tone; "\n" breaks the line. */
  title: string;
  collaboration: InkFeatureCopy;
  reports: InkFeatureCopy & { label: string };
  integrations: InkFeatureCopy & { tools: string[]; verb: string; summary: string };
  insights: InkFeatureCopy & { values: number[]; forecastFrom?: number; pointLabel: string; unit: string; ariaLabel: string };
};

export type InkOrbitFeaturesProps = {
  /** `auto` follows prefers-color-scheme. */
  theme?: "light" | "dark" | "auto";
  /** Shown on the hub chip in the flow diagram. */
  brand?: string;
  tag?: string;
  title?: string;
  /** up to five nodes around the left hub of the flow diagram */
  sources?: InkSource[];
  collaboration?: Partial<InkFeatureCopy>;
  reports?: Partial<InkFeatures["reports"]>;
  integrations?: Partial<InkFeatures["integrations"]>;
  insights?: Partial<InkFeatures["insights"]>;
  className?: string;
  style?: React.CSSProperties;
};

/* ------------------------------------------------------------------ logic */

function clamp(v: number, a: number, b: number): number {
  return Math.min(b, Math.max(a, v));
}

// Smooth line + closed area through values, inside a w×h box.
function chartPaths(values: number[], w: number, h: number, pad: number) {
  const n = values.length;
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const span = hi - lo || 1;
  const pts = values.map((v, i) => [pad + (n < 2 ? 0 : (i / (n - 1)) * (w - pad * 2)), h - pad - ((v - lo) / span) * (h - pad * 2)] as [number, number]);
  let line = "";
  pts.forEach(([x, y], i) => {
    if (i === 0) {
      line = "M" + x.toFixed(1) + "," + y.toFixed(1);
      return;
    }
    const [px, py] = pts[i - 1];
    const cx = (px + x) / 2;
    line += " C" + cx.toFixed(1) + "," + py.toFixed(1) + " " + cx.toFixed(1) + "," + y.toFixed(1) + " " + x.toFixed(1) + "," + y.toFixed(1);
  });
  const area = n ? line + " L" + pts[n - 1][0].toFixed(1) + "," + (h - pad) + " L" + pts[0][0].toFixed(1) + "," + (h - pad) + " Z" : "";
  return { line, area, points: pts };
}

function nearestIndex(xs: number[], x: number): number {
  let best = 0;
  for (let i = 1; i < xs.length; i++) if (Math.abs(xs[i] - x) < Math.abs(xs[best] - x)) best = i;
  return best;
}

// "Smart *Workflow*\nAutomation" → lines of { text, muted } runs. A literal backslash-n counts
// too, since that is what "\n" becomes in a JSX attribute.
export function parseTitle(s: string): { text: string; muted: boolean }[][] {
  return s.split(/\n|\\n/).map((line) => {
    const out: { text: string; muted: boolean }[] = [];
    line.split("*").forEach((text, i) => {
      if (text) out.push({ text, muted: i % 2 === 1 });
    });
    return out;
  });
}

/* --------------------------------------------------------------- defaults */

const D_SOURCES: InkSource[] = [
  { label: "A", name: "Source A" },
  { label: "B", name: "Source B" },
  { label: "C", name: "Source C" },
  { label: "D", name: "Source D" },
  { label: "E", name: "Source E" },
];

const D_FEATURES: InkFeatures = {
  tag: "Features",
  title: "Smart *Workflow*\nAutomation",
  collaboration: { title: "Collected in one place", description: "Inputs flow into one hub." },
  reports: { title: "Reports", description: "Structured reports from your data.", label: "REPORT" },
  integrations: { title: "Integrations", description: "Connect your tools.", tools: ["One", "Two", "Three", "Four"], verb: "syncing", summary: "4 connected" },
  insights: { title: "Insights", description: "A chart you can scrub.", values: [22, 26, 24, 31, 29, 36, 34, 41, 39, 47, 52, 58], pointLabel: "pt", unit: "", ariaLabel: "Chart" },
};

/* -------------------------------------------------------------- component */

export default function InkOrbitFeatures({
  theme = "auto",
  brand = "Cyber Hub",
  tag = D_FEATURES.tag,
  title = D_FEATURES.title,
  sources = D_SOURCES,
  collaboration,
  reports,
  integrations,
  insights,
  className = "",
  style,
}: InkOrbitFeaturesProps) {
  const uid = "ib" + React.useId().replace(/[^a-zA-Z0-9]/g, "");
  const F: InkFeatures = {
    tag,
    title,
    collaboration: { ...D_FEATURES.collaboration, ...collaboration },
    reports: { ...D_FEATURES.reports, ...reports },
    integrations: { ...D_FEATURES.integrations, ...integrations },
    insights: { ...D_FEATURES.insights, ...insights },
  };

  const [dark, setDark] = React.useState(theme === "dark");
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const scheme = window.matchMedia("(prefers-color-scheme: dark)");
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => {
      setDark(theme === "auto" ? scheme.matches : theme === "dark");
      setReduced(motion.matches);
    };
    sync();
    scheme.addEventListener?.("change", sync);
    motion.addEventListener?.("change", sync);
    return () => {
      scheme.removeEventListener?.("change", sync);
      motion.removeEventListener?.("change", sync);
    };
  }, [theme]);

  const [featRef, featIn] = useInView(0.12);

  return (
    <div className={"ib-root " + className} data-theme={dark ? "dark" : "light"} style={style}>
      <style>{IB_CSS}</style>
      <div className="ib-shell">
        <section className="ib-sec" aria-labelledby={uid + "feat"}>
          <div className="ib-reveal" ref={featRef as never} data-in={featIn}>
            <div className="ib-head" id={uid + "feat"}>
              {F.tag && <span className="ib-tag">{F.tag}</span>}
              <Title text={F.title} />
            </div>
            <div className="ib-bento">
              <FlowCard brand={brand} features={F} sources={sources} uid={uid} reduced={reduced} />
              <IntegrationsCard copy={F.integrations} reduced={reduced} />
              <InsightsCard copy={F.insights} uid={uid} reduced={reduced} />
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- pieces */

// true once the element has been on screen
function useInView(threshold = 0.2) {
  const ref = React.useRef(null as HTMLElement | null);
  const [inView, setInView] = React.useState(typeof IntersectionObserver !== "function");
  React.useEffect(() => {
    const el = ref.current;
    if (!el || inView) return;
    const io = new IntersectionObserver(
      (es) => {
        if (es.some((e) => e.isIntersecting)) {
          setInView(true);
          io.disconnect();
        }
      },
      { threshold },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [inView, threshold]);
  return [ref, inView] as const;
}

function Brackets() {
  return (
    <>
      <span className="ib-c ib-c-tl" aria-hidden="true" />
      <span className="ib-c ib-c-tr" aria-hidden="true" />
      <span className="ib-c ib-c-bl" aria-hidden="true" />
      <span className="ib-c ib-c-br" aria-hidden="true" />
    </>
  );
}

function Title({ text, className = "ib-h2" }: { text: string; className?: string }) {
  return (
    <h2 className={className}>
      {parseTitle(text).map((line, i) => (
        <span key={i}>
          {line.map((run, j) => (
            <React.Fragment key={j}>{run.muted ? <span className="ib-muted" style={{ display: "inline" }}>{run.text}</span> : run.text}</React.Fragment>
          ))}
        </span>
      ))}
    </h2>
  );
}

function Mark({ size = 18 }: { size?: number }) {
  // the Cyber Hub shield
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2.5 19.5 5.5v5.2c0 5-3.2 8.8-7.5 10.5-4.3-1.7-7.5-5.5-7.5-10.5V5.5z" fill="none" stroke="var(--ib-accent)" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M8.6 11.5h6.8M12 8.1v6.8" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function ToolGlyph({ index }: { index: number }) {
  const k = index % 4;
  return (
    <g fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      {k === 0 && (
        <>
          <rect x="-6" y="-6" width="12" height="12" rx="1.5" />
          <path d="M-6 -2h12M-6 2h12M-1.5 -6v12" />
        </>
      )}
      {k === 1 && <path d="M-6.5 4 -2 -5h4l4.5 9zm2.4 0h9.2M-2 -5l4.5 9" />}
      {k === 2 && (
        <>
          <path d="M-4.5 -6.5h6l3 3v10h-9z" />
          <path d="M-2 0h4.5M-2 3h4.5" />
        </>
      )}
      {k === 3 && (
        <>
          <circle cx="-1" cy="-1" r="4.5" />
          <path d="M2.4 2.4 6 6" />
        </>
      )}
    </g>
  );
}

function FlowCard({ brand, features, sources, uid, reduced }: { brand: string; features: InkFeatures; sources: InkSource[]; uid: string; reduced: boolean }) {
  const [side, setSide] = React.useState("" as "" | "left" | "right");
  const spots = [
    { x: 58, y: 38 },
    { x: 104, y: 22 },
    { x: 150, y: 40 },
    { x: 46, y: 92 },
    { x: 146, y: 114 },
  ];
  const nodes = sources.slice(0, spots.length).map((s, i) => ({ ...s, ...spots[i] }));
  const L1 = "M117,67 C196,67 210,100 262,100";
  const L2 = "M117,73 C186,73 206,120 262,120";
  const R1 = "M378,100 C412,100 418,86 450,86";
  const R2 = "M378,120 C412,120 418,134 450,134";
  const chip = brand.toUpperCase();
  const chipLong = chip.length * 6.7 > 58;
  const rays = uid + "rays";
  const glow = uid + "glow";
  return (
    <div className="ib-frame ib-frame-hover ib-wide">
      <Brackets />
      <div className="ib-card" style={{ padding: 0, overflow: "hidden" }}>
        <svg className="ib-diagram" viewBox="0 0 640 178" role="img" aria-label={sources.map((s) => s.name).join(", ") + " flow through " + brand + " into " + features.reports.title.toLowerCase()}>
          <defs>
            <radialGradient id={glow} cx="320" cy="110" r="190" gradientUnits="userSpaceOnUse">
              <stop offset="0" stopColor="var(--ib-raise)" stopOpacity="1" />
              <stop offset="1" stopColor="var(--ib-raise)" stopOpacity="0" />
            </radialGradient>
            <linearGradient id={rays} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--ib-line-strong)" stopOpacity=".55" />
              <stop offset="1" stopColor="var(--ib-line-strong)" stopOpacity="0" />
            </linearGradient>
          </defs>
          <rect x="0" y="0" width="640" height="178" fill={"url(#" + glow + ")"} />
          {[-62, -38, -14, 14, 38, 62].map((a, i) => (
            <path
              key={i}
              d={"M320,110 L" + (320 + Math.sin((a * Math.PI) / 180) * 260) + "," + (110 - Math.cos((a * Math.PI) / 180) * 260) + " L" + (320 + Math.sin(((a + 7) * Math.PI) / 180) * 260) + "," + (110 - Math.cos(((a + 7) * Math.PI) / 180) * 260) + "Z"}
              fill={"url(#" + rays + ")"}
              opacity=".5"
            />
          ))}

          {/* source cluster */}
          <g onMouseEnter={() => setSide("left")} onMouseLeave={() => setSide("")}>
            <rect x="20" y="8" width="170" height="130" fill="transparent" />
            {nodes.map((m, i) => (
              <line key={"l" + i} x1={m.x} y1={m.y} x2="104" y2="70" stroke="var(--ib-line-strong)" strokeDasharray="2 3" />
            ))}
            <g transform="translate(91,57)">
              <rect width="26" height="26" rx="5" className="ib-node" />
              <g transform="translate(5,5)" style={{ color: "var(--ib-ink)" }}>
                <Mark size={16} />
              </g>
            </g>
            {nodes.map((m, i) => (
              <g key={i} className="ib-av" tabIndex={0} role="img" aria-label={m.name}>
                <circle cx={m.x} cy={m.y} r="11" fill="var(--ib-raise)" stroke="var(--ib-line-strong)" />
                <text x={m.x} y={m.y + 2.6} textAnchor="middle" fontSize={m.label.length > 2 ? 6.2 : 7.5} fontWeight="600" fill="var(--ib-soft)" fontFamily="var(--ib-sans)">
                  {m.label}
                </text>
                <circle cx={m.x + 8} cy={m.y + 8} r="2.6" fill="var(--ib-accent)" stroke="var(--ib-paper)" className={reduced ? undefined : "ib-presence"} />
                <g className="ib-av-tip" transform={"translate(" + m.x + "," + (m.y - 18) + ")"}>
                  <rect x={-m.name.length * 2.45 - 6} y="-9" width={m.name.length * 4.9 + 12} height="14" rx="2" fill="var(--ib-inv)" />
                  <text x="0" y="1" textAnchor="middle" fontSize="7.5" fill="var(--ib-inv-ink)" fontFamily="var(--ib-sans)">
                    {m.name}
                  </text>
                </g>
              </g>
            ))}
          </g>

          {/* connectors */}
          {[L1, L2].map((d, i) => (
            <path key={d} d={d} className={"ib-flow" + (side === "left" ? " ib-flow-on" : "") + (i ? " ib-dash" : "")} />
          ))}
          {[R1, R2].map((d, i) => (
            <path key={d} d={d} className={"ib-flow" + (side === "right" ? " ib-flow-on" : "") + (i ? " ib-dash" : "")} />
          ))}
          {!reduced &&
            [L1, L2, R1, R2].map((d, i) => (
              <circle key={"p" + i} r="2.2" className="ib-pkt">
                <animateMotion dur={2.2 + (i % 2) * 0.6 + "s"} begin={i * 0.35 + "s"} repeatCount="indefinite" path={d} />
              </circle>
            ))}

          {/* the hub chip */}
          <g transform="translate(262,88)">
            <rect x="-4" y="-4" width="124" height="52" rx="8" fill="none" stroke="var(--ib-line)" className={reduced ? undefined : "ib-glow"} />
            <rect width="116" height="44" rx="6" className="ib-node" style={{ filter: "drop-shadow(0 6px 10px rgba(0,0,0,.25))" }} />
            <g transform="translate(13,14)" style={{ color: "var(--ib-ink)" }}>
              <Mark size={16} />
            </g>
            <text x="36" y="26" fontSize="8.5" letterSpacing="1.4" fontWeight="600" fill="var(--ib-soft)" fontFamily="var(--ib-sans)" textLength={chipLong ? 58 : undefined} lengthAdjust={chipLong ? "spacingAndGlyphs" : undefined}>
              {chip}
            </text>
            <path d="M100 18l4 4-4 4" fill="none" stroke="var(--ib-muted)" strokeWidth="1.3" />
          </g>

          {/* the report stack */}
          <g onMouseEnter={() => setSide("right")} onMouseLeave={() => setSide("")}>
            {[2, 1, 0].map((k) => (
              <g key={k} transform={"translate(" + (450 + k * 12) + "," + (40 - k * 10) + ")"} opacity={1 - k * 0.25}>
                <g className="ib-sheet">
                  <rect width="138" height="102" rx="3" fill="var(--ib-raise)" stroke="var(--ib-line-strong)" />
                  {k === 0 && (
                    <>
                      <text x="10" y="16" fontSize="7" fill="var(--ib-muted)" fontFamily="var(--ib-mono)">
                        {features.reports.label}
                      </text>
                      <rect x="10" y="24" width="64" height="5" rx="1" fill="var(--ib-ink)" opacity=".75" />
                      <rect x="10" y="33" width="92" height="3" rx="1" fill="var(--ib-line-strong)" />
                      <rect x="10" y="39" width="80" height="3" rx="1" fill="var(--ib-line-strong)" />
                      {[18, 26, 14, 30, 22, 34].map((h, j) => (
                        <rect key={j} x={12 + j * 13} y={92 - h} width="8" height={h} fill="var(--ib-accent)" opacity={0.25 + j * 0.12} />
                      ))}
                      <path d="M92 64h34M92 72h28M92 80h32" stroke="var(--ib-line-strong)" strokeWidth="2.5" />
                    </>
                  )}
                </g>
              </g>
            ))}
          </g>
        </svg>
        <div className="ib-wide-copy" style={{ padding: "0 22px 20px" }}>
          <div>
            <h3>{features.collaboration.title}</h3>
            <p>{features.collaboration.description}</p>
          </div>
          <div>
            <h3>{features.reports.title}</h3>
            <p>{features.reports.description}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function IntegrationsCard({ copy, reduced }: { copy: InkFeatures["integrations"]; reduced: boolean }) {
  const [hover, setHover] = React.useState(-1);
  const [auto, setAuto] = React.useState(0);
  React.useEffect(() => {
    if (reduced || hover >= 0) return;
    const t = setInterval(() => setAuto((a) => (a + 1) % 4), 1700);
    return () => clearInterval(t);
  }, [reduced, hover]);
  const on = hover >= 0 ? hover : reduced ? -1 : auto;
  const tiles = [
    { x: 66, y: 34 },
    { x: 66, y: 116 },
    { x: 234, y: 34 },
    { x: 234, y: 116 },
  ];
  const path = (i: number) => {
    const t = tiles[i];
    const dir = t.x < 150 ? -1 : 1;
    return "M" + (150 + dir * 17) + ",75 H" + (150 + dir * 42) + " V" + t.y + " H" + (t.x - dir * 15);
  };
  return (
    <div className="ib-frame ib-frame-hover">
      <Brackets />
      <div className="ib-card">
        <svg className="ib-diagram" viewBox="0 0 300 150" role="group" aria-label={copy.title}>
          {tiles.map((_, i) => (
            <path key={i} d={path(i)} className={"ib-flow" + (on === i ? " ib-flow-on" : "")} />
          ))}
          {!reduced && on >= 0 && (
            <circle key={on} r="2.2" className="ib-pkt">
              <animateMotion dur="1.1s" repeatCount="indefinite" path={path(on)} />
            </circle>
          )}
          <g transform="translate(133,58)">
            <rect width="34" height="34" rx="7" className="ib-node" style={{ filter: "drop-shadow(0 4px 8px rgba(0,0,0,.25))" }} />
            <g transform="translate(8,8)" style={{ color: "var(--ib-ink)" }}>
              <Mark size={18} />
            </g>
          </g>
          {tiles.map((t, i) => (
            <g
              key={i}
              className={"ib-tool" + (on === i ? " ib-tool-on" : "")}
              tabIndex={0}
              role="img"
              aria-label={copy.tools[i] ?? "Tool"}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(-1)}
              onFocus={() => setHover(i)}
              onBlur={() => setHover(-1)}
            >
              <rect x={t.x - 15} y={t.y - 15} width="30" height="30" rx="6" className="ib-node" />
              <g transform={"translate(" + t.x + "," + t.y + ")"} style={{ color: "var(--ib-ink)" }}>
                <ToolGlyph index={i} />
              </g>
              <text x={t.x} y={t.y + (t.y < 75 ? -21 : 28)} textAnchor="middle" fontSize="8" fill="var(--ib-muted)" fontFamily="var(--ib-sans)" opacity={on === i ? 1 : 0} style={{ transition: "opacity .25s" }}>
                {copy.tools[i] ?? ""}
              </text>
            </g>
          ))}
          <text x="150" y="112" textAnchor="middle" fontSize="7" fill="var(--ib-faint)" fontFamily="var(--ib-mono)">
            {on >= 0 ? copy.verb + " · " + (copy.tools[on] ?? "").toLowerCase() : copy.summary}
          </text>
        </svg>
        <div style={{ marginTop: "auto" }}>
          <h3>{copy.title}</h3>
          <p>{copy.description}</p>
        </div>
      </div>
    </div>
  );
}

function InsightsCard({ copy, uid, reduced }: { copy: InkFeatures["insights"]; uid: string; reduced: boolean }) {
  const [ref, inView] = useInView(0.3);
  const [hover, setHover] = React.useState(-1);
  const W = 300;
  const H = 130;
  const vals = copy.values.length > 1 ? copy.values : [1, 2];
  const { line, area, points } = chartPaths(vals, W, H, 14);
  const split = copy.forecastFrom === undefined ? -1 : clamp(copy.forecastFrom, 1, vals.length - 1);
  const fill = uid + "area";
  const last = points[points.length - 1];
  const i = hover >= 0 ? hover : points.length - 1;
  const p = points[i];
  const tip = copy.pointLabel + " " + (i + 1) + ": " + vals[i] + copy.unit;
  // monospace at 7.5px: about 4.6px per character
  const tipW = Math.ceil(tip.length * 4.6 + 12);
  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setHover(nearestIndex(points.map((q) => q[0]), ((e.clientX - r.left) / r.width) * W));
  };
  return (
    <div className="ib-frame ib-frame-hover" ref={ref as never} data-in={inView}>
      <Brackets />
      <div className="ib-card">
        <svg className="ib-diagram ib-chart" viewBox={"0 0 " + W + " " + (H + 6)} onPointerMove={onMove} onPointerLeave={() => setHover(-1)} role="img" aria-label={copy.ariaLabel}>
          <defs>
            <linearGradient id={fill} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--ib-accent)" stopOpacity=".22" />
              <stop offset="1" stopColor="var(--ib-accent)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((g) => (
            <line key={g} x1="14" x2={W - 14} y1={H * g} y2={H * g} stroke="var(--ib-line)" />
          ))}
          <path d={area} fill={"url(#" + fill + ")"} />
          <path d={line} fill="none" stroke="var(--ib-accent)" strokeWidth="1.6" pathLength={1} className="ib-line-draw" />
          {split > 0 && (
            <>
              <line x1={points[split][0]} x2={points[split][0]} y1="10" y2={H - 14} stroke="var(--ib-line-strong)" strokeDasharray="2 3" />
              <text x={points[split][0] - 4} y={H - 18} textAnchor="end" fontSize="7" fill="var(--ib-faint)" fontFamily="var(--ib-mono)">
                FORECAST
              </text>
            </>
          )}
          {hover >= 0 && <line x1={p[0]} x2={p[0]} y1="8" y2={H - 14} stroke="var(--ib-ink)" strokeOpacity=".35" />}
          {!reduced && hover < 0 && <circle cx={last[0]} cy={last[1]} r="7" fill="var(--ib-accent)" opacity=".2" className="ib-glow" />}
          <circle cx={p[0]} cy={p[1]} r="3.2" fill="var(--ib-raise)" stroke="var(--ib-accent)" strokeWidth="1.5" />
          <g transform={"translate(" + clamp(p[0], tipW / 2 + 4, W - tipW / 2 - 4) + "," + (p[1] < 34 ? p[1] + 22 : p[1] - 12) + ")"}>
            <rect x={-tipW / 2} y="-11" width={tipW} height="15" rx="2" fill="var(--ib-inv)" />
            <text x="0" y="-1" textAnchor="middle" fontSize="7.5" fill="var(--ib-inv-ink)" fontFamily="var(--ib-mono)">
              {tip}
            </text>
          </g>
        </svg>
        <div style={{ marginTop: "auto" }}>
          <h3>{copy.title}</h3>
          <p>{copy.description}</p>
        </div>
      </div>
    </div>
  );
}

const IB_CSS = `
.ib-root{--ib-page:#efefef;--ib-hatch:rgba(0,0,0,.06);--ib-paper:#fbfbfb;--ib-card:#f4f4f4;--ib-raise:#ffffff;--ib-ink:#151515;--ib-soft:#3d3d3d;--ib-muted:#7b7b7b;--ib-faint:#a8a8a8;--ib-line:#e2e2e2;--ib-line-strong:#cfcfcf;--ib-bracket:#c9c9c9;--ib-inv:#161616;--ib-inv-ink:#f5f5f5;--ib-accent:#2f6fe0;--ib-shadow:0 1px 2px rgba(0,0,0,.05),0 8px 24px -12px rgba(0,0,0,.12);--ib-sans:"IBM Plex Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--ib-mono:"JetBrains Mono Variable","JetBrains Mono",ui-monospace,Consolas,monospace;position:relative;width:100%;box-sizing:border-box;background-color:var(--ib-page);background-image:repeating-linear-gradient(135deg,var(--ib-hatch) 0 1px,transparent 1px 10px);color:var(--ib-ink);font-family:var(--ib-sans);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;padding:28px clamp(10px,2.4vw,28px);transition:background-color .45s ease,color .45s ease}
.ib-root[data-theme="dark"]{--ib-page:#0b0d10;--ib-hatch:rgba(255,255,255,.03);--ib-paper:#0f1216;--ib-card:#14171e;--ib-raise:#1a1e26;--ib-ink:#e8ebf0;--ib-soft:#c3c9d4;--ib-muted:#8a93a3;--ib-faint:#5f6878;--ib-line:#20252f;--ib-line-strong:#2e3542;--ib-bracket:#3a4252;--ib-inv:#e8ebf0;--ib-inv-ink:#0f1216;--ib-accent:#4c8dff;--ib-shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px -14px rgba(0,0,0,.7)}
.ib-root :where(*){box-sizing:border-box}
.ib-root :focus-visible{outline:2px solid var(--ib-accent);outline-offset:2px}
.ib-root :where(svg){display:block;max-width:none;flex:none}
.ib-root :where(h2,h3,p){margin:0;padding:0;font-size:inherit;font-weight:inherit}
.ib-shell{width:100%;max-width:1180px;margin:0 auto;container-type:inline-size}
.ib-sec{position:relative;background:var(--ib-paper);border:1px solid var(--ib-line);padding:clamp(36px,6cqw,72px) clamp(16px,4cqw,48px);transition:background-color .45s,border-color .45s}
.ib-reveal{opacity:0;transform:translateY(18px);transition:opacity .8s cubic-bezier(.2,.7,.2,1),transform .8s cubic-bezier(.2,.7,.2,1)}
.ib-reveal[data-in="true"]{opacity:1;transform:none}
.ib-head{display:flex;flex-direction:column;align-items:center;text-align:center;gap:14px;margin-bottom:clamp(28px,4.5cqw,52px)}
.ib-tag{display:inline-block;padding:4px 10px;font-size:11.5px;letter-spacing:.02em;color:var(--ib-soft);background:var(--ib-card);border:1px solid var(--ib-line)}
.ib-h2{font-size:clamp(28px,4.4cqw,44px);line-height:1.08;letter-spacing:-.025em;font-weight:600}
.ib-h2>span{display:block}
.ib-muted{color:var(--ib-faint)}
.ib-frame{position:relative}
.ib-c{position:absolute;width:12px;height:12px;border-color:var(--ib-bracket);border-style:solid;border-width:0;pointer-events:none;transition:border-color .3s,transform .35s cubic-bezier(.2,.8,.2,1)}
.ib-c-tl{top:-6px;left:-6px;border-top-width:1.5px;border-left-width:1.5px}
.ib-c-tr{top:-6px;right:-6px;border-top-width:1.5px;border-right-width:1.5px}
.ib-c-bl{bottom:-6px;left:-6px;border-bottom-width:1.5px;border-left-width:1.5px}
.ib-c-br{bottom:-6px;right:-6px;border-bottom-width:1.5px;border-right-width:1.5px}
.ib-frame-hover:hover>.ib-c{border-color:var(--ib-accent)}
.ib-frame-hover:hover>.ib-c-tl{transform:translate(-3px,-3px)}
.ib-frame-hover:hover>.ib-c-tr{transform:translate(3px,-3px)}
.ib-frame-hover:hover>.ib-c-bl{transform:translate(-3px,3px)}
.ib-frame-hover:hover>.ib-c-br{transform:translate(3px,3px)}
.ib-bento{display:grid;grid-template-columns:minmax(0,1fr);gap:clamp(22px,3cqw,34px)}
@container (min-width:720px){.ib-bento{grid-template-columns:repeat(2,minmax(0,1fr))}.ib-wide{grid-column:1 / -1;width:min(100%,820px);justify-self:center}}
.ib-card{background:linear-gradient(180deg,var(--ib-raise),var(--ib-card));border:1px solid var(--ib-line);padding:clamp(14px,2cqw,22px);display:flex;flex-direction:column;gap:14px;transition:border-color .3s,box-shadow .35s,background-color .45s}
.ib-card:hover{border-color:var(--ib-line-strong);box-shadow:var(--ib-shadow)}
.ib-card h3{font-size:14px;font-weight:600;letter-spacing:-.005em}
.ib-card p{font-size:13px;line-height:1.55;color:var(--ib-muted);max-width:44ch}
.ib-diagram{width:100%;height:auto;overflow:visible}
.ib-wide-copy{display:grid;grid-template-columns:1fr;gap:16px}
@container (min-width:560px){.ib-wide-copy{grid-template-columns:1fr 1fr}.ib-wide-copy>div:last-child{justify-self:end;text-align:left}}
.ib-flow{stroke:var(--ib-line-strong);fill:none;stroke-width:1.2;transition:stroke .3s}
.ib-flow-on{stroke:var(--ib-accent)}
.ib-dash{stroke-dasharray:3 4;animation:ib-dash 1.2s linear infinite}
.ib-pkt{fill:var(--ib-accent)}
.ib-node{fill:var(--ib-raise);stroke:var(--ib-line-strong);transition:stroke .3s,transform .3s}
.ib-av{cursor:pointer;transition:transform .35s cubic-bezier(.2,.8,.2,1);transform-box:fill-box;transform-origin:center}
.ib-av:hover,.ib-av:focus-visible{transform:scale(1.18)}
.ib-av-tip{opacity:0;transition:opacity .2s;pointer-events:none}
.ib-av:hover .ib-av-tip,.ib-av:focus .ib-av-tip{opacity:1}
.ib-presence{animation:ib-pulse 2.2s ease-in-out infinite;transform-box:fill-box;transform-origin:center}
.ib-sheet{transition:transform .7s cubic-bezier(.2,.8,.2,1),opacity .7s}
.ib-tool{cursor:pointer;transition:transform .3s cubic-bezier(.2,.8,.2,1);transform-box:fill-box;transform-origin:center}
.ib-tool:hover,.ib-tool-on{transform:translateY(-2px)}
.ib-tool rect{transition:stroke .3s}
.ib-tool-on rect.ib-node{stroke:var(--ib-accent)}
.ib-chart{cursor:crosshair}
.ib-line-draw{stroke-dasharray:1;stroke-dashoffset:1;transition:stroke-dashoffset 1.8s cubic-bezier(.4,.1,.2,1)}
[data-in="true"] .ib-line-draw{stroke-dashoffset:0}
.ib-glow{animation:ib-pulse 2s ease-in-out infinite;transform-box:fill-box;transform-origin:center}
@keyframes ib-dash{to{stroke-dashoffset:-14}}
@keyframes ib-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(1.35)}}
.ib-bento>.ib-frame{display:flex;flex-direction:column}
.ib-bento>.ib-frame>.ib-card{flex:1}
@media (prefers-reduced-motion:reduce){
.ib-reveal{opacity:1;transform:none;transition:none}
.ib-dash,.ib-presence,.ib-glow{animation:none}
.ib-line-draw{transition:none;stroke-dashoffset:0}
}
`;
