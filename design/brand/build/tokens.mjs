// ExploitX design tokens: the single source for design/brand/tokens.json and tokens.css.
// The desktop app imports tokens.css (src/styles/index.css); the website (RChefo/ExploitX-Web) keeps a copy in src/brand/.

export const tokens = {
  brand: {
    ultraviolet: {
      100: "#E6E2FF",
      200: "#CFC8FF",
      300: "#B4A9FF", // soft foreground on dark (selected text, soft badges)
      400: "#9A8CFF", // links and hover text on dark
      500: "#7C6AFF", // THE brand colour: symbol, accents on dark, focus
      600: "#6A57F5", // solid fills with white text (4.9:1)
      700: "#5240E0", // text and marks on light backgrounds
      800: "#3D2FB0",
      900: "#241B6E",
    },
    bone: "#F2F4F7", // the symbol's target chevron and the wordmark on dark
    ink: "#0B0D12", // the wordmark and marks on light
    signal: "#C8F03C", // accent: used sparingly (a live signal, one highlight per view); never for status
    gradient: {
      dusk: "linear-gradient(135deg, #7C6AFF 0%, #3D2FB0 100%)",
      glow: "radial-gradient(closest-side, rgba(124, 106, 255, 0.32), rgba(124, 106, 255, 0))",
    },
  },
  neutral: {
    // dark-first surfaces, from deepest to most raised; separation by fill and shadow, never by stroke
    background: "#0A0B10",
    backgroundSecondary: "#0F1016", // sidebar, recessed areas
    backgroundTertiary: "#12141B",
    surface: "#14161E", // cards, panels
    surfaceRaised: "#1B1E28",
    surfaceTertiary: "#222533",
    surfaceHover: "#1D202B",
    overlay: "#191B25", // menus, popovers, dialogs
    field: "#1C1F2A",
    control: "#1E2130",
    controlHover: "#262A3A",
    separator: "rgba(255, 255, 255, 0.06)", // row dividers only
    border: "transparent", // no decorative strokes (focus and invalid states keep theirs)
    text: "#ECEEF4",
    textSecondary: "#B3B9C7",
    textMuted: "#8B92A5",
    textFaint: "#747B8E", // placeholders, disabled
    light: {
      background: "#F5F6F8",
      surface: "#FFFFFF",
      text: "#0B0D12",
      textMuted: "#565D6E",
    },
  },
  semantic: {
    success: "#3CC88F",
    warning: "#E8A93A",
    error: "#E5484D",
    info: "#4C9BFF",
  },
  severity: {
    // always shown with its name (and an icon or position), never by colour alone
    critical: "#E5484D",
    high: "#F2803A",
    medium: "#F2C94C",
    low: "#4C9BFF",
    info: "#9AA3B5",
  },
  dataviz: {
    // categorical: threat categories, entity types, timeline sources, chart series (in this order)
    categorical: ["#7C6AFF", "#38C9B4", "#F2B33D", "#F0689C", "#4FA3FF", "#A6D94A", "#C58BFF", "#8E9AB0"],
    // sequential: coverage and density (ATT&CK coverage, heat maps), low to high
    sequential: ["#1E2130", "#2E2A5C", "#463A9E", "#6553E0", "#8C7DFF", "#C3BAFF"],
    grid: "rgba(255, 255, 255, 0.06)",
    axis: "#8B92A5",
    edge: "#3B4054", // graph relationships
    edgeActive: "#B4A9FF",
  },
  typography: {
    display: '"Archivo Variable", "Archivo", "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif',
    sans: '"IBM Plex Sans", ui-sans-serif, system-ui, sans-serif',
    mono: '"JetBrains Mono Variable", ui-monospace, "Cascadia Code", Consolas, monospace',
  },
  radius: { xs: "4px", sm: "6px", md: "8px", lg: "12px", xl: "16px", full: "999px" },
  space: { 1: "4px", 2: "8px", 3: "12px", 4: "16px", 5: "20px", 6: "24px", 8: "32px", 10: "40px", 12: "48px" },
  shadow: {
    surface: "0 1px 2px 0 rgba(0, 0, 0, 0.35), 0 10px 28px -14px rgba(0, 0, 0, 0.6)",
    overlay: "0 2px 6px 0 rgba(0, 0, 0, 0.45), 0 22px 56px -12px rgba(0, 0, 0, 0.8)",
  },
  motion: { fast: "120ms", base: "200ms", slow: "320ms", ease: "cubic-bezier(0.25, 1, 0.5, 1)" },
};

/** CSS custom properties, prefixed --ex-. */
export function tokensCss() {
  const t = tokens;
  const lines = [];
  const v = (name, value) => lines.push(`  --ex-${name}: ${value};`);
  for (const [k, c] of Object.entries(t.brand.ultraviolet)) v(`uv-${k}`, c);
  v("bone", t.brand.bone);
  v("ink", t.brand.ink);
  v("signal", t.brand.signal);
  v("gradient-dusk", t.brand.gradient.dusk);
  v("gradient-glow", t.brand.gradient.glow);
  const kebab = (s) => s.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase());
  for (const [k, c] of Object.entries(t.neutral)) if (typeof c === "string") v(kebab(k), c);
  for (const [k, c] of Object.entries(t.neutral.light)) v(`light-${kebab(k)}`, c);
  for (const [k, c] of Object.entries(t.semantic)) v(k, c);
  for (const [k, c] of Object.entries(t.severity)) v(`sev-${k}`, c);
  t.dataviz.categorical.forEach((c, i) => v(`viz-${i + 1}`, c));
  t.dataviz.sequential.forEach((c, i) => v(`viz-seq-${i + 1}`, c));
  v("viz-grid", t.dataviz.grid);
  v("viz-axis", t.dataviz.axis);
  v("viz-edge", t.dataviz.edge);
  v("viz-edge-active", t.dataviz.edgeActive);
  v("font-display", t.typography.display);
  v("font-sans", t.typography.sans);
  v("font-mono", t.typography.mono);
  for (const [k, c] of Object.entries(t.radius)) v(`radius-${k}`, c);
  for (const [k, c] of Object.entries(t.space)) v(`space-${k}`, c);
  for (const [k, c] of Object.entries(t.shadow)) v(`shadow-${k}`, c);
  for (const [k, c] of Object.entries(t.motion)) v(`motion-${k}`, c);
  return `/* ExploitX design tokens. Generated by design/brand/build/build.mjs from tokens.mjs: do not edit by hand. */\n:root {\n${lines.join("\n")}\n}\n`;
}
