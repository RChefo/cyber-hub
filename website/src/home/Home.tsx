import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Footer, Nav } from "../components/Chrome";
import InkOrbitFeatures from "@/components/ui/ink-orbit-features";
import OrbitImages from "@/components/ui/OrbitImages";
import { facts, modules, principles, screens, SHOT, showcase } from "../content";
import { DESKTOP, gsap, MOTION_OK, useGSAP, useReveal } from "../lib/motion";
import { CategoryTag, InlineText, Skeleton } from "../components/release";
import { useReleases } from "../lib/releaseStore";
import { changelogOf, formatDate, highlights } from "../lib/releases";

function Shot({ src, alt, eager, className = "", ...rest }: { src: string; alt: string; eager?: boolean; className?: string } & Record<`data-${string}`, string>) {
  return (
    <div className={`frame ${className}`} {...rest}>
      <img
        src={src}
        alt={alt}
        width={SHOT.width}
        height={SHOT.height}
        loading={eager ? "eager" : "lazy"}
        decoding="async"
        {...(eager ? { fetchPriority: "high" as const } : {})}
      />
    </div>
  );
}

/** A close-up of part of a real screenshot (no retouching): `zoom` times the frame width, centred on
 *  the point (cx, cy) given as fractions of the screenshot. */
function Crop({ src, alt, cx, cy, zoom, aspect = 4 / 3 }: { src: string; alt: string; cx: number; cy: number; zoom: number; aspect?: number }) {
  const ratio = SHOT.height / SHOT.width;
  const left = 0.5 - cx * zoom;
  const top = (0.5 / aspect - cy * zoom * ratio) * aspect;
  return (
    <div className="frame relative" style={{ aspectRatio: String(aspect) }}>
      <img
        src={src}
        alt={alt}
        width={SHOT.width}
        height={SHOT.height}
        loading="lazy"
        decoding="async"
        className="absolute max-w-none"
        style={{ width: `${zoom * 100}%`, left: `${left * 100}%`, top: `${top * 100}%` }}
      />
    </div>
  );
}

/* ───────────── hero: the one orchestrated moment ───────────── */

function Hero() {
  const root = useRef<HTMLElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const tl = gsap.timeline({ defaults: { ease: "power3.out" } });
        tl.from("[data-hero-line]", { autoAlpha: 0, y: 28, duration: 0.9, stagger: 0.09 })
          .from("[data-hero-cta]", { autoAlpha: 0, y: 14, duration: 0.6, stagger: 0.06 }, "-=0.5")
          .from("[data-hero-back]", { autoAlpha: 0, y: 40, duration: 1.1 }, "-=0.55")
          // the signature: a scan line sweeps across and uncovers the investigation graph
          .fromTo("[data-hero-front]", { clipPath: "inset(0 100% 0 0 round 14px)" }, { clipPath: "inset(0 0% 0 0 round 14px)", duration: 1.35, ease: "power2.inOut" }, "-=0.75")
          .fromTo("[data-hero-scan]", { left: "0%", autoAlpha: 1 }, { left: "100%", duration: 1.35, ease: "power2.inOut" }, "<")
          .to("[data-hero-scan]", { autoAlpha: 0, duration: 0.3 })
          .from("[data-hero-glow]", { autoAlpha: 0, duration: 1.6, ease: "none" }, 0.2);
      });
      mm.add(DESKTOP, () => {
        // gentle depth while scrolling away from the hero
        gsap.to("[data-hero-back]", { yPercent: -6, ease: "none", scrollTrigger: { trigger: root.current, start: "top top", end: "bottom top", scrub: true } });
        gsap.to("[data-hero-front]", { yPercent: 4, ease: "none", scrollTrigger: { trigger: root.current, start: "top top", end: "bottom top", scrub: true } });
        gsap.to("[data-hero-glow]", { xPercent: 6, yPercent: -4, duration: 9, ease: "sine.inOut", yoyo: true, repeat: -1 });
      });
      return () => mm.revert();
    },
    { scope: root },
  );

  return (
    <section ref={root} className="relative overflow-hidden pt-28 pb-16 md:pt-32 md:pb-20">
      <div data-hero-glow aria-hidden="true" className="pointer-events-none absolute top-[38%] left-1/2 h-[42rem] w-[70rem] -translate-x-1/2 rounded-full bg-[radial-gradient(closest-side,rgb(76_141_255/0.22),rgb(76_141_255/0.05)_55%,transparent)] blur-2xl" />
      <div className="wrap relative">
        <h1 className="max-w-[14ch] text-[clamp(2.75rem,6.4vw,5rem)] leading-[0.98] font-semibold tracking-[-0.035em]">
          <span data-hero-line className="block">Your Cybersecurity</span>
          <span data-hero-line className="block text-accent-soft">Workspace.</span>
        </h1>
        <p data-hero-line className="mt-5 max-w-[46ch] text-[1.1rem] leading-relaxed text-muted md:text-[1.2rem]">
          One powerful workspace to explore, investigate, analyze, and manage your cybersecurity workflow.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a data-hero-cta href="/download/" className="btn btn-primary">
            Download Cyber Hub
          </a>
          <a data-hero-cta href="#features" className="btn btn-quiet">
            Explore features
          </a>
        </div>
        <p data-hero-cta className="mt-4 text-[0.85rem] text-faint">
          Windows 10/11 and Linux, x64. Local-first, no account.
        </p>

        <div className="relative mt-12 md:mt-14">
          <Shot src={screens.dashboard} alt="Cyber Hub dashboard" eager className="hidden w-[78%] opacity-60 md:block" data-hero-back="" />
          <div data-hero-front className="relative md:absolute md:top-[18%] md:right-0 md:w-[74%]">
            <Shot src={screens.osintGraph} alt="Cyber Hub OSINT workspace: link-analysis graph of a domain, its addresses, network blocks, autonomous system and organizations" eager />
            <span data-hero-scan aria-hidden="true" className="pointer-events-none absolute inset-y-0 w-px bg-accent-soft opacity-0 shadow-[0_0_24px_4px_rgb(76_141_255/0.55)]" />
          </div>
          <div className="hidden md:block md:h-[6vw] md:max-h-20" aria-hidden="true" />
        </div>
      </div>
    </section>
  );
}

/* ───────────── verified numbers ───────────── */

function Facts() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        for (const el of gsap.utils.toArray<HTMLElement>("[data-count]")) {
          const target = Number(el.dataset.count);
          const n = { v: 0 };
          gsap.to(n, {
            v: target,
            duration: 1.2,
            ease: "power2.out",
            snap: { v: 1 },
            onUpdate: () => (el.textContent = String(n.v)),
            scrollTrigger: { trigger: el, start: "top 88%", once: true },
          });
        }
      });
      return () => mm.revert();
    },
    { scope: root },
  );
  return (
    <section ref={root} aria-label="Cyber Hub in numbers" className="wrap">
      <div className="rule" />
      <dl data-reveal-group className="grid grid-cols-2 gap-x-6 gap-y-8 py-10 lg:grid-cols-4">
        {facts.map((f) => (
          <div data-reveal key={f.label}>
            <dt className="sr-only">{f.label}</dt>
            <dd>
              <span data-count={f.value} className="block text-[2.6rem] leading-none font-semibold tracking-[-0.03em] text-ink tabular-nums">
                {f.value}
              </span>
              <span className="mt-2 block max-w-[22ch] text-[0.92rem] leading-snug text-muted" aria-hidden="true">
                {f.label}
              </span>
            </dd>
          </div>
        ))}
      </dl>
      <div className="rule" />
    </section>
  );
}

/* ───────────── capabilities: two spreads, then the index ───────────── */

function Spread({ reverse, title, body, children, shot, alt, id, visual }: { reverse?: boolean; title: string; body: React.ReactNode; children?: React.ReactNode; shot: string; alt: string; id?: string; visual?: React.ReactNode }) {
  const root = useRef<HTMLDivElement>(null);
  useReveal(root);
  return (
    <div ref={root} id={id} data-reveal-group className={`grid grid-cols-[minmax(0,1fr)] items-center gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16 ${reverse ? "lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]" : ""}`}>
      <div className={reverse ? "lg:order-2" : ""}>
        <h3 data-reveal className="text-[clamp(1.75rem,3.2vw,2.5rem)] leading-[1.08] font-semibold tracking-[-0.025em]">
          {title}
        </h3>
        <div data-reveal className="mt-5 space-y-4 text-[1.02rem] leading-relaxed text-muted">
          {body}
        </div>
        {children}
      </div>
      <div data-reveal className={reverse ? "lg:order-1" : ""}>
        {visual ?? <Shot src={shot} alt={alt} />}
      </div>
    </div>
  );
}

function Capabilities() {
  const index = useRef<HTMLDivElement>(null);
  useReveal(index);
  return (
    <section id="features" className="wrap pt-28 md:pt-36" aria-labelledby="features-title">
      <h2 id="features-title" className="max-w-[20ch] text-[clamp(2rem,4.4vw,3.4rem)] leading-[1.04] font-semibold tracking-[-0.03em]">
        Everything an engagement needs, in one desktop app.
      </h2>
      <p className="mt-5 max-w-[56ch] text-[1.05rem] leading-relaxed text-muted">
        Cyber Hub puts the tools, the research and the record of what you found side by side, on your machine.
      </p>

      <div className="mt-20 space-y-28 md:space-y-36">
        <Spread
          title="Investigations that keep their evidence."
          shot={screens.osintGraph}
          alt="Link-analysis graph of an OSINT investigation"
          visual={<Crop src={screens.osintGraph} alt="Close-up of the link-analysis graph: example.com, its IP addresses, network blocks, AS13335 and the organizations behind them" cx={0.585} cy={0.7} zoom={2} />}
          body={
            <>
              <p>The OSINT Workspace maps a target as a graph you can lay out, filter, group and search, with path finding and full-screen analysis.</p>
              <p>Collect from DNS, Team Cymru ASN, RDAP, Certificate Transparency, GitHub, threat intelligence and NVD, review the results, then import what belongs. Every entity and relationship keeps its evidence and a confidence with reasons.</p>
              <p>Saved graphs have version history with compare and non-destructive restore, and export to JSON, GraphML, CSV, PNG, SVG and Markdown reports.</p>
            </>
          }
        />
        <Spread
          reverse
          title="Commands you can read before they run."
          shot={screens.commandCenter}
          alt="Command Center with the Nmap builder and its generated command"
          body={
            <>
              <p>Builders for Nmap, FFUF, Gobuster, Nuclei, SQLmap, Subfinder and HTTPX turn options into structured, validated arguments, next to 49 OS-aware templates with explanations.</p>
              <p>Copy a command, save it with placeholders, or run it inside a project: the targets are checked against the authorized scope and you confirm the exact program and arguments first.</p>
            </>
          }
        >
          <pre data-reveal className="mt-7 overflow-x-auto rounded-[10px] bg-raised px-4 py-3.5 font-mono text-[0.88rem] text-ink" aria-label="Example generated command">
            <code>
              <span className="text-faint select-none">$ </span>nmap -sV --open -T3 example.com 93.184.215.14
            </code>
          </pre>
        </Spread>
      </div>

      <div ref={index} data-reveal-group className="mt-28 md:mt-36">
        <h3 data-reveal className="text-[1.35rem] font-semibold tracking-tight">
          And the rest of the bench
        </h3>
        <ul className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-x-14 md:grid-cols-2">
          {modules.map((m) => (
            <li data-reveal key={m.title} className="border-t border-line py-6">
              <h4 className="text-[1.05rem] font-medium text-ink">{m.title}</h4>
              <p className="mt-2 text-[0.96rem] leading-relaxed text-muted">{m.body}</p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ───────────── how it fits together (InkOrbitFeatures, real content only) ───────────── */

function FitsTogether() {
  return (
    <section className="wrap pt-28 md:pt-36" aria-label="How Cyber Hub fits together">
      <InkOrbitFeatures
        theme="dark"
        brand="Cyber Hub"
        className="ch-ink"
        tag="How it fits together"
        title={"Evidence in,\n*reports out.*"}
        sources={[
          { label: "DNS", name: "DNS (system resolver)" },
          { label: "RD", name: "RDAP registration data" },
          { label: "CT", name: "Certificate Transparency" },
          { label: "AS", name: "Team Cymru ASN" },
          { label: "NVD", name: "NIST NVD" },
        ]}
        collaboration={{
          title: "Collected with its evidence",
          description: "Results from DNS, RDAP, Certificate Transparency, ASN data and NVD arrive for review first; every entity you import keeps the evidence it came from.",
        }}
        reports={{
          title: "Reports you can hand over",
          description: "Projects and investigations export Markdown reports built from your own findings, evidence and decisions.",
          label: "REPORT.md",
        }}
        integrations={{
          title: "Seven intelligence sources, one lookup",
          description: "VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan, each optional, queried only when you press Look up.",
          tools: ["VirusTotal", "AbuseIPDB", "OTX", "Shodan"],
          verb: "lookup",
          summary: "7 sources",
        }}
        insights={{
          title: "Activity at a glance",
          description: "The dashboard charts what happened on this workstation over 7, 30 or 90 days, from local data only. Sample values shown.",
          values: [3, 5, 4, 8, 6, 9, 7, 11, 10, 13, 12, 15],
          pointLabel: "day",
          unit: " events",
          ariaLabel: "Illustration of the dashboard activity chart with sample values",
        }}
      />
    </section>
  );
}

/* ───────────── showcase ───────────── */

function Showcase() {
  const [active, setActive] = useState<string>(showcase[0].id);
  const stage = useRef<HTMLDivElement>(null);
  const { contextSafe } = useGSAP({ scope: stage });
  const select = contextSafe((id: string) => {
    if (id === active) return;
    setActive(id);
    if (window.matchMedia(MOTION_OK).matches) gsap.fromTo("[data-stage-img]", { autoAlpha: 0.35, scale: 0.985 }, { autoAlpha: 1, scale: 1, duration: 0.55, ease: "power2.out" });
  });
  const current = showcase.find((s) => s.id === active)!;
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const n = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!n) return;
    e.preventDefault();
    const next = showcase[(i + n + showcase.length) % showcase.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };
  return (
    <section className="pt-28 md:pt-36" aria-labelledby="showcase-title">
      <div className="wrap">
        <h2 id="showcase-title" className="text-[clamp(1.75rem,3.4vw,2.6rem)] leading-tight font-semibold tracking-[-0.025em]">
          See the real thing.
        </h2>
        <p className="mt-3 max-w-[60ch] text-muted">Screenshots of Cyber Hub running on Windows 11, with demo data.</p>
        <div role="tablist" aria-label="Screens" className="mt-8 flex gap-1 overflow-x-auto pb-2 [scrollbar-width:none]">
          {showcase.map((s, i) => (
            <button
              key={s.id}
              id={`tab-${s.id}`}
              role="tab"
              type="button"
              aria-selected={s.id === active}
              aria-controls="showcase-panel"
              tabIndex={s.id === active ? 0 : -1}
              onKeyDown={(e) => onKey(e, i)}
              onClick={() => select(s.id)}
              className={`shrink-0 rounded-lg px-3.5 py-2 text-[0.9rem] transition-colors ${s.id === active ? "bg-white/[0.08] text-ink" : "text-muted hover:text-ink"}`}
            >
              {s.label}
            </button>
          ))}
        </div>
        <div ref={stage} id="showcase-panel" role="tabpanel" aria-labelledby={`tab-${active}`} className="mt-6">
          <div data-stage-img>
            <Shot src={current.src} alt={current.alt} />
          </div>
        </div>
      </div>
    </section>
  );
}

/* ───────────── security model ───────────── */

function Principles() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  return (
    <section ref={root} id="security" className="wrap pt-28 md:pt-40" aria-labelledby="security-title">
      <div data-reveal-group className="grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-20">
        <div className="lg:sticky lg:top-28 lg:self-start">
          <h2 data-reveal id="security-title" className="text-[clamp(2rem,4vw,3.1rem)] leading-[1.04] font-semibold tracking-[-0.03em]">
            A workspace that asks before it acts.
          </h2>
          <p data-reveal className="mt-5 max-w-[42ch] text-[1.02rem] leading-relaxed text-muted">
            Cyber Hub launches real security software. Its safeguards are part of how it works, not settings you have to find.
          </p>
        </div>
        <ul>
          {principles.map((p) => (
            <li data-reveal key={p.title} className="border-t border-line py-7 first:border-t-0 first:pt-0">
              <h3 className="text-[1.15rem] font-medium text-ink">{p.title}</h3>
              <p className="mt-2 max-w-[58ch] leading-relaxed text-muted">{p.body}</p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ───────────── platforms ───────────── */

function Platforms() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  return (
    <section ref={root} id="platforms" className="wrap pt-28 md:pt-36" aria-labelledby="platforms-title">
      <h2 id="platforms-title" className="text-[clamp(1.75rem,3.4vw,2.6rem)] leading-tight font-semibold tracking-[-0.025em]">
        Built for Windows and Linux.
      </h2>
      <div data-reveal-group className="mt-10 grid grid-cols-[minmax(0,1fr)] gap-4 md:grid-cols-2">
        <div data-reveal className="rounded-[14px] bg-surface p-7">
          <h3 className="text-[1.2rem] font-medium">Windows 10 and 11</h3>
          <p className="mt-1 text-[0.9rem] text-faint">x64</p>
          <p className="mt-4 leading-relaxed text-muted">Installer or MSI package. Uses the WebView2 runtime that ships with Windows. Credentials stay in Windows Credential Manager; tool runs are contained in Job Objects.</p>
        </div>
        <div data-reveal className="rounded-[14px] bg-surface p-7">
          <h3 className="text-[1.2rem] font-medium">Linux</h3>
          <p className="mt-1 text-[0.9rem] text-faint">x64</p>
          <p className="mt-4 leading-relaxed text-muted">AppImage, .deb and .rpm packages, on WebKitGTK 4.1. Tested on Debian 12 and Ubuntu 24.04. Credentials stay in the Secret Service (for example GNOME Keyring).</p>
        </div>
      </div>
      <p className="mt-5 text-[0.9rem] text-faint">macOS is not supported.</p>
    </section>
  );
}

/* ───────────── changelog preview ───────────── */

function ChangelogPreview() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  const state = useReleases();
  const latest = state.kind === "ready" ? state.latest : null;
  const log = latest ? changelogOf(latest) : null;
  const items = log ? highlights(log, 5) : [];
  return (
    <section ref={root} id="changelog" className="wrap pt-28 md:pt-36" aria-labelledby="changelog-title">
      <div data-reveal-group className="grid grid-cols-[minmax(0,1fr)] gap-10 lg:grid-cols-[minmax(0,4fr)_minmax(0,7fr)] lg:gap-16">
        <div>
          <h2 data-reveal id="changelog-title" className="text-[clamp(1.75rem,3.4vw,2.6rem)] leading-tight font-semibold tracking-[-0.025em]">
            What's new
          </h2>
          {latest ? (
            <div data-reveal className="mt-5">
              <div className="text-[2.2rem] leading-none font-semibold tracking-[-0.03em]">{latest.version}</div>
              <div className="mt-2 text-[0.9rem] text-faint">Released {formatDate(latest.publishedAt)}</div>
              {log?.summary && (
                <p className="mt-4 max-w-[40ch] leading-relaxed text-muted">
                  <InlineText v={log.summary} />
                </p>
              )}
            </div>
          ) : state.kind === "loading" ? (
            <div data-reveal className="mt-5 space-y-2">
              <Skeleton className="h-9 w-24" />
              <Skeleton className="h-4 w-40" />
            </div>
          ) : (
            <p data-reveal className="mt-5 max-w-[40ch] leading-relaxed text-muted">
              {state.kind === "error" ? "Release information could not be loaded right now." : "No release has been published yet. The changes of each release appear here once it is out."}
            </p>
          )}
          <a data-reveal href="/changelog/" className="mt-6 inline-block text-[0.95rem] text-accent-soft hover:underline">
            View full changelog
          </a>
        </div>
        {items.length > 0 && (
          <ul className="self-end">
            {items.map((h, i) => (
              <li data-reveal key={i} className="flex items-start gap-3 border-t border-line py-4 first:border-t-0">
                <span className="w-[6.5rem] shrink-0 pt-0.5">
                  <CategoryTag category={h.category} />
                </span>
                <span className="leading-relaxed text-ink/90">
                  <InlineText v={h.item} />
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

/* ───────────── closing ───────────── */

/**
 * Enlarged preview of an orbiting screenshot: on hover (mouse, pen) or tap (touch, toggles).
 * One preview at a time, rendered in a portal above the page and kept inside the viewport.
 * The orbiting card itself is not touched.
 */
function useOrbitPreview(images: { src: string; alt: string }[]) {
  const [shown, setShown] = useState<{ index: number; x: number; y: number; w: number; h: number } | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const lastPointer = useRef("mouse");
  const reduced = () => typeof window !== "undefined" && !window.matchMedia(MOTION_OK).matches;
  const itemOf = (t: EventTarget | null) => (t instanceof Element ? (t.closest("[data-orbit-item]") as HTMLElement | null) : null);

  const show = (card: HTMLElement) => {
    const index = Number(card.getAttribute("data-orbit-item"));
    const r = card.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const m = 16;
    const top = 72; // below the fixed navigation when there is room
    const w = Math.min(780, vw - m * 2);
    const h = (w * SHOT.height) / SHOT.width;
    const x = Math.min(Math.max(r.left + r.width / 2 - w / 2, m), vw - w - m);
    let y = r.top - h - 14; // above the card first,
    if (y < top) y = r.bottom + 14; // then below it,
    if (y + h > vh - m) y = Math.min(Math.max(r.top + r.height / 2 - h / 2, Math.min(top, vh - h - m)), vh - h - m); // else centred on it
    setShown({ index, x, y: Math.max(m, y), w, h });
  };

  const hide = () => {
    const el = box.current;
    if (!el) return setShown(null);
    gsap.killTweensOf(el);
    gsap.to(el, { autoAlpha: 0, scale: 0.96, duration: reduced() ? 0 : 0.2, ease: "power2.in", onComplete: () => setShown(null) });
  };

  // animate in whenever a (new) card is previewed
  useLayoutEffect(() => {
    const el = box.current;
    if (!shown || !el) return;
    gsap.killTweensOf(el);
    gsap.fromTo(el, { autoAlpha: 0, scale: 0.94 }, { autoAlpha: 1, scale: 1, duration: reduced() ? 0 : 0.3, ease: "power2.out" });
  }, [shown]);

  // a fixed preview would drift from its card: close it on scroll, resize, or a tap elsewhere
  useEffect(() => {
    if (!shown) return;
    const close = () => hide();
    const outside = (e: PointerEvent) => {
      if (!itemOf(e.target)) hide();
    };
    window.addEventListener("scroll", close, { passive: true });
    window.addEventListener("resize", close);
    document.addEventListener("pointerdown", outside);
    return () => {
      window.removeEventListener("scroll", close);
      window.removeEventListener("resize", close);
      document.removeEventListener("pointerdown", outside);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shown]);

  return {
    onPointerOver: (e: React.PointerEvent) => {
      if (e.pointerType === "touch") return;
      const card = itemOf(e.target);
      if (card && Number(card.getAttribute("data-orbit-item")) !== shown?.index) show(card);
    },
    onPointerOut: (e: React.PointerEvent) => {
      if (e.pointerType === "touch") return;
      const from = itemOf(e.target);
      const to = itemOf(e.relatedTarget);
      if (from && from !== to && !to) hide();
    },
    onPointerDown: (e: React.PointerEvent) => {
      lastPointer.current = e.pointerType;
    },
    onClick: (e: React.MouseEvent) => {
      if (lastPointer.current !== "touch") return;
      const card = itemOf(e.target);
      if (!card) return hide();
      if (Number(card.getAttribute("data-orbit-item")) === shown?.index) hide();
      else show(card);
    },
    element:
      shown &&
      createPortal(
        <div
          ref={box}
          aria-hidden="true"
          className="pointer-events-none fixed z-[60] overflow-hidden rounded-[12px] bg-surface opacity-0 shadow-[0_0_0_1px_rgb(255_255_255/0.08),0_30px_80px_-20px_rgb(0_0_0/0.85)]"
          style={{ left: shown.x, top: shown.y, width: shown.w, height: shown.h }}
        >
          <img src={images[shown.index]?.src} alt="" width={SHOT.width} height={SHOT.height} className="block h-full w-full" />
        </div>,
        document.body,
      ),
  };
}

function Closing() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  // real screens of the app circle the closing line (React Bits OrbitImages)
  const orbit = [
    { src: screens.osintGraph, alt: "OSINT graph" },
    { src: screens.dashboard, alt: "Dashboard" },
    { src: screens.commandCenter, alt: "Command Center" },
    { src: screens.vulnIntel, alt: "Vulnerability Intel" },
    { src: screens.tools, alt: "Tools Library" },
    { src: screens.dorks, alt: "Dorks Studio" },
    { src: screens.payloads, alt: "Payloads" },
    { src: screens.mcp, alt: "MCP" },
  ];
  const preview = useOrbitPreview(orbit);
  return (
    <section ref={root} className="wrap pt-28 md:pt-40" aria-labelledby="closing-title">
      <div data-reveal-group className="relative overflow-hidden rounded-[18px] bg-surface px-5 pt-10 pb-16 md:px-14 md:pt-14 md:pb-20">
        <div data-reveal className="relative">
          <div onPointerOver={preview.onPointerOver} onPointerOut={preview.onPointerOut} onPointerDown={preview.onPointerDown} onClick={preview.onClick}>
          <OrbitImages
            images={orbit}
            shape="ellipse"
            radiusX={560}
            radiusY={185}
            rotation={-6}
            duration={56}
            itemSize={150}
            itemRadius={16}
            depth={0.6}
            shadow={0.45}
            showPath
            pathColor="rgba(76,141,255,0.28)"
            pathWidth={1.5}
            centerContent={
              <h2 id="closing-title" className="max-w-[16ch] text-center text-[clamp(1.6rem,4.2vw,3.25rem)] leading-[1.02] font-semibold tracking-[-0.03em]">
                Bring your workflow into one place.
              </h2>
            }
          />
          </div>
          {preview.element}
        </div>
        <div className="relative mx-auto max-w-[48ch] text-center">
          <p data-reveal className="mt-4 text-[1.05rem] leading-relaxed text-muted">
            Install Cyber Hub, scan for the tools you already have, and start a project.
          </p>
          <div data-reveal className="mt-8">
            <a href="/download/" className="btn btn-primary">
              Download Cyber Hub
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const releases = useReleases();
  return (
    <>
      <Nav page="home" />
      <main id="main">
        <Hero />
        <Facts />
        <Capabilities />
        <FitsTogether />
        <Showcase />
        <Principles />
        <Platforms />
        <ChangelogPreview />
        <Closing />
      </main>
      <Footer version={releases.kind === "ready" ? (releases.latest?.version ?? null) : null} />
    </>
  );
}
