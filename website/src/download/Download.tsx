import { useMemo, useRef, useState } from "react";
import { Footer, Nav } from "../components/Chrome";
import { config, repoLinks } from "../lib/config";
import { gsap, MOTION_OK, useGSAP, useReveal } from "../lib/motion";
import { type Block, type Inline, parseNotes, sections } from "../lib/notes";
import { currentOs } from "../lib/platform";
import { type Artifact, type Format, FORMAT_LABEL, formatSize, type Os, type Release, type ReleaseState } from "../lib/releases";
import { useLatestRelease } from "../lib/useRelease";

const FORMATS: Record<Os, Format[]> = { windows: ["nsis", "msi"], linux: ["appimage", "deb", "rpm"] };
const OS_LABEL: Record<Os, string> = { windows: "Windows", linux: "Linux" };
const INSTALL_TITLE: Record<Format, string> = {
  nsis: "Install with the installer",
  msi: "Install the MSI package",
  appimage: "Run the AppImage",
  deb: "Install the .deb package",
  rpm: "Install the .rpm package",
};

function formatDate(iso: string | null) {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : "—";
}

/* ───────────── hero with live release facts ───────────── */

function StatusRow({ state }: { state: ReleaseState & { retry: () => void } }) {
  const release = state.kind === "ready" ? state.release : null;
  const platforms = release ? [...new Set(release.artifacts.map((a) => OS_LABEL[a.os]))].join(" and ") || "—" : "Windows and Linux (x64)";
  const status =
    state.kind === "ready" ? "Stable release" : state.kind === "loading" ? "Checking…" : state.kind === "error" ? "Unavailable right now" : "No public release yet";
  const rows: [string, string][] = [
    ["Version", release ? release.version : state.kind === "loading" ? "…" : "—"],
    ["Released", release ? formatDate(release.publishedAt) : state.kind === "loading" ? "…" : "—"],
    ["Status", status],
    ["Platforms", platforms],
  ];
  return (
    <dl className="mt-12 grid grid-cols-2 gap-px overflow-hidden rounded-[14px] bg-line/60 md:grid-cols-4" aria-live="polite" aria-busy={state.kind === "loading"}>
      {rows.map(([k, v]) => (
        <div key={k} className="bg-surface px-5 py-4">
          <dt className="text-[0.82rem] text-faint">{k}</dt>
          <dd className={`mt-1 text-[1.02rem] ${k === "Status" && state.kind === "ready" ? "text-ok" : "text-ink"}`}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Unavailable({ state }: { state: ReleaseState & { retry: () => void } }) {
  const links = repoLinks(config.repository);
  if (state.kind === "error")
    return (
      <div role="alert" className="mt-6 rounded-[12px] bg-warn/10 px-5 py-4 text-[0.95rem] text-[#f1c779]">
        <p>{state.message}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" className="btn btn-quiet h-9 px-3.5 text-[0.88rem]" onClick={state.retry}>
            Try again
          </button>
          {links && (
            <a className="btn btn-quiet h-9 px-3.5 text-[0.88rem]" href={links.releases} target="_blank" rel="noopener noreferrer">
              Open the releases page
            </a>
          )}
        </div>
      </div>
    );
  if (state.kind === "none" || state.kind === "not-configured")
    return (
      <p className="mt-6 max-w-[62ch] rounded-[12px] bg-surface px-5 py-4 text-[0.95rem] leading-relaxed text-muted">
        Cyber Hub has not been publicly released yet, so there is nothing to download. Packages appear here automatically as soon as the first stable release is published.
      </p>
    );
  return null;
}

/* ───────────── platform and package selection ───────────── */

const STEPS: Record<Format, (a: Artifact | null) => { text: React.ReactNode; code?: string }[]> = {
  nsis: () => [
    { text: "Download the installer." },
    { text: "Run it. It installs Cyber Hub for your user account and does not need administrator rights." },
    { text: "If the Microsoft Edge WebView2 Runtime is missing (it ships with Windows 11 and current Windows 10), the installer downloads it." },
    { text: "Start Cyber Hub from the Start menu." },
  ],
  msi: () => [
    { text: "Download the MSI package." },
    { text: "Open it and confirm the administrator prompt: the MSI installs Cyber Hub for all users." },
    { text: "Complete the setup." },
    { text: "Start Cyber Hub from the Start menu." },
  ],
  appimage: (a) => [
    { text: "Download the AppImage and make it executable:", code: `chmod +x ${a?.name ?? "Cyber.Hub_<version>_amd64.AppImage"}` },
    { text: "Run it:", code: `./${a?.name ?? "Cyber.Hub_<version>_amd64.AppImage"}` },
    { text: "Some distributions need FUSE 2 to run AppImages (for example the libfuse2 package on Ubuntu). Keep the file in a folder you can write to so it can update itself. For MCP clients, prefer the .deb or .rpm: the AppImage's internal path changes on every start." },
  ],
  deb: (a) => [
    { text: "Download the package and install it with its dependencies:", code: `sudo apt install ./${a?.name ?? "Cyber.Hub_<version>_amd64.deb"}` },
    { text: "Start Cyber Hub from your applications menu." },
  ],
  rpm: (a) => [
    { text: "Download the package and install it (Fedora, RHEL and derivatives):", code: `sudo dnf install ./${a?.name ?? "Cyber.Hub-<version>-1.x86_64.rpm"}` },
    { text: "On openSUSE:", code: `sudo zypper install ./${a?.name ?? "Cyber.Hub-<version>-1.x86_64.rpm"}` },
    { text: "Start Cyber Hub from your applications menu." },
  ],
};

function Picker({ release }: { release: Release | null }) {
  const detected = useMemo(() => currentOs(), []);
  const [os, setOs] = useState<Os>(detected === "linux" ? "linux" : "windows");
  const available = (f: Format) => release?.artifacts.find((a) => a.format === f) ?? null;
  const firstAvailable = (o: Os) => FORMATS[o].find((f) => available(f)) ?? FORMATS[o][0];
  // the visitor's choice per platform; until they choose, the first package the release has
  const [choice, setChoice] = useState<Partial<Record<Os, Format>>>({});
  const format = choice[os] ?? firstAvailable(os);
  const setFormat = (f: Format) => setChoice((c) => ({ ...c, [os]: f }));
  const artifact = available(format);
  const panel = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.from("[data-swap]", { autoAlpha: 0, y: 10, duration: 0.45, ease: "power2.out", stagger: 0.05 });
      });
      return () => mm.revert();
    },
    { scope: panel, dependencies: [os, format], revertOnUpdate: true },
  );

  return (
    <section className="mt-16" aria-labelledby="choose-title">
      <h2 id="choose-title" className="text-[1.5rem] font-semibold tracking-tight">
        Choose your platform
      </h2>
      {detected === "macos" && <p className="mt-2 text-[0.92rem] text-warn">You seem to be on macOS, which Cyber Hub does not support. Pick Windows or Linux to download for another machine.</p>}
      {detected && detected !== "macos" && <p className="mt-2 text-[0.92rem] text-faint">Suggested for this device: {OS_LABEL[detected]}. You can choose another platform.</p>}

      <div role="radiogroup" aria-label="Operating system" className="mt-6 inline-flex rounded-[12px] bg-surface p-1">
        {(Object.keys(FORMATS) as Os[]).map((o) => (
          <button
            key={o}
            type="button"
            role="radio"
            aria-checked={os === o}
            onClick={() => setOs(o)}
            className={`rounded-[9px] px-5 py-2.5 text-[0.95rem] transition-colors ${os === o ? "bg-white/[0.09] text-ink" : "text-muted hover:text-ink"}`}
          >
            {OS_LABEL[o]} <span className="text-faint">x64</span>
          </button>
        ))}
      </div>

      <div ref={panel} className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-12">
        <div data-swap>
          <h3 className="text-[0.88rem] text-faint">{os === "windows" ? "Windows 10 and 11, x64" : "Linux, x64"}</h3>
          <fieldset className="mt-3">
            <legend className="sr-only">Package format</legend>
            <ul className="space-y-2">
              {FORMATS[os].map((f) => {
                const a = available(f);
                return (
                  <li key={f}>
                    <label className={`flex cursor-pointer items-center justify-between gap-4 rounded-[12px] px-4 py-3.5 transition-colors ${format === f ? "bg-raised shadow-[inset_0_0_0_1px_rgb(76_141_255/0.55)]" : "bg-surface hover:bg-raised"}`}>
                      <span className="flex items-center gap-3">
                        <input type="radio" name={`format-${os}`} value={f} checked={format === f} onChange={() => setFormat(f)} className="size-4 accent-[#4c8dff]" />
                        <span className="text-[0.98rem] text-ink">{FORMAT_LABEL[f]}</span>
                      </span>
                      <span className="text-[0.85rem] text-faint">{a ? formatSize(a.size) : "Not available"}</span>
                    </label>
                  </li>
                );
              })}
            </ul>
          </fieldset>

          <div className="mt-6">
            {artifact ? (
              <>
                <a href={artifact.url} className="btn btn-primary w-full justify-center sm:w-auto" download>
                  Download {FORMAT_LABEL[format]}
                </a>
                <p className="mt-3 font-mono text-[0.78rem] break-all text-faint">
                  {artifact.name} · {formatSize(artifact.size)}
                </p>
                {release?.checksumsUrl && (
                  <a className="mt-2 inline-block text-[0.88rem] text-accent-soft hover:underline" href={release.checksumsUrl}>
                    SHA-256 checksums
                  </a>
                )}
              </>
            ) : (
              <p className="rounded-[12px] bg-surface px-4 py-3.5 text-[0.92rem] text-muted">
                {release ? `The ${release.version} release does not include this package.` : "No package is available yet."}
              </p>
            )}
          </div>
        </div>

        <div data-swap className="rounded-[14px] bg-surface p-6 md:p-7">
          <h3 className="text-[1.05rem] font-medium">{INSTALL_TITLE[format]}</h3>
          <ol className="mt-4 space-y-4">
            {STEPS[format](artifact).map((s, i) => (
              <li key={i} className="grid grid-cols-[1.75rem_1fr] gap-2 text-[0.95rem] leading-relaxed text-muted">
                <span className="font-mono text-[0.85rem] leading-[1.7] text-faint">{i + 1}</span>
                <div>
                  <p>{s.text}</p>
                  {s.code && (
                    <pre className="mt-2 overflow-x-auto rounded-[8px] bg-base px-3 py-2.5 font-mono text-[0.82rem] text-ink">
                      <code>{s.code}</code>
                    </pre>
                  )}
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-6 text-[0.88rem] leading-relaxed text-faint">After that, Cyber Hub keeps itself current: Settings → Updates checks for signed releases and installs them only when you confirm.</p>
        </div>
      </div>
    </section>
  );
}

/* ───────────── release notes ───────────── */

function InlineText({ v }: { v: Inline[] }) {
  return (
    <>
      {v.map((i, k) =>
        i.t === "code" ? (
          <code key={k} className="rounded bg-raised px-1.5 py-0.5 font-mono text-[0.85em] text-ink">
            {i.v}
          </code>
        ) : i.t === "strong" ? (
          <strong key={k} className="font-medium text-ink">
            {i.v}
          </strong>
        ) : i.t === "link" ? (
          <a key={k} href={i.href} className="text-accent-soft hover:underline" target="_blank" rel="noopener noreferrer nofollow">
            {i.v}
          </a>
        ) : (
          <span key={k}>{i.v}</span>
        ),
      )}
    </>
  );
}

function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <div className="space-y-3">
      {blocks.map((b, k) =>
        b.t === "list" ? (
          <ul key={k} className="list-disc space-y-1.5 pl-5 marker:text-faint">
            {b.items.map((it, j) => (
              <li key={j}>
                <InlineText v={it} />
              </li>
            ))}
          </ul>
        ) : b.t === "heading" ? (
          <h4 key={k} className="pt-2 text-[0.98rem] font-medium text-ink">
            <InlineText v={b.v} />
          </h4>
        ) : (
          <p key={k}>
            <InlineText v={b.v} />
          </p>
        ),
      )}
    </div>
  );
}

function ReleaseNotes({ release }: { release: Release }) {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  const parts = sections(parseNotes(release.notes));
  const links = repoLinks(config.repository);
  return (
    <section ref={root} className="mt-24" aria-labelledby="notes-title">
      <div data-reveal-group>
        <h2 data-reveal id="notes-title" className="text-[1.5rem] font-semibold tracking-tight">
          What's in {release.version}
        </h2>
        <p data-reveal className="mt-2 text-[0.92rem] text-faint">
          {release.name} · published {formatDate(release.publishedAt)}
        </p>
        {parts.length ? (
          <div className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-x-12 gap-y-10 md:grid-cols-2">
            {parts.map((s, i) => (
              <div data-reveal key={i} className="text-[0.96rem] leading-relaxed text-muted">
                {s.title && <h3 className="mb-3 text-[1.05rem] font-medium text-ink">{s.title}</h3>}
                <Blocks blocks={s.blocks} />
              </div>
            ))}
          </div>
        ) : (
          <p data-reveal className="mt-6 text-muted">This release has no notes.</p>
        )}
        <div data-reveal className="mt-8 flex flex-wrap gap-4 text-[0.92rem]">
          <a className="text-accent-soft hover:underline" href={release.pageUrl} target="_blank" rel="noopener noreferrer">
            Release on GitHub
          </a>
          {links && (
            <a className="text-accent-soft hover:underline" href={links.releases} target="_blank" rel="noopener noreferrer">
              All releases
            </a>
          )}
        </div>
      </div>
    </section>
  );
}

/* ───────────── requirements ───────────── */

function Requirements() {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  const items: [string, string[]][] = [
    [
      "Windows",
      [
        "Windows 10 or 11, 64-bit (x64).",
        "Microsoft Edge WebView2 Runtime: included in Windows 11 and current Windows 10; installed by the setup if missing.",
        "Provider credentials, if used, are kept in Windows Credential Manager.",
      ],
    ],
    [
      "Linux",
      [
        "A 64-bit (x64) distribution with WebKitGTK 4.1 and GTK 3. The .deb and .rpm packages install them as dependencies.",
        "Provider credentials, if used, need a running Secret Service, such as GNOME Keyring or KWallet.",
        "Tested on Debian 12 and Ubuntu 24.04.",
      ],
    ],
    [
      "Everywhere",
      [
        "The security tools themselves are separate programs. The Tools Library detects what is installed and shows how to install the rest.",
        "Network access is needed only for features that say they use it (live CVE search, lookups, update checks).",
        "No minimum hardware has been published yet.",
      ],
    ],
  ];
  return (
    <section ref={root} className="mt-24" aria-labelledby="req-title">
      <h2 id="req-title" className="text-[1.5rem] font-semibold tracking-tight">
        System requirements
      </h2>
      <div data-reveal-group className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-10 md:grid-cols-3">
        {items.map(([title, lines]) => (
          <div data-reveal key={title}>
            <h3 className="text-[1.02rem] font-medium">{title}</h3>
            <ul className="mt-3 space-y-2.5 text-[0.94rem] leading-relaxed text-muted">
              {lines.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <p className="mt-10 text-[0.9rem] text-faint">macOS is not supported.</p>
    </section>
  );
}

export default function DownloadPage() {
  const state = useLatestRelease();
  const release = state.kind === "ready" ? state.release : null;
  const hero = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.from("[data-hero-line]", { autoAlpha: 0, y: 24, duration: 0.85, ease: "power3.out", stagger: 0.08 });
      });
      return () => mm.revert();
    },
    { scope: hero },
  );
  return (
    <>
      <Nav page="download" />
      <main id="main" className="wrap pt-32 md:pt-40">
        <div ref={hero} className="relative">
          <div aria-hidden="true" className="pointer-events-none absolute -top-40 -left-40 h-[28rem] w-[44rem] rounded-full bg-[radial-gradient(closest-side,rgb(76_141_255/0.16),transparent)] blur-2xl" />
          <h1 data-hero-line className="relative text-[clamp(2.75rem,7vw,5rem)] leading-[0.98] font-semibold tracking-[-0.035em]">
            Get Cyber Hub.
          </h1>
          <p data-hero-line className="relative mt-5 max-w-[46ch] text-[1.1rem] leading-relaxed text-muted md:text-[1.2rem]">
            Bring your cybersecurity workflow into one powerful desktop workspace.
          </p>
          <div data-hero-line className="relative">
            <StatusRow state={state} />
            <Unavailable state={state} />
          </div>
        </div>
        <Picker release={release} />
        {release && <ReleaseNotes release={release} />}
        <Requirements />
      </main>
      <Footer version={release?.version ?? null} />
    </>
  );
}
