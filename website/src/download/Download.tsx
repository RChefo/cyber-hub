import { useEffect, useMemo, useRef, useState } from "react";
import { Footer, Nav } from "../components/Chrome";
import { NoteBlocks, ReleaseStateNotice, Skeleton, Verification } from "../components/release";
import { gsap, MOTION_OK, useGSAP, useReveal } from "../lib/motion";
import { currentPlatform, type Detection, detectionMessage, refineArch, resolveSelection } from "../lib/platform";
import { type ReleasesState, useReleases } from "../lib/releaseStore";
import { changelogOf, FORMAT_HINT, FORMAT_LABEL, formatDate, formatSize, FORMATS_BY_OS, type Format, type Os, OS_LABEL, platformsOf, type Release, type ReleaseAsset } from "../lib/releases";

const INSTALL_TITLE: Record<Format, string> = {
  nsis: "Install with the installer",
  msi: "Install the MSI package",
  appimage: "Run the AppImage",
  deb: "Install the .deb package",
  rpm: "Install the .rpm package",
};

const STEPS: Record<Format, (a: ReleaseAsset | null) => { text: string; code?: string }[]> = {
  nsis: () => [
    { text: "Download the installer." },
    { text: "Run it. It installs ExploitX for your user account and does not need administrator rights." },
    { text: "If the Microsoft Edge WebView2 Runtime is missing (it ships with Windows 11 and current Windows 10), the installer downloads it." },
    { text: "Start it from the Start menu." },
  ],
  msi: () => [
    { text: "Download the MSI package." },
    { text: "Open it and confirm the administrator prompt: the MSI installs ExploitX for all users." },
    { text: "Complete the setup." },
    { text: "Start it from the Start menu." },
  ],
  appimage: (a) => [
    { text: "Download the AppImage and make it executable:", code: `chmod +x ${a?.name ?? "Cyber.Hub_<version>_amd64.AppImage"}` },
    { text: "Run it:", code: `./${a?.name ?? "Cyber.Hub_<version>_amd64.AppImage"}` },
    { text: "Some distributions need FUSE 2 to run AppImages (for example the libfuse2 package on Ubuntu). Keep the file in a folder you can write to so it can update itself. For MCP clients, prefer the .deb or .rpm: the AppImage's internal path changes on every start." },
  ],
  deb: (a) => [
    { text: "Download the package and install it with its dependencies:", code: `sudo apt install ./${a?.name ?? "Cyber.Hub_<version>_amd64.deb"}` },
    { text: "Start it from your applications menu." },
  ],
  rpm: (a) => [
    { text: "Download the package and install it (Fedora, RHEL and derivatives):", code: `sudo dnf install ./${a?.name ?? "Cyber.Hub-<version>-1.x86_64.rpm"}` },
    { text: "On openSUSE:", code: `sudo zypper install ./${a?.name ?? "Cyber.Hub-<version>-1.x86_64.rpm"}` },
    { text: "Start it from your applications menu." },
  ],
};

/* ───────────── release facts ───────────── */

function StatusRow({ state, release }: { state: ReleasesState; release: Release | null }) {
  const loading = state.kind === "loading";
  const platforms = release ? platformsOf(release).map((o) => OS_LABEL[o]).join(" and ") || "—" : "Windows and Linux (x64)";
  const status = release ? "Stable release" : loading ? "Checking…" : state.kind === "error" ? "Unavailable right now" : "No public release yet";
  const rows: [string, React.ReactNode][] = [
    ["Version", release ? release.version : loading ? <Skeleton className="mt-1 h-5 w-14" /> : "—"],
    ["Released", release ? formatDate(release.publishedAt) : loading ? <Skeleton className="mt-1 h-5 w-28" /> : "—"],
    ["Status", status],
    ["Platforms", platforms],
  ];
  return (
    <dl className="mt-12 grid grid-cols-2 gap-px overflow-hidden rounded-[14px] bg-line/60 md:grid-cols-4" aria-live="polite" aria-busy={loading}>
      {rows.map(([k, v]) => (
        <div key={k} className="bg-surface px-5 py-4">
          <dt className="text-[0.82rem] text-faint">{k}</dt>
          <dd className={`mt-1 text-[1.02rem] ${k === "Status" && release ? "text-ok" : "text-ink"}`}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ───────────── recommendation, picker and verification ───────────── */

function Picker({ release }: { release: Release | null }) {
  const [detection, setDetection] = useState<Detection>(() => currentPlatform());
  useEffect(() => {
    let live = true;
    refineArch(detection).then((d) => {
      if (live && d.arch !== detection.arch) setDetection(d);
    });
    return () => {
      live = false;
    };
    // only once, with the first detection
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [chosenOs, setChosenOs] = useState<Os | null>(null);
  const [chosenFormat, setChosenFormat] = useState<Format | null>(null);
  const sel = useMemo(() => resolveSelection(release, detection, chosenOs, chosenFormat), [release, detection, chosenOs, chosenFormat]);
  const has = (f: Format) => release?.assets.find((a) => a.os === sel.os && a.format === f) ?? null;
  const panel = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.from("[data-swap]", { autoAlpha: 0, y: 10, duration: 0.45, ease: "power2.out", stagger: 0.05 });
      });
      return () => mm.revert();
    },
    { scope: panel, dependencies: [sel.os, sel.format], revertOnUpdate: true },
  );
  const message = detectionMessage(detection, release);
  const formats = FORMATS_BY_OS[sel.os];
  const shown = release ? formats.filter((f) => has(f)) : formats;

  return (
    <section className="mt-16" aria-labelledby="choose-title">
      <h2 id="choose-title" className="text-[1.5rem] font-semibold tracking-tight">
        Choose your platform
      </h2>
      <p className={`mt-2 text-[0.94rem] ${detection.os === "macos" || detection.arch === "arm" ? "text-warn" : "text-muted"}`} aria-live="polite">
        {message} {detection.os === "windows" || detection.os === "linux" ? <span className="text-faint">You can choose another platform at any time.</span> : null}
      </p>

      <div role="radiogroup" aria-label="Operating system" className="mt-6 inline-flex rounded-[12px] bg-surface p-1">
        {(Object.keys(FORMATS_BY_OS) as Os[]).map((o) => (
          <button
            key={o}
            type="button"
            role="radio"
            aria-checked={sel.os === o}
            onClick={() => {
              setChosenOs(o);
              setChosenFormat(null);
            }}
            className={`rounded-[9px] px-5 py-2.5 text-[0.95rem] transition-colors ${sel.os === o ? "bg-white/[0.09] text-ink" : "text-muted hover:text-ink"}`}
          >
            {OS_LABEL[o]} <span className="text-faint">x64</span>
          </button>
        ))}
      </div>

      <div ref={panel} className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-12">
        <div data-swap>
          <h3 className="text-[0.88rem] text-faint">{sel.os === "windows" ? "Windows 10 and 11, x64" : "Linux, x64"}</h3>
          {release && !shown.length ? (
            <p className="mt-3 rounded-[12px] bg-surface px-4 py-3.5 text-[0.92rem] text-muted">The {release.version} release has no {OS_LABEL[sel.os]} package.</p>
          ) : (
            <fieldset className="mt-3">
              <legend className="sr-only">Package format</legend>
              <ul className="space-y-2">
                {shown.map((f) => {
                  const a = has(f);
                  const isSuggested = sel.recommended && sel.format === f;
                  return (
                    <li key={f}>
                      <label className={`flex cursor-pointer gap-3 rounded-[12px] px-4 py-3.5 transition-colors ${sel.format === f ? "bg-raised shadow-[inset_0_0_0_1px_rgb(124_106_255/0.55)]" : "bg-surface hover:bg-raised"}`}>
                        <input type="radio" name="format" value={f} checked={sel.format === f} onChange={() => setChosenFormat(f)} className="mt-1 size-4 shrink-0 accent-[#7c6aff]" />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                            <span className="text-[0.98rem] text-ink">{FORMAT_LABEL[f]}</span>
                            <span className="text-[0.85rem] text-faint">{a ? formatSize(a.size) : "Not available"}</span>
                          </span>
                          {isSuggested && <span className="mt-1 inline-block rounded-md bg-accent/15 px-2 py-0.5 text-[0.74rem] font-medium text-accent-soft">Recommended for your device</span>}
                          <span className="mt-1 block text-[0.85rem] leading-snug text-muted">{FORMAT_HINT[f]}</span>
                        </span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            </fieldset>
          )}

          <div className="mt-6">
            {sel.asset ? (
              <a href={sel.asset.downloadUrl} className="btn btn-primary w-full justify-center sm:w-auto" download>
                Download {FORMAT_LABEL[sel.format]}
              </a>
            ) : (
              <p className="rounded-[12px] bg-surface px-4 py-3.5 text-[0.92rem] text-muted">
                {release ? `The ${release.version} release does not include this package.` : "No package is available yet."}
              </p>
            )}
          </div>

          {release && sel.asset && (
            <div className="mt-8 rounded-[14px] bg-surface p-5">
              <h3 className="mb-4 text-[1.02rem] font-medium">Verify your download</h3>
              <Verification release={release} asset={sel.asset} />
            </div>
          )}
        </div>

        <div data-swap className="h-fit rounded-[14px] bg-surface p-6 md:p-7">
          <h3 className="text-[1.05rem] font-medium">{INSTALL_TITLE[sel.format]}</h3>
          <ol className="mt-4 space-y-4">
            {STEPS[sel.format](sel.asset).map((s, i) => (
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
          <p className="mt-6 text-[0.88rem] leading-relaxed text-faint">After that, ExploitX keeps itself current: Settings → Updates checks for signed releases and installs them only when you confirm.</p>
        </div>
      </div>
    </section>
  );
}

/* ───────────── latest release notes ───────────── */

function LatestNotes({ release }: { release: Release }) {
  const root = useRef<HTMLElement>(null);
  useReveal(root);
  const log = changelogOf(release);
  return (
    <section ref={root} className="mt-24" aria-labelledby="notes-title">
      <div data-reveal-group>
        <h2 data-reveal id="notes-title" className="text-[1.5rem] font-semibold tracking-tight">
          What's in {release.version}
        </h2>
        <p data-reveal className="mt-2 text-[0.92rem] text-faint">
          {release.name} · published {formatDate(release.publishedAt)}
        </p>
        {log.groups.length || log.summary ? (
          <div className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-x-12 gap-y-10 text-[0.96rem] leading-relaxed text-muted md:grid-cols-2">
            {log.groups.map((g, i) => (
              <div data-reveal key={i}>
                {g.title && <h3 className="mb-3 text-[1.05rem] font-medium text-ink">{g.title}</h3>}
                <NoteBlocks blocks={g.blocks} />
              </div>
            ))}
          </div>
        ) : (
          <p data-reveal className="mt-6 text-muted">
            This release has no notes.
          </p>
        )}
        <div data-reveal className="mt-8 flex flex-wrap gap-4 text-[0.92rem]">
          <a className="text-accent-soft hover:underline" href="/changelog/">
            Full changelog
          </a>
          <a className="text-accent-soft hover:underline" href="/download/archive/">
            Older versions
          </a>
          <a className="text-accent-soft hover:underline" href={release.htmlUrl} target="_blank" rel="noopener noreferrer">
            Release on GitHub
          </a>
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
  const state = useReleases();
  const release = state.kind === "ready" ? state.latest : null;
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
          <div aria-hidden="true" className="pointer-events-none absolute -top-40 -left-40 h-[28rem] w-[44rem] rounded-full bg-[radial-gradient(closest-side,rgb(124_106_255/0.16),transparent)] blur-2xl" />
          <h1 data-hero-line className="relative text-[clamp(2.75rem,7vw,5rem)] leading-[0.98] font-semibold tracking-[-0.035em]">
            Get ExploitX.
          </h1>
          <p data-hero-line className="relative mt-5 max-w-[46ch] text-[1.1rem] leading-relaxed text-muted md:text-[1.2rem]">
            Bring your cybersecurity workflow into one powerful desktop workspace.
          </p>
          <div data-hero-line className="relative">
            <StatusRow state={state} release={release} />
            {state.kind !== "loading" && !release && (
              <div className="mt-6">
                <ReleaseStateNotice
                  state={state}
                  empty="ExploitX has not been publicly released yet, so there is nothing to download. Packages appear here automatically as soon as the first stable release is published."
                />
                {state.kind === "ready" && state.releases.length > 0 && (
                  <p className="max-w-[62ch] rounded-[12px] bg-surface px-5 py-4 text-[0.95rem] leading-relaxed text-muted">
                    No stable release has been published yet, only pre-releases for testing. They are listed in the version archive.
                  </p>
                )}
              </div>
            )}
            {state.kind === "ready" && state.releases.length > 0 && (
              <p className="mt-4 text-[0.9rem]">
                <a className="text-accent-soft hover:underline" href="/download/archive/">
                  Version archive
                </a>
                <span className="text-faint"> · every published version with its checksums</span>
              </p>
            )}
          </div>
        </div>
        <Picker release={release} />
        {release && <LatestNotes release={release} />}
        <Requirements />
      </main>
      <Footer version={release?.version ?? null} />
    </>
  );
}
