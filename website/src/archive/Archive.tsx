import { useEffect, useMemo, useRef, useState } from "react";
import { Footer, Nav } from "../components/Chrome";
import { ChannelTag, CopyButton, InlineText, NoteBlocks, ReleaseStateNotice } from "../components/release";
import { gsap, MOTION_OK, useGSAP } from "../lib/motion";
import { useReleases } from "../lib/releaseStore";
import { type ArchiveFilter, changelogOf, filterArchive, FORMAT_LABEL, formatDate, formatSize, OS_LABEL, platformsOf, type Release } from "../lib/releases";

function ArchiveEntry({ release, latest, open, onToggle }: { release: Release; latest: Release | null; open: boolean; onToggle: () => void }) {
  const log = changelogOf(release);
  const isLatest = release === latest;
  const older = !isLatest && release.channel === "stable";
  const id = `v${release.version}`;
  return (
    <li id={id} data-entry className="rounded-[14px] bg-surface p-5 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="text-[1.35rem] leading-none font-semibold tracking-tight">{release.version}</h2>
            <ChannelTag release={release} latest={isLatest} />
          </div>
          <p className="mt-2 text-[0.88rem] text-faint">
            {formatDate(release.publishedAt)}
            {release.assets.length > 0 && <> · {platformsOf(release).map((o) => OS_LABEL[o]).join(", ")} · {release.assets.map((a) => FORMAT_LABEL[a.format].split(" ")[0]).join(", ")}</>}
          </p>
          {log.summary && (
            <p className="mt-3 max-w-[70ch] text-[0.95rem] leading-relaxed text-muted">
              <InlineText v={log.summary} />
            </p>
          )}
        </div>
        <button type="button" className="btn btn-quiet h-9 shrink-0 px-3.5 text-[0.88rem]" aria-expanded={open} aria-controls={`${id}-details`} onClick={onToggle}>
          {open ? "Hide details" : "Details and downloads"}
        </button>
      </div>

      <div id={`${id}-details`} hidden={!open} className="mt-6 space-y-6">
        {release.channel === "prerelease" && (
          <p className="rounded-[10px] bg-warn/10 px-4 py-3 text-[0.9rem] text-[#f1c779]">This is a pre-release for testing. It may be incomplete or unstable; installed copies on the stable channel are not offered pre-releases.</p>
        )}
        {older && (
          <p className="rounded-[10px] bg-warn/10 px-4 py-3 text-[0.9rem] text-[#f1c779]">
            An older version, kept for reference. It can contain problems that later releases fixed, including security fixes. Install the latest stable release unless you need this one; nothing guarantees that an older version updates cleanly to the current one.
          </p>
        )}

        {release.assets.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[40rem] text-left text-[0.88rem]">
              <caption className="sr-only">Packages of {release.version}</caption>
              <thead className="text-faint">
                <tr>
                  <th className="pb-2 font-normal">Package</th>
                  <th className="pb-2 font-normal">Size</th>
                  <th className="pb-2 font-normal">SHA-256</th>
                  <th className="pb-2 font-normal" />
                </tr>
              </thead>
              <tbody>
                {release.assets.map((a) => (
                  <tr key={a.name} className="border-t border-line align-top">
                    <td className="py-3 pr-4">
                      <div className="text-ink">
                        {OS_LABEL[a.os]} · {FORMAT_LABEL[a.format]}
                      </div>
                      <div className="mt-0.5 font-mono text-[0.75rem] break-all text-faint">{a.name}</div>
                    </td>
                    <td className="py-3 pr-4 whitespace-nowrap text-muted">{formatSize(a.size)}</td>
                    <td className="py-3 pr-4">
                      {a.sha256 ? (
                        <div className="flex items-start gap-2">
                          <code className="font-mono text-[0.72rem] leading-relaxed break-all text-muted">{a.sha256}</code>
                          <CopyButton text={a.sha256} />
                        </div>
                      ) : (
                        <span className="text-faint">{release.checksumsUrl ? "See SHA256SUMS.txt" : "Not published"}</span>
                      )}
                    </td>
                    <td className="py-3 text-right">
                      <a className="btn btn-quiet h-8 px-3 text-[0.82rem]" href={a.downloadUrl} download>
                        Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-[0.92rem] text-muted">No downloadable packages are available for this release.</p>
        )}

        <div className="flex flex-wrap gap-4 text-[0.9rem]">
          {release.checksumsUrl && (
            <a className="text-accent-soft hover:underline" href={release.checksumsUrl}>
              SHA256SUMS.txt
            </a>
          )}
          <a className="text-accent-soft hover:underline" href={release.htmlUrl} target="_blank" rel="noopener noreferrer">
            Release on GitHub
          </a>
        </div>

        <div className="text-[0.93rem] leading-relaxed text-muted">
          <h3 className="mb-3 text-[1rem] font-medium text-ink">Release notes</h3>
          {log.groups.length ? (
            <div className="space-y-6">
              {log.groups.map((g, i) => (
                <div key={i}>
                  {g.title && <h4 className="mb-2 font-medium text-ink">{g.title}</h4>}
                  <NoteBlocks blocks={g.blocks} />
                </div>
              ))}
            </div>
          ) : (
            <p>This release has no notes.</p>
          )}
        </div>
      </div>
    </li>
  );
}

export default function ArchivePage() {
  const state = useReleases();
  const releases = useMemo(() => (state.kind === "ready" ? state.releases : []), [state]);
  const latest = state.kind === "ready" ? state.latest : null;
  const [filter, setFilter] = useState<ArchiveFilter>({ os: "all", channel: "all", query: "" });
  // a link to #v<version> (from the changelog) opens that release
  const [hashVersion] = useState(() => (typeof location !== "undefined" ? decodeURIComponent(location.hash.replace(/^#v/, "")) : ""));
  const [open, setOpen] = useState<Set<string>>(() => new Set(hashVersion ? [hashVersion] : []));
  const hasPre = releases.some((r) => r.channel === "prerelease");
  const visible = filterArchive(releases, filter);

  useEffect(() => {
    if (hashVersion && releases.some((r) => r.version === hashVersion)) requestAnimationFrame(() => document.getElementById(`v${hashVersion}`)?.scrollIntoView({ block: "start" }));
  }, [releases, hashVersion]);

  const list = useRef<HTMLOListElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        if (!list.current?.querySelector("[data-entry]")) return;
        gsap.from("[data-entry]", { autoAlpha: 0, y: 14, duration: 0.5, ease: "power3.out", stagger: 0.05 });
      });
      return () => mm.revert();
    },
    { scope: list, dependencies: [visible.length, filter.os, filter.channel], revertOnUpdate: true },
  );

  const chip = (active: boolean) => `rounded-lg px-3 py-1.5 text-[0.88rem] transition-colors ${active ? "bg-white/[0.09] text-ink" : "text-muted hover:text-ink"}`;

  return (
    <>
      <Nav page="download" />
      <main id="main" className="wrap pt-32 md:pt-40">
        <p className="text-[0.9rem]">
          <a className="text-accent-soft hover:underline" href="/download/">
            Download
          </a>
          <span className="text-faint"> / Version archive</span>
        </p>
        <h1 className="mt-3 text-[clamp(2.5rem,6vw,4.2rem)] leading-[1] font-semibold tracking-[-0.035em]">Version archive</h1>
        <p className="mt-4 max-w-[60ch] text-[1.1rem] leading-relaxed text-muted">Every published ExploitX release with its packages and checksums. For a new installation, use the latest stable release.</p>

        {state.kind === "ready" && releases.length > 0 && (
          <div className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-3">
            <div role="group" aria-label="Platform" className="flex gap-1">
              {(["all", "windows", "linux"] as const).map((o) => (
                <button key={o} type="button" aria-pressed={filter.os === o} className={chip(filter.os === o)} onClick={() => setFilter((f) => ({ ...f, os: o }))}>
                  {o === "all" ? "All platforms" : OS_LABEL[o]}
                </button>
              ))}
            </div>
            {hasPre && (
              <div role="group" aria-label="Channel" className="flex gap-1">
                {(["all", "stable", "prerelease"] as const).map((c) => (
                  <button key={c} type="button" aria-pressed={filter.channel === c} className={chip(filter.channel === c)} onClick={() => setFilter((f) => ({ ...f, channel: c }))}>
                    {c === "all" ? "All channels" : c === "stable" ? "Stable" : "Pre-release"}
                  </button>
                ))}
              </div>
            )}
            <label className="ml-auto flex min-w-[14rem] items-center gap-2 rounded-lg bg-surface px-3 py-2">
              <span className="sr-only">Search by version</span>
              <svg viewBox="0 0 24 24" className="size-4 text-faint" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
                <circle cx="11" cy="11" r="6.5" />
                <path d="m16 16 4 4" />
              </svg>
              <input
                type="search"
                inputMode="decimal"
                placeholder="Version, e.g. 0.2"
                value={filter.query}
                onChange={(e) => setFilter((f) => ({ ...f, query: e.target.value }))}
                className="w-full bg-transparent text-[0.9rem] text-ink outline-none placeholder:text-faint"
              />
            </label>
          </div>
        )}

        <div className="mt-10">
          <ReleaseStateNotice state={state} empty="No release has been published yet, so the archive is empty." />
          {state.kind === "ready" && releases.length > 0 && visible.length === 0 && <p className="text-muted">No release matches these filters.</p>}
          <ol ref={list} className="space-y-3">
            {visible.map((r) => (
              <ArchiveEntry
                key={r.version}
                release={r}
                latest={latest}
                open={open.has(r.version)}
                onToggle={() =>
                  setOpen((s) => {
                    const n = new Set(s);
                    if (n.has(r.version)) n.delete(r.version);
                    else n.add(r.version);
                    return n;
                  })
                }
              />
            ))}
          </ol>
        </div>
      </main>
      <Footer version={latest?.version ?? null} />
    </>
  );
}
