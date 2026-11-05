import { useMemo, useRef, useState } from "react";
import { Footer, Nav } from "../components/Chrome";
import { CategoryTag, ChannelTag, InlineText, NoteBlocks, ReleaseStateNotice } from "../components/release";
import { gsap, MOTION_OK, useGSAP } from "../lib/motion";
import { useReleases } from "../lib/releaseStore";
import { type Category, CATEGORY_LABEL, changelogOf, formatDate, type Release } from "../lib/releases";

function Entry({ release, latest, filter, open, onToggle }: { release: Release; latest: boolean; filter: Category | "all"; open: boolean; onToggle: () => void }) {
  const log = changelogOf(release);
  const groups = filter === "all" ? log.groups : log.groups.filter((g) => g.category === filter);
  const id = `release-${release.version.replace(/[^0-9a-z]/gi, "-")}`;
  return (
    <li data-entry className="relative grid grid-cols-[minmax(0,1fr)] gap-x-10 pb-14 md:grid-cols-[11rem_minmax(0,1fr)]">
      <div className="mb-3 md:mb-0 md:pt-1">
        <div className="text-[0.85rem] text-faint">{formatDate(release.publishedAt)}</div>
      </div>
      <article aria-labelledby={`${id}-title`}>
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 id={`${id}-title`} className="text-[1.6rem] leading-none font-semibold tracking-[-0.02em]">
            {release.version}
          </h2>
          <ChannelTag release={release} latest={latest} />
        </div>
        {release.name !== `Cyber Hub ${release.version}` && <p className="mt-2 text-ink/90">{release.name}</p>}
        {log.summary && (
          <p className="mt-3 max-w-[70ch] leading-relaxed text-muted">
            <InlineText v={log.summary} />
          </p>
        )}
        <div className="mt-4 flex flex-wrap gap-1.5">
          {[...new Set(log.groups.map((g) => g.category))].map((c) => (
            <CategoryTag key={c} category={c} />
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4 text-[0.9rem]">
          <button type="button" className="text-accent-soft hover:underline" aria-expanded={open} aria-controls={`${id}-details`} onClick={onToggle}>
            {open ? "Hide details" : "Show details"}
          </button>
          <a className="text-accent-soft hover:underline" href={release.htmlUrl} target="_blank" rel="noopener noreferrer">
            Release on GitHub
          </a>
          {release.assets.length > 0 && (
            <a className="text-accent-soft hover:underline" href={`/download/archive/#v${release.version}`}>
              Downloads
            </a>
          )}
        </div>
        <div id={`${id}-details`} hidden={!open} className="mt-6">
          {groups.length ? (
            <div className="grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-8 text-[0.95rem] leading-relaxed text-muted md:grid-cols-2">
              {groups.map((g, i) => (
                <div key={i}>
                  {g.title && (
                    <h3 className="mb-3 flex items-center gap-2 text-[1rem] font-medium text-ink">
                      <CategoryTag category={g.category} /> {g.title}
                    </h3>
                  )}
                  <NoteBlocks blocks={g.blocks} />
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted">{filter === "all" ? "This release has no notes." : `No ${CATEGORY_LABEL[filter as Category].toLowerCase()} changes in this release.`}</p>
          )}
        </div>
      </article>
    </li>
  );
}

export default function ChangelogPage() {
  const state = useReleases();
  const releases = useMemo(() => (state.kind === "ready" ? state.releases : []), [state]);
  const latest = state.kind === "ready" ? state.latest : null;
  const [filter, setFilter] = useState<Category | "all">("all");
  const [showPre, setShowPre] = useState(false);
  // null until the visitor toggles an entry: then the newest visible release starts open
  const [open, setOpen] = useState<Set<string> | null>(null);
  const hasPre = releases.some((r) => r.channel === "prerelease");
  const categories = useMemo(() => [...new Set(releases.flatMap((r) => changelogOf(r).groups.map((g) => g.category)))], [releases]);
  const visible = releases.filter((r) => (showPre || r.channel === "stable") && (filter === "all" || changelogOf(r).groups.some((g) => g.category === filter)));
  const openSet = open ?? new Set(visible[0] ? [visible[0].version] : []);
  const isOpen = (r: Release) => openSet.has(r.version);

  const list = useRef<HTMLOListElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        if (!list.current?.querySelector("[data-entry]")) return;
        gsap.from("[data-entry]", { autoAlpha: 0, y: 16, duration: 0.6, ease: "power3.out", stagger: 0.06 });
      });
      return () => mm.revert();
    },
    { scope: list, dependencies: [visible.length, filter, showPre], revertOnUpdate: true },
  );

  return (
    <>
      <Nav page="changelog" />
      <main id="main" className="wrap pt-32 md:pt-40">
        <h1 className="text-[clamp(2.5rem,6vw,4.2rem)] leading-[1] font-semibold tracking-[-0.035em]">Changelog</h1>
        <p className="mt-4 max-w-[56ch] text-[1.1rem] leading-relaxed text-muted">Every published Cyber Hub release, newest first, taken from the project's GitHub releases.</p>

        {state.kind === "ready" && releases.length > 0 && (
          <div className="mt-10 flex flex-wrap items-center gap-2" role="group" aria-label="Filter changes">
            {(["all", ...categories] as (Category | "all")[]).map((c) => (
              <button
                key={c}
                type="button"
                aria-pressed={filter === c}
                onClick={() => setFilter(c)}
                className={`rounded-lg px-3 py-1.5 text-[0.88rem] transition-colors ${filter === c ? "bg-white/[0.09] text-ink" : "text-muted hover:text-ink"}`}
              >
                {c === "all" ? "All changes" : CATEGORY_LABEL[c]}
              </button>
            ))}
            {hasPre && (
              <label className="ml-auto flex items-center gap-2 text-[0.88rem] text-muted">
                <input type="checkbox" checked={showPre} onChange={(e) => setShowPre(e.target.checked)} className="accent-[#4c8dff]" />
                Include pre-releases
              </label>
            )}
          </div>
        )}

        <div className="mt-12">
          <ReleaseStateNotice state={state} empty="No release has been published yet. The changelog fills in from the project's GitHub releases as soon as the first one is out." />
          {state.kind === "ready" && releases.length > 0 && visible.length === 0 && <p className="text-muted">No release matches this filter.</p>}
          <ol ref={list} className="relative">
            {visible.map((r) => (
              <Entry
                key={r.version}
                release={r}
                latest={r === latest}
                filter={filter}
                open={isOpen(r)}
                onToggle={() => {
                  const n = new Set(openSet);
                  if (n.has(r.version)) n.delete(r.version);
                  else n.add(r.version);
                  setOpen(n);
                }}
              />
            ))}
          </ol>
        </div>
      </main>
      <Footer version={latest?.version ?? null} />
    </>
  );
}
