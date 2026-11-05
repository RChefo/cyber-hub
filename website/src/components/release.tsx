// Release UI shared by the landing page, /changelog, /download and /download/archive.
import { useEffect, useState } from "react";
import { copyText } from "../lib/clipboard";
import { config, repoLinks } from "../lib/config";
import type { Block, Inline } from "../lib/notes";
import type { ReleasesState } from "../lib/releaseStore";
import { CATEGORY_LABEL, type Category, FORMAT_LABEL, formatSize, integrityOf, OS_LABEL, type Release, type ReleaseAsset, verifyCommands } from "../lib/releases";

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 1800);
    return () => clearTimeout(t);
  }, [state]);
  return (
    <button
      type="button"
      onClick={async () => setState((await copyText(text)) ? "copied" : "failed")}
      className="shrink-0 rounded-md bg-white/[0.06] px-2.5 py-1 text-[0.8rem] text-ink transition-colors hover:bg-white/[0.1]"
      aria-label={`${label}: ${text.length > 40 ? "value" : text}`}
    >
      <span aria-live="polite">{state === "copied" ? "Copied ✓" : state === "failed" ? "Copy failed" : label}</span>
    </button>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <span aria-hidden="true" className={`block animate-pulse rounded-md bg-white/[0.06] motion-reduce:animate-none ${className}`} />;
}

const CATEGORY_TONE: Record<Category, string> = {
  features: "bg-accent/15 text-accent-soft",
  improvements: "bg-white/[0.07] text-ink/85",
  fixes: "bg-ok/15 text-[#7fd3b3]",
  security: "bg-warn/15 text-[#f1c779]",
  other: "bg-white/[0.05] text-muted",
};

export function CategoryTag({ category }: { category: Category }) {
  return <span className={`inline-block shrink-0 rounded-md px-2 py-0.5 text-[0.74rem] font-medium ${CATEGORY_TONE[category]}`}>{CATEGORY_LABEL[category]}</span>;
}

export function ChannelTag({ release, latest }: { release: Release; latest: boolean }) {
  if (release.channel === "prerelease") return <span className="rounded-md bg-warn/15 px-2 py-0.5 text-[0.74rem] font-medium text-[#f1c779]">Pre-release</span>;
  if (latest) return <span className="rounded-md bg-ok/15 px-2 py-0.5 text-[0.74rem] font-medium text-[#7fd3b3]">Latest stable</span>;
  return <span className="rounded-md bg-white/[0.06] px-2 py-0.5 text-[0.74rem] font-medium text-muted">Stable</span>;
}

export function InlineText({ v }: { v: Inline[] }) {
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

export function NoteBlocks({ blocks }: { blocks: Block[] }) {
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

/** Loading, not configured, empty and error states shared by every release view. */
export function ReleaseStateNotice({ state, empty }: { state: ReleasesState & { retry: () => void }; empty: string }) {
  const links = repoLinks(config.repository);
  if (state.kind === "loading")
    return (
      <div className="space-y-3" aria-busy="true" aria-label="Loading releases">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-4 w-80 max-w-full" />
        <Skeleton className="h-4 w-64 max-w-full" />
      </div>
    );
  if (state.kind === "error")
    return (
      <div role="alert" className="rounded-[12px] bg-warn/10 px-5 py-4 text-[0.95rem] text-[#f1c779]">
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
  if (state.kind === "not-configured" || (state.kind === "ready" && !state.releases.length))
    return <p className="max-w-[62ch] rounded-[12px] bg-surface px-5 py-4 text-[0.95rem] leading-relaxed text-muted">{empty}</p>;
  return null;
}

/**
 * Integrity information for one artifact. The SHA-256 shown is GitHub's digest of the published
 * file; this page never computes or checks anything itself. The updater signature is a separate
 * mechanism verified by the installed app.
 */
export function Verification({ release, asset, compact = false }: { release: Release; asset: ReleaseAsset; compact?: boolean }) {
  const integrity = integrityOf(asset);
  return (
    <div className="space-y-4 text-[0.92rem]">
      <dl className="grid grid-cols-[8.5rem_minmax(0,1fr)] gap-x-4 gap-y-1.5">
        <dt className="text-faint">File</dt>
        <dd className="font-mono text-[0.82rem] break-all text-ink">{asset.name}</dd>
        <dt className="text-faint">Package</dt>
        <dd>{FORMAT_LABEL[asset.format]}</dd>
        <dt className="text-faint">Platform</dt>
        <dd>
          {OS_LABEL[asset.os]} {asset.arch}
        </dd>
        <dt className="text-faint">Version</dt>
        <dd>{release.version}</dd>
        <dt className="text-faint">Size</dt>
        <dd>{formatSize(asset.size)}</dd>
      </dl>

      <div>
        <h4 className="text-[0.92rem] font-medium text-ink">SHA-256 checksum</h4>
        {integrity === "checksum" ? (
          <>
            <div className="mt-2 flex items-start gap-2 rounded-[8px] bg-base px-3 py-2.5">
              <code className="min-w-0 flex-1 font-mono text-[0.8rem] leading-relaxed break-all text-ink" data-sha256>
                {asset.sha256}
              </code>
              <CopyButton text={asset.sha256!} label="Copy" />
            </div>
            <p className="mt-2 leading-relaxed text-muted">Published by GitHub for this file. After downloading, hash your copy and compare:</p>
            {verifyCommands(asset).map((c) => (
              <div key={c.shell} className="mt-2">
                <div className="text-[0.8rem] text-faint">{c.shell}</div>
                <div className="mt-1 flex items-start gap-2 rounded-[8px] bg-base px-3 py-2.5">
                  <code className="min-w-0 flex-1 font-mono text-[0.8rem] break-all text-ink">{c.command}</code>
                  <CopyButton text={c.command} />
                </div>
              </div>
            ))}
            {!compact && <p className="mt-2 text-muted">The two values must be identical. If they differ, delete the file and do not run it.</p>}
          </>
        ) : (
          <p className="mt-2 leading-relaxed text-muted">
            This file has no checksum in the release information.
            {release.checksumsUrl ? (
              <>
                {" "}Compare against the{" "}
                <a className="text-accent-soft hover:underline" href={release.checksumsUrl}>
                  SHA256SUMS.txt
                </a>{" "}
                published with the release.
              </>
            ) : (
              " No checksum file was published with this release either, so it cannot be checked against a published value."
            )}
          </p>
        )}
      </div>

      {!compact && (
        <div>
          <h4 className="text-[0.92rem] font-medium text-ink">Update signature</h4>
          <p className="mt-2 leading-relaxed text-muted">
            {asset.signatureUrl ? (
              <>
                A Tauri updater signature (
                <a className="text-accent-soft hover:underline" href={asset.signatureUrl}>
                  {asset.name}.sig
                </a>
                ) is published for this package. It is verified by Cyber Hub itself, with the public key built into the app, when it installs an update. This page does not check it.
              </>
            ) : (
              "No updater signature is published for this package. Installed copies of Cyber Hub verify updater signatures themselves during an update; this page does not."
            )}
          </p>
        </div>
      )}
    </div>
  );
}
