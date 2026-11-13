import { Button } from "@heroui/react";
import { ExternalLink, RefreshCw, ShieldCheck, ShieldQuestion } from "lucide-react";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock } from "@/components/ui/Feedback";
import { Panel } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { openExternal } from "@/lib/actions";
import type { VtLookupResult, VtReport, VtStats } from "@/lib/types";
import { cn, formatDateTime, formatRelative } from "@/lib/utils";
import { reputationTone, shares, verdictOf, type VerdictTone } from "./verdict";

const STAT_META: { key: keyof VtStats; label: string; tone: VerdictTone | "muted"; bar: string }[] = [
  { key: "malicious", label: "Malicious", tone: "danger", bar: "bg-sev-critical" },
  { key: "suspicious", label: "Suspicious", tone: "warning", bar: "bg-warning" },
  { key: "harmless", label: "Harmless", tone: "success", bar: "bg-success" },
  { key: "undetected", label: "Undetected", tone: "muted", bar: "bg-white/20" },
];

const TONE_TEXT: Record<VerdictTone | "muted", string> = {
  danger: "text-danger-soft-foreground",
  warning: "text-warning-soft-foreground",
  success: "text-success-soft-foreground",
  default: "text-foreground",
  muted: "text-muted",
};

function StatsBlock({ report }: { report: VtReport }) {
  const parts = shares(report.stats);
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {STAT_META.map((m) => (
          <div key={m.key} className="tile px-3 py-2.5">
            <div className="flex items-center gap-1.5 text-[12px] text-muted">
              <span className={cn("size-1.5 rounded-full", m.bar)} aria-hidden />
              {m.label}
            </div>
            <div className={cn("tabular mt-0.5 text-[20px] font-semibold tracking-tight", report.stats[m.key] > 0 ? TONE_TEXT[m.tone] : "text-muted")}>
              {report.stats[m.key]}
            </div>
          </div>
        ))}
      </div>
      {parts.length > 0 && (
        <div>
          <div className="flex h-2 gap-[2px] overflow-hidden rounded-full" role="img" aria-label={parts.map((p) => `${p.key} ${p.pct}%`).join(", ")}>
            {parts.map((p) => (
              <div key={p.key} className={cn("h-full first:rounded-l-full last:rounded-r-full", STAT_META.find((m) => m.key === p.key)!.bar)} style={{ width: `${p.pct}%` }} />
            ))}
          </div>
          <div className="mt-1.5 text-[12px] text-muted">
            {report.enginesTotal} engines in the last analysis
            {report.stats.timeout > 0 && ` · ${report.stats.timeout} timed out`}
          </div>
        </div>
      )}
    </div>
  );
}

export function ReportView({ result, onRefresh, refreshing }: { result: VtLookupResult; onRefresh: () => void; refreshing: boolean }) {
  const r = result.report;
  const source = (
    <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted">
      <ToneChip tone={result.source === "live" ? "accent" : "default"}>{result.source === "live" ? "Live from VirusTotal" : "From local cache"}</ToneChip>
      <span>
        fetched {formatRelative(result.fetchedAt)} · {result.source === "cache" ? `cached until ${formatDateTime(result.freshUntil)}` : `cached for later lookups`}
      </span>
      <Button size="sm" variant="ghost" isPending={refreshing} onPress={onRefresh}>
        <RefreshCw className="size-3.5" />
        Refresh from VirusTotal
      </Button>
    </div>
  );

  if (!r) {
    return (
      <Panel title={result.indicator} description={`${labelOf(result.kind, result.hashType)} · no VirusTotal record`}>
        <EmptyBlock
          icon={ShieldQuestion}
          title="VirusTotal has no record of this indicator"
          description={
            result.kind === "url"
              ? "It has never been analysed. ExploitX does not submit URLs for scanning, so no analysis is started."
              : result.kind === "file"
                ? "It has never been analysed. A hash lookup never uploads anything; a file is submitted only from File analysis after you confirm it."
                : "VirusTotal has no information about it yet."
          }
        />
        <div className="mt-3">{source}</div>
      </Panel>
    );
  }

  const verdict = verdictOf(r.stats, r.enginesTotal, r.kind);
  const repTone = reputationTone(r.reputation);
  return (
    <div className="flex flex-col gap-3">
      <Panel
        title={
          <span className="flex min-w-0 items-center gap-2">
            <span className="truncate font-mono text-[14px]" data-selectable title={r.indicator}>{r.indicator}</span>
            <CopyButton text={r.indicator} label="Copy indicator" />
          </span>
        }
        description={labelOf(result.kind, result.hashType)}
        actions={
          <Button size="sm" variant="tertiary" onPress={() => openExternal(r.permalink)}>
            <ExternalLink className="size-3.5" />
            Open on VirusTotal
          </Button>
        }
      >
        <div className="mb-4 flex items-start gap-3">
          <FeaturedIcon icon={ShieldCheck} size="md" color={verdict.tone === "danger" ? "error" : verdict.tone === "warning" ? "warning" : verdict.tone === "success" ? "success" : "gray"} />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={cn("text-[18px] font-semibold tracking-tight", TONE_TEXT[verdict.tone])}>{verdict.title}</span>
              {r.threatLabel && <ToneChip tone="danger">{r.threatLabel}</ToneChip>}
            </div>
            <p className="mt-0.5 text-[13px] text-muted">{verdict.summary}</p>
          </div>
        </div>
        <StatsBlock report={r} />
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 text-[13px] sm:grid-cols-3">
          <div>
            <dt className="text-[12px] text-muted">Reputation</dt>
            <dd className={cn("tabular flex items-center gap-1.5", TONE_TEXT[repTone])}>
              {r.reputation !== null && <StatusDot tone={repTone === "default" ? "default" : repTone} />}
              {r.reputation ?? "—"}
            </dd>
          </div>
          <div>
            <dt className="text-[12px] text-muted">Last analysis</dt>
            <dd>{r.lastAnalysisDate ? formatDateTime(new Date(r.lastAnalysisDate * 1000).toISOString()) : "Never analysed"}</dd>
          </div>
          <div>
            <dt className="text-[12px] text-muted">Community votes</dt>
            <dd className="tabular">
              {r.votesMalicious !== null || r.votesHarmless !== null ? `${r.votesMalicious ?? 0} malicious · ${r.votesHarmless ?? 0} harmless` : "—"}
            </dd>
          </div>
        </dl>
        <div className="mt-4">{source}</div>
      </Panel>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Panel title="Flagged by" description={r.flagged.length ? `${r.flagged.length} engines` : undefined}>
          {r.flagged.length === 0 ? (
            <p className="text-[13px] text-muted">No engine flagged this indicator in the last analysis.</p>
          ) : (
            <ul className="scroll-area flex max-h-[320px] flex-col gap-1">
              {r.flagged.map((f) => (
                <li key={f.engine} className="tile flex items-center gap-3 px-3 py-2 text-[13px]">
                  <span className="min-w-0 flex-1 truncate">{f.engine}</span>
                  <span className="min-w-0 truncate font-mono text-[12px] text-muted" title={f.result ?? ""}>{f.result ?? "—"}</span>
                  <ToneChip tone={f.category === "malicious" ? "danger" : "warning"}>{f.category === "malicious" ? "Malicious" : "Suspicious"}</ToneChip>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Details">
          {r.details.length === 0 && r.tags.length === 0 && r.categories.length === 0 ? (
            <p className="text-[13px] text-muted">VirusTotal returned no additional details.</p>
          ) : (
            <>
              <dl className="grid grid-cols-[130px_1fr] gap-x-4 gap-y-1.5 text-[13px]">
                {r.details.map((d) => (
                  <div key={d.label} className="contents">
                    <dt className="text-muted">{d.label}</dt>
                    <dd className="min-w-0 break-all" data-selectable>{d.value}</dd>
                  </div>
                ))}
              </dl>
              {(r.categories.length > 0 || r.tags.length > 0) && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {r.categories.map((c) => (
                    <span key={`c-${c}`} className="rounded-md bg-accent-soft px-1.5 py-0.5 text-[11.5px] text-accent-soft-foreground">{c}</span>
                  ))}
                  {r.tags.filter((t) => !r.categories.some((c) => c.toLowerCase() === t.toLowerCase())).map((t) => (
                    <span key={`t-${t}`} className="rounded-md bg-white/[0.05] px-1.5 py-0.5 text-[11.5px] text-muted">{t}</span>
                  ))}
                </div>
              )}
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}

export function labelOf(kind: VtLookupResult["kind"], hashType: string | null): string {
  if (kind === "file") return `File hash${hashType ? ` (${hashType})` : ""}`;
  return { ip: "IP address", domain: "Domain", url: "URL" }[kind];
}

