import { Button } from "@heroui/react";
import { ExternalLink, History, KeyRound, RefreshCw, Search, ShieldCheck, ShieldQuestion, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, QueryView } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { notify, openExternal } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { VtDetected, VtLookupResult, VtReport, VtStats } from "@/lib/types";
import { cn, debounce, formatDateTime, formatRelative } from "@/lib/utils";
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

function ReportView({ result, onRefresh, refreshing }: { result: VtLookupResult; onRefresh: () => void; refreshing: boolean }) {
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
            result.kind === "url" || result.kind === "file"
              ? "It has never been analysed. Cyber Hub does not submit URLs or upload files for scanning, so no analysis is started."
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

function labelOf(kind: VtLookupResult["kind"], hashType: string | null): string {
  if (kind === "file") return `File hash${hashType ? ` (${hashType})` : ""}`;
  return { ip: "IP address", domain: "Domain", url: "URL" }[kind];
}

export default function VirusTotalPage() {
  const { runtime, navigate, route } = useApp();
  const keyStatus = useQuery(["vt"], api.vtKeyStatus, [], runtime);
  const recent = useQuery(["vt"], () => api.vtRecent(25), [], runtime);
  const confirm = useConfirm();

  const [query, setQuery] = useState(route.params?.q ?? "");
  const [detected, setDetected] = useState<{ ok: VtDetected | null; error: string | null }>({ ok: null, error: null });
  const [result, setResult] = useState<VtLookupResult | null>(null);
  const [error, setError] = useState<{ message: string; kind?: string } | null>(null);
  const [loading, setLoading] = useState<"lookup" | "refresh" | null>(null);

  const detect = useMemo(
    () =>
      debounce((q: string) => {
        if (!q.trim()) return setDetected({ ok: null, error: null });
        api
          .vtDetect(q)
          .then((ok) => setDetected({ ok, error: null }))
          .catch((e) => setDetected({ ok: null, error: errorMessage(e) }));
      }, 250),
    [],
  );
  useEffect(() => {
    if (runtime) detect(query);
  }, [query, runtime, detect]);

  const lookup = async (q: string, refresh = false) => {
    if (!q.trim()) return;
    setLoading(refresh ? "refresh" : "lookup");
    setError(null);
    try {
      const r = await api.vtLookup(q, refresh);
      setResult(r);
      if (r.source === "live") invalidate("vt", "activity");
    } catch (e) {
      setError({ message: errorMessage(e), kind: (e as { kind?: string }).kind });
    } finally {
      setLoading(null);
    }
  };

  const hasKey = keyStatus.data === true;

  return (
    <div>
      <PageHeader
        title="VirusTotal"
        description="Reputation lookups for public IP addresses, domains, URLs and file hashes. Lookups only read existing VirusTotal records — Cyber Hub never uploads files or submits URLs for scanning."
      />

      {keyStatus.data === false && (
        <EmptyBlock
          className="mb-3"
          icon={KeyRound}
          title="Add a VirusTotal API key to start"
          description="The key is stored in your operating system's credential store and used only by the Cyber Hub backend. It is never shown again after saving."
          action={
            <Button size="sm" variant="primary" onPress={() => navigate("settings")}>
              Open Settings
            </Button>
          }
        />
      )}
      {keyStatus.error && <ErrorBlock className="mb-3" message={keyStatus.error} />}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_340px]">
        <div className="flex min-w-0 flex-col gap-3">
          <Panel>
            <div className="flex flex-wrap items-end gap-2">
              <TextInput
                aria-label="Indicator"
                value={query}
                onChange={setQuery}
                placeholder="8.8.8.8, example.com, https://example.com/page or a file hash"
                className="min-w-[280px] flex-1"
                mono
                autoFocus
                onEnter={() => hasKey && detected.ok && lookup(query)}
              />
              <Button variant="primary" isDisabled={!hasKey || !detected.ok || !!loading} isPending={loading === "lookup"} onPress={() => lookup(query)}>
                <Search className="size-3.5" />
                Look up
              </Button>
            </div>
            <div className="mt-2 flex min-h-5 flex-wrap items-center gap-2 text-[12.5px]">
              {detected.ok ? (
                <>
                  <ToneChip tone="accent" dot={false}>
                    {labelOf(detected.ok.kind, detected.ok.hashType)}
                  </ToneChip>
                  <span className="text-muted">The indicator is sent to VirusTotal when you press Look up.</span>
                </>
              ) : detected.error && query.trim() ? (
                <span className="text-warning-soft-foreground">{detected.error}</span>
              ) : (
                <span className="text-muted">The type is detected automatically. Private addresses and internal host names are never sent.</span>
              )}
            </div>
          </Panel>

          {loading === "lookup" && !result && <InlineSpinner label="Looking up…" />}
          {error && (
            <ErrorBlock
              message={error.message}
              onRetry={error.kind === "validation" ? undefined : () => lookup(query, true)}
            />
          )}
          {result ? (
            <ReportView result={result} refreshing={loading === "refresh"} onRefresh={() => lookup(result.indicator, true)} />
          ) : (
            !error &&
            hasKey && (
              <EmptyBlock
                icon={ShieldCheck}
                title="Look up an indicator"
                description="Results show vendor verdicts, reputation, analysis statistics and threat details. They are cached locally for 24 hours; refresh any time."
              />
            )
          )}
        </div>

        <Panel
          title="Recent lookups"
          description="Cached locally"
          actions={
            <Button
              size="sm"
              variant="ghost"
              isDisabled={!recent.data?.length}
              onPress={async () => {
                if (await confirm.ask({ title: "Clear VirusTotal cache?", body: "Cached reports and the recent lookups list are deleted. Your API key is kept.", confirmLabel: "Clear cache" })) {
                  await api.vtCacheClear().catch((e) => notify.error("Could not clear the cache", e));
                  invalidate("vt");
                  setResult(null);
                }
              }}
            >
              <Trash2 className="size-3.5" />
              Clear
            </Button>
          }
          contentClassName="px-2 pb-2"
        >
          <QueryView query={recent} rows={4} isEmpty={(d) => d.length === 0} empty={<EmptyBlock compact icon={History} title="No lookups yet" />}>
            {(items) => (
              <ul className="flex flex-col gap-0.5">
                {items.map((it) => {
                  const tone = it.notFound ? "default" : (it.malicious ?? 0) > 0 ? "danger" : (it.suspicious ?? 0) > 0 ? "warning" : "success";
                  return (
                    <li key={`${it.kind}:${it.indicator}`}>
                      <button
                        type="button"
                        onClick={() => {
                          setQuery(it.indicator);
                          lookup(it.indicator);
                        }}
                        className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left outline-none transition-colors hover:bg-white/[0.03] focus-visible:ring-2 focus-visible:ring-focus"
                      >
                        <StatusDot tone={tone} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-mono text-[12.5px]">{it.indicator}</div>
                          <div className="text-[11.5px] text-muted">
                            {it.notFound ? "No record" : `${it.malicious ?? 0}/${it.enginesTotal ?? 0} malicious`} · {formatRelative(it.fetchedAt)}
                            {!it.fresh && " · stale"}
                          </div>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </QueryView>
        </Panel>
      </div>
      {confirm.element}
    </div>
  );
}
