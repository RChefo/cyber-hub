import { Button, Tabs } from "@heroui/react";
import { Database, History, Radio, Search, ShieldAlert, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBarChart } from "@/components/charts/SeverityBarChart";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CveRecord, CveSearchResult, Severity } from "@/lib/types";
import { cn, formatDate, formatDateTime, formatNumber, formatRelative } from "@/lib/utils";
import { CveDetailModal } from "./CveDetail";
import { bestCvss, isCveId, severityOf } from "./cvss";

function ResultRow({ r, cachedAt, onOpen }: { r: CveRecord; cachedAt?: string; onOpen: () => void }) {
  const best = bestCvss(r);
  return (
    <li>
      <Button variant="ghost" onPress={onOpen} className="tile h-auto w-full flex-col items-stretch gap-1 px-3.5 py-3 text-left font-normal whitespace-normal hover:bg-white/[0.05]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[13px] font-medium text-foreground">{r.id}</span>
          <SeverityBadge severity={severityOf(best)} score={best?.score} />
          {best && <span className="text-[12px] text-muted">CVSS {best.version}</span>}
          {r.kev && <ToneChip tone="danger">CISA KEV</ToneChip>}
          <span className="ml-auto text-[12px] text-muted">
            Published {formatDate(r.published)}
            {cachedAt ? ` · cached ${formatRelative(cachedAt)}` : ""}
          </span>
        </div>
        <p className="line-clamp-2 text-[13px] text-muted">{r.description || "No description."}</p>
      </Button>
    </li>
  );
}

export default function IntelPage() {
  const { runtime, prefs, setPref } = useApp();
  const confirm = useConfirm();
  const live = prefs["cve.preferLive"] !== false;
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<CveSearchResult | null>(null);
  const [lastQuery, setLastQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);
  const [selected, setSelected] = useState<CveRecord | null>(null);

  const history = useQuery(["cve"], api.cveHistory, [], runtime);
  const stats = useQuery(["cve"], api.cveCacheStats, [], runtime);

  const run = async (q = query, useLive = live) => {
    const term = q.trim();
    if (!term) return;
    if (useLive && !isCveId(term) && term.length < 3) {
      setError("Keyword searches need at least 3 characters.");
      return;
    }
    setQuery(term);
    setSearching(true);
    setError(null);
    try {
      const res = await api.cveSearch(term, useLive);
      setResult(res);
      setLastQuery(term);
      invalidate("cve", "activity");
      if (res.records.length === 1 && isCveId(term)) setSelected(res.records[0]);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSearching(false);
    }
  };

  const cachedMap = useMemo(() => new Map(result?.cachedAt ?? []), [result]);
  const distribution = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    for (const r of result?.records ?? []) {
      const s = severityOf(bestCvss(r));
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [result]);

  const rateLimited = error?.toLowerCase().includes("rate limit");

  return (
    <div>
      <PageHeader
        title="Vulnerability intelligence"
        description="Search CVE records from the NIST National Vulnerability Database. Results are cached locally so you can search them offline later."
      />

      <div className="panel mb-3 p-4">
        <div className="flex flex-wrap items-start gap-3">
          <TextInput
            aria-label="CVE ID or keyword"
            value={query}
            onChange={setQuery}
            onEnter={() => run()}
            placeholder="CVE-2021-44228 or keywords like “apache struts”"
            mono
            className="min-w-[280px] flex-1"
            autoFocus
          />
          <Tabs selectedKey={live ? "live" : "cache"} onSelectionChange={(k) => setPref("cve.preferLive", k === "live")}>
            <Tabs.ListContainer>
              <Tabs.List aria-label="Data source" className="h-9">
                <Tabs.Tab id="live" className="gap-1.5 px-3 text-[13px]">
                  <Radio className="size-3.5" />
                  Live (NVD)
                  <Tabs.Indicator />
                </Tabs.Tab>
                <Tabs.Tab id="cache" className="gap-1.5 px-3 text-[13px]">
                  <Database className="size-3.5" />
                  Local cache
                  <Tabs.Indicator />
                </Tabs.Tab>
              </Tabs.List>
            </Tabs.ListContainer>
          </Tabs>
          <Button variant="primary" onPress={() => run()} isPending={searching} isDisabled={!runtime || !query.trim()}>
            <Search className="size-3.5" />
            Search
          </Button>
        </div>
        <p className="mt-2 text-[12.5px] text-muted">
          {live
            ? "Live mode sends your query to services.nvd.nist.gov. Without a provisioned NVD key, NVD allows about 5 requests per 30 seconds."
            : "Cache mode searches only CVE records already stored on this workstation. Nothing leaves your machine."}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <div className="xl:col-span-8">
          {error && (
            <div className="mb-3 flex flex-col gap-2">
              <ErrorBlock message={error} />
              {rateLimited && (
                <div className="flex gap-2">
                  <Button size="sm" variant="ghost" onPress={() => run(query, false)}>
                    Search the local cache instead
                  </Button>
                </div>
              )}
            </div>
          )}
          {searching && !result ? (
            <LoadingRows rows={5} />
          ) : !result ? (
            <EmptyBlock
              icon={ShieldAlert}
              title="Search for a vulnerability"
              description="Enter a CVE identifier for an exact record, or keywords to find matching CVEs. Data comes only from NVD or your local cache."
            />
          ) : (
            <Panel
              title={`${formatNumber(result.totalResults)} result${result.totalResults === 1 ? "" : "s"} for “${lastQuery}”`}
              description={
                result.source === "live"
                  ? `Live from NVD · fetched ${result.fetchedAt ? formatDateTime(result.fetchedAt) : "now"}${result.totalResults > result.records.length ? ` · showing the first ${result.records.length}` : ""}`
                  : "From the local cache · may be out of date; switch to live mode for current data"
              }
              actions={<ToneChip tone={result.source === "live" ? "accent" : "default"}>{result.source === "live" ? "Live data" : "Cached data"}</ToneChip>}
            >
              {result.records.length === 0 ? (
                <EmptyBlock
                  compact
                  icon={Search}
                  title="No matching CVE records"
                  description={result.source === "cache" ? "Nothing in the local cache matches. Try live mode." : "NVD returned no records for this query."}
                />
              ) : (
                <ul className={cn("flex flex-col gap-1.5", searching && "opacity-60")}>
                  {result.records.map((r) => (
                    <ResultRow key={r.id} r={r} cachedAt={cachedMap.get(r.id)} onOpen={() => setSelected(r)} />
                  ))}
                </ul>
              )}
            </Panel>
          )}
        </div>

        <div className="flex flex-col gap-3 xl:col-span-4">
          <Panel title="Severity of current results" description="Highest CVSS version available per record">
            {result && result.records.length > 0 ? (
              <SeverityBarChart counts={distribution} height={180} />
            ) : (
              <p className="text-[13px] text-muted">Run a search to see the distribution.</p>
            )}
          </Panel>

          <Panel
            title="Search history"
            actions={
              (history.data?.length ?? 0) > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  onPress={async () => {
                    if (!(await confirm.ask({ title: "Clear search history?", body: "Your CVE search history will be deleted. Cached CVE records are kept.", confirmLabel: "Clear history" }))) return;
                    try {
                      await api.cveHistoryClear();
                      invalidate("cve");
                    } catch (e) {
                      notify.error("Could not clear history", e);
                    }
                  }}
                >
                  <Trash2 className="size-3.5" />
                  Clear
                </Button>
              )
            }
          >
            {history.error && !history.data ? (
              <ErrorBlock message={history.error} onRetry={history.reload} />
            ) : !history.data ? (
              <LoadingRows rows={3} />
            ) : history.data.length === 0 ? (
              <EmptyBlock compact icon={History} title="No searches yet" />
            ) : (
              <ul className="flex flex-col gap-0.5">
                {history.data.slice(0, 15).map((h) => (
                  <li key={h.id}>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-auto w-full justify-between gap-2 px-2 py-1.5 text-left font-normal whitespace-normal"
                      onPress={() => {
                        setPref("cve.preferLive", h.live);
                        run(h.query, h.live);
                      }}
                    >
                      <span className="min-w-0 truncate font-mono text-[12.5px]">{h.query}</span>
                      <span className="shrink-0 text-[11.5px] text-muted">
                        {h.live ? "live" : "cache"} · {h.resultCount} · {formatRelative(h.createdAt)}
                      </span>
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Local cache">
            {stats.data ? (
              <div className="text-[13px]">
                <div className="flex justify-between">
                  <span className="text-muted">Cached records</span>
                  <span className="tabular">{formatNumber(stats.data[0])}</span>
                </div>
                <div className="mt-1 flex justify-between">
                  <span className="text-muted">Last fetched</span>
                  <span>{stats.data[1] ? formatRelative(stats.data[1]) : "never"}</span>
                </div>
                <p className="mt-2 text-[12px] text-muted">Every record fetched live is stored here, so it can be searched without a network connection.</p>
              </div>
            ) : stats.error ? (
              <ErrorBlock message={stats.error} />
            ) : (
              <LoadingRows rows={2} />
            )}
          </Panel>
        </div>
      </div>

      <CveDetailModal record={selected} cachedAt={selected ? cachedMap.get(selected.id) : undefined} onClose={() => setSelected(null)} />
      {confirm.element}
    </div>
  );
}
