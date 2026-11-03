import { Button, Tabs } from "@heroui/react";
import { FileSearch, History, KeyRound, Search, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, QueryView } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { VtDetected, VtLookupResult } from "@/lib/types";
import { debounce, formatRelative } from "@/lib/utils";
import { FileAnalysis } from "./FileAnalysis";
import { labelOf, ReportView } from "./ReportView";

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
  const [tab, setTab] = useState<string>(route.params?.tab === "file" ? "file" : "lookup");

  const detect = useMemo(
    () =>
      debounce((q: string) => {
        if (!q.trim()) return setDetected({ ok: null, error: null });
        api
          .tiDetect(q)
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
        description="Reputation lookups for public IP addresses, domains, URLs and file hashes, and optional file submission. Lookups only read existing records; a file is uploaded only after you confirm it in a system dialog."
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

      <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(String(k))} className="mb-3">
        <Tabs.ListContainer>
          <Tabs.List aria-label="VirusTotal mode" className="h-9">
            <Tabs.Tab id="lookup" className="gap-1.5 px-3 text-[13px]">
              <Search className="size-3.5" />
              Indicator lookup
              <Tabs.Indicator />
            </Tabs.Tab>
            <Tabs.Tab id="file" className="gap-1.5 px-3 text-[13px]">
              <FileSearch className="size-3.5" />
              File analysis
              <Tabs.Indicator />
            </Tabs.Tab>
          </Tabs.List>
        </Tabs.ListContainer>
      </Tabs>

      {tab === "file" ? (
        <FileAnalysis hasKey={hasKey} />
      ) : (
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
      )}
      {confirm.element}
    </div>
  );
}
