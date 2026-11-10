import { Button, Tabs } from "@heroui/react";
import {
  Bookmark,
  BookmarkCheck,
  ChevronDown,
  Columns3,
  Download,
  ExternalLink,
  History,
  Info,
  LayoutGrid,
  Link2,
  Radar,
  RefreshCw,
  FileDown,
  Search,
  Settings2,
  Trash2,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify, openExternal } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { TiInvestigation, TiProviderResult, TiProviderStatus, TiSavedIndicator, TiSavedStatus, TiSummary, VtDetected } from "@/lib/types";
import { cn, debounce, formatRelative } from "@/lib/utils";
import { availability, compareRows, correlate, LEVEL_META, parseConfidence, RELIABILITY, savedStanding, sortResults, STATUS_META, summaryParts } from "./model";
import { TaxiiFeeds } from "./TaxiiFeeds";

const KIND_LABEL: Record<string, string> = { ip: "IP address", domain: "Domain", url: "URL", file: "File hash" };

/** The saved indicators, searched and paged by the backend, 100 more at a time: a TAXII feed can
 * save 100,000, and sending all of them after every lookup took about 1.7 s and 28.7 MB of JSON
 * (measured in Mission 7). */
function SavedIndicatorsPanel({ onPivot, onEdit, onExportStix }: { onPivot: (value: string) => void; onEdit: (item: TiSavedIndicator) => void; onExportStix: () => void }) {
  const { runtime } = useApp();
  const [query, setQuery] = useState("");
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState(100);
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(query.trim());
      setLimit(100);
    }, 250);
    return () => clearTimeout(t);
  }, [query]);
  const saved = useQuery(["ti"], () => api.tiSavedList(q, limit), [q, limit], runtime);
  const total = saved.data?.total ?? 0;
  return (
    <Panel
      title="Saved indicators"
      contentClassName="px-2 pb-2"
      actions={
        total > 0 ? (
          <Button size="sm" variant="ghost" className="h-7" onPress={onExportStix} aria-label="Export saved indicators as STIX 2.1">
            <FileDown className="size-3.5" />
            STIX 2.1
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-1.5">
        {(total > 10 || query) && <SearchInput value={query} onChange={setQuery} placeholder={`Search ${total.toLocaleString()} indicators`} />}
        <QueryView query={saved} rows={3} isEmpty={(d) => d.total === 0} empty={<EmptyBlock compact icon={Bookmark} title="Nothing saved yet" />}>
          {(page) =>
            page.items.length === 0 ? (
              <p className="px-2.5 py-2 text-[12.5px] text-muted">No saved indicator matches “{q}”.</p>
            ) : (
              <>
                <ul className="flex flex-col gap-0.5">
                  {page.items.map((it) => {
                    const standing = savedStanding(it);
                    return (
                      <li key={it.id} className="flex items-start gap-1">
                        <button type="button" onClick={() => onPivot(it.indicator)} className="flex min-w-0 flex-1 flex-col rounded-lg px-2.5 py-2 text-left outline-none hover:bg-white/[0.03] focus-visible:ring-2 focus-visible:ring-focus">
                          <span className={cn("truncate font-mono text-[12.5px]", it.effective !== "active" && "text-muted line-through decoration-white/30")}>{it.indicator}</span>
                          <span className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-muted">
                            <ToneChip tone={standing.tone} dot={false} className="text-[10.5px]">
                              {standing.label}
                            </ToneChip>
                            {it.confidence != null && <span>confidence {it.confidence} ({it.confidenceLabel})</span>}
                            {it.source && <span className="truncate">from {it.source}{it.reliability ? ` (${it.reliability})` : ""}</span>}
                            <span>
                              {KIND_LABEL[it.kind]} · saved {formatRelative(it.createdAt)}
                            </span>
                          </span>
                        </button>
                        <Button size="sm" variant="ghost" className="mt-1 h-7" aria-label={`Edit ${it.indicator}`} onPress={() => onEdit(it)}>
                          Edit
                        </Button>
                      </li>
                    );
                  })}
                </ul>
                {page.matching > page.items.length && (
                  <div className="flex flex-wrap items-center justify-between gap-2 px-2.5 text-[12px] text-muted">
                    <span>
                      Showing {page.items.length.toLocaleString()} of {page.matching.toLocaleString()}
                    </span>
                    <Button size="sm" variant="ghost" onPress={() => setLimit((l) => l + 100)}>
                      Show {Math.min(100, page.matching - page.items.length).toLocaleString()} more
                    </Button>
                  </div>
                )}
              </>
            )
          }
        </QueryView>
      </div>
    </Panel>
  );
}

function SummaryStrip({ summary }: { summary: TiSummary }) {
  const parts = summaryParts(summary);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-x-5 gap-y-2">
        {parts.map((p) => (
          <div key={p.key} className="flex items-center gap-2 text-[13px]">
            <StatusDot tone={p.tone} />
            <span className="text-muted">{p.label}:</span>
            <span>{p.providers.join(", ")}</span>
          </div>
        ))}
      </div>
      <p className="flex items-start gap-1.5 text-[12px] text-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" />
        Each provider's verdict is shown in its own terms. Cyber Hub only groups providers by what they reported; it does not compute a combined score. AbuseIPDB, OTX and VirusTotal buckets are explained on each card.
      </p>
    </div>
  );
}

const LEVEL_HELP: Record<string, string> = {
  virustotal: "Malicious if any engine flags it as malicious, suspicious if any flags it as suspicious.",
  abuseipdb: "Bucketed by abuse confidence: 75%+ malicious, 25–74% suspicious; lower scores are shown without a verdict.",
  otx: "OTX gives no verdict; being referenced in community pulses is shown as suspicious.",
  urlhaus: "URLhaus lists malware distribution URLs; a host with no online URLs is shown as suspicious.",
  malwarebazaar: "MalwareBazaar contains malware samples only.",
  threatfox: "ThreatFox lists indicators of compromise linked to malware.",
  shodan: "Shodan describes exposure, not maliciousness.",
};

function ProviderCard({ r, onPivot }: { r: TiProviderResult; onPivot: (v: string) => void }) {
  const [open, setOpen] = useState(false);
  const rep = r.report;
  const level = rep?.verdict?.level;
  const tone = r.status === "found" && level ? LEVEL_META[level].tone : STATUS_META[r.status].tone;
  const muted = r.status !== "found";
  return (
    <section className={cn("tile flex flex-col gap-3 p-4", muted && "opacity-90")} aria-label={r.providerName}>
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[14px] font-semibold">{r.providerName}</h3>
            <ToneChip tone={tone}>{r.status === "found" && level ? LEVEL_META[level].label : STATUS_META[r.status].label}</ToneChip>
          </div>
          {rep?.verdict && <p className="mt-1 text-[13px]">{rep.verdict.label}</p>}
          {r.message && <p className={cn("mt-1 text-[12.5px]", r.status === "error" ? "text-danger-soft-foreground" : "text-muted")}>{r.message}</p>}
        </div>
        {rep?.permalink && (
          <Button size="sm" variant="ghost" onPress={() => openExternal(rep.permalink!)}>
            <ExternalLink className="size-3.5" />
            Open
          </Button>
        )}
      </header>

      {rep && rep.scores.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {rep.scores.map((s) => (
            <div key={s.label} className="rounded-lg bg-white/[0.03] px-2.5 py-1.5">
              <div className="text-[11.5px] text-muted">{s.label}</div>
              <div className="tabular text-[15px] font-semibold">{s.display}</div>
            </div>
          ))}
        </div>
      )}

      {rep && (rep.families.length > 0 || rep.categories.length > 0 || rep.tags.length > 0) && (
        <div className="flex flex-col gap-1.5 text-[12.5px]">
          {[
            ["Malware families", rep.families, "bg-danger-soft text-danger-soft-foreground"],
            ["Categories", rep.categories, "bg-accent-soft text-accent-soft-foreground"],
            ["Tags", rep.tags, "bg-white/[0.05] text-muted"],
          ].map(([label, list, cls]) =>
            (list as string[]).length ? (
              <div key={label as string} className="flex flex-wrap items-center gap-1">
                <span className="mr-1 text-muted">{label as string}</span>
                {(list as string[]).slice(0, 12).map((x) => (
                  <span key={x} className={cn("rounded-md px-1.5 py-0.5 text-[11.5px]", cls as string)}>
                    {x}
                  </span>
                ))}
                {(list as string[]).length > 12 && <span className="text-[11.5px] text-muted">+{(list as string[]).length - 12}</span>}
              </div>
            ) : null,
          )}
        </div>
      )}

      {rep && (rep.firstSeen || rep.lastSeen) && (
        <div className="flex flex-wrap gap-x-5 text-[12.5px]">
          {rep.firstSeen && (
            <span>
              <span className="text-muted">First seen </span>
              {rep.firstSeen}
            </span>
          )}
          {rep.lastSeen && (
            <span>
              <span className="text-muted">Last seen </span>
              {rep.lastSeen}
            </span>
          )}
        </div>
      )}

      {rep && (rep.facts.length > 0 || rep.tables.length > 0) && (
        <div>
          <Button size="sm" variant="ghost" onPress={() => setOpen((o) => !o)} aria-expanded={open}>
            <ChevronDown className={cn("size-3.5 transition-transform", open && "rotate-180")} />
            {open ? "Hide details" : `Details${rep.tables.length ? ` (${rep.tables.map((t) => t.title.toLowerCase()).join(", ")})` : ""}`}
          </Button>
          {open && (
            <div className="mt-2 flex flex-col gap-3">
              {rep.facts.length > 0 && (
                <dl className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-1 text-[12.5px]">
                  {rep.facts.map((f) => (
                    <div key={f.label} className="contents">
                      <dt className="text-muted">{f.label}</dt>
                      <dd className="min-w-0 break-words" data-selectable>
                        {f.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
              {rep.tables.map((t) => (
                <div key={t.title} className="min-w-0">
                  <div className="mb-1 text-[12.5px] font-medium">{t.title}</div>
                  <div className="scroll-area max-h-[260px] overflow-auto rounded-lg bg-white/[0.02]">
                    <table className="w-full text-left text-[12px]">
                      <thead className="sticky top-0 bg-surface-secondary text-muted">
                        <tr>
                          {t.columns.map((c) => (
                            <th key={c} className="px-2.5 py-1.5 font-medium">
                              {c}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {t.rows.map((row, i) => (
                          <tr key={i} className="align-top odd:bg-white/[0.015]">
                            {row.map((c, j) => (
                              <td key={j} className="max-w-[320px] break-words px-2.5 py-1.5" data-selectable>
                                {c || "—"}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {t.note && <p className="mt-1 text-[11.5px] text-muted">{t.note}</p>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {rep && rep.related.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 text-[12px]">
          <span className="mr-1 text-muted">Related</span>
          {rep.related.slice(0, 6).map((x) => (
            <button
              key={x.value}
              type="button"
              title={`${x.relation} — look it up`}
              onClick={() => onPivot(x.value)}
              className="max-w-[260px] truncate rounded-md bg-white/[0.04] px-1.5 py-0.5 font-mono text-[11.5px] outline-none hover:bg-white/[0.08] focus-visible:ring-2 focus-visible:ring-focus"
            >
              {x.value}
            </button>
          ))}
          {rep.related.length > 6 && <span className="text-muted">+{rep.related.length - 6} in Related indicators</span>}
        </div>
      )}

      <footer className="mt-auto flex flex-wrap gap-x-3 text-[11.5px] text-muted">
        {r.fetchedAt && (
          <span>
            {r.source === "cache" ? "Cached" : "Fetched"} {formatRelative(r.fetchedAt)}
          </span>
        )}
        {r.quota && <span>{r.quota}</span>}
        {r.status === "found" && LEVEL_HELP[r.provider] && <span>{LEVEL_HELP[r.provider]}</span>}
      </footer>
    </section>
  );
}

function CompareView({ results }: { results: TiProviderResult[] }) {
  const { providers, rows } = compareRows(results);
  if (providers.length === 0) return <EmptyBlock compact icon={Columns3} title="No provider returned data to compare" />;
  return (
    <div className="scroll-area overflow-x-auto rounded-xl bg-white/[0.02]">
      <table className="w-full min-w-[640px] text-left text-[12.5px]">
        <thead>
          <tr className="text-muted">
            <th className="w-[170px] px-3 py-2 font-medium" />
            {providers.map((p) => (
              <th key={p} className="px-3 py-2 font-semibold text-foreground">
                {p}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label} className="align-top odd:bg-white/[0.015]">
              <th scope="row" className="px-3 py-2 font-normal text-muted">
                {row.label}
              </th>
              {row.cells.map((c, i) => (
                <td key={i} className="max-w-[280px] break-words px-3 py-2" data-selectable>
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="px-3 py-2 text-[11.5px] text-muted">Values are shown exactly as each provider reports them; scales differ between providers and are not converted.</p>
    </div>
  );
}

function ProviderPicker({ providers, selected, onToggle, kind }: { providers: TiProviderStatus[]; selected: Set<string>; onToggle: (id: string) => void; kind: string | null }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {providers.map((p) => {
        const applicable = !kind || p.kinds.includes(kind as never);
        const usable = p.enabled && p.configured;
        const on = selected.has(p.id) && usable;
        const reason = !p.enabled ? "off" : !p.configured ? "not configured" : !applicable ? "n/a" : null;
        return (
          <button
            key={p.id}
            type="button"
            aria-pressed={on}
            disabled={!usable}
            onClick={() => onToggle(p.id)}
            title={!p.enabled ? "Turned off in Settings" : !p.configured ? "Unavailable: not configured by the application owner" : !applicable ? `${p.name} does not look up this type` : on ? "Click to skip" : "Click to include"}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[12.5px] outline-none transition-colors focus-visible:ring-2 focus-visible:ring-focus",
              on && applicable ? "bg-accent-soft text-accent-soft-foreground" : "bg-white/[0.04] text-muted",
              usable ? "hover:bg-white/[0.08]" : "cursor-not-allowed opacity-60",
            )}
          >
            {p.name}
            {reason && <span className="text-[11px] opacity-80">({reason})</span>}
          </button>
        );
      })}
    </div>
  );
}

/** The lifecycle of a saved indicator: where it came from and how reliable that source is, how
 * confident the analyst is, until when it is valid, and whether it was revoked or is a false
 * positive; every change is kept in its history. */
function SavedEditor({ item, onClose }: { item: TiSavedIndicator; onClose: () => void }) {
  const { runtime } = useApp();
  const history = useQuery(["ti"], () => api.tiSavedHistory(item.id), [item.id], runtime);
  const [note, setNote] = useState(item.note);
  const [source, setSource] = useState(item.source);
  const [reliability, setReliability] = useState(item.reliability || "none");
  const [confidence, setConfidence] = useState(item.confidence == null ? "" : String(item.confidence));
  const [validUntil, setValidUntil] = useState(item.validUntil ?? "");
  const [status, setStatus] = useState<TiSavedStatus>(item.status);
  const [saving, setSaving] = useState(false);
  const conf = parseConfidence(confidence);
  const dateOk = !validUntil.trim() || /^\d{4}-\d{2}-\d{2}$/.test(validUntil.trim());
  const save = async () => {
    if (conf == null || !dateOk) return;
    setSaving(true);
    try {
      await api.tiSavedUpdate(item.id, { note, source, reliability: reliability === "none" ? "" : reliability, confidence: conf, validUntil: validUntil.trim(), status });
      invalidate("ti");
      notify.success("Indicator updated", item.indicator);
      onClose();
    } catch (e) {
      notify.error("The indicator was not updated", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title={item.indicator}
      description={`Saved ${new Date(item.createdAt).toLocaleString()}. Expired, revoked and false-positive indicators stay saved for the record, but are not shown as current intelligence and are exported to STIX as such.`}
      footer={
        <div className="flex w-full justify-end gap-2">
          <Button size="sm" variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" onPress={() => void save()} isPending={saving} isDisabled={conf == null || !dateOk}>
            Save
          </Button>
        </div>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <TextInput label="Source" value={source} onChange={setSource} placeholder="Report, feed, case or colleague" />
        <SelectInput label="Source reliability" value={reliability} onChange={setReliability} options={[{ id: "none", label: "Not judged" }, ...RELIABILITY]} />
        <TextInput label="Confidence (0–100)" value={confidence} onChange={setConfidence} placeholder="Empty: not set" error={conf == null ? "A whole number from 0 to 100" : undefined} />
        <TextInput label="Valid until" value={validUntil} onChange={setValidUntil} placeholder="YYYY-MM-DD, empty: no expiry" error={dateOk ? undefined : "A date as YYYY-MM-DD"} />
        <SelectInput
          label="Status"
          value={status}
          onChange={(v) => setStatus(v as TiSavedStatus)}
          options={[
            { id: "active", label: "Active" },
            { id: "revoked", label: "Revoked (no longer valid)" },
            { id: "false_positive", label: "False positive" },
          ]}
        />
      </div>
      <TextAreaInput label="Note" value={note} onChange={setNote} rows={2} />
      <section className="flex flex-col gap-1 text-[12.5px]">
        <h3 className="font-medium">History</h3>
        {(history.data ?? []).length === 0 ? (
          <span className="text-muted">No change recorded yet (indicators saved before this version have no history).</span>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {(history.data ?? []).map((h, i) => (
              <li key={i} className="flex gap-2">
                <span className="w-28 shrink-0 text-muted">{formatRelative(h.at)}</span>
                <span>{h.action === "saved" ? "Saved" : h.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </AppModal>
  );
}

export default function ThreatIntelPage() {
  const { runtime, navigate, route } = useApp();
  const overview = useQuery(["ti"], api.tiProviders, [], runtime);
  const history = useQuery(["ti"], () => api.tiHistory(20), [], runtime);
  const exportStix = async () => {
    try {
      const r = await api.tiSavedExportStix();
      if (r) notify.success(`${r.exported} indicators exported as STIX 2.1`, r.skipped.length ? `${r.fileName}; not exportable: ${r.skipped.slice(0, 3).join(", ")}` : r.fileName);
    } catch (e) {
      notify.error("Could not export the indicators", e);
    }
  };
  const confirm = useConfirm();
  const [editing, setEditing] = useState<TiSavedIndicator | null>(null);

  const [query, setQuery] = useState(route.params?.q ?? "");
  const [detected, setDetected] = useState<{ ok: VtDetected | null; error: string | null }>({ ok: null, error: null });
  const [skipped, setSkipped] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<TiInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<"lookup" | "refresh" | null>(null);
  const [view, setView] = useState<string>("cards");

  const providers = overview.data?.providers ?? [];
  const selected = useMemo(() => new Set(providers.filter((p) => !skipped.has(p.id)).map((p) => p.id)), [providers, skipped]);
  const usable = providers.filter((p) => p.enabled && p.configured && selected.has(p.id) && (!detected.ok || p.kinds.includes(detected.ok.kind)));

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

  const run = async (q: string, refresh = false) => {
    if (!q.trim()) return;
    setLoading(refresh ? "refresh" : "lookup");
    setError(null);
    try {
      const ids = providers.filter((p) => selected.has(p.id)).map((p) => p.id);
      const r = await api.tiLookup(q, ids.length === providers.length ? null : ids, refresh);
      setResult(r);
      invalidate("ti", "vt", "activity");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(null);
    }
  };

  const pivot = (v: string) => {
    setQuery(v);
    run(v);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const toggleSave = async () => {
    if (!result) return;
    try {
      if (result.saved) await api.tiSavedRemove(result.indicator);
      else await api.tiSavedAdd(result.indicator, "");
      setResult({ ...result, saved: !result.saved });
      invalidate("ti");
    } catch (e) {
      notify.error("Could not update saved indicators", e);
    }
  };

  const exportReport = async (format: "md" | "json") => {
    if (!result) return;
    try {
      const name = await api.tiExport(result.indicator, format);
      if (name) notify.success(`Report saved as ${name}`);
    } catch (e) {
      notify.error("Could not export the report", e);
    }
  };

  const sorted = result ? sortResults(result.results) : [];
  const related = result ? correlate(result.results, result.indicator) : [];
  const noneConfigured = overview.data && !overview.data.providers.some((p) => p.configured);

  return (
    <div>
      <PageHeader
        title="Threat Intel"
        description="Look up an IP address, domain, URL or file hash across your configured intelligence providers. Each provider answers independently and keeps its own verdict."
        actions={
          <Button size="sm" variant="tertiary" onPress={() => navigate("settings")}>
            <Settings2 className="size-3.5" />
            Providers
          </Button>
        }
      />

      {noneConfigured && (
        <EmptyBlock
          className="mb-3"
          icon={Radar}
          title="Threat intelligence is not available on this installation"
          description="No intelligence provider has been configured. Provider credentials are provisioned by the application owner; there is nothing to set up here."
        />
      )}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_320px]">
        <div className="flex min-w-0 flex-col gap-3">
          <Panel>
            <div className="flex flex-wrap items-end gap-2">
              <TextInput
                aria-label="Indicator"
                value={query}
                onChange={setQuery}
                placeholder="IP address, domain, URL, or MD5 / SHA-1 / SHA-256 hash"
                className="min-w-[280px] flex-1"
                mono
                autoFocus
                onEnter={() => detected.ok && usable.length > 0 && run(query)}
              />
              <Button variant="primary" isDisabled={!detected.ok || usable.length === 0 || !!loading} isPending={loading === "lookup"} onPress={() => run(query)}>
                <Search className="size-3.5" />
                Look up
              </Button>
            </div>
            <div className="mt-2 flex min-h-5 flex-wrap items-center gap-2 text-[12.5px]">
              {detected.ok ? (
                <>
                  <ToneChip tone="accent" dot={false}>
                    {KIND_LABEL[detected.ok.kind]}
                    {detected.ok.hashType ? ` (${detected.ok.hashType})` : ""}
                  </ToneChip>
                  <span className="text-muted">
                    Sent to {usable.length ? usable.map((p) => p.name).join(", ") : "no provider"} when you press Look up. Nothing is submitted for scanning.
                  </span>
                </>
              ) : detected.error && query.trim() ? (
                <span className="text-warning-soft-foreground">{detected.error}</span>
              ) : (
                <span className="text-muted">The type is detected automatically. Private addresses and internal host names are never sent.</span>
              )}
            </div>
            {providers.length > 0 && (
              <div className="mt-3">
                <ProviderPicker
                  providers={providers}
                  selected={selected}
                  kind={detected.ok?.kind ?? null}
                  onToggle={(id) =>
                    setSkipped((s) => {
                      const n = new Set(s);
                      if (n.has(id)) n.delete(id);
                      else n.add(id);
                      return n;
                    })
                  }
                />
              </div>
            )}
          </Panel>

          {loading === "lookup" && !result && <InlineSpinner label="Asking providers…" />}
          {error && <ErrorBlock message={error} />}

          {result && (
            <>
              <Panel
                title={
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono text-[14px]" data-selectable title={result.indicator}>
                      {result.indicator}
                    </span>
                    <CopyButton text={result.indicator} label="Copy indicator" />
                  </span>
                }
                description={`${KIND_LABEL[result.kind]}${result.hashType ? ` (${result.hashType})` : ""} · searched ${formatRelative(result.searchedAt)}`}
                actions={
                  <div className="flex flex-wrap gap-1">
                    <Button size="sm" variant="ghost" onPress={toggleSave}>
                      {result.saved ? <BookmarkCheck className="size-3.5" /> : <Bookmark className="size-3.5" />}
                      {result.saved ? "Saved" : "Save"}
                    </Button>
                    <Button size="sm" variant="ghost" onPress={() => exportReport("md")}>
                      <Download className="size-3.5" />
                      Markdown
                    </Button>
                    <Button size="sm" variant="ghost" onPress={() => exportReport("json")}>
                      <Download className="size-3.5" />
                      JSON
                    </Button>
                    <Button size="sm" variant="ghost" isPending={loading === "refresh"} onPress={() => run(result.indicator, true)}>
                      <RefreshCw className="size-3.5" />
                      Refresh all
                    </Button>
                  </div>
                }
              >
                <SummaryStrip summary={result.summary} />
              </Panel>

              <Tabs selectedKey={view} onSelectionChange={(k) => setView(String(k))}>
                <Tabs.ListContainer>
                  <Tabs.List aria-label="Result view" className="h-9">
                    <Tabs.Tab id="cards" className="gap-1.5 px-3 text-[13px]">
                      <LayoutGrid className="size-3.5" />
                      By provider
                      <Tabs.Indicator />
                    </Tabs.Tab>
                    <Tabs.Tab id="compare" className="gap-1.5 px-3 text-[13px]">
                      <Columns3 className="size-3.5" />
                      Compare
                      <Tabs.Indicator />
                    </Tabs.Tab>
                    <Tabs.Tab id="related" className="gap-1.5 px-3 text-[13px]">
                      <Link2 className="size-3.5" />
                      Related indicators{related.length ? ` (${related.length})` : ""}
                      <Tabs.Indicator />
                    </Tabs.Tab>
                  </Tabs.List>
                </Tabs.ListContainer>
              </Tabs>

              {view === "cards" && (
                <div className="grid grid-cols-1 gap-3 2xl:grid-cols-2">
                  {sorted.map((r) => (
                    <ProviderCard key={r.provider} r={r} onPivot={pivot} />
                  ))}
                </div>
              )}
              {view === "compare" && <CompareView results={sorted} />}
              {view === "related" &&
                (related.length === 0 ? (
                  <EmptyBlock compact icon={Link2} title="No related indicators" description="None of the providers linked this indicator to other IPs, domains, URLs or hashes." />
                ) : (
                  <Panel description="Indicators that providers linked to this one. Select one to investigate it.">
                    <ul className="flex flex-col gap-1">
                      {related.map((x) => (
                        <li key={x.value}>
                          <button
                            type="button"
                            onClick={() => pivot(x.value)}
                            className="flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left outline-none hover:bg-white/[0.03] focus-visible:ring-2 focus-visible:ring-focus"
                          >
                            <ToneChip tone="default" dot={false}>
                              {KIND_LABEL[x.kind]}
                            </ToneChip>
                            <span className="min-w-0 flex-1 truncate font-mono text-[12.5px]">{x.value}</span>
                            <span className="shrink-0 text-[12px] text-muted">{x.sources.map((s) => `${s.provider}: ${s.relation}`).join(" · ")}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </Panel>
                ))}
            </>
          )}

          {!result && !loading && !error && !noneConfigured && (
            <EmptyBlock
              icon={Radar}
              title="Investigate an indicator"
              description="Results show which providers know the indicator, their verdicts and scores in their own terms, malware families, timestamps and related indicators you can pivot to."
            />
          )}
        </div>

        <div className="flex flex-col gap-3">
          <SavedIndicatorsPanel onPivot={pivot} onEdit={setEditing} onExportStix={() => void exportStix()} />

          {editing && <SavedEditor key={editing.id} item={editing} onClose={() => setEditing(null)} />}

          <Panel
            title="Recent searches"
            contentClassName="px-2 pb-2"
            actions={
              <Button
                size="sm"
                variant="ghost"
                isDisabled={!history.data?.length}
                onPress={async () => {
                  if (await confirm.ask({ title: "Clear threat-intel history?", body: "Removes the list of past searches. Cached provider results and saved indicators are kept.", confirmLabel: "Clear history" })) {
                    await api.tiHistoryClear().catch((e) => notify.error("Could not clear history", e));
                    invalidate("ti");
                  }
                }}
              >
                <Trash2 className="size-3.5" />
                Clear
              </Button>
            }
          >
            <QueryView query={history} rows={4} isEmpty={(d) => d.length === 0} empty={<EmptyBlock compact icon={History} title="No searches yet" />}>
              {(items) => (
                <ul className="flex flex-col gap-0.5">
                  {items.map((it) => {
                    const tone = it.summary.malicious.length ? "danger" : it.summary.suspicious.length ? "warning" : "default";
                    return (
                      <li key={it.id}>
                        <button type="button" onClick={() => pivot(it.indicator)} className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left outline-none hover:bg-white/[0.03] focus-visible:ring-2 focus-visible:ring-focus">
                          <StatusDot tone={tone} />
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-mono text-[12.5px]">{it.indicator}</div>
                            <div className="truncate text-[11.5px] text-muted">
                              {it.summary.malicious.length ? `${it.summary.malicious.length} malicious` : it.summary.suspicious.length ? `${it.summary.suspicious.length} suspicious` : "no detections"} · {formatRelative(it.searchedAt)}
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

          <TaxiiFeeds />

          <Panel title="Providers" description="Status of your integrations">
            <ul className="flex flex-col gap-1.5">
              {providers.map((p) => (
                <li key={p.id} className="flex items-center justify-between gap-2 text-[12.5px]">
                  <span className="flex items-center gap-2">
                    <StatusDot tone={availability(p).tone} />
                    {p.name}
                  </span>
                  <span className="text-muted">{availability(p).label}</span>
                </li>
              ))}
            </ul>
            <Button
              size="sm"
              variant="ghost"
              className="mt-3"
              onPress={async () => {
                if (await confirm.ask({ title: "Clear cached provider results?", body: "Cached results for AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan are deleted. VirusTotal's cache is managed on the VirusTotal page.", confirmLabel: "Clear cache" })) {
                  await api.tiCacheClear().catch((e) => notify.error("Could not clear the cache", e));
                  notify.success("Provider cache cleared");
                }
              }}
            >
              <Trash2 className="size-3.5" />
              Clear provider cache
            </Button>
          </Panel>
        </div>
      </div>
      {confirm.element}
    </div>
  );
}
