import { Button } from "@heroui/react";
import { ArrowRight, GitCompareArrows, Route, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { ExposurePathNode, IocIndicator, Project, RunDiff, SnapshotChanges } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { ASSET_TYPE_LABEL, CERTAINTY_META, SOURCE_LABEL } from "./asm";
import { PRIORITY_META } from "./vulns";

const NODE_TONE: Record<ExposurePathNode["kind"], string> = {
  entry: "bg-white/[0.06] text-muted",
  name: "bg-accent-soft text-accent-soft-foreground",
  ip: "bg-accent-soft text-accent-soft-foreground",
  service: "bg-white/[0.06] text-foreground",
  web: "bg-white/[0.06] text-foreground",
  vulnerability: "bg-danger-soft text-danger-soft-foreground",
  finding: "bg-warning-soft text-warning-soft-foreground",
};

const SOURCE_NAME: Record<string, string> = { asset: "Asset", scope: "Scope", finding: "Finding", osint: "OSINT", saved: "Saved indicator" };

function ExposurePaths({ projectId }: { projectId: number }) {
  const { runtime } = useApp();
  const q = useQuery(["assets", "vulns", "findings"], () => api.exposurePaths(projectId), [projectId], runtime);
  return (
    <Panel title="Exposure paths" description="How each open vulnerability or asset-linked finding is reached, highest priority first. Built from recorded assets, DNS and links; nothing is contacted.">
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <LoadingRows rows={3} />
      ) : q.data.length === 0 ? (
        <EmptyBlock compact icon={Route} title="No paths yet" description="Paths appear when vulnerabilities are tracked for assets, or findings are linked to assets." />
      ) : (
        <ol className="flex flex-col gap-1.5">
          {q.data.slice(0, 100).map((p, i) => (
            <li key={i} className="panel-inset flex flex-wrap items-center gap-1.5 px-3 py-2 text-[12.5px]">
              {p.priority ? <ToneChip tone={PRIORITY_META[p.priority].tone}>{PRIORITY_META[p.priority].label}</ToneChip> : <ToneChip tone="default">Finding</ToneChip>}
              {p.nodes.map((n, j) => (
                <span key={j} className="flex items-center gap-1.5">
                  {j > 0 && <ArrowRight className="size-3 text-muted" aria-hidden />}
                  <span className={cn("max-w-[260px] truncate rounded-md px-1.5 py-0.5", NODE_TONE[n.kind], (n.kind === "ip" || n.kind === "service" || n.kind === "web") && "font-mono text-[11.5px]")}>{n.label}</span>
                </span>
              ))}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

function IocCorrelation({ projectId }: { projectId: number }) {
  const { runtime } = useApp();
  const q = useQuery(["assets", "findings", "osint", "ti"], () => api.iocCorrelation(projectId), [projectId], runtime);
  const [filter, setFilter] = useState("correlated");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useMemo(
    () =>
      (q.data ?? []).filter(
        (i: IocIndicator) =>
          (filter === "all" || (filter === "flagged" ? i.flagged : i.sources > 1 || i.flagged || i.ti.length > 0)) && (!query.trim() || i.value.includes(query.trim().toLowerCase())),
      ),
    [q.data, filter, query],
  );
  return (
    <Panel
      title="Indicator correlation"
      description="Where each address, domain, e-mail and file hash of the project appears, with cached threat-intelligence results. Look up new indicators on the Threat Intel page."
      toolbar={
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput value={query} onChange={setQuery} placeholder="Search indicators" className="w-56" />
          <SelectInput
            aria-label="Show"
            value={filter}
            onChange={setFilter}
            options={[
              { id: "correlated", label: "Seen in several places or with intel" },
              { id: "flagged", label: "Flagged only" },
              { id: "all", label: "All indicators" },
            ]}
            className="w-72"
          />
        </div>
      }
    >
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <LoadingRows rows={4} />
      ) : list.length === 0 ? (
        <EmptyBlock compact icon={ShieldAlert} title="Nothing to correlate" description="Indicators appear from assets, the scope, findings and OSINT investigations linked to this project." />
      ) : (
        <ul className="flex flex-col gap-1">
          {list.slice(0, 500).map((i) => {
            const key = `${i.kind}:${i.value}`;
            return (
              <li key={key} className="panel-inset px-3 py-2 text-[12.5px]">
                <button type="button" className="flex w-full items-center gap-2 text-left focus-visible:outline-2 focus-visible:outline-accent" onClick={() => setOpen(open === key ? null : key)} aria-expanded={open === key}>
                  <span className="w-16 shrink-0 text-muted">{i.kind === "file_hash" ? "hash" : i.kind}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-foreground">{i.value}</span>
                  {i.flagged && <ToneChip tone="danger">Flagged</ToneChip>}
                  <span className="text-muted">{[...new Set(i.sightings.map((s) => SOURCE_NAME[s.source]))].join(", ")}</span>
                </button>
                {open === key && (
                  <div className="mt-2 flex flex-col gap-1 pl-[72px]">
                    {i.sightings.map((s, j) => (
                      <div key={j} className="text-muted">
                        <span className="text-foreground">{SOURCE_NAME[s.source]}</span> · {s.detail}
                      </div>
                    ))}
                    {i.ti.map((t, j) => (
                      <div key={`ti${j}`} className="text-muted">
                        <span className="text-foreground">{t.provider}</span> · {t.level}
                        {t.label ? ` (${t.label})` : ""} · {formatRelative(t.fetchedAt)}
                      </div>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function CompareRuns({ project }: { project: Project }) {
  const { runtime } = useApp();
  const snaps = useQuery(["assets"], () => api.discoverySnapshots(project.id, 200), [project.id], runtime);
  const runs = useQuery(["executions"], () => api.projectToolHistory(project.id), [project.id], runtime);
  const [kind, setKind] = useState<"discovery" | "tool">("discovery");
  const [from, setFrom] = useState<string | null>(null);
  const [to, setTo] = useState<string | null>(null);
  const [result, setResult] = useState<SnapshotChanges | RunDiff | null>(null);
  const [busy, setBusy] = useState(false);

  const options =
    kind === "discovery"
      ? (snaps.data ?? []).filter((s) => s.status !== "running").map((s) => ({ id: String(s.id), label: `#${s.id} ${SOURCE_LABEL[s.source] ?? s.source} · ${formatRelative(s.startedAt)} · ${s.assets} assets` }))
      : (runs.data ?? []).filter((r) => r.kind === "run" && r.status !== "running").map((r) => ({ id: String(r.id), label: `#${r.id} ${r.toolId} · ${formatRelative(r.startedAt)}` }));

  const compare = async () => {
    if (!from || !to) return;
    setBusy(true);
    try {
      const [a, b] = [Number(from), Number(to)].sort((x, y) => x - y);
      setResult(kind === "discovery" ? await api.discoveryCompare(a, b) : await api.runsCompare(a, b));
    } catch (e) {
      notify.error("Could not compare", e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Compare runs" description="Discovery runs are compared asset by asset; tool runs line by line (their stored output, credentials redacted).">
      <div className="grid grid-cols-1 items-end gap-3 md:grid-cols-[160px_1fr_1fr_auto]">
        <SelectInput
          label="Compare"
          value={kind}
          onChange={(v) => {
            setKind(v as "discovery" | "tool");
            setFrom(null);
            setTo(null);
            setResult(null);
          }}
          options={[
            { id: "discovery", label: "Discovery runs" },
            { id: "tool", label: "Tool runs" },
          ]}
        />
        <SelectInput label="Earlier run" value={from} onChange={setFrom} options={options} placeholder="Choose a run" />
        <SelectInput label="Later run" value={to} onChange={setTo} options={options} placeholder="Choose a run" />
        <Button variant="secondary" onPress={compare} isPending={busy} isDisabled={!from || !to || from === to}>
          <GitCompareArrows className="size-4" />
          Compare
        </Button>
      </div>
      {result && "changes" in result && (
        <div className="mt-3 flex flex-col gap-1">
          {result.changes.length === 0 ? (
            <p className="text-[12.5px] text-muted">The two runs recorded the same assets with the same data.</p>
          ) : (
            result.changes.slice(0, 500).map((c) => (
              <div key={`${c.change}-${c.assetId}`} className="panel-inset flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                <span className={cn("w-16 shrink-0", c.change === "added" ? "text-success-soft-foreground" : c.change === "missing" ? "text-danger-soft-foreground" : "text-warning-soft-foreground")}>
                  {c.change === "added" ? "New" : c.change === "missing" ? "Missing" : "Changed"}
                </span>
                <span className="w-24 shrink-0 text-muted">{ASSET_TYPE_LABEL[c.assetType]}</span>
                <span className="min-w-0 flex-1 truncate font-mono">{c.value}</span>
                <ToneChip tone={CERTAINTY_META[c.certainty].tone}>{CERTAINTY_META[c.certainty].label}</ToneChip>
              </div>
            ))
          )}
        </div>
      )}
      {result && "lines" in result && (
        <div className="mt-3">
          <p className="mb-1.5 text-[12.5px] text-muted">
            {result.added} lines added, {result.removed} removed{result.truncated ? " (only the first 4,000 lines of each output were compared)" : ""}
          </p>
          <pre className="panel-inset max-h-[420px] overflow-auto px-3 py-2 font-mono text-[11.5px] leading-relaxed">
            {result.lines.map((l, i) => (
              <div
                key={i}
                className={cn(
                  "whitespace-pre-wrap",
                  l.op === "added" && "bg-success-soft text-success-soft-foreground",
                  l.op === "removed" && "bg-danger-soft text-danger-soft-foreground",
                  l.op === "gap" && "text-muted italic",
                )}
              >
                {l.op === "added" ? "+ " : l.op === "removed" ? "- " : l.op === "gap" ? "… " : "  "}
                {l.text}
              </div>
            ))}
          </pre>
        </div>
      )}
    </Panel>
  );
}

export function AnalysisTab({ project }: { project: Project }) {
  return (
    <div className="flex flex-col gap-3">
      <ExposurePaths projectId={project.id} />
      <IocCorrelation projectId={project.id} />
      <CompareRuns project={project} />
    </div>
  );
}
