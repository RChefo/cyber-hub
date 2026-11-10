import { Button } from "@heroui/react";
import { Camera, Trash2 } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { AttackDiffed, AttackLayer } from "@/lib/types";
import { pluralize } from "@/lib/utils";

const HISTORY_KIND: Record<string, string> = { assessment: "Assessment", finding: "Finding", detection: "Detection", link: "Link" };

/** What happened about one technique in the project, oldest first. */
export function TechniqueHistory({ projectId, technique }: { projectId: number; technique: string }) {
  const { runtime } = useApp();
  const h = useQuery(["attack", "findings", "detections"], () => api.attackTechniqueHistory(projectId, technique), [projectId, technique], runtime);
  if (h.error) return <ErrorBlock message={h.error} onRetry={h.reload} />;
  if (!h.data) return null;
  return (
    <section className="flex flex-col gap-1.5">
      <h3 className="text-[13px] font-medium">History ({h.data.length})</h3>
      {h.data.length === 0 ? (
        <p className="text-[12.5px] text-muted">Nothing in this project names this technique yet.</p>
      ) : (
        <ol className="flex flex-col gap-0.5 text-[12px]">
          {h.data.map((e, i) => (
            <li key={i} className="flex flex-wrap gap-2">
              <span className="font-mono text-muted">{e.at.slice(0, 16).replace("T", " ")}</span>
              <ToneChip tone="default" dot={false} className="text-[10.5px]">
                {HISTORY_KIND[e.kind] ?? e.kind}
              </ToneChip>
              <span>{e.summary}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function List({ title, items, side }: { title: string; items: AttackDiffed[]; side: "a" | "b" | "both" }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <h4 className="text-[12.5px] font-medium">
        {title} <span className="font-normal text-muted">({items.length})</span>
      </h4>
      <ul className="flex max-h-64 flex-col gap-0.5 overflow-y-auto text-[12px]">
        {items.map((d) => (
          <li key={d.id} className="truncate" title={`${d.id} ${d.name}${d.a ? ` — ${d.a}` : ""}${d.b ? ` — ${d.b}` : ""}`}>
            <span className="font-mono">{d.id}</span> {d.name}
            {side !== "b" && d.a && <span className="text-muted"> · {d.a}</span>}
            {side === "b" && d.b && <span className="text-muted"> · {d.b}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Two technique sets compared (observed, hypotheses, coverage, a snapshot, a layer), and the
 * coverage snapshots that make coverage changes visible. */
export function AttackCompare({ projectId, layers, archived }: { projectId: number; layers: AttackLayer[]; archived: boolean }) {
  const { runtime } = useApp();
  const snapshots = useQuery(["attack", "detections"], () => api.attackSnapshots(), [], runtime);
  const [a, setA] = useState("observed");
  const [b, setB] = useState("coverage");
  const [label, setLabel] = useState("");
  const cmp = useQuery(["attack", "detections", "findings"], () => (a !== b ? api.attackCompare(projectId, a, b) : Promise.resolve(null)), [projectId, a, b], runtime);
  const options = [
    { id: "observed", label: "Observed in the project" },
    { id: "hypotheses", label: "Hypotheses" },
    { id: "coverage", label: "Detection coverage now" },
    ...(snapshots.data ?? []).map((s) => ({ id: `snapshot:${s.id}`, label: `Coverage snapshot “${s.label}” (${s.takenAt.slice(0, 10)})` })),
    ...layers.map((l) => ({ id: `layer:${l.id}`, label: `Layer “${l.name}”` })),
  ];
  const take = async () => {
    try {
      await api.attackSnapshotTake(label.trim());
      setLabel("");
      invalidate("attack");
      notify.success("Coverage snapshot saved");
    } catch (e) {
      notify.error("Not saved", e);
    }
  };
  return (
    <Panel title="Compare" description="Two sets of techniques side by side. Each keeps its meaning: coverage is what rules could detect, a layer is someone else's view, and only findings and the analyst's assessments say what happened.">
      <div className="flex flex-col gap-3 text-[12.5px]">
        <div className="flex flex-wrap items-end gap-2">
          <SelectInput aria-label="First set" value={a} onChange={setA} options={options} className="w-72" />
          <span className="pb-2 text-muted">compared with</span>
          <SelectInput aria-label="Second set" value={b} onChange={setB} options={options} className="w-72" />
        </div>
        {cmp.error && <ErrorBlock message={cmp.error} onRetry={cmp.reload} />}
        {cmp.data && (
          <>
            <p className="text-muted">{cmp.data.reading}</p>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <List title={`Only in ${cmp.data.aLabel}`} items={cmp.data.onlyA} side="a" />
              <List title="In both" items={cmp.data.both} side="both" />
              <List title={`Only in ${cmp.data.bLabel}`} items={cmp.data.onlyB} side="b" />
            </div>
          </>
        )}
        <div className="flex flex-col gap-1.5">
          <h4 className="text-[12.5px] font-medium">Coverage snapshots</h4>
          <p className="text-muted">A snapshot records which techniques the enabled rules cover now; compare it later with the coverage of that moment to see rules added, removed or disabled.</p>
          {!archived && (
            <div className="flex flex-wrap items-end gap-2">
              <TextInput aria-label="Snapshot label" value={label} onChange={setLabel} placeholder="Before the Q4 rule review" className="w-72" />
              <Button size="sm" variant="secondary" className="h-8 gap-1" onPress={take} isDisabled={!label.trim()}>
                <Camera className="size-3.5" />
                Save snapshot
              </Button>
            </div>
          )}
          <ul className="flex flex-col gap-0.5">
            {(snapshots.data ?? []).map((s) => (
              <li key={s.id} className="flex items-center gap-2">
                <span>{s.label}</span>
                <span className="text-muted">
                  {s.takenAt.slice(0, 10)} · ATT&CK v{s.attackVersion} · {pluralize(s.techniques, "technique")}, {pluralize(s.rules, "rule")}
                </span>
                <Button
                  isIconOnly
                  size="sm"
                  variant="ghost"
                  aria-label={`Delete snapshot ${s.label}`}
                  onPress={async () => {
                    await api.attackSnapshotDelete(s.id).catch((e) => notify.error("Not deleted", e));
                    invalidate("attack");
                  }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Panel>
  );
}
