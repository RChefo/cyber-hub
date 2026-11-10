import { Button, Checkbox, Label } from "@heroui/react";
import { Play, ScanSearch } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { DetectionHit, Project, RecordRef } from "@/lib/types";
import { pluralize } from "@/lib/utils";
import { explain, LEVEL_TONE } from "@/modules/detections/detections";
import { Segmented } from "@/modules/utilities/tools/shared";

const LOGLIKE = /\.(evtx|json|jsonl|ndjson|log|txt)$/i;

/** Projects → Investigation → Detections: the library's rules run on the project's evidence (Sigma
 * on logs, YARA on any file), and their matches (hits) kept for review: a hit is a lead until it
 * becomes a finding. */
export function DetectionHitsView({ project, archived, onOpen }: { project: Project; archived: boolean; onOpen: (r: RecordRef) => void }) {
  const { runtime } = useApp();
  const [status, setStatus] = useState<"new" | "promoted" | "false_positive" | "dismissed" | "all">("new");
  const [running, setRunning] = useState(false);
  const hits = useQuery(["detections", "findings"], () => api.detectionHits(project.id, { status: status === "all" ? null : status, limit: 300 }), [project.id, status], runtime);
  const counts = hits.data?.counts ?? {};
  const act = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn();
      invalidate("detections", "findings", "attack", "projects");
      notify.success(done);
    } catch (e) {
      notify.error("The hit was not changed", e);
    }
  };
  return (
    <Panel
      title="Detection hits"
      description="Matches of the detection library's enabled rules on this project's evidence: Sigma rules on logs, YARA rules on any file. A hit is a lead: promote it to a finding (under review) once you confirm it, or mark it a false positive, which is recorded as feedback on the rule."
      actions={
        <Button size="sm" variant="primary" onPress={() => setRunning(true)} isDisabled={!runtime || archived}>
          <Play className="size-3.5" />
          Run rules…
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        <Segmented
          value={status}
          onChange={setStatus}
          ariaLabel="Hits"
          options={[
            { id: "new", label: `To review (${counts.new ?? 0})` },
            { id: "promoted", label: `Findings (${counts.promoted ?? 0})` },
            { id: "false_positive", label: `False positives (${counts.false_positive ?? 0})` },
            { id: "dismissed", label: `Dismissed (${counts.dismissed ?? 0})` },
            { id: "all", label: "All" },
          ]}
        />
        {hits.error ? (
          <ErrorBlock message={hits.error} onRetry={hits.reload} />
        ) : !hits.data ? (
          <LoadingRows rows={4} />
        ) : hits.data.items.length === 0 ? (
          <EmptyBlock compact icon={ScanSearch} title={status === "new" ? "Nothing to review" : "No hit here"} description="Run the library's rules on the project's evidence: Sigma rules on EVTX, JSON or text logs, YARA rules on any file. Add rules on the Detections page." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {hits.data.items.map((h) => (
              <HitRow
                key={h.id}
                h={h}
                archived={archived}
                onSet={(s, done) => void act(() => api.detectionHitSet(h.id, s), done)}
                onPromote={() =>
                  void (async () => {
                    try {
                      const fid = await api.detectionHitPromote(h.id);
                      invalidate("detections", "findings", "attack", "projects");
                      notify.success("Finding created, under review");
                      onOpen({ kind: "finding", id: fid, sub: "" });
                    } catch (e) {
                      notify.error("The finding was not created", e);
                    }
                  })()
                }
                onOpenFinding={(id) => onOpen({ kind: "finding", id, sub: "" })}
              />
            ))}
          </ul>
        )}
      </div>
      {running && <RunModal project={project} onClose={() => setRunning(false)} />}
    </Panel>
  );
}

function HitRow({ h, archived, onSet, onPromote, onOpenFinding }: { h: DetectionHit; archived: boolean; onSet: (s: "new" | "false_positive" | "dismissed", done: string) => void; onPromote: () => void; onOpenFinding: (id: number) => void }) {
  return (
    <li className="flex flex-col gap-1 rounded-[8px] bg-white/[0.02] px-3 py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <ToneChip tone={LEVEL_TONE[h.ruleLevel] ?? "default"} dot={false} className="text-[11px]">
          {h.ruleLevel || "no level"}
        </ToneChip>
        {h.explanation?.kind === "yara" && (
          <ToneChip tone="accent" dot={false} className="text-[10.5px]">
            YARA
          </ToneChip>
        )}
        <span className="font-medium">{h.ruleTitle}</span>
        <span className="text-muted">v{h.ruleVersion}</span>
        {h.techniques.slice(0, 3).map((t) => (
          <span key={t} className="font-mono text-[11px] text-muted">
            {t}
          </span>
        ))}
        <span className="flex-1" />
        {h.status === "promoted" && h.findingId != null ? (
          <Button size="sm" variant="ghost" className="h-7" onPress={() => onOpenFinding(h.findingId!)}>
            Open the finding
          </Button>
        ) : h.status === "new" ? (
          <>
            <Button size="sm" variant="tertiary" className="h-7" isDisabled={archived} onPress={onPromote}>
              Promote to finding
            </Button>
            <Button size="sm" variant="ghost" className="h-7" isDisabled={archived} onPress={() => onSet("false_positive", "Marked a false positive (recorded on the rule)")}>
              False positive
            </Button>
            <Button size="sm" variant="ghost" className="h-7" isDisabled={archived} onPress={() => onSet("dismissed", "Dismissed")}>
              Dismiss
            </Button>
          </>
        ) : (
          <Button size="sm" variant="ghost" className="h-7" isDisabled={archived} onPress={() => onSet("new", "Back to review")}>
            Review again
          </Button>
        )}
      </div>
      <div className="text-muted">
        {h.event.label ?? "event"} · <span className="font-mono">{h.position}</span>
        {h.eventTime ? ` · ${h.eventTime}` : ""}
        {h.evidence ? ` · ${h.evidence}` : ""}
      </div>
      <details>
        <summary className="cursor-pointer text-muted">Why it matched</summary>
        <ul className="mt-1 ml-3 flex flex-col gap-0.5">
          {explain(h.explanation).map((l) => (
            <li key={l} className="break-all">
              {l}
            </li>
          ))}
        </ul>
        {h.event.fields && h.event.fields.length > 0 && (
          <pre className="panel-inset mt-1.5 max-h-48 overflow-auto px-2 py-1 font-mono text-[11.5px] whitespace-pre-wrap">{h.event.fields.map(([k, v]) => `${k}: ${v}`).join("\n")}</pre>
        )}
      </details>
    </li>
  );
}

function RunModal({ project, onClose }: { project: Project; onClose: () => void }) {
  const { runtime } = useApp();
  const evidence = useQuery(["findings"], () => api.evidenceList(project.id), [project.id], runtime);
  const collections = useQuery(["detections"], () => api.detectionCollections(), [], runtime);
  const files = useMemo(() => (evidence.data ?? []).filter((e) => e.kind === "file"), [evidence.data]);
  const [picked, setPicked] = useState<Set<number> | null>(null);
  const [collection, setCollection] = useState("all");
  const [busy, setBusy] = useState(false);
  const chosen = picked ?? new Set(files.filter((f) => LOGLIKE.test(f.fileName ?? "") || ["log_triage", "evtx_triage"].includes(f.sourceModule)).map((f) => f.id));
  const run = async () => {
    setBusy(true);
    try {
      const r = await api.detectionProjectRun(project.id, [...chosen], collection === "all" ? null : Number(collection));
      invalidate("detections", "attack", "projects");
      const failed = r.files.filter((f) => f.error);
      const notes = r.files.flatMap((f) => f.notes.map((n) => `${f.title}: ${n}`));
      notify.success(
        `${pluralize(r.newHits, "new hit")} from ${pluralize(r.results.length, "rule")}`,
        [`${pluralize(r.rules, "rule")} ran on ${pluralize(r.files.length - failed.length, "file")}`, failed.length ? `not read: ${failed.map((f) => `${f.title} (${f.error})`).join("; ")}` : null, notes.length ? notes.slice(0, 3).join("; ") : null].filter(Boolean).join(" · "),
      );
      onClose();
    } catch (e) {
      notify.error("The rules did not run", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title="Run detection rules"
      description="The enabled rules of the library (or of one collection) run on the chosen evidence files: Sigma rules on the logs, YARA rules on every file. Logs are chosen first; add other files for YARA. Matches become hits to review; nothing becomes a finding by itself. No file is opened or run."
      footer={
        <div className="flex w-full justify-end gap-2">
          <Button size="sm" variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" onPress={() => void run()} isPending={busy} isDisabled={chosen.size === 0}>
            Run on {pluralize(chosen.size, "file")}
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-3 text-[12.5px]">
        {(collections.data?.length ?? 0) > 0 && (
          <SelectInput label="Rules" value={collection} onChange={setCollection} options={[{ id: "all", label: "All enabled rules" }, ...(collections.data ?? []).map((c) => ({ id: String(c.id), label: `Collection: ${c.name}` }))]} />
        )}
        {files.length === 0 ? (
          <span className="text-muted">The evidence vault holds no file. Add a log or a file in the Evidence tab, or record a triage with its file.</span>
        ) : (
          <ul className="flex flex-col gap-1">
            {files.map((f) => (
              <li key={f.id}>
                <Checkbox
                  isSelected={chosen.has(f.id)}
                  onChange={(v) => {
                    const next = new Set(chosen);
                    if (v) next.add(f.id);
                    else next.delete(f.id);
                    setPicked(next);
                  }}
                >
                  <Checkbox.Content className="flex items-center gap-2">
                    <Checkbox.Control>
                      <Checkbox.Indicator />
                    </Checkbox.Control>
                    <Label className="text-[12.5px] font-normal">
                      {f.title} <span className="text-muted">({f.fileName})</span>
                    </Label>
                  </Checkbox.Content>
                </Checkbox>
              </li>
            ))}
          </ul>
        )}
      </div>
    </AppModal>
  );
}
