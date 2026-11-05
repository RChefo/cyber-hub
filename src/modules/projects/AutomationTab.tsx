import { Button, Dropdown } from "@heroui/react";
import { listen } from "@tauri-apps/api/event";
import { ArrowDown, ArrowUp, ChevronDown, Pencil, Play, Plus, Square, Trash2, Workflow as WorkflowIcon, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CodeBlock } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage, runtimeAvailable } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Project, Workflow, WorkflowDefinition, WorkflowNodeSpec, WorkflowStep } from "@/lib/types";
import { formatDateTime, formatRelative } from "@/lib/utils";
import { draftProblems, hasActiveStep, moveStep, newStep, parseTargets, RUN_STATUS_META } from "./workflow";

function useWorkflowEvents(projectId: number) {
  useEffect(() => {
    if (!runtimeAvailable()) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const un = listen<{ projectId: number }>("workflow-changed", (e) => {
      if (e.payload.projectId !== projectId || timer) return;
      timer = setTimeout(() => {
        timer = null;
        invalidate("workflows", "assets", "vulns", "findings");
      }, 400);
    });
    return () => {
      if (timer) clearTimeout(timer);
      void un.then((f) => f());
    };
  }, [projectId]);
}

interface Draft {
  id?: number;
  name: string;
  description: string;
  definition: WorkflowDefinition;
  scheduled: boolean;
  scheduleHours: string;
  enabled: boolean;
}

function StepEditor({ step, spec, index, count, onChange, onMove, onRemove }: { step: WorkflowStep; spec: WorkflowNodeSpec; index: number; count: number; onChange: (s: WorkflowStep) => void; onMove: (by: -1 | 1) => void; onRemove: () => void }) {
  const setParam = (key: string, value: unknown) => onChange({ ...step, params: { ...step.params, [key]: value } });
  return (
    <li className="panel-inset flex flex-col gap-3 px-3 py-3">
      <div className="flex items-center gap-2">
        <span className="tabular text-[12px] text-muted">{index + 1}</span>
        <span className="text-[13px] font-medium text-foreground">{spec.label}</span>
        {spec.active && <ToneChip tone="warning">Contacts targets</ToneChip>}
        <span className="flex-1" />
        <Button isIconOnly size="sm" variant="ghost" aria-label={`Move step ${index + 1} up`} isDisabled={index === 0} onPress={() => onMove(-1)}>
          <ArrowUp className="size-3.5" />
        </Button>
        <Button isIconOnly size="sm" variant="ghost" aria-label={`Move step ${index + 1} down`} isDisabled={index === count - 1} onPress={() => onMove(1)}>
          <ArrowDown className="size-3.5" />
        </Button>
        <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove step ${index + 1}`} onPress={onRemove}>
          <X className="size-3.5" />
        </Button>
      </div>
      <p className="-mt-1 text-[12px] text-muted">{spec.description}</p>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Step name (optional)" value={step.name} onChange={(v) => onChange({ ...step, name: v })} placeholder={spec.label} />
        {spec.params.map((p) => {
          const v = step.params[p.key];
          if (p.kind === "targets")
            return (
              <TextAreaInput
                key={p.key}
                label={p.required ? p.label : `${p.label} (optional)`}
                value={Array.isArray(v) ? v.join("\n") : ""}
                onChange={(t) => setParam(p.key, parseTargets(t))}
                rows={3}
                mono
                description={p.help}
                className="md:col-span-2"
              />
            );
          if (p.kind === "select")
            return <SelectInput key={p.key} label={p.label} value={typeof v === "string" ? v : null} onChange={(x) => setParam(p.key, x)} options={p.options.map(([id, label]) => ({ id, label }))} />;
          if (p.kind === "number")
            return <TextInput key={p.key} label={`${p.label} (${p.min}–${p.max})`} value={typeof v === "number" ? String(v) : ""} onChange={(x) => setParam(p.key, x.trim() === "" ? undefined : Number(x))} mono />;
          return <TextInput key={p.key} label={p.required ? p.label : `${p.label} (optional)`} value={typeof v === "string" ? v : ""} onChange={(x) => setParam(p.key, x)} description={p.help} />;
        })}
        <TextInput
          label={`Time limit in seconds (default ${spec.defaultTimeout})`}
          value={step.timeoutSecs ? String(step.timeoutSecs) : ""}
          onChange={(x) => onChange({ ...step, timeoutSecs: Number(x) || 0 })}
          placeholder={String(spec.defaultTimeout)}
          mono
        />
        {spec.retryable && (
          <SelectInput
            label="Retries after a failure"
            value={String(step.retries)}
            onChange={(x) => onChange({ ...step, retries: Number(x) })}
            options={[0, 1, 2, 3].map((n) => ({ id: String(n), label: n === 0 ? "No retries" : `${n} ${n === 1 ? "retry" : "retries"}` }))}
          />
        )}
      </div>
      <SwitchInput label="Continue with the next step if this one fails" isSelected={step.continueOnError} onChange={(x) => onChange({ ...step, continueOnError: x })} />
    </li>
  );
}

function WorkflowEditor({ draft, onClose, projectId, nodes }: { draft: Draft | null; onClose: () => void; projectId: number; nodes: WorkflowNodeSpec[] }) {
  const [d, setD] = useState<Draft | null>(draft);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    setD(draft);
    setError(null);
  }, [draft]);
  if (!d) return null;
  const active = hasActiveStep(d.definition, nodes);
  const problems = draftProblems(d.name, d.definition, nodes, d.scheduled);
  const setSteps = (steps: WorkflowStep[]) => setD({ ...d, definition: { steps } });
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.workflowSave({
        id: d.id,
        projectId,
        name: d.name,
        description: d.description,
        definition: d.definition,
        scheduleHours: d.scheduled ? Number(d.scheduleHours) || 24 : null,
        enabled: d.enabled,
      });
      invalidate("workflows");
      notify.success(d.id ? "Workflow saved" : "Workflow created");
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen={!!d}
      onOpenChange={(o) => !o && onClose()}
      title={d.id ? "Edit workflow" : "New workflow"}
      description="Steps run in order. Each step is a built-in action with the same scope checks and confirmations as doing it by hand."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={problems.length > 0}>
            Save workflow
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Name" value={d.name} onChange={(v) => setD({ ...d, name: v })} isRequired autoFocus />
        <TextInput label="Description" value={d.description} onChange={(v) => setD({ ...d, description: v })} />
      </div>
      <ol className="flex flex-col gap-2">
        {d.definition.steps.map((s, i) => {
          const spec = nodes.find((n) => n.type === s.type);
          return spec ? (
            <StepEditor
              key={i}
              step={s}
              spec={spec}
              index={i}
              count={d.definition.steps.length}
              onChange={(n) => setSteps(d.definition.steps.map((x, j) => (j === i ? n : x)))}
              onMove={(by) => setSteps(moveStep(d.definition.steps, i, by))}
              onRemove={() => setSteps(d.definition.steps.filter((_, j) => j !== i))}
            />
          ) : null;
        })}
      </ol>
      <Dropdown>
        <Button size="sm" variant="secondary" className="self-start" isDisabled={d.definition.steps.length >= 20}>
          <Plus className="size-3.5" />
          Add step
          <ChevronDown className="size-3" />
        </Button>
        <Dropdown.Popover placement="bottom start">
          <Dropdown.Menu
            aria-label="Step types"
            onAction={(k) => {
              const spec = nodes.find((n) => n.type === k);
              if (spec) setSteps([...d.definition.steps, newStep(spec)]);
            }}
          >
            {nodes.map((n) => (
              <Dropdown.Item key={n.type} id={n.type} textValue={n.label}>
                {n.label}
                {n.active ? " (contacts targets)" : ""}
              </Dropdown.Item>
            ))}
          </Dropdown.Menu>
        </Dropdown.Popover>
      </Dropdown>
      <div className="panel-inset flex flex-col gap-2 px-3 py-3">
        <SwitchInput
          label="Run on a schedule while Cyber Hub is open"
          isSelected={d.scheduled}
          onChange={(v) => setD({ ...d, scheduled: v })}
          description={active ? "Only workflows without steps that contact targets can be scheduled." : "Scheduled runs need no confirmation because they only use passive steps."}
        />
        {d.scheduled && <TextInput label="Every (hours, 1–720)" value={d.scheduleHours} onChange={(v) => setD({ ...d, scheduleHours: v })} mono className="max-w-48" />}
        <SwitchInput label="Enabled" isSelected={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} description="Disabled workflows keep their history but do not run on their schedule." />
      </div>
      {problems.length > 0 && (
        <ul className="list-disc pl-5 text-[12.5px] text-warning-soft-foreground">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function RunDetailModal({ runId, onClose }: { runId: number | null; onClose: () => void }) {
  const { runtime } = useApp();
  const q = useQuery(["workflows"], () => (runId ? api.workflowRunDetail(runId) : Promise.resolve(null)), [runId], runtime && !!runId);
  const [openLog, setOpenLog] = useState<number | null>(null);
  const d = q.data;
  return (
    <AppModal isOpen={!!runId} onOpenChange={(o) => !o && onClose()} title={d ? `Run #${d.run.id}` : "Run"} description={d ? `${d.run.trigger === "schedule" ? "Scheduled" : "Started by you"} · ${formatDateTime(d.run.startedAt)}` : undefined} size="lg">
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !d ? (
        <LoadingRows rows={3} />
      ) : (
        <>
          <div className="flex items-center gap-2 text-[13px]">
            <ToneChip tone={RUN_STATUS_META[d.run.status].tone}>{RUN_STATUS_META[d.run.status].label}</ToneChip>
            <span className="text-muted">{d.run.summary}</span>
            <span className="flex-1" />
            {d.run.status === "running" && (
              <Button size="sm" variant="secondary" onPress={() => api.workflowCancel(d.run.id).catch((e) => notify.error("Could not cancel", e))}>
                <Square className="size-3.5" />
                Cancel run
              </Button>
            )}
          </div>
          <ol className="flex flex-col gap-1.5">
            {d.steps.map((s) => (
              <li key={s.id} className="panel-inset px-3 py-2">
                <div className="flex items-center gap-2 text-[13px]">
                  <span className="tabular text-[12px] text-muted">{s.position + 1}</span>
                  <span className="min-w-0 flex-1 truncate text-foreground">{s.name}</span>
                  {s.attempts > 1 && <span className="text-[12px] text-muted">{s.attempts} attempts</span>}
                  <ToneChip tone={RUN_STATUS_META[s.status].tone}>{RUN_STATUS_META[s.status].label}</ToneChip>
                </div>
                {s.summary && <p className="mt-1 text-[12.5px] text-muted">{s.summary}</p>}
                {s.log && (
                  <Button size="sm" variant="ghost" className="mt-1 h-6 px-1.5 text-[12px]" onPress={() => setOpenLog(openLog === s.id ? null : s.id)}>
                    {openLog === s.id ? "Hide log" : "Show log"}
                  </Button>
                )}
                {openLog === s.id && <CodeBlock code={s.log} className="mt-1" maxHeight={256} />}
              </li>
            ))}
          </ol>
        </>
      )}
    </AppModal>
  );
}

function WorkflowCard({ w, onEdit, onOpenRun }: { w: Workflow; onEdit: () => void; onOpenRun: (id: number) => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const runs = useQuery(["workflows"], () => api.workflowRuns(w.id, 5), [w.id], runtime);
  const [starting, setStarting] = useState(false);
  const running = w.lastRun?.status === "running";
  const run = async () => {
    setStarting(true);
    try {
      const id = await api.workflowRun(w.id);
      invalidate("workflows");
      onOpenRun(id);
    } catch (e) {
      notify.error("The workflow did not start", e);
    } finally {
      setStarting(false);
    }
  };
  const remove = async () => {
    if (!(await confirm.ask({ title: `Delete “${w.name}”?`, body: "The workflow and its run history are deleted. What its runs recorded (assets, evidence) stays.", confirmLabel: "Delete workflow" }))) return;
    try {
      await api.workflowDelete(w.id);
      invalidate("workflows");
    } catch (e) {
      notify.error("Could not delete the workflow", e);
    }
  };
  return (
    <Panel
      title={w.name}
      description={[
        `${w.definition.steps.length} steps`,
        w.scheduleHours ? `every ${w.scheduleHours} h${w.enabled && w.nextRunAt ? `, next ${formatRelative(w.nextRunAt)}` : ""}` : "run by hand",
        w.enabled ? null : "disabled",
        w.description || null,
      ]
        .filter(Boolean)
        .join(" · ")}
      actions={
        <>
          <Button isIconOnly size="sm" variant="ghost" aria-label={`Edit ${w.name}`} onPress={onEdit}>
            <Pencil className="size-3.5" />
          </Button>
          <Button isIconOnly size="sm" variant="ghost" aria-label={`Delete ${w.name}`} onPress={remove} isDisabled={running}>
            <Trash2 className="size-3.5" />
          </Button>
          <Button size="sm" variant="primary" onPress={run} isPending={starting} isDisabled={running}>
            <Play className="size-3.5" />
            Run
          </Button>
        </>
      }
    >
      {!runs.data || runs.data.length === 0 ? (
        <p className="text-[12.5px] text-muted">Not run yet.</p>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {runs.data.map((r) => (
            <li key={r.id}>
              <button type="button" onClick={() => onOpenRun(r.id)} className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-[12.5px] transition-colors hover:bg-white/[0.035] focus-visible:outline-2 focus-visible:outline-accent">
                <ToneChip tone={RUN_STATUS_META[r.status].tone}>{RUN_STATUS_META[r.status].label}</ToneChip>
                <span className="text-muted">{formatRelative(r.startedAt)}</span>
                <span className="min-w-0 flex-1 truncate text-muted">{r.summary}</span>
                {r.trigger === "schedule" && <span className="text-[11.5px] text-muted">scheduled</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
      {confirm.element}
    </Panel>
  );
}

export function AutomationTab({ project }: { project: Project }) {
  const { runtime } = useApp();
  useWorkflowEvents(project.id);
  const nodes = useQuery(["workflows"], () => api.workflowNodes(), [], runtime);
  const templates = useQuery(["workflows"], () => api.workflowTemplates(), [], runtime);
  const list = useQuery(["workflows"], () => api.workflowsList(project.id), [project.id], runtime);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [runId, setRunId] = useState<number | null>(null);
  const nodeList = useMemo(() => nodes.data ?? [], [nodes.data]);

  const start = (name: string, description: string, definition: WorkflowDefinition) =>
    setDraft({ name, description, definition: structuredClone(definition), scheduled: false, scheduleHours: "24", enabled: true });
  const edit = (w: Workflow) =>
    setDraft({ id: w.id, name: w.name, description: w.description, definition: structuredClone(w.definition), scheduled: w.scheduleHours != null, scheduleHours: String(w.scheduleHours ?? 24), enabled: w.enabled });

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Automation"
        description="Workflows chain built-in steps. Steps that contact targets are confirmed in a system dialog when a run starts and are checked against the scope again when they run. Only passive workflows can run on a schedule."
        actions={
          <Dropdown>
            <Button size="sm" variant="primary">
              <Plus className="size-3.5" />
              New workflow
              <ChevronDown className="size-3" />
            </Button>
            <Dropdown.Popover placement="bottom end">
              <Dropdown.Menu
                aria-label="Start from"
                onAction={(k) => {
                  if (k === "blank") return start("", "", { steps: [] });
                  const t = templates.data?.find((x) => x.id === k);
                  if (t) start(t.name, t.description, t.definition);
                }}
              >
                {[
                  <Dropdown.Item key="blank" id="blank" textValue="Empty workflow">
                    Empty workflow
                  </Dropdown.Item>,
                  ...(templates.data ?? []).map((t) => (
                    <Dropdown.Item key={t.id} id={t.id} textValue={t.name}>
                      {t.name}
                    </Dropdown.Item>
                  )),
                ]}
              </Dropdown.Menu>
            </Dropdown.Popover>
          </Dropdown>
        }
      >
        {list.error && !list.data ? (
          <ErrorBlock message={list.error} onRetry={list.reload} />
        ) : !list.data ? (
          <LoadingRows rows={2} />
        ) : list.data.length === 0 ? (
          <EmptyBlock icon={WorkflowIcon} title="No workflows yet" description="Start from a template such as “Passive attack surface refresh” or build your own from the built-in steps." />
        ) : null}
      </Panel>
      {(list.data ?? []).map((w) => (
        <WorkflowCard key={w.id} w={w} onEdit={() => edit(w)} onOpenRun={setRunId} />
      ))}
      <WorkflowEditor draft={draft} onClose={() => setDraft(null)} projectId={project.id} nodes={nodeList} />
      <RunDetailModal runId={runId} onClose={() => setRunId(null)} />
    </div>
  );
}
