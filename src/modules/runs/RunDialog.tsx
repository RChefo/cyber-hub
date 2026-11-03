import { Button, Checkbox, Label } from "@heroui/react";
import { CheckCircle2, Play, ShieldAlert, ShieldCheck, Square, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { EXEC_STATUS_META, ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { InlineSpinner } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { ExecRequest, ExecValidation } from "@/lib/types";
import { debounce, shellQuote, splitArgs } from "@/lib/utils";
import { Console } from "./Console";
import { createLiveHandler, useLiveRun } from "./liveStore";

export interface RunDialogProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  toolId: string;
  initialArgs?: string[];
  initialTargets?: string[];
  initialProjectId?: number | null;
}

/**
 * The only way to start a tool from the UI. The backend re-validates everything
 * (catalog tool, resolved executable, argument limits, project status and scope).
 */
export function RunDialog({ isOpen, onOpenChange, toolId, initialArgs = [], initialTargets = [], initialProjectId = null }: RunDialogProps) {
  const { toolById, navigate } = useApp();
  const tool = toolById(toolId);
  const projects = useQuery(["projects"], api.projectsList, [], isOpen);

  const [argLine, setArgLine] = useState("");
  const [targets, setTargets] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [validation, setValidation] = useState<{ ok: ExecValidation | null; error: string | null; kind?: string; pending: boolean }>({ ok: null, error: null, pending: false });
  const [execId, setExecId] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const live = useLiveRun(execId);

  useEffect(() => {
    if (!isOpen) return;
    setArgLine(initialArgs.map(shellQuote).join(" "));
    setTargets(initialTargets.join(", "));
    setProjectId(initialProjectId ? String(initialProjectId) : null);
    setAuthorized(false);
    setExecId(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  // default to the only active project, if exactly one exists
  useEffect(() => {
    if (!isOpen || projectId || !projects.data) return;
    const active = projects.data.filter((p) => p.status === "active");
    if (active.length === 1) setProjectId(String(active[0].id));
  }, [isOpen, projects.data, projectId]);

  const parsed = useMemo(() => {
    try {
      return { args: splitArgs(argLine), error: null as string | null };
    } catch (e) {
      return { args: [] as string[], error: errorMessage(e) };
    }
  }, [argLine]);

  const request: ExecRequest = useMemo(
    () => ({
      toolId,
      args: parsed.args,
      projectId: projectId ? Number(projectId) : null,
      targets: targets.split(/[,\s]+/).map((t) => t.trim()).filter(Boolean),
      confirmed: false,
    }),
    [toolId, parsed.args, projectId, targets],
  );

  const validate = useMemo(
    () =>
      debounce((req: ExecRequest) => {
        api
          .execValidate(req)
          .then((ok) => setValidation({ ok, error: null, pending: false }))
          .catch((e) => setValidation({ ok: null, error: errorMessage(e), kind: (e as { kind?: string }).kind, pending: false }));
      }, 350),
    [],
  );

  useEffect(() => {
    if (!isOpen || execId !== null) return;
    if (parsed.error) {
      setValidation({ ok: null, error: parsed.error, pending: false });
      return;
    }
    setValidation((v) => ({ ...v, pending: true }));
    validate(request);
  }, [isOpen, request, parsed.error, execId, validate]);

  const requiresScope = tool?.requiresScope ?? false;
  const canStart = !!validation.ok && !validation.pending && (!requiresScope || authorized) && !starting;

  const start = async () => {
    setStarting(true);
    try {
      const handler = createLiveHandler(toolId, "run", (status) => {
        if (status === "succeeded") notify.success(`${tool?.name ?? toolId} finished`);
        else notify.warning(`${tool?.name ?? toolId} ${EXEC_STATUS_META[status].label.toLowerCase()}`);
      });
      // The backend shows a native OS confirmation dialog before anything starts.
      const id = await api.execStart({ ...request, confirmed: true }, handler);
      setExecId(id);
    } catch (e) {
      if ((e as { kind?: string }).kind === "cancelled") notify.info("Run cancelled", "Nothing was started.");
      else notify.error("Could not start the process", e);
    } finally {
      setStarting(false);
    }
  };

  const running = live?.status === "running";
  const activeProjects = (projects.data ?? []).map((p) => ({
    id: String(p.id),
    label: p.name,
    description: p.status === "active" ? `${p.targetCount} scope entries` : `${p.status} — activate the project to run tools`,
  }));

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={(o) => {
        if (!o && running) notify.info("Still running", "Follow it from the Runs page.");
        onOpenChange(o);
      }}
      size="lg"
      isDismissable={!running}
      title={execId === null ? `Run ${tool?.name ?? toolId}` : `${tool?.name ?? toolId}`}
      description={execId === null ? "Review exactly what will be executed. Nothing runs until you press Start." : undefined}
      footer={
        execId === null ? (
          <>
            <Button variant="tertiary" onPress={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="primary" isDisabled={!canStart} isPending={starting} onPress={start}>
              <Play className="size-3.5" />
              Start
            </Button>
          </>
        ) : (
          <>
            <Button variant="tertiary" onPress={() => { onOpenChange(false); navigate("runs"); }}>
              Open in Runs
            </Button>
            {running ? (
              <Button variant="danger" onPress={() => api.execCancel(execId).catch((e) => notify.error("Could not cancel", e))}>
                <Square className="size-3.5" />
                Cancel process
              </Button>
            ) : (
              <Button variant="primary" onPress={() => onOpenChange(false)}>
                Close
              </Button>
            )}
          </>
        )
      }
    >
      {execId === null ? (
        <>
          {requiresScope ? (
            <div className="tile flex items-start gap-2.5 px-3 py-2.5 text-[13px] text-muted">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warning-soft-foreground" />
              <div>
                {tool?.name} sends traffic to targets. It can only run inside an <span className="text-foreground">active project</span>, and every target
                on the command line must be inside that project's authorized scope.
              </div>
            </div>
          ) : (
            <div className="tile flex items-start gap-2.5 px-3 py-2.5 text-[13px] text-muted">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-success-soft-foreground" />
              <div>{tool?.name} works on local data; no project scope is required.</div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <SelectInput
              label={requiresScope ? "Project (required)" : "Project (optional)"}
              value={projectId}
              onChange={setProjectId}
              options={activeProjects}
              placeholder={projects.data?.length ? "Select a project" : "No projects yet"}
              isDisabled={!projects.data?.length}
            />
            <TextInput
              label="Targets"
              value={targets}
              onChange={setTargets}
              placeholder="example.com, 10.0.0.0/24"
              description="Hosts given here are checked in addition to any found in the arguments."
              mono
            />
          </div>
          {requiresScope && !projects.data?.length && (
            <Button size="sm" variant="tertiary" className="self-start" onPress={() => { onOpenChange(false); navigate("projects", { new: "1" }); }}>
              Create a project with a scope
            </Button>
          )}

          <TextAreaInput
            label="Arguments"
            value={argLine}
            onChange={setArgLine}
            rows={3}
            mono
            description="Passed directly to the program as separate arguments — never through a shell. Target files named in the arguments are read and every entry is checked against the scope. After Start, your operating system asks for a final confirmation."
          />

          <div className="panel-inset px-3.5 py-3">
            <div className="mb-2 flex items-center justify-between">
              <Label className="text-[12.5px] text-muted">Execution preview</Label>
              {validation.pending && <InlineSpinner label="Validating" />}
            </div>
            <div className="font-mono text-[12px] break-all text-foreground" data-selectable>
              {validation.ok?.program ?? tool?.detect?.binaries[0] ?? toolId}
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {parsed.args.length === 0 && <span className="text-[12px] text-muted">No arguments</span>}
              {parsed.args.map((a, i) => (
                <span key={i} className="rounded-md bg-white/[0.05] px-1.5 py-0.5 font-mono text-[11.5px]" data-selectable>
                  {a}
                </span>
              ))}
            </div>
            {validation.ok && validation.ok.checkedTargets.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[12.5px]">
                <CheckCircle2 className="size-3.5 text-success" />
                <span className="text-muted">In scope:</span>
                {validation.ok.checkedTargets.slice(0, 24).map((t) => (
                  <ToneChip key={t} tone="success" dot={false}>{t}</ToneChip>
                ))}
                {validation.ok.checkedTargets.length > 24 && (
                  <span className="text-muted">+{validation.ok.checkedTargets.length - 24} more</span>
                )}
              </div>
            )}
            {validation.ok?.notes.map((n) => (
              <div key={n} className="mt-2 flex items-start gap-2 text-[12.5px] text-muted">
                <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-success" />
                <span className="break-all">{n}</span>
              </div>
            ))}
            {validation.ok?.warnings.map((w) => (
              <div key={w} className="mt-2 flex items-start gap-2 text-[12.5px] text-warning-soft-foreground">
                <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
                {w}
              </div>
            ))}
            {validation.error && (
              <div className="mt-3 flex items-start gap-2 text-[12.5px] text-danger-soft-foreground" role="alert">
                <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
                {validation.error}
              </div>
            )}
          </div>

          {requiresScope && (
            <Checkbox isSelected={authorized} onChange={setAuthorized} isDisabled={!validation.ok}>
              <Checkbox.Content className="flex items-start gap-2.5">
                <Checkbox.Control className="mt-0.5">
                  <Checkbox.Indicator />
                </Checkbox.Control>
                <Label className="text-[13px] font-normal">I confirm I am authorized to test these targets under this project's rules of engagement.</Label>
              </Checkbox.Content>
            </Checkbox>
          )}
        </>
      ) : (
        <>
          <div className="flex items-center gap-2">
            {live && <ToneChip tone={EXEC_STATUS_META[live.status].tone}>{EXEC_STATUS_META[live.status].label}</ToneChip>}
            {live?.exitCode !== null && live?.exitCode !== undefined && <span className="text-[12.5px] text-muted">exit code {live.exitCode}</span>}
          </div>
          <Console lines={live?.lines ?? []} height={380} />
        </>
      )}
    </AppModal>
  );
}
