import { Button } from "@heroui/react";
import { Activity, Square, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { EXEC_STATUS_META, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows, QueryView } from "@/components/ui/Feedback";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ExecutionRecord } from "@/lib/types";
import { cn, formatDateTime, formatRelative, parseDate, shellQuote } from "@/lib/utils";
import { Console, textToLines } from "./Console";
import { useLiveRun } from "./liveStore";

function duration(r: ExecutionRecord): string {
  const start = parseDate(r.startedAt).getTime();
  const end = r.finishedAt ? parseDate(r.finishedAt).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - start) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

function OutputView({ record }: { record: ExecutionRecord }) {
  const live = useLiveRun(record.running ? record.id : null);
  const [stored, setStored] = useState<{ text: string | null; error: string | null }>({ text: null, error: null });

  useEffect(() => {
    if (record.running) return;
    setStored({ text: null, error: null });
    api
      .execOutput(record.id)
      .then((text) => setStored({ text, error: null }))
      .catch((e) => setStored({ text: null, error: errorMessage(e) }));
  }, [record.id, record.running, record.status]);

  const command = [record.program, ...record.args.map(shellQuote)].join(" ");

  return (
    <div className="flex flex-col gap-3">
      <div className="panel-inset flex items-start gap-2 px-3 py-2">
        <code data-selectable className="min-w-0 flex-1 font-mono text-[12px] break-all">{command}</code>
        <CopyButton text={command} label="Copy command line" />
      </div>
      {record.running ? (
        live ? (
          <Console lines={live.lines} height={420} />
        ) : (
          <div className="tile px-3 py-3 text-[13px] text-muted">
            This process was started from another window session; its output will be available here when it exits.
          </div>
        )
      ) : stored.error ? (
        <ErrorBlock message={stored.error} />
      ) : stored.text === null ? (
        <LoadingRows rows={5} />
      ) : (
        <>
          <Console lines={stored.text ? textToLines(stored.text) : []} height={420} />
          {record.truncated && <div className="text-[12px] text-warning-soft-foreground">Output exceeded 2 MB; later lines were not stored.</div>}
        </>
      )}
    </div>
  );
}

export default function RunsPage() {
  const { runtime, toolById } = useApp();
  const q = useQuery(["executions"], () => api.execList(200), [], runtime);
  const [selected, setSelected] = useState<number | null>(null);
  const confirm = useConfirm();

  // refresh durations / running state while something is running
  const anyRunning = (q.data ?? []).some((r) => r.running);
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => invalidate("executions"), 2000);
    return () => clearInterval(t);
  }, [anyRunning]);

  const records = q.data ?? [];
  const current = records.find((r) => r.id === selected) ?? records[0];

  return (
    <div>
      <PageHeader
        title="Runs"
        description="Every tool execution and managed installation started from Cyber Hub, with its exit status and captured output."
        actions={
          <Button
            size="sm"
            variant="tertiary"
            isDisabled={!records.length}
            onPress={async () => {
              if (await confirm.ask({ title: "Clear run history?", body: "Stored output for finished runs is deleted. Running processes are kept.", confirmLabel: "Clear history" })) {
                await api.execHistoryClear().catch((e) => notify.error("Could not clear history", e));
                invalidate("executions");
              }
            }}
          >
            <Trash2 className="size-3.5" />
            Clear history
          </Button>
        }
      />
      <QueryView
        query={q}
        rows={6}
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyBlock
            icon={Activity}
            title="No runs yet"
            description="Start a tool from the Tools Library or a Command Center builder. Every run is previewed and confirmed before it starts."
          />
        }
      >
        {() => (
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(340px,420px)_1fr]">
            <Panel title="History" description={`${records.length} recorded`} contentClassName="px-2 pb-2">
              <ul className="scroll-area flex max-h-[calc(100vh-260px)] flex-col gap-0.5">
                {records.map((r) => {
                  const meta = EXEC_STATUS_META[r.running ? "running" : r.status];
                  return (
                    <li key={r.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(r.id)}
                        className={cn(
                          "flex w-full items-start gap-3 rounded-lg px-2.5 py-2 text-left outline-none transition-colors focus-visible:ring-2 focus-visible:ring-focus",
                          current?.id === r.id ? "bg-white/[0.06]" : "hover:bg-white/[0.03]",
                        )}
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="truncate text-[13.5px]">{toolById(r.toolId)?.name ?? r.toolId}</span>
                            {r.kind === "install" && <span className="text-[11.5px] text-muted">install</span>}
                          </div>
                          <div className="truncate font-mono text-[11.5px] text-muted">{r.args.join(" ") || "no arguments"}</div>
                          <div className="mt-0.5 text-[11.5px] text-muted">
                            {formatRelative(r.startedAt)} · {duration(r)}
                          </div>
                        </div>
                        <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </Panel>
            {current && (
              <Panel
                title={`${toolById(current.toolId)?.name ?? current.toolId} · ${current.kind === "install" ? "installation" : "run"} #${current.id}`}
                description={`Started ${formatDateTime(current.startedAt)}${current.finishedAt ? ` · finished ${formatDateTime(current.finishedAt)}` : ""}${current.exitCode !== null ? ` · exit code ${current.exitCode}` : ""}`}
                actions={
                  current.running ? (
                    <Button size="sm" variant="danger" onPress={() => api.execCancel(current.id).then(() => invalidate("executions")).catch((e) => notify.error("Could not cancel", e))}>
                      <Square className="size-3.5" />
                      Cancel
                    </Button>
                  ) : undefined
                }
              >
                <OutputView record={current} />
              </Panel>
            )}
          </div>
        )}
      </QueryView>
      {confirm.element}
    </div>
  );
}
