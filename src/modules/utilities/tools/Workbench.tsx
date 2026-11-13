// SPDX-License-Identifier: Apache-2.0
import { Button, Dropdown, Switch, Tooltip } from "@heroui/react";
import { ArrowDown, ArrowDownUp, ArrowUp, Plus, RotateCcw, Trash2, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { EmptyBlock } from "@/components/ui/Feedback";
import { TextAreaInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { cn } from "@/lib/utils";
import { OPERATIONS, opById, runRecipe, type StepResult } from "../lib/workbench";
import { Output, PrivacyNote } from "./shared";

interface Step {
  key: number;
  opId: string;
  enabled: boolean;
}

const GROUPS = ["Encoding", "Text", "Data", "Hashing"] as const;
let nextKey = 1;

export function WorkbenchTool() {
  const [input, setInput] = useState("");
  const [steps, setSteps] = useState<Step[]>([]);
  const [run, setRun] = useState<{ results: StepResult[]; output: string; failedAt: number | null } | null>(null);

  const recipeKey = useMemo(() => JSON.stringify(steps.map((s) => [s.opId, s.enabled])), [steps]);
  useEffect(() => {
    let alive = true;
    runRecipe(input, steps)
      .then((r) => alive && setRun(r))
      .catch((e) => {
        // steps report their own errors; this only guards against unexpected failures
        if (alive) notify.error("The recipe could not be run", e);
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, recipeKey]);

  const add = (opId: string) => setSteps((s) => [...s, { key: nextKey++, opId, enabled: true }]);
  const update = (idx: number, patch: Partial<Step>) => setSteps((s) => s.map((x, i) => (i === idx ? { ...x, ...patch } : x)));
  const move = (idx: number, dir: -1 | 1) =>
    setSteps((s) => {
      const next = [...s];
      const [item] = next.splice(idx, 1);
      next.splice(idx + dir, 0, item);
      return next;
    });

  const failed = run?.failedAt ?? null;
  const output = failed === null ? (run?.output ?? "") : "";

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-3">
          <TextAreaInput label="Input" value={input} onChange={setInput} rows={7} mono placeholder="Paste data to transform" />
          <div className="flex items-center justify-between">
            <span className="text-[12.5px] font-medium text-muted">Recipe {steps.length > 0 && `· ${steps.filter((s) => s.enabled).length} of ${steps.length} active`}</span>
            <div className="flex items-center gap-1">
              {steps.length > 0 && (
                <Button size="sm" variant="ghost" onPress={() => setSteps([])}>
                  <RotateCcw className="size-3.5" />
                  Clear
                </Button>
              )}
              <Dropdown>
                <Button size="sm" variant="tertiary">
                  <Plus className="size-3.5" />
                  Add operation
                </Button>
                <Dropdown.Popover placement="bottom end" className="max-h-[360px] overflow-auto">
                  <Dropdown.Menu aria-label="Operations" onAction={(k) => add(String(k))}>
                    {GROUPS.map((g) => (
                      <Dropdown.Section key={g} aria-label={g}>
                        {OPERATIONS.filter((o) => o.group === g).map((o) => (
                          <Dropdown.Item key={o.id} id={o.id} textValue={o.name}>
                            <span>{o.name}</span>
                            <span className="ml-auto pl-4 text-[11.5px] text-muted">{g}</span>
                          </Dropdown.Item>
                        ))}
                      </Dropdown.Section>
                    ))}
                  </Dropdown.Menu>
                </Dropdown.Popover>
              </Dropdown>
            </div>
          </div>
          {steps.length === 0 ? (
            <EmptyBlock compact icon={Workflow} title="Build a recipe" description="Add operations; they run top to bottom and the output updates as you type." />
          ) : (
            <ol className="flex flex-col gap-1">
              {steps.map((s, idx) => {
                const op = opById(s.opId);
                const res = run?.results[idx];
                return (
                  <li key={s.key} className={cn("tile flex flex-col gap-1 px-3 py-2", !s.enabled && "opacity-55", res?.error && "bg-danger-soft")}>
                    <div className="flex items-center gap-2">
                      <span className="w-5 text-[12px] text-muted tabular">{idx + 1}</span>
                      <span className="min-w-0 flex-1 truncate text-[13.5px]">{op?.name ?? s.opId}</span>
                      <Switch size="sm" isSelected={s.enabled} onChange={(v) => update(idx, { enabled: v })} aria-label={`${s.enabled ? "Disable" : "Enable"} ${op?.name}`}>
                        <Switch.Content>
                          <Switch.Control>
                            <Switch.Thumb />
                          </Switch.Control>
                        </Switch.Content>
                      </Switch>
                      <Button isIconOnly size="sm" variant="ghost" aria-label="Move up" isDisabled={idx === 0} onPress={() => move(idx, -1)}>
                        <ArrowUp className="size-3.5" />
                      </Button>
                      <Button isIconOnly size="sm" variant="ghost" aria-label="Move down" isDisabled={idx === steps.length - 1} onPress={() => move(idx, 1)}>
                        <ArrowDown className="size-3.5" />
                      </Button>
                      <Tooltip delay={400}>
                        <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove ${op?.name}`} onPress={() => setSteps((x) => x.filter((_, i) => i !== idx))}>
                          <Trash2 className="size-3.5" />
                        </Button>
                        <Tooltip.Content>Remove step</Tooltip.Content>
                      </Tooltip>
                    </div>
                    {res?.error && (
                      <div role="alert" className="pl-7 text-[12.5px] text-danger-soft-foreground">
                        Failed here: {res.error}
                      </div>
                    )}
                    {failed !== null && idx > failed && s.enabled && <div className="pl-7 text-[12px] text-muted">Skipped because an earlier step failed</div>}
                  </li>
                );
              })}
            </ol>
          )}
        </div>
        <div className="flex flex-col gap-3">
          <Output label="Output" value={output} error={failed !== null ? `Step ${failed + 1} failed — fix the input or remove that step.` : null} minHeight={180} />
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="tertiary" isDisabled={!output || failed !== null} onPress={() => setInput(output)}>
              <ArrowDownUp className="size-3.5" />
              Use output as input
            </Button>
            {output && (
              <span className="text-[12px] text-muted">
                {Array.from(output).length.toLocaleString()} characters · {new TextEncoder().encode(output).length.toLocaleString()} bytes
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
