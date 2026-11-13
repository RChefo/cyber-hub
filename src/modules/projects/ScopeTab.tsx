// SPDX-License-Identifier: Apache-2.0
import { Button, Chip, Tooltip } from "@heroui/react";
import { CheckCircle2, Info, Plus, ShieldCheck, ShieldX, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SwitchInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage, IpcError } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { Project, ScopeCheck } from "@/lib/types";
import { cn } from "@/lib/utils";

const KIND_LABEL: Record<string, string> = { domain: "Domain", wildcard: "Wildcard", ip: "IP", cidr: "CIDR", url: "URL" };

function useClassify(value: string) {
  const [state, setState] = useState<{ kind?: string; normalized?: string; error?: string }>({});
  useEffect(() => {
    const v = value.trim();
    if (!v) {
      setState({});
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      api
        .scopeClassify(v)
        .then(([normalized, kind]) => alive && setState({ normalized, kind }))
        .catch((e) => alive && setState({ error: errorMessage(e) }));
    }, 250);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [value]);
  return state;
}

export function ScopeTab({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const confirm = useConfirm();
  const [value, setValue] = useState("");
  const [inScope, setInScope] = useState(true);
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);
  const cls = useClassify(value);

  const [testValue, setTestValue] = useState("");
  const [testResults, setTestResults] = useState<ScopeCheck[] | null>(null);
  const [testing, setTesting] = useState(false);

  const add = async () => {
    if (!value.trim() || cls.error) return;
    setAdding(true);
    try {
      await api.projectTargetAdd(project.id, { value, inScope, note });
      setValue("");
      setNote("");
      setInScope(true);
      invalidate("projects");
      onChanged();
      notify.success(inScope ? "Added to scope" : "Exclusion added");
    } catch (e) {
      // internal addresses are authorized in a native dialog; declining it is not an error
      if (e instanceof IpcError && e.kind === "cancelled") notify.info("Scope unchanged", "The internal addresses were not authorized.");
      else notify.error("Could not add scope entry", e);
    } finally {
      setAdding(false);
    }
  };

  const remove = async (id: number, label: string, inScope: boolean) => {
    // removing an exclusion widens the scope: the backend asks in a native dialog instead
    if (inScope && !(await confirm.ask({ title: "Remove scope entry?", body: `“${label}” will no longer be part of this project's scope.`, confirmLabel: "Remove" }))) return;
    try {
      await api.projectTargetDelete(id);
      invalidate("projects");
      onChanged();
    } catch (e) {
      if (e instanceof IpcError && e.kind === "cancelled") notify.info("Scope unchanged", "The exclusion was kept.");
      else notify.error("Could not remove scope entry", e);
    }
  };

  const test = async () => {
    const targets = testValue
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (!targets.length) return;
    setTesting(true);
    try {
      setTestResults(await api.scopeCheck(project.id, targets));
    } catch (e) {
      notify.error("Scope check failed", e);
    } finally {
      setTesting(false);
    }
  };

  const inEntries = project.targets.filter((t) => t.inScope);
  const outEntries = project.targets.filter((t) => !t.inScope);

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <div className="flex flex-col gap-3 xl:col-span-8">
        <Panel
          title="Add scope entry"
          description="Domains, wildcards, IP addresses and CIDR ranges authorize hosts. A URL authorizes only requests to its path (same scheme, host and port), never the host itself: port, service and TLS scans need the host in the scope."
        >
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_1fr_auto]">
            <TextInput
              label="Target"
              value={value}
              onChange={setValue}
              placeholder="*.example.com, 10.0.0.0/24, https://app.example.com/api/"
              mono
              onEnter={add}
              error={cls.error ?? null}
              description={cls.kind ? `Detected: ${KIND_LABEL[cls.kind] ?? cls.kind} · saved as ${cls.normalized}` : "Type a value to validate it"}
            />
            <TextInput label="Note" value={note} onChange={setNote} placeholder="Optional, e.g. staging only" onEnter={add} />
            <div className="flex items-end">
              <Button variant="primary" onPress={add} isDisabled={!value.trim() || !!cls.error} isPending={adding}>
                <Plus className="size-3.5" />
                Add
              </Button>
            </div>
          </div>
          <div className="mt-3">
            <SwitchInput
              label={inScope ? "In scope (authorized target)" : "Out of scope (explicit exclusion)"}
              isSelected={inScope}
              onChange={setInScope}
              description="Exclusions always win over in-scope entries."
            />
          </div>
        </Panel>

        <Panel title="Authorized scope" description={`${inEntries.length} in scope · ${outEntries.length} excluded`}>
          {project.targets.length === 0 ? (
            <EmptyBlock icon={ShieldCheck} title="No scope defined" description="Tools that send traffic to targets cannot run for this project until at least one in-scope entry exists." />
          ) : (
            <ul className="flex flex-col gap-1">
              {[...inEntries, ...outEntries].map((t) => (
                <li key={t.id} className="tile flex items-center gap-3 px-3 py-2">
                  {t.inScope ? <ShieldCheck className="size-4 shrink-0 text-success" /> : <ShieldX className="size-4 shrink-0 text-danger" />}
                  <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[13px]">
                    {t.value}
                  </code>
                  {t.note && <span className="hidden max-w-[220px] truncate text-[12px] text-muted md:inline">{t.note}</span>}
                  <Chip size="sm" variant="soft">
                    <Chip.Label>{KIND_LABEL[t.kind] ?? t.kind}</Chip.Label>
                  </Chip>
                  <ToneChip tone={t.inScope ? "success" : "danger"}>{t.inScope ? "In scope" : "Excluded"}</ToneChip>
                  <Tooltip delay={400}>
                    <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove ${t.value}`} onPress={() => remove(t.id, t.value, t.inScope)}>
                      <Trash2 className="size-3.5" />
                    </Button>
                    <Tooltip.Content>Remove</Tooltip.Content>
                  </Tooltip>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="flex flex-col gap-3 xl:col-span-4">
        <Panel title="Test a target" description="Checks targets with the same rules the execution engine uses.">
          <div className="flex gap-2">
            <TextInput aria-label="Targets to test" value={testValue} onChange={setTestValue} placeholder="api.example.com 10.0.0.9" mono onEnter={test} className="flex-1" />
            <Button variant="tertiary" onPress={test} isPending={testing} isDisabled={!testValue.trim()}>
              Check
            </Button>
          </div>
          {testResults && (
            <ul className="mt-3 flex flex-col gap-1.5">
              {testResults.map((r) => (
                <li key={r.target} className={cn("flex items-start gap-2 rounded-lg px-2.5 py-2 text-[13px]", r.allowed ? "bg-success-soft" : "bg-danger-soft")}>
                  {r.allowed ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-danger" />}
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px]">{r.target}</div>
                    <div className={r.allowed ? "text-success-soft-foreground" : "text-danger-soft-foreground"}>{r.allowed ? "Allowed" : "Blocked"} · {r.reason}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="How scope is matched">
          <ul className="flex flex-col gap-2 text-[13px] text-muted">
            {[
              ["example.com", "matches exactly that host — subdomains are not included."],
              ["*.example.com", "matches any subdomain (a.example.com, a.b.example.com) but not the apex."],
              ["10.0.0.0/24", "matches addresses and smaller ranges fully contained in it."],
              ["Exclusions", "an out-of-scope entry blocks a target even when another entry allows it."],
              ["URLs", "authorize requests under the URL's path (same scheme, host and port), not the whole host."],
              ["Internal addresses", "private, loopback and link-local entries are authorized in a system dialog, outside this page."],
            ].map(([k, v]) => (
              <li key={k} className="flex gap-2">
                <Info className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  <code className="font-mono text-foreground">{k}</code> {v}
                </span>
              </li>
            ))}
          </ul>
          <div className="panel-inset mt-3 px-3 py-2 text-[12.5px] text-muted">
            Tools that send traffic only run when this project is <span className="text-foreground">active</span> and every target on the command line is in scope.
            Target files named in arguments (for example <code className="font-mono">-iL</code>) are read too: every entry in them must be in scope, and the run uses a checked copy.
          </div>
        </Panel>
      </div>
      {confirm.element}
    </div>
  );
}
