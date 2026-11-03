import { Button, Tabs, Tooltip } from "@heroui/react";
import { BookOpen, Download, ExternalLink, Play, Rocket, ScanLine, SquareTerminal, Star, X } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { DETECTION_META, DetectionChip, OsBadges, StatusDot, ToneChip } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { Panel } from "@/components/ui/Panel";
import { copyCommand, notify, openExternal } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ManagedInstall, OsId, ToolDef } from "@/types/catalog";
import { cn, formatRelative } from "@/lib/utils";
import { RunDialog } from "@/modules/runs/RunDialog";
import { InstallDialog } from "./InstallDialog";

const OS_NAMES: Record<OsId, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

export function ToolDetail({ tool, onClose }: { tool: ToolDef; onClose: () => void }) {
  const { detections, os, isFavorite, toggleFavorite, scanTools, scanning, navigate, runtime, catalog } = useApp();
  const det = detections.get(tool.id);
  const managers = useQuery([], api.packageManagers, [], runtime);
  const [installRecipe, setInstallRecipe] = useState<ManagedInstall | null>(null);
  const [runOpen, setRunOpen] = useState(false);
  const [osTab, setOsTab] = useState<OsId>(tool.install[os] ? os : ((Object.keys(tool.install)[0] as OsId) ?? os));

  const status = tool.kind === "web" ? "catalog" : tool.kind === "script" ? null : det?.status ?? "unknown";
  const installed = det?.status === "installed" || det?.status === "dependency_missing";
  const fav = isFavorite("tool", tool.id);
  const category = catalog?.categories.find((c) => c.id === tool.category);
  const recipes = tool.managed.filter((m) => m.os.includes(os));
  const managerAvailable = (m: string) => managers.data?.find((x) => x.manager === m)?.available ?? false;

  const launch = async () => {
    try {
      await api.toolLaunch(tool.id);
      invalidate("activity");
      notify.success(`Launched ${tool.name}`);
    } catch (e) {
      notify.error(`Could not launch ${tool.name}`, e);
    }
  };

  return (
    <Panel
      className="sticky top-0"
      title={
        <span className="flex items-center gap-2">
          {tool.name}
          {status && <DetectionChip status={status} />}
        </span>
      }
      description={`${category?.name ?? tool.category} · ${tool.kind === "cli" ? "Command-line" : tool.kind === "gui" ? "Desktop application" : tool.kind === "web" ? "Web service" : "Script"}`}
      actions={
        <>
          <Tooltip delay={400}>
            <Button isIconOnly size="sm" variant="ghost" aria-label={fav ? "Remove from favorites" : "Add to favorites"} onPress={() => toggleFavorite("tool", tool.id, tool.name)}>
              <Star className={cn("size-4", fav && "fill-warning text-warning")} />
            </Button>
            <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
          </Tooltip>
          <Button isIconOnly size="sm" variant="ghost" aria-label="Close details" onPress={onClose}>
            <X className="size-4" />
          </Button>
        </>
      }
    >
      <div className="scroll-area -mr-2 flex max-h-[calc(100vh-230px)] flex-col gap-5 pr-2">
        <p className="text-[13.5px] leading-relaxed text-muted">{tool.description}</p>

        <div className="flex flex-wrap gap-2">
          {tool.kind === "cli" && (
            <Button size="sm" variant="primary" isDisabled={!installed} onPress={() => setRunOpen(true)}>
              <Play className="size-3.5" />
              Run…
            </Button>
          )}
          {tool.kind === "gui" && (
            <Button size="sm" variant="primary" isDisabled={!installed} onPress={launch}>
              <Rocket className="size-3.5" />
              Launch
            </Button>
          )}
          {tool.builder && (
            <Button size="sm" variant="tertiary" onPress={() => navigate("commands", { tab: "builders", builder: tool.builder! })}>
              <SquareTerminal className="size-3.5" />
              Open builder
            </Button>
          )}
          <Button size="sm" variant="tertiary" onPress={() => openExternal(tool.website)}>
            <ExternalLink className="size-3.5" />
            Website
          </Button>
          {tool.docs && (
            <Button size="sm" variant="tertiary" onPress={() => openExternal(tool.docs!)}>
              <BookOpen className="size-3.5" />
              Documentation
            </Button>
          )}
          {tool.detect && (
            <Button size="sm" variant="ghost" isPending={scanning} isDisabled={!runtime} onPress={() => scanTools(true, [tool.id])}>
              <ScanLine className="size-3.5" />
              Recheck
            </Button>
          )}
        </div>

        <dl className="grid grid-cols-[130px_1fr] gap-x-4 gap-y-2 text-[13px]">
          <dt className="text-muted">Status</dt>
          <dd>
            {status ? (
              <span className="flex items-center gap-2">
                <StatusDot tone={DETECTION_META[status].tone} />
                {DETECTION_META[status].label}
                {det && <span className="text-muted">· checked {formatRelative(det.checkedAt)}</span>}
              </span>
            ) : (
              <span className="text-muted">Script — download and run manually</span>
            )}
          </dd>
          {det?.version && (
            <>
              <dt className="text-muted">Version</dt>
              <dd className="font-mono text-[12.5px]">{det.version}</dd>
            </>
          )}
          {det?.path && (
            <>
              <dt className="text-muted">Location</dt>
              <dd className="flex items-center gap-1">
                <code data-selectable className="min-w-0 truncate font-mono text-[12px]" title={det.path}>{det.path}</code>
                <CopyButton text={det.path} label="Copy path" />
              </dd>
            </>
          )}
          {det?.message && (
            <>
              <dt className="text-muted">Note</dt>
              <dd className="text-warning-soft-foreground">{det.message}</dd>
            </>
          )}
          <dt className="text-muted">Platforms</dt>
          <dd><OsBadges os={tool.os} current={os} /></dd>
          <dt className="text-muted">Scope</dt>
          <dd>{tool.requiresScope ? "Targets must be inside an active project's scope" : "Runs locally; no target scope needed"}</dd>
          {tool.tags.length > 0 && (
            <>
              <dt className="text-muted">Tags</dt>
              <dd className="flex flex-wrap gap-1">
                {tool.tags.map((t) => (
                  <span key={t} className="rounded-md bg-white/[0.05] px-1.5 py-0.5 text-[11.5px] text-muted">{t}</span>
                ))}
              </dd>
            </>
          )}
        </dl>

        {tool.dependencies.length > 0 && (
          <section>
            <h3 className="mb-2 text-[13.5px] font-medium">Dependencies</h3>
            <ul className="flex flex-col gap-1">
              {tool.dependencies.map((d) => {
                const missing = det?.missingDependencies.includes(d.name);
                return (
                  <li key={d.name} className="tile flex items-center justify-between px-3 py-2 text-[13px]">
                    <span>
                      {d.name}
                      {d.optional && <span className="text-muted"> · optional</span>}
                      <span className="ml-2 font-mono text-[11.5px] text-muted">{d.binaries.join(" / ")}</span>
                    </span>
                    {det && installed && (missing ? <ToneChip tone="warning">Missing</ToneChip> : <ToneChip tone="success">Found</ToneChip>)}
                  </li>
                );
              })}
            </ul>
          </section>
        )}

        {tool.kind !== "web" && (
          <section>
            <h3 className="mb-2 text-[13.5px] font-medium">Installation</h3>
            {recipes.length > 0 && (
              <div className="mb-3 flex flex-col gap-1.5">
                {recipes.map((r) => {
                  const avail = managerAvailable(r.manager);
                  return (
                    <div key={r.manager + r.args.join(" ")} className="tile flex items-center gap-3 px-3 py-2">
                      <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]">{[r.manager, ...r.args].join(" ")}</code>
                      <Tooltip delay={300}>
                        <Button size="sm" variant="tertiary" isDisabled={!avail || !runtime} onPress={() => setInstallRecipe(r)}>
                          <Download className="size-3.5" />
                          Install
                        </Button>
                        <Tooltip.Content>{avail ? `Install using ${r.manager}` : `${r.manager} was not found on this system`}</Tooltip.Content>
                      </Tooltip>
                    </div>
                  );
                })}
              </div>
            )}
            <Tabs selectedKey={osTab} onSelectionChange={(k) => setOsTab(k as OsId)}>
              <Tabs.ListContainer>
                <Tabs.List aria-label="Operating system" className="h-8">
                  {(["windows", "macos", "linux"] as OsId[])
                    .filter((o) => tool.install[o])
                    .map((o) => (
                      <Tabs.Tab key={o} id={o} className="px-2.5 text-[12.5px]">
                        {OS_NAMES[o]}
                        {o === os ? " (this system)" : ""}
                        <Tabs.Indicator />
                      </Tabs.Tab>
                    ))}
                </Tabs.List>
              </Tabs.ListContainer>
              {(["windows", "macos", "linux"] as OsId[])
                .filter((o) => tool.install[o])
                .map((o) => (
                  <Tabs.Panel key={o} id={o} className="pt-2.5">
                    <ol className="flex flex-col gap-1.5">
                      {tool.install[o]!.map((step, i) => {
                        const looksLikeCommand = /^(sudo |brew |pipx |pip |go |gem |git |winget |apt |choco |scoop )/.test(step);
                        return (
                          <li key={i} className="flex items-start gap-2 text-[13px]">
                            <span className="mt-0.5 text-[12px] text-muted tabular">{i + 1}.</span>
                            {looksLikeCommand ? (
                              <div className="panel-inset flex min-w-0 flex-1 items-center gap-1 py-0.5 pr-1 pl-2.5">
                                <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]">{step}</code>
                                <CopyButton text={step} label="Copy command" onCopy={(t) => copyCommand(t, "tool", tool.id)} />
                              </div>
                            ) : (
                              <span className="text-muted">{step}</span>
                            )}
                          </li>
                        );
                      })}
                    </ol>
                  </Tabs.Panel>
                ))}
            </Tabs>
          </section>
        )}

        {tool.commands.length > 0 && (
          <section>
            <h3 className="mb-2 text-[13.5px] font-medium">Common commands</h3>
            <div className="flex flex-col gap-2.5">
              {tool.commands.map((c) => (
                <div key={c.title}>
                  <div className="mb-1 flex items-baseline justify-between gap-2">
                    <span className="text-[13px]">{c.title}</span>
                    <span className="truncate text-[12px] text-muted">{c.description}</span>
                  </div>
                  <CodeBlock code={c.command} actions={<CopyButton text={c.command} label="Copy command" onCopy={(t) => copyCommand(t, "tool", tool.id)} />} />
                </div>
              ))}
            </div>
            <p className="mt-2 text-[12px] text-muted">Placeholders like {"{target}"} must be replaced before running.</p>
          </section>
        )}
      </div>

      <InstallDialog tool={tool} recipe={installRecipe} isOpen={!!installRecipe} onOpenChange={(o) => !o && setInstallRecipe(null)} />
      {tool.kind === "cli" && <RunDialog isOpen={runOpen} onOpenChange={setRunOpen} toolId={tool.id} />}
    </Panel>
  );
}
