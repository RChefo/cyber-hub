import { Button, Checkbox, Dropdown, Label, Tabs, Tooltip } from "@heroui/react";
import {
  BookMarked,
  Boxes,
  ChevronDown,
  Copy,
  Cpu,
  FolderKanban,
  ListTodo,
  Plus,
  Radar,
  ScanLine,
  Search,
  Star,
  SquareTerminal,
  Trash2,
  Wrench,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ActivityAreaChart, type ActivityPoint } from "@/components/charts/ActivityAreaChart";
import { DETECTION_META, PROJECT_STATUS_META, StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import CountUp from "@/components/vendor/reactbits/CountUp";
import { DotPattern } from "@/components/vendor/lightswind/DotPattern";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { RESOURCES } from "@/data/resources";
import { copyCommand, notify, openResource } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn, formatBytes, formatDuration, formatRelative } from "@/lib/utils";
import { ACTIVITY_META, ActivityIcon } from "./activityMeta";

/* ───────────────────────── Readiness hero ───────────────────────── */

export function ReadinessWidget() {
  const { catalog, detections, scanTools, scanning, prefs, runtime, navigate, os } = useApp();
  const lastScan = typeof prefs["tools.lastScan"] === "string" ? (prefs["tools.lastScan"] as string) : null;

  const rows = useMemo(() => {
    if (!catalog) return [];
    return catalog.categories.map((c) => {
      const tools = catalog.tools.filter((t) => t.category === c.id && t.kind !== "web" && t.kind !== "script" && t.os.includes(os));
      const installed = tools.filter((t) => {
        const s = detections.get(t.id)?.status;
        return s === "installed" || s === "dependency_missing";
      }).length;
      return { id: c.id, name: c.name, total: tools.length, installed };
    });
  }, [catalog, detections, os]);

  const total = rows.reduce((a, r) => a + r.total, 0);
  const installed = rows.reduce((a, r) => a + r.installed, 0);
  const issues = [...detections.values()].filter((d) => d.status === "dependency_missing" || d.status === "installation_failed").length;
  const scanned = !!lastScan;

  let state: { tone: "success" | "warning" | "default"; label: string };
  if (!runtime) state = { tone: "default", label: "Runtime offline" };
  else if (!scanned) state = { tone: "warning", label: "Not scanned yet" };
  else if (issues) state = { tone: "warning", label: `${issues} need attention` };
  else state = { tone: "success", label: "Ready" };

  return (
    <div className="panel relative overflow-hidden p-4">
      <DotPattern width={18} height={18} className="fill-white/[0.05] [mask-image:linear-gradient(to_left,white,transparent_70%)]" />
      <div className="relative">
        <div>
          <div className="text-[12.5px] text-muted">Workstation readiness</div>
          <div className="mt-1.5 flex items-center gap-2.5">
            <span className="tabular text-[28px] leading-none font-semibold tracking-tight">
              {scanned ? installed : "—"}
              <span className="text-[16px] font-normal text-muted"> / {total}</span>
            </span>
            <ToneChip tone={state.tone}>{state.label}</ToneChip>
          </div>
          <div className="mt-1.5 text-[13px] text-muted">
            {scanned
              ? `Installable tools detected for this OS · last scan ${formatRelative(lastScan)}`
              : "Scan to detect which catalog tools are installed. Nothing is executed during a PATH scan."}
          </div>
        </div>
      </div>

      <div className="relative mt-4 grid grid-cols-7 gap-x-1.5 gap-y-2.5" aria-label="Tool coverage by category">
        {rows.map((r) => {
          const pct = r.total ? r.installed / r.total : 0;
          return (
            <Tooltip key={r.id} delay={150}>
              <Button
                variant="ghost"
                onPress={() => navigate("tools", { category: r.id })}
                className="group flex h-auto w-full min-w-0 flex-col items-stretch gap-1 overflow-hidden rounded-md bg-transparent p-0 text-left font-normal whitespace-normal hover:bg-transparent"
                aria-label={`${r.name}: ${r.installed} of ${r.total} installed`}
              >
                <div className="relative h-7 overflow-hidden rounded-[4px] bg-white/[0.045]">
                  <div
                    className="absolute inset-x-0 bottom-0 rounded-[4px] bg-accent/80 transition-[height] group-hover:bg-accent"
                    style={{ height: `${scanned ? Math.max(pct * 100, r.installed ? 8 : 0) : 0}%` }}
                  />
                </div>
                <div className="truncate text-[11px] text-muted group-hover:text-foreground">{SHORT_CATEGORY[r.id] ?? r.name}</div>
              </Button>
              <Tooltip.Content>
                {r.name}: {scanned ? `${r.installed} of ${r.total} installed` : `${r.total} tools, not scanned`}
              </Tooltip.Content>
            </Tooltip>
          );
        })}
      </div>

      <div className="relative mt-4 flex items-center gap-1.5">
        <Button size="sm" variant={scanned ? "tertiary" : "primary"} isPending={scanning} isDisabled={!runtime} onPress={() => scanTools(false)}>
          <ScanLine className="size-3.5" />
          {scanned ? "Rescan" : "Scan tools"}
        </Button>
        <Tooltip delay={300}>
          <Button size="sm" variant="ghost" isDisabled={!runtime || scanning} onPress={() => scanTools(true)}>
            Detect versions
          </Button>
          <Tooltip.Content className="max-w-[260px]">Runs each detected command-line tool once with its version flag (e.g. nmap --version) to read the installed version.</Tooltip.Content>
        </Tooltip>
      </div>
    </div>
  );
}

const SHORT_CATEGORY: Record<string, string> = {
  web: "Web",
  network: "Network",
  osint: "OSINT",
  recon: "Recon",
  vuln: "Vuln",
  password: "Password",
  forensics: "Forensics",
  malware: "Malware",
  wireless: "Wireless",
  cloud: "Cloud",
  reversing: "Reversing",
  crypto: "Crypto",
  linux: "Linux",
  ad: "AD",
};

/* ───────────────────────── Activity chart ───────────────────────── */

export function ActivityChartWidget() {
  const { runtime } = useApp();
  const [days, setDays] = useState<"7" | "30" | "90">("30");
  const q = useQuery(["activity"], () => api.activityDaily(Number(days)), [days], runtime);

  const data = useMemo<ActivityPoint[]>(() => {
    const n = Number(days);
    const byDate = new Map<string, number>();
    for (const r of q.data ?? []) byDate.set(r.date, (byDate.get(r.date) ?? 0) + r.count);
    const out: ActivityPoint[] = [];
    for (let i = n - 1; i >= 0; i--) {
      const d = new Date();
      d.setUTCDate(d.getUTCDate() - i);
      const key = d.toISOString().slice(0, 10);
      out.push({ date: key, label: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }), events: byDate.get(key) ?? 0 });
    }
    return out;
  }, [q.data, days]);
  const total = data.reduce((a, p) => a + p.events, 0);

  return (
    <Panel
      title="Workspace activity"
      description={q.data ? `${total} recorded events in the last ${days} days` : "Tool runs, searches, commands and project changes"}
      actions={
        <Tabs selectedKey={days} onSelectionChange={(k) => setDays(String(k) as "7" | "30" | "90")}>
          <Tabs.ListContainer>
            <Tabs.List aria-label="Time range" className="h-8">
              {(["7", "30", "90"] as const).map((d) => (
                <Tabs.Tab key={d} id={d} className="px-2.5 text-[12.5px]">
                  {d === "7" ? "7 days" : d === "30" ? "30 days" : "90 days"}
                  <Tabs.Indicator />
                </Tabs.Tab>
              ))}
            </Tabs.List>
          </Tabs.ListContainer>
        </Tabs>
      }
      className="h-full"
    >
      <QueryView query={q} rows={4}>
        {() =>
          total === 0 ? (
            <EmptyBlock compact icon={Radar} title="No activity in this period" description="Activity appears as you run tools, copy commands, search dorks or update projects." />
          ) : (
            <ActivityAreaChart data={data} />
          )
        }
      </QueryView>
    </Panel>
  );
}

/* ───────────────────────── KPI tiles ───────────────────────── */

export function KpiWidget() {
  const { runtime, detections } = useApp();
  const projects = useQuery(["projects"], api.projectsList, [], runtime);
  const history = useQuery(["history"], () => api.commandHistoryList(500), [], runtime);
  const tasks = useQuery(["tasks"], api.tasksList, [], runtime);

  const installed = [...detections.values()].filter((d) => d.status === "installed").length;
  const active = (projects.data ?? []).filter((p) => p.status === "active").length;
  const openFindings = (projects.data ?? []).reduce((a, p) => a + p.openFindings, 0);
  const weekAgo = Date.now() - 7 * 86400_000;
  const commandsWeek = (history.data ?? []).filter((h) => new Date(h.createdAt).getTime() > weekAgo).length;
  const pending = (tasks.data ?? []).filter((t) => !t.done).length;

  const tiles = [
    { label: "Installed tools", value: installed, icon: Boxes, hint: detections.size ? "From the last scan" : "Not scanned yet", tone: "default" },
    { label: "Active projects", value: active, icon: FolderKanban, hint: `${projects.data?.length ?? 0} total`, tone: "default" },
    { label: "Open findings", value: openFindings, icon: Search, hint: openFindings ? "Not yet resolved or accepted" : "None recorded", tone: openFindings ? "warning" : "success" },
    { label: "Commands this week", value: commandsWeek, icon: SquareTerminal, hint: `${pending} pending tasks`, tone: "default" },
  ] as const;

  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
      {tiles.map((t) => (
        <div key={t.label} className="panel flex items-start gap-3 p-4">
          <FeaturedIcon icon={t.icon} size="md" color="gray" />
          <div className="min-w-0">
            <div className="text-[12.5px] text-muted">{t.label}</div>
            <div className="tabular mt-0.5 text-[22px] leading-tight font-semibold tracking-tight">
              {runtime ? <CountUp to={t.value} duration={0.6} trigger="load" /> : "—"}
            </div>
            <div className={cn("mt-0.5 flex items-center gap-1.5 text-[12px]", t.tone === "warning" ? "text-warning-soft-foreground" : t.tone === "success" ? "text-success-soft-foreground" : "text-muted")}>
              {t.tone !== "default" && <StatusDot tone={t.tone} />}
              {t.hint}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ───────────────────────── Recent activity feed ───────────────────────── */

const FEED_FILTERS: { id: string; label: string; kinds: string[] | null }[] = [
  { id: "all", label: "All activity", kinds: null },
  { id: "tools", label: "Tools", kinds: ["tool_run", "tool_install", "tool_launch", "tool_scan"] },
  { id: "projects", label: "Projects & findings", kinds: ["project", "finding"] },
  { id: "research", label: "Research", kinds: ["dork_search", "dork_saved", "resource_open", "cve_search", "vt_lookup", "vt_upload", "ti_lookup", "vuln_lookup"] },
  { id: "commands", label: "Commands & utilities", kinds: ["command_copy", "command_saved", "utility", "payload_copy", "wordlist"] },
];

export function ActivityFeedWidget() {
  const { runtime } = useApp();
  const [filter, setFilter] = useState("all");
  const q = useQuery(["activity"], () => api.activityList(150), [], runtime);
  const f = FEED_FILTERS.find((x) => x.id === filter)!;
  const items = (q.data ?? []).filter((a) => !f.kinds || f.kinds.includes(a.kind)).slice(0, 12);

  return (
    <Panel
      title="Recent activity"
      description="Everything recorded locally on this workstation"
      actions={
        <Dropdown>
          <Button size="sm" variant="tertiary" className="gap-1.5">
            {f.label}
            <ChevronDown className="size-3.5" />
          </Button>
          <Dropdown.Popover placement="bottom end">
            <Dropdown.Menu aria-label="Filter activity" selectionMode="single" selectedKeys={[filter]} onAction={(k) => setFilter(String(k))}>
              {FEED_FILTERS.map((o) => (
                <Dropdown.Item key={o.id} id={o.id} textValue={o.label}>
                  {o.label}
                  <Dropdown.ItemIndicator />
                </Dropdown.Item>
              ))}
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
      }
      className="h-full"
    >
      <QueryView query={q} rows={6}>
        {() =>
          items.length === 0 ? (
            <EmptyBlock icon={Radar} title="No activity yet" description="Runs, installs, searches and project updates will be listed here." />
          ) : (
            <ul className="-mx-2 flex flex-col gap-0.5">
              {items.map((a) => (
                <li key={a.id} className="flex items-start gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-white/[0.025]">
                  <ActivityIcon kind={a.kind} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px] text-foreground">{a.title}</div>
                    <div className="truncate text-[12px] text-muted">
                      {ACTIVITY_META[a.kind]?.label ?? a.kind}
                      {a.detail ? ` · ${a.detail}` : ""}
                    </div>
                  </div>
                  <div className="shrink-0 pt-0.5 text-[12px] text-muted tabular">{formatRelative(a.createdAt)}</div>
                </li>
              ))}
            </ul>
          )
        }
      </QueryView>
    </Panel>
  );
}

/* ───────────────────────── Pending tasks ───────────────────────── */

export function TasksWidget() {
  const { runtime } = useApp();
  const q = useQuery(["tasks"], api.tasksList, [], runtime);
  const [title, setTitle] = useState("");
  const pending = (q.data ?? []).filter((t) => !t.done).length;

  const add = async () => {
    if (!title.trim()) return;
    try {
      await api.taskUpsert({ title, done: false });
      setTitle("");
      invalidate("tasks");
    } catch (e) {
      notify.error("Could not add task", e);
    }
  };

  return (
    <Panel title="What needs doing" description={q.data ? `${pending} pending` : "Personal task list"} className="h-full">
      <div className="mb-3 flex gap-2">
        <TextInput aria-label="New task" value={title} onChange={setTitle} placeholder="Add a task and press Enter" onEnter={add} className="flex-1" />
        <Button isIconOnly variant="tertiary" aria-label="Add task" onPress={add} isDisabled={!title.trim()}>
          <Plus className="size-4" />
        </Button>
      </div>
      <QueryView
        query={q}
        rows={3}
        isEmpty={(d) => d.length === 0}
        empty={<EmptyBlock compact icon={ListTodo} title="No tasks" description="Track follow-ups like retests, report deadlines or scope confirmations." />}
      >
        {(tasks) => (
          <ul className="flex flex-col gap-1.5">
            {tasks.slice(0, 8).map((t) => (
              <li key={t.id} className={cn("tile group flex items-center gap-2.5 px-2.5 py-2", t.done && "opacity-60")}>
                <Checkbox
                  isSelected={t.done}
                  onChange={async (v) => {
                    await api.taskUpsert({ id: t.id, title: t.title, done: v, projectId: t.projectId, dueDate: t.dueDate }).catch((e) => notify.error("Could not update task", e));
                    invalidate("tasks");
                  }}
                  aria-label={`Mark “${t.title}” ${t.done ? "not done" : "done"}`}
                >
                  <Checkbox.Content>
                    <Checkbox.Control>
                      <Checkbox.Indicator />
                    </Checkbox.Control>
                  </Checkbox.Content>
                </Checkbox>
                <div className="min-w-0 flex-1">
                  <div className={cn("truncate text-[13px]", t.done && "line-through")}>{t.title}</div>
                  {(t.projectName || t.dueDate) && (
                    <div className="truncate text-[11.5px] text-muted">{[t.projectName, t.dueDate && `due ${t.dueDate}`].filter(Boolean).join(" · ")}</div>
                  )}
                </div>
                <Button
                  isIconOnly
                  size="sm"
                  variant="ghost"
                  aria-label="Delete task"
                  className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100"
                  onPress={async () => {
                    await api.taskDelete(t.id).catch((e) => notify.error("Could not delete task", e));
                    invalidate("tasks");
                  }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

/* ───────────────────────── Tools: favorites & recent ───────────────────────── */

export function ToolsWidget() {
  const { catalog, favorites, detections, navigate, runtime } = useApp();
  const activity = useQuery(["activity"], () => api.activityList(300), [], runtime);
  const [tab, setTab] = useState<"favorites" | "recent">("favorites");

  const favTools = favorites.filter((f) => f.kind === "tool").map((f) => catalog?.tools.find((t) => t.id === f.itemId)).filter(Boolean);
  const recentIds: string[] = [];
  for (const a of activity.data ?? []) {
    if (a.refKind === "tool" && a.refId && !recentIds.includes(a.refId)) recentIds.push(a.refId);
  }
  const recentTools = recentIds.map((id) => catalog?.tools.find((t) => t.id === id)).filter(Boolean);
  const list = (tab === "favorites" ? favTools : recentTools).slice(0, 6);

  return (
    <Panel
      title="Tools"
      className="h-full"
      actions={
        <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(k as "favorites" | "recent")}>
          <Tabs.ListContainer>
            <Tabs.List aria-label="Tool list" className="h-8">
              <Tabs.Tab id="favorites" className="px-2.5 text-[12.5px]">Favorites<Tabs.Indicator /></Tabs.Tab>
              <Tabs.Tab id="recent" className="px-2.5 text-[12.5px]">Recently used<Tabs.Indicator /></Tabs.Tab>
            </Tabs.List>
          </Tabs.ListContainer>
        </Tabs>
      }
    >
      {list.length === 0 ? (
        <EmptyBlock
          compact
          icon={tab === "favorites" ? Star : Boxes}
          title={tab === "favorites" ? "No favorite tools" : "No tools used yet"}
          description={tab === "favorites" ? "Star tools in the Tools Library to pin them here." : "Tools you run, launch or install appear here."}
          action={<Button size="sm" variant="tertiary" onPress={() => navigate("tools")}>Open Tools Library</Button>}
        />
      ) : (
        <ul className="flex flex-col gap-1">
          {list.map((t) => {
            const d = detections.get(t!.id);
            const meta = t!.kind === "web" ? DETECTION_META.catalog : DETECTION_META[d?.status ?? "unknown"];
            return (
              <li key={t!.id}>
                <button
                  type="button"
                  onClick={() => navigate("tools", { tool: t!.id })}
                  className="flex w-full items-center gap-3 rounded-lg px-2 py-1.5 text-left outline-none hover:bg-white/[0.035] focus-visible:ring-2 focus-visible:ring-focus"
                >
                  <FeaturedIcon icon={Boxes} size="sm" color="gray" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px]">{t!.name}</div>
                    <div className="truncate text-[12px] text-muted">{d?.version ? `v${d.version}` : t!.tags.slice(0, 3).join(", ")}</div>
                  </div>
                  <span className="flex items-center gap-1.5 text-[12px] text-muted">
                    <StatusDot tone={meta.tone} />
                    {meta.label}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

/* ───────────────────────── Recent commands ───────────────────────── */

export function RecentCommandsWidget() {
  const { runtime, navigate } = useApp();
  const q = useQuery(["history"], () => api.commandHistoryList(8), [], runtime);
  return (
    <Panel title="Recent commands" description="Copied, built or executed" className="h-full" actions={<Button size="sm" variant="ghost" onPress={() => navigate("commands", { tab: "history" })}>History</Button>}>
      <QueryView
        query={q}
        rows={4}
        isEmpty={(d) => d.length === 0}
        empty={<EmptyBlock compact icon={SquareTerminal} title="No commands yet" description="Commands you copy or build in Command Center are kept here." />}
      >
        {(items) => (
          <ul className="flex flex-col gap-1.5">
            {items.map((h) => (
              <li key={h.id} className="flex items-center gap-2 rounded-lg bg-background-secondary py-1 pr-1 pl-3">
                <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground">{h.command}</code>
                <span className="shrink-0 text-[11.5px] text-muted">{formatRelative(h.createdAt)}</span>
                <CopyButton text={h.command} label="Copy command" onCopy={(t) => copyCommand(t, "manual", h.toolId)} />
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

/* ───────────────────────── Recent projects ───────────────────────── */

export function RecentProjectsWidget() {
  const { runtime, navigate } = useApp();
  const q = useQuery(["projects"], api.projectsList, [], runtime);
  return (
    <Panel title="Recent projects" className="h-full" actions={<Button size="sm" variant="ghost" onPress={() => navigate("projects")}>All projects</Button>}>
      <QueryView
        query={q}
        rows={3}
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyBlock
            compact
            icon={FolderKanban}
            title="No projects yet"
            description="Create a project to define an authorized scope before running tools against targets."
            action={<Button size="sm" variant="primary" onPress={() => navigate("projects", { new: "1" })}><Plus className="size-3.5" />New project</Button>}
          />
        }
      >
        {(items) => (
          <ul className="flex flex-col gap-1">
            {items.slice(0, 5).map((p) => (
              <li key={p.id}>
                <button
                  type="button"
                  onClick={() => navigate("projects", { project: String(p.id) })}
                  className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left outline-none hover:bg-white/[0.035] focus-visible:ring-2 focus-visible:ring-focus"
                >
                  <FeaturedIcon icon={FolderKanban} size="sm" color={p.status === "active" ? "brand" : "gray"} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px]">{p.name}</div>
                    <div className="truncate text-[12px] text-muted">
                      {p.targetCount} scope entries · {p.openFindings} open findings · updated {formatRelative(p.updatedAt)}
                    </div>
                  </div>
                  <ToneChip tone={PROJECT_STATUS_META[p.status].tone}>{PROJECT_STATUS_META[p.status].label}</ToneChip>
                </button>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

/* ───────────────────────── Quick actions ───────────────────────── */

export function QuickActionsWidget() {
  const { navigate, setPaletteOpen } = useApp();
  const actions = [
    { label: "New project", hint: "Define scope first", icon: FolderKanban, run: () => navigate("projects", { new: "1" }) },
    { label: "Build a command", hint: "Nmap, FFUF, Nuclei…", icon: SquareTerminal, run: () => navigate("commands", { tab: "builders" }) },
    { label: "Compose a dork", hint: "Visual query builder", icon: Search, run: () => navigate("dorks") },
    { label: "Look up a CVE", hint: "NVD search with cache", icon: Radar, run: () => navigate("intel") },
    { label: "Decode data", hint: "Transform workbench", icon: Wrench, run: () => navigate("utilities", { utility: "workbench" }) },
    { label: "Search everything", hint: "Ctrl + K", icon: Copy, run: () => setPaletteOpen(true) },
  ];
  return (
    <Panel title="Quick actions" className="h-full">
      <div className="grid grid-cols-2 gap-2">
        {actions.map((a) => (
          <button
            key={a.label}
            type="button"
            onClick={a.run}
            className="tile flex items-center gap-2.5 px-2.5 py-2 text-left outline-none transition-colors hover:bg-white/[0.05] focus-visible:ring-2 focus-visible:ring-focus"
          >
            <a.icon className="size-4 shrink-0 text-accent-soft-foreground" strokeWidth={1.75} />
            <div className="min-w-0">
              <div className="truncate text-[13px]">{a.label}</div>
              <div className="truncate text-[11.5px] text-muted">{a.hint}</div>
            </div>
          </button>
        ))}
      </div>
    </Panel>
  );
}

/* ───────────────────────── Resource shortcuts ───────────────────────── */

export function ResourcesWidget() {
  const { runtime, favorites, navigate } = useApp();
  const recent = useQuery(["resources"], () => api.resourceRecent(6), [], runtime);
  const favIds = favorites.filter((f) => f.kind === "resource").map((f) => f.itemId);
  const favRes = RESOURCES.filter((r) => favIds.includes(r.id));
  const fallback = RESOURCES.filter((r) => ["portswigger-academy", "mitre-attack", "nvd", "owasp-cheatsheets"].includes(r.id));
  const shortcuts = (favRes.length ? favRes : fallback).slice(0, 6);

  return (
    <Panel title="Resource shortcuts" description={favRes.length ? "Your favorites" : "Suggested — star resources to replace these"} className="h-full" actions={<Button size="sm" variant="ghost" onPress={() => navigate("resources")}>Directory</Button>}>
      <div className="flex flex-wrap gap-1.5">
        {shortcuts.map((r) => (
          <Button key={r.id} size="sm" variant="tertiary" onPress={() => openResource(r.id, r.title, r.url)}>
            <BookMarked className="size-3.5" />
            {r.title}
          </Button>
        ))}
      </div>
      {(recent.data?.length ?? 0) > 0 && (
        <>
          <div className="mt-4 mb-1.5 text-[12px] text-muted">Recently visited</div>
          <ul className="flex flex-col">
            {recent.data!.map((v) => (
              <li key={v.resourceKey}>
                <button type="button" onClick={() => openResource(v.resourceKey, v.title, v.url)} className="flex w-full items-center justify-between gap-3 rounded-md px-1 py-1 text-left text-[13px] hover:bg-white/[0.035]">
                  <span className="truncate">{v.title}</span>
                  <span className="shrink-0 text-[11.5px] text-muted">{formatRelative(v.visitedAt)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

/* ───────────────────────── System info ───────────────────────── */

export function SystemWidget() {
  const { system, runtime } = useApp();
  if (!runtime || !system) {
    return (
      <Panel title="System" className="h-full">
        <EmptyBlock compact icon={Cpu} title="Desktop runtime not connected" description="System information is read locally by the Cyber Hub backend." />
      </Panel>
    );
  }
  const memPct = system.totalMemory ? Math.round((system.usedMemory / system.totalMemory) * 100) : 0;
  const rows: [string, string][] = [
    ["Host", system.hostname],
    ["Operating system", `${system.osName} ${system.osVersion}`],
    ["Kernel", system.kernelVersion],
    ["Architecture", system.arch],
    ["CPU", `${system.cpuBrand} · ${system.cpuCores} threads`],
    ["Uptime", formatDuration(system.uptimeSecs)],
    ["Cyber Hub", `v${system.appVersion} · schema ${system.dbSchemaVersion}`],
  ];
  return (
    <Panel title="System" description="Read locally, never sent anywhere" className="h-full">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[13px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="truncate text-right" title={v}>{v}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-3">
        <div className="mb-1 flex justify-between text-[12px] text-muted">
          <Label>Memory</Label>
          <span className="tabular">
            {formatBytes(system.usedMemory)} of {formatBytes(system.totalMemory)}
          </span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]" role="meter" aria-valuenow={memPct} aria-valuemin={0} aria-valuemax={100} aria-label="Memory usage">
          <div className={cn("h-full rounded-full", memPct > 85 ? "bg-warning" : "bg-accent")} style={{ width: `${memPct}%` }} />
        </div>
      </div>
    </Panel>
  );
}
