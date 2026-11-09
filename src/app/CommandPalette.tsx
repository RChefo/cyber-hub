import { Modal } from "@heroui/react";
import {
  BookMarked,
  Boxes,
  Bug,
  CornerDownLeft,
  FileArchive,
  FileText,
  FolderKanban,
  LayoutGrid,
  Network,
  Package,
  Route,
  Search,
  Server,
  ShieldAlert,
  SquareTerminal,
  Syringe,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Kbd } from "@/components/ui/Code";
import { COMMAND_TEMPLATES } from "@/data/commandTemplates";
import { DORK_TEMPLATES } from "@/data/dorkTemplates";
import { PAYLOADS } from "@/data/payloads";
import { RESOURCES } from "@/data/resources";
import { openResource } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { RecordKind, SearchHit } from "@/lib/types";
import { cn } from "@/lib/utils";
import { KIND_LABEL, refKey } from "@/modules/projects/investigation";
import { UTILITIES } from "@/modules/utilities/registry";
import { ALL_NAV, type PageId } from "./routes";
import { useApp } from "./store";

interface ResultItem {
  key: string;
  group: string;
  icon: LucideIcon;
  title: string;
  subtitle?: string;
  haystack: string;
  run: () => void;
}

/** Groups whose subtitles are literal data (commands, queries, URLs, paths). */
const MONO_GROUPS = new Set(["Commands", "Dorks", "Resources", "Wordlists"]);

const GROUP_ORDER = ["Pages", "Tools", "Projects", "Records", "Commands", "Resources", "Dorks", "Payloads", "Wordlists", "Utilities"];

/** Project records found by the backend (techniques have no project and are left out here). */
const RECORD_KINDS: RecordKind[] = ["finding", "asset", "vulnerability", "evidence", "osint_entity", "execution", "api_endpoint", "sbom_component"];
const RECORD_ICON: Partial<Record<RecordKind, LucideIcon>> = { finding: Bug, asset: Server, vulnerability: ShieldAlert, evidence: FileArchive, osint_entity: Network, execution: SquareTerminal, api_endpoint: Route, sbom_component: Package };

function score(item: ResultItem, terms: string[]): number {
  let s = 0;
  const title = item.title.toLowerCase();
  for (const t of terms) {
    if (title.startsWith(t)) s += 6;
    else if (title.includes(t)) s += 4;
    else if (item.haystack.includes(t)) s += 1;
    else return 0;
  }
  return s;
}

export function CommandPalette() {
  const { paletteOpen, setPaletteOpen, navigate, catalog, runtime } = useApp();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const enabled = paletteOpen && runtime;
  const projects = useQuery(["projects"], api.projectsList, [], enabled);
  const savedCommands = useQuery(["commands"], api.savedCommandsList, [], enabled);
  const savedDorks = useQuery(["dorks"], api.savedDorksList, [], enabled);
  const customPayloads = useQuery(["payloads"], api.customPayloadsList, [], enabled);
  const wordlists = useQuery(["wordlists"], api.wordlistsList, [], enabled);
  const customResources = useQuery(["resources"], api.customResourcesList, [], enabled);

  // records of open projects, searched in the backend as the query is typed
  const [records, setRecords] = useState<SearchHit[]>([]);
  useEffect(() => {
    const q = query.trim();
    if (!enabled || q.length < 2) {
      setRecords([]);
      return;
    }
    let stale = false;
    const t = setTimeout(() => {
      api.recordsSearch({ text: q, kinds: RECORD_KINDS, includeArchived: false, limit: 24 }).then(
        (hits) => !stale && setRecords(hits),
        () => !stale && setRecords([]),
      );
    }, 180);
    return () => {
      stale = true;
      clearTimeout(t);
    };
  }, [query, enabled]);

  const close = () => setPaletteOpen(false);
  const go = (page: PageId, params?: Record<string, string>) => () => {
    navigate(page, params);
    close();
  };

  const items = useMemo<ResultItem[]>(() => {
    const out: ResultItem[] = [];
    for (const n of ALL_NAV) out.push({ key: `page:${n.id}`, group: "Pages", icon: LayoutGrid, title: n.label, subtitle: n.description, haystack: `${n.label} ${n.description}`.toLowerCase(), run: go(n.id) });
    for (const t of catalog?.tools ?? [])
      out.push({ key: `tool:${t.id}`, group: "Tools", icon: Boxes, title: t.name, subtitle: t.description, haystack: `${t.name} ${t.id} ${t.tags.join(" ")} ${t.category} ${t.description}`.toLowerCase(), run: go("tools", { tool: t.id }) });
    for (const p of projects.data ?? [])
      out.push({ key: `project:${p.id}`, group: "Projects", icon: FolderKanban, title: p.name, subtitle: p.description || p.status, haystack: `${p.name} ${p.description}`.toLowerCase(), run: go("projects", { project: String(p.id) }) });
    for (const c of COMMAND_TEMPLATES)
      out.push({ key: `tpl:${c.id}`, group: "Commands", icon: SquareTerminal, title: c.title, subtitle: c.template, haystack: `${c.title} ${c.template} ${c.category} ${c.description}`.toLowerCase(), run: go("commands", { template: c.id }) });
    for (const c of savedCommands.data ?? [])
      out.push({ key: `cmd:${c.id}`, group: "Commands", icon: SquareTerminal, title: c.title, subtitle: c.command, haystack: `${c.title} ${c.command} ${c.tags.join(" ")}`.toLowerCase(), run: go("commands", { saved: String(c.id) }) });
    for (const r of RESOURCES)
      out.push({ key: `res:${r.id}`, group: "Resources", icon: BookMarked, title: r.title, subtitle: r.url, haystack: `${r.title} ${r.description} ${r.tags.join(" ")} ${r.url}`.toLowerCase(), run: () => { openResource(r.id, r.title, r.url); close(); } });
    for (const r of customResources.data ?? [])
      out.push({ key: `cres:${r.id}`, group: "Resources", icon: BookMarked, title: r.title, subtitle: r.url, haystack: `${r.title} ${r.description} ${r.url}`.toLowerCase(), run: () => { openResource(`custom:${r.id}`, r.title, r.url); close(); } });
    for (const d of savedDorks.data ?? [])
      out.push({ key: `dork:${d.id}`, group: "Dorks", icon: Search, title: d.title, subtitle: d.query, haystack: `${d.title} ${d.query}`.toLowerCase(), run: go("dorks", { query: d.query }) });
    for (const d of DORK_TEMPLATES)
      out.push({ key: `dtpl:${d.id}`, group: "Dorks", icon: Search, title: d.title, subtitle: d.query, haystack: `${d.title} ${d.query} ${d.description}`.toLowerCase(), run: go("dorks", { template: d.id }) });
    for (const p of PAYLOADS)
      out.push({ key: `pl:${p.id}`, group: "Payloads", icon: Syringe, title: p.title, subtitle: p.category.toUpperCase(), haystack: `${p.title} ${p.category} ${p.description} ${p.tags.join(" ")}`.toLowerCase(), run: go("payloads", { payload: p.id }) });
    for (const p of customPayloads.data ?? [])
      out.push({ key: `cpl:${p.id}`, group: "Payloads", icon: Syringe, title: p.title, subtitle: p.category.toUpperCase(), haystack: `${p.title} ${p.category} ${p.description}`.toLowerCase(), run: go("payloads", { payload: `custom:${p.id}` }) });
    for (const w of wordlists.data ?? [])
      out.push({ key: `wl:${w.id}`, group: "Wordlists", icon: FileText, title: w.name, subtitle: w.path, haystack: `${w.name} ${w.category} ${w.path}`.toLowerCase(), run: go("payloads", { tab: "wordlists", wordlist: String(w.id) }) });
    for (const u of UTILITIES)
      out.push({ key: `util:${u.id}`, group: "Utilities", icon: Wrench, title: u.name, subtitle: u.description, haystack: `${u.name} ${u.description} ${u.group}`.toLowerCase(), run: go("utilities", { utility: u.id }) });
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog, projects.data, savedCommands.data, savedDorks.data, customPayloads.data, wordlists.data, customResources.data]);

  const results = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return items.filter((i) => i.group === "Pages");
    const scored = items
      .map((i) => ({ i, s: score(i, terms) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s);
    const perGroup = new Map<string, ResultItem[]>();
    for (const { i } of scored) {
      const g = perGroup.get(i.group) ?? [];
      if (g.length < 6) g.push(i);
      perGroup.set(i.group, g);
    }
    perGroup.set(
      "Records",
      records.filter((h) => h.projectId != null).slice(0, 8).map((h) => {
        const pid = String(h.projectId);
        const params: Record<string, string> = h.node.ref.kind === "finding" ? { project: pid, tab: "findings", finding: String(h.node.ref.id) } : { project: pid, tab: "investigation", record: refKey(h.node.ref) };
        return {
          key: `rec:${h.node.key}`,
          group: "Records",
          icon: RECORD_ICON[h.node.ref.kind] ?? Search,
          title: h.node.label,
          subtitle: [`${KIND_LABEL[h.node.ref.kind]} in ${h.project}`, h.node.detail].filter(Boolean).join(" · "),
          haystack: "",
          run: () => {
            // the time makes a second jump to the same record apply again
            navigate("projects", { ...params, at: String(Date.now()) });
            close();
          },
        };
      }),
    );
    return GROUP_ORDER.flatMap((g) => perGroup.get(g) ?? []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, query, records]);

  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    if (!paletteOpen) setQuery("");
  }, [paletteOpen]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      results[active]?.run();
    }
  };

  let lastGroup = "";
  return (
    <Modal.Backdrop isOpen={paletteOpen} onOpenChange={setPaletteOpen}>
        <Modal.Container placement="top" size="lg" className="pt-[12vh]">
          <Modal.Dialog className="overflow-hidden bg-overlay p-0 sm:max-w-[640px]" aria-label="Global search">
            <div className="flex items-center gap-2.5 bg-white/[0.02] px-4">
              <Search className="size-[18px] text-muted" strokeWidth={1.75} />
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={onKeyDown}
                placeholder="Search tools, commands, projects and their records (findings, assets, evidence…), resources, dorks, payloads"
                className="h-12 flex-1 bg-transparent text-[14.5px] text-foreground outline-none placeholder:text-field-placeholder"
                aria-label="Search query"
                role="combobox"
                aria-expanded="true"
                aria-controls="palette-results"
                aria-activedescendant={results[active] ? `palette-${results[active].key}` : undefined}
              />
              <Kbd>Esc</Kbd>
            </div>
            <div ref={listRef} id="palette-results" role="listbox" className="scroll-area max-h-[min(460px,60vh)] p-1.5">
              {results.length === 0 && <div className="px-3 py-10 text-center text-[13px] text-muted">No matches for “{query}”.</div>}
              {results.map((r, idx) => {
                const header = r.group !== lastGroup ? r.group : null;
                lastGroup = r.group;
                const Icon = r.icon;
                return (
                  <div key={r.key}>
                    {header && <div className="px-2.5 pt-2.5 pb-1 text-[11.5px] font-medium text-muted">{header}</div>}
                    <div
                      id={`palette-${r.key}`}
                      role="option"
                      aria-selected={idx === active}
                      data-index={idx}
                      onMouseMove={() => setActive(idx)}
                      onClick={() => r.run()}
                      className={cn("flex cursor-pointer items-center gap-3 rounded-lg px-2.5 py-2", idx === active ? "bg-white/[0.06]" : "")}
                    >
                      <Icon className="size-4 shrink-0 text-muted" strokeWidth={1.75} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13.5px] text-foreground">{r.title}</div>
                        {r.subtitle && (
                          <div className={cn("truncate text-muted", MONO_GROUPS.has(r.group) ? "font-mono text-[11.5px]" : "text-[12px]")}>{r.subtitle}</div>
                        )}
                      </div>
                      {idx === active && <CornerDownLeft className="size-3.5 text-muted" />}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-4 bg-white/[0.02] px-4 py-2 text-[11.5px] text-muted">
              <span className="flex items-center gap-1.5"><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span>
              <span className="flex items-center gap-1.5"><Kbd>↵</Kbd> open</span>
              {!runtime && <span className="ml-auto">Desktop runtime offline — only static catalogs are searchable</span>}
            </div>
          </Modal.Dialog>
        </Modal.Container>
    </Modal.Backdrop>
  );
}
