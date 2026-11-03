import { Button, Tooltip } from "@heroui/react";
import { icons, Boxes, ScanLine, Star } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { DETECTION_META, StatusDot } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput } from "@/components/ui/Fields";
import { PageHeader } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import type { ToolDef } from "@/types/catalog";
import { cn, formatRelative } from "@/lib/utils";
import { ToolDetail } from "./ToolDetail";

type StatusFilter = "all" | "installed" | "missing" | "attention" | "web";

const STATUS_OPTIONS = [
  { id: "all", label: "All statuses" },
  { id: "installed", label: "Installed" },
  { id: "missing", label: "Not installed" },
  { id: "attention", label: "Needs attention" },
  { id: "web", label: "Web services & scripts" },
];

function iconFor(name: string) {
  const key = name.replace(/(^|-)(\w)/g, (_, __, c: string) => c.toUpperCase()) as keyof typeof icons;
  return icons[key] ?? Boxes;
}

export default function ToolsPage() {
  const { catalog, catalogError, detections, os, route, navigate, isFavorite, toggleFavorite, scanTools, scanning, prefs, runtime } = useApp();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [onlyMyOs, setOnlyMyOs] = useState(false);
  const category = route.params?.category ?? "all";
  const selectedId = route.params?.tool;
  const lastScan = typeof prefs["tools.lastScan"] === "string" ? (prefs["tools.lastScan"] as string) : null;

  const statusOf = (t: ToolDef) => (t.kind === "web" ? "catalog" : t.kind === "script" ? "script" : detections.get(t.id)?.status ?? "unknown");

  const filtered = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    return (catalog?.tools ?? []).filter((t) => {
      if (category === "favorites" ? !isFavorite("tool", t.id) : category !== "all" && t.category !== category) return false;
      if (onlyMyOs && !t.os.includes(os)) return false;
      const s = statusOf(t);
      if (status === "installed" && s !== "installed" && s !== "dependency_missing") return false;
      if (status === "missing" && !(s === "not_installed" || s === "unknown")) return false;
      if (status === "attention" && !(s === "dependency_missing" || s === "installation_failed")) return false;
      if (status === "web" && !(t.kind === "web" || t.kind === "script")) return false;
      const hay = `${t.name} ${t.id} ${t.description} ${t.tags.join(" ")}`.toLowerCase();
      return terms.every((x) => hay.includes(x));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog, query, status, onlyMyOs, category, detections, os, isFavorite]);

  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const t of catalog?.tools ?? []) m.set(t.category, (m.get(t.category) ?? 0) + 1);
    return m;
  }, [catalog]);

  const selected = catalog?.tools.find((t) => t.id === selectedId);
  const setParam = (patch: Record<string, string | undefined>) => {
    const next = { ...(route.params ?? {}), ...patch };
    Object.keys(next).forEach((k) => next[k] === undefined && delete next[k]);
    navigate("tools", next as Record<string, string>);
  };

  if (catalogError) return <ErrorBlock message={catalogError} />;
  if (!catalog) return <LoadingRows rows={8} />;

  const rail = [
    { id: "all", name: "All tools", icon: "layout-grid", count: catalog.tools.length },
    { id: "favorites", name: "Favorites", icon: "star", count: catalog.tools.filter((t) => isFavorite("tool", t.id)).length },
    ...catalog.categories.map((c) => ({ id: c.id, name: c.name, icon: c.icon, count: counts.get(c.id) ?? 0 })),
  ];

  return (
    <div>
      <PageHeader
        title="Tools Library"
        description={`${catalog.tools.length} curated tools across ${catalog.categories.length} categories. Detection checks PATH and known install locations — it never assumes a tool is installed.`}
        actions={
          <>
            <span className="text-[12.5px] text-muted">{lastScan ? `Last scan ${formatRelative(lastScan)}` : "Not scanned yet"}</span>
            <Button size="sm" variant="tertiary" isPending={scanning} isDisabled={!runtime} onPress={() => scanTools(false)}>
              <ScanLine className="size-3.5" />
              Scan system
            </Button>
            <Button size="sm" variant="ghost" isDisabled={!runtime || scanning} onPress={() => scanTools(true)}>
              Detect versions
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[208px_1fr]">
        <nav aria-label="Tool categories" className="flex flex-col gap-0.5 lg:sticky lg:top-0 lg:self-start">
          {rail.map((r) => {
            const Icon = iconFor(r.icon);
            const active = category === r.id;
            return (
              <Button
                key={r.id}
                variant="ghost"
                onPress={() => setParam({ category: r.id === "all" ? undefined : r.id, tool: undefined })}
                aria-current={active ? "true" : undefined}
                className={cn(
                  "h-8 w-full justify-start gap-2.5 rounded-md px-2.5 text-[13px] font-normal",
                  active ? "bg-white/[0.06] text-foreground" : "text-muted hover:text-foreground",
                )}
              >
                <Icon className="size-4 shrink-0" strokeWidth={1.75} />
                <span className="flex-1 truncate text-left">{r.name}</span>
                <span className="text-[11.5px] text-muted tabular">{r.count}</span>
              </Button>
            );
          })}
        </nav>

        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <SearchInput value={query} onChange={setQuery} placeholder="Search by name, tag or capability" className="max-w-[340px]" />
            <SelectInput aria-label="Status filter" value={status} onChange={(v) => setStatus(v as StatusFilter)} options={STATUS_OPTIONS} className="w-[190px]" />
            <SwitchInput label="Available for my OS" isSelected={onlyMyOs} onChange={setOnlyMyOs} />
            <span className="ml-auto text-[12.5px] text-muted">{filtered.length} shown</span>
          </div>

          <div className={cn("grid gap-3", selected ? "xl:grid-cols-[minmax(0,1fr)_minmax(420px,520px)]" : "")}>
            <div className={cn("grid content-start gap-2.5", selected ? "grid-cols-1 2xl:grid-cols-2" : "grid-cols-1 md:grid-cols-2 2xl:grid-cols-3")}>
              {filtered.length === 0 && (
                <div className="col-span-full">
                  <EmptyBlock icon={Boxes} title="No tools match" description="Try a different search, category or status filter." />
                </div>
              )}
              {filtered.map((t) => {
                const s = statusOf(t);
                const meta = s === "script" ? { label: "Script", tone: "default" as const } : DETECTION_META[s];
                const det = detections.get(t.id);
                const cat = catalog.categories.find((c) => c.id === t.category);
                const fav = isFavorite("tool", t.id);
                const active = selectedId === t.id;
                return (
                  <div
                    key={t.id}
                    className={cn(
                      "panel group relative flex cursor-pointer flex-col gap-2 p-3.5 transition-colors",
                      active ? "bg-surface-secondary" : "hover:bg-surface-hover",
                    )}
                    onClick={() => setParam({ tool: t.id })}
                  >
                    <div className="flex items-start gap-3">
                      <FeaturedIcon icon={iconFor(cat?.icon ?? "boxes")} size="sm" color={s === "installed" ? "brand" : "gray"} />
                      <div className="min-w-0 flex-1">
                        <button
                          type="button"
                          className="block max-w-full truncate rounded text-left text-[14px] font-medium outline-none after:absolute after:inset-0 focus-visible:ring-2 focus-visible:ring-focus"
                          onClick={(e) => {
                            e.stopPropagation();
                            setParam({ tool: t.id });
                          }}
                          aria-label={`${t.name} details`}
                        >
                          {t.name}
                        </button>
                        <div className="truncate text-[12px] text-muted">{cat?.name}</div>
                      </div>
                      <Tooltip delay={400}>
                        <Button
                          isIconOnly
                          size="sm"
                          variant="ghost"
                          className="relative z-10 -mt-1 -mr-1"
                          aria-label={fav ? `Remove ${t.name} from favorites` : `Add ${t.name} to favorites`}
                          onPress={() => toggleFavorite("tool", t.id)}
                        >
                          <Star className={cn("size-3.5", fav ? "fill-warning text-warning" : "text-muted")} />
                        </Button>
                        <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
                      </Tooltip>
                    </div>
                    <p className="line-clamp-2 text-[12.5px] leading-relaxed text-muted">{t.description}</p>
                    <div className="mt-auto flex items-center gap-2 pt-1 text-[12px]">
                      <StatusDot tone={meta.tone} />
                      <span className={cn(meta.tone === "default" ? "text-muted" : "text-foreground")}>{meta.label}</span>
                      {det?.version && <span className="font-mono text-[11.5px] text-muted">v{det.version}</span>}
                      {!t.os.includes(os) && <span className="ml-auto text-[11.5px] text-muted">Not for this OS</span>}
                    </div>
                  </div>
                );
              })}
            </div>
            {selected && <ToolDetail key={selected.id} tool={selected} onClose={() => setParam({ tool: undefined })} />}
          </div>
        </div>
      </div>
    </div>
  );
}
