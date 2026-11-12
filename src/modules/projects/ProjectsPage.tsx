import { Button } from "@heroui/react";
import { FolderKanban, Plus } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { PROJECT_STATUS_META, StatusDot, ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { PageHeader } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { ProjectSummary } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { ProjectDetail } from "./ProjectDetail";
import { ProjectFormModal, STATUS_OPTIONS } from "./ProjectFormModal";

function ProjectRow({ p, onOpen }: { p: ProjectSummary; onOpen: () => void }) {
  const meta = PROJECT_STATUS_META[p.status];
  const dates = p.startDate || p.endDate ? `${p.startDate ?? "?"} → ${p.endDate ?? "?"}` : "Not set";
  return (
    <Button
      variant="ghost"
      onPress={onOpen}
      className="panel h-auto w-full justify-start gap-4 px-4 py-3.5 text-left font-normal whitespace-normal hover:bg-surface-hover"
      aria-label={`Open project ${p.name}`}
    >
      <FeaturedIcon icon={FolderKanban} size="md" color={p.status === "active" ? "brand" : "gray"} />
      {/* the name keeps room, and the details give way to it (Mission 11: the row scrolled the page sideways just above the lg width) */}
      <div className="min-w-40 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-[14.5px] font-medium text-foreground">{p.name}</span>
          <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
        </div>
        <div className="mt-0.5 truncate text-[12.5px] text-muted">{p.description || "No description"}</div>
      </div>
      <dl className="hidden min-w-0 grid-cols-4 gap-6 text-[12.5px] lg:grid">
        <div className="min-w-0">
          <dt className="text-muted">Dates</dt>
          <dd className="tabular mt-0.5 truncate text-foreground" title={dates}>
            {dates}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Scope</dt>
          <dd className="tabular mt-0.5 truncate text-foreground">{p.targetCount} entries</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Findings</dt>
          <dd className="tabular mt-0.5 flex items-center gap-1.5 text-foreground">
            {p.openFindings > 0 && <StatusDot tone="warning" />}
            <span className="truncate">
              {p.openFindings} open / {p.findingCount}
            </span>
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Updated</dt>
          <dd className="mt-0.5 truncate text-foreground">{formatRelative(p.updatedAt)}</dd>
        </div>
      </dl>
    </Button>
  );
}

function ProjectList() {
  const { runtime, route, navigate } = useApp();
  const q = useQuery(["projects"], api.projectsList, [], runtime);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [creating, setCreating] = useState(route.params?.new === "1");

  useEffect(() => {
    if (route.params?.new === "1") setCreating(true);
  }, [route.params?.new]);

  const list = useMemo(() => {
    const s = search.trim().toLowerCase();
    return (q.data ?? []).filter((p) => (status === "all" || p.status === status) && (!s || `${p.name} ${p.description}`.toLowerCase().includes(s)));
  }, [q.data, search, status]);

  return (
    <div>
      <PageHeader
        title="Projects"
        description="Each assessment keeps its authorized scope, findings, notes and tool history together. Tools that send traffic only run against the scope of an active project."
        actions={
          <Button variant="primary" size="sm" onPress={() => setCreating(true)} isDisabled={!runtime}>
            <Plus className="size-3.5" />
            New project
          </Button>
        }
      />
      <div className="mb-3 flex flex-wrap gap-2">
        <SearchInput value={search} onChange={setSearch} placeholder="Search projects" className="max-w-sm" />
        <SelectInput aria-label="Filter by status" value={status} onChange={setStatus} options={[{ id: "all", label: "All statuses" }, ...STATUS_OPTIONS]} className="w-48" />
      </div>
      <QueryView
        query={q}
        rows={4}
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyBlock
            icon={FolderKanban}
            title="No projects yet"
            description="Create a project for each authorized assessment. Define its scope before running any tool against a target."
            action={
              <Button size="sm" variant="primary" onPress={() => setCreating(true)}>
                <Plus className="size-3.5" />
                Create your first project
              </Button>
            }
          />
        }
      >
        {() =>
          list.length === 0 ? (
            <EmptyBlock compact icon={FolderKanban} title="No projects match" description="Try a different search or status filter." />
          ) : (
            <div className="flex flex-col gap-2">
              {list.map((p) => (
                <ProjectRow key={p.id} p={p} onOpen={() => navigate("projects", { project: String(p.id) })} />
              ))}
            </div>
          )
        }
      </QueryView>
      <ProjectFormModal
        isOpen={creating}
        onOpenChange={(o) => {
          setCreating(o);
          if (!o && route.params?.new) navigate("projects");
        }}
        onSaved={(id) => navigate("projects", { project: String(id) })}
      />
    </div>
  );
}

export default function ProjectsPage() {
  const { route } = useApp();
  const id = Number(route.params?.project);
  if (Number.isInteger(id) && id > 0) return <ProjectDetail key={id} id={id} />;
  return <ProjectList />;
}
