import { Button, Dropdown } from "@heroui/react";
import { listen } from "@tauri-apps/api/event";
import { Ban, Globe, History, MoreHorizontal, Plus, Radar, RotateCcw, ScanSearch, Server, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel, Stat } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage, runtimeAvailable } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Asset, AssetType, DiscoverySnapshot, Project, SnapshotChange } from "@/lib/types";
import { formatDateTime, formatRelative } from "@/lib/utils";
import {
  ASSET_STATUS_META,
  ASSET_TYPE_LABEL,
  CERTAINTY_META,
  certaintyOf,
  describeAsset,
  matchesFilter,
  SNAPSHOT_STATUS_META,
  SOURCE_LABEL,
  suggestedScanTargets,
  summarize,
} from "./asm";

const TYPE_OPTIONS = (Object.keys(ASSET_TYPE_LABEL) as AssetType[]).map((id) => ({ id, label: ASSET_TYPE_LABEL[id] }));
const ASSET_PLACEHOLDER: Record<AssetType, string> = {
  domain: "example.com",
  subdomain: "api.example.com",
  ip: "192.0.2.10",
  dns_record: "example.com MX mail.example.com",
  service: "192.0.2.10:443/tcp",
  http_service: "https://app.example.com",
  certificate: "SHA-256 fingerprint",
  technology: "nginx",
  endpoint: "https://app.example.com/api/v1/login",
};

/** Follows background discovery: progress lines and refreshes when a run ends. */
function useDiscoveryEvents(projectId: number) {
  const [message, setMessage] = useState<string | null>(null);
  useEffect(() => {
    if (!runtimeAvailable()) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const un = listen<{ projectId: number; snapshotId: number; message: string | null }>("asm-changed", (e) => {
      if (e.payload.projectId !== projectId) return;
      setMessage(e.payload.message);
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        invalidate("assets", "projects");
      }, 500);
    });
    return () => {
      if (timer) clearTimeout(timer);
      void un.then((f) => f());
    };
  }, [projectId]);
  return message;
}

function AddAssetModal({ isOpen, onOpenChange, projectId }: { isOpen: boolean; onOpenChange: (o: boolean) => void; projectId: number }) {
  const [type, setType] = useState<AssetType>("subdomain");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setValue("");
      setError(null);
    }
  }, [isOpen]);
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const a = await api.assetAdd({ projectId, type, value });
      invalidate("assets");
      notify.success("Asset recorded", a.value);
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title="Add asset"
      description="Record an asset you know about. Nothing is contacted."
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!value.trim()}>
            Add asset
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-[180px_1fr]">
        <SelectInput label="Type" value={type} onChange={(v) => setType(v as AssetType)} options={TYPE_OPTIONS} />
        <TextInput label="Value" value={value} onChange={setValue} placeholder={ASSET_PLACEHOLDER[type]} mono autoFocus onEnter={save} />
      </div>
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function ScanModal({ isOpen, onOpenChange, project }: { isOpen: boolean; onOpenChange: (o: boolean) => void; project: Project }) {
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState<"quick" | "standard">("quick");
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setTargets(suggestedScanTargets(project).join("\n"));
      setError(null);
    }
  }, [isOpen, project]);
  const list = targets
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      await api.discoveryScanStart(project.id, list, profile);
      invalidate("assets", "executions");
      notify.success("Service scan started", "Results are added when the scan finishes. Follow it under Commands & runs.");
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setStarting(false);
    }
  };
  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title="Service scan"
      description="Runs Nmap with service detection against in-scope targets. Every target is checked against the scope, and you confirm the exact command in a system dialog."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={start} isPending={starting} isDisabled={list.length === 0 || list.length > 64}>
            Review and start
          </Button>
        </>
      }
    >
      <TextAreaInput label="Targets" value={targets} onChange={setTargets} rows={5} placeholder={"192.0.2.0/28\napp.example.com"} mono description="One per line: hosts, addresses or networks (at most 64)." />
      <SelectInput
        label="Ports"
        value={profile}
        onChange={(v) => setProfile(v as "quick" | "standard")}
        options={[
          { id: "quick", label: "100 most common ports (faster)" },
          { id: "standard", label: "1,000 most common ports" },
        ]}
      />
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function ObservationsModal({ asset, onClose }: { asset: Asset | null; onClose: () => void }) {
  const { runtime } = useApp();
  const obs = useQuery(["assets"], () => (asset ? api.assetObservations(asset.id) : Promise.resolve([])), [asset?.id], runtime && !!asset);
  return (
    <AppModal isOpen={!!asset} onOpenChange={(o) => !o && onClose()} title={asset?.value ?? ""} description="Every time discovery saw this asset, newest first." size="lg">
      {obs.loading && !obs.data ? (
        <LoadingRows rows={3} />
      ) : !obs.data?.length ? (
        <p className="text-[13px] text-muted">Recorded by hand; no discovery has seen it yet.</p>
      ) : (
        <ol className="flex flex-col gap-1.5">
          {obs.data.map((o) => {
            const d = (o.data ?? {}) as Record<string, unknown>;
            const certainty = typeof d.certainty === "string" && d.certainty in CERTAINTY_META ? (d.certainty as keyof typeof CERTAINTY_META) : null;
            const details = Object.entries(d)
              .filter(([k, v]) => k !== "certainty" && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
              .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
            return (
              <li key={o.id} className="panel-inset px-3 py-2 text-[12.5px]">
                <div className="flex items-center gap-2">
                  <span className="text-foreground">{formatDateTime(o.observedAt)}</span>
                  <span className="text-muted">{SOURCE_LABEL[o.source] ?? o.source}</span>
                  {certainty && <ToneChip tone={CERTAINTY_META[certainty].tone}>{CERTAINTY_META[certainty].label}</ToneChip>}
                </div>
                {details.length > 0 && <div className="mt-1 font-mono text-[11.5px] break-all text-muted">{details.join(" · ")}</div>}
              </li>
            );
          })}
        </ol>
      )}
    </AppModal>
  );
}

const CHANGE_LABEL: Record<SnapshotChange["change"], string> = { added: "New", changed: "Changed", missing: "Missing" };

function ChangesModal({ snapshot, onClose }: { snapshot: DiscoverySnapshot | null; onClose: () => void }) {
  const { runtime } = useApp();
  const q = useQuery(["assets"], () => (snapshot ? api.discoveryChanges(snapshot.id) : Promise.resolve(null)), [snapshot?.id], runtime && !!snapshot);
  const groups = useMemo(() => {
    const g: Record<SnapshotChange["change"], SnapshotChange[]> = { added: [], changed: [], missing: [] };
    for (const c of q.data?.changes ?? []) g[c.change].push(c);
    return g;
  }, [q.data]);
  return (
    <AppModal
      isOpen={!!snapshot}
      onOpenChange={(o) => !o && onClose()}
      title={snapshot ? `${SOURCE_LABEL[snapshot.source] ?? snapshot.source} · ${formatDateTime(snapshot.startedAt)}` : ""}
      description={q.data ? (q.data.previous ? "Compared with the previous run of the same kind." : "The first run of this kind: everything it found is new.") : undefined}
      size="lg"
    >
      {snapshot?.note && <p className="text-[12.5px] text-muted">{snapshot.note}</p>}
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <LoadingRows rows={3} />
      ) : q.data.changes.length === 0 ? (
        <p className="text-[13px] text-muted">No changes since the previous run.</p>
      ) : (
        <div className="flex flex-col gap-4">
          {(Object.keys(groups) as SnapshotChange["change"][]).map((k) =>
            groups[k].length === 0 ? null : (
              <section key={k}>
                <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">
                  {CHANGE_LABEL[k]} ({groups[k].length})
                </h3>
                <ul className="flex flex-col gap-1">
                  {groups[k].slice(0, 300).map((c) => (
                    <li key={`${k}-${c.assetId}`} className="panel-inset flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                      <span className="w-24 shrink-0 text-muted">{ASSET_TYPE_LABEL[c.assetType]}</span>
                      <span className="min-w-0 flex-1 truncate font-mono">{c.value}</span>
                      <ToneChip tone={CERTAINTY_META[c.certainty].tone}>{CERTAINTY_META[c.certainty].label}</ToneChip>
                    </li>
                  ))}
                </ul>
              </section>
            ),
          )}
          <dl className="grid grid-cols-1 gap-1 text-[12px] text-muted md:grid-cols-2">
            {Object.values(CERTAINTY_META).map((m) => (
              <div key={m.label}>
                <dt className="inline font-medium text-foreground">{m.label}: </dt>
                <dd className="inline">{m.help}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </AppModal>
  );
}

export function AttackSurfaceTab({ project }: { project: Project }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const assets = useQuery(["assets"], () => api.assetsList(project.id), [project.id], runtime);
  const snaps = useQuery(["assets"], () => api.discoverySnapshots(project.id), [project.id], runtime);
  const progress = useDiscoveryEvents(project.id);
  const [filter, setFilter] = useState({ type: "all", status: "all", query: "" });
  const [adding, setAdding] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [history, setHistory] = useState<Asset | null>(null);
  const [changes, setChanges] = useState<DiscoverySnapshot | null>(null);
  const [starting, setStarting] = useState<"passive" | "http" | null>(null);

  const list = assets.data ?? [];
  const summary = useMemo(() => summarize(list), [list]);
  const shown = useMemo(() => list.filter((a) => matchesFilter(a, filter)), [list, filter]);
  const running = (snaps.data ?? []).filter((s) => s.status === "running");
  const background = running.find((s) => s.source !== "nmap");

  const start = async (kind: "passive" | "http") => {
    setStarting(kind);
    try {
      if (kind === "passive") await api.discoveryPassiveStart(project.id);
      else await api.discoveryHttpStart(project.id);
      invalidate("assets");
    } catch (e) {
      notify.error(kind === "passive" ? "Passive discovery did not start" : "The HTTP check did not start", e);
    } finally {
      setStarting(null);
    }
  };

  const setStatus = async (a: Asset, status: Asset["status"]) => {
    try {
      await api.assetSetStatus(a.id, status);
      invalidate("assets");
    } catch (e) {
      notify.error("Could not change the asset", e);
    }
  };

  const remove = async (a: Asset) => {
    if (!(await confirm.ask({ title: "Delete asset?", body: `“${a.value}” and its observation history will be deleted. To keep the history of an asset that no longer exists, retire it instead.`, confirmLabel: "Delete asset" }))) return;
    try {
      await api.assetDelete(a.id);
      invalidate("assets");
      notify.success("Asset deleted");
    } catch (e) {
      notify.error("Could not delete the asset", e);
    }
  };

  const typeCounts = (Object.keys(ASSET_TYPE_LABEL) as AssetType[]).filter((t) => summary.byType[t]);

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <div className="flex flex-col gap-3 xl:col-span-8">
        <div className="panel grid grid-cols-2 gap-4 p-4 md:grid-cols-4">
          <Stat label="Assets" value={summary.total} hint={typeCounts.length ? `${typeCounts.length} kinds` : "None recorded"} />
          <Stat label="Active" value={summary.byStatus.active} tone={summary.byStatus.active ? "success" : "default"} hint="Seen by the latest runs" />
          <Stat label="Not observed" value={summary.byStatus.not_observed} tone={summary.byStatus.not_observed ? "warning" : "default"} hint="Missing from a finished run" />
          <Stat label="Retired" value={summary.byStatus.retired} hint="Kept for history" />
        </div>

        <Panel
          title="Assets"
          description={typeCounts.length ? typeCounts.map((t) => `${summary.byType[t]} ${ASSET_TYPE_LABEL[t].toLowerCase()}`).join(" · ") : "Discovered and recorded assets of this project"}
          actions={
            <Button size="sm" variant="tertiary" onPress={() => setAdding(true)}>
              <Plus className="size-3.5" />
              Add asset
            </Button>
          }
          toolbar={
            list.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <SearchInput value={filter.query} onChange={(query) => setFilter((f) => ({ ...f, query }))} placeholder="Search assets" className="w-56" />
                <SelectInput aria-label="Filter by type" value={filter.type} onChange={(type) => setFilter((f) => ({ ...f, type }))} options={[{ id: "all", label: "All types" }, ...TYPE_OPTIONS]} className="w-40" />
                <SelectInput
                  aria-label="Filter by status"
                  value={filter.status}
                  onChange={(status) => setFilter((f) => ({ ...f, status }))}
                  options={[{ id: "all", label: "All statuses" }, ...Object.entries(ASSET_STATUS_META).map(([id, m]) => ({ id, label: m.label }))]}
                  className="w-40"
                />
              </div>
            )
          }
        >
          {assets.error && !assets.data ? (
            <ErrorBlock message={assets.error} onRetry={assets.reload} />
          ) : assets.loading && !assets.data ? (
            <LoadingRows rows={5} />
          ) : list.length === 0 ? (
            <EmptyBlock
              icon={Radar}
              title="No assets yet"
              description="Run passive discovery to collect names and addresses from certificate logs and DNS, or add assets you already know."
            />
          ) : shown.length === 0 ? (
            <EmptyBlock compact icon={Radar} title="No assets match these filters" />
          ) : (
            <div className="panel-inset overflow-x-auto px-3 py-1">
              <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
                <thead>
                  <tr className="text-[12px] text-muted">
                    <th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Asset</th>
                    <th className="py-2 pr-3 font-medium">Certainty</th>
                    <th className="py-2 pr-3 font-medium">Status</th>
                    <th className="py-2 pr-3 font-medium">Last seen</th>
                    <th className="py-2 font-medium">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.slice(0, 1000).map((a) => {
                    const c = certaintyOf(a);
                    const detail = describeAsset(a);
                    return (
                      <tr key={a.id} className="align-top transition-colors hover:bg-white/[0.025]">
                        <td className="py-2 pr-3 whitespace-nowrap text-muted">{ASSET_TYPE_LABEL[a.type]}</td>
                        <td className="max-w-[380px] py-2 pr-3">
                          <div className="truncate font-mono text-[12.5px] text-foreground">{a.value}</div>
                          {detail && <div className="truncate text-[12px] text-muted">{detail}</div>}
                        </td>
                        <td className="py-2 pr-3">{c ? <ToneChip tone={CERTAINTY_META[c].tone}>{CERTAINTY_META[c].label}</ToneChip> : <span className="text-[12px] text-muted">Manual</span>}</td>
                        <td className="py-2 pr-3">
                          <ToneChip tone={ASSET_STATUS_META[a.status].tone}>{ASSET_STATUS_META[a.status].label}</ToneChip>
                        </td>
                        <td className="py-2 pr-3 whitespace-nowrap text-muted">{formatRelative(a.lastSeen)}</td>
                        <td className="py-1.5 text-right">
                          <Dropdown>
                            <Button isIconOnly size="sm" variant="ghost" aria-label={`Actions for ${a.value}`}>
                              <MoreHorizontal className="size-4" />
                            </Button>
                            <Dropdown.Popover placement="bottom end">
                              <Dropdown.Menu
                                aria-label="Asset actions"
                                onAction={(k) => {
                                  if (k === "history") setHistory(a);
                                  else if (k === "retire") void setStatus(a, "retired");
                                  else if (k === "activate") void setStatus(a, "active");
                                  else if (k === "delete") void remove(a);
                                }}
                              >
                                <Dropdown.Item id="history" textValue="Observation history">
                                  <History className="size-3.5" /> Observation history
                                </Dropdown.Item>
                                {a.status === "retired" ? (
                                  <Dropdown.Item id="activate" textValue="Mark active">
                                    <RotateCcw className="size-3.5" /> Mark active
                                  </Dropdown.Item>
                                ) : (
                                  <Dropdown.Item id="retire" textValue="Retire">
                                    <Ban className="size-3.5" /> Retire
                                  </Dropdown.Item>
                                )}
                                <Dropdown.Item id="delete" textValue="Delete" variant="danger">
                                  <Trash2 className="size-3.5" /> Delete
                                </Dropdown.Item>
                              </Dropdown.Menu>
                            </Dropdown.Popover>
                          </Dropdown>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {shown.length > 1000 && <p className="py-2 text-[12px] text-muted">Showing the first 1,000 of {shown.length}. Narrow the filters to see the rest.</p>}
            </div>
          )}
        </Panel>
      </div>

      <div className="flex flex-col gap-3 xl:col-span-4">
        <Panel title="Discovery" description="Passive runs ask public sources only. Checks that contact targets need an active project and are confirmed in a system dialog.">
          <div className="flex flex-col gap-2">
            <Button variant="primary" className="justify-start" onPress={() => start("passive")} isPending={starting === "passive"} isDisabled={!!background}>
              <Globe className="size-4" />
              Passive discovery
            </Button>
            <Button variant="secondary" className="justify-start" onPress={() => start("http")} isPending={starting === "http"} isDisabled={!!background}>
              <ScanSearch className="size-4" />
              Check web services
            </Button>
            <Button variant="secondary" className="justify-start" onPress={() => setScanning(true)}>
              <Server className="size-4" />
              Service scan…
            </Button>
          </div>
          {running.length > 0 && (
            <div className="panel-inset mt-3 flex items-center gap-2 px-3 py-2 text-[12.5px]">
              <InlineSpinner />
              <span className="min-w-0 flex-1 truncate">{(background && progress) || `${running.map((s) => SOURCE_LABEL[s.source]).join(", ")} running`}</span>
              {background && (
                <Button size="sm" variant="ghost" onPress={() => api.discoveryCancel(project.id).catch((e) => notify.error("Could not cancel", e))}>
                  Cancel
                </Button>
              )}
            </div>
          )}
        </Panel>

        <Panel title="Runs" description="Select a run to see what changed since the previous one.">
          {snaps.error && !snaps.data ? (
            <ErrorBlock message={snaps.error} onRetry={snaps.reload} />
          ) : !snaps.data ? (
            <LoadingRows rows={3} />
          ) : snaps.data.length === 0 ? (
            <p className="text-[12.5px] text-muted">No discovery has run for this project.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {snaps.data.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    onClick={() => setChanges(s)}
                    disabled={s.status === "running"}
                    className="w-full rounded-lg px-2.5 py-2 text-left transition-colors hover:bg-white/[0.035] focus-visible:outline-2 focus-visible:outline-accent disabled:cursor-default"
                  >
                    <div className="flex items-center gap-2 text-[13px]">
                      <span className="min-w-0 flex-1 truncate text-foreground">{SOURCE_LABEL[s.source] ?? s.source}</span>
                      <ToneChip tone={SNAPSHOT_STATUS_META[s.status].tone}>{SNAPSHOT_STATUS_META[s.status].label}</ToneChip>
                    </div>
                    <div className="mt-0.5 text-[12px] text-muted">
                      {formatRelative(s.startedAt)} · {s.assets} assets
                    </div>
                    {s.note && <div className="mt-0.5 line-clamp-2 text-[12px] text-muted">{s.note}</div>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <AddAssetModal isOpen={adding} onOpenChange={setAdding} projectId={project.id} />
      <ScanModal isOpen={scanning} onOpenChange={setScanning} project={project} />
      <ObservationsModal asset={history} onClose={() => setHistory(null)} />
      <ChangesModal snapshot={changes} onClose={() => setChanges(null)} />
      {confirm.element}
    </div>
  );
}
