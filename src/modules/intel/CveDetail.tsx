import { Button, Chip } from "@heroui/react";
import { ExternalLink, FolderPlus } from "lucide-react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal } from "@/components/ui/Dialogs";
import { SelectInput } from "@/components/ui/Fields";
import { notify, openExternal } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CveRecord, CvssScore } from "@/lib/types";
import { formatDate, formatDateTime } from "@/lib/utils";
import { bestCvss, nvdUrl, parseVector, severityOf } from "./cvss";
import { CWE_NAMES, cweUrl } from "./cwe";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-[13px] font-medium text-muted">{title}</h3>
      {children}
    </section>
  );
}

function CvssEntry({ s }: { s: CvssScore }) {
  const parts = parseVector(s.vector);
  return (
    <div className="panel-inset p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={severityOf(s)} score={s.score} />
        <span className="text-[13px]">CVSS {s.version}</span>
        <span className="text-[12px] text-muted">{s.source}</span>
      </div>
      {s.vector && (
        <div className="mt-2 flex items-center gap-1">
          <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px] text-muted">
            {s.vector}
          </code>
          <CopyButton text={s.vector} label="Copy vector" />
        </div>
      )}
      {parts.length > 0 && (
        <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[12.5px] md:grid-cols-3">
          {parts.map((p) => (
            <div key={p.key} className="flex justify-between gap-2">
              <dt className="truncate text-muted" title={p.name}>
                {p.name}
              </dt>
              <dd className="shrink-0 text-foreground">{p.label}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function AddAsFinding({ record, isOpen, onOpenChange }: { record: CveRecord; isOpen: boolean; onOpenChange: (o: boolean) => void }) {
  const { runtime, navigate } = useApp();
  const projects = useQuery(["projects"], api.projectsList, [], runtime && isOpen);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const best = bestCvss(record);

  useEffect(() => {
    if (isOpen && !projectId && projects.data?.length) setProjectId(String(projects.data[0].id));
  }, [isOpen, projectId, projects.data]);

  const save = async () => {
    if (!projectId) return;
    setSaving(true);
    try {
      const short = record.description.split(/(?<=\.)\s/)[0] ?? "";
      const title = `${record.id}: ${short}`.slice(0, 200);
      await api.findingUpsert({
        projectId: Number(projectId),
        title,
        severity: severityOf(best),
        status: "new",
        description: `${record.description}\n\n${best ? `CVSS ${best.version} ${best.score} (${best.vector})\n` : ""}Source: NVD record, confirm applicability to the affected target before reporting.`.slice(0, 50000),
        affectedTarget: "",
        cve: record.id,
        evidence: [{ label: "NVD record", reference: nvdUrl(record.id) }],
      });
      invalidate("findings", "projects", "activity");
      notify.success("Finding recorded", "Edit it in the project to add the affected target.");
      onOpenChange(false);
    } catch (e) {
      notify.error("Could not record finding", errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const options = (projects.data ?? []).map((p) => ({ id: String(p.id), label: p.name, description: p.status }));
  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title={`Add ${record.id} as a finding`}
      description="Creates an open finding prefilled from the NVD record. Only add it once you have confirmed the affected asset is in scope."
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isDisabled={!projectId} isPending={saving}>
            Record finding
          </Button>
        </>
      }
    >
      {projects.data && options.length === 0 ? (
        <div className="flex flex-col items-start gap-2 text-[13px] text-muted">
          You have no projects yet.
          <Button size="sm" variant="tertiary" onPress={() => navigate("projects", { new: "1" })}>
            Create a project
          </Button>
        </div>
      ) : (
        <SelectInput label="Project" value={projectId} onChange={setProjectId} options={options} placeholder="Choose a project" />
      )}
      <div className="panel-inset flex items-center gap-2 px-3 py-2 text-[13px]">
        <SeverityBadge severity={severityOf(best)} score={best?.score} />
        <span className="truncate">{record.id}</span>
      </div>
    </AppModal>
  );
}

export function CveDetailModal({ record, cachedAt, onClose }: { record: CveRecord | null; cachedAt?: string; onClose: () => void }) {
  const [adding, setAdding] = useState(false);
  if (!record) return null;
  const best = bestCvss(record);
  const sortedCvss = [...record.cvss].sort((a, b) => (b.version > a.version ? 1 : b.version < a.version ? -1 : 0));

  return (
    <>
      <AppModal
        isOpen={!!record}
        onOpenChange={(o) => !o && onClose()}
        size="lg"
        title={
          <span className="flex flex-wrap items-center gap-2">
            {record.id}
            <SeverityBadge severity={severityOf(best)} score={best?.score} />
            {record.kev && <ToneChip tone="danger">CISA KEV</ToneChip>}
          </span>
        }
        description={`${record.status || "Unknown status"} · published ${formatDate(record.published)} · modified ${formatDate(record.lastModified)}${cachedAt ? ` · cached ${formatDateTime(cachedAt)}` : ""}`}
        footer={
          <>
            <Button variant="tertiary" onPress={() => openExternal(nvdUrl(record.id))}>
              <ExternalLink className="size-3.5" />
              Open on NVD
            </Button>
            <Button variant="primary" onPress={() => setAdding(true)}>
              <FolderPlus className="size-3.5" />
              Add as finding
            </Button>
          </>
        }
      >
        <Section title="Description">
          <p data-selectable className="text-[13.5px] leading-relaxed whitespace-pre-wrap">
            {record.description || "No description provided by NVD."}
          </p>
        </Section>

        <Section title="CVSS scores">
          {sortedCvss.length === 0 ? (
            <p className="text-[13px] text-muted">NVD has not published a CVSS score for this record yet.</p>
          ) : (
            <div className="flex flex-col gap-2">
              {sortedCvss.map((s, i) => (
                <CvssEntry key={`${s.version}-${s.source}-${i}`} s={s} />
              ))}
            </div>
          )}
        </Section>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Section title="Weaknesses (CWE)">
            {record.cwes.length === 0 ? (
              <p className="text-[13px] text-muted">No CWE mapping.</p>
            ) : (
              <ul className="flex flex-col gap-1">
                {record.cwes.map((c) => {
                  const url = cweUrl(c);
                  return (
                    <li key={c}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="tile h-auto w-full justify-between px-3 py-2 text-left font-normal whitespace-normal"
                        onPress={() => url && openExternal(url)}
                        isDisabled={!url}
                      >
                        <span className="min-w-0">
                          <span className="font-mono text-[12.5px]">{c}</span>
                          <span className="ml-2 text-[12.5px] text-muted">{CWE_NAMES[c] ?? "View definition"}</span>
                        </span>
                        <ExternalLink className="size-3.5 shrink-0 text-muted" />
                      </Button>
                    </li>
                  );
                })}
              </ul>
            )}
          </Section>
          <Section title={`Affected products (${record.products.length})`}>
            {record.products.length === 0 ? (
              <p className="text-[13px] text-muted">No CPE configuration published.</p>
            ) : (
              <ul className="panel-inset scroll-area flex max-h-48 flex-col gap-0.5 p-2">
                {record.products.map((p) => (
                  <li key={p} data-selectable className="truncate font-mono text-[12px]" title={p}>
                    {p}
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>

        <Section title={`References (${record.references.length})`}>
          {record.references.length === 0 ? (
            <p className="text-[13px] text-muted">No references.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {record.references.map((r, i) => (
                <li key={`${r.url}-${i}`}>
                  <Button variant="ghost" size="sm" className="tile h-auto w-full justify-start gap-3 px-3 py-2 text-left font-normal whitespace-normal" onPress={() => openExternal(r.url)}>
                    <ExternalLink className="size-3.5 shrink-0 text-muted" />
                    <span className="min-w-0 flex-1 truncate text-[12.5px] text-link">{r.url}</span>
                    <span className="flex shrink-0 flex-wrap justify-end gap-1">
                      {r.tags.slice(0, 3).map((t) => (
                        <Chip key={t} size="sm" variant="soft">
                          <Chip.Label>{t}</Chip.Label>
                        </Chip>
                      ))}
                    </span>
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </AppModal>
      <AddAsFinding record={record} isOpen={adding} onOpenChange={setAdding} />
    </>
  );
}
