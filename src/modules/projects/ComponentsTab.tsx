import { Button, Checkbox } from "@heroui/react";
import { Boxes, Check, PackageSearch, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Project, SbomIssue, SbomSummary, SbomView, SbomVuln } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { ISSUE_AREA_LABEL, LICENSE_RISK_META, NOT_APPLICABLE, SBOM_FORMAT_LABEL, checkable, componentFacts, componentLabel, filterComponents, vulnRows, vulnSummary } from "./sbom";

const ROWS_SHOWN = 300;

function Severity({ v }: { v: Pick<SbomVuln, "severity"> | Pick<SbomIssue, "severity"> }) {
  return v.severity === "unknown" ? (
    <ToneChip tone="default" dot={false}>
      Unrated
    </ToneChip>
  ) : (
    <SeverityBadge severity={v.severity} />
  );
}

/** Projects → Components: SBOMs, the known vulnerabilities of their components, licenses. */
export function ComponentsTab({ project, onOpenFindings }: { project: Project; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const docs = useQuery(["sboms"], () => api.sbomsList(project.id), [project.id], runtime);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const confirm = useConfirm();
  const list = docs.data ?? [];
  const current = list.find((s) => s.id === selected) ?? list[0] ?? null;

  const importFile = async () => {
    setBusy(true);
    try {
      const s = await api.sbomImport(project.id);
      if (s) {
        invalidate("sboms", "findings", "assets", "activity");
        setSelected(s.id);
        notify.success(s.format.startsWith("lockfile-") ? "Lockfile imported" : "SBOM imported", `${s.components} components from ${s.name}`);
      }
    } catch (e) {
      notify.error("Could not import the file", e);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (s: SbomSummary) => {
    const ok = await confirm.ask({ title: `Remove ${s.name}?`, body: "The components leave the project. The file stays in the evidence vault, and findings recorded from it stay.", confirmLabel: "Remove" });
    if (!ok) return;
    try {
      await api.sbomDelete(s.id);
      invalidate("sboms", "activity");
      setSelected(null);
    } catch (e) {
      notify.error("Could not remove the SBOM", e);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="Software components (SBOMs and lockfiles)"
        description="CycloneDX (JSON or XML) and SPDX 2.x (JSON or tag-value) SBOMs, or dependency lockfiles (npm, Yarn, pnpm, Cargo, Poetry, uv, Pipfile, requirements.txt, Composer, Bundler, go.mod, NuGet, Gradle): components, licenses, supply-chain risks and known vulnerabilities. Reading a file contacts nothing; OSV.dev is asked only when you check, with package URLs only."
        actions={
          <Button size="sm" variant="primary" onPress={() => void importFile()} isPending={busy} isDisabled={!runtime}>
            <Upload className="size-3.5" />
            Import…
          </Button>
        }
      >
        {docs.error ? (
          <ErrorBlock message={docs.error} onRetry={docs.reload} />
        ) : !docs.data ? (
          <LoadingRows rows={2} />
        ) : list.length === 0 ? (
          <EmptyBlock compact icon={Boxes} title="No SBOM or lockfile yet" description="Import an SBOM from your build (for example from Syft, Trivy, cdxgen, the CycloneDX plugins or GitHub's dependency graph export), or the project's lockfile, such as package-lock.json, Cargo.lock or poetry.lock." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {list.map((s) => (
              <li key={s.id}>
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelected(s.id)}
                  onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(s.id)}
                  className={cn("tile flex cursor-pointer items-center gap-3 px-3 py-2", current?.id === s.id && "bg-accent-soft/40")}
                >
                  <Boxes className="size-4 shrink-0 text-muted" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px]">{s.subject || s.name}</div>
                    <div className="truncate text-[12px] text-muted">
                      {SBOM_FORMAT_LABEL[s.format] ?? s.format} · {s.components} components · vulnerabilities: {vulnSummary(s)}
                      {s.checkedAt ? ` · checked ${formatRelative(s.checkedAt)}` : " · not checked online"} · {s.name}
                    </div>
                  </div>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove ${s.name}`} onPress={() => void remove(s)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      {current && <SbomDetail key={current.id} id={current.id} onOpenFindings={onOpenFindings} />}
      {confirm.element}
    </div>
  );
}

function SbomDetail({ id, onOpenFindings }: { id: number; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const q = useQuery(["sboms", "findings"], () => api.sbomGet(id), [id], runtime);
  if (q.error) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!q.data) return <LoadingRows rows={4} />;
  const v = q.data;
  return (
    <>
      {v.sbom.warnings.length > 0 && (
        <ul className="flex flex-col gap-1 rounded-[10px] bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
          {v.sbom.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      <Vulnerabilities view={v} onOpenFindings={onOpenFindings} />
      <Checks view={v} onOpenFindings={onOpenFindings} />
      <Components view={v} />
    </>
  );
}

function Vulnerabilities({ view, onOpenFindings }: { view: SbomView; onOpenFindings: () => void }) {
  const confirm = useConfirm();
  const [checking, setChecking] = useState(false);
  const [recording, setRecording] = useState(false);
  const [hide, setHide] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const rows = useMemo(() => vulnRows(view.vulns, hide), [view.vulns, hide]);
  const open = rows.filter((r) => !view.recorded[r.key]);
  const comps = view.sbom.components;
  const lockfile = view.sbom.format.startsWith("lockfile-");
  const n = checkable(comps);

  const check = async () => {
    const ok = await confirm.ask({
      title: `Check ${n} components on OSV.dev?`,
      body: `Cyber Hub sends the package URL (ecosystem, name and version) of each of these components to api.osv.dev, the open vulnerability database, and nothing else: no file, project, supplier or hash. ${comps.length - n} components without a package URL or version are not checked.`,
      confirmLabel: "Check",
      tone: "accent",
    });
    if (!ok) return;
    setChecking(true);
    try {
      const r = await api.sbomCheck(view.summary.id);
      invalidate("sboms", "activity");
      notify.success("Checked on OSV.dev", `${r.vulns} known vulnerabilities · ${r.checked} components checked${r.skipped ? `, ${r.skipped} without a package URL or version not checked` : ""}`);
    } catch (e) {
      notify.error("The check failed", e);
    } finally {
      setChecking(false);
    }
  };
  const record = async (keys: string[]) => {
    setRecording(true);
    try {
      const r = await api.sbomRecord(view.summary.id, keys);
      invalidate("sboms", "findings", "activity");
      setPicked(new Set());
      notify.success(`${r.created} findings recorded`, r.existing ? `${r.existing} were recorded before` : "Linked to the SBOM file in the evidence vault");
    } catch (e) {
      notify.error("Could not record the findings", e);
    } finally {
      setRecording(false);
    }
  };
  const toggle = (k: string) => setPicked((p) => (p.has(k) ? new Set([...p].filter((x) => x !== k)) : new Set([...p, k])));

  return (
    <Panel
      title={`Known vulnerabilities (${rows.length})`}
      description={
        view.summary.checkedAt
          ? `From ${lockfile ? "" : "the SBOM and "}OSV.dev, checked ${formatRelative(view.summary.checkedAt)}. One row per vulnerability and affected component.`
          : lockfile
            ? "A lockfile states no vulnerabilities. Check on OSV.dev to look the components up."
            : "From the SBOM itself. Check on OSV.dev to look the components up."
      }
      actions={
        <div className="flex flex-wrap gap-2">
          {picked.size > 0 && (
            <Button size="sm" variant="tertiary" onPress={() => void record([...picked])} isPending={recording}>
              Record {picked.size} as findings
            </Button>
          )}
          <Button size="sm" variant="primary" onPress={() => void check()} isPending={checking} isDisabled={n === 0}>
            <PackageSearch className="size-3.5" />
            {view.summary.checkedAt ? "Check again on OSV.dev" : "Check on OSV.dev"}
          </Button>
        </div>
      }
      toolbar={
        <div className="flex flex-wrap items-center gap-4">
          {!lockfile && <SwitchInput label="Hide vulnerabilities the SBOM marks as not affecting it (VEX)" isSelected={hide} onChange={setHide} />}
          {open.length > 0 && picked.size === 0 && (
            <Button size="sm" variant="ghost" onPress={() => setPicked(new Set(open.map((r) => r.key)))}>
              Select all {open.length} not yet recorded
            </Button>
          )}
        </div>
      }
    >
      {rows.length === 0 ? (
        <EmptyBlock compact icon={ShieldCheck} title={view.summary.checkedAt ? "No known vulnerabilities" : lockfile ? "Not checked yet" : "No vulnerabilities stated in the SBOM"} description={view.summary.checkedAt ? "OSV.dev knows no vulnerability for the checked components. Components without a version cannot be checked." : undefined} />
      ) : (
        <ul className="flex flex-col gap-1">
          {rows.slice(0, ROWS_SHOWN).map((r) => {
            const c = comps[r.component];
            const fid = view.recorded[r.key];
            return (
              <li key={r.key} className={cn("tile flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2", picked.has(r.key) && "bg-accent-soft/40")}>
                <Checkbox aria-label={`Select ${r.vuln.id} in ${c ? componentLabel(c) : "component"}`} isSelected={picked.has(r.key)} onChange={() => toggle(r.key)} isDisabled={!!fid}>
                  <Checkbox.Content>
                    <Checkbox.Control>
                      <Checkbox.Indicator />
                    </Checkbox.Control>
                  </Checkbox.Content>
                </Checkbox>
                <Severity v={r.vuln} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px]">
                    <span className="font-mono">{r.vuln.id}</span>
                    {r.vuln.aliases.length > 0 && <span className="text-muted"> · {r.vuln.aliases.slice(0, 3).join(", ")}</span>}
                    <span className="text-muted"> in </span>
                    <span className="font-mono">{c ? componentLabel(c) : "?"}</span>
                  </div>
                  <div className="truncate text-[12px] text-muted">
                    {[r.vuln.summary, r.vuln.fixed.length ? `fixed in ${r.vuln.fixed.join(", ")}` : "no fixed version listed", r.vuln.source === "sbom" ? "stated in the SBOM" : "OSV.dev"].filter(Boolean).join(" · ")}
                  </div>
                </div>
                {r.vuln.analysis && (
                  <ToneChip tone={NOT_APPLICABLE.includes(r.vuln.analysis) ? "success" : "warning"} dot={false}>
                    VEX: {r.vuln.analysis.replace(/_/g, " ")}
                  </ToneChip>
                )}
                {fid ? (
                  <Button size="sm" variant="ghost" onPress={onOpenFindings}>
                    <Check className="size-3.5" />
                    Finding #{fid}
                  </Button>
                ) : (
                  <Button size="sm" variant="ghost" onPress={() => void record([r.key])} isDisabled={recording}>
                    Record finding
                  </Button>
                )}
              </li>
            );
          })}
          {rows.length > ROWS_SHOWN && <li className="px-1 text-[12px] text-muted">Showing {ROWS_SHOWN} of {rows.length}.</li>}
        </ul>
      )}
      {confirm.element}
    </Panel>
  );
}

function Checks({ view, onOpenFindings }: { view: SbomView; onOpenFindings: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  if (view.issues.length === 0) return null;
  const record = async (i: SbomIssue) => {
    setBusy(i.id);
    try {
      const r = await api.sbomRecord(view.summary.id, [`issue:${i.id}`]);
      invalidate("sboms", "findings", "activity");
      notify.success(r.created ? "Finding recorded" : "Already recorded", i.title);
    } catch (e) {
      notify.error("Could not record the finding", e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <Panel title="Checks" description="License risks from SPDX identifiers (OR takes the most permissive choice, AND the most restrictive), the NTIA minimum elements of an SBOM, and for lockfiles the supply-chain risks: plain HTTP, missing hashes, Git and URL dependencies, several registries or package indexes.">
      <ul className="flex flex-col gap-2">
        {view.issues.map((i) => {
          const fid = view.recorded[`issue:${i.id}`];
          return (
            <li key={i.id} className="panel-inset flex flex-col gap-1.5 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Severity v={i} />
                <span className="text-[13.5px] font-medium">{i.title}</span>
                <ToneChip tone="default" dot={false} className="text-[11px]">
                  {ISSUE_AREA_LABEL[i.area] ?? i.area}
                </ToneChip>
                <span className="flex-1" />
                {fid ? (
                  <Button size="sm" variant="ghost" onPress={onOpenFindings}>
                    <Check className="size-3.5" />
                    Finding #{fid}
                  </Button>
                ) : (
                  <Button size="sm" variant="tertiary" onPress={() => void record(i)} isPending={busy === i.id}>
                    Record finding
                  </Button>
                )}
              </div>
              <p className="text-[12.5px] text-muted">{i.detail}</p>
              {i.components.length > 0 && <p className="font-mono text-[11.5px] break-all">{i.components.slice(0, 12).join(", ")}{i.components.length > 12 ? ` … and ${i.components.length - 12} more` : ""}</p>}
              <p className="text-[12.5px]">
                <span className="text-muted">Recommendation: </span>
                {i.recommendation}
              </p>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function Components({ view }: { view: SbomView }) {
  const [text, setText] = useState("");
  const [ecosystem, setEcosystem] = useState("all");
  const [risk, setRisk] = useState("all");
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const comps = view.sbom.components;
  const lockfile = view.sbom.format.startsWith("lockfile-");
  const affected = useMemo(() => {
    const s = new Map<number, number>();
    for (const v of view.vulns) if (!NOT_APPLICABLE.includes(v.analysis)) for (const c of v.components) s.set(c, (s.get(c) ?? 0) + 1);
    return s;
  }, [view.vulns]);
  const ecosystems = useMemo(() => [...new Set(comps.map((c) => c.ecosystem || "other"))].sort(), [comps]);
  const matched = useMemo(() => filterComponents(comps, new Set(affected.keys()), { text, ecosystem, risk, vulnerableOnly }), [comps, affected, text, ecosystem, risk, vulnerableOnly]);
  return (
    <Panel
      title={`Components (${comps.length})`}
      description={[view.sbom.subject && `Software: ${view.sbom.subject}`, view.sbom.tools.length ? `made by ${view.sbom.tools.join(", ")}` : "", view.sbom.created && `on ${view.sbom.created}`].filter(Boolean).join(" · ") || undefined}
      toolbar={
        <div className="flex flex-wrap items-end gap-2">
          <SearchInput value={text} onChange={setText} placeholder="Search names, versions, licenses, suppliers" className="min-w-[220px] flex-1" />
          <SelectInput aria-label="Ecosystem" value={ecosystem} onChange={setEcosystem} options={[{ id: "all", label: "All ecosystems" }, ...ecosystems.map((e) => ({ id: e, label: e }))]} className="w-44" />
          <SelectInput
            aria-label="License risk"
            value={risk}
            onChange={setRisk}
            options={[{ id: "all", label: "All licenses" }, ...Object.entries(LICENSE_RISK_META).map(([id, m]) => ({ id, label: m.label }))]}
            className="w-48"
          />
          <SwitchInput label="Vulnerable only" isSelected={vulnerableOnly} onChange={setVulnerableOnly} />
        </div>
      }
    >
      {matched.length === 0 ? (
        <EmptyBlock compact icon={Boxes} title="No component matches" />
      ) : (
        <ul className="flex flex-col gap-1">
          {matched.slice(0, ROWS_SHOWN).map((i) => {
            const c = comps[i];
            const meta = LICENSE_RISK_META[c.licenseRisk] ?? LICENSE_RISK_META.unknown;
            const n = affected.get(i) ?? 0;
            return (
              <li key={`${i}-${c.reference}`} className="tile flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[12.5px]" title={c.purl || undefined}>
                    {componentLabel(c)}
                  </div>
                  <div className="truncate text-[12px] text-muted">{componentFacts(c, lockfile)}</div>
                </div>
                <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
                {n > 0 && <ToneChip tone="danger">{n === 1 ? "1 vulnerability" : `${n} vulnerabilities`}</ToneChip>}
              </li>
            );
          })}
          {matched.length > ROWS_SHOWN && <li className="px-1 text-[12px] text-muted">Showing {ROWS_SHOWN} of {matched.length}. Search to narrow the list.</li>}
        </ul>
      )}
    </Panel>
  );
}
