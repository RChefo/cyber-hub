// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ExternalLink, FilePlus2, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel, Stat } from "@/components/ui/Panel";
import { notify, openExternal } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Confidence, Exposure, Project, Vulnerability, VulnStatus } from "@/lib/types";
import { formatDateTime, formatRelative } from "@/lib/utils";
import { nvdUrl } from "@/modules/intel/cvss";
import { ASSET_TYPE_LABEL } from "./asm";
import { countByPriority, EXPOSURE_LABEL, formatEpss, isOpenVuln, isOverdue, needsReason, PRIORITY_META, VULN_STATUS_META } from "./vulns";
import { AcceptRiskModal } from "./RiskTab";

const STATUS_OPTIONS = (Object.keys(VULN_STATUS_META) as VulnStatus[]).map((id) => ({ id, label: VULN_STATUS_META[id].label }));
const EXPOSURE_OPTIONS = (Object.keys(EXPOSURE_LABEL) as Exposure[]).map((id) => ({ id, label: EXPOSURE_LABEL[id] }));
const CRITICALITY_OPTIONS = [
  { id: "high", label: "High criticality" },
  { id: "medium", label: "Medium criticality" },
  { id: "low", label: "Low criticality" },
];

function Alert({ children }: { children: React.ReactNode }) {
  return (
    <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
      {children}
    </div>
  );
}

function AddVulnModal({ isOpen, onOpenChange, project }: { isOpen: boolean; onOpenChange: (o: boolean) => void; project: Project }) {
  const { runtime } = useApp();
  const assets = useQuery(["assets"], () => api.assetsList(project.id, { status: "active" }), [project.id], runtime && isOpen);
  const [cve, setCve] = useState("");
  const [assetId, setAssetId] = useState("none");
  const [exposure, setExposure] = useState("auto");
  const [criticality, setCriticality] = useState<Confidence>("medium");
  const [exploitKnown, setExploitKnown] = useState(false);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setCve("");
      setAssetId("none");
      setExposure("auto");
      setCriticality("medium");
      setExploitKnown(false);
      setNotes("");
      setError(null);
    }
  }, [isOpen]);
  const assetOptions = useMemo(
    () => [
      { id: "none", label: "No specific asset" },
      ...(assets.data ?? [])
        .filter((a) => ["service", "ip", "http_service", "domain", "subdomain", "endpoint", "technology", "cloud_resource"].includes(a.type))
        .slice(0, 500)
        .map((a) => ({ id: String(a.id), label: `${a.value} (${ASSET_TYPE_LABEL[a.type]})` })),
    ],
    [assets.data],
  );
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const r = await api.vulnAdd({
        projectId: project.id,
        cveId: cve,
        assetId: assetId === "none" ? null : Number(assetId),
        exposure: exposure === "auto" ? undefined : (exposure as Exposure),
        criticality,
        exploitKnown,
        notes,
      });
      invalidate("vulns");
      notify.success(`${r.vulnerability.cveId} tracked as ${r.vulnerability.priority.toUpperCase()}`, r.warnings.join(" ") || undefined);
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
      title="Track a vulnerability"
      description="The CVE's score and KEV status come from NVD (local cache first). The EPSS score comes from FIRST.org when it is turned on. Only the CVE ID is sent."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!cve.trim()}>
            Track vulnerability
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <TextInput label="CVE" value={cve} onChange={setCve} placeholder="CVE-2024-3094" mono isRequired autoFocus />
        <SelectInput label="Affected asset" value={assetId} onChange={setAssetId} options={assetOptions} />
        <SelectInput label="Exposure" value={exposure} onChange={setExposure} options={[{ id: "auto", label: "From the asset (or unknown)" }, ...EXPOSURE_OPTIONS]} />
        <SelectInput label="Asset criticality" value={criticality} onChange={(v) => setCriticality(v as Confidence)} options={CRITICALITY_OPTIONS} />
        <div className="md:col-span-2">
          <SwitchInput label="Exploitation is known" isSelected={exploitKnown} onChange={setExploitKnown} description="Set when you know of working exploits or attacks beyond the CISA KEV catalog." />
        </div>
        <TextAreaInput label="Notes" value={notes} onChange={setNotes} rows={3} className="md:col-span-2" />
      </div>
      {error && <Alert>{error}</Alert>}
    </AppModal>
  );
}

function VulnDetailModal({ vuln, onClose }: { vuln: Vulnerability | null; onClose: () => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const history = useQuery(["vulns"], () => (vuln ? api.vulnHistory(vuln.id) : Promise.resolve([])), [vuln?.id], runtime && !!vuln);
  const [ctx, setCtx] = useState({ exposure: "unknown" as Exposure, criticality: "medium" as Confidence, exploitKnown: false });
  const [status, setStatus] = useState<VulnStatus>("open");
  const [statusNote, setStatusNote] = useState("");
  const [plan, setPlan] = useState({ text: "", owner: "", due: "" });
  const [verifyNote, setVerifyNote] = useState("");
  const [accepting, setAccepting] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!vuln) return;
    setCtx({ exposure: vuln.exposure, criticality: vuln.criticality, exploitKnown: vuln.exploitKnown });
    setStatus(vuln.status);
    setStatusNote("");
    setPlan({ text: vuln.remediation, owner: vuln.remediationOwner, due: vuln.remediationDue ?? "" });
    setVerifyNote("");
    setError(null);
  }, [vuln]);

  const run = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
      invalidate("vulns", "findings");
      notify.success(done);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };
  if (!vuln) return null;
  const ctxChanged = ctx.exposure !== vuln.exposure || ctx.criticality !== vuln.criticality || ctx.exploitKnown !== vuln.exploitKnown;
  const planChanged = plan.text !== vuln.remediation || plan.owner !== vuln.remediationOwner || plan.due !== (vuln.remediationDue ?? "");

  return (
    <AppModal isOpen={!!vuln} onOpenChange={(o) => !o && onClose()} title={vuln.cveId} description={vuln.title || undefined} size="lg">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <ToneChip tone={PRIORITY_META[vuln.priority].tone}>
          {PRIORITY_META[vuln.priority].label} · {vuln.priorityScore.toFixed(1)}
        </ToneChip>
        <ToneChip tone={VULN_STATUS_META[vuln.status].tone}>{VULN_STATUS_META[vuln.status].label}</ToneChip>
        {vuln.kev && <ToneChip tone="danger">CISA KEV</ToneChip>}
        {vuln.asset && <span className="font-mono text-muted">{vuln.asset}</span>}
        <Button size="sm" variant="ghost" onPress={() => openExternal(nvdUrl(vuln.cveId))}>
          <ExternalLink className="size-3.5" />
          NVD
        </Button>
      </div>

      <section>
        <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">Why this priority</h3>
        <ul className="panel-inset flex flex-col gap-1 px-3 py-2 text-[12.5px]">
          {vuln.priorityReasons.map((r) => (
            <li key={r.factor} className="flex gap-3">
              <span className={r.effect > 0 ? "w-12 shrink-0 tabular text-warning-soft-foreground" : r.effect < 0 ? "w-12 shrink-0 tabular text-success-soft-foreground" : "w-12 shrink-0 tabular text-muted"}>
                {r.factor === "cvss" ? r.effect.toFixed(1) : `${r.effect > 0 ? "+" : ""}${r.effect.toFixed(1)}`}
              </span>
              <span>{r.text}</span>
            </li>
          ))}
        </ul>
        <p className="mt-1 text-[12px] text-muted">P1 from 11, P2 from 8.5, P3 from 6. CVSS {vuln.cvssScore?.toFixed(1) ?? "unknown"}{vuln.cvssVersion ? ` (v${vuln.cvssVersion})` : ""}; EPSS {formatEpss(vuln)}{vuln.epssDate ? ` on ${vuln.epssDate}` : ""}.</p>
      </section>

      <section className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <SelectInput label="Exposure" value={ctx.exposure} onChange={(v) => setCtx((c) => ({ ...c, exposure: v as Exposure }))} options={EXPOSURE_OPTIONS} />
        <SelectInput label="Asset criticality" value={ctx.criticality} onChange={(v) => setCtx((c) => ({ ...c, criticality: v as Confidence }))} options={CRITICALITY_OPTIONS} />
        <SwitchInput label="Exploitation is known" isSelected={ctx.exploitKnown} onChange={(v) => setCtx((c) => ({ ...c, exploitKnown: v }))} />
        <div className="flex justify-end">
          <Button size="sm" variant="secondary" isDisabled={!ctxChanged} isPending={busy === "ctx"} onPress={() => run("ctx", () => api.vulnSetContext(vuln.id, ctx.exposure, ctx.criticality, ctx.exploitKnown), "Priority recomputed")}>
            Save context
          </Button>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-3 md:grid-cols-[200px_1fr_auto] md:items-end">
        <SelectInput label="Status" value={status} onChange={(v) => setStatus(v as VulnStatus)} options={STATUS_OPTIONS} />
        <TextInput label={needsReason(status) ? "Reason (required)" : "Note"} value={statusNote} onChange={setStatusNote} isDisabled={status === "accepted_risk" && vuln.status !== "accepted_risk"} />
        <Button
          size="sm"
          variant="secondary"
          isDisabled={status === vuln.status || (needsReason(status) && !statusNote.trim())}
          isPending={busy === "status"}
          onPress={() =>
            status === "accepted_risk"
              ? setAccepting(true)
              : run("status", () => api.vulnSetStatus(vuln.id, status, statusNote), `Marked as ${VULN_STATUS_META[status].label.toLowerCase()}`)
          }
        >
          {status === "accepted_risk" ? "Accept risk…" : "Change status"}
        </Button>
      </section>
      {accepting && (
        <AcceptRiskModal
          projectId={vuln.projectId}
          items={[{ kind: "vulnerability", refId: vuln.id }]}
          labels={[`${vuln.cveId}${vuln.title ? ` · ${vuln.title}` : ""}`]}
          defaultTitle={`${vuln.cveId} accepted`}
          isOpen
          onOpenChange={(o) => !o && setAccepting(false)}
        />
      )}

      <section className="flex flex-col gap-3">
        <TextAreaInput label="Remediation plan" value={plan.text} onChange={(v) => setPlan((p) => ({ ...p, text: v }))} rows={3} placeholder="Upgrade, configuration change or compensating control" />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_180px_auto] md:items-end">
          <TextInput label="Owner" value={plan.owner} onChange={(v) => setPlan((p) => ({ ...p, owner: v }))} placeholder="Team or person" />
          <TextInput label="Due date" value={plan.due} onChange={(v) => setPlan((p) => ({ ...p, due: v }))} placeholder="YYYY-MM-DD" mono />
          <Button size="sm" variant="secondary" isDisabled={!planChanged} isPending={busy === "plan"} onPress={() => run("plan", () => api.vulnSetRemediation(vuln.id, plan.text, plan.owner, plan.due || null), "Remediation saved")}>
            Save plan
          </Button>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto] md:items-end">
        <TextInput
          label="Verification"
          value={verifyNote}
          onChange={setVerifyNote}
          placeholder={vuln.verifiedAt ? `Verified ${formatDateTime(vuln.verifiedAt)}: ${vuln.verificationNote}` : "How the fix was confirmed (rescan, version check…)"}
        />
        <Button size="sm" variant="primary" isDisabled={!verifyNote.trim()} isPending={busy === "verify"} onPress={() => run("verify", () => api.vulnVerify(vuln.id, verifyNote), "Fix verified; marked as resolved")}>
          <ShieldCheck className="size-3.5" />
          Mark fix verified
        </Button>
      </section>

      {error && <Alert>{error}</Alert>}

      <section>
        <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">History</h3>
        {!history.data ? (
          <LoadingRows rows={2} />
        ) : (
          <ol className="flex flex-col gap-1 text-[12.5px]">
            {history.data.map((e) => (
              <li key={e.id} className="flex gap-3">
                <span className="w-32 shrink-0 text-muted">{formatRelative(e.at)}</span>
                <span className="min-w-0">
                  <span className="text-foreground">
                    {e.kind === "status" || e.kind === "priority" || e.kind === "verification" ? `${e.kind}: ${e.fromValue ?? "—"} → ${e.toValue ?? "—"}` : e.kind}
                  </span>
                  {e.note && <span className="text-muted"> · {e.note}</span>}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>

      <div className="flex flex-wrap justify-between gap-2">
        <Button
          size="sm"
          variant="ghost"
          onPress={async () => {
            if (!(await confirm.ask({ title: `Stop tracking ${vuln.cveId}?`, body: "Its history and remediation plan are deleted; linked findings stay.", confirmLabel: "Delete" }))) return;
            await run("delete", () => api.vulnDelete(vuln.id), "Vulnerability deleted");
            onClose();
          }}
        >
          <Trash2 className="size-3.5" />
          Delete
        </Button>
        <Button size="sm" variant="secondary" isPending={busy === "finding"} onPress={() => run("finding", () => api.vulnCreateFinding(vuln.id), "Finding recorded and linked")}>
          <FilePlus2 className="size-3.5" />
          Create finding
        </Button>
      </div>
      {confirm.element}
    </AppModal>
  );
}

export function VulnerabilitiesTab({ project }: { project: Project }) {
  const { runtime, prefs, setPref } = useApp();
  const vulns = useQuery(["vulns"], () => api.vulnsList(project.id), [project.id], runtime);
  const [adding, setAdding] = useState(false);
  const [openId, setOpenId] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState({ query: "", status: "open", priority: "all" });
  const epssOn = prefs["epss.enabled"] !== false;

  const list = vulns.data ?? [];
  const counts = useMemo(() => countByPriority(list), [list]);
  const overdue = list.filter((v) => isOverdue(v)).length;
  const shown = list.filter(
    (v) =>
      (filter.status === "all" || (filter.status === "open" ? isOpenVuln(v.status) : !isOpenVuln(v.status))) &&
      (filter.priority === "all" || v.priority === filter.priority) &&
      (!filter.query.trim() || `${v.cveId} ${v.title} ${v.asset ?? ""}`.toLowerCase().includes(filter.query.trim().toLowerCase())),
  );
  const current = list.find((v) => v.id === openId) ?? null;

  const refresh = async () => {
    setRefreshing(true);
    try {
      const r = await api.vulnsRefresh(project.id);
      invalidate("vulns");
      notify.success(`Updated ${r.updated} vulnerabilities`, r.warnings.join(" ") || undefined);
    } catch (e) {
      notify.error("Could not update the scores", e);
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="panel grid grid-cols-2 gap-4 p-4 md:grid-cols-5">
        {(["p1", "p2", "p3", "p4"] as const).map((p) => (
          <Stat key={p} label={`${PRIORITY_META[p].label} open`} value={counts[p]} hint={PRIORITY_META[p].help} tone={counts[p] && (p === "p1" || p === "p2") ? (p === "p1" ? "danger" : "warning") : "default"} />
        ))}
        <Stat label="Overdue" value={overdue} hint="Open past the due date" tone={overdue ? "danger" : "default"} />
      </div>
      <Panel
        title="Vulnerabilities"
        description="Ordered by priority. Every priority lists the factors it was computed from."
        actions={
          <>
            <Button size="sm" variant="tertiary" onPress={refresh} isPending={refreshing} isDisabled={list.length === 0}>
              <RefreshCw className="size-3.5" />
              Update scores
            </Button>
            <Button size="sm" variant="primary" onPress={() => setAdding(true)}>
              <Plus className="size-3.5" />
              Track vulnerability
            </Button>
          </>
        }
        toolbar={
          <div className="flex flex-wrap items-center gap-3">
            <SearchInput value={filter.query} onChange={(query) => setFilter((f) => ({ ...f, query }))} placeholder="Search CVE, title or asset" className="w-60" />
            <SelectInput
              aria-label="Filter by status"
              value={filter.status}
              onChange={(status) => setFilter((f) => ({ ...f, status }))}
              options={[
                { id: "open", label: "Needs work" },
                { id: "closed", label: "Closed" },
                { id: "all", label: "All statuses" },
              ]}
              className="w-36"
            />
            <SelectInput
              aria-label="Filter by priority"
              value={filter.priority}
              onChange={(priority) => setFilter((f) => ({ ...f, priority }))}
              options={[{ id: "all", label: "All priorities" }, ...(["p1", "p2", "p3", "p4"] as const).map((p) => ({ id: p, label: PRIORITY_META[p].label }))]}
              className="w-36"
            />
            <SwitchInput label="Use EPSS (FIRST.org)" isSelected={epssOn} onChange={(v) => void setPref("epss.enabled", v)} />
          </div>
        }
      >
        {vulns.error && !vulns.data ? (
          <ErrorBlock message={vulns.error} onRetry={vulns.reload} />
        ) : vulns.loading && !vulns.data ? (
          <LoadingRows rows={4} />
        ) : list.length === 0 ? (
          <EmptyBlock icon={ShieldCheck} title="No vulnerabilities tracked" description="Track CVEs that affect this project's assets to prioritize and follow their remediation." />
        ) : shown.length === 0 ? (
          <EmptyBlock compact icon={ShieldCheck} title="No vulnerabilities match these filters" />
        ) : (
          <div className="panel-inset overflow-x-auto px-3 py-1">
            <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
              <thead>
                <tr className="text-[12px] text-muted">
                  <th className="py-2 pr-3 font-medium">Priority</th>
                  <th className="py-2 pr-3 font-medium">Vulnerability</th>
                  <th className="py-2 pr-3 font-medium">Asset</th>
                  <th className="py-2 pr-3 font-medium">CVSS</th>
                  <th className="py-2 pr-3 font-medium">EPSS</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 font-medium">Due</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((v) => (
                  <tr key={v.id} className="cursor-pointer align-top transition-colors hover:bg-white/[0.025]" onClick={() => setOpenId(v.id)}>
                    <td className="py-2 pr-3">
                      <ToneChip tone={PRIORITY_META[v.priority].tone}>{PRIORITY_META[v.priority].label}</ToneChip>
                    </td>
                    <td className="max-w-[360px] py-2 pr-3">
                      <button type="button" className="font-mono text-[12.5px] text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-accent" onClick={() => setOpenId(v.id)}>
                        {v.cveId}
                      </button>
                      {v.kev && <span className="ml-2 text-[11.5px] text-danger-soft-foreground">KEV</span>}
                      <div className="truncate text-[12px] text-muted">{v.title || "No NVD description"}</div>
                    </td>
                    <td className="max-w-[200px] truncate py-2 pr-3 font-mono text-[12px] text-muted">{v.asset ?? "—"}</td>
                    <td className="py-2 pr-3 tabular">{v.cvssScore?.toFixed(1) ?? "—"}</td>
                    <td className="py-2 pr-3 tabular text-muted">{formatEpss(v)}</td>
                    <td className="py-2 pr-3">
                      <ToneChip tone={VULN_STATUS_META[v.status].tone}>{VULN_STATUS_META[v.status].label}</ToneChip>
                    </td>
                    <td className={isOverdue(v) ? "py-2 whitespace-nowrap text-danger-soft-foreground" : "py-2 whitespace-nowrap text-muted"}>{v.remediationDue ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <AddVulnModal isOpen={adding} onOpenChange={setAdding} project={project} />
      <VulnDetailModal vuln={current} onClose={() => setOpenId(null)} />
    </div>
  );
}
