// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { AlertTriangle, History, RefreshCw, ShieldCheck, ShieldOff } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Project, RiskAcceptance, RiskDraft, RiskItemRef } from "@/lib/types";
import { pluralize } from "@/lib/utils";
import { addDays, draftProblems, expiryText, newDraft, RISK_STANDING, todayUtc } from "./risk";

const ITEM_KIND: Record<string, string> = { finding: "Finding", vulnerability: "Vulnerability", asvs: "ASVS", wstg: "WSTG test" };

/** Records a risk acceptance for `items`: the only way to make a finding or a vulnerability an
 * accepted risk, or to give a non-compliant ASVS requirement or a failed WSTG test an exception. */
export function AcceptRiskModal({
  projectId,
  items,
  labels,
  defaultTitle,
  isOpen,
  onOpenChange,
  onDone,
}: {
  projectId: number;
  items: RiskItemRef[];
  /** what each item is, shown to the analyst */
  labels: string[];
  defaultTitle?: string;
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  onDone?: () => void;
}) {
  const today = todayUtc();
  const [d, setD] = useState<RiskDraft>(() => newDraft(today, defaultTitle ?? ""));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problems = draftProblems(d, today);
  const set = (k: keyof RiskDraft, v: string) => setD((x) => ({ ...x, [k]: k === "reviewAt" ? v || null : v }));
  // a requirement or a test is excepted; a finding or a vulnerability is an accepted risk
  const exceptionOnly = items.length > 0 && items.every((i) => i.kind === "asvs" || i.kind === "wstg");
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.riskAccept(projectId, d, items);
      invalidate("risk", "findings", "vulns", "asvs", "projects");
      notify.success(exceptionOnly ? "Exception recorded" : "Risk acceptance recorded", `${pluralize(items.length, "item")} covered until ${d.expiresAt}`);
      onOpenChange(false);
      onDone?.();
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
      size="lg"
      title={exceptionOnly ? "Record an exception" : "Accept risk"}
      description={
        exceptionOnly
          ? "An exception is not compliance: excepted requirements stay non-compliant and excepted tests stay failed. It is listed with the risk acceptances until it expires or is revoked."
          : "Accepting a risk is not fixing it: the items stay listed as accepted risks, apart from open and resolved ones, until the acceptance expires or is revoked."
      }
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isDisabled={problems.length > 0} isPending={saving}>
            {exceptionOnly ? "Record exception" : "Record acceptance"}
          </Button>
        </>
      }
    >
      <section className="rounded-lg bg-white/[0.03] px-3 py-2 text-[12.5px]">
        <div className="mb-1 font-medium">{pluralize(items.length, "item")} covered</div>
        <ul className="flex max-h-28 flex-col gap-0.5 overflow-y-auto text-muted">
          {labels.map((l, i) => (
            <li key={i} className="truncate">
              {l}
            </li>
          ))}
        </ul>
      </section>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Title" value={d.title} onChange={(v) => set("title", v)} isRequired className="md:col-span-2" placeholder="Legacy TLS on the payment gateway" />
        <TextAreaInput label="Justification" value={d.justification} onChange={(v) => set("justification", v)} rows={3} className="md:col-span-2" placeholder="Why the risk is accepted rather than fixed now, and what it would cost to fix" />
        <TextAreaInput label="Compensating controls" value={d.compensating} onChange={(v) => set("compensating", v)} rows={2} className="md:col-span-2" placeholder="What reduces the risk meanwhile (optional)" />
        <TextInput label="Risk owner" value={d.owner} onChange={(v) => set("owner", v)} isRequired placeholder="Who carries the risk" />
        <TextInput label="Approved by" value={d.approver} onChange={(v) => set("approver", v)} isRequired placeholder="Who approved the acceptance" />
        <TextInput label="Approval date" type="date" value={d.approvedAt} onChange={(v) => set("approvedAt", v)} isRequired />
        <TextInput label="Expires on" type="date" value={d.expiresAt} onChange={(v) => set("expiresAt", v)} isRequired description="At most three years after the approval" />
        <TextInput label="Review on" type="date" value={d.reviewAt ?? ""} onChange={(v) => set("reviewAt", v)} description="Optional: flags the acceptance for review before it expires" />
      </div>
      {problems.length > 0 && <p className="text-[12.5px] text-muted">Still needed: {problems.join(", ")}.</p>}
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

/** A new approval and expiry for an acceptance (renewal), or its revocation with a reason. */
function RenewModal({ a, onClose }: { a: RiskAcceptance; onClose: () => void }) {
  const today = todayUtc();
  const [d, setD] = useState<RiskDraft>({ title: a.title, justification: a.justification, compensating: a.compensating, owner: a.owner, approver: a.approver, approvedAt: today, expiresAt: addDays(today, 90), reviewAt: null });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const problems = draftProblems(d, today);
  const set = (k: keyof RiskDraft, v: string) => setD((x) => ({ ...x, [k]: k === "reviewAt" ? v || null : v }));
  const save = async () => {
    setSaving(true);
    try {
      await api.riskRenew(a.id, d);
      invalidate("risk", "findings", "vulns", "asvs");
      notify.success("Acceptance renewed", `until ${d.expiresAt}`);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title="Renew acceptance"
      description="A renewal is a new approval: who approved it, when, and the new expiry. The history keeps the previous one."
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isDisabled={problems.length > 0} isPending={saving}>
            Renew
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextAreaInput label="Justification" value={d.justification} onChange={(v) => set("justification", v)} rows={3} className="md:col-span-2" />
        <TextInput label="Risk owner" value={d.owner} onChange={(v) => set("owner", v)} isRequired />
        <TextInput label="Approved by" value={d.approver} onChange={(v) => set("approver", v)} isRequired />
        <TextInput label="Approval date" type="date" value={d.approvedAt} onChange={(v) => set("approvedAt", v)} isRequired />
        <TextInput label="Expires on" type="date" value={d.expiresAt} onChange={(v) => set("expiresAt", v)} isRequired />
        <TextInput label="Review on" type="date" value={d.reviewAt ?? ""} onChange={(v) => set("reviewAt", v)} />
      </div>
      {problems.length > 0 && <p className="text-[12.5px] text-muted">Still needed: {problems.join(", ")}.</p>}
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function RevokeModal({ a, onClose }: { a: RiskAcceptance; onClose: () => void }) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const open = a.items.filter((i) => !i.removedAt);
  const revoke = async () => {
    setSaving(true);
    try {
      await api.riskRevoke(a.id, reason);
      invalidate("risk", "findings", "vulns", "asvs", "projects");
      notify.success("Acceptance revoked", open.length ? `${pluralize(open.length, "item")} reopened` : undefined);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title="Revoke acceptance"
      description={`The risk is no longer accepted. Findings it covers are reopened and vulnerabilities set open again${open.some((i) => i.kind === "asvs") ? "; ASVS requirements lose their exception" : ""}${open.some((i) => i.kind === "wstg") ? "; WSTG tests lose their exception and stay failed" : ""}.`}
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button variant="danger" onPress={revoke} isDisabled={!reason.trim()} isPending={saving}>
            Revoke
          </Button>
        </>
      }
    >
      <TextAreaInput label="Reason" value={reason} onChange={setReason} rows={3} isRequired placeholder="Why the risk is no longer accepted" />
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function HistoryList({ id }: { id: number }) {
  const { runtime } = useApp();
  const h = useQuery(["risk"], () => api.riskHistory(id), [id], runtime);
  if (h.error) return <ErrorBlock message={h.error} onRetry={h.reload} />;
  return (
    <ol className="flex flex-col gap-0.5 text-[12px] text-muted">
      {(h.data ?? []).map((e, i) => (
        <li key={i}>
          <span className="font-mono">{e.at.slice(0, 16).replace("T", " ")}</span> · {e.action.replace("_", " ")}
          {e.detail && <> — {e.detail}</>}
          {e.source !== "user" && <> ({e.source})</>}
        </li>
      ))}
    </ol>
  );
}

function AcceptanceCard({ a, archived, today }: { a: RiskAcceptance; archived: boolean; today: string }) {
  const [renewing, setRenewing] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const meta = RISK_STANDING[a.standing];
  const open = a.items.filter((i) => !i.removedAt);
  const left = a.items.filter((i) => i.removedAt);
  return (
    <li className="flex flex-col gap-2 rounded-[10px] bg-white/[0.03] px-3.5 py-3 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <ToneChip tone={meta.tone} dot={false} className="text-[11px]">
          {meta.label}
        </ToneChip>
        <span className="text-[13px] font-medium">{a.title}</span>
        <span className="text-muted">#{a.id}</span>
        <span className="ml-auto text-muted">{expiryText(a, today)}</span>
      </div>
      <div className="grid grid-cols-1 gap-x-6 gap-y-0.5 text-muted md:grid-cols-2">
        <span>
          Owner: <span className="text-foreground">{a.owner}</span>
        </span>
        <span>
          Approved by <span className="text-foreground">{a.approver}</span> on {a.approvedAt}
        </span>
        {a.reviewAt && <span>Review on {a.reviewAt}</span>}
        {a.status === "revoked" && (
          <span>
            Revoked {a.revokedAt?.slice(0, 10)}: {a.revokedReason}
          </span>
        )}
      </div>
      <p className="whitespace-pre-wrap">{a.justification}</p>
      {a.compensating && <p className="whitespace-pre-wrap text-muted">Compensating controls: {a.compensating}</p>}
      <ul className="flex flex-col gap-0.5">
        {open.map((i) => (
          <li key={`${i.kind}:${i.refId}:${i.requirement}`} className="flex flex-wrap items-center gap-2">
            <span className="text-muted">{ITEM_KIND[i.kind]}</span>
            <span className="truncate">{i.label}</span>
            <span className="text-muted">({i.status.replace(/_/g, " ")})</span>
          </li>
        ))}
        {open.length === 0 && <li className="text-muted">It covers nothing now.</li>}
      </ul>
      <details>
        <summary className="cursor-pointer text-muted">
          <History className="mr-1 inline size-3.5" />
          History{left.length > 0 ? ` · ${pluralize(left.length, "item")} no longer covered` : ""}
        </summary>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {left.map((i) => (
            <div key={`left:${i.kind}:${i.refId}:${i.requirement}`} className="text-[12px] text-muted">
              {ITEM_KIND[i.kind]} {i.label}: left {i.removedAt?.slice(0, 10)} — {i.removedReason}
            </div>
          ))}
          <HistoryList id={a.id} />
        </div>
      </details>
      {a.status === "active" && !archived && (
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" className="h-7 gap-1" onPress={() => setRenewing(true)}>
            <RefreshCw className="size-3.5" />
            Renew…
          </Button>
          <Button size="sm" variant="ghost" className="h-7 gap-1 text-danger" onPress={() => setRevoking(true)}>
            <ShieldOff className="size-3.5" />
            Revoke…
          </Button>
        </div>
      )}
      {renewing && <RenewModal a={a} onClose={() => setRenewing(false)} />}
      {revoking && <RevokeModal a={a} onClose={() => setRevoking(false)} />}
    </li>
  );
}

/** Projects → Risks: the risk register. */
export function RiskTab({ project }: { project: Project }) {
  const { runtime } = useApp();
  const list = useQuery(["risk"], () => api.riskList(project.id), [project.id], runtime);
  const overview = useQuery(["risk", "findings"], () => api.riskOverview(project.id), [project.id], runtime);
  const [documenting, setDocumenting] = useState(false);
  const today = todayUtc();
  const archived = project.status === "archived";
  const undocumented = overview.data?.undocumented ?? [];
  const s = overview.data?.summary;
  const counts = useMemo(() => (s ? [`${s.active} active`, s.reviewDue ? `${s.reviewDue} due for review` : "", s.expired ? `${s.expired} expired` : "", s.revoked ? `${s.revoked} revoked` : ""].filter(Boolean).join(" · ") : ""), [s]);
  if (list.error) return <ErrorBlock message={list.error} onRetry={list.reload} />;
  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Risk acceptances and exceptions"
        description="Who accepted which risk, why, approved by whom and until when. Findings and vulnerabilities become accepted risks only through an acceptance; an expired one changes nothing by itself and is flagged until it is renewed or revoked."
        actions={counts ? <span className="text-[12.5px] text-muted">{counts}</span> : undefined}
      >
        {undocumented.length > 0 && (
          <div role="status" className="mb-3 flex flex-wrap items-center gap-2 rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
            <AlertTriangle className="size-4" />
            {pluralize(undocumented.length, "finding")} {undocumented.length === 1 ? "is" : "are"} marked as accepted without a record of who accepted {undocumented.length === 1 ? "it" : "them"}.
            {!archived && (
              <Button size="sm" variant="secondary" className="ml-auto h-7" onPress={() => setDocumenting(true)}>
                Record the acceptance…
              </Button>
            )}
          </div>
        )}
        {list.loading && !list.data ? (
          <LoadingRows rows={3} />
        ) : (list.data ?? []).length === 0 ? (
          <EmptyBlock compact icon={ShieldCheck} title="No risk accepted" description="Accept a risk from a finding (its status menu) or a vulnerability, or record an exception for a non-compliant ASVS requirement or a failed test in the Checklist." />
        ) : (
          <ul className="flex flex-col gap-2">
            {(list.data ?? []).map((a) => (
              <AcceptanceCard key={a.id} a={a} archived={archived} today={today} />
            ))}
          </ul>
        )}
      </Panel>
      {documenting && (
        <AcceptRiskModal
          projectId={project.id}
          items={undocumented.map(([id]) => ({ kind: "finding", refId: id }))}
          labels={undocumented.map(([id, title]) => `Finding #${id} · ${title}`)}
          isOpen
          onOpenChange={(o) => !o && setDocumenting(false)}
        />
      )}
    </div>
  );
}
