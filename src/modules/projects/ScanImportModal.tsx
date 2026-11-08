import { Button } from "@heroui/react";
import { FileUp } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { SeverityBadge, ToneChip, type Tone } from "@/components/ui/Badges";
import { importCount, knownCount, nothingToImport, OUTCOME_META, shownOutcome } from "./scanImport";
import { AppModal } from "@/components/ui/Dialogs";
import { ErrorBlock, InlineSpinner } from "@/components/ui/Feedback";
import { SwitchInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ScanImportOptions, ScanImportPending, ScanImportPreview, Severity } from "@/lib/types";
import { formatDateTime, formatNumber, pluralize } from "@/lib/utils";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ScanImportModal({ isOpen, onOpenChange, projectId }: { isOpen: boolean; onOpenChange: (o: boolean) => void; projectId: number }) {
  const [pending, setPending] = useState<ScanImportPending | null>(null);
  const [preview, setPreview] = useState<ScanImportPreview | null>(null);
  const [options, setOptions] = useState<ScanImportOptions>({ includeInfo: false, reopenResolved: true, useTemplates: true });
  const [busy, setBusy] = useState<"pick" | "preview" | "apply" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tokenRef = useRef<string | null>(null);
  const history = useQuery(["findings"], () => api.scanImportsList(projectId), [projectId], isOpen);

  useEffect(() => {
    if (isOpen) {
      setPending(null);
      setPreview(null);
      setError(null);
      setOptions({ includeInfo: false, reopenResolved: true, useTemplates: true });
    }
  }, [isOpen]);

  const discard = () => {
    if (tokenRef.current) {
      void api.scanImportDiscard(tokenRef.current).catch(() => undefined);
      tokenRef.current = null;
    }
  };

  const close = (o: boolean) => {
    if (!o) discard();
    onOpenChange(o);
  };

  const pick = async () => {
    setBusy("pick");
    setError(null);
    try {
      const p = await api.scanImportPick(projectId, options);
      if (!p) return;
      discard();
      tokenRef.current = p.token;
      setPending(p);
      setPreview(p);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const changeOption = async (patch: Partial<ScanImportOptions>) => {
    const next = { ...options, ...patch };
    setOptions(next);
    if (!pending) return;
    setBusy("preview");
    try {
      setPreview(await api.scanImportPreview(pending.token, next));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (!pending) return;
    setBusy("apply");
    setError(null);
    try {
      const r = await api.scanImportCommit(pending.token, options);
      tokenRef.current = null;
      invalidate("findings", "projects", "assets");
      notify.success(`${pending.tool} results imported`, r.summary);
      onOpenChange(false);
    } catch (e) {
      // the preview is used up either way; choosing the file again starts over
      tokenRef.current = null;
      setPending(null);
      setPreview(null);
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const creating = preview ? importCount(preview, options) : 0;
  const nothing = preview ? nothingToImport(preview, options) : true;

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={close}
      size="lg"
      title="Import scan results"
      description="Nmap and Nessus XML, Burp Suite issue exports, Nuclei, OWASP ZAP and SARIF JSON. You see what the file contains before anything is recorded."
      footer={
        <>
          <Button variant="tertiary" onPress={() => close(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={apply} isDisabled={!pending || busy !== null || nothing} isPending={busy === "apply"}>
            {creating > 0 ? `Import ${pluralize(creating, "finding")}` : "Import"}
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={pending ? "tertiary" : "primary"} onPress={pick} isPending={busy === "pick"}>
          <FileUp className="size-4" />
          {pending ? "Choose another file" : "Choose file"}
        </Button>
        {pending && (
          <span className="min-w-0 truncate font-mono text-[12.5px] text-muted" title={`SHA-256 ${pending.sha256}`}>
            {pending.fileName} · {formatNumber(Math.ceil(pending.size / 1024))} KB
          </span>
        )}
        {busy === "preview" && <InlineSpinner label="Checking…" />}
      </div>

      {!pending && (
        <div className="flex flex-col gap-3 text-[13px] text-muted">
          <p>
            The format is recognized from the content. Hosts outside the project scope are listed and left out. A finding imported before is not duplicated: its history records the new sighting. Findings you dismissed stay dismissed. The file is kept in the evidence vault, and every imported finding links to it.
          </p>
          {history.data && history.data.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <div className="text-[12px] font-medium text-foreground">Earlier imports</div>
              <ul className="panel-inset flex flex-col gap-1 px-3 py-2 text-[12.5px]">
                {history.data.slice(0, 6).map((h) => (
                  <li key={h.id} className="flex flex-wrap items-baseline gap-x-2">
                    <span className="text-foreground">{h.tool}</span>
                    <span className="truncate font-mono text-muted">{h.fileName}</span>
                    <span className="text-muted">{formatDateTime(h.createdAt)}</span>
                    {h.summary.text && <span className="w-full text-muted">{h.summary.text}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {pending && preview && (
        <div className="flex flex-col gap-4">
          <div className="panel-inset grid gap-3 px-4 py-3 sm:grid-cols-5">
            <Stat label="Tool" value={preview.tool} hint={preview.formatLabel} />
            <Stat label="Findings in the file" value={formatNumber(preview.findings)} />
            <Stat label="New" value={formatNumber(creating)} />
            <Stat label="Already recorded" value={formatNumber(knownCount(preview))} />
            <Stat label="Assets" value={formatNumber(preview.assets)} hint={preview.assetsNew > 0 ? `${formatNumber(preview.assetsNew)} new` : undefined} />
          </div>

          {preview.findings > 0 && (
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.filter((s) => (preview.bySeverity[s] ?? 0) > 0).map((s) => (
                <span key={s} className="flex items-center gap-1.5 text-[12.5px] text-muted">
                  <SeverityBadge severity={s} /> {formatNumber(preview.bySeverity[s] ?? 0)}
                </span>
              ))}
            </div>
          )}

          <div className="flex flex-col gap-2 text-[13px]">
            {preview.counts.recurring > 0 && (
              <SwitchInput
                isSelected={options.reopenResolved}
                onChange={(v) => setOptions({ ...options, reopenResolved: v })}
                label={`Reopen ${pluralize(preview.counts.recurring, "resolved finding")} that the file reports again`}
                description="Otherwise the sighting is only noted in their history."
              />
            )}
            {preview.counts.info > 0 && (
              <SwitchInput
                isSelected={options.includeInfo}
                onChange={(v) => void changeOption({ includeInfo: v })}
                label={`Also import ${pluralize(preview.counts.info, "informational finding")}`}
                description="Usually inventory (scan details, detected software). Hosts and services are recorded either way."
              />
            )}
            {(preview.templated > 0 || !options.useTemplates) && (
              <SwitchInput
                isSelected={options.useTemplates}
                onChange={(v) => void changeOption({ useTemplates: v })}
                label={options.useTemplates ? `Write ${pluralize(preview.templated, "finding")} from your finding library templates` : "Write matching findings from your finding library templates"}
                description="Templates whose import rule names the scanner rule replace its title, severity, description and remediation. Targets, CVEs and the scanner's evidence stay."
              />
            )}
            {preview.counts.dismissed > 0 && <Note tone="default">{pluralize(preview.counts.dismissed, "finding")} you dismissed earlier (false positive or accepted risk) stay dismissed.</Note>}
            {preview.markedFalsePositive > 0 && <Note tone="default">{pluralize(preview.markedFalsePositive, "alert")} marked as false positive in the file are not imported.</Note>}
            {preview.merged > 0 && <Note tone="default">{pluralize(preview.merged, "repeated result")} in the file merged into one finding each.</Note>}
            {preview.counts.outOfScope + preview.assetsOutOfScope > 0 && (
              <Note tone="danger">
                {pluralize(preview.counts.outOfScope, "finding")} and {pluralize(preview.assetsOutOfScope, "asset")} are outside the project scope and will not be recorded
                {preview.outOfScopeHosts.length > 0 && <>: {preview.outOfScopeHosts.join(", ")}</>}. Add them to the scope first if they are authorized.
              </Note>
            )}
          </div>

          {preview.warnings.length > 0 && (
            <ul className="max-h-32 overflow-auto rounded-[10px] bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
              {preview.warnings.map((w, i) => (
                <li key={i} className="py-0.5 break-words">
                  {w}
                </li>
              ))}
            </ul>
          )}

          {preview.items.length > 0 && (
            <div className="panel-inset max-h-72 overflow-auto px-3 py-1">
              <table className="w-full border-separate border-spacing-y-0.5 text-left text-[12.5px]">
                <thead>
                  <tr className="text-[12px] text-muted">
                    <th className="py-1.5 pr-3 font-medium">Severity</th>
                    <th className="py-1.5 pr-3 font-medium">Finding</th>
                    <th className="py-1.5 pr-3 font-medium">Target</th>
                    <th className="py-1.5 font-medium">On import</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.items.map((it, i) => {
                    const outcome = shownOutcome(it.outcome, options);
                    return (
                      <tr key={i} className="align-top">
                        <td className="py-1.5 pr-3">
                          <SeverityBadge severity={it.severity} />
                        </td>
                        <td className="py-1.5 pr-3 text-foreground">
                          {it.title}
                          {it.template && options.useTemplates && <div className="text-[11.5px] text-muted">From the library template</div>}
                        </td>
                        <td className="max-w-[240px] py-1.5 pr-3 font-mono break-all text-muted">{it.target}</td>
                        <td className="py-1.5 whitespace-nowrap">
                          <ToneChip tone={OUTCOME_META[outcome].tone}>{OUTCOME_META[outcome].label}</ToneChip>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {preview.findings > preview.items.length && <p className="py-2 text-[12px] text-muted">The first {formatNumber(preview.items.length)} of {formatNumber(preview.findings)} are listed.</p>}
            </div>
          )}
        </div>
      )}
    </AppModal>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[12px] text-muted">{label}</div>
      <div className="truncate text-[15px] font-semibold text-foreground">{value}</div>
      {hint && <div className="truncate text-[11.5px] text-muted">{hint}</div>}
    </div>
  );
}

function Note({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 text-muted">
      <ToneChip tone={tone} className="mt-0.5 shrink-0">
        {tone === "danger" ? "Scope" : "Note"}
      </ToneChip>
      <span>{children}</span>
    </div>
  );
}
