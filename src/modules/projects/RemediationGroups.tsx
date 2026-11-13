// SPDX-License-Identifier: Apache-2.0
import { Wrench } from "lucide-react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { RemediationGroup } from "@/lib/types";

const KIND: Record<RemediationGroup["kind"], string> = { cve: "Same CVE", package: "Same package", check: "Same check", fix: "Same remediation" };

/** Findings → Remediation groups: findings that one fix addresses, with how many are open,
 * resolved and verified by a rescan. Read-only: nothing is merged or closed here. */
export function RemediationGroups({ projectId, onOpen }: { projectId: number; onOpen: (findingId: number) => void }) {
  const { runtime } = useApp();
  const groups = useQuery(["findings"], () => api.remediationGroups(projectId), [projectId], runtime);
  if (groups.error) return <ErrorBlock message={groups.error} onRetry={groups.reload} />;
  if (!groups.data) return <LoadingRows rows={4} />;
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[12.5px] text-muted">
        Findings that one fix addresses, from every module: the same CVE, the same package, the same check on several targets, or the same remediation. A fix counts as verified only when a rescan by the same tool resolved the finding; a finding is never closed because another tool did not report it.
      </p>
      {groups.data.length === 0 ? (
        <EmptyBlock compact icon={Wrench} title="No remediation groups" description="Groups appear when several findings share a CVE, a package, a check reported on several targets, or the same remediation." />
      ) : (
        groups.data.map((g) => (
          <section key={`${g.kind}:${g.key}`} className="panel-inset flex flex-col gap-1.5 px-3 py-2.5" aria-label={`${KIND[g.kind]}: ${g.label}`}>
            <div className="flex flex-wrap items-center gap-2">
              <ToneChip tone="default" dot={false} className="text-[11px]">
                {KIND[g.kind]}
              </ToneChip>
              <SeverityBadge severity={g.severity} />
              <span className="min-w-0 truncate text-[13px] font-medium">{g.label}</span>
              <span className="flex-1" />
              <span className="text-[12px] text-muted">
                {g.open} open · {g.resolved} resolved{g.verified ? ` (${g.verified} verified by rescan)` : ""}
              </span>
            </div>
            <span className="text-[12px] text-muted">
              {g.reason}
              {g.kind !== "check" && g.targets > 1 ? ` · ${g.targets} targets` : ""}
            </span>
            {g.fix && (
              <p className="text-[12.5px]">
                <span className="text-muted">Fix: </span>
                {g.fix}
              </p>
            )}
            <ul className="flex flex-col gap-0.5">
              {g.findings.map((m) => (
                <li key={m.id}>
                  <button type="button" onClick={() => onOpen(m.id)} className="flex w-full items-center gap-2 rounded-[6px] px-1.5 py-1 text-left text-[12.5px] hover:bg-white/[0.04]">
                    <SeverityBadge severity={m.severity} />
                    <span className="min-w-0 flex-1 truncate">{m.title}</span>
                    <span className="max-w-[40%] truncate text-muted">{m.target}</span>
                    <span className="text-muted">{m.status.replace("_", " ")}</span>
                    {m.verified && (
                      <ToneChip tone="success" dot={false} className="text-[11px]">
                        verified
                      </ToneChip>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </section>
        ))
      )}
    </div>
  );
}
