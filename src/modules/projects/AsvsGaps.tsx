// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { AsvsSummary } from "@/lib/types";
import { pluralize } from "@/lib/utils";
import { ASVS_STATUS } from "./asvs";
import { RISK_STANDING } from "./risk";

const DIRECTION: Record<string, { label: string; tone: "success" | "danger" | "default" }> = {
  improved: { label: "improved", tone: "success" },
  regressed: { label: "regressed", tone: "danger" },
  changed: { label: "changed", tone: "default" },
};

/** The assessment's gaps by chapter, their exceptions and remediation, compliant requirements
 * without evidence, and how it compares with another assessment of the project. */
export function AsvsGaps({ assessment, others }: { assessment: AsvsSummary; others: AsvsSummary[] }) {
  const { runtime } = useApp();
  const gaps = useQuery(["asvs", "risk", "findings"], () => api.asvsGaps(assessment.id), [assessment.id], runtime);
  const candidates = others.filter((o) => o.id !== assessment.id);
  const [against, setAgainst] = useState<string>("");
  const cmp = useQuery(["asvs"], () => (against ? api.asvsCompare(Number(against), assessment.id) : Promise.resolve(null)), [against, assessment.id], runtime);
  if (gaps.error) return <ErrorBlock message={gaps.error} onRetry={gaps.reload} />;
  if (!gaps.data) return <LoadingRows rows={3} />;
  const g = gaps.data;
  const open = g.gaps.filter((x) => !x.exception || x.exception.standing === "expired");
  return (
    <Panel title="Gaps" description="Non-compliant requirements of the level. An exception (a recorded risk acceptance) covers a gap; it does not close it. Nothing here changes a status.">
      <div className="flex flex-col gap-3 text-[12.5px]">
        <div className="flex flex-wrap gap-1.5">
          <ToneChip tone={open.length ? "danger" : "success"} dot={false}>
            {pluralize(open.length, "open gap")}
          </ToneChip>
          <ToneChip tone="accent" dot={false}>
            {pluralize(g.gaps.length - open.length, "with an exception", "with exceptions")}
          </ToneChip>
          {g.exceptionsExpired > 0 && (
            <ToneChip tone="danger" dot={false}>
              {pluralize(g.exceptionsExpired, "exception")} expired
            </ToneChip>
          )}
          {g.withoutEvidence.length > 0 && (
            <ToneChip tone="warning" dot={false}>
              {pluralize(g.withoutEvidence.length, "compliant requirement")} without evidence
            </ToneChip>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="text-muted">
              <tr>
                <th className="py-1 pr-3 font-normal">Chapter</th>
                <th className="py-1 pr-3 font-normal">Compliant</th>
                <th className="py-1 pr-3 font-normal">Non-compliant</th>
                <th className="py-1 pr-3 font-normal">Excepted</th>
                <th className="py-1 pr-3 font-normal">Needs review</th>
                <th className="py-1 pr-3 font-normal">Not assessed</th>
              </tr>
            </thead>
            <tbody>
              {g.chapters.map((c) => (
                <tr key={c.id}>
                  <td className="py-0.5 pr-3">
                    {c.id} {c.name}
                  </td>
                  <td className="tabular py-0.5 pr-3">
                    {c.compliant}/{c.total - c.notApplicable}
                  </td>
                  <td className={`tabular py-0.5 pr-3 ${c.nonCompliant - c.excepted > 0 ? "text-danger" : ""}`}>{c.nonCompliant}</td>
                  <td className="tabular py-0.5 pr-3">{c.excepted}</td>
                  <td className="tabular py-0.5 pr-3">{c.needsReview}</td>
                  <td className="tabular py-0.5 pr-3 text-muted">{c.notAssessed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {g.gaps.length > 0 && (
          <details>
            <summary className="cursor-pointer text-muted">{pluralize(g.gaps.length, "gap")}, with exceptions and remediation</summary>
            <ul className="mt-1.5 flex flex-col gap-1">
              {g.gaps.map((x) => (
                <li key={x.requirement} className="flex flex-col gap-0.5 rounded-[8px] bg-white/[0.02] px-2.5 py-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11.5px]">{x.requirement}</span>
                    {x.exception ? (
                      <ToneChip tone={x.exception.standing === "active" ? "accent" : RISK_STANDING[x.exception.standing].tone} dot={false} className="text-[10.5px]">
                        {x.exception.standing === "expired" ? `exception expired ${x.exception.expiresAt}` : `exception #${x.exception.id} until ${x.exception.expiresAt}`}
                      </ToneChip>
                    ) : (
                      <ToneChip tone="danger" dot={false} className="text-[10.5px]">
                        open
                      </ToneChip>
                    )}
                    <span className="text-muted">{x.remediation}</span>
                  </div>
                  <span className="line-clamp-2 text-muted">{x.text}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
        {g.withoutEvidence.length > 0 && <p className="text-muted">Compliant on the analyst's word, without linked evidence: {g.withoutEvidence.join(", ")}.</p>}
        {candidates.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <SelectInput
              aria-label="Compare with another assessment"
              value={against}
              onChange={setAgainst}
              options={[{ id: "", label: "Compare with an earlier assessment…" }, ...candidates.map((c) => ({ id: String(c.id), label: `${c.name} (level ${c.level})` }))]}
              className="w-80"
            />
            {cmp.data && (
              <div className="flex flex-col gap-1">
                <p>
                  Since “{cmp.data.from.name}”: {cmp.data.improved} improved, {cmp.data.regressed} regressed, {cmp.data.changed} changed to or from not assessed, {cmp.data.unchanged} unchanged.
                </p>
                <ul className="flex flex-col gap-0.5">
                  {cmp.data.changes.slice(0, 200).map((x) => (
                    <li key={x.requirement} className="flex flex-wrap items-center gap-2">
                      <ToneChip tone={DIRECTION[x.direction].tone} dot={false} className="text-[10.5px]">
                        {DIRECTION[x.direction].label}
                      </ToneChip>
                      <span className="font-mono text-[11.5px]">{x.requirement}</span>
                      <span className="text-muted">
                        {ASVS_STATUS[x.from]?.label ?? x.from} → {ASVS_STATUS[x.to]?.label ?? x.to}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  );
}
