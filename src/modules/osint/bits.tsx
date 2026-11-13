// SPDX-License-Identifier: Apache-2.0
/** Small presentational pieces shared by the OSINT tabs. Collected values are rendered as text only. */
import { useEffect, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { cn } from "@/lib/utils";
import { CONFIDENCE_META, typeStyle, VERIFICATION_META } from "./model";
import type { Operation, Verification } from "./types";

export function TypeBadge({ type, label, className }: { type: string; label?: string; className?: string }) {
  const s = typeStyle(type);
  return (
    <span className={cn("inline-flex min-w-0 items-center gap-1.5 text-[12.5px] text-muted", className)}>
      <span
        aria-hidden
        className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[9.5px] font-semibold text-[#0a0b10]"
        style={{ backgroundColor: s.color }}
      >
        {s.glyph}
      </span>
      {label !== undefined && <span className="truncate">{label}</span>}
    </span>
  );
}

export function VerificationChip({ value }: { value: Verification | string }) {
  const m = VERIFICATION_META[value as Verification] ?? { label: value, tone: "default" as const };
  return <ToneChip tone={m.tone}>{m.label}</ToneChip>;
}

export function ConfidenceText({ value }: { value: string }) {
  const m = CONFIDENCE_META[value];
  return <span className="text-[12.5px] text-muted">{m ? m.label.replace(" confidence", "") : value}</span>;
}

export const OP_STATUS_META: Record<Operation["status"], { label: string; tone: "default" | "accent" | "success" | "warning" | "danger" }> = {
  running: { label: "Running", tone: "accent" },
  completed: { label: "Completed", tone: "success" },
  failed: { label: "Failed", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "default" },
};

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[12px] text-muted">{label}</div>
      <div className="mt-0.5 text-[13px] break-words text-foreground">{children}</div>
    </div>
  );
}
