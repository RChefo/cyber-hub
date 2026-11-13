// SPDX-License-Identifier: Apache-2.0
import { Tabs } from "@heroui/react";
import { CloudUpload, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { StatusDot } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { cn } from "@/lib/utils";

/** Single-select segmented control built on HeroUI Tabs (list only). */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { id: T; label: string }[];
  ariaLabel: string;
}) {
  return (
    <Tabs selectedKey={value} onSelectionChange={(k) => onChange(String(k) as T)}>
      <Tabs.ListContainer>
        <Tabs.List aria-label={ariaLabel} className="h-8">
          {options.map((o) => (
            <Tabs.Tab key={o.id} id={o.id} className="px-2.5 text-[12.5px]">
              {o.label}
              <Tabs.Indicator />
            </Tabs.Tab>
          ))}
        </Tabs.List>
      </Tabs.ListContainer>
    </Tabs>
  );
}

/** States where data goes. Local tools say so; network tools say exactly what is sent. */
export function PrivacyNote({ network, children }: { network?: boolean; children?: ReactNode }) {
  const Icon = network ? CloudUpload : ShieldCheck;
  return (
    <div className={cn("flex items-start gap-2 rounded-lg px-3 py-2 text-[12.5px]", network ? "bg-warning-soft text-warning-soft-foreground" : "bg-white/[0.025] text-muted")}>
      <Icon className="mt-px size-3.5 shrink-0" />
      <span>{children ?? "Runs entirely on this device. Nothing you enter is sent anywhere."}</span>
    </div>
  );
}

/** Read-only output area with copy. */
export function Output({ label, value, error, mono = true, minHeight = 96 }: { label: string; value: string; error?: string | null; mono?: boolean; minHeight?: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[12.5px] font-medium text-muted">{label}</span>
        {!error && value && <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} />}
      </div>
      {error ? (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2.5 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      ) : (
        <pre
          data-selectable
          className={cn("panel-inset scroll-area max-h-[420px] px-3.5 py-3 text-[12.5px] leading-relaxed break-all whitespace-pre-wrap text-foreground", mono ? "font-mono" : "font-sans text-[13.5px]")}
          style={{ minHeight }}
          aria-label={label}
        >
          {value || <span className="text-muted">Output appears here</span>}
        </pre>
      )}
    </div>
  );
}

/** Two-column key/value list. Values are selectable; optional copy per row. */
export function KeyValues({ rows, mono = true }: { rows: { k: string; v: ReactNode; copy?: string; tone?: "warning" | "danger" | "success" }[]; mono?: boolean }) {
  return (
    <dl className="flex flex-col gap-1">
      {rows.map((r) => (
        <div key={r.k} className="tile flex items-center gap-3 px-3 py-1.5">
          <dt className="w-40 shrink-0 text-[12.5px] text-muted">{r.k}</dt>
          <dd data-selectable className={cn("min-w-0 flex-1 text-[13px] break-all text-foreground", mono && "font-mono text-[12.5px]")}>
            <span className="inline-flex items-center gap-1.5">
              {r.tone && <StatusDot tone={r.tone} />}
              {r.v}
            </span>
          </dd>
          {r.copy ? <CopyButton text={r.copy} label={`Copy ${r.k.toLowerCase()}`} /> : <span className="w-8" />}
        </div>
      ))}
    </dl>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[12.5px] font-medium text-muted">{label}</span>
      {children}
    </div>
  );
}
