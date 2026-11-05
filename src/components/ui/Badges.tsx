import { Chip, Tooltip } from "@heroui/react";
import type { OsId } from "@/types/catalog";
import type { DetectionStatus, ExecutionStatus, FindingStatus, ProjectStatus, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

export type Tone = "default" | "accent" | "success" | "warning" | "danger";

const DOT: Record<Tone, string> = {
  default: "bg-muted",
  accent: "bg-accent",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
};

export function StatusDot({ tone, className, pulse }: { tone: Tone; className?: string; pulse?: boolean }) {
  return (
    <span className={cn("relative inline-flex size-1.5 shrink-0 rounded-full", DOT[tone], className)}>
      {pulse && <span className={cn("absolute inset-0 animate-ping rounded-full opacity-60", DOT[tone])} />}
    </span>
  );
}

export function ToneChip({ tone, children, dot = true, className }: { tone: Tone; children: React.ReactNode; dot?: boolean; className?: string }) {
  const color = tone === "default" ? "default" : tone;
  return (
    <Chip size="sm" variant="soft" color={color as "default" | "accent" | "success" | "warning" | "danger"} className={cn("gap-1.5", className)}>
      {dot && <StatusDot tone={tone} />}
      <Chip.Label>{children}</Chip.Label>
    </Chip>
  );
}

export const DETECTION_META: Record<DetectionStatus | "unknown" | "catalog", { label: string; tone: Tone; hint: string }> = {
  installed: { label: "Installed", tone: "success", hint: "Executable found on this system" },
  not_installed: { label: "Not installed", tone: "default", hint: "Executable not found on PATH or known locations" },
  dependency_missing: { label: "Dependency missing", tone: "warning", hint: "Found, but a required runtime is missing" },
  installation_failed: { label: "Installation failed", tone: "danger", hint: "The last managed installation did not succeed" },
  unsupported_os: { label: "Unsupported OS", tone: "default", hint: "Not officially available for this operating system" },
  unknown: { label: "Not scanned", tone: "default", hint: "Run a tool scan to detect installation status" },
  catalog: { label: "Web service", tone: "accent", hint: "Online service — nothing to install" },
};

export function DetectionChip({ status }: { status: keyof typeof DETECTION_META }) {
  const m = DETECTION_META[status];
  return (
    <Tooltip delay={500}>
      <Tooltip.Trigger className="inline-flex rounded-full outline-none focus-visible:ring-2 focus-visible:ring-focus">
        <ToneChip tone={m.tone}>{m.label}</ToneChip>
      </Tooltip.Trigger>
      <Tooltip.Content>{m.hint}</Tooltip.Content>
    </Tooltip>
  );
}

export const SEVERITY_META: Record<Severity, { label: string; className: string }> = {
  critical: { label: "Critical", className: "bg-sev-critical/15 text-[#f2878a]" },
  high: { label: "High", className: "bg-sev-high/15 text-[#f6a473]" },
  medium: { label: "Medium", className: "bg-sev-medium/15 text-[#f5d987]" },
  low: { label: "Low", className: "bg-sev-low/15 text-[#8fb6ff]" },
  info: { label: "Info", className: "bg-white/5 text-muted" },
};

export function SeverityBadge({ severity, score, className }: { severity: Severity; score?: number; className?: string }) {
  const m = SEVERITY_META[severity];
  return (
    <span className={cn("tabular inline-flex h-5 items-center gap-1 rounded-md px-1.5 text-[11.5px] font-medium", m.className, className)}>
      {score !== undefined && <span>{score.toFixed(1)}</span>}
      {m.label}
    </span>
  );
}

export function severityFromCvss(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export const PROJECT_STATUS_META: Record<ProjectStatus, { label: string; tone: Tone }> = {
  planning: { label: "Planning", tone: "default" },
  active: { label: "Active", tone: "success" },
  paused: { label: "Paused", tone: "warning" },
  completed: { label: "Completed", tone: "accent" },
  archived: { label: "Archived", tone: "default" },
};

export const FINDING_STATUS_META: Record<FindingStatus, { label: string; tone: Tone }> = {
  new: { label: "New", tone: "danger" },
  under_review: { label: "Under review", tone: "warning" },
  confirmed: { label: "Confirmed", tone: "warning" },
  in_remediation: { label: "In remediation", tone: "accent" },
  reopened: { label: "Reopened", tone: "danger" },
  resolved: { label: "Resolved", tone: "success" },
  accepted_risk: { label: "Accepted risk", tone: "default" },
  false_positive: { label: "False positive", tone: "default" },
};

export const EXEC_STATUS_META: Record<ExecutionStatus, { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "accent" },
  succeeded: { label: "Succeeded", tone: "success" },
  failed: { label: "Failed", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "warning" },
  error: { label: "Error", tone: "danger" },
};

const OS_LABEL: Record<OsId, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

export function OsBadges({ os, current }: { os: OsId[]; current?: OsId }) {
  return (
    <div className="flex flex-wrap gap-1">
      {(["windows", "macos", "linux"] as OsId[]).map((o) => {
        const supported = os.includes(o);
        return (
          <span
            key={o}
            className={cn(
              "inline-flex h-5 items-center rounded-md px-1.5 text-[11.5px]",
              supported ? "bg-white/[0.05] text-foreground" : "text-muted/50 line-through",
              supported && o === current && "bg-accent-soft text-accent-soft-foreground",
            )}
            title={supported ? `Supported on ${OS_LABEL[o]}` : `Not available for ${OS_LABEL[o]}`}
          >
            {OS_LABEL[o]}
          </span>
        );
      })}
    </div>
  );
}

export function osLabel(o: OsId | "any"): string {
  return o === "any" ? "Any OS" : OS_LABEL[o];
}
