import { Card } from "@heroui/react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PanelProps {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  contentClassName?: string;
  /** Rendered between the header and the content, full-bleed (e.g. tabs). */
  toolbar?: ReactNode;
}

/** The layered surface every widget sits on. Built on HeroUI Card. */
export function Panel({ title, description, actions, children, className, contentClassName, toolbar }: PanelProps) {
  return (
    <Card className={cn("panel gap-0 overflow-hidden p-0", className)}>
      {(title || actions) && (
        <Card.Header className="flex flex-row items-start justify-between gap-3 px-4 pt-3.5 pb-3">
          <div className="min-w-0">
            {title && <Card.Title className="text-[15px] font-medium tracking-tight text-foreground">{title}</Card.Title>}
            {description && <Card.Description className="mt-0.5 text-[13px] text-muted">{description}</Card.Description>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
        </Card.Header>
      )}
      {toolbar}
      <Card.Content className={cn("px-4 pb-4", !title && !actions && "pt-4", contentClassName)}>{children}</Card.Content>
    </Card>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold tracking-tight text-foreground">{title}</h1>
        {description && <p className="mt-1 max-w-[72ch] text-[13.5px] text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, tone = "default" }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "default" | "success" | "warning" | "danger" | "accent" }) {
  const toneClass = {
    default: "text-muted",
    success: "text-success-soft-foreground",
    warning: "text-warning-soft-foreground",
    danger: "text-danger-soft-foreground",
    accent: "text-accent-soft-foreground",
  }[tone];
  return (
    <div className="min-w-0">
      <div className="text-[12.5px] text-muted">{label}</div>
      <div className="tabular mt-1 text-[22px] font-semibold tracking-tight text-foreground">{value}</div>
      {hint && <div className={cn("mt-0.5 text-[12px]", toneClass)}>{hint}</div>}
    </div>
  );
}
