// SPDX-License-Identifier: Apache-2.0
import { Button, EmptyState, Skeleton, Spinner } from "@heroui/react";
import { AlertTriangle, MonitorX, RotateCw } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { DotPattern } from "@/components/vendor/lightswind/DotPattern";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { cn } from "@/lib/utils";

export function EmptyBlock({
  icon,
  title,
  description,
  action,
  className,
  compact,
}: {
  icon: LucideIcon;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  compact?: boolean;
}) {
  return (
    <EmptyState
      className={cn(
        "relative flex flex-col items-center justify-center overflow-hidden rounded-[10px] bg-white/[0.018] text-center",
        compact ? "gap-2 px-4 py-6" : "gap-3 px-6 py-10",
        className,
      )}
    >
      <DotPattern className="fill-white/[0.06] [mask-image:radial-gradient(260px_circle_at_center,white,transparent)]" />
      <FeaturedIcon icon={icon} size={compact ? "sm" : "md"} color="gray" />
      <div className="relative">
        <div className="text-[14px] font-medium text-foreground">{title}</div>
        {description && <div className="mx-auto mt-1 max-w-[46ch] text-[13px] text-muted">{description}</div>}
      </div>
      {action && <div className="relative mt-1">{action}</div>}
    </EmptyState>
  );
}

export function ErrorBlock({ message, onRetry, className }: { message: string; onRetry?: () => void; className?: string }) {
  const runtime = message.includes("desktop runtime");
  return (
    <div
      role="alert"
      className={cn("flex items-start gap-3 rounded-[10px] bg-danger-soft px-3.5 py-3 text-[13px]", className)}
    >
      {runtime ? (
        <MonitorX className="mt-0.5 size-4 shrink-0 text-danger-soft-foreground" />
      ) : (
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger-soft-foreground" />
      )}
      <div className="min-w-0 flex-1 text-danger-soft-foreground">{message}</div>
      {onRetry && !runtime && (
        <Button size="sm" variant="ghost" onPress={onRetry}>
          <RotateCw className="size-3.5" />
          Retry
        </Button>
      )}
    </div>
  );
}

export function LoadingRows({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-2", className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 rounded-lg" />
      ))}
    </div>
  );
}

export function InlineSpinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-[13px] text-muted">
      <Spinner size="sm" />
      {label}
    </span>
  );
}

/** Renders loading / error / empty / data states for a query consistently. */
export function QueryView<T>({
  query,
  empty,
  isEmpty,
  rows,
  children,
}: {
  query: { data: T | undefined; error: string | null; loading: boolean; reload: () => void };
  empty?: ReactNode;
  isEmpty?: (d: T) => boolean;
  rows?: number;
  children: (data: T) => ReactNode;
}) {
  if (query.error && query.data === undefined) return <ErrorBlock message={query.error} onRetry={query.reload} />;
  if (query.data === undefined) return <LoadingRows rows={rows} />;
  if (empty && isEmpty?.(query.data)) return <>{empty}</>;
  return <>{children(query.data)}</>;
}
