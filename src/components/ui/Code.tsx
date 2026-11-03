import { Button, Tooltip } from "@heroui/react";
import { Check, Copy } from "lucide-react";
import { useState, type ReactNode } from "react";
import { copyText } from "@/lib/actions";
import { cn } from "@/lib/utils";

export function CopyButton({
  text,
  label = "Copy",
  onCopy,
  size = "sm",
  showLabel,
}: {
  text: string;
  label?: string;
  onCopy?: (text: string) => void | Promise<void>;
  size?: "sm" | "md";
  showLabel?: boolean;
}) {
  const [done, setDone] = useState(false);
  const handle = async () => {
    if (onCopy) await onCopy(text);
    else await copyText(text);
    setDone(true);
    setTimeout(() => setDone(false), 1400);
  };
  const icon = done ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />;
  if (showLabel) {
    return (
      <Button size={size} variant="tertiary" onPress={handle} isDisabled={!text}>
        {icon}
        {done ? "Copied" : label}
      </Button>
    );
  }
  return (
    <Tooltip delay={400}>
      <Button size={size} variant="ghost" isIconOnly aria-label={label} onPress={handle} isDisabled={!text}>
        {icon}
      </Button>
      <Tooltip.Content>{label}</Tooltip.Content>
    </Tooltip>
  );
}

export function CodeBlock({ code, className, actions, wrap = true, maxHeight }: { code: string; className?: string; actions?: ReactNode; wrap?: boolean; maxHeight?: number }) {
  return (
    <div className={cn("group panel-inset relative", className)}>
      <pre
        data-selectable
        className={cn(
          "scroll-area px-3.5 py-3 pr-12 font-mono text-[12.5px] leading-relaxed text-foreground",
          wrap ? "break-all whitespace-pre-wrap" : "whitespace-pre",
        )}
        style={maxHeight ? { maxHeight } : undefined}
      >
        {code || <span className="text-muted">—</span>}
      </pre>
      <div className="absolute top-1.5 right-1.5 flex items-center gap-1">{actions ?? <CopyButton text={code} />}</div>
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded bg-default px-1 font-sans text-[11px] text-muted">
      {children}
    </kbd>
  );
}
