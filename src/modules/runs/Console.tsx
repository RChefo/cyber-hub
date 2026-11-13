// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { Button } from "@heroui/react";
import { ArrowDownToLine } from "lucide-react";
import { cn } from "@/lib/utils";
import type { LiveLine } from "./liveStore";

/** Monospace process output with stderr tinting and stick-to-bottom scrolling. */
export function Console({ lines, height = 340, className }: { lines: LiveLine[]; height?: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [stick, setStick] = useState(true);

  useEffect(() => {
    if (stick && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines, stick]);

  return (
    <div className={cn("panel-inset relative", className)}>
      <div
        ref={ref}
        data-selectable
        role="log"
        aria-live="polite"
        aria-label="Process output"
        onScroll={(e) => {
          const el = e.currentTarget;
          setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
        className="scroll-area px-3.5 py-3 font-mono text-[12px] leading-[1.55]"
        style={{ height }}
      >
        {lines.length === 0 && <div className="text-muted">Waiting for output…</div>}
        {lines.map((l, i) => (
          <div
            key={i}
            className={cn(
              "break-all whitespace-pre-wrap",
              l.stream === "stderr" && "text-warning-soft-foreground",
              l.stream === "system" && "text-muted",
            )}
          >
            {l.text || " "}
          </div>
        ))}
      </div>
      {!stick && (
        <Button
          size="sm"
          variant="tertiary"
          className="absolute right-3 bottom-3"
          onPress={() => {
            setStick(true);
            if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
          }}
        >
          <ArrowDownToLine className="size-3.5" />
          Follow output
        </Button>
      )}
    </div>
  );
}

export function textToLines(text: string): LiveLine[] {
  return text
    .split("\n")
    .filter((l, i, arr) => !(i === arr.length - 1 && l === ""))
    .map((l) => (l.startsWith("[stderr] ") ? { stream: "stderr" as const, text: l.slice(9) } : { stream: "stdout" as const, text: l }));
}
