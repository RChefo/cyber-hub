import { Button, Checkbox } from "@heroui/react";
import { History, RotateCcw, Trash2 } from "lucide-react";
import { useMemo } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { CodeBlock } from "@/components/ui/Code";
import { EmptyBlock } from "@/components/ui/Feedback";
import type { HttpResponseOut } from "@/lib/types";
import { cn } from "@/lib/utils";
import { diffHeaders, diffLines, repeaterHistory, type HistoryEntry } from "./repeater";

export const statusTone = (s: number) => (s < 300 ? "success" : s < 400 ? "accent" : s < 500 ? "warning" : "danger");

export function ResponseView({ res }: { res: HttpResponseOut }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <ToneChip tone={statusTone(res.status)}>
          {res.status} {res.reason}
        </ToneChip>
        <span className="text-muted">
          {res.version} · {res.elapsedMs} ms · {res.bodyBytes.toLocaleString()} bytes{res.truncated ? " (cut)" : ""}
        </span>
      </div>
      {res.redirects.length > 0 && (
        <ol className="flex flex-col gap-0.5 text-[12.5px] text-muted">
          {res.redirects.map((h, i) => (
            <li key={i} className="font-mono break-all">
              {h.status} {h.from} → {h.to}
            </li>
          ))}
        </ol>
      )}
      {res.redirectStopped && <p className="rounded-[10px] bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">{res.redirectStopped}</p>}
      <CodeBlock code={res.headers.map(([k, v]) => `${k}: ${v}`).join("\n")} maxHeight={220} />
      {res.body && <CodeBlock code={res.body} maxHeight={420} />}
    </div>
  );
}

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

/** The session's requests: load one into the editor, or pick two to compare. */
export function HistoryPanel({ entries, selected, onToggle, onLoad }: { entries: HistoryEntry[]; selected: number[]; onToggle: (id: number) => void; onLoad: (e: HistoryEntry) => void }) {
  if (entries.length === 0) {
    return <EmptyBlock compact icon={History} title="No requests sent yet" description="Every request you send is listed here until Cyber Hub closes. It is not saved, because requests can carry credentials." />;
  }
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2 text-[12.5px] text-muted">
        <span className="flex-1">Kept in memory until Cyber Hub closes; never saved. Pick two to compare.</span>
        <Button size="sm" variant="ghost" onPress={() => repeaterHistory.clear()}>
          <Trash2 className="size-3.5" />
          Clear
        </Button>
      </div>
      <ul className="flex flex-col gap-1">
        {entries.map((e) => (
          <li key={e.id} className={cn("tile flex items-center gap-3 px-3 py-1.5", selected.includes(e.id) && "bg-accent-soft/40")}>
            <Checkbox aria-label={`Compare request ${e.id}`} isSelected={selected.includes(e.id)} onChange={() => onToggle(e.id)} isDisabled={!e.response || (!selected.includes(e.id) && selected.length >= 2)}>
              <Checkbox.Content>
                <Checkbox.Control>
                  <Checkbox.Indicator />
                </Checkbox.Control>
              </Checkbox.Content>
            </Checkbox>
            <span className="tabular w-[64px] shrink-0 text-[12px] text-muted">{time(e.at)}</span>
            <span className="w-[58px] shrink-0 font-mono text-[11.5px]">{e.request.method}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-[12px]" title={e.request.url}>
              {e.request.url}
            </span>
            {e.response ? (
              <ToneChip tone={statusTone(e.response.status)}>{e.response.status}</ToneChip>
            ) : (
              <ToneChip tone="danger">error</ToneChip>
            )}
            <span className="tabular w-[110px] shrink-0 text-right text-[12px] text-muted">{e.response ? `${e.response.bodyBytes.toLocaleString()} B · ${e.response.elapsedMs} ms` : ""}</span>
            <Button isIconOnly size="sm" variant="ghost" aria-label={`Load request ${e.id} into the editor`} onPress={() => onLoad(e)}>
              <RotateCcw className="size-3.5" />
            </Button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Two responses side by side: status, timing and size, changed headers, and a line diff of the bodies. */
export function ComparePanel({ a, b }: { a: HistoryEntry; b: HistoryEntry }) {
  const ra = a.response!;
  const rb = b.response!;
  const headers = useMemo(() => diffHeaders(ra.headers, rb.headers), [ra, rb]);
  const body = useMemo(() => diffLines(ra.body, rb.body), [ra, rb]);
  const changed = body.filter((o) => o.kind === "added" || o.kind === "removed").length;
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-1 gap-2 text-[12.5px] md:grid-cols-2">
        {[a, b].map((e, i) => (
          <div key={e.id} className="panel-inset flex flex-col gap-0.5 px-3 py-2">
            <span className="text-muted">{i === 0 ? "Before" : "After"} · {time(e.at)}</span>
            <span className="truncate font-mono" title={e.request.url}>
              {e.request.method} {e.request.url}
            </span>
            <span>
              <ToneChip tone={statusTone(e.response!.status)}>
                {e.response!.status} {e.response!.reason}
              </ToneChip>{" "}
              <span className="text-muted">
                {e.response!.bodyBytes.toLocaleString()} bytes · {e.response!.elapsedMs} ms
              </span>
            </span>
          </div>
        ))}
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[12.5px] font-medium text-muted">Headers {headers.length === 0 ? "(no difference)" : `(${headers.length} differ)`}</span>
        {headers.length > 0 && (
          <ul className="panel-inset flex flex-col gap-0.5 px-3 py-2 font-mono text-[11.5px]">
            {headers.map((h) => (
              <li key={h.name} className="break-all">
                <span className="text-muted">{h.name}: </span>
                {h.before !== null && <span className="bg-danger-soft px-1 text-danger-soft-foreground">{h.before}</span>}
                {h.before !== null && h.after !== null && " → "}
                {h.after !== null && <span className="bg-success-soft px-1 text-success-soft-foreground">{h.after}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[12.5px] font-medium text-muted">Body {changed === 0 ? "(no difference)" : `(${changed} lines differ)`}</span>
        {changed > 0 && (
          <pre className="panel-inset max-h-[420px] overflow-auto px-3 py-2 font-mono text-[11.5px] leading-[1.55]">
            {body.map((o, i) =>
              o.kind === "skip" ? (
                <div key={i} className="text-muted">
                  ⋯ {o.count} unchanged {o.count === 1 ? "line" : "lines"}
                </div>
              ) : (
                <div key={i} className={cn("whitespace-pre-wrap break-all", o.kind === "added" && "bg-success-soft text-success-soft-foreground", o.kind === "removed" && "bg-danger-soft text-danger-soft-foreground")}>
                  {o.kind === "added" ? "+ " : o.kind === "removed" ? "- " : "  "}
                  {o.text}
                </div>
              ),
            )}
          </pre>
        )}
      </div>
    </div>
  );
}

