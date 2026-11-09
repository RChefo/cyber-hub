import { Button, Checkbox } from "@heroui/react";
import type { LucideIcon } from "lucide-react";
import { FileSearch, FolderSearch, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ContainerFileReport, ContainerIssue, ContainerScan, FindingInput } from "@/lib/types";
import { cn } from "@/lib/utils";
import { countSummary, issueKey } from "../lib/containers";
import { PrivacyNote } from "./shared";

/** What differs between the configuration checkers (containers, cloud). */
export interface ConfigCheckConfig {
  privacy: string;
  /** types to choose for pasted text, "auto" first */
  kinds: { id: string; label: string }[];
  kindLabel: Record<string, string>;
  placeholder: string;
  folderHint: string;
  empty: { icon: LucideIcon; title: string; description: string };
  scanText: (text: string, kind: string) => Promise<ContainerFileReport>;
  scanPick: (folder: boolean) => Promise<ContainerScan | null>;
  finding: (projectId: number, report: ContainerFileReport, issue: ContainerIssue) => FindingInput;
}

interface Result {
  root: string;
  files: ContainerFileReport[];
  seen: number;
  truncated: boolean;
}

/** Pasted text, a file or a folder checked offline, with the issues recordable as findings. */
export function ConfigCheckTool({ config }: { config: ConfigCheckConfig }) {
  const { runtime } = useApp();
  const projects = useQuery(["projects"], () => api.projectsList(), [], runtime);
  const [mode, setMode] = useState<"paste" | "files">("paste");
  const [text, setText] = useState("");
  const [kind, setKind] = useState("auto");
  const [busy, setBusy] = useState<null | "text" | "file" | "folder">(null);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [projectId, setProjectId] = useState<string | null>(null);
  const [recording, setRecording] = useState(false);

  const run = async (what: "text" | "file" | "folder") => {
    setBusy(what);
    setError(null);
    try {
      if (what === "text") {
        const r = await config.scanText(text, kind);
        setResult({ root: "pasted text", files: [r], seen: 1, truncated: false });
      } else {
        const r = await config.scanPick(what === "folder");
        if (!r) return;
        setResult({ root: r.root, files: r.result.files, seen: r.result.filesSeen, truncated: r.result.truncated });
      }
      setPicked(new Set());
    } catch (e) {
      setResult(null);
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const record = async () => {
    if (!result || !projectId) return;
    setRecording(true);
    try {
      const pid = Number(projectId);
      const existing = new Set((await api.findingsList(pid)).map((f) => f.title));
      let created = 0;
      let skipped = 0;
      const failed: string[] = [];
      for (const report of result.files) {
        for (const i of report.issues) {
          if (!picked.has(issueKey(report.file, i))) continue;
          const f = config.finding(pid, report, i);
          if (existing.has(f.title)) {
            skipped++;
            continue;
          }
          try {
            await api.findingUpsert(f);
            existing.add(f.title);
            created++;
          } catch (e) {
            failed.push(`${i.title}: ${errorMessage(e)}`);
          }
        }
      }
      invalidate("findings", "projects", "activity");
      setPicked(new Set());
      if (failed.length) notify.error(`${failed.length} findings could not be recorded`, failed[0]);
      notify.success(`${created} findings recorded`, skipped ? `${skipped} were recorded before` : "In the project's Findings tab");
    } catch (e) {
      notify.error("Could not record the findings", e);
    } finally {
      setRecording(false);
    }
  };

  const toggle = (k: string) => setPicked((p) => (p.has(k) ? new Set([...p].filter((x) => x !== k)) : new Set([...p, k])));
  const all = result ? result.files.flatMap((f) => f.issues) : [];
  const EmptyIcon = config.empty.icon;

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>{config.privacy}</PrivacyNote>
      <div className="flex gap-1 self-start rounded-[10px] bg-white/[0.04] p-1" role="group" aria-label="Input">
        {(["paste", "files"] as const).map((m) => (
          <Button key={m} size="sm" variant={mode === m ? "secondary" : "ghost"} onPress={() => setMode(m)} aria-pressed={mode === m}>
            {m === "paste" ? "Paste" : "File or folder"}
          </Button>
        ))}
      </div>
      {mode === "paste" ? (
        <>
          <SelectInput label="Type" value={kind} onChange={setKind} options={config.kinds} className="w-56" />
          <TextAreaInput label="Configuration" value={text} onChange={setText} rows={12} mono placeholder={config.placeholder} />
          <Button variant="primary" className="self-start" onPress={() => void run("text")} isPending={busy === "text"} isDisabled={!text.trim()}>
            <ShieldCheck className="size-3.5" />
            Check
          </Button>
        </>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button variant="tertiary" onPress={() => void run("file")} isPending={busy === "file"} isDisabled={!runtime}>
            <FileSearch className="size-3.5" />
            Choose a file…
          </Button>
          <Button variant="tertiary" onPress={() => void run("folder")} isPending={busy === "folder"} isDisabled={!runtime}>
            <FolderSearch className="size-3.5" />
            Choose a folder…
          </Button>
          <span className="self-center text-[12.5px] text-muted">{config.folderHint}</span>
        </div>
      )}
      {error && <ErrorBlock message={error} />}
      {result && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <span className="font-medium">{result.root}</span>
            <span className="text-muted">
              {result.files.length} configuration {result.files.length === 1 ? "file" : "files"}
              {mode === "files" ? ` of ${result.seen} files` : ""} · {countSummary(all)}
              {result.truncated ? " · stopped at the limit" : ""}
            </span>
            <span className="flex-1" />
            {all.length > 0 && (
              <>
                <SelectInput aria-label="Project for findings" value={projectId} onChange={setProjectId} options={(projects.data ?? []).map((p) => ({ id: String(p.id), label: p.name }))} placeholder="Project for findings" className="w-56" />
                <Button size="sm" variant="ghost" onPress={() => setPicked(picked.size ? new Set() : new Set(result.files.flatMap((f) => f.issues.map((i) => issueKey(f.file, i)))))}>
                  {picked.size ? "Clear selection" : "Select all"}
                </Button>
                <Button size="sm" variant="primary" onPress={() => void record()} isPending={recording} isDisabled={!projectId || picked.size === 0}>
                  Record {picked.size || ""} as findings
                </Button>
              </>
            )}
          </div>
          {result.files.length === 0 && <EmptyBlock compact icon={EmptyIcon} title={config.empty.title} description={config.empty.description} />}
          {result.files.map((f) => (
            <section key={f.file} className="panel-inset flex flex-col gap-2 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[12.5px] break-all">{f.file}</span>
                <ToneChip tone="default" dot={false}>
                  {config.kindLabel[f.kind] ?? f.kind}
                </ToneChip>
                <span className="text-[12px] text-muted">{f.error ? "" : countSummary(f.issues)}</span>
              </div>
              {f.sha256 && <span className="font-mono text-[11.5px] break-all text-muted">SHA-256 {f.sha256}</span>}
              {f.error && <p className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-[12.5px] text-warning-soft-foreground">{f.error}</p>}
              {f.issues.length > 0 && (
                <ul className="flex flex-col gap-1.5">
                  {f.issues.map((i) => {
                    const k = issueKey(f.file, i);
                    return (
                      <li key={k} className={cn("flex items-start gap-2.5 rounded-[8px] px-2 py-1.5", picked.has(k) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                        <Checkbox aria-label={`Select ${i.title} at ${i.location}`} isSelected={picked.has(k)} onChange={() => toggle(k)} className="mt-0.5">
                          <Checkbox.Content>
                            <Checkbox.Control>
                              <Checkbox.Indicator />
                            </Checkbox.Control>
                          </Checkbox.Content>
                        </Checkbox>
                        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={i.severity} />
                            <span className="text-[13px] font-medium">{i.title}</span>
                            <span className="font-mono text-[11.5px] text-muted">{i.location}</span>
                          </div>
                          <p className="text-[12.5px] text-muted">{i.detail}</p>
                          <p className="text-[12.5px]">
                            <span className="text-muted">Fix: </span>
                            {i.remediation}
                          </p>
                          <p className="text-[11.5px] text-muted">
                            {i.rule} · {i.reference}
                          </p>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
