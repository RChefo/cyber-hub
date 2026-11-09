import { Button } from "@heroui/react";
import { FileScan, Radar, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SearchInput } from "@/components/ui/Fields";
import { api, errorMessage } from "@/lib/ipc";
import type { BinaryScan } from "@/lib/types";
import { cn } from "@/lib/utils";
import { capabilityFinding, hardeningSummary, stringIndicators } from "../lib/binary";
import { formatBytes } from "../lib/triage";
import { PrivacyNote } from "./shared";
import { Pick, RecordBar, Table } from "./TriageTools";

/** Security utility: static triage of a PE or ELF file (hashes, sections, imports, capabilities, strings). */
export function FileTriageTool() {
  const { runtime, navigate } = useApp();
  const [scan, setScan] = useState<BinaryScan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await api.binaryAnalyzePick();
      if (!s) return;
      setScan(s);
      setFilter("");
      setPicked(new Set(s.report.capabilities.filter((c) => c.severity === "high" || c.severity === "medium").map((c) => c.id)));
    } catch (e) {
      setScan(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const r = scan?.report;
  const indicators = useMemo(() => (r ? stringIndicators(r.strings) : []), [r]);
  const shown = useMemo(() => {
    if (!r) return [];
    const q = filter.trim().toLowerCase();
    return (q ? r.strings.filter((s) => s.toLowerCase().includes(q)) : r.strings).slice(0, 300);
  }, [r, filter]);

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Reads the file on this device and never runs it; nothing is uploaded. Capabilities come from the imported functions and the file's structure: legitimate programs import many of the same functions, so they are leads, not a verdict. Hash lookups open VirusTotal or Threat Intel only when you press them.</PrivacyNote>
      <Button variant="primary" className="self-start" onPress={() => void run()} isPending={busy} isDisabled={!runtime}>
        <FileScan className="size-3.5" />
        Choose a file…
      </Button>
      {error && <ErrorBlock message={error} />}
      {scan && r && (
        <div className="flex flex-col gap-4">
          <div className="text-[13px]">
            <span className="font-medium">{scan.file}</span>
            <span className="text-muted">
              {" "}
              · {r.format === "unknown" ? "not a PE or ELF file" : `${r.format} · ${r.machine} · ${r.kind}${r.dotnet ? " · .NET" : ""}`} · {formatBytes(r.size)} · entropy {r.entropy.toFixed(2)}
              {r.compiled ? ` · linked ${r.compiled}` : ""}
              {r.interpreter ? ` · ${r.interpreter}` : ""}
            </span>
          </div>
          {r.warnings.map((w) => (
            <p key={w} className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-[12.5px] text-warning-soft-foreground">
              {w}
            </p>
          ))}
          <section className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="flex-1 text-[13.5px] font-medium">Hashes</h3>
              <Button size="sm" variant="tertiary" onPress={() => navigate("virustotal", { q: r.sha256 })}>
                <ShieldCheck className="size-3.5" />
                Look up on VirusTotal
              </Button>
              <Button size="sm" variant="tertiary" onPress={() => navigate("threatintel", { q: r.sha256 })}>
                <Radar className="size-3.5" />
                Look up in Threat Intel
              </Button>
            </div>
            {(
              [
                ["SHA-256", r.sha256],
                ["SHA-1", r.sha1],
                ["MD5", r.md5],
                ["Import hash", r.imphash],
              ] as const
            )
              .filter(([, v]) => v)
              .map(([label, value]) => (
                <div key={label} className="flex items-center gap-2 text-[12.5px]">
                  <span className="w-24 text-muted">{label}</span>
                  <span className="min-w-0 flex-1 font-mono break-all">{value}</span>
                  <CopyButton text={value} label={`Copy ${label}`} />
                </div>
              ))}
          </section>
          {r.hardening.length > 0 && (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Hardening ({hardeningSummary(r)})</h3>
              <div className="flex flex-wrap gap-1.5">
                {r.hardening.map((h) => (
                  <span key={h.name} title={h.detail}>
                    <ToneChip tone={h.present ? "success" : "warning"}>
                      {h.name}: {h.present ? "yes" : "no"}
                    </ToneChip>
                  </span>
                ))}
              </div>
            </section>
          )}
          {r.format !== "unknown" &&
            (r.capabilities.length === 0 ? (
              <EmptyBlock compact icon={FileScan} title="No notable capability" description="None of the imported functions or structures matched a capability rule." />
            ) : (
              <section className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="flex-1 text-[13.5px] font-medium">Capabilities ({r.capabilities.length})</h3>
                  <RecordBar picked={picked.size} build={(pid) => r.capabilities.filter((c) => picked.has(c.id)).map((c) => capabilityFinding(pid, scan.file, r, c))} onDone={() => setPicked(new Set())} />
                </div>
                {r.capabilities.map((c) => (
                  <div key={c.id} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(c.id) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                    <Pick label={`Select ${c.title}`} selected={picked.has(c.id)} onToggle={() => setPicked((p) => (p.has(c.id) ? new Set([...p].filter((x) => x !== c.id)) : new Set([...p, c.id])))} />
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={c.severity} />
                        <span className="text-[13px] font-medium">{c.title}</span>
                        {c.technique && (
                          <ToneChip tone="accent" dot={false} className="text-[11px]">
                            ATT&CK {c.technique}
                          </ToneChip>
                        )}
                      </div>
                      <p className="text-[12.5px] text-muted">{c.detail}</p>
                      {c.evidence.length > 0 && <p className="font-mono text-[11.5px] break-all">{c.evidence.join(" · ")}</p>}
                    </div>
                  </div>
                ))}
              </section>
            ))}
          {r.sections.length > 0 && (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Sections</h3>
              <Table head={["Name", "Size", "Entropy", "Access", "Note"]} rows={r.sections.map((s) => [s.name || "(no name)", formatBytes(s.size), s.entropy.toFixed(2), s.flags, s.note || "—"])} />
            </section>
          )}
          {r.libraries.length > 0 && (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Imports ({r.libraries.length} libraries)</h3>
              <ul className="flex flex-col gap-1">
                {r.libraries.map((l) => (
                  <li key={l.name} className="text-[12.5px]">
                    <details>
                      <summary className="cursor-pointer">
                        <span className="font-mono">{l.name}</span>
                        <span className="text-muted"> · {l.functions.length} functions</span>
                      </summary>
                      <p className="mt-1 font-mono text-[11.5px] break-all text-muted">{l.functions.join(" · ") || "—"}</p>
                    </details>
                  </li>
                ))}
              </ul>
              {r.exports.length > 0 && <p className="text-[12.5px] text-muted">{r.exports.length === 200 ? "200 or more" : r.exports.length} exported functions, among them {r.exports.slice(0, 8).join(", ")}</p>}
            </section>
          )}
          {indicators.length > 0 && (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Indicators in the strings</h3>
              <p className="text-[12px] text-muted">Found in the file's text; references to vendors and standards appear here too.</p>
              {indicators.map((k) => (
                <div key={k.kind} className="flex items-start gap-2 text-[12.5px]">
                  <span className="w-32 shrink-0 text-muted">{k.label}</span>
                  <span className="min-w-0 flex-1 font-mono break-all">{k.values.slice(0, 40).join(" · ")}</span>
                  <CopyButton text={k.values.join("\n")} label={`Copy ${k.label}`} />
                </div>
              ))}
            </section>
          )}
          <section className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="flex-1 text-[13.5px] font-medium">
                Strings ({r.stringsTotal.toLocaleString()}
                {r.stringsTotal > r.strings.length ? `, first ${r.strings.length.toLocaleString()} searched` : ""})
              </h3>
              <SearchInput value={filter} onChange={setFilter} placeholder="Search strings" className="w-60" />
            </div>
            <pre className="panel-inset max-h-80 overflow-auto px-3 py-2 font-mono text-[11.5px] whitespace-pre-wrap break-all">{shown.join("\n") || "No string matches."}</pre>
          </section>
        </div>
      )}
    </div>
  );
}
