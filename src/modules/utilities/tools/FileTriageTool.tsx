// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { FileScan, Radar, ScanSearch, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { api, errorMessage } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { BinaryScan, YaraTriageScan } from "@/lib/types";
import { cn, pluralize } from "@/lib/utils";
import { LEVEL_TONE, yaraString } from "@/modules/detections/detections";
import { capabilityFinding, hardeningSummary, stringIndicators, yaraFinding } from "../lib/binary";
import { formatBytes } from "../lib/triage";
import { PrivacyNote } from "./shared";
import { Pick, RecordBar, Table } from "./TriageTools";

/** The triaged file scanned with the detection library's enabled YARA rules (of a collection when
 * chosen). Matches are leads: the analyst records the ones that matter as findings under review,
 * with the file as evidence. */
function YaraSection({ scan }: { scan: BinaryScan }) {
  const { runtime, navigate } = useApp();
  const collections = useQuery(["detections"], () => api.detectionCollections(), [], runtime);
  const library = useQuery(["detections"], () => api.detectionRulesList({ kind: "yara", enabled: true, limit: 1 }), [], runtime);
  const [collection, setCollection] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<YaraTriageScan | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const key = (m: { ruleId: number; rule: string }) => `${m.ruleId}:${m.rule}`;
  const token = scan.token;
  const none = library.data?.total === 0;
  const run = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const s = await api.yaraScanFile(token, collection === "all" ? null : Number(collection));
      setResult(s);
      setPicked(new Set(s.matches.map(key)));
    } catch (e) {
      setResult(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  if (!token) return null;
  return (
    <section className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="flex-1 text-[13.5px] font-medium">YARA rules{result ? ` (${pluralize(result.matches.length, "match", "matches")})` : ""}</h3>
        {(collections.data?.length ?? 0) > 0 && (
          <SelectInput aria-label="YARA rules to run" value={collection} onChange={setCollection} options={[{ id: "all", label: "All enabled YARA rules" }, ...(collections.data ?? []).map((c) => ({ id: String(c.id), label: `Collection: ${c.name}` }))]} className="w-56" />
        )}
        <Button size="sm" variant="tertiary" onPress={() => void run()} isPending={busy} isDisabled={!runtime || none}>
          <ScanSearch className="size-3.5" />
          Scan with YARA rules
        </Button>
      </div>
      {none && (
        <p className="text-[12.5px] text-muted">
          The detection library has no enabled YARA rule.{" "}
          <button type="button" className="text-accent hover:underline" onClick={() => navigate("detections")}>
            Import YARA rules in Detections
          </button>
          .
        </p>
      )}
      {error && <ErrorBlock message={error} />}
      {result && (
        <div className="flex flex-col gap-2">
          {result.notes.map((n) => (
            <p key={n} className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-[12.5px] text-warning-soft-foreground">
              {n}
            </p>
          ))}
          {result.failed.length > 0 && <p className="text-[12.5px] text-warning">Not run: {result.failed.map(([t, why]) => `${t} (${why})`).join("; ")}</p>}
          {result.matches.length === 0 ? (
            <p className="text-[12.5px] text-muted">No rule matched ({pluralize(result.files, "rule file")} ran). A file no rule matches is not shown to be harmless.</p>
          ) : (
            <>
              <div className="flex justify-end">
                <RecordBar
                  picked={picked.size}
                  build={(pid) => result.matches.filter((m) => picked.has(key(m))).map((m) => yaraFinding(pid, scan.file, scan.report, m))}
                  onDone={() => setPicked(new Set())}
                  source={{ module: "file_triage", subject: scan.file, token, report: () => ({ ...scan.report, strings: scan.report.strings.slice(0, 2000), yara: result }) }}
                />
              </div>
              {result.matches.map((m) => (
                <div key={key(m)} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(key(m)) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                  <Pick label={`Select ${m.rule}`} selected={picked.has(key(m))} onToggle={() => setPicked((p) => (p.has(key(m)) ? new Set([...p].filter((x) => x !== key(m))) : new Set([...p, key(m)])))} />
                  <div className="flex min-w-0 flex-1 flex-col gap-1 text-[12.5px]">
                    <div className="flex flex-wrap items-center gap-2">
                      <ToneChip tone={LEVEL_TONE[m.level] ?? "default"} dot={false} className="text-[11px]">
                        {m.level || "no level"}
                      </ToneChip>
                      <span className="font-mono text-[13px] font-medium">{m.rule}</span>
                      <span className="text-muted">
                        {m.title} · v{m.version}
                      </span>
                      {m.techniques.map((t) => (
                        <ToneChip key={t} tone="accent" dot={false} className="text-[11px]">
                          ATT&CK {t}
                        </ToneChip>
                      ))}
                      {m.tags.map((t) => (
                        <ToneChip key={t} tone="default" dot={false} className="text-[10.5px]">
                          {t}
                        </ToneChip>
                      ))}
                    </div>
                    {m.metas.find(([k]) => k.toLowerCase() === "description") && <p className="text-muted">{m.metas.find(([k]) => k.toLowerCase() === "description")?.[1]}</p>}
                    <ul className="flex flex-col gap-0.5 font-mono text-[11.5px] break-all">
                      {m.strings.length === 0 ? <li className="font-sans text-muted">Its condition holds on the file's properties; no string was needed.</li> : m.strings.slice(0, 8).map((s) => <li key={s.id}>{yaraString(s)}</li>)}
                      {m.strings.length > 8 && <li className="font-sans text-muted">and {pluralize(m.strings.length - 8, "more string")}</li>}
                    </ul>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </section>
  );
}

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
                  <RecordBar
                    picked={picked.size}
                    build={(pid) => r.capabilities.filter((c) => picked.has(c.id)).map((c) => capabilityFinding(pid, scan.file, r, c))}
                    onDone={() => setPicked(new Set())}
                    source={{ module: "file_triage", subject: scan.file, token: scan.token, report: () => ({ ...r, strings: r.strings.slice(0, 2000) }) }}
                  />
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
          <YaraSection key={scan.token ?? scan.file} scan={scan} />
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
