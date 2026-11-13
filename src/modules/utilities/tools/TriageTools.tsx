// SPDX-License-Identifier: Apache-2.0
import { Button, Checkbox, Label } from "@heroui/react";
import { FileSearch, Network, ScrollText, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CaptureReport, CaptureScan, FindingInput, LogScan, UtilityModule } from "@/lib/types";
import { cn, pluralize } from "@/lib/utils";
import { beaconFinding, beaconLine, captureFinding, captureSpan, chainFinding, chainLine, dnsLeadFinding, formatBytes, logFinding } from "../lib/triage";
import { PrivacyNote } from "./shared";

/** Where recorded findings come from: the utility, what it analysed, the file's token from the
 * analysis (the file goes into the evidence vault) and the analysis itself (kept as text evidence). */
export interface RecordSource {
  module: UtilityModule;
  subject: string;
  token?: string | null;
  report?: () => unknown;
}

/** Windows logon types (4624/4625 LogonType) by name; unknown codes stay as written. */
const LOGON_TYPES: Record<string, string> = {
  "2": "interactive",
  "3": "network",
  "4": "batch",
  "5": "service",
  "7": "unlock",
  "8": "network cleartext",
  "9": "new credentials",
  "10": "remote interactive",
  "11": "cached interactive",
  "12": "cached remote interactive",
  "13": "cached unlock",
};
const logonType = (t: string) => (LOGON_TYPES[t] ? `${LOGON_TYPES[t]} (${t})` : t);

/** Project choice and "Record as findings" for the selected entries (each title once). `project`
 * preselects a project, such as the one a request was sent for. With a `source`, the backend
 * records the findings together with their evidence and a timeline event, in one step. */
export function RecordBar({ build, picked, onDone, project, source }: { build: (projectId: number) => FindingInput[]; picked: number; onDone: () => void; project?: number | null; source?: RecordSource }) {
  const { runtime } = useApp();
  const projects = useQuery(["projects"], () => api.projectsList(), [], runtime);
  const [projectId, setProjectId] = useState<string | null>(project != null ? String(project) : null);
  const [busy, setBusy] = useState(false);
  const [keep, setKeep] = useState(true);
  const record = async () => {
    if (!projectId) return;
    setBusy(true);
    try {
      const pid = Number(projectId);
      if (source) {
        const r = await api.utilityRecord({
          projectId: pid,
          module: source.module,
          token: keep ? (source.token ?? null) : null,
          subject: source.subject,
          report: keep && source.report ? JSON.stringify(source.report(), null, 2) : null,
          findings: build(pid),
        });
        invalidate("findings", "projects", "activity", "relations");
        onDone();
        const kept = r.evidenceId != null ? "The file and the analysis are in the evidence vault" : r.reportId != null ? "The analysis is in the evidence vault" : null;
        notify.success(`${pluralize(r.created, "finding")} recorded`, [r.existing ? `${r.existing} recorded before` : null, kept, r.reportTooLarge ? "the analysis was too large to keep" : null].filter(Boolean).join("; ") || "In the project's Findings tab");
        return;
      }
      const existing = new Set((await api.findingsList(pid)).map((f) => f.title));
      let created = 0;
      let skipped = 0;
      const failed: string[] = [];
      for (const f of build(pid)) {
        if (existing.has(f.title)) {
          skipped++;
          continue;
        }
        try {
          await api.findingUpsert(f);
          existing.add(f.title);
          created++;
        } catch (e) {
          failed.push(`${f.title}: ${errorMessage(e)}`);
        }
      }
      invalidate("findings", "projects", "activity");
      onDone();
      if (failed.length) notify.error(`${failed.length} findings could not be recorded`, failed[0]);
      notify.success(`${created} findings recorded`, skipped ? `${skipped} were recorded before` : "In the project's Findings tab");
    } catch (e) {
      notify.error("Could not record the findings", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SelectInput aria-label="Project for findings" value={projectId} onChange={setProjectId} options={(projects.data ?? []).filter((p) => p.status !== "archived").map((p) => ({ id: String(p.id), label: p.name }))} placeholder="Project for findings" className="w-56" />
      {source && (source.token || source.report) && (
        <Checkbox isSelected={keep} onChange={setKeep}>
          <Checkbox.Content className="flex items-center gap-1.5">
            <Checkbox.Control>
              <Checkbox.Indicator />
            </Checkbox.Control>
            <Label className="text-[12.5px] font-normal text-muted">{source.token ? "Keep the file as evidence" : "Keep the analysis as evidence"}</Label>
          </Checkbox.Content>
        </Checkbox>
      )}
      <Button size="sm" variant="primary" onPress={() => void record()} isPending={busy} isDisabled={!projectId || picked === 0}>
        Record {picked || ""} as findings
      </Button>
    </div>
  );
}

export function Pick({ label, selected, onToggle }: { label: string; selected: boolean; onToggle: () => void }) {
  return (
    <Checkbox aria-label={label} isSelected={selected} onChange={onToggle} className="mt-0.5">
      <Checkbox.Content>
        <Checkbox.Control>
          <Checkbox.Indicator />
        </Checkbox.Control>
      </Checkbox.Content>
    </Checkbox>
  );
}

export function Table({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  if (rows.length === 0) return <p className="text-[12.5px] text-muted">None.</p>;
  return (
    <div className="max-h-[320px] overflow-auto rounded-[8px] bg-white/[0.02]">
      <table className="w-full text-left text-[12px]">
        <thead className="sticky top-0 bg-surface text-muted">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-2.5 py-1.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="align-top">
              {r.map((c, j) => (
                <td key={j} className={cn("px-2.5 py-1 break-all", typeof c === "string" && j === 0 && "font-mono")}>
                  {typeof c === "number" ? c.toLocaleString() : c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ───────────────────────── packet captures ───────────────────────── */

export function CaptureTool() {
  const { runtime } = useApp();
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState<CaptureScan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const open = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.pcapAnalyzePick();
      if (r) {
        setScan(r);
        setPicked(new Set(r.report.issues.map((_, i) => i)));
      }
    } catch (e) {
      setScan(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const r = scan?.report;
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Reads a pcap or pcapng file on this device; nothing is contacted or replayed. Passwords seen in cleartext are never shown, only their length.</PrivacyNote>
      <Button variant="primary" className="self-start" onPress={() => void open()} isPending={busy} isDisabled={!runtime}>
        <FileSearch className="size-3.5" />
        Choose a capture…
      </Button>
      {error && <ErrorBlock message={error} />}
      {scan && r && (
        <div className="flex flex-col gap-4">
          <div className="text-[13px]">
            <span className="font-medium">{scan.file}</span>
            <span className="text-muted">
              {" "}
              · {r.format} ({r.links.join(", ")}) · {r.packets.toLocaleString()} packets · {formatBytes(r.bytes)} · {captureSpan(r.first, r.last)}
              {r.undecoded ? ` · ${r.undecoded.toLocaleString()} not decoded (other protocols)` : ""}
            </span>
          </div>
          {r.warnings.map((w) => (
            <p key={w} className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-[12.5px] text-warning-soft-foreground">
              {w}
            </p>
          ))}
          {r.issues.length === 0 ? (
            <EmptyBlock compact icon={ShieldCheck} title="No cleartext credentials or protocols found" />
          ) : (
            <section className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="flex-1 text-[13.5px] font-medium">Issues</h3>
                <RecordBar
                  picked={picked.size}
                  build={(pid) => r.issues.filter((_, i) => picked.has(i)).map((i) => captureFinding(pid, scan.file, i))}
                  onDone={() => setPicked(new Set())}
                  source={{ module: "pcap_triage", subject: scan.file, token: scan.token, report: () => r }}
                />
              </div>
              {r.issues.map((i, idx) => (
                <div key={i.rule} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(idx) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                  <Pick label={`Select ${i.title}`} selected={picked.has(idx)} onToggle={() => setPicked((p) => (p.has(idx) ? new Set([...p].filter((x) => x !== idx)) : new Set([...p, idx])))} />
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={i.severity} />
                      <span className="text-[13px] font-medium">{i.title}</span>
                    </div>
                    <p className="text-[12.5px] text-muted">{i.detail}</p>
                    <p className="font-mono text-[11.5px] break-all text-muted">{i.evidence.slice(0, 8).join(" · ")}{i.evidence.length > 8 ? ` … +${i.evidence.length - 8}` : ""}</p>
                    <p className="text-[12.5px]">
                      <span className="text-muted">Fix: </span>
                      {i.remediation}
                    </p>
                  </div>
                </div>
              ))}
            </section>
          )}
          <HuntingLeads key={scan.token ?? scan.file} scan={scan} r={r} />
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13.5px] font-medium">Cleartext credentials ({r.credentials.length})</h3>
            <Table head={["Protocol", "Client", "Server", "User", "Secret"]} rows={r.credentials.map((c) => [c.protocol, c.client, c.server, c.user || "(unknown)", `${c.secretLength} characters, not shown`])} />
          </section>
          <section className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <h3 className="flex-1 text-[13.5px] font-medium">Hosts ({r.hosts.length})</h3>
              {r.hosts.length > 0 && <CopyButton text={r.hosts.map((h) => h.ip).join("\n")} label="Copy addresses" />}
            </div>
            <Table head={["Address", "Packets", "Bytes", "Peers"]} rows={r.hosts.slice(0, 200).map((h) => [h.ip, h.packets, formatBytes(h.bytes), h.peers])} />
          </section>
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13.5px] font-medium">Conversations ({r.conversations.length})</h3>
            <Table head={["Server", "Client", "Protocol", "Packets", "Bytes"]} rows={r.conversations.slice(0, 200).map((c) => [c.server, c.client, c.protocol, c.packets, formatBytes(c.bytes)])} />
          </section>
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13.5px] font-medium">DNS names ({r.dns.length})</h3>
            <Table head={["Name", "Type", "Answers", "Seen"]} rows={r.dns.map((d) => [d.name, d.kind, d.answers.join(", "), d.queries])} />
          </section>
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13.5px] font-medium">TLS server names ({r.tls.length})</h3>
            <Table head={["Server name", "Server", "Handshakes"]} rows={r.tls.map((t) => [t.name, t.server, t.count])} />
          </section>
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13.5px] font-medium">HTTP requests ({r.http.length})</h3>
            <Table head={["Host and path", "Method", "User-Agent", "Server", "Seen"]} rows={r.http.map((h) => [`${h.host}${h.path}`, h.method, h.userAgent, h.server, h.count])} />
          </section>
        </div>
      )}
      {!scan && !error && <EmptyBlock compact icon={Network} title="No capture open" description="Captures from Wireshark, tcpdump or a network tap: pcap and pcapng, up to 2 GB." />}
    </div>
  );
}

/** Beacon-like schedules and DNS patterns of a capture: leads, each with what else it can be. The
 * analyst records the ones to investigate as findings under review. */
function HuntingLeads({ scan, r }: { scan: CaptureScan; r: CaptureReport }) {
  const h = r.hunting;
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const toggle = (k: string) => setPicked((p) => (p.has(k) ? new Set([...p].filter((x) => x !== k)) : new Set([...p, k])));
  const total = h.beacons.length + h.dns.length;
  return (
    <section className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="flex-1 text-[13.5px] font-medium">Hunting leads ({total})</h3>
        {total > 0 && (
          <RecordBar
            picked={picked.size}
            build={(pid) => [...h.beacons.flatMap((b, i) => (picked.has(`b${i}`) ? [beaconFinding(pid, scan.file, b)] : [])), ...h.dns.flatMap((d, i) => (picked.has(`d${i}`) ? [dnsLeadFinding(pid, scan.file, d)] : []))]}
            onDone={() => setPicked(new Set())}
            source={{ module: "pcap_triage", subject: scan.file, token: scan.token, report: () => r }}
          />
        )}
      </div>
      <p className="text-[12.5px] text-muted">Patterns worth a look, not findings: connections on a regular schedule (beacon-like timing) and DNS names that look like tunnels or generated domains. Each says what else it can be. Record the ones you will investigate; they become findings under review.</p>
      {h.notes.map((n) => (
        <p key={n} className="text-[12.5px] text-warning">
          {n}
        </p>
      ))}
      {total === 0 && <span className="text-[12.5px] text-muted">No regular schedule over two minutes or more, and no DNS pattern, in this capture.</span>}
      {h.beacons.map((b, i) => (
        <div key={`b${i}`} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(`b${i}`) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
          <Pick label={`Select ${b.client} to ${b.server}`} selected={picked.has(`b${i}`)} onToggle={() => toggle(`b${i}`)} />
          <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-[12.5px]">
            <div className="flex flex-wrap items-center gap-2">
              <ToneChip tone={b.note ? "default" : "warning"} dot={false} className="text-[11px]">
                {b.regularity === "regular" ? "regular schedule" : "schedule with jitter"}
              </ToneChip>
              <span className="font-mono">{beaconLine(b)}</span>
            </div>
            <p className="text-muted">{b.note ? `${b.note}.` : "Beacons call home on a schedule; so do updaters, time sync and health checks. Check the process on the client and the destination."}</p>
          </div>
        </div>
      ))}
      {h.dns.map((d, i) => (
        <div key={`d${i}`} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(`d${i}`) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
          <Pick label={`Select ${d.title}`} selected={picked.has(`d${i}`)} onToggle={() => toggle(`d${i}`)} />
          <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-[12.5px]">
            <div className="flex flex-wrap items-center gap-2">
              <ToneChip tone="warning" dot={false} className="text-[11px]">
                {d.rule}
              </ToneChip>
              <span className="text-[13px] font-medium">{d.title}</span>
              {d.techniques.map((t) => (
                <span key={t} className="font-mono text-[11px] text-muted">
                  if confirmed: {t}
                </span>
              ))}
            </div>
            <p className="text-muted">{d.detail}</p>
            <p className="text-muted">Also possible: {d.benign}</p>
            <p className="font-mono text-[11.5px] break-all text-muted">{d.examples.slice(0, 5).join(" · ")}</p>
          </div>
        </div>
      ))}
    </section>
  );
}

/* ───────────────────────── logs ───────────────────────── */

export function LogTool() {
  const { runtime } = useApp();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState<null | "text" | "file">(null);
  const [scan, setScan] = useState<LogScan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [pickedChains, setPickedChains] = useState<Set<number>>(new Set());
  const run = async (what: "text" | "file") => {
    setBusy(what);
    setError(null);
    try {
      const r = what === "text" ? { file: "pasted log", report: await api.logAnalyzeText(text), token: null } : await api.logAnalyzePick();
      if (r) {
        setScan(r);
        setPicked(new Set(r.report.detections.filter((d) => d.severity === "high" || d.severity === "medium").map((d) => d.rule)));
        setPickedChains(new Set());
      }
    } catch (e) {
      setScan(null);
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };
  const r = scan?.report;
  const sources = r ? [...new Set(r.detections.flatMap((d) => d.sources.map((s) => s.ip)))] : [];
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Reads web server access logs (Apache, Nginx), OpenSSH authentication logs and Windows event log files (EVTX) on this device; nothing is contacted. Matches are attempts or leads, not proof of a compromise; examples are shown with credentials redacted.</PrivacyNote>
      <TextAreaInput label="Log lines" value={text} onChange={setText} rows={8} mono placeholder={'203.0.113.7 - - [09/Nov/2026:10:00:01 +0000] "GET /item?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 512 "-" "sqlmap/1.7"'} />
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onPress={() => void run("text")} isPending={busy === "text"} isDisabled={!text.trim()}>
          <ShieldCheck className="size-3.5" />
          Analyze
        </Button>
        <Button variant="tertiary" onPress={() => void run("file")} isPending={busy === "file"} isDisabled={!runtime}>
          <FileSearch className="size-3.5" />
          Open a log file…
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {scan && r && (
        <div className="flex flex-col gap-4">
          <div className="text-[13px]">
            <span className="font-medium">{scan.file}</span>
            <span className="text-muted">
              {" "}
              · {r.kind === "web" ? "web access log" : r.kind === "ssh" ? "SSH authentication log" : r.kind === "mixed" ? "web and SSH lines" : r.kind === "windows" ? "Windows event log" : "format not recognised"} · {r.recognised.toLocaleString()} of {r.lines.toLocaleString()} {r.kind === "windows" ? "events" : "lines"} read
              {r.computers?.length ? ` · ${r.computers.slice(0, 3).join(", ")}${r.computers.length > 3 ? ` and ${r.computers.length - 3} more` : ""}` : ""}
              {r.first ? ` · ${r.first} to ${r.last}` : ""}
            </span>
          </div>
          {r.warnings.map((w) => (
            <p key={w} className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-[12.5px] text-warning-soft-foreground">
              {w}
            </p>
          ))}
          {(r.detections.length > 0 || (r.kind === "windows" && (r.chains?.length ?? 0) > 0)) && (
            // one bar records the selected detections and process chains together (Mission 7)
            <div className="flex flex-wrap items-center gap-2 rounded-[8px] bg-white/[0.03] px-2.5 py-2">
              <span className="flex-1 text-[12.5px] text-muted">
                {picked.size + pickedChains.size > 0
                  ? `${pluralize(picked.size, "detection")} and ${pluralize(pickedChains.size, "process chain")} selected`
                  : "Select detections or process chains below to record them as findings"}
              </span>
              <RecordBar
                picked={picked.size + pickedChains.size}
                build={(pid) => [
                  ...r.detections.filter((d) => picked.has(d.rule)).map((d) => logFinding(pid, scan.file, d)),
                  ...(r.chains ?? []).filter((_, i) => pickedChains.has(i)).map((c) => chainFinding(pid, scan.file, c)),
                ]}
                onDone={() => {
                  setPicked(new Set());
                  setPickedChains(new Set());
                }}
                source={{ module: r.kind === "windows" ? "evtx_triage" : "log_triage", subject: scan.file, token: scan.token, report: () => r }}
              />
            </div>
          )}
          {r.detections.length === 0 ? (
            (r.chains?.length ?? 0) > 0 ? (
              <p className="text-[12.5px] text-muted">None of the Windows event detections matched; the process chains below were flagged.</p>
            ) : (
              <EmptyBlock compact icon={ScrollText} title="Nothing suspicious found" description={r.kind === "windows" ? "None of the Windows event detections matched." : "No attack pattern, scan or password guessing was matched."} />
            )
          ) : (
            <section className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="flex-1 text-[13.5px] font-medium">Detections ({r.detections.length})</h3>
                {sources.length > 0 && <CopyButton text={sources.join("\n")} label={r.kind === "windows" ? "Copy sources" : "Copy source addresses"} />}
              </div>
              {r.detections.map((d) => (
                <div key={d.rule} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", picked.has(d.rule) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                  <Pick label={`Select ${d.title}`} selected={picked.has(d.rule)} onToggle={() => setPicked((p) => (p.has(d.rule) ? new Set([...p].filter((x) => x !== d.rule)) : new Set([...p, d.rule])))} />
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={d.severity} />
                      <span className="text-[13px] font-medium">{d.title}</span>
                      <ToneChip tone="default" dot={false}>
                        {d.count.toLocaleString()}
                      </ToneChip>
                      {d.technique && (
                        <ToneChip tone="accent" dot={false} className="text-[11px]">
                          ATT&CK {d.technique}
                        </ToneChip>
                      )}
                    </div>
                    <p className="text-[12.5px] text-muted">{d.detail}</p>
                    {d.sources.length > 0 && (
                      <p className="font-mono text-[11.5px] break-all">
                        {d.sources.slice(0, 8).map((s) => `${s.ip} (${s.count})`).join(" · ")}
                        {d.sources.length > 8 ? " …" : ""}
                      </p>
                    )}
                    {d.sources[0]?.examples[0] && <p className="font-mono text-[11px] break-all text-muted">{d.sources[0].examples[0]}</p>}
                    <p className="text-[12.5px]">
                      <span className="text-muted">Next step: </span>
                      {d.remediation}
                    </p>
                  </div>
                </div>
              ))}
            </section>
          )}
          {r.kind === "windows" && (r.chains?.length ?? 0) > 0 && (
            <section className="flex flex-col gap-2" aria-label="Process chains">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="flex-1 text-[13.5px] font-medium">Process chains ({r.chains!.length})</h3>
              </div>
              <p className="text-[12px] text-muted">Parent → child relationships from process creation events (Security 4688, Sysmon 1) that are rare in normal use. Each shows what the log says, why it was flagged, and what it may mean; recording one makes a finding under review.</p>
              {r.chains!.map((c, i) => (
                <div key={`${c.pattern}:${i}`} className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", pickedChains.has(i) ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
                  <Pick label={`Select ${c.title} on ${c.computer}${c.processes.find((p) => p.role === "flagged")?.record ? `, record ${c.processes.find((p) => p.role === "flagged")!.record}` : ""}`} selected={pickedChains.has(i)} onToggle={() => setPickedChains((p) => (p.has(i) ? new Set([...p].filter((x) => x !== i)) : new Set([...p, i])))} />
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={c.severity} />
                      <span className="text-[13px] font-medium">{c.title}</span>
                      <span className="text-[12px] text-muted">{c.computer}</span>
                      {c.technique && (
                        <ToneChip tone="accent" dot={false} className="text-[11px]">
                          ATT&CK {c.technique}
                        </ToneChip>
                      )}
                    </div>
                    <div className="text-[11.5px] text-muted">Observed</div>
                    <pre className="max-h-48 overflow-auto rounded-[6px] bg-black/20 px-2 py-1.5 font-mono text-[11px] whitespace-pre-wrap break-all">{c.processes.map(chainLine).join("\n")}</pre>
                    <p className="text-[12.5px]">
                      <span className="text-muted">Why it was flagged: </span>
                      {c.why}
                    </p>
                    <p className="text-[12.5px]">
                      <span className="text-muted">Hypotheses to test: </span>
                      {c.hypotheses}
                    </p>
                  </div>
                </div>
              ))}
            </section>
          )}
          {r.kind === "windows" && (r.logons?.length ?? 0) > 0 && (
            <section className="flex flex-col gap-1.5" aria-label="Logons per account">
              <h3 className="text-[13.5px] font-medium">Logons per account</h3>
              <p className="text-[12px] text-muted">As the log records them (4624, 4625); user and service accounts, not computer or system identities. Facts to hunt from, not detections.</p>
              <Table
                head={["Account", "Logons", "Failures", "Logon types", "Busiest sources", "First", "Last"]}
                rows={r.logons!.map((l) => [l.account, l.logons.toLocaleString(), l.failures.toLocaleString(), l.types.map(([t, n]) => `${logonType(t)}: ${n}`).join(", ") || "—", l.sources.map(([s, n]) => `${s} (${n})`).join(", "), l.first.slice(0, 19), l.last.slice(0, 19)])}
              />
            </section>
          )}
          {r.kind === "windows" ? (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Most frequent events</h3>
              <Table head={["Event ID", "Log", "Meaning", "Count"]} rows={(r.events ?? []).map((e) => [e.id, e.channel, e.name || "—", e.count.toLocaleString()])} />
            </section>
          ) : (
            <section className="flex flex-col gap-1.5">
              <h3 className="text-[13.5px] font-medium">Most active clients</h3>
              <Table head={["Address", "Requests", "4xx", "5xx", "SSH failures", "SSH logins"]} rows={r.clients.slice(0, 50).map((c) => [c.ip, c.requests, c.clientErrors, c.serverErrors, c.sshFailures, c.sshLogins])} />
            </section>
          )}
        </div>
      )}
    </div>
  );
}
