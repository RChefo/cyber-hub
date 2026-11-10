import type { CaptureBeacon, CaptureDnsLead, CaptureIssue, ChainProcess, FindingInput, LogDetection, ProcessChain } from "@/lib/types";

const cap = (s: string, n = 200) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** The finding a packet-capture issue becomes. */
export function captureFinding(projectId: number, file: string, i: CaptureIssue): FindingInput {
  const evidence = i.evidence.slice(0, 50).map((e) => `- ${e}`);
  return {
    projectId,
    title: cap(`${i.title} (${file})`),
    severity: i.severity,
    status: "new",
    category: "Network traffic",
    confidence: "high",
    description: `${i.detail}\n\nSeen in the capture ${file}:\n${evidence.join("\n")}${i.evidence.length > 50 ? `\n- … and ${i.evidence.length - 50} more` : ""}`,
    affectedTarget: file,
    technicalDetails: `Rule ${i.rule} (packet capture triage).`,
    remediation: i.remediation,
    tags: ["pcap"],
  };
}

const when = (t: number) => new Date(t * 1000).toISOString().replace(".000Z", "Z");

/** Seconds as a short duration: 45 s, 5 min, 2 h 10 min. */
export function duration(s: number): string {
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  const h = Math.floor(s / 3600);
  const m = Math.round((s - h * 3600) / 60);
  return m ? `${h} h ${m} min` : `${h} h`;
}

/** A schedule in a sentence. */
export function beaconLine(b: CaptureBeacon): string {
  return `${b.client} → ${b.server} (${b.protocol}): ${b.connections} connections about every ${duration(b.interval)} (jitter ${b.jitter}%, ${b.onSchedule}% on schedule) over ${duration(b.last - b.first)}`;
}

/** The finding a beacon-like schedule becomes when the analyst records it: a hypothesis to
 * check, under review with low confidence. No technique is tagged: timing alone shows none. */
export function beaconFinding(projectId: number, file: string, b: CaptureBeacon): FindingInput {
  return {
    projectId,
    title: cap(`Connections on a regular schedule: ${b.client} → ${b.server} (${file})`),
    severity: "info",
    status: "under_review",
    category: "Threat hunting",
    confidence: "low",
    description: `${beaconLine(b)}, from ${when(b.first)} to ${when(b.last)}.\n\nA regular schedule is how implants call home (beaconing), but updaters, time synchronization, health checks and monitoring keep schedules too.${b.note ? ` ${b.note}.` : ""} Check what runs on ${b.client} and who ${b.server} is before treating it as command and control.`,
    affectedTarget: b.client,
    technicalDetails: `Hunting lead from the packet capture triage of ${file}: ${b.regularity} timing, median interval ${b.interval} s. If confirmed as command and control, ATT&CK T1071 (Application Layer Protocol) would apply.`,
    remediation: "Identify the process behind the connections on the client; block the destination and investigate the host if it is not a known service.",
    tags: ["pcap", "hunting", "beacon"],
  };
}

/** The finding a DNS pattern becomes when the analyst records it: a hypothesis to check. */
export function dnsLeadFinding(projectId: number, file: string, d: CaptureDnsLead): FindingInput {
  return {
    projectId,
    title: cap(`${d.title} (${file})`),
    severity: "info",
    status: "under_review",
    category: "Threat hunting",
    confidence: "low",
    description: `${d.detail}\n\nAlso possible: ${d.benign}\n\nClients: ${d.clients.join(", ") || "—"}\nExamples:\n${d.examples.map((e) => `- ${e}`).join("\n")}`,
    affectedTarget: d.subject,
    technicalDetails: `Hunting lead ${d.rule} from the packet capture triage of ${file}. If confirmed, ATT&CK ${d.techniques.join(" and ")} would apply.`,
    remediation: "Look at the process that sent the queries and at the domain's owner and history before blocking it or treating it as an exfiltration channel.",
    tags: ["pcap", "hunting", "dns"],
  };
}

/** The finding a log detection becomes: the sources and their counts, with redacted examples. */
export function logFinding(projectId: number, file: string, d: LogDetection): FindingInput {
  const sources = d.sources.slice(0, 20).map((s) => `- ${s.ip}: ${s.count}`);
  const examples = d.sources.flatMap((s) => s.examples).slice(0, 5);
  return {
    projectId,
    title: cap(`${d.title} (${file})`),
    severity: d.severity,
    status: "new",
    category: "Log analysis",
    confidence: "medium",
    description: `${d.detail}\n\nSources in ${file}:\n${sources.join("\n")}${examples.length ? `\n\nExamples:\n${examples.map((e) => `- ${e}`).join("\n")}` : ""}`,
    affectedTarget: file,
    technicalDetails: d.technique
      ? `Rule ${d.rule} (Windows event log triage). MITRE ATT&CK: ${d.technique}. A detection is a lead for the investigation, not proof of a compromise.`
      : `Rule ${d.rule} (log triage). Matches are attempts; check the responses before treating them as successful.`,
    remediation: d.remediation,
    tags: d.technique ? ["logs", "windows", d.technique.split(" ")[0]] : ["logs"],
  };
}

/** One process of a chain as a line: who started what, when, from which event record. */
export function chainLine(p: ChainProcess): string {
  const name = p.image.split(/[\\/]/).pop() || p.image;
  const indent = p.depth < 0 ? "" : "  ".repeat(p.depth + 1);
  const where = p.record ? `${p.time} · record ${p.record} · ${p.eventId === 1 ? "Sysmon 1" : `event ${p.eventId}`} · PID ${p.pid}` : "started before the log (known only by name)";
  const cmd = p.commandLine && p.commandLine !== p.image ? ` — ${p.commandLine}` : "";
  return `${indent}${p.role === "flagged" ? "▶ " : ""}${name} (${where}${p.user ? ` · ${p.user}` : ""})${cmd}`;
}

/** A flagged process chain as a finding under review: observed facts, the derived signal and the
 *  hypotheses stay in separate parts of the text, and only a technique the chain shows is tagged. */
export function chainFinding(projectId: number, file: string, c: ProcessChain): FindingInput {
  const flagged = c.processes.find((p) => p.role === "flagged");
  const parent = [...c.processes].reverse().find((p) => p.role === "ancestor");
  const name = (p?: ChainProcess) => (p ? p.image.split(/[\\/]/).pop() || p.image : "?");
  return {
    projectId,
    title: cap(`${c.title}: ${name(parent)} → ${name(flagged)} (${file})`),
    severity: c.severity,
    status: "under_review",
    category: "Log analysis",
    confidence: "low",
    description: `Observed in ${file} on ${c.computer}:\n${c.processes.map((p) => `- ${chainLine(p)}`).join("\n")}\n\nWhy it was flagged (derived): ${c.why}\n\nHypotheses to test: ${c.hypotheses}`,
    affectedTarget: c.computer || file,
    technicalDetails: `Pattern ${c.pattern} (Windows event log process chains).${c.technique ? ` MITRE ATT&CK: ${c.technique}.` : " No ATT&CK technique is claimed: the relationship alone does not show one."} A chain is a lead for the investigation, not proof of a compromise.`,
    remediation: "Confirm or rule out the hypotheses from the evidence: the documents, requests or services named above, and what the flagged process did next.",
    tags: ["logs", "windows", "process-chain", ...(c.technique ? [c.technique.split(" ")[0]] : [])],
  };
}

/** Bytes in a short human form. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[u]}`;
}

/** The capture's time span: "2026-11-09 10:00:00 UTC, 1 min 30 s". */
export function captureSpan(first: number | null, last: number | null): string {
  if (first == null || last == null) return "no timestamps";
  const start = new Date(first * 1000).toISOString().replace("T", " ").slice(0, 19);
  const secs = Math.max(0, Math.round(last - first));
  const span = secs >= 3600 ? `${Math.floor(secs / 3600)} h ${Math.floor((secs % 3600) / 60)} min` : secs >= 60 ? `${Math.floor(secs / 60)} min ${secs % 60} s` : `${secs} s`;
  return `${start} UTC, ${span}`;
}
