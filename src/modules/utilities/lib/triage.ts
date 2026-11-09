import type { CaptureIssue, FindingInput, LogDetection } from "@/lib/types";

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
