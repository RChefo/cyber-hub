import { Button } from "@heroui/react";
import { FileSearch, FolderSearch, Globe, Lock, Plus, Radar, Send, ServerCog, ShieldAlert, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CodeBlock } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { DnsIntelReport, HttpResponseOut, LeakScanResult, TlsReport, ToolIssue } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { searchPorts } from "../lib/ports";
import { PrivacyNote } from "./shared";

const ISSUE_TONE: Record<ToolIssue["level"], "danger" | "warning" | "default"> = { critical: "danger", warning: "warning", info: "default" };

function Issues({ issues }: { issues: ToolIssue[] }) {
  if (issues.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1">
      {issues.map((i, n) => (
        <li key={n} className="panel-inset flex items-start gap-2 px-3 py-2 text-[12.5px]">
          <ToneChip tone={ISSUE_TONE[i.level]}>{i.level === "critical" ? "Critical" : i.level === "warning" ? "Warning" : "Note"}</ToneChip>
          <span className="pt-0.5">{i.text}</span>
        </li>
      ))}
    </ul>
  );
}

/** Project selection for tools that contact targets (their scope is checked against it). */
function useProjectPicker(optional = false, initial: string | null = null) {
  const { runtime } = useApp();
  const projects = useQuery(["projects"], () => api.projectsList(), [], runtime);
  const [projectId, setProjectId] = useState<string | null>(initial ?? (optional ? "none" : null));
  const options = [
    ...(optional ? [{ id: "none", label: "No project" }] : []),
    ...(projects.data ?? []).map((p) => ({ id: String(p.id), label: `${p.name} (${p.status})` })),
  ];
  const picker = <SelectInput label="Project" value={projectId} onChange={setProjectId} options={options} placeholder="Choose a project" className="w-64" />;
  return { projectId: projectId && projectId !== "none" ? Number(projectId) : null, picker };
}

/* ───────────────────────── HTTP request builder ───────────────────────── */

const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

export function HttpBuilderTool() {
  // opened from a project's API inventory: project, method and URL come with the route
  const { route } = useApp();
  const pre = route.params ?? {};
  const { projectId, picker } = useProjectPicker(false, pre.project && /^\d+$/.test(pre.project) ? pre.project : null);
  const [method, setMethod] = useState(pre.method && HTTP_METHODS.includes(pre.method) ? pre.method : "GET");
  const [url, setUrl] = useState(pre.url ?? "");
  const [headers, setHeaders] = useState<[string, string][]>([["Accept", "*/*"]]);
  const [body, setBody] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [follow, setFollow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<HttpResponseOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  const send = async () => {
    if (!projectId || !url.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setRes(await api.httpSend({ projectId, method, url: url.trim(), headers: headers.filter(([k]) => k.trim()), body, insecure, followRedirects: follow }));
      invalidate("activity");
    } catch (e) {
      setRes(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote network>
        Sends one request to the URL when you press Send. The URL (and the same path on any Host header) must be in the selected project&apos;s authorized scope; the project must be active. Redirects are followed only when you turn it on, at most 5, and each one is checked against the scope before it is sent.
      </PrivacyNote>
      <div className="flex flex-wrap items-end gap-3">
        {picker}
        <SelectInput label="Method" value={method} onChange={setMethod} options={HTTP_METHODS.map((m) => ({ id: m, label: m }))} className="w-32" />
        <TextInput label="URL" value={url} onChange={setUrl} onEnter={send} placeholder="https://app.example.com/api/health" mono className="min-w-[280px] flex-1" />
      </div>
      <div className="flex flex-col gap-2">
        <span className="text-[12.5px] font-medium text-muted">Headers</span>
        {headers.map(([k, v], i) => (
          <div key={i} className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] gap-2">
            <TextInput aria-label={`Header ${i + 1} name`} value={k} onChange={(x) => setHeaders((h) => h.map((p, j) => (j === i ? [x, p[1]] : p)))} mono />
            <TextInput aria-label={`Header ${i + 1} value`} value={v} onChange={(x) => setHeaders((h) => h.map((p, j) => (j === i ? [p[0], x] : p)))} mono />
            <Button isIconOnly variant="ghost" aria-label={`Remove header ${i + 1}`} onPress={() => setHeaders((h) => h.filter((_, j) => j !== i))}>
              <Trash2 className="size-3.5" />
            </Button>
          </div>
        ))}
        <Button size="sm" variant="tertiary" className="self-start" onPress={() => setHeaders((h) => [...h, ["", ""]])} isDisabled={headers.length >= 50}>
          <Plus className="size-3.5" />
          Add header
        </Button>
      </div>
      {method !== "GET" && method !== "HEAD" && <TextAreaInput label="Body" value={body} onChange={setBody} rows={5} mono placeholder='{"example": true}' />}
      <div className="flex flex-wrap items-center gap-4">
        <SwitchInput label="Accept untrusted certificates" isSelected={insecure} onChange={setInsecure} />
        <SwitchInput label="Follow redirects (each checked against the scope)" isSelected={follow} onChange={setFollow} />
        <span className="flex-1" />
        <Button variant="primary" onPress={send} isPending={busy} isDisabled={!projectId || !url.trim()}>
          <Send className="size-3.5" />
          Send
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {res && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <ToneChip tone={res.status < 300 ? "success" : res.status < 400 ? "accent" : res.status < 500 ? "warning" : "danger"}>
              {res.status} {res.reason}
            </ToneChip>
            <span className="text-muted">
              {res.version} · {res.elapsedMs} ms · {res.bodyBytes.toLocaleString()} bytes{res.truncated ? " (cut at 2 MB)" : ""}
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
          {res.redirectStopped && (
            <p className="rounded-[10px] bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">{res.redirectStopped}</p>
          )}
          <CodeBlock code={res.headers.map(([k, v]) => `${k}: ${v}`).join("\n")} maxHeight={220} />
          {res.body && <CodeBlock code={res.body} maxHeight={420} />}
        </div>
      )}
    </div>
  );
}

/* ───────────────────────── TLS analyzer ───────────────────────── */

export function TlsTool() {
  const { projectId, picker } = useProjectPicker();
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<TlsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (!projectId || !target.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await api.tlsAnalyze(projectId, target.trim()));
      invalidate("assets", "activity");
    } catch (e) {
      setReport(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const leaf = report?.chain[0];
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote network>Connects to the host and performs up to three TLS handshakes (no data is sent after them). The host must be in the selected project&apos;s authorized scope; the certificate is recorded as a project asset.</PrivacyNote>
      <div className="flex flex-wrap items-end gap-3">
        {picker}
        <TextInput label="Host and port" value={target} onChange={setTarget} onEnter={run} placeholder="app.example.com:443" mono className="min-w-[260px] flex-1" />
        <Button variant="primary" onPress={run} isPending={busy} isDisabled={!projectId || !target.trim()}>
          <Lock className="size-3.5" />
          Analyze
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {report && (
        <>
          <div className="panel-inset grid grid-cols-2 gap-x-6 gap-y-2 px-3 py-3 text-[12.5px] md:grid-cols-4">
            <Fact label="Negotiated" value={report.protocol ?? "—"} />
            <Fact label="Cipher suite" value={report.cipher ?? "—"} mono />
            <Fact label="TLS 1.3 / 1.2" value={`${report.tls13 ? "yes" : "no"} / ${report.tls12 ? "yes" : "no"}`} />
            <Fact label="Trusted" value={report.trusted ? "yes" : "no"} />
            {leaf && (
              <>
                <Fact label="Subject" value={leaf.subject} />
                <Fact label="Issuer" value={leaf.issuer} />
                <Fact label="Expires" value={`${leaf.notAfter.slice(0, 10)} (${leaf.daysLeft} days)`} />
                <Fact label="Key and signature" value={`${leaf.key}${leaf.keyBits ? ` ${leaf.keyBits}` : ""} · ${leaf.signature}`} />
                <div className="col-span-2 md:col-span-4">
                  <Fact label="Names" value={leaf.sans.join(", ") || "—"} mono />
                </div>
                <div className="col-span-2 md:col-span-4">
                  <Fact label="SHA-256 fingerprint" value={leaf.sha256} mono />
                </div>
              </>
            )}
          </div>
          <Issues issues={report.issues} />
          {report.chain.length > 1 && (
            <div className="text-[12.5px] text-muted">
              Chain: {report.chain.map((c) => c.subject).join(" ← ")}
            </div>
          )}
        </>
      )}
      {!report && !error && <EmptyBlock compact icon={Lock} title="No analysis yet" description="Choose a project, enter an in-scope host and press Analyze." />}
    </div>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-muted">{label}</div>
      <div data-selectable className={cn("break-all text-foreground", mono && "font-mono text-[11.5px]")}>
        {value}
      </div>
    </div>
  );
}

/* ───────────────────────── DNS intelligence ───────────────────────── */

export function DnsIntelTool() {
  const { projectId, picker } = useProjectPicker(true);
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<DnsIntelReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (!domain.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await api.dnsIntel(projectId, domain.trim()));
      invalidate("activity");
    } catch (e) {
      setReport(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote network>Sends DNS queries for the domain through your system resolver (records, _dmarc, common DKIM selectors, DNSKEY). Internal names are refused; with a project, its exclusions apply.</PrivacyNote>
      <div className="flex flex-wrap items-end gap-3">
        {picker}
        <TextInput label="Domain" value={domain} onChange={setDomain} onEnter={run} placeholder="example.com" mono className="min-w-[240px] flex-1" />
        <Button variant="primary" onPress={run} isPending={busy} isDisabled={!domain.trim()}>
          <Globe className="size-3.5" />
          Analyze
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {report && (
        <>
          <Issues issues={report.issues} />
          <div className="panel-inset grid grid-cols-1 gap-x-6 gap-y-2 px-3 py-3 text-[12.5px] md:grid-cols-2">
            <Fact label="SPF" value={report.spf.record ?? "none"} mono />
            <Fact label="DMARC" value={report.dmarc.record ?? "none"} mono />
            <Fact label="DKIM selectors found" value={report.dkimSelectors.join(", ") || "none of the common ones"} />
            <Fact label="CAA / DNSSEC" value={`${report.caa.length ? report.caa.join(", ") : "no CAA"} · ${report.dnssec ? "DNSSEC on" : "no DNSSEC"}`} />
          </div>
          <div className="panel-inset px-3 py-2">
            <table className="w-full text-left text-[12.5px]">
              <tbody>
                {report.records
                  .filter((r) => r.values.length)
                  .map((r) => (
                    <tr key={r.type} className="align-top">
                      <td className="w-16 py-1 pr-3 text-muted">{r.type}</td>
                      <td data-selectable className="py-1 font-mono break-all">
                        {r.values.join("\n")}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {report.errors.length > 0 && <p className="text-[12px] text-muted">Some queries failed: {report.errors.join("; ")}</p>}
        </>
      )}
      {!report && !error && <EmptyBlock compact icon={Globe} title="No analysis yet" description="Enter a public domain to review its records and e-mail authentication." />}
    </div>
  );
}

/* ───────────────────────── Port and service reference ───────────────────────── */

export function PortsTool() {
  const { runtime } = useApp();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const list = useMemo(() => searchPorts(query), [query]);
  const seen = useQuery(["assets"], () => (selected ? api.servicesByPort(selected) : Promise.resolve([])), [selected], runtime && selected != null);
  const info = list.find((p) => p.port === selected) ?? null;
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Offline reference. The &quot;Seen in projects&quot; list comes from services recorded by discovery.</PrivacyNote>
      <SearchInput value={query} onChange={setQuery} placeholder="Port number or service, e.g. 445 or redis" className="max-w-md" />
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[280px_minmax(0,1fr)]">
        <ul className="panel-inset flex max-h-[520px] flex-col gap-0.5 overflow-auto p-1.5">
          {list.map((p) => (
            <li key={p.port}>
              <button
                type="button"
                onClick={() => setSelected(p.port)}
                className={cn("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[13px] hover:bg-white/[0.035] focus-visible:outline-2 focus-visible:outline-accent", selected === p.port && "bg-white/[0.06]")}
              >
                <span className="w-14 tabular text-muted">{p.port}</span>
                <span className="truncate">{p.service}</span>
              </button>
            </li>
          ))}
          {list.length === 0 && <li className="px-2 py-1.5 text-[12.5px] text-muted">No port matches.</li>}
        </ul>
        {info ? (
          <div className="flex flex-col gap-3 text-[13px]">
            <div>
              <div className="text-[15px] font-medium text-foreground">
                {info.port}/{info.proto} · {info.service}
              </div>
              <p className="text-muted">{info.description}</p>
            </div>
            <section>
              <h3 className="mb-1 text-[12.5px] font-medium text-muted">Typical risks</h3>
              <ul className="list-disc pl-5">{info.risks.map((r) => <li key={r}>{r}</li>)}</ul>
            </section>
            <section>
              <h3 className="mb-1 text-[12.5px] font-medium text-muted">What to check (within the authorized scope)</h3>
              <ul className="list-disc pl-5">{info.checks.map((r) => <li key={r}>{r}</li>)}</ul>
            </section>
            <section>
              <h3 className="mb-1 text-[12.5px] font-medium text-muted">Seen in projects</h3>
              {!seen.data ? (
                <LoadingRows rows={2} />
              ) : seen.data.length === 0 ? (
                <p className="text-[12.5px] text-muted">No recorded service uses this port.</p>
              ) : (
                <ul className="flex flex-col gap-1">
                  {seen.data.map((s) => (
                    <li key={s.assetId} className="panel-inset flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                      <span className="font-mono">{s.value}</span>
                      <span className="text-muted">{[s.service, s.product].filter(Boolean).join(" · ")}</span>
                      <span className="flex-1" />
                      <span className="text-muted">{s.project} · {formatRelative(s.lastSeen)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        ) : (
          <EmptyBlock compact icon={ServerCog} title="Choose a port" description="Select a port to see what usually runs there and what to check." />
        )}
      </div>
    </div>
  );
}

/* ───────────────────────── Subdomain monitor ───────────────────────── */

export function SubdomainMonitorTool() {
  const { runtime } = useApp();
  const { projectId, picker } = useProjectPicker();
  const snaps = useQuery(["assets"], () => (projectId ? api.discoverySnapshots(projectId, 50) : Promise.resolve([])), [projectId], runtime && !!projectId);
  const passive = (snaps.data ?? []).filter((s) => s.source === "passive" && s.status !== "running");
  const changes = useQuery(
    ["assets"],
    async () => {
      const out = [];
      for (const s of passive.slice(0, 10)) {
        const c = await api.discoveryChanges(s.id);
        out.push({ snapshot: s, changes: c.changes.filter((x) => x.assetType === "subdomain" || x.assetType === "domain"), first: c.previous == null });
      }
      return out;
    },
    [passive.map((s) => s.id).join(",")],
    runtime && passive.length > 0,
  );
  const workflows = useQuery(["workflows"], () => (projectId ? api.workflowsList(projectId) : Promise.resolve([])), [projectId], runtime && !!projectId);
  const monitor = (workflows.data ?? []).find((w) => w.scheduleHours && w.definition.steps.length === 1 && w.definition.steps[0].type === "passive_discovery");
  const [hours, setHours] = useState("24");
  const [saving, setSaving] = useState(false);

  const schedule = async () => {
    if (!projectId) return;
    setSaving(true);
    try {
      await api.workflowSave({
        id: monitor?.id,
        projectId,
        name: monitor?.name ?? "Subdomain monitor",
        description: "Passive discovery on a schedule; new and missing names appear in the Subdomain monitor.",
        definition: { steps: [{ type: "passive_discovery", name: "", params: {}, timeoutSecs: 0, retries: 1, continueOnError: false }] },
        scheduleHours: Math.min(720, Math.max(1, Number(hours) || 24)),
        enabled: true,
      });
      invalidate("workflows");
      notify.success("Monitoring scheduled", `Passive discovery every ${hours} hours while Cyber Hub is open`);
    } catch (e) {
      notify.error("Could not schedule monitoring", e);
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => setHours(String(monitor?.scheduleHours ?? 24)), [monitor?.scheduleHours]);

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote network>Monitoring uses passive discovery only (certificate logs and DNS for the project&apos;s in-scope domains); nothing is sent to the targets.</PrivacyNote>
      <div className="flex flex-wrap items-end gap-3">
        {picker}
        <TextInput label="Every (hours)" value={hours} onChange={setHours} mono className="w-32" />
        <Button variant="primary" onPress={schedule} isPending={saving} isDisabled={!projectId}>
          <Radar className="size-3.5" />
          {monitor ? "Update schedule" : "Monitor on a schedule"}
        </Button>
        {monitor?.nextRunAt && <span className="pb-2 text-[12.5px] text-muted">Next run {formatRelative(monitor.nextRunAt)}</span>}
      </div>
      {!projectId ? (
        <EmptyBlock compact icon={Radar} title="Choose a project" description="New and missing subdomains of its passive discovery runs appear here." />
      ) : !changes.data ? (
        passive.length === 0 ? <EmptyBlock compact icon={Radar} title="No passive runs yet" description="Run passive discovery in the project, or schedule monitoring." /> : <LoadingRows rows={3} />
      ) : (
        <ol className="flex flex-col gap-2">
          {changes.data.map(({ snapshot, changes: c, first }) => (
            <li key={snapshot.id} className="panel-inset px-3 py-2 text-[12.5px]">
              <div className="flex items-center gap-2">
                <span className="text-foreground">{formatRelative(snapshot.startedAt)}</span>
                <ToneChip tone={snapshot.status === "completed" ? "success" : "warning"}>{snapshot.status}</ToneChip>
                <span className="text-muted">{first ? "first run" : `${c.filter((x) => x.change === "added").length} new, ${c.filter((x) => x.change === "missing").length} missing`}</span>
              </div>
              {!first &&
                c
                  .filter((x) => x.change !== "changed")
                  .slice(0, 50)
                  .map((x) => (
                    <div key={`${x.change}-${x.assetId}`} className={cn("mt-1 font-mono", x.change === "added" ? "text-success-soft-foreground" : "text-danger-soft-foreground")}>
                      {x.change === "added" ? "+ " : "- "}
                      {x.value}
                      <span className="ml-2 font-sans text-muted">{x.certainty}</span>
                    </div>
                  ))}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

/* ───────────────────────── Secrets scanner ───────────────────────── */

export function SecretsTool() {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState<"text" | "file" | "folder" | null>(null);
  const [result, setResult] = useState<{ root: string; result: LeakScanResult } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async (kind: "text" | "file" | "folder") => {
    setBusy(kind);
    setError(null);
    try {
      if (kind === "text") setResult({ root: "pasted text", result: await api.leakScanText(text) });
      else {
        const r = await api.leakScanPick(kind === "folder");
        if (r) setResult(r);
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };
  const r = result?.result;
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Scans locally for API keys, tokens, private keys and passwords. Matches are shown masked; nothing is stored or sent.</PrivacyNote>
      <TextAreaInput label="Text to scan" value={text} onChange={setText} rows={6} mono placeholder="Paste configuration, code or logs" />
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onPress={() => run("text")} isPending={busy === "text"} isDisabled={!text.trim()}>
          <FileSearch className="size-3.5" />
          Scan text
        </Button>
        <Button variant="secondary" onPress={() => run("file")} isPending={busy === "file"}>
          <FileSearch className="size-3.5" />
          Scan a file…
        </Button>
        <Button variant="secondary" onPress={() => run("folder")} isPending={busy === "folder"}>
          <FolderSearch className="size-3.5" />
          Scan a folder…
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {r && (
        <>
          <p className="text-[12.5px] text-muted">
            {result.root}: {r.hits.length} findings in {r.filesScanned.toLocaleString()} files{r.filesSkipped ? `, ${r.filesSkipped} skipped (binary or over 5 MB)` : ""}
            {r.truncated ? ". The scan stopped at its limit (20,000 files or 5,000 findings)." : "."} Dependency and version-control folders are skipped.
          </p>
          {r.hits.length === 0 ? (
            <EmptyBlock compact icon={ShieldAlert} title="No secrets found" description="Only known formats and high-entropy assignments are detected; absence is not proof." />
          ) : (
            <div className="panel-inset overflow-x-auto px-3 py-1">
              <table className="w-full text-left text-[12.5px]">
                <thead className="text-muted">
                  <tr>
                    <th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Location</th>
                    <th className="py-2 font-medium">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {r.hits.slice(0, 1000).map((h, i) => (
                    <tr key={i}>
                      <td className="py-1 pr-3">{h.label}</td>
                      <td className="py-1 pr-3 font-mono text-muted">
                        {h.file}:{h.line}:{h.column}
                      </td>
                      <td className="py-1 font-mono">{h.masked}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
