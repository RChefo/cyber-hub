// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { Globe2, Network, Radar, ScanSearch, Send } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { DnsRecord, HttpInspection } from "@/lib/types";
import { analyzeHeaders, parseRawHeaders, type CheckLevel, type HeaderList } from "../lib/headers";
import { calculate, formatBig, parseIpv4, parseIpv6 } from "../lib/ipcalc";
import { KeyValues, PrivacyNote, Segmented } from "./shared";

/* ───────────────────────── URL parser ───────────────────────── */

export function UrlParserTool() {
  const [input, setInput] = useState("");
  const parsed = useMemo(() => {
    const raw = input.trim();
    if (!raw) return null;
    try {
      const u = new URL(raw);
      const flags: string[] = [];
      if (u.username || u.password) flags.push("Contains credentials (userinfo). Everything before @ is not the host — a common phishing trick.");
      if (parseIpv4(u.hostname) !== null || parseIpv6(u.hostname.replace(/^\[|\]$/g, "")) !== null) flags.push("Host is a raw IP address rather than a domain name.");
      if (u.hostname.split(".").some((l) => l.startsWith("xn--"))) flags.push("Host uses punycode (xn--): check for look-alike internationalized domains.");
      if (u.protocol === "http:") flags.push("Plain HTTP: traffic is not encrypted.");
      if (u.protocol === "javascript:" || u.protocol === "data:") flags.push(`${u.protocol} URL: can execute or embed content when opened.`);
      if (/%2f|%5c|\.\.\//i.test(u.pathname)) flags.push("Path contains encoded slashes or traversal sequences.");
      const redirectParam = [...u.searchParams.keys()].find((k) => /^(url|redirect|next|return|returnto|dest|continue|goto)$/i.test(k));
      if (redirectParam) flags.push(`Parameter “${redirectParam}” looks like a redirect target — test for open redirects (in scope only).`);
      return { u, flags, error: null };
    } catch {
      return { u: null, flags: [], error: "Not a valid absolute URL (include the scheme, e.g. https://)" };
    }
  }, [input]);

  const defaultPort: Record<string, string> = { "http:": "80", "https:": "443", "ftp:": "21", "ws:": "80", "wss:": "443" };

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <TextInput label="URL" value={input} onChange={setInput} mono placeholder="https://user@app.example.com:8443/path?q=1#frag" />
      {!parsed ? (
        <EmptyBlock compact icon={Globe2} title="Enter a URL" description="Scheme, credentials, host, port, path, query parameters and fragment are broken out and decoded." />
      ) : parsed.error ? (
        <ErrorBlock message={parsed.error} />
      ) : (
        parsed.u && (
          <>
            {parsed.flags.length > 0 && (
              <ul className="flex flex-col gap-1">
                {parsed.flags.map((f) => (
                  <li key={f} className="tile flex items-start gap-2.5 px-3 py-2 text-[13px]">
                    <StatusDot tone="warning" className="mt-1.5" />
                    <span>
                      <span className="font-medium">Notice: </span>
                      {f}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <KeyValues
              rows={[
                { k: "Scheme", v: parsed.u.protocol.replace(/:$/, "") },
                ...(parsed.u.username ? [{ k: "Username", v: decodeURIComponent(parsed.u.username) }] : []),
                ...(parsed.u.password ? [{ k: "Password", v: "•".repeat(Math.min(parsed.u.password.length, 12)) + " (hidden)" }] : []),
                { k: "Host", v: parsed.u.hostname, copy: parsed.u.hostname },
                { k: "Port", v: parsed.u.port || `${defaultPort[parsed.u.protocol] ?? "—"} (default)` },
                { k: "Origin", v: parsed.u.origin, copy: parsed.u.origin },
                { k: "Path", v: decodeURIComponent(parsed.u.pathname) || "/" },
                ...(parsed.u.hash ? [{ k: "Fragment", v: decodeURIComponent(parsed.u.hash.slice(1)) }] : []),
              ]}
            />
            {[...parsed.u.searchParams].length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className="text-[12.5px] font-medium text-muted">Query parameters</span>
                <div className="panel-inset scroll-area">
                  <table className="w-full text-left text-[12.5px]">
                    <thead className="text-muted">
                      <tr>
                        <th className="px-3 py-2 font-medium">Name</th>
                        <th className="px-3 py-2 font-medium">Decoded value</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono">
                      {[...parsed.u.searchParams].map(([k, v], i) => (
                        <tr key={`${k}-${i}`} className="odd:bg-white/[0.02]">
                          <td className="px-3 py-1.5 align-top">{k}</td>
                          <td data-selectable className="px-3 py-1.5 break-all">
                            {v || <span className="text-muted">(empty)</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )
      )}
    </div>
  );
}

/* ───────────────────────── IP / CIDR calculator ───────────────────────── */

export function IpTool() {
  const [input, setInput] = useState("");
  const res = useMemo(() => {
    if (!input.trim()) return null;
    try {
      return { info: calculate(input), error: null };
    } catch (e) {
      return { info: null, error: (e as Error).message };
    }
  }, [input]);
  const i = res?.info;
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <TextInput label="Address or range" value={input} onChange={setInput} mono placeholder="10.20.30.40/22, 192.168.1.10 255.255.255.0 or 2001:db8::1/64" />
      {!res ? (
        <EmptyBlock compact icon={Network} title="Enter an IPv4 or IPv6 address" description="Add /prefix or a dotted subnet mask to calculate the network range." />
      ) : res.error ? (
        <ErrorBlock message={res.error} />
      ) : (
        i && (
          <>
            <div className="flex flex-wrap gap-2">
              <ToneChip tone="accent" dot={false}>IPv{i.version}</ToneChip>
              <ToneChip tone={/Private|Loopback|Link-local|Unique local/.test(i.scope) ? "success" : /Public|Global/.test(i.scope) ? "warning" : "default"}>{i.scope}</ToneChip>
              {i.ipClass && <ToneChip tone="default" dot={false}>Class {i.ipClass}</ToneChip>}
            </div>
            <KeyValues
              rows={[
                { k: "Address", v: i.address, copy: i.address },
                ...(i.expanded ? [{ k: "Expanded", v: i.expanded, copy: i.expanded }] : []),
                { k: "Network", v: `${i.network}/${i.prefix}`, copy: `${i.network}/${i.prefix}` },
                { k: "Netmask", v: i.netmask },
                ...(i.wildcard ? [{ k: "Wildcard mask", v: i.wildcard }] : []),
                ...(i.broadcast ? [{ k: "Broadcast", v: i.broadcast }] : []),
                { k: "First usable", v: i.firstHost },
                { k: "Last usable", v: i.lastHost },
                { k: "Total addresses", v: formatBig(i.totalAddresses) },
                { k: "Usable hosts", v: formatBig(i.usableHosts) },
                ...(i.binary ? [{ k: "Binary", v: i.binary }] : []),
                { k: "Integer", v: i.integer.toString() },
                { k: "Reverse DNS name", v: i.reversePointer, copy: i.reversePointer },
              ]}
            />
          </>
        )
      )}
    </div>
  );
}

/* ───────────────────────── DNS lookup (network) ───────────────────────── */

const RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "PTR", "SRV"];

export function DnsTool() {
  const { runtime } = useApp();
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ records: DnsRecord[]; query: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const records = await api.dnsLookup(name.trim(), type);
      setResult({ records, query: `${type} ${name.trim()}` });
      invalidate("activity");
    } catch (e) {
      setResult(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote network>Sends a DNS query using your system resolver when you press Run lookup. Only the name and record type are sent.</PrivacyNote>
      <div className="flex flex-wrap items-end gap-3">
        <TextInput label={type === "PTR" ? "IP address" : "Host name"} value={name} onChange={setName} onEnter={run} mono placeholder={type === "PTR" ? "8.8.8.8" : "example.com"} className="min-w-[260px] flex-1" />
        <SelectInput label="Record type" value={type} onChange={setType} className="w-32" options={RECORD_TYPES.map((t) => ({ id: t, label: t }))} />
        <Button variant="primary" onPress={run} isPending={busy} isDisabled={!name.trim() || !runtime}>
          <Send className="size-3.5" />
          Run lookup
        </Button>
      </div>
      {error && <ErrorBlock message={error} />}
      {result &&
        (result.records.length === 0 ? (
          <EmptyBlock compact icon={Radar} title="No records" description={`The resolver returned no ${result.query} records.`} />
        ) : (
          <div className="panel-inset scroll-area">
            <table className="w-full text-left text-[12.5px]">
              <thead className="text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Type</th>
                  <th className="px-3 py-2 font-medium">Value</th>
                  <th className="px-3 py-2 text-right font-medium">TTL</th>
                  <th className="w-10" />
                </tr>
              </thead>
              <tbody>
                {result.records.map((r, idx) => (
                  <tr key={idx} className="odd:bg-white/[0.02]">
                    <td className="px-3 py-1.5 text-muted">{r.recordType}</td>
                    <td data-selectable className="px-3 py-1.5 font-mono break-all">{r.value}</td>
                    <td className="px-3 py-1.5 text-right text-muted tabular">{r.ttl}s</td>
                    <td className="px-1">
                      <CopyButton text={r.value} label="Copy value" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      {!result && !error && <EmptyBlock compact icon={Radar} title="No lookup yet" description="Enter a name, choose a record type and press Run lookup." />}
    </div>
  );
}

/* ───────────────────────── HTTP header analyzer ───────────────────────── */

const LEVEL_META: Record<CheckLevel, { tone: "success" | "warning" | "danger" | "default"; label: string }> = {
  pass: { tone: "success", label: "Pass" },
  warn: { tone: "warning", label: "Review" },
  fail: { tone: "danger", label: "Missing / weak" },
  info: { tone: "default", label: "Info" },
};

export function HeadersTool() {
  const { runtime } = useApp();
  const [mode, setMode] = useState<"paste" | "fetch">("paste");
  const [raw, setRaw] = useState("");
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState<"GET" | "HEAD">("HEAD");
  const [busy, setBusy] = useState(false);
  const [fetched, setFetched] = useState<HttpInspection | null>(null);
  const [error, setError] = useState<string | null>(null);

  const data = useMemo<{ headers: HeaderList; status?: string; https?: boolean } | null>(() => {
    if (mode === "paste") {
      if (!raw.trim()) return null;
      const p = parseRawHeaders(raw);
      return { headers: p.headers, status: p.status };
    }
    if (!fetched) return null;
    return {
      headers: fetched.headers.map(([k, v]) => [k.toLowerCase(), v] as [string, string]),
      status: `${fetched.httpVersion} ${fetched.status} ${fetched.statusText}`,
      https: fetched.url.startsWith("https:"),
    };
  }, [mode, raw, fetched]);
  const checks = useMemo(() => (data ? analyzeHeaders(data.headers, { https: data.https }) : []), [data]);
  const counts = checks.reduce<Record<CheckLevel, number>>((a, c) => ({ ...a, [c.level]: a[c.level] + 1 }), { pass: 0, warn: 0, fail: 0, info: 0 });

  const fetchHeaders = async () => {
    setBusy(true);
    setError(null);
    try {
      setFetched(await api.httpInspect(url.trim(), method));
      invalidate("activity");
    } catch (e) {
      setFetched(null);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Segmented
        value={mode}
        onChange={setMode}
        ariaLabel="Source"
        options={[
          { id: "paste", label: "Paste headers" },
          { id: "fetch", label: "Fetch from URL" },
        ]}
      />
      {mode === "paste" ? (
        <>
          <PrivacyNote>Pasted headers are analyzed locally.</PrivacyNote>
          <TextAreaInput label="Raw response headers" value={raw} onChange={setRaw} rows={8} mono placeholder={"HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000"} />
        </>
      ) : (
        <>
          <PrivacyNote network>Sends one {method} request to this URL when you press Fetch headers. Redirects are not followed and the response body is not downloaded. Only inspect sites you own or are authorized to test.</PrivacyNote>
          <div className="flex flex-wrap items-end gap-3">
            <TextInput label="URL" value={url} onChange={setUrl} onEnter={fetchHeaders} mono placeholder="https://app.example.com/" className="min-w-[280px] flex-1" />
            <SelectInput label="Method" value={method} onChange={(v) => setMethod(v as "GET" | "HEAD")} className="w-28" options={[{ id: "HEAD", label: "HEAD" }, { id: "GET", label: "GET" }]} />
            <Button variant="primary" onPress={fetchHeaders} isPending={busy} isDisabled={!url.trim() || !runtime}>
              <Send className="size-3.5" />
              Fetch headers
            </Button>
          </div>
          {error && <ErrorBlock message={error} />}
          {fetched && (
            <div className="text-[12.5px] text-muted">
              {fetched.url} · {fetched.remoteAddr ?? "address unknown"} · {fetched.elapsedMs} ms
            </div>
          )}
        </>
      )}

      {!data ? (
        <EmptyBlock compact icon={ScanSearch} title={mode === "paste" ? "Paste response headers" : "Fetch a URL"} description="Security headers, cookies, CORS and information disclosure are evaluated." />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            {data.status && <ToneChip tone="accent" dot={false}>{data.status}</ToneChip>}
            <ToneChip tone="success">{counts.pass} pass</ToneChip>
            <ToneChip tone="warning">{counts.warn} to review</ToneChip>
            <ToneChip tone="danger">{counts.fail} missing or weak</ToneChip>
          </div>
          <ul className="flex flex-col gap-1">
            {checks.map((c) => (
              <li key={c.id} className="tile flex items-start gap-3 px-3 py-2.5">
                <div className="w-[120px] shrink-0 pt-px">
                  <ToneChip tone={LEVEL_META[c.level].tone}>{LEVEL_META[c.level].label}</ToneChip>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[13.5px] font-medium">{c.title}</div>
                  <div className="text-[12.5px] text-muted">{c.detail}</div>
                  {c.value && (
                    <code data-selectable className="mt-1 block font-mono text-[11.5px] break-all text-foreground/80">
                      {c.value}
                    </code>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <details className="tile px-3 py-2">
            <summary className="cursor-pointer text-[12.5px] text-muted">All headers ({data.headers.length})</summary>
            <table className="mt-2 w-full text-left text-[12.5px]">
              <tbody className="font-mono">
                {data.headers.map(([k, v], idx) => (
                  <tr key={idx} className="odd:bg-white/[0.02]">
                    <td className="px-2 py-1 align-top text-muted">{k}</td>
                    <td data-selectable className="px-2 py-1 break-all">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </>
      )}
    </div>
  );
}
