// SPDX-License-Identifier: Apache-2.0
import { Button, Tooltip } from "@heroui/react";
import { ArrowLeftRight, FileUp, Send, ShieldCheck, ShieldUser } from "lucide-react";
import { useRef, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { discoveryUrls, oauthFinding, reviewMetadata, type OAuthCheck, type OAuthReview } from "../lib/oauth";
import { PrivacyNote, Segmented } from "./shared";
import { Pick, RecordBar } from "./TriageTools";

const MAX_FILE = 1024 * 1024;

interface Result {
  review: OAuthReview;
  /** the file name, "pasted text" or the address the metadata came from */
  source: string;
  /** the project the metadata was fetched for */
  projectId: number | null;
  /** redirects followed to fetch it */
  redirects: number;
  run: number;
}

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`This is not JSON: ${errorMessage(e)}`);
  }
}

/** Security utility: review of OAuth 2.0 and OpenID Connect authorization server metadata. */
export function OAuthTool() {
  const { runtime } = useApp();
  const projects = useQuery(["projects"], () => api.projectsList(), [], runtime);
  const [mode, setMode] = useState<"paste" | "fetch">("paste");
  const [text, setText] = useState("");
  const [issuer, setIssuer] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const show = (review: OAuthReview, source: string, project: number | null, redirects = 0) => {
    setResult((r) => ({ review, source, projectId: project, redirects, run: (r?.run ?? 0) + 1 }));
    setError(null);
  };
  const fail = (e: unknown) => {
    setResult(null);
    setError(errorMessage(e));
  };

  const reviewText = (raw: string, source: string) => {
    try {
      show(reviewMetadata(parseJson(raw)), source, null);
    } catch (e) {
      fail(e);
    }
  };

  const onFile = async (f: File | undefined) => {
    if (fileRef.current) fileRef.current.value = "";
    if (!f) return;
    if (f.size > MAX_FILE) {
      fail(`${f.name} is larger than 1 MB; metadata documents are a few kilobytes.`);
      return;
    }
    try {
      const raw = await f.text();
      setText(raw);
      reviewText(raw, f.name);
    } catch (e) {
      fail(`Could not read ${f.name}: ${errorMessage(e)}`);
    }
  };

  // the OpenID Connect address first, then the RFC 8414 one; each request passes the scope check
  const fetchMetadata = async () => {
    if (!projectId) return;
    const urls = discoveryUrls(issuer);
    if (urls.length === 0) {
      fail("Enter the issuer as an http or https URL, such as https://login.example.com");
      return;
    }
    setBusy(true);
    setError(null);
    const misses: string[] = [];
    try {
      for (const url of urls) {
        const res = await api.httpSend({ projectId: Number(projectId), method: "GET", url, headers: [["Accept", "application/json"]], body: "", insecure: false, followRedirects: true });
        invalidate("activity");
        if (res.status !== 200) {
          misses.push(`${url} answered ${res.status}${res.reason ? ` ${res.reason}` : ""}${res.redirectStopped ? ` (${res.redirectStopped})` : ""}`);
          continue;
        }
        if (res.truncated) {
          misses.push(`${url} sent a response too large for metadata`);
          continue;
        }
        try {
          show(reviewMetadata(parseJson(res.body), url), url, Number(projectId), res.redirects.length);
          return;
        } catch (e) {
          misses.push(`${url}: ${errorMessage(e)}`);
        }
      }
      fail(`No metadata found. ${misses.join(". ")}.`);
    } catch (e) {
      fail(e);
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
          { id: "paste", label: "Paste or open a file" },
          { id: "fetch", label: "Fetch from the issuer" },
        ]}
      />
      {mode === "paste" ? (
        <>
          <PrivacyNote>The document is reviewed on this device. Paste the JSON of an OpenID Connect discovery document (/.well-known/openid-configuration) or of OAuth 2.0 authorization server metadata (/.well-known/oauth-authorization-server).</PrivacyNote>
          <TextAreaInput label="Metadata (JSON)" value={text} onChange={setText} rows={10} mono placeholder={'{\n  "issuer": "https://login.example.com",\n  "authorization_endpoint": "https://login.example.com/authorize",\n  "token_endpoint": "https://login.example.com/token",\n  "response_types_supported": ["code"]\n}'} />
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onPress={() => reviewText(text, "pasted text")} isDisabled={!text.trim()}>
              <ShieldCheck className="size-3.5" />
              Review
            </Button>
            <input ref={fileRef} type="file" accept=".json,application/json,text/plain" className="hidden" onChange={(e) => void onFile(e.target.files?.[0])} aria-hidden tabIndex={-1} />
            <Button variant="tertiary" onPress={() => fileRef.current?.click()}>
              <FileUp className="size-3.5" />
              Open a file…
            </Button>
          </div>
        </>
      ) : (
        <>
          <PrivacyNote network>
            Sends a GET request for the issuer&apos;s metadata when you press Fetch: /.well-known/openid-configuration, then /.well-known/oauth-authorization-server if the first is missing. The issuer must be in the selected project&apos;s authorized scope and the project must be active; redirects are followed only within the scope. No authorization or token request is made, and the review runs on this device.
          </PrivacyNote>
          <div className="flex flex-wrap items-end gap-3">
            <SelectInput label="Project" value={projectId} onChange={setProjectId} options={(projects.data ?? []).map((p) => ({ id: String(p.id), label: `${p.name} (${p.status})` }))} placeholder="Choose a project" className="w-64" />
            <TextInput label="Issuer" value={issuer} onChange={setIssuer} onEnter={() => void fetchMetadata()} mono placeholder="https://login.example.com" className="min-w-[280px] flex-1" />
            <Button variant="primary" onPress={() => void fetchMetadata()} isPending={busy} isDisabled={!runtime || !projectId || !issuer.trim()}>
              <Send className="size-3.5" />
              Fetch
            </Button>
          </div>
        </>
      )}
      {error && <ErrorBlock message={error} />}
      {result ? (
        <ReviewView key={result.run} result={result} />
      ) : (
        !error && <EmptyBlock compact icon={ShieldUser} title={mode === "paste" ? "Paste or open a metadata document" : "Fetch an issuer's metadata"} description="Grants, PKCE, signing algorithms, transport and the endpoints worth testing are reviewed against RFC 9700 and the OpenID Connect specifications." />
      )}
    </div>
  );
}

function ReviewView({ result }: { result: Result }) {
  const { navigate } = useApp();
  const r = result.review;
  const issues = r.checks.filter((c) => c.kind === "issue");
  const tests = r.checks.filter((c) => c.kind === "test");
  const [picked, setPicked] = useState<Set<string>>(() => new Set(issues.filter((c) => c.severity === "high" || c.severity === "medium").map((c) => c.id)));
  const toggle = (id: string) => setPicked((p) => (p.has(id) ? new Set([...p].filter((x) => x !== id)) : new Set([...p, id])));
  const openInBuilder = (url: string) => navigate("utilities", { utility: "http-builder", method: "GET", url, ...(result.projectId ? { project: String(result.projectId) } : {}) });

  return (
    <div className="flex flex-col gap-4">
      <div className="text-[13px]">
        <span className="font-medium break-all">{r.issuer || "(no issuer)"}</span>
        <span className="text-muted">
          {" "}
          · {r.kind} · from {result.source}
          {result.redirects ? ` after ${result.redirects} ${result.redirects === 1 ? "redirect" : "redirects"}` : ""} · {issues.length} {issues.length === 1 ? "issue" : "issues"} · {tests.length} to test
        </span>
      </div>
      {r.strengths.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[12.5px] text-muted">In place:</span>
          {r.strengths.map((s) => (
            <ToneChip key={s} tone="success">
              {s}
            </ToneChip>
          ))}
        </div>
      )}
      {issues.length === 0 ? (
        <EmptyBlock compact icon={ShieldCheck} title="No configuration issue" description="Nothing in the metadata goes against the checks. The metadata shows what the server offers, not how each client is set up, so test the flows too." />
      ) : (
        <section className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="flex-1 text-[13.5px] font-medium">Issues ({issues.length})</h3>
            <RecordBar
              picked={picked.size}
              project={result.projectId}
              build={(pid) => issues.filter((c) => picked.has(c.id)).map((c) => oauthFinding(pid, r, c))}
              onDone={() => setPicked(new Set())}
              source={{ module: "oauth_review", subject: r.issuer || "authorization server metadata", report: () => r }}
            />
          </div>
          {issues.map((c) => (
            <CheckRow key={c.id} check={c} selected={picked.has(c.id)} onToggle={() => toggle(c.id)} />
          ))}
        </section>
      )}
      {tests.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="text-[13.5px] font-medium">To test ({tests.length})</h3>
          <p className="text-[12px] text-muted">Leads from what the server offers, not confirmed weaknesses; they are not recorded as findings. Test only with authorization.</p>
          {tests.map((c) => (
            <CheckRow key={c.id} check={c} />
          ))}
        </section>
      )}
      {r.endpoints.length > 0 && (
        <section className="flex flex-col gap-1.5">
          <h3 className="text-[13.5px] font-medium">Endpoints ({r.endpoints.length})</h3>
          {r.endpoints.map((e) => (
            <div key={e.name} className="flex items-center gap-2 text-[12.5px]">
              <span className="w-48 shrink-0 text-muted">{e.name}</span>
              <span className={cn("min-w-0 flex-1 font-mono break-all", e.url.startsWith("http://") && "text-warning")}>{e.url}</span>
              <CopyButton text={e.url} label={`Copy the ${e.name} endpoint`} />
              <Tooltip delay={400}>
                <Button isIconOnly size="sm" variant="ghost" aria-label={`Open the ${e.name} endpoint in the HTTP request builder`} onPress={() => openInBuilder(e.url)}>
                  <ArrowLeftRight className="size-3.5" />
                </Button>
                <Tooltip.Content>Open in the HTTP request builder</Tooltip.Content>
              </Tooltip>
            </div>
          ))}
        </section>
      )}
      <section className="flex flex-col gap-1.5">
        <h3 className="text-[13.5px] font-medium">Advertised support</h3>
        {r.advertised.map((a) => (
          <div key={a.label} className="flex items-start gap-2 text-[12.5px]">
            <span className="w-48 shrink-0 text-muted">{a.label}</span>
            <span className={cn("min-w-0 flex-1 break-all", a.values.length ? "font-mono" : "text-muted")}>{a.values.length ? a.values.join(", ") : a.defaults ? `not listed; the default is ${a.defaults.join(", ")}` : "not listed"}</span>
          </div>
        ))}
      </section>
    </div>
  );
}

function CheckRow({ check: c, selected, onToggle }: { check: OAuthCheck; selected?: boolean; onToggle?: () => void }) {
  return (
    <div className={cn("flex items-start gap-2.5 rounded-[8px] px-2.5 py-2", selected ? "bg-accent-soft/40" : "bg-white/[0.02]")}>
      {onToggle && <Pick label={`Select ${c.title}`} selected={!!selected} onToggle={onToggle} />}
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={c.severity} />
          <span className="text-[13px] font-medium">{c.title}</span>
        </div>
        <p className="text-[12.5px] text-muted">{c.detail}</p>
        <p className="text-[12.5px]">
          <span className="text-muted">{c.kind === "issue" ? "Fix: " : "How to test: "}</span>
          {c.recommendation}
        </p>
        <p className="text-[11.5px] text-muted">
          {c.id} · {c.reference}
        </p>
      </div>
    </div>
  );
}
