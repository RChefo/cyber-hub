// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { FileUp, Fingerprint, KeyRound, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { formatBytes } from "@/lib/utils";
import { digestHex } from "../lib/encoding";
import { identifyHash } from "../lib/hashid";
import { decodeJwt } from "../lib/jwt";
import { md5Hex } from "../lib/md5";
import { parseUserAgent } from "../lib/ua";
import { KeyValues, PrivacyNote } from "./shared";

/* ───────────────────────── JWT ───────────────────────── */

const STATUS_META = {
  valid: { tone: "success", label: "Not expired" },
  expired: { tone: "danger", label: "Expired" },
  not_yet_valid: { tone: "warning", label: "Not yet valid (nbf)" },
  no_expiry: { tone: "warning", label: "No expiry" },
} as const;

export function JwtTool() {
  const [token, setToken] = useState("");
  const result = useMemo(() => {
    if (!token.trim()) return null;
    try {
      return { ok: decodeJwt(token), error: null };
    } catch (e) {
      return { ok: null, error: (e as Error).message };
    }
  }, [token]);
  const d = result?.ok;

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Decoded locally — the token never leaves this device. The signature is not verified: decoding shows what a token claims, not whether it is genuine.</PrivacyNote>
      <TextAreaInput label="Token" value={token} onChange={setToken} rows={4} mono placeholder="eyJhbGciOi… (a Bearer prefix is accepted)" />
      {!result && <EmptyBlock compact icon={KeyRound} title="Paste a JSON Web Token" description="Header, claims, timestamps and common weaknesses will be shown here." />}
      {result?.error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2.5 text-[13px] text-danger-soft-foreground">
          {result.error}
        </div>
      )}
      {d && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <ToneChip tone={STATUS_META[d.status].tone}>{STATUS_META[d.status].label}</ToneChip>
            <ToneChip tone="default" dot={false}>alg {String(d.header.alg ?? "missing")}</ToneChip>
            {d.header.typ !== undefined && <ToneChip tone="default" dot={false}>typ {String(d.header.typ)}</ToneChip>}
            <ToneChip tone="default" dot={false}>{d.parts === 5 ? "JWE (encrypted)" : "JWS (signed)"}</ToneChip>
          </div>
          {d.warnings.length > 0 && (
            <ul className="flex flex-col gap-1">
              {d.warnings.map((w) => (
                <li key={w.message} className="tile flex items-start gap-2.5 px-3 py-2 text-[13px]">
                  <StatusDot tone={w.level === "danger" ? "danger" : w.level === "warning" ? "warning" : "default"} className="mt-1.5" />
                  <span>
                    <span className="font-medium">{w.level === "danger" ? "Risk: " : w.level === "warning" ? "Warning: " : "Note: "}</span>
                    {w.message}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div className="grid gap-4 xl:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <span className="text-[12.5px] font-medium text-muted">Header</span>
              <CodeBlock code={JSON.stringify(d.header, null, 2)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-[12.5px] font-medium text-muted">Payload</span>
              <CodeBlock code={d.payload ? JSON.stringify(d.payload, null, 2) : d.payloadText || "(encrypted)"} maxHeight={360} />
            </div>
          </div>
          {d.times.length > 0 && (
            <KeyValues
              mono={false}
              rows={d.times.map((t) => ({
                k: { exp: "Expires (exp)", iat: "Issued at (iat)", nbf: "Not before (nbf)" }[t.claim],
                v: `${t.date.toLocaleString()} · ${t.value}`,
                tone: t.claim === "exp" ? (t.date.getTime() < Date.now() ? "danger" : "success") : undefined,
              }))}
            />
          )}
          <KeyValues rows={[{ k: "Signature", v: d.signature || "(empty)", copy: d.signature || undefined }]} />
        </>
      )}
    </div>
  );
}

/* ───────────────────────── Hash identifier ───────────────────────── */

export function HashIdTool() {
  const [hash, setHash] = useState("");
  const candidates = useMemo(() => identifyHash(hash), [hash]);
  const tone = { high: "success", medium: "warning", low: "default" } as const;
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <TextInput label="Hash" value={hash} onChange={setHash} mono placeholder="5f4dcc3b5aa765d61d8327deb882cf99" description="Identification uses length, alphabet and prefixes — results are likely candidates, not proof." />
      {!hash.trim() ? (
        <EmptyBlock compact icon={Fingerprint} title="Enter a hash" description="Supports raw hex digests, Unix crypt formats, bcrypt, Argon2, Kerberos, NetNTLMv2 and more." />
      ) : candidates.length === 0 ? (
        <EmptyBlock compact icon={Fingerprint} title="No match" description={`Length ${hash.trim().length}. The value does not match any known hash format.`} />
      ) : (
        <ul className="flex flex-col gap-1">
          {candidates.map((c) => (
            <li key={c.name} className="tile flex items-center gap-3 px-3 py-2.5">
              <div className="min-w-0 flex-1">
                <div className="text-[13.5px] font-medium">{c.name}</div>
                {c.note && <div className="text-[12px] text-muted">{c.note}</div>}
              </div>
              {c.hashcat !== undefined && (
                <span className="font-mono text-[12px] text-muted">
                  hashcat -m {c.hashcat}
                  {c.john ? ` · john --format=${c.john}` : ""}
                </span>
              )}
              <ToneChip tone={tone[c.confidence]}>{c.confidence} confidence</ToneChip>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* ───────────────────────── Hash calculator ───────────────────────── */

const ALGOS = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const;
type Algo = (typeof ALGOS)[number];

async function computeAll(data: Uint8Array): Promise<Record<Algo, string>> {
  const [s1, s256, s384, s512] = await Promise.all([digestHex("SHA-1", data), digestHex("SHA-256", data), digestHex("SHA-384", data), digestHex("SHA-512", data)]);
  return { MD5: md5Hex(data), "SHA-1": s1, "SHA-256": s256, "SHA-384": s384, "SHA-512": s512 };
}

const MAX_FILE = 512 * 1024 * 1024;

export function HashCalcTool() {
  const [text, setText] = useState("");
  const [file, setFile] = useState<{ name: string; size: number; data: Uint8Array } | null>(null);
  const [upper, setUpper] = useState(false);
  const [hashes, setHashes] = useState<Record<Algo, string> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let alive = true;
    const data = file ? file.data : new TextEncoder().encode(text);
    setBusy(true);
    computeAll(data)
      .then((h) => alive && (setHashes(h), setError(null)))
      .catch((e) => alive && setError((e as Error).message))
      .finally(() => alive && setBusy(false));
    return () => {
      alive = false;
    };
  }, [text, file]);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_FILE) {
      setError(`File is ${formatBytes(f.size)}; the limit for in-app hashing is ${formatBytes(MAX_FILE)}.`);
      return;
    }
    setBusy(true);
    try {
      setFile({ name: f.name, size: f.size, data: new Uint8Array(await f.arrayBuffer()) });
    } catch (e) {
      setError(`Could not read file: ${(e as Error).message}`);
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Hashing runs locally with Web Crypto (SHA family) and a built-in MD5. Files are read into memory and never uploaded.</PrivacyNote>
      {file ? (
        <div className="tile flex items-center gap-3 px-3 py-2.5">
          <FileUp className="size-4 text-muted" />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13.5px]">{file.name}</div>
            <div className="text-[12px] text-muted">{formatBytes(file.size)}</div>
          </div>
          <Button size="sm" variant="ghost" onPress={() => setFile(null)}>
            <X className="size-3.5" />
            Hash text instead
          </Button>
        </div>
      ) : (
        <TextAreaInput label="Text (UTF-8)" value={text} onChange={setText} rows={4} mono placeholder="Text to hash" />
      )}
      <div className="flex flex-wrap items-center gap-3">
        <input ref={fileRef} type="file" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} aria-hidden tabIndex={-1} />
        <Button size="sm" variant="tertiary" onPress={() => fileRef.current?.click()}>
          <FileUp className="size-3.5" />
          Hash a file
        </Button>
        <SwitchInput label="Uppercase hex" isSelected={upper} onChange={setUpper} />
        {busy && <span className="text-[12.5px] text-muted">Computing…</span>}
      </div>
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2.5 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
      {hashes && (
        <ul className="flex flex-col gap-1">
          {ALGOS.map((a) => {
            const v = upper ? hashes[a].toUpperCase() : hashes[a];
            return (
              <li key={a} className="tile flex items-center gap-3 px-3 py-2">
                <span className="w-20 shrink-0 text-[12.5px] text-muted">{a}</span>
                <code data-selectable className="min-w-0 flex-1 font-mono text-[12.5px] break-all">{v}</code>
                <CopyButton text={v} label={`Copy ${a}`} />
              </li>
            );
          })}
        </ul>
      )}
      {!file && !text && <p className="text-[12px] text-muted">Shown values are the digests of empty input.</p>}
    </div>
  );
}

/* ───────────────────────── User-Agent parser ───────────────────────── */

export function UserAgentTool() {
  const [ua, setUa] = useState("");
  const parsed = useMemo(() => (ua.trim() ? parseUserAgent(ua) : null), [ua]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <TextAreaInput label="User-Agent string" value={ua} onChange={setUa} rows={3} mono placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) …" />
      <div>
        <Button size="sm" variant="tertiary" onPress={() => setUa(navigator.userAgent)}>
          Use this app's User-Agent
        </Button>
      </div>
      {parsed ? (
        <>
          {parsed.bot.isBot && <ToneChip tone="warning">Automated client: {parsed.bot.name}</ToneChip>}
          <KeyValues
            mono={false}
            rows={[
              { k: "Browser / client", v: `${parsed.browser.name}${parsed.browser.version ? ` ${parsed.browser.version}` : ""}` },
              { k: "Rendering engine", v: `${parsed.engine.name}${parsed.engine.version ? ` ${parsed.engine.version}` : ""}` },
              { k: "Operating system", v: `${parsed.os.name}${parsed.os.version ? ` ${parsed.os.version}` : ""}` },
              { k: "Device type", v: parsed.device },
            ]}
          />
          <p className="text-[12px] text-muted">User-Agent strings are self-reported and trivially spoofed; treat this as a hint, not identification.</p>
        </>
      ) : (
        <EmptyBlock compact icon={Fingerprint} title="Paste a User-Agent" description="Browser, engine, operating system, device type and known bots or scanners are detected." />
      )}
    </div>
  );
}
