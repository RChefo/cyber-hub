// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { Copy, Crosshair, Radar } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { EmptyBlock } from "@/components/ui/Feedback";
import { TextAreaInput } from "@/components/ui/Fields";
import { copyText } from "@/lib/actions";
import { formatNumber } from "@/lib/utils";
import { defang, extractIocs, IOC_KINDS, iocCount, type IocKind } from "../lib/ioc";
import { PrivacyNote, Segmented } from "./shared";

/** Kinds the Threat Intel page can look up. */
const LOOKUP: IocKind[] = ["url", "domain", "ipv4", "ipv6", "md5", "sha1", "sha256"];
/** Pasted text beyond this is not read (keeps the window responsive). */
const MAX_INPUT = 2_000_000;

export function IocTool() {
  const { navigate } = useApp();
  const [text, setText] = useState("");
  const [style, setStyle] = useState<"plain" | "defanged">("defanged");
  const result = useMemo(() => extractIocs(text.slice(0, MAX_INPUT)), [text]);
  const total = iocCount(result);
  const shown = (v: string, k: IocKind) => (style === "defanged" ? defang(v, k) : v);
  const all = IOC_KINDS.filter((k) => result[k.id].length > 0)
    .map((k) => `# ${k.label}\n${result[k.id].map((v) => shown(v, k.id)).join("\n")}`)
    .join("\n\n");

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <TextAreaInput
        label="Text"
        value={text}
        onChange={setText}
        rows={8}
        placeholder="Paste a report, an e-mail, a log or a ticket. Defanged indicators (hxxp, [.], [@]) are recognized."
        description={text.length > MAX_INPUT ? `Only the first ${formatNumber(MAX_INPUT)} characters are read.` : undefined}
      />
      {!text.trim() ? (
        <EmptyBlock compact icon={Crosshair} title="Paste text to extract indicators" description="URLs, domains, IPv4 and IPv6 addresses, e-mail addresses, MD5, SHA-1, SHA-256 and SHA-512 hashes, and CVE IDs. File names such as report.pdf are not taken for domains." />
      ) : total === 0 ? (
        <EmptyBlock compact icon={Crosshair} title="No indicators found" />
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[13px] text-muted">{formatNumber(total)} indicators</span>
            <div className="flex items-center gap-2">
              <Segmented
                ariaLabel="Output style"
                value={style}
                onChange={setStyle}
                options={[
                  { id: "defanged", label: "Defanged" },
                  { id: "plain", label: "Plain" },
                ]}
              />
              <Button size="sm" variant="secondary" onPress={() => void copyText(all, `${formatNumber(total)} indicators copied`)}>
                <Copy className="size-3.5" />
                Copy all
              </Button>
            </div>
          </div>
          {IOC_KINDS.filter((k) => result[k.id].length > 0).map((k) => (
            <section key={k.id} className="tile flex flex-col gap-1.5 px-3 py-2.5" aria-label={k.label}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-medium">
                  {k.label} <span className="text-muted">{formatNumber(result[k.id].length)}</span>
                </span>
                <Button size="sm" variant="ghost" className="h-7" onPress={() => void copyText(result[k.id].map((v) => shown(v, k.id)).join("\n"), `${k.label} copied`)}>
                  <Copy className="size-3.5" />
                  Copy
                </Button>
              </div>
              <ul className="max-h-48 overflow-auto font-mono text-[12.5px]">
                {result[k.id].map((v) => (
                  <li key={v} className="flex items-center gap-2 py-0.5">
                    <span className="min-w-0 flex-1 break-all">{shown(v, k.id)}</span>
                    {LOOKUP.includes(k.id) && (
                      <Button size="sm" variant="ghost" isIconOnly className="size-6 min-w-6" aria-label={`Look up ${v} in Threat Intel`} onPress={() => navigate("threatintel", { q: v })}>
                        <Radar className="size-3.5" />
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
