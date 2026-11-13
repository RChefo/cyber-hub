// SPDX-License-Identifier: Apache-2.0
import { Button, Checkbox, Label } from "@heroui/react";
import { ArrowDownUp, Regex } from "lucide-react";
import { useDeferredValue, useMemo, useState, type ReactNode } from "react";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { htmlEscape, htmlUnescape } from "../lib/encoding";
import { FormatError, formatHtml, formatJson, formatXml } from "../lib/format";
import { Output, PrivacyNote, Segmented } from "./shared";

/* ───────────────────────── Regex tester ───────────────────────── */

const MAX_TEXT = 200_000;
const MAX_MATCHES = 5_000;
const FLAGS = [
  { f: "g", label: "Global" },
  { f: "i", label: "Ignore case" },
  { f: "m", label: "Multiline" },
  { f: "s", label: "Dot matches newline" },
  { f: "u", label: "Unicode" },
  { f: "y", label: "Sticky" },
];

interface MatchInfo {
  index: number;
  text: string;
  groups: (string | undefined)[];
  named: Record<string, string | undefined> | undefined;
}

export function RegexTool() {
  const [pattern, setPattern] = useState("");
  const [flags, setFlags] = useState("g");
  const [text, setText] = useState("");
  const dPattern = useDeferredValue(pattern);
  const dText = useDeferredValue(text);

  const result = useMemo(() => {
    if (!dPattern) return null;
    if (dText.length > MAX_TEXT) return { error: `Test text is limited to ${MAX_TEXT.toLocaleString()} characters.` };
    let re: RegExp;
    try {
      // matchAll requires the g flag; without a user-selected g we stop after the first match.
      re = new RegExp(dPattern, flags.includes("g") ? flags : `${flags}g`);
    } catch (e) {
      return { error: (e as Error).message };
    }
    const matches: MatchInfo[] = [];
    let truncated = false;
    const started = performance.now();
    for (const m of dText.matchAll(re)) {
      matches.push({ index: m.index ?? 0, text: m[0], groups: m.slice(1), named: m.groups });
      if (!flags.includes("g")) break;
      if (matches.length >= MAX_MATCHES || performance.now() - started > 750) {
        truncated = true;
        break;
      }
    }
    return { matches, truncated, groupCount: matches[0]?.groups.length ?? 0 };
  }, [dPattern, dText, flags]);

  const highlighted = useMemo<ReactNode[]>(() => {
    if (!result || "error" in result || !result.matches.length) return [dText];
    const nodes: ReactNode[] = [];
    let last = 0;
    result.matches.forEach((m, i) => {
      if (m.index < last) return;
      nodes.push(dText.slice(last, m.index));
      nodes.push(
        <mark key={i} className="rounded-[3px] bg-accent/30 px-px text-foreground" title={`Match ${i + 1} at ${m.index}`}>
          {m.text || "​"}
        </mark>,
      );
      last = m.index + m.text.length;
    });
    nodes.push(dText.slice(last));
    return nodes;
  }, [result, dText]);

  const toggle = (f: string) => setFlags((cur) => (cur.includes(f) ? cur.replace(f, "") : cur + f));

  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Uses this app's JavaScript regex engine locally. Text is limited to 200,000 characters and 5,000 matches to keep runaway patterns from freezing the app.</PrivacyNote>
      <TextInput label="Pattern" value={pattern} onChange={setPattern} mono placeholder="(\w+)@([\w.-]+)" />
      <div className="flex flex-wrap gap-x-5 gap-y-2" role="group" aria-label="Flags">
        {FLAGS.map(({ f, label }) => (
          <Checkbox key={f} isSelected={flags.includes(f)} onChange={() => toggle(f)}>
            <Checkbox.Content className="flex items-center gap-2">
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
              <Label className="text-[13px]">
                {label} <span className="font-mono text-muted">{f}</span>
              </Label>
            </Checkbox.Content>
          </Checkbox>
        ))}
      </div>
      <TextAreaInput label="Test text" value={text} onChange={setText} rows={7} mono placeholder="Text to search" />
      {!result ? (
        <EmptyBlock compact icon={Regex} title="Enter a pattern" description="Matches are highlighted live, with capture groups listed below." />
      ) : "error" in result ? (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2.5 text-[13px] text-danger-soft-foreground">
          {result.error}
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <span className="text-[12.5px] font-medium text-muted">
              {result.matches.length.toLocaleString()} {result.matches.length === 1 ? "match" : "matches"}
              {result.truncated && " (stopped early: match or time limit reached)"}
            </span>
          </div>
          <pre data-selectable className="panel-inset scroll-area max-h-[320px] px-3.5 py-3 font-mono text-[12.5px] leading-relaxed break-all whitespace-pre-wrap">
            {highlighted}
          </pre>
          {result.matches.length > 0 && (
            <div className="panel-inset scroll-area max-h-[320px]">
              <table className="w-full text-left text-[12.5px]">
                <thead className="sticky top-0 bg-background-secondary text-muted">
                  <tr>
                    <th className="px-3 py-2 font-medium">#</th>
                    <th className="px-3 py-2 font-medium">Index</th>
                    <th className="px-3 py-2 font-medium">Match</th>
                    {Array.from({ length: result.groupCount }, (_, i) => (
                      <th key={i} className="px-3 py-2 font-medium">
                        Group {i + 1}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {result.matches.slice(0, 500).map((m, i) => (
                    <tr key={i} className="odd:bg-white/[0.02]">
                      <td className="px-3 py-1.5 text-muted">{i + 1}</td>
                      <td className="px-3 py-1.5 text-muted">{m.index}</td>
                      <td className="px-3 py-1.5 break-all">{m.text}</td>
                      {m.groups.map((g, gi) => (
                        <td key={gi} className="px-3 py-1.5 break-all">
                          {g ?? <span className="text-muted">—</span>}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              {result.matches.length > 500 && <div className="px-3 py-2 text-[12px] text-muted">Showing the first 500 matches in the table.</div>}
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ───────────────────────── Formatters ───────────────────────── */

function errorText(e: unknown): string {
  if (e instanceof FormatError && e.line) return `Line ${e.line}, column ${e.column}: ${e.message}`;
  return (e as Error).message;
}

function useFormatted(fn: () => string, deps: unknown[]) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => {
    try {
      return { value: fn(), error: null as string | null };
    } catch (e) {
      return { value: "", error: errorText(e) };
    }
  }, deps);
}

function SwapButton({ value, onUse }: { value: string; onUse: (v: string) => void }) {
  return (
    <Button size="sm" variant="ghost" onPress={() => onUse(value)} isDisabled={!value}>
      <ArrowDownUp className="size-3.5" />
      Use output as input
    </Button>
  );
}

export function JsonTool() {
  const [input, setInput] = useState("");
  const [indent, setIndent] = useState<"2" | "4" | "tab" | "0">("2");
  const [sortKeys, setSortKeys] = useState(false);
  const out = useFormatted(() => (input.trim() ? formatJson(input, { indent: indent === "tab" ? "tab" : (Number(indent) as 0 | 2 | 4), sortKeys }) : ""), [input, indent, sortKeys]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <div className="flex flex-wrap items-center gap-4">
        <Segmented
          value={indent}
          onChange={setIndent}
          ariaLabel="Output style"
          options={[
            { id: "2", label: "2 spaces" },
            { id: "4", label: "4 spaces" },
            { id: "tab", label: "Tabs" },
            { id: "0", label: "Minify" },
          ]}
        />
        <SwitchInput label="Sort keys" isSelected={sortKeys} onChange={setSortKeys} />
        <SwapButton value={out.value} onUse={setInput} />
      </div>
      <TextAreaInput label="JSON" value={input} onChange={setInput} rows={8} mono placeholder='{"name":"value"}' />
      {input.trim() && !out.error && <div className="text-[12.5px] text-success-soft-foreground">Valid JSON</div>}
      <Output label="Formatted" value={out.value} error={out.error} />
    </div>
  );
}

export function XmlTool() {
  const [input, setInput] = useState("");
  const [indent, setIndent] = useState<"2" | "4">("2");
  const out = useFormatted(() => (input.trim() ? formatXml(input, Number(indent)) : ""), [input, indent]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Parsed locally with the built-in XML parser. External entities and DTDs are never fetched.</PrivacyNote>
      <div className="flex flex-wrap items-center gap-4">
        <Segmented value={indent} onChange={setIndent} ariaLabel="Indentation" options={[{ id: "2", label: "2 spaces" }, { id: "4", label: "4 spaces" }]} />
        <SwapButton value={out.value} onUse={setInput} />
      </div>
      <TextAreaInput label="XML" value={input} onChange={setInput} rows={8} mono placeholder="<root><item id='1'>value</item></root>" />
      {input.trim() && !out.error && <div className="text-[12.5px] text-success-soft-foreground">Well-formed XML</div>}
      <Output label="Formatted" value={out.value} error={out.error} />
    </div>
  );
}

export function HtmlTool() {
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<"pretty" | "escape" | "unescape">("pretty");
  const [indent, setIndent] = useState("2");
  const out = useFormatted(() => {
    if (!input) return "";
    if (mode === "escape") return htmlEscape(input);
    if (mode === "unescape") return htmlUnescape(input);
    return formatHtml(input, Number(indent));
  }, [input, mode, indent]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote>Formatted as text only — markup is never rendered or executed.</PrivacyNote>
      <div className="flex flex-wrap items-end gap-4">
        <Segmented
          value={mode}
          onChange={setMode}
          ariaLabel="Mode"
          options={[
            { id: "pretty", label: "Pretty print" },
            { id: "escape", label: "Escape entities" },
            { id: "unescape", label: "Unescape entities" },
          ]}
        />
        {mode === "pretty" && (
          <SelectInput
            aria-label="Indentation"
            value={indent}
            onChange={setIndent}
            className="w-36"
            options={[
              { id: "2", label: "2 spaces" },
              { id: "4", label: "4 spaces" },
            ]}
          />
        )}
        <SwapButton value={out.value} onUse={setInput} />
      </div>
      <TextAreaInput label="HTML" value={input} onChange={setInput} rows={8} mono placeholder="<div><p>Hello</p></div>" />
      <Output label="Output" value={out.value} error={out.error} />
    </div>
  );
}
