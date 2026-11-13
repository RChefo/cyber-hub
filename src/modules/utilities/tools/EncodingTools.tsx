// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ArrowDownUp } from "lucide-react";
import { useMemo, useState } from "react";
import { SelectInput, SwitchInput, TextAreaInput } from "@/components/ui/Fields";
import { base64Decode, base64Encode, hexDecode, hexEncode, urlDecode, urlEncode } from "../lib/encoding";
import { Output, PrivacyNote, Segmented } from "./shared";

type Dir = "encode" | "decode";

function useTransform(fn: () => string, deps: unknown[]) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => {
    try {
      return { value: fn(), error: null as string | null };
    } catch (e) {
      return { value: "", error: (e as Error).message };
    }
  }, deps);
}

function DirectionBar({ dir, setDir, onSwap, canSwap }: { dir: Dir; setDir: (d: Dir) => void; onSwap: () => void; canSwap: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Segmented value={dir} onChange={setDir} ariaLabel="Direction" options={[{ id: "encode", label: "Encode" }, { id: "decode", label: "Decode" }]} />
      <Button size="sm" variant="ghost" onPress={onSwap} isDisabled={!canSwap}>
        <ArrowDownUp className="size-3.5" />
        Use output as input
      </Button>
    </div>
  );
}

export function Base64Tool() {
  const [dir, setDir] = useState<Dir>("encode");
  const [input, setInput] = useState("");
  const [urlSafe, setUrlSafe] = useState(false);
  const out = useTransform(() => (input ? (dir === "encode" ? base64Encode(input, urlSafe) : base64Decode(input)) : ""), [input, dir, urlSafe]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <DirectionBar
        dir={dir}
        setDir={setDir}
        canSwap={!!out.value}
        onSwap={() => {
          setInput(out.value);
          setDir(dir === "encode" ? "decode" : "encode");
        }}
      />
      {dir === "encode" && <SwitchInput label="Base64url (URL-safe alphabet, no padding)" isSelected={urlSafe} onChange={setUrlSafe} />}
      <TextAreaInput label={dir === "encode" ? "Text" : "Base64 or Base64url"} value={input} onChange={setInput} rows={6} mono placeholder={dir === "encode" ? "Text to encode (UTF-8)" : "SGVsbG8="} />
      <Output label={dir === "encode" ? "Base64" : "Decoded text"} value={out.value} error={out.error} />
    </div>
  );
}

export function UrlTool() {
  const [dir, setDir] = useState<Dir>("encode");
  const [mode, setMode] = useState<"component" | "uri">("component");
  const [plus, setPlus] = useState(false);
  const [input, setInput] = useState("");
  const out = useTransform(() => (input ? (dir === "encode" ? urlEncode(input, mode) : urlDecode(input, plus)) : ""), [input, dir, mode, plus]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <DirectionBar
        dir={dir}
        setDir={setDir}
        canSwap={!!out.value}
        onSwap={() => {
          setInput(out.value);
          setDir(dir === "encode" ? "decode" : "encode");
        }}
      />
      {dir === "encode" ? (
        <SelectInput
          label="Mode"
          value={mode}
          onChange={(v) => setMode(v as "component" | "uri")}
          className="max-w-sm"
          options={[
            { id: "component", label: "Component (encodeURIComponent)", description: "Encodes / ? & = # — use for parameter values" },
            { id: "uri", label: "Full URL (encodeURI)", description: "Keeps URL structure characters intact" },
          ]}
        />
      ) : (
        <SwitchInput label="Treat + as a space (form encoding)" isSelected={plus} onChange={setPlus} />
      )}
      <TextAreaInput label="Input" value={input} onChange={setInput} rows={5} mono placeholder={dir === "encode" ? "a value with spaces & symbols" : "a%20value%20with%20spaces"} />
      <Output label={dir === "encode" ? "Encoded" : "Decoded"} value={out.value} error={out.error} />
    </div>
  );
}

export function HexTool() {
  const [dir, setDir] = useState<Dir>("encode");
  const [sep, setSep] = useState("space");
  const [upper, setUpper] = useState(false);
  const [input, setInput] = useState("");
  const SEPS: Record<string, string> = { none: "", space: " ", colon: ":", "0x": " 0x", "\\x": "\\x" };
  const out = useTransform(() => {
    if (!input) return "";
    if (dir === "decode") return hexDecode(input);
    const raw = hexEncode(input, SEPS[sep], upper);
    return sep === "0x" ? `0x${raw}` : sep === "\\x" ? `\\x${raw}` : raw;
  }, [input, dir, sep, upper]);
  return (
    <div className="flex flex-col gap-4">
      <PrivacyNote />
      <DirectionBar
        dir={dir}
        setDir={setDir}
        canSwap={!!out.value}
        onSwap={() => {
          setInput(out.value);
          setDir(dir === "encode" ? "decode" : "encode");
        }}
      />
      {dir === "encode" && (
        <div className="flex flex-wrap items-end gap-4">
          <SelectInput
            label="Separator"
            value={sep}
            onChange={setSep}
            className="w-56"
            options={[
              { id: "none", label: "None (48656c6c6f)" },
              { id: "space", label: "Space (48 65 6c)" },
              { id: "colon", label: "Colon (48:65:6c)" },
              { id: "0x", label: "0x prefix (0x48 0x65)" },
              { id: "\\x", label: "\\x escapes (\\x48\\x65)" },
            ]}
          />
          <SwitchInput label="Uppercase" isSelected={upper} onChange={setUpper} />
        </div>
      )}
      <TextAreaInput
        label={dir === "encode" ? "Text" : "Hex"}
        value={input}
        onChange={setInput}
        rows={5}
        mono
        description={dir === "decode" ? "Spaces, colons, dashes, 0x and \\x prefixes are ignored." : undefined}
      />
      <Output label={dir === "encode" ? "Hex" : "Decoded text"} value={out.value} error={out.error} />
    </div>
  );
}
