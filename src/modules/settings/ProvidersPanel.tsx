import { Button, Switch } from "@heroui/react";
import { ExternalLink, KeyRound, PlugZap } from "lucide-react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify, openExternal } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { TiKeyCheck, TiKeyStatus, TiProviderStatus } from "@/lib/types";

const KIND_LABEL: Record<string, string> = { ip: "IPs", domain: "domains", url: "URLs", file: "hashes" };

function KeyRow({ k, providers }: { k: TiKeyStatus; providers: TiProviderStatus[] }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [check, setCheck] = useState<TiKeyCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const trimmed = value.trim();
  const looksValid = k.id === "virustotal" ? /^[0-9a-fA-F]{64}$/.test(trimmed) : /^[A-Za-z0-9._-]{8,256}$/.test(trimmed);
  const notes = [...new Set(providers.map((p) => p.accessNote))];

  const save = async () => {
    setBusy("save");
    setError(null);
    setCheck(null);
    try {
      const r = await api.tiKeySet(k.id, trimmed);
      setValue("");
      setCheck(r);
      invalidate("ti", "vt");
      notify.success(`${k.label} verified and saved`);
    } catch (e) {
      // backend messages never contain the key
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy("test");
    setError(null);
    try {
      setCheck(await api.tiKeyTest(k.id));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <li className="tile flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-medium">{k.label}</span>
            <ToneChip tone={k.stored ? "success" : "default"}>{k.stored ? "Key stored" : "No key"}</ToneChip>
          </div>
          {notes.map((n) => (
            <p key={n} className="mt-1 max-w-[68ch] text-[12.5px] text-muted">
              {n}
            </p>
          ))}
        </div>
        <Button size="sm" variant="ghost" onPress={() => openExternal(k.signupUrl)}>
          <ExternalLink className="size-3.5" />
          Get a key
        </Button>
      </div>

      <div className="flex flex-col gap-2">
        {providers.map((p) => (
          <div key={p.id} className="flex items-center justify-between gap-3 rounded-lg bg-white/[0.02] px-3 py-2">
            <div className="min-w-0">
              <div className="text-[13px]">{p.name}</div>
              <div className="text-[12px] text-muted">
                {p.description} Looks up {p.kinds.map((x) => KIND_LABEL[x]).join(", ")}. Cyber Hub limit: {p.rateLimit}.
              </div>
            </div>
            <Switch
              size="sm"
              isSelected={p.enabled}
              isDisabled={!runtime}
              aria-label={`Use ${p.name}`}
              onChange={(v) =>
                api
                  .tiProviderSetEnabled(p.id, v)
                  .then(() => invalidate("ti"))
                  .catch((e) => notify.error(`Could not update ${p.name}`, e))
              }
            >
              <Switch.Content>
                <Switch.Control>
                  <Switch.Thumb />
                </Switch.Control>
              </Switch.Content>
            </Switch>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <TextInput
          label={k.stored ? "Replace key" : "API key"}
          type="password"
          value={value}
          onChange={(v) => {
            setValue(v);
            setError(null);
          }}
          placeholder={`Paste your ${k.label}`}
          className="min-w-[300px] flex-1"
          mono
          onEnter={() => looksValid && save()}
        />
        <Button variant="primary" isDisabled={!looksValid || !runtime || !!busy} isPending={busy === "save"} onPress={save}>
          <KeyRound className="size-3.5" />
          Verify and save
        </Button>
        {k.stored && (
          <>
            <Button variant="tertiary" isDisabled={!!busy} isPending={busy === "test"} onPress={test}>
              <PlugZap className="size-3.5" />
              Test connection
            </Button>
            <Button
              variant="danger-soft"
              isDisabled={!!busy}
              onPress={async () => {
                if (await confirm.ask({ title: `Remove the ${k.label}?`, body: `${k.providers.join(", ")} lookups stop until you add a key again. Cached results are kept.`, confirmLabel: "Remove key" })) {
                  await api.tiKeyDelete(k.id).catch((e) => notify.error("Could not remove the key", e));
                  setCheck(null);
                  invalidate("ti", "vt");
                }
              }}
            >
              Remove
            </Button>
          </>
        )}
      </div>
      {trimmed && !looksValid && (
        <p className="text-[12.5px] text-warning-soft-foreground">
          {k.id === "virustotal" ? "A VirusTotal API key is 64 hexadecimal characters." : "Keys contain only letters, digits, '-', '_' or '.' (8–256 characters)."}
        </p>
      )}
      {check && (
        <p className={check.ok ? "text-[12.5px] text-success-soft-foreground" : "text-[12.5px] text-danger-soft-foreground"}>
          {check.message}
          {check.quota && <span className="text-muted"> · {check.quota}</span>}
        </p>
      )}
      {error && <p className="text-[12.5px] text-danger-soft-foreground">{error}</p>}
      <p className="text-[12px] text-muted">Saving checks the key with one read-only request to the provider; no lookup data is sent.</p>
      {confirm.element}
    </li>
  );
}

function UploadLimit() {
  const { prefs, setPref, runtime } = useApp();
  const current = typeof prefs["vt.uploadLimitMb"] === "number" ? (prefs["vt.uploadLimitMb"] as number) : 32;
  const [value, setValue] = useState(String(current));
  useEffect(() => setValue(String(current)), [current]);
  const n = Number(value);
  const valid = Number.isInteger(n) && n >= 1 && n <= 650;
  return (
    <div className="flex flex-wrap items-end gap-2">
      <TextInput
        label="VirusTotal upload limit (MB)"
        description="Files above this size cannot be uploaded from File analysis. VirusTotal accepts up to 650 MB; files over 32 MB use a one-time upload URL."
        value={value}
        onChange={setValue}
        className="w-[420px] max-w-full"
        error={value && !valid ? "Enter a whole number from 1 to 650" : undefined}
      />
      <Button size="sm" variant="tertiary" isDisabled={!runtime || !valid || n === current} onPress={() => setPref("vt.uploadLimitMb", n)}>
        Save limit
      </Button>
    </div>
  );
}

export function ProvidersPanel() {
  const { runtime } = useApp();
  const overview = useQuery(["ti"], api.tiProviders, [], runtime);
  return (
    <Panel
      title="Threat intelligence providers"
      description="Keys are kept in your operating system's credential store and used only by the Cyber Hub backend; they are never shown again after saving. Turn a provider off to stop sending it indicators."
      className="xl:col-span-2"
    >
      {overview.error && <ErrorBlock message={overview.error} onRetry={overview.reload} />}
      {!overview.data && !overview.error && <LoadingRows rows={3} />}
      {overview.data && (
        <ul className="flex flex-col gap-2">
          {overview.data.keys.map((k) => (
            <KeyRow key={k.id} k={k} providers={overview.data!.providers.filter((p) => p.keyId === k.id)} />
          ))}
        </ul>
      )}
      <div className="mt-4">
        <UploadLimit />
      </div>
    </Panel>
  );
}
