import { Button, Switch } from "@heroui/react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { TiProviderStatus } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { availability } from "@/modules/threatintel/model";

const KIND_LABEL: Record<string, string> = { ip: "IPs", domain: "domains", url: "URLs", file: "hashes" };

/** One provider: what it does, whether it is available, and an on/off switch. No credentials. */
function ProviderRow({ p }: { p: TiProviderStatus }) {
  const { runtime } = useApp();
  const a = availability(p);
  return (
    <li className="tile flex flex-col gap-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-medium">{p.name}</span>
            <ToneChip tone={a.tone}>{a.label}</ToneChip>
          </div>
          <p className="mt-1 max-w-[72ch] text-[12.5px] text-muted">
            {p.description} Looks up {p.kinds.map((k) => KIND_LABEL[k]).join(", ")}.
          </p>
        </div>
        <Switch
          size="sm"
          isSelected={p.enabled}
          isDisabled={!runtime || !p.configured}
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
      <div className="flex flex-col gap-0.5 text-[12px] text-muted">
        <span>{p.serviceNote}</span>
        {a.detail && <span className={a.tone === "danger" ? "text-danger-soft-foreground" : a.tone === "warning" ? "text-warning-soft-foreground" : undefined}>{a.detail}</span>}
        {p.health && (
          <span>
            Last request {formatRelative(p.health.at)}
            {p.health.quota && ` · ${p.health.quota}`}
          </span>
        )}
      </div>
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
      description="Services are configured by the application owner. Turn a provider off to stop sending it indicators. Availability reflects the last request made since ExploitX started."
      className="xl:col-span-2"
    >
      {overview.error && <ErrorBlock message={overview.error} onRetry={overview.reload} />}
      {!overview.data && !overview.error && <LoadingRows rows={3} />}
      {overview.data && (
        <>
          <ul className="grid grid-cols-1 gap-2 2xl:grid-cols-2">
            {overview.data.providers.map((p) => (
              <ProviderRow key={p.id} p={p} />
            ))}
          </ul>
          <div className="mt-3 flex items-center gap-2 text-[12.5px] text-muted">
            <StatusDot tone={overview.data.nvdConfigured ? "success" : "default"} />
            Vulnerability Intel (NVD): {overview.data.nvdConfigured ? "uses the owner-provisioned key (higher rate limit)" : "uses NVD's public rate limit (about 5 requests per 30 seconds)"}
          </div>
        </>
      )}
      <div className="mt-4">
        <UploadLimit />
      </div>
    </Panel>
  );
}
