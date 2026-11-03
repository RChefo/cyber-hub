import { Button } from "@heroui/react";
import { FolderOpen, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton, Kbd } from "@/components/ui/Code";
import { useConfirm } from "@/components/ui/Dialogs";
import { SwitchInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { formatBytes, modKey } from "@/lib/utils";

function NvdKeyPanel() {
  const { runtime } = useApp();
  const exists = useQuery(["system"], () => api.secretExists("nvd_api_key"), [], runtime);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const confirm = useConfirm();

  const save = async () => {
    setSaving(true);
    try {
      await api.secretSet("nvd_api_key", value);
      setValue("");
      exists.reload();
      notify.success("NVD API key saved to the system keychain");
    } catch (e) {
      notify.error("Could not save the key", e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel
      title="NVD API key"
      description="Optional. Raises the NVD rate limit for live CVE searches. Stored in your operating system's credential store — never in the database, never shown again."
      actions={exists.data !== undefined && <ToneChip tone={exists.data ? "success" : "default"}>{exists.data ? "Key stored" : "No key"}</ToneChip>}
    >
      <div className="flex flex-wrap items-end gap-2">
        <TextInput label={exists.data ? "Replace key" : "API key"} type="password" value={value} onChange={setValue} placeholder="Paste your NVD API key" className="min-w-[320px] flex-1" mono />
        <Button variant="primary" isDisabled={!value.trim() || !runtime} isPending={saving} onPress={save}>
          <KeyRound className="size-3.5" />
          Save key
        </Button>
        {exists.data && (
          <Button
            variant="danger-soft"
            onPress={async () => {
              if (await confirm.ask({ title: "Remove the NVD API key?", body: "Live CVE searches will use the anonymous rate limit.", confirmLabel: "Remove key" })) {
                await api.secretDelete("nvd_api_key").catch((e) => notify.error("Could not remove the key", e));
                exists.reload();
              }
            }}
          >
            Remove
          </Button>
        )}
      </div>
      <p className="mt-2 text-[12px] text-muted">Request a free key at nvd.nist.gov/developers/request-an-api-key.</p>
      {exists.error && <p className="mt-2 text-[12.5px] text-danger-soft-foreground">{exists.error}</p>}
      {confirm.element}
    </Panel>
  );
}

function VirusTotalKeyPanel() {
  const { runtime, navigate } = useApp();
  const exists = useQuery(["vt"], api.vtKeyStatus, [], runtime);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = useConfirm();
  const trimmed = value.trim();
  const wellFormed = /^[0-9a-fA-F]{64}$/.test(trimmed);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.vtKeySet(trimmed);
      setValue("");
      invalidate("vt");
      notify.success("VirusTotal API key verified and saved to the system keychain");
    } catch (e) {
      // backend errors never contain the key
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel
      title="VirusTotal API key"
      description="Required for VirusTotal reputation lookups. Stored in your operating system's credential store and used only by the Cyber Hub backend — never in the database, never shown again."
      actions={exists.data !== undefined && <ToneChip tone={exists.data ? "success" : "default"}>{exists.data ? "Key stored" : "No key"}</ToneChip>}
    >
      <div className="flex flex-wrap items-end gap-2">
        <TextInput
          label={exists.data ? "Replace key" : "API key"}
          type="password"
          value={value}
          onChange={(v) => {
            setValue(v);
            setError(null);
          }}
          placeholder="Paste your 64-character VirusTotal API key"
          className="min-w-[320px] flex-1"
          mono
        />
        <Button variant="primary" isDisabled={!wellFormed || !runtime} isPending={saving} onPress={save}>
          <KeyRound className="size-3.5" />
          Verify and save
        </Button>
        {exists.data && (
          <Button
            variant="danger-soft"
            onPress={async () => {
              if (await confirm.ask({ title: "Remove the VirusTotal API key?", body: "VirusTotal lookups stop working until you add a key again. Cached reports are kept.", confirmLabel: "Remove key" })) {
                await api.vtKeyDelete().catch((e) => notify.error("Could not remove the key", e));
                invalidate("vt");
              }
            }}
          >
            Remove
          </Button>
        )}
      </div>
      {trimmed && !wellFormed && <p className="mt-2 text-[12.5px] text-warning-soft-foreground">A VirusTotal API key is 64 hexadecimal characters.</p>}
      {error && <p className="mt-2 text-[12.5px] text-danger-soft-foreground">{error}</p>}
      {exists.error && <p className="mt-2 text-[12.5px] text-danger-soft-foreground">{exists.error}</p>}
      <p className="mt-2 text-[12px] text-muted">
        Saving checks the key with one lookup of 8.8.8.8, which counts toward your VirusTotal quota. Find your key under your profile at virustotal.com.{" "}
        {exists.data && (
          <button type="button" className="text-accent underline-offset-2 hover:underline focus-visible:underline" onClick={() => navigate("virustotal")}>
            Open VirusTotal lookups
          </button>
        )}
      </p>
      {confirm.element}
    </Panel>
  );
}

function DataPanel() {
  const { system, runtime } = useApp();
  const confirm = useConfirm();
  const clear = async (label: string, body: string, fn: () => Promise<void>, tags: Parameters<typeof invalidate>) => {
    if (!(await confirm.ask({ title: `Clear ${label}?`, body, confirmLabel: `Clear ${label}` }))) return;
    try {
      await fn();
      invalidate(...tags);
      notify.success(`${label[0].toUpperCase()}${label.slice(1)} cleared`);
    } catch (e) {
      notify.error(`Could not clear ${label}`, errorMessage(e));
    }
  };
  const rows: { label: string; body: string; fn: () => Promise<void>; tags: Parameters<typeof invalidate> }[] = [
    { label: "activity log", body: "Removes all recorded activity shown on the dashboard.", fn: api.activityClear, tags: ["activity"] },
    { label: "command history", body: "Removes copied and executed command history. Saved commands are kept.", fn: api.commandHistoryClear, tags: ["history"] },
    { label: "dork history", body: "Removes Google search history. Saved dorks are kept.", fn: api.dorkHistoryClear, tags: ["dorks"] },
    { label: "CVE search history", body: "Removes the list of past CVE searches. Cached CVE records are kept.", fn: api.cveHistoryClear, tags: ["cve"] },
    { label: "run history", body: "Removes finished runs and their stored output.", fn: api.execHistoryClear, tags: ["executions"] },
  ];
  return (
    <Panel title="Local data" description="Everything Cyber Hub stores lives in one folder on this computer.">
      <div className="panel-inset mb-4 flex items-center gap-2 py-1.5 pr-1.5 pl-3">
        <FolderOpen className="size-4 shrink-0 text-muted" />
        <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]">{system?.dataDir ?? "Desktop runtime not connected"}</code>
        {system && <CopyButton text={system.dataDir} label="Copy path" />}
      </div>
      <ul className="flex flex-col gap-1.5">
        {rows.map((r) => (
          <li key={r.label} className="tile flex items-center justify-between gap-3 px-3 py-2">
            <div className="min-w-0">
              <div className="text-[13.5px]">{r.label[0].toUpperCase() + r.label.slice(1)}</div>
              <div className="text-[12px] text-muted">{r.body}</div>
            </div>
            <Button size="sm" variant="tertiary" isDisabled={!runtime} onPress={() => clear(r.label, r.body, r.fn, r.tags)}>
              <Trash2 className="size-3.5" />
              Clear
            </Button>
          </li>
        ))}
      </ul>
      {confirm.element}
    </Panel>
  );
}

function PreferencesPanel() {
  const { prefs, setPref, runtime } = useApp();
  const dir = typeof prefs["wordlists.directory"] === "string" ? (prefs["wordlists.directory"] as string) : "";
  return (
    <Panel title="Preferences" description="Saved locally in the Cyber Hub database.">
      <div className="flex flex-col gap-4">
        <SwitchInput label="Collapse the sidebar" isSelected={prefs["ui.sidebarCollapsed"] === true} onChange={(v) => setPref("ui.sidebarCollapsed", v)} />
        <SwitchInput
          label="Search NVD live by default"
          description="When off, Vulnerability Intel searches the local cache until you switch to live."
          isSelected={prefs["cve.preferLive"] !== false}
          onChange={(v) => setPref("cve.preferLive", v)}
        />
        <div>
          <div className="mb-1.5 text-[12.5px] font-medium text-muted">Extra wordlist folder</div>
          <div className="flex items-center gap-2">
            <div className="panel-inset min-w-0 flex-1 truncate px-3 py-2 font-mono text-[12px]">{dir || <span className="text-muted">Not set — only the managed folder is scanned</span>}</div>
            <Button
              size="sm"
              variant="tertiary"
              isDisabled={!runtime}
              onPress={async () => {
                // the folder picker is opened by the backend; the path never comes from the web view
                try {
                  if (await api.wordlistsChooseDirectory()) invalidate("prefs");
                } catch (e) {
                  notify.error("Could not set the wordlist folder", e);
                }
              }}
            >
              Choose…
            </Button>
            {dir && (
              <Button
                size="sm"
                variant="ghost"
                onPress={async () => {
                  try {
                    await api.wordlistsClearDirectory();
                    invalidate("prefs");
                  } catch (e) {
                    notify.error("Could not clear the wordlist folder", e);
                  }
                }}
              >
                Clear
              </Button>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}

const SHORTCUTS: [string[], string][] = [
  [[modKey, "K"], "Open global search"],
  [["↑", "↓"], "Move through search results"],
  [["Enter"], "Open the selected result"],
  [["Esc"], "Close dialogs and search"],
  [["Tab"], "Move focus between controls"],
];

export default function SettingsPage() {
  const { system, catalog } = useApp();
  return (
    <div>
      <PageHeader title="Settings" description="Preferences, credentials and local data. Cyber Hub has no account, no telemetry and no background network activity." />
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <PreferencesPanel />
        <div className="flex flex-col gap-3">
          <NvdKeyPanel />
          <VirusTotalKeyPanel />
        </div>
        <DataPanel />
        <div className="flex flex-col gap-3">
          <Panel title="Privacy and safety">
            <ul className="flex flex-col gap-2 text-[13px] text-muted">
              {[
                "Local-first: all data stays in the local SQLite database and OS keychain.",
                "No telemetry and no automatic uploads. Network requests happen only when you press a button that says it sends one (live CVE search, VirusTotal lookup, DNS lookup, header fetch, opening links).",
                "VirusTotal lookups only read existing reports. Files are never uploaded and URLs are never submitted for scanning.",
                "Tools never run automatically. Every run shows the exact program and arguments and needs confirmation.",
                "Tools that touch targets run only inside an active project and only against in-scope targets.",
                "Commands run without a shell, so injected pipes or redirection have no effect.",
              ].map((t) => (
                <li key={t} className="flex items-start gap-2">
                  <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-success-soft-foreground" />
                  {t}
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Keyboard shortcuts">
            <ul className="flex flex-col gap-1.5">
              {SHORTCUTS.map(([keys, label]) => (
                <li key={label} className="flex items-center justify-between text-[13px]">
                  <span className="text-muted">{label}</span>
                  <span className="flex gap-1">{keys.map((k) => <Kbd key={k}>{k}</Kbd>)}</span>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="About">
            <dl className="grid grid-cols-[150px_1fr] gap-y-1.5 text-[13px]">
              <dt className="text-muted">Version</dt>
              <dd>{system ? `Cyber Hub ${system.appVersion}` : "—"}</dd>
              <dt className="text-muted">Database schema</dt>
              <dd>{system ? `v${system.dbSchemaVersion}` : "—"}</dd>
              <dt className="text-muted">Tool catalog</dt>
              <dd>{catalog ? `v${catalog.version} · ${catalog.tools.length} tools` : "—"}</dd>
              <dt className="text-muted">Memory in use</dt>
              <dd>{system ? `${formatBytes(system.usedMemory)} of ${formatBytes(system.totalMemory)}` : "—"}</dd>
            </dl>
          </Panel>
        </div>
      </div>
    </div>
  );
}
