// SPDX-License-Identifier: Apache-2.0
import { Button, ProgressBar } from "@heroui/react";
import { listen } from "@tauri-apps/api/event";
import { Download, RefreshCw, RotateCcw, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { ErrorBlock, InlineSpinner } from "@/components/ui/Feedback";
import { SelectInput, SwitchInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage, IpcError } from "@/lib/ipc";
import type { UpdateStatus } from "@/lib/types";
import { formatBytes, formatDate, formatDateTime, formatRelative } from "@/lib/utils";
import { FREQUENCY_OPTIONS, INSTALL_KIND_LABEL, lastResultText, PHASE_META, platformLabel, progressPercent, updateActions } from "./updateModel";

function useUpdateStatus(runtime: boolean) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(() => {
    api.updateStatus().then(setStatus, (e) => setError(errorMessage(e)));
  }, []);
  useEffect(() => {
    if (!runtime) return;
    refresh();
    let un: (() => void) | undefined;
    let disposed = false;
    // progress and state changes are pushed by the backend
    listen<UpdateStatus>("update-status", (e) => setStatus(e.payload))
      .then((fn) => (disposed ? fn() : (un = fn)))
      .catch(() => undefined);
    return () => {
      disposed = true;
      un?.();
    };
  }, [runtime, refresh]);
  return { status, setStatus, error };
}

export function UpdatesPanel() {
  const { runtime } = useApp();
  const { status: s, setStatus, error } = useUpdateStatus(runtime);
  const [busy, setBusy] = useState<string | null>(null);

  const run = async (label: string, fn: () => Promise<UpdateStatus>, after?: (s: UpdateStatus) => void) => {
    setBusy(label);
    try {
      const next = await fn();
      setStatus(next);
      after?.(next);
    } catch (e) {
      if (!(e instanceof IpcError && e.kind === "cancelled")) notify.error(`Could not ${label}`, e);
    } finally {
      setBusy(null);
    }
  };

  const check = () =>
    run("check for updates", api.updateCheck, (next) => {
      if (next.phase === "upToDate") notify.success("ExploitX is up to date", `Version ${next.currentVersion} is the latest stable release.`);
      else if (next.phase === "failed" && next.error) notify.error("Update check failed", next.error.message);
    });

  if (!runtime) {
    return (
      <Panel title="Updates">
        <p className="text-[13px] text-muted">The desktop runtime is not connected.</p>
      </Panel>
    );
  }
  if (!s) {
    return <Panel title="Updates">{error ? <ErrorBlock message={error} /> : <InlineSpinner label="Loading update status…" />}</Panel>;
  }

  const actions = updateActions(s);
  const meta = PHASE_META[s.phase];
  const pct = progressPercent(s.progress);
  const rel = s.available;

  return (
    <Panel
      title="Updates"
      description="Signed releases from the ExploitX update feed. Updates are downloaded and installed only when you choose to."
      actions={<ToneChip tone={meta.tone}>{meta.label}</ToneChip>}
    >
      <dl className="grid grid-cols-[150px_1fr] gap-y-1.5 text-[13px]">
        <dt className="text-muted">Installed version</dt>
        <dd>ExploitX {s.currentVersion}</dd>
        <dt className="text-muted">Platform</dt>
        <dd>
          {platformLabel(s)} · {INSTALL_KIND_LABEL[s.installKind]}
        </dd>
        <dt className="text-muted">Channel</dt>
        <dd>Stable</dd>
        <dt className="text-muted">Last check</dt>
        <dd>
          {s.lastCheck ? (
            <span title={formatDateTime(s.lastCheck)}>
              {formatRelative(s.lastCheck)}
              {lastResultText(s) && <span className="text-muted"> · {lastResultText(s)}</span>}
            </span>
          ) : (
            "never"
          )}
        </dd>
        {s.configured && s.autoCheck && s.nextCheck && (
          <>
            <dt className="text-muted">Next automatic check</dt>
            <dd>{new Date(s.nextCheck).getTime() <= Date.now() ? "within a few minutes" : formatDateTime(s.nextCheck)}</dd>
          </>
        )}
      </dl>

      {!s.configured && (
        <p className="panel-inset mt-3 px-3 py-2 text-[12.5px] text-muted">
          This build has no update feed (development and local builds do not check for updates). Release builds check the project's GitHub release feed.
        </p>
      )}
      {s.warning && <Notice tone="warning">{s.warning}</Notice>}
      {s.configured && !s.supported && s.supportNote && <Notice tone="warning">{s.supportNote}</Notice>}
      {s.supported && s.supportNote && (rel || s.phase === "ready") && <p className="mt-3 text-[12px] text-muted">{s.supportNote}</p>}

      {rel && (
        <div className="tile mt-4 px-3 py-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="text-[14px] font-medium">ExploitX {rel.version}</div>
            <div className="text-[12px] text-muted">
              {[rel.date && `Released ${formatDate(rel.date)}`, rel.size && formatBytes(rel.size)].filter(Boolean).join(" · ")}
            </div>
          </div>
          {rel.notes ? (
            <div data-selectable className="scroll-area mt-2 max-h-56 text-[12.5px] leading-relaxed whitespace-pre-wrap text-muted">
              {rel.notes}
            </div>
          ) : (
            <p className="mt-2 text-[12.5px] text-muted">No release notes were published with this version.</p>
          )}
        </div>
      )}

      {(s.phase === "downloading" || s.phase === "verifying") && (
        <div className="mt-4" aria-live="polite">
          <ProgressBar aria-label="Update download" value={pct ?? 0} isIndeterminate={s.phase === "verifying" || pct === null} size="sm">
            <div className="mb-1.5 flex items-center justify-between text-[12.5px]">
              <span>{s.phase === "verifying" ? "Verifying the signature…" : "Downloading…"}</span>
              {s.progress && s.phase === "downloading" && (
                <span className="tabular text-muted">
                  {formatBytes(s.progress.downloaded)}
                  {s.progress.total ? ` of ${formatBytes(s.progress.total)}` : ""}
                </span>
              )}
            </div>
            <ProgressBar.Track>
              <ProgressBar.Fill />
            </ProgressBar.Track>
          </ProgressBar>
        </div>
      )}

      {s.phase === "ready" && (
        <div className="mt-4 flex flex-col gap-2">
          <p className="flex items-center gap-2 text-[13px]">
            <ShieldCheck className="size-4 shrink-0 text-success-soft-foreground" />
            The download matches the ExploitX signing key. It is ready to install.
          </p>
          {s.blockers.length > 0 && (
            <Notice tone="warning">
              Finish or stop this work before installing:
              <ul className="mt-1 list-disc pl-5">
                {s.blockers.map((b) => (
                  <li key={b}>{b}</li>
                ))}
              </ul>
            </Notice>
          )}
        </div>
      )}
      {s.phase === "installing" && (
        <div className="mt-4">
          <InlineSpinner label={s.os === "windows" ? "Starting the installer…" : "Installing the update…"} />
        </div>
      )}
      {s.phase === "restartRequired" && <p className="mt-4 text-[13px]">The update is installed. Restart ExploitX to start the new version.</p>}
      {s.phase === "cancelled" && <p className="mt-4 text-[13px] text-muted">The download was cancelled. Nothing was installed.</p>}
      {s.error && (s.phase === "failed" || s.phase === "ready") && <ErrorBlock className="mt-4" message={s.error.message} />}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {actions.restart && (
          <Button variant="primary" onPress={() => api.updateRestart().catch((e) => notify.error("Could not restart", e))}>
            <RotateCcw className="size-3.5" />
            Restart now
          </Button>
        )}
        {actions.install && (
          <Button variant="primary" isDisabled={actions.installBlocked || !!busy} isPending={busy === "install the update"} onPress={() => run("install the update", api.updateInstall)}>
            <ShieldCheck className="size-3.5" />
            Install and restart…
          </Button>
        )}
        {actions.download && (
          <Button variant="primary" isDisabled={!!busy} isPending={busy === "download the update"} onPress={() => run("download the update", api.updateDownload)}>
            <Download className="size-3.5" />
            {s.phase === "available" ? "Download" : "Download again"}
          </Button>
        )}
        {actions.cancel && (
          <Button variant="ghost" onPress={() => run("cancel the download", api.updateCancel)}>
            <X className="size-3.5" />
            Cancel download
          </Button>
        )}
        <Button variant="tertiary" isDisabled={!actions.check || !!busy} isPending={s.phase === "checking" || busy === "check for updates"} onPress={check}>
          <RefreshCw className="size-3.5" />
          Check for updates
        </Button>
        {actions.install && <span className="text-[12px] text-muted">A system dialog asks you to confirm before ExploitX closes.</span>}
      </div>

      <div className="mt-5 flex flex-col gap-3">
        <SwitchInput
          label="Check for updates automatically"
          description="Only the small update manifest is fetched. Nothing is downloaded or installed without your approval."
          isSelected={s.autoCheck}
          onChange={(v) => run("save the update setting", () => api.updateSettingsSet(v, s.frequencyHours))}
        />
        {s.autoCheck && (
          <SelectInput
            className="max-w-[240px]"
            label="How often"
            value={String(s.frequencyHours)}
            options={FREQUENCY_OPTIONS}
            onChange={(v) => run("save the update setting", () => api.updateSettingsSet(s.autoCheck, Number(v)))}
          />
        )}
      </div>
    </Panel>
  );
}

function Notice({ tone, children }: { tone: "warning"; children: React.ReactNode }) {
  return (
    <div className={tone === "warning" ? "mt-3 flex items-start gap-2 rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground" : ""}>
      <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
      <div className="min-w-0">{children}</div>
    </div>
  );
}
