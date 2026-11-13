// SPDX-License-Identifier: Apache-2.0
import { Button, Checkbox, Label } from "@heroui/react";
import { AlertTriangle, FileUp, FolderOpen, Hash, RefreshCw, Search, Upload, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock, InlineSpinner } from "@/components/ui/Feedback";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { VtAnalysisStatus, VtLookupResult, VtPickedFile, VtUploadEvent } from "@/lib/types";
import { cn, formatBytes } from "@/lib/utils";
import { ReportView } from "./ReportView";

/** Poll interval for analysis status. Each poll is one request against the 4/minute public quota. */
const POLL_MS = 20_000;
const POLL_LIMIT_MS = 30 * 60_000;

const PHASE_LABEL: Record<VtUploadEvent["phase"], string> = {
  confirming: "Waiting for your confirmation in the system dialog…",
  preparing: "Verifying the file and preparing a temporary copy…",
  uploading: "Uploading to VirusTotal…",
  processing: "Upload finished; waiting for VirusTotal to accept it…",
};

function HashRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 py-1">
      <dt className="w-16 shrink-0 text-[12px] text-muted">{label}</dt>
      <dd className="min-w-0 flex-1 truncate font-mono text-[12.5px]" data-selectable title={value}>
        {value}
      </dd>
      <CopyButton text={value} label={`Copy ${label}`} />
    </div>
  );
}

export function FileAnalysis({ hasKey }: { hasKey: boolean }) {
  const { navigate } = useApp();
  const [file, setFile] = useState<VtPickedFile | null>(null);
  const [picking, setPicking] = useState(false);
  const [pickError, setPickError] = useState<string | null>(null);

  const [hashResult, setHashResult] = useState<VtLookupResult | null>(null);
  const [hashLoading, setHashLoading] = useState(false);
  const [hashError, setHashError] = useState<string | null>(null);

  const [acknowledged, setAcknowledged] = useState(false);
  const [progress, setProgress] = useState<VtUploadEvent | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<VtAnalysisStatus | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [report, setReport] = useState<VtLookupResult | null>(null);
  const pollStarted = useRef(0);
  const [pollTick, setPollTick] = useState(0);

  const reset = () => {
    setHashResult(null);
    setHashError(null);
    setAcknowledged(false);
    setProgress(null);
    setUploadError(null);
    setAnalysisId(null);
    setAnalysis(null);
    setAnalysisError(null);
    setReport(null);
  };

  const pick = async () => {
    setPicking(true);
    setPickError(null);
    try {
      const f = await api.vtFilePick();
      if (f) {
        if (file) api.vtFileForget(file.handle).catch(() => undefined);
        reset();
        setFile(f);
      }
    } catch (e) {
      setPickError(errorMessage(e));
    } finally {
      setPicking(false);
    }
  };

  const clear = () => {
    if (file) api.vtFileForget(file.handle).catch(() => undefined);
    setFile(null);
    reset();
  };

  const checkHash = async (refresh = false) => {
    if (!file) return;
    setHashLoading(true);
    setHashError(null);
    try {
      const r = await api.vtLookup(file.sha256, refresh);
      setHashResult(r);
      if (r.source === "live") invalidate("vt", "activity");
    } catch (e) {
      setHashError(errorMessage(e));
    } finally {
      setHashLoading(false);
    }
  };

  const upload = async () => {
    if (!file || !acknowledged) return;
    setUploading(true);
    setUploadError(null);
    setProgress({ phase: "confirming", sent: 0, total: file.size });
    try {
      const r = await api.vtFileUpload(file.handle, setProgress);
      completedSha.current = null;
      setAnalysisId(r.analysisId);
      setAnalysis(null);
      setReport(null);
      pollStarted.current = Date.now();
      setPollTick((t) => t + 1);
      invalidate("activity");
      notify.success("File uploaded; VirusTotal is analysing it");
    } catch (e) {
      const kind = (e as { kind?: string }).kind;
      if (kind === "cancelled") notify.info("Upload cancelled — nothing was sent");
      else setUploadError(errorMessage(e));
    } finally {
      // every upload needs a fresh acknowledgement
      setAcknowledged(false);
      setUploading(false);
      setProgress(null);
    }
  };

  // poll the analysis until it completes, then load the full file report (retrying on the
  // next tick if that request is refused, e.g. by the 4/minute limit)
  const completedSha = useRef<string | null>(null);
  useEffect(() => {
    if (!analysisId || report) return;
    let cancelled = false;
    const timer = setTimeout(
      async () => {
        try {
          if (!completedSha.current) {
            const st = await api.vtAnalysis(analysisId);
            if (cancelled) return;
            setAnalysis(st);
            setAnalysisError(null);
            if (st.status === "completed") completedSha.current = st.sha256 ?? file?.sha256 ?? null;
          }
          if (completedSha.current) {
            const r = await api.vtLookup(completedSha.current, true);
            if (cancelled) return;
            setReport(r);
            setAnalysisError(null);
            invalidate("vt");
            return;
          }
        } catch (e) {
          if (!cancelled) setAnalysisError(errorMessage(e));
        }
        if (!cancelled && Date.now() - pollStarted.current < POLL_LIMIT_MS) setPollTick((t) => t + 1);
      },
      pollTick <= 1 ? 3_000 : POLL_MS,
    );
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [analysisId, pollTick, report, file]);

  const pct = progress && progress.total > 0 ? Math.round((progress.sent / progress.total) * 100) : 0;
  const polling = !!analysisId && !report && Date.now() - pollStarted.current < POLL_LIMIT_MS;

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Choose a file"
        description="The file is read and hashed on this computer. Nothing is sent to VirusTotal in this step."
        actions={
          file && (
            <Button size="sm" variant="ghost" onPress={clear} isDisabled={uploading}>
              <X className="size-3.5" />
              Clear
            </Button>
          )
        }
      >
        {file ? (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 truncate text-[15px] font-medium" data-selectable title={file.name}>
                {file.name}
              </span>
              <ToneChip tone="default" dot={false}>
                {formatBytes(file.size)}
              </ToneChip>
            </div>
            <dl className="panel-inset px-3 py-1.5">
              <HashRow label="SHA-256" value={file.sha256} />
              <HashRow label="SHA-1" value={file.sha1} />
              <HashRow label="MD5" value={file.md5} />
            </dl>
            <div>
              <Button size="sm" variant="tertiary" onPress={pick} isPending={picking} isDisabled={uploading}>
                <FolderOpen className="size-3.5" />
                Choose another file…
              </Button>
            </div>
          </div>
        ) : (
          <EmptyBlock
            compact
            icon={FileUp}
            title="No file selected"
            description="Pick a file with the system file picker. ExploitX never modifies or deletes it."
            action={
              <Button size="sm" variant="primary" onPress={pick} isPending={picking}>
                <FolderOpen className="size-3.5" />
                Choose file…
              </Button>
            }
          />
        )}
        {pickError && <ErrorBlock className="mt-3" message={pickError} />}
      </Panel>

      {file && (
        <Panel
          title="Check for an existing report"
          description="Sends only the SHA-256 hash to VirusTotal — not the file."
          actions={
            <Button size="sm" variant="primary" onPress={() => checkHash(false)} isPending={hashLoading} isDisabled={!hasKey}>
              <Hash className="size-3.5" />
              Look up hash
            </Button>
          }
        >
          {!hasKey && <p className="text-[13px] text-muted">VirusTotal is not configured on this installation, so lookups and uploads are unavailable.</p>}
          {hashLoading && !hashResult && <InlineSpinner label="Looking up the hash…" />}
          {hashError && <ErrorBlock message={hashError} onRetry={() => checkHash(true)} />}
          {hashResult && (
            <div className="-mx-1">
              <ReportView result={hashResult} refreshing={hashLoading} onRefresh={() => checkHash(true)} />
            </div>
          )}
          {!hashResult && !hashLoading && !hashError && hasKey && (
            <p className="text-[13px] text-muted">Most files that matter already have a report. Check the hash first; you may not need to upload anything.</p>
          )}
        </Panel>
      )}

      {file && (
        <Panel title="Upload for a new analysis" description="Optional. Use only for files you are allowed to share publicly.">
          <div className="rounded-xl bg-danger-soft/60 p-4" role="note">
            <div className="flex items-center gap-2 text-[14px] font-semibold text-danger-soft-foreground">
              <AlertTriangle className="size-4" />
              Uploading makes the file public
            </div>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-[13px] text-foreground/90">
              <li>This is a standard public submission, not a private scan.</li>
              <li>VirusTotal keeps the file and shares it with its partners and the security community. Premium users can download submitted files.</li>
              <li>Never upload sensitive, confidential, proprietary or personal files: documents, source code, internal builds, credentials, customer or employee data.</li>
              <li>The upload counts toward your VirusTotal quota. Your original file is not modified; a temporary copy is uploaded and deleted afterwards.</li>
            </ul>
          </div>

          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-[12.5px] text-muted">
            <span>
              Method: {file.uploadMode === "direct" ? "standard upload (up to 32 MB)" : "large-file upload through a one-time VirusTotal upload URL (up to 650 MB); some accounts may not be permitted to use it"}
            </span>
            <span>Your limit: {formatBytes(file.limitBytes)}</span>
          </div>

          {!file.withinLimit ? (
            <div className="mt-3 flex flex-wrap items-center gap-3 text-[13px] text-warning-soft-foreground">
              This file is larger than your upload limit.
              <Button size="sm" variant="tertiary" onPress={() => navigate("settings")}>
                Change the limit in Settings
              </Button>
            </div>
          ) : (
            <div className="mt-4 flex flex-col gap-3">
              <Checkbox isSelected={acknowledged} onChange={setAcknowledged} isDisabled={uploading || !hasKey}>
                <Checkbox.Content className="flex items-start gap-2.5">
                  <Checkbox.Control className="mt-0.5">
                    <Checkbox.Indicator />
                  </Checkbox.Control>
                  <Label className="text-[13px] font-normal">
                    I understand this file will be shared publicly through VirusTotal, and it contains no sensitive, confidential, proprietary or personal data.
                  </Label>
                </Checkbox.Content>
              </Checkbox>
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="danger" onPress={upload} isDisabled={!acknowledged || uploading || !hasKey} isPending={uploading && progress?.phase === "confirming"}>
                  <Upload className="size-3.5" />
                  Upload to VirusTotal…
                </Button>
                {uploading && progress && progress.phase !== "confirming" && progress.phase !== "processing" && (
                  <Button variant="ghost" onPress={() => api.vtFileCancel(file.handle).catch((e) => notify.error("Could not cancel the upload", e))}>
                    Cancel upload
                  </Button>
                )}
                <span className="text-[12px] text-muted">A system dialog asks you to confirm before anything is sent.</span>
              </div>
            </div>
          )}

          {uploading && progress && (
            <div className="mt-4" aria-live="polite">
              <div className="mb-1.5 flex items-center justify-between text-[12.5px]">
                <span>{PHASE_LABEL[progress.phase]}</span>
                {progress.phase === "uploading" && (
                  <span className="tabular text-muted">
                    {formatBytes(progress.sent)} of {formatBytes(progress.total)}
                  </span>
                )}
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label="Upload progress">
                <div className={cn("h-full rounded-full bg-accent transition-[width]", progress.phase !== "uploading" && progress.phase !== "processing" && "w-1/4 animate-pulse")} style={progress.phase === "uploading" || progress.phase === "processing" ? { width: `${progress.phase === "processing" ? 100 : pct}%` } : undefined} />
              </div>
            </div>
          )}
          {uploadError && <ErrorBlock className="mt-3" message={uploadError} />}
        </Panel>
      )}

      {analysisId && (
        <Panel
          title="Analysis"
          description="VirusTotal analyses new files within minutes. Status is checked every 20 seconds (each check uses one request of your quota)."
          actions={
            !report && (
              <Button size="sm" variant="ghost" onPress={() => setPollTick((t) => t + 1)}>
                <RefreshCw className="size-3.5" />
                Check now
              </Button>
            )
          }
        >
          <div className="flex flex-wrap items-center gap-3 text-[13px]">
            <span className="text-muted">Analysis ID</span>
            <code className="min-w-0 truncate font-mono text-[12px]" data-selectable>
              {analysisId}
            </code>
            <CopyButton text={analysisId} label="Copy analysis ID" />
            <ToneChip tone={analysis?.status === "completed" ? "success" : "accent"}>{analysis ? analysis.status.replace("-", " ") : "queued"}</ToneChip>
            {analysis && analysis.status !== "queued" && (
              <span className="tabular text-muted">
                {analysis.stats.malicious} malicious · {analysis.stats.suspicious} suspicious · {analysis.stats.undetected} undetected{analysis.status === "completed" ? "" : " so far"}
              </span>
            )}
          </div>
          {polling && !analysisError && (
            <div className="mt-3">
              <InlineSpinner label="Waiting for VirusTotal to finish…" />
            </div>
          )}
          {analysisError && <p className="mt-3 text-[12.5px] text-warning-soft-foreground">{analysisError} Retrying automatically.</p>}
          {!polling && !report && <p className="mt-3 text-[12.5px] text-muted">Stopped checking after 30 minutes. Use Check now, or look up the hash later.</p>}
        </Panel>
      )}

      {report && <ReportView result={report} refreshing={false} onRefresh={() => api.vtLookup(report.indicator, true).then(setReport).catch((e) => notify.error("Could not refresh", e))} />}

      {!file && (
        <p className="flex items-center gap-2 px-1 text-[12.5px] text-muted">
          <Search className="size-3.5" />
          Already have a hash? Paste it in Indicator lookup instead — no file needed.
        </p>
      )}
    </div>
  );
}
