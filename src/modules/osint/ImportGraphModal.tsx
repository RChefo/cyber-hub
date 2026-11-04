import { Button } from "@heroui/react";
import { FileUp } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { ErrorBlock, InlineSpinner } from "@/components/ui/Feedback";
import { SelectInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import { TypeBadge } from "./bits";
import { plural } from "./model";
import type { ImportPreview, PendingImport } from "./types";

type Target = "this" | "new";

export function ImportGraphModal({
  isOpen,
  onOpenChange,
  investigationId,
  onImported,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  investigationId: number | null;
  onImported: (r: { investigationId: number; graphId: number }) => void;
}) {
  const [pending, setPending] = useState<PendingImport | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [target, setTarget] = useState<Target>(investigationId != null ? "this" : "new");
  const [graphName, setGraphName] = useState("");
  const [busy, setBusy] = useState<"pick" | "preview" | "apply" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tokenRef = useRef<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setPending(null);
      setPreview(null);
      setError(null);
      setGraphName("");
      setTarget(investigationId != null ? "this" : "new");
    }
  }, [isOpen, investigationId]);

  const discard = () => {
    if (tokenRef.current) {
      void api.osintImportDiscard(tokenRef.current).catch(() => undefined);
      tokenRef.current = null;
    }
  };

  const close = (o: boolean) => {
    if (!o) discard();
    onOpenChange(o);
  };

  const pick = async () => {
    setBusy("pick");
    setError(null);
    try {
      const into = target === "this" ? investigationId : null;
      const p = await api.osintImportPick(into);
      if (!p) return;
      discard();
      tokenRef.current = p.token;
      setPending(p);
      setPreview(p.preview);
      setGraphName(p.preview.graphName);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const changeTarget = async (t: Target) => {
    setTarget(t);
    if (!pending) return;
    setBusy("preview");
    try {
      setPreview(await api.osintImportPreview(pending.token, t === "this" ? investigationId : null));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (!pending) return;
    setBusy("apply");
    setError(null);
    try {
      const r = await api.osintImportApply(pending.token, target === "this" ? investigationId : null, graphName.trim());
      tokenRef.current = null;
      invalidate("osint");
      notify.success("Graph imported", `${pending.fileName} → new graph “${graphName.trim() || preview?.graphName}”`);
      onImported(r);
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={close}
      size="lg"
      title="Import graph"
      description="Cyber Hub graph files (.json) and GraphML (.graphml). The import always creates a new graph; nothing existing is overwritten."
      footer={
        <>
          <Button variant="tertiary" onPress={() => close(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={apply} isDisabled={!pending || busy !== null} isPending={busy === "apply"}>
            Import as new graph
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={pending ? "tertiary" : "primary"} onPress={pick} isPending={busy === "pick"}>
          <FileUp className="size-4" />
          {pending ? "Choose another file" : "Choose file"}
        </Button>
        {pending && <span className="truncate font-mono text-[12.5px] text-muted">{pending.fileName}</span>}
        {busy === "preview" && <InlineSpinner label="Checking…" />}
      </div>

      {!pending && (
        <p className="text-[13px] text-muted">
          The file is validated first: size and element limits, duplicate IDs, entity and relationship types. You see what it contains before anything is written.
        </p>
      )}

      {pending && preview && (
        <div className="flex flex-col gap-4">
          {investigationId != null && (
            <SelectInput
              label="Import into"
              value={target}
              onChange={(v) => void changeTarget(v as Target)}
              options={[
                { id: "this", label: "This investigation", description: "Entities that already exist here are reused, not duplicated" },
                { id: "new", label: "A new investigation", description: "Created from the file's investigation details" },
              ]}
            />
          )}
          <TextInput label="Name of the new graph" value={graphName} onChange={setGraphName} placeholder={preview.graphName} />
          <div className="panel-inset grid gap-3 px-4 py-3 sm:grid-cols-4">
            <PreviewStat label="Format" value={preview.format === "json" ? "Cyber Hub" : "GraphML"} />
            <PreviewStat label="Entities" value={preview.entities.toLocaleString()} />
            <PreviewStat label="Relationships" value={preview.relationships.toLocaleString()} />
            <PreviewStat label="Evidence" value={preview.evidence.toLocaleString()} />
          </div>
          <div className="text-[13px] text-muted">
            From “{preview.investigationName}” · target {preview.target}
            {target === "this" && preview.existingMatches > 0 && <> · {plural(preview.existingMatches, "entity already exists", "entities already exist")} in this investigation</>}
          </div>
          {Object.keys(preview.byType).length > 0 && (
            <div className="flex flex-wrap gap-x-4 gap-y-2">
              {Object.entries(preview.byType).map(([t, n]) => (
                <TypeBadge key={t} type={t} label={`${t.replace(/_/g, " ")} ${n}`} />
              ))}
            </div>
          )}
          {preview.warnings.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2 text-[13px] font-medium text-foreground">
                <ToneChip tone="warning">{plural(preview.warnings.length, "note", "notes")}</ToneChip>
                Elements listed here are skipped or adjusted
              </div>
              <ul className="max-h-48 overflow-auto rounded-[10px] bg-white/[0.025] px-3 py-2 text-[12.5px] text-muted">
                {preview.warnings.map((w, i) => (
                  <li key={i} className="py-0.5 break-words">
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-[12px] text-muted">
            Imported entities and relationships start as observed (or inferred); review decisions recorded in the file are kept as notes, not adopted.
          </p>
        </div>
      )}
    </AppModal>
  );
}

function PreviewStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[12px] text-muted">{label}</div>
      <div className="tabular mt-0.5 text-[16px] font-semibold text-foreground">{value}</div>
    </div>
  );
}
