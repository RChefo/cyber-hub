import { Button } from "@heroui/react";
import { Download, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { EXEC_STATUS_META, ToneChip } from "@/components/ui/Badges";
import { CodeBlock } from "@/components/ui/Code";
import { AppModal } from "@/components/ui/Dialogs";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { ManagedInstall, ToolDef } from "@/types/catalog";
import { Console } from "@/modules/runs/Console";
import { createLiveHandler, useLiveRun } from "@/modules/runs/liveStore";

export function InstallDialog({ tool, recipe, isOpen, onOpenChange }: { tool: ToolDef; recipe: ManagedInstall | null; isOpen: boolean; onOpenChange: (o: boolean) => void }) {
  const { scanTools } = useApp();
  const [execId, setExecId] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const live = useLiveRun(execId);

  useEffect(() => {
    if (isOpen) setExecId(null);
  }, [isOpen]);

  if (!recipe) return null;
  const command = [recipe.manager, ...recipe.args].join(" ");
  const running = live?.status === "running";

  const start = async () => {
    setStarting(true);
    try {
      const handler = createLiveHandler(tool.id, "install", async (status) => {
        // the backend re-detects the tool after the installer exits
        invalidate("detections");
        if (status === "succeeded") notify.success(`${tool.name} installation finished`, "Detection has been refreshed.");
        else notify.error(`${tool.name} installation ${EXEC_STATUS_META[status].label.toLowerCase()}`);
        await scanTools(true, [tool.id]);
      });
      setExecId(await api.toolInstall(tool.id, recipe.manager, handler));
    } catch (e) {
      if ((e as { kind?: string }).kind === "cancelled") notify.info("Installation cancelled", "Nothing was installed.");
      else notify.error("Could not start the installer", e);
    } finally {
      setStarting(false);
    }
  };

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      size="lg"
      isDismissable={!running}
      title={`Install ${tool.name} with ${recipe.manager}`}
      description={execId === null ? "ExploitX will run exactly this command with your user account. Review it before continuing." : undefined}
      footer={
        execId === null ? (
          <>
            <Button variant="tertiary" onPress={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="primary" isPending={starting} onPress={start}>
              <Download className="size-3.5" />
              Install
            </Button>
          </>
        ) : running ? (
          <Button variant="danger" onPress={() => api.execCancel(execId).catch((e) => notify.error("Could not cancel", e))}>
            Cancel installation
          </Button>
        ) : (
          <Button variant="primary" onPress={() => onOpenChange(false)}>
            Close
          </Button>
        )
      }
    >
      {execId === null ? (
        <>
          <CodeBlock code={command} />
          <ul className="flex flex-col gap-1.5 text-[13px] text-muted">
            <li>• Downloads and installs software from the {recipe.manager} source; it may take several minutes.</li>
            <li>• Runs non-interactively. Installers that need administrator rights may fail or prompt separately.</li>
            <li>• If it fails, the tool is marked “Installation failed” and the full log is kept in Runs.</li>
          </ul>
          {recipe.manager === "go" && (
            <div className="tile flex items-start gap-2 px-3 py-2 text-[12.5px] text-warning-soft-foreground">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
              go install places binaries in $GOPATH/bin (usually ~/go/bin). Make sure that folder is on PATH, then rescan.
            </div>
          )}
        </>
      ) : (
        <>
          {live && <ToneChip tone={EXEC_STATUS_META[live.status].tone}>{EXEC_STATUS_META[live.status].label}</ToneChip>}
          <Console lines={live?.lines ?? []} height={360} />
        </>
      )}
    </AppModal>
  );
}
