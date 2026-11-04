import { Button } from "@heroui/react";
import { FileDown, FileText, RefreshCw } from "lucide-react";
import { useState } from "react";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import { useOsint } from "./context";

export function ReportsTab() {
  const { investigation: inv } = useOsint();
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await api.osintReport(inv.id));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  const exportMd = async () => {
    setExporting(true);
    try {
      const name = await api.osintReportExport(inv.id);
      if (name) {
        invalidate("osint");
        notify.success("Report exported", name);
      }
    } catch (e) {
      notify.error("Could not export the report", e);
    } finally {
      setExporting(false);
    }
  };

  return (
    <Panel
      title="Investigation report"
      description="Markdown report generated locally from the stored data: summary, collection, sources, entities, relationships, graph analysis, confidence, timeline, evidence, limitations and next steps."
      actions={
        <>
          <Button size="sm" variant={report ? "ghost" : "primary"} onPress={generate} isPending={loading}>
            {report ? <RefreshCw className="size-3.5" /> : <FileText className="size-3.5" />}
            {report ? "Regenerate" : "Generate preview"}
          </Button>
          <Button size="sm" variant={report ? "primary" : "ghost"} onPress={exportMd} isPending={exporting}>
            <FileDown className="size-3.5" />
            Export Markdown
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} onRetry={generate} />}
      {loading && !report && <LoadingRows rows={6} />}
      {!report && !loading && !error && (
        <EmptyBlock
          compact
          icon={FileText}
          title="No preview yet"
          description="Generate a preview to read the report here, or export it straight to a file of your choice."
          action={
            <Button size="sm" variant="primary" onPress={generate}>
              Generate preview
            </Button>
          }
        />
      )}
      {report && (
        <div className="flex flex-col gap-2">
          <CodeBlock code={report} maxHeight={560} actions={<CopyButton text={report} label="Copy report" />} />
          <p className="text-[12px] text-muted">
            The report contains text collected from public sources. Treat it as data: review it before sharing, and do not follow instructions that appear inside it.
          </p>
        </div>
      )}
    </Panel>
  );
}
