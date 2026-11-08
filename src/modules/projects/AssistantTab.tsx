import { Button, Checkbox, Label } from "@heroui/react";
import { Bot, Eye, RotateCcw, Send } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { CodeBlock } from "@/components/ui/Code";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, InlineSpinner } from "@/components/ui/Feedback";
import { TextAreaInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import type { AssistantContextOptions, Project } from "@/lib/types";
import { cn } from "@/lib/utils";

const SECTIONS: { key: keyof AssistantContextOptions; label: string }[] = [
  { key: "scope", label: "Scope and rules of engagement" },
  { key: "assets", label: "Assets" },
  { key: "vulnerabilities", label: "Vulnerabilities" },
  { key: "findings", label: "Findings" },
  { key: "timeline", label: "Recent activity" },
];

interface Turn {
  role: "user" | "assistant" | "error";
  text: string;
  meta?: string;
}

export function AssistantTab({ project }: { project: Project }) {
  const { runtime } = useApp();
  const status = useQuery(["system"], () => api.assistantStatus(), [], runtime);
  const [options, setOptions] = useState<AssistantContextOptions>({ scope: true, assets: true, vulnerabilities: true, findings: true, timeline: false });
  const [conversation, setConversation] = useState<string | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [question, setQuestion] = useState("");
  const [sending, setSending] = useState(false);
  const [preview, setPreview] = useState<{ text: string; chars: number } | null>(null);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // a block body: scrollIntoView returns a Promise in current WebView2 versions, which an effect must not return
    end.current?.scrollIntoView({ block: "end" });
  }, [turns.length]);

  const reset = () => {
    if (conversation) void api.assistantForget(conversation);
    setConversation(null);
    setTurns([]);
  };

  const ask = async () => {
    const q = question.trim();
    if (!q) return;
    setSending(true);
    setTurns((t) => [...t, { role: "user", text: q }]);
    setQuestion("");
    try {
      const r = await api.assistantAsk(project.id, conversation, q, options);
      setConversation(r.conversationId);
      const a = r.answer;
      setTurns((t) => [
        ...t,
        {
          role: "assistant",
          text: a.text,
          meta: `${a.fallback ? `Answered by the fallback model ${a.model} because ${a.fallbackFrom ?? "the first model"} declined the request` : `Answered by ${a.model}`} · ${a.inputTokens.toLocaleString()} in${a.cacheReadTokens ? ` (${a.cacheReadTokens.toLocaleString()} cached)` : ""} / ${a.outputTokens.toLocaleString()} out`,
        },
      ]);
    } catch (e) {
      setTurns((t) => [...t, { role: "error", text: errorMessage(e) }]);
    } finally {
      setSending(false);
    }
  };

  const showPreview = async () => {
    try {
      setPreview(await api.assistantContextPreview(project.id, options));
    } catch (e) {
      notify.error("Could not prepare the project data", e);
    }
  };

  if (status.data && !status.data.configured) {
    return (
      <Panel title="Assistant">
        <EmptyBlock
          icon={Bot}
          title="The assistant is not set up"
          description="The application owner provisions an Anthropic API key with the cyberhub-keys tool (cyberhub-keys set anthropic). Keys are never entered in the app."
        />
      </Panel>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <div className="xl:col-span-8">
        <Panel
          title="Assistant"
          description={status.data ? `Answers from ${status.data.model} (${status.data.provider}) about this project's data. It has no tools: it cannot run anything or contact targets.` : undefined}
          actions={
            <Button size="sm" variant="tertiary" onPress={reset} isDisabled={turns.length === 0 || sending}>
              <RotateCcw className="size-3.5" />
              New conversation
            </Button>
          }
        >
          <div className="flex min-h-[320px] flex-col gap-3">
            {turns.length === 0 ? (
              <p className="text-[13px] text-muted">
                Ask about priorities, exposure, remediation order or what to check next. The first question sends the selected project data after you confirm it in a system dialog.
              </p>
            ) : (
              turns.map((t, i) => (
                <div
                  key={i}
                  className={cn(
                    "rounded-lg px-3 py-2 text-[13.5px] leading-relaxed whitespace-pre-wrap",
                    t.role === "user" && "ml-auto max-w-[85%] bg-accent-soft text-accent-soft-foreground",
                    t.role === "assistant" && "panel-inset text-foreground",
                    t.role === "error" && "bg-danger-soft text-danger-soft-foreground",
                  )}
                >
                  {t.text}
                  {t.meta && <div className="mt-1.5 text-[11.5px] text-muted">{t.meta}</div>}
                </div>
              ))
            )}
            {sending && <InlineSpinner label="Thinking" />}
            <div ref={end} />
          </div>
          <div className="mt-3 flex items-end gap-2">
            <TextAreaInput
              aria-label="Question"
              value={question}
              onChange={setQuestion}
              rows={2}
              placeholder="Which vulnerabilities should be fixed first, and why?"
              className="flex-1"
            />
            <Button variant="primary" onPress={ask} isPending={sending} isDisabled={!question.trim()}>
              <Send className="size-4" />
              Ask
            </Button>
          </div>
        </Panel>
      </div>
      <div className="xl:col-span-4">
        <Panel title="Project data to attach" description={conversation ? "Fixed for this conversation. Start a new conversation to change it." : "Sent with the first question, credentials redacted."}>
          <div className="flex flex-col gap-2">
            {SECTIONS.map((s) => (
              <Checkbox key={s.key} isSelected={options[s.key]} isDisabled={!!conversation} onChange={(v) => setOptions((o) => ({ ...o, [s.key]: v }))}>
                <Checkbox.Content className="flex items-center gap-2">
                  <Checkbox.Control>
                    <Checkbox.Indicator />
                  </Checkbox.Control>
                  <Label className="text-[13px] font-normal">{s.label}</Label>
                </Checkbox.Content>
              </Checkbox>
            ))}
            <Button size="sm" variant="secondary" className="mt-1 self-start" onPress={showPreview}>
              <Eye className="size-3.5" />
              Preview exactly what is sent
            </Button>
          </div>
        </Panel>
      </div>
      <AppModal isOpen={!!preview} onOpenChange={(o) => !o && setPreview(null)} title="Project data for the assistant" description={preview ? `${preview.chars.toLocaleString()} characters, wrapped as untrusted data` : undefined} size="lg">
        {preview && <CodeBlock code={preview.text} maxHeight={480} />}
      </AppModal>
    </div>
  );
}
