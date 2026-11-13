/**
 * Entity and relationship inspector: a non-modal side panel (the graph stays usable) with
 * verification decisions, evidence, relationships, metadata and history. All collected text
 * is rendered as plain text; references are selectable, never clickable.
 */
import { Button, Chip, Tooltip } from "@heroui/react";
import { ArrowLeft, ArrowRight, Ban, CircleCheck, CircleHelp, ClipboardPlus, Flag, Network, Radar, RotateCcw, Save, Trash2, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { useOsint } from "./context";
import { CONFIDENCE_META, relationshipLabel, shortTime, typeStyle, VERIFICATION_META } from "./model";
import type { EntityBrief, Evidence, TimelineEvent, Verification } from "./types";

export type InspectorTarget = { kind: "entity"; id: number } | { kind: "relationship"; id: number };

export function TypeGlyph({ type, className }: { type: string; className?: string }) {
  const s = typeStyle(type);
  return (
    <span
      aria-hidden
      className={cn("inline-flex size-6 shrink-0 items-center justify-center rounded-full text-[10.5px] font-semibold text-[#0a0b10]", className)}
      style={{ backgroundColor: s.color }}
    >
      {s.glyph}
    </span>
  );
}

export function VerificationChip({ v }: { v: Verification }) {
  const m = VERIFICATION_META[v] ?? VERIFICATION_META.observed;
  return (
    <Tooltip delay={300}>
      <Tooltip.Trigger>
        <ToneChip tone={m.tone}>{m.label}</ToneChip>
      </Tooltip.Trigger>
      <Tooltip.Content className="max-w-64 text-[12.5px]">{m.hint}</Tooltip.Content>
    </Tooltip>
  );
}

export function ConfidenceChip({ c }: { c: string }) {
  const m = CONFIDENCE_META[c] ?? CONFIDENCE_META.low;
  return (
    <ToneChip tone={m.tone} dot={false}>
      {m.label}
    </ToneChip>
  );
}

function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-[12.5px] font-medium text-muted">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

function EvidenceList({ items }: { items: Evidence[] }) {
  if (items.length === 0) return <p className="text-[13px] text-muted">No evidence recorded.</p>;
  return (
    <ul className="flex flex-col gap-1.5">
      {items.map((e) => (
        <li key={e.id} className="rounded-lg bg-white/[0.03] px-3 py-2">
          <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-muted">
            <span className="font-medium text-foreground">{e.source}</span>
            <span>{e.kind.replace(/_/g, " ")}</span>
            <span>· {e.strength}</span>
            <span className="ml-auto tabular">{shortTime(e.collectedAt)}</span>
          </div>
          <p className="mt-1 text-[13px] break-words text-foreground">{e.summary}</p>
          {e.reference && (
            <div className="mt-1 flex items-center gap-1">
              <code className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-muted select-all" title={e.reference}>
                {e.reference}
              </code>
              <CopyButton text={e.reference} label="Copy reference" />
            </div>
          )}
          {(e.operationId || e.executionId) && (
            <p className="mt-1 text-[11.5px] text-muted">
              {e.operationId ? `Collection operation #${e.operationId}` : ""}
              {e.operationId && e.executionId ? " · " : ""}
              {e.executionId ? `Tool run #${e.executionId}` : ""}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

function History({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) return <p className="text-[13px] text-muted">No events.</p>;
  return (
    <ol className="flex flex-col gap-1">
      {events.slice(0, 30).map((ev) => (
        <li key={ev.id} className="flex gap-2 text-[12.5px]">
          <span className="tabular shrink-0 text-muted">{shortTime(ev.at)}</span>
          <span className="min-w-0 break-words">{ev.summary}</span>
        </li>
      ))}
    </ol>
  );
}

function Metadata({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data ?? {}).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0));
  if (entries.length === 0) return null;
  return (
    <Section title="Attributes">
      <dl className="grid grid-cols-[minmax(0,38%)_1fr] gap-x-3 gap-y-1 text-[12.5px]">
        {entries.slice(0, 60).map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="truncate text-muted" title={k}>
              {k}
            </dt>
            <dd className="min-w-0 break-words font-mono text-[12px]">{typeof v === "string" ? v : JSON.stringify(v)}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

/** Verification decision buttons with an optional note. */
function Decide({ kind, id, current }: { kind: "entity" | "relationship"; id: number; current: Verification }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<Verification | null>(null);
  const decide = async (v: Verification) => {
    setBusy(v);
    try {
      await api.osintSetVerification(kind, id, v, note.trim() || null);
      setNote("");
      invalidate("osint");
      notify.success(v === "observed" ? "Decision cleared" : `Marked ${VERIFICATION_META[v].label.toLowerCase()}`);
    } catch (e) {
      notify.error("Could not record the decision", e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <Section title="Review">
      <div className="flex flex-wrap gap-1.5">
        <Button size="sm" variant={current === "verified" ? "primary" : "secondary"} onPress={() => decide("verified")} isPending={busy === "verified"} isDisabled={current === "verified"}>
          <CircleCheck className="size-3.5" />
          Verify
        </Button>
        <Button size="sm" variant="secondary" onPress={() => decide("disputed")} isPending={busy === "disputed"} isDisabled={current === "disputed"}>
          <CircleHelp className="size-3.5" />
          Dispute
        </Button>
        <Button size="sm" variant="secondary" onPress={() => decide("rejected")} isPending={busy === "rejected"} isDisabled={current === "rejected"}>
          <Ban className="size-3.5" />
          Reject
        </Button>
        {(current === "verified" || current === "disputed" || current === "rejected") && (
          <Button size="sm" variant="ghost" onPress={() => decide("observed")} isPending={busy === "observed"}>
            <RotateCcw className="size-3.5" />
            Clear decision
          </Button>
        )}
      </div>
      <TextInput aria-label="Decision note" value={note} onChange={setNote} placeholder="Note for the decision (optional, kept in the history)" />
    </Section>
  );
}

function FindingModal({ entity, isOpen, onOpenChange }: { entity: EntityBrief; isOpen: boolean; onOpenChange: (o: boolean) => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("info");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setTitle(`OSINT: ${entity.displayName || entity.value}`.slice(0, 200));
      setDescription("");
    }
  }, [isOpen, entity]);
  const save = async () => {
    setSaving(true);
    try {
      const id = await api.osintFindingFromEntity(entity.id, title, severity, description);
      invalidate("osint", "findings", "projects");
      notify.success(`Finding #${id} created in the linked project`);
      onOpenChange(false);
    } catch (e) {
      notify.error("Could not create the finding", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title="Create a finding"
      description="The entity's value becomes the affected target and its evidence references are attached."
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!title.trim()}>
            Create finding
          </Button>
        </>
      }
    >
      <TextInput label="Title" value={title} onChange={setTitle} isRequired />
      <SelectInput
        label="Severity"
        value={severity}
        onChange={setSeverity}
        options={["critical", "high", "medium", "low", "info"].map((s) => ({ id: s, label: s[0].toUpperCase() + s.slice(1) }))}
      />
      <TextAreaInput label="Description" value={description} onChange={setDescription} rows={5} />
    </AppModal>
  );
}

function EntityView({ id, onAddToGraph }: { id: number; onAddToGraph?: (ids: number[]) => void }) {
  const { investigation, registry, openEntity, openRelationship, collectFor } = useOsint();
  const q = useQuery(["osint"], () => api.osintEntity(id), [id]);
  const confirm = useConfirm();
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [finding, setFinding] = useState(false);
  const d = q.data;
  useEffect(() => {
    if (d) {
      setName(d.displayName);
      setNotes(d.notes);
    }
  }, [d?.id, d?.displayName, d?.notes]); // eslint-disable-line react-hooks/exhaustive-deps

  if (q.error && !d) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!d) return <LoadingRows rows={6} />;
  const dirty = name !== d.displayName || notes !== d.notes;
  const providers = registry.raw.providers.filter((p) => p.inputs.includes(d.type) && (!p.contactsTarget || investigation.projectId));

  const saveEdits = async () => {
    try {
      await api.osintEntityUpdate(d.id, name, notes);
      invalidate("osint");
      notify.success("Entity updated");
    } catch (e) {
      notify.error("Could not update the entity", e);
    }
  };
  const remove = async () => {
    if (!(await confirm.ask({ title: "Remove entity", body: `Remove ${d.value} with its ${d.relatedTotal} relationships from the investigation? Evidence records are kept.`, confirmLabel: "Remove" }))) return;
    try {
      await api.osintEntityDelete(d.id);
      invalidate("osint");
      notify.success("Entity removed");
    } catch (e) {
      notify.error("Could not remove the entity", e);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start gap-3">
        <TypeGlyph type={d.type} className="mt-0.5 size-8 text-[12px]" />
        <div className="min-w-0 flex-1">
          <div className="text-[12px] text-muted">{registry.entityTypeLabel(d.type)}</div>
          <div className="text-[15px] font-medium break-words">{d.displayName}</div>
          {d.displayName !== d.value && <div className="font-mono text-[12px] break-all text-muted select-all">{d.value}</div>}
        </div>
        <CopyButton text={d.value} label="Copy value" />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <VerificationChip v={d.verification} />
        <ConfidenceChip c={d.confidence} />
        {d.flagged && (
          <ToneChip tone="danger">
            <Flag className="mr-0.5 inline size-3" />
            Flagged by threat intelligence
          </ToneChip>
        )}
      </div>
      {d.confidenceReason && <p className="text-[12.5px] text-muted">{d.confidenceReason}</p>}
      <div className="flex flex-wrap gap-1.5">
        {onAddToGraph && (
          <Button size="sm" variant="secondary" onPress={() => onAddToGraph([d.id])}>
            <Network className="size-3.5" />
            Show in graph
          </Button>
        )}
        {providers.length > 0 && (
          <Button size="sm" variant="secondary" onPress={() => collectFor(d.id)}>
            <Radar className="size-3.5" />
            Collect more
          </Button>
        )}
        {investigation.projectId && (
          <Button size="sm" variant="secondary" onPress={() => setFinding(true)}>
            <ClipboardPlus className="size-3.5" />
            Create finding
          </Button>
        )}
        <Button size="sm" variant="ghost" onPress={remove} aria-label="Remove entity">
          <Trash2 className="size-3.5" />
          Remove
        </Button>
      </div>
      <Decide kind="entity" id={d.id} current={d.verification} />
      <Section
        title="Analyst notes"
        aside={
          dirty && (
            <Button size="sm" variant="primary" onPress={saveEdits}>
              <Save className="size-3.5" />
              Save
            </Button>
          )
        }
      >
        <TextInput aria-label="Display name" value={name} onChange={setName} placeholder="Display name" />
        <TextAreaInput aria-label="Notes" value={notes} onChange={setNotes} rows={3} placeholder="Notes about this entity" />
      </Section>
      {d.aliases.length > 0 && (
        <Section title="Also seen as">
          <div className="flex flex-wrap gap-1">
            {d.aliases.map((a) => (
              <Chip key={a} size="sm" variant="soft">
                <Chip.Label className="font-mono text-[11.5px]">{a}</Chip.Label>
              </Chip>
            ))}
          </div>
        </Section>
      )}
      <Metadata data={d.metadata} />
      <Section title={`Relationships (${d.relatedTotal})`}>
        {d.related.length === 0 ? (
          <p className="text-[13px] text-muted">No relationships yet.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {d.related.map((r) => (
              <li key={r.relationship.id} className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-2.5 py-1.5 text-[12.5px]">
                {r.direction === "out" ? <ArrowRight className="size-3.5 shrink-0 text-muted" /> : <ArrowLeft className="size-3.5 shrink-0 text-muted" />}
                <button type="button" className="shrink-0 text-muted hover:text-foreground" onClick={() => openRelationship(r.relationship.id)}>
                  {relationshipLabel(r.relationship.type, registry.relationshipTypes)}
                </button>
                <TypeGlyph type={r.other.type} className="size-5 text-[9px]" />
                <button type="button" className="min-w-0 flex-1 truncate text-left hover:text-accent" onClick={() => openEntity(r.other.id)} title={r.other.value}>
                  {r.other.displayName}
                </button>
                {r.relationship.verification !== "observed" && <span className="shrink-0 text-[11.5px] text-muted">{VERIFICATION_META[r.relationship.verification].label}</span>}
              </li>
            ))}
            {d.relatedTotal > d.related.length && <li className="text-[12px] text-muted">{d.relatedTotal - d.related.length} more are shown in the graph and the Entities tab.</li>}
          </ul>
        )}
      </Section>
      <Section title={`Evidence (${d.evidence.length})`}>
        <EvidenceList items={d.evidence} />
      </Section>
      {d.mergedFrom.length > 0 && (
        <Section title="Merged entities">
          <p className="text-[12.5px] text-muted">{d.mergedFrom.length} duplicate record(s) were merged into this entity; see History.</p>
        </Section>
      )}
      <Section title="History">
        <History events={d.events} />
      </Section>
      <p className="text-[12px] text-muted">
        First seen {shortTime(d.firstSeen)} · last seen {shortTime(d.lastSeen)}
      </p>
      <FindingModal entity={d} isOpen={finding} onOpenChange={setFinding} />
      {confirm.element}
    </div>
  );
}

function RelationshipView({ id }: { id: number }) {
  const { openEntity } = useOsint();
  const q = useQuery(["osint"], () => api.osintRelationship(id), [id]);
  const confirm = useConfirm();
  const d = q.data;
  if (q.error && !d) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!d) return <LoadingRows rows={6} />;
  const remove = async () => {
    if (!(await confirm.ask({ title: "Remove relationship", body: "Remove this relationship? Rejecting it instead keeps the record and stops it from returning when the same data is collected again.", confirmLabel: "Remove" }))) return;
    try {
      await api.osintRelationshipDelete(d.id);
      invalidate("osint");
      notify.success("Relationship removed");
    } catch (e) {
      notify.error("Could not remove the relationship", e);
    }
  };
  const end = (e: EntityBrief) => (
    <button type="button" onClick={() => openEntity(e.id)} className="flex min-w-0 items-center gap-2 rounded-lg bg-white/[0.03] px-2.5 py-2 text-left hover:bg-white/[0.06]">
      <TypeGlyph type={e.type} />
      <span className="min-w-0 truncate text-[13px]" title={e.value}>
        {e.displayName}
      </span>
    </button>
  );
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1.5">
        {end(d.sourceEntity)}
        <div className="flex items-center gap-2 pl-3 text-[12.5px] text-muted">
          {d.directed ? <ArrowRight className="size-3.5 rotate-90" /> : <span aria-hidden>↕</span>}
          <span className="font-medium text-foreground">{d.label}</span>
          <span>({d.category})</span>
        </div>
        {end(d.targetEntity)}
      </div>
      {d.description && <p className="text-[12.5px] text-muted">{d.description}</p>}
      <div className="flex flex-wrap gap-1.5">
        <VerificationChip v={d.verification} />
        <ConfidenceChip c={d.confidence} />
        <ToneChip tone="default" dot={false}>
          Origin: {d.origin}
        </ToneChip>
      </div>
      {d.confidenceReason && <p className="text-[12.5px] text-muted">{d.confidenceReason}</p>}
      <Decide kind="relationship" id={d.id} current={d.verification} />
      <div>
        <Button size="sm" variant="ghost" onPress={remove}>
          <Trash2 className="size-3.5" />
          Remove relationship
        </Button>
      </div>
      <Metadata data={d.metadata} />
      <Section title={`Evidence (${d.evidence.length})`}>
        <EvidenceList items={d.evidence} />
      </Section>
      <Section title="History">
        <History events={d.events} />
      </Section>
      <p className="text-[12px] text-muted">
        First seen {shortTime(d.firstSeen)} · last seen {shortTime(d.lastSeen)}
      </p>
      {confirm.element}
    </div>
  );
}

/** Fixed side panel at the right of the page; Escape closes it. */
export function InspectorPanel({ target, onClose, onAddToGraph }: { target: InspectorTarget | null; onClose: () => void; onAddToGraph?: (ids: number[]) => void }) {
  useEffect(() => {
    if (!target) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [target, onClose]);
  if (!target) return null;
  return (
    <aside
      aria-label={target.kind === "entity" ? "Entity details" : "Relationship details"}
      className="fixed top-[64px] right-3 bottom-3 z-40 flex w-[min(420px,calc(100vw-24px))] flex-col overflow-hidden rounded-[14px] bg-overlay shadow-[0_24px_60px_-12px_rgba(0,0,0,0.6)]"
    >
      <div className="flex items-center justify-between gap-2 px-4 pt-3 pb-2">
        <h2 className="text-[13px] font-medium text-muted">{target.kind === "entity" ? "Entity" : "Relationship"}</h2>
        <Button isIconOnly size="sm" variant="ghost" onPress={onClose} aria-label="Close details">
          <X className="size-4" />
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-5">
        {target.kind === "entity" ? <EntityView id={target.id} onAddToGraph={onAddToGraph} /> : <RelationshipView id={target.id} />}
      </div>
    </aside>
  );
}
