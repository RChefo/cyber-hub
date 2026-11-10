import { Button } from "@heroui/react";
import { KeyRound, Pencil, Plus, RefreshCw, Rss, Search, Trash2 } from "lucide-react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { TaxiiCollection, TaxiiServer, TaxiiServerInput } from "@/lib/types";
import { formatRelative, pluralize } from "@/lib/utils";
import { editDropsCollections, editDropsCredential, editKeepsPasswordOfOtherUser } from "./taxiiCredential";

const STATUS_TONE: Record<string, "success" | "warning" | "danger" | "default"> = { succeeded: "success", partial: "warning", failed: "danger", running: "default" };

function ServerForm({ initial, onClose }: { initial: TaxiiServer | null; onClose: () => void }) {
  const [f, setF] = useState<TaxiiServerInput>(() =>
    initial
      ? { id: initial.id, name: initial.name, discoveryUrl: initial.discoveryUrl, auth: initial.auth, username: initial.username, headerName: initial.headerName, reliability: initial.reliability, defaultConfidence: initial.defaultConfidence }
      : { name: "", discoveryUrl: "https://", auth: "none", username: "", headerName: "", reliability: "", defaultConfidence: null },
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const save = async () => {
    setSaving(true);
    try {
      await api.taxiiServerSave(f);
      invalidate("ti");
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title={initial ? "Edit TAXII server" : "Add a TAXII server"}
      description="Only the server's address and how to authenticate are kept here. A password or API key is typed into a dialog of the operating system, never into this window, and kept in the OS credential store, never in the app's database."
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!f.name.trim() || !f.discoveryUrl.trim()}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Name" value={f.name} onChange={(v) => setF({ ...f, name: v })} isRequired />
        <TextInput label="Discovery URL" value={f.discoveryUrl} onChange={(v) => setF({ ...f, discoveryUrl: v })} mono isRequired description="https://…/taxii2/" />
        <SelectInput
          label="Authentication"
          value={f.auth}
          onChange={(v) => setF({ ...f, auth: v as TaxiiServerInput["auth"] })}
          options={[
            { id: "none", label: "None" },
            { id: "basic", label: "HTTP Basic (user name and password)" },
            { id: "header", label: "API key in a header" },
          ]}
        />
        {f.auth === "basic" && <TextInput label="User name" value={f.username} onChange={(v) => setF({ ...f, username: v })} isRequired />}
        {f.auth === "header" && <TextInput label="Header name" value={f.headerName} onChange={(v) => setF({ ...f, headerName: v })} placeholder="X-Api-Key" isRequired mono />}
        <SelectInput
          label="Source reliability"
          value={f.reliability}
          onChange={(v) => setF({ ...f, reliability: v })}
          options={[{ id: "", label: "Not judged" }, ...["A", "B", "C", "D", "E", "F"].map((r) => ({ id: r, label: r }))]}
        />
        <TextInput
          label="Confidence when an indicator gives none"
          value={f.defaultConfidence == null ? "" : String(f.defaultConfidence)}
          onChange={(v) => setF({ ...f, defaultConfidence: v.trim() === "" || Number.isNaN(Number(v)) ? null : Math.round(Number(v)) })}
          placeholder="0–100, or empty"
        />
      </div>
      {editKeepsPasswordOfOtherUser(initial, f) && (
        <p className="rounded-lg bg-white/[0.04] px-3 py-2 text-[12.5px] text-muted">
          The stored password was typed for “{initial?.username}”. If “{f.username.trim()}” has another one, replace the credential after saving.
        </p>
      )}
      {editDropsCredential(initial, f) && (
        <p className="rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
          Saving deletes the stored credential: it is never sent to another address, used for another kind of authentication or sent in another header. Store it again after saving.
        </p>
      )}
      {editDropsCollections(initial, f) && (
        <p className="rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
          Saving removes the {pluralize(initial?.collections.length ?? 0, "collection")} listed for the old address, with their synchronization history; indicators already saved from them stay, with their source. Discover the new address to list its collections.
        </p>
      )}
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

function CollectionRow({ c }: { c: TaxiiCollection }) {
  const { runtime } = useApp();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const history = useQuery(["ti"], () => (open ? api.taxiiSyncs(c.id) : Promise.resolve([])), [c.id, open], runtime);
  const sync = async () => {
    setBusy(true);
    try {
      const r = await api.taxiiSync(c.id);
      invalidate("ti");
      notify.success(
        r.status === "succeeded" ? "Feed synchronized" : r.status === "partial" ? "Feed partly synchronized" : "The synchronization failed",
        `${r.added} added, ${r.updated} updated, ${r.revoked} revoked, ${r.sighted} already saved, ${r.skipped} skipped${r.message ? ` — ${r.message}` : ""}`,
      );
    } catch (e) {
      notify.error("Not synchronized", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className="flex flex-col gap-1 rounded-[8px] bg-white/[0.02] px-2.5 py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{c.title || c.collection}</span>
        {c.lastStatus && (
          <ToneChip tone={STATUS_TONE[c.lastStatus] ?? "default"} dot={false} className="text-[10.5px]">
            {c.lastStatus} {c.lastSyncAt ? formatRelative(c.lastSyncAt) : ""}
          </ToneChip>
        )}
        <span className="text-muted">{pluralize(c.indicators, "indicator")}</span>
        <Button size="sm" variant="secondary" className="ml-auto h-7 gap-1" isDisabled={!c.canRead} isPending={busy} onPress={sync}>
          <RefreshCw className="size-3.5" />
          Sync
        </Button>
      </div>
      {c.lastError && <p className="text-danger">{c.lastError}</p>}
      {!c.canRead && <p className="text-muted">These credentials cannot read this collection.</p>}
      <details onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer text-muted">History{c.addedAfter ? ` · continues after ${c.addedAfter}` : ""}</summary>
        <ul className="mt-1 flex flex-col gap-0.5 text-[12px] text-muted">
          {(history.data ?? []).map((s) => (
            <li key={s.id}>
              {s.startedAt.slice(0, 16).replace("T", " ")} · {s.status} · {s.objects} objects in {pluralize(s.pages, "page")}: {s.added} added, {s.updated} updated, {s.revoked} revoked, {s.sighted} already saved, {s.skipped} skipped
              {s.message && ` — ${s.message}`}
            </li>
          ))}
          {history.data?.length === 0 && <li>Never synchronized.</li>}
        </ul>
      </details>
    </li>
  );
}

function ServerCard({ s, onEdit }: { s: TaxiiServer; onEdit: () => void }) {
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [credBusy, setCredBusy] = useState(false);
  const discover = async () => {
    setBusy(true);
    try {
      const r = await api.taxiiDiscover(s.id);
      invalidate("ti");
      notify.success("Collections listed", `${pluralize(r.collections.length, "collection")} on ${r.title || s.name}`);
    } catch (e) {
      notify.error("Discovery failed", e);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!(await confirm.ask({ title: "Remove this TAXII server?", body: s.credentialStored ? "Its collections, their history and its stored credential are removed. Indicators already saved from it stay, with their source." : "Its collections and their history are removed. Indicators already saved from it stay, with their source.", confirmLabel: "Remove server" }))) return;
    try {
      await api.taxiiServerDelete(s.id);
      invalidate("ti");
    } catch (e) {
      notify.error("Not removed", e);
    }
  };
  const storeCredential = async () => {
    setCredBusy(true);
    try {
      if (await api.taxiiAuthPrompt(s.id)) notify.success(s.credentialStored ? "Credential replaced" : "Credential stored", "In this computer's credential store");
      invalidate("ti");
    } catch (e) {
      notify.error("No credential stored", e);
    } finally {
      setCredBusy(false);
    }
  };
  const forgetCredential = async () => {
    setCredBusy(true);
    try {
      if (!(await api.taxiiAuthForget(s.id))) notify.success("Credential deleted", "From this computer's credential store");
      invalidate("ti");
    } catch (e) {
      notify.error("Not deleted", e);
    } finally {
      setCredBusy(false);
    }
  };
  return (
    <li className="flex flex-col gap-2 rounded-[10px] bg-white/[0.03] px-3 py-2.5 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{s.name}</span>
        <span className="text-muted">#{s.id}</span>
        {s.reliability && (
          <ToneChip tone="default" dot={false} className="text-[10.5px]">
            reliability {s.reliability}
          </ToneChip>
        )}
        <div className="ml-auto flex gap-1">
          <Button size="sm" variant="secondary" className="h-7 gap-1" isPending={busy} onPress={discover} isDisabled={s.auth !== "none" && !s.credentialStored}>
            <Search className="size-3.5" />
            Discover
          </Button>
          <Button isIconOnly size="sm" variant="ghost" aria-label={`Edit ${s.name}`} onPress={onEdit}>
            <Pencil className="size-3.5" />
          </Button>
          <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove ${s.name}`} onPress={remove}>
            <Trash2 className="size-3.5" />
          </Button>
        </div>
      </div>
      <span className="truncate font-mono text-[11.5px] text-muted">{s.discoveryUrl}</span>
      {s.auth !== "none" && (
        <div className="flex flex-wrap items-center gap-2">
          {s.credentialStored ? (
            <span className="text-muted">{s.auth === "basic" ? `HTTP Basic as ${s.username}` : `API key in ${s.headerName}`}: credential stored in the OS credential store.</span>
          ) : (
            <span className="text-warning-soft-foreground">No credential stored yet: store one, then Discover.</span>
          )}
          <Button size="sm" variant="tertiary" className="h-7 gap-1" isPending={credBusy} onPress={storeCredential}>
            <KeyRound className="size-3.5" />
            {s.credentialStored ? "Replace credential…" : "Store credential…"}
          </Button>
          {s.credentialStored && (
            <Button size="sm" variant="ghost" className="h-7" isDisabled={credBusy} onPress={forgetCredential}>
              Forget credential…
            </Button>
          )}
        </div>
      )}
      {s.collections.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {s.collections.map((c) => (
            <CollectionRow key={c.id} c={c} />
          ))}
        </ul>
      ) : (
        <span className="text-muted">{s.discoveredAt ? "The server lists no collection." : "Discover to list its collections."}</span>
      )}
      {confirm.element}
    </li>
  );
}

/** Threat Intel → TAXII feeds: STIX 2.1 indicators from TAXII 2.1 servers the analyst adds. */
export function TaxiiFeeds() {
  const { runtime } = useApp();
  const servers = useQuery(["ti"], () => api.taxiiServers(), [], runtime);
  const [editing, setEditing] = useState<TaxiiServer | "new" | null>(null);
  return (
    <Panel
      title="TAXII feeds"
      description="STIX 2.1 indicators from TAXII 2.1 servers you add. Nothing connects until you ask, and each connection is confirmed. Indicators become saved indicators with their source, confidence and validity; a feed never creates a finding."
      actions={
        <Button size="sm" variant="ghost" className="gap-1" onPress={() => setEditing("new")}>
          <Plus className="size-3.5" />
          Add server
        </Button>
      }
    >
      {servers.error ? (
        <ErrorBlock message={servers.error} onRetry={servers.reload} />
      ) : (servers.data ?? []).length === 0 ? (
        <EmptyBlock compact icon={Rss} title="No feed" description="Add a TAXII 2.1 server by its discovery URL." />
      ) : (
        <ul className="flex flex-col gap-2">
          {(servers.data ?? []).map((s) => (
            <ServerCard key={s.id} s={s} onEdit={() => setEditing(s)} />
          ))}
        </ul>
      )}
      {editing && <ServerForm initial={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </Panel>
  );
}
