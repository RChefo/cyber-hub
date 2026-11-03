/**
 * Typed bridge to the Rust backend. This is the ONLY module that calls `invoke`.
 * The frontend has no shell, filesystem or SQL access of its own.
 */
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import type { ToolCatalog } from "@/types/catalog";
import type * as T from "./types";

export const runtimeAvailable = (): boolean => isTauri();

export class IpcError extends Error {
  kind: T.AppError["kind"];
  constructor(err: T.AppError) {
    super(err.message);
    this.kind = err.kind;
  }
}

async function call<R>(cmd: string, args?: Record<string, unknown>): Promise<R> {
  if (!runtimeAvailable()) {
    throw new IpcError({
      kind: "runtime",
      message: "The desktop runtime is not available. Start Cyber Hub with `npm run tauri dev`.",
    });
  }
  try {
    return await invoke<R>(cmd, args);
  } catch (e) {
    if (e && typeof e === "object" && "message" in e && "kind" in e) throw new IpcError(e as T.AppError);
    throw new IpcError({ kind: "internal", message: String(e) });
  }
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

export const api = {
  // activity, preferences, favorites, tasks
  activityList: (limit?: number, kind?: string) => call<T.Activity[]>("activity_list", { limit, kind }),
  activityLog: (input: { kind: string; title: string; detail?: string; refKind?: string; refId?: string; projectId?: number | null }) =>
    call<void>("activity_log", { input: { detail: "", ...input } }),
  activityClear: () => call<void>("activity_clear"),
  activityDaily: (days: number) => call<T.DailyCount[]>("activity_daily", { days }),
  prefsGetAll: () => call<Record<string, unknown>>("prefs_get_all"),
  prefsSet: (key: string, value: unknown) => call<void>("prefs_set", { key, value }),
  favoritesList: () => call<T.Favorite[]>("favorites_list"),
  favoriteToggle: (kind: T.FavoriteKind, itemId: string) => call<boolean>("favorite_toggle", { kind, itemId }),
  tasksList: () => call<T.Task[]>("tasks_list"),
  taskUpsert: (input: { id?: number; title: string; done: boolean; projectId?: number | null; dueDate?: string | null }) =>
    call<number>("task_upsert", { input }),
  taskDelete: (id: number) => call<void>("task_delete", { id }),

  // libraries
  customResourcesList: () => call<T.CustomResource[]>("custom_resources_list"),
  customResourceUpsert: (input: { id?: number; title: string; url: string; category: string; description: string }) =>
    call<number>("custom_resource_upsert", { input }),
  customResourceDelete: (id: number) => call<void>("custom_resource_delete", { id }),
  resourceVisit: (resourceKey: string, title: string, url: string) => call<void>("resource_visit", { resourceKey, title, url }),
  resourceRecent: (limit = 10) => call<T.ResourceVisit[]>("resource_recent", { limit }),
  savedCommandsList: () => call<T.SavedCommand[]>("saved_commands_list"),
  savedCommandUpsert: (input: Omit<T.SavedCommand, "id" | "createdAt" | "updatedAt"> & { id?: number }) =>
    call<number>("saved_command_upsert", { input }),
  savedCommandDelete: (id: number) => call<void>("saved_command_delete", { id }),
  commandHistoryList: (limit = 100) => call<T.CommandHistoryItem[]>("command_history_list", { limit }),
  commandHistoryAdd: (command: string, source: string, toolId?: string | null, projectId?: number | null) =>
    call<void>("command_history_add", { command, source, toolId: toolId ?? null, projectId: projectId ?? null }),
  commandHistoryClear: () => call<void>("command_history_clear"),
  savedDorksList: () => call<T.SavedDork[]>("saved_dorks_list"),
  savedDorkUpsert: (input: { id?: number; title: string; query: string; category: string; notes: string }) =>
    call<number>("saved_dork_upsert", { input }),
  savedDorkDelete: (id: number) => call<void>("saved_dork_delete", { id }),
  dorkHistoryList: (limit = 50) => call<T.DorkHistoryItem[]>("dork_history_list", { limit }),
  dorkHistoryAdd: (query: string) => call<void>("dork_history_add", { query }),
  dorkHistoryClear: () => call<void>("dork_history_clear"),
  customPayloadsList: () => call<T.CustomPayload[]>("custom_payloads_list"),
  customPayloadUpsert: (input: Omit<T.CustomPayload, "id" | "createdAt"> & { id?: number }) =>
    call<number>("custom_payload_upsert", { input }),
  customPayloadDelete: (id: number) => call<void>("custom_payload_delete", { id }),

  // projects
  projectsList: () => call<T.ProjectSummary[]>("projects_list"),
  projectGet: (id: number) => call<T.Project>("project_get", { id }),
  projectUpsert: (input: {
    id?: number;
    name: string;
    description: string;
    status: T.ProjectStatus;
    scopeNotes: string;
    notes: string;
    startDate: string | null;
    endDate: string | null;
  }) => call<number>("project_upsert", { input }),
  projectDelete: (id: number) => call<void>("project_delete", { id }),
  scopeClassify: (value: string) => call<[string, string]>("scope_classify", { value }),
  projectTargetAdd: (projectId: number, input: { value: string; inScope: boolean; note: string }) =>
    call<number>("project_target_add", { projectId, input }),
  projectTargetDelete: (id: number) => call<void>("project_target_delete", { id }),
  scopeCheck: (projectId: number, targets: string[]) => call<T.ScopeCheck[]>("scope_check", { projectId, targets }),
  findingsList: (projectId?: number | null) => call<T.Finding[]>("findings_list", { projectId: projectId ?? null }),
  findingUpsert: (input: Omit<T.Finding, "id" | "createdAt" | "updatedAt"> & { id?: number }) =>
    call<number>("finding_upsert", { input }),
  findingDelete: (id: number) => call<void>("finding_delete", { id }),
  projectToolHistory: (projectId: number) => call<T.ProjectExecution[]>("project_tool_history", { projectId }),

  // tools & execution engine
  toolsCatalog: () => call<ToolCatalog>("tools_catalog"),
  toolsDetectionList: () => call<T.Detection[]>("tools_detection_list"),
  toolsScan: (probeVersions: boolean, toolIds?: string[]) => call<T.Detection[]>("tools_scan", { probeVersions, toolIds: toolIds ?? null }),
  packageManagers: () => call<T.ManagerAvailability[]>("package_managers"),
  toolInstall: (toolId: string, manager: string, onEvent: (e: T.ExecEvent) => void) => {
    const channel = new Channel<T.ExecEvent>();
    channel.onmessage = onEvent;
    return call<number>("tool_install", { toolId, manager, confirmed: true, onEvent: channel });
  },
  toolLaunch: (toolId: string) => call<void>("tool_launch", { toolId }),
  execValidate: (request: T.ExecRequest) => call<T.ExecValidation>("exec_validate", { request }),
  execStart: (request: T.ExecRequest, onEvent: (e: T.ExecEvent) => void) => {
    const channel = new Channel<T.ExecEvent>();
    channel.onmessage = onEvent;
    return call<number>("exec_start", { request, onEvent: channel });
  },
  execCancel: (executionId: number) => call<boolean>("exec_cancel", { executionId }),
  execList: (limit = 50) => call<T.ExecutionRecord[]>("exec_list", { limit }),
  execOutput: (executionId: number) => call<string>("exec_output", { executionId }),
  execHistoryClear: () => call<void>("exec_history_clear"),

  // wordlists
  wordlistsList: () => call<T.Wordlist[]>("wordlists_list"),
  // file and folder selection happens in native dialogs opened by the backend; the web view never supplies paths
  wordlistsPick: (copy: boolean, category?: string | null) => call<number[]>("wordlists_pick", { copy, category: category ?? null }),
  wordlistsChooseDirectory: () => call<string | null>("wordlists_choose_directory"),
  wordlistsClearDirectory: () => call<void>("wordlists_clear_directory"),
  wordlistsScan: () => call<number>("wordlists_scan"),
  wordlistUpdate: (id: number, name: string, category: string) => call<void>("wordlist_update", { id, name, category }),
  wordlistRemove: (id: number, deleteFile: boolean) => call<void>("wordlist_remove", { id, deleteFile }),
  wordlistPreview: (id: number, filter?: string, limit?: number) =>
    call<T.WordlistPreview>("wordlist_preview", { id, filter: filter ?? null, limit: limit ?? null }),
  wordlistExport: (id: number) => call<number | null>("wordlist_export", { id }),
  wordlistsDir: () => call<string>("wordlists_dir"),

  // intelligence & network utilities
  dnsLookup: (name: string, recordType: string) => call<T.DnsRecord[]>("dns_lookup", { name, recordType }),
  httpInspect: (url: string, method: "GET" | "HEAD") => call<T.HttpInspection>("http_inspect", { url, method }),
  cveSearch: (query: string, live: boolean) => call<T.CveSearchResult>("cve_search", { query, live }),
  cveGetCached: (id: string) => call<[T.CveRecord, string] | null>("cve_get_cached", { id }),
  cveHistory: () => call<T.CveHistoryItem[]>("cve_history"),
  cveCacheStats: () => call<[number, string | null]>("cve_cache_stats"),
  cveHistoryClear: () => call<void>("cve_history_clear"),

  // system
  systemInfo: () => call<T.SystemInfo>("system_info"),
  openTerminal: (cwd?: string | null) => call<string>("open_terminal", { cwd: cwd ?? null }),
  secretSet: (name: string, value: string) => call<void>("secret_set", { name, value }),
  secretExists: (name: string) => call<boolean>("secret_exists", { name }),
  secretDelete: (name: string) => call<void>("secret_delete", { name }),
};
