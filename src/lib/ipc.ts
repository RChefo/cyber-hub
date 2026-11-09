/**
 * Typed bridge to the Rust backend. This is the ONLY module that calls `invoke`.
 * The frontend has no shell, filesystem or SQL access of its own.
 */
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import type { ToolCatalog } from "@/types/catalog";
import type * as O from "@/modules/osint/types";
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
  } & T.Engagement) => call<number>("project_upsert", { input }),
  projectDelete: (id: number) => call<void>("project_delete", { id }),
  scopeClassify: (value: string) => call<[string, string]>("scope_classify", { value }),
  projectTargetAdd: (projectId: number, input: { value: string; inScope: boolean; note: string }) =>
    call<number>("project_target_add", { projectId, input }),
  projectTargetDelete: (id: number) => call<void>("project_target_delete", { id }),
  scopeCheck: (projectId: number, targets: string[]) => call<T.ScopeCheck[]>("scope_check", { projectId, targets }),
  findingsList: (projectId?: number | null) => call<T.Finding[]>("findings_list", { projectId: projectId ?? null }),
  findingUpsert: (input: T.FindingInput) => call<number>("finding_upsert", { input }),
  findingDelete: (id: number) => call<void>("finding_delete", { id }),
  findingSetStatus: (id: number, status: T.FindingStatus, note?: string) => call<T.FindingStatus>("finding_set_status", { id, status, note: note ?? null }),
  findingAddNote: (id: number, note: string) => call<void>("finding_add_note", { id, note }),
  findingHistory: (id: number) => call<T.FindingEvent[]>("finding_history", { id }),
  findingLinks: (id: number) => call<T.FindingLink[]>("finding_links", { id }),
  findingLink: (id: number, kind: T.FindingLinkKind, refId: number) => call<boolean>("finding_link", { id, kind, refId }),
  findingUnlink: (id: number, kind: T.FindingLinkKind, refId: number) => call<boolean>("finding_unlink", { id, kind, refId }),
  // shared project data (schema 9, docs/DATA_MODEL.md)
  assetsList: (projectId: number, filter: { kind?: T.AssetType; status?: T.AssetStatus; limit?: number; offset?: number } = {}) =>
    call<T.Asset[]>("assets_list", { projectId, kind: filter.kind ?? null, status: filter.status ?? null, limit: filter.limit ?? null, offset: filter.offset ?? null }),
  assetAdd: (input: { projectId: number; type: T.AssetType; value: string; confidence?: T.Confidence; data?: unknown }) =>
    call<T.Asset>("asset_add", { input: { ...input, source: "manual" } }),
  assetSetStatus: (id: number, status: T.AssetStatus) => call<T.Asset>("asset_set_status", { id, status }),
  assetObservations: (id: number) => call<T.AssetObservation[]>("asset_observations", { id }),
  assetDelete: (id: number) => call<void>("asset_delete", { id }),
  scopeHistory: (projectId: number, limit?: number) => call<T.ScopeEvent[]>("scope_history", { projectId, limit: limit ?? null }),
  scopeDecide: (projectId: number | null, targets: string[], mode: "passive" | "active") => call<T.ScopeDecision>("scope_decide", { projectId, targets, mode }),
  projectTimeline: (projectId: number, opts: { types?: T.TimelineEventType[]; before?: string; limit?: number } = {}) =>
    call<T.TimelineEvent[]>("project_timeline", { projectId, types: opts.types ?? null, before: opts.before ?? null, limit: opts.limit ?? null }),
  evidenceList: (projectId: number) => call<T.EvidenceRecord[]>("evidence_list", { projectId }),
  evidenceAddText: (projectId: number, title: string, content: string, description?: string) =>
    call<T.EvidenceRecord>("evidence_add_text", { projectId, title, content, description: description ?? null }),
  evidenceAddFile: (projectId: number, title?: string, description?: string) =>
    call<T.EvidenceRecord | null>("evidence_add_file", { projectId, title: title ?? null, description: description ?? null }),
  evidenceLinkExecution: (projectId: number, executionId: number, title?: string) =>
    call<T.EvidenceRecord>("evidence_link_execution", { projectId, executionId, title: title ?? null }),
  evidenceLinkOsint: (projectId: number, osintEvidenceId: number) => call<T.EvidenceRecord>("evidence_link_osint", { projectId, osintEvidenceId }),
  evidenceExport: (id: number) => call<string | null>("evidence_export", { id }),
  evidenceVerify: (projectId: number) => call<T.EvidenceIntegrity>("evidence_verify", { projectId }),
  evidenceDelete: (id: number) => call<void>("evidence_delete", { id }),
  scanImportPick: (projectId: number, options: T.ScanImportOptions) => call<T.ScanImportPending | null>("scan_import_pick", { projectId, options }),
  scanImportPreview: (token: string, options: T.ScanImportOptions) => call<T.ScanImportPreview>("scan_import_preview", { token, options }),
  scanImportRemap: (token: string, mapping: T.CsvMapping, options: T.ScanImportOptions) => call<T.ScanImportPreview>("scan_import_remap", { token, mapping, options }),
  scanImportCommit: (token: string, options: T.ScanImportOptions) => call<T.ScanImportResult>("scan_import_commit", { token, options }),
  scanImportDiscard: (token: string) => call<void>("scan_import_discard", { token }),
  scanImportsList: (projectId: number) => call<T.ScanImportRecord[]>("scan_imports_list", { projectId }),
  // API security: definitions, collections and captures read into an endpoint inventory (nothing is contacted)
  apiSpecImport: (projectId: number) => call<T.ApiSpecSummary | null>("api_spec_import", { projectId }),
  apiSpecsList: (projectId: number) => call<T.ApiSpecSummary[]>("api_specs_list", { projectId }),
  apiSpecGet: (id: number) => call<T.ApiSpecView>("api_spec_get", { id }),
  apiSpecDelete: (id: number) => call<void>("api_spec_delete", { id }),
  apiIssueRecord: (specId: number, issueId: string) => call<T.ApiRecordedIssue>("api_issue_record", { specId, issueId }),
  // SBOM analysis: reading contacts nothing; sbomCheck asks OSV.dev with package URLs only
  sbomImport: (projectId: number) => call<T.SbomSummary | null>("sbom_import", { projectId }),
  sbomsList: (projectId: number) => call<T.SbomSummary[]>("sboms_list", { projectId }),
  sbomGet: (id: number) => call<T.SbomView>("sbom_get", { id }),
  sbomCheck: (id: number) => call<T.SbomCheck>("sbom_check", { id }),
  sbomRecord: (id: number, keys: string[]) => call<T.SbomRecorded>("sbom_record", { id, keys }),
  sbomDelete: (id: number) => call<void>("sbom_delete", { id }),
  // Container and Kubernetes configuration checks (local only)
  containerScanText: (text: string, kind: string) => call<T.ContainerFileReport>("container_scan_text", { text, kind }),
  containerScanPick: (folder: boolean) => call<T.ContainerScan | null>("container_scan_pick", { folder }),
  // Packet capture and log triage (local only)
  pcapAnalyzePick: () => call<{ file: string; report: T.CaptureReport } | null>("pcap_analyze_pick"),
  logAnalyzeText: (text: string) => call<T.LogReport>("log_analyze_text", { text }),
  logAnalyzePick: () => call<{ file: string; report: T.LogReport } | null>("log_analyze_pick"),
  findingTemplatesList: () => call<T.FindingTemplate[]>("finding_templates_list"),
  findingTemplateSave: (input: T.FindingTemplateInput) => call<T.FindingTemplate>("finding_template_save", { input }),
  findingTemplateDelete: (id: number) => call<void>("finding_template_delete", { id }),
  findingTemplateUsed: (id: number) => call<void>("finding_template_used", { id }),
  findingTemplatesAddStarters: () => call<number>("finding_templates_add_starters"),
  findingTemplatesExport: () => call<string | null>("finding_templates_export"),
  findingTemplatesImport: () => call<T.LibraryImport | null>("finding_templates_import"),
  cvssScore: (vector: string) => call<T.CvssResult>("cvss_score", { vector }),
  findingsBulkEdit: (ids: number[], edit: { addTags: string[]; removeTags: string[]; assignee: string | null }) =>
    call<{ changed: number[]; skipped: [number, string][] }>("findings_bulk_edit", { ids, edit }),
  findingsExport: (projectId: number, ids: number[], format: "csv" | "json" | "sarif") => call<string | null>("findings_export", { projectId, ids, format }),
  wstgCatalog: () => call<T.WstgCatalog>("wstg_catalog"),
  databaseBackup: () => call<{ fileName: string; size: number } | null>("database_backup"),
  databaseRestoreInspect: () => call<{ token: string; info: T.BackupInfo } | null>("database_restore_inspect"),
  databaseRestoreApply: (token: string) => call<T.BackupInfo>("database_restore_apply", { token }),
  databaseRestoreOutcome: () => call<T.RestoreOutcome | null>("database_restore_outcome"),
  databaseRestorePending: () => call<boolean>("database_restore_pending"),
  databaseRestoreCancel: () => call<boolean>("database_restore_cancel"),
  checklistItems: (projectId: number) => call<T.ChecklistItem[]>("checklist_items", { projectId }),
  checklistSet: (projectId: number, testId: string, status: T.ChecklistStatus, note: string, findingId: number | null, unlink = false) =>
    call<T.ChecklistItem>("checklist_set", { projectId, testId, status, note, findingId, unlink }),
  tiSavedExportStix: () => call<{ fileName: string; exported: number; skipped: string[] } | null>("ti_saved_export_stix"),
  reportHtml: (projectId: number, options: T.ReportOptions) => call<string>("report_html", { projectId, options }),
  reportExportHtml: (projectId: number, options: T.ReportOptions) => call<string | null>("report_export_html", { projectId, options }),
  reportSaveEvidence: (projectId: number, options: T.ReportOptions) => call<T.EvidenceRecord>("report_save_evidence", { projectId, options }),
  reportPrinted: (projectId: number) => call<void>("report_printed", { projectId }),
  // attack surface discovery
  discoveryPassiveStart: (projectId: number) => call<number>("discovery_passive_start", { projectId }),
  discoveryHttpStart: (projectId: number, hosts?: string[]) => call<number>("discovery_http_start", { projectId, hosts: hosts?.length ? hosts : null }),
  discoveryScanStart: (projectId: number, targets: string[], profile: "quick" | "standard") =>
    call<{ snapshotId: number; executionId: number }>("discovery_scan_start", { projectId, targets, profile }),
  discoveryCancel: (projectId: number) => call<boolean>("discovery_cancel", { projectId }),
  discoveryRunning: (projectId: number) => call<number | null>("discovery_running", { projectId }),
  discoverySnapshots: (projectId: number, limit?: number) => call<T.DiscoverySnapshot[]>("discovery_snapshots", { projectId, limit: limit ?? null }),
  discoveryChanges: (snapshotId: number) => call<T.SnapshotChanges>("discovery_changes", { snapshotId }),
  // vulnerabilities
  vulnsList: (projectId: number) => call<T.Vulnerability[]>("vulns_list", { projectId }),
  vulnAdd: (input: { projectId: number; cveId: string; assetId?: number | null; exposure?: T.Exposure; criticality?: T.Confidence; exploitKnown?: boolean; notes?: string }) =>
    call<{ vulnerability: T.Vulnerability; warnings: string[] }>("vuln_add", { input }),
  vulnsRefresh: (projectId: number) => call<{ updated: number; warnings: string[] }>("vulns_refresh", { projectId }),
  vulnSetContext: (id: number, exposure: T.Exposure, criticality: T.Confidence, exploitKnown: boolean) =>
    call<T.Vulnerability>("vuln_set_context", { id, exposure, criticality, exploitKnown }),
  vulnSetStatus: (id: number, status: T.VulnStatus, note?: string) => call<T.Vulnerability>("vuln_set_status", { id, status, note: note ?? null }),
  vulnSetRemediation: (id: number, plan: string, owner: string, due: string | null) => call<T.Vulnerability>("vuln_set_remediation", { id, plan, owner, due }),
  vulnVerify: (id: number, note: string) => call<T.Vulnerability>("vuln_verify", { id, note }),
  vulnHistory: (id: number) => call<T.VulnEvent[]>("vuln_history", { id }),
  vulnDelete: (id: number) => call<void>("vuln_delete", { id }),
  vulnCreateFinding: (id: number) => call<number>("vuln_create_finding", { id }),
  // workflows
  workflowNodes: () => call<T.WorkflowNodeSpec[]>("workflow_nodes"),
  workflowTemplates: () => call<T.WorkflowTemplate[]>("workflow_templates"),
  workflowsList: (projectId: number) => call<T.Workflow[]>("workflows_list", { projectId }),
  workflowSave: (input: { id?: number; projectId: number; name: string; description: string; definition: T.WorkflowDefinition; scheduleHours: number | null; enabled: boolean }) =>
    call<T.Workflow>("workflow_save", { input }),
  workflowDelete: (id: number) => call<void>("workflow_delete", { id }),
  workflowRun: (id: number) => call<number>("workflow_run", { id }),
  workflowCancel: (runId: number) => call<boolean>("workflow_cancel", { runId }),
  workflowRuns: (workflowId: number, limit?: number) => call<T.WorkflowRunSummary[]>("workflow_runs", { workflowId, limit: limit ?? null }),
  workflowRunDetail: (runId: number) => call<T.WorkflowRunDetail>("workflow_run_detail", { runId }),
  // analysis (stored data only)
  iocCorrelation: (projectId: number) => call<T.IocIndicator[]>("ioc_correlation", { projectId }),
  exposurePaths: (projectId: number) => call<T.ExposurePath[]>("exposure_paths", { projectId }),
  discoveryCompare: (from: number, to: number) => call<T.SnapshotChanges>("discovery_compare", { from, to }),
  runsCompare: (a: number, b: number) => call<T.RunDiff>("runs_compare", { a, b }),
  // project assistant (Anthropic; the key is owner-provisioned and never reaches the web view)
  assistantStatus: () => call<{ configured: boolean; provider: string; model: string }>("assistant_status"),
  assistantContextPreview: (projectId: number, options: T.AssistantContextOptions) => call<{ text: string; chars: number }>("assistant_context_preview", { projectId, options }),
  assistantAsk: (projectId: number, conversationId: string | null, question: string, options: T.AssistantContextOptions) =>
    call<{ conversationId: string; answer: T.AssistantAnswer }>("assistant_ask", { projectId, conversationId, question, options }),
  assistantForget: (conversationId: string) => call<void>("assistant_forget", { conversationId }),
  // security utilities
  tlsAnalyze: (projectId: number, target: string, port?: number) => call<T.TlsReport>("tls_analyze", { projectId, target, port: port ?? null }),
  dnsIntel: (projectId: number | null, domain: string) => call<T.DnsIntelReport>("dns_intel", { projectId, domain }),
  httpSend: (input: { projectId: number; method: string; url: string; headers: [string, string][]; body: string; insecure: boolean; followRedirects: boolean }) =>
    call<T.HttpResponseOut>("http_send", { input }),
  leakScanText: (text: string) => call<T.LeakScanResult>("leak_scan_text", { text }),
  leakScanPick: (folder: boolean) => call<{ root: string; result: T.LeakScanResult } | null>("leak_scan_pick", { folder }),
  servicesByPort: (port: number) => call<T.PortSighting[]>("services_by_port", { port }),
  findingsBulkStatus: (ids: number[], status: T.FindingStatus, note?: string) =>
    call<{ changed: number[]; skipped: [number, string][] }>("findings_bulk_status", { ids, status, note: note ?? null }),
  projectToolHistory: (projectId: number) => call<T.ProjectExecution[]>("project_tool_history", { projectId }),
  projectReport: (id: number) => call<string>("project_report", { id }),
  /** native save dialog; returns the file name or null when cancelled */
  projectReportExport: (id: number) => call<string | null>("project_report_export", { id }),

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
  execHistoryClear: () => call<T.HistoryCleared>("exec_history_clear"),

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
  cveHistory: () => call<T.CveHistoryItem[]>("cve_history"),
  cveCacheStats: () => call<[number, string | null]>("cve_cache_stats"),
  cveHistoryClear: () => call<void>("cve_history_clear"),

  // VirusTotal — requests are made by the backend with the key from the OS credential store.
  // The key is write-only: it can be saved (after verification) or removed, never read.
  vtLookup: (query: string, refresh = false) => call<T.VtLookupResult>("vt_lookup", { query, refresh }),
  vtRecent: (limit = 20) => call<T.VtRecentLookup[]>("vt_recent", { limit }),
  vtCacheClear: () => call<void>("vt_cache_clear"),
  vtKeyStatus: () => call<boolean>("vt_key_status"),
  /** opens the native file picker in the backend and hashes the file locally */
  vtFilePick: () => call<T.VtPickedFile | null>("vt_file_pick"),
  vtFileForget: (handle: string) => call<void>("vt_file_forget", { handle }),
  /** the backend shows a native confirmation before anything is uploaded */
  vtFileUpload: (handle: string, onEvent: (e: T.VtUploadEvent) => void) => {
    const channel = new Channel<T.VtUploadEvent>();
    channel.onmessage = onEvent;
    return call<T.VtUploadResult>("vt_file_upload", { handle, onEvent: channel });
  },
  vtFileCancel: (handle: string) => call<boolean>("vt_file_cancel", { handle }),
  vtAnalysis: (analysisId: string) => call<T.VtAnalysisStatus>("vt_analysis", { analysisId }),

  // threat intelligence providers
  tiDetect: (query: string) => call<T.VtDetected>("ti_detect", { query }),
  tiProviders: () => call<T.TiProvidersOverview>("ti_providers"),
  tiProviderSetEnabled: (providerId: string, enabled: boolean) => call<void>("ti_provider_set_enabled", { providerId, enabled }),
  tiLookup: (query: string, providers: string[] | null, refresh = false) => call<T.TiInvestigation>("ti_lookup", { query, providers, refresh }),
  tiHistory: (limit = 30) => call<T.TiHistoryEntry[]>("ti_history", { limit }),
  tiHistoryClear: () => call<void>("ti_history_clear"),
  tiCacheClear: () => call<void>("ti_cache_clear"),
  tiSavedList: () => call<T.TiSavedIndicator[]>("ti_saved_list"),
  tiSavedAdd: (query: string, note = "") => call<void>("ti_saved_add", { query, note }),
  tiSavedRemove: (query: string) => call<void>("ti_saved_remove", { query }),
  /** writes through a native save dialog; returns the file name or null when cancelled */
  tiExport: (query: string, format: "md" | "json") => call<string | null>("ti_export", { query, format }),

  // MCP integration (decisions and policy are only reachable from this window, never from MCP clients)
  mcpStatus: () => call<T.McpStatus>("mcp_status"),
  mcpSetEnabled: (enabled: boolean) => call<void>("mcp_set_enabled", { enabled }),
  mcpSetPolicy: (category: string, policy: T.McpPolicy) => call<void>("mcp_set_policy", { category, policy }),
  mcpPending: () => call<T.McpPending[]>("mcp_pending"),
  mcpDecide: (id: string, approve: boolean) => call<boolean>("mcp_decide", { id, approve }),
  mcpAudit: (limit = 50, filter?: T.McpAuditFilter) => call<T.McpAuditRow[]>("mcp_audit", { limit, filter: filter ?? null }),
  mcpCatalog: () => call<T.McpCatalog>("mcp_catalog"),
  mcpClients: () => call<T.McpClientRow[]>("mcp_clients"),
  mcpAuditClear: () => call<void>("mcp_audit_clear"),
  mcpClientConfigs: () => call<T.McpClientConfigs>("mcp_client_configs"),

  // OSINT workspace
  osintRegistry: () => call<O.Registry>("osint_registry"),
  osintInvestigations: (includeArchived = false) => call<O.Investigation[]>("osint_investigations", { includeArchived }),
  osintInvestigationGet: (id: number, touch = false) => call<O.Investigation>("osint_investigation_get", { id, touch }),
  osintInvestigationCreate: (input: O.InvestigationInput) => call<O.Investigation>("osint_investigation_create", { input }),
  osintInvestigationUpdate: (id: number, input: O.InvestigationInput) => call<O.Investigation>("osint_investigation_update", { id, input }),
  osintInvestigationSetStatus: (id: number, status: O.InvestigationStatus) => call<void>("osint_investigation_set_status", { id, status }),
  /** asks for confirmation in a native dialog; false when the user cancelled */
  osintInvestigationDelete: (id: number) => call<boolean>("osint_investigation_delete", { id }),
  osintCompare: (a: number, b: number) => call<O.SharedEntity[]>("osint_compare", { a, b }),
  osintEntities: (investigationId: number, query: O.EntityQuery) => call<O.Page<O.EntityRow>>("osint_entities", { investigationId, query }),
  osintEntity: (id: number) => call<O.EntityDetail>("osint_entity", { id }),
  osintRelationship: (id: number) => call<O.RelationshipDetail>("osint_relationship", { id }),
  osintSetVerification: (kind: "entity" | "relationship", id: number, verification: O.Verification, note?: string | null) =>
    call<void>("osint_set_verification", { kind, id, verification, note: note ?? null }),
  osintEntityUpdate: (id: number, displayName: string | null, notes: string | null) => call<void>("osint_entity_update", { id, displayName, notes }),
  osintEntityDelete: (id: number) => call<void>("osint_entity_delete", { id }),
  osintRelationshipDelete: (id: number) => call<void>("osint_relationship_delete", { id }),
  osintEntityMerge: (keep: number, merge: number) => call<void>("osint_entity_merge", { keep, merge }),
  osintEntityAdd: (input: O.ManualEntityInput) => call<O.ChangeSummary>("osint_entity_add", { input }),
  osintLink: (source: number, target: number, relType: string, note: string) => call<number>("osint_link", { source, target, relType, note }),
  osintNeighbors: (investigationId: number, ids: number[], includeRejected = false, limit?: number) =>
    call<O.Neighborhood>("osint_neighbors", { investigationId, ids, includeRejected, limit: limit ?? null }),
  osintEntitiesByIds: (investigationId: number, ids: number[]) => call<O.Neighborhood>("osint_entities_by_ids", { investigationId, ids }),
  osintDuplicates: (investigationId: number) => call<O.EntityBrief[][]>("osint_duplicates", { investigationId }),
  osintFindingFromEntity: (entityId: number, title: string, severity: string, description: string) =>
    call<number>("osint_finding_from_entity", { entityId, title, severity, description }),
  osintGraphs: (investigationId: number | null) => call<O.GraphMeta[]>("osint_graphs", { investigationId }),
  osintGraphCreate: (investigationId: number, name: string, description: string, followNew: boolean) =>
    call<number>("osint_graph_create", { investigationId, name, description, followNew }),
  /** touch=false for refreshes of an open graph (no "last opened" write) */
  osintGraphLoad: (id: number, touch = true) => call<O.GraphData>("osint_graph_load", { id, touch }),
  osintGraphSave: (id: number, save: O.GraphSave) => call<O.SaveResult>("osint_graph_save", { id, save }),
  osintGraphSaveAs: (from: number, name: string, nodes: O.GraphNodeState[], workspace: unknown, followNew: boolean) =>
    call<number>("osint_graph_save_as", { from, name, nodes, workspace, followNew }),
  osintGraphDuplicate: (from: number, name: string) => call<number>("osint_graph_duplicate", { from, name }),
  osintGraphRename: (id: number, name: string, description?: string | null, followNew?: boolean | null) =>
    call<void>("osint_graph_rename", { id, name, description: description ?? null, followNew: followNew ?? null }),
  /** asks for confirmation in a native dialog; false when the user cancelled */
  osintGraphDelete: (id: number) => call<boolean>("osint_graph_delete", { id }),
  osintVersions: (graphId: number) => call<O.VersionRow[]>("osint_versions", { graphId }),
  osintVersionCreate: (graphId: number, label: string) => call<number | null>("osint_version_create", { graphId, label }),
  osintVersionCompare: (a: number, b: number | null) => call<O.Diff>("osint_version_compare", { a, b }),
  osintVersionRestore: (versionId: number) => call<{ version: number; missing: number }>("osint_version_restore", { versionId }),
  osintTimeline: (investigationId: number, query: O.TimelineQuery) => call<O.Page<O.TimelineEvent>>("osint_timeline", { investigationId, query }),
  osintAnalysis: (investigationId: number, graphId: number | null, includeInferred: boolean) =>
    call<O.Overview>("osint_analysis", { investigationId, graphId, includeInferred }),
  osintPath: (investigationId: number, graphId: number | null, from: number, to: number, includeInferred: boolean, maxDepth?: number) =>
    call<O.GraphPath | null>("osint_path", { investigationId, graphId, from, to, includeInferred, maxDepth: maxDepth ?? null }),
  osintSuggestions: (investigationId: number) => call<O.Suggestion[]>("osint_suggestions", { investigationId }),
  osintDiscover: (request: O.DiscoverRequest) =>
    call<number>("osint_discover", { request: { autoImport: false, refresh: false, entityId: null, entityType: null, value: null, ...request } }),
  osintOperations: (investigationId: number) => call<O.Operation[]>("osint_operations", { investigationId }),
  osintOperation: (id: number) => call<O.OperationDetail>("osint_operation", { id }),
  osintOperationCancel: (id: number) => call<boolean>("osint_operation_cancel", { id }),
  osintOperationImport: (id: number, selection: O.ResultSelection | null) => call<O.ChangeSummary>("osint_operation_import", { id, selection }),
  osintImportSources: (projectId: number | null) => call<O.ImportSource[]>("osint_import_sources", { projectId }),
  osintImportInternal: (investigationId: number, kind: string, id: string) => call<O.ChangeSummary>("osint_import_internal", { investigationId, kind, id }),
  /** native save dialog; returns the file name or null when cancelled */
  osintExport: (graphId: number, format: O.ExportFormat) => call<string | null>("osint_export", { graphId, format }),
  osintExportImage: (graphId: number, format: "png" | "svg", data: string) => call<string | null>("osint_export_image", { graphId, format, data }),
  osintReport: (investigationId: number) => call<string>("osint_report", { investigationId }),
  osintReportExport: (investigationId: number) => call<string | null>("osint_report_export", { investigationId }),
  /** native open dialog + validation; nothing is imported until osintImportApply */
  osintImportPick: (investigationId: number | null) => call<O.PendingImport | null>("osint_import_pick", { investigationId }),
  osintImportPreview: (token: string, investigationId: number | null) => call<O.ImportPreview>("osint_import_preview", { token, investigationId }),
  osintImportApply: (token: string, investigationId: number | null, graphName: string) =>
    call<{ investigationId: number; graphId: number }>("osint_import_apply", { token, investigationId, graphName }),
  osintImportDiscard: (token: string) => call<void>("osint_import_discard", { token }),

  // updates (the backend owns the whole flow; the page has no updater permission of its own)
  updateStatus: () => call<T.UpdateStatus>("update_status"),
  updateCheck: () => call<T.UpdateStatus>("update_check"),
  updateDownload: () => call<T.UpdateStatus>("update_download"),
  updateCancel: () => call<T.UpdateStatus>("update_cancel"),
  updateInstall: () => call<T.UpdateStatus>("update_install"),
  updateRestart: () => call<void>("update_restart"),
  updateSettingsSet: (autoCheck: boolean, frequencyHours: number) => call<T.UpdateStatus>("update_settings_set", { autoCheck, frequencyHours }),

  // system
  systemInfo: () => call<T.SystemInfo>("system_info"),
  openTerminal: (cwd?: string | null) => call<string>("open_terminal", { cwd: cwd ?? null }),
};
