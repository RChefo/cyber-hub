/** DTOs returned by the Rust backend (src-tauri/src/commands/*). Keep in sync. */

export interface AppError {
  kind: "database" | "io" | "validation" | "not_found" | "scope" | "network" | "secret" | "cancelled" | "rate_limited" | "internal" | "conflict" | "runtime";
  message: string;
}

export type DetectionStatus = "installed" | "not_installed" | "dependency_missing" | "installation_failed" | "unsupported_os";

export interface Detection {
  toolId: string;
  status: DetectionStatus;
  path: string | null;
  version: string | null;
  missingDependencies: string[];
  message: string | null;
  checkedAt: string;
}

export interface Activity {
  id: number;
  kind: string;
  title: string;
  detail: string;
  refKind: string | null;
  refId: string | null;
  projectId: number | null;
  createdAt: string;
}

export interface DailyCount {
  date: string;
  kind: string;
  count: number;
}

export interface Favorite {
  kind: FavoriteKind;
  itemId: string;
  createdAt: string;
}

export type FavoriteKind = "tool" | "resource" | "command" | "dork" | "payload" | "wordlist" | "utility" | "template";

export interface Task {
  id: number;
  title: string;
  done: boolean;
  projectId: number | null;
  projectName: string | null;
  dueDate: string | null;
  createdAt: string;
}

export interface CustomResource {
  id: number;
  title: string;
  url: string;
  category: string;
  description: string;
  createdAt: string;
}

export interface ResourceVisit {
  resourceKey: string;
  title: string;
  url: string;
  visitedAt: string;
}

export interface SavedCommand {
  id: number;
  title: string;
  command: string;
  description: string;
  categoryId: string;
  os: "any" | "windows" | "macos" | "linux";
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface CommandHistoryItem {
  id: number;
  command: string;
  source: string;
  toolId: string | null;
  projectId: number | null;
  createdAt: string;
}

export interface SavedDork {
  id: number;
  title: string;
  query: string;
  category: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface DorkHistoryItem {
  id: number;
  query: string;
  createdAt: string;
}

export interface CustomPayload {
  id: number;
  title: string;
  payload: string;
  category: string;
  description: string;
  context: string;
  tags: string[];
  createdAt: string;
}

export type ProjectStatus = "planning" | "active" | "paused" | "completed" | "archived";

export interface ProjectSummary {
  id: number;
  name: string;
  description: string;
  status: ProjectStatus;
  startDate: string | null;
  endDate: string | null;
  targetCount: number;
  findingCount: number;
  openFindings: number;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectTarget {
  id: number;
  value: string;
  kind: "domain" | "wildcard" | "ip" | "cidr" | "url";
  inScope: boolean;
  note: string;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  status: ProjectStatus;
  scopeNotes: string;
  notes: string;
  startDate: string | null;
  endDate: string | null;
  createdAt: string;
  updatedAt: string;
  targets: ProjectTarget[];
}

export interface ScopeCheck {
  target: string;
  allowed: boolean;
  reason: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "new"
  | "under_review"
  | "confirmed"
  | "accepted_risk"
  | "in_remediation"
  | "resolved"
  | "reopened"
  | "false_positive";
export type Confidence = "low" | "medium" | "high";

export interface Evidence {
  label: string;
  reference: string;
}

export interface Finding {
  id: number;
  projectId: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  category: string;
  confidence: Confidence;
  description: string;
  affectedTarget: string;
  cve: string;
  /** Free-form references; stored evidence is attached through finding links. */
  evidence: Evidence[];
  reproduction: string;
  technicalDetails: string;
  remediation: string;
  /** Who recorded it: user, mcp, osint, manual (before schema 9)… */
  source: string;
  tags: string[];
  assignee: string;
  dueDate: string | null;
  createdAt: string;
  updatedAt: string;
}

/** What the backend accepts when saving; fields added in schema 9 are optional. */
export type FindingInput = Pick<Finding, "projectId" | "title" | "severity" | "status"> &
  Partial<Omit<Finding, "id" | "projectId" | "title" | "severity" | "status" | "source" | "createdAt" | "updatedAt">> & { id?: number };

export interface FindingEvent {
  id: number;
  kind: "created" | "status" | "updated" | "note" | "link" | "unlink" | "migrated";
  fromStatus: FindingStatus | null;
  toStatus: FindingStatus | null;
  note: string;
  source: string;
  at: string;
}

export type FindingLinkKind = "asset" | "vulnerability" | "osint_entity" | "execution" | "evidence";

export interface FindingLink {
  kind: FindingLinkKind;
  refId: number;
  /** Null when the linked record was deleted since. */
  label: string | null;
  createdAt: string;
}

export type AssetType = "domain" | "subdomain" | "ip" | "dns_record" | "service" | "http_service" | "certificate" | "technology" | "endpoint";
export type AssetStatus = "active" | "not_observed" | "retired";

export interface Asset {
  id: number;
  projectId: number;
  type: AssetType;
  value: string;
  status: AssetStatus;
  confidence: Confidence;
  source: string;
  osintEntityId: number | null;
  data: unknown;
  firstSeen: string;
  lastSeen: string;
  updatedAt: string;
}

export interface AssetObservation {
  id: number;
  snapshotId: number | null;
  observedAt: string;
  source: string;
  data: unknown;
}

export interface EvidenceRecord {
  id: number;
  projectId: number;
  kind: "file" | "text" | "execution" | "osint_evidence";
  title: string;
  description: string;
  source: string;
  sha256: string | null;
  size: number | null;
  fileName: string | null;
  content: string | null;
  executionId: number | null;
  osintEvidenceId: number | null;
  createdAt: string;
}

export type TimelineEventType =
  | "execution"
  | "finding"
  | "vulnerability"
  | "scope"
  | "evidence"
  | "investigation"
  | "discovery"
  | "asset"
  | "workflow"
  | "remediation"
  | "report"
  | "note";

export interface TimelineEvent {
  type: TimelineEventType;
  title: string;
  detail: string;
  refKind: string | null;
  refId: number | null;
  at: string;
}

export interface ScopeEvent {
  id: number;
  action: "added" | "updated" | "removed" | "blocked";
  value: string;
  kind: string;
  inScope: boolean | null;
  note: string;
  source: string;
  at: string;
}

export type Certainty = "confirmed" | "observed" | "possible" | "incomplete";
export type DiscoverySource = "passive" | "http" | "nmap";
export type SnapshotStatus = "running" | "completed" | "partial" | "failed" | "cancelled";

export interface DiscoverySnapshot {
  id: number;
  mode: "passive" | "active" | "manual";
  source: DiscoverySource;
  status: SnapshotStatus;
  note: string;
  executionId: number | null;
  startedAt: string;
  finishedAt: string | null;
  /** assets observed by this run */
  assets: number;
}

export interface SnapshotChange {
  change: "added" | "changed" | "missing";
  assetId: number;
  assetType: AssetType;
  value: string;
  certainty: Certainty;
}

export interface SnapshotChanges {
  snapshot: DiscoverySnapshot;
  previous: number | null;
  changes: SnapshotChange[];
}

export type VulnStatus = "open" | "triaged" | "in_remediation" | "mitigated" | "resolved" | "accepted_risk" | "false_positive";
export type Exposure = "internet" | "internal" | "unknown";
export type PriorityLevel = "p1" | "p2" | "p3" | "p4";

export interface PriorityReason {
  factor: "cvss" | "kev" | "exploit" | "epss" | "exposure" | "criticality";
  effect: number;
  text: string;
}

export interface Vulnerability {
  id: number;
  projectId: number;
  cveId: string;
  assetId: number | null;
  asset: string | null;
  title: string;
  status: VulnStatus;
  cvssScore: number | null;
  cvssVersion: string | null;
  cvssVector: string | null;
  kev: boolean;
  epss: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  exploitKnown: boolean;
  exposure: Exposure;
  criticality: Confidence;
  priority: PriorityLevel;
  priorityScore: number;
  priorityReasons: PriorityReason[];
  remediation: string;
  remediationOwner: string;
  remediationDue: string | null;
  verifiedAt: string | null;
  verificationNote: string;
  notes: string;
  source: string;
  createdAt: string;
  updatedAt: string;
}

export interface VulnEvent {
  id: number;
  kind: "created" | "status" | "priority" | "remediation" | "verification" | "note" | "updated";
  fromValue: string | null;
  toValue: string | null;
  note: string;
  source: string;
  at: string;
}

export type WorkflowParamKind = "targets" | "select" | "number" | "text";

export interface WorkflowParamSpec {
  key: string;
  label: string;
  kind: WorkflowParamKind;
  required: boolean;
  help: string;
  options: [string, string][];
  min: number;
  max: number;
}

export interface WorkflowNodeSpec {
  type: string;
  label: string;
  description: string;
  /** contacts targets: confirmed natively, never scheduled */
  active: boolean;
  retryable: boolean;
  defaultTimeout: number;
  maxTimeout: number;
  params: WorkflowParamSpec[];
}

export interface WorkflowStep {
  type: string;
  name: string;
  params: Record<string, unknown>;
  /** 0 = the step type's default */
  timeoutSecs: number;
  retries: number;
  continueOnError: boolean;
}

export interface WorkflowDefinition {
  steps: WorkflowStep[];
}

export type WorkflowRunStatus = "running" | "succeeded" | "partial" | "failed" | "cancelled";

export interface WorkflowRunSummary {
  id: number;
  status: WorkflowRunStatus;
  trigger: "manual" | "schedule";
  startedAt: string;
  finishedAt: string | null;
  summary: string;
}

export interface Workflow {
  id: number;
  projectId: number;
  name: string;
  description: string;
  definition: WorkflowDefinition;
  scheduleHours: number | null;
  enabled: boolean;
  nextRunAt: string | null;
  createdAt: string;
  updatedAt: string;
  lastRun: WorkflowRunSummary | null;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  definition: WorkflowDefinition;
}

export interface WorkflowRunStep {
  id: number;
  position: number;
  kind: string;
  name: string;
  status: "pending" | "running" | "succeeded" | "failed" | "skipped" | "cancelled";
  attempts: number;
  summary: string;
  log: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface WorkflowRunDetail {
  run: WorkflowRunSummary;
  workflowId: number;
  steps: WorkflowRunStep[];
}

export interface IocSighting {
  source: "asset" | "scope" | "finding" | "osint" | "saved";
  detail: string;
  refKind: string | null;
  refId: number | null;
}

export interface IocIndicator {
  kind: "ip" | "domain" | "email" | "file_hash";
  value: string;
  sightings: IocSighting[];
  sources: number;
  ti: { provider: string; level: string; label: string; fetchedAt: string }[];
  flagged: boolean;
}

export interface ExposurePathNode {
  kind: "entry" | "name" | "ip" | "service" | "web" | "vulnerability" | "finding";
  label: string;
  refKind: string | null;
  refId: number | null;
}

export interface ExposurePath {
  nodes: ExposurePathNode[];
  priority: PriorityLevel | null;
  score: number;
  exposure: string;
}

export interface RunDiff {
  lines: { op: "same" | "added" | "removed" | "gap"; text: string }[];
  added: number;
  removed: number;
  truncated: boolean;
}

export interface AssistantContextOptions {
  scope: boolean;
  assets: boolean;
  vulnerabilities: boolean;
  findings: boolean;
  timeline: boolean;
}

export interface AssistantAnswer {
  text: string;
  stopReason: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  fallback: boolean;
}

export interface ScopeDecision {
  mode: "passive" | "active";
  verdicts: ScopeCheck[];
}

export interface ProjectExecution {
  id: number;
  toolId: string;
  kind: "run" | "install";
  args: string[];
  status: ExecutionStatus;
  exitCode: number | null;
  startedAt: string;
  finishedAt: string | null;
}

export type ExecutionStatus = "running" | "succeeded" | "failed" | "cancelled" | "error";

export interface ExecutionRecord {
  id: number;
  toolId: string;
  kind: "run" | "install";
  program: string;
  args: string[];
  projectId: number | null;
  status: ExecutionStatus;
  exitCode: number | null;
  truncated: boolean;
  startedAt: string;
  finishedAt: string | null;
  running: boolean;
}

export type ExecEvent =
  | { type: "started"; executionId: number; program: string; args: string[] }
  | { type: "stdout"; line: string }
  | { type: "stderr"; line: string }
  | { type: "exit"; status: ExecutionStatus; code: number | null };

export interface ExecRequest {
  toolId: string;
  args: string[];
  projectId: number | null;
  targets: string[];
  confirmed: boolean;
}

export interface ExecValidation {
  program: string;
  /** arguments with credentials redacted */
  args: string[];
  checkedTargets: string[];
  /** distinct targets that came from validated target files */
  fileTargets: number;
  requiresScope: boolean;
  warnings: string[];
  notes: string[];
}

export interface ManagerAvailability {
  manager: string;
  available: boolean;
  path: string | null;
}

export interface Wordlist {
  id: number;
  name: string;
  path: string;
  category: string;
  sizeBytes: number;
  lineCount: number | null;
  managed: boolean;
  exists: boolean;
  addedAt: string;
  modifiedAt: string | null;
}

export interface WordlistPreview {
  lines: string[];
  scannedLines: number;
  truncated: boolean;
}

export interface DnsRecord {
  recordType: string;
  value: string;
  ttl: number;
}

export interface HttpInspection {
  url: string;
  status: number;
  statusText: string;
  httpVersion: string;
  remoteAddr: string | null;
  headers: [string, string][];
  elapsedMs: number;
}

export interface CvssScore {
  version: string;
  score: number;
  severity: string;
  vector: string;
  source: string;
}

export interface CveRecord {
  id: string;
  published: string;
  lastModified: string;
  status: string;
  description: string;
  cvss: CvssScore[];
  cwes: string[];
  products: string[];
  references: { url: string; source: string; tags: string[] }[];
  kev: boolean;
}

export interface CveSearchResult {
  records: CveRecord[];
  source: "live" | "cache";
  totalResults: number;
  fetchedAt: string | null;
  cachedAt: [string, string][];
}

export interface CveHistoryItem {
  id: number;
  query: string;
  resultCount: number;
  live: boolean;
  createdAt: string;
}

export interface SystemInfo {
  os: "windows" | "macos" | "linux";
  osName: string;
  osVersion: string;
  kernelVersion: string;
  hostname: string;
  arch: string;
  cpuBrand: string;
  cpuCores: number;
  totalMemory: number;
  usedMemory: number;
  uptimeSecs: number;
  appVersion: string;
  dataDir: string;
  dbSchemaVersion: number;
  runningProcesses: number;
}

/* ─────────────── VirusTotal ─────────────── */

export type VtKind = "ip" | "domain" | "url" | "file";

export interface VtDetected {
  kind: VtKind;
  label: string;
  value: string;
  hashType: string | null;
}

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
}

export interface VtReport {
  kind: VtKind;
  indicator: string;
  stats: VtStats;
  enginesTotal: number;
  reputation: number | null;
  /** unix seconds */
  lastAnalysisDate: number | null;
  votesHarmless: number | null;
  votesMalicious: number | null;
  flagged: { engine: string; category: "malicious" | "suspicious" | string; result: string | null }[];
  threatLabel: string | null;
  tags: string[];
  categories: string[];
  details: { label: string; value: string }[];
  permalink: string;
}

export interface VtLookupResult {
  kind: VtKind;
  indicator: string;
  hashType: string | null;
  /** null when VirusTotal has no record of the indicator */
  report: VtReport | null;
  source: "live" | "cache";
  fetchedAt: string;
  freshUntil: string;
}

export interface VtRecentLookup {
  kind: VtKind;
  indicator: string;
  malicious: number | null;
  suspicious: number | null;
  enginesTotal: number | null;
  notFound: boolean;
  fetchedAt: string;
  fresh: boolean;
}

export interface VtPickedFile {
  /** opaque backend handle; the web view never sees the file path */
  handle: string;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  uploadMode: "direct" | "upload_url";
  limitBytes: number;
  withinLimit: boolean;
}

export interface VtUploadEvent {
  phase: "confirming" | "preparing" | "uploading" | "processing";
  sent: number;
  total: number;
}

export interface VtUploadResult {
  analysisId: string;
  sha256: string;
}

export interface VtAnalysisStatus {
  status: "queued" | "in-progress" | "completed";
  stats: VtStats;
  date: number | null;
  sha256: string | null;
}

/* ─────────────── Threat intelligence providers ─────────────── */

export type TiLevel = "malicious" | "suspicious" | "clean" | "info" | "unknown";
export type TiStatus = "found" | "not_found" | "unsupported" | "no_key" | "disabled" | "rate_limited" | "error";

export interface TiReport {
  verdict: { level: TiLevel; label: string } | null;
  scores: { label: string; value: number; max: number | null; display: string }[];
  categories: string[];
  families: string[];
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  facts: { label: string; value: string }[];
  tables: { title: string; columns: string[]; rows: string[][]; note: string | null }[];
  related: { kind: VtKind; value: string; relation: string }[];
  permalink: string | null;
}

export interface TiProviderResult {
  provider: string;
  providerName: string;
  status: TiStatus;
  report: TiReport | null;
  message: string | null;
  source: "live" | "cache" | null;
  fetchedAt: string | null;
  freshUntil: string | null;
  quota: string | null;
}

export interface TiSummary {
  malicious: string[];
  suspicious: string[];
  clean: string[];
  informational: string[];
  noVerdict: string[];
  noRecord: string[];
  failed: string[];
  skipped: string[];
}

export interface TiInvestigation {
  kind: VtKind;
  indicator: string;
  hashType: string | null;
  results: TiProviderResult[];
  summary: TiSummary;
  searchedAt: string;
  saved: boolean;
}

export interface TiHealth {
  state: "ok" | "rate_limited" | "rejected" | "error";
  /** sanitized; never contains a credential */
  message: string | null;
  at: string;
  quota: string | null;
}

export interface TiProviderStatus {
  id: string;
  name: string;
  description: string;
  kinds: VtKind[];
  /** credentials provisioned by the application owner (the value is never sent to the UI) */
  configured: boolean;
  enabled: boolean;
  serviceNote: string;
  docsUrl: string;
  rateLimit: string;
  /** last observed outcome of a real lookup since the app started */
  health: TiHealth | null;
}

export interface TiProvidersOverview {
  providers: TiProviderStatus[];
  nvdConfigured: boolean;
}

export interface TiHistoryEntry {
  id: number;
  kind: VtKind;
  indicator: string;
  summary: TiSummary;
  searchedAt: string;
}

export interface TiSavedIndicator {
  id: number;
  kind: VtKind;
  indicator: string;
  note: string;
  createdAt: string;
}

/* ─────────────── MCP integration ─────────────── */

export type McpPolicy = "allow" | "ask" | "deny";

export interface McpPolicyRow {
  category: string;
  label: string;
  policy: McpPolicy;
  options: McpPolicy[];
  tools: string[];
}

export interface McpConnection {
  id: number;
  /** self-reported by the MCP client ("name version") */
  client: string;
  clientName: string;
  clientVersion: string;
  connectedAt: string;
  requests: number;
  lastRequestAt: string | null;
}

export interface McpStatus {
  enabled: boolean;
  running: boolean;
  address: string | null;
  startedAt: string | null;
  transport: string;
  serverPath: string | null;
  /** why the server path is missing or will not stay valid (AppImage mount) */
  serverPathNote: string | null;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  connections: McpConnection[];
  pending: number;
  policy: McpPolicyRow[];
}

export interface McpPending {
  id: string;
  client: string;
  connection: number;
  tool: string;
  category: string;
  summary: string;
  details: { label: string; value: string }[];
  /** checks Cyber Hub performed before showing the request */
  checks: string[];
  projectId: number | null;
  createdAt: string;
  expiresInSecs: number;
}

export interface McpAuditRow {
  id: number;
  at: string;
  client: string;
  connection: number;
  tool: string;
  arguments: string;
  projectId: number | null;
  approval: string;
  approvalId: string | null;
  executionId: number | null;
  result: string;
  message: string;
  durationMs: number;
  /** permission category that applied */
  category: string | null;
}

export type McpAuditResult = "ok" | "awaiting_approval" | "refused" | "error";

export interface McpAuditFilter {
  client?: string;
  category?: string;
  result?: McpAuditResult;
}

export interface McpParam {
  name: string;
  kind: string;
  required: boolean;
  description: string;
  values: string[];
}

export interface McpCatalogTool {
  name: string;
  title: string;
  group: string;
  groupLabel: string;
  description: string;
  category: string;
  categoryLabel: string;
  policy: McpPolicy;
  requiresApproval: boolean;
  nativeConfirmation: boolean;
  available: boolean;
  note: string | null;
  readOnly: boolean;
  parameters: McpParam[];
}

export interface McpCatalogResource {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
  template: boolean;
  servedBy: string;
  parameters: McpParam[];
}

export interface McpCatalogPrompt {
  name: string;
  title: string;
  description: string;
  arguments: McpParam[];
}

export interface McpCatalog {
  groups: [string, string][];
  tools: McpCatalogTool[];
  resources: McpCatalogResource[];
  prompts: McpCatalogPrompt[];
  instructions: string;
}

export interface McpClientRow {
  /** self-reported, never verified */
  label: string;
  name: string;
  version: string;
  connected: boolean;
  connections: number;
  connectedSince: string | null;
  sessionRequests: number;
  loggedRequests: number;
  lastActivity: string | null;
  lastTool: string | null;
  lastResult: string | null;
  lastApproval: string | null;
}

export interface McpClientConfigs {
  claudeCodeCommand: string;
  claudeCodeJson: string;
  claudeDesktopJson: string;
  claudeDesktopConfigPath: string | null;
}

/* ───────────── updates (Settings → Updates) ───────────── */

export type UpdatePhase =
  | "idle"
  | "checking"
  | "upToDate"
  | "available"
  | "downloading"
  | "verifying"
  | "ready"
  | "installing"
  | "restartRequired"
  | "cancelled"
  | "failed";

export type InstallKind = "nsis" | "msi" | "appimage" | "deb" | "rpm" | "unknown";

export interface UpdateStatus {
  phase: UpdatePhase;
  currentVersion: string;
  os: "windows" | "macos" | "linux";
  arch: string;
  installKind: InstallKind;
  supported: boolean;
  supportNote: string | null;
  channel: "stable";
  configured: boolean;
  warning: string | null;
  lastCheck: string | null;
  lastResult: "upToDate" | "available" | "failed" | null;
  nextCheck: string | null;
  available: { version: string; date: string | null; notes: string; size: number | null } | null;
  progress: { downloaded: number; total: number | null } | null;
  error: { kind: string; message: string } | null;
  autoCheck: boolean;
  frequencyHours: number;
  blockers: string[];
}
