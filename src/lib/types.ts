/** DTOs returned by the Rust backend (src-tauri/src/commands/*). Keep in sync. */

export interface AppError {
  kind: "database" | "io" | "validation" | "not_found" | "scope" | "network" | "secret" | "cancelled" | "internal" | "runtime";
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
export type FindingStatus = "open" | "confirmed" | "reported" | "resolved" | "false_positive";

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
  description: string;
  affectedTarget: string;
  cve: string;
  evidence: Evidence[];
  createdAt: string;
  updatedAt: string;
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
