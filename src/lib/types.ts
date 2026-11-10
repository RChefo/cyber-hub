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

export interface Project extends Engagement {
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

/** Engagement details (schema 12). */
export interface Engagement {
  client: string;
  engagementType: string;
  authorizationRef: string;
  objectives: string;
  methodology: string;
  contacts: string;
}

export interface ReportOptions {
  title: string;
  author: string;
  classification: string;
  summary: string;
  includeScope: boolean;
  includeFindings: boolean;
  minSeverity: Severity;
  includeClosed: boolean;
  includeVulnerabilities: boolean;
  includeAssets: boolean;
  includeEvidence: boolean;
  includeTimeline: boolean;
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
  /** canonical CVSS v3.1 or v4.0 vector, empty when none was given */
  cvssVector: string;
  /** computed by the backend from the vector */
  cvssScore: number | null;
}

/** What the backend accepts when saving; fields added in schema 9 are optional. */
export type FindingInput = Pick<Finding, "projectId" | "title" | "severity" | "status"> &
  Partial<Omit<Finding, "id" | "projectId" | "title" | "severity" | "status" | "source" | "createdAt" | "updatedAt">> & { id?: number };

export interface CvssResult {
  version: "3.0" | "3.1" | "4.0";
  vector: string;
  score: number;
  baseScore: number;
  rating: "none" | "low" | "medium" | "high" | "critical";
  label: string;
}

export interface WstgTest {
  id: string;
  name: string;
  reference: string;
  objectives: string[];
}

export interface WstgCategory {
  id: string;
  name: string;
  tests: WstgTest[];
}

export interface WstgCatalog {
  source: string;
  url: string;
  commit: string;
  retrieved: string;
  license: string;
  categories: WstgCategory[];
}

export type ChecklistStatus = "not_started" | "in_progress" | "passed" | "failed" | "not_applicable";

/** A backup checked before it is restored (Settings → Local data). */
export interface BackupInfo {
  fileName: string;
  size: number;
  modified: string | null;
  schema: number;
  latest: number;
  projects: number;
  findings: number;
  evidenceReferenced: number;
  evidenceAvailable: number;
}

/** The result of a restore, reported once after the restart. */
export interface RestoreOutcome {
  ok: boolean;
  source: string;
  keptIn: string | null;
  evidenceKept: number;
  evidenceRestored: number;
  /** the restored database had the MCP bridge on; it was turned off */
  mcpTurnedOff: boolean;
  /** the backup waits for the next start (the database was still in use) */
  retry: boolean;
  error: string | null;
}

export interface ChecklistItem {
  testId: string;
  status: ChecklistStatus;
  note: string;
  findingId: number | null;
  updatedAt: string;
}

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

export type AssetType = "domain" | "subdomain" | "ip" | "dns_record" | "service" | "http_service" | "certificate" | "technology" | "endpoint" | "cloud_resource";
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
  executionId: number | null;
  osintEvidenceId: number | null;
  createdAt: string;
  /** provenance: the module and record it came from, the tool, when the source collected it */
  sourceModule: string;
  sourceRef: string;
  tool: string;
  toolVersion: string;
  collectedAt: string | null;
  derivedFrom: number | null;
  /** the result of the last integrity check */
  verification: "unverified" | "intact" | "damaged" | "missing";
  verifiedAt: string | null;
}

/** What importing one finding of a scan file would do (docs/DATA_MODEL.md#scan-import). */
export type ScanImportOutcome = "new" | "seen_again" | "recurring" | "dismissed" | "out_of_scope" | "info";

export interface ScanImportOptions {
  includeInfo: boolean;
  reopenResolved: boolean;
  useTemplates: boolean;
  /** resolve open findings of earlier imports of the same tool that the file no longer reports on a host it covers */
  resolveMissing: boolean;
  /** track the CVEs of recorded findings as vulnerabilities of their asset */
  trackCves: boolean;
}

/** A reusable finding write-up from the finding library (docs/DATA_MODEL.md#finding-library-schema-14). */
export interface FindingTemplate {
  id: number;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  remediation: string;
  references: string[];
  tags: string[];
  /** import rules `format:rule`, for example `nessus:57582` */
  rules: string[];
  useCount: number;
  createdAt: string;
  updatedAt: string;
}

export type FindingTemplateInput = Pick<FindingTemplate, "title" | "severity" | "category" | "description" | "remediation" | "references" | "tags" | "rules"> & { id?: number };

export interface LibraryImport {
  created: number;
  skipped: string[];
  invalid: string[];
}

export interface ScanImportPreview {
  format: string;
  formatLabel: string;
  tool: string;
  findings: number;
  bySeverity: Partial<Record<Severity, number>>;
  counts: { new: number; seenAgain: number; recurring: number; dismissed: number; outOfScope: number; info: number };
  assets: number;
  assetsNew: number;
  assetsOutOfScope: number;
  outOfScopeHosts: string[];
  items: { title: string; severity: Severity; target: string; outcome: ScanImportOutcome; findingId: number | null; template: string | null }[];
  warnings: string[];
  merged: number;
  markedFalsePositive: number;
  hasScope: boolean;
  templated: number;
  /** open findings of earlier imports of this tool that the file no longer reports (at most 200 listed) */
  notReported: ScanImportPreview["items"];
  notReportedCount: number;
  /** of those, findings whose checks the file reports as passing (Prowler) */
  notReportedPassed: number;
  /** a CSV file's columns and the mapping used */
  csv: CsvInfo | null;
  /** distinct CVEs named by findings that would be recorded */
  cves: number;
}

/** Which column (0-based) holds which field of a CSV import; null: not read. */
export interface CsvMapping {
  title: number | null;
  severity: number | null;
  target: number | null;
  port: number | null;
  description: number | null;
  remediation: number | null;
  cve: number | null;
  cvss: number | null;
  ruleId: number | null;
  references: number | null;
  details: number | null;
}

export interface CsvInfo {
  headers: string[];
  /** the first rows, cells cut to 120 characters */
  sample: string[][];
  rows: number;
  delimiter: string;
  mapping: CsvMapping;
  /** how the severity column was read */
  severityScale: "words" | "levels" | "scores" | null;
}

export interface ScanImportPending extends ScanImportPreview {
  token: string;
  fileName: string;
  sha256: string;
  size: number;
}

export interface ScanImportResult {
  importId: number;
  created: number;
  seenAgain: number;
  reopened: number;
  dismissed: number;
  outOfScope: number;
  infoSkipped: number;
  assetsNew: number;
  assetsSeen: number;
  templated: number;
  notReported: number;
  resolved: number;
  vulnsTracked: number;
  vulnsLinked: number;
  vulnsSkipped: number;
  summary: string;
}

export interface ScanImportRecord {
  id: number;
  format: string;
  tool: string;
  fileName: string;
  sha256: string;
  evidenceId: number | null;
  snapshotId: number | null;
  summary: { text?: string; created?: number; seenAgain?: number; reopened?: number };
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
  | "note"
  | "utility"
  | "checklist"
  | "correlation"
  | "detection"
  | "risk";

export interface TimelineEvent {
  type: TimelineEventType;
  title: string;
  detail: string;
  refKind: string | null;
  refId: number | null;
  at: string;
  /** when the source observed or collected it, when that differs from `at` (evidence) */
  observedAt: string | null;
  /** where the next page starts (`before`) */
  cursor: string;
}

/** Filters of the project timeline (`timeline_query`). */
export interface TimelineQuery {
  types?: TimelineEventType[];
  before?: string;
  limit?: number;
  refKind?: string;
  refId?: number;
  search?: string;
  from?: string;
  to?: string;
}

/* ───────────── investigation layer (schema 22) ───────────── */

export type RecordKind = "finding" | "asset" | "vulnerability" | "evidence" | "osint_entity" | "api_endpoint" | "sbom_component" | "technique" | "execution" | "project";

/** A record of any module: kind, row id, and an index inside a document or a technique ID. */
export interface RecordRef {
  kind: RecordKind;
  id: number;
  sub: string;
}

export interface RecordNode {
  ref: RecordRef;
  /** "finding:12", "api_endpoint:3:5", "technique:T1059.001" */
  key: string;
  label: string;
  detail: string;
  severity: Severity | null;
  flagged: boolean;
}

export interface RelationMatch {
  fieldA: string;
  valueA: string;
  fieldB: string;
  valueB: string;
  /** exact, normalized, alias */
  how: string;
}

export type RelationOrigin = "observed" | "imported" | "derived" | "inferred" | "manual" | "suggested";
export type RelationVerification = "observed" | "verified" | "inferred" | "disputed" | "rejected";
export type RelationReview = "pending" | "done" | "dismissed";

export interface Relation {
  id: number;
  projectId: number;
  a: RecordNode;
  b: RecordNode;
  type: string;
  label: string;
  directed: boolean;
  origin: RelationOrigin;
  verification: RelationVerification;
  review: RelationReview;
  confidence: "low" | "medium" | "high";
  rules: string[];
  reason: string;
  matched: RelationMatch[];
  createdBy: string;
  materialized: boolean;
  note: string;
  createdAt: string;
  updatedAt: string;
  reviewedAt: string | null;
}

export interface RelationPage {
  items: Relation[];
  total: number;
  pending: number;
  done: number;
  dismissed: number;
}

export interface RelationFilter {
  review?: RelationReview;
  verification?: RelationVerification;
  kind?: RecordKind;
  minConfidence?: "low" | "medium" | "high";
  rule?: string;
  limit?: number;
  offset?: number;
}

export interface RelatedItem {
  node: RecordNode;
  via: string;
  origin: RelationOrigin;
  verification: RelationVerification;
  relationId: number | null;
}

export interface RelatedView {
  node: RecordNode;
  related: RelatedItem[];
  events: TimelineEvent[];
}

export interface InvestigationEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  directed: boolean;
  origin: RelationOrigin;
  verification: RelationVerification;
  confidence: "low" | "medium" | "high";
  relationId: number | null;
  updatedAt: string;
}

export interface InvestigationGraph {
  nodes: RecordNode[];
  edges: InvestigationEdge[];
  truncated: boolean;
}

export interface InvestigationGraphFilter {
  includePending?: boolean;
  includeRejected?: boolean;
  minConfidence?: "low" | "medium" | "high";
  origins?: RelationOrigin[];
  kinds?: RecordKind[];
  since?: string;
  limit?: number;
  focus?: string;
  depth?: number;
}

export interface CorrelationReport {
  byRule: Record<string, number>;
  stored: { new: number; updated: number; decided: number; linked: number; truncated: boolean };
  elapsedMs: number;
}

export interface SearchHit {
  projectId: number | null;
  project: string;
  archived: boolean;
  node: RecordNode;
  /** 3 exact, 2 prefix, 1 substring */
  score: number;
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
  /** further identical refusals counted on this entry */
  repeats: number;
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

/** ATT&CK over time (Mission 5). */
export interface AttackHistoryEntry {
  at: string;
  kind: "assessment" | "finding" | "detection" | "link";
  summary: string;
  actor: string;
  refId: number | null;
}

/** An ATT&CK matrix: Enterprise, Mobile or ICS. */
export type AttackDomain = "enterprise-attack" | "mobile-attack" | "ics-attack";

export interface AttackSnapshot {
  /** the ATT&CK domain (Mission 6) */
  domain: AttackDomain;
  id: number;
  label: string;
  attackVersion: string;
  takenAt: string;
  techniques: number;
  rules: number;
}

export interface AttackDiffed {
  id: string;
  name: string;
  a: string;
  b: string;
}

export interface AttackComparison {
  /** the ATT&CK domain (Mission 6) */
  domain: AttackDomain;
  aLabel: string;
  bLabel: string;
  aKind: string;
  bKind: string;
  onlyA: AttackDiffed[];
  onlyB: AttackDiffed[];
  both: AttackDiffed[];
  reading: string;
}

/** A TAXII 2.1 collection of a server (Mission 5). */
export interface TaxiiCollection {
  id: number;
  serverId: number;
  apiRoot: string;
  collection: string;
  title: string;
  description: string;
  canRead: boolean;
  /** the incremental cursor */
  addedAfter: string | null;
  lastSyncAt: string | null;
  lastStatus: "" | "succeeded" | "partial" | "failed";
  lastError: string;
  indicators: number;
}

export interface TaxiiServer {
  id: number;
  name: string;
  discoveryUrl: string;
  auth: "none" | "basic" | "header";
  username: string;
  headerName: string;
  reliability: string;
  defaultConfidence: number | null;
  title: string;
  discoveredAt: string | null;
  createdAt: string;
  updatedAt: string;
  /** a credential is stored (never its value) */
  credentialStored: boolean;
  credentialCommand: string;
  collections: TaxiiCollection[];
}

export interface TaxiiServerInput {
  id?: number;
  name: string;
  discoveryUrl: string;
  auth: "none" | "basic" | "header";
  username: string;
  headerName: string;
  reliability: string;
  defaultConfidence: number | null;
}

export interface TaxiiSync {
  id: number;
  collectionId: number;
  startedAt: string;
  finishedAt: string | null;
  status: "running" | "succeeded" | "partial" | "failed";
  pages: number;
  objects: number;
  added: number;
  updated: number;
  revoked: number;
  sighted: number;
  skipped: number;
  message: string;
}

/** Risk acceptance (Mission 5): who accepted which risk, why, approved by whom, until when. */
export type RiskStanding = "active" | "review_due" | "expired" | "revoked";
export type RiskItemKind = "finding" | "vulnerability" | "asvs" | "wstg";

export interface RiskItemRef {
  kind: RiskItemKind;
  refId: number;
  /** the ASVS requirement id (kind asvs; refId is the assessment) */
  requirement?: string;
}

export interface RiskItem {
  kind: RiskItemKind;
  refId: number;
  requirement: string;
  label: string;
  /** its status now; "deleted" when the record is gone */
  status: string;
  addedAt: string;
  removedAt: string | null;
  removedReason: string;
}

export interface RiskAcceptance {
  id: number;
  projectId: number;
  title: string;
  justification: string;
  compensating: string;
  owner: string;
  approver: string;
  approvedAt: string;
  expiresAt: string;
  reviewAt: string | null;
  status: "active" | "revoked";
  standing: RiskStanding;
  revokedAt: string | null;
  revokedReason: string;
  createdAt: string;
  updatedAt: string;
  items: RiskItem[];
}

export interface RiskDraft {
  title: string;
  justification: string;
  compensating: string;
  owner: string;
  approver: string;
  approvedAt: string;
  expiresAt: string;
  reviewAt: string | null;
}

export interface RiskEvent {
  action: string;
  detail: string;
  source: string;
  at: string;
}

export interface RiskOverview {
  summary: { active: number; reviewDue: number; expired: number; revoked: number; undocumented: number };
  /** findings marked accepted that no acceptance covers: [id, title] */
  undocumented: [number, string][];
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
  source: "asset" | "scope" | "finding" | "osint" | "saved" | "evidence";
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
  /** relationships between records and the ATT&CK matrix, confirmed apart from suggested */
  investigation: boolean;
}

export interface AssistantAnswer {
  text: string;
  stopReason: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  fallback: boolean;
  /** the model that declined first, when a fallback model answered */
  fallbackFrom: string | null;
}

export interface ToolIssue {
  level: "critical" | "warning" | "info";
  text: string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  sans: string[];
  key: string;
  keyBits: number | null;
  signature: string;
  sha256: string;
  selfSigned: boolean;
}

export interface TlsReport {
  host: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  alpn: string | null;
  tls13: boolean;
  tls12: boolean;
  trusted: boolean;
  trustError: string | null;
  chain: CertInfo[];
  issues: ToolIssue[];
}

export interface DnsIntelReport {
  domain: string;
  records: { type: string; values: string[] }[];
  spf: { record: string | null; all: string | null; lookups: number; count: number };
  dmarc: { record: string | null; policy: string | null; subdomainPolicy: string | null; pct: number | null; reports: boolean };
  dkimSelectors: string[];
  caa: string[];
  dnssec: boolean;
  issues: ToolIssue[];
  errors: string[];
}

/** The result of checking a project's evidence against the recorded SHA-256 values. */
export interface EvidenceIntegrity {
  checked: number;
  references: number;
  problems: { id: number; title: string; problem: string }[];
}

/** What clearing the run history did: runs that other records refer to are kept. */
export interface HistoryCleared {
  removed: number;
  kept: number;
}

export interface HttpResponseOut {
  status: number;
  reason: string;
  version: string;
  headers: [string, string][];
  body: string;
  bodyBytes: number;
  truncated: boolean;
  elapsedMs: number;
  /** redirects followed before this response */
  redirects: { status: number; from: string; to: string }[];
  /** why a redirect of this response was not followed */
  redirectStopped: string | null;
}

export interface LeakHit {
  rule: string;
  label: string;
  file: string;
  line: number;
  column: number;
  masked: string;
}

export interface LeakScanResult {
  hits: LeakHit[];
  filesScanned: number;
  filesSkipped: number;
  truncated: boolean;
}

export interface PortSighting {
  projectId: number;
  project: string;
  assetId: number;
  value: string;
  service: string;
  product: string;
  lastSeen: string;
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

export type TiSavedStatus = "active" | "revoked" | "false_positive";

/** A saved indicator with its lifecycle (docs/PROVIDERS.md#saved-indicators). */
export interface TiSavedIndicator {
  id: number;
  kind: VtKind;
  indicator: string;
  note: string;
  source: string;
  /** A–F (Admiralty scale), "" when not judged */
  reliability: string;
  /** 0–100 (STIX 2.1) */
  confidence: number | null;
  confidenceLabel: "none" | "low" | "medium" | "high" | null;
  status: TiSavedStatus;
  /** the status today: an active indicator past its validity is expired */
  effective: TiSavedStatus | "expired";
  /** YYYY-MM-DD */
  validUntil: string | null;
  /** when it was saved (the collection time) */
  createdAt: string;
  updatedAt: string;
}

export interface TiSavedChanges {
  note?: string;
  source?: string;
  reliability?: string;
  /** -1 clears it */
  confidence?: number;
  status?: TiSavedStatus;
  /** "" clears it */
  validUntil?: string;
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

/* ───────── API security (workspace/apisec.rs) ───────── */

export interface ApiParam {
  name: string;
  /** path, query, header, cookie or form */
  location: string;
  required: boolean;
  kind: string;
  bounded: boolean;
}

export interface ApiEndpoint {
  method: string;
  path: string;
  operationId: string;
  summary: string;
  tags: string[];
  params: ApiParam[];
  bodyTypes: string[];
  bodyFields: string[];
  /** alternatives that authorize a call, each a list of schemes that must all be met */
  auth: string[][];
  anonymous: boolean;
  deprecated: boolean;
  servers: string[];
  responses: string[];
  /** requests seen in a capture (HAR) */
  seen: number;
}

export interface ApiScheme {
  name: string;
  kind: string;
  detail: string;
  param: string;
  flows: string[];
}

export interface ApiSpec {
  /** openapi-3.0, openapi-3.1, swagger-2.0, postman or har */
  format: string;
  title: string;
  version: string;
  servers: string[];
  schemes: ApiScheme[];
  authApplied: boolean;
  endpoints: ApiEndpoint[];
  warnings: string[];
}

export interface ApiChange {
  /** "POST /users" in the newer definition */
  endpoint: string;
  details: string[];
}

export interface ApiComparison {
  added: string[];
  removed: string[];
  changed: ApiChange[];
  unchanged: number;
  serversAdded: string[];
  serversRemoved: string[];
  issues: ApiIssue[];
}

export interface ApiCompareView {
  old: ApiSpecSummary;
  new: ApiSpecSummary;
  comparison: ApiComparison;
  /** issue id → finding id */
  recorded: Record<string, number>;
}

export interface ApiIssue {
  id: string;
  rule: string;
  /** "API2:2023" */
  owasp: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** issue: a property of the definition; test: endpoints to test */
  kind: "issue" | "test";
  title: string;
  detail: string;
  endpoints: string[];
  recommendation: string;
}

export interface ApiSpecSummary {
  id: number;
  projectId: number;
  name: string;
  format: string;
  title: string;
  version: string;
  endpoints: number;
  sha256: string;
  evidenceId: number | null;
  importedAt: string;
  /** issues per severity: critical, high, medium, low, info */
  issues: [number, number, number, number, number];
  tests: number;
}

export interface ApiEndpointScope {
  url: string;
  inScope: boolean;
  reason: string;
}

export interface ApiSpecView {
  summary: ApiSpecSummary;
  spec: ApiSpec;
  issues: ApiIssue[];
  scope: ApiEndpointScope[];
  recorded: Record<string, number>;
}

export interface ApiRecordedIssue {
  findingId: number;
  created: boolean;
}

/* ───────── SBOM analysis (workspace/sbom.rs) ───────── */

export interface SbomComponent {
  name: string;
  group: string;
  version: string;
  purl: string;
  cpe: string;
  kind: string;
  ecosystem: string;
  licenses: string[];
  licenseRisk: "permissive" | "weak-copyleft" | "copyleft" | "network-copyleft" | "restricted" | "unknown";
  supplier: string;
  hashes: string[];
  direct: boolean;
  reference: string;
  /** a development dependency (lockfiles) */
  dev: boolean;
  /** where a lockfile resolves the package from: a registry, a Git repository, a URL */
  resolved: string;
}

export interface SbomVuln {
  id: string;
  aliases: string[];
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  score: number | null;
  vector: string;
  fixed: string[];
  references: string[];
  published: string;
  /** indices of the affected components */
  components: number[];
  /** osv (looked up) or sbom (stated in the file) */
  source: "osv" | "sbom";
  /** VEX analysis state from the file, or "" */
  analysis: string;
}

export interface Sbom {
  format: string;
  specVersion: string;
  subject: string;
  created: string;
  tools: string[];
  components: SbomComponent[];
  relationships: boolean;
  vulns: SbomVuln[];
  warnings: string[];
  /** package indexes a lockfile names */
  sources: string[];
}

export interface SbomIssue {
  id: string;
  area: "license" | "completeness" | "supply-chain";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  components: string[];
  recommendation: string;
}

export interface SbomSummary {
  id: number;
  projectId: number;
  name: string;
  format: string;
  subject: string;
  components: number;
  sha256: string;
  evidenceId: number | null;
  importedAt: string;
  checkedAt: string | null;
  /** critical, high, medium, low, unknown */
  vulns: [number, number, number, number, number];
  vulnerable: number;
}

export interface SbomView {
  summary: SbomSummary;
  sbom: Sbom;
  vulns: SbomVuln[];
  issues: SbomIssue[];
  /** "vuln:<id>:<component>" or "issue:<id>" → finding id */
  recorded: Record<string, number>;
}

export interface SbomCheck {
  checked: number;
  skipped: number;
  vulns: number;
}

export interface SbomChange {
  /** "npm lodash" */
  component: string;
  from: string;
  to: string;
  direction: "upgraded" | "downgraded" | "changed";
}

export interface SbomVulnDelta {
  id: string;
  severity: string;
  /** "name@version" */
  components: string[];
}

export interface SbomComparison {
  added: string[];
  removed: string[];
  changed: SbomChange[];
  unchanged: number;
  /** both SBOMs have the same kind of vulnerability data (both checked online, or neither) */
  vulnsCompared: boolean;
  vulnsNew: SbomVulnDelta[];
  vulnsFixed: SbomVulnDelta[];
  issues: SbomIssue[];
}

export interface SbomCompareView {
  old: SbomSummary;
  new: SbomSummary;
  comparison: SbomComparison;
  /** issue id → finding id */
  recorded: Record<string, number>;
}

export interface SbomRecorded {
  created: number;
  existing: number;
}

/* ───────── Container and Kubernetes checks (sectools/containers.rs) ───────── */

export interface ContainerIssue {
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  location: string;
  detail: string;
  remediation: string;
  reference: string;
}

export interface ContainerFileReport {
  file: string;
  /** dockerfile, compose, kubernetes (or unknown when it could not be read) */
  kind: string;
  issues: ContainerIssue[];
  error: string;
  /** SHA-256 of the file's bytes, where the checker keeps it (Linux persistence) */
  sha256?: string;
}

export interface ContainerScanResult {
  files: ContainerFileReport[];
  filesSeen: number;
  truncated: boolean;
}

export interface ContainerScan {
  root: string;
  result: ContainerScanResult;
}

/* ───────── Packet capture and log triage (sectools/pcap.rs, sectools/logs.rs) ───────── */

export interface CaptureIssue {
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  remediation: string;
  evidence: string[];
}

export interface CaptureReport {
  format: string;
  links: string[];
  packets: number;
  bytes: number;
  first: number | null;
  last: number | null;
  hosts: { ip: string; packets: number; bytes: number; peers: number }[];
  conversations: { client: string; server: string; protocol: string; port: number; packets: number; bytes: number }[];
  dns: { name: string; kind: string; answers: string[]; queries: number }[];
  http: { method: string; host: string; path: string; userAgent: string; server: string; count: number }[];
  tls: { name: string; server: string; count: number }[];
  credentials: { protocol: string; client: string; server: string; user: string; secretLength: number }[];
  issues: CaptureIssue[];
  hunting: CaptureHunting;
  undecoded: number;
  warnings: string[];
}

/** Connections on a regular schedule: a hunting lead (updaters and health checks keep schedules too). */
export interface CaptureBeacon {
  client: string;
  server: string;
  protocol: string;
  port: number;
  connections: number;
  /** median seconds between connections */
  interval: number;
  /** median distance from the interval, in percent of it */
  jitter: number;
  onSchedule: number;
  first: number;
  last: number;
  regularity: "regular" | "jittered";
  note: string | null;
}

export interface CaptureDnsLead {
  rule: "DNS-TUNNEL" | "DNS-LONG" | "DNS-TXT" | "DNS-NXDOMAIN";
  title: string;
  detail: string;
  /** what else the pattern can be */
  benign: string;
  subject: string;
  clients: string[];
  examples: string[];
  count: number;
  techniques: string[];
}

export interface CaptureHunting {
  beacons: CaptureBeacon[];
  dns: CaptureDnsLead[];
  notes: string[];
}

export interface LogDetection {
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  remediation: string;
  count: number;
  sources: { ip: string; count: number; examples: string[] }[];
  /** the MITRE ATT&CK technique, for Windows event log detections */
  technique?: string;
}

export interface BinaryCapability {
  id: string;
  severity: "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  /** "T1055 Process Injection", or "" */
  technique: string;
  evidence: string[];
}

export interface BinaryReport {
  format: "PE32" | "PE32+" | "ELF32" | "ELF64" | "unknown";
  machine: string;
  kind: string;
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
  imphash: string;
  compiled: string;
  interpreter: string;
  entropy: number;
  dotnet: boolean;
  sections: { name: string; size: number; virtualSize: number; entropy: number; flags: string; note: string }[];
  libraries: { name: string; functions: string[] }[];
  exports: string[];
  hardening: { name: string; present: boolean; detail: string }[];
  capabilities: BinaryCapability[];
  strings: string[];
  stringsTotal: number;
  overlay: number;
  warnings: string[];
}

export interface BinaryScan {
  file: string;
  report: BinaryReport;
  /** names the analysed file when its results are recorded in a project (the path stays in the backend) */
  token: string | null;
}

export interface CaptureScan {
  file: string;
  report: CaptureReport;
  token: string | null;
}

export interface LogScan {
  file: string;
  report: LogReport;
  token: string | null;
}

/** A utility's result recorded in a project (docs/DATA_MODEL.md#utility-results). */
export type UtilityModule = "file_triage" | "pcap_triage" | "log_triage" | "evtx_triage" | "linux_persistence" | "oauth_review";

export interface UtilityRecordInput {
  projectId: number;
  module: UtilityModule;
  /** the analysed file; null for pasted text or fetched metadata */
  token: string | null;
  /** what was analysed when there is no file */
  subject: string;
  /** the analysis as JSON, kept as text evidence */
  report: string | null;
  findings: FindingInput[];
}

export interface UtilityRecorded {
  created: number;
  existing: number;
  evidenceId: number | null;
  reportId: number | null;
  reportTooLarge: boolean;
}

export interface LogReport {
  kind: "web" | "ssh" | "mixed" | "windows" | "unknown";
  lines: number;
  recognised: number;
  first: string;
  last: string;
  clients: { ip: string; requests: number; clientErrors: number; serverErrors: number; sshFailures: number; sshLogins: number }[];
  detections: LogDetection[];
  warnings: string[];
  /** Windows event logs: the most frequent event IDs */
  events?: { id: number; channel: string; name: string; count: number }[];
  /** Windows event logs: the computers that wrote the events */
  computers?: string[];
  /** Windows event logs: flagged parent → child process relationships (Mission 6) */
  chains?: ProcessChain[];
  /** Windows event logs: logons and failures per user account, as observed (Mission 6) */
  logons?: AccountLogons[];
}

/** One process of a chain, as the log has it. */
export interface ChainProcess {
  role: "ancestor" | "flagged" | "descendant";
  /** generations from the flagged process (negative for its ancestors) */
  depth: number;
  time: string;
  /** the event record that started it (0: known only by name, it started before the log) */
  record: number;
  eventId: number;
  pid: string;
  image: string;
  commandLine: string;
  user: string;
}

/** A flagged parent → child process relationship: what the log says, why it was flagged, and what it may mean. */
export interface ProcessChain {
  pattern: string;
  title: string;
  severity: "high" | "medium";
  technique?: string;
  why: string;
  hypotheses: string;
  computer: string;
  processes: ChainProcess[];
}

export interface AccountLogons {
  account: string;
  logons: number;
  failures: number;
  /** [logon type, count] */
  types: [string, number][];
  sources: [string, number][];
  first: string;
  last: string;
}

/* ───────────── ATT&CK matrix (docs/DATA_MODEL.md#attck-matrix-schema-23) ───────────── */

export interface AttackTactic {
  id: string;
  shortname: string;
  name: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  parent?: string;
}

export interface AttackCatalog {
  /** the ATT&CK domain (Mission 6) */
  domain: AttackDomain;
  version: string;
  modified: string;
  retrieved: string;
  url: string;
  notice: string;
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
}

export type AttackIdState = { state: "current" } | { state: "revoked"; by: string } | { state: "deprecated" } | { state: "unknown" };

export type AttackStatus = "confirmed" | "hypothesis" | "ruled_out";

export interface AttackObserved {
  findingId: number;
  title: string;
  severity: Severity;
  status: string;
  confidence: string;
  evidence: number;
}

export interface AttackAssessment {
  status: AttackStatus;
  confidence: "low" | "medium" | "high";
  note: string;
  attackVersion: string;
  createdBy: string;
  updatedAt: string;
}

export interface AttackLayerMark {
  layerId: number;
  score: number | null;
  color: string;
  comment: string;
  enabled: boolean;
}

export interface AttackLinked {
  relationId: number;
  label: string;
  key: string;
  verification: RelationVerification;
  origin: RelationOrigin;
}

export interface AttackEntry {
  id: string;
  name: string;
  tactics: string[];
  parent: string | null;
  state: AttackIdState;
  observed: AttackObserved[];
  linked: AttackLinked[];
  assessment: AttackAssessment | null;
  layers: AttackLayerMark[];
  /** detection rules of the library mapped to the technique: coverage, not observation */
  rules: AttackRuleCoverage[];
  /** open detection matches in the project (leads) */
  hits: number;
}

export interface AttackLayer {
  /** the ATT&CK domain (Mission 6) */
  domain: AttackDomain;
  id: number;
  name: string;
  description: string;
  fileName: string;
  evidenceId: number | null;
  layerVersion: string;
  attackVersion: string;
  navigatorVersion: string;
  techniques: number;
  unknown: string[];
  remapped: Record<string, string>;
  warnings: string[];
  importedAt: string;
}

export interface AttackMatrix {
  /** the ATT&CK domain (Mission 6) */
  domain: AttackDomain;
  attackVersion: string;
  attackModified: string;
  attackRetrieved: string;
  entries: AttackEntry[];
  layers: AttackLayer[];
  counts: { observed: number; confirmed: number; hypothesis: number; ruledOut: number; findings: number; covered: number; uncovered: number };
}

/** Findings that one fix addresses (docs/DATA_MODEL.md#remediation-groups). */
export interface RemediationMember {
  id: number;
  title: string;
  severity: Severity;
  status: string;
  target: string;
  /** resolved by a rescan that no longer reported it */
  verified: boolean;
}

export interface RemediationGroup {
  kind: "cve" | "package" | "check" | "fix";
  key: string;
  label: string;
  reason: string;
  fix: string;
  severity: Severity;
  open: number;
  resolved: number;
  verified: number;
  targets: number;
  findings: RemediationMember[];
}


/* ───────────── detection engineering (docs/DATA_MODEL.md#detection-engineering-schema-24) ───────────── */

export interface DetectionIssue {
  level: "error" | "unsupported" | "warning";
  message: string;
}

export interface DetectionRuleSummary {
  id: number;
  kind: "sigma" | "yara";
  title: string;
  status: string;
  level: string;
  logsource: string;
  techniques: string[];
  tags: string[];
  enabled: boolean;
  runnable: boolean;
  version: number;
  source: string;
  updatedAt: string;
  errors: number;
  warnings: number;
  collections: number[];
  testsPassed: number;
  testsFailed: number;
  falsePositives: number;
  hits: number;
}

export interface DetectionRulePage {
  items: DetectionRuleSummary[];
  total: number;
}

export interface DetectionRuleFilter {
  kind?: string | null;
  text?: string | null;
  enabled?: boolean | null;
  technique?: string | null;
  collection?: number | null;
  level?: string | null;
  limit?: number;
  offset?: number;
}

export interface DetectionTestRow {
  id: number;
  version: number;
  sampleId: number;
  expect: "none" | "match" | "no_match";
  events: number;
  matched: number;
  passed: boolean | null;
  ranAt: string;
}

export interface DetectionRuleSample {
  sampleId: number;
  fileName: string;
  kind: string;
  events: number;
  sha256: string;
  expect: "none" | "match" | "no_match";
  last: DetectionTestRow | null;
}

export interface DetectionRuleDetail {
  summary: DetectionRuleSummary;
  content: string;
  meta: Record<string, unknown>;
  issues: DetectionIssue[];
  versions: { version: number; sha256: string; note: string; createdAt: string }[];
  samples: DetectionRuleSample[];
  feedback: { id: number; projectId: number | null; project: string; verdict: "false_positive" | "true_positive" | "note"; note: string; event: string; createdAt: string }[];
  projects: { projectId: number; project: string; hits: number; findings: number }[];
}

export interface DetectionCollection {
  id: number;
  name: string;
  description: string;
  rules: number;
}

export interface DetectionSample {
  id: number;
  sha256: string;
  fileName: string;
  kind: string;
  size: number;
  events: number;
  addedAt: string;
}

export interface DetectionHitDetail {
  field: string;
  condition: string;
  value: string;
}

export interface SigmaExplanation {
  kind?: undefined;
  condition: string;
  selections: { name: string; matched: boolean; hits: DetectionHitDetail[] }[];
}

/** A string of a YARA rule that matched: how often (boreal counts up to 1,000), and the first matches. */
export interface YaraStringHit {
  id: string;
  count: number;
  matches: { offset: number; length: number; text: string; hex: string; xor: number | null }[];
}

export interface YaraExplanation {
  kind: "yara";
  rule: string;
  tags: string[];
  metas: [string, string][];
  strings: YaraStringHit[];
  /** matches counted per string */
  limit: number;
  /** matches kept per string */
  kept: number;
}

/** An event a correlation combined: the referenced rule (as the correlation names it), where the
 * event is and the evidence or sample it came from. A chained correlation's own match appears as
 * one event whose position is its window. */
export interface CorrelationEventRef {
  rule: string;
  position: string;
  time: string;
  source: string;
  sourceId: number;
}

export type CorrelationType = "event_count" | "value_count" | "temporal" | "temporal_ordered" | "value_sum" | "value_avg";

/** Why a Sigma correlation rule matched: the group, the window and what was measured in it. */
export interface CorrelationExplanation {
  kind: "correlation";
  type: CorrelationType;
  rules: { ref: string; title: string }[];
  groupBy: [string, string][];
  timespan: string;
  /** "count ≥ 10", "distinct User ≥ 100", "all 2 rules in order" */
  condition: string;
  value: number;
  first: string;
  last: string;
  events: CorrelationEventRef[];
  /** events in the window; only the first `kept` are listed */
  total: number;
  kept: number;
}

/** The correlation section of a valid Sigma correlation rule (in a library entry's meta). */
export interface CorrelationMeta {
  type: CorrelationType;
  rules: string[];
  groupBy: string[];
  timespan: number;
  timespanText: string;
  condition: [string, number][];
  fields: string[];
  aliases: Record<string, Record<string, string>>;
  generate: boolean;
}

export type DetectionExplanation = SigmaExplanation | YaraExplanation | CorrelationExplanation;

export interface DetectionMatch {
  position: string;
  time: string;
  label: string;
  fields: [string, string][];
  explanation: DetectionExplanation;
}

export interface DetectionRunResult {
  events: number;
  inSource: number;
  matched: number;
  matches: DetectionMatch[];
  notes: string[];
}

export interface DetectionTestOutcome {
  sample: DetectionSample;
  previous: DetectionTestRow | null;
  test: DetectionTestRow;
  result: DetectionRunResult;
}

export interface DetectionImportReport {
  imported: { id: number; title: string; outcome: "added" | "updated" | "unchanged"; version: number; errors: number }[];
  failed: [string, string][];
  /** what the import did besides adding rules (rules disabled because only a correlation uses them) */
  notes?: string[];
}

export interface DetectionProjectRun {
  files: { evidenceId: number; title: string; kind: string; events: number; scanned: boolean; error: string | null; notes: string[] }[];
  rules: number;
  results: { ruleId: number; title: string; matched: number; new: number; notes: string[] }[];
  newHits: number;
}

export interface DetectionHit {
  id: number;
  ruleId: number | null;
  ruleTitle: string;
  ruleVersion: number;
  ruleLevel: string;
  techniques: string[];
  evidenceId: number | null;
  evidence: string;
  position: string;
  eventTime: string;
  event: { label?: string; fields?: [string, string][] };
  explanation: DetectionExplanation;
  status: "new" | "false_positive" | "dismissed" | "promoted";
  findingId: number | null;
  createdAt: string;
}

export interface DetectionHitPage {
  items: DetectionHit[];
  total: number;
  counts: Record<string, number>;
}

export interface DetectionEngine {
  spec: string;
  modifiers: string[];
  unsupported: string[];
  categories: string[];
  services: string[];
  yara: { engine: string; modules: string[]; unsupported: string[]; limits: { ruleFileKb: number; stringsPerRule: number; scanSeconds: number; fileMb: number; matchesPerString: number } };
  correlation?: { types: CorrelationType[]; unsupported: string[]; maxTimespan: string; maxChain: number };
}

/** What a YARA rule file says about itself (`meta` of a YARA library entry). */
export interface YaraMeta {
  rules: { name: string; tags: string[]; metas: [string, string][]; private: boolean; global: boolean }[];
  imports: string[];
  description: string;
  author: string;
  level: string;
  references: string[];
  techniques: string[];
  tags: string[];
}

/** A YARA rule of the library that matched the file File Triage analysed. */
export interface YaraTriageMatch {
  ruleId: number;
  title: string;
  version: number;
  level: string;
  techniques: string[];
  rule: string;
  tags: string[];
  metas: [string, string][];
  strings: YaraStringHit[];
}

export interface YaraTriageScan {
  files: number;
  matches: YaraTriageMatch[];
  failed: [string, string][];
  notes: string[];
}

export interface AttackRuleCoverage {
  ruleId: number;
  kind: "sigma" | "yara";
  title: string;
  enabled: boolean;
  runnable: boolean;
  tested: boolean;
}


/* ───────────── OWASP ASVS assessments (docs/DATA_MODEL.md#asvs-assessments-schema-25) ───────────── */

export type AsvsStatus = "not_assessed" | "compliant" | "non_compliant" | "not_applicable" | "needs_review";

export interface AsvsRequirement {
  id: string;
  chapter: string;
  section: string;
  text: string;
  level: 1 | 2 | 3;
}

export interface AsvsCatalog {
  name: string;
  version: string;
  source: string;
  license: string;
  chapters: { id: string; name: string; sections: { id: string; name: string }[] }[];
  requirements: AsvsRequirement[];
}

export interface AsvsCounts {
  total: number;
  notAssessed: number;
  compliant: number;
  nonCompliant: number;
  notApplicable: number;
  needsReview: number;
}

export interface AsvsChapterGap {
  id: string;
  name: string;
  total: number;
  compliant: number;
  nonCompliant: number;
  /** non-compliant requirements an active exception covers */
  excepted: number;
  needsReview: number;
  notAssessed: number;
  notApplicable: number;
}

export interface AsvsGap {
  requirement: string;
  text: string;
  level: number;
  chapter: string;
  exception: { id: number; title: string; owner: string; approver: string; expiresAt: string; standing: RiskStanding } | null;
  findings: { id: number; title: string; severity: string; status: string }[];
  remediation: string;
}

export interface AsvsGaps {
  summary: AsvsSummary;
  chapters: AsvsChapterGap[];
  gaps: AsvsGap[];
  /** compliant requirements no evidence supports */
  withoutEvidence: string[];
  exceptionsExpired: number;
}

export interface AsvsComparison {
  from: AsvsSummary;
  to: AsvsSummary;
  improved: number;
  regressed: number;
  changed: number;
  unchanged: number;
  changes: { requirement: string; text: string; from: AsvsStatus; to: AsvsStatus; direction: "improved" | "regressed" | "changed" }[];
}

export interface AsvsSummary {
  id: number;
  projectId: number;
  name: string;
  version: string;
  level: 1 | 2 | 3;
  scope: string;
  counts: AsvsCounts;
  createdAt: string;
  updatedAt: string;
}

export interface AsvsItem {
  requirement: AsvsRequirement;
  inLevel: boolean;
  status: AsvsStatus;
  note: string;
  updatedAt: string | null;
  findings: { id: number; title: string; severity: Severity; status: string }[];
  evidence: { id: number; title: string }[];
  mappings: { id: number; framework: string; reference: string; note: string; origin: "analyst" }[];
}

export interface AsvsView {
  summary: AsvsSummary;
  items: AsvsItem[];
  history: { requirement: string; fromStatus: AsvsStatus; toStatus: AsvsStatus; note: string; actor: string; at: string }[];
}
