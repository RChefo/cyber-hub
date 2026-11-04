/** Wire types of the OSINT workspace commands (mirror src-tauri/src/osint and commands/osint.rs). */

export type Verification = "observed" | "verified" | "inferred" | "disputed" | "rejected";
export type Confidence = "low" | "medium" | "high";
export type Strength = "direct" | "corroborating" | "weak";
export type Origin = "observed" | "derived" | "inferred" | "manual" | "suggested";
export type InvestigationStatus = "active" | "archived" | "closed";

export interface EntityTypeInfo {
  id: string;
  label: string;
  target: boolean;
}

export interface RelationshipTypeInfo {
  id: string;
  label: string;
  category: string;
  directed: boolean;
  inferred: boolean;
  description: string;
}

export interface ProviderInfo {
  id: string;
  name: string;
  category: string;
  description: string;
  inputs: string[];
  usesThreatIntel: boolean;
  contactsTarget: boolean;
  rate: [number, number];
  cacheHours: number;
  sourceUrl: string;
  terms: string;
}

export interface Registry {
  entityTypes: EntityTypeInfo[];
  relationshipTypes: RelationshipTypeInfo[];
  providers: ProviderInfo[];
  eventKinds: string[];
  running: number;
}

export interface Counts {
  entities: number;
  relationships: number;
  evidence: number;
  graphs: number;
  operations: number;
  pendingReview: number;
  flagged: number;
}

export interface Investigation {
  id: number;
  name: string;
  description: string;
  targetType: string;
  targetValue: string;
  status: InvestigationStatus;
  tags: string[];
  notes: string;
  authorization: string;
  projectId: number | null;
  projectName: string | null;
  createdAt: string;
  updatedAt: string;
  lastOpenedAt: string | null;
  counts: Counts;
}

export interface InvestigationInput {
  name: string;
  description: string;
  targetType: string;
  targetValue: string;
  tags: string[];
  notes: string;
  authorization: string;
  projectId: number | null;
}

export interface EntityBrief {
  id: number;
  type: string;
  value: string;
  displayName: string;
  verification: Verification;
  confidence: Confidence;
  flagged: boolean;
}

export interface EntityRow extends EntityBrief {
  firstSeen: string;
  lastSeen: string;
  relationships: number;
  evidence: number;
  sources: string[];
}

export interface EntityQuery {
  q?: string;
  type?: string;
  verification?: string;
  flagged?: boolean;
  offset?: number;
  limit?: number;
  sort?: "recent" | "value" | "connections";
}

export interface Page<T> {
  total: number;
  offset: number;
  items: T[];
}

export interface Evidence {
  id: number;
  kind: string;
  source: string;
  reference: string | null;
  observedAt: string;
  collectedAt: string;
  operationId: number | null;
  executionId: number | null;
  summary: string;
  data: unknown;
  strength: Strength;
}

export interface RelationshipBrief {
  id: number;
  source: number;
  target: number;
  type: string;
  directed: boolean;
  origin: Origin;
  verification: Verification;
  confidence: Confidence;
}

export interface RelatedEntity {
  relationship: RelationshipBrief;
  other: EntityBrief;
  direction: "out" | "in";
}

export interface TimelineEvent {
  id: number;
  at: string;
  kind: string;
  summary: string;
  source: string | null;
  entityId: number | null;
  relationshipId: number | null;
  operationId: number | null;
  graphId: number | null;
}

export interface EntityDetail extends EntityBrief {
  investigationId: number;
  aliases: string[];
  metadata: Record<string, unknown>;
  notes: string;
  firstSeen: string;
  lastSeen: string;
  confidenceReason: string;
  related: RelatedEntity[];
  relatedTotal: number;
  evidence: Evidence[];
  events: TimelineEvent[];
  mergedFrom: unknown[];
}

export interface RelationshipDetail extends RelationshipBrief {
  investigationId: number;
  label: string;
  category: string;
  description: string;
  sourceEntity: EntityBrief;
  targetEntity: EntityBrief;
  confidenceReason: string;
  metadata: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
  evidence: Evidence[];
  events: TimelineEvent[];
}

export interface GraphMeta {
  id: number;
  investigationId: number;
  investigationName: string;
  primaryTarget: string;
  name: string;
  description: string;
  followNew: boolean;
  revision: number;
  createdAt: string;
  updatedAt: string;
  lastOpenedAt: string | null;
  entityCount: number;
  relationshipCount: number;
  versionCount: number;
  latestVersion: number | null;
}

export interface GraphNodeState {
  entityId: number;
  x: number | null;
  y: number | null;
  pinned: boolean;
  hidden: boolean;
  group: string | null;
}

export interface GraphData {
  graph: GraphMeta;
  workspace: unknown;
  nodes: GraphNodeState[];
  entities: EntityBrief[];
  relationships: RelationshipBrief[];
  warning: string | null;
}

export interface GraphSave {
  baseRevision: number;
  nodes: GraphNodeState[];
  removed: number[];
  workspace: unknown;
  versionLabel?: string | null;
  manualVersion?: boolean;
}

export interface SaveResult {
  revision: number;
  version: number | null;
  mergedConcurrentChanges: boolean;
}

export interface Diff {
  entitiesAdded: [number, string, string][];
  entitiesRemoved: [number, string, string][];
  relationshipsAdded: [number, string][];
  relationshipsRemoved: [number, string][];
  verificationChanges: [number, string, string, string][];
  evidenceChanges: [number, string, number, number][];
  nodesMoved: number;
  workspaceChanged: boolean;
}

export interface VersionRow {
  id: number;
  number: number;
  createdAt: string;
  kind: "save" | "manual" | "restore" | "import" | "created";
  label: string;
  /** a Diff against the previous version, or counts for the first one */
  summary: Partial<Diff> | { entitiesAdded: number; relationshipsAdded: number };
  entityCount: number;
  relationshipCount: number;
}

export interface TimelineQuery {
  kinds?: string[];
  from?: string | null;
  to?: string | null;
  entityId?: number | null;
  relationshipId?: number | null;
  source?: string | null;
  q?: string | null;
  offset?: number;
  limit?: number;
}

export interface SharedEntity {
  type: string;
  value: string;
  aId: number;
  bId: number;
  aRelationships: number;
  bRelationships: number;
}

export interface Component {
  entities: number[];
  relationships: number;
}

export interface Centrality {
  entity: number;
  degree: number;
  normalized: number;
  byType: Record<string, number>;
}

export interface SharedInfrastructure {
  infrastructure: number;
  via: string;
  members: number[];
  relationships: number[];
  note: string;
}

export interface Overview {
  entities: number;
  relationships: number;
  components: Component[];
  hubs: Centrality[];
  isolated: number[];
  sharedInfrastructure: SharedInfrastructure[];
  explanation: string[];
}

export interface GraphPath {
  entities: number[];
  relationships: number[];
  explanation: string;
}

export interface Suggestion {
  kind: "review_inferred" | "resolve_duplicates" | "corroborate" | "collect" | "review_flagged" | "connect_isolated";
  title: string;
  reason: string;
  entityIds: number[];
  relationshipIds: number[];
  provider: string | null;
}

export interface Operation {
  id: number;
  investigationId: number;
  provider: string;
  providerName: string;
  inputType: string;
  inputValue: string;
  inputEntityId: number | null;
  status: "running" | "completed" | "failed" | "cancelled";
  requestedBy: string;
  startedAt: string;
  finishedAt: string | null;
  resultCount: number;
  message: string | null;
  importedAt: string | null;
  importedCount: number;
}

export interface ObservationEntity {
  type: string;
  value: string;
  displayName?: string | null;
  metadata?: Record<string, unknown>;
  flagged?: boolean;
}

export interface ObservationRelationship {
  source: number;
  target: number;
  type: string;
  strength: Strength;
  origin: Origin;
  metadata?: Record<string, unknown>;
}

export interface Observation {
  evidence: { kind: string; source: string; reference?: string | null; observedAt?: string | null; summary: string; data?: unknown; strength: Strength };
  entities: ObservationEntity[];
  relationships: ObservationRelationship[];
}

export interface OperationDetail extends Operation {
  results: Observation[];
  truncated: boolean;
  rateNote: string | null;
}

export interface ChangeSummary {
  evidenceId: number | null;
  newEntities: number[];
  updatedEntities: number[];
  newRelationships: number[];
  updatedRelationships: number[];
  inferredRelationships: number[];
  rejected: string[];
}

export interface DiscoverRequest {
  investigationId: number;
  provider: string;
  entityId?: number | null;
  entityType?: string | null;
  value?: string | null;
  autoImport?: boolean;
  refresh?: boolean;
}

export interface ResultSelection {
  /** [observation index, entity index] */
  entities: [number, number][];
  /** [observation index, relationship index] */
  relationships: [number, number][];
}

export interface ImportSource {
  kind: "run" | "lookup" | "cve" | "finding" | "scope";
  id: string;
  label: string;
  detail: string;
  at: string;
}

export interface ImportPreview {
  format: string;
  graphName: string;
  investigationName: string;
  target: string;
  entities: number;
  relationships: number;
  evidence: number;
  byType: Record<string, number>;
  warnings: string[];
  existingMatches: number;
}

export interface PendingImport {
  token: string;
  fileName: string;
  preview: ImportPreview;
}

export interface Neighborhood {
  entities: EntityBrief[];
  relationships: RelationshipBrief[];
}

export interface ManualEntityInput {
  investigationId: number;
  type: string;
  value: string;
  note: string;
  linkTo?: number | null;
  linkType?: string | null;
  linkOutgoing?: boolean;
}

export type ExportFormat = "json" | "graphml" | "csv-entities" | "csv-relationships";
