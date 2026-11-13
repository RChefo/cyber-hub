// SPDX-License-Identifier: Apache-2.0
/**
 * Shared state of an open investigation: the registry (entity/relationship types, sources),
 * the investigation itself and navigation helpers used by every tab.
 */
import { createContext, useContext } from "react";
import type { EntityTypeInfo, Investigation, ProviderInfo, Registry, RelationshipTypeInfo } from "./types";

export type OsintTab = "overview" | "graph" | "entities" | "timeline" | "sources" | "reports";

export interface RegistryMaps {
  raw: Registry;
  entityTypes: EntityTypeInfo[];
  entityTypeLabel: (id: string) => string;
  relationshipTypes: Map<string, RelationshipTypeInfo>;
  providers: Map<string, ProviderInfo>;
}

export function registryMaps(r: Registry): RegistryMaps {
  const labels = new Map(r.entityTypes.map((t) => [t.id, t.label]));
  return {
    raw: r,
    entityTypes: r.entityTypes,
    entityTypeLabel: (id) => labels.get(id) ?? id,
    relationshipTypes: new Map(r.relationshipTypes.map((t) => [t.id, t])),
    providers: new Map(r.providers.map((p) => [p.id, p])),
  };
}

export interface OsintContext {
  investigation: Investigation;
  registry: RegistryMaps;
  /** open the entity inspector (a side sheet at page level) */
  openEntity: (id: number) => void;
  openRelationship: (id: number) => void;
  /** switch to Link Analysis with this saved graph */
  openGraph: (graphId: number) => void;
  /** switch tab; `focusEntity` selects an entity in the graph */
  goTab: (tab: OsintTab) => void;
  /** start a discovery for an entity (opens the Data Sources tab with the form prefilled) */
  collectFor: (entityId: number, provider?: string) => void;
}

export const Ctx = createContext<OsintContext | null>(null);

export function useOsint(): OsintContext {
  const c = useContext(Ctx);
  if (!c) throw new Error("useOsint outside an investigation");
  return c;
}
