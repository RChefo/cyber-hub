import type { ApiEndpoint, ApiEndpointScope, ApiSpecSummary } from "@/lib/types";
import type { Tone } from "@/components/ui/Badges";

export const API_FORMAT_LABEL: Record<string, string> = {
  "openapi-3.0": "OpenAPI 3.0",
  "openapi-3.1": "OpenAPI 3.1",
  "swagger-2.0": "Swagger 2.0",
  postman: "Postman collection",
  har: "HAR capture",
};

export const METHOD_TONE: Record<string, Tone> = { GET: "accent", HEAD: "default", OPTIONS: "default", POST: "success", PUT: "warning", PATCH: "warning", DELETE: "danger", TRACE: "danger" };

/** Who may call an endpoint, in words: "None", "bearerAuth", "a or b + c", "Optional (bearerAuth)". */
export function authLabel(e: Pick<ApiEndpoint, "auth" | "anonymous">): string {
  if (e.auth.length === 0) return "None";
  const alternatives = e.auth.map((a) => a.join(" + ")).join(" or ");
  return e.anonymous ? `Optional (${alternatives})` : alternatives;
}

export type EndpointView = "all" | "anonymous" | "outOfScope" | "deprecated";

export interface EndpointFilter {
  text: string;
  method: string;
  view: EndpointView;
}

/** Indices of the endpoints that match the filter (`scope` is in the same order as `endpoints`). */
export function filterEndpoints(endpoints: ApiEndpoint[], scope: ApiEndpointScope[], f: EndpointFilter): number[] {
  const text = f.text.trim().toLowerCase();
  const out: number[] = [];
  endpoints.forEach((e, i) => {
    if (f.method !== "all" && e.method !== f.method) return;
    if (f.view === "anonymous" && !e.anonymous) return;
    if (f.view === "outOfScope" && scope[i]?.inScope !== false) return;
    if (f.view === "deprecated" && !e.deprecated) return;
    if (text) {
      const hay = [e.method, e.path, e.summary, e.operationId, ...e.tags, ...e.params.map((p) => p.name), ...e.bodyFields].join(" ").toLowerCase();
      if (!hay.includes(text)) return;
    }
    out.push(i);
  });
  return out;
}

/** Navigation parameters that open the HTTP request builder on an endpoint. */
export function builderParams(projectId: number, method: string, url: string): Record<string, string> {
  return { utility: "http-builder", project: String(projectId), method, url };
}

/** "2 high, 3 medium" from a summary's issue counts; "no issues" when there are none. */
export function issueSummary(s: Pick<ApiSpecSummary, "issues">): string {
  const names = ["critical", "high", "medium", "low", "info"];
  const parts = s.issues.map((n, i) => (n > 0 ? `${n} ${names[i]}` : "")).filter(Boolean);
  return parts.length ? parts.join(", ") : "no issues";
}
