// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { Asset, DiscoverySnapshot, Project } from "@/lib/types";
import { certaintyOf, latestBySource, matchesFilter, suggestedScanTargets, summarize } from "./asm";

const asset = (id: number, type: Asset["type"], value: string, status: Asset["status"] = "active", data: unknown = {}): Asset => ({
  id,
  projectId: 1,
  type,
  value,
  status,
  confidence: "medium",
  source: "passive",
  osintEntityId: null,
  data,
  firstSeen: "t",
  lastSeen: "t",
  updatedAt: "t",
});

describe("attack surface helpers", () => {
  it("summarizes assets by status and type", () => {
    const s = summarize([asset(1, "ip", "192.0.2.1"), asset(2, "ip", "192.0.2.2", "not_observed"), asset(3, "subdomain", "a.example.com", "retired")]);
    expect(s.total).toBe(3);
    expect(s.byStatus).toEqual({ active: 1, not_observed: 1, retired: 1 });
    expect(s.byType).toEqual({ ip: 2, subdomain: 1 });
  });

  it("reads the recorded certainty and ignores unknown values", () => {
    expect(certaintyOf(asset(1, "ip", "x", "active", { certainty: "confirmed" }))).toBe("confirmed");
    expect(certaintyOf(asset(1, "ip", "x", "active", { certainty: "sure" }))).toBeNull();
    expect(certaintyOf(asset(1, "ip", "x", "active", null))).toBeNull();
  });

  it("suggests only in-scope hosts and networks as scan targets", () => {
    const p = {
      targets: [
        { id: 1, value: "192.0.2.0/24", kind: "cidr", inScope: true, note: "" },
        { id: 2, value: "192.0.2.5", kind: "ip", inScope: false, note: "" },
        { id: 3, value: "*.example.com", kind: "wildcard", inScope: true, note: "" },
        { id: 4, value: "example.com", kind: "domain", inScope: true, note: "" },
      ],
    } as unknown as Project;
    expect(suggestedScanTargets(p)).toEqual(["192.0.2.0/24", "example.com"]);
  });

  it("filters by type, status and text", () => {
    const a = asset(1, "subdomain", "API.example.com");
    expect(matchesFilter(a, { type: "all", status: "all", query: "api" })).toBe(true);
    expect(matchesFilter(a, { type: "ip", status: "all", query: "" })).toBe(false);
    expect(matchesFilter(a, { type: "all", status: "retired", query: "" })).toBe(false);
  });

  it("finds the newest run of each source", () => {
    const s = (id: number, source: DiscoverySnapshot["source"]) => ({ id, source }) as DiscoverySnapshot;
    const latest = latestBySource([s(3, "passive"), s(5, "http"), s(4, "passive")]);
    expect(latest.passive?.id).toBe(4);
    expect(latest.http?.id).toBe(5);
    expect(latest.nmap).toBeUndefined();
  });
});

describe("asset descriptions", () => {
  it("summarizes what discovery recorded", async () => {
    const { describeAsset } = await import("./asm");
    expect(describeAsset(asset(1, "http_service", "https://a.example.com", "active", { status: 200, title: "Sign in", tlsTrusted: false }))).toBe("HTTP 200 · Sign in · certificate not trusted");
    expect(describeAsset(asset(2, "ip", "192.0.2.1", "active", { names: ["a", "b", "c", "d"], inScope: false }))).toBe("a, b, c +1 · outside the authorized scope");
    // a cloud resource from a configuration audit (Mission 6)
    expect(
      describeAsset(asset(3, "cloud_resource", "arn:aws:s3:::logs", "active", { provider: "aws", account: "123456789012", accountName: "production", region: "eu-west-1", resourceType: "AwsS3Bucket", owner: "data-team", exposure: { level: "public", basis: "Prowler check s3_bucket_public_access failed" } })),
    ).toBe("AWS · account 123456789012 (production) · eu-west-1 · AwsS3Bucket · owner data-team · public: Prowler check s3_bucket_public_access failed");
    expect(describeAsset(asset(4, "cloud_resource", "projects/p/zones/z/instances/i", "active", { provider: "gcp", service: "compute" }))).toBe("Google Cloud · compute");
    expect(describeAsset(asset(3, "service", "192.0.2.1:22/tcp", "active", { service: "ssh", product: "OpenSSH", version: "9.6" }))).toBe("ssh · OpenSSH 9.6");
    expect(describeAsset(asset(4, "endpoint", "https://a.example.com/x", "active", null))).toBe("");
  });
});

describe("asset counts", () => {
  it("uses singular and plural forms", async () => {
    const { countLabel } = await import("./asm");
    expect(countLabel(1, "subdomain")).toBe("1 subdomain");
    expect(countLabel(4, "subdomain")).toBe("4 subdomains");
    expect(countLabel(1, "ip")).toBe("1 IP address");
    expect(countLabel(2, "ip")).toBe("2 IP addresses");
    expect(countLabel(3, "technology")).toBe("3 technologies");
  });
});

