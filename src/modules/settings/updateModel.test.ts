import { describe, expect, it } from "vitest";
import type { UpdateStatus } from "@/lib/types";
import { PHASE_META, progressPercent, updateActions } from "./updateModel";

const base: UpdateStatus = {
  phase: "idle",
  currentVersion: "0.1.0",
  os: "windows",
  arch: "x86_64",
  installKind: "nsis",
  supported: true,
  supportNote: null,
  channel: "stable",
  configured: true,
  warning: null,
  lastCheck: null,
  lastResult: null,
  nextCheck: null,
  available: null,
  progress: null,
  error: null,
  autoCheck: true,
  frequencyHours: 24,
  blockers: [],
};
const release = { version: "0.2.0", date: "2026-11-05T00:00:00Z", notes: "Fixes", size: 1000 };

describe("update center actions", () => {
  it("offers checking only when a feed is configured and nothing is running", () => {
    expect(updateActions(base).check).toBe(true);
    expect(updateActions({ ...base, configured: false }).check).toBe(false);
    for (const phase of ["checking", "downloading", "verifying", "installing", "restartRequired"] as const) {
      expect(updateActions({ ...base, phase, available: release }).check).toBe(false);
    }
    // a newer release may appear after a download: checking stays possible (the backend keeps the
    // verified download when the feed still announces it)
    expect(updateActions({ ...base, phase: "ready", available: release }).check).toBe(true);
  });

  it("downloads only an available release on a copy that can update itself", () => {
    expect(updateActions({ ...base, phase: "available", available: release }).download).toBe(true);
    expect(updateActions({ ...base, phase: "cancelled", available: release }).download).toBe(true);
    expect(updateActions({ ...base, phase: "failed", available: release }).download).toBe(true);
    expect(updateActions({ ...base, phase: "failed", available: null }).download).toBe(false);
    expect(updateActions({ ...base, phase: "available", available: release, supported: false }).download).toBe(false);
  });

  it("never offers installing before the signature was verified, and waits for running work", () => {
    for (const phase of ["available", "downloading", "verifying", "failed"] as const) {
      expect(updateActions({ ...base, phase, available: release }).install).toBe(false);
    }
    expect(updateActions({ ...base, phase: "ready", available: release }).install).toBe(true);
    expect(updateActions({ ...base, phase: "ready", available: release, blockers: ["1 tool run in progress"] }).installBlocked).toBe(true);
    expect(updateActions({ ...base, phase: "restartRequired" }).restart).toBe(true);
  });

  it("labels every phase and computes progress", () => {
    expect(Object.keys(PHASE_META)).toHaveLength(11);
    expect(progressPercent({ downloaded: 50, total: 200 })).toBe(25);
    expect(progressPercent({ downloaded: 50, total: null })).toBeNull();
    expect(progressPercent({ downloaded: 300, total: 200 })).toBe(100);
    expect(progressPercent(null)).toBeNull();
  });
});
