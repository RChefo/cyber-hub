import type { Tone } from "@/components/ui/Badges";
import type { ScanImportOptions, ScanImportOutcome, ScanImportPreview } from "@/lib/types";

export const OUTCOME_META: Record<ScanImportOutcome, { label: string; tone: Tone }> = {
  new: { label: "New", tone: "accent" },
  seen_again: { label: "Already recorded", tone: "default" },
  recurring: { label: "Resolved, reported again", tone: "warning" },
  dismissed: { label: "Dismissed earlier", tone: "default" },
  out_of_scope: { label: "Outside the scope", tone: "danger" },
  info: { label: "Informational", tone: "default" },
};

/** How many findings an import would create with these options. */
export function importCount(p: ScanImportPreview, o: ScanImportOptions): number {
  return p.counts.new + (o.includeInfo ? p.counts.info : 0);
}

/** Findings of the file that are already in the project (in any state). */
export function knownCount(p: ScanImportPreview): number {
  return p.counts.seenAgain + p.counts.recurring + p.counts.dismissed;
}

/** True when importing would change nothing: no new findings, no sightings, no assets. */
export function nothingToImport(p: ScanImportPreview, o: ScanImportOptions): boolean {
  return importCount(p, o) === 0 && knownCount(p) === 0 && p.assets === 0;
}

/** The outcome shown for one item: an informational item becomes new once informational findings are included. */
export function shownOutcome(outcome: ScanImportOutcome, o: ScanImportOptions): ScanImportOutcome {
  return outcome === "info" && o.includeInfo ? "new" : outcome;
}
