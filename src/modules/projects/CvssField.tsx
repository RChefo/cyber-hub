import { Button } from "@heroui/react";
import { Calculator } from "lucide-react";
import { useEffect, useState } from "react";
import { SeverityBadge } from "@/components/ui/Badges";
import { TextInput } from "@/components/ui/Fields";
import { api, errorMessage } from "@/lib/ipc";
import type { CvssResult, Severity } from "@/lib/types";
import { buildVector, type CvssVersion, defaultSelection, METRICS, ratingSeverity, vectorParts, versionOf } from "./cvssForm";

const VERSIONS: CvssVersion[] = ["4.0", "3.1"];

/**
 * CVSS vector with a live score from the backend, an optional base-metric calculator, and a
 * suggestion to align the finding's severity with the rating.
 */
export function CvssField({ value, onChange, severity, onSeverity }: { value: string; onChange: (v: string) => void; severity: Severity; onSeverity: (s: Severity) => void }) {
  const [result, setResult] = useState<CvssResult | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [version, setVersion] = useState<CvssVersion>(versionOf(value) ?? "4.0");

  useEffect(() => {
    const v = value.trim();
    if (!v) {
      setResult(null);
      setProblem(null);
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api
        .cvssScore(v)
        .then((r) => {
          if (!live) return;
          setResult(r);
          setProblem(null);
        })
        .catch((e) => {
          if (!live) return;
          setResult(null);
          setProblem(errorMessage(e));
        });
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [value]);

  const selection = { ...defaultSelection(version), ...(versionOf(value) === version ? vectorParts(value) : {}) };
  const pick = (key: string, id: string) => onChange(buildVector(version, { ...selection, [key]: id }, value));
  const switchVersion = (v: CvssVersion) => {
    setVersion(v);
    if (versionOf(value) !== v) onChange(buildVector(v, defaultSelection(v)));
  };
  const toggle = () => {
    if (!open && !value.trim()) onChange(buildVector(version, defaultSelection(version)));
    setOpen(!open);
  };
  const suggested = result ? ratingSeverity(result.rating) : null;

  return (
    <div className="flex flex-col gap-2 md:col-span-2">
      <div className="flex items-end gap-2">
        <TextInput label="CVSS vector (optional)" value={value} onChange={onChange} placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" mono className="min-w-0 flex-1" />
        <Button variant="tertiary" size="sm" className="mb-0.5" onPress={toggle} aria-expanded={open}>
          <Calculator className="size-3.5" />
          {open ? "Hide calculator" : "Calculator"}
        </Button>
      </div>
      {result && (
        <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
          <SeverityBadge severity={ratingSeverity(result.rating)} score={result.score} />
          <span>
            CVSS {result.version} · {result.label}
            {result.score !== result.baseScore && ` · base score ${result.baseScore.toFixed(1)}`}
          </span>
          {suggested && suggested !== severity && (
            <Button size="sm" variant="ghost" className="h-7" onPress={() => onSeverity(suggested)}>
              Set severity to {suggested}
            </Button>
          )}
        </div>
      )}
      {problem && <p className="text-[12px] text-danger">{problem}</p>}
      {open && (
        <div className="panel-inset flex flex-col gap-2 px-3 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex gap-1" role="group" aria-label="CVSS version">
              {VERSIONS.map((v) => (
                <Button key={v} size="sm" className="h-7" variant={version === v ? "primary" : "tertiary"} onPress={() => switchVersion(v)} aria-pressed={version === v}>
                  CVSS {v}
                </Button>
              ))}
            </div>
            {/* the score stays in view while metrics are chosen */}
            {result && (
              <div className="flex items-center gap-2 text-[12px] text-muted" aria-live="polite">
                <SeverityBadge severity={ratingSeverity(result.rating)} score={result.score} />
                {result.label}
              </div>
            )}
          </div>
          {METRICS[version].map((m) => (
            <div key={m.key} className="grid grid-cols-1 items-center gap-1 sm:grid-cols-[220px_minmax(0,1fr)] sm:gap-2" role="group" aria-label={m.label}>
              <span className="text-[12px] text-muted">{m.label}</span>
              <div className="flex flex-wrap gap-1">
                {m.values.map((o) => (
                  <Button key={o.id} size="sm" className="h-7 px-2.5 text-[12px]" variant={selection[m.key] === o.id ? "primary" : "tertiary"} onPress={() => pick(m.key, o.id)} aria-pressed={selection[m.key] === o.id}>
                    {o.label}
                  </Button>
                ))}
              </div>
            </div>
          ))}
          <p className="text-[11.5px] text-muted">Environmental and supplemental metrics can be typed into the vector. Scores are computed as in FIRST's calculators and are always shown with the vector.</p>
        </div>
      )}
    </div>
  );
}
