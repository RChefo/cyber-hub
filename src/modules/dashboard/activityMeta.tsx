import {
  BookOpen,
  Boxes,
  Copy,
  Download,
  FileSearch,
  FolderKanban,
  ListChecks,
  Play,
  Radar,
  Rocket,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Syringe,
  Upload,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { FeaturedIcon, type FeaturedIconColor } from "@/components/vendor/untitledui/FeaturedIcon";

export const ACTIVITY_META: Record<string, { icon: LucideIcon; color: FeaturedIconColor; label: string }> = {
  tool_run: { icon: Play, color: "brand", label: "Tool runs" },
  tool_install: { icon: Download, color: "success", label: "Installs" },
  tool_launch: { icon: Rocket, color: "brand", label: "Launches" },
  tool_scan: { icon: ScanLine, color: "gray", label: "Tool scans" },
  command_copy: { icon: Copy, color: "gray", label: "Commands" },
  command_saved: { icon: ListChecks, color: "gray", label: "Commands" },
  dork_search: { icon: Search, color: "gray", label: "Dorks" },
  dork_saved: { icon: Search, color: "gray", label: "Dorks" },
  resource_open: { icon: BookOpen, color: "gray", label: "Resources" },
  project: { icon: FolderKanban, color: "brand", label: "Projects" },
  finding: { icon: ShieldAlert, color: "warning", label: "Findings" },
  wordlist: { icon: FileSearch, color: "gray", label: "Wordlists" },
  cve_search: { icon: ShieldAlert, color: "gray", label: "CVE searches" },
  utility: { icon: Wrench, color: "gray", label: "Utilities" },
  payload_copy: { icon: Syringe, color: "gray", label: "Payloads" },
  vt_lookup: { icon: ShieldCheck, color: "brand", label: "VirusTotal" },
  vt_upload: { icon: Upload, color: "warning", label: "VirusTotal uploads" },
  ti_lookup: { icon: Radar, color: "brand", label: "Threat intel" },
};

export function ActivityIcon({ kind }: { kind: string }) {
  const m = ACTIVITY_META[kind] ?? { icon: Boxes, color: "gray" as const };
  return <FeaturedIcon icon={m.icon} color={m.color} size="sm" />;
}
