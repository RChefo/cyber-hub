import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BookMarked,
  Bot,
  Boxes,
  FolderKanban,
  LibraryBig,
  LayoutDashboard,
  Network,
  Radar,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SquareTerminal,
  Syringe,
  Wrench,
} from "lucide-react";

export type PageId =
  | "dashboard"
  | "projects"
  | "library"
  | "runs"
  | "tools"
  | "commands"
  | "payloads"
  | "dorks"
  | "resources"
  | "intel"
  | "virustotal"
  | "threatintel"
  | "osint"
  | "utilities"
  | "mcp"
  | "settings";

export interface NavItem {
  id: PageId;
  label: string;
  icon: LucideIcon;
  description: string;
}

export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Workspace",
    items: [
      { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, description: "Workstation overview" },
      { id: "projects", label: "Projects", icon: FolderKanban, description: "Assessments, scope and findings" },
      { id: "library", label: "Finding Library", icon: LibraryBig, description: "Reusable finding write-ups and import rules" },
      { id: "runs", label: "Runs", icon: Activity, description: "Tool executions and installs" },
    ],
  },
  {
    label: "Arsenal",
    items: [
      { id: "tools", label: "Tools Library", icon: Boxes, description: "Catalog, detection and launch" },
      { id: "commands", label: "Command Center", icon: SquareTerminal, description: "Builders, templates, saved commands" },
      { id: "payloads", label: "Payloads & Wordlists", icon: Syringe, description: "Test strings and local wordlists" },
    ],
  },
  {
    label: "Research",
    items: [
      { id: "osint", label: "OSINT Workspace", icon: Network, description: "Investigations, entity mapping and public-source collection" },
      { id: "dorks", label: "Dorks Studio", icon: Search, description: "Advanced search query builder" },
      { id: "resources", label: "Cyber Resources", icon: BookMarked, description: "Curated security websites" },
      { id: "intel", label: "Vulnerability Intel", icon: ShieldAlert, description: "CVE search and details" },
      { id: "threatintel", label: "Threat Intel", icon: Radar, description: "Look up an indicator across intelligence providers" },
      { id: "virustotal", label: "VirusTotal", icon: ShieldCheck, description: "Reputation lookups and file analysis" },
    ],
  },
  {
    label: "Toolkit",
    items: [{ id: "utilities", label: "Security Utilities", icon: Wrench, description: "Encoders, parsers and analyzers" }],
  },
  {
    label: "Integrations",
    items: [{ id: "mcp", label: "MCP", icon: Bot, description: "AI client access, approvals and audit" }],
  },
];

export const SETTINGS_ITEM: NavItem = { id: "settings", label: "Settings", icon: Settings, description: "Preferences and data" };

export const ALL_NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), SETTINGS_ITEM];

export function navItem(id: PageId): NavItem {
  return ALL_NAV.find((n) => n.id === id) ?? ALL_NAV[0];
}
