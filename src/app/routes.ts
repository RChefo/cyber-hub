import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BookMarked,
  Boxes,
  FolderKanban,
  LayoutDashboard,
  Search,
  Settings,
  ShieldAlert,
  SquareTerminal,
  Syringe,
  Wrench,
} from "lucide-react";

export type PageId =
  | "dashboard"
  | "projects"
  | "runs"
  | "tools"
  | "commands"
  | "payloads"
  | "dorks"
  | "resources"
  | "intel"
  | "utilities"
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
      { id: "dorks", label: "Dorks Studio", icon: Search, description: "Advanced search query builder" },
      { id: "resources", label: "Cyber Resources", icon: BookMarked, description: "Curated security websites" },
      { id: "intel", label: "Vulnerability Intel", icon: ShieldAlert, description: "CVE search and details" },
    ],
  },
  {
    label: "Toolkit",
    items: [{ id: "utilities", label: "Security Utilities", icon: Wrench, description: "Encoders, parsers and analyzers" }],
  },
];

export const SETTINGS_ITEM: NavItem = { id: "settings", label: "Settings", icon: Settings, description: "Preferences and data" };

export const ALL_NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), SETTINGS_ITEM];

export function navItem(id: PageId): NavItem {
  return ALL_NAV.find((n) => n.id === id) ?? ALL_NAV[0];
}
