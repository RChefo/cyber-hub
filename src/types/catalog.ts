// SPDX-License-Identifier: Apache-2.0
/**
 * Static catalog contracts. Static catalogs ship with the app (versioned in git);
 * user-created data lives in SQLite. The tools catalog JSON lives in
 * src-tauri/catalog/tools.json and is served by the Rust backend (single source of truth).
 */

export type OsId = "windows" | "macos" | "linux";

export type ToolKind = "cli" | "gui" | "web" | "script";

export interface ToolCategory {
  id: string;
  name: string;
  /** lucide icon name, kebab-case */
  icon: string;
  description: string;
}

export interface ToolDetect {
  /** executable names searched on PATH (no extension; PATHEXT is applied on Windows) */
  binaries: string[];
  /** extra absolute candidates per OS; supports {ProgramFiles}, {ProgramFiles(x86)}, {LOCALAPPDATA}, {APPDATA}, {HOME} */
  paths?: Partial<Record<OsId, string[]>>;
  /** arguments used to probe the version (cli tools only). Empty/absent = no probe. */
  versionArgs?: string[];
  /** regex with one capture group extracting the version. Defaults to a generic x.y.z match. */
  versionRegex?: string;
}

export interface ManagedInstall {
  os: OsId[];
  manager: "winget" | "brew" | "pipx" | "go";
  args: string[];
}

export interface ToolDependency {
  name: string;
  binaries: string[];
  optional?: boolean;
}

export interface ToolCommandExample {
  title: string;
  command: string;
  description: string;
}

export interface ToolDef {
  id: string;
  name: string;
  category: string;
  description: string;
  website: string;
  docs?: string;
  os: OsId[];
  kind: ToolKind;
  tags: string[];
  detect?: ToolDetect;
  install: Partial<Record<OsId, string[]>>;
  managed: ManagedInstall[];
  dependencies: ToolDependency[];
  commands: ToolCommandExample[];
  /** true when the tool sends traffic to a target; execution then requires an authorized project scope */
  requiresScope: boolean;
  /** id of a dedicated command builder in Command Center, if any */
  builder?: string;
}

export interface ToolCatalog {
  version: number;
  categories: ToolCategory[];
  tools: ToolDef[];
}

export type ResourceCategory =
  | "learning"
  | "intelligence"
  | "documentation"
  | "vulnerability-databases"
  | "tools-online"
  | "community";

export interface Resource {
  id: string;
  title: string;
  url: string;
  category: ResourceCategory;
  description: string;
  tags: string[];
}

export type DorkCategory =
  | "public-documents"
  | "exposed-directories"
  | "login-pages"
  | "dev-docs"
  | "config-references"
  | "tech-discovery";

export interface DorkTemplate {
  id: string;
  title: string;
  category: DorkCategory;
  description: string;
  /** Google query; `{domain}` is replaced by the user's domain. */
  query: string;
}

export type PayloadCategory =
  | "xss"
  | "sqli"
  | "ssrf"
  | "lfi"
  | "path-traversal"
  | "ssti"
  | "xxe"
  | "auth"
  | "input-validation"
  | "http";

export interface PayloadDef {
  id: string;
  title: string;
  category: PayloadCategory;
  payload: string;
  description: string;
  /** where the payload is meant to be used, e.g. "HTML body", "URL parameter" */
  context: string;
  tags: string[];
}

export interface CommandVariable {
  name: string;
  label: string;
  placeholder: string;
  default?: string;
}

export interface CommandTemplate {
  id: string;
  title: string;
  category: string;
  /** tool id from the tools catalog, if any */
  tool?: string;
  os: "any" | OsId;
  /** uses {{var}} placeholders matching `variables[].name` */
  template: string;
  description: string;
  explanation: { part: string; meaning: string }[];
  variables: CommandVariable[];
}
