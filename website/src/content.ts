// Website copy. Every capability listed here exists in the desktop app (see README "Modules" and
// docs/*.md); numbers are counted from the app's catalogs. Update this file when the app changes.
import commandCenter from "./assets/screens/command-center.webp";
import dashboard from "./assets/screens/dashboard.webp";
import dorks from "./assets/screens/dorks.webp";
import mcp from "./assets/screens/mcp.webp";
import osintGraph from "./assets/screens/osint-graph.webp";
import osintOverview from "./assets/screens/osint-overview.webp";
import payloads from "./assets/screens/payloads.webp";
import projects from "./assets/screens/projects.webp";
import tools from "./assets/screens/tools.webp";
import vulnIntel from "./assets/screens/vuln-intel.webp";

/** Real screenshots of the app (2880×1800, captured from the running app with demo data). */
export const SHOT = { width: 2880, height: 1800 };
export const screens = { commandCenter, dashboard, dorks, mcp, osintGraph, osintOverview, payloads, projects, tools, vulnIntel };

/** Counted from src-tauri/catalog/tools.json, the command builders, src-tauri/src/mcp/catalog.rs and src-tauri/src/ti. */
export const facts = [
  { value: 70, label: "tools in the library, across 14 categories" },
  { value: 7, label: "command builders with structured, validated arguments" },
  { value: 7, label: "threat-intelligence sources in one lookup" },
  { value: 49, label: "MCP tools for Claude and other clients, behind your approval" },
];

export const modules: { title: string; body: string }[] = [
  { title: "Tools Library", body: "70 security tools with documentation, install steps per OS and real detection on this machine. Install through winget, pipx or go after seeing the exact command." },
  { title: "Projects and findings", body: "Engagements with an authorized scope (domains, wildcards, IPs, CIDRs, exclusions), findings with evidence, notes, run history and a Markdown report." },
  { title: "Vulnerability Intel", body: "NVD CVE search, live or from the local cache: CVSS 4.0, 3.x and 2.0 with the vector explained, CWE names, affected products, CISA KEV, add as finding." },
  { title: "Threat Intel and VirusTotal", body: "One lookup across VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan, plus local file hashing before any upload." },
  { title: "Dorks Studio", body: "A visual Google operator builder with live preview, templates, saved queries and history." },
  { title: "Payloads and Wordlists", body: "Reference detection payloads with encode-on-copy, and an index of the wordlists on your machine with preview and search." },
  { title: "Security Utilities", body: "Encoders, a JWT inspector, hash tools, regex tester, formatters, an IP/CIDR calculator, DNS lookup and an HTTP header analyzer." },
  { title: "MCP integration", body: "Claude Code, Claude Desktop and other MCP clients can use Cyber Hub through an authenticated local bridge that is off by default. Sensitive requests wait for you." },
];

export const principles: { title: string; body: string }[] = [
  { title: "Your data stays on this machine", body: "Projects, findings, investigations and history live in a local SQLite database. Credentials stay in the OS credential store. No account, no telemetry." },
  { title: "Nothing runs without you", body: "Every tool run and installation shows the exact program and arguments in a system dialog that page script cannot click." },
  { title: "Scope is enforced, not suggested", body: "Tools that touch targets run only inside an active project, and every target on the command line and inside target files must be in scope." },
  { title: "No shell in between", body: "Commands start as argument lists, never through a shell, so injected pipes or redirection do nothing. Whole process trees stop when you cancel." },
  { title: "Updates you can verify", body: "Updates are signed with the Cyber Hub key, checked before installation and installed only after you confirm." },
];

export const showcase = [
  { id: "dashboard", label: "Dashboard", src: dashboard, alt: "Cyber Hub dashboard with workstation readiness, activity, findings and tasks" },
  { id: "graph", label: "Investigation graph", src: osintGraph, alt: "OSINT link-analysis graph of a domain with IP addresses, network blocks, an autonomous system and organizations" },
  { id: "tools", label: "Tools Library", src: tools, alt: "Tools Library listing security tools with detection status" },
  { id: "command", label: "Command Center", src: commandCenter, alt: "Command Center with the Nmap builder and the generated command" },
  { id: "cve", label: "Vulnerability Intel", src: vulnIntel, alt: "CVE-2021-44228 record with CVSS scores and vector breakdown" },
  { id: "projects", label: "Projects", src: projects, alt: "Projects workspace with an engagement and its scope" },
] as const;
