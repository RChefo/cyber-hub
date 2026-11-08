import type { LucideIcon } from "lucide-react";
import {
  ArrowLeftRight,
  Binary,
  FileKey,
  Lock,
  MailCheck,
  ServerCog,
  Telescope,
  Braces,
  Code2,
  Crosshair,
  FileCode2,
  Fingerprint,
  Globe2,
  Hash,
  KeyRound,
  Link2,
  Network,
  Radar,
  Regex,
  ScanSearch,
  Shuffle,
  UserRound,
  Workflow,
} from "lucide-react";

export type UtilityId =
  | "workbench"
  | "base64"
  | "url"
  | "hex"
  | "jwt"
  | "hash-id"
  | "hash-calc"
  | "ioc"
  | "regex"
  | "json"
  | "xml"
  | "html"
  | "url-parser"
  | "ip"
  | "dns"
  | "headers"
  | "user-agent"
  | "http-builder"
  | "tls"
  | "dns-intel"
  | "ports"
  | "subdomain-monitor"
  | "secrets";

export interface UtilityDef {
  id: UtilityId;
  name: string;
  description: string;
  icon: LucideIcon;
  group: "Encoding" | "Analysis" | "Formatting" | "Network" | "Assessment";
  /** true when the utility makes a network request (only on explicit action) */
  network?: boolean;
}

export const UTILITIES: UtilityDef[] = [
  { id: "workbench", name: "Transform workbench", description: "Chain encoding, hashing and text operations like a recipe.", icon: Workflow, group: "Encoding" },
  { id: "base64", name: "Base64", description: "Encode and decode Base64 and Base64url.", icon: Binary, group: "Encoding" },
  { id: "url", name: "URL encoding", description: "Percent-encode and decode text.", icon: Link2, group: "Encoding" },
  { id: "hex", name: "Hex", description: "Convert text to and from hexadecimal.", icon: Shuffle, group: "Encoding" },
  { id: "jwt", name: "JWT inspector", description: "Decode JSON Web Tokens and review claims locally.", icon: KeyRound, group: "Analysis" },
  { id: "hash-id", name: "Hash identifier", description: "Suggest likely algorithms for a hash string.", icon: Fingerprint, group: "Analysis" },
  { id: "hash-calc", name: "Hash calculator", description: "MD5, SHA-1, SHA-256, SHA-384 and SHA-512 digests.", icon: Hash, group: "Analysis" },
  { id: "ioc", name: "IOC extractor", description: "Extract, refang and defang URLs, domains, IPs, e-mail, hashes and CVE IDs from text.", icon: Crosshair, group: "Analysis" },
  { id: "regex", name: "Regex tester", description: "Test JavaScript regular expressions with live matches.", icon: Regex, group: "Analysis" },
  { id: "user-agent", name: "User-Agent parser", description: "Identify browser, engine, OS and device from a UA string.", icon: UserRound, group: "Analysis" },
  { id: "json", name: "JSON formatter", description: "Validate, pretty-print and minify JSON.", icon: Braces, group: "Formatting" },
  { id: "xml", name: "XML formatter", description: "Validate and pretty-print XML.", icon: FileCode2, group: "Formatting" },
  { id: "html", name: "HTML formatter", description: "Pretty-print HTML and escape/unescape entities.", icon: Code2, group: "Formatting" },
  { id: "url-parser", name: "URL parser", description: "Break a URL into scheme, host, path and parameters.", icon: Globe2, group: "Network" },
  { id: "ip", name: "IP & CIDR calculator", description: "Address class, ranges, masks and host counts.", icon: Network, group: "Network" },
  { id: "dns", name: "DNS lookup", description: "Query A, AAAA, MX, TXT, NS and other records.", icon: Radar, group: "Network", network: true },
  { id: "headers", name: "HTTP header analyzer", description: "Fetch or paste headers and review security headers.", icon: ScanSearch, group: "Network", network: true },
  { id: "dns-intel", name: "DNS intelligence", description: "Records plus SPF, DMARC, DKIM, CAA and DNSSEC assessment for a domain.", icon: MailCheck, group: "Network", network: true },
  { id: "ports", name: "Port & service reference", description: "What usually runs on a port, its risks, and where projects expose it.", icon: ServerCog, group: "Analysis" },
  { id: "secrets", name: "Secrets scanner", description: "Find API keys, tokens, private keys and passwords in text, files or folders.", icon: FileKey, group: "Analysis" },
  { id: "http-builder", name: "HTTP request builder", description: "Send one crafted request to an in-scope target and inspect the response.", icon: ArrowLeftRight, group: "Assessment", network: true },
  { id: "tls", name: "TLS analyzer", description: "Protocols, cipher, certificate chain and trust of an in-scope service.", icon: Lock, group: "Assessment", network: true },
  { id: "subdomain-monitor", name: "Subdomain monitor", description: "New and missing names across passive discovery runs, on a schedule.", icon: Telescope, group: "Assessment", network: true },
];
