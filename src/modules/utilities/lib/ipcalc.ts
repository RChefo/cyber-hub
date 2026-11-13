// SPDX-License-Identifier: Apache-2.0
/** IPv4 / IPv6 address and CIDR calculations using BigInt. Pure functions. */

export type IpVersion = 4 | 6;

export interface IpInfo {
  version: IpVersion;
  input: string;
  address: string;
  prefix: number;
  /** IPv4: dotted mask; IPv6: prefix notation */
  netmask: string;
  wildcard?: string;
  network: string;
  broadcast?: string;
  firstHost: string;
  lastHost: string;
  totalAddresses: bigint;
  usableHosts: bigint;
  /** e.g. "Private (RFC 1918)" */
  scope: string;
  ipClass?: string;
  expanded?: string;
  compressed?: string;
  binary?: string;
  integer: bigint;
  reversePointer: string;
}

export function parseIpv4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p.startsWith("0"))) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

export function formatIpv4(n: bigint): string {
  return [24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 255n)).join(".");
}

export function parseIpv6(input: string): bigint | null {
  let s = input.toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  // embedded IPv4 tail
  const v4m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4m) {
    const v4 = parseIpv4(v4m[2]);
    if (v4 === null) return null;
    s = `${v4m[1]}${((v4 >> 16n) & 0xffffn).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(":") : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (dbl.length === 1 && head.length !== 8) return null;
  if (dbl.length === 2 && missing < 1) return null;
  const groups = [...head, ...Array(dbl.length === 2 ? missing : 0).fill("0"), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

export function expandIpv6(n: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16).padStart(4, "0"));
  return groups.join(":");
}

export function compressIpv6(n: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

function inV4(n: bigint, cidr: string): boolean {
  const [a, p] = cidr.split("/");
  const base = parseIpv4(a)!;
  const bits = BigInt(32 - Number(p));
  return n >> bits === base >> bits;
}

function inV6(n: bigint, cidr: string): boolean {
  const [a, p] = cidr.split("/");
  const base = parseIpv6(a)!;
  const bits = BigInt(128 - Number(p));
  return n >> bits === base >> bits;
}

const V4_SCOPES: [string, string][] = [
  ["0.0.0.0/8", "This network (RFC 1122)"],
  ["10.0.0.0/8", "Private (RFC 1918)"],
  ["100.64.0.0/10", "Carrier-grade NAT (RFC 6598)"],
  ["127.0.0.0/8", "Loopback"],
  ["169.254.0.0/16", "Link-local"],
  ["172.16.0.0/12", "Private (RFC 1918)"],
  ["192.0.0.0/24", "IETF protocol assignments"],
  ["192.0.2.0/24", "Documentation (TEST-NET-1)"],
  ["192.168.0.0/16", "Private (RFC 1918)"],
  ["198.18.0.0/15", "Benchmarking (RFC 2544)"],
  ["198.51.100.0/24", "Documentation (TEST-NET-2)"],
  ["203.0.113.0/24", "Documentation (TEST-NET-3)"],
  ["224.0.0.0/4", "Multicast"],
  ["255.255.255.255/32", "Limited broadcast"],
  ["240.0.0.0/4", "Reserved (future use)"],
];

const V6_SCOPES: [string, string][] = [
  ["::/128", "Unspecified"],
  ["::1/128", "Loopback"],
  ["::ffff:0:0/96", "IPv4-mapped"],
  ["64:ff9b::/96", "IPv4/IPv6 translation"],
  ["2001:db8::/32", "Documentation"],
  ["2002::/16", "6to4"],
  ["fc00::/7", "Unique local (private)"],
  ["fe80::/10", "Link-local"],
  ["ff00::/8", "Multicast"],
  ["2000::/3", "Global unicast"],
];

export function ipv4Scope(n: bigint): string {
  return V4_SCOPES.find(([c]) => inV4(n, c))?.[1] ?? "Public (global unicast)";
}

export function ipv6Scope(n: bigint): string {
  return V6_SCOPES.find(([c]) => inV6(n, c))?.[1] ?? "Reserved / unassigned";
}

function ipv4Class(n: bigint): string {
  const first = Number(n >> 24n);
  if (first < 128) return "A";
  if (first < 192) return "B";
  if (first < 224) return "C";
  if (first < 240) return "D (multicast)";
  return "E (reserved)";
}

/** Parse "addr", "addr/prefix" or "addr mask" (IPv4 dotted mask). */
export function calculate(input: string): IpInfo {
  const raw = input.trim();
  if (!raw) throw new Error("Enter an IP address or CIDR range");
  let [addrPart, prefixPart] = raw.split("/");
  if (!prefixPart && /\s/.test(raw)) {
    const [a, m] = raw.split(/\s+/);
    addrPart = a;
    const mask = parseIpv4(m);
    if (mask === null) throw new Error("Invalid subnet mask");
    const bin = mask.toString(2).padStart(32, "0");
    if (!/^1*0*$/.test(bin)) throw new Error("Subnet mask is not contiguous");
    prefixPart = String(bin.indexOf("0") === -1 ? 32 : bin.indexOf("0"));
  }
  addrPart = addrPart.trim().replace(/^\[|\]$/g, "");

  const v4 = parseIpv4(addrPart);
  if (v4 !== null) {
    const prefix = prefixPart === undefined ? 32 : Number(prefixPart);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error("IPv4 prefix must be between 0 and 32");
    const hostBits = BigInt(32 - prefix);
    const mask = ((1n << 32n) - 1n) ^ ((1n << hostBits) - 1n);
    const network = v4 & mask;
    const broadcast = network | ((1n << hostBits) - 1n);
    const total = 1n << hostBits;
    let first = network + 1n;
    let last = broadcast - 1n;
    let usable = total - 2n;
    if (prefix >= 31) {
      first = network;
      last = broadcast;
      usable = total; // RFC 3021 point-to-point and single host
    }
    const o = formatIpv4(v4).split(".");
    return {
      version: 4,
      input: raw,
      address: formatIpv4(v4),
      prefix,
      netmask: formatIpv4(mask),
      wildcard: formatIpv4(mask ^ ((1n << 32n) - 1n)),
      network: formatIpv4(network),
      broadcast: formatIpv4(broadcast),
      firstHost: formatIpv4(first),
      lastHost: formatIpv4(last),
      totalAddresses: total,
      usableHosts: usable,
      scope: ipv4Scope(v4),
      ipClass: ipv4Class(v4),
      binary: v4.toString(2).padStart(32, "0").replace(/(.{8})(?!$)/g, "$1."),
      integer: v4,
      reversePointer: `${o.reverse().join(".")}.in-addr.arpa`,
    };
  }

  const v6 = parseIpv6(addrPart);
  if (v6 === null) throw new Error("Not a valid IPv4 or IPv6 address");
  const prefix = prefixPart === undefined ? 128 : Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) throw new Error("IPv6 prefix must be between 0 and 128");
  const hostBits = BigInt(128 - prefix);
  const all = (1n << 128n) - 1n;
  const mask = all ^ ((1n << hostBits) - 1n);
  const network = v6 & mask;
  const last = network | ((1n << hostBits) - 1n);
  const expanded = expandIpv6(v6);
  return {
    version: 6,
    input: raw,
    address: compressIpv6(v6),
    prefix,
    netmask: `/${prefix}`,
    network: compressIpv6(network),
    firstHost: compressIpv6(network),
    lastHost: compressIpv6(last),
    totalAddresses: 1n << hostBits,
    usableHosts: 1n << hostBits,
    scope: ipv6Scope(v6),
    expanded,
    compressed: compressIpv6(v6),
    integer: v6,
    reversePointer: `${expanded.replace(/:/g, "").split("").reverse().join(".")}.ip6.arpa`,
  };
}

export function formatBig(n: bigint): string {
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
