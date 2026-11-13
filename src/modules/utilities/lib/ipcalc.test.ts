// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { calculate, compressIpv6, expandIpv6, parseIpv4, parseIpv6 } from "./ipcalc";

describe("ipcalc IPv4", () => {
  it("computes a /24", () => {
    const r = calculate("192.168.1.130/24");
    expect(r).toMatchObject({
      version: 4,
      network: "192.168.1.0",
      broadcast: "192.168.1.255",
      netmask: "255.255.255.0",
      wildcard: "0.0.0.255",
      firstHost: "192.168.1.1",
      lastHost: "192.168.1.254",
      scope: "Private (RFC 1918)",
      ipClass: "C",
      reversePointer: "130.1.168.192.in-addr.arpa",
    });
    expect(r.totalAddresses).toBe(256n);
    expect(r.usableHosts).toBe(254n);
  });

  it("accepts dotted masks and handles /31 and /32", () => {
    expect(calculate("10.0.0.5 255.255.255.252")).toMatchObject({ prefix: 30, network: "10.0.0.4", lastHost: "10.0.0.6" });
    expect(calculate("10.0.0.0/31").usableHosts).toBe(2n);
    expect(calculate("8.8.8.8").usableHosts).toBe(1n);
    expect(calculate("8.8.8.8").scope).toBe("Public (global unicast)");
  });

  it("classifies special ranges", () => {
    expect(calculate("100.64.1.1").scope).toMatch(/Carrier-grade/);
    expect(calculate("169.254.10.1").scope).toBe("Link-local");
    expect(calculate("203.0.113.9").scope).toMatch(/Documentation/);
    expect(calculate("239.1.1.1").scope).toBe("Multicast");
  });

  it("rejects invalid input", () => {
    expect(parseIpv4("256.1.1.1")).toBeNull();
    expect(parseIpv4("01.1.1.1")).toBeNull();
    expect(() => calculate("1.2.3.4/33")).toThrow();
    expect(() => calculate("10.0.0.1 255.0.255.0")).toThrow(/contiguous/);
    expect(() => calculate("nope")).toThrow();
  });
});

describe("ipcalc IPv6", () => {
  it("expands and compresses", () => {
    const n = parseIpv6("2001:db8::1")!;
    expect(expandIpv6(n)).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(compressIpv6(n)).toBe("2001:db8::1");
    expect(compressIpv6(parseIpv6("::")!)).toBe("::");
    expect(compressIpv6(parseIpv6("fe80:0:0:1:0:0:0:1")!)).toBe("fe80:0:0:1::1");
  });

  it("computes a /64 and scopes", () => {
    const r = calculate("2001:db8:abcd:12::5/64");
    expect(r.network).toBe("2001:db8:abcd:12::");
    expect(r.lastHost).toBe("2001:db8:abcd:12:ffff:ffff:ffff:ffff");
    expect(r.totalAddresses).toBe(1n << 64n);
    expect(r.scope).toBe("Documentation");
    expect(calculate("fe80::1%eth0").scope).toBe("Link-local");
    expect(calculate("::1").scope).toBe("Loopback");
    expect(calculate("::ffff:192.0.2.1").scope).toBe("IPv4-mapped");
  });

  it("rejects malformed IPv6", () => {
    expect(parseIpv6("1::2::3")).toBeNull();
    expect(parseIpv6("12345::")).toBeNull();
    expect(parseIpv6("1:2:3:4:5:6:7")).toBeNull();
  });
});
