import { describe, expect, it } from "vitest";
import { BUILDERS, defaultValues } from "./builders";
import { splitArgs } from "@/lib/utils";

const get = (id: string) => BUILDERS.find((b) => b.id === id)!;
const build = (id: string, patch: Record<string, string | boolean>) => {
  const def = get(id);
  return def.build({ ...defaultValues(def), ...patch });
};

describe("command builders", () => {
  it("covers all seven required tools", () => {
    expect(BUILDERS.map((b) => b.id).sort()).toEqual(["ffuf", "gobuster", "httpx", "nmap", "nuclei", "sqlmap", "subfinder"]);
  });

  it("nmap builds argv with targets last and validates ports", () => {
    const r = build("nmap", { target: "10.0.0.5 scanme.example.com", ports: "22,80,443" });
    expect(r.errors).toEqual([]);
    expect(r.args).toEqual(["-p", "22,80,443", "-sV", "--open", "-T3", "10.0.0.5", "scanme.example.com"]);
    expect(r.targets).toEqual(["10.0.0.5", "scanme.example.com"]);
    expect(build("nmap", { target: "10.0.0.5", ports: "80;rm" }).errors[0]).toMatch(/Ports/);
    expect(build("nmap", { target: "" }).errors).toContain("At least one target is required");
  });

  it("nmap host discovery skips port options", () => {
    const r = build("nmap", { target: "10.0.0.0/24", scan: "sn", ports: "80" });
    expect(r.args).toEqual(["-sn", "-T3", "10.0.0.0/24"]);
  });

  it("ffuf requires FUZZ and extracts the host as a target", () => {
    const r = build("ffuf", { url: "https://app.example.com/FUZZ", wordlist: "common.txt" });
    expect(r.errors).toEqual([]);
    expect(r.targets).toEqual(["app.example.com"]);
    expect(r.args.slice(0, 4)).toEqual(["-u", "https://app.example.com/FUZZ", "-w", "common.txt"]);
    expect(build("ffuf", { url: "https://app.example.com/", wordlist: "x" }).errors[0]).toMatch(/FUZZ/);
  });

  it("gobuster dns mode targets the domain", () => {
    const r = build("gobuster", { mode: "dns", domain: "Example.com", wordlist: "subs.txt" });
    expect(r.errors).toEqual([]);
    expect(r.args).toEqual(["dns", "-d", "example.com", "-w", "subs.txt", "-t", "10"]);
    expect(r.targets).toEqual(["example.com"]);
  });

  it("nuclei excludes dos templates by default", () => {
    const r = build("nuclei", { url: "https://app.example.com" });
    expect(r.args).toContain("-etags");
    expect(r.args[r.args.indexOf("-etags") + 1]).toBe("dos,fuzz");
  });

  it("sqlmap defaults to the safest level and risk", () => {
    const r = build("sqlmap", { url: "https://app.example.com/item?id=1", param: "id" });
    expect(r.args).toEqual(["-u", "https://app.example.com/item?id=1", "-p", "id", "--level=1", "--risk=1", "--batch"]);
  });

  it("subfinder validates domains", () => {
    expect(build("subfinder", { domain: "not a domain" }).errors[0]).toMatch(/valid domain/);
    expect(build("subfinder", { domain: "example.org" }).targets).toEqual(["example.org"]);
  });

  it("httpx joins multiple targets", () => {
    const r = build("httpx", { target: "a.example.com b.example.com" });
    expect(r.args.slice(0, 2)).toEqual(["-u", "a.example.com,b.example.com"]);
    expect(r.targets).toHaveLength(2);
  });
});

describe("splitArgs", () => {
  it("handles quotes and escapes without a shell", () => {
    expect(splitArgs(`-u 'https://x/?a=1&b=2' --data "a=\\"q\\"" ''`)).toEqual(["-u", "https://x/?a=1&b=2", "--data", 'a="q"', ""]);
    expect(splitArgs("a | b ; c")).toEqual(["a", "|", "b", ";", "c"]);
    expect(() => splitArgs("'open")).toThrow();
  });
});
