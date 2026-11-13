// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { commitsBetween, dcoProblems, parseIdentity } from "./check-dco.mjs";

// Mission 15: contributions are accepted under the Developer Certificate of Origin.
const commit = (over = {}) => ({ sha: "abcdef0123", parents: 1, authorName: "Ada Lovelace", authorEmail: "ada@example.org", subject: "fix: a thing", signoffs: ["Ada Lovelace <ada@example.org>"], ...over });

describe("DCO rules", () => {
  it("accepts a commit signed off by its author, the email compared without case", () => {
    expect(dcoProblems([commit()])).toEqual([]);
    expect(dcoProblems([commit({ signoffs: ["A. Lovelace <ADA@example.org>"] })])).toEqual([]);
    expect(dcoProblems([commit({ signoffs: ["Someone Else <else@example.org>", "Ada Lovelace <ada@example.org>"] })])).toEqual([]);
  });

  it("refuses a missing sign-off and a sign-off by someone else", () => {
    expect(dcoProblems([commit({ signoffs: [] })])[0]).toMatch(/^abcdef0 \("fix: a thing"\): no Signed-off-by line/);
    expect(dcoProblems([commit({ signoffs: ["Mallory <m@example.org>"] })])[0]).toMatch(/the sign-off must be the author's/);
    expect(dcoProblems([commit({ signoffs: ["not an identity"] })])[0]).toMatch(/no Signed-off-by line/);
  });

  it("skips merge commits", () => {
    expect(dcoProblems([commit({ parents: 2, signoffs: [] })])).toEqual([]);
  });

  it("accepts Dependabot's signed-off commits only in Dependabot's own pull requests", () => {
    const bot = commit({ authorName: "dependabot[bot]", authorEmail: "49699333+dependabot[bot]@users.noreply.github.com", signoffs: ["dependabot[bot] <support@github.com>"] });
    expect(dcoProblems([bot], { prAuthor: "dependabot[bot]" })).toEqual([]);
    expect(dcoProblems([{ ...bot, signoffs: [] }], { prAuthor: "dependabot[bot]" })).toHaveLength(1);
    // a contributor's pull request with a commit made to look like Dependabot's
    expect(dcoProblems([bot], { prAuthor: "someone" })).toHaveLength(1);
  });

  it("reads identities", () => {
    expect(parseIdentity("Ada Lovelace <ada@example.org>")).toEqual({ name: "Ada Lovelace", email: "ada@example.org" });
    expect(parseIdentity("<ada@example.org>")).toBeNull();
    expect(parseIdentity("Ada")).toBeNull();
  });
});

describe("DCO check on a real repository", () => {
  let dir;
  const git = (...args) => execFileSync("git", args, { cwd: dir, encoding: "utf8" }).trim();
  const make = (file, message, author, signoff) => {
    writeFileSync(join(dir, file), file);
    git("add", file);
    const env = ["-c", `user.name=${author.split(" <")[0]}`, "-c", `user.email=${author.split("<")[1].slice(0, -1)}`];
    execFileSync("git", [...env, "commit", "-q", ...(signoff ? ["-s"] : []), "-m", message], { cwd: dir });
    return git("rev-parse", "HEAD");
  };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "dco-"));
    git("init", "-q", "-b", "main");
    make("base.txt", "chore: base", "Owner <owner@example.org>", false);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("passes a branch whose commits are signed off with git commit -s, merges included", () => {
    const base = git("rev-parse", "HEAD");
    git("checkout", "-q", "-b", "good");
    make("a.txt", "feat: a", "Ada Lovelace <ada@example.org>", true);
    git("checkout", "-q", "main");
    make("m.txt", "chore: main moves on", "Owner <owner@example.org>", false);
    git("checkout", "-q", "good");
    execFileSync("git", ["-c", "user.name=Ada Lovelace", "-c", "user.email=ada@example.org", "merge", "-q", "--no-ff", "-m", "Merge main", "main"], { cwd: dir });
    make("b.txt", "fix: b", "Ada Lovelace <ada@example.org>", true);
    const commits = commitsBetween(base, "HEAD", dir).filter((c) => c.subject !== "chore: main moves on");
    expect(commits.map((c) => c.parents)).toEqual([1, 2, 1]);
    expect(commits[0].signoffs).toEqual(["Ada Lovelace <ada@example.org>"]);
    expect(dcoProblems(commits)).toEqual([]);
  });

  it("fails a branch with an unsigned commit, and passes it after git rebase --signoff", () => {
    git("checkout", "-q", "main");
    const base = git("rev-parse", "HEAD");
    git("checkout", "-q", "-b", "bad");
    make("c.txt", "feat: c", "Ada Lovelace <ada@example.org>", true);
    make("d.txt", "feat: d", "Ada Lovelace <ada@example.org>", false);
    const before = dcoProblems(commitsBetween(base, "HEAD", dir));
    expect(before).toHaveLength(1);
    expect(before[0]).toMatch(/"feat: d"\): no Signed-off-by line/);
    execFileSync("git", ["-c", "user.name=Ada Lovelace", "-c", "user.email=ada@example.org", "rebase", "-q", "--signoff", base], { cwd: dir });
    expect(dcoProblems(commitsBetween(base, "HEAD", dir))).toEqual([]);
  });
});
