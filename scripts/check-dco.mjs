#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Developer Certificate of Origin check (Mission 15). CI runs it on every pull request:
//
//   node scripts/check-dco.mjs <base sha> <head sha>      (env PR_AUTHOR: the pull request's author)
//
// Every commit between base and head, merge commits aside, needs a `Signed-off-by:` trailer whose email
// is the commit author's (git commit -s writes exactly that). Commits of an automated account are
// accepted only when that account opened the pull request itself and the commits carry its sign-off:
// naming a commit's author "dependabot[bot]" in a contributor's pull request does not bypass the check.
// See DCO (the certificate) and CONTRIBUTING.md, "Sign-off". Only Node built-ins and git.
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Automated accounts whose commits come signed off by the account (login → commit author email). */
export const BOTS = {
  "dependabot[bot]": "49699333+dependabot[bot]@users.noreply.github.com",
};

/** `Name <email>` → { name, email }, or null. */
export function parseIdentity(text) {
  const m = /^\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(text || "");
  return m && m[1] ? { name: m[1], email: m[2] } : null;
}

/**
 * Problems with the commits of a pull request. A commit is
 * `{ sha, parents, authorName, authorEmail, signoffs: ["Name <email>", …] }`.
 */
export function dcoProblems(commits, { prAuthor = "" } = {}) {
  const problems = [];
  for (const c of commits) {
    if (c.parents > 1) continue;
    const short = c.sha.slice(0, 7);
    const signoffs = c.signoffs.map(parseIdentity).filter(Boolean);
    const bot = BOTS[prAuthor];
    if (bot && c.authorName === prAuthor && c.authorEmail.toLowerCase() === bot.toLowerCase()) {
      if (!signoffs.length) problems.push(`${short}: a commit of ${prAuthor} without its Signed-off-by`);
      continue;
    }
    if (!signoffs.length) {
      problems.push(`${short} ("${c.subject}"): no Signed-off-by line. Sign it with git commit -s (CONTRIBUTING.md, "Sign-off")`);
      continue;
    }
    if (!signoffs.some((s) => s.email.toLowerCase() === c.authorEmail.toLowerCase())) {
      problems.push(`${short} ("${c.subject}"): signed off by ${signoffs.map((s) => `${s.name} <${s.email}>`).join(", ")}, but authored by ${c.authorName} <${c.authorEmail}>; the sign-off must be the author's`);
    }
  }
  return problems;
}

/** The commits between base and head, read from git. */
export function commitsBetween(base, head, cwd = process.cwd()) {
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
  const shas = git("rev-list", "--reverse", `${base}..${head}`).split("\n").filter(Boolean);
  return shas.map((sha) => {
    const [parents, authorName, authorEmail, subject] = git("log", "-1", "--format=%P%x00%an%x00%ae%x00%s", sha).replace(/\n$/, "").split("\0");
    const signoffs = git("log", "-1", "--format=%(trailers:key=Signed-off-by,valueonly,unfold)", sha).split("\n").map((s) => s.trim()).filter(Boolean);
    return { sha, parents: parents.split(" ").filter(Boolean).length, authorName, authorEmail, subject, signoffs };
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [base, head] = process.argv.slice(2);
  if (!base || !head) {
    console.log("usage: node scripts/check-dco.mjs <base sha> <head sha>   (env PR_AUTHOR)");
    process.exit(2);
  }
  const commits = commitsBetween(base, head);
  const problems = dcoProblems(commits, { prAuthor: process.env.PR_AUTHOR || "" });
  console.log(`checked ${commits.length} commits (${commits.filter((c) => c.parents > 1).length} merge commits skipped)`);
  if (problems.length) {
    for (const p of problems) console.log(`::error::${p}`);
    console.log("Fix: git rebase --signoff <base branch> on your branch (or git commit --amend --no-edit -s for the last commit), then push it again. See CONTRIBUTING.md, \"Sign-off\".");
    process.exit(1);
  }
  console.log("every commit is signed off by its author (Developer Certificate of Origin)");
}
