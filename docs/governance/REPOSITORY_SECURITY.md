# Repository security

How the public repository `RChefo/ExploitX` (formerly `RChefo/cyber-hub`, renamed by the owner; the old name redirects) is protected, what was audited when it became public, and what the maintainer keeps in place. Status of 2026-11-13 (Mission 12), reviewed again in Mission 14 ("Mission 14 review", below).

## History audit

The repository is public, so its **entire history** is public, not only the latest commit. Checked on 2026-11-13:

| Check | Result |
|---|---|
| gitleaks 8.30.1, every commit of every branch and tag (210 commits, 10 refs) | **No leak.** Nine findings are suppressed by `.gitleaksignore`. Each was opened and confirmed to be a test fixture: the jwt.io example token, made-up Stripe-, AWS- and npm-shaped values in redaction tests, a truncated made-up RSA key, and throwaway values of a local TAXII mock server |
| The update-signing private key (minisign format) | Never committed. The only match is the release workflow's own check that searches for it |
| Environment and key files | Only `src-tauri/secrets.example.env`, a template with empty values, was ever committed. No `.env`, `.pem`, `.key`, `.p12` or `.pfx` file exists in the history |
| Deleted files | Two in the whole history, both the project's own source files |
| Personal and machine information | No home-directory paths, user names or private addresses in the code. The internal release-engineering documents mention the maintainer's test environment (a drive folder and VM names); this is informational only, with no credential |
| Commit identities | Every commit carries the owner's GitHub account and a personal e-mail address in its metadata. That is public and cannot be changed without rewriting history (not done) |

**Recommendation to the owner:** turn on *Keep my email addresses private* and *Block command line pushes that expose my email* in GitHub's e-mail settings, so future commits use the GitHub no-reply address. The steps, in the order that avoids refused pushes, are in [EMAIL_PRIVACY.md](EMAIL_PRIVACY.md).

## Repository settings

| Setting | State | Since |
|---|---|---|
| Secret scanning | **On** | 2026-11-13 |
| Push protection (refuses pushes that contain recognised secrets) | **On** | 2026-11-13 |
| Secret scanning of non-provider patterns, validity checks | Off: not applied by GitHub to this account (part of the paid Secret Protection) | |
| Dependabot alerts, dependency graph | On | |
| Dependabot security updates | **On** | 2026-11-13 |
| Dependabot version updates | `.github/dependabot.yml`: weekly, grouped (Cargo, npm, GitHub Actions) | 2026-11-13 |
| Private vulnerability reporting | **On** (SECURITY.md) | 2026-11-13 |
| Ruleset "Default branch protection" | **Active:** no deletion, no force push, changes through pull requests with resolved conversations, required checks: the five CI jobs and "Repository checks". Repository administrators may bypass (the owner's direct maintenance) | 2026-11-13 |
| Ruleset "Release tag protection" (`v*`) | **Active:** tags cannot be deleted, moved or force-updated; administrators may bypass, deliberately and visibly | 2026-11-13 |
| GitHub Actions | Selected actions only, each pinned to a full commit SHA (enforced by GitHub and by `ci_tests.rs`); the default token is read-only; Actions cannot approve pull requests | |
| Workflow runs from outside contributors | **Need the maintainer's approval for every outside contributor** (stricter than GitHub's default) | 2026-11-13 |
| `release` environment | Deployments only from `main` and `release/*`; **the owner must approve each deployment**; administrators cannot bypass; holds the update-signing key and its password | Reviewer since 2026-11-13 |
| `RELEASE_PUBLISHING` | Unset. Set only by the owner, for one authorized release run | |
| Discussions, wiki | Off | |
| Webhooks, deploy keys | **None** (the API lists no webhook and no deploy key) | Checked 2026-11-13 (Mission 14) |

## CI/CD in a public repository

* **CI** (`ci.yml`):
  * runs for every pull request, including from forks and Dependabot, and for pushes to `main`, `release/**` and `v*` tags (a branch is checked once, through its pull request);
  * has `contents: read` only and reads no secret;
  * checks out without keeping credentials;
  * never runs `pull_request_target`, `workflow_run` or comment triggers;
  * fork pull requests get no secrets and a read-only token from GitHub.

  Values from a pull request (its title) reach scripts only through `env:`, never inside the script text; `ci_tests.rs` enforces this for every step.
* **Release** (`release.yml`) cannot run for pull requests. It builds only in a manual run, with `RELEASE_PUBLISHING` set and the owner's approval of the `release` environment.
  * The signing secrets exist only in that environment's build step.
  * Uploads go to a draft, and a release candidate is never published.
  * The tag is checked against the built commit twice.
* **Artifacts.** In a public repository any signed-in GitHub user can download a run's artifacts. The release workflow's build artifacts therefore live one day, and the publish job deletes them once the draft holds the files (Mission 12). CI uploads no artifacts.
* **Caches.** CI uses npm and Rust caches, which GitHub scopes so that a pull request cannot overwrite the default branch's caches. The release workflow uses no cache.

## Third-party GitHub Apps

The owner's account has eight third-party GitHub Apps installed with access to all repositories, this one included. Some have write access to administration or workflows. None is used by this repository: their check suites stay queued and do nothing.

**Recommendation:** under *Settings → Applications → Installed GitHub Apps*, give each app access only to the repositories it serves, or remove it. An app with administration or workflow write access could change the release protections or the workflows. The list and permissions, read from the apps' check suites, are in [GITHUB_FIRST_RUN.md](../release/GITHUB_FIRST_RUN.md#mission-9-the-private-repository-and-the-first-ci-runs-2026-11-11) (Mission 10's table). The same eight apps still attached check suites to the commits of 2026-11-13.

## Mission 14 review (2026-11-13)

**Third-party GitHub Apps.** Read again from the check suites of the latest commits of both repositories. The installations list itself still needs a GitHub App token. Nothing was revoked or changed: these are account-level installations, and some may serve the owner's other projects.

| App (owner) | Write permissions (from its check suite) | Used by RChefo/ExploitX | Used by RChefo/ExploitX-Web |
|---|---|---|---|
| Cloudflare Workers and Pages (cloudflare) | administration, checks, contents, deployments, pull requests | No (suite stays queued) | **Yes: "Workers Builds: exploitx-web" builds every push** (production for `main`, previews for other branches). The previews of both Dependabot branches failed while every `main` build passed; the build logs are only in the Cloudflare dashboard |
| Vercel (vercel) | administration, checks, contents, deployments, issues, pull requests, repository hooks, statuses, workflows | No | No |
| Render (renderinc) | actions, checks, deployments, environments, issues, pull requests, repository hooks, statuses, workflows | No | No |
| Cursor (cursor) | actions, checks, contents, discussions, issues, merge queues, pull requests, workflows | No | No |
| Wasmer (wasmerio) | actions, administration, checks, contents, deployments, pull requests, statuses | No | No |
| Claude (anthropics) | actions, checks, contents, discussions, issues, pull requests, repository creation, repository hooks, workflows | No | No |
| Mintlify (mintlify) | checks, contents, deployments, pull requests | No | No |
| Netlify (netlify) | checks, issues, pull requests, statuses | No | No |

"No" means the app attaches a check suite to every commit and leaves it queued: it has access, and does nothing here. **Recommendation (owner):** under *Settings → Applications → Installed GitHub Apps → Configure*, switch each app from "All repositories" to "Only select repositories". Keep Cloudflare Workers and Pages on RChefo/ExploitX-Web while it builds the site, and give the others only the repositories they serve. An app with `administration` or `workflows` write access to RChefo/ExploitX could change the rulesets or the release workflow.

**The website repository (RChefo/ExploitX-Web, private)** was brought in line where GitHub allows it:

| Setting | Before | After (2026-11-13) |
|---|---|---|
| Allowed actions | All actions and reusable workflows | **Selected:** `actions/checkout`, `actions/setup-node` only |
| SHA pinning of actions | Not required | **Required** (the workflow already pins both) |
| Dependabot alerts (vulnerability alerts) | Not reported by the API | **On** (enabled and confirmed) |
| Dependabot security updates | Not reported by the API | **On** (enabled and confirmed) |
| Secret scanning, push protection | Off | Not available: GitHub offers them for private repositories only with GitHub Advanced Security |
| Webhooks, deploy keys | | None |
| Default workflow token | Read-only; cannot approve pull requests | Unchanged |

**Dependency updates.** Each Dependabot pull request was reviewed on its own (the mission report lists the outcome). The RustCrypto hashes (`sha1`, `sha2`, `md-5`, `hmac`, `digest`) now form one Dependabot group, because they only compile when they move together.

## Mission 15 review (2026-11-13)

**Visibility, the owner's decision:** RChefo/ExploitX stays **public**, RChefo/ExploitX-Web stays **private**. Neither was changed.

**Main repository settings, verified again:**
* secret scanning, push protection and Dependabot security updates are on;
* Actions are limited to six selected actions, each SHA-pinned (enforced);
* the default workflow token is read-only and cannot approve pull requests;
* no webhook and no deploy key.

**New required check.** The ruleset "Default branch protection" also requires *Developer Certificate of Origin* (added 2026-11-13, after the check passed a signed-off pull request and failed an unsigned one). The rest of the ruleset is unchanged: no deletion, no force push, pull requests with resolved conversations, the six CI jobs, administrator bypass.

**Release path.** The `release` environment still requires the owner's approval for every deployment. The approval of a release run's build jobs is the owner's to give in the GitHub interface; this session's automation was not allowed to give it. `RELEASE_PUBLISHING` is set only for an authorized private candidate run and unset afterwards (MISSION_REPORT.md, "Mission 15").

**GitHub Apps.** Unchanged. The CLI token cannot list or change GitHub App installations (GitHub answers that this needs a GitHub App user token), so every scope change is the owner's (*Settings → Applications → Installed GitHub Apps → Configure → Repository access*). The table in "Mission 14 review" still applies. Recommended scopes:

| App | Keep on | Remove from |
|---|---|---|
| Cloudflare Workers and Pages | RChefo/ExploitX-Web (it builds and deploys the website) | RChefo/ExploitX (it does nothing there, and holds administration write access) |
| Vercel, Render, Wasmer | Only the repositories they deploy | Both ExploitX repositories (unused here; administration, workflow or environment write access) |
| Cursor, Claude | The repositories the owner works on with them | Either ExploitX repository the owner does not use them on (they hold workflow write access) |
| Mintlify, Netlify | Only where used | Both ExploitX repositories (unused here) |

**The website repository (private).** Its Actions allow only the two actions its workflow uses, SHA-pinned, and Dependabot alerts and security updates are on. CI now also runs actionlint. Rulesets and required checks need GitHub Pro for a private repository, so its DCO check reports without blocking. The built site is public; the build emits no source maps, and preview builds go to Cloudflare, not to a public artifact.

## Keeping it this way

* Never commit credentials, signing keys or `.env` files. Push protection and gitleaks catch the common formats, not all of them.
* If a secret is ever pushed:
  1. revoke or rotate it first;
  2. then decide about the history. Removing it from history means rewriting public history, which needs the owner's decision.
* Review Dependabot pull requests like any other change. CI runs on them, including the license policy.
* When adding a workflow or a step:
  * pin actions by SHA;
  * grant the least permissions;
  * keep secrets in the `release` environment;
  * run actionlint (CONTRIBUTING.md, "Checks").
