# First run on GitHub (M8)

This guide is for the owner. It covers the static review, the repository settings to make before the first push, the first push itself, and the release workflow's validation runs. Nothing here builds, signs or publishes anything until the owner sets up signing and enables publishing on purpose. Mission 8 prepared it without pushing. **Mission 9 did the first push**: the next section records what was done and what GitHub refused.

## Mission 9: the private repository and the first CI runs (2026-11-11)

**The repository** is `https://github.com/RChefo/cyber-hub`.
* **Visibility:** private.
* **Creation:** no README or licence was added on GitHub.
* **Before pushing:** gitleaks scanned the whole history first: 191 commits, no leaks.
* **What was pushed:** only `release/v0.1.0`, which is therefore the default branch. No tag was pushed.

**Settings applied through the API before the first push:**

| Setting | Value |
|---|---|
| Actions permissions | Selected actions only: the six the workflows use (`actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/download-artifact`, `dtolnay/rust-toolchain`, `Swatinem/rust-cache`). GitHub-owned and verified creators are *not* allowed wholesale. **Full-length SHA pinning required** |
| Workflow token | Read-only (`contents: read` by default); workflows cannot approve pull requests |
| Fork pull requests | Do not run, get no write token and no secrets (the private-repository defaults, checked) |
| Environment `release` | Exists. Deployments only from the branches `main` and `release/*`; administrator bypass off; no secrets yet |
| Dependabot alerts | On. Automatic security-fix pull requests stay off |

**Refused by the plan.** The account is on GitHub Free, and for a private repository GitHub answered:

| Feature | GitHub's answer |
|---|---|
| Required reviewers on the `release` environment | HTTP 422, "ensure the billing plan supports the required reviewers protection rule" |
| A wait timer | The same |
| Rulesets: tag protection for `v*`, required status checks for `release/*` | HTTP 403, "Upgrade to GitHub Pro or make this repository public" |
| Branch protection | Not available either |
| Secret scanning and push protection | HTTP 422, "Secret scanning is not available for this repository" |

Without them:
* **No approval step:** a manual release run with `RELEASE_PUBLISHING=enabled` builds without asking anyone. Keep the variable unset except for the one candidate run.
* **Tags are not protected,** but the publish job's tag check still stops a moved tag.
* **Secrets are caught only by CI:** the `audit` job's gitleaks on every push is the only secret scanning.
* **Upgrading to GitHub Pro adds:** tag rulesets and branch protection.
* **Required reviewers for a private repository's environment need GitHub Enterprise.**

**CI results:**

| Run | Commit | Result |
|---|---|---|
| [43084985623](https://github.com/RChefo/cyber-hub/actions/runs/43084985623) | `a1edbaf` | **Green, 22 min.** `windows-2022`, `ubuntu-24.04`, Debian 12: 637 Rust tests passed, 28 ignored, on each. Dependency and secret scans: cargo audit 0 vulnerabilities (8 allowed warnings), gitleaks 191 commits without leaks, actionlint 1.7.7 with shellcheck clean (first run), npm audit 0. MSRV 1.90 green |
| [43089305680](https://github.com/RChefo/cyber-hub/actions/runs/43089305680) | `5ad2ad1` | **Green, 12 min** (with caches), all five jobs |
| [43095621019](https://github.com/RChefo/cyber-hub/actions/runs/43095621019) | `ed99331` | **Queued, never started:** GitHub created no job. Pushed at 20:22Z |
| [43097581846](https://github.com/RChefo/cyber-hub/actions/runs/43097581846) | `63d2cd6` | The same, pushed at 20:41Z. GitHub's status page showed no incident |
| [43105721393](https://github.com/RChefo/cyber-hub/actions/runs/43105721393) | `d4372b5` | **Green, 12 min, the final code.** 641 passed, 28 ignored, on each of the three platforms; 56 frontend test files; MSRV 1.90; gitleaks 196 commits, cargo audit 0 (8 allowed warnings), actionlint clean |

**Why those two runs did not start is not known.** The next push, at 21:44Z, started at once and passed (above). Cancelling the two was requested; GitHub still lists them as queued. The likeliest cause is the account's Actions minutes for private repositories, or a billing restriction. This token has no scope to read billing. Check *Settings → Billing and plans → Usage*: GitHub Free includes 2,000 minutes a month for private repositories, and Windows minutes count twice. The runs start once the cause is cleared; nothing in them needs a change. A CI run of this repository takes about 85 billed minutes cold and fewer with caches.

**Third-party GitHub Apps can see this private repository.** Each pushed commit received a check suite from eight apps besides GitHub Actions: Vercel, Render, Cursor, Netlify, Wasmer, Mintlify, Claude and Cloudflare Workers and Pages. They are installed on the account with access to *all* repositories, so they can likely read this source. Under *Settings → Applications → Installed GitHub Apps*, give each one access only to the repositories it needs. Mission 9 changed nothing there: these are account-wide settings.

**Mission 10: what each app may do (2026-11-12).** Read from the apps' check suites on `c7052bd`. The installations list itself needs a GitHub App token, which `gh` does not have. Every suite stays *queued*: none of these apps does anything for this repository, and none is needed by it.

| App (owner) | Permissions that matter here |
|---|---|
| Vercel (vercel) | **administration: write**, **workflows: write**, contents, deployments, hooks, pull requests, statuses: write |
| Render (renderinc) | **environments: write**, **actions: write**, **workflows: write**, deployments, hooks, pull requests: write |
| Cursor (cursor) | **actions: write**, **workflows: write**, contents, discussions, merge queues, pull requests: write; administration: read |
| Netlify (netlify) | checks, issues, pull requests, statuses: write; contents: read |
| Wasmer (wasmerio) | **administration: write**, **actions: write**, contents, deployments, pull requests, statuses: write |
| Mintlify (mintlify) | contents, deployments, issues, pull requests: write |
| Claude (anthropics) | **actions: write**, **workflows: write**, **repository creation: write**, contents, hooks, pull requests: write; administration: read |
| Cloudflare Workers and Pages (cloudflare) | **administration: write**, contents, deployments, pull requests: write |

Why it matters for releases:
* *Administration* can change the `release` environment's protection, such as its branch rule.
* *Environments* can change environments too.
* *Actions* can start workflow runs.
* *Workflows* can change the workflow files themselves.
* *Contents* can push code.

**Least privilege, for the owner to apply:** for each app choose *Only select repositories* and leave `cyber-hub` out, or uninstall the apps that are no longer used. Mission 10 removed nothing and revoked nothing.

## 1. What runs, and when

* **`ci.yml`:** on every push and pull request. It verifies; it never builds packages and never uses a secret.

  | Job | Runner | Checks |
  |---|---|---|
  | `verify` | `windows-2022`, `ubuntu-24.04` | `npm ci` (with the dependency patches and their self-test), tsc, vitest, Vite build, clippy with warnings denied, `cargo test`, the fuzzing entry points, the MCP sidecar staging, `npm audit` |
  | `debian` | `ubuntu-24.04`, in the Rust 1.99.1 Debian 12 image pinned by digest | tsc, vitest, Vite build, `cargo test` |
  | `audit` | `ubuntu-24.04` | `cargo audit` 0.22.2; gitleaks 8.30.1 over the whole history; actionlint 1.7.7 with shellcheck. Both downloads are checked against pinned SHA-256 sums |
  | `msrv` | `ubuntu-24.04` | `cargo check --all-targets` with Rust 1.90.0 |

* **`release.yml`:** on a pushed tag `vMAJOR.MINOR.PATCH`, or a manual run naming an existing tag.

  | Job | Runs | Does |
  |---|---|---|
  | `validate` | Always | Checks the version, the tag and the branch; the updater configuration; that no update key is committed; the release notes; that no release exists yet. Then runs the tests, clippy and both audits. No secret, read-only token |
  | `build` | Only in a manual run while the repository variable `RELEASE_PUBLISHING` is `enabled`; environment `release` | Builds and update-signs the NSIS and MSI packages (Windows) and the AppImage, deb and rpm (Ubuntu 22.04) |
  | `publish` | Same condition; environment `release` | Writes and checks `latest.json` and `SHA256SUMS.txt`. Checks that the tag still names the built commit, uploads a **draft** release, and checks the uploaded digests. The release becomes public only if *draft* was unchecked and the tag typed again in *confirm*, after a second tag check |

  A tag push only validates, also while publishing is enabled.

## 2. Static review (Mission 8)

actionlint could not run locally: it is not installed, and running its container was not permitted in this environment. It runs in the `audit` job instead, on the first push. In its place, Mission 8 did the following.

* **Action pins.** Each pinned commit was compared with the upstream tag it claims, using `git ls-remote` (read-only).

  | Action | Pin | Claimed | Result |
  |---|---|---|---|
  | `actions/checkout` | `3d3c42e5aac5` | v7.0.1 | matches the tag |
  | `actions/setup-node` | `949feb2413d6` | v7.1.0 | matches the tag |
  | `actions/upload-artifact` | `cf430e030ddb` | v7.0.2 | matches the tag |
  | `actions/download-artifact` | `9000827ccba6` | v8.0.2 | matches the tag |
  | `Swatinem/rust-cache` | `d1527c8f67ef` | v2.9.3 | matches the tag (used in `ci.yml` only) |
  | `dtolnay/rust-toolchain` | `b725eda52536` | `stable` | the current head of its `stable` branch. The commit is immutable, and the toolchain is set by the explicit `toolchain:` input |

* **Downloads.**
  * The pinned SHA-256 sums of gitleaks 8.30.1 and actionlint 1.7.7 equal the projects' published checksum files.
  * The Debian image digest `sha256:9181b56c…` is an official `rust` image index, built 2026-10-28, with `RUST_VERSION=1.99.1` on bookworm.
  * The `rust:1.99.1-bookworm` tag has been rebuilt since, on newer base layers. The pin deliberately ignores that; refresh it on purpose when needed.
* **Toolchains.** Rust 1.99.1 and Node 22.12.0 are the same in both workflows; the minimum version, 1.90.0, is checked; cargo-audit is pinned with `--locked`. What still floats:
  * the GitHub runner images, which GitHub updates weekly;
  * the Ubuntu packages installed with `apt-get`.

  Neither can be pinned on hosted runners. Both are installed fresh on every run, and the release jobs use no cache.
* **Permissions.**
  * `ci.yml` has `contents: read` and nothing else.
  * `release.yml` grants nothing at the top level. Its `validate` and `build` jobs get `contents: read`, and only `publish` gets `contents: write`.
* **Pull requests.**
  * `ci.yml` uses `pull_request`, never `pull_request_target`, and reads no secret, so a fork's code never sees one.
  * `release.yml` has no pull-request trigger at all.
  * Secrets are read only by the jobs of the `release` environment.
* **Publishing.** It needs four things:
  1. a manual run;
  2. the repository variable `RELEASE_PUBLISHING` set to `enabled`;
  3. the environment's reviewers;
  4. for a public release, *draft* unchecked and the tag typed again.

  A tag push never builds anything.
* **Tag integrity.** Added in Mission 8. Before the draft upload, and again before publishing, the publish job checks that the tag still names the commit that was validated and built. This was tested locally against a stubbed `gh`: lightweight and annotated tags pass; a moved tag stops both steps.
* **Separation.**
  * Verification (`ci.yml`) and release (`release.yml`) are separate workflows.
  * CI never runs `tauri build` and never needs the update key.
  * No workflow touches user data: tests use in-memory databases and temporary folders, and the runners are discarded after each job.
* **Static guards** that run in every `cargo test`, in `src-tauri/src/ci_tests.rs`:
  * every action pinned to a 40-character commit;
  * exact toolchains, and a timeout on every job;
  * no expression inside a run script;
  * least privilege, and secrets only in the environment;
  * the release switch, the draft default and the typed confirmation;
  * only keys GitHub knows at each level;
  * every step one action or one script;
  * expressions that read known contexts only;
  * every run script valid bash, checked on Linux. All 43 also passed `bash -n` on Windows;
  * checkouts without credentials, downloads checked against pinned hashes;
  * the release's triggers, environments and job order, and the tag check.
* **The release build's Linux environment** was checked on Ubuntu 22.04.5 (WebKitGTK 2.50.4, GTK 3.24.33, libsoup 3.0.7, glibc 2.35), with the release job's packages, Rust 1.99.1 and Node 22.12.0. `cargo check --locked --release --bins` passed. It was a type-check: no binary was produced.

**Not verified until it runs on GitHub:**

* actionlint's and shellcheck's findings;
* the hosted runners' current images;
* the Windows job's `npm ci` patches;
* the sidecar staging on a runner;
* GitHub's handling of the environment, variables and uploads.

## 3. Repository settings, before the first push

Make these in GitHub's web interface. They are the owner's decisions; nothing in the repository makes them.

1. **Create the repository.** Make it private until the release is public. Do not add a README or licence on GitHub, so the first push is a fast-forward.
2. ***Settings → Actions → General*:**
   * *Actions permissions:* allow only the actions the workflows use:
     * `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/download-artifact`;
     * `dtolnay/rust-toolchain`, `Swatinem/rust-cache`;
     * later, the signing route's action, such as `azure/login`.

     If the setting to *require actions to be pinned to a full-length commit SHA* is offered, turn it on: every action here already is.
   * *Workflow permissions:* **Read repository contents and packages permissions**. Leave *Allow GitHub Actions to create and approve pull requests* off.
   * *Fork pull request workflows:* require approval for all outside collaborators.
3. ***Settings → Environments → New environment*, named `release`:**
   * *Required reviewers:* yourself, and a second maintainer if there is one. Turn on *Prevent self-review* only if someone else can approve.
   * Leave *Allow administrators to bypass configured protection rules* off.
   * *Deployment branches and tags:* choose *Selected branches and tags* and add `main` and `release/*`. A manual run runs on the branch you choose under *Run workflow*; tags never reach this environment.
   * *Environment secrets:* add them later, with signing (`SIGNING_SETUP.md`).
4. ***Settings → Secrets and variables → Actions → Variables*:** do **not** create `RELEASE_PUBLISHING` yet. Without it, every release run only validates.
5. **Protect the tags**, recommended. Add a ruleset that restricts creating, updating and deleting tags matching `v*` to administrators. The workflow's tag check would stop a moved tag, but the ruleset prevents the move.
6. **Immutable releases**, recommended if your plan offers them (*Settings → General → Releases*). Once published, a release's assets and tag cannot change.

## 4. The first push

Before you start, check what you are about to push:

```bash
git status                     # clean
git log --oneline -5           # the expected commits
git rev-parse --abbrev-ref HEAD  # release/v0.1.0
```

Then:

```bash
git remote add origin https://github.com/<owner>/<repo>.git
git push -u origin release/v0.1.0
```

If you want `main` as the default branch, also run `git push origin release/v0.1.0:refs/heads/main`, then choose `main` under *Settings → General → Default branch*. The release workflow accepts commits on `main` or a `release/*` branch.

**Expected:** *Actions → CI* runs five jobs: `windows-2022`, `ubuntu-24.04`, *Debian 12*, *Dependency and secret scans* and *Minimum Rust version (1.90.0)*. All end green.

Check in particular:

* actionlint, which runs here for the first time. It prints nothing when the workflows are clean;
* gitleaks: *no leaks found* over the whole history;
* `cargo audit`: no vulnerability; warnings are allowed;
* the test counts, which should match the last local run in MISSION_REPORT.md, "Mission 8" (Rust tests per system, the ignored ones, and the frontend test files).

**If a job fails:** read its log and fix the cause in a new commit. Do not re-run it until it passes by chance. A failure on GitHub that the local runs did not show is new information about the hosted environment; record it.

## 5. Release-workflow runs that only validate

These runs build, sign and upload nothing.

1. **The tag.** Create it on the release-candidate commit only, after M1–M7 (`RELEASE_CANDIDATE_PROCEDURE.md`, step 1):

   ```bash
   git tag -a v0.1.0 -m "Cyber Hub 0.1.0" <release-candidate commit>
   git push origin v0.1.0
   ```

   **Expected:** *Actions → Release* runs for the tag. *Validate* is green and shows the notice *RELEASE_PUBLISHING is not 'enabled': this run only validates; nothing is built, signed or uploaded.* (While publishing is enabled, a tag push says *A tag push only validates…* instead.) *Build and sign* and *Publish* are skipped.

   Pre-release tags such as `v0.1.0-rc.1` are refused by design, because the update channel has no pre-releases. The validation run fails at *Version, tag and branch* for them. Use the final version's tag, and let the draft release be the release candidate.
2. **A manual run, still without `RELEASE_PUBLISHING`.** Choose *Actions → Release → Run workflow*, *Use workflow from* `release/v0.1.0`, tag `v0.1.0`, and leave *draft* checked.

   **Expected:** *Validate* is green with the notice *RELEASE_PUBLISHING is not 'enabled': this run only validates…*. The other jobs are skipped.

Building, signing and the draft release come after signing is set up (M9), in `RELEASE_CANDIDATE_PROCEDURE.md`, and need the owner's explicit authorization.

**Mission 10 (2026-11-12): both checks ran as expected.**
* **The tag push:** run 43219450467, *Validate* green, with the notice "RELEASE_PUBLISHING is not 'enabled'…". *Build and sign* and *Publish* were skipped.
* **A manual run without the variable:** run 43222864191, the same.
* **The draft runs.** With the owner's authorization, three draft runs followed, with the variable set only during each. The third, 43242424304, built the candidate as a private draft (`RELEASE_CANDIDATE_PROCEDURE.md`, "Status after Mission 10").
* **The plan:** environment secrets reach the build job in this private repository on GitHub Free.

## 6. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| *Validate* fails at *Version, tag and branch*: "is not on main or a release/* branch" | The tag names a commit that was not pushed to such a branch | Push the branch, then run by hand again |
| *Validate* fails at *Version, tag and branch*: "is not vMAJOR.MINOR.PATCH" | A pre-release tag | Use `v0.1.0` (section 5) |
| *Validate* fails at *Release notes* | No `docs/releases/0.1.0.md` at the tagged commit | It exists; check that the tag names the expected commit |
| *Validate* fails at *No release exists yet* | A draft or release for the tag already exists | Delete the draft after review, or use the existing one |
| *Build and sign* waits | The environment needs a reviewer's approval | Approve under the run's *Review deployments* |
| *Build and sign* fails: "no TAURI_SIGNING_PRIVATE_KEY…" | The secrets are not in the `release` environment | Add them (`SIGNING_SETUP.md`), never as repository secrets |
| actionlint reports something | It runs for the first time | Fix it in the workflow and push; the static guards in `ci_tests.rs` must still pass |

## 7. Never

* Enable `RELEASE_PUBLISHING` before signing is set up and M1–M10 are planned.
* Add `pull_request_target`, or a repository-level signing secret.
* Push a `v*` tag casually: every tag push runs the release validation.
* Re-run a failed release run without understanding the failure.
