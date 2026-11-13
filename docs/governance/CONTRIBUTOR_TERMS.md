# Contribution terms: DCO or CLA

**Status (Mission 14, 2026-11-13): proposed, not enforced.** ExploitX does not yet accept outside pull requests for merging (CONTRIBUTING.md), and no project license is selected ([LICENSE_COMPARISON.md](LICENSE_COMPARISON.md)). This document compares the two usual ways of recording the terms of a contribution and proposes one for the owner to approve together with the license. **It is not legal advice.**

## The two options

| | Developer Certificate of Origin (DCO) | Contributor License Agreement (CLA) |
|---|---|---|
| What it is | A short statement (DCO 1.1, <https://developercertificate.org/>) that the contributor wrote the change or has the right to submit it under the project's license. Created for the Linux kernel in 2004 | A signed agreement between each contributor and the project owner. Common forms: the Apache Individual CLA (a broad copyright and patent license to the owner), the Harmony agreements, copyright assignment |
| How a contributor agrees | A `Signed-off-by: Name <email>` line in each commit (`git commit -s`) | Signing once, usually through a bot on the first pull request (CLA Assistant, EasyCLA), or on paper |
| Rights the owner receives | Only the project license itself ("inbound = outbound"): each contributor keeps the copyright and licenses the change under the same terms as everyone else. Apache-2.0 §5 states this for contributions | Whatever the agreement grants: typically the right to relicense the contribution, including under other or proprietary terms |
| Relicensing or dual licensing later | Needs every contributor's consent (or removal of their code) | Possible, within the agreement |
| Friction for contributors | Low: one flag; no account, no legal review by their employer in most cases | Higher: reading and signing a legal document; employees often need their employer's approval; some developers refuse CLAs on principle |
| Administration | None beyond a check on pull requests | Storing signatures, corporate CLAs, a bot with access to the repository, questions about the agreement |
| Who uses it | Linux, Git, Docker/Moby, GitLab (moved from a CLA to the DCO in 2017), Chef (moved in 2016), many CNCF projects | Apache Software Foundation, Google, Microsoft, and companies selling a commercial edition of an open project |

## Recommendation: the DCO

For ExploitX, with one owner and a permissive license recommended:
* it records, per commit, that the contributor had the right to submit the change, which is the main protection the project needs;
* together with Apache-2.0 §5, the inbound terms are clear without any separate agreement;
* it costs contributors one flag and needs no third-party service or bot with repository access ([REPOSITORY_SECURITY.md](REPOSITORY_SECURITY.md) keeps GitHub Apps to a minimum);
* it does not require a legal entity to sign agreements with.

**Choose a CLA instead only if** the owner plans to sell ExploitX under other terms than its open-source license (dual licensing), or to relicense it later without asking contributors. A CLA that transfers or broadly licenses contributors' rights to the owner is not introduced without the owner's explicit decision, and its text should then be reviewed by a lawyer.

The DCO starts when it is adopted: existing commits are not rewritten, and the owner's own commits before adoption need no sign-off.

## Sign-off guide (for CONTRIBUTING.md once adopted)

The DCO 1.1 text, which a sign-off certifies:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

How to sign off:
* **Each commit:** `git commit -s` adds `Signed-off-by: Your Name <your@email>` from `user.name` and `user.email`.
* **Forgot on the last commit:** `git commit --amend --no-edit -s` (on your own branch, before review).
* **Several commits on your branch:** `git rebase --signoff <base branch>`, then push your branch again.
* **Editors:** VS Code has "Git: Always Sign Off" (`git.alwaysSignOff`); most Git clients have a sign-off option.
* **Commits made on github.com:** the repository can require a sign-off on web commits (Settings > General, "Require contributors to sign off on web-based commits").
* **Privacy:** the sign-off records the email of the commit. To keep a personal address out of the public history, use your GitHub noreply address (`<id>+<login>@users.noreply.github.com`, shown at <https://github.com/settings/emails>) for `user.email` ([EMAIL_PRIVACY.md](EMAIL_PRIVACY.md)).
* **Use your real name or a name you are known by consistently;** anonymous contributions cannot be certified.

## Proposed enforcement (not enabled)

When the owner adopts the DCO, add this step to the "Repository checks" job in `.github/workflows/ci.yml`, after the pull request title check. It needs the full history of the pull request (`fetch-depth: 0` on that job's checkout), reads commits as data, and uses no third-party app or secret:

```yaml
      - name: Developer Certificate of Origin (every commit signed off by its author)
        if: github.event_name == 'pull_request'
        env:
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          set -euo pipefail
          bad=0
          for c in $(git rev-list --no-merges "$BASE..$HEAD"); do
            author=$(git log -1 --format='%an <%ae>' "$c")
            if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c" | grep -qxF "$author"; then
              echo "::error::Commit $c has no 'Signed-off-by: $author' (CONTRIBUTING.md, \"Sign-off\")"; bad=1
            fi
          done
          exit "$bad"
```

The alternative, the "DCO" GitHub App, needs read access to pull requests and write access to checks; the workflow step above needs neither.

Then: enable "Require contributors to sign off on web-based commits", add the sign-off section to CONTRIBUTING.md, and pin the step in `src-tauri/src/ci_tests.rs`.

## Decision requested

Together with the license: **"Contributions under the DCO"** (recommended), or **"a CLA"** (then name the purpose, for example dual licensing, and the agreement is drafted for legal review).
