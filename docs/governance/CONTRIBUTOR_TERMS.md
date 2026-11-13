# Contribution terms: DCO or CLA

**Status (Mission 15, 2026-11-13): adopted and enforced.** The owner approved the **Developer Certificate of Origin** for contributions, together with the Apache License 2.0. The certificate is in [`DCO`](../../DCO), the sign-off rules for contributors in [CONTRIBUTING.md](../../CONTRIBUTING.md#sign-off-developer-certificate-of-origin), and CI checks every pull request. There is no contributor license agreement. This document keeps the comparison that led to the choice. **It is not legal advice.**

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

## Sign-off guide

The guide for contributors is in [CONTRIBUTING.md](../../CONTRIBUTING.md#sign-off-developer-certificate-of-origin). It covers `git commit -s`, fixing a missing sign-off with `git commit --amend -s` or `git rebase --signoff`, editors and web commits, and the noreply address for privacy ([EMAIL_PRIVACY.md](EMAIL_PRIVACY.md)). The certificate's text, DCO 1.1 unmodified (checked identical to <https://developercertificate.org/> on 2026-11-13), is the [`DCO`](../../DCO) file at the repository root.

A sign-off certifies the origin of a contribution. It does not transfer copyright: each contributor keeps it and licenses the contribution under Apache-2.0, as section 5 of that license states.

## Enforcement

**RChefo/ExploitX (public).**
* **The check:** CI's job *Developer Certificate of Origin* runs on every pull request, using `scripts/check-dco.mjs` and its tests in `scripts/check-dco.test.mjs`.
  * It reads the commits between the pull request's base and head with full history.
  * It skips merge commits.
  * It requires on every other commit a `Signed-off-by:` trailer whose email is the commit author's, compared without case.
* **Automated accounts:**
  * Dependabot's commits carry `Signed-off-by: dependabot[bot] <support@github.com>`; they pass only in pull requests Dependabot opened itself.
  * A contributor cannot get a commit through by naming its author "dependabot[bot]".
* **Safety:**
  * no secret and no third-party action or app;
  * the pull request's data reaches the script only through `env`;
  * the job's token is the workflow's read-only one.
* **Required:** the job is a required check of the default branch's ruleset, so a pull request with an unsigned commit cannot be merged. The owner's direct pushes to the default branch are not pull requests and are not checked.
* **Tested:**
  * unit tests: signed, unsigned, someone else's sign-off, merges, Dependabot and a commit made to look like Dependabot's;
  * a real repository: `git commit -s`, a merge, an unsigned commit, and its fix with `git rebase --signoff`;
  * pull requests on GitHub: one signed off (passes), one not (fails), and Dependabot's pull requests (pass). The results are in MISSION_REPORT.md, "Mission 15".

**RChefo/ExploitX-Web (private).**
* The same script and job run in its CI.
* A private repository on GitHub's Free plan cannot enforce rulesets or required checks, so there the check reports but does not block a merge; the maintainers review it.
* The website's code is licensed under Apache-2.0 too, but its repository is private: it is not publicly available source. The license governs what the people who receive the code may do.

## Decision

Approved by the owner for Mission 15 (2026-11-13): **Apache-2.0 for both repositories, contributions under the DCO.** No CLA was introduced.
