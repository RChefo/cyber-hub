# Security policy

ExploitX is a security tool: it starts other programs, reaches network targets, stores findings and evidence, and holds service credentials. We take vulnerabilities in it seriously and ask you to report them privately.

## Supported versions

ExploitX has **no stable release yet**. Release candidates exist only as private drafts and are not distributed.

| Version | Supported for security reports |
|---|---|
| The default branch (`release/v0.1.0`) | Yes |
| Release candidates of 0.1.0 | Yes, as they are built from that branch |
| Anything else (forks, modified builds, builds of older commits) | No |

When stable releases exist, this table will name the versions that receive security fixes.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability,** and do not post details, proofs of concept or exploit code anywhere public.

Report it privately through GitHub:

1. Open the repository's [**Security** tab → **Report a vulnerability**](https://github.com/RChefo/ExploitX/security/advisories/new). This uses GitHub's private vulnerability reporting.
2. Only you and the maintainer can see the report. The maintainer can invite you to a private fork to work on the fix.

If you cannot use GitHub's form, open a public issue that says only that you have a security report and need a private channel. Leave out every detail of the vulnerability.

### What to include

* The affected component (for example the execution engine, scope checks, the MCP bridge, the updater, a parser) and the version or commit.
* Your platform: Windows or Linux distribution, version and architecture, and the installation format (NSIS, MSI, deb, rpm, AppImage, or a build from source).
* Steps to reproduce, with the smallest input that shows the problem (a file, a command, a project setup).
* The impact you expect: what an attacker controls, what they gain, and under which conditions.
* Logs or screenshots, **with credentials, tokens, personal data and third-party target data removed**.
* Whether you would like to be credited, and how.

Test only against your own installation and data, and against systems you are authorized to test. Do not use real credentials of others, and do not access data that is not yours.

## What happens next

* The maintainer reviews reports as their availability allows. **No response or fix time is guaranteed:** ExploitX is maintained by its owner without a support agreement.
* A confirmed vulnerability is fixed privately where possible. A GitHub security advisory is published with the fix; a CVE can be requested through it when the impact warrants one.
* We aim for coordinated disclosure: please give the maintainer reasonable time to fix the issue before you disclose it, and agree on a date together.
* Reporters are credited in the advisory unless they prefer otherwise.

## Scope

**In scope:** ExploitX's own code and configuration in this repository, its build and release workflows, and the packages built from them. Areas of particular interest:

* the native confirmations and the execution engine (a page or an MCP client starting a program without the user's decision);
* scope enforcement (a tool reaching a target outside the project's authorized scope);
* the MCP bridge and its approvals;
* the updater and its signature checks;
* credential storage and redaction;
* parsers of untrusted files (scan imports, logs, packet captures, Windows event logs, SBOMs, Sigma and YARA rules, backups);
* TLS verification of network clients;
* the GitHub Actions workflows (for example a way for a pull request to reach secrets or publish a release).

**Out of scope:**

* vulnerabilities in the third-party tools ExploitX launches, such as Nmap or Nuclei. Report those to their projects;
* problems that require an already compromised operating-system account or administrator rights on the user's machine;
* the absence of Authenticode signatures on Windows installers, which is known and documented;
* findings from automated scanners without a demonstrated impact;
* social engineering of the maintainer or users.

## Security model

How ExploitX protects its users is described in [docs/SECURITY.md](docs/SECURITY.md): trust boundaries, controls, scope semantics, provider and upload safeguards, and accepted risks.
