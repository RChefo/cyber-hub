# Documentation

Cyber Hub's documents fall into three groups. Start with the one that fits what you want to do.

## For users

| Document | What it covers |
|---|---|
| [../README.md](../README.md) | What Cyber Hub is, its modules, status and how to build it |
| [PLATFORMS.md](PLATFORMS.md) | Supported platforms, per-OS dependencies and behaviour, validation status, troubleshooting |
| [SECURITY.md](SECURITY.md) | The security model: trust boundaries, confirmations, scope, providers, uploads, accepted risks |
| [UPGRADE.md](UPGRADE.md) | Database upgrades, backups, restoring a backup, rollback |
| [UPDATER.md](UPDATER.md) | Signed automatic updates: how they work and their limits (it also documents the release side) |
| [OSINT.md](OSINT.md) | The OSINT workspace |
| [PROVIDERS.md](PROVIDERS.md) | Threat-intelligence providers and their limits |
| [UTILITIES.md](UTILITIES.md) | The security utilities |
| [WORKFLOWS.md](WORKFLOWS.md) | Workflow automation in projects |
| [MCP.md](MCP.md) | Connecting MCP clients (Claude Code, Claude Desktop, others) |
| [ASSISTANT.md](ASSISTANT.md) | The project assistant |
| [releases/](releases/README.md) | Release notes |
| [../SECURITY.md](../SECURITY.md), [../SUPPORT.md](../SUPPORT.md) | Reporting a vulnerability privately; getting help |

## For contributors

| Document | What it covers |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Setup, checks, standards, database rules, commits and pull requests |
| [governance/DEVELOPMENT_GUIDE.md](governance/DEVELOPMENT_GUIDE.md) | The architecture, security boundaries, network behaviour, tests and the release workflow, from a developer's view |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Backend and frontend structure, the execution engine, UI libraries |
| [DATA_MODEL.md](DATA_MODEL.md) | The database schema, migration by migration |
| [PROVISIONING.md](PROVISIONING.md) | Storing provider credentials for development with the `cyberhub-keys` tool |
| [governance/LICENSE_COMPARISON.md](governance/LICENSE_COMPARISON.md) | License options under consideration (no license is selected yet) |
| [governance/THIRD_PARTY_LICENSE_AUDIT.md](governance/THIRD_PARTY_LICENSE_AUDIT.md), [governance/third-party/](governance/third-party/RUST_CRATES.md) | Dependency and asset licenses, and the full inventories |
| [governance/REPOSITORY_SECURITY.md](governance/REPOSITORY_SECURITY.md) | How the public repository is protected: settings, CI, secrets, the audit of its history |
| [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Notices for copied code, data, fonts and icons |
| [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards |

## Internal: release engineering and project history

These records are kept for transparency and for the maintainer. **They are not user instructions.**
* They describe private release candidates, the maintainer's test machines and procedures, and decisions in progress.
* They mention internal paths of the maintainer's test environment, which have no meaning elsewhere.
* Their contents can be superseded by the documents above.

| Document | What it is |
|---|---|
| [release/](release/RELEASE_READINESS.md) | Release readiness, the release-candidate procedure, manual validation, signing setup, first GitHub run, the TAXII credential test |
| [SIGNING.md](SIGNING.md) | Windows Authenticode signing: options and setup (not set up yet) |
| [autonomous/](autonomous/MISSION_REPORT.md) | The development missions' state, implementation log, reports and backlog |
| [EXPANSION_PLAN.md](EXPANSION_PLAN.md) | The platform expansion plan and audit (historical) |
| [research/](research/CYBER_HUB_MARKET_RESEARCH.md) | Market research behind the feature choices |
| [WEBSITE.md](WEBSITE.md) | The marketing website in `website/` (not deployed) |
