//! MCP integration (see docs/MCP.md).
//!
//! * `server` + `client` run in the `cyberhub-mcp` process launched by an MCP client (stdio).
//! * `bridge` + `ops` + `approvals` run inside the Cyber Hub app and execute requests with
//!   the app's own services, policy checks, approvals and audit log.
//! * `proto` is the authenticated loopback protocol between the two; `catalog` and `prompts`
//!   are shared definitions.

pub mod approvals;
pub mod assessment;
pub mod bridge;
pub mod catalog;
pub mod client;
pub mod detection;
pub mod ops;
pub mod prompts;
pub mod proto;
pub mod server;
