//! Shared data foundation for the project workspace (docs/DATA_MODEL.md): assets, findings
//! lifecycle, evidence, scope decisions and the project timeline. Commands live in
//! `commands::workspace`; the logic here takes a `&Connection` so it can be tested and reused.

pub mod assets;
pub mod discovery;
pub mod evidence;
pub mod findings;
pub mod scope_gate;
pub mod timeline;
