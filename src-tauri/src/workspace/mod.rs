//! Shared data foundation for the project workspace (docs/DATA_MODEL.md): assets, findings
//! lifecycle, evidence, scope decisions and the project timeline. Commands live in
//! `commands::workspace`; the logic here takes a `&Connection` so it can be tested and reused.

pub mod analysis;
pub mod apisec;
pub mod attack;
pub mod attack_matrix;
pub mod asvs;
pub mod assets;
pub mod correlate;
pub mod detections;
pub mod discovery;
pub mod evidence;
pub mod findings;
pub mod attack_layer;
pub mod findings_export;
pub mod lockfiles;
pub mod relations;
pub mod remediation;
pub mod report;
pub mod sbom;
pub mod scan_import;
pub mod scope_gate;
pub mod search;
pub mod templates;
pub mod timeline;
pub mod vulns;
pub mod workflows;

#[cfg(test)]
mod integration_tests;
