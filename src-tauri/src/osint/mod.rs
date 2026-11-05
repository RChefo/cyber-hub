//! OSINT workspace: investigations, entity extraction and resolution, the evidence-backed
//! relationship graph, discovery providers, saved graphs with versions, analysis, import/export
//! and reports. See docs/OSINT.md.

pub mod confidence;
pub mod discovery;
#[cfg(test)]
mod durability_tests;
pub mod ingest;
pub mod io;
pub mod model;
pub mod analysis;
pub mod normalize;
pub mod providers;
pub mod report;
pub mod store;
