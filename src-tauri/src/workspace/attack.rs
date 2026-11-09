//! MITRE ATT&CK in projects (docs/DATA_MODEL.md#attck): the Enterprise catalog bundled with the
//! app (`catalog/attack-enterprise.json`, built by `scripts/attack-catalog.mjs` from MITRE's STIX
//! data; © The MITRE Corporation, see THIRD_PARTY_NOTICES.md), and the techniques a project's
//! findings name.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Tactic {
    pub id: String,
    pub shortname: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactics: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub source: String,
    pub url: String,
    pub sha256: String,
    pub version: String,
    pub modified: String,
    pub retrieved: String,
    pub domain: String,
    pub notice: String,
    pub license: String,
    pub tactics: Vec<Tactic>,
    pub techniques: Vec<Technique>,
    /// revoked technique → the technique that replaced it
    pub revoked: HashMap<String, String>,
    pub deprecated: Vec<String>,
}

static CATALOG: Lazy<Catalog> = Lazy::new(|| serde_json::from_str(include_str!("../../catalog/attack-enterprise.json")).expect("catalog/attack-enterprise.json is invalid"));
static INDEX: Lazy<HashMap<String, usize>> = Lazy::new(|| CATALOG.techniques.iter().enumerate().map(|(i, t)| (t.id.clone(), i)).collect());

pub fn catalog() -> &'static Catalog {
    &CATALOG
}

pub fn technique(id: &str) -> Option<&'static Technique> {
    INDEX.get(&id.to_ascii_uppercase()).map(|&i| &CATALOG.techniques[i])
}

pub fn technique_name(id: &str) -> Option<String> {
    technique(id).map(|t| t.name.clone())
}

/// What the catalog says about an ID: current, revoked (and by what), deprecated, or unknown.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum IdState {
    Current,
    Revoked { by: String },
    Deprecated,
    Unknown,
}

pub fn id_state(id: &str) -> IdState {
    let id = id.to_ascii_uppercase();
    if technique(&id).is_some() {
        IdState::Current
    } else if let Some(by) = CATALOG.revoked.get(&id) {
        IdState::Revoked { by: by.clone() }
    } else if CATALOG.deprecated.contains(&id) {
        IdState::Deprecated
    } else {
        IdState::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_catalog_is_complete_and_attributed() {
        let c = catalog();
        assert_eq!(c.domain, "enterprise-attack");
        assert!(c.notice.contains("The MITRE Corporation") && c.license.contains("royalty-free"));
        assert!(c.tactics.len() >= 14, "{} tactics", c.tactics.len());
        assert!(c.techniques.len() > 600);
        // every technique's tactics exist, every sub-technique's parent exists
        let tactics: Vec<&str> = c.tactics.iter().map(|t| t.shortname.as_str()).collect();
        for t in &c.techniques {
            assert!(!t.tactics.is_empty() && t.tactics.iter().all(|x| tactics.contains(&x.as_str())), "{}", t.id);
            if let Some(p) = &t.parent {
                assert!(technique(p).is_some(), "{} has no parent {p}", t.id);
            }
        }
        assert_eq!(technique_name("t1053.003").as_deref(), Some("Cron"));
        assert_eq!(technique_name("T1059.001").as_deref(), Some("PowerShell"));
        assert_eq!(id_state("T1530"), IdState::Current);
        assert_eq!(id_state("T9999"), IdState::Unknown);
        let (old, new) = c.revoked.iter().next().unwrap();
        assert_eq!(id_state(old), IdState::Revoked { by: new.clone() });
    }
}
