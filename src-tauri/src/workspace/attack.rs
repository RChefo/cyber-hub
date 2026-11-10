//! MITRE ATT&CK in projects (docs/DATA_MODEL.md#attck): the catalogs bundled with the app
//! (`catalog/attack-{enterprise,mobile,ics}.json`, built by `scripts/attack-catalog.mjs` from MITRE's
//! STIX data; © The MITRE Corporation, see THIRD_PARTY_NOTICES.md), and the techniques a project's
//! findings name.
//!
//! Enterprise is the default everywhere (`catalog`, `technique`, `id_state`). Mobile and ICS
//! (Mission 6) are separate matrices with their own tactics and versions: an ID is placed in the
//! domain whose catalog knows it ([`domain_of`]), never by its number (the three domains share one
//! numbering, and the same technique name has a different ID in each).

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

pub const ENTERPRISE: &str = "enterprise-attack";
pub const MOBILE: &str = "mobile-attack";
pub const ICS: &str = "ics-attack";
/// The ATT&CK domains Cyber Hub bundles, in the order they are offered.
pub const DOMAINS: &[&str] = &[ENTERPRISE, MOBILE, ICS];

static CATALOG: Lazy<Catalog> = Lazy::new(|| serde_json::from_str(include_str!("../../catalog/attack-enterprise.json")).expect("catalog/attack-enterprise.json is invalid"));
static MOBILE_CATALOG: Lazy<Catalog> = Lazy::new(|| serde_json::from_str(include_str!("../../catalog/attack-mobile.json")).expect("catalog/attack-mobile.json is invalid"));
static ICS_CATALOG: Lazy<Catalog> = Lazy::new(|| serde_json::from_str(include_str!("../../catalog/attack-ics.json")).expect("catalog/attack-ics.json is invalid"));
static INDEX: Lazy<HashMap<String, usize>> = Lazy::new(|| CATALOG.techniques.iter().enumerate().map(|(i, t)| (t.id.clone(), i)).collect());
static MOBILE_INDEX: Lazy<HashMap<String, usize>> = Lazy::new(|| MOBILE_CATALOG.techniques.iter().enumerate().map(|(i, t)| (t.id.clone(), i)).collect());
static ICS_INDEX: Lazy<HashMap<String, usize>> = Lazy::new(|| ICS_CATALOG.techniques.iter().enumerate().map(|(i, t)| (t.id.clone(), i)).collect());

/// The Enterprise catalog.
pub fn catalog() -> &'static Catalog {
    &CATALOG
}

/// A domain's catalog (`enterprise-attack`, `mobile-attack`, `ics-attack`).
pub fn catalog_for(domain: &str) -> Option<&'static Catalog> {
    match domain {
        ENTERPRISE => Some(&CATALOG),
        MOBILE => Some(&MOBILE_CATALOG),
        ICS => Some(&ICS_CATALOG),
        _ => None,
    }
}

fn index_for(domain: &str) -> Option<&'static HashMap<String, usize>> {
    match domain {
        ENTERPRISE => Some(&INDEX),
        MOBILE => Some(&MOBILE_INDEX),
        ICS => Some(&ICS_INDEX),
        _ => None,
    }
}

/// "Enterprise", "Mobile" or "ICS".
pub fn domain_label(domain: &str) -> &'static str {
    match domain {
        MOBILE => "Mobile",
        ICS => "ICS",
        _ => "Enterprise",
    }
}

/// A domain as the app's API or a Navigator layer names it (older layers used `mitre-…`).
pub fn parse_domain(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "enterprise-attack" | "mitre-enterprise" | "enterprise" => Some(ENTERPRISE),
        "mobile-attack" | "mitre-mobile" | "mobile" => Some(MOBILE),
        "ics-attack" | "mitre-ics" | "ics" => Some(ICS),
        _ => None,
    }
}

/// A technique of a domain's catalog.
pub fn technique_in(domain: &str, id: &str) -> Option<&'static Technique> {
    let (cat, idx) = (catalog_for(domain)?, index_for(domain)?);
    idx.get(&id.to_ascii_uppercase()).map(|&i| &cat.techniques[i])
}

/// What a domain's catalog says about an ID.
pub fn id_state_in(domain: &str, id: &str) -> IdState {
    let id = id.to_ascii_uppercase();
    let Some(cat) = catalog_for(domain) else { return IdState::Unknown };
    if technique_in(domain, &id).is_some() {
        IdState::Current
    } else if let Some(by) = cat.revoked.get(&id) {
        IdState::Revoked { by: by.clone() }
    } else if cat.deprecated.contains(&id) {
        IdState::Deprecated
    } else {
        IdState::Unknown
    }
}

/// The domain whose catalog knows the ID (current, revoked or deprecated), Enterprise first; None
/// when no catalog does. The bundled catalogs share no ID (a test checks it).
pub fn domain_of(id: &str) -> Option<&'static str> {
    DOMAINS.iter().copied().find(|d| id_state_in(d, id) != IdState::Unknown)
}

/// Whether an ID belongs in a domain's matrix: its domain's, or Enterprise for an ID no catalog
/// knows (as before there were several).
pub fn in_domain(id: &str, domain: &str) -> bool {
    domain_of(id).map_or(domain == ENTERPRISE, |d| d == domain)
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

    /// Mission 6: Mobile and ICS are complete, attributed, of the same release as Enterprise, and
    /// share no ID with Enterprise or with each other, so an ID names its domain.
    #[test]
    fn mobile_and_ics_catalogs_are_complete_and_their_ids_name_their_domain() {
        for d in [MOBILE, ICS] {
            let c = catalog_for(d).unwrap();
            assert_eq!(c.domain, d);
            assert_eq!(c.version, catalog().version, "all three from one ATT&CK release");
            assert!(c.notice.contains("The MITRE Corporation") && c.license.contains("royalty-free"));
            assert!(c.tactics.len() >= 12 && c.techniques.len() > 90, "{d}: {} tactics, {} techniques", c.tactics.len(), c.techniques.len());
            let tactics: Vec<&str> = c.tactics.iter().map(|t| t.shortname.as_str()).collect();
            for t in &c.techniques {
                assert!(!t.tactics.is_empty() && t.tactics.iter().all(|x| tactics.contains(&x.as_str())), "{d} {}", t.id);
                if let Some(p) = &t.parent {
                    assert!(technique_in(d, p).is_some(), "{d}: {} has no parent {p}", t.id);
                }
            }
        }
        // no ID in two catalogs: current, revoked or deprecated
        let mut seen: HashMap<String, &str> = HashMap::new();
        for d in DOMAINS {
            let c = catalog_for(d).unwrap();
            let ids = c.techniques.iter().map(|t| t.id.clone()).chain(c.revoked.keys().cloned()).chain(c.deprecated.iter().cloned());
            for id in ids {
                if let Some(other) = seen.insert(id.clone(), d) {
                    assert_eq!(other, *d, "{id} is in {other} and {d}");
                }
            }
        }
        // the same name, three IDs
        assert_eq!(technique_in(ENTERPRISE, "T1059").unwrap().name, "Command and Scripting Interpreter");
        assert_eq!(technique_in(MOBILE, "T1623").unwrap().name, "Command and Scripting Interpreter");
        assert_eq!(technique_in(ICS, "T1701").unwrap().name, "Command and Scripting Interpreter");
        assert_eq!((domain_of("t1404"), domain_of("T0800"), domain_of("T1059.001"), domain_of("T9999")), (Some(MOBILE), Some(ICS), Some(ENTERPRISE), None));
        assert!(in_domain("T9999", ENTERPRISE) && !in_domain("T9999", MOBILE) && in_domain("T1404", MOBILE) && !in_domain("T1404", ENTERPRISE));
        assert_eq!(id_state("T1404"), IdState::Unknown, "Enterprise lookups stay Enterprise");
        assert_eq!((parse_domain("mitre-mobile"), parse_domain("ICS-attack"), parse_domain("pre-attack")), (Some(MOBILE), Some(ICS), None));
    }
}
