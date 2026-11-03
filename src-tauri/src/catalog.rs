//! Tool catalog — compiled into the binary from `catalog/tools.json`.
//! The catalog is the registry that adapters (detection, install, launch, run) work from.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCategory {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Detect {
    pub binaries: Vec<String>,
    #[serde(default)]
    pub paths: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub version_args: Vec<String>,
    #[serde(default)]
    pub version_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedInstall {
    pub os: Vec<String>,
    pub manager: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub name: String,
    pub binaries: Vec<String>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandExample {
    pub title: String,
    pub command: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDef {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub website: String,
    #[serde(default)]
    pub docs: Option<String>,
    pub os: Vec<String>,
    pub kind: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub detect: Option<Detect>,
    #[serde(default)]
    pub install: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub managed: Vec<ManagedInstall>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub commands: Vec<CommandExample>,
    #[serde(default)]
    pub requires_scope: bool,
    #[serde(default)]
    pub builder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub version: i64,
    pub categories: Vec<ToolCategory>,
    pub tools: Vec<ToolDef>,
}

pub static CATALOG: Lazy<Catalog> = Lazy::new(|| {
    serde_json::from_str(include_str!("../catalog/tools.json")).expect("catalog/tools.json is invalid")
});

pub fn tool(id: &str) -> Option<&'static ToolDef> {
    CATALOG.tools.iter().find(|t| t.id == id)
}

pub const ALLOWED_MANAGERS: &[&str] = &["winget", "brew", "pipx", "go"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_is_consistent() {
        let c = &*CATALOG;
        assert!(c.tools.len() >= 40, "catalog unexpectedly small");
        let cats: HashSet<_> = c.categories.iter().map(|c| c.id.as_str()).collect();
        let mut ids = HashSet::new();
        for t in &c.tools {
            assert!(ids.insert(t.id.as_str()), "duplicate tool id {}", t.id);
            assert!(cats.contains(t.category.as_str()), "{} has unknown category {}", t.id, t.category);
            assert!(["cli", "gui", "web", "script"].contains(&t.kind.as_str()), "{} bad kind", t.id);
            assert!(t.website.starts_with("https://") || t.website.starts_with("http://"), "{} bad website", t.id);
            for os in &t.os {
                assert!(["windows", "macos", "linux"].contains(&os.as_str()), "{} bad os {os}", t.id);
            }
            if let Some(d) = &t.detect {
                if let Some(r) = &d.version_regex {
                    regex::Regex::new(r).unwrap_or_else(|e| panic!("{} bad regex: {e}", t.id));
                }
            }
            for m in &t.managed {
                assert!(ALLOWED_MANAGERS.contains(&m.manager.as_str()), "{} bad manager", t.id);
            }
        }
    }
}
