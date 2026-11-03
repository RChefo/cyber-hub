//! Normalized provider results.
//!
//! Every provider keeps its own verdict wording (`Verdict::label`) and its own scores.
//! `Level` is a coarse bucket used only for sorting and colour; how each provider maps to it
//! is documented next to that provider's parser and in docs/SECURITY.md. Scores from
//! different providers are never combined.

use serde::{Deserialize, Serialize};

use super::indicator::Kind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Malicious,
    Suspicious,
    /// the provider positively says the indicator is benign (e.g. allow-listed)
    Clean,
    /// informational data without a verdict (e.g. exposed services)
    Info,
    /// data exists but the provider gives no verdict
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub level: Level,
    /// the provider's own wording, e.g. "Abuse confidence 87%", "3 of 84 engines"
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    /// what the number is, in the provider's terms
    pub label: String,
    pub value: f64,
    pub max: Option<f64>,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub title: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Related {
    pub kind: Kind,
    pub value: String,
    /// how it relates, in the provider's terms ("payload served", "host")
    pub relation: String,
}

/// What a provider said about an indicator.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Report {
    pub verdict: Option<Verdict>,
    pub scores: Vec<Score>,
    pub categories: Vec<String>,
    pub families: Vec<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub facts: Vec<Fact>,
    pub tables: Vec<Table>,
    pub related: Vec<Related>,
    pub permalink: Option<String>,
}

impl Report {
    pub fn fact(&mut self, label: &str, value: Option<String>) {
        if let Some(v) = value.filter(|v| !v.trim().is_empty()) {
            self.facts.push(Fact { label: label.into(), value: v });
        }
    }
    pub fn relate(&mut self, value: &str, relation: &str) {
        if self.related.len() >= 40 {
            return;
        }
        if let Ok(ind) = super::indicator::detect(value) {
            if !self.related.iter().any(|r| r.value == ind.value) {
                self.related.push(Related { kind: ind.kind, value: ind.value, relation: relation.into() });
            }
        }
    }
}

/// Parser output: whether the provider has a record, plus whatever it returned.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub found: bool,
    pub report: Report,
}

impl Parsed {
    pub fn found(report: Report) -> Self {
        Self { found: true, report }
    }
    pub fn none() -> Self {
        Self { found: false, report: Report::default() }
    }
    pub fn none_with(report: Report) -> Self {
        Self { found: false, report }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Found,
    NotFound,
    /// this provider does not handle this indicator type
    Unsupported,
    NoKey,
    Disabled,
    RateLimited,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResult {
    pub provider: String,
    pub provider_name: String,
    pub status: Status,
    pub report: Option<Report>,
    /// error / status explanation for the UI
    pub message: Option<String>,
    /// "live" or "cache"
    pub source: Option<String>,
    pub fetched_at: Option<String>,
    pub fresh_until: Option<String>,
    /// remaining quota reported by the provider with this response, if any
    pub quota: Option<String>,
}

/// Sort-normalized lists: trimmed, deduplicated, capped.
pub fn tidy(mut v: Vec<String>, cap: usize) -> Vec<String> {
    v = v
        .into_iter()
        .map(|s| s.chars().filter(|c| !c.is_control() && *c != '\u{2028}' && *c != '\u{2029}').collect::<String>().trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .collect();
    let mut seen = std::collections::HashSet::new();
    v.retain(|s| seen.insert(s.to_ascii_lowercase()));
    v.truncate(cap);
    v
}

/// Earliest / latest of provider timestamps that share one format.
pub fn min_max(dates: impl Iterator<Item = String>) -> (Option<String>, Option<String>) {
    let mut v: Vec<String> = dates.filter(|d| !d.is_empty()).collect();
    v.sort();
    (v.first().cloned(), v.last().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_cached_record_deserializes() {
        // "no record" results are cached as `{}`
        assert_eq!(serde_json::from_str::<Report>("{}").unwrap(), Report::default());
    }
}
