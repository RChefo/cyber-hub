//! OSINT data model: entity types, the relationship registry, verification and confidence.
//!
//! Intelligence (entities, relationships, evidence) belongs to an investigation. Saved graphs are
//! views over that intelligence: their own membership plus presentation state (see `store.rs`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Domain,
    Ip,
    Netblock,
    Url,
    Email,
    Username,
    Profile,
    Organization,
    Person,
    HostingProvider,
    Certificate,
    Asn,
    Technology,
    Repository,
    Location,
    Vulnerability,
    FileHash,
    Service,
    Threat,
    Other,
}

impl EntityType {
    pub const ALL: [EntityType; 20] = [
        EntityType::Domain,
        EntityType::Ip,
        EntityType::Netblock,
        EntityType::Url,
        EntityType::Email,
        EntityType::Username,
        EntityType::Profile,
        EntityType::Organization,
        EntityType::Person,
        EntityType::HostingProvider,
        EntityType::Certificate,
        EntityType::Asn,
        EntityType::Technology,
        EntityType::Repository,
        EntityType::Location,
        EntityType::Vulnerability,
        EntityType::FileHash,
        EntityType::Service,
        EntityType::Threat,
        EntityType::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EntityType::Domain => "domain",
            EntityType::Ip => "ip",
            EntityType::Netblock => "netblock",
            EntityType::Url => "url",
            EntityType::Email => "email",
            EntityType::Username => "username",
            EntityType::Profile => "profile",
            EntityType::Organization => "organization",
            EntityType::Person => "person",
            EntityType::HostingProvider => "hosting_provider",
            EntityType::Certificate => "certificate",
            EntityType::Asn => "asn",
            EntityType::Technology => "technology",
            EntityType::Repository => "repository",
            EntityType::Location => "location",
            EntityType::Vulnerability => "vulnerability",
            EntityType::FileHash => "file_hash",
            EntityType::Service => "service",
            EntityType::Threat => "threat",
            EntityType::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<EntityType> {
        EntityType::ALL.into_iter().find(|t| t.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            EntityType::Domain => "Domain",
            EntityType::Ip => "IP address",
            EntityType::Netblock => "Network block",
            EntityType::Url => "URL",
            EntityType::Email => "Email address",
            EntityType::Username => "Username",
            EntityType::Profile => "Public profile",
            EntityType::Organization => "Organization",
            EntityType::Person => "Person",
            EntityType::HostingProvider => "Hosting provider",
            EntityType::Certificate => "Certificate",
            EntityType::Asn => "Autonomous system",
            EntityType::Technology => "Technology",
            EntityType::Repository => "Repository",
            EntityType::Location => "Location",
            EntityType::Vulnerability => "Vulnerability",
            EntityType::FileHash => "File hash",
            EntityType::Service => "Network service",
            EntityType::Threat => "Threat / malware family",
            EntityType::Other => "Other",
        }
    }

    /// Types an investigation can start from (its primary target).
    pub fn is_target_type(self) -> bool {
        matches!(
            self,
            EntityType::Domain | EntityType::Ip | EntityType::Netblock | EntityType::Url | EntityType::Email | EntityType::Username | EntityType::Organization | EntityType::Person | EntityType::Asn | EntityType::Repository | EntityType::FileHash | EntityType::Other
        )
    }
}

/// How far an element has been confirmed. Only an analyst moves something to `Verified`,
/// `Disputed` or `Rejected`; automated sources produce `Observed` (direct data) or `Inferred`
/// (a correlation rule or a suggestion that needs review).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Observed,
    Verified,
    Inferred,
    Disputed,
    Rejected,
}

impl Verification {
    pub fn as_str(self) -> &'static str {
        match self {
            Verification::Observed => "observed",
            Verification::Verified => "verified",
            Verification::Inferred => "inferred",
            Verification::Disputed => "disputed",
            Verification::Rejected => "rejected",
        }
    }
    pub fn parse(s: &str) -> Option<Verification> {
        [Verification::Observed, Verification::Verified, Verification::Inferred, Verification::Disputed, Verification::Rejected].into_iter().find(|v| v.as_str() == s)
    }
    /// States an analyst sets by hand.
    pub fn is_analyst_decision(self) -> bool {
        matches!(self, Verification::Verified | Verification::Disputed | Verification::Rejected)
    }
}

/// Qualitative confidence. Deliberately not a percentage: it summarises what kind of evidence
/// exists (see `confidence::assess`), not a probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
    pub fn parse(s: &str) -> Option<Confidence> {
        match s {
            "low" => Some(Confidence::Low),
            "medium" => Some(Confidence::Medium),
            "high" => Some(Confidence::High),
            _ => None,
        }
    }
}

/// What a piece of evidence says about the fact it supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// the source states the fact itself (a DNS answer, an RDAP record, a certificate's names)
    Direct,
    /// the source reports the fact, but as an aggregated or third-party observation
    Corroborating,
    /// a heuristic signal (shared IP, same provider, similar name): never proof on its own
    Weak,
}

impl Strength {
    pub fn as_str(self) -> &'static str {
        match self {
            Strength::Direct => "direct",
            Strength::Corroborating => "corroborating",
            Strength::Weak => "weak",
        }
    }
    pub fn parse(s: &str) -> Option<Strength> {
        match s {
            "direct" => Some(Strength::Direct),
            "corroborating" => Some(Strength::Corroborating),
            "weak" => Some(Strength::Weak),
            _ => None,
        }
    }
}

/// A known relationship type. Analysts may also use custom types (`is_valid_type`).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipType {
    pub id: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    pub directed: bool,
    /// produced only by correlation rules: always starts as `inferred`
    pub inferred: bool,
    pub description: &'static str,
}

const fn rt(id: &'static str, label: &'static str, category: &'static str, directed: bool, inferred: bool, description: &'static str) -> RelationshipType {
    RelationshipType { id, label, category, directed, inferred, description }
}

pub const RELATIONSHIP_TYPES: &[RelationshipType] = &[
    // infrastructure
    rt("RESOLVES_TO", "resolves to", "infrastructure", true, false, "A DNS A/AAAA answer for the domain contains the address."),
    rt("ALIAS_OF", "alias of", "infrastructure", true, false, "The domain is a DNS CNAME for the target."),
    rt("REVERSE_DNS", "reverse DNS name", "infrastructure", true, false, "The address's PTR record names the domain (set by the address holder; not proof of ownership)."),
    rt("USES_NAMESERVER", "uses name server", "infrastructure", true, false, "The domain's NS records name the target."),
    rt("USES_MAIL_SERVER", "uses mail server", "infrastructure", true, false, "The domain's MX records name the target."),
    rt("HOSTED_ON", "hosted on", "infrastructure", true, false, "The address or service is hosted by the provider or network."),
    rt("PART_OF", "part of", "infrastructure", true, false, "The address lies inside the network block."),
    rt("ANNOUNCES_PREFIX", "announces prefix", "infrastructure", true, false, "The autonomous system announces the network block (BGP origin)."),
    rt("ROUTES_THROUGH", "routed by", "infrastructure", true, false, "The address is routed by the autonomous system."),
    rt("OPERATED_BY", "operated by", "infrastructure", true, false, "The network or autonomous system is registered to the organization."),
    rt("USES_CERTIFICATE", "uses certificate", "infrastructure", true, false, "The certificate lists the domain among its names."),
    rt("EXPOSES_SERVICE", "exposes service", "infrastructure", true, false, "A scan or provider observed the service on the address."),
    rt("USES_TECHNOLOGY", "uses technology", "infrastructure", true, false, "The service or site announces the technology (banner, header)."),
    rt("SHARES_INFRASTRUCTURE", "shares infrastructure with", "infrastructure", false, true, "Both use the same address, name server or certificate. A weak signal: it does not prove common ownership."),
    // domain and web
    rt("SUBDOMAIN_OF", "subdomain of", "web", true, false, "The name is below the parent domain in the DNS tree."),
    rt("ON_HOST", "on host", "web", true, false, "The URL is served from this host."),
    rt("REDIRECTS_TO", "redirects to", "web", true, false, "An HTTP response redirected to the target."),
    rt("LINKS_TO", "links to", "web", true, false, "The page links to the target."),
    rt("REFERENCES", "references", "web", true, false, "The source mentions the target."),
    rt("SERVES_CONTENT_FROM", "serves content from", "web", true, false, "The page loads resources from the target."),
    rt("SERVES_FILE", "serves file", "web", true, false, "The URL or host delivered the file."),
    // identity and organization
    rt("REGISTERED_WITH", "registered with", "identity", true, false, "The registry names the organization as registrar."),
    rt("REGISTERED_TO", "registered to", "identity", true, false, "The registry names the organization as registrant or holder."),
    rt("ASSOCIATED_WITH", "associated with", "identity", false, false, "A source links the two without a more specific relation."),
    rt("BELONGS_TO", "belongs to", "identity", true, false, "The address or account is under the target (e.g. an email under its domain)."),
    rt("MAINTAINED_BY", "maintained by", "identity", true, false, "The repository or project is maintained by the account or organization."),
    rt("MENTIONS", "mentions", "identity", true, false, "The source text names the target."),
    rt("USES_USERNAME", "uses username", "identity", true, false, "The person or address uses the username."),
    rt("HAS_PROFILE", "has profile", "identity", true, false, "The account has the public profile page."),
    rt("LOCATED_IN", "located in", "identity", true, false, "A registry or provider places the element in the location."),
    // repository and code
    rt("CONTAINS_REFERENCE_TO", "contains reference to", "code", true, false, "The repository contains the value."),
    rt("REFERENCES_DOMAIN", "references domain", "code", true, false, "The repository or code references the domain."),
    rt("REFERENCES_EMAIL", "references email", "code", true, false, "The repository or code references the email address."),
    rt("REFERENCES_IP", "references IP", "code", true, false, "The repository or code references the address."),
    // threat intelligence
    rt("INDICATED_AS_MALICIOUS", "reported malicious by", "threat", true, false, "A threat-intelligence provider reports the element as malicious."),
    rt("ASSOCIATED_WITH_THREAT", "associated with threat", "threat", true, false, "A provider associates the element with the threat or malware family."),
    rt("HOSTS_SUSPICIOUS_CONTENT", "hosts suspicious content", "threat", true, false, "The host serves content a provider flags."),
    rt("AFFECTED_BY", "affected by", "threat", true, false, "The technology or service is affected by the vulnerability."),
];

pub fn relationship_type(id: &str) -> Option<&'static RelationshipType> {
    RELATIONSHIP_TYPES.iter().find(|r| r.id == id)
}

/// Known types, or a custom type written like the built-in ones (`UPPER_SNAKE`, 3-40 chars).
pub fn is_valid_type(id: &str) -> bool {
    relationship_type(id).is_some()
        || (id.len() >= 3 && id.len() <= 40 && id.starts_with(|c: char| c.is_ascii_uppercase()) && id.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
}

pub fn is_directed(id: &str) -> bool {
    relationship_type(id).map_or(true, |r| r.directed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_round_trip_and_custom_relationships_are_constrained() {
        for t in EntityType::ALL {
            assert_eq!(EntityType::parse(t.as_str()), Some(t));
        }
        let mut ids: Vec<_> = RELATIONSHIP_TYPES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RELATIONSHIP_TYPES.len(), "unique relationship ids");
        assert!(is_valid_type("RESOLVES_TO") && is_valid_type("OWNS_BRAND"));
        for bad in ["resolves_to", "X", "A-B", "DROP TABLE", "", "ÄÖ_TYPE"] {
            assert!(!is_valid_type(bad), "{bad}");
        }
        assert!(!is_directed("SHARES_INFRASTRUCTURE") && is_directed("RESOLVES_TO") && is_directed("CUSTOM_TYPE"));
        assert!(relationship_type("SHARES_INFRASTRUCTURE").unwrap().inferred);
    }
}
