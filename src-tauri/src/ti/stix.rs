//! STIX 2.1 export of saved indicators (docs/PROVIDERS.md#stix-21-export).
//!
//! Each saved indicator becomes an `indicator` object with a STIX pattern
//! (`[ipv4-addr:value = '…']`, `[domain-name:value = '…']`, `[url:value = '…']`,
//! `[file:hashes.'SHA-256' = '…']`) in one `bundle`. Indicator IDs are UUIDv5 values derived from
//! the indicator, so exporting the same indicator again gives the same ID and a platform that
//! imports both files updates one object instead of creating duplicates. The bundle ID is random
//! (UUIDv4), as the specification recommends. Timestamps are UTC with millisecond precision.
//!
//! Only what the analyst saved is exported, with their note as the description. No provider
//! verdicts are claimed: `indicator_types` is left out. The lifecycle goes with it: `confidence`
//! (0–100), `valid_until` (the end of the day the analyst named), `revoked` for revoked indicators
//! and false positives, and the source as an external reference with its reliability. An
//! indicator whose validity ended before it was saved is not exported: STIX requires
//! `valid_until` to be later than `valid_from`.

use serde_json::{json, Value};
use sha1::{Digest, Sha1};

/// UUID namespace of ExploitX's indicator IDs (fixed; changing it would change every exported ID).
const NAMESPACE: [u8; 16] = [184, 17, 82, 60, 127, 142, 69, 80, 172, 151, 8, 101, 133, 225, 175, 112];

fn uuid_text(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// RFC 4122 UUID version 5 (SHA-1 of namespace and name).
pub fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(namespace);
    h.update(name);
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_text(&b)
}

/// RFC 4122 UUID version 4 (random).
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_text(&b)
}

/// A string literal of the STIX patterning language: only `\` and `'` are escaped.
fn literal(v: &str) -> String {
    format!("'{}'", v.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The STIX pattern of a saved indicator (`kind` as stored: ip, domain, url, file), or None for a
/// file hash of an unknown length.
pub fn pattern(kind: &str, value: &str) -> Option<String> {
    let v = value.trim();
    match kind {
        "ip" if v.contains(':') => Some(format!("[ipv6-addr:value = {}]", literal(v))),
        "ip" => Some(format!("[ipv4-addr:value = {}]", literal(v))),
        "domain" => Some(format!("[domain-name:value = {}]", literal(&v.to_lowercase()))),
        "url" => Some(format!("[url:value = {}]", literal(v))),
        "file" => {
            let algo = match v.len() {
                32 => "MD5",
                40 => "'SHA-1'",
                64 => "'SHA-256'",
                128 => "'SHA-512'",
                _ => return None,
            };
            v.bytes().all(|b| b.is_ascii_hexdigit()).then(|| format!("[file:hashes.{algo} = {}]", literal(&v.to_lowercase())))
        }
        _ => None,
    }
}

/// RFC 3339 UTC with milliseconds (`2026-11-08T22:37:41.000Z`), from a stored timestamp.
pub fn stix_time(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// One saved indicator and its lifecycle.
pub struct Saved<'a> {
    pub kind: &'a str,
    pub value: &'a str,
    pub note: &'a str,
    pub saved_at: &'a str,
    pub source: &'a str,
    pub reliability: &'a str,
    pub confidence: Option<i64>,
    /// YYYY-MM-DD
    pub valid_until: Option<&'a str>,
    /// active, revoked or false_positive
    pub status: &'a str,
}

/// The bundle, and the indicators that could not be expressed as patterns.
pub fn bundle(items: &[Saved]) -> (Value, Vec<String>) {
    let mut objects = Vec::new();
    let mut skipped = Vec::new();
    for it in items {
        let Some(p) = pattern(it.kind, it.value) else {
            skipped.push(it.value.to_string());
            continue;
        };
        let t = stix_time(it.saved_at);
        let until = it.valid_until.filter(|d| !d.is_empty()).map(|d| format!("{d}T23:59:59.999Z"));
        if until.as_deref().is_some_and(|u| u <= t.as_str()) {
            skipped.push(format!("{} (its validity ended before it was saved)", it.value));
            continue;
        }
        let mut o = json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", uuid_v5(&NAMESPACE, format!("{}:{}", it.kind, it.value.trim().to_lowercase()).as_bytes())),
            "created": t,
            "modified": t,
            "name": it.value.trim(),
            "pattern": p,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": t,
        });
        let note = it.note.trim();
        let fp = if it.status == "false_positive" { " Marked a false positive." } else { "" };
        o["description"] = json!(if note.is_empty() { format!("Saved in ExploitX.{fp}") } else { format!("{note} (saved in ExploitX).{fp}") });
        if let Some(c) = it.confidence {
            o["confidence"] = json!(c.clamp(0, 100));
        }
        if let Some(u) = until {
            o["valid_until"] = json!(u);
        }
        if it.status != "active" {
            o["revoked"] = json!(true);
        }
        if !it.source.trim().is_empty() {
            let reliability = crate::ti::lifecycle::RELIABILITY.iter().find(|(k, _)| *k == it.reliability).map(|(k, l)| format!("source reliability {k} ({l})"));
            o["external_references"] = json!([{ "source_name": it.source.trim(), "description": reliability.unwrap_or_else(|| "where the indicator came from".into()) }]);
        }
        objects.push(o);
    }
    (json!({ "type": "bundle", "id": format!("bundle--{}", uuid_v4()), "objects": objects }), skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v5_matches_the_rfc_construction() {
        // the STIX 2.1 SCO namespace and the identifier python-stix2 derives for this IPv4 address
        let stix_ns: [u8; 16] = [0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7];
        assert_eq!(uuid_v5(&stix_ns, br#"{"value":"198.51.100.3"}"#), "28bb3599-77cd-5a82-a950-b5bc3caf07c4");
        let v4 = uuid_v4();
        assert_eq!((v4.len(), &v4[14..15]), (36, "4"));
        assert!(matches!(&v4[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn patterns_follow_the_patterning_language() {
        assert_eq!(pattern("ip", "198.51.100.7").unwrap(), "[ipv4-addr:value = '198.51.100.7']");
        assert_eq!(pattern("ip", "2001:db8::1").unwrap(), "[ipv6-addr:value = '2001:db8::1']");
        assert_eq!(pattern("domain", "Evil.Example.com").unwrap(), "[domain-name:value = 'evil.example.com']");
        assert_eq!(pattern("url", "http://x.example/a'b\\c").unwrap(), r"[url:value = 'http://x.example/a\'b\\c']", "quotes and backslashes are escaped");
        assert_eq!(pattern("file", "D41D8CD98F00B204E9800998ECF8427E").unwrap(), "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']");
        assert!(pattern("file", &"a".repeat(64)).unwrap().contains("hashes.'SHA-256'"));
        assert!(pattern("file", "abc").is_none());
        assert!(pattern("file", &"z".repeat(32)).is_none());
    }

    #[test]
    fn bundles_have_stable_indicator_ids_and_required_properties() {
        let items = [
            saved("domain", "evil.example.com", "Phishing kit"),
            saved("file", "1234", ""),
        ];
        let (a, skipped) = bundle(&items);
        let (b, _) = bundle(&items);
        assert_eq!(skipped, vec!["1234".to_string()]);
        assert_eq!(a["type"], "bundle");
        assert!(a.get("spec_version").is_none(), "a bundle has no spec_version in STIX 2.1");
        assert_ne!(a["id"], b["id"], "bundle IDs are random");
        let o = &a["objects"][0];
        assert_eq!(o["id"], b["objects"][0]["id"], "indicator IDs are stable");
        for key in ["type", "spec_version", "id", "created", "modified", "pattern", "pattern_type", "valid_from"] {
            assert!(o.get(key).is_some(), "{key} is required");
        }
        assert_eq!(o["created"], "2026-11-08T22:37:41.000Z");
        assert_eq!(o["description"], "Phishing kit (saved in ExploitX).");
        assert!(o["id"].as_str().unwrap().starts_with("indicator--"));
        assert!(o.get("indicator_types").is_none(), "no verdict is claimed");
        for key in ["confidence", "valid_until", "revoked", "external_references"] {
            assert!(o.get(key).is_none(), "{key} only when the analyst set it");
        }
    }

    fn saved<'a>(kind: &'a str, value: &'a str, note: &'a str) -> Saved<'a> {
        Saved { kind, value, note, saved_at: "2026-11-08T22:37:41Z", source: "", reliability: "", confidence: None, valid_until: None, status: "active" }
    }

    #[test]
    fn the_lifecycle_goes_with_the_indicator() {
        let items = [
            Saved { source: "Vendor report 41", reliability: "B", confidence: Some(85), valid_until: Some("2026-12-31"), ..saved("domain", "evil.example.com", "C2") },
            Saved { status: "false_positive", ..saved("ip", "198.51.100.7", "") },
            Saved { status: "revoked", source: "Feed", ..saved("ip", "198.51.100.8", "") },
            Saved { valid_until: Some("2026-11-01"), ..saved("ip", "198.51.100.9", "") },
        ];
        let (b, skipped) = bundle(&items);
        assert_eq!(skipped, vec!["198.51.100.9 (its validity ended before it was saved)".to_string()]);
        let o = &b["objects"];
        assert_eq!((o[0]["confidence"].as_i64(), o[0]["valid_until"].as_str()), (Some(85), Some("2026-12-31T23:59:59.999Z")));
        assert!(o[0]["valid_until"].as_str().unwrap() > o[0]["valid_from"].as_str().unwrap());
        assert_eq!(o[0]["external_references"][0]["source_name"], "Vendor report 41");
        assert_eq!(o[0]["external_references"][0]["description"], "source reliability B (Usually reliable)");
        assert!(o[0].get("revoked").is_none());
        assert_eq!((o[1]["revoked"].as_bool(), o[1]["description"].as_str()), (Some(true), Some("Saved in ExploitX. Marked a false positive.")));
        assert_eq!(o[2]["revoked"], true);
        assert_eq!(o[2]["external_references"][0]["description"], "where the indicator came from");
    }
}
