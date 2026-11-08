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
//! verdicts are claimed: `indicator_types` is left out.

use serde_json::{json, Value};
use sha1::{Digest, Sha1};

/// UUID namespace of Cyber Hub's indicator IDs (fixed; changing it would change every exported ID).
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

/// One saved indicator: (kind, value, note, saved at).
pub struct Saved<'a> {
    pub kind: &'a str,
    pub value: &'a str,
    pub note: &'a str,
    pub saved_at: &'a str,
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
        o["description"] = json!(if note.is_empty() { "Saved in Cyber Hub".to_string() } else { format!("{note} (saved in Cyber Hub)") });
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
            Saved { kind: "domain", value: "evil.example.com", note: "Phishing kit", saved_at: "2026-11-08T22:37:41Z" },
            Saved { kind: "file", value: "1234", note: "", saved_at: "2026-11-08T22:37:41Z" },
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
        assert_eq!(o["description"], "Phishing kit (saved in Cyber Hub)");
        assert!(o["id"].as_str().unwrap().starts_with("indicator--"));
        assert!(o.get("indicator_types").is_none(), "no verdict is claimed");
    }
}
