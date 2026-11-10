//! The lifecycle of saved indicators (docs/PROVIDERS.md#saved-indicators): where an indicator
//! came from and how reliable that source is, how confident the analyst is, until when it is
//! valid, and whether it was revoked or found to be a false positive. Every change is kept.
//!
//! An indicator past its `valid_until` date is *expired*: computed when read, never written, so
//! nothing has to run for indicators to age. Expired, revoked and false-positive indicators stay
//! saved for the record but are not presented as current intelligence.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{validation, AppError, AppResult};
use crate::util::now;

pub const STATUSES: &[&str] = &["active", "revoked", "false_positive"];
/// Source reliability, the Admiralty (NATO) scale.
pub const RELIABILITY: &[(&str, &str)] = &[
    ("A", "Completely reliable"),
    ("B", "Usually reliable"),
    ("C", "Fairly reliable"),
    ("D", "Not usually reliable"),
    ("E", "Unreliable"),
    ("F", "Reliability cannot be judged"),
];

/// The STIX 2.1 "None / Low / Med / High" reading of a 0–100 confidence.
pub fn confidence_label(c: i64) -> &'static str {
    match c {
        0 => "none",
        1..=29 => "low",
        30..=69 => "medium",
        _ => "high",
    }
}

/// The status as it stands today: an active indicator past its validity is expired.
pub fn effective(status: &str, valid_until: Option<&str>, today: &str) -> &'static str {
    match status {
        "revoked" => "revoked",
        "false_positive" => "false_positive",
        _ if valid_until.is_some_and(|v| !v.is_empty() && v < today) => "expired",
        _ => "active",
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    pub id: i64,
    pub kind: String,
    pub indicator: String,
    pub note: String,
    /// where the indicator came from (a report, a feed, a case); empty when not recorded
    pub source: String,
    /// A–F (Admiralty scale), empty when not judged
    pub reliability: String,
    /// 0–100 (STIX 2.1), None when not set
    pub confidence: Option<i64>,
    pub confidence_label: Option<&'static str>,
    pub status: String,
    /// active, expired, revoked or false_positive
    pub effective: &'static str,
    /// YYYY-MM-DD
    pub valid_until: Option<String>,
    /// when it was saved: the collection time
    pub created_at: String,
    pub updated_at: String,
}

const COLS: &str = "id, kind, indicator, note, source, reliability, confidence, status, valid_until, created_at, updated_at";

fn row(r: &rusqlite::Row, today: &str) -> rusqlite::Result<Saved> {
    let status: String = r.get(7)?;
    let valid_until: Option<String> = r.get(8)?;
    let confidence: Option<i64> = r.get(6)?;
    Ok(Saved {
        id: r.get(0)?,
        kind: r.get(1)?,
        indicator: r.get(2)?,
        note: r.get(3)?,
        source: r.get(4)?,
        reliability: r.get(5)?,
        confidence,
        confidence_label: confidence.map(confidence_label),
        effective: effective(&status, valid_until.as_deref(), today),
        status,
        valid_until,
        created_at: r.get(9)?,
        updated_at: r.get(10)?,
    })
}

fn today() -> String {
    now().get(..10).unwrap_or("").to_string()
}

/// One page of the saved indicators and how many there are (Mission 7).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedPage {
    pub items: Vec<Saved>,
    /// all saved indicators
    pub total: i64,
    /// those that match the search
    pub matching: i64,
}

/// The newest `limit` saved indicators whose value, source or note contains `query` (any case),
/// with the counts. A TAXII feed can save 100,000 indicators, and sending them all to the page
/// after every lookup and synchronization took about 1.7 s and 28.7 MB of JSON each time
/// (measured in Mission 7); a page of them is what the list shows anyway.
pub fn page(c: &Connection, query: &str, limit: usize) -> AppResult<SavedPage> {
    let t = today();
    let q = query.trim().to_lowercase();
    let like = format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let filter = r"(?1 = '' OR lower(indicator) LIKE ?2 ESCAPE '\' OR lower(source) LIKE ?2 ESCAPE '\' OR lower(note) LIKE ?2 ESCAPE '\')";
    let total: i64 = c.query_row("SELECT COUNT(*) FROM ti_saved", [], |r| r.get(0))?;
    let matching: i64 = c.query_row(&format!("SELECT COUNT(*) FROM ti_saved WHERE {filter}"), params![q, like], |r| r.get(0))?;
    let mut st = c.prepare(&format!("SELECT {COLS} FROM ti_saved WHERE {filter} ORDER BY created_at DESC, id DESC LIMIT ?3"))?;
    let items = st.query_map(params![q, like, limit.clamp(1, 5000) as i64], |r| row(r, &t))?.collect::<Result<Vec<_>, _>>()?;
    Ok(SavedPage { items, total, matching })
}

pub fn list(c: &Connection) -> AppResult<Vec<Saved>> {
    let t = today();
    let mut st = c.prepare(&format!("SELECT {COLS} FROM ti_saved ORDER BY created_at DESC"))?;
    let rows = st.query_map([], |r| row(r, &t))?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn get(c: &Connection, id: i64) -> AppResult<Saved> {
    let t = today();
    c.query_row(&format!("SELECT {COLS} FROM ti_saved WHERE id = ?1"), params![id], |r| row(r, &t)).optional()?.ok_or_else(|| AppError::NotFound(format!("saved indicator {id}")))
}

/// The saved indicator with this value, if any.
pub fn find(c: &Connection, value: &str) -> AppResult<Option<Saved>> {
    let t = today();
    Ok(c.query_row(&format!("SELECT {COLS} FROM ti_saved WHERE indicator = ?1"), params![value], |r| row(r, &t)).optional()?)
}

pub fn record(c: &Connection, id: i64, action: &str, detail: &str) -> AppResult<()> {
    c.execute("INSERT INTO ti_saved_events (saved_id, action, detail, at) VALUES (?1, ?2, ?3, ?4)", params![id, action, detail, now()])?;
    Ok(())
}

/// What may change about a saved indicator; `None` leaves a field as it is.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub reliability: Option<String>,
    /// a number from 0 to 100; -1 clears it
    #[serde(default)]
    pub confidence: Option<i64>,
    #[serde(default)]
    pub status: Option<String>,
    /// YYYY-MM-DD; an empty string clears it
    #[serde(default)]
    pub valid_until: Option<String>,
}

fn text(field: &str, v: &str, max: usize) -> AppResult<String> {
    let v = v.trim();
    if v.chars().count() > max || v.chars().any(|ch| ch.is_control() && ch != '\n') {
        return Err(validation(format!("The {field} has at most {max} characters and no control characters")));
    }
    Ok(v.to_string())
}

/// Applies changes and records each one in the indicator's history.
pub fn update(c: &Connection, id: i64, ch: &Changes) -> AppResult<Saved> {
    let before = get(c, id)?;
    let mut done: Vec<String> = Vec::new();
    let tx = c.unchecked_transaction()?;
    if let Some(n) = &ch.note {
        let n = text("note", n, 500)?;
        if n != before.note {
            tx.execute("UPDATE ti_saved SET note = ?2 WHERE id = ?1", params![id, n])?;
            done.push("note changed".into());
        }
    }
    if let Some(s) = &ch.source {
        let s = text("source", s, 300)?;
        if s != before.source {
            tx.execute("UPDATE ti_saved SET source = ?2 WHERE id = ?1", params![id, s])?;
            done.push(if s.is_empty() { "source cleared".into() } else { format!("source: {s}") });
        }
    }
    if let Some(r) = &ch.reliability {
        let r = r.trim().to_ascii_uppercase();
        if !r.is_empty() && !RELIABILITY.iter().any(|(k, _)| *k == r) {
            return Err(validation("The source reliability is A to F, or empty"));
        }
        if r != before.reliability {
            tx.execute("UPDATE ti_saved SET reliability = ?2 WHERE id = ?1", params![id, r])?;
            done.push(if r.is_empty() { "reliability cleared".into() } else { format!("source reliability {r}") });
        }
    }
    if let Some(v) = ch.confidence {
        let v = if v < 0 { None } else { Some(v) };
        if v.is_some_and(|x| x > 100) {
            return Err(validation("Confidence is a number from 0 to 100"));
        }
        if v != before.confidence {
            tx.execute("UPDATE ti_saved SET confidence = ?2 WHERE id = ?1", params![id, v])?;
            done.push(match v {
                Some(x) => format!("confidence {x} ({})", confidence_label(x)),
                None => "confidence cleared".into(),
            });
        }
    }
    if let Some(s) = &ch.status {
        if !STATUSES.contains(&s.as_str()) {
            return Err(validation("The status is active, revoked or false_positive"));
        }
        if *s != before.status {
            tx.execute("UPDATE ti_saved SET status = ?2 WHERE id = ?1", params![id, s])?;
            done.push(format!("status {} → {}", before.status.replace('_', " "), s.replace('_', " ")));
        }
    }
    if let Some(d) = &ch.valid_until {
        let d = d.trim();
        let v = if d.is_empty() {
            None
        } else {
            chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| validation("Valid until is a date (YYYY-MM-DD)"))?;
            Some(d.to_string())
        };
        if v != before.valid_until {
            tx.execute("UPDATE ti_saved SET valid_until = ?2 WHERE id = ?1", params![id, v])?;
            done.push(match &v {
                Some(d) => format!("valid until {d}"),
                None => "no expiry".into(),
            });
        }
    }
    if !done.is_empty() {
        tx.execute("UPDATE ti_saved SET updated_at = ?2 WHERE id = ?1", params![id, now()])?;
        record(&tx, id, "updated", &done.join("; "))?;
    }
    tx.commit()?;
    get(c, id)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub action: String,
    pub detail: String,
    pub at: String,
}

pub fn history(c: &Connection, id: i64) -> AppResult<Vec<Event>> {
    get(c, id)?;
    let mut st = c.prepare("SELECT action, detail, at FROM ti_saved_events WHERE saved_id = ?1 ORDER BY id DESC LIMIT 200")?;
    let rows = st.query_map(params![id], |r| Ok(Event { action: r.get(0)?, detail: r.get(1)?, at: r.get(2)? }))?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// How a saved indicator reads where it is sighted (the Analysis tab): its standing, so a stale or
/// rejected indicator is not taken for current intelligence.
pub fn sighting_detail(s: &Saved) -> String {
    let mut parts = vec![if s.note.is_empty() { "Saved indicator".to_string() } else { s.note.clone() }];
    match s.effective {
        "expired" => parts.push(format!("expired {}: no longer current", s.valid_until.as_deref().unwrap_or(""))),
        "revoked" => parts.push("revoked".into()),
        "false_positive" => parts.push("marked a false positive".into()),
        _ => {}
    }
    if !s.source.is_empty() {
        parts.push(format!("source {}{}", s.source, if s.reliability.is_empty() { String::new() } else { format!(" ({})", s.reliability) }));
    }
    if let (Some(c), Some(l)) = (s.confidence, s.confidence_label) {
        parts.push(format!("confidence {c} ({l})"));
    }
    parts.join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    /// Mission 7: the list sends a page with the counts, searched on the value, the source and the
    /// note; `%` and `_` in a search are plain characters.
    #[test]
    fn saved_indicators_come_in_pages() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            for i in 0..250 {
                c.execute(
                    "INSERT INTO ti_saved (kind, indicator, note, source, created_at, updated_at) VALUES ('domain', ?1, ?2, ?3, ?4, ?4)",
                    params![format!("host{i}.example.net"), if i == 7 { "seen 100% in logs" } else { "" }, if i % 2 == 0 { "TAXII: Partner" } else { "IR_42" }, format!("2026-11-01T00:{:02}:{:02}Z", i / 60, i % 60)],
                )?;
            }
            let p = page(c, "", 100)?;
            assert_eq!((p.items.len(), p.total, p.matching), (100, 250, 250));
            assert_eq!(p.items[0].indicator, "host249.example.net", "newest first");
            let p = page(c, "HOST12", 100)?;
            assert_eq!(p.matching, 11, "host12 and host120–129, in any case");
            assert_eq!(page(c, "partner", 10)?.matching, 125, "the source");
            assert_eq!(page(c, "100%", 10)?.matching, 1, "the note, with % as a plain character");
            assert_eq!(page(c, "ir_4", 10)?.matching, 125, "_ as a plain character");
            assert_eq!(page(c, "irx4", 10)?.matching, 0);
            Ok(())
        })
        .unwrap();
    }

    fn save(c: &Connection, kind: &str, v: &str) -> i64 {
        c.execute("INSERT INTO ti_saved (kind, indicator, note, created_at, updated_at) VALUES (?1, ?2, '', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')", params![kind, v]).unwrap();
        c.last_insert_rowid()
    }

    #[test]
    fn confidence_reliability_expiry_and_status_are_kept_with_their_history() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let id = save(c, "domain", "evil.example");
            let s = get(c, id)?;
            assert_eq!((s.effective, s.confidence, s.reliability.as_str(), s.status.as_str()), ("active", None, "", "active"));
            let s = update(c, id, &Changes { source: Some("Vendor report 2026-41".into()), reliability: Some("b".into()), confidence: Some(85), valid_until: Some("2026-12-31".into()), ..Default::default() })?;
            assert_eq!((s.source.as_str(), s.reliability.as_str(), s.confidence, s.confidence_label, s.valid_until.as_deref()), ("Vendor report 2026-41", "B", Some(85), Some("high"), Some("2026-12-31")));
            // invalid values are refused and change nothing
            for bad in [
                Changes { confidence: Some(101), ..Default::default() },
                Changes { reliability: Some("G".into()), ..Default::default() },
                Changes { status: Some("malicious".into()), ..Default::default() },
                Changes { valid_until: Some("31/12/2026".into()), ..Default::default() },
                Changes { source: Some("x".repeat(301)), ..Default::default() },
            ] {
                assert!(update(c, id, &bad).is_err(), "{bad:?}");
            }
            assert_eq!(get(c, id)?.confidence, Some(85));
            // an unchanged save records nothing
            update(c, id, &Changes { confidence: Some(85), ..Default::default() })?;
            let s = update(c, id, &Changes { status: Some("false_positive".into()), confidence: Some(-1), ..Default::default() })?;
            assert_eq!((s.effective, s.confidence), ("false_positive", None));
            let h = history(c, id)?;
            assert_eq!(h.len(), 2);
            assert!(h[0].detail.contains("confidence cleared") && h[0].detail.contains("status active → false positive"), "{h:?}");
            assert!(h[1].detail.contains("source reliability B") && h[1].detail.contains("valid until 2026-12-31"), "{h:?}");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn expiry_is_computed_when_read() {
        assert_eq!(effective("active", Some("2026-11-09"), "2026-11-10"), "expired");
        assert_eq!(effective("active", Some("2026-11-10"), "2026-11-10"), "active", "valid through the day it names");
        assert_eq!(effective("active", None, "2026-11-10"), "active");
        assert_eq!(effective("revoked", Some("2020-01-01"), "2026-11-10"), "revoked");
        assert_eq!(effective("false_positive", None, "2026-11-10"), "false_positive");
        assert_eq!([0, 1, 29, 30, 69, 70, 100].map(confidence_label), ["none", "low", "low", "medium", "medium", "high", "high"]);
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            let id = save(c, "ip", "198.51.100.7");
            let s = update(c, id, &Changes { valid_until: Some("2020-01-31".into()), note: Some("Scanner seen in October".into()), ..Default::default() })?;
            assert_eq!(s.effective, "expired");
            assert_eq!(sighting_detail(&s), "Scanner seen in October · expired 2020-01-31: no longer current");
            let s = update(c, id, &Changes { valid_until: Some(String::new()), source: Some("Honeypot".into()), reliability: Some("C".into()), confidence: Some(40), ..Default::default() })?;
            assert_eq!((s.effective, sighting_detail(&s).as_str()), ("active", "Scanner seen in October · source Honeypot (C) · confidence 40 (medium)"));
            Ok(())
        })
        .unwrap();
    }
}
