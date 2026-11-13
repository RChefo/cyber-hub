// SPDX-License-Identifier: Apache-2.0
//! Confidence assessment. Confidence is qualitative and traceable: it is derived only from the
//! evidence attached to an element and from analyst decisions, and every result carries the
//! reason that produced it.
//!
//! Rules (relationships and entities alike):
//! * analyst decisions win: verified → high, disputed / rejected → low;
//! * several observations from the **same** source count once (they are not independent);
//! * high: at least one source states the fact directly, or two independent sources report it;
//! * medium: one source reports it (corroborating strength);
//! * low: only weak, heuristic signals (shared IP, same provider, similar names), or no evidence.

use std::collections::BTreeMap;

use super::model::{Confidence, Strength, Verification};

pub fn assess(verification: Verification, evidence: &[(String, Strength)]) -> (Confidence, String) {
    // best strength per independent source
    let mut by_source: BTreeMap<&str, (Strength, usize)> = BTreeMap::new();
    for (src, st) in evidence {
        let e = by_source.entry(src.as_str()).or_insert((*st, 0));
        e.1 += 1;
        if rank(*st) > rank(e.0) {
            e.0 = *st;
        }
    }
    let observations = evidence.len();
    let list = |want: Strength| by_source.iter().filter(|(_, (s, _))| *s == want).map(|(n, _)| *n).collect::<Vec<_>>();
    let (direct, corr, weak) = (list(Strength::Direct), list(Strength::Corroborating), list(Strength::Weak));
    let obs_note = if observations > by_source.len() { format!(" ({observations} observations from {} independent source{})", by_source.len(), plural(by_source.len())) } else { String::new() };
    let evidence_text = if !direct.is_empty() {
        format!("directly observed by {}{obs_note}", direct.join(", "))
    } else if !corr.is_empty() {
        format!("reported by {}{obs_note}", corr.join(", "))
    } else if !weak.is_empty() {
        format!("only weak signals from {}{obs_note}", weak.join(", "))
    } else {
        "no supporting evidence recorded".to_string()
    };

    match verification {
        Verification::Verified => (Confidence::High, format!("Verified by the analyst; {evidence_text}.")),
        Verification::Disputed => (Confidence::Low, format!("Disputed by the analyst; {evidence_text}.")),
        Verification::Rejected => (Confidence::Low, format!("Rejected by the analyst; {evidence_text}.")),
        Verification::Observed | Verification::Inferred => {
            let c = if !direct.is_empty() || corr.len() >= 2 {
                Confidence::High
            } else if corr.len() == 1 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let mut reason = capitalize(&evidence_text);
            if corr.len() >= 2 && direct.is_empty() {
                reason.push_str(&format!(" — {} independent sources agree", corr.len()));
            }
            if verification == Verification::Inferred {
                reason.push_str("; inferred, not confirmed: needs analyst review");
            }
            reason.push('.');
            (c, reason)
        }
    }
}

fn rank(s: Strength) -> u8 {
    match s {
        Strength::Weak => 0,
        Strength::Corroborating => 1,
        Strength::Direct => 2,
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use Strength::*;

    fn ev(v: &[(&str, Strength)]) -> Vec<(String, Strength)> {
        v.iter().map(|(s, st)| (s.to_string(), *st)).collect()
    }

    #[test]
    fn direct_evidence_is_high_and_repeats_from_one_source_do_not_add_up() {
        assert_eq!(assess(Verification::Observed, &ev(&[("dns", Direct)])).0, Confidence::High);
        let (c, why) = assess(Verification::Observed, &ev(&[("otx", Corroborating), ("otx", Corroborating), ("otx", Corroborating)]));
        assert_eq!(c, Confidence::Medium, "three reports from one provider are one source");
        assert!(why.contains("3 observations from 1 independent source"), "{why}");
        let (c, why) = assess(Verification::Observed, &ev(&[("otx", Corroborating), ("shodan", Corroborating)]));
        assert_eq!(c, Confidence::High);
        assert!(why.contains("2 independent sources agree"), "{why}");
    }

    #[test]
    fn weak_signals_stay_low_and_analyst_decisions_win() {
        let (c, why) = assess(Verification::Inferred, &ev(&[("correlation", Weak), ("correlation", Weak)]));
        assert_eq!(c, Confidence::Low);
        assert!(why.contains("needs analyst review"));
        assert_eq!(assess(Verification::Verified, &ev(&[("correlation", Weak)])).0, Confidence::High);
        assert_eq!(assess(Verification::Rejected, &ev(&[("dns", Direct)])).0, Confidence::Low);
        assert_eq!(assess(Verification::Disputed, &[]).0, Confidence::Low);
        assert_eq!(assess(Verification::Observed, &[]).1, "No supporting evidence recorded.");
    }
}
