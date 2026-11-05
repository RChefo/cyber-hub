//! DNS intelligence for a domain: the main records plus an assessment of e-mail authentication
//! (SPF, DMARC, common DKIM selectors), CAA and DNSSEC. Queries go to the system resolver only.

use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use serde::Serialize;

use super::tls::Issue;

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Spf {
    pub record: Option<String>,
    /// the qualifier of `all` (+, -, ~, ?) or None when missing
    pub all: Option<String>,
    /// mechanisms that cost a DNS lookup (include, a, mx, ptr, exists, redirect)
    pub lookups: usize,
    pub count: usize,
}

pub fn analyze_spf(txt: &[String]) -> Spf {
    let records: Vec<&String> = txt.iter().filter(|t| t.trim_matches('"').to_ascii_lowercase().starts_with("v=spf1")).collect();
    let Some(rec) = records.first() else { return Spf::default() };
    let rec = rec.trim_matches('"').to_string();
    let mut s = Spf { record: Some(rec.clone()), count: records.len(), ..Default::default() };
    for term in rec.split_whitespace().skip(1) {
        let t = term.to_ascii_lowercase();
        let (q, mech) = match t.chars().next() {
            Some(c @ ('+' | '-' | '~' | '?')) => (c.to_string(), &t[1..]),
            _ => ("+".to_string(), t.as_str()),
        };
        let name = mech.split([':', '/', '=']).next().unwrap_or("");
        if name == "all" {
            s.all = Some(q);
        }
        if matches!(name, "include" | "a" | "mx" | "ptr" | "exists" | "redirect") {
            s.lookups += 1;
        }
    }
    s
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Dmarc {
    pub record: Option<String>,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub pct: Option<u32>,
    pub reports: bool,
}

pub fn analyze_dmarc(txt: &[String]) -> Dmarc {
    let Some(rec) = txt.iter().map(|t| t.trim_matches('"').to_string()).find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1")) else { return Dmarc::default() };
    let mut d = Dmarc { record: Some(rec.clone()), ..Default::default() };
    for tag in rec.split(';') {
        let Some((k, v)) = tag.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "p" => d.policy = Some(v.to_ascii_lowercase()),
            "sp" => d.subdomain_policy = Some(v.to_ascii_lowercase()),
            "pct" => d.pct = v.parse().ok(),
            "rua" | "ruf" => d.reports = d.reports || !v.is_empty(),
            _ => {}
        }
    }
    d
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecordSet {
    #[serde(rename = "type")]
    pub kind: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsIntel {
    pub domain: String,
    pub records: Vec<DnsRecordSet>,
    pub spf: Spf,
    pub dmarc: Dmarc,
    pub dkim_selectors: Vec<String>,
    pub caa: Vec<String>,
    pub dnssec: bool,
    pub issues: Vec<Issue>,
    /// queries that failed (other than "no records")
    pub errors: Vec<String>,
}

pub fn assess(d: &DnsIntel) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut push = |level: &'static str, text: &str| out.push(Issue { level, text: text.to_string() });
    let mx = d.records.iter().any(|r| r.kind == "MX" && !r.values.is_empty());
    match (&d.spf.record, d.spf.all.as_deref()) {
        (None, _) if mx => push("warning", "No SPF record: anyone can send mail claiming to be this domain"),
        (None, _) => push("info", "No SPF record (the domain has no MX; publish \"v=spf1 -all\" if it sends no mail)"),
        (Some(_), Some("+")) => push("critical", "SPF ends with +all: every server is allowed to send mail for this domain"),
        (Some(_), Some("?")) | (Some(_), None) => push("warning", "SPF has no restrictive \"all\" (use -all or ~all)"),
        _ => {}
    }
    if d.spf.count > 1 {
        push("critical", "Several SPF records: receivers treat this as an error (permerror)");
    }
    if d.spf.lookups > 10 {
        push("warning", "SPF needs more than 10 DNS lookups, which receivers reject");
    }
    match d.dmarc.policy.as_deref() {
        None if d.dmarc.record.is_none() => push(if mx { "warning" } else { "info" }, "No DMARC record"),
        Some("none") => push("warning", "DMARC policy is none: spoofed mail is only monitored, not rejected"),
        Some("quarantine" | "reject") if d.dmarc.pct.is_some_and(|p| p < 100) => push("info", "DMARC applies to part of the mail only (pct below 100)"),
        _ => {}
    }
    if d.dmarc.record.is_some() && !d.dmarc.reports {
        push("info", "DMARC sends no aggregate reports (no rua address)");
    }
    if mx && d.dkim_selectors.is_empty() {
        push("info", "No DKIM key found under common selectors (the domain may use others)");
    }
    if d.caa.is_empty() {
        push("info", "No CAA record: any certificate authority may issue certificates for this domain");
    }
    if !d.dnssec {
        push("info", "DNSSEC is not enabled (no DNSKEY records)");
    }
    out
}

pub const DKIM_SELECTORS: &[&str] = &["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim", "smtp"];

async fn query(r: &hickory_resolver::TokioResolver, name: &str, t: RecordType, errors: &mut Vec<String>) -> Vec<String> {
    match tokio::time::timeout(Duration::from_secs(8), r.lookup(name, t)).await {
        Err(_) => {
            errors.push(format!("{t} {name}: timed out"));
            vec![]
        }
        Ok(Ok(l)) => l.answers().iter().filter(|a| a.record_type() == t).map(|a| a.data.to_string()).collect(),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => vec![],
        Ok(Err(e)) => {
            errors.push(format!("{t} {name}: {e}"));
            vec![]
        }
    }
}

/// Collects and assesses. The domain must already be validated (and checked by the passive gate).
pub async fn collect(domain: &str) -> Result<DnsIntel, String> {
    let r = hickory_resolver::Resolver::builder_tokio().map_err(|e| format!("Resolver configuration error: {e}"))?.build().map_err(|e| format!("Resolver configuration error: {e}"))?;
    let mut errors = Vec::new();
    let mut records = Vec::new();
    let mut txt = Vec::new();
    let mut caa = Vec::new();
    for t in [RecordType::A, RecordType::AAAA, RecordType::CNAME, RecordType::NS, RecordType::MX, RecordType::SOA, RecordType::TXT, RecordType::CAA] {
        let values = query(&r, domain, t, &mut errors).await;
        match t {
            RecordType::TXT => txt = values.clone(),
            RecordType::CAA => caa = values.clone(),
            _ => {}
        }
        records.push(DnsRecordSet { kind: t.to_string(), values });
    }
    let dmarc_txt = query(&r, &format!("_dmarc.{domain}"), RecordType::TXT, &mut errors).await;
    let mut dkim = Vec::new();
    for sel in DKIM_SELECTORS {
        let v = query(&r, &format!("{sel}._domainkey.{domain}"), RecordType::TXT, &mut errors).await;
        if v.iter().any(|t| t.to_ascii_lowercase().contains("p=")) {
            dkim.push(sel.to_string());
        }
    }
    let dnssec = !query(&r, domain, RecordType::DNSKEY, &mut errors).await.is_empty();
    let mut d = DnsIntel { domain: domain.to_string(), records, spf: analyze_spf(&txt), dmarc: analyze_dmarc(&dmarc_txt), dkim_selectors: dkim, caa, dnssec, issues: vec![], errors };
    d.issues = assess(&d);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn spf_and_dmarc_are_read() {
        let spf = analyze_spf(&s(&["\"google-site-verification=x\"", "\"v=spf1 include:_spf.google.com ip4:192.0.2.0/24 mx ~all\""]));
        assert_eq!((spf.all.as_deref(), spf.lookups, spf.count), (Some("~"), 2, 1));
        assert_eq!(analyze_spf(&s(&["v=spf1 +all"])).all.as_deref(), Some("+"));
        assert_eq!(analyze_spf(&s(&["v=spf1 a"])).all, None);
        assert_eq!(analyze_spf(&s(&["v=spf1 -all", "v=spf1 ~all"])).count, 2);
        let d = analyze_dmarc(&s(&["\"v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:d@example.com\""]));
        assert_eq!((d.policy.as_deref(), d.subdomain_policy.as_deref(), d.pct, d.reports), (Some("quarantine"), Some("reject"), Some(50), true));
        assert_eq!(analyze_dmarc(&s(&["v=spf1 -all"])), Dmarc::default());
    }

    fn intel(spf: &[&str], dmarc: &[&str], mx: bool) -> DnsIntel {
        DnsIntel {
            domain: "example.com".into(),
            records: vec![DnsRecordSet { kind: "MX".into(), values: if mx { s(&["10 mail.example.com."]) } else { vec![] } }],
            spf: analyze_spf(&s(spf)),
            dmarc: analyze_dmarc(&s(dmarc)),
            dkim_selectors: vec![],
            caa: vec![],
            dnssec: false,
            issues: vec![],
            errors: vec![],
        }
    }

    #[test]
    fn weak_mail_authentication_is_reported() {
        let issues = assess(&intel(&["v=spf1 +all"], &["v=DMARC1; p=none"], true));
        assert!(issues.iter().any(|i| i.level == "critical" && i.text.contains("+all")));
        assert!(issues.iter().any(|i| i.text.contains("policy is none")));
        let missing = assess(&intel(&[], &[], true));
        assert!(missing.iter().any(|i| i.level == "warning" && i.text.starts_with("No SPF")));
        assert!(missing.iter().any(|i| i.level == "warning" && i.text == "No DMARC record"));
        let no_mail = assess(&intel(&[], &[], false));
        assert!(no_mail.iter().all(|i| i.level == "info"), "domains without mail get advice, not warnings: {no_mail:?}");
        let strict = assess(&intel(&["v=spf1 -all"], &["v=DMARC1; p=reject; rua=mailto:a@example.com"], true));
        assert!(strict.iter().all(|i| i.level == "info"), "{strict:?}");
    }
}
