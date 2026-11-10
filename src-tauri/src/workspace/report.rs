//! HTML assessment report built from the project's data and the options chosen in the report
//! builder. Everything is escaped; the document carries its own Content-Security-Policy (no
//! scripts, no remote content), so a saved report is inert in any browser. It prints to PDF from
//! the system web view's print dialog.

use rusqlite::{params, Connection};
use serde::Deserialize;

use crate::commands::projects::{findings_of, project_load, Finding};
use crate::error::AppResult;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReportOptions {
    pub title: String,
    pub author: String,
    /// e.g. "Confidential"; shown on every page header
    pub classification: String,
    /// executive summary written by the analyst
    pub summary: String,
    pub include_scope: bool,
    pub include_findings: bool,
    /// lowest severity included: critical, high, medium, low, info
    pub min_severity: String,
    /// also resolved, accepted and false-positive findings
    pub include_closed: bool,
    pub include_vulnerabilities: bool,
    pub include_assets: bool,
    pub include_evidence: bool,
    pub include_timeline: bool,
    /// risk acceptances and exceptions (Mission 6)
    pub include_risks: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            title: String::new(),
            author: String::new(),
            classification: "Confidential".into(),
            summary: String::new(),
            include_scope: true,
            include_findings: true,
            min_severity: "info".into(),
            include_closed: false,
            include_vulnerabilities: true,
            include_assets: true,
            include_evidence: true,
            include_timeline: false,
            include_risks: true,
        }
    }
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => o.push(c),
        }
    }
    o
}

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
const CLOSED: &[&str] = &["resolved", "accepted_risk", "false_positive"];

fn label(s: &str) -> String {
    let t = s.replace('_', " ");
    let mut c = t.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

const STYLE: &str = r#"
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.5 "Segoe UI", "Helvetica Neue", Arial, sans-serif; color: #1c2430; margin: 0; background: #fff; }
main { max-width: 860px; margin: 0 auto; padding: 32px 28px; }
.class { text-transform: uppercase; letter-spacing: .08em; font-size: 8.5pt; color: #8a5a00; font-weight: 600; }
h1 { font-size: 24pt; line-height: 1.15; margin: 8px 0 4px; }
h2 { font-size: 15pt; margin: 32px 0 10px; padding-bottom: 4px; border-bottom: 2px solid #1c2430; break-after: avoid; }
h3 { font-size: 12pt; margin: 22px 0 6px; break-after: avoid; }
.meta { color: #4a5568; margin: 0 0 4px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 14px; font-size: 9.5pt; }
th, td { text-align: left; padding: 5px 8px; vertical-align: top; border-bottom: 1px solid #e2e6ec; }
th { background: #f3f5f8; font-weight: 600; }
tr { break-inside: avoid; }
.sev { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 8.5pt; font-weight: 600; color: #fff; }
.sev-critical { background: #8e1b1b; } .sev-high { background: #c2410c; } .sev-medium { background: #b7791f; }
.sev-low { background: #2b6cb0; } .sev-info { background: #64748b; }
.finding { break-inside: avoid-page; margin-bottom: 18px; }
.kv { color: #4a5568; font-size: 9.5pt; margin: 2px 0 8px; }
.text { white-space: pre-wrap; margin: 4px 0 8px; }
.label { font-weight: 600; margin-top: 8px; }
.mono { font-family: Consolas, "SFMono-Regular", Menlo, monospace; font-size: 9pt; word-break: break-all; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 10px 0; }
.card { background: #f3f5f8; border-radius: 6px; padding: 10px 12px; }
.card b { display: block; font-size: 17pt; }
.muted { color: #64748b; }
footer { margin-top: 36px; color: #64748b; font-size: 8.5pt; }
@media print { main { padding: 0; } h2 { break-before: auto; } }
"#;

/// A table cell: text (always escaped) or a severity badge (from the fixed severity list).
enum Cell {
    Text(String),
    Badge(String),
}

struct W(String);

impl W {
    fn raw(&mut self, s: &str) {
        self.0.push_str(s);
    }
    fn el(&mut self, tag: &str, class: &str, text: &str) {
        if class.is_empty() {
            self.0.push_str(&format!("<{tag}>{}</{tag}>", esc(text)));
        } else {
            self.0.push_str(&format!("<{tag} class=\"{class}\">{}</{tag}>", esc(text)));
        }
    }
    fn table(&mut self, head: &[&str], rows: Vec<Vec<String>>) {
        self.cells(head, rows.into_iter().map(|r| r.into_iter().map(Cell::Text).collect()).collect());
    }
    fn cells(&mut self, head: &[&str], rows: Vec<Vec<Cell>>) {
        self.raw("<table><thead><tr>");
        for h in head {
            self.el("th", "", h);
        }
        self.raw("</tr></thead><tbody>");
        for r in rows {
            self.raw("<tr>");
            for cell in r {
                match cell {
                    Cell::Text(t) => self.el("td", "", &t),
                    Cell::Badge(sev) => self.raw(&format!("<td>{}</td>", sev_badge(&sev))),
                }
            }
            self.raw("</tr>");
        }
        self.raw("</tbody></table>");
    }
}

fn sev_badge(s: &str) -> String {
    let s = if SEVERITIES.contains(&s) { s } else { "info" };
    format!("<span class=\"sev sev-{s}\">{}</span>", label(s))
}

fn included(f: &Finding, o: &ReportOptions) -> bool {
    let min = SEVERITIES.iter().position(|s| *s == o.min_severity).unwrap_or(SEVERITIES.len() - 1);
    let rank = SEVERITIES.iter().position(|s| *s == f.severity).unwrap_or(SEVERITIES.len() - 1);
    rank <= min && (o.include_closed || !CLOSED.contains(&f.status.as_str()))
}

/// The closed and the below-minimum findings a report leaves out, in words ("" when none).
fn left_out(d: &Data) -> Vec<String> {
    let mut out = Vec::new();
    if d.closed > 0 {
        out.push(format!(
            "{} closed finding{} (resolved, accepted risk or false positive) {} not listed.",
            d.closed,
            if d.closed == 1 { "" } else { "s" },
            if d.closed == 1 { "is" } else { "are" }
        ));
    }
    if d.below > 0 {
        out.push(format!(
            "{} finding{} below the report's minimum severity ({}) {} not listed.",
            d.below,
            if d.below == 1 { "" } else { "s" },
            label(&d.o.min_severity),
            if d.below == 1 { "is" } else { "are" }
        ));
    }
    out
}

/// Everything a report shows, read once. The HTML and the Markdown report render the same data with
/// the same sections, order and terms. The project's internal notes and contacts are never part of
/// it.
struct Data {
    title: String,
    o: ReportOptions,
    today: String,
    p: crate::commands::projects::Project,
    /// the analyst's executive summary, or the project description
    summary: String,
    findings: Vec<Finding>,
    /// closed findings left out (resolved, accepted risk, false positive)
    closed: usize,
    /// findings below the minimum severity left out
    below: usize,
    open_vulns: i64,
    assets: i64,
    coverage: crate::methodology::Coverage,
    /// per finding: evidence records linked to it (title, kind, SHA-256)
    linked: std::collections::HashMap<i64, Vec<(String, String, String)>>,
    vulnerabilities: Vec<Vec<String>>,
    asset_rows: Vec<Vec<String>>,
    evidence: Vec<Vec<String>>,
    timeline: Vec<Vec<String>>,
    timeline_cut: bool,
    /// risk acceptances and exceptions that are not revoked (Mission 6), and how many were revoked
    risks: Vec<Vec<String>>,
    risks_revoked: usize,
    /// findings marked accepted risk without a covering acceptance: (id, title)
    risks_undocumented: Vec<(i64, String)>,
    /// failed WSTG tests under an exception
    wstg_excepted: usize,
}

fn severity_ok(f: &Finding, o: &ReportOptions) -> bool {
    let min = SEVERITIES.iter().position(|s| *s == o.min_severity).unwrap_or(SEVERITIES.len() - 1);
    SEVERITIES.iter().position(|s| *s == f.severity).unwrap_or(SEVERITIES.len() - 1) <= min
}

fn collect(c: &Connection, project_id: i64, o: &ReportOptions, today: &str) -> AppResult<Data> {
    let p = project_load(c, project_id)?;
    let title = if !o.title.trim().is_empty() {
        o.title.trim().to_string()
    } else if p.name.to_ascii_lowercase().contains("assessment") {
        format!("{} report", p.name)
    } else {
        format!("{} assessment report", p.name)
    };
    let all: Vec<Finding> = if o.include_findings { findings_of(c, project_id)? } else { vec![] };
    let closed = if o.include_closed { 0 } else { all.iter().filter(|f| CLOSED.contains(&f.status.as_str()) && severity_ok(f, o)).count() };
    let below = all.iter().filter(|f| !severity_ok(f, o) && (o.include_closed || !CLOSED.contains(&f.status.as_str()))).count();
    let findings: Vec<Finding> = all.into_iter().filter(|f| included(f, o)).collect();
    let open_vulns: i64 = c.query_row("SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?1 AND status IN ('open','triaged','in_remediation')", params![project_id], |r| r.get(0))?;
    let assets: i64 = c.query_row("SELECT COUNT(*) FROM assets WHERE project_id = ?1 AND status <> 'retired'", params![project_id], |r| r.get(0))?;
    let mut linked = std::collections::HashMap::new();
    if o.include_evidence {
        let mut st = c.prepare("SELECT e.title, e.kind, COALESCE(e.sha256, '') FROM finding_links l JOIN evidence e ON e.id = l.ref_id WHERE l.finding_id = ?1 AND l.kind = 'evidence' ORDER BY e.id")?;
        for f in &findings {
            let rows: Vec<(String, String, String)> = st.query_map(params![f.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
            linked.insert(f.id, rows);
        }
    }
    let vulnerabilities = if o.include_vulnerabilities {
        let mut st = c.prepare(
            "SELECT v.priority, v.cve_id, COALESCE(a.value, ''), v.cvss_score, v.status, COALESCE(v.remediation_due, ''), v.title FROM vulnerabilities v
             LEFT JOIN assets a ON a.id = v.asset_id WHERE v.project_id = ?1 ORDER BY v.priority, v.priority_score DESC",
        )?;
        let rows = st
            .query_map(params![project_id], |r| {
                Ok(vec![
                    r.get::<_, String>(0)?.to_uppercase(),
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<f64>>(3)?.map(|x| format!("{x:.1}")).unwrap_or_else(|| "–".into()),
                    label(&r.get::<_, String>(4)?),
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ])
            })?
            .collect::<Result<_, _>>()?;
        rows
    } else {
        vec![]
    };
    let asset_rows = if o.include_assets {
        let mut st = c.prepare("SELECT type, value, status, last_seen, data FROM assets WHERE project_id = ?1 AND status <> 'retired' ORDER BY type, value LIMIT 1000")?;
        let rows = st
            .query_map(params![project_id], |r| {
                let (kind, value): (String, String) = (r.get(0)?, r.get(1)?);
                // a cloud resource's identifier rarely says where it is: its provider, account and region do
                let shown = if kind == "cloud_resource" { cloud_place(&value, &r.get::<_, String>(4)?) } else { value };
                Ok(vec![label(&kind), shown, label(&r.get::<_, String>(2)?), r.get::<_, String>(3)?.chars().take(10).collect()])
            })?
            .collect::<Result<_, _>>()?;
        rows
    } else {
        vec![]
    };
    let evidence = if o.include_evidence {
        crate::workspace::evidence::list(c, project_id)?
            .into_iter()
            .map(|e| {
                // where the record came from: module, tool and version, when the source collected it
                let source = [
                    (!e.source_module.is_empty()).then(|| e.source_module.replace('_', " ")),
                    (!e.tool.is_empty()).then(|| if e.tool_version.is_empty() { e.tool.clone() } else { format!("{} {}", e.tool, e.tool_version) }),
                    e.collected_at.as_ref().map(|t| format!("collected {}", t.chars().take(10).collect::<String>())),
                    e.derived_from.map(|d| format!("derived from #{d}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
                vec![e.id.to_string(), e.title, e.kind, e.sha256.unwrap_or_default(), source, e.created_at.chars().take(10).collect()]
            })
            .collect()
    } else {
        vec![]
    };
    let (timeline, timeline_cut) = if o.include_timeline {
        let events = crate::workspace::timeline::project_timeline(c, project_id, &[], None, 201)?;
        let cut = events.len() > 200;
        (events.into_iter().take(200).map(|e| vec![e.at.replace('T', " ").chars().take(16).collect(), e.kind, e.title]).collect(), cut)
    } else {
        (vec![], false)
    };
    let summary = if !o.summary.trim().is_empty() { o.summary.trim().to_string() } else { p.description.trim().to_string() };
    let acceptances = crate::workspace::risk::list(c, project_id)?;
    let risks_revoked = acceptances.iter().filter(|a| a.standing == "revoked").count();
    let standing = acceptances.iter().filter(|a| a.standing != "revoked");
    let wstg_excepted = standing.clone().flat_map(|a| a.items.iter()).filter(|i| i.kind == "wstg" && i.removed_at.is_none()).count();
    let risks: Vec<Vec<String>> = if !o.include_risks {
        vec![]
    } else {
        standing
            .filter_map(|a| {
                let covers: Vec<String> = a
                    .items
                    .iter()
                    .filter(|i| i.removed_at.is_none())
                    .map(|i| match i.kind.as_str() {
                        // a section left out of the report is not brought back through this one
                        "finding" if o.include_findings => format!("Finding #{} {} (accepted risk)", i.ref_id, i.label),
                        "finding" => format!("Finding #{} (accepted risk)", i.ref_id),
                        "vulnerability" if o.include_vulnerabilities => format!("Vulnerability {} (accepted risk)", i.label),
                        "vulnerability" => format!("Vulnerability #{} (accepted risk)", i.ref_id),
                        "asvs" => format!("{} (non-compliant, exception)", i.label),
                        "wstg" => format!("{} (test failed, exception)", i.label),
                        _ => i.label.clone(),
                    })
                    .collect();
                // an acceptance whose items were all released covers nothing any more
                if covers.is_empty() {
                    return None;
                }
                let why: String = a.justification.chars().take(300).collect();
                Some(vec![format!("#{} {}", a.id, a.title), label(&a.standing), a.owner.clone(), format!("{}, {}", a.approver, a.approved_at), a.expires_at.clone(), why, covers.join("; ")])
            })
            .collect()
    };
    let risks_undocumented = if o.include_risks { crate::workspace::risk::uncovered_findings(c, project_id)? } else { vec![] };
    Ok(Data {
        title,
        o: o.clone(),
        today: today.to_string(),
        summary,
        findings,
        closed,
        below,
        open_vulns,
        assets,
        coverage: crate::methodology::coverage(c, project_id)?,
        linked,
        vulnerabilities,
        asset_rows,
        evidence,
        timeline,
        timeline_cut,
        risks,
        risks_revoked,
        risks_undocumented,
        wstg_excepted,
        p,
    })
}

/// The engagement details shown under the title (label, value).
fn engagement(d: &Data) -> Vec<(&'static str, String)> {
    let p = &d.p;
    let mut out = vec![("Project", p.name.clone())];
    if !p.client.trim().is_empty() {
        out.push(("Client", p.client.trim().to_string()));
    }
    if !p.engagement_type.is_empty() {
        out.push(("Engagement", label(&p.engagement_type)));
    }
    out.push(("Period", format!("{} – {}", p.start_date.as_deref().unwrap_or("not set"), p.end_date.as_deref().unwrap_or("not set"))));
    out.push(("Report date", d.today.clone()));
    if !d.o.author.trim().is_empty() {
        out.push(("Author", d.o.author.trim().to_string()));
    }
    if !p.authorization_ref.trim().is_empty() {
        out.push(("Authorization", p.authorization_ref.trim().to_string()));
    }
    out
}

/// The key figures of the executive summary (value, label).
fn figures(d: &Data) -> Vec<(i64, &'static str)> {
    let high = d.findings.iter().filter(|f| f.severity == "critical" || f.severity == "high").count() as i64;
    vec![(d.findings.len() as i64, "findings in this report"), (high, "critical and high"), (d.open_vulns, "open vulnerabilities"), (d.assets, "assets")]
}

fn checklist_line(d: &Data) -> Option<String> {
    let cov = &d.coverage;
    (cov.done() + cov.in_progress > 0).then(|| {
        // the section is referred to only when the report includes it
        let see = if d.o.include_risks { " (see Risk acceptances and exceptions)" } else { "" };
        let excepted = match d.wstg_excepted {
            0 => String::new(),
            1 => format!(" One failed test has a documented exception and stays failed{see}."),
            n => format!(" {n} failed tests have a documented exception and stay failed{see}."),
        };
        format!(
            "OWASP Web Security Testing Guide: {} of {} tests have a result ({} passed, {} failed, {} not applicable); {} in progress.{excepted}",
            cov.done(),
            cov.total,
            cov.passed,
            cov.failed,
            cov.not_applicable,
            cov.in_progress
        )
    })
}

/// A cloud resource as the report shows it: its identifier, then its provider, account and region
/// (or namespace), as the configuration audit recorded them.
fn cloud_place(value: &str, data: &str) -> String {
    let d: serde_json::Value = serde_json::from_str(data).unwrap_or(serde_json::Value::Null);
    let s = |k: &str| d.get(k).and_then(serde_json::Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
    let provider = s("provider").map(|p| match p.as_str() {
        "aws" => "AWS".to_string(),
        "azure" => "Azure".into(),
        "gcp" => "Google Cloud".into(),
        "kubernetes" => "Kubernetes".into(),
        _ => p,
    });
    let account = s("account").map(|a| match s("accountName") {
        Some(n) => format!("account {a} ({n})"),
        None => format!("account {a}"),
    });
    let place: Vec<String> = [provider, account, s("region").or_else(|| s("namespace"))].into_iter().flatten().collect();
    if place.is_empty() {
        value.to_string()
    } else {
        format!("{value} ({})", place.join(" · "))
    }
}

const RISKS_HEAD: &[&str] = &["Acceptance", "Standing", "Owner", "Approved", "Until", "Justification", "Covers"];
const RISKS_NOTE: &str = "Accepting a risk is not fixing it: covered findings and vulnerabilities stay accepted risks, excepted ASVS requirements stay non-compliant and excepted WSTG tests stay failed. An expired acceptance changes nothing by itself and is listed as expired until it is renewed or revoked.";

/// The register's closing lines: revoked acceptances and findings accepted without a record.
fn risk_notes(d: &Data) -> Vec<String> {
    let mut out = Vec::new();
    if d.risks_revoked > 0 {
        out.push(format!("{} revoked acceptance{} not listed.", d.risks_revoked, if d.risks_revoked == 1 { " is" } else { "s are" }));
    }
    if !d.risks_undocumented.is_empty() {
        let ids: Vec<String> = d.risks_undocumented.iter().map(|(id, _)| format!("#{id}")).collect();
        out.push(format!("Marked accepted risk without a risk acceptance: finding{} {}.", if ids.len() == 1 { "" } else { "s" }, ids.join(", ")));
    }
    out
}

/// A finding's facts in report order (label, value); the severity comes first.
fn finding_facts(f: &Finding) -> Vec<(&'static str, String)> {
    let mut out = vec![("Severity", label(&f.severity)), ("Status", label(&f.status)), ("Confidence", f.confidence.clone())];
    if !f.category.is_empty() {
        out.push(("Category", f.category.clone()));
    }
    if !f.cve.is_empty() {
        out.push(("CVE", f.cve.clone()));
    }
    // FIRST: a CVSS score is always published together with its vector
    if let (Some(score), false) = (f.cvss_score, f.cvss_vector.is_empty()) {
        out.push(("CVSS", format!("{score:.1} ({})", f.cvss_vector)));
    }
    if !f.affected_target.is_empty() {
        out.push(("Affected", f.affected_target.clone()));
    }
    out
}

const FINDING_TEXTS: &[&str] = &["Description", "Reproduction", "Technical details", "Remediation"];

fn finding_text<'a>(f: &'a Finding, head: &str) -> &'a str {
    match head {
        "Description" => &f.description,
        "Reproduction" => &f.reproduction,
        "Technical details" => &f.technical_details,
        _ => &f.remediation,
    }
}

const SCOPE_HEAD: &[&str] = &["Target", "Type", "Scope", "Note"];
const FINDINGS_HEAD: &[&str] = &["#", "Title", "Severity", "Status", "Affected"];
const VULNS_HEAD: &[&str] = &["Priority", "CVE", "Asset", "CVSS", "Status", "Due", "Description"];
const ASSETS_HEAD: &[&str] = &["Type", "Asset", "Status", "Last seen"];
const EVIDENCE_HEAD: &[&str] = &["#", "Title", "Kind", "SHA-256", "Source", "Added"];
const TIMELINE_HEAD: &[&str] = &["When", "Type", "Event"];

fn scope_rows(d: &Data) -> Vec<Vec<String>> {
    d.p.targets.iter().map(|t| vec![t.value.clone(), t.kind.clone(), if t.in_scope { "In scope".into() } else { "Excluded".into() }, t.note.clone()]).collect()
}

/// The HTML report (inert: escaped, with its own Content-Security-Policy).
pub fn render(c: &Connection, project_id: i64, o: &ReportOptions, today: &str) -> AppResult<String> {
    let d = collect(c, project_id, o, today)?;
    let mut w = W(String::new());
    w.raw("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    w.raw("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'\">");
    w.raw("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>");
    w.raw(&esc(&d.title));
    w.raw("</title><style>");
    w.raw(STYLE);
    w.raw("</style></head><body><main>");

    // cover: classification, title, engagement details
    if !d.o.classification.trim().is_empty() {
        w.el("div", "class", d.o.classification.trim());
    }
    w.el("h1", "", &d.title);
    let details = engagement(&d);
    w.el("p", "meta", &details.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(" · "));

    // executive summary
    w.el("h2", "", "Executive summary");
    if !d.summary.is_empty() {
        w.el("div", "text", &d.summary);
    }
    w.raw("<div class=\"cards\">");
    for (n, l) in figures(&d) {
        w.raw(&format!("<div class=\"card\"><b>{n}</b><span class=\"muted\">{}</span></div>", esc(l)));
    }
    w.raw("</div>");
    for note in left_out(&d) {
        w.el("p", "muted", &note);
    }
    for (head, text) in [("Objectives", &d.p.objectives), ("Methodology", &d.p.methodology)] {
        if !text.trim().is_empty() {
            w.el("div", "label", head);
            w.el("div", "text", text.trim());
        }
    }
    if let Some(line) = checklist_line(&d) {
        w.el("div", "label", "Testing checklist");
        w.el("div", "text", &line);
    }

    if d.o.include_scope {
        w.el("h2", "", "Scope");
        let rows = scope_rows(&d);
        if rows.is_empty() {
            w.el("p", "muted", "No scope entries recorded.");
        } else {
            w.table(SCOPE_HEAD, rows);
        }
        if !d.p.scope_notes.trim().is_empty() {
            w.el("div", "label", "Rules of engagement");
            w.el("div", "text", d.p.scope_notes.trim());
        }
    }

    if d.o.include_findings {
        w.el("h2", "", "Findings");
        if d.findings.is_empty() {
            w.el("p", "muted", "No findings match the report's criteria.");
        } else {
            w.cells(
                FINDINGS_HEAD,
                d.findings
                    .iter()
                    .enumerate()
                    .map(|(i, f)| vec![Cell::Text((i + 1).to_string()), Cell::Text(f.title.clone()), Cell::Badge(f.severity.clone()), Cell::Text(label(&f.status)), Cell::Text(f.affected_target.clone())])
                    .collect(),
            );
            for (i, f) in d.findings.iter().enumerate() {
                w.raw("<section class=\"finding\">");
                w.el("h3", "", &format!("{}. {}", i + 1, f.title));
                let facts: Vec<String> = finding_facts(f).into_iter().skip(1).map(|(k, v)| format!("{k}: {v}")).collect();
                w.raw(&format!("<div class=\"kv\">{} · {}</div>", sev_badge(&f.severity), esc(&facts.join(" · "))));
                for head in FINDING_TEXTS {
                    let text = finding_text(f, head);
                    if !text.trim().is_empty() {
                        w.el("div", "label", head);
                        w.el("div", "text", text.trim());
                    }
                }
                let linked = d.linked.get(&f.id).cloned().unwrap_or_default();
                if d.o.include_evidence && (!f.evidence.is_empty() || !linked.is_empty()) {
                    w.el("div", "label", "Evidence");
                    w.raw("<ul>");
                    for e in &f.evidence {
                        w.raw(&format!("<li>{}: <span class=\"mono\">{}</span></li>", esc(&e.label), esc(&e.reference)));
                    }
                    for (t, kind, sha) in &linked {
                        w.raw(&format!("<li>{} ({}){}</li>", esc(t), esc(kind), if sha.is_empty() { String::new() } else { format!(" <span class=\"mono\">SHA-256 {}</span>", esc(sha)) }));
                    }
                    w.raw("</ul>");
                }
                w.raw("</section>");
            }
        }
    }

    if d.o.include_vulnerabilities {
        w.el("h2", "", "Vulnerabilities");
        if d.vulnerabilities.is_empty() {
            w.el("p", "muted", "No vulnerabilities tracked.");
        } else {
            w.table(VULNS_HEAD, d.vulnerabilities.clone());
        }
    }
    if d.o.include_risks && (!d.risks.is_empty() || !d.risks_undocumented.is_empty()) {
        w.el("h2", "", "Risk acceptances and exceptions");
        w.el("p", "muted", RISKS_NOTE);
        if !d.risks.is_empty() {
            w.table(RISKS_HEAD, d.risks.clone());
        }
        for line in risk_notes(&d) {
            w.el("p", "muted", &line);
        }
    }
    if d.o.include_assets {
        w.el("h2", "", "Assets");
        if d.asset_rows.is_empty() {
            w.el("p", "muted", "No assets recorded.");
        } else {
            w.table(ASSETS_HEAD, d.asset_rows.clone());
        }
    }
    if d.o.include_evidence {
        w.el("h2", "", "Evidence register");
        if d.evidence.is_empty() {
            w.el("p", "muted", "No evidence registered.");
        } else {
            w.table(EVIDENCE_HEAD, d.evidence.clone());
        }
    }
    if d.o.include_timeline {
        w.el("h2", "", "Timeline");
        if d.timeline_cut {
            w.el("p", "muted", "The 200 most recent events. The project's Timeline tab has the complete history.");
        }
        w.table(TIMELINE_HEAD, d.timeline.clone());
    }

    w.raw(&format!("<footer>{} · generated by Cyber Hub on {}</footer>", esc(&d.title), esc(&d.today)));
    w.raw("</main></body></html>");
    Ok(w.0)
}

/* ───────────────────────── Markdown ───────────────────────── */

/// A table cell: one line, `|` and `\` escaped, and no character that could open HTML.
fn md_cell(v: &str) -> String {
    let t: String = v.chars().map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c }).filter(|c| !c.is_control()).collect();
    let t = t.replace('\\', "\\\\").replace('|', "\\|").replace('<', "&lt;").replace('[', "\\[");
    let t = t.trim();
    if t.is_empty() {
        "—".into()
    } else {
        t.to_string()
    }
}

/// A short value on one line (headings, list values): `<` cannot open HTML.
fn md_line(v: &str) -> String {
    v.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().replace('<', "&lt;").replace('[', "\\[").trim().to_string()
}

/// A value shown as code, on one line: backticks inside become `'` so the value cannot end the code
/// span (inside it, `<` is plain text).
fn md_code(v: &str) -> String {
    let t: String = v.chars().map(|c| if c.is_control() { ' ' } else if c == '`' { '\'' } else { c }).collect();
    format!("`{}`", t.trim())
}

/// A line that CommonMark could read as a code fence: its character (`` ` `` or `~`), the length
/// of its run, its indentation in spaces (at most 3) and what follows the run.
fn fence_line(line: &str) -> Option<(char, usize, usize, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let ch = rest.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = rest.chars().take_while(|c| *c == ch).count();
    (run >= 3).then(|| (ch, run, indent, &rest[run..]))
}

/// Free text as written (paragraphs, lists, emphasis, code blocks), except that it can never become
/// markup in a Markdown viewer (imported scanner output, for example). Mission 7, after a review
/// found ways through the earlier rules:
/// * a `<` that could open an HTML tag, comment or declaration is escaped everywhere outside a
///   code block, code spans included (CommonMark pairs backticks across lines, so a code span
///   cannot be trusted to contain it; inside a span the escape shows as `&lt;`);
/// * `![` is escaped, so an image never loads when the report is opened;
/// * the only code blocks are fences that start a line with no indentation, read exactly as
///   CommonMark reads them; any other line that a viewer could read as a fence (indented, or inside
///   a list item, whose end would close the fence early) is escaped so that it is not one, a fence
///   left open is closed at the end of the text, and a lone carriage return ends a line as it does
///   in CommonMark.
pub(crate) fn md_text(t: &str) -> String {
    let normalized = t.replace("\r\n", "\n").replace('\r', "\n");
    let mut out: Vec<String> = Vec::new();
    // the open fence: its character and the length of its run
    let mut fence: Option<(char, usize)> = None;
    for line in normalized.trim().split('\n') {
        if let Some((fch, frun)) = fence {
            // inside a fence: the line is code, until a closing fence (the same character, a run
            // at least as long, at most three spaces of indentation, nothing after it but blanks)
            if fence_line(line).is_some_and(|(ch, run, _, after)| ch == fch && run >= frun && after.chars().all(|c| c == ' ' || c == '\t')) {
                fence = None;
            }
            out.push(line.to_string());
            continue;
        }
        if let Some((ch, run, indent, info)) = fence_line(line) {
            if indent == 0 && (ch == '~' || !info.contains('`')) {
                fence = Some((ch, run));
                out.push(line.to_string());
            } else {
                // could be a fence for some reader: a backslash makes it plain text for every one
                out.push(format!("{}\\{}", &line[..indent], &line[indent..]));
            }
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let mut l = String::with_capacity(line.len());
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' && i + 1 < chars.len() {
                // a backslash escape: the next character is literal (a `<` after it shows as `<`;
                // inside a code span both are code)
                l.push(ch);
                l.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == '<' && chars.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '/' | '!' | '?')) {
                l.push_str("&lt;");
            } else if ch == '!' && chars.get(i + 1) == Some(&'[') {
                // an image would make the viewer request its URL when the report is opened; it
                // stays a link, which needs a click
                l.push_str("\\!");
            } else {
                l.push(ch);
            }
            i += 1;
        }
        out.push(l);
    }
    if let Some((ch, run)) = fence {
        out.push(ch.to_string().repeat(run));
    }
    out.join("\n")
}

fn md_table(l: &mut Vec<String>, head: &[&str], rows: &[Vec<String>]) {
    l.push(format!("| {} |", head.join(" | ")));
    l.push(format!("|{}", " --- |".repeat(head.len())));
    for r in rows {
        l.push(format!("| {} |", r.iter().map(|c| md_cell(c)).collect::<Vec<_>>().join(" | ")));
    }
}

/// The Markdown report: the same sections, order and terms as the HTML report.
pub fn markdown(c: &Connection, project_id: i64, o: &ReportOptions, today: &str) -> AppResult<String> {
    let d = collect(c, project_id, o, today)?;
    let mut l: Vec<String> = Vec::new();
    if !d.o.classification.trim().is_empty() {
        l.push(format!("**{}**", md_line(d.o.classification.trim())));
        l.push(String::new());
    }
    l.push(format!("# {}", md_line(&d.title)));
    l.push(String::new());
    for (k, v) in engagement(&d) {
        l.push(format!("- **{k}:** {}", md_line(&v)));
    }

    l.push(String::new());
    l.push("## Executive summary".into());
    if !d.summary.is_empty() {
        l.push(String::new());
        l.push(md_text(&d.summary));
    }
    l.push(String::new());
    for (n, label_) in figures(&d) {
        l.push(format!("- **{n}** {label_}"));
    }
    for note in left_out(&d) {
        l.push(String::new());
        l.push(format!("_{}_", md_line(&note)));
    }
    for (head, text) in [("Objectives", &d.p.objectives), ("Methodology", &d.p.methodology)] {
        if !text.trim().is_empty() {
            l.push(String::new());
            l.push(format!("**{head}**"));
            l.push(String::new());
            l.push(md_text(text));
        }
    }
    if let Some(line) = checklist_line(&d) {
        l.push(String::new());
        l.push("**Testing checklist**".into());
        l.push(String::new());
        l.push(line);
    }

    if d.o.include_scope {
        l.push(String::new());
        l.push("## Scope".into());
        l.push(String::new());
        let rows = scope_rows(&d);
        if rows.is_empty() {
            l.push("No scope entries recorded.".into());
        } else {
            md_table(&mut l, SCOPE_HEAD, &rows);
        }
        if !d.p.scope_notes.trim().is_empty() {
            l.push(String::new());
            l.push("**Rules of engagement**".into());
            l.push(String::new());
            l.push(md_text(&d.p.scope_notes));
        }
    }

    if d.o.include_findings {
        l.push(String::new());
        l.push("## Findings".into());
        l.push(String::new());
        if d.findings.is_empty() {
            l.push("No findings match the report's criteria.".into());
        } else {
            let rows: Vec<Vec<String>> = d.findings.iter().enumerate().map(|(i, f)| vec![(i + 1).to_string(), f.title.clone(), label(&f.severity), label(&f.status), f.affected_target.clone()]).collect();
            md_table(&mut l, FINDINGS_HEAD, &rows);
            for (i, f) in d.findings.iter().enumerate() {
                l.push(String::new());
                l.push(format!("### {}. {}", i + 1, md_line(&f.title)));
                l.push(String::new());
                for (k, v) in finding_facts(f) {
                    let shown = if matches!(k, "Affected" | "CVSS") { md_code(&v) } else { md_line(&v) };
                    l.push(format!("- **{k}:** {shown}"));
                }
                for head in FINDING_TEXTS {
                    let text = finding_text(f, head);
                    if !text.trim().is_empty() {
                        l.push(String::new());
                        l.push(format!("**{head}**"));
                        l.push(String::new());
                        l.push(md_text(text));
                    }
                }
                let linked = d.linked.get(&f.id).cloned().unwrap_or_default();
                if d.o.include_evidence && (!f.evidence.is_empty() || !linked.is_empty()) {
                    l.push(String::new());
                    l.push("**Evidence**".into());
                    l.push(String::new());
                    for e in &f.evidence {
                        l.push(format!("- {}: {}", md_line(&e.label), md_code(&e.reference)));
                    }
                    for (t, kind, sha) in &linked {
                        l.push(format!("- {} ({}){}", md_line(t), md_line(kind), if sha.is_empty() { String::new() } else { format!(" SHA-256 {}", md_code(sha)) }));
                    }
                }
            }
        }
    }

    for (on, head, cols, rows, empty) in [
        (d.o.include_vulnerabilities, "Vulnerabilities", VULNS_HEAD, &d.vulnerabilities, "No vulnerabilities tracked."),
        (d.o.include_risks, "Risk acceptances and exceptions", RISKS_HEAD, &d.risks, ""),
        (d.o.include_assets, "Assets", ASSETS_HEAD, &d.asset_rows, "No assets recorded."),
        (d.o.include_evidence, "Evidence register", EVIDENCE_HEAD, &d.evidence, "No evidence registered."),
    ] {
        if head == "Risk acceptances and exceptions" {
            if d.risks.is_empty() && d.risks_undocumented.is_empty() {
                continue;
            }
            l.push(String::new());
            l.push(format!("## {head}"));
            l.push(String::new());
            l.push(format!("_{RISKS_NOTE}_"));
            if !rows.is_empty() {
                l.push(String::new());
                md_table(&mut l, cols, rows);
            }
            for line in risk_notes(&d) {
                l.push(String::new());
                l.push(md_line(&line));
            }
            continue;
        }
        if on {
            l.push(String::new());
            l.push(format!("## {head}"));
            l.push(String::new());
            if rows.is_empty() {
                l.push(empty.into());
            } else {
                md_table(&mut l, cols, rows);
            }
        }
    }
    if d.o.include_timeline {
        l.push(String::new());
        l.push("## Timeline".into());
        l.push(String::new());
        if d.timeline_cut {
            l.push("_The 200 most recent events. The project's Timeline tab has the complete history._".into());
            l.push(String::new());
        }
        md_table(&mut l, TIMELINE_HEAD, &d.timeline);
    }
    l.push(String::new());
    l.push("---".into());
    l.push(String::new());
    l.push(format!("_{} · generated by Cyber Hub on {}_", md_line(&d.title), d.today));
    l.push(String::new());
    Ok(l.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn content_is_escaped_and_options_are_respected() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, client, created_at, updated_at) VALUES (1,'Acme <test>','active','Acme Corp','t','t')", [])?;
            c.execute(
                "INSERT INTO findings (project_id, title, severity, status, description, created_at, updated_at) VALUES (1,'XSS <script>alert(1)</script>','high','new','Payload: \"><img src=x onerror=alert(1)>','t','t')",
                [],
            )?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1,'Old banner','low','resolved','t','t')", [])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1,'Verbose header','info','new','t','t')", [])?;
            let html = render(c, 1, &ReportOptions::default(), "2026-11-05")?;
            assert!(!html.contains("<script>") && !html.contains("<img"), "no markup from data");
            assert!(html.contains("XSS &lt;script&gt;alert(1)&lt;/script&gt;"));
            assert!(html.contains("default-src 'none'") && html.contains("form-action 'none'"), "the document forbids scripts, remote content and forms");
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1,'<span class=\"sev x\"><form action=https://evil.example>','critical','new','t','t')", [])?;
            let forged = render(c, 1, &ReportOptions::default(), "2026-11-05")?;
            assert!(!forged.contains("<form") && forged.contains("&lt;span class=&quot;sev x&quot;&gt;"), "text that looks like markup is escaped everywhere");
            assert!(html.contains("Acme Corp") && html.contains("Acme &lt;test&gt; assessment report"));
            assert!(!html.contains("Old banner"), "closed findings are left out by default");
            assert!(html.contains("Verbose header"));
            let high_only = render(c, 1, &ReportOptions { min_severity: "high".into(), include_closed: true, include_assets: false, ..Default::default() }, "2026-11-05")?;
            assert!(!high_only.contains("Verbose header") && !high_only.contains("Old banner") && !high_only.contains("<h2>Assets</h2>"));
            let with_closed = render(c, 1, &ReportOptions { include_closed: true, ..Default::default() }, "2026-11-05")?;
            assert!(with_closed.contains("Old banner"));
            Ok(())
        })
        .unwrap();
        assert_eq!(esc("a&b<\"'>\u{0}"), "a&amp;b&lt;&quot;&#39;&gt;");
    }

    /// A project with everything a report shows, plus what it must never show: internal notes,
    /// contacts and closed findings.
    fn engagement_fixture(c: &Connection) -> AppResult<()> {
        c.execute(
            "INSERT INTO projects (id, name, status, client, engagement_type, authorization_ref, description, objectives, methodology, scope_notes, notes, contacts, start_date, end_date, created_at, updated_at)
             VALUES (1, 'Acme external', 'active', 'Acme Corp', 'external', 'SOW-2026-117', 'Quarterly external test.', 'Find exposed admin panels.', 'OWASP WSTG and manual testing.',
                     'Testing window 09:00-17:00 UTC.', 'INTERNAL: the client contact is difficult', 'Jane Roe +1 555 0100', '2026-11-01', '2026-11-15', 't', 't')",
            [],
        )?;
        c.execute("INSERT INTO project_targets (project_id, value, kind, in_scope, note, created_at) VALUES (1, '*.acme.test', 'wildcard', 1, '', 't'), (1, 'vpn.acme.test', 'domain', 0, 'Production VPN | do not touch', 't')", [])?;
        c.execute(
            "INSERT INTO findings (id, project_id, title, severity, status, description, remediation, affected_target, cve, cvss_vector, cvss_score, confidence, evidence, created_at, updated_at) VALUES
               (1, 1, 'Log4Shell in the login service', 'critical', 'confirmed', 'JNDI lookup in a header.', 'Upgrade log4j-core to 2.17.1.', 'https://app.acme.test/login', 'CVE-2021-44228',
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'high', '[{\"label\":\"Request\",\"reference\":\"evidence/req-1.txt\"}]', 't', '2026-11-03'),
               (2, 1, 'Verbose server banner', 'low', 'new', '', '', 'app.acme.test:443', '', '', NULL, 'medium', '[]', 't', '2026-11-02'),
               (3, 1, 'Old TLS configuration', 'medium', 'resolved', '', '', '', '', '', NULL, 'medium', '[]', 't', '2026-11-01'),
               (4, 1, 'Not a real issue', 'high', 'false_positive', '', '', '', '', '', NULL, 'medium', '[]', 't', '2026-11-01')",
            [],
        )?;
        c.execute("INSERT INTO evidence (id, project_id, kind, title, source, sha256, size, file_name, created_at, source_module, tool, tool_version) VALUES (7, 1, 'file', 'Login request', 'user', ?1, 10, 'req.txt', '2026-11-03', 'scan_import', 'Burp Suite', '2026.10')", params!["ab".repeat(32)])?;
        c.execute("INSERT INTO finding_links (finding_id, kind, ref_id, created_at) VALUES (1, 'evidence', 7, 't')", [])?;
        c.execute("INSERT INTO assets (id, project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (3, 1, 'subdomain', 'app.acme.test', 'app.acme.test', 'manual', 't', '2026-11-02', 't', 't')", [])?;
        c.execute(
            "INSERT INTO vulnerabilities (project_id, cve_id, asset_id, title, status, cvss_score, priority, priority_score, created_at, updated_at) VALUES (1, 'CVE-2021-44228', 3, 'Apache Log4j2 JNDI', 'open', 10.0, 'p1', 9.5, 't', 't')",
            [],
        )?;
        crate::methodology::set(c, 1, "WSTG-ATHZ-04", "failed", "", crate::methodology::Link::To(1), "user")?;
        Ok(())
    }

    /// The section headings of each format, in order.
    fn html_sections(html: &str) -> Vec<String> {
        html.split("<h2>").skip(1).map(|s| s.split("</h2>").next().unwrap_or("").to_string()).collect()
    }
    fn md_sections(md: &str) -> Vec<String> {
        md.lines().filter_map(|l| l.strip_prefix("## ")).map(str::to_string).collect()
    }

    #[test]
    fn both_formats_carry_the_same_report() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            engagement_fixture(c)?;
            for o in [ReportOptions::default(), ReportOptions { include_timeline: true, ..Default::default() }, ReportOptions { min_severity: "medium".into(), include_assets: false, ..Default::default() }] {
                let html = render(c, 1, &o, "2026-11-09")?;
                let md = markdown(c, 1, &o, "2026-11-09")?;
                // the same sections in the same order, with the same terms
                assert_eq!(html_sections(&html), md_sections(&md), "{o:?}");
                // the same findings in the same order
                let html_findings: Vec<String> = html.split("<h3>").skip(1).map(|s| s.split("</h3>").next().unwrap_or("").to_string()).collect();
                let md_findings: Vec<String> = md.lines().filter_map(|l| l.strip_prefix("### ")).map(str::to_string).collect();
                assert_eq!(html_findings, md_findings, "{o:?}");
            }
            let o = ReportOptions::default();
            let html = render(c, 1, &o, "2026-11-09")?;
            let md = markdown(c, 1, &o, "2026-11-09")?;
            assert_eq!(md_sections(&md), ["Executive summary", "Scope", "Findings", "Vulnerabilities", "Assets", "Evidence register"]);
            // what both state
            for fact in [
                "Confidential",
                "Acme external assessment report",
                "Acme Corp",
                "SOW-2026-117",
                "2026-11-01 – 2026-11-15",
                "Report date",
                "2026-11-09",
                "Quarterly external test.",
                "Find exposed admin panels.",
                "OWASP WSTG and manual testing.",
                "Testing window 09:00-17:00 UTC.",
                "Rules of engagement",
                "Excluded",
                "1. Log4Shell in the login service",
                "2. Verbose server banner",
                "Critical",
                "Confirmed",
                "CVE-2021-44228",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "Upgrade log4j-core to 2.17.1.",
                "evidence/req-1.txt",
                &"ab".repeat(32),
                "Login request",
                "scan import, Burp Suite 2026.10",
                "2 closed findings (resolved, accepted risk or false positive) are not listed.",
                "OWASP Web Security Testing Guide: 1 of",
                "P1",
                "app.acme.test",
            ] {
                let in_html = html.contains(fact) || html.contains(&esc(fact));
                assert!(in_html && md.contains(fact), "{fact}: html {in_html}, markdown {}", md.contains(fact));
            }
            // what neither may state: internal notes, contacts, closed findings
            for secret in ["INTERNAL: the client contact", "Jane Roe", "Old TLS configuration", "Not a real issue"] {
                assert!(!html.contains(secret) && !md.contains(secret), "{secret}");
            }
            // the severity filter is stated in both
            let medium = ReportOptions { min_severity: "medium".into(), ..Default::default() };
            let (h, m) = (render(c, 1, &medium, "2026-11-09")?, markdown(c, 1, &medium, "2026-11-09")?);
            let note = "1 finding below the report's minimum severity (Medium) is not listed.";
            assert!(h.contains(&esc(note)) && m.contains(note));
            assert!(!h.contains("Verbose server banner") && !m.contains("Verbose server banner"));
            Ok(())
        })
        .unwrap();
    }

    use crate::util::commonmark_markup as markup_in;

    /// Mission 7: free text never becomes markup in a Markdown viewer, whatever a CommonMark
    /// parser makes of its backticks and fences: code spans across lines, lines that look like
    /// fences but are not, fences that a list item's end or a lone carriage return closes, fences
    /// left open, and images.
    #[test]
    fn markdown_text_never_becomes_markup() {
        let img = "<img src=https://x.example/p.png>";
        let cases = [
            format!("`a\nb` {img} `c`"),
            format!("x\n    ```\n{img}"),
            format!("```a`\n{img}\n```"),
            format!("```\n```x\n```\n{img}"),
            format!("1. x\n   ```\n{img}\n   ```"),
            format!("- x\n\n  ```\n{img}\n  ```"),
            format!("> ```\n{img}"),
            format!("   ```\nx\n```\n{img}\n```"),
            format!("```\nx\r```\r{img}"),
            format!("~~~\nx\n~~~~\n{img}\n~~~"),
            format!("````\n```\n{img}"),
            "![x](https://x.example/i.png) and ![y][r]\n\n[r]: https://x.example/j.png".to_string(),
            format!("\\\\{img}"),
            "<!-- x --> <?php ?> <![CDATA[ x ]]> </p> <https://x.example/auto>".to_string(),
        ];
        for text in &cases {
            let md = md_text(text);
            assert_eq!(markup_in(&md), Vec::<String>::new(), "{text:?} -> {md:?}");
        }
        // a fence left open is closed at the end of the text, so what follows is not code
        assert_eq!(md_text("```\n<b>"), "```\n<b>\n```");
        assert_eq!(md_text("````\n```\n<b>"), "````\n```\n<b>\n````");
    }

    #[test]
    fn markdown_reports_are_inert_and_keep_their_formatting() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Acme | <b>', 'active', 't', 't')", [])?;
            c.execute(
                "INSERT INTO findings (project_id, title, severity, status, description, reproduction, affected_target, evidence, created_at, updated_at) VALUES
                 (1, 'XSS <script>alert(1)</script>', 'high', 'new', 'Scanner said: <img src=x onerror=alert(1)> and \\`<img src=y>\\`',
                  'Send:\n\n```\n<script>alert(1)</script>\n```\n\nThen `<b>` appears.', 'a|b', '[{\"label\":\"Payload\",\"reference\":\"x`<img src=z>\"}]', 't', 't')",
                [],
            )?;
            let md = markdown(c, 1, &ReportOptions::default(), "2026-11-09")?;
            // a CommonMark parser finds no raw HTML and no image anywhere in the report
            assert_eq!(markup_in(&md), Vec::<String>::new(), "{md}");
            assert!(md.contains("&lt;img src=x onerror=alert(1)>"), "{md}");
            assert!(md.contains("\\`&lt;img src=y>\\`"), "an escaped backtick opens no code span: {md}");
            // code stays code, and tables stay tables
            assert!(md.contains("```\n<script>alert(1)</script>\n```"), "{md}");
            assert!(md.contains("Then `&lt;b>` appears."), "a code span cannot be trusted to contain a tag (Mission 7): {md}");
            assert!(md.contains("| a\\|b |"), "{md}");
            assert!(md.contains("`x'<img src=z>`"), "a backtick cannot end the code span: {md}");
            assert!(md.contains("# Acme | &lt;b> assessment report"));
            Ok(())
        })
        .unwrap();
        assert_eq!(md_text("a <b>c</b> `<i>` \\<u> <3 x<y"), "a &lt;b>c&lt;/b> `&lt;i>` \\<u> <3 x&lt;y");
        assert_eq!(md_text("``a ` <b>`` <i>"), "``a ` &lt;b>`` &lt;i>");
        assert_eq!(md_text("` <b> unclosed"), "` &lt;b> unclosed");
    }

    #[test]
    fn empty_projects_do_not_fabricate_content() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'Empty', 'active', 't', 't')", [])?;
            c.execute("INSERT INTO findings (project_id, title, severity, status, created_at, updated_at) VALUES (1, 'Fixed', 'low', 'resolved', 't', 't')", [])?;
            let md = markdown(c, 1, &ReportOptions::default(), "2026-11-09")?;
            let html = render(c, 1, &ReportOptions::default(), "2026-11-09")?;
            for text in ["No scope entries recorded.", "No findings match the report's criteria.", "No vulnerabilities tracked.", "No assets recorded.", "No evidence registered.", "1 closed finding (resolved, accepted risk or false positive) is not listed."] {
                assert!(md.contains(text) && html.contains(&esc(text)), "{text}");
            }
            assert!(!md.contains("Fixed") && !html.contains("Fixed"));
            assert!(markdown(c, 9, &ReportOptions::default(), "2026-11-09").is_err(), "an unknown project");
            Ok(())
        })
        .unwrap();
    }
}
