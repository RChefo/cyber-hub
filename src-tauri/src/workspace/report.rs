//! HTML assessment report built from the project's data and the options chosen in the report
//! builder. Everything is escaped; the document carries its own Content-Security-Policy (no
//! scripts, no remote content), so a saved report is inert in any browser. It prints to PDF from
//! the system web view's print dialog.

use std::collections::BTreeMap;

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

pub fn render(c: &Connection, project_id: i64, o: &ReportOptions, today: &str) -> AppResult<String> {
    let p = project_load(c, project_id)?;
    let title = if !o.title.trim().is_empty() {
        o.title.trim().to_string()
    } else if p.name.to_ascii_lowercase().contains("assessment") {
        format!("{} report", p.name)
    } else {
        format!("{} assessment report", p.name)
    };
    let findings: Vec<Finding> = if o.include_findings { findings_of(c, project_id)?.into_iter().filter(|f| included(f, o)).collect() } else { vec![] };
    let mut w = W(String::new());
    w.raw("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    w.raw("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'\">");
    w.raw("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>");
    w.raw(&esc(&title));
    w.raw("</title><style>");
    w.raw(STYLE);
    w.raw("</style></head><body><main>");

    // cover
    if !o.classification.trim().is_empty() {
        w.el("div", "class", o.classification.trim());
    }
    w.el("h1", "", &title);
    let mut meta = vec![format!("Project: {}", p.name)];
    if !p.client.trim().is_empty() {
        meta.push(format!("Client: {}", p.client.trim()));
    }
    if !p.engagement_type.is_empty() {
        meta.push(format!("Engagement: {}", label(&p.engagement_type)));
    }
    w.el("p", "meta", &meta.join(" · "));
    let mut meta2 = vec![format!("Period: {} – {}", p.start_date.as_deref().unwrap_or("not set"), p.end_date.as_deref().unwrap_or("not set")), format!("Report date: {today}")];
    if !o.author.trim().is_empty() {
        meta2.push(format!("Author: {}", o.author.trim()));
    }
    if !p.authorization_ref.trim().is_empty() {
        meta2.push(format!("Authorization: {}", p.authorization_ref.trim()));
    }
    w.el("p", "meta", &meta2.join(" · "));

    // summary
    w.el("h2", "", "Executive summary");
    if !o.summary.trim().is_empty() {
        w.el("div", "text", o.summary.trim());
    } else if !p.description.trim().is_empty() {
        w.el("div", "text", p.description.trim());
    }
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for f in &findings {
        *counts.entry(SEVERITIES.iter().position(|s| *s == f.severity).unwrap_or(4)).or_default() += 1;
    }
    let open_vulns: i64 = c.query_row("SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?1 AND status IN ('open','triaged','in_remediation')", params![project_id], |r| r.get(0))?;
    let assets: i64 = c.query_row("SELECT COUNT(*) FROM assets WHERE project_id = ?1 AND status <> 'retired'", params![project_id], |r| r.get(0))?;
    w.raw("<div class=\"cards\">");
    for (n, l) in [(findings.len() as i64, "findings in this report"), (*counts.get(&0).unwrap_or(&0) as i64 + *counts.get(&1).unwrap_or(&0) as i64, "critical and high"), (open_vulns, "open vulnerabilities"), (assets, "assets")] {
        w.raw(&format!("<div class=\"card\"><b>{n}</b><span class=\"muted\">{}</span></div>", esc(l)));
    }
    w.raw("</div>");
    if !p.objectives.trim().is_empty() {
        w.el("div", "label", "Objectives");
        w.el("div", "text", p.objectives.trim());
    }
    if !p.methodology.trim().is_empty() {
        w.el("div", "label", "Methodology");
        w.el("div", "text", p.methodology.trim());
    }
    let cov = crate::methodology::coverage(c, project_id)?;
    if cov.done() + cov.in_progress > 0 {
        w.el("div", "label", "Testing checklist");
        w.el(
            "div",
            "text",
            &format!(
                "OWASP Web Security Testing Guide: {} of {} tests have a result ({} passed, {} failed, {} not applicable); {} in progress.",
                cov.done(),
                cov.total,
                cov.passed,
                cov.failed,
                cov.not_applicable,
                cov.in_progress
            ),
        );
    }

    if o.include_scope {
        w.el("h2", "", "Scope");
        let rows = p.targets.iter().map(|t| vec![t.value.clone(), t.kind.clone(), if t.in_scope { "In scope".into() } else { "Excluded".into() }, t.note.clone()]).collect::<Vec<_>>();
        if rows.is_empty() {
            w.el("p", "muted", "No scope entries recorded.");
        } else {
            w.table(&["Target", "Type", "Scope", "Note"], rows);
        }
        if !p.scope_notes.trim().is_empty() {
            w.el("div", "label", "Rules of engagement");
            w.el("div", "text", p.scope_notes.trim());
        }
    }

    if o.include_findings {
        w.el("h2", "", "Findings");
        if findings.is_empty() {
            w.el("p", "muted", "No findings match the report's criteria.");
        } else {
            w.cells(
                &["#", "Title", "Severity", "Status", "Affected"],
                findings
                    .iter()
                    .enumerate()
                    .map(|(i, f)| vec![Cell::Text((i + 1).to_string()), Cell::Text(f.title.clone()), Cell::Badge(f.severity.clone()), Cell::Text(label(&f.status)), Cell::Text(f.affected_target.clone())])
                    .collect(),
            );
            let mut ev_st = c.prepare("SELECT e.title, e.kind, COALESCE(e.sha256, '') FROM finding_links l JOIN evidence e ON e.id = l.ref_id WHERE l.finding_id = ?1 AND l.kind = 'evidence'")?;
            for (i, f) in findings.iter().enumerate() {
                w.raw("<section class=\"finding\">");
                w.el("h3", "", &format!("{}. {}", i + 1, f.title));
                let mut kv = vec![format!("Status: {}", label(&f.status)), format!("Confidence: {}", f.confidence)];
                if !f.category.is_empty() {
                    kv.push(format!("Category: {}", f.category));
                }
                if !f.cve.is_empty() {
                    kv.push(format!("CVE: {}", f.cve));
                }
                // FIRST: a CVSS score is always published together with its vector
                if let (Some(score), false) = (f.cvss_score, f.cvss_vector.is_empty()) {
                    kv.push(format!("CVSS {score:.1} ({})", f.cvss_vector));
                }
                if !f.affected_target.is_empty() {
                    kv.push(format!("Affected: {}", f.affected_target));
                }
                w.raw(&format!("<div class=\"kv\">{} · {}</div>", sev_badge(&f.severity), esc(&kv.join(" · "))));
                for (head, text) in [("Description", &f.description), ("Reproduction", &f.reproduction), ("Technical details", &f.technical_details), ("Remediation", &f.remediation)] {
                    if !text.trim().is_empty() {
                        w.el("div", "label", head);
                        w.el("div", "text", text.trim());
                    }
                }
                let linked: Vec<(String, String, String)> = ev_st.query_map(params![f.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
                if o.include_evidence && (!f.evidence.is_empty() || !linked.is_empty()) {
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

    if o.include_vulnerabilities {
        w.el("h2", "", "Vulnerabilities");
        let mut st = c.prepare(
            "SELECT v.priority, v.cve_id, COALESCE(a.value, ''), v.cvss_score, v.status, COALESCE(v.remediation_due, ''), v.title FROM vulnerabilities v
             LEFT JOIN assets a ON a.id = v.asset_id WHERE v.project_id = ?1 ORDER BY v.priority, v.priority_score DESC",
        )?;
        let rows: Vec<Vec<String>> = st
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
        if rows.is_empty() {
            w.el("p", "muted", "No vulnerabilities tracked.");
        } else {
            w.table(&["Priority", "CVE", "Asset", "CVSS", "Status", "Due", "Description"], rows);
        }
    }

    if o.include_assets {
        w.el("h2", "", "Assets");
        let mut st = c.prepare("SELECT type, value, status, last_seen FROM assets WHERE project_id = ?1 AND status <> 'retired' ORDER BY type, value LIMIT 1000")?;
        let rows: Vec<Vec<String>> = st.query_map(params![project_id], |r| Ok(vec![label(&r.get::<_, String>(0)?), r.get(1)?, label(&r.get::<_, String>(2)?), r.get::<_, String>(3)?.chars().take(10).collect()]))?.collect::<Result<_, _>>()?;
        if rows.is_empty() {
            w.el("p", "muted", "No assets recorded.");
        } else {
            w.table(&["Type", "Asset", "Status", "Last seen"], rows);
        }
    }

    if o.include_evidence {
        w.el("h2", "", "Evidence register");
        let rows: Vec<Vec<String>> = crate::workspace::evidence::list(c, project_id)?
            .into_iter()
            .map(|e| vec![e.id.to_string(), e.title, e.kind, e.sha256.unwrap_or_default(), e.created_at.chars().take(10).collect()])
            .collect();
        if rows.is_empty() {
            w.el("p", "muted", "No evidence registered.");
        } else {
            w.table(&["#", "Title", "Kind", "SHA-256", "Added"], rows);
        }
    }

    if o.include_timeline {
        w.el("h2", "", "Timeline");
        let events = crate::workspace::timeline::project_timeline(c, project_id, &[], None, 200)?;
        w.table(&["When", "Type", "Event"], events.into_iter().map(|e| vec![e.at.replace('T', " ").chars().take(16).collect(), e.kind, e.title]).collect());
    }

    w.raw(&format!("<footer>{} · generated by Cyber Hub on {}</footer>", esc(&title), esc(today)));
    w.raw("</main></body></html>");
    Ok(w.0)
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
}
