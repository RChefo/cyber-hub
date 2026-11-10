//! Investigation layer commands (`workspace/relations.rs`, `workspace/correlate.rs`): correlation,
//! the review of its suggestions, links made by hand, related records, the investigation graph and
//! the filtered timeline. Nothing here contacts a network.

use rusqlite::{params, Connection};
use tauri::{AppHandle, Manager, State};

use crate::commands::workspace::main_window_dialog;
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::workspace::relations::{self, Ref};
use crate::workspace::{correlate, timeline};

/// Work over a whole project (correlation, the graph, search) runs on a blocking thread, so a
/// large project never holds up the async workers that other commands use.
async fn blocking<T: Send + 'static>(app: &AppHandle, f: impl FnOnce(&Connection) -> AppResult<T> + Send + 'static) -> AppResult<T> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || handle.state::<Db>().with(f)).await.map_err(|e| AppError::Internal(format!("the task failed: {e}")))?
}

/// Runs the correlation rules over a project and stores what they find as suggestions.
#[tauri::command]
pub async fn correlate_project(app: AppHandle, project_id: i64) -> AppResult<correlate::Report> {
    blocking(&app, move |c| correlate::run(c, project_id)).await
}

#[tauri::command]
pub async fn relations_list(db: State<'_, Db>, project_id: i64, filter: Option<relations::Filter>) -> AppResult<relations::Page> {
    db.with(|c| relations::list(c, project_id, &filter.unwrap_or_default()))
}

/// accept, reject, dismiss, reviewed or restore
#[tauri::command]
pub async fn relation_review(db: State<'_, Db>, id: i64, action: String, note: Option<String>) -> AppResult<relations::Relation> {
    db.with(|c| relations::review(c, id, &action, note.as_deref().unwrap_or(""), "user"))
}

#[tauri::command]
pub async fn relation_link(db: State<'_, Db>, project_id: i64, a: Ref, b: Ref, rel_type: String, note: Option<String>) -> AppResult<relations::Relation> {
    db.with(|c| relations::link(c, project_id, a, b, &rel_type, note.as_deref().unwrap_or(""), "user"))
}

#[tauri::command]
pub async fn relation_unlink(db: State<'_, Db>, id: i64, note: Option<String>) -> AppResult<()> {
    db.with(|c| relations::unlink(c, id, note.as_deref().unwrap_or(""), "user"))
}

#[tauri::command]
pub async fn related_records(db: State<'_, Db>, project_id: i64, record: Ref, include_rejected: Option<bool>) -> AppResult<relations::RelatedView> {
    db.with(|c| relations::related(c, project_id, &record, include_rejected.unwrap_or(false)))
}

#[tauri::command]
pub async fn investigation_graph(app: AppHandle, project_id: i64, filter: Option<relations::GraphFilter>) -> AppResult<relations::Graph> {
    blocking(&app, move |c| relations::graph(c, project_id, &filter.unwrap_or_default())).await
}

/// Findings that one fix addresses (`workspace/remediation.rs`).
#[tauri::command]
pub async fn remediation_groups(app: AppHandle, project_id: i64) -> AppResult<Vec<crate::workspace::remediation::Group>> {
    blocking(&app, move |c| {
        relations::project_status(c, project_id)?;
        crate::workspace::remediation::groups(c, project_id)
    })
    .await
}

/// Records of one project or of every project that match some text (see `workspace/search.rs`).
#[tauri::command]
pub async fn records_search(app: AppHandle, query: crate::workspace::search::Query) -> AppResult<Vec<crate::workspace::search::Hit>> {
    blocking(&app, move |c| crate::workspace::search::search(c, &query)).await
}

/// Saves the investigation graph as drawn (PNG as base64, or SVG) through a native dialog.
#[tauri::command]
pub async fn investigation_graph_export_image(app: AppHandle, project_id: i64, format: String, data: String) -> AppResult<Option<String>> {
    if data.len() > 80 * 1024 * 1024 {
        return Err(validation("The image is too large to export"));
    }
    let bytes = match format.as_str() {
        "png" => {
            let b = crate::sectools::pcap::base64_decode(&data).ok_or_else(|| validation("Invalid PNG data"))?;
            if !b.starts_with(&[0x89, b'P', b'N', b'G']) {
                return Err(validation("Invalid PNG data"));
            }
            b
        }
        "svg" => {
            if !data.trim_start().starts_with("<svg") && !data.trim_start().starts_with("<?xml") {
                return Err(validation("Invalid SVG data"));
            }
            // the drawing escapes every label; an image that could run code when opened elsewhere
            // is refused all the same
            if !svg_is_inert(&data) {
                return Err(validation("The SVG contains scripts or links and was not saved"));
            }
            data.into_bytes()
        }
        _ => return Err(validation("Unknown image format")),
    };
    let name: String = app.state::<Db>().with(|c| Ok(c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?))?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export investigation graph").set_file_name(format!("{safe}-investigation-graph.{format}")).add_filter(format.to_uppercase(), &[format.as_str()]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, bytes).map_err(|e| AppError::Internal(format!("Could not write the export: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", &format!("Investigation graph exported ({})", format.to_uppercase()), &file, None, None));
    Ok(Some(file))
}

/// The correlation rules and what each matches, for the review screen.
#[tauri::command]
pub async fn correlation_rules() -> AppResult<Vec<(String, String)>> {
    Ok(correlate::RULES.iter().map(|(r, d)| (r.to_string(), d.to_string())).collect())
}

/// A shortest chain of relationships between two records in the project's graph (with the same
/// filters), as node keys; None when they are not connected.
#[tauri::command]
pub async fn investigation_path(app: AppHandle, project_id: i64, from: String, to: String, filter: Option<relations::GraphFilter>) -> AppResult<Option<Vec<String>>> {
    blocking(&app, move |c| {
        let mut f = filter.unwrap_or_default();
        f.focus = None;
        let g = relations::graph(c, project_id, &f)?;
        Ok(relations::shortest_path(&g, &from, &to))
    })
    .await
}

/// Saves the investigation graph (with every edge's provenance) as JSON through a native dialog.
/// Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn investigation_graph_export(app: AppHandle, project_id: i64, filter: Option<relations::GraphFilter>) -> AppResult<Option<String>> {
    let (name, content) = {
        let db = app.state::<Db>();
        db.with(|c| {
            let name: String = c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?;
            let g = relations::graph(c, project_id, &filter.unwrap_or_default())?;
            Ok((name.clone(), relations::export_json(&name, &crate::util::now(), &g)))
        })?
    };
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export investigation graph").set_file_name(format!("{safe}-investigation-graph.json")).add_filter("JSON", &["json"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the export: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", "Investigation graph exported (JSON)", &file, None, None));
    Ok(Some(file))
}

/// The project timeline with filters: types, a record, words, a time range, paging.
#[tauri::command]
pub async fn timeline_query(db: State<'_, Db>, project_id: i64, query: timeline::Query) -> AppResult<Vec<timeline::TimelineEvent>> {
    db.with(|c| {
        relations::project_status(c, project_id)?;
        timeline::query(c, project_id, &query)
    })
}

/// Saves the filtered timeline as CSV or JSON through a native dialog (at most 10,000 events).
#[tauri::command]
pub async fn timeline_export(app: AppHandle, project_id: i64, query: timeline::Query, format: String) -> AppResult<Option<String>> {
    if format != "csv" && format != "json" {
        return Err(validation("Export the timeline as csv or json"));
    }
    let (name, content, count) = {
        let db = app.state::<Db>();
        db.with(|c| {
            let name: String = c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?;
            let mut events = Vec::new();
            let mut q = query.clone();
            q.limit = Some(1000);
            loop {
                let page = timeline::query(c, project_id, &q)?;
                let last = page.last().map(|e| e.cursor.clone());
                let n = page.len();
                events.extend(page);
                if n < 1000 || events.len() >= 10_000 {
                    break;
                }
                q.before = last;
            }
            events.truncate(10_000);
            let content = if format == "json" {
                serde_json::to_string_pretty(&serde_json::json!({ "format": "cyberhub-timeline", "version": 1, "project": name, "exportedAt": crate::util::now(), "events": events })).unwrap_or_default()
            } else {
                let cell = crate::workspace::findings_export::cell;
                let mut out = String::from("\u{feff}\"at\",\"observed_at\",\"type\",\"title\",\"detail\",\"ref_kind\",\"ref_id\"\r\n");
                for e in &events {
                    let row = [e.at.as_str(), e.observed_at.as_deref().unwrap_or(""), e.kind.as_str(), e.title.as_str(), e.detail.as_str(), e.ref_kind.as_deref().unwrap_or(""), &e.ref_id.map(|i| i.to_string()).unwrap_or_default()].map(cell).join(",");
                    out.push_str(&row);
                    out.push_str("\r\n");
                }
                out
            };
            Ok((name, content, events.len()))
        })?
    };
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export timeline").set_file_name(format!("{safe}-timeline.{format}")).add_filter(format.to_uppercase(), &[format.as_str()]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the export: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", &format!("Timeline exported ({}, {count} events)", format.to_uppercase()), &file, None, None));
    Ok(Some(file))
}

/// True when an SVG only draws: the drawing elements the graph export writes, no scripts, event
/// handlers, embedded documents, style sheets or links, and no references outside the image.
pub(crate) fn svg_is_inert(svg: &str) -> bool {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static EVENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|[\s/])on[a-z]+\s*=").expect("event attribute"));
    const ALLOWED: &[&str] = &["svg", "g", "defs", "marker", "path", "line", "polyline", "polygon", "rect", "circle", "ellipse", "text", "tspan", "title", "desc"];
    let s = svg.to_ascii_lowercase();
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(off) = s[i..].find('<') {
        let start = i + off + 1;
        if s[start..].starts_with("!--") {
            match s[start..].find("-->") {
                Some(e) => {
                    i = start + e + 3;
                    continue;
                }
                None => return false,
            }
        }
        // a tag ends at the first '>' outside quotes
        let mut quote: Option<u8> = None;
        let mut end = None;
        for (j, &ch) in b[start..].iter().enumerate() {
            match quote {
                Some(q) if ch == q => quote = None,
                Some(_) => {}
                None if ch == b'"' || ch == b'\'' => quote = Some(ch),
                None if ch == b'>' => {
                    end = Some(start + j);
                    break;
                }
                None => {}
            }
        }
        let Some(end) = end else { return false };
        let tag = &s[start..end];
        i = end + 1;
        if tag.starts_with('/') {
            continue;
        }
        if tag.starts_with('?') {
            // the XML declaration only: a style-sheet instruction would load something
            if tag == "?xml?" || tag.starts_with("?xml ") {
                continue;
            }
            return false;
        }
        if tag.starts_with('!') {
            // DOCTYPE (entities) and CDATA
            return false;
        }
        let name: String = tag.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_')).collect();
        if !ALLOWED.contains(&name.as_str()) {
            return false;
        }
        let attrs = tag[name.len()..].replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
        if EVENT.is_match(&attrs) || ["href", "javascript:", "http:", "https:", "data:", "file:", "@import"].iter().any(|x| attrs.contains(x)) {
            return false;
        }
        // a character reference or a CSS escape could spell what the checks above look for
        // (`&#117;rl(`, `ur\l(`); the exports never write either in an attribute (Mission 7)
        if attrs.contains("&#") || attrs.contains('\\') {
            return false;
        }
        // url() only to something inside the image (an arrow marker)
        let mut k = 0;
        while let Some(p) = attrs[k..].find("url(") {
            if !attrs[k + p + 4..].trim_start_matches(['"', '\'', ' ']).starts_with('#') {
                return false;
            }
            k += p + 4;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::svg_is_inert;

    #[test]
    fn only_drawings_are_saved_as_svg() {
        let drawing = r##"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><title>Acme: &lt;script&gt;</title><defs><marker id="m1"><path d="M0 0"/></marker></defs><g><line x1="0" y1="0" x2="5" y2="5" marker-end="url(#m1)"/><circle r="3" fill="#123456"/><text>onload=x &gt; y</text></g><!-- a > comment --></svg>"##;
        assert!(svg_is_inert(drawing), "the export's own drawing, with markup in its labels escaped");
        for bad in [
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>"#,
            // Mission 7: references and escapes that spell url() or a scheme
            r##"<svg xmlns="http://www.w3.org/2000/svg"><rect fill="&#117;rl(//x.example/a.svg#p)"/></svg>"##,
            r##"<svg xmlns="http://www.w3.org/2000/svg"><rect fill="&#x75;rl(//x.example/a.svg#p)"/></svg>"##,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:ur\l(//x.example/a.svg)"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><g title="a>b" onclick="x()"></g></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="https://example.com"><text>x</text></a></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://example.com/x)"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="background:url('javascript:x')"/></svg>"#,
            r#"<?xml-stylesheet href="https://example.com/x.css"?><svg xmlns="http://www.w3.org/2000/svg"></svg>"#,
            r#"<!DOCTYPE svg [<!ENTITY a "x">]><svg xmlns="http://www.w3.org/2000/svg"></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><rect "#,
        ] {
            assert!(!svg_is_inert(bad), "{bad}");
        }
    }
}
