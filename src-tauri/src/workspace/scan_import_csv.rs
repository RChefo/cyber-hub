// SPDX-License-Identifier: Apache-2.0
//! CSV findings with a column mapping (docs/DATA_MODEL.md#csv-findings).
//!
//! Any CSV file with a header row: a spreadsheet of findings, or a CSV export of Nessus, Qualys or
//! Greenbone. The columns are suggested from the header names and can be changed in the preview.
//! A CSV file never verifies fixes: exports are often filtered, so a finding it does not list
//! proves nothing.

use super::*;

/// Columns read per row; more are ignored.
pub const MAX_COLUMNS: usize = 200;
/// Characters kept per cell (the field limits cut further).
const MAX_CELL: usize = 50_000;

/// Which column (0-based) holds which field. `None`: the field is not read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CsvMapping {
    #[serde(default)]
    pub title: Option<usize>,
    #[serde(default)]
    pub severity: Option<usize>,
    #[serde(default)]
    pub target: Option<usize>,
    #[serde(default)]
    pub port: Option<usize>,
    #[serde(default)]
    pub description: Option<usize>,
    #[serde(default)]
    pub remediation: Option<usize>,
    #[serde(default)]
    pub cve: Option<usize>,
    #[serde(default)]
    pub cvss: Option<usize>,
    #[serde(default)]
    pub rule_id: Option<usize>,
    #[serde(default)]
    pub references: Option<usize>,
    #[serde(default)]
    pub details: Option<usize>,
}

impl CsvMapping {
    fn columns(&self) -> [Option<usize>; 11] {
        [self.title, self.severity, self.target, self.port, self.description, self.remediation, self.cve, self.cvss, self.rule_id, self.references, self.details]
    }
}

/// The file as the mapping step shows it.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvInfo {
    pub headers: Vec<String>,
    /// the first rows, cells cut to 120 characters
    pub sample: Vec<Vec<String>>,
    /// data rows read (without the header)
    pub rows: usize,
    /// `,`, `;` or a tab
    pub delimiter: String,
    pub mapping: CsvMapping,
    /// how the severity column was read: `words`, `levels` (1 to 5, 5 critical) or `scores`
    /// (CVSS 0 to 10)
    pub severity_scale: Option<String>,
}

/// The start of a text: at most 64 K characters, cut on a character boundary (never on a byte
/// offset: with `panic = "abort"` a split character would end the app).
fn head(text: &str) -> &str {
    let end = text.char_indices().nth(64 * 1024).map_or(text.len(), |(i, _)| i);
    &text[..end]
}

/// The delimiter: of comma, semicolon and tab, the one that splits the header row into at least two
/// columns and the next rows into as many, read with the same quoting rules as the rows. Then the
/// most columns; a comma wins a tie.
fn delimiter(text: &str) -> Option<char> {
    let head = head(text);
    let mut best: Option<(char, (usize, usize))> = None;
    for d in [',', ';', '\t'] {
        let (rows, _, _) = split_rows(head, d, 5);
        let Some(n) = rows.first().map(Vec::len).filter(|n| *n >= 2) else { continue };
        let score = (rows[1..].iter().filter(|r| r.len() == n).count(), n);
        if best.is_none_or(|(_, s)| score > s) {
            best = Some((d, score));
        }
    }
    best.map(|(d, _)| d)
}

/// Rows of a CSV text (RFC 4180): quoted fields with `""` escapes, delimiters and line breaks
/// inside quotes, CRLF or LF line ends; blank lines are skipped. Returns the rows (at most
/// `max_rows`), the rows past that limit, and whether the text ended inside a quoted field.
fn split_rows(text: &str, delim: char, max_rows: usize) -> (Vec<Vec<String>>, usize, bool) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut past = 0usize;
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut field_chars = 0usize;
    let mut quoted = false;
    let mut at_start = true;
    let mut chars = text.chars().peekable();

    fn end_field(row: &mut Vec<String>, field: &mut String, field_chars: &mut usize) {
        if row.len() < MAX_COLUMNS {
            row.push(std::mem::take(field));
        } else {
            field.clear();
        }
        *field_chars = 0;
    }
    let end_row = |rows: &mut Vec<Vec<String>>, past: &mut usize, row: &mut Vec<String>| {
        let r = std::mem::take(row);
        if r.iter().all(|c| c.trim().is_empty()) {
            return; // a blank line
        }
        if rows.len() < max_rows {
            rows.push(r);
        } else {
            *past += 1;
        }
    };

    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                } else {
                    quoted = false;
                    continue;
                }
            }
            if field_chars < MAX_CELL {
                field.push(c);
                field_chars += 1;
            }
            continue;
        }
        match c {
            '"' if at_start => {
                quoted = true;
                at_start = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\r' | '\n' => {
                end_field(&mut row, &mut field, &mut field_chars);
                end_row(&mut rows, &mut past, &mut row);
                at_start = true;
            }
            c if c == delim => {
                end_field(&mut row, &mut field, &mut field_chars);
                at_start = true;
            }
            _ => {
                if field_chars < MAX_CELL {
                    field.push(c);
                    field_chars += 1;
                }
                at_start = false;
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        end_field(&mut row, &mut field, &mut field_chars);
        end_row(&mut rows, &mut past, &mut row);
    }
    (rows, past, quoted)
}

/// Whether a text looks like CSV with a header row: a delimiter and at least two named columns.
pub fn looks_like_csv(text: &str) -> bool {
    let Some(d) = delimiter(text) else { return false };
    let (rows, _, _) = split_rows(head(text), d, 1);
    rows.first().is_some_and(|h| h.iter().filter(|c| !c.trim().is_empty()).count() >= 2 && h.iter().all(|c| c.chars().count() <= 200))
}

fn header_key(h: &str) -> String {
    h.trim().to_lowercase().replace(['_', '-'], " ").split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Header names that suggest a field, in order of preference.
const SUGGESTIONS: &[(&str, &[&str])] = &[
    ("title", &["name", "title", "vulnerability", "vulnerability name", "vulnerability title", "plugin name", "nvt name", "issue", "issue name", "finding", "finding name", "alert", "check name"]),
    ("severity", &["severity", "risk", "risk level", "risk rating", "risk factor", "criticality", "threat level"]),
    ("target", &["host", "hostname", "ip", "ip address", "target", "asset", "address", "url", "affected host", "affected target", "affected url", "dns name", "fqdn", "endpoint", "uri"]),
    ("port", &["port"]),
    ("description", &["description", "synopsis", "summary", "threat", "details", "impact"]),
    ("remediation", &["solution", "remediation", "recommendation", "recommendations", "fix", "mitigation"]),
    ("cve", &["cve", "cves", "cve id", "cve ids"]),
    ("cvss", &["cvss v4.0 vector", "cvss4 vector", "cvss v3.1 vector", "cvss v3.0 vector", "cvss3 vector", "cvss vector", "cvss v4.0 base score", "cvss v3.1 base score", "cvss v3.0 base score", "cvss3 base score", "cvss base score", "cvss base", "cvss score", "cvss", "cvss v2.0 base score"]),
    ("rule_id", &["plugin id", "pluginid", "plugin", "qid", "nvt oid", "oid", "rule", "rule id", "check id", "vulnerability id", "template id"]),
    ("references", &["see also", "references", "reference", "links", "vendor reference"]),
    ("details", &["plugin output", "output", "evidence", "proof", "results", "specific result"]),
];

/// A mapping from the header names (each column used once).
pub fn suggest(headers: &[String]) -> CsvMapping {
    let keys: Vec<String> = headers.iter().map(|h| header_key(h)).collect();
    let mut used: Vec<usize> = Vec::new();
    let mut m = CsvMapping::default();
    for (field, names) in SUGGESTIONS {
        let found = names.iter().find_map(|n| keys.iter().enumerate().find(|(i, k)| k == n && !used.contains(i)).map(|(i, _)| i));
        if let Some(i) = found {
            used.push(i);
            let slot = match *field {
                "title" => &mut m.title,
                "severity" => &mut m.severity,
                "target" => &mut m.target,
                "port" => &mut m.port,
                "description" => &mut m.description,
                "remediation" => &mut m.remediation,
                "cve" => &mut m.cve,
                "cvss" => &mut m.cvss,
                "rule_id" => &mut m.rule_id,
                "references" => &mut m.references,
                _ => &mut m.details,
            };
            *slot = Some(i);
        }
    }
    m
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scale {
    Words,
    Levels,
    Scores,
}

fn number(s: &str) -> Option<f64> {
    s.trim().replace(',', ".").parse::<f64>().ok().filter(|n| n.is_finite())
}

/// Numbers with a decimal part or above 5 are CVSS scores; whole numbers up to 5 are levels (as in
/// Qualys, 5 = critical); otherwise words.
fn scale_of<'a>(values: impl Iterator<Item = &'a str>) -> Scale {
    let mut numeric = false;
    for v in values {
        if let Some(n) = number(v) {
            numeric = true;
            if n.fract() != 0.0 || n > 5.0 || v.contains(['.', ',']) {
                return Scale::Scores;
            }
        }
    }
    if numeric {
        Scale::Levels
    } else {
        Scale::Words
    }
}

fn score_severity(n: f64) -> &'static str {
    match n {
        n if n >= 9.0 => "critical",
        n if n >= 7.0 => "high",
        n if n >= 4.0 => "medium",
        n if n > 0.0 => "low",
        _ => "info",
    }
}

fn csv_severity(raw: &str, scale: Scale) -> Option<&'static str> {
    let t = raw.trim().to_lowercase();
    let word = match t.as_str() {
        "critical" | "crit" | "urgent" => Some("critical"),
        "high" => Some("high"),
        "medium" | "moderate" | "med" => Some("medium"),
        "low" => Some("low"),
        "info" | "informational" | "information" | "none" | "log" | "note" | "minimal" => Some("info"),
        _ => None,
    };
    if word.is_some() {
        return word;
    }
    let n = number(&t)?;
    Some(match scale {
        Scale::Levels => match n as i64 {
            5 => "critical",
            4 => "high",
            3 => "medium",
            2 => "low",
            _ => "info",
        },
        _ => score_severity(n),
    })
}

/// Reads CSV findings with `mapping`, or with the mapping suggested by the headers.
pub fn parse_csv(text: &str, mapping: Option<&CsvMapping>) -> Result<Parsed, String> {
    let delim = delimiter(text).ok_or("The CSV file's first row has no comma, semicolon or tab between columns")?;
    let (mut rows, past, broken) = split_rows(text, delim, MAX_FINDINGS + 1);
    if rows.is_empty() {
        return Err("The CSV file is empty".into());
    }
    // a file without a header row would show its first data row here: redacted like any value
    let headers: Vec<String> = rows.remove(0).into_iter().map(|h| clean_text(&redact_text(h.trim()), 120)).collect();
    let m = mapping.cloned().unwrap_or_else(|| suggest(&headers));
    if let Some(bad) = m.columns().into_iter().flatten().find(|i| *i >= headers.len()) {
        return Err(format!("Column {} does not exist in this file", bad.saturating_add(1)));
    }
    let mut p = Parsed::new(Format::Csv, "CSV");
    p.no_absence = true;
    p.truncated = past;
    p.incomplete = past > 0 || broken;
    if broken {
        p.warnings.push("The file ends inside a quoted value; the last row may be cut".into());
    }
    let cell = |row: &[String], col: Option<usize>| -> String { col.and_then(|i| row.get(i)).map(|s| s.trim().to_string()).unwrap_or_default() };
    let scale = m.severity.map(|col| scale_of(rows.iter().filter_map(|r| r.get(col)).map(String::as_str)));
    let info = CsvInfo {
        headers: headers.clone(),
        sample: rows.iter().take(3).map(|r| r.iter().map(|c| trunc(&clean_text(&redact_text(c), 400), 120)).collect()).collect(),
        rows: rows.len(),
        delimiter: if delim == '\t' { "tab".into() } else { delim.to_string() },
        mapping: m.clone(),
        severity_scale: scale.map(|s| match s {
            Scale::Words => "words".into(),
            Scale::Levels => "levels".into(),
            Scale::Scores => "scores".into(),
        }),
    };
    if m.title.is_none() {
        p.warnings.push("Choose the column that holds the finding titles".into());
        p.csv = Some(info);
        return Ok(p);
    }
    if m.severity.is_none() && m.cvss.is_none() {
        p.warnings.push("No severity or CVSS column is chosen, so every finding is informational".into());
    }
    if m.target.is_none() {
        p.warnings.push("No target column is chosen, so the findings are recorded without a target (there is nothing to check against the scope)".into());
    }
    let mut untitled = 0usize;
    let mut hosts: BTreeSet<(String, bool)> = BTreeSet::new();
    for row in &rows {
        let title = cell(row, m.title);
        if title.is_empty() {
            untitled += 1;
            continue;
        }
        let cvss_raw = cell(row, m.cvss);
        let cvss = valid_cvss(&cvss_raw);
        let severity = m
            .severity
            .and_then(|_| csv_severity(&cell(row, m.severity), scale.unwrap_or(Scale::Words)))
            .or_else(|| (!cvss.is_empty()).then(|| crate::cvss::parse(&cvss).map(|c| severity_word(c.rating)).unwrap_or("info")))
            .or_else(|| number(&cvss_raw).map(score_severity))
            .unwrap_or("info");
        let raw_target = cell(row, m.target);
        let port = cell(row, m.port);
        let has_port = port.parse::<u32>().is_ok_and(|n| n > 0 && n <= 65_535);
        // a port column joins a plain host (not a URL or a value that has a port already)
        let target = if has_port && !raw_target.contains("://") && host_of(&raw_target).is_some_and(|h| h == raw_target.to_lowercase().trim_matches(['[', ']'])) {
            format!("{}:{port}", bracket(&raw_target))
        } else {
            raw_target.clone()
        };
        let host = (!target.is_empty()).then(|| host_of(&target)).flatten();
        if let Some(h) = host.as_ref() {
            hosts.insert((h.clone(), crate::osint::normalize::ip(h).is_ok()));
        }
        let rule = cell(row, m.rule_id);
        let references: Vec<String> = cell(row, m.references)
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .map(|r| r.trim_matches(|c: char| matches!(c, '<' | '>' | '(' | ')' | '"' | '\'')))
            .filter(|r| r.starts_with("http://") || r.starts_with("https://"))
            .map(String::from)
            .take(20)
            .collect();
        // rows without a rule ID are told apart by their title
        let key = if rule.is_empty() { format!("title\u{1f}{title}") } else { format!("rule\u{1f}{rule}") };
        let mut technical = cell(row, m.details);
        if !cvss_raw.is_empty() && cvss.is_empty() {
            technical = format!("CVSS (as reported): {cvss_raw}\n{technical}").trim().to_string();
        }
        p.push_finding(ImportedFinding {
            rule_id: trunc(&rule, 200),
            title,
            severity,
            confidence: "medium",
            asset: host.as_ref().map(|h| (if crate::osint::normalize::ip(h).is_ok() { "ip" } else { "name" }, h.clone())),
            target: trunc(&target, 500),
            host: host.clone(),
            description: cell(row, m.description),
            remediation: cell(row, m.remediation),
            technical,
            references,
            cve: cve_list(cell(row, m.cve).split(|c: char| c.is_whitespace() || c == ',' || c == ';').map(String::from)),
            category: String::new(),
            tags: tool_tags("csv", std::iter::empty()),
            fingerprint: fingerprint(&["csv", &key, &target]),
            cvss,
            // with a target column, a row whose target is empty or unreadable counts as outside
            // the scope, as for the other formats
            network: m.target.is_some(),
        });
    }
    for (h, is_ip) in hosts {
        p.push_asset(if is_ip { "ip" } else { "name" }, &h, &h, json!({}));
    }
    if untitled > 0 {
        p.warnings.push(format!("{} without a title {} skipped", crate::workspace::discovery::plural(untitled, "row", "rows"), if untitled == 1 { "was" } else { "were" }));
    }
    p.csv = Some(info);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4180_quoting_line_breaks_and_delimiters() {
        let text = "Name,Description,Host\r\n\"SQL injection\",\"Line one\r\nline \"\"two\"\", with comma\",10.0.0.5\r\n\r\nXSS,plain,app.example.com\n";
        let (rows, past, broken) = split_rows(text, ',', 100);
        assert_eq!((rows.len(), past, broken), (3, 0, false));
        assert_eq!(rows[1], ["SQL injection", "Line one\r\nline \"two\", with comma", "10.0.0.5"]);
        assert_eq!(rows[2], ["XSS", "plain", "app.example.com"]);
        assert_eq!(delimiter("a;b;\"c,d,e\"\n1;2;3"), Some(';'), "commas inside quotes do not count");
        assert_eq!(delimiter("a\tb\n"), Some('\t'));
        assert_eq!(delimiter("a,b;c,d;e\n"), Some(','), "a comma wins a tie");
        assert_eq!(delimiter("no delimiter here"), None);
        let (rows, _, broken) = split_rows("a,b\n\"open,1\n", ',', 10);
        assert!(broken && rows.len() == 2, "{rows:?}");
        let (rows, past, _) = split_rows("h\n1\n2\n3\n", ',', 2);
        assert_eq!((rows.len(), past), (2, 2));
    }

    #[test]
    fn detection_never_cuts_a_character_and_follows_the_row_quoting() {
        // more than 64 K characters of 2-byte text: byte 65,536 falls inside a character
        let wide = format!("a,b\nx{}", "é".repeat(40_000));
        assert!(looks_like_csv(&wide));
        let cjk = format!("名前,ホスト\n{}", "日本語,".repeat(30_000));
        assert!(looks_like_csv(&cjk));
        assert_eq!(head(&"é".repeat(70_000)).chars().count(), 64 * 1024);
        // a quote inside a header cell is a plain character, as in the rows
        assert_eq!(delimiter("5\" pipe,name,x\n1,2,3"), Some(','));
        // blank lines before the header are skipped
        assert_eq!(delimiter("\r\n\nName;Host\nA;b"), Some(';'));
        assert_eq!(delimiter("one column only\nvalue"), None);
    }

    #[test]
    fn columns_are_suggested_from_common_exports() {
        let nessus: Vec<String> = ["Plugin ID", "CVE", "CVSS v2.0 Base Score", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output"].map(String::from).into();
        let m = suggest(&nessus);
        assert_eq!((m.title, m.severity, m.target, m.port, m.description, m.remediation), (Some(7), Some(3), Some(4), Some(6), Some(9), Some(10)));
        assert_eq!((m.cve, m.cvss, m.rule_id, m.references, m.details), (Some(1), Some(2), Some(0), Some(11), Some(12)));
        let qualys: Vec<String> = ["IP", "DNS", "QID", "Title", "Severity", "Port", "CVE ID", "Threat", "Solution", "Results"].map(String::from).into();
        let m = suggest(&qualys);
        assert_eq!((m.title, m.severity, m.target, m.rule_id, m.description, m.details), (Some(3), Some(4), Some(0), Some(2), Some(7), Some(9)));
    }

    #[test]
    fn severities_are_read_as_words_levels_or_scores() {
        assert_eq!(scale_of(["High", "Low"].into_iter()), Scale::Words);
        assert_eq!(scale_of(["5", "3", "1"].into_iter()), Scale::Levels);
        assert_eq!(scale_of(["5", "7.5"].into_iter()), Scale::Scores);
        assert_eq!(scale_of(["5", "9"].into_iter()), Scale::Scores);
        assert_eq!(csv_severity("5", Scale::Levels), Some("critical"));
        assert_eq!(csv_severity("2", Scale::Levels), Some("low"));
        assert_eq!(csv_severity("7,5", Scale::Scores), Some("high"));
        assert_eq!(csv_severity("Moderate", Scale::Levels), Some("medium"), "words always win");
        assert_eq!(csv_severity("None", Scale::Words), Some("info"));
        assert_eq!(csv_severity("whatever", Scale::Words), None);
    }
}
