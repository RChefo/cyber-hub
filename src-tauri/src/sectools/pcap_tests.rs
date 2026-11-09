use super::*;

fn eth(ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(l3);
    f
}

fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 1, 0x40, 0, 64, proto, 0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h.extend_from_slice(l4);
    h
}

fn tcp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

const CLIENT: [u8; 4] = [10, 0, 0, 5];
const SERVER: [u8; 4] = [93, 184, 216, 34];

fn dns_response() -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    for label in ["app", "example", "com"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34]);
    m
}

fn client_hello(name: &str) -> Vec<u8> {
    let mut ext = vec![0, 0];
    let list_len = (3 + name.len()) as u16;
    ext.extend_from_slice(&(list_len + 2).to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name.as_bytes());
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// The frames of a small session: DNS, HTTP with Basic credentials, TLS, FTP, IMAP, SMTP, a
/// VLAN-tagged packet, an IPv6 packet and an ARP frame.
fn frames() -> Vec<Vec<u8>> {
    let http = b"GET /admin?token=x HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: curl/8.5\r\nAuthorization: Basic YWxpY2U6czNjcmV0IQ==\r\n\r\n";
    let mut vlan = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x81, 0x00, 0x00, 0x0a, 0x08, 0x00];
    vlan.extend_from_slice(&ipv4(17, CLIENT, [10, 0, 0, 1], &udp(40000, 53, &[0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'w', b'p', b'a', b'd', 0, 0, 1, 0, 1])));
    let mut v6 = vec![0x60, 0, 0, 0];
    let payload = udp(5000, 161, b"public-community");
    v6.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v6.extend_from_slice(&[17, 64]);
    v6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    v6.extend_from_slice(&payload);
    vec![
        eth(0x0800, &ipv4(17, [10, 0, 0, 1], CLIENT, &udp(53, 40001, &dns_response()))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51000, 80, http))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51001, 443, &client_hello("Secure.Example.com")))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51002, 21, b"USER bob\r\n"))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51002, 21, b"PASS hunter2\r\n"))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51003, 143, b"a1 LOGIN carol \"pw12345\"\r\n"))),
        eth(0x0800, &ipv4(6, CLIENT, SERVER, &tcp(51004, 587, b"AUTH PLAIN AGRhdmUAc2VjcmV0cGFzcw==\r\n"))),
        vlan,
        eth(0x86dd, &v6),
        eth(0x0806, &[0u8; 28]),
    ]
}

fn pcap_file(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut f = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
    for (i, fr) in frames.iter().enumerate() {
        f.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
        f.extend_from_slice(&250_000u32.to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(fr);
    }
    f
}

fn pcapng_file(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut f = Vec::new();
    // section header block
    f.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    f.extend_from_slice(&28u32.to_le_bytes());
    f.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    f.extend_from_slice(&[1, 0, 0, 0]);
    f.extend_from_slice(&(-1i64).to_le_bytes());
    f.extend_from_slice(&28u32.to_le_bytes());
    // interface description block (Ethernet, microseconds)
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&20u32.to_le_bytes());
    f.extend_from_slice(&[1, 0, 0, 0]);
    f.extend_from_slice(&65535u32.to_le_bytes());
    f.extend_from_slice(&20u32.to_le_bytes());
    for (i, fr) in frames.iter().enumerate() {
        let padded = fr.len().div_ceil(4) * 4;
        let total = (32 + padded) as u32;
        let ts = (1_700_000_000u64 + i as u64) * 1_000_000 + 250_000;
        f.extend_from_slice(&6u32.to_le_bytes());
        f.extend_from_slice(&total.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        f.extend_from_slice(&(ts as u32).to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(fr);
        f.extend(std::iter::repeat_n(0u8, padded - fr.len()));
        f.extend_from_slice(&total.to_le_bytes());
    }
    f
}

fn check(r: &Report) {
    assert_eq!(r.packets, 10);
    assert_eq!(r.undecoded, 1, "the ARP frame");
    assert_eq!((r.first, r.last), (Some(1_700_000_000.25), Some(1_700_000_009.25)));
    let dns = r.dns.iter().find(|d| d.name == "app.example.com").unwrap();
    assert_eq!((dns.kind.as_str(), dns.answers.clone()), ("A", vec!["93.184.216.34".to_string()]));
    assert!(r.dns.iter().any(|d| d.name == "wpad"), "the query in the VLAN-tagged frame");
    let http = &r.http[0];
    assert_eq!((http.method.as_str(), http.host.as_str(), http.path.as_str(), http.user_agent.as_str()), ("GET", "app.example.com", "/admin", "curl/8.5"), "the query string is not kept");
    assert_eq!(r.tls, vec![TlsServer { name: "secure.example.com".into(), server: "93.184.216.34:443".into(), count: 1 }]);
    let creds: Vec<(String, String, usize)> = r.credentials.iter().map(|c| (c.protocol.clone(), c.user.clone(), c.secret_length)).collect();
    assert_eq!(
        creds,
        vec![("http-basic".into(), "alice".into(), 7), ("ftp".into(), "bob".into(), 7), ("imap".into(), "carol".into(), 7), ("smtp".into(), "dave".into(), 10)]
    );
    let rules: Vec<&str> = r.issues.iter().map(|i| i.rule.as_str()).collect();
    assert_eq!(rules, vec!["PCAP-CLEARTEXT-CREDENTIALS", "PCAP-CLEARTEXT-PROTOCOL", "PCAP-PLAIN-HTTP"]);
    let cleartext = &r.issues[1];
    assert!(cleartext.title.contains("FTP") && cleartext.title.contains("IMAP") && cleartext.title.contains("SNMP"), "{}", cleartext.title);
    assert!(r.hosts.iter().any(|h| h.ip == "fd00::1"), "IPv6 hosts are counted");
    assert!(r.conversations.iter().any(|c| c.server == "93.184.216.34:80" && c.client == "10.0.0.5" && c.protocol == "tcp"));
    let json = serde_json::to_string(r).unwrap();
    for secret in ["s3cret!", "hunter2", "pw12345", "secretpass"] {
        assert!(!json.contains(secret), "{secret} must never be in the report");
    }
}

#[test]
fn pcap_and_pcapng_give_the_same_report() {
    let f = frames();
    let a = analyze(std::io::Cursor::new(pcap_file(&f))).unwrap();
    assert_eq!((a.format.as_str(), a.links.clone()), ("pcap", vec!["Ethernet".to_string()]));
    check(&a);
    let b = analyze(std::io::Cursor::new(pcapng_file(&f))).unwrap();
    assert_eq!(b.format, "pcapng");
    check(&b);
    assert_eq!((a.dns.clone(), a.http.clone(), a.credentials.clone(), a.issues.clone()), (b.dns.clone(), b.http.clone(), b.credentials.clone(), b.issues.clone()));
}

#[test]
fn damaged_and_other_files() {
    assert!(analyze(std::io::Cursor::new(b"hello world".to_vec())).unwrap_err().contains("not a pcap"));
    assert!(analyze(std::io::Cursor::new(vec![0xd4, 0xc3])).is_err());
    let mut f = pcap_file(&frames());
    f.truncate(f.len() - 10);
    let r = analyze(std::io::Cursor::new(f)).unwrap();
    assert_eq!(r.packets, 9, "the cut packet is left out");
    assert!(r.warnings[0].contains("ends in the middle"), "{:?}", r.warnings);
    // a record claiming an absurd length stops the reading instead of allocating it
    let mut g = pcap_file(&frames()[..1]);
    g.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0]);
    let r = analyze(std::io::Cursor::new(g)).unwrap();
    assert_eq!(r.packets, 1);
    assert!(r.warnings[0].contains("damaged"));
}

#[test]
fn helpers() {
    assert_eq!(base64_decode("YWxpY2U6czNjcmV0IQ==").unwrap(), b"alice:s3cret!");
    assert_eq!(base64_decode("YQ").unwrap(), b"a");
    assert!(base64_decode("not base64!").is_none());
    assert_eq!(tls_sni(&client_hello("api.example.org")).as_deref(), Some("api.example.org"));
    assert_eq!(tls_sni(b"\x16\x03\x01\x00"), None);
    assert_eq!(tls_sni(b"GET / HTTP/1.1"), None);
    // a DNS compression pointer that points forward is refused (no loops)
    assert!(dns_name(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x0e, 3, b'a', b'b', b'c', 0], 12).is_none());
}
