// SPDX-License-Identifier: Apache-2.0
//! TLS analyzer: handshake details, supported protocol versions, the certificate chain and its
//! trust, with plain-language issues. The chain is recorded by a verifier that also runs the
//! real trust check (system roots), so untrusted certificates can still be analyzed.
//! TLS 1.0/1.1 cannot be tested: the TLS library deliberately does not implement them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct Recorder {
    inner: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    chain: Mutex<Vec<Vec<u8>>>,
    verdict: Mutex<Option<Result<(), String>>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = match &self.inner {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp, now).map(|_| ()).map_err(|e| e.to_string()),
            None => Err("No trusted root certificates are available on this system".into()),
        };
        if let Ok(mut c) = self.chain.lock() {
            *c = std::iter::once(end_entity).chain(intermediates.iter()).map(|d| d.as_ref().to_vec()).collect();
        }
        if let Ok(mut v) = self.verdict.lock() {
            *v = Some(verdict);
        }
        // analysis continues for untrusted certificates; nothing else is sent over this connection
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn trust_verifier(provider: &Arc<CryptoProvider>) -> Option<Arc<WebPkiServerVerifier>> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return None;
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().ok()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    /// days until expiry (negative when expired)
    pub days_left: i64,
    pub sans: Vec<String>,
    pub key: String,
    pub key_bits: Option<u32>,
    pub signature: String,
    pub sha256: String,
    pub self_signed: bool,
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA",
        "1.2.840.113549.1.1.4" => "MD5 with RSA",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.2.840.10045.4.1" => "ECDSA with SHA-1",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => return other.to_string(),
    }
    .to_string()
}

/// Reads a DER certificate.
pub fn parse_cert(der: &[u8], now: i64) -> Result<CertInfo, String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("Unreadable certificate: {e}"))?;
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for n in &ext.value.general_names {
            match n {
                GeneralName::DNSName(d) => sans.push(d.to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => sans.push(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
                    16 => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(b);
                        sans.push(std::net::Ipv6Addr::from(a).to_string());
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let (key, key_bits) = match cert.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(r)) => ("RSA".to_string(), Some(r.key_size() as u32)),
        Ok(x509_parser::public_key::PublicKey::EC(e)) => ("EC".to_string(), Some(e.key_size() as u32)),
        Ok(other) => (format!("{other:?}").split('(').next().unwrap_or("other").to_string(), None),
        Err(_) => ("unknown".into(), None),
    };
    let not_after = cert.validity().not_after.timestamp();
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    Ok(CertInfo {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: cert.raw_serial_as_string(),
        not_before: chrono::DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0).map(|d| d.to_rfc3339()).unwrap_or_default(),
        not_after: chrono::DateTime::from_timestamp(not_after, 0).map(|d| d.to_rfc3339()).unwrap_or_default(),
        days_left: (not_after - now).div_euclid(86_400),
        sans,
        key,
        key_bits,
        signature: signature_name(&cert.signature_algorithm.algorithm.to_id_string()),
        sha256: Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect(),
    })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    /// critical, warning, info
    pub level: &'static str,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TlsReport {
    pub host: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub tls13: bool,
    pub tls12: bool,
    pub trusted: bool,
    pub trust_error: Option<String>,
    pub chain: Vec<CertInfo>,
    pub issues: Vec<Issue>,
}

/// Plain-language issues for a report (pure, tested).
pub fn assess(r: &TlsReport) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut push = |level: &'static str, text: String| out.push(Issue { level, text });
    if let Some(e) = &r.trust_error {
        push("critical", format!("The certificate is not trusted: {e}"));
    }
    if let Some(leaf) = r.chain.first() {
        if leaf.days_left < 0 {
            push("critical", format!("The certificate expired {} days ago ({})", -leaf.days_left, leaf.not_after));
        } else if leaf.days_left < 30 {
            push("warning", format!("The certificate expires in {} days ({})", leaf.days_left, leaf.not_after));
        }
        if leaf.self_signed {
            push("warning", "The certificate is self-signed".into());
        }
        if leaf.key == "RSA" && leaf.key_bits.is_some_and(|b| b < 2048) {
            push("critical", format!("RSA key of {} bits; use at least 2048", leaf.key_bits.unwrap_or(0)));
        }
        if leaf.signature.contains("SHA-1") || leaf.signature.contains("MD5") {
            push("critical", format!("Weak certificate signature ({})", leaf.signature));
        }
    }
    if !r.tls13 {
        push("warning", "TLS 1.3 is not supported".into());
    }
    if !r.tls12 && r.tls13 {
        push("info", "Only TLS 1.3 is offered (clients without TLS 1.3 cannot connect)".into());
    }
    push("info", "TLS 1.0 and 1.1 were not tested: the TLS library does not implement them. Use a dedicated scanner to check for them.".into());
    out
}

struct Handshake {
    protocol: String,
    cipher: String,
    alpn: Option<String>,
    chain: Vec<Vec<u8>>,
    verdict: Option<Result<(), String>>,
}

async fn handshake(host: &str, addrs: &[std::net::SocketAddr], versions: &[&'static rustls::SupportedProtocolVersion], provider: &Arc<CryptoProvider>, trust: &Option<Arc<WebPkiServerVerifier>>) -> Result<Handshake, String> {
    let recorder = Arc::new(Recorder { inner: trust.clone(), provider: provider.clone(), chain: Mutex::new(vec![]), verdict: Mutex::new(None) });
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name = ServerName::try_from(host.to_string()).map_err(|_| format!("{host} is not a valid server name"))?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addrs))
        .await
        .map_err(|_| "The connection timed out".to_string())?
        .map_err(|e| format!("Could not connect: {e}"))?;
    let tls = tokio::time::timeout(Duration::from_secs(10), tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp))
        .await
        .map_err(|_| "The TLS handshake timed out".to_string())?
        .map_err(|e| format!("The TLS handshake failed: {e}"))?;
    let (_, conn) = tls.get_ref();
    let out = Handshake {
        protocol: conn.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1.")).unwrap_or_default(),
        cipher: conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default(),
        alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).to_string()),
        chain: recorder.chain.lock().map(|c| c.clone()).unwrap_or_default(),
        verdict: recorder.verdict.lock().ok().and_then(|v| v.clone()),
    };
    Ok(out)
}

/// Analyzes a TLS service at the given (scope-checked, vetted) addresses of `host`.
pub async fn analyze(host: &str, port: u16, addrs: &[std::net::SocketAddr]) -> Result<TlsReport, String> {
    let provider = provider();
    let trust = trust_verifier(&provider);
    let main = handshake(host, addrs, &[&rustls::version::TLS13, &rustls::version::TLS12], &provider, &trust).await?;
    let tls13 = main.protocol == "TLS 1.3" || handshake(host, addrs, &[&rustls::version::TLS13], &provider, &trust).await.is_ok();
    let tls12 = main.protocol == "TLS 1.2" || handshake(host, addrs, &[&rustls::version::TLS12], &provider, &trust).await.is_ok();
    let now = chrono::Utc::now().timestamp();
    let chain = main.chain.iter().filter_map(|d| parse_cert(d, now).ok()).collect();
    let (trusted, trust_error) = match main.verdict {
        Some(Ok(())) => (true, None),
        Some(Err(e)) => (false, Some(e)),
        None => (false, Some("The server sent no certificate".into())),
    };
    let mut r = TlsReport { host: host.to_string(), port, protocol: Some(main.protocol), cipher: Some(main.cipher), alpn: main.alpn, tls13, tls12, trusted, trust_error, chain, issues: vec![] };
    r.issues = assess(&r);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(days_left: i64, self_signed: bool, bits: u32, sig: &str) -> CertInfo {
        CertInfo {
            subject: "CN=a".into(),
            issuer: if self_signed { "CN=a".into() } else { "CN=CA".into() },
            serial: "01".into(),
            not_before: String::new(),
            not_after: "2026-12-01".into(),
            days_left,
            sans: vec![],
            key: "RSA".into(),
            key_bits: Some(bits),
            signature: sig.into(),
            sha256: String::new(),
            self_signed,
        }
    }

    fn report(chain: Vec<CertInfo>, tls13: bool, trust_error: Option<&str>) -> TlsReport {
        TlsReport { host: "a".into(), port: 443, protocol: None, cipher: None, alpn: None, tls13, tls12: true, trusted: trust_error.is_none(), trust_error: trust_error.map(str::to_string), chain, issues: vec![] }
    }

    #[test]
    fn issues_are_explained() {
        let good = assess(&report(vec![leaf(200, false, 2048, "SHA-256 with RSA")], true, None));
        assert!(good.iter().all(|i| i.level == "info"), "{good:?}");
        let bad = assess(&report(vec![leaf(-3, true, 1024, "SHA-1 with RSA")], false, Some("UnknownIssuer")));
        let crit = bad.iter().filter(|i| i.level == "critical").count();
        assert_eq!(crit, 4, "{bad:?}");
        assert!(bad.iter().any(|i| i.text.contains("expired 3 days ago")));
        assert!(bad.iter().any(|i| i.text.contains("TLS 1.3 is not supported")));
        assert!(assess(&report(vec![leaf(10, false, 4096, "ECDSA with SHA-256")], true, None)).iter().any(|i| i.text.contains("expires in 10 days")));
    }

    #[test]
    fn system_root_certificates_are_parsed() {
        let roots = rustls_native_certs::load_native_certs().certs;
        if roots.is_empty() {
            return; // no system store in this environment
        }
        let now = chrono::Utc::now().timestamp();
        let parsed: Vec<CertInfo> = roots.iter().filter_map(|c| parse_cert(c.as_ref(), now).ok()).collect();
        assert!(!parsed.is_empty());
        let c = &parsed[0];
        assert!(!c.subject.is_empty() && c.sha256.len() == 64 && !c.signature.is_empty());
        assert!(parse_cert(b"not a certificate", now).is_err());
        assert_eq!(signature_name("1.2.840.113549.1.1.11"), "SHA-256 with RSA");
    }
}
