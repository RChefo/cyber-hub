// SPDX-License-Identifier: Apache-2.0
//! HTTPS trust roots and building network clients (Mission 11).
//!
//! reqwest checks a server's certificate with `rustls-platform-verifier`:
//! * on **Windows** it asks Windows' certificate store during each connection, so building a client
//!   never fails there;
//! * on **Linux** it loads the system's CA certificates (`rustls-native-certs`: the distribution's
//!   bundle, or only `SSL_CERT_FILE` / `SSL_CERT_DIR` when they are set) while a client is *built*,
//!   and refuses to build one when there are none.
//!
//! Mission 10 found that this stopped ExploitX from starting on a Linux system without CA
//! certificates ("ExploitX could not start: builder error"): the VirusTotal and threat-intelligence
//! states built their clients during start-up. Now:
//! * nothing network-related is built while ExploitX starts: those two clients are [`LazyClient`]s;
//! * every client is built through [`build`], which names the missing CA certificates and what to do;
//! * verification is never weakened: without CA certificates no client exists, so no HTTPS request
//!   is made at all, and nothing falls back to plain HTTP or to accepting any certificate.

use std::sync::Mutex;

/// What a network feature reports when the system has no CA certificates.
pub const NO_TRUST_ROOTS: &str = "Secure connections are not available: no trusted CA certificates were found on this computer, so ExploitX cannot verify any server's certificate and sends no request. Install the system's CA certificates (the ca-certificates package on Debian, Ubuntu and Fedora), then try again. Offline features keep working.";

/// Whether the system offers at least one CA certificate where the TLS verifier looks for them
/// (always true on Windows, where Windows' own store is asked during each connection).
pub fn system_roots_available() -> bool {
    #[cfg(all(unix, not(target_os = "android"), not(target_vendor = "apple")))]
    {
        !rustls_native_certs::load_native_certs().certs.is_empty()
    }
    #[cfg(not(all(unix, not(target_os = "android"), not(target_vendor = "apple"))))]
    {
        true
    }
}

/// Builds a client. If that fails because the system has no CA certificates, the error is
/// [`NO_TRUST_ROOTS`]; any other failure names its innermost cause.
pub fn build(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, String> {
    builder.build().map_err(|e| describe_build_error(&e))
}

/// The message for a client that could not be built, also for clients that libraries build (the
/// updater's).
pub fn describe_build_error(e: &reqwest::Error) -> String {
    if !system_roots_available() {
        return NO_TRUST_ROOTS.into();
    }
    let mut cause: &dyn std::error::Error = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    format!("ExploitX could not prepare a network connection: {cause}")
}

type Make = Box<dyn Fn() -> Result<reqwest::Client, String> + Send + Sync>;

/// A client built when it is first needed, so that starting ExploitX never depends on the
/// network stack. A failure is not remembered: once CA certificates are installed, the next request
/// builds the client. A built client is kept and shared (a reqwest client is a handle to a pool).
pub struct LazyClient {
    make: Make,
    client: Mutex<Option<reqwest::Client>>,
}

impl LazyClient {
    pub fn new(make: impl Fn() -> Result<reqwest::Client, String> + Send + Sync + 'static) -> Self {
        Self { make: Box::new(make), client: Mutex::new(None) }
    }

    pub fn get(&self) -> Result<reqwest::Client, String> {
        let mut slot = self.client.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        let c = (self.make)()?;
        *slot = Some(c.clone());
        Ok(c)
    }

    #[cfg(test)]
    pub fn is_built(&self) -> bool {
        self.client.lock().unwrap_or_else(|p| p.into_inner()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// a normal system: the platform's CA certificates are there and a client builds
    #[test]
    fn a_client_builds_with_the_systems_ca_certificates() {
        if !system_roots_available() {
            return; // a build environment without CA certificates: covered by the child test below
        }
        assert!(build(reqwest::Client::builder()).is_ok());
        assert!(crate::ti::http::client(std::time::Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn a_lazy_client_is_built_on_first_use_tried_again_after_a_failure_and_then_kept() {
        let calls = Arc::new(AtomicUsize::new(0));
        let n = calls.clone();
        let lazy = LazyClient::new(move || match n.fetch_add(1, Ordering::SeqCst) {
            0 => Err(NO_TRUST_ROOTS.to_string()),
            _ => reqwest::Client::builder().build().map_err(|e| e.to_string()),
        });
        assert!(!lazy.is_built(), "nothing is built before the first request");
        assert_eq!(lazy.get().unwrap_err(), NO_TRUST_ROOTS);
        assert!(!lazy.is_built(), "a failure is not remembered");
        assert!(lazy.get().is_ok(), "once the certificates are there, the next request builds the client");
        assert!(lazy.get().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the built client is kept");
    }

    #[test]
    fn the_start_up_states_build_no_client() {
        let vt = crate::commands::virustotal::VtState::new();
        let ti = crate::commands::threat_intel::TiState::new();
        assert!(!vt.http.is_built() && !ti.http.is_built());
    }

    // ---- an untrusted certificate is still refused (Mission 11) ----

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let n = body.len();
        let mut out = vec![tag];
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend([0x81, n as u8]);
        } else {
            out.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    /// A self-signed ECDSA P-256 certificate for `localhost`, made for this test (DER), and its key
    /// (PKCS #8). Nothing is stored in the repository.
    fn self_signed_localhost() -> (Vec<u8>, Vec<u8>) {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let ecdsa_sha256 = seq(&[&der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
        let name = seq(&[&der(0x31, &seq(&[&der(0x06, &[0x55, 0x04, 0x03]), &der(0x0c, b"localhost")]))]);
        let time = |t: chrono::DateTime<chrono::Utc>| der(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes());
        let now = chrono::Utc::now();
        let validity = seq(&[&time(now - chrono::Duration::days(1)), &time(now + chrono::Duration::days(30))]);
        let ec_p256 = seq(&[&der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), &der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])]);
        let spki = seq(&[&ec_p256, &der(0x03, &[&[0u8][..], key.public_key().as_ref()].concat())]);
        let san = seq(&[&der(0x06, &[0x55, 0x1d, 0x11]), &der(0x04, &seq(&[&der(0x82, b"localhost")]))]);
        let tbs = seq(&[&der(0xa0, &der(0x02, &[2])), &der(0x02, &[1]), &ecdsa_sha256, &name, &validity, &name, &spki, &der(0xa3, &seq(&[&san]))]);
        let sig = key.sign(&rng, &tbs).unwrap();
        let cert = seq(&[&tbs, &ecdsa_sha256, &der(0x03, &[&[0u8][..], sig.as_ref()].concat())]);
        (cert, pkcs8.as_ref().to_vec())
    }

    /// A TLS server on 127.0.0.1 for `connections` connections; it answers `200 ok` to a client that
    /// completes the handshake.
    fn tls_server(cert: Vec<u8>, key: Vec<u8>, connections: usize) -> (u16, std::thread::JoinHandle<()>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::{Read, Write};
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .unwrap();
        let config = Arc::new(config);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(connections) {
                let Ok(stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config.clone()).unwrap(), stream);
                let mut buf = [0u8; 4096];
                if matches!(tls.read(&mut buf), Ok(n) if n > 0) {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            }
        });
        (port, handle)
    }

    fn chain(e: &reqwest::Error) -> String {
        let mut text = e.to_string();
        let mut cause: &dyn std::error::Error = e;
        while let Some(next) = cause.source() {
            text.push_str(" / ");
            text.push_str(&next.to_string());
            cause = next;
        }
        text
    }

    #[tokio::test]
    async fn an_untrusted_certificate_is_still_refused() {
        let (cert, key) = self_signed_localhost();
        let (port, server) = tls_server(cert.clone(), key, 2);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let url = format!("https://localhost:{port}/");
        // the clients ExploitX builds verify the certificate: a self-signed one is refused
        let client = build(reqwest::Client::builder().no_proxy().resolve("localhost", addr)).unwrap();
        let err = client.get(&url).send().await.expect_err("an untrusted certificate must be refused");
        assert!(chain(&err).to_lowercase().contains("certificate"), "refused for its certificate: {}", chain(&err));
        // control: the same server is reached when its certificate is trusted explicitly
        let trusted = build(reqwest::Client::builder().no_proxy().resolve("localhost", addr).add_root_certificate(reqwest::Certificate::from_der(&cert).unwrap())).unwrap();
        let ok = trusted.get(&url).send().await.unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.text().await.unwrap(), "ok");
        server.join().unwrap();
    }

    // ---- a Linux system without CA certificates (Mission 11) ----
    // rustls-native-certs reads only SSL_CERT_FILE and SSL_CERT_DIR when one is set, so a child
    // process with both pointing at empty places is such a system. A child process keeps the
    // variables away from the other tests, which run in parallel threads of this process.

    #[cfg(all(unix, not(target_os = "android"), not(target_vendor = "apple")))]
    #[test]
    fn without_ca_certificates_cyber_hub_starts_and_says_why_requests_cannot_be_made() {
        let dir = std::env::temp_dir().join(format!("cyberhub-no-ca-{}", std::process::id()));
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        let empty = dir.join("none.pem");
        std::fs::write(&empty, "").unwrap();
        // the system's bundle, for the recovery step
        let bundle = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"].into_iter().find(|p| std::path::Path::new(p).is_file()).unwrap_or("");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["tls_trust::tests::child_without_ca_certificates", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
            .env("CYBERHUB_TLS_CHILD", "1")
            .env("CYBERHUB_TLS_BUNDLE", bundle)
            .env("SSL_CERT_FILE", &empty)
            .env("SSL_CERT_DIR", &certs)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "child failed:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("1 passed"), "the child test did not run:\n{stdout}");
    }

    #[test]
    #[ignore = "run by without_ca_certificates_cyber_hub_starts_and_says_why_requests_cannot_be_made in a child process"]
    fn child_without_ca_certificates() {
        if std::env::var_os("CYBERHUB_TLS_CHILD").is_none() {
            return;
        }
        assert!(!system_roots_available(), "this child must see no CA certificate");
        // building a client fails, with the message that says what to do
        assert_eq!(build(reqwest::Client::builder()).unwrap_err(), NO_TRUST_ROOTS);
        assert_eq!(crate::ti::http::client(std::time::Duration::from_secs(5)).unwrap_err(), NO_TRUST_ROOTS);
        // what start-up builds succeeds: the states that need clients build them only when used
        let vt = crate::commands::virustotal::VtState::new();
        let ti = crate::commands::threat_intel::TiState::new();
        // a request needs the client, and gets the clear error instead of a weaker connection
        assert_eq!(vt.http.get().unwrap_err(), NO_TRUST_ROOTS);
        assert_eq!(ti.http.get().unwrap_err(), NO_TRUST_ROOTS);
        // the updater's message for a client it could not build
        let e = reqwest::Client::builder().build().unwrap_err();
        assert_eq!(crate::updates::classify(&tauri_plugin_updater::Error::Reqwest(e)).message, NO_TRUST_ROOTS);
        // offline work goes on: the database opens and is written
        let db = crate::db::Db::open_in_memory().unwrap();
        db.with(|c| c.execute("INSERT INTO user_preferences (key, value, updated_at) VALUES ('qa.offline', '1', datetime('now'))", []).map_err(Into::into)).unwrap();
        assert_eq!(db.with(|c| c.query_row("SELECT value FROM user_preferences WHERE key = 'qa.offline'", [], |r| r.get::<_, String>(0)).map_err(Into::into)).unwrap(), "1");
        // recovery: once CA certificates are there, the next request builds the client
        let bundle = std::env::var("CYBERHUB_TLS_BUNDLE").unwrap_or_default();
        if bundle.is_empty() {
            println!("no system CA bundle in this environment: recovery not checked");
            return;
        }
        std::env::set_var("SSL_CERT_FILE", &bundle);
        std::env::remove_var("SSL_CERT_DIR");
        assert!(system_roots_available());
        assert!(vt.http.get().is_ok() && ti.http.get().is_ok());
    }
}
