//! Local bridge protocol between the `cyberhub-mcp` stdio server and the running Cyber Hub app.
//!
//! * Transport: TCP on the IPv4 loopback interface only (`127.0.0.1`, random port), opened only
//!   while the user has MCP enabled in Settings. Nothing listens on a public interface.
//! * Discovery: the app writes `bridge.json` (port, pid) and `bridge.key` (a fresh random
//!   256-bit key per session) into `<app data>/mcp/`, which only the user's account can read.
//! * Mutual authentication before any request: the app sends a nonce; the client answers with
//!   HMAC-SHA256(key, "client" ‖ server nonce ‖ client nonce); the app answers with
//!   HMAC-SHA256(key, "server" ‖ client nonce ‖ server nonce). A process without the key can
//!   neither use the bridge nor impersonate the app towards the MCP server.
//! * Framing: one JSON object per line, at most `MAX_FRAME` bytes.

use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL: &str = "cyberhub-bridge/1";
/// Largest accepted frame (requests and responses).
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const INFO_FILE: &str = "bridge.json";
pub const KEY_FILE: &str = "bridge.key";
pub const APP_IDENTIFIER: &str = "dev.cyberhub.workstation";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BridgeInfo {
    pub protocol: String,
    pub port: u16,
    pub pid: u32,
    pub started_at: String,
}

/// Self-reported MCP client identity (from the MCP `initialize` request). Shown to the user
/// as "reported by the client"; never used for authorization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClientIdentity {
    pub name: String,
    pub version: String,
}

impl ClientIdentity {
    pub fn sanitized(&self) -> ClientIdentity {
        // nothing that could reorder, hide or break the text it is shown in (Mission 7)
        let clean = |s: &str, n: usize| s.chars().filter(|c| !crate::util::is_deceptive_char(*c)).take(n).collect::<String>();
        let name = clean(&self.name, 64);
        ClientIdentity { name: if name.trim().is_empty() { "unknown MCP client".into() } else { name }, version: clean(&self.version, 32) }
    }
    pub fn label(&self) -> String {
        let c = self.sanitized();
        if c.version.is_empty() {
            c.name
        } else {
            format!("{} {}", c.name, c.version)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub protocol: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Auth {
    pub nonce: String,
    pub mac: String,
    pub client: ClientIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthOk {
    pub ok: bool,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    /// "tool" | "ping"
    pub method: String,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hexadecimal to bytes. Works on bytes, not `str` slices: the text comes from a client that has
/// not authenticated yet, and slicing a multi-byte character would panic (and abort the app).
fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || b.len() > 256 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let (pairs, _) = b.as_chunks::<2>();
    pairs.iter().map(|[hi, lo]| Some(digit(*hi)? << 4 | digit(*lo)?)).collect()
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).expect("OS random number generator");
    hex(&b)
}

fn mac(key: &[u8], role: &str, a: &str, b: &str) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(role.as_bytes());
    m.update(b"\0");
    m.update(a.as_bytes());
    m.update(b"\0");
    m.update(b.as_bytes());
    m
}

/// Proof that the client knows the key.
pub fn client_mac(key: &[u8], server_nonce: &str, client_nonce: &str) -> String {
    hex(&mac(key, "client", server_nonce, client_nonce).finalize().into_bytes())
}

/// Proof that the server knows the key.
pub fn server_mac(key: &[u8], client_nonce: &str, server_nonce: &str) -> String {
    hex(&mac(key, "server", client_nonce, server_nonce).finalize().into_bytes())
}

/// Constant-time verification.
pub fn verify(key: &[u8], role: &str, a: &str, b: &str, given_hex: &str) -> bool {
    match unhex(given_hex) {
        Some(given) => mac(key, role, a, b).verify_slice(&given).is_ok(),
        None => false,
    }
}

/// Read one frame (line). `Ok(None)` at end of stream; error if the frame is too large or
/// not UTF-8.
pub async fn read_frame<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return if buf.is_empty() { Ok(None) } else { Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated frame")) };
        }
        if let Some(pos) = chunk.iter().position(|b| *b == b'\n') {
            buf.extend_from_slice(&chunk[..pos]);
            r.consume(pos + 1);
            break;
        }
        let n = chunk.len();
        buf.extend_from_slice(chunk);
        r.consume(n);
        if buf.len() > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
        }
    }
    if buf.len() > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    String::from_utf8(buf).map(Some).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame is not UTF-8"))
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> std::io::Result<()> {
    let mut s = serde_json::to_string(value).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if s.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    s.push('\n');
    w.write_all(s.as_bytes()).await?;
    w.flush().await
}

/// `<app data>/mcp`. Matches Tauri's `app_data_dir()` (`dirs::data_dir()/<identifier>`).
/// Debug builds accept `CYBERHUB_DATA_DIR` so tests can use a temporary directory.
pub fn bridge_dir() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Ok(d) = std::env::var("CYBERHUB_DATA_DIR") {
            return Some(PathBuf::from(d).join("mcp"));
        }
    }
    dirs::data_dir().map(|d| d.join(APP_IDENTIFIER).join("mcp"))
}

/// Write a file readable only by the current user (Unix: mode 0600; Windows: the per-user
/// application-data directory is already private to the account).
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, contents.as_bytes())?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mission 7: a client's name cannot carry text-direction, invisible or line-separator
    /// characters into approvals and confirmations.
    #[test]
    fn client_names_are_shown_without_hidden_characters() {
        let id = ClientIdentity { name: "Claude\u{202E}edoC\u{2028}Approved: yes\u{200B}".into(), version: "1\u{2029}2".into() };
        let s = id.sanitized();
        assert_eq!((s.name.as_str(), s.version.as_str()), ("ClaudeedoCApproved: yes", "12"));
        assert_eq!(ClientIdentity { name: "\u{200B}\u{202E}".into(), version: String::new() }.sanitized().name, "unknown MCP client");
    }

    #[test]
    fn mutual_macs_verify_only_with_the_right_key_and_role() {
        let key = b"0123456789abcdef0123456789abcdef";
        let (s, c) = ("server-nonce", "client-nonce");
        let cm = client_mac(key, s, c);
        assert!(verify(key, "client", s, c, &cm));
        assert!(!verify(b"another key another key another k", "client", s, c, &cm));
        // a client proof cannot be replayed as a server proof
        assert!(!verify(key, "server", c, s, &cm));
        assert!(verify(key, "server", c, s, &server_mac(key, c, s)));
        assert!(!verify(key, "client", s, c, "zz"));
        assert!(!verify(key, "client", s, c, ""));
        // multi-byte text of an even length, from a client that has not authenticated: never
        // sliced inside a character
        assert!(!verify(key, "client", s, c, "a€"));
        assert!(!verify(key, "client", s, c, "€€"));
    }

    #[tokio::test]
    async fn frames_are_size_limited() {
        let data = format!("{}\n{{\"a\":1}}\n", "x".repeat(100));
        let mut r = tokio::io::BufReader::new(data.as_bytes());
        assert!(read_frame(&mut r, 50).await.is_err());
        let mut r = tokio::io::BufReader::new(&b"{\"a\":1}\npartial"[..]);
        assert_eq!(read_frame(&mut r, 50).await.unwrap().as_deref(), Some("{\"a\":1}"));
        assert!(read_frame(&mut r, 50).await.is_err(), "truncated frame");
        let mut r = tokio::io::BufReader::new(&b""[..]);
        assert_eq!(read_frame(&mut r, 50).await.unwrap(), None);
    }

    #[test]
    fn client_identity_is_sanitized() {
        let c = ClientIdentity { name: "Evil\nName\u{7}".repeat(20), version: "1.0\r\n".into() };
        let s = c.sanitized();
        assert!(!s.name.contains('\n') && s.name.chars().count() <= 64 && s.version == "1.0");
        assert_eq!(ClientIdentity::default().label(), "unknown MCP client");
    }

    #[test]
    fn requests_reject_unknown_fields() {
        assert!(serde_json::from_str::<Request>(r#"{"id":1,"method":"tool","tool":"x","arguments":{},"approve":true}"#).is_err());
    }
}
