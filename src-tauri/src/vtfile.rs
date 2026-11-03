//! VirusTotal file submission.
//!
//! Safety properties (all enforced here, in Rust):
//! * A file is uploaded only after `confirm` resolves to true. Commands pass a native OS dialog
//!   that page script cannot click; nothing touches the network before that.
//! * The user's file is never modified. It is copied into a private snapshot while being
//!   re-hashed; if the content differs from what was hashed at selection, nothing is uploaded.
//!   The snapshot is deleted when the operation ends (success, error or cancellation).
//! * Files up to 32 MB go to `POST /files`; larger ones (≤ 650 MB) to a one-time URL from
//!   `GET /files/upload_url`, which must be a VirusTotal host served over HTTPS.
//! * A configurable size limit is checked before anything else.

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use md5::Md5;
use serde::Serialize;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::ti::http::{self, ApiError};
use crate::vt;

/// `POST /files` limit.
pub const DIRECT_MAX: u64 = 32 * 1024 * 1024;
/// Documented upload-URL limit.
pub const API_MAX: u64 = 650 * 1024 * 1024;
/// Default for the user-configurable upload limit.
pub const DEFAULT_LIMIT_MB: u64 = 32;
/// Files above this are not even hashed.
pub const HASH_MAX: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hash_reader(mut r: impl Read) -> std::io::Result<Hashes> {
    let (mut a, mut b, mut c) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut buf = vec![0u8; 256 * 1024];
    let mut size = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        c.update(&buf[..n]);
        size += n as u64;
    }
    Ok(Hashes { sha256: hex(&a.finalize()), sha1: hex(&b.finalize()), md5: hex(&c.finalize()), size })
}

/// Hash a regular file (symlinks are resolved first; directories and devices are refused).
pub fn hash_file(path: &Path) -> Result<Hashes, String> {
    let real = std::fs::canonicalize(path).map_err(|e| format!("Cannot open the file: {e}"))?;
    let meta = std::fs::metadata(&real).map_err(|e| format!("Cannot read the file: {e}"))?;
    if !meta.is_file() {
        return Err("Only regular files can be analysed.".into());
    }
    if meta.len() > HASH_MAX {
        return Err("The file is larger than 2 GB.".into());
    }
    let f = std::fs::File::open(&real).map_err(|e| format!("Cannot open the file: {e}"))?;
    hash_reader(std::io::BufReader::new(f)).map_err(|e| format!("Cannot read the file: {e}"))
}

/// A private copy that is removed when dropped.
pub struct Snapshot {
    pub path: PathBuf,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn token() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        b.copy_from_slice(&n.to_le_bytes());
    }
    hex(&b)
}

/// Copy `src` into `dir` while hashing; refuse if the content no longer matches `expected`.
pub fn snapshot(src: &Path, dir: &Path, expected: &Hashes) -> Result<Snapshot, UploadError> {
    std::fs::create_dir_all(dir).map_err(|e| UploadError::Io(e.to_string()))?;
    let snap = Snapshot { path: dir.join(format!("vt-upload-{}", token())) };
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(&snap.path).map_err(|e| UploadError::Io(e.to_string()))?;
    let mut input = std::fs::File::open(src).map_err(|e| UploadError::Io(format!("cannot open the file: {e}")))?;
    let mut h = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = input.read(&mut buf).map_err(|e| UploadError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > expected.size {
            return Err(UploadError::Changed);
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| UploadError::Io(e.to_string()))?;
    }
    out.flush().map_err(|e| UploadError::Io(e.to_string()))?;
    if size != expected.size || hex(&h.finalize()) != expected.sha256 {
        return Err(UploadError::Changed);
    }
    Ok(snap)
}

/// Only VirusTotal hosts over HTTPS (the documented example uses http://, which is upgraded).
/// Loopback is accepted only when the debug mock API is active.
pub fn valid_upload_url(raw: &str, allow_loopback: bool) -> Result<url::Url, UploadError> {
    let mut u = url::Url::parse(raw.trim()).map_err(|_| UploadError::BadUploadUrl)?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(UploadError::BadUploadUrl);
    }
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    let vt_host = host == "virustotal.com" || host.ends_with(".virustotal.com");
    if vt_host && u.port().is_none() {
        match u.scheme() {
            "https" => return Ok(u),
            "http" => {
                u.set_scheme("https").map_err(|_| UploadError::BadUploadUrl)?;
                return Ok(u);
            }
            _ => {}
        }
    }
    if allow_loopback && u.scheme() == "http" && (host == "127.0.0.1" || host == "localhost") {
        return Ok(u);
    }
    Err(UploadError::BadUploadUrl)
}

pub fn valid_analysis_id(id: &str) -> bool {
    (1..=256).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || "+/=_:-".contains(c))
}

pub fn analysis_path(id: &str) -> String {
    format!("/analyses/{}", url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>())
}

/// File name sent with the upload: base name only, no control characters, ≤ 200 chars.
pub fn upload_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base.chars().filter(|c| !c.is_control() && *c != '"').take(200).collect();
    if clean.trim().is_empty() {
        "upload.bin".into()
    } else {
        clean
    }
}

pub fn human_size(n: u64) -> String {
    let mb = n as f64 / (1024.0 * 1024.0);
    if n < 1024 {
        format!("{n} bytes")
    } else if mb < 1.0 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{mb:.1} MB")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UploadError {
    TooLarge { size: u64, limit: u64 },
    Cancelled,
    /// the file changed after it was selected and hashed
    Changed,
    BadUploadUrl,
    RateLimited(String),
    Io(String),
    Api(ApiError),
}

impl UploadError {
    pub fn message(&self) -> String {
        match self {
            UploadError::TooLarge { size, limit } => format!(
                "The file is {}; the upload limit is {}. Raise the limit in Settings (VirusTotal accepts up to 650 MB).",
                human_size(*size),
                human_size(*limit)
            ),
            UploadError::Cancelled => "Upload cancelled. Nothing was sent to VirusTotal.".into(),
            UploadError::Changed => "The file changed after it was selected. Select it again; nothing was uploaded.".into(),
            UploadError::BadUploadUrl => "VirusTotal returned an upload address outside virustotal.com; the file was not sent.".into(),
            UploadError::RateLimited(m) => format!("{m} Nothing was uploaded."),
            UploadError::Io(e) => format!("Could not prepare the file: {e}"),
            UploadError::Api(e) => e.message(vt::NAME),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Confirming,
    Preparing,
    Uploading,
    Processing,
}

pub fn confirmation_text(name: &str, h: &Hashes) -> String {
    format!(
        "Upload this file to VirusTotal for analysis?\n\nFile: {name}\nSize: {}\nSHA-256: {}\n\n\
         This is a PUBLIC submission, not a private scan. VirusTotal keeps the file and shares it with \
         its partners and the security community; premium users can download submitted files.\n\n\
         Do not upload sensitive, confidential, proprietary or personal files.\n\n\
         Your original file is not modified. A temporary copy is uploaded and deleted afterwards.",
        human_size(h.size),
        h.sha256
    )
}

pub struct Plan<'a> {
    pub client: &'a reqwest::Client,
    pub base: &'a str,
    pub key: &'a str,
    pub source: &'a Path,
    pub file_name: &'a str,
    pub hashes: &'a Hashes,
    /// user-configured limit in bytes
    pub limit: u64,
    /// threshold for the upload-URL flow (DIRECT_MAX in production)
    pub direct_max: u64,
    pub work_dir: &'a Path,
    pub allow_loopback: bool,
    /// Called once, after the user approved and before anything is sent (rate limiting).
    pub admit: &'a (dyn Fn() -> Result<(), String> + Send + Sync),
}

/// Run the whole submission. Returns the analysis id.
pub async fn upload<C, Fut, P>(plan: Plan<'_>, confirm: C, progress: P, cancel: CancellationToken) -> Result<String, UploadError>
where
    C: FnOnce(String) -> Fut,
    Fut: Future<Output = bool>,
    P: Fn(Phase, u64, u64) + Send + Sync + 'static,
{
    let size = plan.hashes.size;
    let limit = plan.limit.min(API_MAX);
    if size > limit {
        return Err(UploadError::TooLarge { size, limit });
    }
    progress(Phase::Confirming, 0, size);
    if !confirm(confirmation_text(plan.file_name, plan.hashes)).await || cancel.is_cancelled() {
        return Err(UploadError::Cancelled);
    }
    (plan.admit)().map_err(UploadError::RateLimited)?;

    progress(Phase::Preparing, 0, size);
    let (src, dir, expected) = (plan.source.to_path_buf(), plan.work_dir.to_path_buf(), plan.hashes.clone());
    let snap = tokio::task::spawn_blocking(move || snapshot(&src, &dir, &expected)).await.map_err(|e| UploadError::Io(e.to_string()))??;
    if cancel.is_cancelled() {
        return Err(UploadError::Cancelled);
    }

    let progress = Arc::new(progress);
    let work = async {
        let target = if size <= plan.direct_max {
            format!("{}/files", plan.base)
        } else {
            let body = vt::get(plan.client, plan.base, "/files/upload_url", plan.key).await.map_err(UploadError::Api)?;
            let raw = body.get("data").and_then(Value::as_str).ok_or(UploadError::Api(ApiError::Unexpected("no upload URL".into())))?;
            valid_upload_url(raw, plan.allow_loopback)?.to_string()
        };

        let file = tokio::fs::File::open(&snap.path).await.map_err(|e| UploadError::Io(e.to_string()))?;
        let sent = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(0));
        let p = progress.clone();
        let stream = tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024).map(move |chunk| {
            if let Ok(c) = &chunk {
                let now = sent.fetch_add(c.len() as u64, Ordering::Relaxed) + c.len() as u64;
                // at most ~100 events per upload
                if now == size || now - last.load(Ordering::Relaxed) >= (size / 100).max(1) {
                    last.store(now, Ordering::Relaxed);
                    p(Phase::Uploading, now, size);
                }
            }
            chunk
        });
        let part = reqwest::multipart::Part::stream_with_length(reqwest::Body::wrap_stream(stream), size)
            .file_name(upload_name(plan.file_name))
            .mime_str("application/octet-stream")
            .map_err(|e| UploadError::Io(e.to_string()))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let rb = plan.client.post(&target).header("x-apikey", plan.key).timeout(Duration::from_secs(3600)).multipart(form);
        let resp = http::send(rb, plan.key).await.map_err(UploadError::Api)?;
        progress(Phase::Processing, size, size);
        if resp.status != 200 {
            return Err(UploadError::Api(vt::map_error(&resp, plan.key)));
        }
        resp.body
            .pointer("/data/id")
            .and_then(Value::as_str)
            .filter(|id| valid_analysis_id(id))
            .map(str::to_string)
            .ok_or(UploadError::Api(ApiError::Unexpected("no analysis id".into())))
    };

    let result = tokio::select! {
        r = work => r,
        _ = cancel.cancelled() => Err(UploadError::Cancelled),
    };
    drop(snap);
    result
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStatus {
    /// queued | in-progress | completed
    pub status: String,
    pub stats: vt::Stats,
    pub date: Option<i64>,
    pub sha256: Option<String>,
}

pub fn parse_analysis(body: &Value) -> Result<AnalysisStatus, ApiError> {
    let a = body.pointer("/data/attributes").ok_or_else(|| ApiError::Unexpected("missing attributes".into()))?;
    let st = a.get("stats").cloned().unwrap_or(Value::Null);
    let n = |k: &str| st.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
    let status = a.get("status").and_then(Value::as_str).unwrap_or("queued");
    if !matches!(status, "queued" | "in-progress" | "completed") {
        return Err(ApiError::Unexpected(format!("unknown status {}", http::short(status, 30))));
    }
    Ok(AnalysisStatus {
        status: status.to_string(),
        stats: vt::Stats { malicious: n("malicious"), suspicious: n("suspicious"), harmless: n("harmless"), undetected: n("undetected"), timeout: n("timeout") },
        date: a.get("date").and_then(Value::as_i64),
        sha256: body.pointer("/meta/file_info/sha256").and_then(Value::as_str).map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ti::http::mock;
    use std::sync::atomic::AtomicBool;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            let d = std::env::temp_dir().join(format!("cyberhub-vtfile-{}", token()));
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn file(&self, name: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, data).unwrap();
            p
        }
        fn work(&self) -> PathBuf {
            self.0.join("work")
        }
        fn leftovers(&self) -> usize {
            std::fs::read_dir(self.work()).map(|d| d.count()).unwrap_or(0)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn plan<'a>(client: &'a reqwest::Client, base: &'a str, src: &'a Path, h: &'a Hashes, work: &'a Path) -> Plan<'a> {
        Plan { client, base, key: KEY, source: src, file_name: "sample.bin", hashes: h, limit: DIRECT_MAX, direct_max: DIRECT_MAX, work_dir: work, allow_loopback: true, admit: &|| Ok(()) }
    }

    #[test]
    fn hashes_known_vectors() {
        let h = hash_reader(&b"abc"[..]).unwrap();
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.size, 3);
    }

    #[test]
    fn hash_file_refuses_directories() {
        let t = Tmp::new();
        assert!(hash_file(&t.0).is_err());
        assert_eq!(hash_file(&t.file("a.txt", b"abc")).unwrap().md5, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn upload_urls_must_be_virustotal_https() {
        assert_eq!(valid_upload_url("https://www.virustotal.com/_ah/upload/x/", false).unwrap().scheme(), "https");
        assert_eq!(valid_upload_url("http://www.virustotal.com/_ah/upload/x/", false).unwrap().as_str(), "https://www.virustotal.com/_ah/upload/x/");
        for bad in ["https://virustotal.com.evil.net/x", "https://evil.example/x", "https://user:pw@www.virustotal.com/x", "ftp://www.virustotal.com/x", "https://www.virustotal.com:8443/x", "http://127.0.0.1:9/x", "nonsense"] {
            assert!(valid_upload_url(bad, false).is_err(), "{bad}");
        }
        assert!(valid_upload_url("http://127.0.0.1:9/x", true).is_ok());
    }

    #[test]
    fn analysis_ids_and_names_are_sanitized() {
        assert!(valid_analysis_id("NjY0MjRlOTFjMDIyYTkyNDFhYjZjZGFmMzk2ZjNlOTk6MTY2NzQxNDE5Ng=="));
        assert!(!valid_analysis_id("../../etc"));
        assert!(!valid_analysis_id(""));
        assert_eq!(analysis_path("a/b=="), "/analyses/a%2Fb%3D%3D");
        assert_eq!(upload_name("C:\\Users\\me\\secret dir\\report.pdf"), "report.pdf");
        assert_eq!(upload_name("/"), "upload.bin");
    }

    #[test]
    fn parses_analysis_status() {
        let a = parse_analysis(&serde_json::json!({"data": {"type": "analysis", "id": "x", "attributes": {"status": "completed", "date": 1700000000,
            "stats": {"malicious": 3, "suspicious": 0, "harmless": 0, "undetected": 60, "timeout": 1, "type-unsupported": 8}}},
            "meta": {"file_info": {"sha256": "abc"}}})).unwrap();
        assert_eq!((a.status.as_str(), a.stats.malicious, a.sha256.as_deref()), ("completed", 3, Some("abc")));
        assert!(parse_analysis(&serde_json::json!({"data": {"attributes": {"status": "weird"}}})).is_err());
    }

    #[tokio::test]
    async fn nothing_is_uploaded_when_the_user_declines() {
        let t = Tmp::new();
        let src = t.file("sample.bin", b"MZ test payload");
        let h = hash_file(&src).unwrap();
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"type":"analysis","id":"abc"}}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let shown = Arc::new(std::sync::Mutex::new(String::new()));
        let s2 = shown.clone();
        let r = upload(plan(&c, &srv.base, &src, &h, &t.work()), |msg| async move { *s2.lock().unwrap() = msg; false }, |_, _, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(UploadError::Cancelled));
        assert!(srv.seen.lock().unwrap().is_empty(), "no request may be made before approval");
        assert_eq!(t.leftovers(), 0, "no snapshot is created before approval");
        let msg = shown.lock().unwrap().clone();
        assert!(msg.contains("PUBLIC submission") && msg.contains(&h.sha256) && msg.contains("Do not upload sensitive"));
        assert_eq!(std::fs::read(&src).unwrap(), b"MZ test payload", "the original file is untouched");
    }

    #[tokio::test]
    async fn approved_upload_sends_the_file_and_cleans_up() {
        let t = Tmp::new();
        let data = b"MZ test payload for upload".to_vec();
        let src = t.file("sample.bin", &data);
        let h = hash_file(&src).unwrap();
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"type":"analysis","id":"NjY0Mjo="}}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let max_sent = Arc::new(AtomicU64::new(0));
        let ms = max_sent.clone();
        let id = upload(plan(&c, &srv.base, &src, &h, &t.work()), |_| async { true }, move |phase, sent, _| {
            if phase == Phase::Uploading {
                ms.fetch_max(sent, Ordering::Relaxed);
            }
        }, CancellationToken::new())
        .await
        .unwrap();
        assert_eq!(id, "NjY0Mjo=");
        let seen = srv.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].first_line(), "POST /files HTTP/1.1");
        assert_eq!(seen[0].header("x-apikey").as_deref(), Some(KEY));
        assert!(seen[0].header("content-type").unwrap().starts_with("multipart/form-data"));
        let body = String::from_utf8_lossy(&seen[0].body);
        assert!(body.contains("name=\"file\"; filename=\"sample.bin\"") && body.contains("MZ test payload for upload"));
        assert_eq!(max_sent.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(t.leftovers(), 0, "snapshot removed");
        assert_eq!(std::fs::read(&src).unwrap(), data);
    }

    #[tokio::test]
    async fn refuses_files_over_the_limit_before_asking() {
        let t = Tmp::new();
        let src = t.file("big.bin", &[7u8; 64]);
        let h = hash_file(&src).unwrap();
        let srv = mock::serve(vec![]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let asked = Arc::new(AtomicBool::new(false));
        let a2 = asked.clone();
        let work = t.work();
        let mut p = plan(&c, &srv.base, &src, &h, &work);
        p.limit = 10;
        let r = upload(p, |_| async move { a2.store(true, Ordering::Relaxed); true }, |_, _, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(UploadError::TooLarge { size: 64, limit: 10 }));
        assert!(!asked.load(Ordering::Relaxed));
        assert!(srv.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_file_changed_after_selection_is_not_uploaded() {
        let t = Tmp::new();
        let src = t.file("sample.bin", b"original content");
        let h = hash_file(&src).unwrap();
        std::fs::write(&src, b"tampered content").unwrap();
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"id":"x"}}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let r = upload(plan(&c, &srv.base, &src, &h, &t.work()), |_| async { true }, |_, _, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(UploadError::Changed));
        assert!(srv.seen.lock().unwrap().is_empty());
        assert_eq!(t.leftovers(), 0);
    }

    #[tokio::test]
    async fn cancellation_after_approval_sends_nothing_and_cleans_up() {
        let t = Tmp::new();
        let src = t.file("sample.bin", b"payload");
        let h = hash_file(&src).unwrap();
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"id":"x"}}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        let r = upload(plan(&c, &srv.base, &src, &h, &t.work()), move |_| async move { c2.cancel(); true }, |_, _, _| {}, cancel).await;
        assert_eq!(r, Err(UploadError::Cancelled));
        assert!(srv.seen.lock().unwrap().is_empty());
        assert_eq!(t.leftovers(), 0);
    }

    #[tokio::test]
    async fn large_files_use_a_verified_upload_url() {
        let t = Tmp::new();
        let src = t.file("large.bin", &[1u8; 4096]);
        let h = hash_file(&src).unwrap();
        let target = mock::serve(vec![mock::ok(r#"{"data":{"type":"analysis","id":"large-id"}}"#)]);
        let api = mock::serve(vec![mock::ok(&format!(r#"{{"data":"{}/_ah/upload/one-time/"}}"#, target.base))]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let work = t.work();
        let mut p = plan(&c, &api.base, &src, &h, &work);
        p.direct_max = 1024;
        let id = upload(p, |_| async { true }, |_, _, _| {}, CancellationToken::new()).await.unwrap();
        assert_eq!(id, "large-id");
        assert_eq!(api.seen.lock().unwrap()[0].first_line(), "GET /files/upload_url HTTP/1.1");
        let up = target.seen.lock().unwrap()[0].clone();
        assert_eq!(up.first_line(), "POST /_ah/upload/one-time/ HTTP/1.1");
        assert_eq!(up.header("x-apikey").as_deref(), Some(KEY));
        assert!(up.body.len() > 4096);
    }

    #[tokio::test]
    async fn a_foreign_upload_url_is_refused() {
        let t = Tmp::new();
        let src = t.file("large.bin", &[1u8; 4096]);
        let h = hash_file(&src).unwrap();
        let api = mock::serve(vec![mock::ok(r#"{"data":"https://uploads.evil.example/steal/"}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let work = t.work();
        let mut p = plan(&c, &api.base, &src, &h, &work);
        p.direct_max = 1024;
        let r = upload(p, |_| async { true }, |_, _, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(UploadError::BadUploadUrl));
        assert_eq!(api.seen.lock().unwrap().len(), 1);
        assert_eq!(t.leftovers(), 0);
    }

    #[tokio::test]
    async fn a_rate_limit_after_approval_sends_nothing() {
        let t = Tmp::new();
        let src = t.file("sample.bin", b"payload");
        let h = hash_file(&src).unwrap();
        let srv = mock::serve(vec![mock::ok(r#"{"data":{"id":"x"}}"#)]);
        let c = http::client(Duration::from_secs(5)).unwrap();
        let work = t.work();
        let mut p = plan(&c, &srv.base, &src, &h, &work);
        let deny = || Err::<(), String>("Try again in 10 s.".into());
        p.admit = &deny;
        let r = upload(p, |_| async { true }, |_, _, _| {}, CancellationToken::new()).await;
        assert_eq!(r, Err(UploadError::RateLimited("Try again in 10 s.".into())));
        assert!(srv.seen.lock().unwrap().is_empty());
        assert_eq!(t.leftovers(), 0);
    }
}
