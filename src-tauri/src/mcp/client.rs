// SPDX-License-Identifier: Apache-2.0
//! Bridge client used by the `cyberhub-mcp` process. Connects lazily, verifies that the peer
//! is the real ExploitX app (mutual HMAC), multiplexes concurrent requests and reconnects
//! after the app restarts.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::BufReader;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};

use super::proto::{self, Auth, AuthOk, BridgeInfo, ClientIdentity, ErrorBody, Hello, Request, Response, MAX_FRAME, PROTOCOL};

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

struct Conn {
    writer: OwnedWriteHalf,
    pending: Pending,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

pub struct BridgeClient {
    dir: Option<PathBuf>,
    identity: std::sync::Mutex<ClientIdentity>,
    conn: Mutex<Option<Conn>>,
    next: AtomicU64,
}

pub fn not_running() -> ErrorBody {
    ErrorBody {
        kind: "unavailable".into(),
        message: "ExploitX is not running or MCP is turned off. Start ExploitX and turn on MCP on its MCP page.".into(),
    }
}

impl BridgeClient {
    pub fn new(identity: ClientIdentity) -> Self {
        Self { dir: proto::bridge_dir(), identity: std::sync::Mutex::new(identity), conn: Mutex::new(None), next: AtomicU64::new(1) }
    }

    pub fn with_dir(dir: PathBuf, identity: ClientIdentity) -> Self {
        Self { dir: Some(dir), identity: std::sync::Mutex::new(identity), conn: Mutex::new(None), next: AtomicU64::new(1) }
    }

    /// Set the self-reported MCP client identity (used for the next connection).
    pub fn set_identity(&self, id: ClientIdentity) {
        if let Ok(mut i) = self.identity.lock() {
            *i = id;
        }
    }

    async fn connect(&self) -> Result<Conn, ErrorBody> {
        let dir = self.dir.clone().ok_or_else(not_running)?;
        let info: BridgeInfo = std::fs::read_to_string(dir.join(proto::INFO_FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).ok_or_else(not_running)?;
        let key = std::fs::read_to_string(dir.join(proto::KEY_FILE)).map_err(|_| not_running())?;
        let key = key.trim().as_bytes().to_vec();
        if info.protocol != PROTOCOL {
            return Err(ErrorBody { kind: "unavailable".into(), message: "ExploitX uses a different bridge protocol; update cyberhub-mcp to match the app.".into() });
        }
        let stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(("127.0.0.1", info.port))).await.map_err(|_| not_running())?.map_err(|_| not_running())?;
        let _ = stream.set_nodelay(true);
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        let auth_failed = || ErrorBody { kind: "unavailable".into(), message: "could not authenticate the ExploitX app; restart ExploitX and try again".into() };

        let hello: Hello = match tokio::time::timeout(Duration::from_secs(5), proto::read_frame(&mut rd, 4096)).await {
            Ok(Ok(Some(l))) => serde_json::from_str(&l).map_err(|_| auth_failed())?,
            _ => return Err(auth_failed()),
        };
        if hello.protocol != PROTOCOL || hello.nonce.len() < 16 || hello.nonce.len() > 128 {
            return Err(auth_failed());
        }
        let nonce = proto::random_hex(16);
        let identity = self.identity.lock().map(|i| i.sanitized()).unwrap_or_default();
        proto::write_frame(&mut wr, &Auth { nonce: nonce.clone(), mac: proto::client_mac(&key, &hello.nonce, &nonce), client: identity }).await.map_err(|_| auth_failed())?;
        let ok: AuthOk = match tokio::time::timeout(Duration::from_secs(5), proto::read_frame(&mut rd, 4096)).await {
            Ok(Ok(Some(l))) => serde_json::from_str(&l).map_err(|_| auth_failed())?,
            _ => return Err(auth_failed()),
        };
        // the app must prove it holds the key too, or this is an impostor on the port
        if !ok.ok || !proto::verify(&key, "server", &nonce, &hello.nonce, &ok.mac) {
            return Err(auth_failed());
        }

        let pending: Pending = Arc::default();
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (p2, a2) = (pending.clone(), alive.clone());
        tokio::spawn(async move {
            while let Ok(Some(line)) = proto::read_frame(&mut rd, MAX_FRAME).await {
                if let Ok(resp) = serde_json::from_str::<Response>(&line) {
                    if let Some(tx) = p2.lock().ok().and_then(|mut m| m.remove(&resp.id)) {
                        let _ = tx.send(resp);
                    }
                }
            }
            a2.store(false, Ordering::Relaxed);
            // fail everything still waiting
            if let Ok(mut m) = p2.lock() {
                m.clear();
            }
        });
        Ok(Conn { writer: wr, pending, alive })
    }

    /// Call a bridge tool. Errors are returned as `ErrorBody` (never panics, never hangs past
    /// `timeout`).
    pub async fn call(&self, tool: &str, arguments: Value, timeout: Duration) -> Result<Value, ErrorBody> {
        self.call_until(tool, arguments, timeout, std::future::pending()).await
    }

    /// `call`, given up when `cancelled` completes (the MCP client cancelled its request): the app
    /// is told to cancel that request's approval if it is still waiting, and the answer is
    /// "cancelled". Work the user already approved goes on in the app.
    pub async fn call_until(&self, tool: &str, arguments: Value, timeout: Duration, cancelled: impl std::future::Future<Output = ()>) -> Result<Value, ErrorBody> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.conn.lock().await;
            if guard.as_ref().is_none_or(|c| !c.alive.load(Ordering::Relaxed)) {
                *guard = Some(self.connect().await?);
            }
            let conn = guard.as_mut().expect("connected");
            conn.pending.lock().map_err(|_| not_running())?.insert(id, tx);
            let req = Request { id, method: "tool".into(), tool: Some(tool.into()), arguments };
            if proto::write_frame(&mut conn.writer, &req).await.is_err() {
                *guard = None;
                return Err(not_running());
            }
        }
        let answer = tokio::select! {
            a = tokio::time::timeout(timeout, rx) => a,
            () = cancelled => {
                let mut guard = self.conn.lock().await;
                if let Some(conn) = guard.as_mut() {
                    if let Ok(mut m) = conn.pending.lock() {
                        m.remove(&id);
                    }
                    let cancel = Request { id: self.next.fetch_add(1, Ordering::Relaxed), method: "cancel".into(), tool: None, arguments: serde_json::json!({ "request": id }) };
                    if proto::write_frame(&mut conn.writer, &cancel).await.is_err() {
                        *guard = None;
                    }
                }
                return Err(ErrorBody { kind: "cancelled".into(), message: "The client cancelled the request.".into() });
            }
        };
        match answer {
            Ok(Ok(resp)) => match (resp.result, resp.error) {
                (_, Some(e)) => Err(e),
                (Some(v), None) => Ok(v),
                (None, None) => Ok(Value::Null),
            },
            Ok(Err(_)) => Err(ErrorBody { kind: "unavailable".into(), message: "ExploitX closed the connection.".into() }),
            Err(_) => {
                if let Some(c) = self.conn.lock().await.as_ref() {
                    if let Ok(mut m) = c.pending.lock() {
                        m.remove(&id);
                    }
                }
                Err(ErrorBody { kind: "timeout".into(), message: format!("ExploitX did not answer within {} s.", timeout.as_secs()) })
            }
        }
    }
}
