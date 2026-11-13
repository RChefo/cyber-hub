// SPDX-License-Identifier: Apache-2.0
//! The bridge listener inside the running ExploitX app (see `proto.rs` for the protocol).
//! It authenticates `cyberhub-mcp` processes and hands each request to a `Dispatcher`
//! (`ops::AppDispatcher` in the app), which runs it through ExploitX's existing commands.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use super::approvals::Approvals;
use super::proto::{self, Auth, AuthOk, BridgeInfo, ClientIdentity, ErrorBody, Hello, Request, Response, MAX_FRAME, PROTOCOL};

/// Simultaneous authenticated bridge connections (MCP server processes).
pub const MAX_CONNECTIONS: usize = 8;
/// Open sockets including those still authenticating.
pub const MAX_SOCKETS: usize = 16;
/// Requests processed at the same time per connection.
pub const MAX_IN_FLIGHT: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct ConnCtx {
    pub id: u64,
    pub client: ClientIdentity,
    /// the bridge request being served (0 outside a request)
    pub request: u64,
}

pub type DispatchFuture = Pin<Box<dyn Future<Output = Result<Value, ErrorBody>> + Send>>;

pub trait Dispatcher: Send + Sync + 'static {
    fn call(&self, conn: ConnCtx, tool: String, arguments: Value) -> DispatchFuture;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnView {
    pub id: u64,
    /// self-reported by the MCP client ("name version")
    pub client: String,
    /// self-reported name and version, shown as such; never used for authorization
    pub client_name: String,
    pub client_version: String,
    pub connected_at: String,
    pub requests: u64,
    pub last_request_at: Option<String>,
}

struct Active {
    port: u16,
    started_at: String,
    dir: PathBuf,
    accept: tauri::async_runtime::JoinHandle<()>,
    tasks: Arc<Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>>,
}

#[derive(Default)]
pub struct Bridge {
    active: Mutex<Option<Active>>,
    conns: Arc<Mutex<HashMap<u64, ConnView>>>,
    next_id: Arc<AtomicU64>,
    /// open sockets, authenticated or not
    sockets: Arc<std::sync::atomic::AtomicUsize>,
    pub approvals: Arc<Approvals>,
}

/// Decrements the socket count when a connection task ends (also when aborted).
struct SocketGuard(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Bridge {
    /// Start listening on 127.0.0.1 and publish the connection files in `dir`. Returns the
    /// bridge info and whether it was newly started. The whole start runs under the state lock
    /// (no awaits), so concurrent starts cannot leave an orphaned listener.
    pub fn start(&self, dir: PathBuf, dispatcher: Arc<dyn Dispatcher>) -> Result<(BridgeInfo, bool), String> {
        let mut active = self.active.lock().map_err(|e| e.to_string())?;
        if let Some(a) = active.as_ref() {
            return Ok((BridgeInfo { protocol: PROTOCOL.into(), port: a.port, pid: std::process::id(), started_at: a.started_at.clone() }, false));
        }
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("cannot open the local bridge: {e}"))?;
        std_listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = std_listener.local_addr().map_err(|e| e.to_string())?.port();
        let key_hex = proto::random_hex(32);
        let key: Arc<Vec<u8>> = Arc::new(key_hex.as_bytes().to_vec());
        let info = BridgeInfo { protocol: PROTOCOL.into(), port, pid: std::process::id(), started_at: crate::util::now() };
        proto::write_private(&dir.join(proto::KEY_FILE), &key_hex).map_err(|e| format!("cannot write the bridge key: {e}"))?;
        proto::write_private(&dir.join(proto::INFO_FILE), &serde_json::to_string(&info).map_err(|e| e.to_string())?)
            .map_err(|e| format!("cannot write the bridge info: {e}"))?;

        let tasks: Arc<Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>> = Arc::default();
        let (conns, next_id, approvals, tasks2, sockets) = (self.conns.clone(), self.next_id.clone(), self.approvals.clone(), tasks.clone(), self.sockets.clone());
        let accept = tauri::async_runtime::spawn(async move {
            let listener = match TcpListener::from_std(std_listener) {
                Ok(l) => l,
                Err(_) => return,
            };
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => {
                        // e.g. out of file handles: back off instead of spinning
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                // loopback only; anything else is dropped immediately
                if !peer.ip().is_loopback() {
                    continue;
                }
                // cap every open socket, including ones still authenticating
                if sockets.fetch_add(1, Ordering::Relaxed) >= MAX_SOCKETS || conns.lock().map(|c| c.len()).unwrap_or(MAX_CONNECTIONS) >= MAX_CONNECTIONS {
                    sockets.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                let guard = SocketGuard(sockets.clone());
                let id = next_id.fetch_add(1, Ordering::Relaxed) + 1;
                let h = tauri::async_runtime::spawn(serve_connection(stream, id, key.clone(), dispatcher.clone(), conns.clone(), approvals.clone(), guard));
                if let Ok(mut t) = tasks2.lock() {
                    t.retain(|x| !x.inner().is_finished());
                    t.push(h);
                }
            }
        });
        *active = Some(Active { port, started_at: info.started_at.clone(), dir, accept, tasks });
        Ok((info, true))
    }

    /// Stop listening, drop every connection, cancel pending approvals and remove the files.
    pub fn stop(&self) {
        let active = self.active.lock().ok().and_then(|mut a| a.take());
        if let Some(a) = active {
            a.accept.abort();
            if let Ok(mut t) = a.tasks.lock() {
                for h in t.drain(..) {
                    h.abort();
                }
            }
            let _ = std::fs::remove_file(a.dir.join(proto::KEY_FILE));
            let _ = std::fs::remove_file(a.dir.join(proto::INFO_FILE));
        }
        if let Ok(mut c) = self.conns.lock() {
            c.clear();
        }
        self.approvals.cancel_all();
    }

    pub fn is_connected(&self, id: u64) -> bool {
        self.conns.lock().map(|c| c.contains_key(&id)).unwrap_or(false)
    }

    pub fn info(&self) -> Option<(u16, String)> {
        self.active.lock().ok()?.as_ref().map(|a| (a.port, a.started_at.clone()))
    }

    pub fn connections(&self) -> Vec<ConnView> {
        let mut v: Vec<ConnView> = self.conns.lock().map(|c| c.values().cloned().collect()).unwrap_or_default();
        v.sort_by_key(|c| c.id);
        v
    }
}

async fn serve_connection(
    stream: TcpStream,
    id: u64,
    key: Arc<Vec<u8>>,
    dispatcher: Arc<dyn Dispatcher>,
    conns: Arc<Mutex<HashMap<u64, ConnView>>>,
    approvals: Arc<Approvals>,
    _guard: SocketGuard,
) {
    let _ = stream.set_nodelay(true);
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // ── mutual authentication
    let server_nonce = proto::random_hex(16);
    if proto::write_frame(&mut wr, &Hello { protocol: PROTOCOL.into(), nonce: server_nonce.clone() }).await.is_err() {
        return;
    }
    let auth: Option<Auth> = match tokio::time::timeout(HANDSHAKE_TIMEOUT, proto::read_frame(&mut rd, 4096)).await {
        Ok(Ok(Some(line))) => serde_json::from_str(&line).ok(),
        _ => None,
    };
    let Some(auth) = auth.filter(|a| a.nonce.len() >= 16 && a.nonce.len() <= 128 && proto::verify(&key, "client", &server_nonce, &a.nonce, &a.mac)) else {
        let _ = proto::write_frame(&mut wr, &AuthOk { ok: false, mac: String::new() }).await;
        return;
    };
    if proto::write_frame(&mut wr, &AuthOk { ok: true, mac: proto::server_mac(&key, &auth.nonce, &server_nonce) }).await.is_err() {
        return;
    }
    let client = auth.client.sanitized();
    if let Ok(mut c) = conns.lock() {
        c.insert(id, ConnView { id, client: client.label(), client_name: client.name.clone(), client_version: client.version.clone(), connected_at: crate::util::now(), requests: 0, last_request_at: None });
    }

    // ── requests
    let (tx, mut rx) = mpsc::channel::<Response>(64);
    let writer = tauri::async_runtime::spawn(async move {
        while let Some(resp) = rx.recv().await {
            if proto::write_frame(&mut wr, &resp).await.is_err() {
                break;
            }
        }
    });
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let ctx = ConnCtx { id, client, request: 0 };
    // request tasks belong to this connection: dropping the set (disconnect, MCP turned off)
    // aborts every request still being processed
    let mut inflight = tokio::task::JoinSet::new();
    loop {
        if tx.is_closed() {
            break; // the writer failed: the peer cannot receive answers any more
        }
        let line = match proto::read_frame(&mut rd, MAX_FRAME).await {
            Ok(Some(l)) => l,
            _ => break, // closed, oversized or malformed stream: drop the connection
        };
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => break,
        };
        // the client cancelled one of its requests: answered at once, ahead of the requests it may
        // be cancelling (they may hold every in-flight slot while they wait for the user)
        if req.method == "cancel" {
            let n = req.arguments.get("request").and_then(Value::as_u64).map_or(0, |r| approvals.cancel_request(id, r));
            if tx.send(Response { id: req.id, result: Some(serde_json::json!({ "cancelled": n })), error: None }).await.is_err() {
                break;
            }
            continue;
        }
        if let Ok(mut c) = conns.lock() {
            if let Some(v) = c.get_mut(&id) {
                v.requests += 1;
                v.last_request_at = Some(crate::util::now());
            }
        }
        // backpressure: at most MAX_IN_FLIGHT requests per connection are admitted
        let Ok(permit) = limit.clone().acquire_owned().await else { break };
        while inflight.try_join_next().is_some() {}
        let (tx, dispatcher, ctx) = (tx.clone(), dispatcher.clone(), ConnCtx { request: req.id, ..ctx.clone() });
        inflight.spawn(async move {
            let _permit = permit;
            let mut resp = match req.method.as_str() {
                "ping" => Response { id: req.id, result: Some(serde_json::json!({ "pong": true })), error: None },
                "tool" => match req.tool {
                    Some(tool) => match dispatcher.call(ctx, tool, req.arguments).await {
                        Ok(v) => Response { id: req.id, result: Some(v), error: None },
                        Err(e) => Response { id: req.id, result: None, error: Some(e) },
                    },
                    None => Response { id: req.id, result: None, error: Some(ErrorBody { kind: "invalid_request".into(), message: "missing tool".into() }) },
                },
                _ => Response { id: req.id, result: None, error: Some(ErrorBody { kind: "invalid_request".into(), message: "unknown method".into() }) },
            };
            // never let one oversized result break the connection
            if serde_json::to_string(&resp).map(|s| s.len() + 1 > MAX_FRAME).unwrap_or(true) {
                resp = Response { id: resp.id, result: None, error: Some(ErrorBody { kind: "too_large".into(), message: "The result is too large; narrow the request (for example a smaller limit or tail).".into() }) };
            }
            let _ = tx.send(resp).await;
        });
    }
    drop(inflight);
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    if let Ok(mut c) = conns.lock() {
        c.remove(&id);
    }
    approvals.cancel_connection(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::client::BridgeClient;
    use serde_json::json;

    struct Echo;
    impl Dispatcher for Echo {
        fn call(&self, conn: ConnCtx, tool: String, arguments: Value) -> DispatchFuture {
            Box::pin(async move {
                if tool == "slow" {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                if tool == "fail" {
                    return Err(ErrorBody { kind: "validation".into(), message: "bad".into() });
                }
                Ok(json!({ "tool": tool, "args": arguments, "client": conn.client.name, "conn": conn.id }))
            })
        }
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("cyberhub-bridge-{}", proto::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn authenticated_clients_can_call_and_requests_run_concurrently() {
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        let client = Arc::new(BridgeClient::with_dir(dir.clone(), ClientIdentity { name: "Test client".into(), version: "1".into() }));
        let r = client.call("cyberhub_list_projects", json!({"a": 1}), Duration::from_secs(5)).await.unwrap();
        assert_eq!(r["client"], "Test client");
        assert_eq!(r["args"]["a"], 1);
        // a failing request does not affect others
        assert_eq!(client.call("fail", json!({}), Duration::from_secs(5)).await.unwrap_err().kind, "validation");
        // concurrent requests are multiplexed on one connection
        let started = std::time::Instant::now();
        let calls: Vec<_> = (0..6).map(|i| { let c = client.clone(); tokio::spawn(async move { c.call("slow", json!({"i": i}), Duration::from_secs(5)).await }) }).collect();
        for (i, h) in calls.into_iter().enumerate() {
            assert_eq!(h.await.unwrap().unwrap()["args"]["i"], i);
        }
        assert!(started.elapsed() < Duration::from_millis(1500), "requests ran in parallel");
        assert_eq!(bridge.connections().len(), 1);
        bridge.stop();
        assert!(!dir.join(proto::KEY_FILE).exists(), "key removed on stop");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Asks for the user's approval the way the app's operations do, and answers with the decision.
    struct Asks(Arc<crate::mcp::approvals::Approvals>);
    impl Dispatcher for Asks {
        fn call(&self, conn: ConnCtx, tool: String, _arguments: Value) -> DispatchFuture {
            let approvals = self.0.clone();
            Box::pin(async move {
                if tool != "ask" {
                    return Ok(json!({ "tool": tool }));
                }
                let new = crate::mcp::approvals::NewRequest { connection: conn.id, request: conn.request, client: "x".into(), tool, category: crate::mcp::catalog::Category::LocalWrite, summary: String::new(), details: vec![], checks: vec![], project_id: None };
                let (_, rx) = approvals.request(new).map_err(|m| ErrorBody { kind: "busy".into(), message: m })?;
                Ok(json!({ "decision": format!("{:?}", rx.await.unwrap_or(crate::mcp::approvals::Decision::Cancelled)) }))
            })
        }
    }

    /// Mission 6: an MCP client that cancels a call (notifications/cancelled) cancels its approval
    /// in the app, and only that one; the connection and the client's other requests go on.
    #[tokio::test]
    async fn a_cancelled_call_cancels_its_approval_in_the_app() {
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Asks(bridge.approvals.clone()))).unwrap();
        let client = Arc::new(BridgeClient::with_dir(dir.clone(), ClientIdentity::default()));
        // two calls wait for the user; the client gives up on the first one only
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let c1 = client.clone();
        let first = tokio::spawn(async move { c1.call_until("ask", json!({}), Duration::from_secs(10), async { let _ = cancel_rx.await; }).await });
        let c2 = client.clone();
        let second = tokio::spawn(async move { c2.call("ask", json!({}), Duration::from_secs(10)).await });
        let waiting = || bridge.approvals.list().len();
        for _ in 0..50 {
            if waiting() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(waiting(), 2, "both requests reached the user");
        cancel_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap_err().kind, "cancelled");
        for _ in 0..50 {
            if waiting() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let left = bridge.approvals.list();
        assert_eq!(left.len(), 1, "only the cancelled request left the Approval Center");
        // the other request is still answered when the user decides
        assert!(bridge.approvals.decide(&left[0].id, true));
        assert_eq!(second.await.unwrap().unwrap()["decision"], "Approved");
        // and the connection still serves calls
        assert_eq!(client.call("other", json!({}), Duration::from_secs(5)).await.unwrap()["tool"], "other");
        assert_eq!(bridge.connections().len(), 1);
        bridge.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_wrong_key_is_rejected_and_the_app_is_authenticated() {
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        // a client holding a different key cannot call
        let good = std::fs::read_to_string(dir.join(proto::KEY_FILE)).unwrap();
        std::fs::write(dir.join(proto::KEY_FILE), "00".repeat(32)).unwrap();
        let bad = BridgeClient::with_dir(dir.clone(), ClientIdentity::default());
        assert!(bad.call("cyberhub_get_status", json!({}), Duration::from_secs(3)).await.is_err());
        assert!(bridge.connections().is_empty());
        std::fs::write(dir.join(proto::KEY_FILE), good).unwrap();

        // an impostor listening on the advertised port without the key is detected by the client
        let impostor = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = impostor.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = impostor.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            proto::write_frame(&mut w, &Hello { protocol: PROTOCOL.into(), nonce: "a".repeat(32) }).await.unwrap();
            let _ = proto::read_frame(&mut r, 4096).await;
            proto::write_frame(&mut w, &AuthOk { ok: true, mac: "00".repeat(32) }).await.unwrap();
        });
        let mut info: BridgeInfo = serde_json::from_str(&std::fs::read_to_string(dir.join(proto::INFO_FILE)).unwrap()).unwrap();
        info.port = port;
        std::fs::write(dir.join(proto::INFO_FILE), serde_json::to_string(&info).unwrap()).unwrap();
        let c = BridgeClient::with_dir(dir.clone(), ClientIdentity::default());
        let e = c.call("cyberhub_get_status", json!({}), Duration::from_secs(3)).await.unwrap_err();
        assert!(e.message.contains("could not authenticate"), "{}", e.message);
        bridge.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn starting_twice_keeps_one_listener() {
        let dir = tmp();
        let bridge = Bridge::default();
        let (a, first) = bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        let (b, second) = bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        assert!(first && !second);
        assert_eq!(a.port, b.port);
        bridge.stop();
        assert!(bridge.info().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn oversized_results_become_errors_and_the_connection_survives() {
        struct Big;
        impl Dispatcher for Big {
            fn call(&self, _c: ConnCtx, tool: String, _a: Value) -> DispatchFuture {
                Box::pin(async move { if tool == "big" { Ok(json!("x".repeat(MAX_FRAME + 10))) } else { Ok(json!("ok")) } })
            }
        }
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Big)).unwrap();
        let client = BridgeClient::with_dir(dir.clone(), ClientIdentity::default());
        assert_eq!(client.call("big", json!({}), Duration::from_secs(5)).await.unwrap_err().kind, "too_large");
        assert_eq!(client.call("small", json!({}), Duration::from_secs(5)).await.unwrap(), json!("ok"));
        bridge.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unauthenticated_sockets_are_capped() {
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        let (port, _) = bridge.info().unwrap();
        // hold many unauthenticated sockets open
        let mut held = vec![];
        for _ in 0..(MAX_SOCKETS + 4) {
            held.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(bridge.sockets.load(Ordering::Relaxed) <= MAX_SOCKETS);
        drop(held);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // after they close, a real client gets in
        let client = BridgeClient::with_dir(dir.clone(), ClientIdentity::default());
        assert!(client.call("cyberhub_get_status", json!({}), Duration::from_secs(8)).await.is_ok());
        bridge.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disconnects_and_oversized_frames_close_only_that_connection() {
        use tokio::io::AsyncWriteExt;
        let dir = tmp();
        let bridge = Bridge::default();
        bridge.start(dir.clone(), Arc::new(Echo)).unwrap();
        let (port, _) = bridge.info().unwrap();
        // unauthenticated garbage is dropped
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(&vec![b'x'; 10_000]).await.unwrap();
        drop(s);
        // a pending approval of a client is cancelled when it disconnects
        let (_id, rx) = bridge
            .approvals
            .request(crate::mcp::approvals::NewRequest { connection: 99, request: 1, client: "x".into(), tool: "t".into(), category: crate::mcp::catalog::Category::RunTools, summary: String::new(), details: vec![], checks: vec![], project_id: None })
            .unwrap();
        bridge.approvals.cancel_connection(99);
        assert_eq!(rx.await.unwrap(), crate::mcp::approvals::Decision::Cancelled);
        // a well-behaved client still works
        let client = BridgeClient::with_dir(dir.clone(), ClientIdentity::default());
        assert!(client.call("cyberhub_get_status", json!({}), Duration::from_secs(3)).await.is_ok());
        bridge.stop();
        // after stop, calls fail cleanly
        assert!(client.call("cyberhub_get_status", json!({}), Duration::from_secs(3)).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
