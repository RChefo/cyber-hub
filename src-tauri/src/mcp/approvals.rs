// SPDX-License-Identifier: Apache-2.0
//! Pending approvals for sensitive MCP requests.
//!
//! An approval is created by the bridge when an MCP client asks for a sensitive operation. It
//! can only be decided by the human user through ExploitX's own window (a Tauri command
//! that the bridge does not expose), expires after `TTL`, and is cancelled when the client's
//! bridge connection closes. The MCP client can only *read* the status of an approval.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use tokio::sync::oneshot;

use super::catalog::Category;

/// How long a request waits for the user.
pub const TTL: Duration = Duration::from_secs(180);
const MAX_PENDING: usize = 20;
/// Pending requests per client connection, so one client cannot fill the queue.
const MAX_PENDING_PER_CONNECTION: usize = 5;
const MAX_FINISHED: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub label: String,
    pub value: String,
}

/// What the user sees for a pending request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingView {
    pub id: String,
    pub client: String,
    pub connection: u64,
    pub tool: String,
    pub category: Category,
    pub summary: String,
    pub details: Vec<Detail>,
    /// validation ExploitX performed before showing the request
    pub checks: Vec<String>,
    pub project_id: Option<i64>,
    pub created_at: String,
    pub expires_in_secs: u64,
}

/// What the MCP client can read about an approval.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalStatus {
    pub approval_id: String,
    /// pending | approved | denied | expired | cancelled | completed | failed
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Pending {
    view: PendingView,
    /// the bridge request that asked for it, so that the client can cancel exactly that one
    request: u64,
    deadline: Instant,
    tx: Option<oneshot::Sender<Decision>>,
}

/// Requests a client cancelled, remembered per connection (also when the cancellation arrives
/// before the request's approval exists) until the request has been handled. Each connection keeps
/// its newest cancellations up to this number: a client flooding cancellations only loses its own
/// oldest ones, never another client's (Mission 7).
const MAX_CANCELLED_PER_CONNECTION: usize = 256;

#[derive(Default)]
pub struct Approvals {
    pending: Mutex<HashMap<String, Pending>>,
    finished: Mutex<VecDeque<ApprovalStatus>>,
    /// connection → the requests it cancelled, oldest first
    cancelled: Mutex<HashMap<u64, VecDeque<u64>>>,
}

pub struct NewRequest {
    pub connection: u64,
    /// the bridge request id (per connection)
    pub request: u64,
    pub client: String,
    pub tool: String,
    pub category: Category,
    pub summary: String,
    pub details: Vec<Detail>,
    pub checks: Vec<String>,
    pub project_id: Option<i64>,
}

impl Approvals {
    /// Register a request. Returns its ID and a receiver for the decision.
    pub fn request(&self, r: NewRequest) -> Result<(String, oneshot::Receiver<Decision>), String> {
        let mut map = self.pending.lock().map_err(|_| "approval registry poisoned".to_string())?;
        self.expire_locked(&mut map);
        if map.len() >= MAX_PENDING || map.values().filter(|p| p.view.connection == r.connection).count() >= MAX_PENDING_PER_CONNECTION {
            return Err("Too many requests are waiting for approval in ExploitX. Ask the user to review them first.".into());
        }
        let id = format!("apr_{}", super::proto::random_hex(12));
        let (tx, rx) = oneshot::channel();
        let view = PendingView {
            id: id.clone(),
            client: r.client,
            connection: r.connection,
            tool: r.tool,
            category: r.category,
            summary: r.summary,
            details: r.details,
            checks: r.checks,
            project_id: r.project_id,
            created_at: crate::util::now(),
            expires_in_secs: TTL.as_secs(),
        };
        map.insert(id.clone(), Pending { view, request: r.request, deadline: Instant::now() + TTL, tx: Some(tx) });
        Ok((id, rx))
    }

    fn resolve(&self, id: &str, d: Decision) -> bool {
        let entry = self.pending.lock().ok().and_then(|mut m| m.remove(id));
        match entry {
            Some(mut p) => {
                let status = match d {
                    Decision::Approved => "approved",
                    Decision::Denied => "denied",
                    Decision::Expired => "expired",
                    Decision::Cancelled => "cancelled",
                };
                self.record(ApprovalStatus { approval_id: id.to_string(), status: status.into(), result: None, error: None });
                if let Some(tx) = p.tx.take() {
                    let _ = tx.send(d);
                }
                true
            }
            None => false,
        }
    }

    /// The user's decision (called only from ExploitX's own UI).
    pub fn decide(&self, id: &str, approve: bool) -> bool {
        // an overdue request can no longer be approved, even if the expiry sweep has not run
        let overdue = self.pending.lock().ok().and_then(|m| m.get(id).map(|p| Instant::now() >= p.deadline)).unwrap_or(false);
        if overdue {
            self.resolve(id, Decision::Expired);
            return false;
        }
        self.resolve(id, if approve { Decision::Approved } else { Decision::Denied })
    }

    /// Expire overdue requests (also called periodically).
    pub fn expire(&self) -> usize {
        let ids: Vec<String> = match self.pending.lock() {
            Ok(m) => m.iter().filter(|(_, p)| Instant::now() >= p.deadline).map(|(k, _)| k.clone()).collect(),
            Err(_) => return 0,
        };
        ids.iter().filter(|id| self.resolve(id, Decision::Expired)).count()
    }

    fn expire_locked(&self, map: &mut HashMap<String, Pending>) {
        let now = Instant::now();
        let overdue: Vec<String> = map.iter().filter(|(_, p)| now >= p.deadline).map(|(k, _)| k.clone()).collect();
        for id in overdue {
            if let Some(mut p) = map.remove(&id) {
                if let Some(tx) = p.tx.take() {
                    let _ = tx.send(Decision::Expired);
                }
                self.record(ApprovalStatus { approval_id: id, status: "expired".into(), result: None, error: None });
            }
        }
    }

    /// Cancel everything a disconnected client was waiting for.
    pub fn cancel_connection(&self, connection: u64) -> usize {
        if let Ok(mut c) = self.cancelled.lock() {
            c.remove(&connection);
        }
        let ids: Vec<String> = match self.pending.lock() {
            Ok(m) => m.iter().filter(|(_, p)| p.view.connection == connection).map(|(k, _)| k.clone()).collect(),
            Err(_) => return 0,
        };
        ids.iter().filter(|id| self.resolve(id, Decision::Cancelled)).count()
    }

    /// The client cancelled one of its requests (MCP `notifications/cancelled`): its approval is
    /// cancelled if it is still waiting, and remembered so that it cannot be asked for later.
    /// Work the user already approved goes on, as when a client disconnects.
    pub fn cancel_request(&self, connection: u64, request: u64) -> usize {
        if let Ok(mut c) = self.cancelled.lock() {
            let q = c.entry(connection).or_default();
            if !q.contains(&request) {
                q.push_back(request);
                if q.len() > MAX_CANCELLED_PER_CONNECTION {
                    q.pop_front();
                }
            }
        }
        let ids: Vec<String> = match self.pending.lock() {
            Ok(m) => m.iter().filter(|(_, p)| p.view.connection == connection && p.request == request).map(|(k, _)| k.clone()).collect(),
            Err(_) => return 0,
        };
        ids.iter().filter(|id| self.resolve(id, Decision::Cancelled)).count()
    }

    /// Whether the client already cancelled this request.
    pub fn was_cancelled(&self, connection: u64, request: u64) -> bool {
        self.cancelled.lock().map(|c| c.get(&connection).is_some_and(|q| q.contains(&request))).unwrap_or(false)
    }

    /// A request has been handled: its cancellation no longer needs to be remembered.
    pub fn forget_cancelled(&self, connection: u64, request: u64) {
        if let Ok(mut c) = self.cancelled.lock() {
            if let Some(q) = c.get_mut(&connection) {
                q.retain(|r| *r != request);
                if q.is_empty() {
                    c.remove(&connection);
                }
            }
        }
    }

    pub fn cancel_all(&self) -> usize {
        let ids: Vec<String> = self.pending.lock().map(|m| m.keys().cloned().collect()).unwrap_or_default();
        ids.iter().filter(|id| self.resolve(id, Decision::Cancelled)).count()
    }

    pub fn list(&self) -> Vec<PendingView> {
        let now = Instant::now();
        let mut v: Vec<PendingView> = self
            .pending
            .lock()
            .map(|m| {
                m.values()
                    .map(|p| {
                        let mut view = p.view.clone();
                        view.expires_in_secs = p.deadline.saturating_duration_since(now).as_secs();
                        view
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        v
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Store the outcome of an approved operation so the client can read it later.
    pub fn record(&self, s: ApprovalStatus) {
        if let Ok(mut f) = self.finished.lock() {
            f.retain(|x| x.approval_id != s.approval_id);
            f.push_back(s);
            while f.len() > MAX_FINISHED {
                f.pop_front();
            }
        }
    }

    pub fn status(&self, id: &str) -> Option<ApprovalStatus> {
        if self.pending.lock().ok()?.contains_key(id) {
            return Some(ApprovalStatus { approval_id: id.into(), status: "pending".into(), result: None, error: None });
        }
        self.finished.lock().ok()?.iter().find(|s| s.approval_id == id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(conn: u64) -> NewRequest {
        NewRequest { connection: conn, request: 1, client: "test".into(), tool: "cyberhub_run_tool".into(), category: Category::RunTools, summary: "Run nmap".into(), details: vec![], checks: vec![], project_id: Some(1) }
    }

    #[tokio::test]
    async fn approve_and_deny_reach_the_waiting_request() {
        let a = Approvals::default();
        let (id, rx) = a.request(req(1)).unwrap();
        assert_eq!(a.status(&id).unwrap().status, "pending");
        assert!(a.decide(&id, true));
        assert_eq!(rx.await.unwrap(), Decision::Approved);
        assert_eq!(a.status(&id).unwrap().status, "approved");
        assert!(!a.decide(&id, false), "a decision is final");

        let (id2, rx2) = a.request(req(1)).unwrap();
        assert!(a.decide(&id2, false));
        assert_eq!(rx2.await.unwrap(), Decision::Denied);
    }

    /// Mission 7: cancellations are remembered per connection, so a client flooding them cannot make
    /// another client's be forgotten, and an entry goes once its request has been handled.
    #[test]
    fn cancellations_are_remembered_per_connection() {
        let a = Approvals::default();
        for r in 0..2000 {
            a.cancel_request(1, r);
        }
        a.cancel_request(2, 7);
        assert!(a.was_cancelled(2, 7), "another connection's flood does not push it out");
        assert!(a.was_cancelled(1, 1999) && !a.was_cancelled(1, 0), "a connection keeps its newest");
        a.forget_cancelled(2, 7);
        assert!(!a.was_cancelled(2, 7));
        a.cancel_connection(1);
        assert!(!a.was_cancelled(1, 1999));
    }

    #[tokio::test]
    async fn a_cancelled_request_loses_only_its_own_approval() {
        let a = Approvals::default();
        let (_, rx1) = a.request(NewRequest { request: 7, ..req(1) }).unwrap();
        let (keep, _rx2) = a.request(NewRequest { request: 8, ..req(1) }).unwrap();
        let (other, _rx3) = a.request(NewRequest { request: 7, ..req(2) }).unwrap();
        assert_eq!(a.cancel_request(1, 7), 1);
        assert_eq!(rx1.await.unwrap(), Decision::Cancelled);
        let left: Vec<String> = a.list().into_iter().map(|p| p.id).collect();
        assert!(left.contains(&keep) && left.contains(&other) && left.len() == 2, "the same id on another connection is another request");
        // a cancellation that arrives before the approval exists is remembered
        assert_eq!(a.cancel_request(1, 9), 0);
        assert!(a.was_cancelled(1, 9) && !a.was_cancelled(2, 9));
        // and forgotten with the connection
        a.cancel_connection(1);
        assert!(!a.was_cancelled(1, 9) && !a.was_cancelled(1, 7));
    }

    #[tokio::test]
    async fn disconnecting_cancels_only_that_clients_requests() {
        let a = Approvals::default();
        let (_x, rx1) = a.request(req(1)).unwrap();
        let (y, _rx2) = a.request(req(2)).unwrap();
        assert_eq!(a.cancel_connection(1), 1);
        assert_eq!(rx1.await.unwrap(), Decision::Cancelled);
        assert_eq!(a.status(&y).unwrap().status, "pending");
        assert_eq!(a.list().len(), 1);
    }

    #[tokio::test]
    async fn overdue_requests_expire() {
        let a = Approvals::default();
        let (id, rx) = a.request(req(1)).unwrap();
        a.pending.lock().unwrap().get_mut(&id).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        assert!(!a.decide(&id, true), "overdue requests cannot be approved even before the sweep");
        assert_eq!(rx.await.unwrap(), Decision::Expired);
        assert_eq!(a.status(&id).unwrap().status, "expired");
        assert!(!a.decide(&id, true), "an expired request cannot be approved");
    }

    #[test]
    fn the_queue_is_bounded_globally_and_per_client() {
        let a = Approvals::default();
        let mut keep = vec![];
        for _ in 0..MAX_PENDING_PER_CONNECTION {
            keep.push(a.request(req(1)).unwrap());
        }
        assert!(a.request(req(1)).is_err(), "one client cannot fill the queue");
        for c in 2..=(MAX_PENDING as u64) {
            if keep.len() >= MAX_PENDING {
                break;
            }
            keep.push(a.request(req(c)).unwrap());
        }
        assert!(a.request(req(999)).is_err(), "global cap");
    }
}
