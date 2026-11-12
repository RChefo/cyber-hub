use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

/// Error type returned by every Tauri command. Serialized as `{ kind, message }`
/// so the frontend can render meaningful error states.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{}", db_message(.0))]
    Db(#[from] rusqlite::Error),
    #[error("File system error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Validation(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Scope(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Secure storage error: {0}")]
    Secret(String),
    /// the user declined a native confirmation dialog
    #[error("{0}")]
    Cancelled(String),
    /// a remote API or client-side limiter refused the request for now
    #[error("{0}")]
    RateLimited(String),
    #[error("{0}")]
    Internal(String),
    /// the stored state changed since the client loaded it (optimistic concurrency)
    #[error("{0}")]
    Conflict(String),
}

impl AppError {
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::Db(_) => "database",
            AppError::Io(_) => "io",
            AppError::Validation(_) => "validation",
            AppError::NotFound(_) => "not_found",
            AppError::Scope(_) => "scope",
            AppError::Network(_) => "network",
            AppError::Secret(_) => "secret",
            AppError::Cancelled(_) => "cancelled",
            AppError::RateLimited(_) => "rate_limited",
            AppError::Internal(_) => "internal",
            AppError::Conflict(_) => "conflict",
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("Serialization error: {e}"))
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        let host = e.url().and_then(|u| u.host_str()).map(str::to_string);
        AppError::Network(describe_reqwest(e.without_url(), host.as_deref()))
    }
}

/// A network error for people (Mission 7): what failed, its innermost cause and what to check. The
/// URL is reduced to its host, so a query string, which may carry a key, never reaches the page.
pub fn describe_reqwest(e: reqwest::Error, host: Option<&str>) -> String {
    let site = host.unwrap_or("the service");
    if e.is_builder() {
        // no request was sent: the client could not be set up (no CA certificates, Mission 11)
        return crate::tls_trust::describe_build_error(&e);
    }
    if e.is_timeout() {
        return format!("{site} did not answer in time; check the network connection, or try again later");
    }
    let mut cause: &dyn std::error::Error = &e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    let inner = cause.to_string();
    if e.is_connect() {
        return format!("could not connect to {site} ({inner}); check the network connection or proxy");
    }
    let top = e.to_string();
    if inner == top {
        format!("{top} ({site})")
    } else {
        format!("{top} ({site}: {inner})")
    }
}

impl From<tauri::Error> for AppError {
    fn from(e: tauri::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// A locked database (another program holds a write lock longer than the busy timeout) gets a
/// message that says what to do; other database errors keep SQLite's text.
fn db_message(e: &rusqlite::Error) -> String {
    match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            "The Cyber Hub database is busy because another program is using it (for example a database browser). Nothing was saved. Close the other program and try again.".into()
        }
        _ => format!("Database error: {e}"),
    }
}

pub fn validation(msg: impl Into<String>) -> AppError {
    AppError::Validation(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_database_says_what_to_do() {
        let dir = std::env::temp_dir().join(format!("cyberhub-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let a = rusqlite::Connection::open(&path).unwrap();
        a.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE t (x); BEGIN IMMEDIATE; INSERT INTO t VALUES (1);").unwrap();
        let b = rusqlite::Connection::open(&path).unwrap();
        b.busy_timeout(std::time::Duration::from_millis(50)).unwrap();
        let err = AppError::from(b.execute("INSERT INTO t VALUES (2)", []).unwrap_err());
        assert_eq!(err.kind(), "database");
        assert!(err.to_string().starts_with("The Cyber Hub database is busy"), "{err}");
        let other = AppError::from(rusqlite::Error::QueryReturnedNoRows);
        assert!(other.to_string().starts_with("Database error: "));
        drop((a, b));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod network_tests {
    /// Mission 7: a network error says what to check and never repeats the URL's query (which may
    /// carry a key). The port is closed on this computer, so nothing else is contacted.
    #[tokio::test]
    async fn network_errors_say_what_to_check_without_the_url() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/v1?apiKey=SECRET-KEY-123")).send().await.unwrap_err();
        let msg = super::AppError::from(e).to_string();
        assert!(msg.contains("could not connect to 127.0.0.1") && msg.contains("check the network connection"), "{msg}");
        assert!(!msg.contains("SECRET-KEY-123") && !msg.contains("apiKey"), "{msg}");
    }
}
