use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

/// Error type returned by every Tauri command. Serialized as `{ kind, message }`
/// so the frontend can render meaningful error states.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
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
        AppError::Network(e.to_string())
    }
}

impl From<tauri::Error> for AppError {
    fn from(e: tauri::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

pub fn validation(msg: impl Into<String>) -> AppError {
    AppError::Validation(msg.into())
}
