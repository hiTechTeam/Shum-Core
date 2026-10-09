//! Authenticated record storage, compatible with iOS spec/09.
//! State is published only after a durable SQLite transaction succeeds.

#![forbid(unsafe_code)]

pub mod codec;
pub mod engine;
mod layout;
pub mod profiles;
mod sqlite;
pub mod vault;
pub use layout::empty_state;
pub use sqlite::{CommitStats, Store};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid encrypted database: {0}")]
    Invalid(&'static str),
    #[error("database belongs to another identity or state version")]
    Identity,
    #[error("database authentication failed")]
    Authentication,
    #[error("profile is already open in another process")]
    Locked,
    #[error("database changed outside this connection; reopen it")]
    Conflict,
    #[error("operating system random source unavailable")]
    Random,
    #[error("system key storage is unavailable or access was denied")]
    Keyring,
    #[error("file key storage requires a Unix filesystem with private permissions")]
    FileKeysUnsupported,
    #[error("secret file or profile directory has unsafe permissions")]
    Permissions,
    #[error("profile not found")]
    ProfileNotFound,
    #[error("profile name is empty, too long or contains controls")]
    ProfileName,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] shum_core::Error),
}
