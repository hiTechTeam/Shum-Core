//! Bounded reconnecting Nostr connections and signed Shum push requests.

#![forbid(unsafe_code)]

pub mod push;
mod relay;
pub use relay::{RelayPool, RelayUpdate, DEFAULT_RELAYS};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid relay or API configuration")]
    Configuration,
    #[error("relay publication timed out or was rejected")]
    Publication,
    #[error("transport queue is full or closed")]
    Queue,
    #[error("random source unavailable")]
    Random,
    #[error("push API returned HTTP {0}")]
    HttpStatus(u16),
    #[error(transparent)]
    Core(#[from] shum_core::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
