//! Bounded reconnecting Nostr connections and signed Shum push requests.

#![forbid(unsafe_code)]

pub mod protocol;
pub mod push;
#[cfg(feature = "native")]
mod relay;
pub use protocol::DEFAULT_RELAYS;
#[cfg(feature = "native")]
pub use relay::{RelayPool, RelayUpdate};

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
    #[cfg(feature = "native")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
