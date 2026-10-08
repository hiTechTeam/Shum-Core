//! Shum protocol core: bytes and events in, actions out.
//!
//! Protocol implementations follow the Swift compatibility vectors in
//! `protocol/vectors`. This crate must not access files, clocks, random-number
//! devices, sockets, Bluetooth adapters, or system key stores. Those inputs
//! belong to the embedding client.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod card;
pub mod crypto;
pub mod invitation;
pub mod noise;
pub mod packet;
pub mod profile;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
pub mod bindings;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("authentication failed")]
    Authentication,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
