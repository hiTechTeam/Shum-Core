//! A running Shum profile for any client: the engine, encrypted storage,
//! Nostr relays, Bluetooth and push, driven by [`Request`] commands. The
//! session itself is [`machine::Machine`], the same everywhere; native
//! clients run it with [`Session`] (feature `native`), the browser from
//! WebAssembly.
//!
//! Clients own presentation: they translate [`Failure`] texts, render
//! snapshots and decide how the process starts and stops. State keys with a
//! `cli` prefix keep their names so existing profiles open unchanged.

#![forbid(unsafe_code)]

pub mod contact;
pub mod machine;
#[cfg(feature = "native")]
pub mod registration;
#[cfg(feature = "native")]
mod runtime;
#[cfg(feature = "native")]
pub mod service;
pub mod timeline;

use anyhow::Result;
#[cfg(feature = "native")]
pub use runtime::{Command, Reply, Session};
use serde::{Deserialize, Serialize};
use shum_core::packet::ReactionKind;

/// Version of the [`Request`] API. Clients compare it with a running session.
pub const COMMAND_SCHEMA_VERSION: u64 = 3;

/// Why a request failed, in a form each client can present in its own words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Failure {
    /// Source text for the client's translation catalog, or a technical error.
    #[error("{text}")]
    Text { text: String },
    /// The invitation phase does not allow the action; clients say what to do next.
    #[error("invitation phase {phase}")]
    Phase { phase: String },
}
impl Failure {
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }
    /// Keeps a typed failure and turns any other error into its message.
    pub fn from_error(error: anyhow::Error) -> Self {
        match error.downcast::<Failure>() {
            Ok(failure) => failure,
            Err(error) => Self::text(error.to_string()),
        }
    }
}
fn text(text: &'static str) -> anyhow::Error {
    Failure::text(text).into()
}
fn phase(phase: shum_core::rules::Phase) -> anyhow::Error {
    let value = serde_json::to_value(phase).unwrap_or_default();
    Failure::Phase {
        phase: value.as_str().unwrap_or("").into(),
    }
    .into()
}

/// Milliseconds since 1970.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
/// Milliseconds since 1970; the browser has no system clock for Rust.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn now() -> i64 {
    js_sys::Date::now() as i64
}
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| text("Системный генератор случайных чисел недоступен"))?;
    Ok(bytes)
}
pub fn uuid() -> Result<String> {
    let mut bytes = random::<16>()?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let h = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Snapshot,
    /// Seal the profile into a backup file (protocol section 13).
    Backup {
        password: String,
        created_at: String,
    },
    Add {
        link: String,
    },
    Invite {
        contact: String,
    },
    Accept {
        contact: String,
    },
    Decline {
        contact: String,
    },
    Send {
        contact: String,
        text: String,
    },
    Read {
        contact: String,
    },
    Focus {
        contact: Option<String>,
    },
    Typing {
        contact: String,
        active: bool,
    },
    Presence {
        contact: String,
        online: bool,
    },
    Reaction {
        message: String,
        reaction: ReactionKind,
    },
    Clear {
        contact: String,
    },
    Cancel {
        message: String,
    },
    Profile {
        name: Option<String>,
        bio: Option<String>,
        seed: Option<u64>,
    },
    Block {
        contact: String,
        blocked: bool,
    },
    Stop,
}
