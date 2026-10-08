//! Presentation belongs to the client, separate from the protocol core.
#![forbid(unsafe_code)]
pub mod avatar;
pub mod display;
pub mod ipc;
#[cfg(target_os = "macos")]
mod macos;
pub mod onboarding;
pub mod runtime;
pub mod service;
pub mod terminal;
pub mod ui;
