//! Shum v1 BLE. `mesh` is the link and session machine every client runs,
//! around the tested Bitchat/Noise codecs of shum-core; with the `radio`
//! feature desktop clients also get native GATT I/O (btleplug and a macOS
//! peripheral helper). The iPhone runs `mesh` with its own CoreBluetooth radio.
#![forbid(unsafe_code)]
#[cfg(all(feature = "radio", target_os = "macos"))]
mod macos;
pub mod mesh;
#[cfg(feature = "radio")]
mod radio;
#[cfg(feature = "radio")]
mod service;
#[cfg(feature = "radio")]
pub use service::*;
