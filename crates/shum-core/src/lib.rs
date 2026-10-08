//! Shum protocol core: bytes and events in, actions out.
//!
//! Protocol implementations follow the Swift compatibility vectors in
//! `protocol/vectors`. This crate must not access files, clocks, random-number
//! devices, sockets, Bluetooth adapters, or system key stores. Those inputs
//! belong to the embedding client.

#![forbid(unsafe_code)]
