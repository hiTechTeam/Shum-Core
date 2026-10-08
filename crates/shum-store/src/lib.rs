//! Encrypted SQLite adapter for Shum, to be implemented from section 09.
//!
//! Each profile has its own keys, database, and conversations. Key retrieval
//! belongs to this adapter and the client, never to `shum-core`.

#![forbid(unsafe_code)]
