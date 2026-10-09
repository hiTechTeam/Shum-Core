# Shum Core

English · [Русский](README.ru.md)

Rust messaging core for Shum: cryptography, Bluetooth and Nostr transports, and encrypted local storage. Shared protocol code for clients; UI, avatars and QR rendering belong to the clients.

## Status

The current v1 draft is implemented and checked against Swift test vectors. Bluetooth discovery, invitations, messages and read receipts have been tested with an iPhone on macOS. Linux and Windows discovery exists, but GATT server support and platform acceptance are pending.

Multiple devices per profile, history sync and profile relays are planned for v1 stable. Swift and Kotlin bindings use UniFFI; iOS migration is pending. See [Shum Protocol](https://github.com/hiTechTeam/Shum-Protocol).

## Packages

| Package | Purpose |
| :--- | :--- |
| `shum-core` | Protocol, cryptography and state without I/O |
| `shum-transport-nostr` | Relays, subscriptions, delivery and push requests |
| `shum-transport-ble` | Discovery, GATT, Noise and Bluetooth mesh |
| `shum-store` | Encrypted SQLite storage and profile keys |

[Shum CLI](https://github.com/hiTechTeam/Shum-CLI) uses the core directly. Mobile, desktop and browser integration are at different stages of development.

## Build

Rust stable and, for macOS Bluetooth, Xcode Command Line Tools are required.

```sh
git clone --recurse-submodules https://github.com/hiTechTeam/Shum-Core.git
cd Shum-Core
cargo test --workspace --locked --all-features
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Clients should pin the same Git revision for all four packages. Protocol compatibility is pinned through the `protocol/` submodule. Sections 01–09 and their vectors describe the current draft; sections 10–12 describe future v1 stable work.

Strict Ed25519 validation and Noise replay rejection are approved compatibility differences from Swift. Tests involving live networks or the system keychain are excluded from the default run. CI runs manually.

## Documentation

[Core API](docs/core-api.md) · [Storage](docs/storage.md) · [Protocol and vectors](https://github.com/hiTechTeam/Shum-Protocol) · [Issues](https://github.com/hiTechTeam/Shum-Core/issues)

## License

[MIT](LICENSE), copyright 2026 hiTechTeam.
