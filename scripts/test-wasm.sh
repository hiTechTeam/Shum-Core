#!/bin/sh
# Builds Shum-Core's pure crate for WebAssembly and runs its tests in Node.js.
# Needs the wasm32-wasip1 Rust target, Homebrew llvm (clang) and lld (wasm-ld).
set -eu
cd "$(dirname "$0")/.."
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
# Cargo runs each test from its crate folder, so the runner path is absolute.
export CARGO_TARGET_WASM32_WASIP1_RUNNER="node --no-warnings $(pwd)/scripts/wasi-run.mjs"
export SHUM_WASI_ROOT="$(pwd)"
export CARGO_TARGET_WASM32_WASIP1_LINKER=/opt/homebrew/opt/lld/bin/wasm-ld
export CC_wasm32_wasip1=/opt/homebrew/opt/llvm/bin/clang
export AR_wasm32_wasip1=/opt/homebrew/opt/llvm/bin/llvm-ar
# secp256k1's minimal WebAssembly headers do not declare memmove.
export CFLAGS_wasm32_wasip1="-Dmemmove=__builtin_memmove"
cargo test -p shum-core --target wasm32-wasip1 "$@"
