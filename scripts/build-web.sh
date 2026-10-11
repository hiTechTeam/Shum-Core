#!/bin/sh
# Builds Shum-Core for the browser: shum-web compiled to WebAssembly plus its
# JavaScript bindings, written to the folder given as the first argument
# (default: target/web). Needs the wasm32-unknown-unknown Rust target,
# wasm-bindgen-cli 0.2.129, Homebrew llvm (clang) and lld (wasm-ld); Homebrew
# binaryen (wasm-opt) is optional.
set -eu
# The output folder is relative to where the script is called from.
out=$(mkdir -p "${1:-target/web}" && cd "${1:-target/web}" && pwd)
cd "$(dirname "$0")/.."
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER=/opt/homebrew/opt/lld/bin/wasm-ld
export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
export AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
# secp256k1's minimal WebAssembly headers do not declare memmove.
export CFLAGS_wasm32_unknown_unknown="-Dmemmove=__builtin_memmove"
cargo build -p shum-web --target wasm32-unknown-unknown --profile web
wasm-bindgen --target web --out-dir "$out" target/wasm32-unknown-unknown/web/shum_web.wasm
# Binaryen shrinks it further when installed (brew install binaryen). The
# features are the ones Rust enables for wasm32 by default.
if command -v wasm-opt >/dev/null; then
    wasm-opt -Oz --enable-bulk-memory --enable-mutable-globals --enable-nontrapping-float-to-int \
        --enable-sign-ext --enable-reference-types --enable-multivalue \
        -o "$out/shum_web_bg.wasm" "$out/shum_web_bg.wasm"
fi
ls -l "$out"
