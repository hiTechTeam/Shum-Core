#!/bin/sh
# Builds Shum-Core for the iPhone: shum-mobile as ShumCoreFFI.xcframework
# (device and Apple Silicon simulator), zipped with its checksum for a
# Shum-Core release, plus its Swift bindings, written to the folder given as
# the first argument (default: target/ios). Needs the
# aarch64-apple-ios and aarch64-apple-ios-sim Rust targets and Xcode.
set -eu
out=$(mkdir -p "${1:-target/ios}" && cd "${1:-target/ios}" && pwd)
cd "$(dirname "$0")/.."
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$PATH"
export IPHONEOS_DEPLOYMENT_TARGET=16.0
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    cargo build -p shum-mobile --release --target "$target"
done
# The Swift API is read from a Mac build of the same crate.
cargo build -p shum-mobile --release
work=$(mktemp -d)
cargo run -q -p shum-mobile --features bindgen --bin uniffi-bindgen -- \
    generate --library target/release/libshum_mobile.dylib --language swift --out-dir "$work"
mkdir -p "$work/include"
cp "$work/shum_mobileFFI.h" "$work/include/"
cat > "$work/include/module.modulemap" <<MAP
module shum_mobileFFI {
    header "shum_mobileFFI.h"
    export *
}
MAP
rm -rf "$out/ShumCoreFFI.xcframework"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libshum_mobile.a -headers "$work/include" \
    -library target/aarch64-apple-ios-sim/release/libshum_mobile.a -headers "$work/include" \
    -output "$out/ShumCoreFFI.xcframework" >/dev/null
# Debug symbols are not needed to link; without them the archive is a third smaller.
for library in "$out"/ShumCoreFFI.xcframework/*/libshum_mobile.a; do
    xcrun strip -S -x "$library" 2>/dev/null
done
cp "$work/shum_mobile.swift" "$out/"
rm -f "$out/ShumCoreFFI.xcframework.zip"
(cd "$out" && ditto -c -k --keepParent ShumCoreFFI.xcframework ShumCoreFFI.xcframework.zip)
# The iOS app downloads the archive from a Shum-Core release and checks this.
swift package compute-checksum "$out/ShumCoreFFI.xcframework.zip" > "$out/checksum"
git rev-parse HEAD > "$out/SHUM_CORE_REVISION"
rm -rf "$work"
du -sh "$out"/*
