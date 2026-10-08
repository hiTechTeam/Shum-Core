fn main() {
    println!("cargo:rerun-if-changed=native/Peripheral.swift");
    println!("cargo:rerun-if-changed=native/Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let status = std::process::Command::new("xcrun")
        .args([
            "swiftc",
            "-O",
            "-framework",
            "CoreBluetooth",
            "-module-cache-path",
        ])
        .arg(out.join("swift-cache"))
        .args([
            "native/Peripheral.swift",
            "-Xlinker",
            "-sectcreate",
            "-Xlinker",
            "__TEXT",
            "-Xlinker",
            "__info_plist",
            "-Xlinker",
            "native/Info.plist",
            "-o",
        ])
        .arg(out.join("shum-ble-peripheral"))
        .status()
        .expect("Xcode Command Line Tools are required for CoreBluetooth");
    assert!(
        status.success(),
        "CoreBluetooth peripheral helper failed to compile"
    );
}
