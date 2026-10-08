fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let path = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("native/Info.plist");
        println!("cargo:rerun-if-changed={}", path.display());
        println!(
            "cargo:rustc-link-arg-bin=shum=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            path.display()
        );
    }
}
