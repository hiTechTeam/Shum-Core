//! Launch the daemon as a macOS application, so Bluetooth permission belongs
//! to Shum instead of a terminal which may lack a Bluetooth purpose string.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    process::Command,
};

const PLIST: &str = include_str!("../native/Info.plist");

pub(crate) fn prepare(root: &Path) -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let mut source = File::open(&executable)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    digest.update(PLIST);
    // Keep running versions intact, including their signed bundle metadata.
    // Replacing a live bundle can invalidate macOS's privacy attribution.
    let cache = root.join("services");
    fs::create_dir_all(&cache)?;
    let version = cache.join(hex::encode(digest.finalize()));
    let app = version.join("Shum.app");
    if app.is_dir() {
        return Ok(app);
    }
    let staging = tempfile::tempdir_in(&cache)?;
    let bundle = staging.path().join("Shum.app");
    let contents = bundle.join("Contents");
    fs::create_dir_all(contents.join("MacOS"))?;
    source.rewind()?;
    let binary = contents.join("MacOS/shum");
    let mut destination = File::create(&binary)?;
    std::io::copy(&mut source, &mut destination)?;
    fs::set_permissions(&binary, source.metadata()?.permissions())?;
    drop(destination);
    File::create(contents.join("Info.plist"))?.write_all(PLIST.as_bytes())?;
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--identifier", "org.shum.cli"])
        .arg(&bundle)
        .output()
        .context("Не удалось подписать локальную службу Shum")?;
    if !signed.status.success() {
        bail!(
            "Подпись службы Shum: {}",
            crate::terminal::safe(&String::from_utf8_lossy(&signed.stderr))
        );
    }
    match fs::rename(staging.path(), &version) {
        Ok(()) => {}
        // Concurrent CLI launches can prepare the same immutable bundle.
        Err(_) if app.is_dir() => {}
        Err(error) => return Err(error.into()),
    }
    Ok(app)
}

pub(crate) fn launch(root: &Path, id: &str) -> Result<()> {
    let root = root.canonicalize()?;
    let bundle = prepare(&root)?;
    let log = root.join(id).join("daemon.log");
    let result = Command::new("/usr/bin/open")
        .args(["-n", "-g", "-a"])
        .arg(bundle)
        .arg("--stdout")
        .arg(&log)
        .arg("--stderr")
        .arg(&log)
        .args(["--args", "--data-dir"])
        .arg(&root)
        .args(["--profile", id, "daemon", "--run"])
        .output()
        .context("Не удалось открыть службу Shum через macOS")?;
    if !result.status.success() {
        bail!(
            "Запуск службы Shum: {}",
            crate::terminal::safe(&String::from_utf8_lossy(&result.stderr))
        );
    }
    Ok(())
}
