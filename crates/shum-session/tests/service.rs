//! Stopping a profile owner must never open keys or a database it does not hold.
use std::fs::{self, OpenOptions};

#[tokio::test]
async fn stale_endpoint_cleanup_never_opens_keys_or_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let id = "f8067d32e74e4ea4a362e4f4a63f6c7c";
    let profile = dir.path().join(id);
    fs::create_dir(&profile).unwrap();
    let endpoint = profile.join("daemon.json");
    fs::write(&endpoint, b"invalid endpoint").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(profile.join("messages.sqlite.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    assert!(shum_session::service::stop(dir.path(), id).await.is_err());
    assert!(
        endpoint.exists(),
        "a locked database must protect the running service"
    );
    drop(lock);
    shum_session::service::stop(dir.path(), id).await.unwrap();
    assert!(!endpoint.exists());
    // Missing profile registry, key vault and DB would make Profiles::open fail.
    assert!(!profile.join("keys.bin").exists());
    assert!(!profile.join("messages.sqlite").exists());
    shum_session::service::stop(dir.path(), id).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_lock_cannot_prove_an_endpoint_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let id = "f8067d32e74e4ea4a362e4f4a63f6c7c";
    let profile = dir.path().join(id);
    fs::create_dir(&profile).unwrap();
    let endpoint = profile.join("daemon.json");
    fs::write(&endpoint, b"invalid endpoint").unwrap();
    let target = dir.path().join("unrelated-lock");
    fs::write(&target, b"unrelated").unwrap();
    std::os::unix::fs::symlink(&target, profile.join("messages.sqlite.lock")).unwrap();
    assert!(shum_session::service::stop(dir.path(), id).await.is_err());
    assert!(endpoint.exists());
    assert_eq!(fs::read(target).unwrap(), b"unrelated");
}
