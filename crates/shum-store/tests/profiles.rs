use serde_json::json;
use shum_store::{profiles::Profiles, vault::KeyMode, Error};
#[cfg(unix)]
use std::fs;

#[cfg(unix)]
#[test]
fn profiles_isolate_all_keys_databases_selection_and_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profiles");
    let profiles = Profiles::new(&root).unwrap();
    let first = profiles.create("Личный", KeyMode::File).unwrap();
    let second = profiles.create("Рабочий", KeyMode::File).unwrap();
    assert_ne!(first.id, second.id);
    assert_ne!(first.owner_id, second.owner_id);
    let mut a = profiles.open(Some(&first.id)).unwrap();
    let b = profiles.open(Some(&second.id)).unwrap();
    for (left, right) in [
        (&a.keys.noise, &b.keys.noise),
        (&a.keys.signing, &b.keys.signing),
        (&a.keys.nostr, &b.keys.nostr),
        (&a.keys.storage, &b.keys.storage),
    ] {
        assert_ne!(left.expose(), right.expose());
    }
    assert_ne!(a.keys.noise.expose(), a.keys.storage.expose());
    assert_ne!(a.keys.signing.expose(), a.keys.storage.expose());
    a.store
        .transaction(|s| {
            s["privateMemo"] = json!("first profile only");
            Ok(())
        })
        .unwrap();
    assert!(b.store.state()["privateMemo"].is_null());
    assert!(matches!(profiles.open(Some(&first.id)), Err(Error::Locked)));
    assert!(matches!(profiles.delete(&first.id), Err(Error::Locked)));
    profiles.select("Рабочий").unwrap();
    assert_eq!(profiles.list().unwrap().0, Some(second.id.clone()));
    assert!(profiles.create("Рабочий", KeyMode::File).is_err());
    assert!(profiles.create("../escape\n", KeyMode::File).is_err());
    drop(a);
    drop(b);
    assert_eq!(profiles.open(None).unwrap().profile.id, second.id);
    let a = profiles.open(Some("Личный")).unwrap();
    assert_eq!(a.store.state()["privateMemo"], "first profile only");
    drop(a);
    profiles.delete("Личный").unwrap();
    assert!(!root.join(&first.id).exists());
    assert_eq!(profiles.list().unwrap().1.len(), 1);
    assert!(profiles.open(Some(&first.id)).is_err());
    profiles.delete("Рабочий").unwrap();
    assert_eq!(profiles.list().unwrap(), (None, vec![]));
}

#[cfg(unix)]
#[test]
fn file_fallback_requires_0600_and_rejects_symlinks_without_regeneration() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profiles");
    let profiles = Profiles::new(&root).unwrap();
    let p = profiles.create("server", KeyMode::File).unwrap();
    let keys = root.join(&p.id).join("keys.bin");
    let original = fs::read(&keys).unwrap();
    assert_eq!(
        fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(profiles.open(None), Err(Error::Permissions)));
    assert_eq!(fs::read(&keys).unwrap(), original);
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    let target = root.join("external-secret");
    fs::rename(&keys, &target).unwrap();
    symlink(&target, &keys).unwrap();
    assert!(matches!(profiles.open(None), Err(Error::Permissions)));
    assert_eq!(fs::read(&target).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn missing_profile_database_is_not_silently_recreated() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profiles");
    let profiles = Profiles::new(&root).unwrap();
    let p = profiles.create("existing", KeyMode::File).unwrap();
    let path = root.join(&p.id).join("messages.sqlite");
    fs::remove_file(&path).unwrap();
    assert!(profiles.open(None).is_err());
    assert!(!path.exists());
}

#[test]
#[ignore = "accesses the real operating system credential store; run explicitly"]
fn native_keyring_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profiles");
    let profiles = Profiles::new(&root).unwrap();
    let profile = profiles
        .create("ephemeral-keyring-test", KeyMode::System)
        .unwrap();
    let result = profiles.open(Some(&profile.id));
    let owner = result.as_ref().map(|p| p.keys.owner_id()).map_err(|_| ());
    drop(result);
    let cleanup = profiles.delete(&profile.id);
    assert_eq!(owner.unwrap(), profile.owner_id);
    cleanup.unwrap();
    assert!(!root.join(profile.id).join("keys.bin").exists());
}
