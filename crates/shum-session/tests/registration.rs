//! A new profile is checked, signed, selected and holds default settings.
use shum_session::registration::{create, prepare, validate_name, Settings};
use shum_store::{profiles::Profiles, vault::KeyMode};

/// Profile data must be readable by its owner only, as in the real data folder.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

#[test]
fn a_created_profile_is_selected_with_its_name_and_avatar() {
    let dir = private_dir();
    let mut steps = Vec::new();
    let keys = prepare(dir.path(), |step| steps.push(step)).unwrap();
    assert_eq!(steps, [0, 1, 2, 3, 4]);
    let created = create(
        dir.path(),
        "Руслан",
        Some(42),
        KeyMode::File,
        &Settings::default(),
        keys,
    )
    .unwrap();
    assert_eq!(created.card.name, "Руслан");
    assert_eq!(created.card.avatar_seed, Some(42));
    let profiles = Profiles::new(dir.path()).unwrap();
    let (selected, list) = profiles.list().unwrap();
    assert_eq!(selected.as_deref(), Some(created.profile.id.as_str()));
    assert_eq!(list.len(), 1);
    let open = profiles.open(None).unwrap();
    assert_eq!(open.store.state()["ownProfileCard"]["name"], "Руслан");
    assert_eq!(open.store.state()["cliSettings"]["bluetooth"], true);
    // Nothing temporary is left beside the profile.
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".registration-")));
}

#[test]
fn names_are_checked_before_anything_is_written() {
    assert!(validate_name("").is_err());
    assert!(validate_name(" Руслан").is_err());
    assert!(validate_name(&"я".repeat(33)).is_err());
    assert!(validate_name("Руслан").is_ok());
    let dir = private_dir();
    let keys = prepare(dir.path(), |_| {}).unwrap();
    assert!(create(
        dir.path(),
        " ",
        None,
        KeyMode::File,
        &Settings::default(),
        keys
    )
    .is_err());
    assert!(Profiles::new(dir.path())
        .unwrap()
        .list()
        .unwrap()
        .1
        .is_empty());
}
