use shum_cli::onboarding::{create, Settings};
use shum_store::{
    profiles::Profiles,
    vault::{KeyMode, ProfileKeys},
};
#[test]
fn confirmed_avatar_and_prepared_keys_survive_reopening_without_duplicate_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    let settings = Settings {
        relays: vec!["ws://127.0.0.1:9".into()],
        push_url: None,
    };
    let keys = ProfileKeys::generate().unwrap();
    let owner = keys.owner_id();
    let created = create(&root, "Имя", Some(42), KeyMode::File, &settings, keys).unwrap();
    assert_eq!(created.card.id(), owner);
    assert_eq!(created.card.avatar_seed, Some(42));
    let profiles = Profiles::new(&root).unwrap();
    let open = profiles.open(Some(&created.profile.id)).unwrap();
    assert_eq!(open.store.state()["ownProfileCard"]["avatarSeed"], 42);
    assert_eq!(open.keys.owner_id(), owner);
    drop(open);
    assert!(create(
        &root,
        "Имя",
        Some(99),
        KeyMode::File,
        &settings,
        ProfileKeys::generate().unwrap()
    )
    .is_err());
    assert!(create(
        &root,
        " ",
        Some(99),
        KeyMode::File,
        &settings,
        ProfileKeys::generate().unwrap()
    )
    .is_err());
    let (selected, list) = profiles.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(selected.as_deref(), Some(created.profile.id.as_str()));
    profiles.delete(&created.profile.id).unwrap();
}
