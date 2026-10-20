//! A backup sealed by any client restores on the iPhone: the bridge opens
//! the file, writes the profile's database, and the session runs on it.
use serde_json::Value;
use shum_core::card::Card;
use shum_mobile::{
    backup_summary, open_backup, write_database, MobileKeys, MobileProfile, MobileSession,
};
use shum_store::{empty_state, keys::ProfileKeys};

#[test]
fn a_backup_from_another_client_restores_into_a_new_database() {
    let keys = ProfileKeys::generate().unwrap();
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        "Аня".into(),
        "",
        Some(7),
        1,
    )
    .unwrap();
    let owner = keys.owner_id();
    let mut state = empty_state(&owner);
    state["ownProfileCard"] = serde_json::to_value(&card).unwrap();
    let password = "длинный пароль 1";
    let file =
        shum_store::backup::seal(&state, &keys, "Аня", password, "2026-10-20T12:00:00Z").unwrap();

    let summary = backup_summary(file.clone()).unwrap();
    assert_eq!(summary.profile_name, "Аня");
    assert_eq!(summary.created_at, "2026-10-20T12:00:00Z");
    assert!(open_backup(file.clone(), "неверный пароль".into()).is_err());
    let opened = open_backup(file, password.into()).unwrap();
    assert_eq!(opened.owner_id, owner);
    assert_eq!(opened.keys.noise, keys.noise.expose().to_vec());
    assert_eq!(opened.keys.signing, keys.signing.expose().to_vec());
    assert_eq!(opened.keys.nostr, keys.nostr.expose().to_vec());
    assert_ne!(
        opened.keys.storage,
        keys.storage.expose().to_vec(),
        "a new storage key"
    );

    let folder = std::env::temp_dir().join(format!("shum-mobile-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let database = folder
        .join("restored.sqlite")
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&database);
    write_database(
        database.clone(),
        opened.owner_id.clone(),
        opened.keys.storage.clone(),
        opened.state.clone(),
    )
    .unwrap();
    assert!(
        write_database(
            database.clone(),
            owner.clone(),
            opened.keys.storage.clone(),
            opened.state
        )
        .is_err(),
        "an existing profile is never overwritten"
    );

    let session = MobileSession::open(
        MobileProfile {
            database,
            id: "restored".into(),
            name: opened.name,
            relays: vec!["ws://127.0.0.1:9".into()],
            push: false,
            client: "{}".into(),
            encounter_retention_hours: 0,
        },
        MobileKeys {
            noise: opened.keys.noise,
            signing: opened.keys.signing,
            nostr: opened.keys.nostr,
            storage: opened.keys.storage,
        },
        1_800_000_000_000,
    )
    .unwrap();
    let snapshot: Value = serde_json::from_str(&session.snapshot()).unwrap();
    assert_eq!(snapshot["card"], serde_json::to_value(&card).unwrap());
    std::fs::remove_dir_all(folder).unwrap();
}
