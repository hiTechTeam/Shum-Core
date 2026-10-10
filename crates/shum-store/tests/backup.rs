#![cfg(unix)]
use serde_json::json;
use shum_core::card::Card;
use shum_store::{backup, profiles::Profiles, vault::KeyMode, Error};

const PASSWORD: &str = "пароль-от-копии";
const CREATED: &str = "2026-10-10T18:04:00Z";

/// A profile with its own card, a contact row and device-only relay data.
fn profile_with_history(root: &std::path::Path) -> (Profiles, String, serde_json::Value) {
    let profiles = Profiles::new(root).unwrap();
    let created = profiles.create("Руслан", KeyMode::File).unwrap();
    let mut open = profiles.open(Some(&created.id)).unwrap();
    let card = Card::create(
        &open.keys.noise,
        &open.keys.signing,
        &open.keys.nostr,
        "Руслан".into(),
        "",
        None,
        1,
    )
    .unwrap();
    open.store
        .transaction(|s| {
            s["ownProfileCard"] = serde_json::to_value(&card).unwrap();
            s["futureHeader"] = json!({"kept": true});
            s["seenRelay"] = json!({"relay-event": 1});
            Ok(())
        })
        .unwrap();
    let state = open.store.state().clone();
    (profiles, created.id, state)
}

fn without_device_buckets(mut state: serde_json::Value) -> serde_json::Value {
    state["seenRelay"] = json!({});
    state["relay"] = json!([]);
    state
}

#[test]
fn backup_restores_on_another_device_with_a_new_storage_key() {
    let temp = tempfile::tempdir().unwrap();
    let (profiles, id, state) = profile_with_history(&temp.path().join("a"));
    let open = profiles.open(Some(&id)).unwrap();
    let file = backup::export(&open, PASSWORD, CREATED).unwrap();
    assert!(file.starts_with(b"SHUM-BACKUP-2\n"));
    assert_eq!(backup::summary(&file).unwrap().profile_name, "Руслан");
    assert_eq!(backup::summary(&file).unwrap().created_at, CREATED);

    let other = Profiles::new(temp.path().join("b")).unwrap();
    let restored = backup::restore(&other, &file, PASSWORD, KeyMode::File, false).unwrap();
    assert_eq!(restored.owner_id, open.profile.owner_id);
    assert_eq!(restored.name, "Руслан");
    let copy = other.open(Some(&restored.id)).unwrap();
    assert_eq!(copy.keys.noise.expose(), open.keys.noise.expose());
    assert_eq!(copy.keys.signing.expose(), open.keys.signing.expose());
    assert_eq!(copy.keys.nostr.expose(), open.keys.nostr.expose());
    assert_ne!(copy.keys.storage.expose(), open.keys.storage.expose());
    assert_eq!(copy.store.state(), &without_device_buckets(state));
}

#[test]
fn wrong_password_and_damaged_file_are_rejected_alike() {
    let temp = tempfile::tempdir().unwrap();
    let (profiles, id, _) = profile_with_history(&temp.path().join("a"));
    let file = backup::export(&profiles.open(Some(&id)).unwrap(), PASSWORD, CREATED).unwrap();
    let other = Profiles::new(temp.path().join("b")).unwrap();
    let wrong = backup::restore(&other, &file, "другой-пароль-123", KeyMode::File, false);
    assert!(matches!(
        wrong,
        Err(Error::Core(shum_core::Error::Authentication))
    ));
    let mut damaged = file.clone();
    let at = damaged.len() - 10;
    damaged[at] = if damaged[at] == b'A' { b'B' } else { b'A' };
    let broken = backup::restore(&other, &damaged, PASSWORD, KeyMode::File, false);
    assert!(broken.is_err());
    assert!(
        other.list().unwrap().1.is_empty(),
        "nothing is written on failure"
    );
    assert!(backup::check_password("short").is_err());
}

#[test]
fn restoring_an_existing_identity_needs_explicit_replace() {
    let temp = tempfile::tempdir().unwrap();
    let (profiles, id, _) = profile_with_history(&temp.path().join("a"));
    let file = backup::export(&profiles.open(Some(&id)).unwrap(), PASSWORD, CREATED).unwrap();
    assert!(matches!(
        backup::restore(&profiles, &file, PASSWORD, KeyMode::File, false),
        Err(Error::ProfileExists)
    ));
    let restored = backup::restore(&profiles, &file, PASSWORD, KeyMode::File, true).unwrap();
    let (selected, all) = profiles.list().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, restored.id);
    assert_eq!(selected.as_deref(), Some(restored.id.as_str()));
    assert_ne!(restored.id, id);
}
