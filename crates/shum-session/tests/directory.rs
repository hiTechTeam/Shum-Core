//! Encounters, pins and the address book, as the iOS app keeps them in the
//! profile state. Runs natively and in WebAssembly (scripts/test-wasm.sh).
use serde_json::json;
use shum_core::{card::Card, crypto::Secret32};
use shum_session::directory::*;
use std::collections::HashSet;

fn card(byte: u8, name: &str) -> Card {
    let key = |b: u8| Secret32::new([b; 32]);
    Card::create(
        &key(byte),
        &key(byte + 1),
        &key(byte + 2),
        name.into(),
        "",
        Some(7),
        1,
    )
    .unwrap()
}
const NOW: i64 = 1_800_000_000_000;
const DAY: i64 = DEFAULT_RETENTION_MS;

#[test]
fn encounters_are_recorded_once_a_minute_and_kept_a_day() {
    let mut state = json!({});
    let anya = card(10, "Аня");
    assert!(record_encounter(&mut state, &anya, NOW, DAY));
    assert!(
        !record_encounter(&mut state, &anya, NOW + 30_000, DAY),
        "same minute"
    );
    assert!(record_encounter(&mut state, &anya, NOW + 61_000, DAY));
    let list = encounters(&state, &HashSet::new(), NOW + 61_000, DAY);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["seenCount"], 2);
    assert_eq!(list[0]["viewed"], false);
    assert_eq!(list[0]["firstSeen"], NOW);
    // Stored as the iOS app stores dates: seconds since 2001.
    assert!(
        (state["encounters"][0]["firstSeen"].as_f64().unwrap()
            - (NOW as f64 / 1000.0 - 978_307_200.0))
            .abs()
            < 0.001
    );

    view_encounters(&mut state, Some(&anya.id()));
    assert_eq!(
        encounters(&state, &HashSet::new(), NOW, DAY)[0]["viewed"],
        true
    );
    assert!(
        encounters(&state, &HashSet::new(), NOW + 61_000 + DAY + 1, DAY).is_empty(),
        "a day later"
    );
    let blocked: HashSet<String> = [anya.id()].into();
    assert!(encounters(&state, &blocked, NOW, DAY).is_empty());

    // Seen again after a day, it is new again.
    assert!(record_encounter(&mut state, &anya, NOW + 61_000 + DAY, DAY));
    assert_eq!(
        encounters(&state, &HashSet::new(), NOW + 61_000 + DAY, DAY)[0]["viewed"],
        false
    );
}

#[test]
fn other_keys_under_a_known_shum_id_are_refused() {
    let mut state = json!({});
    let anya = card(10, "Аня");
    record_encounter(&mut state, &anya, NOW, DAY);
    let mut forged = card(10, "Аня");
    forged.nostr_key = card(20, "x").nostr_key;
    assert!(!record_encounter(&mut state, &forged, NOW + 120_000, DAY));
}

#[test]
fn deleting_encounters_drops_their_marks_and_pins() {
    let mut state = json!({});
    let (anya, boris) = (card(10, "Аня"), card(30, "Борис"));
    record_encounter(&mut state, &anya, NOW, DAY);
    record_encounter(&mut state, &boris, NOW, DAY);
    assert!(toggle_pin(&mut state, "encounters", &anya.id()));
    delete_encounters(&mut state, Some(&anya.id()));
    let left = encounters(&state, &HashSet::new(), NOW, DAY);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["id"], boris.id());
    assert_eq!(pins(&state)["encounters"], json!([]));
    delete_encounters(&mut state, None);
    assert!(encounters(&state, &HashSet::new(), NOW, DAY).is_empty());
    assert!(pins(&state).get("encounters").is_none());
}

#[test]
fn pins_toggle_at_the_top_of_each_list() {
    let mut state = json!({});
    assert!(toggle_pin(&mut state, "contacts", "a"));
    assert!(toggle_pin(&mut state, "contacts", "b"));
    assert_eq!(pins(&state)["contacts"], json!(["b", "a"]));
    assert!(!toggle_pin(&mut state, "contacts", "b"));
    assert!(!toggle_pin(&mut state, "contacts", "a"));
    assert!(
        pins(&state).get("contacts").is_none(),
        "empty lists disappear"
    );
}

#[test]
fn a_contact_can_leave_the_address_book_and_keep_its_chat() {
    let anya = card(10, "Аня");
    let mut state = json!({"contacts": [{"card": anya, "metadata": {}}]});
    assert!(in_address_book(&state, &anya.id()));
    assert!(remove_from_contacts(&mut state, &anya.id()));
    assert!(!in_address_book(&state, &anya.id()));
    assert_eq!(state["contacts"][0]["metadata"]["addressBook"], "false");
    assert!(!remove_from_contacts(&mut state, "unknown"));
}

#[test]
fn each_client_chooses_how_long_encounters_stay() {
    let mut state = json!({});
    let anya = card(10, "Аня");
    let hour = 60 * 60 * 1000;
    record_encounter(&mut state, &anya, NOW, hour);
    assert_eq!(
        encounters(&state, &HashSet::new(), NOW + hour, hour).len(),
        1
    );
    assert!(encounters(&state, &HashSet::new(), NOW + hour + 1, hour).is_empty());
    assert_eq!(
        encounters(&state, &HashSet::new(), NOW + hour + 1, DAY).len(),
        1,
        "another client keeps a day"
    );
}
