//! Two iPhones running Shum-Core's Bluetooth mesh, linked by a pretend radio
//! that carries `ble-frames` effects between them: they find each other,
//! exchange an invitation and a message without any internet.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use shum_core::card::Card;
use shum_mobile::{write_database, MobileKeys, MobileProfile, MobileSession};
use shum_store::{empty_state, keys::ProfileKeys};
use std::sync::Arc;

struct Phone {
    session: Arc<MobileSession>,
    card: Card,
    /// This phone's name for its link to the other one.
    link: &'static str,
}

fn phone(folder: &std::path::Path, name: &str, link: &'static str) -> Phone {
    let keys = ProfileKeys::generate().unwrap();
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        name.into(),
        "",
        Some(7),
        1,
    )
    .unwrap();
    let owner = keys.owner_id();
    let mut state = empty_state(&owner);
    state["ownProfileCard"] = serde_json::to_value(&card).unwrap();
    let database = folder
        .join(format!("{name}.sqlite"))
        .to_string_lossy()
        .into_owned();
    write_database(
        database.clone(),
        owner,
        keys.storage.expose().to_vec(),
        state.to_string(),
    )
    .unwrap();
    let session = MobileSession::open(
        MobileProfile {
            database,
            id: name.into(),
            name: name.into(),
            relays: vec!["ws://127.0.0.1:9".into()],
            push: false,
            client: "{}".into(),
            encounter_retention_hours: 0,
        },
        MobileKeys {
            noise: keys.noise.expose().to_vec(),
            signing: keys.signing.expose().to_vec(),
            nostr: keys.nostr.expose().to_vec(),
            storage: keys.storage.expose().to_vec(),
        },
        NOW,
    )
    .unwrap();
    Phone {
        session,
        card,
        link,
    }
}

const NOW: u64 = 1_800_000_000_000;

/// Carries frames both ways and ticks both phones until nothing moves.
fn radio(a: &Phone, b: &Phone, now: &mut u64) {
    for _ in 0..40 {
        let mut moved = false;
        for (from, to) in [(a, b), (b, a)] {
            from.session.tick(*now);
            let effects: Vec<Value> = serde_json::from_str(&from.session.effects(*now)).unwrap();
            for effect in effects.iter().filter(|e| e["type"] == "ble-frames") {
                assert_eq!(effect["link"], from.link);
                for frame in effect["frames"].as_array().unwrap() {
                    moved = true;
                    let bytes = STANDARD.decode(frame.as_str().unwrap()).unwrap();
                    to.session.ble_received(to.link.into(), bytes, *now);
                }
            }
        }
        *now += 200;
        if !moved {
            return;
        }
    }
}

fn snapshot(phone: &Phone) -> Value {
    serde_json::from_str(&phone.session.snapshot()).unwrap()
}

fn contact<'a>(snapshot: &'a Value, card: &Card) -> Option<&'a Value> {
    snapshot["contacts"]
        .as_array()?
        .iter()
        .find(|c| c["id"] == card.id())
}

fn request(phone: &Phone, id: u64, json: Value, now: u64) {
    if let Some(answer) = phone.session.request(id, json.to_string(), now) {
        assert!(answer.contains("\"ok\""), "{answer}");
    }
}

#[test]
fn two_iphones_meet_and_talk_over_shum_cores_bluetooth() {
    let folder = std::env::temp_dir().join(format!("shum-mobile-ble-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    let anya = phone(&folder, "Аня", "to-boris");
    let boris = phone(&folder, "Борис", "to-anya");
    let mut now = NOW;
    anya.session.ble_start(now).unwrap();
    boris.session.ble_start(now).unwrap();
    anya.session
        .ble_connected(anya.link.into(), 512, Some(-50), now);
    boris
        .session
        .ble_connected(boris.link.into(), 512, Some(-50), now);
    radio(&anya, &boris, &mut now);

    // They see each other nearby, with the other's own card.
    let seen = snapshot(&anya);
    let met = seen["encounters"].as_array().unwrap();
    assert!(met.iter().any(|e| e["id"] == boris.card.id()), "{seen}");

    // An invitation and its answer go over Bluetooth only.
    request(
        &anya,
        1,
        serde_json::json!({"command": "add", "link": boris.card.invitation().unwrap()}),
        now,
    );
    request(
        &anya,
        2,
        serde_json::json!({"command": "invite", "contact": boris.card.id()}),
        now,
    );
    radio(&anya, &boris, &mut now);
    request(
        &boris,
        3,
        serde_json::json!({"command": "accept", "contact": anya.card.id()}),
        now,
    );
    radio(&anya, &boris, &mut now);
    assert_eq!(
        contact(&snapshot(&anya), &boris.card).unwrap()["phase"],
        "accepted"
    );

    request(
        &anya,
        4,
        serde_json::json!({"command": "send", "contact": boris.card.id(), "text": "Привет по Bluetooth"}),
        now,
    );
    radio(&anya, &boris, &mut now);
    let messages = snapshot(&boris)["messages"].clone();
    assert!(
        messages
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["text"] == "Привет по Bluetooth"),
        "{messages}"
    );
    // And the receipt comes back: the sender sees it delivered.
    radio(&anya, &boris, &mut now);
    let sent = snapshot(&anya)["messages"].clone();
    assert!(
        sent.as_array()
            .unwrap()
            .iter()
            .any(|m| m["text"] == "Привет по Bluetooth" && m["status"] == "delivered"),
        "{sent}"
    );

    // Going out of reach clears them from nearby; the nearby revision tells
    // the app to show it, while the stored state did not change.
    let (stored, nearby) = (anya.session.revision(), anya.session.nearby_revision());
    anya.session.ble_disconnected(anya.link.into());
    assert!(anya.session.nearby_revision() > nearby);
    assert_eq!(anya.session.revision(), stored);
    let away = snapshot(&anya);
    assert_ne!(contact(&away, &boris.card).unwrap()["nearby"], true);
    let _ = std::fs::remove_dir_all(&folder);
}
