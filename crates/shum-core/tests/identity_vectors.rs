use serde_json::Value;
use shum_core::{
    card::Card,
    crypto::{self, Secret32},
    invitation::{self, Invitation},
};

fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(format!(
            "{}/../../protocol/vectors/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(text(v, k)).unwrap()
}
fn card(v: &Value, k: &str) -> Card {
    serde_json::from_str(text(v, k)).unwrap()
}
fn secret(v: &Value, k: &str) -> Secret32 {
    Secret32::new(bytes(v, k).try_into().unwrap())
}

#[test]
fn identity_keys_and_ids() {
    for c in fixture("01-shum-id")["cases"].as_array().unwrap() {
        let k = &c["keys"];
        assert_eq!(
            hex::encode(secret(k, "noise_private_key").noise_public()),
            text(k, "noise_public_key")
        );
        assert_eq!(
            hex::encode(secret(k, "signing_private_key").ed_public()),
            text(k, "signing_public_key")
        );
        assert_eq!(
            hex::encode(secret(k, "nostr_private_key").nostr_public().unwrap()),
            text(k, "nostr_public_key")
        );
        assert_eq!(
            crypto::id(&bytes(k, "noise_public_key")),
            text(c, "shum_id")
        );
        assert_eq!(
            hex::encode(bytes(k, "noise_public_key")),
            text(c, "bluetooth_peer_id")
        );
    }
}
#[test]
fn avatar_seeds() {
    for c in fixture("01-avatar-seed")["cases"].as_array().unwrap() {
        let seed = crypto::avatar_seed(&bytes(c, "noise_public_key"));
        assert_eq!(seed.to_string(), text(c, "avatar_seed"));
        assert_eq!(
            hex::encode(seed.to_le_bytes()),
            text(c, "avatar_seed_hex_le")
        );
    }
}
#[test]
fn swift_ed25519_signatures() {
    for c in fixture("01-signatures")["cases"].as_array().unwrap() {
        assert_eq!(
            crypto::verify_ed(
                &bytes(c, "public_key"),
                &bytes(c, "signature"),
                &bytes(c, "message_hex")
            ),
            c["valid"].as_bool().unwrap()
        );
    }
}
#[test]
fn exact_canonical_bytes() {
    for c in fixture("02-canonical-json")["cases"].as_array().unwrap() {
        let value = card(c, "card_json");
        assert_eq!(
            hex::encode(value.signed_bytes().unwrap()),
            text(c, "card_bytes_hex"),
            "{}",
            c["label"]
        );
        assert_eq!(
            hex::encode(value.profile_bytes().unwrap()),
            text(c, "profile_bytes_hex"),
            "{}",
            c["label"]
        );
        assert_eq!(
            hex::encode(value.seed_bytes().unwrap()),
            text(c, "seed_bytes_hex")
        );
        assert_eq!(value.profile_id().unwrap(), text(c, "profile_id"));
        value.validate().unwrap();
    }
}
#[test]
fn swift_validation_cases() {
    for c in fixture("02-validate")["cases"].as_array().unwrap() {
        assert_eq!(
            card(c, "card_json").validate().is_ok(),
            c["swift_valid"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
    }
}
#[test]
fn swift_merge_cases() {
    for c in fixture("02-merge")["cases"].as_array().unwrap() {
        let incoming = card(c, "incoming_json");
        let previous = card(c, "previous_json");
        let result = incoming.preferred(&previous);
        let winner = match result {
            Err(_) => "error",
            Ok(v) if std::ptr::eq(v, &incoming) => "incoming",
            Ok(_) => "previous",
        };
        assert_eq!(winner, text(c, "winner"), "{}", c["label"]);
    }
}
#[test]
fn swift_invitation_cases() {
    let f = fixture("02-invite");
    for c in f["cases"].as_array().unwrap() {
        let parsed = invitation::parse(text(c, "url"));
        assert_eq!(
            parsed.is_ok(),
            c["result"]["valid"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
        match parsed {
            Ok(Invitation::Card(v)) => assert_eq!(*v, card(&c["result"], "card_json")),
            Ok(Invitation::Locator(v)) => assert_eq!(v, text(&c["result"], "nostr_key")),
            Err(_) => (),
        }
    }
    let own = card(&f, "source_card_json");
    let url = own.invitation().unwrap();
    assert_eq!(url, text(&f["cases"][0], "url"));
    if let Invitation::Card(parsed) = invitation::parse(&url).unwrap() {
        assert_eq!(parsed.profile_id().unwrap(), own.profile_id().unwrap());
    } else {
        panic!("expected card");
    }
}
