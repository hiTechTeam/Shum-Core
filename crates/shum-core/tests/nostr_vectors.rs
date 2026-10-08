use serde_json::Value;
use shum_core::{crypto::Secret32, nostr::*};
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}
fn secret(v: &Value) -> Secret32 {
    Secret32::new(
        hex::decode(s(v, "nostr_private_key"))
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
#[test]
fn swift_event_id_and_bip340() {
    let f: Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/07-events.json")).unwrap();
    for c in f["cases"].as_array().unwrap() {
        let mut event: Event = serde_json::from_str(s(c, "event_json")).unwrap();
        assert_eq!(hex::encode(event.id_bytes().unwrap()), s(c, "id_bytes_hex"));
        assert!(event.verify());
        event.sign(&secret(&f["sender_keys"]), &[0; 32]).unwrap();
        assert!(event.verify());
    }
}
#[test]
fn swift_nested_wrappers_and_authentication() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/07-private-envelopes.json"
    ))
    .unwrap();
    let recipient = secret(&f["recipient_keys"]);
    let event: Event = serde_json::from_str(s(&f, "event_json")).unwrap();
    let opened = open_private(&event, &recipient).unwrap();
    assert_eq!(opened.content, s(&f, "swift_content"));
    assert_eq!(opened.sender, s(&f, "swift_sender"));
    let wrap = decrypt_content(&recipient, &event.pubkey, &event.content).unwrap();
    assert_eq!(
        wrap,
        String::from(s(&f["wrap_layer"], "plaintext_json")).into_bytes()
    );
    let seal: Event = serde_json::from_slice(&wrap).unwrap();
    assert_eq!(
        decrypt_content(&recipient, &seal.pubkey, &seal.content).unwrap(),
        s(&f["seal_layer"], "plaintext_json").as_bytes()
    );
    let nonce: [u8; 24] = hex::decode(s(&f["seal_layer"], "nonce_hex"))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        encrypt_content(
            &secret(&f["sender_keys"]),
            s(&f["recipient_keys"], "nostr_public_key"),
            &nonce,
            s(&f["seal_layer"], "plaintext_json").as_bytes()
        )
        .unwrap(),
        seal.content
    );
    for c in f["validation_cases"].as_array().unwrap() {
        let e: Event = serde_json::from_str(s(c, "event_json")).unwrap();
        assert_eq!(
            open_private(&e, &secret(&c["recipient_keys"])).is_ok(),
            c["swift_valid"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
    }
    let sender = secret(&f["sender_keys"]);
    let outer = Secret32::new([7; 32]);
    let built = create_private(
        &sender,
        s(&f["recipient_keys"], "nostr_public_key"),
        "Привет".into(),
        1_800_000_000,
        WrapEntropy {
            outer_key: &outer,
            seal_nonce: [3; 24],
            wrap_nonce: [4; 24],
            seal_aux: [5; 32],
            wrap_aux: [6; 32],
            seal_time: 1_799_999_998,
            wrap_time: 1_799_999_999,
        },
    )
    .unwrap();
    assert_eq!(open_private(&built, &recipient).unwrap().content, "Привет");
}
