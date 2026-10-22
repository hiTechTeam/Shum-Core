//! The signed push request clients send themselves (the iPhone and the
//! browser) carries the event, the signature headers and the exact body.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use shum_core::{card::Card, queue::PushKind};
use shum_session::driver::push_request;
use shum_store::keys::ProfileKeys;

#[test]
fn a_push_request_is_signed_and_names_the_recipient_and_event() {
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
    let recipient = "ab".repeat(32);
    let event = "11111111-2222-4333-8444-555555555555";
    let push = push_request(
        &card,
        &keys.signing,
        &recipient,
        event,
        PushKind::Message,
        1_800_000_000_000,
    )
    .unwrap();
    assert_eq!(push["type"], "push");
    assert_eq!(push["event"], event);
    assert_eq!(push["path"], "/v1/notifications");
    let headers = &push["headers"];
    assert_eq!(headers["X-Shum-Timestamp"], "1800000000");
    for name in ["X-Shum-Public-Key", "X-Shum-Nonce", "X-Shum-Signature"] {
        assert!(!headers[name].as_str().unwrap().is_empty(), "{name}");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(push["body"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(body["recipient_id"], recipient);
    assert_eq!(body["event_id"], event);
    // A second request gets a fresh nonce.
    let again = push_request(
        &card,
        &keys.signing,
        &recipient,
        event,
        PushKind::Message,
        1_800_000_000_000,
    )
    .unwrap();
    assert_ne!(again["headers"]["X-Shum-Nonce"], headers["X-Shum-Nonce"]);
}
