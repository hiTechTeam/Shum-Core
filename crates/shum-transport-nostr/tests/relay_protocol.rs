//! Relay messages without a connection, as the browser uses them. Runs
//! natively and in WebAssembly (scripts/test-wasm.sh).
use serde_json::{json, Value};
use shum_core::{
    crypto::Secret32,
    nostr::{create_private, Event, WrapEntropy},
};
use shum_transport_nostr::protocol::{self, Incoming, SUBSCRIPTION};

fn key(byte: u8) -> Secret32 {
    Secret32::new([byte; 32])
}
fn inbox() -> String {
    hex::encode(key(2).nostr_public().unwrap())
}
fn wrap() -> Event {
    create_private(
        &key(1),
        &inbox(),
        "hello".into(),
        1_700_000_000,
        WrapEntropy {
            outer_key: &key(3),
            seal_nonce: [4; 24],
            wrap_nonce: [5; 24],
            seal_aux: [6; 32],
            wrap_aux: [7; 32],
            seal_time: 1_699_999_999,
            wrap_time: 1_699_999_998,
        },
    )
    .unwrap()
}
fn delivered(event: &Event) -> String {
    json!(["EVENT", SUBSCRIPTION, event]).to_string()
}

#[test]
fn subscribes_to_the_last_three_days_of_gift_wraps() {
    let request: Value =
        serde_json::from_str(&protocol::subscription(&inbox(), 1_000_000)).unwrap();
    assert_eq!(
        request,
        json!(["REQ", SUBSCRIPTION, {"kinds":[1059],"#p":[inbox()],"since":1_000_000 - 3 * 86400,"limit":100}])
    );
    let early: Value = serde_json::from_str(&protocol::subscription(&inbox(), 5)).unwrap();
    assert_eq!(early[2]["since"], 0);
}

#[test]
fn accepts_only_valid_gift_wraps_for_this_inbox() {
    let event = wrap();
    assert_eq!(
        protocol::read(&delivered(&event), &inbox()),
        Some(Incoming::Event(Box::new(event.clone())))
    );
    assert_eq!(
        protocol::read(&delivered(&event), &"ab".repeat(32)),
        None,
        "someone else's inbox"
    );
    let other = json!(["EVENT", "another", event]).to_string();
    assert_eq!(protocol::read(&other, &inbox()), None, "other subscription");

    let mut forged = event.clone();
    forged.content.push('x');
    assert_eq!(protocol::read(&delivered(&forged), &inbox()), None, "ID");
    let mut unsigned = event.clone();
    unsigned.sig = None;
    assert_eq!(
        protocol::read(&delivered(&unsigned), &inbox()),
        None,
        "signature"
    );
    for text in [
        "",
        "{}",
        "[]",
        "[1]",
        "not json",
        &" ".repeat(protocol::MAX_MESSAGE + 1),
    ] {
        assert_eq!(protocol::read(text, &inbox()), None, "{text:.20}");
    }
}

#[test]
fn reads_acknowledgements_and_subscription_end() {
    let ok = |accepted: Value| json!(["OK", "e1", accepted, ""]).to_string();
    assert_eq!(
        protocol::read(&ok(json!(true)), &inbox()),
        Some(Incoming::Ok {
            id: "e1".into(),
            accepted: true
        })
    );
    for refused in [json!(false), json!("true"), Value::Null] {
        assert_eq!(
            protocol::read(&ok(refused), &inbox()),
            Some(Incoming::Ok {
                id: "e1".into(),
                accepted: false
            })
        );
    }
    let eose = json!(["EOSE", SUBSCRIPTION]).to_string();
    assert_eq!(
        protocol::read(&eose, &inbox()),
        Some(Incoming::EndOfStoredEvents)
    );
    let closed = json!(["CLOSED", SUBSCRIPTION, "error"]).to_string();
    assert_eq!(protocol::read(&closed, &inbox()), Some(Incoming::Closed));
    let foreign = json!(["CLOSED", "another", ""]).to_string();
    assert_eq!(protocol::read(&foreign, &inbox()), None);
}

#[test]
fn publishes_only_signed_events() {
    let event = wrap();
    let wire: Value = serde_json::from_str(&protocol::publication(&event).unwrap()).unwrap();
    assert_eq!(wire, json!(["EVENT", event]));
    let mut unsigned = event;
    unsigned.sig = None;
    assert!(protocol::publication(&unsigned).is_err());
}

#[test]
fn relay_addresses_must_be_secure() {
    let urls = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let defaults = urls(protocol::DEFAULT_RELAYS);
    assert!(protocol::validate_urls(&defaults).is_ok());
    assert!(protocol::validate_urls(&urls(&["ws://localhost:7777"])).is_ok());
    for bad in [
        "ws://relay.example",
        "https://relay.example",
        "wss://user@relay.example",
        "wss://relay.example/#x",
        "nonsense",
    ] {
        assert!(protocol::validate_urls(&urls(&[bad])).is_err(), "{bad}");
    }
    assert!(protocol::validate_urls(&[]).is_err());
    assert!(protocol::validate_inbox(&inbox()).is_ok());
    assert!(protocol::validate_inbox("zz").is_err());
}
