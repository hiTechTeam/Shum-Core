//! The relay connection machine every client runs. Runs natively and in
//! WebAssembly (scripts/test-wasm.sh).
use serde_json::json;
use shum_core::{
    crypto::Secret32,
    nostr::{create_private, Event, WrapEntropy},
};
use shum_transport_nostr::{
    links::{Effect, Relays},
    protocol::{self, SUBSCRIPTION},
    Error,
};

const A: &str = "wss://a.example";
const B: &str = "wss://b.example";
const T0: u64 = 1_700_000_000_000;

fn key(byte: u8) -> Secret32 {
    Secret32::new([byte; 32])
}
fn inbox() -> String {
    hex::encode(key(2).nostr_public().unwrap())
}
fn event(nonce: u8) -> Event {
    create_private(
        &key(1),
        &inbox(),
        format!("hello {nonce}"),
        1_700_000_000,
        WrapEntropy {
            outer_key: &key(3),
            seal_nonce: [nonce; 24],
            wrap_nonce: [nonce; 24],
            seal_aux: [6; 32],
            wrap_aux: [7; 32],
            seal_time: 1_699_999_999,
            wrap_time: 1_699_999_998,
        },
    )
    .unwrap()
}
fn relays(urls: &[&str], pings: bool) -> Relays {
    let urls: Vec<String> = urls.iter().map(|s| s.to_string()).collect();
    Relays::new(&urls, &inbox(), pings, T0).unwrap()
}
fn ok(id: &str, accepted: bool) -> String {
    json!(["OK", id, accepted, ""]).to_string()
}
/// Connects relay `relay` (attempt `attempt`) at `now` and drops its effects.
fn open(r: &mut Relays, relay: usize, attempt: u64, now: u64) {
    r.opened(relay, attempt, now);
    r.effects();
}

#[test]
fn connects_subscribes_and_reports() {
    let mut r = relays(&[A, B], true);
    r.tick(T0);
    assert_eq!(
        r.effects(),
        vec![
            Effect::Connect {
                relay: 0,
                attempt: 1
            },
            Effect::Connect {
                relay: 1,
                attempt: 1
            }
        ]
    );
    assert!(r.connected().is_empty());
    r.opened(1, 1, T0 + 500);
    assert_eq!(
        r.effects(),
        vec![
            Effect::Send {
                relay: 1,
                text: protocol::subscription(&inbox(), T0 / 1000)
            },
            Effect::Connected(B.into())
        ]
    );
    assert_eq!(r.connected(), vec![B.to_string()]);

    let wrap = event(4);
    let delivered = json!(["EVENT", SUBSCRIPTION, wrap]).to_string();
    r.received(1, 1, &delivered, T0 + 600);
    r.received(1, 1, &json!(["EOSE", SUBSCRIPTION]).to_string(), T0 + 600);
    assert_eq!(
        r.effects(),
        vec![
            Effect::Event {
                relay: B.into(),
                event: Box::new(wrap)
            },
            Effect::EndOfStoredEvents(B.into())
        ]
    );
    // Nothing arrives from a relay that is not connected.
    r.received(0, 1, &delivered, T0 + 600);
    assert!(r.effects().is_empty());
}

#[test]
fn a_publication_counts_once_any_relay_accepts_it() {
    let mut r = relays(&[A, B], true);
    r.tick(T0);
    r.effects();
    open(&mut r, 0, 1, T0);
    open(&mut r, 1, 1, T0);
    let e = event(4);
    let ticket = r.publish(&e, true, T0).unwrap().unwrap();
    let wire = protocol::publication(&e).unwrap();
    assert_eq!(
        r.effects(),
        vec![
            Effect::Send {
                relay: 0,
                text: wire.clone()
            },
            Effect::Send {
                relay: 1,
                text: wire
            }
        ]
    );
    r.received(0, 1, &ok(&e.id, false), T0 + 10);
    assert!(r.effects().is_empty(), "one relay may still accept");
    r.received(1, 1, &ok(&e.id, true), T0 + 20);
    assert_eq!(
        r.effects(),
        vec![Effect::Published {
            ticket,
            accepted: true
        }]
    );

    // Refused everywhere.
    let e = event(5);
    let ticket = r.publish(&e, true, T0).unwrap().unwrap();
    r.effects();
    r.received(0, 1, &ok(&e.id, false), T0 + 10);
    r.received(1, 1, &ok(&e.id, false), T0 + 10);
    assert_eq!(
        r.effects(),
        vec![Effect::Published {
            ticket,
            accepted: false
        }]
    );

    // No answer in ten seconds.
    let e = event(6);
    let ticket = r.publish(&e, true, T0).unwrap().unwrap();
    r.effects();
    r.tick(T0 + 9_999);
    assert!(r.effects().is_empty());
    r.tick(T0 + 10_000);
    assert_eq!(
        r.effects(),
        vec![Effect::Published {
            ticket,
            accepted: false
        }]
    );

    // Without confirmation there is no ticket.
    assert_eq!(r.publish(&event(7), false, T0).unwrap(), None);
}

#[test]
fn publications_wait_for_an_offline_relay() {
    let mut r = relays(&[A], true);
    let e = event(4);
    let ticket = r.publish(&e, true, T0).unwrap().unwrap();
    r.publish(&event(5), false, T0).unwrap();
    r.tick(T0);
    assert_eq!(
        r.effects(),
        vec![Effect::Connect {
            relay: 0,
            attempt: 1
        }]
    );
    r.opened(0, 1, T0 + 100);
    let effects = r.effects();
    assert_eq!(
        effects.len(),
        4,
        "subscription, connected, two publications"
    );
    assert_eq!(
        effects[2],
        Effect::Send {
            relay: 0,
            text: protocol::publication(&e).unwrap()
        }
    );
    r.received(0, 1, &ok(&e.id, true), T0 + 200);
    assert_eq!(
        r.effects(),
        vec![Effect::Published {
            ticket,
            accepted: true
        }]
    );

    let mut r = relays(&[A], true);
    for n in 0..64 {
        r.publish(&event(n), false, T0).unwrap();
    }
    assert!(matches!(
        r.publish(&event(64), false, T0),
        Err(Error::Queue)
    ));
    assert!(matches!(
        r.publish(&event(64), true, T0),
        Err(Error::Publication)
    ));
}

#[test]
fn failed_attempts_wait_longer_each_time() {
    let mut r = relays(&[A], true);
    let mut now = T0;
    let mut attempt = 0;
    for pause in [1, 2, 4, 8, 16, 32, 60, 60] {
        r.tick(now);
        attempt += 1;
        assert_eq!(r.effects(), vec![Effect::Connect { relay: 0, attempt }]);
        r.closed(0, attempt, now);
        assert_eq!(r.effects(), vec![Effect::Disconnected(A.into())]);
        r.tick(now + pause * 1000 - 1);
        assert!(r.effects().is_empty(), "waits {pause} s");
        now += pause * 1000;
    }
    // A working connection resets the pause, and losing it retries soon.
    r.tick(now);
    attempt += 1;
    r.effects();
    open(&mut r, 0, attempt, now);
    r.closed(0, attempt, now + 5_000);
    assert_eq!(r.effects(), vec![Effect::Disconnected(A.into())]);
    r.tick(now + 6_000);
    assert_eq!(
        r.effects(),
        vec![Effect::Connect {
            relay: 0,
            attempt: attempt + 1
        }]
    );
    r.closed(0, attempt + 1, now + 6_000);
    r.effects();
    r.tick(now + 7_000);
    assert_eq!(
        r.effects(),
        vec![Effect::Connect {
            relay: 0,
            attempt: attempt + 2
        }],
        "the next failure waits one second again"
    );
}

#[test]
fn events_of_an_older_connection_are_ignored() {
    let mut r = relays(&[A], true);
    r.tick(T0);
    r.effects();
    // The attempt timed out before the socket opened.
    r.tick(T0 + 8_000);
    assert_eq!(
        r.effects(),
        vec![Effect::Close { relay: 0 }, Effect::Disconnected(A.into())]
    );
    r.opened(0, 1, T0 + 8_100);
    r.closed(0, 1, T0 + 8_200);
    assert!(r.effects().is_empty());
    assert!(r.connected().is_empty());
}

#[test]
fn a_lost_connection_refuses_what_waited_for_it() {
    let mut r = relays(&[A], true);
    r.tick(T0);
    r.effects();
    open(&mut r, 0, 1, T0);
    let ticket = r.publish(&event(4), true, T0).unwrap().unwrap();
    r.effects();
    r.received(
        0,
        1,
        &json!(["CLOSED", SUBSCRIPTION, "bye"]).to_string(),
        T0 + 50,
    );
    assert_eq!(
        r.effects(),
        vec![
            Effect::Close { relay: 0 },
            Effect::Disconnected(A.into()),
            Effect::Published {
                ticket,
                accepted: false
            }
        ]
    );
}

#[test]
fn quiet_relays_are_pinged_and_silent_ones_dropped() {
    let mut r = relays(&[A], true);
    r.tick(T0);
    r.effects();
    open(&mut r, 0, 1, T0);
    r.tick(T0 + 19_999);
    assert!(r.effects().is_empty());
    r.tick(T0 + 20_000);
    assert_eq!(r.effects(), vec![Effect::Ping { relay: 0 }]);
    r.tick(T0 + 60_001);
    assert_eq!(
        r.effects(),
        vec![Effect::Close { relay: 0 }, Effect::Disconnected(A.into())]
    );

    // The browser cannot ping; its WebSocket notices a dead connection.
    let mut r = relays(&[A], false);
    r.tick(T0);
    r.effects();
    open(&mut r, 0, 1, T0);
    r.tick(T0 + 120_000);
    assert!(r.effects().is_empty());
}

#[test]
fn waking_connects_waiting_relays_and_checks_open_ones() {
    let mut r = relays(&[A, B], true);
    r.tick(T0);
    r.effects();
    open(&mut r, 0, 1, T0);
    // B failed a few times and waits 8 seconds before the next attempt.
    let mut now = T0;
    for attempt in 1..=4 {
        r.closed(1, attempt, now);
        r.effects();
        now += 1000 << (attempt - 1);
        r.tick(now);
        r.effects();
    }
    r.closed(1, 5, now);
    r.effects();
    r.received(0, 1, &json!(["EOSE", SUBSCRIPTION]).to_string(), now);
    r.effects();
    r.wake(now + 1);
    assert_eq!(
        r.effects(),
        vec![
            Effect::Ping { relay: 0 },
            Effect::Connect {
                relay: 1,
                attempt: 6
            }
        ]
    );
    // Waking twice in a row does not open a second connection.
    r.wake(now + 2);
    assert_eq!(r.effects(), vec![Effect::Ping { relay: 0 }]);
}
