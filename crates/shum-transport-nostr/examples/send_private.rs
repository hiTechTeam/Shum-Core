//! Sends one private test event to a Nostr inbox through the default relays,
//! from fresh disposable keys. Used to check a client that receives:
//! `cargo run -p shum-transport-nostr --example send_private -- <inbox hex>`
use shum_core::{
    crypto::Secret32,
    nostr::{create_private, WrapEntropy},
};
use shum_transport_nostr::{RelayPool, DEFAULT_RELAYS};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("random source");
    bytes
}
fn key() -> Secret32 {
    loop {
        let key = Secret32::new(random());
        if key.nostr_public().is_ok() {
            return key;
        }
    }
}

#[tokio::main]
async fn main() {
    let inbox = std::env::args().nth(1).expect("inbox public key in hex");
    let relays: Vec<String> = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
    // The pool listens on a throwaway inbox; it is only used to publish.
    let own = hex::encode(key().nostr_public().unwrap());
    let (pool, _incoming) = RelayPool::start(&relays, &own).expect("relays");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let outer = key();
    let event = create_private(
        &key(),
        &inbox,
        format!("shum-relay-check:{}", hex::encode(random::<8>())),
        now,
        WrapEntropy {
            outer_key: &outer,
            seal_nonce: random(),
            wrap_nonce: random(),
            seal_aux: random(),
            wrap_aux: random(),
            seal_time: now - 1,
            wrap_time: now - 2,
        },
    )
    .expect("event");
    let id = event.id.clone();
    tokio::time::sleep(Duration::from_secs(3)).await;
    match pool.publish(event).await {
        Ok(()) => println!("published {id} via {:?}", pool.connected()),
        Err(error) => println!("not published: {error}"),
    }
}
