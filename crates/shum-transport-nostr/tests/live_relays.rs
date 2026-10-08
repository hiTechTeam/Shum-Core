use shum_core::{
    crypto::Secret32,
    nostr::{create_private, open_private, WrapEntropy},
};
use shum_transport_nostr::{RelayPool, RelayUpdate, DEFAULT_RELAYS};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};

fn key() -> Secret32 {
    loop {
        let mut raw = [0; 32];
        getrandom::fill(&mut raw).unwrap();
        let key = Secret32::new(raw);
        if key.nostr_public().is_ok() {
            return key;
        }
    }
}
#[tokio::test]
#[ignore = "Uses public Nostr relays with fresh disposable keys"]
async fn live_private_roundtrip() {
    let sender = key();
    let recipient = key();
    let relays = DEFAULT_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let (pool, mut incoming) =
        RelayPool::start(&relays, &hex::encode(recipient.nostr_public().unwrap())).unwrap();
    timeout(Duration::from_secs(30), async {
        while pool.connected().is_empty() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("at least one public relay connected");
    println!("Connected: {:?}", pool.connected());
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut salt = [0; 24];
    getrandom::fill(&mut salt).unwrap();
    let content = format!("shum-cli-network-test:{}", hex::encode(salt));
    let outer = key();
    let event = create_private(
        &sender,
        &hex::encode(recipient.nostr_public().unwrap()),
        content.clone(),
        timestamp,
        WrapEntropy {
            outer_key: &outer,
            seal_nonce: salt,
            wrap_nonce: salt,
            seal_aux: [0; 32],
            wrap_aux: [1; 32],
            seal_time: timestamp - 1,
            wrap_time: timestamp - 2,
        },
    )
    .unwrap();
    let expected = event.id.clone();
    pool.publish(event)
        .await
        .expect("public relay accepted the signed event");
    timeout(Duration::from_secs(30), async {
        while let Some(update) = incoming.recv().await {
            if let RelayUpdate::Event { event, relay } = update {
                if event.id == expected {
                    let opened = open_private(&event, &recipient).unwrap();
                    assert_eq!(opened.content, content);
                    println!("Encrypted roundtrip via {relay}");
                    return;
                }
            }
        }
        panic!("relay stream ended");
    })
    .await
    .expect("public relay delivered the encrypted event");
}
