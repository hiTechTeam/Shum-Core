use serde_json::Value;
use shum_core::{card::Card, packet::*, queue::*};
fn fixture(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("../../protocol/vectors/{name}.json")).unwrap())
        .unwrap()
}
fn number(v: &Value) -> i64 {
    v.as_i64()
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
#[test]
fn swift_message_queue_schedule_and_delivery_proofs() {
    let f = fixture("05-outbox");
    let message: Value = serde_json::from_str(f["message_json"].as_str().unwrap()).unwrap();
    let envelope: Envelope = serde_json::from_value(message["envelope"].clone()).unwrap();
    let own: Card = serde_json::from_str(f["own_card_json"].as_str().unwrap()).unwrap();
    let mut outbox = Outbox::default();
    outbox.enqueue(envelope).unwrap();
    let base = number(&f["base_unix_seconds"]) * 1000;
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let mut sent = 0;
    let mut receipts = f["receipt_packets_json"].as_array().unwrap().iter();
    for step in f["steps"].as_array().unwrap() {
        let now = base + number(&step["elapsed_seconds"]) * 1000;
        let action = step["action"].as_str().unwrap();
        if ["delivered", "read"].contains(&action) {
            let p = Packet::decode(receipts.next().unwrap().as_str().unwrap().as_bytes()).unwrap();
            outbox.apply_receipt(p.receipt.unwrap(), None, now).unwrap();
        } else {
            sent += outbox
                .tick(&own, &routes, now)
                .iter()
                .filter(|a| matches!(a,Action::SendNostr {packet,..} if packet.envelope.is_some()))
                .count();
            if action == "relay-accepts" {
                let id = outbox.messages[0].envelope.id.clone();
                outbox.relay_result(&id, true, now, false);
            }
        }
        assert_eq!(sent, step["nostr_envelopes"].as_u64().unwrap() as usize);
        let d = &outbox.messages[0].delivery;
        assert_eq!(
            d.nostr_attempts,
            step["nostr_attempts"].as_u64().unwrap() as u32
        );
        assert_eq!(serde_json::to_value(d.status).unwrap(), step["status"]);
        assert_eq!(d.nostr_accepted, step["nostr_accepted"].as_bool().unwrap());
    }
}
#[test]
fn swift_invitation_ble_retries_and_six_reply_limit() {
    let f = fixture("05-invitation-retries");
    let own: Card = serde_json::from_str(f["own_card_json"].as_str().unwrap()).unwrap();
    let peer: Card = serde_json::from_str(f["contact_card_json"].as_str().unwrap()).unwrap();
    let routes = Routes {
        internet: false,
        peers: vec![Peer::authenticated(
            "1112131415161718".into(),
            peer.clone(),
            peer.noise_key.as_slice().try_into().unwrap(),
        )
        .unwrap()],
    };
    let base = number(&f["base_unix_seconds"]) * 1000;
    for case in f["cases"].as_array().unwrap() {
        let c: InvitationControl =
            serde_json::from_str(case["control_json"].as_str().unwrap()).unwrap();
        let mut outbox = Outbox::default();
        outbox.enqueue_control(QueuedControl {
            id: c.id.clone(),
            recipient: c.recipient.clone(),
            expires: c.expires_at,
            kind: if c.fields.action == InvitationAction::Request {
                ControlKind::InvitationRequest
            } else {
                ControlKind::InvitationReply
            },
            packet: Packet {
                invitation: Some(c),
                ..Packet::default()
            },
            retry: Retry::default(),
        });
        let mut sent = 0;
        for step in case["steps"].as_array().unwrap() {
            sent += outbox
                .tick(
                    &own,
                    &routes,
                    base + number(&step["elapsed_seconds"]) * 1000,
                )
                .iter()
                .filter(|a| matches!(a,Action::SendBle {packet,..} if packet.invitation.is_some()))
                .count();
            assert_eq!(
                sent,
                step["sent"].as_u64().unwrap() as usize,
                "{} t={}",
                case["action"],
                step["elapsed_seconds"]
            );
            assert_eq!(
                outbox.controls.len(),
                step["queued"].as_u64().unwrap() as usize
            );
            assert_eq!(
                outbox.controls.first().map_or(0, |c| c.retry.attempts),
                step["attempts"].as_u64().unwrap() as u32
            );
        }
    }
}
