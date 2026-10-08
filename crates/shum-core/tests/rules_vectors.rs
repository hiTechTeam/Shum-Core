use serde_json::Value;
use shum_core::{card::Card, crypto::Secret32, packet::*, rules::*};
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
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}
fn int(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or_else(|| s(v, k).parse().unwrap())
}
fn setup(f: &Value, phase: Phase) -> (Inbox, Secret32, Card) {
    let own: Card = serde_json::from_str(s(f, "own_card_json")).unwrap();
    let peer: Card = serde_json::from_str(s(f, "contact_card_json")).unwrap();
    let mut inbox = Inbox::new(own);
    inbox.contacts.insert(peer.id(), peer.clone());
    inbox.invitations.insert(
        peer.id(),
        InvitationState {
            phase,
            updated_at: int(f, "now_ms") - 1,
            event_id: "previous".into(),
        },
    );
    let key = Secret32::new(
        hex::decode(s(&f["recipient_keys"], "noise_private_key"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    (inbox, key, peer)
}
#[test]
fn swift_inbound_delivery_and_tombstones() {
    let f = fixture("05-delivery");
    let now = int(&f, "now_ms");
    for c in f["cases"].as_array().unwrap() {
        let phase = serde_json::from_value(c["phase"].clone()).unwrap();
        let (mut inbox, key, peer) = setup(&f, phase);
        if c["blocked"].as_bool().unwrap() {
            inbox.blocked.insert(peer.id());
        }
        let packet = Packet::decode(s(c, "packet_json").as_bytes()).unwrap();
        let effect = inbox
            .receive(packet, Source::Nostr(s(c, "nostr_sender")), &key, now)
            .unwrap_or(InboundEffect::Dropped);
        assert_eq!(
            inbox.messages.len() as u64,
            c["swift_message_count"].as_u64().unwrap(),
            "{}",
            c["label"]
        );
        assert_eq!(
            u64::from(matches!(
                effect,
                InboundEffect::Accepted(_) | InboundEffect::RepeatReceipt(_)
            )),
            c["swift_receipt_count"].as_u64().unwrap(),
            "{}",
            c["label"]
        );
        assert_eq!(
            inbox.messages.first().map(|m| m.unread).unwrap_or(false),
            c["swift_unread"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
    }
    let (mut inbox, key, peer) = setup(&f, Phase::Accepted);
    for (i, step) in f["steps"].as_array().unwrap().iter().enumerate() {
        let action = s(step, "action");
        if action == "clear-locally" {
            inbox.clear_chat(&peer.id(), now);
        } else {
            let packet = if i == 2 {
                s(&f, "conflicting_packet_json")
            } else {
                s(&f, "duplicate_packet_json")
            };
            let _ = inbox.receive(
                Packet::decode(packet.as_bytes()).unwrap(),
                Source::Nostr(&peer.nostr_key),
                &key,
                now,
            );
        }
        assert_eq!(
            inbox.messages.len() as u64,
            step["message_count"].as_u64().unwrap(),
            "step {i} {action}"
        );
        assert_eq!(
            inbox.phase(&peer.id()),
            serde_json::from_value(step["phase"].clone()).unwrap()
        );
        assert_eq!(
            !inbox.deleted.is_empty(),
            step["deleted"].as_bool().unwrap()
        );
    }
}
#[test]
fn swift_invitation_transitions() {
    let f = fixture("05-invitations");
    let own: Card = serde_json::from_str(s(&f, "own_card_json")).unwrap();
    for c in f["cases"].as_array().unwrap() {
        let packet = Packet::decode(s(c, "packet_json").as_bytes()).unwrap();
        let control = packet.invitation.unwrap();
        let mut state = InvitationState {
            phase: serde_json::from_value(c["initial_phase"].clone()).unwrap(),
            updated_at: int(&f, "initial_updated_at"),
            event_id: s(&f, "initial_event_id").into(),
        };
        let effect = state.receive(&control, &own.id(), false, false);
        assert_eq!(
            state.phase,
            serde_json::from_value(c["swift_phase"].clone()).unwrap(),
            "{} {}",
            c["initial_phase"],
            c["action"]
        );
        assert_eq!(
            u64::from(effect == InvitationEffect::Incoming),
            c["swift_requests"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(effect == InvitationEffect::ReaffirmAccept),
            c["swift_outbox"].as_u64().unwrap()
        );
    }
}
#[test]
fn swift_newest_reactions_and_ephemeral_signals() {
    let f = fixture("05-newest-signals");
    let own: Card = serde_json::from_str(s(&f, "own_card_json")).unwrap();
    let peer: Card = serde_json::from_str(s(&f, "contact_card_json")).unwrap();
    let mut mark: Option<ReactionMark> = None;
    for c in f["reaction_steps"].as_array().unwrap() {
        let control = Packet::decode(s(c, "packet_json").as_bytes())
            .unwrap()
            .reaction
            .unwrap();
        if let Some(m) = &mut mark {
            m.apply(&control);
        } else {
            mark = Some(ReactionMark::from_control(&control));
        }
        let expected: Value = serde_json::from_str(s(c, "swift_mark_json")).unwrap();
        assert_eq!(
            serde_json::to_value(&mark).unwrap(),
            expected,
            "{}",
            c["label"]
        );
    }
    let mut inbox = Inbox::new(own);
    inbox.contacts.insert(peer.id(), peer.clone());
    inbox.invitations.insert(
        peer.id(),
        InvitationState {
            phase: Phase::Accepted,
            updated_at: 0,
            event_id: "accepted".into(),
        },
    );
    let dummy = Secret32::new([1; 32]);
    let now = int(&f, "now_ms");
    for c in f["ephemeral_steps"].as_array().unwrap() {
        for field in ["typing_packet_json", "presence_packet_json"] {
            inbox
                .receive(
                    Packet::decode(s(c, field).as_bytes()).unwrap(),
                    Source::Nostr(&peer.nostr_key),
                    &dummy,
                    now,
                )
                .unwrap();
        }
        assert_eq!(
            inbox.typing.get(&peer.id()).is_some_and(|v| v.active(now)),
            c["swift_typing"].as_bool().unwrap()
        );
        assert_eq!(
            inbox
                .presence
                .get(&peer.id())
                .is_some_and(|v| v.active(now)),
            c["swift_in_chat"].as_bool().unwrap()
        );
    }
}
#[test]
fn swift_outbox_schedule_relay_ok_and_receipts() {
    let f = fixture("05-outbox");
    let message: Value = serde_json::from_str(s(&f, "message_json")).unwrap();
    let envelope: Envelope = serde_json::from_value(message["envelope"].clone()).unwrap();
    let mut state = DeliveryState::default();
    let mut sends = 0;
    let base = int(&f, "base_unix_seconds") * 1000;
    let mut receipts = f["receipt_packets_json"].as_array().unwrap().iter();
    for step in f["steps"].as_array().unwrap() {
        let now = base + int(step, "elapsed_seconds") * 1000;
        let action = s(step, "action");
        if ["delivered", "read"].contains(&action) {
            let packet =
                Packet::decode(receipts.next().unwrap().as_str().unwrap().as_bytes()).unwrap();
            state
                .apply_receipt(packet.receipt.unwrap(), &envelope, now)
                .unwrap();
        } else {
            if state.attempt_nostr(now, envelope.expires_at) {
                sends += 1;
            }
            if action == "relay-accepts" {
                state.relay_result(true);
            }
        }
        assert_eq!(serde_json::to_value(state.status).unwrap(), step["status"]);
        assert_eq!(
            state.nostr_accepted,
            step["nostr_accepted"].as_bool().unwrap()
        );
        assert_eq!(
            u64::from(state.nostr_attempts),
            step["nostr_attempts"].as_u64().unwrap()
        );
        assert_eq!(sends, step["nostr_envelopes"].as_u64().unwrap());
        assert_eq!(
            u64::from(state.receipt.is_some()),
            step["receipt_count"].as_u64().unwrap()
        );
    }
}
