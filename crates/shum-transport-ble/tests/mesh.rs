use shum_core::{
    card::Card,
    crypto::Secret32,
    packet::Packet,
    wire::{self, Frame},
};
use shum_transport_ble::mesh::{Effect, Mesh};
use std::collections::{HashSet, VecDeque};
fn identity(seed: u8) -> (Card, Secret32, Secret32) {
    let noise = Secret32::new([seed; 32]);
    let signing = Secret32::new([seed + 1; 32]);
    let nostr = Secret32::new([seed + 2; 32]);
    let card = Card::create(
        &noise,
        &signing,
        &nostr,
        format!("Peer {seed}"),
        "",
        Some(42),
        1,
    )
    .unwrap();
    (card, noise, signing)
}
fn deliver(a: &mut Mesh, b: &mut Mesh, initial: Vec<(bool, Effect)>) -> Vec<(bool, Effect)> {
    let mut queue: VecDeque<_> = initial.into();
    let mut received = vec![];
    let mut count = 0;
    while let Some((from_a, effect)) = queue.pop_front() {
        count += 1;
        assert!(count < 1000, "unexpected echo loop");
        match effect {
            Effect::Send { link, frames } => {
                assert_eq!(link, "wire");
                assert!(frames.iter().all(|f| f.len() <= 180));
                let receiver = if from_a { &mut *b } else { &mut *a };
                // All fragment streams must tolerate reversed delivery.
                for frame in frames.into_iter().rev() {
                    for effect in receiver.receive("wire", &frame, 1000).unwrap() {
                        queue.push_back((!from_a, effect));
                    }
                }
            }
            other => received.push((!from_a, other)),
        }
    }
    received
}
#[test]
fn two_roles_authenticate_cards_with_real_fragmentation_and_rssi() {
    let (ac, an, asign) = identity(1);
    let (bc, bn, bsign) = identity(11);
    let mut a = Mesh::new(ac.clone(), an, asign, vec![], HashSet::new()).unwrap();
    let mut b = Mesh::new(bc.clone(), bn, bsign, vec![], HashSet::new()).unwrap();
    let mut events = a
        .connected("wire".into(), 180, Some(-59), 1000)
        .unwrap()
        .into_iter()
        .map(|e| (true, e))
        .collect::<Vec<_>>();
    events.extend(
        b.connected("wire".into(), 180, Some(-65), 1000)
            .unwrap()
            .into_iter()
            .map(|e| (false, e)),
    );
    let got = deliver(&mut a, &mut b, events);
    assert!(got
        .iter()
        .any(|(_, e)| matches!(e,Effect::Peer{card,direct:true,..} if **card==ac)));
    assert!(got
        .iter()
        .any(|(_, e)| matches!(e,Effect::Peer{card,direct:true,..} if **card==bc)));
    let arouting = hex::encode(wire::routing_id(&ac.noise_key.clone().try_into().unwrap()));
    let brouting = hex::encode(wire::routing_id(&bc.noise_key.clone().try_into().unwrap()));
    assert!(a.tick(1000).unwrap().iter().any(|e| matches!(
        e,
        Effect::Peer {
            distance: Some(1),
            ..
        }
    )));
    let packet = Packet {
        card: Some(ac.clone()),
        ..Packet::default()
    };
    let effect = a.send(&brouting, &packet, 1000).unwrap();
    let got = deliver(&mut a, &mut b, vec![(true, effect)]);
    assert!(got.iter().any(|(_,e)|matches!(e,Effect::Packet{routing,packet:p,..} if routing==&arouting && **p==packet)));
    assert!(a
        .disconnected("wire")
        .iter()
        .any(|e| matches!(e,Effect::Gone(id) if *id==brouting)));
    assert!(a.send(&brouting, &packet, 1001).is_err());
}
#[test]
fn forged_announce_does_not_forward_or_create_a_peer() {
    let (ac, an, asign) = identity(1);
    let (_, bn, _) = identity(11);
    let mut a = Mesh::new(ac, an, asign, vec![], HashSet::new()).unwrap();
    a.connected("wire".into(), 512, None, 1000).unwrap();
    let frame = Frame {
        version: 1,
        kind: 1,
        ttl: 7,
        timestamp: 1000,
        sender: wire::routing_id(&bn.noise_public()).to_vec(),
        recipient: None,
        route: None,
        payload: vec![1, 1, b'a'],
        signature: Some(vec![0; 64]),
        is_rsr: false,
    };
    assert!(a
        .receive("wire", &frame.encode(false).unwrap(), 1000)
        .is_err());
    assert!(!a
        .tick(4001)
        .unwrap()
        .iter()
        .any(|e| matches!(e, Effect::Peer { .. })));
}

fn pair() -> (Mesh, Mesh, Card, Card) {
    let (ac, an, asign) = identity(1);
    let (bc, bn, bsign) = identity(11);
    let mut a = Mesh::new(ac.clone(), an, asign, vec![], HashSet::new()).unwrap();
    let mut b = Mesh::new(bc.clone(), bn, bsign, vec![], HashSet::new()).unwrap();
    connect(&mut a, &mut b);
    (a, b, ac, bc)
}
fn connect(a: &mut Mesh, b: &mut Mesh) {
    let initial = a
        .connected("wire".into(), 180, Some(-59), 1000)
        .unwrap()
        .into_iter()
        .map(|e| (true, e))
        .chain(
            b.connected("wire".into(), 180, Some(-65), 1000)
                .unwrap()
                .into_iter()
                .map(|e| (false, e)),
        )
        .collect();
    deliver(a, b, initial);
}
fn routing(card: &Card) -> String {
    hex::encode(wire::routing_id(
        &card.noise_key.clone().try_into().unwrap(),
    ))
}
fn transfer(sender: &mut Mesh, receiver: &mut Mesh, recipient: &Card, packet: Packet) -> Packet {
    let effect = sender.send(&routing(recipient), &packet, 1000).unwrap();
    deliver(sender, receiver, vec![(true, effect)])
        .into_iter()
        .find_map(|(_, e)| {
            if let Effect::Packet { packet, .. } = e {
                Some(*packet)
            } else {
                None
            }
        })
        .expect("authenticated packet reaches receiver")
}

#[test]
fn reconnect_rejects_replay_and_preserves_the_latest_authenticated_card() {
    let (mut a, mut b, ac, bc) = pair();
    let newer = Card::create(
        &Secret32::new([11; 32]),
        &Secret32::new([12; 32]),
        &Secret32::new([13; 32]),
        "Updated".into(),
        "",
        Some(43),
        2,
    )
    .unwrap();
    let updates = b
        .update(newer.clone(), vec![], HashSet::new(), 1000)
        .unwrap();
    let got = deliver(
        &mut a,
        &mut b,
        updates.into_iter().map(|e| (false, e)).collect(),
    );
    assert!(got
        .iter()
        .any(|(_, e)| matches!(e,Effect::Peer{card,..} if **card==newer)));
    transfer(
        &mut b,
        &mut a,
        &ac,
        Packet {
            card: Some(bc.clone()),
            ..Packet::default()
        },
    );
    assert!(a
        .tick(1001)
        .unwrap()
        .iter()
        .any(|e| matches!(e,Effect::Peer{card,..} if **card==newer)));

    let packet = Packet {
        card: Some(newer),
        ..Packet::default()
    };
    let Effect::Send { frames, .. } = b.send(&routing(&ac), &packet, 1000).unwrap() else {
        panic!()
    };
    let mut packets = 0;
    for frame in &frames {
        packets += a
            .receive("wire", frame, 1000)
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Effect::Packet { .. }))
            .count();
    }
    assert_eq!(packets, 1);
    for frame in &frames {
        assert!(a.receive("wire", frame, 1000).unwrap().is_empty());
    }
    a.disconnected("wire");
    b.disconnected("wire");
    // Cached signed announces must also restore a fresh physical connection.
    let initial = a
        .connected("wire".into(), 180, None, 1000)
        .unwrap()
        .into_iter()
        .map(|e| (true, e))
        .chain(
            b.connected("wire".into(), 180, None, 1000)
                .unwrap()
                .into_iter()
                .map(|e| (false, e)),
        )
        .collect();
    deliver(&mut a, &mut b, initial);
    let packet = Packet {
        card: Some(ac.clone()),
        ..Packet::default()
    };
    assert_eq!(transfer(&mut a, &mut b, &bc, packet.clone()), packet);
    assert!(a
        .update(ac, vec![], HashSet::from([bc.id()]), 2001)
        .unwrap()
        .iter()
        .any(|e| matches!(e,Effect::Gone(id) if *id==routing(&bc))));
    assert!(a.send(&routing(&bc), &Packet::default(), 2001).is_err());
}

#[test]
fn invalid_link_budget_does_not_break_good_links() {
    let (mut a, _, _, _) = pair();
    assert!(a.connected("bad".into(), 20, None, 1000).is_err());
    assert!(a.tick(16000).is_ok());
}

#[test]
fn offline_engines_exchange_invitation_text_delivery_and_read_over_noise() {
    use shum_core::{
        engine::{Context, Engine, Keys},
        packet::InvitationAction,
        queue::{Action, Peer, Routes},
        rules::{Delivery, Phase, Source},
    };
    fn outgoing(actions: Vec<Action>, choose: impl Fn(&Packet) -> bool) -> Packet {
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendNostr { .. })),
            "offline must not use Nostr"
        );
        actions
            .into_iter()
            .find_map(|a| match a {
                Action::SendBle { packet, .. } if choose(&packet) => Some(*packet),
                _ => None,
            })
            .unwrap()
    }
    let (mut a, mut b, ac, bc) = pair();
    let an = Secret32::new([1; 32]);
    let asig = Secret32::new([2; 32]);
    let ano = Secret32::new([3; 32]);
    let bn = Secret32::new([11; 32]);
    let bsig = Secret32::new([12; 32]);
    let bno = Secret32::new([13; 32]);
    let ar = Routes {
        internet: false,
        peers: vec![Peer::authenticated(routing(&bc), bc.clone(), &bn.noise_public()).unwrap()],
    };
    let br = Routes {
        internet: false,
        peers: vec![Peer::authenticated(routing(&ac), ac.clone(), &an.noise_public()).unwrap()],
    };
    let mut ea = Engine::new(ac.clone()).unwrap();
    let mut eb = Engine::new(bc.clone()).unwrap();
    ea.add_contact(bc.clone()).unwrap();
    let ca = Context {
        now: 1000,
        uuid: "11111111-2222-4333-8444-000000000001",
        routes: &ar,
        keys: Keys {
            noise: &an,
            signing: &asig,
            nostr: &ano,
        },
    };
    let cb = Context {
        now: 1001,
        uuid: "11111111-2222-4333-8444-000000000002",
        routes: &br,
        keys: Keys {
            noise: &bn,
            signing: &bsig,
            nostr: &bno,
        },
    };
    let aid = routing(&ac);
    let bid = routing(&bc);
    let ap = an.noise_public();
    let bp = bn.noise_public();
    let sa = || Source::Ble {
        peer: &aid,
        session_noise: &ap,
    };
    let sb = || Source::Ble {
        peer: &bid,
        session_noise: &bp,
    };
    let invite = outgoing(
        ea.invitation(&bc.id(), InvitationAction::Request, None, &ca)
            .unwrap(),
        |p| p.invitation.is_some(),
    );
    eb.receive(transfer(&mut a, &mut b, &bc, invite), sa(), &cb)
        .unwrap();
    assert_eq!(eb.inbox.phase(&ac.id()), Phase::IncomingPending);
    let accept = outgoing(
        eb.invitation(&ac.id(), InvitationAction::Accept, None, &cb)
            .unwrap(),
        |p| p.invitation.is_some(),
    );
    ea.receive(transfer(&mut b, &mut a, &ac, accept), sb(), &ca)
        .unwrap();
    assert_eq!(ea.inbox.phase(&bc.id()), Phase::Accepted);
    let ca = Context {
        now: 1002,
        uuid: "11111111-2222-4333-8444-000000000003",
        ..ca
    };
    let sent = outgoing(
        ea.send(
            &bc.id(),
            "Привет по Bluetooth",
            None,
            &Secret32::new([80; 32]),
            &ca,
        )
        .unwrap(),
        |p| p.envelope.is_some(),
    );
    eb.receive(transfer(&mut a, &mut b, &bc, sent), sa(), &cb)
        .unwrap();
    assert_eq!(eb.inbox.messages[0].plaintext.text, "Привет по Bluetooth");
    let ack = outgoing(eb.tick(&br, 1003), |p| p.receipt.is_some());
    ea.receive(transfer(&mut b, &mut a, &ac, ack), sb(), &ca)
        .unwrap();
    assert_eq!(ea.outbox.messages[0].delivery.status, Delivery::Delivered);
    let cb = Context {
        now: 1004,
        uuid: "11111111-2222-4333-8444-000000000004",
        ..cb
    };
    let read = outgoing(eb.mark_read(&ac.id(), &cb).unwrap(), |p| {
        p.receipt.as_ref().is_some_and(|r| r.read)
    });
    ea.receive(transfer(&mut b, &mut a, &ac, read), sb(), &ca)
        .unwrap();
    assert_eq!(ea.outbox.messages[0].delivery.status, Delivery::Read);
    let cb = Context {
        now: 1005,
        uuid: "11111111-2222-4333-8444-000000000005",
        ..cb
    };
    let reply = outgoing(
        eb.send(
            &ac.id(),
            "Ответ без релея",
            None,
            &Secret32::new([81; 32]),
            &cb,
        )
        .unwrap(),
        |p| p.envelope.is_some(),
    );
    ea.receive(transfer(&mut b, &mut a, &ac, reply), sb(), &ca)
        .unwrap();
    assert_eq!(ea.inbox.messages[0].plaintext.text, "Ответ без релея");
}
