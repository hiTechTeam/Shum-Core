use shum_core::{
    card::Card,
    crypto::Secret32,
    engine::{Context, Engine, Keys},
    packet::*,
    queue::*,
    rules::*,
};
struct Identity {
    noise: Secret32,
    signing: Secret32,
    nostr: Secret32,
    card: Card,
}
impl Identity {
    fn new(n: u8, name: &str) -> Self {
        let noise = Secret32::new([n; 32]);
        let signing = Secret32::new([n + 1; 32]);
        let nostr = Secret32::new([n + 2; 32]);
        let card = Card::create(&noise, &signing, &nostr, name.into(), "", None, 1).unwrap();
        Self {
            noise,
            signing,
            nostr,
            card,
        }
    }
    fn context<'a>(&'a self, routes: &'a Routes, now: i64, uuid: &'a str) -> Context<'a> {
        Context {
            now,
            uuid,
            routes,
            keys: Keys {
                noise: &self.noise,
                signing: &self.signing,
                nostr: &self.nostr,
            },
        }
    }
}
fn id(n: u8) -> String {
    format!("11111111-2222-4333-8444-{n:012}")
}
fn packet(actions: &[Action], kind: impl Fn(&Packet) -> bool) -> Packet {
    actions
        .iter()
        .find_map(|a| match a {
            Action::SendNostr { packet, .. } | Action::SendBle { packet, .. } if kind(packet) => {
                Some(*packet.clone())
            }
            _ => None,
        })
        .expect("expected packet action")
}
fn accepted(a: &Identity, b: &Identity) -> Engine {
    let mut engine = Engine::new(a.card.clone()).unwrap();
    engine.add_contact(b.card.clone()).unwrap();
    engine.inbox.invitations.insert(
        b.card.id(),
        InvitationState {
            phase: Phase::Accepted,
            updated_at: 0,
            event_id: "accepted".into(),
        },
    );
    engine
}
#[test]
fn invitation_message_delivery_read_and_clear_between_two_identities() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let mut ea = Engine::new(a.card.clone()).unwrap();
    ea.add_contact(b.card.clone()).unwrap();
    let mut eb = Engine::new(b.card.clone()).unwrap();
    eb.add_contact(a.card.clone()).unwrap();
    assert!(ea
        .send(
            &b.card.id(),
            "до принятия",
            None,
            &Secret32::new([80; 32]),
            &a.context(&routes, now, &id(1))
        )
        .is_err());
    let invite = ea
        .invitation(
            &b.card.id(),
            InvitationAction::Request,
            None,
            &a.context(&routes, now, &id(2)),
        )
        .unwrap();
    eb.receive(
        packet(&invite, |p| p.invitation.is_some()),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now, &id(3)),
    )
    .unwrap();
    assert_eq!(eb.inbox.phase(&a.card.id()), Phase::IncomingPending);
    let accept = eb
        .invitation(
            &a.card.id(),
            InvitationAction::Accept,
            None,
            &b.context(&routes, now, &id(4)),
        )
        .unwrap();
    ea.receive(
        packet(&accept, |p| p.invitation.is_some()),
        Source::Nostr(&b.card.nostr_key),
        &a.context(&routes, now + 1, &id(5)),
    )
    .unwrap();
    assert_eq!(ea.inbox.phase(&b.card.id()), Phase::Accepted);
    let outgoing = ea
        .send(
            &b.card.id(),
            "  Привет\n",
            None,
            &Secret32::new([81; 32]),
            &a.context(&routes, now + 2, &id(6)),
        )
        .unwrap();
    let message = packet(&outgoing, |p| p.envelope.is_some());
    eb.receive(
        message.clone(),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 3, &id(7)),
    )
    .unwrap();
    assert_eq!(eb.inbox.messages[0].plaintext.text, "Привет");
    assert!(eb.inbox.messages[0].unread);
    assert_eq!(eb.outbox.receipts.len(), 1);
    let ack = packet(&eb.tick(&routes, now + 4), |p| p.receipt.is_some());
    ea.receive(
        ack,
        Source::Nostr(&b.card.nostr_key),
        &a.context(&routes, now + 4, &id(8)),
    )
    .unwrap();
    assert_eq!(ea.outbox.messages[0].delivery.status, Delivery::Delivered);
    let read = eb
        .mark_read(&a.card.id(), &b.context(&routes, now + 5, &id(9)))
        .unwrap();
    ea.receive(
        packet(&read, |p| p.receipt.as_ref().is_some_and(|r| r.read)),
        Source::Nostr(&b.card.nostr_key),
        &a.context(&routes, now + 5, &id(10)),
    )
    .unwrap();
    assert_eq!(ea.outbox.messages[0].delivery.status, Delivery::Read);
    eb.clear_chat(&a.card.id(), now + 6);
    eb.receive(
        message,
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 7, &id(11)),
    )
    .unwrap();
    assert!(eb.inbox.messages.is_empty());
    assert!(eb.outbox.receipts.is_empty());
    assert_eq!(eb.inbox.phase(&a.card.id()), Phase::Accepted);
}
#[test]
fn tentative_transition_and_blocking_do_not_send_before_commit() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let ea = accepted(&a, &b);
    let prepared = ea
        .prepare(|e| {
            e.send(
                &b.card.id(),
                "текст",
                None,
                &Secret32::new([82; 32]),
                &a.context(&routes, now, &id(1)),
            )
        })
        .unwrap();
    assert!(ea.outbox.messages.is_empty());
    assert_eq!(prepared.state.outbox.messages.len(), 1);
    assert!(!prepared.actions.is_empty());
    assert!(ea
        .prepare(|e| e.send(
            &b.card.id(),
            "",
            None,
            &Secret32::new([83; 32]),
            &a.context(&routes, now, &id(2))
        ))
        .is_err());
    assert!(ea.outbox.messages.is_empty());
    let mut next = prepared.state;
    next.block(&b.card.id(), true).unwrap();
    assert_eq!(next.outbox.messages[0].delivery.status, Delivery::Cancelled);
    assert!(next.tick(&routes, now + 10000).is_empty());
    next.retire();
    next.outbox.relay_result(&id(1), true, now + 11000, false);
    assert!(next.tick(&routes, now + 12000).is_empty());
}
#[test]
fn typing_reaction_withdrawal_and_profile_are_authenticated() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let mut ea = accepted(&a, &b);
    let mut eb = accepted(&b, &a);
    ea.inbox.foreground_contact = Some(b.card.id());
    let typing = ea
        .set_typing(&b.card.id(), true, &a.context(&routes, now, &id(1)))
        .unwrap();
    eb.receive(
        packet(&typing, |p| p.typing.is_some()),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now, &id(2)),
    )
    .unwrap();
    assert!(eb.inbox.typing[&a.card.id()].active(now));
    assert!(ea
        .set_typing(&b.card.id(), true, &a.context(&routes, now + 1000, &id(3)))
        .unwrap()
        .is_empty());
    let send = ea
        .send(
            &b.card.id(),
            "отзываемый",
            None,
            &Secret32::new([84; 32]),
            &a.context(&routes, now + 1000, &id(4)),
        )
        .unwrap();
    eb.receive(
        packet(&send, |p| p.envelope.is_some()),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 1001, &id(5)),
    )
    .unwrap();
    let reaction = eb
        .toggle_reaction(
            &id(4),
            ReactionKind::Heart,
            &b.context(&routes, now + 2000, &id(6)),
        )
        .unwrap();
    ea.receive(
        packet(&reaction, |p| p.reaction.is_some()),
        Source::Nostr(&b.card.nostr_key),
        &a.context(&routes, now + 2000, &id(7)),
    )
    .unwrap();
    assert_eq!(
        ea.inbox.reactions[&(id(4), b.card.id())].reaction,
        Some(ReactionKind::Heart)
    );
    let cancelled = ea
        .cancel_sending(&id(4), &a.context(&routes, now + 3000, &id(8)))
        .unwrap();
    eb.receive(
        packet(&cancelled, |p| p.retract.is_some()),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 3000, &id(9)),
    )
    .unwrap();
    assert!(eb.inbox.messages.is_empty());
    assert!(eb.inbox.deleted.contains_key(&id(4)));
    ea.update_profile(
        "Новая Аня".into(),
        "новое bio".into(),
        Some(33),
        None,
        &a.context(&routes, now + 4000, &id(10)),
    )
    .unwrap();
    let sync = packet(&ea.tick(&routes, now + 4000), |p| p.profile_sync.is_some());
    let response = eb
        .receive(
            sync,
            Source::Nostr(&a.card.nostr_key),
            &b.context(&routes, now + 4001, &id(11)),
        )
        .unwrap();
    assert_eq!(eb.inbox.contacts[&a.card.id()].name, "Новая Аня");
    ea.receive(
        packet(&response, |p| p.profile_sync.is_some()),
        Source::Nostr(&b.card.nostr_key),
        &a.context(&routes, now + 4002, &id(12)),
    )
    .unwrap();
    assert!(ea.outbox.profiles.is_empty());
}
#[test]
fn rate_limits_are_per_class_and_reset_at_exact_boundary() {
    let mut limiter = RateLimiter::default();
    for _ in 0..80 {
        assert!(limiter.allow("sender", Traffic::Content, 0));
    }
    assert!(!limiter.allow("sender", Traffic::Content, 59999));
    assert!(limiter.allow("sender", Traffic::Receipt, 59999));
    assert!(limiter.allow("sender", Traffic::Content, 60000));
}
