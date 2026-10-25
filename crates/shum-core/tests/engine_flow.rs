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
#[test]
fn an_expired_message_is_sent_again_at_the_end_of_the_chat() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let offline = Routes::default();
    let now = 1800000000000;
    let mut ea = accepted(&a, &b);
    let reply = Reply {
        message_id: id(9),
        sender_id: b.card.id(),
        text: "вопрос".into(),
    };
    ea.send(
        &b.card.id(),
        "Не дошло",
        Some(reply.clone()),
        &Secret32::new([81; 32]),
        &a.context(&offline, now, &id(1)),
    )
    .unwrap();
    // Waiting messages cannot be resent: they are still on their way.
    assert!(ea
        .resend(
            &id(1),
            &Secret32::new([82; 32]),
            &a.context(&offline, now + 1, &id(2))
        )
        .is_err());
    let later = now + 24 * 60 * 60 * 1000 + 1;
    ea.tick(&offline, later);
    assert_eq!(ea.outbox.messages[0].delivery.status, Delivery::Expired);
    ea.resend(
        &id(1),
        &Secret32::new([83; 32]),
        &a.context(&offline, later, &id(3)),
    )
    .unwrap();
    assert_eq!(ea.outbox.messages.len(), 1, "the expired copy is gone");
    let again = &ea.outbox.messages[0];
    assert_eq!(again.envelope.id, id(3));
    assert_eq!(again.delivery.status, Delivery::Queued);
    let text = again.plaintext.as_ref().unwrap();
    assert_eq!(text.text, "Не дошло");
    assert_eq!(text.reply, Some(reply));
    assert_eq!(text.timestamp, later);
    // The old ID is gone, so a second tap does nothing twice.
    assert!(ea
        .resend(
            &id(1),
            &Secret32::new([84; 32]),
            &a.context(&offline, later, &id(4))
        )
        .is_err());
}
#[test]
fn an_invitation_notifies_and_its_answer_wakes_the_app_silently() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let pushes = |actions: Vec<Action>| -> Vec<PushKind> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Push { kind, .. } => Some(kind),
                _ => None,
            })
            .collect()
    };
    let mut ea = Engine::new(a.card.clone()).unwrap();
    ea.add_contact(b.card.clone()).unwrap();
    let mut eb = Engine::new(b.card.clone()).unwrap();
    eb.add_contact(a.card.clone()).unwrap();
    let invite = ea
        .invitation(
            &b.card.id(),
            InvitationAction::Request,
            None,
            &a.context(&routes, now, &id(1)),
        )
        .unwrap();
    ea.outbox.relay_result(&id(1), true, now, false);
    assert_eq!(
        pushes(ea.tick(&routes, now + 1)),
        vec![PushKind::Invitation]
    );
    eb.receive(
        packet(&invite, |p| p.invitation.is_some()),
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 2, &id(2)),
    )
    .unwrap();
    eb.invitation(
        &a.card.id(),
        InvitationAction::Accept,
        None,
        &b.context(&routes, now + 3, &id(3)),
    )
    .unwrap();
    eb.outbox.relay_result(&id(3), true, now + 4, false);
    assert_eq!(
        pushes(eb.tick(&routes, now + 5)),
        vec![PushKind::InvitationUpdate]
    );
    assert_eq!(
        serde_json::to_value(PushKind::InvitationUpdate).unwrap(),
        "invitation_update"
    );
}

/// One profile on two devices: what one device sends shows as sent on the
/// other, its delivery status follows there, and reading on one reads on
/// the other. Only the profile's own key can send these copies.
#[test]
fn a_profile_on_two_devices_shares_what_it_sends_and_reads() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let mut phone = accepted(&a, &b);
    let mut laptop = accepted(&a, &b);
    let mut igor = accepted(&b, &a);

    let sent = phone
        .send(
            &b.card.id(),
            "с телефона",
            None,
            &Secret32::new([80; 32]),
            &a.context(&routes, now, &id(1)),
        )
        .unwrap();
    let message = packet(&sent, |p| p.envelope.is_some());
    let (operation, recipient, copy) = sent
        .iter()
        .find_map(|action| match action {
            Action::SendNostr {
                operation,
                recipient,
                packet,
            } if packet.own_copy.is_some() => {
                Some((operation.clone(), recipient.id(), *packet.clone()))
            }
            _ => None,
        })
        .expect("a copy for the profile's other devices");
    assert_eq!(
        recipient,
        a.card.id(),
        "the copy goes to the profile itself"
    );

    // Another key cannot plant a sent message.
    let mut fooled = accepted(&a, &b);
    fooled
        .receive(
            copy.clone(),
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 1, &id(2)),
        )
        .unwrap();
    assert!(fooled.outbox.messages.is_empty());

    laptop
        .receive(
            copy,
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 1, &id(2)),
        )
        .unwrap();
    let mirrored = laptop
        .outbox
        .messages
        .iter()
        .find(|m| m.envelope.id == id(1))
        .expect("the laptop shows the message as sent");
    assert!(mirrored.mirror);
    assert_eq!(mirrored.plaintext.as_ref().unwrap().text, "с телефона");
    // The phone delivers it; the laptop does not send it again.
    assert!(laptop
        .tick(&routes, now + 60_000)
        .iter()
        .all(|action| !matches!(action, Action::SendNostr { packet, .. } | Action::SendBle { packet, .. } if packet.envelope.is_some() || packet.own_copy.is_some())));

    // Igor's receipt reaches both devices of the profile.
    igor.receive(
        message,
        Source::Nostr(&a.card.nostr_key),
        &b.context(&routes, now + 2, &id(3)),
    )
    .unwrap();
    let receipt = packet(&igor.tick(&routes, now + 3), |p| p.receipt.is_some());
    laptop
        .receive(
            receipt,
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 4, &id(4)),
        )
        .unwrap();
    assert_eq!(
        laptop.outbox.messages[0].delivery.status,
        Delivery::Delivered
    );

    // Once a relay took the copy, the phone stops offering it.
    phone.outbox.relay_result(&operation, true, now + 5, false);
    assert!(phone.tick(&routes, now + 120_000).iter().all(
        |action| !matches!(action, Action::SendNostr { packet, .. } if packet.own_copy.is_some())
    ));

    // A message to the profile reaches both devices; reading it on the
    // phone reads it on the laptop.
    let reply = igor
        .send(
            &a.card.id(),
            "привет обоим",
            None,
            &Secret32::new([81; 32]),
            &b.context(&routes, now + 6, &id(5)),
        )
        .unwrap();
    let incoming = packet(&reply, |p| p.envelope.is_some());
    for device in [&mut phone, &mut laptop] {
        device
            .receive(
                incoming.clone(),
                Source::Nostr(&b.card.nostr_key),
                &a.context(&routes, now + 7, &id(6)),
            )
            .unwrap();
        assert!(device.inbox.messages.iter().any(|m| m.unread));
    }
    let read = phone
        .mark_read(&b.card.id(), &a.context(&routes, now + 8, &id(7)))
        .unwrap();
    laptop
        .receive(
            packet(&read, |p| p.own_read.is_some()),
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 9, &id(8)),
        )
        .unwrap();
    assert!(laptop.inbox.messages.iter().all(|m| !m.unread && m.read));
}

/// One profile on two devices: a reaction set on one shows on the other, and
/// a message withdrawn on one disappears from the other, even when the copy
/// of that message arrives late. Only the profile's own key can send these.
#[test]
fn a_profile_on_two_devices_shares_reactions_and_withdrawals() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let mut phone = accepted(&a, &b);
    let mut laptop = accepted(&a, &b);
    let mut igor = accepted(&b, &a);

    let reply = igor
        .send(
            &a.card.id(),
            "реакцию сюда",
            None,
            &Secret32::new([82; 32]),
            &b.context(&routes, now, &id(1)),
        )
        .unwrap();
    let incoming = packet(&reply, |p| p.envelope.is_some());
    for device in [&mut phone, &mut laptop] {
        device
            .receive(
                incoming.clone(),
                Source::Nostr(&b.card.nostr_key),
                &a.context(&routes, now + 1, &id(2)),
            )
            .unwrap();
    }
    let reacted = phone
        .toggle_reaction(
            &id(1),
            ReactionKind::Heart,
            &a.context(&routes, now + 2, &id(3)),
        )
        .unwrap();
    assert!(
        reacted.iter().any(|action| matches!(action, Action::SendNostr { recipient, packet, .. } if packet.reaction.is_some() && recipient.id() == b.card.id())),
        "Igor still gets the reaction"
    );
    let own = packet(&reacted, |p| p.own_reaction.is_some());
    let mark = (id(1), a.card.id());

    // Another key cannot set a reaction for the profile.
    let mut fooled = accepted(&a, &b);
    fooled
        .receive(
            incoming.clone(),
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 1, &id(2)),
        )
        .unwrap();
    fooled
        .receive(
            own.clone(),
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 3, &id(4)),
        )
        .unwrap();
    assert!(!fooled.inbox.reactions.contains_key(&mark));

    laptop
        .receive(
            own,
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 3, &id(4)),
        )
        .unwrap();
    assert_eq!(
        laptop.inbox.reactions[&mark].reaction,
        Some(ReactionKind::Heart)
    );
    // Taking it back on the phone takes it back on the laptop.
    let cleared = phone
        .toggle_reaction(
            &id(1),
            ReactionKind::Heart,
            &a.context(&routes, now + 4, &id(5)),
        )
        .unwrap();
    laptop
        .receive(
            packet(&cleared, |p| p.own_reaction.is_some()),
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 5, &id(6)),
        )
        .unwrap();
    assert_eq!(laptop.inbox.reactions[&mark].reaction, None);

    // A message withdrawn on the phone leaves the laptop too.
    let sent = phone
        .send(
            &b.card.id(),
            "передумала",
            None,
            &Secret32::new([83; 32]),
            &a.context(&routes, now + 6, &id(7)),
        )
        .unwrap();
    let copy = packet(&sent, |p| p.own_copy.is_some());
    let withdrawn = phone
        .cancel_sending(&id(7), &a.context(&routes, now + 7, &id(8)))
        .unwrap();
    assert!(
        withdrawn.iter().any(|action| matches!(action, Action::SendNostr { recipient, packet, .. } if packet.retract.is_some() && recipient.id() == b.card.id())),
        "Igor still gets the retract"
    );
    let own = packet(&withdrawn, |p| p.own_retract.is_some());
    laptop
        .receive(
            copy.clone(),
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 8, &id(9)),
        )
        .unwrap();
    assert!(laptop
        .outbox
        .messages
        .iter()
        .any(|m| m.envelope.id == id(7)));
    laptop
        .receive(
            own.clone(),
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 9, &id(10)),
        )
        .unwrap();
    assert!(laptop
        .outbox
        .messages
        .iter()
        .all(|m| m.envelope.id != id(7)));

    // The retract can outrun the copy: the copy then stays away.
    let mut tablet = accepted(&a, &b);
    for (p, n) in [(own, 11), (copy, 12)] {
        tablet
            .receive(
                p,
                Source::Nostr(&a.card.nostr_key),
                &a.context(&routes, now + 10, &id(n)),
            )
            .unwrap();
    }
    assert!(tablet.outbox.messages.is_empty());
}

/// One profile on two devices: clearing a chat on one clears it on the
/// other, while what came after the clear stays. Only the profile's own key
/// can clear its chats.
#[test]
fn a_profile_on_two_devices_shares_cleared_chats() {
    let a = Identity::new(1, "Аня");
    let b = Identity::new(10, "Игорь");
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1800000000000;
    let mut phone = accepted(&a, &b);
    let mut laptop = accepted(&a, &b);
    let mut igor = accepted(&b, &a);

    let before = igor
        .send(
            &a.card.id(),
            "до очистки",
            None,
            &Secret32::new([84; 32]),
            &b.context(&routes, now, &id(1)),
        )
        .unwrap();
    let old = packet(&before, |p| p.envelope.is_some());
    for device in [&mut phone, &mut laptop] {
        device
            .receive(
                old.clone(),
                Source::Nostr(&b.card.nostr_key),
                &a.context(&routes, now + 1, &id(2)),
            )
            .unwrap();
    }
    let sent = phone
        .send(
            &b.card.id(),
            "тоже до очистки",
            None,
            &Secret32::new([85; 32]),
            &a.context(&routes, now + 2, &id(3)),
        )
        .unwrap();
    laptop
        .receive(
            packet(&sent, |p| p.own_copy.is_some()),
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 3, &id(4)),
        )
        .unwrap();
    phone
        .toggle_reaction(
            &id(1),
            ReactionKind::Fire,
            &a.context(&routes, now + 4, &id(5)),
        )
        .unwrap();

    phone.clear_chat(&b.card.id(), now + 10);
    assert!(phone.inbox.messages.is_empty() && phone.outbox.messages.is_empty());
    let clear = packet(&phone.tick(&routes, now + 11), |p| p.own_clear.is_some());

    // A message written after the clear reaches the laptop first.
    let after = igor
        .send(
            &a.card.id(),
            "после очистки",
            None,
            &Secret32::new([86; 32]),
            &b.context(&routes, now + 20, &id(6)),
        )
        .unwrap();
    laptop
        .receive(
            packet(&after, |p| p.envelope.is_some()),
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 21, &id(7)),
        )
        .unwrap();

    // Another key cannot clear the profile's chats.
    laptop
        .receive(
            clear.clone(),
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 22, &id(8)),
        )
        .unwrap();
    assert_eq!(laptop.inbox.messages.len(), 2);

    laptop
        .receive(
            clear,
            Source::Nostr(&a.card.nostr_key),
            &a.context(&routes, now + 22, &id(8)),
        )
        .unwrap();
    assert!(laptop.outbox.messages.is_empty());
    let left: Vec<_> = laptop
        .inbox
        .messages
        .iter()
        .map(|m| m.envelope.id.clone())
        .collect();
    assert_eq!(left, vec![id(6)], "what came after the clear stays");
    assert!(laptop.inbox.reactions.keys().all(|(m, _)| *m != id(1)));

    // The old message does not come back from a relay.
    laptop
        .receive(
            old,
            Source::Nostr(&b.card.nostr_key),
            &a.context(&routes, now + 23, &id(9)),
        )
        .unwrap();
    assert_eq!(laptop.inbox.messages.len(), 1);
}
