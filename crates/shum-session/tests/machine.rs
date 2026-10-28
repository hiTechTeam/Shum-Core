//! The session machine every client runs, without sockets, files or a
//! runtime: two profiles kept in memory invite each other and talk, with
//! their publications handed over as relays would. Runs natively and in
//! WebAssembly (scripts/test-wasm.sh).
use serde_json::{json, Value};
use shum_core::card::Card;
use shum_session::{
    machine::{Effect, Host, Machine},
    Request,
};
use shum_store::{empty_state, keys::ProfileKeys, records::Records};

struct Memory {
    keys: ProfileKeys,
    records: Records,
    commits: usize,
}
impl Host for Memory {
    fn keys(&self) -> &ProfileKeys {
        &self.keys
    }
    fn state(&self) -> &Value {
        self.records.state()
    }
    fn commit(&mut self, next: Value) -> anyhow::Result<()> {
        if let Some(plan) = self.records.plan(next)? {
            self.records.apply(plan);
            self.commits += 1;
        }
        Ok(())
    }
    fn profile(&self) -> Value {
        json!({"id": "test", "ownerId": self.keys.owner_id()})
    }
}

fn profile(name: &str) -> Machine<Memory> {
    let keys = ProfileKeys::generate().unwrap();
    keys.check().unwrap();
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        name.into(),
        "",
        Some(7),
        1,
    )
    .unwrap();
    let owner = keys.owner_id();
    let mut state = empty_state(&owner);
    state["ownProfileCard"] = serde_json::to_value(&card).unwrap();
    let (records, _) = Records::create(&owner, keys.storage_key(), &state).unwrap();
    let host = Memory {
        keys,
        records,
        commits: 0,
    };
    let mut machine = Machine::new(host, false, Default::default()).unwrap();
    machine.set_relays(vec!["wss://relay.example".into()]);
    machine
}

/// Hands `from`'s publications to `to` and confirms confirmed ones, as
/// relays do. Returns whether anything happened.
fn pass(
    from: &mut Machine<Memory>,
    to: &mut Machine<Memory>,
    replies: &mut Vec<(u64, Value)>,
) -> bool {
    let effects = from.effects();
    let busy = !effects.is_empty();
    for effect in effects {
        match effect {
            Effect::Publish { operation, event } => {
                assert!(event.verify());
                if event.tags[0][1] == to.inbox() {
                    to.incoming(event);
                }
                if let Some(operation) = operation {
                    from.published(&operation, true);
                }
            }
            Effect::Reply { id, result } => replies.push((id, result.unwrap())),
            Effect::Push { .. } | Effect::SendBle { .. } | Effect::Broadcast { .. } => {}
        }
    }
    busy
}

/// Relays both ways until both sides are quiet; returns delayed answers.
fn relay(a: &mut Machine<Memory>, b: &mut Machine<Memory>) -> Vec<(u64, Value)> {
    let mut replies = Vec::new();
    while pass(a, b, &mut replies) | pass(b, a, &mut replies) {}
    replies
}

fn ok(machine: &mut Machine<Memory>, request: Value) -> Value {
    let request: Request = serde_json::from_value(request).unwrap();
    machine.request(0, request).unwrap().unwrap()
}

#[test]
fn two_profiles_invite_each_other_and_talk() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let boris_id = boris.host.keys.owner_id();
    let anya_id = anya.host.keys.owner_id();

    let link = boris.engine.inbox.own.invitation().unwrap();
    assert_eq!(
        ok(&mut anya, json!({"command":"add","link":link}))["contactID"],
        boris_id
    );
    ok(&mut anya, json!({"command":"invite","contact":boris_id}));
    relay(&mut anya, &mut boris);
    let phase = |m: &Machine<Memory>, id: &str| {
        m.snapshot()["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .map(|c| c["phase"].clone())
    };
    assert_eq!(phase(&boris, &anya_id), Some(json!("incomingPending")));

    ok(&mut boris, json!({"command":"accept","contact":anya_id}));
    relay(&mut anya, &mut boris);
    assert_eq!(phase(&anya, &boris_id), Some(json!("accepted")));

    ok(
        &mut anya,
        json!({"command":"send","contact":boris_id,"text":"Привет"}),
    );
    relay(&mut anya, &mut boris);
    let messages = boris.snapshot()["messages"].clone();
    assert!(messages
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["text"] == "Привет" && m["outgoing"] == false));

    // Everything that changed went through the host's commits.
    assert!(anya.host.commits > 0 && boris.host.commits > 0);
    let reopened = Records::load(
        &boris_id,
        boris.host.keys.storage_key(),
        boris.host.records.all(),
    )
    .unwrap();
    assert_eq!(reopened.state(), boris.host.records.state());
}

#[test]
fn a_lookup_by_network_id_answers_later() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let key = boris.inbox().to_owned();
    let request: Request =
        serde_json::from_value(json!({"command":"invite","contact":key})).unwrap();
    assert!(
        anya.request(41, request).is_none(),
        "waits for Борис's card"
    );
    let replies = relay(&mut anya, &mut boris);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, 41);
    assert_eq!(replies[0].1["contactID"], boris.host.keys.owner_id());
}

#[test]
fn an_invitation_made_offline_leaves_once_relays_connect() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let anya_id = anya.host.keys.owner_id();
    let link = boris.engine.inbox.own.invitation().unwrap();
    ok(&mut anya, json!({"command":"add","link":link}));
    anya.set_relays(vec![]);
    ok(
        &mut anya,
        json!({"command":"invite","contact":boris.host.keys.owner_id()}),
    );
    anya.tick();
    relay(&mut anya, &mut boris);
    assert!(
        boris.engine.inbox.contacts.is_empty(),
        "nothing leaves offline"
    );
    let boris_row = |m: &Machine<Memory>| {
        m.snapshot()["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["card"]["name"] == "Борис")
            .unwrap()
            .clone()
    };
    let row = boris_row(&anya);
    assert_eq!(row["invitationWaiting"], true);
    assert_eq!(row["invitationCancellable"], true);

    anya.set_relays(vec!["wss://relay.example".into()]);
    anya.tick();
    relay(&mut anya, &mut boris);
    assert_eq!(
        boris.engine.inbox.phase(&anya_id),
        shum_core::rules::Phase::IncomingPending
    );
    assert_eq!(boris_row(&anya)["invitationWaiting"], false);
    let request: Request = serde_json::from_value(
        json!({"command":"cancel_invitation","contact":boris.host.keys.owner_id()}),
    )
    .unwrap();
    assert_eq!(
        anya.request(2, request).unwrap().unwrap_err(),
        shum_session::Failure::text("Приглашение уже отправлено")
    );
}

#[test]
fn an_invitation_that_never_left_can_be_cancelled() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let boris_id = boris.host.keys.owner_id();
    let link = boris.engine.inbox.own.invitation().unwrap();
    ok(&mut anya, json!({"command":"add","link":link}));
    anya.set_relays(vec![]);
    ok(&mut anya, json!({"command":"invite","contact":boris_id}));
    ok(
        &mut anya,
        json!({"command":"cancel_invitation","contact":boris_id}),
    );
    let snapshot = anya.snapshot();
    let row = &snapshot["contacts"][0];
    assert_eq!(row["phase"], "ready");
    assert_eq!(row["invitationWaiting"], false);
    assert!(
        snapshot["events"].as_array().unwrap().is_empty(),
        "no \"invitation sent\" row is left"
    );

    anya.set_relays(vec!["wss://relay.example".into()]);
    anya.tick();
    relay(&mut anya, &mut boris);
    assert!(
        boris.engine.inbox.contacts.is_empty(),
        "nothing leaves later"
    );
    // Inviting again works as before.
    ok(&mut anya, json!({"command":"invite","contact":boris_id}));
    relay(&mut anya, &mut boris);
    assert!(boris
        .engine
        .inbox
        .requests
        .contains_key(&anya.host.keys.owner_id()));
}

#[test]
fn find_shows_a_card_without_adding_it() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let boris_id = boris.host.keys.owner_id();
    let request: Request =
        serde_json::from_value(json!({"command":"find","contact":boris.inbox()})).unwrap();
    assert!(anya.request(7, request).is_none(), "waits for Борис's card");
    let replies = relay(&mut anya, &mut boris);
    assert_eq!(replies.len(), 1);
    let found = &replies[0].1;
    assert_eq!(found["card"]["name"], "Борис");
    assert_eq!(found["contactID"], boris_id);
    assert!(
        anya.engine.inbox.contacts.is_empty(),
        "nothing is added yet"
    );
    assert!(boris.engine.inbox.requests.is_empty(), "nobody is invited");

    // The returned link adds the same card, and a link is shown at once.
    let link = found["link"].as_str().unwrap().to_owned();
    let shown = ok(&mut anya, json!({"command":"find","contact":link}));
    assert_eq!(shown["contactID"], boris_id);
    assert_eq!(
        ok(&mut anya, json!({"command":"add","link":link}))["contactID"],
        boris_id
    );

    let own = anya.engine.inbox.own.invitation().unwrap();
    let request: Request = serde_json::from_value(json!({"command":"find","contact":own})).unwrap();
    assert_eq!(
        anya.request(8, request).unwrap().unwrap_err(),
        shum_session::Failure::text("Это ваш профиль")
    );
}

#[test]
fn a_profile_cannot_add_its_own_card() {
    let mut anya = profile("Аня");
    let link = anya.engine.inbox.own.invitation().unwrap();
    let request: Request = serde_json::from_value(json!({"command":"add","link":link})).unwrap();
    let failure = anya.request(1, request).unwrap().unwrap_err();
    assert_eq!(failure, shum_session::Failure::text("Это ваш профиль"));
    assert!(anya.engine.inbox.contacts.is_empty());
}

#[test]
fn stop_and_errors_come_back_as_requests_answers() {
    let mut anya = profile("Аня");
    let request: Request =
        serde_json::from_value(json!({"command":"send","contact":"nobody","text":"x"})).unwrap();
    assert!(anya.request(1, request).unwrap().is_err());
    assert!(!anya.stopped());
    ok(&mut anya, json!({"command":"stop"}));
    assert!(anya.stopped());
}

#[test]
fn people_nearby_become_encounters_that_can_be_pinned() {
    use shum_session::machine::Nearby;
    let mut anya = profile("Аня");
    let boris = profile("Борис");
    let card = boris.engine.inbox.own.clone();
    let noise = boris.host.keys.noise.noise_public();
    anya.nearby(Nearby::Peer {
        routing: "0011223344556677".into(),
        card: Box::new(card.clone()),
        noise,
        distance: Some(3),
        direct: true,
    })
    .unwrap();
    let snapshot = anya.snapshot();
    assert_eq!(snapshot["encounters"][0]["id"], card.id());
    assert_eq!(snapshot["encounters"][0]["viewed"], false);

    let pinned = ok(
        &mut anya,
        json!({"command":"pin","contact":card.id(),"directory":"encounters"}),
    );
    assert_eq!(pinned["pinned"], true);
    ok(
        &mut anya,
        json!({"command":"view_encounters","contact":null}),
    );
    let snapshot = anya.snapshot();
    assert_eq!(snapshot["pins"]["encounters"][0], card.id());
    assert_eq!(snapshot["encounters"][0]["viewed"], true);
    ok(
        &mut anya,
        json!({"command":"delete_encounters","contact":card.id()}),
    );
    assert_eq!(anya.snapshot()["encounters"], json!([]));
}

/// Carries `from`'s open-chat events to `to`, as the mesh would.
fn mesh(
    from: &mut Machine<Memory>,
    to: &mut Machine<Memory>,
) -> Vec<shum_core::public::PublicEvent> {
    let card = from.engine.inbox.own.clone();
    let events: Vec<_> = from
        .effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::Broadcast { id, body } => {
                Some(shum_core::public::PublicEvent::new(id, body, card.clone()).unwrap())
            }
            _ => None,
        })
        .collect();
    for event in &events {
        hear(to, event);
    }
    events
}

fn hear(to: &mut Machine<Memory>, event: &shum_core::public::PublicEvent) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    to.nearby(shum_session::machine::Nearby::Public {
        event: Box::new(event.clone()),
        timestamp: now,
    })
    .unwrap();
}

#[test]
fn the_open_chat_carries_quotes_reactions_and_withdrawals_for_a_day() {
    let mut anya = profile("Аня");
    let mut boris = profile("Борис");
    let anya_card = anya.engine.inbox.own.clone();
    let anya_id = anya_card.id();
    let boris_id = boris.host.keys.owner_id();
    let chat = |m: &Machine<Memory>| m.snapshot()["publicChat"].clone();

    // Борис blocked Аня, yet the open chat still shows her, once.
    ok(
        &mut boris,
        json!({"command":"add","link":anya_card.invitation().unwrap()}),
    );
    ok(
        &mut boris,
        json!({"command":"block","contact":anya_id,"blocked":true}),
    );
    let id = ok(
        &mut anya,
        json!({"command":"broadcast","text":"Всем привет!"}),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(chat(&anya)[0]["outgoing"], true);
    let hello = mesh(&mut anya, &mut boris);
    hear(&mut boris, &hello[0]);
    assert_eq!(chat(&boris).as_array().unwrap().len(), 1);
    assert_eq!(chat(&boris)[0]["card"]["name"], "Аня");
    assert_eq!(chat(&boris)[0]["outgoing"], false);

    // Борис answers with a quote and reacts; Аня sees both, then the
    // reaction goes away when he takes it back.
    ok(
        &mut boris,
        json!({"command":"broadcast","text":"И тебе!",
            "reply":{"messageID":id,"senderID":anya_id,"text":"Всем привет!"}}),
    );
    ok(
        &mut boris,
        json!({"command":"public_reaction","note":id,"author":anya_id,"reaction":"heart"}),
    );
    mesh(&mut boris, &mut anya);
    let notes = chat(&anya);
    assert_eq!(notes[1]["reply"]["messageID"], id.as_str());
    assert_eq!(notes[0]["reactions"][0]["personID"], boris_id.as_str());
    assert_eq!(notes[0]["reactions"][0]["reaction"], "heart");
    assert_eq!(notes[0]["reactions"][0]["card"]["name"], "Борис");
    ok(
        &mut boris,
        json!({"command":"public_reaction","note":id,"author":anya_id}),
    );
    mesh(&mut boris, &mut anya);
    assert!(chat(&anya)[0]["reactions"].as_array().unwrap().is_empty());

    // Аня withdraws her note; a late copy does not bring it back.
    ok(&mut anya, json!({"command":"public_retract","note":id}));
    mesh(&mut anya, &mut boris);
    hear(&mut boris, &hello[0]);
    let left = chat(&boris);
    assert!(left
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["id"] != id.as_str()));
    assert_eq!(left.as_array().unwrap().len(), 1, "Борис's answer stays");
    // Only the author can withdraw: Борис cannot take back Аня's notes.
    assert!(boris
        .request(
            0,
            serde_json::from_value(json!({"command":"public_retract","note":"nope"})).unwrap()
        )
        .unwrap()
        .is_err());

    // A flood from one author stops at 20 a minute.
    let mut vera = profile("Вера");
    for n in 0..30 {
        ok(
            &mut vera,
            json!({"command":"broadcast","text":format!("спам {n}")}),
        );
    }
    mesh(&mut vera, &mut boris);
    let from_vera = chat(&boris)
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["card"]["name"] == "Вера")
        .count();
    assert_eq!(from_vera, 20);

    // Someone relayed by others is on the mesh without being nearby.
    ok(
        &mut boris,
        json!({"command":"block","contact":anya_id,"blocked":false}),
    );
    let noise = anya.host.keys.noise.noise_public();
    boris
        .nearby(shum_session::machine::Nearby::Peer {
            routing: hex::encode(shum_core::wire::routing_id(&noise)),
            card: Box::new(anya_card.clone()),
            noise,
            distance: None,
            direct: false,
        })
        .unwrap();
    let row = boris.snapshot()["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == anya_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        (row["mesh"].clone(), row["nearby"].clone()),
        (json!(true), json!(false))
    );

    // A day later the notes are gone.
    let later = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + shum_session::public::RETENTION_MS
        + 1;
    assert!(shum_session::public::notes(boris.host.state(), later).is_empty());
}

/// Another device of the same profile: same keys and card, its own state.
fn twin(of: &Machine<Memory>) -> Machine<Memory> {
    let k = &of.host.keys;
    let keys = ProfileKeys {
        noise: shum_core::crypto::Secret32::new(*k.noise.expose()),
        signing: shum_core::crypto::Secret32::new(*k.signing.expose()),
        nostr: shum_core::crypto::Secret32::new(*k.nostr.expose()),
        storage: shum_core::crypto::Secret32::new(*k.storage.expose()),
    };
    let owner = keys.owner_id();
    let mut state = empty_state(&owner);
    state["ownProfileCard"] = serde_json::to_value(&of.engine.inbox.own).unwrap();
    let (records, _) = Records::create(&owner, keys.storage_key(), &state).unwrap();
    let mut machine = Machine::new(
        Memory {
            keys,
            records,
            commits: 0,
        },
        false,
        Default::default(),
    )
    .unwrap();
    machine.set_relays(vec!["wss://relay.example".into()]);
    machine
}

/// Hands `from`'s open-chat copies to `to` through the relays and confirms
/// them; returns how many went out.
fn copy(from: &mut Machine<Memory>, to: &mut Machine<Memory>) -> usize {
    let mut sent = 0;
    for effect in from.effects() {
        if let Effect::Publish {
            operation: Some(operation),
            event,
        } = effect
        {
            if operation.starts_with("public-copy:") {
                sent += 1;
                to.incoming(event);
                from.published(&operation, true);
            }
        }
    }
    sent
}

#[test]
fn the_open_chat_reaches_the_profiles_other_devices_through_relays() {
    let mut phone = profile("Аня");
    let mut mac = twin(&phone);
    let mut boris = profile("Борис");

    // Written offline, the copy waits for relays and then leaves.
    phone.set_relays(vec![]);
    ok(
        &mut phone,
        json!({"command":"broadcast","text":"С телефона"}),
    );
    assert_eq!(copy(&mut phone, &mut mac), 0);
    phone.set_relays(vec!["wss://relay.example".into()]);
    phone.tick();
    assert_eq!(copy(&mut phone, &mut mac), 1);
    let chat = mac.snapshot()["publicChat"].clone();
    assert_eq!(chat[0]["text"], "С телефона");
    assert_eq!(chat[0]["outgoing"], true);
    assert!(
        phone.host.state()["publicCopies"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a copy a relay took no longer waits"
    );

    // What the phone heard over Bluetooth reaches the Mac too, once.
    ok(
        &mut boris,
        json!({"command":"broadcast","text":"Привет от Бориса"}),
    );
    mesh(&mut boris, &mut phone);
    assert_eq!(copy(&mut phone, &mut mac), 1);
    let chat = mac.snapshot()["publicChat"].clone();
    assert_eq!(chat[1]["text"], "Привет от Бориса");
    assert_eq!(chat[1]["outgoing"], false);
    // The Mac does not copy what it got from the phone back again.
    assert_eq!(copy(&mut mac, &mut phone), 0);
}

#[test]
fn refused_open_chat_copies_wait_before_they_go_again() {
    let mut phone = profile("Аня");
    let mut mac = twin(&phone);
    for n in 0..30 {
        ok(
            &mut phone,
            json!({"command":"broadcast","text":format!("note {n}")}),
        );
    }
    // Each note leaves at once; the relays refuse them all.
    let refuse = |from: &mut Machine<Memory>| {
        let mut sent = 0;
        for effect in from.effects() {
            if let Effect::Publish {
                operation: Some(operation),
                ..
            } = effect
            {
                if operation.starts_with("public-copy:") {
                    sent += 1;
                    from.published(&operation, false);
                }
            }
        }
        sent
    };
    assert_eq!(refuse(&mut phone), 30);
    for _ in 0..3 {
        phone.tick();
        assert_eq!(
            refuse(&mut phone),
            0,
            "refused copies wait instead of going every tick"
        );
    }
    // Nothing is lost: the copies still wait for a relay that takes them.
    assert_eq!(
        phone.host.state()["publicCopies"].as_array().unwrap().len(),
        30
    );
    assert_eq!(copy(&mut mac, &mut phone), 0);
}
