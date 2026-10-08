use serde_json::json;
use shum_core::{
    card::Card,
    crypto::Secret32,
    engine::{Context, Engine, Keys},
    queue::Routes,
    rules::{InvitationState, Phase},
};
use shum_store::engine::{project, restore};

#[test]
fn outgoing_text_and_nostr_retries_survive_projection_and_unknown_fields() {
    let noise = Secret32::new([1; 32]);
    let signing = Secret32::new([2; 32]);
    let nostr = Secret32::new([3; 32]);
    let own = Card::create(&noise, &signing, &nostr, "Alice".into(), "", None, 1).unwrap();
    let peer = Card::create(
        &Secret32::new([11; 32]),
        &Secret32::new([12; 32]),
        &Secret32::new([13; 32]),
        "Bob".into(),
        "",
        None,
        1,
    )
    .unwrap();
    let mut engine = Engine::new(own.clone()).unwrap();
    engine.add_contact(peer.clone()).unwrap();
    engine.inbox.invitations.insert(
        peer.id(),
        InvitationState {
            phase: Phase::Accepted,
            updated_at: 0,
            event_id: "accepted".into(),
        },
    );
    let routes = Routes {
        internet: true,
        ..Routes::default()
    };
    let now = 1_800_000_000_000;
    let id = "11111111-2222-4333-8444-555555555555";
    let context = Context {
        now,
        uuid: id,
        routes: &routes,
        keys: Keys {
            noise: &noise,
            signing: &signing,
            nostr: &nostr,
        },
    };
    engine
        .send(
            &peer.id(),
            "Привет\nещё строка",
            None,
            &Secret32::new([21; 32]),
            &context,
        )
        .unwrap();
    engine.outbox.relay_result(id, true, now, false);
    let state = json!({"ownerID":own.id(),"ownProfileCard":own,"futureHeader":{"preserved":true}});
    let mut state = project(&state, &engine, now).unwrap();
    state["messages"][0]["futureRow"] = json!(42);
    state["messages"][0]["envelope"]["futureEnvelope"] = json!("keep");
    let restored = restore(&state, &signing).unwrap();
    assert_eq!(
        restored.outbox.messages[0].delivery,
        engine.outbox.messages[0].delivery
    );
    assert_eq!(
        restored.outbox.messages[0].plaintext,
        engine.outbox.messages[0].plaintext
    );
    let next = project(&state, &restored, now + 1).unwrap();
    assert_eq!(next["futureHeader"], state["futureHeader"]);
    assert_eq!(next["messages"][0]["futureRow"], 42);
    assert_eq!(next["messages"][0]["envelope"]["futureEnvelope"], "keep");
    assert_eq!(
        next, state,
        "an idle restored engine must not rewrite storage every second"
    );
}
