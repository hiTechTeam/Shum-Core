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
            Effect::Push { .. } | Effect::SendBle { .. } => {}
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
fn stop_and_errors_come_back_as_requests_answers() {
    let mut anya = profile("Аня");
    let request: Request =
        serde_json::from_value(json!({"command":"send","contact":"nobody","text":"x"})).unwrap();
    assert!(anya.request(1, request).unwrap().is_err());
    assert!(!anya.stopped());
    ok(&mut anya, json!({"command":"stop"}));
    assert!(anya.stopped());
}
