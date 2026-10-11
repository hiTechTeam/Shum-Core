//! The record layout without any storage backend, as the browser uses it:
//! the iOS app's records open, plans round-trip, and tampering is caught.
//! Runs natively and in WebAssembly (scripts/test-wasm.sh).
use serde_json::{json, Value};
use shum_core::crypto::Secret32;
use shum_store::{
    empty_state,
    records::{Plan, Record, Records},
    Error,
};
use std::collections::BTreeMap;

type Backend = BTreeMap<(String, String), Record>;

fn vector() -> Value {
    serde_json::from_str(include_str!("../../../protocol/vectors/09-storage.json")).unwrap()
}
fn key(v: &Value) -> Secret32 {
    Secret32::new(
        hex::decode(v["storage_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
/// The records exactly as the iOS app stored them in SQLite.
fn ios_records(v: &Value) -> Vec<Record> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Record {
            bucket: row["bucket"].as_str().unwrap().into(),
            id: row["index_id"].as_str().unwrap().into(),
            position: row["position"].as_i64().unwrap(),
            payload: hex::decode(row["ciphertext_hex"].as_str().unwrap()).unwrap(),
        })
        .collect()
}
fn persist(backend: &mut Backend, plan: &Plan) {
    for record in &plan.write {
        backend.insert((record.bucket.clone(), record.id.clone()), record.clone());
    }
    for token in &plan.delete {
        backend.remove(token);
    }
}

#[test]
fn the_ios_apps_records_open_without_sqlite() {
    let v = vector();
    let owner = v["owner_id"].as_str().unwrap();
    let records = Records::load(owner, key(&v), ios_records(&v)).unwrap();
    let expected: Value = serde_json::from_str(v["state_json"].as_str().unwrap()).unwrap();
    assert_eq!(records.state(), &expected);
    assert!(
        records.plan(expected).unwrap().is_none(),
        "no-op commits nothing"
    );
}

#[test]
fn plans_round_trip_through_any_record_store() {
    let owner = "ab".repeat(32);
    let key = || Secret32::new([7; 32]);
    let (mut records, created) = Records::create(&owner, key(), &empty_state(&owner)).unwrap();
    let mut backend: Backend = created
        .into_iter()
        .map(|r| ((r.bucket.clone(), r.id.clone()), r))
        .collect();

    let mut next = records.state().clone();
    next["conversations"] = json!([{"id": "c1", "title": "Аня"}, {"id": "c2"}]);
    next["blocked"] = json!({"peer": {"name": "spam"}});
    let plan = records.plan(next.clone()).unwrap().unwrap();
    assert!(plan.delete.is_empty());
    persist(&mut backend, &plan);
    records.apply(plan);

    // Only what changed is rewritten; removed items are deleted.
    let mut later = next.clone();
    later["conversations"] = json!([{"id": "c2"}]);
    let plan = records.plan(later.clone()).unwrap().unwrap();
    assert_eq!(plan.delete.len(), 1, "c1 is gone");
    assert!(plan
        .write
        .iter()
        .all(|r| r.bucket == "header" || r.bucket == "conversations"));
    persist(&mut backend, &plan);
    records.apply(plan);

    let reopened = Records::load(&owner, key(), backend.values().cloned()).unwrap();
    assert_eq!(reopened.state(), &later);
    assert_eq!(reopened.state(), records.state());
}

#[test]
fn tampered_or_foreign_records_are_rejected() {
    let v = vector();
    let owner = v["owner_id"].as_str().unwrap();
    let good = ios_records(&v);

    let mut flipped = good.clone();
    let last = flipped[0].payload.len() - 1;
    flipped[0].payload[last] ^= 1;
    assert!(matches!(
        Records::load(owner, key(&v), flipped),
        Err(Error::Core(_)) | Err(Error::Authentication) | Err(Error::Invalid(_))
    ));

    let mut moved = good.clone();
    let message = moved.iter_mut().find(|r| r.bucket == "messages").unwrap();
    message.position += 1;
    assert!(
        Records::load(owner, key(&v), moved).is_err(),
        "position is authenticated"
    );

    let mut missing = good.clone();
    missing.retain(|r| r.bucket != "contacts");
    assert!(
        Records::load(owner, key(&v), missing).is_err(),
        "row counts are checked"
    );

    assert!(
        Records::load(&"cd".repeat(32), key(&v), good.clone()).is_err(),
        "other owner"
    );
    assert!(
        Records::load(owner, Secret32::new([1; 32]), good).is_err(),
        "wrong key"
    );
}
