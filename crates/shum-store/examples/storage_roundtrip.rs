//! Export an encrypted test-only database for the real Swift reader.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use shum_core::crypto::Secret32;
use shum_store::Store;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("output JSON path required")?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/09-storage.json"))?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("roundtrip.sqlite");
    std::fs::write(
        &path,
        STANDARD.decode(fixture["sqlite_base64"].as_str().ok_or("SQLite fixture")?)?,
    )?;
    let owner = fixture["owner_id"].as_str().ok_or("owner")?;
    let key = hex::decode(fixture["storage_key_hex"].as_str().ok_or("key")?)?
        .try_into()
        .map_err(|_| "key length")?;
    let mut store = Store::open(&path, owner, Secret32::new(key))?;
    store.transaction(|state| {
        state["messages"][0]["text"] = json!("Rust → Swift: привет 🦀");
        state["contacts"].as_array_mut().unwrap().reverse();
        state["seenRelay"]["rust-date"] = json!(-1.875);
        state["deletedMessageIDs"]["rust-tombstone"] = json!(821692801.625);
        Ok(())
    })?;
    let expected = store.state().clone();
    let snapshot = store.portable_snapshot()?;
    store.checkpoint()?;
    drop(store);
    let document = json!({"description":"Test-only storage roundtrip: Swift SQLite changed by Rust, read by Swift. The edited stored text is storage data, not a newly signed wire envelope.","generator":"Shum-Core shum-store/examples/storage_roundtrip.rs","owner_id":owner,"storage_key_hex":fixture["storage_key_hex"],"state_json":serde_json::to_string(&expected)?,"sqlite_base64":STANDARD.encode(std::fs::read(path)?),"snapshot_base64":STANDARD.encode(snapshot)});
    std::fs::write(output, serde_json::to_vec_pretty(&document)?)?;
    Ok(())
}
