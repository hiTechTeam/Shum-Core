use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::Connection;
use serde_json::{json, Value};
use shum_core::crypto::Secret32;
use shum_store::{codec, Error, Store};
use std::{collections::BTreeMap, fs, path::Path};

fn vector() -> Value {
    serde_json::from_str(include_str!("../../../protocol/vectors/09-storage.json")).unwrap()
}
fn key(v: &Value) -> [u8; 32] {
    hex::decode(v["storage_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn fixture(path: &Path, v: &Value) {
    fs::write(
        path,
        STANDARD
            .decode(v["sqlite_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
}
fn raw(path: &Path) -> BTreeMap<(String, String), (i64, Vec<u8>)> {
    let db = Connection::open(path).unwrap();
    let mut q = db
        .prepare("SELECT bucket,id,position,payload FROM records")
        .unwrap();
    q.query_map([], |r| Ok(((r.get(0)?, r.get(1)?), (r.get(2)?, r.get(3)?))))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn cryptokit_records_match_every_byte() {
    let v = vector();
    let key = key(&v);
    for row in v["rows"].as_array().unwrap() {
        let bucket = row["bucket"].as_str().unwrap();
        let id = row["real_id"].as_str().unwrap();
        let position = row["position"].as_i64().unwrap();
        let index = codec::index_id(&key, bucket, id);
        assert_eq!(index, row["index_id"]);
        let aad = codec::aad(bucket, &index, position);
        assert_eq!(hex::encode(&aad), row["aad_hex"]);
        let json = row["payload_json"].as_str().unwrap().as_bytes();
        let packed = codec::pack(id, json).unwrap();
        assert_eq!(hex::encode(&packed), row["packed_plaintext_hex"]);
        let cipher = hex::decode(row["ciphertext_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            codec::seal(&key, cipher[..12].try_into().unwrap(), &packed, &aad).unwrap(),
            cipher
        );
        let plain = codec::open(&key, &cipher, &aad).unwrap();
        assert_eq!(codec::unpack(&plain).unwrap(), (id, json));
        assert!(codec::open(&[255; 32], &cipher, &aad).is_err());
    }
}

#[test]
fn swift_database_full_state_and_noop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("swift.sqlite");
    let v = vector();
    fixture(&path, &v);
    let before = raw(&path);
    let mut store = Store::open(
        &path,
        v["owner_id"].as_str().unwrap(),
        Secret32::new(key(&v)),
    )
    .unwrap();
    let expected: Value = serde_json::from_str(v["state_json"].as_str().unwrap()).unwrap();
    assert_eq!(store.state(), &expected);
    assert_eq!(store.stats().transactions, 0);
    assert!(!store.commit(expected).unwrap());
    assert_eq!(raw(&path), before);
    assert!(matches!(
        Store::open(
            &path,
            v["owner_id"].as_str().unwrap(),
            Secret32::new(key(&v))
        ),
        Err(Error::Locked)
    ));
    let snapshot = store.portable_snapshot().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&codec::open(&key(&v), &snapshot, &[]).unwrap()).unwrap(),
        *store.state()
    );
}

#[test]
fn rejects_swift_corruption_cases_and_wrong_identity() {
    let v = vector();
    for case in v["validation_cases"].as_array().unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.sqlite");
        fixture(&path, &v);
        Connection::open(&path)
            .unwrap()
            .execute_batch(case["sql"].as_str().unwrap())
            .unwrap();
        assert!(
            Store::open(
                &path,
                v["owner_id"].as_str().unwrap(),
                Secret32::new(key(&v))
            )
            .is_err(),
            "{}",
            case["label"]
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.sqlite");
    fixture(&path, &v);
    assert!(matches!(
        Store::open(&path, "wrong-owner", Secret32::new(key(&v))),
        Err(Error::Identity)
    ));
    assert!(Store::open(
        &path,
        v["owner_id"].as_str().unwrap(),
        Secret32::new([255; 32])
    )
    .is_err());
}

#[test]
fn diff_preserves_nonces_gaps_unknown_metadata_and_atomic_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("diff.sqlite");
    let v = vector();
    fixture(&path, &v);
    let owner = v["owner_id"].as_str().unwrap();
    let mut store = Store::open(&path, owner, Secret32::new(key(&v))).unwrap();
    let before = raw(&path);
    let old = store.state().clone();
    store
        .transaction(|s| {
            s["messages"][0]["text"] = json!("Rust → Swift, привет 🦀");
            s["futureMetadata"] = json!({"opaque":[1,"留",-0.125]});
            Ok(())
        })
        .unwrap();
    let after = raw(&path);
    for (token, cipher) in &before {
        if token.0 != "messages" && token.0 != "header" {
            assert_eq!(after[token], *cipher);
        }
    }
    assert_eq!(store.stats().written_rows, 2);
    let saved = store.state().clone();
    assert!(store
        .transaction(|s| {
            let duplicate = s["contacts"][0].clone();
            s["contacts"].as_array_mut().unwrap().push(duplicate);
            Ok(())
        })
        .is_err());
    assert_eq!(*store.state(), saved);
    assert_eq!(raw(&path), after);
    store
        .transaction(|s| {
            s["contacts"].as_array_mut().unwrap().remove(0);
            Ok(())
        })
        .unwrap();
    let contacts: Vec<_> = raw(&path)
        .into_iter()
        .filter(|(token, _)| token.0 == "contacts")
        .collect();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].1 .0, 1);
    store
        .transaction(|s| {
            s["contacts"]
                .as_array_mut()
                .unwrap()
                .push(old["contacts"][0].clone());
            Ok(())
        })
        .unwrap();
    let contacts: Vec<_> = raw(&path)
        .into_iter()
        .filter(|(token, _)| token.0 == "contacts")
        .collect();
    assert!(contacts.iter().any(|(_, (position, _))| *position == 2));
    store
        .transaction(|s| {
            s["contacts"].as_array_mut().unwrap().reverse();
            Ok(())
        })
        .unwrap();
    let contacts: Vec<_> = raw(&path)
        .into_iter()
        .filter(|(token, _)| token.0 == "contacts")
        .collect();
    assert!(contacts.iter().any(|(_, (position, _))| *position == 0));
    drop(store);
    let store = Store::open(&path, owner, Secret32::new(key(&v))).unwrap();
    assert_eq!(store.state()["futureMetadata"], saved["futureMetadata"]);
    assert_eq!(
        store.state()["messages"][0]["text"],
        saved["messages"][0]["text"]
    );
}

#[test]
fn stale_writer_and_failed_sql_transaction_publish_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conflict.sqlite");
    let v = vector();
    fixture(&path, &v);
    let owner = v["owner_id"].as_str().unwrap();
    let mut store = Store::open(&path, owner, Secret32::new(key(&v))).unwrap();
    let before = store.state().clone();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER reject_message BEFORE UPDATE ON records WHEN NEW.bucket='messages' BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    // Reopen to acknowledge this external schema change before testing rollback.
    drop(store);
    store = Store::open(&path, owner, Secret32::new(key(&v))).unwrap();
    assert!(store
        .transaction(|s| {
            s["messages"][0]["text"] = json!("should roll back");
            s["changedHeader"] = json!(true);
            Ok(())
        })
        .is_err());
    assert_eq!(*store.state(), before);
    assert_eq!(store.stats().transactions, 0);
    db.execute_batch("DROP TRIGGER reject_message; UPDATE records SET position=position+1 WHERE bucket='messages';").unwrap();
    assert!(matches!(store.commit(before.clone()), Err(Error::Conflict)));
    assert_eq!(*store.state(), before);
}

#[test]
fn creates_private_database_and_migrates_portable_v1_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.sqlite");
    let mut store = Store::open(&path, "owner", Secret32::new([7; 32])).unwrap();
    store
        .transaction(|s| {
            s["futureMetadata"] = json!("kept");
            Ok(())
        })
        .unwrap();
    let expected = store.state().clone();
    let snapshot = store.portable_snapshot().unwrap();
    drop(store);
    let legacy = dir.path().join("legacy.db");
    fs::write(&legacy, &snapshot).unwrap();
    let store = Store::open(&legacy, "owner", Secret32::new([7; 32])).unwrap();
    assert_eq!(*store.state(), expected);
    assert_eq!(
        fs::read(dir.path().join("legacy.db.v1-recovery")).unwrap(),
        snapshot
    );
    assert!(fs::read(&legacy).unwrap().starts_with(b"SQLite format 3\0"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bad = dir.path().join("bad.db");
    fs::write(&bad, b"original invalid snapshot").unwrap();
    assert!(Store::open(&bad, "owner", Secret32::new([7; 32])).is_err());
    assert_eq!(fs::read(&bad).unwrap(), b"original invalid snapshot");
}

#[test]
fn cryptokit_legacy_aes_layer_uses_a_separate_key_and_imports_once() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/09-legacy-cipher.json"
    ))
    .unwrap();
    let key: [u8; 32] = hex::decode(v["legacy_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let cipher = hex::decode(v["combined_hex"].as_str().unwrap()).unwrap();
    let plain = codec::open_legacy_archive(&key, &cipher).unwrap();
    assert_eq!(hex::encode(&plain), v["plaintext_hex"]);
    assert!(codec::open_legacy_archive(&[7; 32], &cipher).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-import.sqlite");
    let mut store = Store::open(&path, "owner", Secret32::new([7; 32])).unwrap();
    assert!(store
        .import_legacy_archive(&cipher, &Secret32::new(key))
        .unwrap());
    assert_eq!(
        store.state()["legacyHistory"]["cryptoTest"],
        "Архив Swift ☕️"
    );
    assert!(!store
        .import_legacy_archive(&cipher, &Secret32::new(key))
        .unwrap());
    drop(store);
    let store = Store::open(&path, "owner", Secret32::new([7; 32])).unwrap();
    assert_eq!(
        store.state()["legacyHistory"]["cryptoTest"],
        "Архив Swift ☕️"
    );
}
