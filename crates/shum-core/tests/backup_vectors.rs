//! Protocol section 13 vectors. Regenerate with
//! `SHUM_WRITE_VECTORS=1 cargo test -p shum-core --test backup_vectors -- --ignored`.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};
use shum_core::{
    backup::{self, Keys, Payload, ProfileInfo, Seal},
    card::Card,
    crypto::{self, Secret32},
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/vectors/13-backup.json"
);

fn secret(byte: u8) -> Secret32 {
    Secret32::new([byte; 32])
}
fn payload(noise: u8, owner_override: Option<&str>) -> Payload {
    let (n, s, x) = (secret(noise), secret(0x22), secret(0x33));
    let card = Card::create(&n, &s, &x, "Руслан".into(), "", None, 1).unwrap();
    let owner = crypto::id(&n.noise_public());
    let owner = owner_override.map(str::to_string).unwrap_or(owner);
    Payload {
        version: 2,
        created_at: "2026-10-10T18:04:00Z".into(),
        profile: ProfileInfo {
            name: "Руслан".into(),
            owner_id: owner.clone(),
            extra: Map::new(),
        },
        keys: Keys {
            noise: n,
            signing: s,
            nostr: x,
        },
        state: json!({"version":1,"ownerID":owner,"ownProfileCard":card,"contacts":[],"requests":[],"conversations":[],"messages":[],"receipts":[],"invitationStates":{},"invitationOutbox":[]}),
        extra: Map::new(),
    }
}
fn seal_with(payload: &Payload, password: &str) -> Vec<u8> {
    backup::seal(
        payload,
        password,
        &Seal {
            salt: [7; 16],
            nonce: [9; 12],
            iterations: 210_000,
            created_at: "2026-10-10T18:04:00Z",
        },
    )
    .unwrap()
}

#[test]
#[ignore]
fn write_vectors() {
    if std::env::var_os("SHUM_WRITE_VECTORS").is_none() {
        return;
    }
    let password = "пароль-от-копии";
    let good = payload(0x11, None);
    let file = seal_with(&good, password);
    let key = backup::derive_key(password, &[7; 16], 210_000).unwrap();
    // Flip one ciphertext bit, keeping the header valid.
    let mut header: Value = serde_json::from_slice(&file[backup::MAGIC.len()..]).unwrap();
    let mut ciphertext = STANDARD
        .decode(header["ciphertext"].as_str().unwrap())
        .unwrap();
    ciphertext[0] ^= 1;
    header["ciphertext"] = json!(STANDARD.encode(ciphertext));
    let mut damaged = backup::MAGIC.to_vec();
    damaged.extend(serde_json::to_vec(&header).unwrap());
    let foreign = seal_with(&payload(0x11, Some(&"0".repeat(64))), password);
    let vectors = json!({
        "section": "13",
        "description": "Profile backup version 2. Salt and nonce are fixed only for these vectors; real backups use fresh random values.",
        "password": password,
        "salt": STANDARD.encode([7u8; 16]),
        "nonce": STANDARD.encode([9u8; 12]),
        "iterations": 210000,
        "key": hex::encode(*key),
        "payload": serde_json::to_value(&good).unwrap(),
        "file": STANDARD.encode(&file),
        "wrongPassword": "другой-пароль-123",
        "damagedFile": STANDARD.encode(&damaged),
        "foreignOwnerFile": STANDARD.encode(&foreign)
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn backup_vectors() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let password = v["password"].as_str().unwrap();
    let file = STANDARD.decode(v["file"].as_str().unwrap()).unwrap();
    let salt = STANDARD.decode(v["salt"].as_str().unwrap()).unwrap();
    let key = backup::derive_key(password, &salt, 210_000).unwrap();
    assert_eq!(hex::encode(*key), v["key"]);
    // Sealing the same payload with the same inputs gives the same bytes.
    assert_eq!(seal_with(&payload(0x11, None), password), file);
    let opened = backup::open(&file, password).unwrap();
    assert_eq!(serde_json::to_value(&opened).unwrap(), v["payload"]);
    assert_eq!(opened.check().unwrap().name, "Руслан");
    assert_eq!(backup::summary(&file).unwrap().profile_name, "Руслан");
    assert!(matches!(
        backup::open(&file, v["wrongPassword"].as_str().unwrap()),
        Err(shum_core::Error::Authentication)
    ));
    let damaged = STANDARD.decode(v["damagedFile"].as_str().unwrap()).unwrap();
    assert!(matches!(
        backup::open(&damaged, password),
        Err(shum_core::Error::Authentication)
    ));
    let foreign = STANDARD
        .decode(v["foreignOwnerFile"].as_str().unwrap())
        .unwrap();
    assert!(backup::open(&foreign, password).unwrap().check().is_err());
}
