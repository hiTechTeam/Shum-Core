use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use shum_core::{packet::*, Result};
fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(format!(
            "{}/../../protocol/vectors/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}
fn check<T: DeserializeOwned + Serialize>(
    f: &Value,
    kind: &str,
    validate: impl Fn(&T, i64) -> Result<()>,
    signing: impl Fn(&T) -> Result<Vec<u8>>,
) {
    let now = s(f, "now_ms").parse::<i64>().unwrap();
    for c in f[kind].as_array().unwrap() {
        let v: T = serde_json::from_str(s(c, "control_json")).unwrap();
        assert_eq!(
            hex::encode(signing(&v).unwrap()),
            s(c, "signing_bytes_hex"),
            "{} {}",
            kind,
            c["label"]
        );
        assert_eq!(
            validate(&v, now).is_ok(),
            c["swift_valid"].as_bool().unwrap(),
            "{} {}",
            kind,
            c["label"]
        );
        let packet = Packet::decode(s(c, "packet_json").as_bytes()).unwrap();
        assert_eq!(
            serde_json::to_value(packet).unwrap(),
            serde_json::from_str::<Value>(s(c, "packet_json")).unwrap()
        );
    }
}
#[test]
fn envelope_signatures_and_boundaries() {
    let f = fixture("03-envelope");
    for c in f["cases"].as_array().unwrap() {
        let e: Envelope = serde_json::from_str(s(c, "envelope_json")).unwrap();
        assert_eq!(e.digest(), s(c, "digest"));
        assert_eq!(
            hex::encode(e.signing_bytes().unwrap()),
            s(c, "signing_bytes_hex")
        );
        assert_eq!(
            e.validate(s(&f, "now_ms").parse::<i64>().unwrap()).is_ok(),
            c["swift_valid"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
    }
    let e: Envelope = serde_json::from_str(s(&f["cases"][0], "envelope_json")).unwrap();
    let k = shum_core::crypto::Secret32::new(
        hex::decode(s(&f["recipient_keys"], "noise_private_key"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        shum_core::canonical::encode(&e.open(&k, s(&f, "now_ms").parse::<i64>().unwrap()).unwrap())
            .unwrap(),
        hex::decode(s(&f, "plaintext_hex")).unwrap()
    );
}
#[test]
fn all_control_signing_and_validation_cases() {
    let f = fixture("04-controls");
    check::<InvitationControl>(
        &f,
        "invitation",
        |v, n| v.validate(n),
        |v| v.signing_bytes(),
    );
    check::<Typing>(&f, "typing", |v, n| v.validate(n), |v| v.signing_bytes());
    check::<Presence>(&f, "presence", |v, n| v.validate(n), |v| v.signing_bytes());
    check::<Receipt>(&f, "receipt", |v, n| v.validate(n), |v| v.signing_bytes());
    check::<Retract>(&f, "retract", |v, n| v.validate(n), |v| v.signing_bytes());
    check::<Reaction>(&f, "reaction", |v, n| v.validate(n), |v| v.signing_bytes());
}
#[test]
fn swift_profile_sync_cases() {
    for c in fixture("04-profile-sync")["cases"].as_array().unwrap() {
        let sync: ProfileSync = serde_json::from_str(s(c, "sync_json")).unwrap();
        assert_eq!(
            hex::encode(sync.signing_bytes().unwrap()),
            s(c, "signing_bytes_hex")
        );
        assert_eq!(sync.validate().is_ok(), c["swift_valid"].as_bool().unwrap());
        Packet::decode(s(c, "packet_json").as_bytes()).unwrap();
    }
}
