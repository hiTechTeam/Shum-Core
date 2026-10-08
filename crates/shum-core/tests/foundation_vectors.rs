use serde_json::Value;
use shum_core::card;
#[test]
fn exact_foundation_whitespace_set() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/02-foundation-ed25519.json"
    ))
    .unwrap();
    let actual: Vec<_> = (0..=0x10ffff)
        .filter_map(char::from_u32)
        .filter(|c| card::foundation_space(*c))
        .map(|c| u64::from(c as u32))
        .collect();
    let expected: Vec<_> = fixture["whitespace_scalars"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn approved_strict_ed25519_exception_is_explicit() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/02-foundation-ed25519.json"
    ))
    .unwrap();
    for c in f["ed25519_cases"].as_array().unwrap() {
        let valid = shum_core::crypto::verify_ed(
            &hex::decode(c["public_key"].as_str().unwrap()).unwrap(),
            &hex::decode(c["signature"].as_str().unwrap()).unwrap(),
            &hex::decode(c["message_hex"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(valid, c["label"] == "valid", "{}", c["label"]);
        if c["label"] == "identity-public-and-R-zero-S" || c["label"] == "zero-public-and-R-zero-S"
        {
            assert!(c["swift_valid"].as_bool().unwrap());
            assert!(!valid);
        }
    }
}
