use serde_json::Value;
use shum_core::{crypto::Secret32, noise};
fn b(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn secret(v: &Value, k: &str) -> Secret32 {
    Secret32::new(b(v, k).try_into().unwrap())
}
#[test]
fn swift_courier_read_write_and_rejection() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/03-courier.json")).unwrap();
    for c in fixture["cases"].as_array().unwrap() {
        let sender = secret(&c["sender_keys"], "noise_private_key");
        let recipient = secret(&c["recipient_keys"], "noise_private_key");
        let ephemeral = secret(c, "ephemeral_private_key");
        let plain = b(c, "plaintext_hex");
        let cipher =
            noise::seal_courier(&sender, &recipient.noise_public(), &ephemeral, &plain).unwrap();
        assert_eq!(cipher, b(c, "ciphertext_hex"), "{}", c["label"]);
        for field in ["ciphertext_hex", "service_ciphertext_hex"] {
            let (opened, author) = noise::open_courier(&recipient, &b(c, field)).unwrap();
            assert_eq!(opened, plain);
            assert_eq!(author.to_vec(), b(c, "swift_sender_static_key"));
        }
        for n in c["negative_cases"].as_array().unwrap() {
            let wrong = n["recipient_private_key"]
                .as_str()
                .map(|k| Secret32::new(hex::decode(k).unwrap().try_into().unwrap()));
            assert_eq!(
                noise::open_courier(
                    wrong.as_ref().unwrap_or(&recipient),
                    &b(n, "ciphertext_hex")
                )
                .is_ok(),
                n["swift_valid"].as_bool().unwrap(),
                "{}",
                n["label"]
            );
        }
    }
}
