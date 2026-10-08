use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use shum_core::{card::Card, crypto::Secret32};
use shum_transport_nostr::push;
#[test]
fn requests_match_actual_swift_bytes_and_signatures() {
    let v: Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/08-requests.json")).unwrap();
    let raw = hex::decode(v["sender_keys"]["signing_private_key"].as_str().unwrap()).unwrap();
    let key = Secret32::new(raw.try_into().unwrap());
    let card: Card = serde_json::from_str(v["card_json"].as_str().unwrap()).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let headers = &case["headers"];
        let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
        let request = push::signed_request(
            case["method"].as_str().unwrap(),
            case["path"].as_str().unwrap(),
            body.clone(),
            &key,
            headers["X-Shum-Timestamp"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            headers["X-Shum-Nonce"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&request.signing_bytes),
            case["signing_bytes_hex"]
        );
        // CryptoKit randomizes Ed25519 signatures; compare verification, not bytes.
        for signature in [
            &request.signature,
            headers["X-Shum-Signature"].as_str().unwrap(),
        ] {
            assert!(shum_core::crypto::verify_ed(
                &key.ed_public(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
                &request.signing_bytes
            ));
        }
        assert_eq!(request.public_key, headers["X-Shum-Public-Key"]);
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(push::card_dto(&card).unwrap(), json["card"]);
        if case["path"] == "/v1/notifications" {
            assert_eq!(
                push::notification_body(
                    &card,
                    json["recipient_id"].as_str().unwrap(),
                    json["event_id"].as_str().unwrap(),
                    serde_json::from_value(json["kind"].clone()).unwrap()
                )
                .unwrap(),
                body
            );
        }
    }
}
