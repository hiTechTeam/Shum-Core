use serde_json::Value;
use shum_core::{crypto::Secret32, noise::*};
fn b(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn secret(v: &Value, k: &str) -> Secret32 {
    Secret32::new(b(v, k).try_into().unwrap())
}
#[test]
fn exact_swift_xx_transcript_and_transport_ciphers() {
    let f: Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/06-noise-xx.json")).unwrap();
    let mut i = HandshakeXX::new(
        Role::Initiator,
        secret(&f["initiator_keys"], "noise_private_key"),
        secret(&f, "initiator_ephemeral_private_key"),
    );
    let mut r = HandshakeXX::new(
        Role::Responder,
        secret(&f["responder_keys"], "noise_private_key"),
        secret(&f, "responder_ephemeral_private_key"),
    );
    let a = i.write(&[]).unwrap();
    assert!(r.read(&a).unwrap().is_empty());
    let b = r.write(&[]).unwrap();
    assert!(i.read(&b).unwrap().is_empty());
    let c = i.write(&[]).unwrap();
    assert!(r.read(&c).unwrap().is_empty());
    assert_eq!(
        vec![hex::encode(a), hex::encode(b), hex::encode(c)],
        f["handshake_messages_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    );
    let i = i.finish().unwrap();
    let r = r.finish().unwrap();
    assert_eq!(
        hex::encode(i.handshake_hash),
        f["handshake_hash"].as_str().unwrap()
    );
    assert_eq!(i.handshake_hash, r.handshake_hash);
    for (index, c) in f["traffic"].as_array().unwrap().iter().enumerate() {
        let (send, receive, count) = if index < 2 {
            (&i.send, &r.receive, index as u32)
        } else {
            (&r.send, &i.receive, 0)
        };
        let bytes = hex::decode(c["plaintext_hex"].as_str().unwrap()).unwrap();
        let expected = hex::decode(c["ciphertext_hex"].as_str().unwrap()).unwrap();
        assert_eq!(seal_transport(send, count, &bytes).unwrap(), expected);
        assert_eq!(open_transport(receive, &expected).unwrap(), (count, bytes));
    }
    // The Swift replay-window defect is recorded in spec/06. A session guard
    // is pending the owner's decision; this test covers the AEAD primitive.
}

#[test]
fn authenticated_replay_window_keeps_bits_and_ignores_bad_tags() {
    use shum_core::{
        crypto::Secret32,
        noise::{seal_transport, Session, SplitKeys},
    };
    let key = Secret32::new([3; 32]);
    let mut receiver = Session::new(SplitKeys {
        send: Secret32::new([4; 32]),
        receive: Secret32::new([3; 32]),
        remote_static: [5; 32],
        handshake_hash: [6; 32],
    });
    let zero = seal_transport(&key, 0, b"zero").unwrap();
    let one = seal_transport(&key, 1, b"one").unwrap();
    assert_eq!(receiver.receive(&zero).unwrap(), b"zero");
    assert_eq!(receiver.receive(&one).unwrap(), b"one");
    assert!(receiver.receive(&zero).is_err());
    let two = seal_transport(&key, 2, b"two").unwrap();
    let mut corrupt = two.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(receiver.receive(&corrupt).is_err());
    assert_eq!(receiver.receive(&two).unwrap(), b"two");
    let future = seal_transport(&key, 130, b"future").unwrap();
    assert!(receiver.receive(&future).is_ok());
    let middle = seal_transport(&key, 65, b"middle").unwrap();
    assert!(receiver.receive(&middle).is_ok());
    assert!(receiver.receive(&middle).is_err());
    assert!(receiver.receive(&zero).is_err());
    assert!(receiver
        .receive(&seal_transport(&key, 2048, b"far").unwrap())
        .is_ok());
    assert!(receiver.receive(&one).is_err());
}
