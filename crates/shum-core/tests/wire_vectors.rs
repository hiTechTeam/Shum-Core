use serde_json::Value;
use shum_core::{
    crypto,
    wire::{fragments, routing_id, Announcement, Assemblies, Frame},
};
fn vector(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!("../../protocol/vectors/{name}.json")).unwrap(),
    )
    .unwrap()
}
fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
#[test]
fn swift_binary_frames_padding_compression_and_signatures() {
    let data = vector("06-frames");
    for case in data["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let frame: Frame = serde_json::from_str(case["packet_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            frame.encode(false).unwrap(),
            hex(&case["wire_hex"]),
            "{label}"
        );
        assert_eq!(
            frame.encode(true).unwrap(),
            hex(&case["padded_wire_hex"]),
            "{label}"
        );
        assert_eq!(
            frame.signing_bytes().unwrap(),
            hex(&case["signing_bytes_hex"]),
            "{label}"
        );
        assert_eq!(
            Frame::decode(&hex(&case["wire_hex"])).unwrap(),
            frame,
            "{label}"
        );
        assert_eq!(
            Frame::decode(&hex(&case["padded_wire_hex"])).unwrap(),
            frame,
            "{label}"
        );
        assert!(
            frame
                .verify(&hex(&data["keys"]["signing_public_key"]))
                .unwrap(),
            "{label}"
        );
        for len in [0, 1, 11, 13, 21] {
            assert!(Frame::decode(&hex(&case["wire_hex"])[..len]).is_err());
        }
    }
    let announce = Announcement::decode(&hex(&data["announcement_hex"])).unwrap();
    assert_eq!(announce.nickname, data["announcement_decoded_name"]);
    assert_eq!(announce.encode().unwrap(), hex(&data["announcement_hex"]));
    assert_eq!(
        routing_id(&announce.noise).as_slice(),
        hex::decode(data["routing_peer_id"].as_str().unwrap()).unwrap()
    );
    assert_eq!(crypto::id(&announce.noise)[..16], data["routing_peer_id"]);
}
#[test]
fn swift_fragment_stream_reversed_and_bounded() {
    let data = vector("06-fragments");
    let original = Frame::decode(&hex(&data["original_wire_hex"])).unwrap();
    let expected: Vec<Frame> = data["fragment_packets_json"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_str(v.as_str().unwrap()).unwrap())
        .collect();
    let generated = fragments(
        &original,
        expected[0].payload[..8].try_into().unwrap(),
        100,
        false,
    )
    .unwrap();
    assert_eq!(generated, expected);
    let mut buffer = Assemblies::default();
    let mut result = None;
    for (f, wire) in expected
        .iter()
        .zip(data["fragment_wire_hex"].as_array().unwrap())
        .rev()
    {
        assert_eq!(f.encode(false).unwrap(), hex(wire));
        assert_eq!(Frame::decode(&hex(wire)).unwrap(), *f);
        result = buffer.ingest(f, 1000).unwrap().or(result);
    }
    assert_eq!(
        result.unwrap().encode(false).unwrap(),
        hex(&data["swift_reassembled_hex"])
    );
    // Expiring a partial transfer must not mix a subsequent transfer with it.
    let mut buffer = Assemblies::default();
    assert!(buffer.ingest(&expected[0], 0).unwrap().is_none());
    for f in expected.iter().skip(1) {
        assert!(buffer.ingest(f, 30000).unwrap().is_none());
    }
    assert!(buffer.ingest(&expected[0], 30001).unwrap().is_some());
}
