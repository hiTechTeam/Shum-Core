use serde_json::Value;
use shum_core::{
    canonical,
    packet::{InvitationAvatar, InvitationControl},
    profile::{Manifest, ProfilePacket},
};
fn fixture(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!("../../protocol/vectors/{name}.json")).unwrap(),
    )
    .unwrap()
}
#[test]
fn swift_profile_manifests_and_auxiliary_packets() {
    let f = fixture("04-profile-packets");
    for c in f["cases"].as_array().unwrap() {
        let json = c["manifest_json"].as_str().unwrap();
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(
            m.valid(),
            c["manifest_valid"].as_bool().unwrap(),
            "{}",
            c["label"]
        );
        assert_eq!(m.revision(), c["revision"]);
        assert_eq!(canonical::encode(&m).unwrap(), json.as_bytes());
        ProfilePacket::decode(c["packet_json"].as_str().unwrap().as_bytes()).unwrap();
    }
    for p in f["other_packets_json"].as_array().unwrap() {
        let json = p.as_str().unwrap();
        let packet = ProfilePacket::decode(json.as_bytes()).unwrap();
        assert_eq!(canonical::encode(&packet).unwrap(), json.as_bytes());
    }
}
#[test]
fn swift_attachment_signing_bytes_without_image_rendering() {
    let f = fixture("04-invitation-avatar");
    let a: InvitationAvatar = serde_json::from_str(f["avatar_json"].as_str().unwrap()).unwrap();
    let mut c: InvitationControl =
        serde_json::from_str(f["control_json"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(a.signing_bytes(&c)), f["signing_bytes_hex"]);
    assert!(a.authenticate(&c));
    c.fields.action = shum_core::packet::InvitationAction::Decline;
    assert!(!a.authenticate(&c));
}
