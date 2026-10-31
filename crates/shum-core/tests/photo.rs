//! Photos in messages, protocol section 04.9.
use shum_core::{
    crypto::Secret32,
    packet::Packet,
    photo::{Photo, PhotoPart, MAX_PARTS, MAX_SIZE, PART},
};

const ID: &str = "11111111-2222-4333-8444-000000000001";

fn jpeg(size: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
    v[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
    v
}

fn sealed(size: usize) -> (Vec<u8>, Photo, Vec<PhotoPart>) {
    let bytes = jpeg(size);
    let (photo, parts) =
        Photo::seal(ID, &bytes, 1280, 960, false, &Secret32::new([9; 32])).unwrap();
    (bytes, photo, parts)
}

#[test]
fn a_photo_goes_in_parts_and_comes_back_whole() {
    let (bytes, photo, parts) = sealed(2 * PART + 100);
    assert_eq!(photo.count(), 3);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2].data.len(), 100 + 16);
    let opened: Vec<_> = parts.iter().map(|p| photo.open(ID, p).unwrap()).collect();
    assert_eq!(photo.join(&opened).unwrap(), bytes);
    // Out of order or with a part missing it does not join.
    assert!(photo
        .join(&[opened[1].clone(), opened[0].clone(), opened[2].clone()])
        .is_err());
    assert!(photo.join(&opened[..2]).is_err());
}

#[test]
fn a_part_opens_only_for_its_message_and_place() {
    let (_, photo, parts) = sealed(2 * PART);
    let mut forged = parts[0].clone();
    forged.data[5] ^= 1;
    assert!(photo.open(ID, &forged).is_err(), "changed bytes");
    let mut moved = parts[0].clone();
    moved.index = 1;
    assert!(photo.open(ID, &moved).is_err(), "another place");
    let mut other = parts[0].clone();
    other.message_id = "11111111-2222-4333-8444-000000000002".into();
    assert!(
        photo.open(&other.message_id, &other).is_err(),
        "another message"
    );
    assert!(photo
        .open("11111111-2222-4333-8444-000000000002", &parts[0])
        .is_err());
    let (_, stranger, _) = {
        let bytes = jpeg(2 * PART);
        let (p, parts) = Photo::seal(ID, &bytes, 10, 10, false, &Secret32::new([8; 32])).unwrap();
        (bytes, p, parts)
    };
    assert!(stranger.open(ID, &parts[0]).is_err(), "another key");
}

#[test]
fn photos_stay_within_the_limits() {
    assert_eq!(MAX_PARTS, 11);
    let key = Secret32::new([9; 32]);
    assert!(Photo::seal(ID, &jpeg(MAX_SIZE), 2048, 2048, true, &key).is_ok());
    assert!(Photo::seal(ID, &jpeg(MAX_SIZE + 1), 10, 10, true, &key).is_err());
    assert!(Photo::seal(ID, &jpeg(100), 2049, 10, true, &key).is_err());
    assert!(Photo::seal(ID, &jpeg(100), 10, 0, true, &key).is_err());
    assert!(
        Photo::seal(ID, b"\x89PNG....", 10, 10, true, &key).is_err(),
        "JPEG only"
    );
    assert!(Photo::seal("not-a-uuid", &jpeg(100), 10, 10, true, &key).is_err());

    let (_, photo, _) = sealed(100);
    for broken in [
        Photo {
            kind: "image/png".into(),
            ..photo.clone()
        },
        Photo {
            sha256: photo.sha256.to_uppercase(),
            ..photo.clone()
        },
        Photo {
            key: vec![1; 31],
            ..photo.clone()
        },
        Photo {
            size: 0,
            ..photo.clone()
        },
    ] {
        assert!(broken.validate().is_err());
    }
}

#[test]
fn a_full_part_fits_one_packet() {
    let (_, _, parts) = sealed(MAX_SIZE);
    assert_eq!(parts.len(), MAX_PARTS);
    let packet = Packet {
        photo_part: Some(parts[0].clone()),
        ..Packet::default()
    };
    let bytes = serde_json::to_vec(&packet).unwrap();
    assert!(bytes.len() < 24_000, "{}", bytes.len());
    assert_eq!(Packet::decode(&bytes).unwrap(), packet);
    // A part is a packet of its own, never next to a message.
    let mut two = serde_json::to_value(&packet).unwrap();
    two["typing"] = serde_json::to_value(&Packet::default()).unwrap();
    assert!(Packet::decode(&serde_json::to_vec(&two).unwrap()).is_err());
}

#[test]
fn the_sealed_bytes_are_fixed_by_key_message_and_place() {
    // Vector for other clients: key 09 × 32, message ID above, JPEG of 20
    // bytes as built by jpeg(20).
    let (bytes, photo, parts) = sealed(20);
    assert_eq!(
        hex::encode(&bytes),
        "ffd8ff15 1c23 2a31 383f 464d 545b 6269 7077 7e85".replace(' ', "")
    );
    assert_eq!(photo.sha256, shum_core::crypto::id(&bytes));
    assert_eq!(parts.len(), 1);
    assert_eq!(hex::encode(&parts[0].data), VECTOR);
}

/// Sealed with CryptoKit, independently of this code.
const VECTOR: &str = "61dc41ed8ff97e754dcbfde0e8691fe786981dedf81cae411ce7f210c7a8b6578f57cef9";
