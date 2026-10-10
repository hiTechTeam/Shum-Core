//! Profile backup file, protocol section 13.
//!
//! A password seals the payload: the three private keys and the section 09
//! database state. Salt, nonce and creation time come from the caller; this
//! module neither reads files nor draws randomness.
use crate::{card::Card, crypto::Secret32, Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload as Aad},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8] = b"SHUM-BACKUP-2\n";
const AAD: &[u8] = b"SHUM-BACKUP-2";
pub const VERSION: u32 = 2;
pub const EXTENSION: &str = "shumbackup";
pub const ITERATIONS: u32 = 210_000;
const ITERATION_RANGE: std::ops::RangeInclusive<u32> = 100_000..=1_000_000;
pub const MAX_FILE_BYTES: usize = 192 * 1024 * 1024;
pub const MIN_PASSWORD_CHARACTERS: usize = 10;
const MAX_PASSWORD_BYTES: usize = 256;
const KDF: &str = "PBKDF2-HMAC-SHA256";
const CIPHER: &str = "AES-256-GCM";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Header {
    version: u32,
    created_at: String,
    profile_name: String,
    kdf: Kdf,
    cipher: String,
    nonce: String,
    ciphertext: String,
}
#[derive(Serialize, Deserialize)]
struct Kdf {
    name: String,
    salt: String,
    iterations: u32,
}

/// Header fields shown before the password is entered. Not authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub profile_name: String,
    pub created_at: String,
}

/// Decrypted backup contents. Unknown fields survive a restore and re-export.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub version: u32,
    pub created_at: String,
    pub profile: ProfileInfo,
    pub keys: Keys,
    pub state: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: String,
    #[serde(rename = "ownerID")]
    pub owner_id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
#[derive(Serialize, Deserialize)]
pub struct Keys {
    #[serde(with = "secret")]
    pub noise: Secret32,
    #[serde(with = "secret")]
    pub signing: Secret32,
    #[serde(with = "secret")]
    pub nostr: Secret32,
}

/// Fresh random inputs and the creation time, supplied by the caller.
pub struct Seal<'a> {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub iterations: u32,
    pub created_at: &'a str,
}

/// Normalizes and checks a password chosen for a new backup.
pub fn check_password(password: &str) -> Result<()> {
    normalized(password).map(|_| ())
}

fn normalized(password: &str) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(password.nfc().collect::<String>());
    if value.graphemes(true).count() < MIN_PASSWORD_CHARACTERS || value.len() > MAX_PASSWORD_BYTES {
        return Err(Error::Invalid("backup password"));
    }
    Ok(value)
}

/// PBKDF2-HMAC-SHA256 with one 32-byte output block.
fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mac =
        <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC takes keys of any length");
    let mut round = mac.clone();
    round.update(salt);
    round.update(&1u32.to_be_bytes());
    let mut block: [u8; 32] = round.finalize().into_bytes().into();
    let mut key = Zeroizing::new(block);
    for _ in 1..iterations {
        let mut round = mac.clone();
        round.update(&block);
        block = round.finalize().into_bytes().into();
        for (out, byte) in key.iter_mut().zip(block) {
            *out ^= byte;
        }
    }
    block.zeroize();
    key
}

/// The 32-byte AES key for a password; exposed for test vectors.
pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<Zeroizing<[u8; 32]>> {
    Ok(pbkdf2(normalized(password)?.as_bytes(), salt, iterations))
}

impl Payload {
    /// Checks that keys, owner and the own card belong together (section 13.5).
    /// Returns the own card on success.
    pub fn check(&self) -> Result<Card> {
        let noise = self.keys.noise.noise_public();
        let owner = crate::crypto::id(&noise);
        if self.version != VERSION
            || self.profile.owner_id != owner
            || self.state["ownerID"].as_str() != Some(owner.as_str())
            || self.state["version"].as_u64() != Some(1)
            || crate::card::trim(&self.profile.name).is_empty()
            || self.profile.name.len() > 64
        {
            return Err(Error::Invalid("backup owner"));
        }
        let card: Card = serde_json::from_value(self.state["ownProfileCard"].clone())?;
        card.validate()?;
        let nostr = hex::encode(self.keys.nostr.nostr_public()?);
        if card.noise_key != noise
            || card.signing_key != self.keys.signing.ed_public()
            || card.nostr_key != nostr
        {
            return Err(Error::Invalid("backup keys"));
        }
        Ok(card)
    }
}

/// Encrypts a payload into a complete `.shumbackup` file.
pub fn seal(payload: &Payload, password: &str, seal: &Seal<'_>) -> Result<Vec<u8>> {
    if !ITERATION_RANGE.contains(&seal.iterations) {
        return Err(Error::Invalid("backup iterations"));
    }
    let key = derive_key(password, &seal.salt, seal.iterations)?;
    let plain = Zeroizing::new(serde_json::to_vec(payload)?);
    let ciphertext = Aes256Gcm::new(key.as_ref().into())
        .encrypt(
            Nonce::from_slice(&seal.nonce),
            Aad {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| Error::Invalid("backup size"))?;
    let header = Header {
        version: VERSION,
        created_at: seal.created_at.into(),
        profile_name: payload.profile.name.clone(),
        kdf: Kdf {
            name: KDF.into(),
            salt: STANDARD.encode(seal.salt),
            iterations: seal.iterations,
        },
        cipher: CIPHER.into(),
        nonce: STANDARD.encode(seal.nonce),
        ciphertext: STANDARD.encode(ciphertext),
    };
    let mut file = MAGIC.to_vec();
    file.extend(serde_json::to_vec(&header)?);
    if file.len() > MAX_FILE_BYTES {
        return Err(Error::Invalid("backup size"));
    }
    Ok(file)
}

fn header(file: &[u8]) -> Result<Header> {
    if file.len() <= MAGIC.len() || file.len() > MAX_FILE_BYTES || !file.starts_with(MAGIC) {
        return Err(Error::Invalid("backup file"));
    }
    let header: Header = serde_json::from_slice(&file[MAGIC.len()..])?;
    if header.version != VERSION
        || header.kdf.name != KDF
        || header.cipher != CIPHER
        || !ITERATION_RANGE.contains(&header.kdf.iterations)
    {
        return Err(Error::Invalid("backup version"));
    }
    Ok(header)
}

/// Name and date to show before asking for the password.
pub fn summary(file: &[u8]) -> Result<Summary> {
    let header = header(file)?;
    Ok(Summary {
        profile_name: header.profile_name,
        created_at: header.created_at,
    })
}

/// Decrypts a backup. A wrong password and a damaged file both give
/// `Error::Authentication`.
pub fn open(file: &[u8], password: &str) -> Result<Payload> {
    let header = header(file)?;
    let decode = |value: &str| {
        STANDARD
            .decode(value)
            .map_err(|_| Error::Invalid("backup encoding"))
    };
    let salt = decode(&header.kdf.salt)?;
    let nonce = decode(&header.nonce)?;
    let ciphertext = decode(&header.ciphertext)?;
    if salt.len() != 16 || nonce.len() != 12 {
        return Err(Error::Invalid("backup header"));
    }
    let key = derive_key(password, &salt, header.kdf.iterations)?;
    let plain = Zeroizing::new(
        Aes256Gcm::new(key.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Aad {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let payload: Payload = serde_json::from_slice(&plain)?;
    if payload.version != VERSION {
        return Err(Error::Invalid("backup version"));
    }
    Ok(payload)
}

mod secret {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Secret32,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&Zeroizing::new(STANDARD.encode(value.expose())))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Secret32, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = Zeroizing::new(
            STANDARD
                .decode(text.as_bytes())
                .map_err(serde::de::Error::custom)?,
        );
        let array: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("key must be 32 bytes"))?;
        Ok(Secret32::new(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc7914() {
        // RFC 7914, section 11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1.
        let key = pbkdf2(b"passwd", b"salt", 1);
        assert_eq!(
            hex::encode(*key),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn password_rules_count_characters_after_normalization() {
        assert!(check_password("короткий").is_err());
        assert!(check_password("пароль-от-копии").is_ok());
        assert!(
            check_password(&"я".repeat(129)).is_err(),
            "more than 256 UTF-8 bytes"
        );
        // "е" + combining diaeresis is one character after NFC: 18 code points, 9 characters.
        assert!(check_password(&"е\u{308}".repeat(9)).is_err());
    }
}
