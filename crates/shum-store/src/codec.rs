//! CryptoKit ChaChaPoly combined bytes; no network canonicalization here.
use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAX_BYTES: usize = 100_000_000;

pub fn index_id(key: &[u8; 32], bucket: &str, real_id: &str) -> String {
    if bucket == "header" {
        return real_id.to_owned();
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("32-byte HMAC key");
    mac.update(bucket.as_bytes());
    mac.update(&[0]);
    mac.update(real_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
pub fn aad(bucket: &str, index: &str, position: i64) -> Vec<u8> {
    format!("{bucket}\0{index}\0{position}").into_bytes()
}
pub fn pack(real_id: &str, json: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u16::try_from(real_id.len()).map_err(|_| Error::Invalid("ID length"))?;
    if len == 0 || json.is_empty() || json.len() > MAX_BYTES {
        return Err(Error::Invalid("packed length"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(2 + real_id.len() + json.len()));
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(real_id.as_bytes());
    bytes.extend_from_slice(json);
    Ok(bytes)
}
pub fn unpack(bytes: &[u8]) -> Result<(&str, &[u8])> {
    if bytes.len() < 3 {
        return Err(Error::Invalid("packed length"));
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if len == 0 || len + 2 >= bytes.len() {
        return Err(Error::Invalid("packed ID length"));
    }
    let id = std::str::from_utf8(&bytes[2..2 + len]).map_err(|_| Error::Invalid("ID UTF-8"))?;
    Ok((id, &bytes[2 + len..]))
}
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if plain.is_empty() || plain.len() > MAX_BYTES - 28 {
        return Err(Error::Invalid("plaintext size"));
    }
    let cipher = ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::Authentication)?;
    let mut combined = Vec::with_capacity(12 + cipher.len());
    combined.extend_from_slice(nonce);
    combined.extend(cipher);
    Ok(combined)
}
pub fn open(key: &[u8; 32], combined: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if combined.len() <= 28 || combined.len() > MAX_BYTES {
        return Err(Error::Invalid("ciphertext size"));
    }
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&combined[..12]),
            Payload {
                msg: &combined[12..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}
pub(crate) fn random_nonce() -> Result<[u8; 12]> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
    Ok(nonce)
}

/// Old Bitchat archive encryption uses its own independent legacy key.
/// The caller supplies it explicitly; the storage key is never substituted.
pub fn open_legacy_archive(key: &[u8; 32], combined: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if combined.len() <= 28 || combined.len() > MAX_BYTES {
        return Err(Error::Invalid("legacy ciphertext size"));
    }
    aes_gcm::Aes256Gcm::new(key.into())
        .decrypt(aes_gcm::Nonce::from_slice(&combined[..12]), &combined[12..])
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}
