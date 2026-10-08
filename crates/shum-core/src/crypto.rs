use crate::{Error, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// No Debug/Serialize; secret ownership zeroizes on drop. No OS RNG in core.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);
impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn ed_public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.0).sign(message).to_bytes()
    }
    pub fn noise_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.0)).to_bytes()
    }
    pub fn nostr_public(&self) -> Result<[u8; 32]> {
        let sk = secp256k1::SecretKey::from_byte_array(self.0)
            .map_err(|_| Error::Invalid("secp256k1 secret"))?;
        Ok(sk
            .keypair(&secp256k1::Secp256k1::new())
            .x_only_public_key()
            .0
            .serialize())
    }
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn id(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}
pub fn verify_ed(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; 32]>::try_from(public) else {
        return false;
    };
    let Ok(public) = VerifyingKey::from_bytes(bytes) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    public.verify_strict(message, &signature).is_ok()
}
pub fn avatar_seed(noise_public: &[u8]) -> u64 {
    let mut bytes = b"shum.pixel-avatar.v1\0".to_vec();
    bytes.extend_from_slice(noise_public);
    u64::from_le_bytes(sha256(&bytes)[..8].try_into().expect("fixed SHA256 size"))
}
