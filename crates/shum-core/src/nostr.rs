//! Shum/Bitchat private Nostr wrapping, deliberately not NIP-44 encryption.
use crate::{
    canonical,
    crypto::{sha256, Secret32},
    invitation::decode_url_base64,
    Error, Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use hkdf::Hkdf;
use secp256k1::{ecdh, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

const MAX_ENVELOPE: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}
impl Event {
    pub fn id_bytes(&self) -> Result<Vec<u8>> {
        canonical::encode(&serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]))
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.id_bytes()?))
    }
    pub fn verify(&self) -> bool {
        let result = (|| -> Result<()> {
            if self.tags.len() > 64
                || self
                    .tags
                    .iter()
                    .any(|v| v.len() > 16 || v.iter().any(|s| s.len() > 1024))
            {
                return Err(Error::Invalid("Nostr tags"));
            }
            let hash = self.digest()?;
            if self.id != hex::encode(hash) {
                return Err(Error::Authentication);
            }
            let key: [u8; 32] = hex::decode(&self.pubkey)
                .map_err(|_| Error::Invalid("Nostr pubkey"))?
                .try_into()
                .map_err(|_| Error::Invalid("Nostr pubkey size"))?;
            let public =
                XOnlyPublicKey::from_byte_array(key).map_err(|_| Error::Invalid("Nostr point"))?;
            let signature: [u8; 64] = hex::decode(self.sig.as_ref().ok_or(Error::Authentication)?)
                .map_err(|_| Error::Authentication)?
                .try_into()
                .map_err(|_| Error::Authentication)?;
            Secp256k1::verification_only()
                .verify_schnorr(
                    &secp256k1::schnorr::Signature::from_byte_array(signature),
                    &hash,
                    &public,
                )
                .map_err(|_| Error::Authentication)
        })();
        result.is_ok()
    }
    pub fn sign(&mut self, secret: &Secret32, aux: &[u8; 32]) -> Result<()> {
        let ctx = Secp256k1::new();
        let sk = SecretKey::from_byte_array(*secret.expose())
            .map_err(|_| Error::Invalid("Nostr secret"))?;
        let keypair = sk.keypair(&ctx);
        self.pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        let hash = self.digest()?;
        self.id = hex::encode(hash);
        self.sig = Some(hex::encode(
            ctx.sign_schnorr_with_aux_rand(&hash, &keypair, aux)
                .to_byte_array(),
        ));
        Ok(())
    }
}

/// Full compressed shared point required by the Swift P256K API.
fn shared_point(secret: &Secret32, x: &[u8; 32], parity: u8) -> Result<[u8; 33]> {
    let sk =
        SecretKey::from_byte_array(*secret.expose()).map_err(|_| Error::Invalid("Nostr secret"))?;
    let mut encoded = [0; 33];
    encoded[0] = parity;
    encoded[1..].copy_from_slice(x);
    let pk = PublicKey::from_slice(&encoded).map_err(|_| Error::Invalid("Nostr point"))?;
    let mut point = ecdh::shared_secret_point(&pk, &sk);
    let mut shared = [0; 33];
    shared[0] = 2 + (point[63] & 1);
    shared[1..].copy_from_slice(&point[..32]);
    point.zeroize();
    Ok(shared)
}
fn derive(shared: &[u8; 33]) -> [u8; 32] {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&[]), shared)
        .expand(b"nip44-v2", &mut key)
        .expect("fixed valid HKDF size");
    key
}
fn public_bytes(public: &str) -> Result<[u8; 32]> {
    hex::decode(public)
        .map_err(|_| Error::Invalid("Nostr public hex"))?
        .try_into()
        .map_err(|_| Error::Invalid("Nostr public size"))
}
pub fn encrypt_content(
    sender: &Secret32,
    recipient: &str,
    nonce: &[u8; 24],
    plain: &[u8],
) -> Result<String> {
    let mut shared = shared_point(sender, &public_bytes(recipient)?, 2)?;
    let mut key = derive(&shared);
    shared.zeroize();
    let encrypted = XChaCha20Poly1305::new((&key).into())
        .encrypt(nonce.into(), plain)
        .map_err(|_| Error::Authentication);
    key.zeroize();
    let mut combined = nonce.to_vec();
    combined.extend(encrypted?);
    Ok(format!("v2:{}", URL_SAFE_NO_PAD.encode(combined)))
}
pub fn decrypt_content(recipient: &Secret32, sender: &str, content: &str) -> Result<Vec<u8>> {
    if content.len() > MAX_ENVELOPE {
        return Err(Error::Invalid("Nostr content limit"));
    }
    let data = decode_url_base64(
        content
            .strip_prefix("v2:")
            .ok_or(Error::Invalid("Nostr cipher version"))?,
    )?;
    if data.len() <= 40 {
        return Err(Error::Invalid("Nostr ciphertext length"));
    }
    let x = public_bytes(sender)?;
    for parity in [2, 3] {
        let mut shared = shared_point(recipient, &x, parity)?;
        let mut key = derive(&shared);
        shared.zeroize();
        let opened = XChaCha20Poly1305::new((&key).into()).decrypt(data[..24].into(), &data[24..]);
        key.zeroize();
        if let Ok(bytes) = opened {
            if bytes.len() > MAX_ENVELOPE || std::str::from_utf8(&bytes).is_err() {
                return Err(Error::Invalid("Nostr plaintext"));
            }
            return Ok(bytes);
        }
    }
    Err(Error::Authentication)
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub content: String,
    pub sender: String,
    pub timestamp: i64,
}
pub fn open_private(outer: &Event, recipient: &Secret32) -> Result<PrivateMessage> {
    let own = hex::encode(recipient.nostr_public()?);
    let p = vec![vec!["p".to_string(), own]];
    if outer.kind != 1059 || outer.tags != p || !outer.verify() {
        return Err(Error::Authentication);
    }
    let seal: Event =
        serde_json::from_slice(&decrypt_content(recipient, &outer.pubkey, &outer.content)?)?;
    if seal.kind != 13 || !seal.tags.is_empty() || !seal.verify() {
        return Err(Error::Authentication);
    }
    let rumor: Event =
        serde_json::from_slice(&decrypt_content(recipient, &seal.pubkey, &seal.content)?)?;
    if rumor.kind != 14
        || (!rumor.tags.is_empty() && rumor.tags != p)
        || rumor.sig.is_some()
        || rumor.pubkey != seal.pubkey
    {
        return Err(Error::Authentication);
    }
    Ok(PrivateMessage {
        content: rumor.content,
        sender: seal.pubkey,
        timestamp: rumor.created_at,
    })
}

/// Every random input is supplied by the transport; deterministic in fixtures.
pub struct WrapEntropy<'a> {
    pub outer_key: &'a Secret32,
    pub seal_nonce: [u8; 24],
    pub wrap_nonce: [u8; 24],
    pub seal_aux: [u8; 32],
    pub wrap_aux: [u8; 32],
    pub seal_time: i64,
    pub wrap_time: i64,
}
pub fn create_private(
    sender: &Secret32,
    recipient: &str,
    content: String,
    now: i64,
    entropy: WrapEntropy<'_>,
) -> Result<Event> {
    let author = hex::encode(sender.nostr_public()?);
    let mut rumor = Event {
        id: String::new(),
        pubkey: author.clone(),
        created_at: now,
        kind: 14,
        tags: vec![],
        content,
        sig: None,
    };
    rumor.id = hex::encode(rumor.digest()?);
    let mut seal = Event {
        id: String::new(),
        pubkey: author,
        created_at: entropy.seal_time,
        kind: 13,
        tags: vec![],
        content: encrypt_content(
            sender,
            recipient,
            &entropy.seal_nonce,
            &canonical::encode(&rumor)?,
        )?,
        sig: None,
    };
    seal.sign(sender, &entropy.seal_aux)?;
    let mut outer = Event {
        id: String::new(),
        pubkey: String::new(),
        created_at: entropy.wrap_time,
        kind: 1059,
        tags: vec![vec!["p".into(), recipient.into()]],
        content: encrypt_content(
            entropy.outer_key,
            recipient,
            &entropy.wrap_nonce,
            &canonical::encode(&seal)?,
        )?,
        sig: None,
    };
    outer.sign(entropy.outer_key, &entropy.wrap_aux)?;
    Ok(outer)
}
