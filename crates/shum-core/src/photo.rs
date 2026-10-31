//! Photos in messages (protocol section 04.9). The message carries a fresh
//! key and the photo's hash; the JPEG travels in parts sealed with that key,
//! so parts need no cards or signatures of their own.
use crate::{canonical, crypto, packet::uuid, Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};

/// Bytes of the JPEG in every part but the last.
pub const PART: usize = 12_288;
/// Largest photo a receiver accepts.
pub const MAX_SIZE: usize = 131_072;
pub const MAX_PARTS: usize = MAX_SIZE.div_ceil(PART);
/// Longest side a receiver accepts, in pixels.
pub const MAX_SIDE: i64 = 2048;
const TYPE: &str = "image/jpeg";
const TAG: usize = 16;

/// The photo of a message, inside its encrypted plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Photo {
    #[serde(rename = "type")]
    pub kind: String,
    pub size: i64,
    pub sha256: String,
    #[serde(with = "canonical::bytes")]
    pub key: Vec<u8>,
    pub width: i64,
    pub height: i64,
    /// Whether the message text is a caption; otherwise it only stands in
    /// for the photo on clients that do not know photos.
    pub caption: bool,
}

/// One sealed part of a photo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPart {
    #[serde(rename = "messageID")]
    pub message_id: String,
    pub index: i64,
    #[serde(with = "canonical::bytes")]
    pub data: Vec<u8>,
}

impl Photo {
    /// Seals a JPEG for the message `message_id` with `key`, fresh for
    /// every photo; the caller supplies it, as the core has no randomness.
    pub fn seal(
        message_id: &str,
        jpeg: &[u8],
        width: i64,
        height: i64,
        caption: bool,
        key: &crypto::Secret32,
    ) -> Result<(Self, Vec<PhotoPart>)> {
        let photo = Self {
            kind: TYPE.into(),
            size: jpeg.len() as i64,
            sha256: crypto::id(jpeg),
            key: key.expose().to_vec(),
            width,
            height,
            caption,
        };
        photo.validate()?;
        if !uuid(message_id) || !jpeg.starts_with(&[0xff, 0xd8, 0xff]) {
            return Err(Error::Invalid("photo"));
        }
        let parts = jpeg
            .chunks(PART)
            .enumerate()
            .map(|(index, part)| {
                Ok(PhotoPart {
                    message_id: message_id.into(),
                    index: index as i64,
                    data: cipher(&photo.key)?
                        .encrypt(
                            (&nonce(index)).into(),
                            Payload {
                                msg: part,
                                aad: &aad(message_id),
                            },
                        )
                        .map_err(|_| Error::Invalid("photo part"))?,
                })
            })
            .collect::<Result<_>>()?;
        Ok((photo, parts))
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != TYPE
            || !(1..=MAX_SIZE as i64).contains(&self.size)
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || self.key.len() != 32
            || !(1..=MAX_SIDE).contains(&self.width)
            || !(1..=MAX_SIDE).contains(&self.height)
        {
            return Err(Error::Invalid("photo"));
        }
        Ok(())
    }

    /// How many parts the photo travels in.
    pub fn count(&self) -> usize {
        (self.size.max(0) as usize).div_ceil(PART)
    }

    /// The JPEG bytes of one part of the message `message_id`, if it opens
    /// with this photo's key and has the expected length.
    pub fn open(&self, message_id: &str, part: &PhotoPart) -> Result<Vec<u8>> {
        part.validate()?;
        let index = part.index as usize;
        if part.message_id != message_id || index >= self.count() {
            return Err(Error::Invalid("photo part"));
        }
        let expected = if index + 1 == self.count() {
            self.size as usize - PART * index
        } else {
            PART
        };
        if part.data.len() != expected + TAG {
            return Err(Error::Invalid("photo part"));
        }
        cipher(&self.key)?
            .decrypt(
                (&nonce(index)).into(),
                Payload {
                    msg: &part.data,
                    aad: &aad(message_id),
                },
            )
            .map_err(|_| Error::Authentication)
    }

    /// The whole JPEG from its opened parts in order, checked against the
    /// size and hash the message promised.
    pub fn join(&self, parts: &[Vec<u8>]) -> Result<Vec<u8>> {
        let jpeg = parts.concat();
        if parts.len() != self.count()
            || jpeg.len() as i64 != self.size
            || crypto::id(&jpeg) != self.sha256
        {
            return Err(Error::Invalid("photo hash"));
        }
        Ok(jpeg)
    }
}

impl PhotoPart {
    pub fn validate(&self) -> Result<()> {
        if !uuid(&self.message_id)
            || !(0..MAX_PARTS as i64).contains(&self.index)
            || !(TAG + 1..=PART + TAG).contains(&self.data.len())
        {
            return Err(Error::Invalid("photo part"));
        }
        Ok(())
    }
}

fn cipher(key: &[u8]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid("photo key"))
}

fn nonce(index: usize) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&(index as u64).to_le_bytes());
    n
}

fn aad(message_id: &str) -> Vec<u8> {
    [b"shum.photo-part.v1\0".as_slice(), message_id.as_bytes()].concat()
}
