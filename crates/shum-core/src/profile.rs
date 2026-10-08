//! Signed profile protocol metadata. Raster generation and image decoding belong
//! to clients; no image/terminal/UI library is linked by this module.
use crate::{canonical, card, crypto, Error, Result};
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;
fn control(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control | GeneralCategory::Format
    )
}
fn newline(c: char) -> bool {
    matches!(c, '\u{a}'..='\u{d}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}
pub fn valid_text(name: &str, bio: &str) -> bool {
    !name.is_empty()
        && name == card::trim(name)
        && name.len() <= 64
        && name.graphemes(true).count() <= 50
        && !name.chars().any(control)
        && name.nfc().eq(name.chars())
        && bio.len() <= 640
        && bio.graphemes(true).count() <= 72
        && !bio.chars().any(|c| control(c) && !newline(c))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub name: String,
    pub bio: String,
    pub avatar_bytes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_version: Option<i64>,
}
impl Manifest {
    pub fn revision(&self) -> String {
        crypto::id(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                self.name,
                self.bio,
                self.avatar_hash.as_deref().unwrap_or(""),
                self.avatar_seed.map(|v| v.to_string()).unwrap_or_default(),
                self.avatar_version
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )
            .as_bytes(),
        )
    }
    pub fn valid(&self) -> bool {
        valid_text(&self.name, &self.bio)
            && (0..=40960).contains(&self.avatar_bytes)
            && if self.avatar_seed.is_some() {
                self.avatar_version == Some(1)
                    && self.avatar_hash.is_none()
                    && self.avatar_bytes == 0
            } else {
                self.avatar_version.is_none()
                    && self
                        .avatar_hash
                        .as_ref()
                        .map_or(self.avatar_bytes == 0, |h| {
                            h.len() == 64
                                && h.bytes()
                                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                                && self.avatar_bytes > 0
                        })
            }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Query,
    Manifest,
    ChunkRequest,
    Chunk,
    Changed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePacket {
    pub version: i64,
    pub kind: Kind,
    #[serde(default)]
    pub request: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "canonical::optional_bytes"
    )]
    pub data: Option<Vec<u8>>,
}
impl ProfilePacket {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 6144 {
            return Err(Error::Invalid("profile packet size"));
        }
        let p: Self = serde_json::from_slice(bytes)?;
        if p.version != 1 || p.request.len() > 64 {
            return Err(Error::Invalid("profile packet"));
        }
        Ok(p)
    }
}
