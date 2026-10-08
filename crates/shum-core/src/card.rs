use crate::{canonical, crypto, Error, Result};
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub version: i64,
    #[serde(with = "canonical::bytes")]
    pub noise_key: Vec<u8>,
    #[serde(with = "canonical::bytes")]
    pub signing_key: Vec<u8>,
    pub nostr_key: String,
    pub name: String,
    pub bio: String,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_version: Option<i64>,
    #[serde(
        default,
        with = "canonical::optional_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub avatar_seed_signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_revision: Option<u64>,
    #[serde(
        default,
        with = "canonical::optional_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_signature: Option<Vec<u8>>,
}

/// Foundation CharacterSet.whitespacesAndNewlines, explicitly versioned.
pub fn foundation_space(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200b}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}
pub fn trim(value: &str) -> &str {
    value.trim_matches(foundation_space)
}

impl Card {
    pub fn id(&self) -> String {
        crypto::id(&self.noise_key)
    }
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut value = self.clone();
        value.signature.clear();
        value.avatar_seed = None;
        value.avatar_version = None;
        value.avatar_seed_signature = None;
        value.profile_revision = None;
        value.profile_signature = None;
        canonical::encode(&value)
    }
    pub fn seed_bytes(&self) -> Option<Vec<u8>> {
        if self.avatar_version != Some(1) {
            return None;
        }
        let mut out = b"shum.avatar-seed.v1\0".to_vec();
        out.extend_from_slice(&self.noise_key);
        out.extend_from_slice(&self.avatar_seed?.to_le_bytes());
        Some(out)
    }
    pub fn profile_bytes(&self) -> Result<Vec<u8>> {
        let mut value = self.clone();
        value.signature.clear();
        value.avatar_seed_signature = None;
        value.profile_signature = None;
        let mut bytes = b"shum.profile.v1\0".to_vec();
        bytes.extend(canonical::encode(&value)?);
        Ok(bytes)
    }
    pub fn profile_id(&self) -> Result<String> {
        Ok(crypto::id(&self.profile_bytes()?))
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.noise_key.len() != 32
            || self.noise_key.iter().all(|v| *v == 0)
            || self.signing_key.len() != 32
            || self.nostr_key.len() != 64
            || !self
                .nostr_key
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || trim(&self.name).is_empty()
            || self.name.len() > 64
            || self.bio.len() > 640
            || self.bio.graphemes(true).count() > 72
        {
            return Err(Error::Invalid("contact"));
        }
        let verify = |sig: &[u8], bytes: &[u8]| crypto::verify_ed(&self.signing_key, sig, bytes);
        if let Some(revision) = self.profile_revision {
            if revision == 0
                || self.avatar_seed.is_none()
                || self.avatar_version != Some(1)
                || !self
                    .profile_signature
                    .as_ref()
                    .is_some_and(|s| self.profile_bytes().is_ok_and(|b| verify(s, &b)))
            {
                return Err(Error::Authentication);
            }
            if !self.signature.is_empty() && !verify(&self.signature, &self.signed_bytes()?) {
                return Err(Error::Authentication);
            }
            if let Some(sig) = &self.avatar_seed_signature {
                if !self.seed_bytes().is_some_and(|b| verify(sig, &b)) {
                    return Err(Error::Authentication);
                }
            }
        } else {
            if self.profile_signature.is_some() || !verify(&self.signature, &self.signed_bytes()?) {
                return Err(Error::Authentication);
            }
            if self.avatar_seed.is_some() {
                if !self
                    .avatar_seed_signature
                    .as_ref()
                    .is_some_and(|s| self.seed_bytes().is_some_and(|b| verify(s, &b)))
                {
                    return Err(Error::Authentication);
                }
            } else if self.avatar_version.is_some() || self.avatar_seed_signature.is_some() {
                return Err(Error::Invalid("orphan avatar fields"));
            }
        }
        Ok(())
    }
    pub fn preferred<'a>(&'a self, previous: &'a Self) -> Result<&'a Self> {
        self.validate()?;
        if self.noise_key != previous.noise_key
            || self.signing_key != previous.signing_key
            || self.nostr_key != previous.nostr_key
        {
            return Err(Error::Invalid("changed pinned keys"));
        }
        let new = self.profile_revision.unwrap_or(0);
        let old = previous.profile_revision.unwrap_or(0);
        if new != old {
            return Ok(if new > old { self } else { previous });
        }
        if new == 0 {
            return Ok(self);
        }
        let new_id = self.profile_id()?;
        let old_id = previous.profile_id()?;
        if new_id != old_id {
            return Ok(if new_id > old_id { self } else { previous });
        }
        let auxiliary = |c: &Self| {
            usize::from(!c.signature.is_empty()) + usize::from(c.avatar_seed_signature.is_some())
        };
        Ok(if auxiliary(self) > auxiliary(previous) {
            self
        } else {
            previous
        })
    }
    pub fn create(
        noise: &crypto::Secret32,
        signing: &crypto::Secret32,
        nostr: &crypto::Secret32,
        name: String,
        bio: &str,
        seed: Option<u64>,
        revision: u64,
    ) -> Result<Self> {
        let mut value = Self {
            version: 1,
            noise_key: noise.noise_public().to_vec(),
            signing_key: signing.ed_public().to_vec(),
            nostr_key: hex::encode(nostr.nostr_public()?),
            name,
            bio: bio.graphemes(true).take(72).collect(),
            signature: vec![],
            avatar_seed: None,
            avatar_version: None,
            avatar_seed_signature: None,
            profile_revision: None,
            profile_signature: None,
        };
        value.signature = signing.sign(&value.signed_bytes()?).to_vec();
        value.avatar_seed = Some(seed.unwrap_or_else(|| crypto::avatar_seed(&value.noise_key)));
        value.avatar_version = Some(1);
        value.avatar_seed_signature = Some(
            signing
                .sign(&value.seed_bytes().expect("seed set"))
                .to_vec(),
        );
        value.profile_revision = Some(revision);
        value.profile_signature = Some(signing.sign(&value.profile_bytes()?).to_vec());
        value.validate()?;
        Ok(value)
    }
}
