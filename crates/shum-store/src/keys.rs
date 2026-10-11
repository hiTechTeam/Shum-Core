//! A profile's four private keys and their storage bundle, the same for the
//! system key store and the browser.
use crate::{Error, Result};
use shum_core::crypto::Secret32;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SHUMKEY1";

pub struct ProfileKeys {
    pub noise: Secret32,
    pub signing: Secret32,
    pub nostr: Secret32,
    pub storage: Secret32,
}
pub(crate) fn random_secret() -> Result<Secret32> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| Error::Random)?;
    Ok(Secret32::new(*bytes))
}
impl ProfileKeys {
    /// Seals and opens a test value with the storage key and checks a
    /// signature, as every client does with new keys before asking for a name.
    pub fn check(&self) -> Result<()> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let challenge = b"shum.registration.check.v1";
        let sealed = crate::codec::seal(self.storage.expose(), &nonce, challenge, b"")?;
        if crate::codec::open(self.storage.expose(), &sealed, b"")?.as_slice() != challenge
            || !shum_core::crypto::verify_ed(
                &self.signing.ed_public(),
                &self.signing.sign(challenge),
                challenge,
            )
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub fn generate() -> Result<Self> {
        let noise = random_secret()?;
        let signing = random_secret()?;
        let nostr = loop {
            let secret = random_secret()?;
            if secret.nostr_public().is_ok() {
                break secret;
            }
        };
        Ok(Self {
            noise,
            signing,
            nostr,
            storage: random_secret()?,
        })
    }
    pub fn owner_id(&self) -> String {
        shum_core::crypto::id(&self.noise.noise_public())
    }
    /// The 136-byte bundle kept in the system key store or, in the browser,
    /// sealed with a WebCrypto key.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(136));
        bytes.extend_from_slice(MAGIC);
        for key in [&self.noise, &self.signing, &self.nostr, &self.storage] {
            bytes.extend_from_slice(key.expose());
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 136 || &bytes[..8] != MAGIC {
            return Err(Error::Invalid("secret bundle version or size"));
        }
        let secret =
            |offset| Secret32::new(bytes[offset..offset + 32].try_into().expect("checked size"));
        let keys = Self {
            noise: secret(8),
            signing: secret(40),
            nostr: secret(72),
            storage: secret(104),
        };
        if keys.nostr.nostr_public().is_err() {
            return Err(Error::Invalid("Nostr secret"));
        }
        Ok(keys)
    }
    pub fn storage_key(&self) -> Secret32 {
        Secret32::new(*self.storage.expose())
    }
}
