//! OS credentials and explicit Unix server fallback. No secret implements Debug.
use crate::{sqlite::private_options, Error, Result};
use serde::{Deserialize, Serialize};
use shum_core::crypto::Secret32;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SHUMKEY1";
const SERVICE: &str = "org.shum.cli.profile.v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum KeyBackend {
    System,
    File,
}
#[derive(Clone, Copy, Debug)]
pub enum KeyMode {
    Auto,
    System,
    File,
}
impl KeyMode {
    pub fn backend(self) -> Result<KeyBackend> {
        match self {
            Self::File => {
                if cfg!(unix) {
                    Ok(KeyBackend::File)
                } else {
                    Err(Error::FileKeysUnsupported)
                }
            }
            Self::System => system_supported().map(|_| KeyBackend::System),
            Self::Auto => {
                // An absent session bus on a Linux server means no Secret Service.
                // Locked/denied/unavailable credentials on desktop never trigger
                // replacement keys or a silent downgrade to a plaintext file.
                if cfg!(target_os = "linux")
                    && std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
                {
                    Ok(KeyBackend::File)
                } else {
                    system_supported().map(|_| KeyBackend::System)
                }
            }
        }
    }
}
fn system_supported() -> Result<()> {
    if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "linux"
    )) {
        Ok(())
    } else {
        Err(Error::Keyring)
    }
}

pub struct ProfileKeys {
    pub noise: Secret32,
    pub signing: Secret32,
    pub nostr: Secret32,
    pub storage: Secret32,
}
fn random_secret() -> Result<Secret32> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| Error::Random)?;
    Ok(Secret32::new(*bytes))
}
impl ProfileKeys {
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
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(136));
        bytes.extend_from_slice(MAGIC);
        for key in [&self.noise, &self.signing, &self.nostr, &self.storage] {
            bytes.extend_from_slice(key.expose());
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
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
fn check_secret(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Permissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(Error::Permissions);
        }
    }
    if !cfg!(unix) {
        return Err(Error::FileKeysUnsupported);
    }
    Ok(())
}
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux"
))]
fn entry(profile: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, profile).map_err(|_| Error::Keyring)
}

pub(crate) fn create(
    backend: KeyBackend,
    directory: &Path,
    profile: &str,
    keys: &ProfileKeys,
) -> Result<()> {
    let bytes = keys.encode();
    match backend {
        KeyBackend::File => {
            if !cfg!(unix) {
                return Err(Error::FileKeysUnsupported);
            }
            let path = directory.join("keys.bin");
            let mut file = private_options().create_new(true).open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            check_secret(&path)?;
        }
        KeyBackend::System => {
            system_supported()?;
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows",
                target_os = "linux"
            ))]
            {
                let entry = entry(profile)?;
                match entry.get_secret() {
                    Err(keyring::Error::NoEntry) => {}
                    Ok(secret) => {
                        drop(Zeroizing::new(secret));
                        return Err(Error::Invalid("credential already exists"));
                    }
                    Err(_) => return Err(Error::Keyring),
                }
                entry.set_secret(&bytes).map_err(|_| Error::Keyring)?;
                let stored = Zeroizing::new(entry.get_secret().map_err(|_| Error::Keyring)?);
                if *stored != *bytes {
                    return Err(Error::Keyring);
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn load(backend: KeyBackend, directory: &Path, profile: &str) -> Result<ProfileKeys> {
    let bytes = match backend {
        KeyBackend::File => {
            let path = directory.join("keys.bin");
            check_secret(&path)?;
            let mut bytes = Zeroizing::new(Vec::new());
            File::open(path)?.take(137).read_to_end(&mut bytes)?;
            bytes
        }
        KeyBackend::System => {
            system_supported()?;
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows",
                target_os = "linux"
            ))]
            {
                Zeroizing::new(entry(profile)?.get_secret().map_err(|_| Error::Keyring)?)
            }
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows",
                target_os = "linux"
            )))]
            {
                return Err(Error::Keyring);
            }
        }
    };
    ProfileKeys::decode(&bytes)
}
pub(crate) fn delete(backend: KeyBackend, directory: &Path, profile: &str) -> Result<()> {
    match backend {
        KeyBackend::File => {
            let path = directory.join("keys.bin");
            if path.exists() {
                check_secret(&path)?;
                fs::remove_file(path)?;
            }
        }
        KeyBackend::System => {
            system_supported()?;
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows",
                target_os = "linux"
            ))]
            match entry(profile)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(_) => return Err(Error::Keyring),
            }
        }
    }
    Ok(())
}
