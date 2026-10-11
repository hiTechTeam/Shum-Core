//! OS credentials and explicit Unix server fallback. No secret implements Debug.
use crate::{sqlite::private_options, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub(crate) use crate::keys::random_secret;
pub use crate::keys::ProfileKeys;

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
