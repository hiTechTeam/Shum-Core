//! Independent profiles; registry mutations are serialized across processes.
//! Display names may repeat. Registry selectors are profile IDs, never names.
use crate::{
    sqlite::private_options,
    vault::{self, KeyBackend, KeyMode, ProfileKeys},
    Error, Result, Store,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub key_backend: KeyBackend,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleting: bool,
}
#[derive(Serialize, Deserialize)]
struct Registry {
    version: u32,
    selected: Option<String>,
    profiles: Vec<Profile>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            selected: None,
            profiles: Vec::new(),
        }
    }
}
pub struct Profiles {
    root: PathBuf,
}
pub struct OpenProfile {
    pub profile: Profile,
    pub keys: ProfileKeys,
    pub store: Store,
    root: PathBuf,
}
impl OpenProfile {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn check_name(&self, name: &str) -> Result<()> {
        let profiles = Profiles::new(&self.root)?;
        let _lock = profiles.lock()?;
        let registry = profiles.read()?;
        if name.is_empty()
            || name.len() > 64
            || name.trim() != name
            || name.chars().any(char::is_control)
            || registry.profiles.iter().all(|p| p.id != self.profile.id)
        {
            return Err(Error::ProfileName);
        }
        Ok(())
    }
    /// The encrypted card is authoritative; opening the profile reconciles a
    /// crash between committing that card and updating this public label.
    pub fn refresh_name(&mut self) -> Result<()> {
        let Some(name) = self.store.state()["ownProfileCard"]["name"].as_str() else {
            return Ok(());
        };
        if name == self.profile.name {
            return Ok(());
        }
        let profiles = Profiles::new(&self.root)?;
        let _lock = profiles.lock()?;
        let mut registry = profiles.read()?;
        let profile = registry
            .profiles
            .iter_mut()
            .find(|p| p.id == self.profile.id)
            .ok_or(Error::ProfileNotFound)?;
        profile.name = name.into();
        profiles.write(&registry)?;
        self.profile.name = name.into();
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Permissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(Error::Permissions);
        }
    }
    Ok(())
}
impl Profiles {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        private_directory(root.as_ref())?;
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }
    fn lock(&self) -> Result<File> {
        let path = self.root.join("profiles.lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
            return Err(Error::Permissions);
        }
        let file = private_options().create(true).truncate(false).open(path)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(Error::Locked)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(file)
    }
    fn read(&self) -> Result<Registry> {
        let path = self.root.join("profiles.json");
        if !path.exists() {
            return Ok(Registry::default());
        }
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1_000_000 {
            return Err(Error::Invalid("profile registry file"));
        }
        let mut json = Vec::new();
        File::open(path)?.take(1_000_001).read_to_end(&mut json)?;
        let registry: Registry = serde_json::from_slice(&json)?;
        if registry.version != 1 {
            return Err(Error::Invalid("profile registry version"));
        }
        let mut ids = std::collections::HashSet::new();
        for profile in &registry.profiles {
            if profile.id.len() != 32
                || !profile
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                || !ids.insert(&profile.id)
            {
                return Err(Error::Invalid("profile registry ID"));
            }
        }
        if registry
            .selected
            .as_ref()
            .is_some_and(|id| !ids.contains(id))
        {
            return Err(Error::Invalid("selected profile"));
        }
        Ok(registry)
    }
    fn write(&self, registry: &Registry) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(&serde_json::to_vec(registry)?)?;
        file.as_file().sync_all()?;
        file.persist(self.root.join("profiles.json"))
            .map_err(|e| Error::Io(e.error))?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn find<'a>(registry: &'a Registry, selector: Option<&str>) -> Result<&'a Profile> {
        let selector = selector
            .or(registry.selected.as_deref())
            .ok_or(Error::ProfileNotFound)?;
        registry
            .profiles
            .iter()
            .find(|p| p.id == selector && !p.deleting)
            .ok_or(Error::ProfileNotFound)
    }
    pub fn list(&self) -> Result<(Option<String>, Vec<Profile>)> {
        let _lock = self.lock()?;
        let r = self.read()?;
        Ok((r.selected, r.profiles))
    }
    pub fn select(&self, selector: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut r = self.read()?;
        r.selected = Some(Self::find(&r, Some(selector))?.id.clone());
        self.write(&r)
    }
    pub fn create(&self, name: &str, mode: KeyMode) -> Result<Profile> {
        self.create_with_keys(name, mode, ProfileKeys::generate()?)
    }
    /// Publish keys prepared by an interactive client only after confirmation.
    pub fn create_with_keys(
        &self,
        name: &str,
        mode: KeyMode,
        keys: ProfileKeys,
    ) -> Result<Profile> {
        if name.is_empty()
            || name.len() > 128
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(Error::ProfileName);
        }
        let _lock = self.lock()?;
        let mut r = self.read()?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Random)?;
        let id = hex::encode(random);
        let directory = self.root.join(&id);
        let backend = mode.backend()?;
        // create_dir is exclusive; never claim or remove an existing directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&directory)?;
        let profile = Profile {
            id,
            name: name.into(),
            owner_id: keys.owner_id(),
            key_backend: backend,
            deleting: false,
        };
        let mut publishing = false;
        let result = (|| {
            vault::create(backend, &directory, &profile.id, &keys)?;
            let store = Store::open(
                directory.join("messages.sqlite"),
                &profile.owner_id,
                keys.storage_key(),
            )?;
            store.checkpoint()?;
            drop(store);
            r.profiles.push(profile.clone());
            if r.selected.is_none() {
                r.selected = Some(profile.id.clone());
            }
            publishing = true;
            self.write(&r)
        })();
        if let Err(error) = result {
            // A rename followed by a failed directory fsync has an uncertain
            // durable outcome. Never destroy keys after publication was tried.
            if !publishing {
                let _ = vault::delete(backend, &directory, &profile.id);
                let _ = fs::remove_dir_all(&directory);
            }
            return Err(error);
        }
        Ok(profile)
    }
    pub fn open(&self, selector: Option<&str>) -> Result<OpenProfile> {
        let _lock = self.lock()?;
        let registry = self.read()?;
        let profile = Self::find(&registry, selector)?.clone();
        let directory = self.root.join(&profile.id);
        private_directory(&directory)?;
        let keys = vault::load(profile.key_backend, &directory, &profile.id)?;
        if keys.owner_id() != profile.owner_id {
            return Err(Error::Identity);
        }
        if !directory.join("messages.sqlite").is_file() {
            return Err(Error::Invalid("existing profile database is missing"));
        }
        let store = Store::open(
            directory.join("messages.sqlite"),
            &profile.owner_id,
            keys.storage_key(),
        )?;
        Ok(OpenProfile {
            profile,
            keys,
            store,
            root: self.root.clone(),
        })
    }
    /// Explicit delete intent. A durable tombstone makes interrupted deletion
    /// retryable and prevents the identity from being opened halfway through.
    pub fn delete(&self, selector: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut r = self.read()?;
        let index = r
            .profiles
            .iter()
            .position(|p| p.id == selector)
            .ok_or(Error::ProfileNotFound)?;
        let profile = r.profiles[index].clone();
        let directory = self.root.join(&profile.id);
        if !profile.deleting {
            private_directory(&directory)?;
            let keys = vault::load(profile.key_backend, &directory, &profile.id)?;
            let store = Store::open(
                directory.join("messages.sqlite"),
                &profile.owner_id,
                keys.storage_key(),
            )?;
            store.checkpoint()?;
            drop(store);
            r.profiles[index].deleting = true;
            self.write(&r)?;
        }
        vault::delete(profile.key_backend, &directory, &profile.id)?;
        if directory.exists() {
            private_directory(&directory)?;
            fs::remove_dir_all(&directory)?;
        }
        r.profiles.remove(index);
        if r.selected.as_deref() == Some(&profile.id) {
            r.selected = r
                .profiles
                .iter()
                .find(|p| !p.deleting)
                .map(|p| p.id.clone());
        }
        self.write(&r)
    }
}
