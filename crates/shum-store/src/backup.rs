//! Profile backups, protocol section 13: seal a profile into a
//! password-protected file and open one as a new local profile. Sealing and
//! opening are the same everywhere; native clients export and restore
//! through their profile folders (feature `native`), the browser through
//! IndexedDB.
use crate::{
    keys::{random_secret, ProfileKeys},
    Error, Result,
};
#[cfg(feature = "native")]
use crate::{
    profiles::{OpenProfile, Profile, Profiles},
    vault::KeyMode,
};
use serde_json::{json, Map, Value};
use shum_core::{
    backup::{self, Keys, Payload, ProfileInfo, Seal},
    crypto::Secret32,
};

pub use shum_core::backup::{check_password, summary, Summary, EXTENSION};

/// Buckets that belong to this device rather than the profile (section 13.4).
const DEVICE_ONLY: &[&str] = &["relay", "seenRelay"];

fn copy(secret: &Secret32) -> Secret32 {
    Secret32::new(*secret.expose())
}

/// Seals a profile's state and keys. `name` stands in when the state has no
/// card; `created_at` is RFC 3339 UTC with whole seconds.
pub fn seal(
    state: &Value,
    keys: &ProfileKeys,
    name: &str,
    password: &str,
    created_at: &str,
) -> Result<Vec<u8>> {
    let mut state = state.clone();
    if let Some(object) = state.as_object_mut() {
        for bucket in DEVICE_ONLY {
            object.remove(*bucket);
        }
    }
    let name = state["ownProfileCard"]["name"]
        .as_str()
        .unwrap_or(name)
        .to_string();
    let payload = Payload {
        version: backup::VERSION,
        created_at: created_at.into(),
        profile: ProfileInfo {
            name,
            owner_id: keys.owner_id(),
            extra: Map::new(),
        },
        keys: Keys {
            noise: copy(&keys.noise),
            signing: copy(&keys.signing),
            nostr: copy(&keys.nostr),
        },
        state,
        extra: Map::new(),
    };
    // A backup that could not be restored is worse than no backup.
    payload.check()?;
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
    Ok(backup::seal(
        &payload,
        password,
        &Seal {
            salt,
            nonce,
            iterations: backup::ITERATIONS,
            created_at,
        },
    )?)
}

/// A profile opened from a backup, with a fresh storage key, ready to be
/// stored as a new local profile.
pub struct Opened {
    pub name: String,
    pub owner_id: String,
    pub keys: ProfileKeys,
    pub state: Value,
}

/// Opens and checks a backup file.
pub fn open(file: &[u8], password: &str) -> Result<Opened> {
    let payload = backup::open(file, password)?;
    payload.check()?;
    let mut state = payload.state;
    if let Some(object) = state.as_object_mut() {
        object.entry("relay").or_insert_with(|| json!([]));
        object.entry("seenRelay").or_insert_with(|| json!({}));
    }
    Ok(Opened {
        name: payload.profile.name,
        owner_id: payload.profile.owner_id,
        keys: ProfileKeys {
            noise: payload.keys.noise,
            signing: payload.keys.signing,
            nostr: payload.keys.nostr,
            storage: random_secret()?,
        },
        state,
    })
}

/// Seals the open profile. `created_at` is RFC 3339 UTC with whole seconds.
#[cfg(feature = "native")]
pub fn export(profile: &OpenProfile, password: &str, created_at: &str) -> Result<Vec<u8>> {
    seal(
        profile.store.state(),
        &profile.keys,
        &profile.profile.name,
        password,
        created_at,
    )
}

/// Restores a backup as a new local profile with fresh storage key.
///
/// With `replace`, local profiles of the same identity are deleted only after
/// the restored one is fully written. Without it, such a profile is an error.
#[cfg(feature = "native")]
pub fn restore(
    profiles: &Profiles,
    file: &[u8],
    password: &str,
    mode: KeyMode,
    replace: bool,
) -> Result<Profile> {
    let opened = open(file, password)?;
    let (_, existing) = profiles.list()?;
    let same: Vec<Profile> = existing
        .into_iter()
        .filter(|p| p.owner_id == opened.owner_id && !p.deleting)
        .collect();
    if !same.is_empty() && !replace {
        return Err(Error::ProfileExists);
    }
    let restored =
        profiles.create_with_state(&opened.name, mode, opened.keys, Some(opened.state))?;
    if !same.is_empty() {
        for old in same {
            profiles.delete(&old.id)?;
        }
        profiles.select(&restored.id)?;
    }
    Ok(restored)
}
