//! Profile backups, protocol section 13: export an open profile to a
//! password-sealed file and restore one as a new local profile.
use crate::{
    profiles::{OpenProfile, Profile, Profiles},
    vault::{random_secret, KeyMode, ProfileKeys},
    Error, Result,
};
use serde_json::{json, Map};
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

/// Seals the open profile. `created_at` is RFC 3339 UTC with whole seconds.
pub fn export(profile: &OpenProfile, password: &str, created_at: &str) -> Result<Vec<u8>> {
    let mut state = profile.store.state().clone();
    if let Some(object) = state.as_object_mut() {
        for bucket in DEVICE_ONLY {
            object.remove(*bucket);
        }
    }
    let name = profile.store.state()["ownProfileCard"]["name"]
        .as_str()
        .unwrap_or(&profile.profile.name)
        .to_string();
    let payload = Payload {
        version: backup::VERSION,
        created_at: created_at.into(),
        profile: ProfileInfo {
            name,
            owner_id: profile.profile.owner_id.clone(),
            extra: Map::new(),
        },
        keys: Keys {
            noise: copy(&profile.keys.noise),
            signing: copy(&profile.keys.signing),
            nostr: copy(&profile.keys.nostr),
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

/// Restores a backup as a new local profile with fresh storage key.
///
/// With `replace`, local profiles of the same identity are deleted only after
/// the restored one is fully written. Without it, such a profile is an error.
pub fn restore(
    profiles: &Profiles,
    file: &[u8],
    password: &str,
    mode: KeyMode,
    replace: bool,
) -> Result<Profile> {
    let payload = backup::open(file, password)?;
    payload.check()?;
    let (_, existing) = profiles.list()?;
    let same: Vec<Profile> = existing
        .into_iter()
        .filter(|p| p.owner_id == payload.profile.owner_id && !p.deleting)
        .collect();
    if !same.is_empty() && !replace {
        return Err(Error::ProfileExists);
    }
    let mut state = payload.state;
    if let Some(object) = state.as_object_mut() {
        object.entry("relay").or_insert_with(|| json!([]));
        object.entry("seenRelay").or_insert_with(|| json!({}));
    }
    let keys = ProfileKeys {
        noise: payload.keys.noise,
        signing: payload.keys.signing,
        nostr: payload.keys.nostr,
        storage: random_secret()?,
    };
    let restored = profiles.create_with_state(&payload.profile.name, mode, keys, Some(state))?;
    if !same.is_empty() {
        for old in same {
            profiles.delete(&old.id)?;
        }
        profiles.select(&restored.id)?;
    }
    Ok(restored)
}
