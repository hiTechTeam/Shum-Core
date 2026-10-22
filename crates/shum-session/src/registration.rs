//! Creating a new local profile, the same way in every client: keys are
//! prepared and checked first, and nothing is published in the profile
//! registry until the person confirms a name and an avatar.
use crate::Failure;
use anyhow::{anyhow, Result};
use serde_json::json;
use shum_core::card::Card;
use shum_store::{
    profiles::{Profile, Profiles},
    vault::{KeyMode, ProfileKeys},
};
use std::path::Path;

/// Push service used by new profiles unless the person chooses otherwise.
pub const DEFAULT_PUSH_URL: &str = "https://push.getshum.tech";
/// Push services that no longer run. Profiles that stored one of them use
/// [`DEFAULT_PUSH_URL`] instead, so nobody has to change a setting.
const RETIRED_PUSH_URLS: &[&str] = &["https://d5d5lr0h6812sbjiiqoa.ccx97b51.apigw.yandexcloud.net"];

/// The push service to call for a stored setting.
pub fn current_push_url(stored: &str) -> &str {
    if RETIRED_PUSH_URLS.contains(&stored.trim_end_matches('/')) {
        DEFAULT_PUSH_URL
    } else {
        stored
    }
}

fn ensure(condition: bool, text: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Failure::text(text).into())
    }
}

/// The avatar a new profile starts with, derived from its signing key.
pub fn initial_seed(keys: &ProfileKeys) -> u64 {
    shum_core::crypto::avatar_seed(&keys.signing.ed_public())
}

/// Prepares and checks keys before asking for a name. Temporary encrypted
/// storage is removed before returning; secrets stay in memory until the
/// person confirms the profile. `progress` receives steps 0 to 4.
pub fn prepare(root: &Path, mut progress: impl FnMut(usize)) -> Result<ProfileKeys> {
    progress(0);
    let keys = ProfileKeys::generate()?;
    progress(1);
    ensure(keys.check().is_ok(), "Не прошла проверка ключей")?;
    progress(2);
    Profiles::new(root)?;
    let temporary = tempfile::Builder::new()
        .prefix(".registration-")
        .tempdir_in(root)?;
    let database = temporary.path().join("check.sqlite");
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        "Подготовка".into(),
        "",
        Some(0),
        1,
    )?;
    let mut store = shum_store::Store::open(&database, &keys.owner_id(), keys.storage_key())?;
    store.transaction(|state| {
        state["ownProfileCard"] = serde_json::to_value(&card)?;
        Ok(())
    })?;
    store.checkpoint()?;
    drop(store);
    progress(3);
    let reopened = shum_store::Store::open(&database, &keys.owner_id(), keys.storage_key())?;
    let stored: Card = serde_json::from_value(reopened.state()["ownProfileCard"].clone())?;
    stored.validate()?;
    ensure(stored == card, "Не прошла проверка защищённого хранилища")?;
    drop(reopened);
    temporary.close()?;
    progress(4);
    Ok(keys)
}

/// Network settings a new profile starts with.
#[derive(Clone, Debug)]
pub struct Settings {
    pub bluetooth: bool,
    pub relays: Vec<String>,
    pub push_url: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            bluetooth: true,
            relays: shum_transport_nostr::DEFAULT_RELAYS
                .iter()
                .map(|s| (*s).into())
                .collect(),
            push_url: Some(DEFAULT_PUSH_URL.into()),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        shum_transport_nostr::RelayPool::validate_urls(&self.relays)?;
        if let Some(url) = &self.push_url {
            shum_transport_nostr::push::PushClient::new(url)?;
        }
        Ok(())
    }
}

/// A profile name: 1–64 bytes of UTF-8, no spaces at the edges.
pub fn validate_name(name: &str) -> Result<()> {
    ensure(
        shum_core::card::valid_name(name),
        "Имя: 1–64 байта UTF-8, без пробелов по краям (до 32 русских букв)",
    )
}

pub struct Created {
    pub profile: Profile,
    pub card: Card,
}

/// Publishes prepared keys as a new selected profile. The stored card is
/// read back and checked; a profile that fails is removed again.
pub fn create(
    root: &Path,
    name: &str,
    seed: Option<u64>,
    mode: KeyMode,
    settings: &Settings,
    keys: ProfileKeys,
) -> Result<Created> {
    validate_name(name)?;
    settings.validate()?;
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        name.into(),
        "",
        Some(seed.unwrap_or_else(|| initial_seed(&keys))),
        1,
    )?;
    card.validate()?;
    let profiles = Profiles::new(root)?;
    let p = profiles.create_with_keys(name, mode, keys)?;
    let save = (|| -> Result<()> {
        let mut open = profiles.open(Some(&p.id))?;
        open.store.transaction(|s| {
            s["ownProfileCard"] = serde_json::to_value(&card)?;
            s["cliSettings"] = json!({"relays":settings.relays,"pushURL":settings.push_url,"bluetooth":settings.bluetooth});
            Ok(())
        })?;
        drop(open);
        let reopened = profiles.open(Some(&p.id))?;
        let stored: Card =
            serde_json::from_value(reopened.store.state()["ownProfileCard"].clone())?;
        stored.validate()?;
        ensure(
            stored == card && stored.id() == reopened.keys.owner_id(),
            "Не прошла проверка сохранённого профиля",
        )?;
        drop(reopened);
        profiles.select(&p.id)?;
        Ok(())
    })();
    if let Err(error) = save {
        if let Err(cleanup) = profiles.delete(&p.id) {
            return Err(anyhow!(
                "{error}; не удалось удалить незавершённый профиль {}: {cleanup}",
                p.id
            ));
        }
        return Err(error);
    }
    Ok(Created { profile: p, card })
}
