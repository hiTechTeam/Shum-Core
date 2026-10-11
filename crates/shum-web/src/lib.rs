//! Shum-Core in the browser. A profile lives in memory here; its encrypted
//! records (protocol section 09, the same layout as SQLite in native
//! clients) and its sealed key bundle live in IndexedDB, written by the page.
//! Saving is two steps: [`WebProfile::plan`] says what to write and delete,
//! the page stores that in one IndexedDB transaction, then calls
//! [`WebProfile::applied`]. Nothing is published to memory before that.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shum_core::card::Card;
use shum_store::{
    empty_state,
    keys::ProfileKeys,
    records::{Plan, Record, Records},
};
use wasm_bindgen::prelude::*;

/// A record as the page stores it: the payload in base64.
#[derive(Serialize, Deserialize)]
struct Stored {
    bucket: String,
    id: String,
    position: i64,
    payload: String,
}
impl From<&Record> for Stored {
    fn from(r: &Record) -> Self {
        Self {
            bucket: r.bucket.clone(),
            id: r.id.clone(),
            position: r.position,
            payload: STANDARD.encode(&r.payload),
        }
    }
}
impl TryFrom<Stored> for Record {
    type Error = JsError;
    fn try_from(s: Stored) -> Result<Self, JsError> {
        Ok(Record {
            bucket: s.bucket,
            id: s.id,
            position: s.position,
            payload: STANDARD
                .decode(s.payload)
                .map_err(|e| JsError::new(&e.to_string()))?,
        })
    }
}

fn error(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub struct WebProfile {
    keys: ProfileKeys,
    records: Records,
    pending: Option<Plan>,
}

#[wasm_bindgen]
impl WebProfile {
    /// A new profile with fresh keys and a signed card. The page stores
    /// `records()` and the sealed `keyBundle()` before using it.
    pub fn create(name: &str, avatar_seed: Option<String>) -> Result<WebProfile, JsError> {
        let keys = ProfileKeys::generate().map_err(error)?;
        let name = shum_core::card::trim(name);
        let seed = match avatar_seed {
            Some(seed) => seed.parse::<u64>().map_err(error)?,
            None => shum_core::crypto::avatar_seed(&keys.signing.ed_public()),
        };
        let card = Card::create(
            &keys.noise,
            &keys.signing,
            &keys.nostr,
            name.into(),
            "",
            Some(seed),
            1,
        )
        .map_err(error)?;
        card.validate().map_err(error)?;
        let owner = keys.owner_id();
        let mut state = empty_state(&owner);
        state["ownProfileCard"] = serde_json::to_value(&card)?;
        let (records, _) = Records::create(&owner, keys.storage_key(), &state).map_err(error)?;
        Ok(Self {
            keys,
            records,
            pending: None,
        })
    }

    /// Opens a stored profile: the unsealed key bundle and all its records.
    pub fn open(key_bundle: &[u8], records_json: &str) -> Result<WebProfile, JsError> {
        let keys = ProfileKeys::decode(key_bundle).map_err(error)?;
        let stored: Vec<Stored> = serde_json::from_str(records_json)?;
        let stored = stored
            .into_iter()
            .map(Record::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let records = Records::load(&keys.owner_id(), keys.storage_key(), stored).map_err(error)?;
        let mut profile = Self {
            keys,
            records,
            pending: None,
        };
        // Like every open, bring an older layout up to date.
        if let Some(plan) = profile.records.normalize().map_err(error)? {
            profile.pending = Some(plan);
        }
        Ok(profile)
    }

    #[wasm_bindgen(js_name = ownerId)]
    pub fn owner_id(&self) -> String {
        self.keys.owner_id()
    }

    /// The profile state (protocol section 09) as JSON.
    pub fn state(&self) -> String {
        self.records.state().to_string()
    }

    /// Every record, for writing a newly created profile.
    pub fn records(&self) -> Result<String, JsError> {
        let all: Vec<Stored> = self.records.all().iter().map(Stored::from).collect();
        Ok(serde_json::to_string(&all)?)
    }

    /// The 136-byte key bundle. The page seals it with a non-extractable
    /// WebCrypto key before it touches storage.
    #[wasm_bindgen(js_name = keyBundle)]
    pub fn key_bundle(&self) -> Vec<u8> {
        self.keys.encode().to_vec()
    }

    /// A plan opened by `open` that the page should store first, if any.
    #[wasm_bindgen(js_name = pendingPlan)]
    pub fn pending_plan(&self) -> Result<Option<String>, JsError> {
        self.pending.as_ref().map(plan_json).transpose()
    }

    /// Plans storing `state_json`: `{write, delete}` as JSON, or `null`
    /// when nothing changes. The plan waits for `applied`.
    pub fn plan(&mut self, state_json: &str) -> Result<Option<String>, JsError> {
        let next: Value = serde_json::from_str(state_json)?;
        let plan = self.records.plan(next).map_err(error)?;
        let json = plan.as_ref().map(plan_json).transpose()?;
        self.pending = plan;
        Ok(json)
    }

    /// The page stored the pending plan; it becomes the current state.
    pub fn applied(&mut self) {
        if let Some(plan) = self.pending.take() {
            self.records.apply(plan);
        }
    }
}

fn plan_json(plan: &Plan) -> Result<String, JsError> {
    #[derive(Serialize)]
    struct Json<'a> {
        write: Vec<Stored>,
        delete: &'a [(String, String)],
    }
    Ok(serde_json::to_string(&Json {
        write: plan.write.iter().map(Stored::from).collect(),
        delete: &plan.delete,
    })?)
}
