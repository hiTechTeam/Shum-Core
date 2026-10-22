//! Shum-Core for the iPhone. The profile session is the one every client
//! runs (`shum_session::driver`); its records live in the same SQLite file
//! the iOS app already keeps (protocol section 09), opened with the keys the
//! app keeps in the Keychain. Swift owns the radio, the WebSockets, HTTP and
//! the clock, and carries out `effects()` in order.
//!
//! Requests and answers travel as JSON, the same `Request` commands and
//! snapshots as the CLI, the desktop app and the browser.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};
use shum_core::crypto::Secret32;
use shum_session::{
    driver::{push_request, Driver, Output},
    machine::{Host, Nearby},
    Failure, Request,
};
use shum_store::{keys::ProfileKeys, Store};
use std::sync::{Arc, Mutex};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("{0}")]
    Failed(String),
}
fn failed(error: impl std::fmt::Display) -> MobileError {
    MobileError::Failed(error.to_string())
}

/// The four private keys of a profile, 32 bytes each, as the Keychain holds
/// them: Noise static, Ed25519 signing, Nostr and the storage key.
#[derive(uniffi::Record)]
pub struct MobileKeys {
    pub noise: Vec<u8>,
    pub signing: Vec<u8>,
    pub nostr: Vec<u8>,
    pub storage: Vec<u8>,
}

/// Where and how a profile runs.
#[derive(uniffi::Record)]
pub struct MobileProfile {
    /// The profile's SQLite file (protocol section 09).
    pub database: String,
    /// The local profile ID and name.
    pub id: String,
    pub name: String,
    pub relays: Vec<String>,
    /// Whether Swift sends push requests.
    pub push: bool,
    /// JSON object merged into every snapshot, for example the app version.
    pub client: String,
    /// How long encounters nearby stay listed, in hours; 0 keeps the
    /// default of 24.
    pub encounter_retention_hours: u32,
}

fn secret(bytes: &[u8]) -> Result<Secret32, MobileError> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| failed("Ключ профиля должен быть 32 байта"))?;
    Ok(Secret32::new(raw))
}

/// The profile's records in its SQLite file. Every commit is durable before
/// the session sends anything that follows from it.
struct StoreHost {
    id: String,
    name: String,
    keys: ProfileKeys,
    store: Store,
    renamed: bool,
    /// Counts commits, so Swift knows when the stored state changed.
    commits: u64,
}

impl Host for StoreHost {
    fn keys(&self) -> &ProfileKeys {
        &self.keys
    }
    fn state(&self) -> &Value {
        self.store.state()
    }
    fn commit(&mut self, next: Value) -> anyhow::Result<()> {
        if self.store.commit(next)? {
            self.commits += 1;
        }
        Ok(())
    }
    fn profile(&self) -> Value {
        json!({"id": self.id, "name": self.name, "ownerId": self.keys.owner_id()})
    }
    fn renamed(&mut self) -> anyhow::Result<()> {
        let name = self.store.state()["ownProfileCard"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !name.is_empty() && name != self.name {
            self.name = name;
            self.renamed = true;
        }
        Ok(())
    }
    fn backup(&self, password: &str, created_at: &str) -> anyhow::Result<Vec<u8>> {
        Ok(shum_store::backup::seal(
            self.store.state(),
            &self.keys,
            &self.name,
            password,
            created_at,
        )?)
    }
}

fn answer(result: Result<Value, Failure>) -> Value {
    match result {
        Ok(value) => json!({ "ok": value }),
        Err(failure) => json!({ "error": failure }),
    }
}

/// A running profile on the iPhone.
#[derive(uniffi::Object)]
pub struct MobileSession {
    driver: Mutex<Driver<StoreHost>>,
}

#[uniffi::export]
impl MobileSession {
    /// Opens a profile from its SQLite file with its keys and starts the
    /// session. `now` is milliseconds since 1970.
    #[uniffi::constructor]
    pub fn open(
        profile: MobileProfile,
        keys: MobileKeys,
        now: u64,
    ) -> Result<Arc<Self>, MobileError> {
        let MobileProfile {
            database,
            id,
            name,
            relays,
            push,
            client,
            encounter_retention_hours,
        } = profile;
        let keys = ProfileKeys {
            noise: secret(&keys.noise)?,
            signing: secret(&keys.signing)?,
            nostr: secret(&keys.nostr)?,
            storage: secret(&keys.storage)?,
        };
        let store = Store::open(
            &database,
            &keys.owner_id(),
            Secret32::new(*keys.storage.expose()),
        )
        .map_err(failed)?;
        let host = StoreHost {
            id,
            name,
            keys,
            store,
            renamed: false,
            commits: 0,
        };
        let client: Map<String, Value> = serde_json::from_str(&client).unwrap_or_default();
        let mut driver = Driver::new(host, push, client, &relays, true, now).map_err(failed)?;
        if encounter_retention_hours > 0 {
            driver
                .machine
                .set_encounter_retention(i64::from(encounter_retention_hours) * 60 * 60 * 1000);
        }
        Ok(Arc::new(Self {
            driver: Mutex::new(driver),
        }))
    }

    pub fn snapshot(&self) -> String {
        self.lock().snapshot().to_string()
    }

    /// Grows with every change to the stored state; Swift reads `state()`
    /// again only when it did.
    pub fn revision(&self) -> u64 {
        self.lock().machine.host.commits
    }

    /// The stored profile state (protocol section 09) as JSON, the same
    /// layout the iOS app decodes into its own model.
    pub fn state(&self) -> String {
        self.lock().machine.host.store.state().to_string()
    }

    /// Handles a request given as JSON. Returns `{"ok": …}` or
    /// `{"error": …}` at once, or nothing when the answer comes later as a
    /// `reply` effect with this `id`.
    pub fn request(&self, id: u64, request: String, now: u64) -> Option<String> {
        let request: Request = match serde_json::from_str(&request) {
            Ok(request) => request,
            Err(e) => {
                return Some(json!({"error": {"kind": "text", "text": e.to_string()}}).to_string())
            }
        };
        let result = self.lock().request(id, request, now)?;
        Some(answer(result).to_string())
    }

    pub fn opened(&self, relay: u32, attempt: u64, now: u64) {
        self.lock().opened(relay as usize, attempt, now);
    }

    pub fn received(&self, relay: u32, attempt: u64, text: String, now: u64) {
        self.lock().received(relay as usize, attempt, &text, now);
    }

    pub fn closed(&self, relay: u32, attempt: u64, now: u64) {
        self.lock().closed(relay as usize, attempt, now);
    }

    /// Call about once a second.
    pub fn tick(&self, now: u64) {
        self.lock().tick(now);
    }

    /// The app is back in the foreground, or a push woke it: relays
    /// reconnect at once.
    pub fn wake(&self, now: u64) {
        self.lock().wake(now);
    }

    pub fn url(&self, relay: u32) -> Option<String> {
        self.lock().url(relay as usize).map(Into::into)
    }

    /// Someone nearby over Bluetooth: their routing ID, signed card (JSON),
    /// Noise session key, estimated distance in metres and whether the link
    /// is direct. The session records the encounter and can deliver to them.
    pub fn nearby_peer(
        &self,
        routing: String,
        card: String,
        noise: Vec<u8>,
        distance: Option<u32>,
        direct: bool,
    ) -> Result<(), MobileError> {
        let card: shum_core::card::Card = serde_json::from_str(&card).map_err(failed)?;
        card.validate().map_err(failed)?;
        let noise: [u8; 32] = noise
            .try_into()
            .map_err(|_| failed("Ключ Noise должен быть 32 байта"))?;
        self.lock()
            .machine
            .nearby(Nearby::Peer {
                routing,
                card: Box::new(card),
                noise,
                distance,
                direct,
            })
            .map_err(failed)
    }

    /// Someone nearby went out of reach.
    pub fn nearby_gone(&self, routing: String) {
        let _ = self.lock().machine.nearby(Nearby::Gone(routing));
    }

    /// A Shum packet (its JSON bytes) arrived over Bluetooth from `routing`,
    /// whose Noise session key is `noise`.
    pub fn nearby_packet(
        &self,
        routing: String,
        noise: Vec<u8>,
        packet: Vec<u8>,
    ) -> Result<(), MobileError> {
        if packet.len() > 24_000 {
            return Err(failed("Пакет слишком большой"));
        }
        let packet = shum_core::packet::Packet::decode(&packet).map_err(failed)?;
        let noise: [u8; 32] = noise
            .try_into()
            .map_err(|_| failed("Ключ Noise должен быть 32 байта"))?;
        self.lock()
            .machine
            .nearby(Nearby::Packet {
                routing,
                noise,
                packet: Box::new(packet),
            })
            .map_err(failed)
    }

    /// Bluetooth state for snapshots: `role` is "scan" or "advertise".
    pub fn bluetooth(&self, role: String, state: String) {
        let role = if role == "advertise" {
            "advertise"
        } else {
            "scan"
        };
        let _ = self.lock().machine.nearby(Nearby::State { role, state });
    }

    /// The push service answered for `event`; `error` says why it failed.
    pub fn pushed(&self, event: String, error: Option<String>) {
        self.lock().pushed(&event, error);
    }

    /// What Swift does now, in order, as a JSON array of `{"type": …}`:
    /// `connect` (relay, attempt), `send` (relay, text), `ping` (relay),
    /// `close` (relay); news `connected`, `disconnected`, `eose` (url);
    /// `renamed` (name); `reply` (id, ok or error); `push` (event, path,
    /// headers, body in base64) to POST to the push service; `ble` (peer,
    /// packet bytes in base64) for a nearby device.
    pub fn effects(&self, now: u64) -> String {
        let mut driver = self.lock();
        let outputs = driver.outputs();
        let mut all = Vec::new();
        let host = &mut driver.machine.host;
        if std::mem::take(&mut host.renamed) {
            all.push(json!({"type": "renamed", "name": host.name}));
        }
        for output in outputs {
            match output {
                Output::Relay(effect) => all.extend(relay_json(effect)),
                Output::Reply { id, result } => {
                    let mut reply = answer(result);
                    reply["type"] = "reply".into();
                    reply["id"] = id.into();
                    all.push(reply);
                }
                Output::Push {
                    card,
                    key,
                    recipient,
                    event,
                    kind,
                } => match push_request(&card, &key, &recipient, &event, kind, now) {
                    Ok(push) => all.push(push),
                    Err(error) => driver.pushed(&event, Some(error.to_string())),
                },
                // The packet goes over Bluetooth as its JSON bytes.
                Output::SendBle { peer, packet } => {
                    match shum_core::canonical::encode(packet.as_ref()) {
                        Ok(bytes) => all.push(json!({
                            "type": "ble",
                            "peer": peer,
                            "packet": STANDARD.encode(bytes),
                        })),
                        Err(error) => driver.machine.bluetooth["error"] = json!(error.to_string()),
                    }
                }
            }
        }
        Value::from(all).to_string()
    }
}

impl MobileSession {
    fn lock(&self) -> std::sync::MutexGuard<'_, Driver<StoreHost>> {
        self.driver.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn relay_json(effect: shum_transport_nostr::links::Effect) -> Option<Value> {
    use shum_transport_nostr::links::Effect;
    Some(match effect {
        Effect::Connect { relay, attempt } => {
            json!({"type": "connect", "relay": relay, "attempt": attempt})
        }
        Effect::Send { relay, text } => json!({"type": "send", "relay": relay, "text": text}),
        Effect::Ping { relay } => json!({"type": "ping", "relay": relay}),
        Effect::Close { relay } => json!({"type": "close", "relay": relay}),
        Effect::Connected(url) => json!({"type": "connected", "url": url}),
        Effect::Disconnected(url) => json!({"type": "disconnected", "url": url}),
        Effect::EndOfStoredEvents(url) => json!({"type": "eose", "url": url}),
        // Events and publication results stay inside the session.
        Effect::Event { .. } | Effect::Published { .. } => return None,
    })
}

/// Shum-Core's version of the request API, for checks from Swift.
#[uniffi::export]
pub fn command_schema_version() -> u64 {
    shum_session::COMMAND_SCHEMA_VERSION
}

/// The v1 pixel avatar as 36x36 RGBA bytes.
#[uniffi::export]
pub fn avatar_pixels(seed: u64) -> Vec<u8> {
    shum_core::avatar::render(seed)
        .pixels
        .into_iter()
        .flatten()
        .collect()
}

/// What a backup file says about itself before the password is entered.
#[derive(uniffi::Record)]
pub struct MobileBackupSummary {
    pub profile_name: String,
    /// RFC 3339 UTC.
    pub created_at: String,
}

/// A backup opened with its password (protocol section 13): the profile, its
/// keys and its stored state. The storage key is new; the database written
/// from this backup uses it.
#[derive(uniffi::Record)]
pub struct MobileBackup {
    pub name: String,
    pub owner_id: String,
    pub keys: MobileKeys,
    /// The stored profile state (protocol section 09) as JSON.
    pub state: String,
}

/// Reads the profile name and date of a backup file.
#[uniffi::export]
pub fn backup_summary(file: Vec<u8>) -> Result<MobileBackupSummary, MobileError> {
    let summary = shum_store::backup::summary(&file).map_err(failed)?;
    Ok(MobileBackupSummary {
        profile_name: summary.profile_name,
        created_at: summary.created_at,
    })
}

/// Opens and checks a backup file.
#[uniffi::export]
pub fn open_backup(file: Vec<u8>, password: String) -> Result<MobileBackup, MobileError> {
    let opened = shum_store::backup::open(&file, &password).map_err(failed)?;
    Ok(MobileBackup {
        name: opened.name,
        owner_id: opened.owner_id,
        keys: MobileKeys {
            noise: opened.keys.noise.expose().to_vec(),
            signing: opened.keys.signing.expose().to_vec(),
            nostr: opened.keys.nostr.expose().to_vec(),
            storage: opened.keys.storage.expose().to_vec(),
        },
        state: opened.state.to_string(),
    })
}

/// Writes a restored profile state into a new database file, sealed with
/// the restored storage key. An existing database is refused.
#[uniffi::export]
pub fn write_database(
    database: String,
    owner_id: String,
    storage: Vec<u8>,
    state: String,
) -> Result<(), MobileError> {
    if std::path::Path::new(&database).exists() {
        return Err(failed("the profile database already exists"));
    }
    let state: Value = serde_json::from_str(&state).map_err(failed)?;
    let mut store = Store::open(&database, &owner_id, secret(&storage)?).map_err(failed)?;
    store.commit(state).map_err(failed)?;
    store.checkpoint().map_err(failed)?;
    Ok(())
}
