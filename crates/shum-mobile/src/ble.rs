//! Bluetooth on the iPhone. Swift's CoreBluetooth radio reports links,
//! bytes and signal strength; Shum-Core's mesh, the same one desktop clients
//! run, does the handshakes, peers, frames and relaying; the session decides
//! what to send. Swift only writes the `ble-frames` effects to their links.
use crate::{failed, MobileError, MobileSession, StoreHost};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use shum_core::{card::Card, crypto::Secret32, packet::Packet};
use shum_session::{driver::Driver, machine::Nearby};
use shum_transport_ble::mesh::{Effect, Mesh};
use std::collections::HashSet;

#[derive(Default)]
pub(crate) struct Ble {
    mesh: Option<Mesh>,
    /// Frames for Swift to write, in order, as `ble-frames` effects.
    frames: Vec<Value>,
    /// The profile the mesh was last given, to update it only on changes.
    profile: String,
}

/// The own card, the cards to recognise (contacts and blocked people) and
/// the blocked IDs, with a key that changes when any of them changes.
fn profile(driver: &Driver<StoreHost>) -> (Card, Vec<Card>, HashSet<String>, String) {
    let inbox = &driver.machine.engine.inbox;
    let pins: Vec<Card> = inbox
        .contacts
        .values()
        .chain(inbox.blocked_cards.values())
        .cloned()
        .collect();
    let mut ids: Vec<String> = pins
        .iter()
        .map(|c| format!("{}:{}", c.id(), hex::encode(&c.signature)))
        .collect();
    ids.sort();
    let mut blocked: Vec<&String> = inbox.blocked.iter().collect();
    blocked.sort();
    let key = format!(
        "{}|{}|{:?}",
        serde_json::to_string(&inbox.own).unwrap_or_default(),
        ids.join(","),
        blocked
    );
    (inbox.own.clone(), pins, inbox.blocked.clone(), key)
}

impl Ble {
    /// Frames wait for Swift; peers and packets go to the session.
    fn apply(&mut self, driver: &mut Driver<StoreHost>, effects: anyhow::Result<Vec<Effect>>) {
        let effects = match effects {
            Ok(effects) => effects,
            Err(error) => {
                driver.machine.bluetooth["error"] = json!(error.to_string());
                return;
            }
        };
        for effect in effects {
            let news = match effect {
                Effect::Send { link, frames } => {
                    let frames: Vec<String> = frames.iter().map(|f| STANDARD.encode(f)).collect();
                    self.frames
                        .push(json!({"type": "ble-frames", "link": link, "frames": frames}));
                    continue;
                }
                Effect::Peer {
                    routing,
                    card,
                    noise,
                    distance,
                    direct,
                } => Nearby::Peer {
                    routing,
                    card,
                    noise,
                    distance,
                    direct,
                },
                Effect::Gone(routing) => Nearby::Gone(routing),
                Effect::Packet {
                    routing,
                    noise,
                    packet,
                } => Nearby::Packet {
                    routing,
                    noise,
                    packet,
                },
            };
            if let Err(error) = driver.machine.nearby(news) {
                driver.machine.bluetooth["error"] = json!(error.to_string());
            }
        }
    }

    /// Gives the mesh the current profile when it changed.
    fn refresh(&mut self, driver: &mut Driver<StoreHost>, now: u64) {
        let Some(mesh) = self.mesh.as_mut() else {
            return;
        };
        let (card, pins, blocked, key) = profile(driver);
        if key == self.profile {
            return;
        }
        self.profile = key;
        let effects = mesh.update(card, pins, blocked, now as i64);
        self.apply(driver, effects);
    }

    /// About once a second: announcements, handshakes and expiry.
    pub(crate) fn tick(&mut self, driver: &mut Driver<StoreHost>, now: u64) {
        self.refresh(driver, now);
        if let Some(mesh) = self.mesh.as_mut() {
            let effects = mesh.tick(now as i64);
            self.apply(driver, effects);
        }
    }

    /// Sends a session packet through the mesh. Returns false without a
    /// mesh, so the packet takes the app's own Bluetooth instead.
    pub(crate) fn send(
        &mut self,
        driver: &mut Driver<StoreHost>,
        peer: &str,
        packet: &Packet,
        now: u64,
    ) -> bool {
        let Some(mesh) = self.mesh.as_mut() else {
            return false;
        };
        let effects = mesh.send(peer, packet, now as i64).map(|e| vec![e]);
        self.apply(driver, effects);
        true
    }

    pub(crate) fn take_frames(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.frames)
    }
}

#[uniffi::export]
impl MobileSession {
    /// Bluetooth is on: Shum-Core's mesh starts for this profile. Until
    /// then `ble` effects carry whole packets for the app's own Bluetooth.
    pub fn ble_start(&self, now: u64) -> Result<(), MobileError> {
        let mut driver = self.lock();
        let mut ble = self.ble();
        let (card, pins, blocked, key) = profile(&driver);
        let keys = &driver.machine.host.keys;
        let mesh = Mesh::new(
            card,
            Secret32::new(*keys.noise.expose()),
            Secret32::new(*keys.signing.expose()),
            pins,
            blocked,
        )
        .map_err(failed)?;
        ble.mesh = Some(mesh);
        ble.profile = key;
        ble.tick(&mut driver, now);
        Ok(())
    }

    /// Bluetooth is off: everyone nearby is gone.
    pub fn ble_stop(&self) {
        let mut driver = self.lock();
        let mut ble = self.ble();
        ble.mesh = None;
        ble.frames.clear();
        driver.machine.clear_nearby();
    }

    /// A link opened. `budget` is the largest write in bytes; `rssi` the
    /// signal strength when known.
    pub fn ble_connected(&self, link: String, budget: u32, rssi: Option<i16>, now: u64) {
        let mut driver = self.lock();
        let mut ble = self.ble();
        if let Some(mesh) = ble.mesh.as_mut() {
            let effects = mesh.connected(link, budget as usize, rssi, now as i64);
            ble.apply(&mut driver, effects);
        }
    }

    pub fn ble_disconnected(&self, link: String) {
        let mut driver = self.lock();
        let mut ble = self.ble();
        if let Some(mesh) = ble.mesh.as_mut() {
            let effects = Ok(mesh.disconnected(&link));
            ble.apply(&mut driver, effects);
        }
    }

    /// Bytes a link received (one GATT write or notification).
    pub fn ble_received(&self, link: String, bytes: Vec<u8>, now: u64) {
        let mut driver = self.lock();
        let mut ble = self.ble();
        if let Some(mesh) = ble.mesh.as_mut() {
            let effects = mesh.receive(&link, &bytes, now as i64);
            ble.apply(&mut driver, effects);
        }
    }

    /// A signal strength reading of a link, for distance.
    pub fn ble_rssi(&self, link: String, rssi: i16, now: u64) {
        let mut driver = self.lock();
        let mut ble = self.ble();
        if let Some(mesh) = ble.mesh.as_mut() {
            let effects = mesh.measured(&link, rssi, now as i64);
            ble.apply(&mut driver, effects);
        }
    }
}
