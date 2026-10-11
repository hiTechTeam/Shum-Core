//! The profile session in the browser: the same machine native clients run
//! (`shum_session::machine`), with the relay connection machine beside it.
//! The page keeps the WebSockets and IndexedDB and carries out `effects()`
//! strictly in order: storage writes come first, so nothing is sent before
//! the state that caused it is stored.
use crate::{error, invitation_json, relays::effect_json, Stored, WebProfile};
use serde_json::{json, Value};
use shum_session::{
    driver::{quote_seeds, Driver, Output},
    machine::Host,
    Request,
};
use shum_store::{keys::ProfileKeys, records::Records};
use wasm_bindgen::prelude::*;

/// Storage of an open browser profile: the records live in memory and
/// every commit becomes a write the page stores before anything else.
struct WebHost {
    id: String,
    name: String,
    keys: ProfileKeys,
    records: Records,
    writes: Vec<Value>,
    renamed: bool,
}

impl Host for WebHost {
    fn keys(&self) -> &ProfileKeys {
        &self.keys
    }
    fn state(&self) -> &Value {
        self.records.state()
    }
    fn commit(&mut self, next: Value) -> anyhow::Result<()> {
        if let Some(plan) = self.records.plan(next)? {
            let write: Vec<Stored> = plan.write.iter().map(Stored::from).collect();
            self.writes
                .push(json!({"type": "store", "write": write, "delete": plan.delete}));
            self.records.apply(plan);
        }
        Ok(())
    }
    fn profile(&self) -> Value {
        json!({"id": self.id, "name": self.name, "ownerId": self.keys.owner_id()})
    }
    fn backup(&self, password: &str, created_at: &str) -> anyhow::Result<Vec<u8>> {
        Ok(shum_store::backup::seal(
            self.records.state(),
            &self.keys,
            &self.name,
            password,
            created_at,
        )?)
    }
    fn renamed(&mut self) -> anyhow::Result<()> {
        let name = self.records.state()["ownProfileCard"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if name != self.name {
            self.name = name;
            self.renamed = true;
        }
        Ok(())
    }
}

#[wasm_bindgen]
pub struct WebSession {
    driver: Driver<WebHost>,
}

#[wasm_bindgen]
impl WebSession {
    /// Starts the session of an opened profile. `id` and `name` are its
    /// local entry; times are milliseconds since 1970 (`Date.now()`).
    #[wasm_bindgen(constructor)]
    pub fn new(
        profile: WebProfile,
        id: String,
        name: String,
        relays: Vec<String>,
        now: f64,
    ) -> Result<WebSession, JsError> {
        let WebProfile { keys, records, .. } = profile;
        let host = WebHost {
            id,
            name,
            keys,
            records,
            writes: Vec::new(),
            renamed: false,
        };
        let mut client = serde_json::Map::new();
        client.insert("owner".into(), "browser".into());
        // The browser cannot send WebSocket pings, so the relays get none.
        let driver = Driver::new(host, false, client, &relays, false, now as u64).map_err(error)?;
        Ok(Self { driver })
    }

    pub fn snapshot(&mut self) -> String {
        let mut snapshot = self.driver.snapshot();
        quote_seeds(&mut snapshot);
        snapshot.to_string()
    }

    /// Handles a request given as JSON. Returns `{"ok": …}` or
    /// `{"error": …}` at once, or `undefined` when the answer comes later as
    /// a `reply` effect with this `id`.
    pub fn request(&mut self, id: f64, request_json: &str, now: f64) -> Option<String> {
        let request: Request = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(e) => {
                return Some(json!({"error": {"kind": "text", "text": e.to_string()}}).to_string())
            }
        };
        let result = self.driver.request(id as u64, request, now as u64)?;
        Some(answer(result).to_string())
    }

    pub fn opened(&mut self, relay: usize, attempt: f64, now: f64) {
        self.driver.opened(relay, attempt as u64, now as u64);
    }

    pub fn received(&mut self, relay: usize, attempt: f64, text: &str, now: f64) {
        self.driver
            .received(relay, attempt as u64, text, now as u64);
    }

    pub fn closed(&mut self, relay: usize, attempt: f64, now: f64) {
        self.driver.closed(relay, attempt as u64, now as u64);
    }

    /// Call about once a second.
    pub fn tick(&mut self, now: f64) {
        self.driver.tick(now as u64);
    }

    /// This profile's invitation link and QR code: `{"link": …, "qr": …}`.
    pub fn invitation(&self) -> Result<String, JsError> {
        invitation_json(&self.driver.machine.engine.inbox.own)
    }

    pub fn url(&self, relay: usize) -> Option<String> {
        self.driver.url(relay).map(Into::into)
    }

    /// What the page does now, in this order, as a JSON array: `store`
    /// (write, delete) writes to keep first; `renamed` (name); the relay
    /// effects of `WebRelays.effects`; `reply` (id, ok or error).
    pub fn effects(&mut self) -> String {
        let outputs = self.driver.outputs();
        let host = &mut self.driver.machine.host;
        let mut all: Vec<Value> = std::mem::take(&mut host.writes);
        if std::mem::take(&mut host.renamed) {
            all.push(json!({"type": "renamed", "name": host.name}));
        }
        for output in outputs {
            match output {
                Output::Relay(effect) => all.extend(effect_json(effect)),
                Output::Reply { id, result } => {
                    let mut reply = answer(result);
                    reply["type"] = "reply".into();
                    reply["id"] = id.into();
                    all.push(reply);
                }
                // The browser has neither push requests nor Bluetooth.
                Output::Push { .. } | Output::SendBle { .. } => {}
            }
        }
        Value::from(all).to_string()
    }
}

fn answer(result: Result<Value, shum_session::Failure>) -> Value {
    match result {
        Ok(mut value) => {
            quote_seeds(&mut value);
            json!({ "ok": value })
        }
        Err(failure) => json!({ "error": failure }),
    }
}
