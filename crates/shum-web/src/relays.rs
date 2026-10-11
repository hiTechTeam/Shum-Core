//! Relay connections for the page. The page keeps the WebSockets; what to
//! connect, send and close is decided by the same machine native clients
//! run ([`Relays`]), and it checks everything that arrives.
use crate::error;
use serde_json::{json, Value};
use shum_core::nostr::Event;
use shum_transport_nostr::{
    links::{Effect, Relays},
    protocol,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = defaultRelays)]
pub fn default_relays() -> Vec<String> {
    protocol::DEFAULT_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The machine for one inbox. Times are milliseconds since 1970
/// (`Date.now()`). After every call the page carries out `effects()`.
#[wasm_bindgen]
pub struct WebRelays {
    relays: Relays,
}

#[wasm_bindgen]
impl WebRelays {
    /// Relays for `inbox` (a Nostr public key in hex). The browser cannot
    /// send WebSocket pings, so the machine does not ask for them.
    #[wasm_bindgen(constructor)]
    pub fn new(urls: Vec<String>, inbox: &str, now: f64) -> Result<WebRelays, JsError> {
        Ok(Self {
            relays: Relays::new(&urls, inbox, false, now as u64).map_err(error)?,
        })
    }

    pub fn url(&self, relay: usize) -> Option<String> {
        self.relays.url(relay).map(Into::into)
    }

    pub fn connected(&self) -> Vec<String> {
        self.relays.connected()
    }

    /// Publishes a signed event given as JSON. With `confirm` returns the
    /// ticket a later `published` effect answers.
    pub fn publish(
        &mut self,
        event_json: &str,
        confirm: bool,
        now: f64,
    ) -> Result<Option<f64>, JsError> {
        let event: Event = serde_json::from_str(event_json)?;
        let ticket = self
            .relays
            .publish(&event, confirm, now as u64)
            .map_err(error)?;
        Ok(ticket.map(|t| t as f64))
    }

    pub fn opened(&mut self, relay: usize, attempt: f64, now: f64) {
        self.relays.opened(relay, attempt as u64, now as u64);
    }

    pub fn received(&mut self, relay: usize, attempt: f64, text: &str, now: f64) {
        self.relays
            .received(relay, attempt as u64, text, now as u64);
    }

    pub fn closed(&mut self, relay: usize, attempt: f64, now: f64) {
        self.relays.closed(relay, attempt as u64, now as u64);
    }

    pub fn tick(&mut self, now: f64) {
        self.relays.tick(now as u64);
    }

    /// What to do now, as a JSON array of `{"type": …}` objects: `connect`
    /// (relay, attempt), `send` (relay, text), `close` (relay), and the
    /// news `connected`, `disconnected`, `eose` (relay URL), `event` (relay
    /// URL, event) and `published` (ticket, accepted).
    pub fn effects(&mut self) -> String {
        Value::from(
            self.relays
                .effects()
                .into_iter()
                .filter_map(effect_json)
                .collect::<Vec<_>>(),
        )
        .to_string()
    }
}

pub(crate) fn effect_json(effect: Effect) -> Option<Value> {
    Some(match effect {
        Effect::Connect { relay, attempt } => {
            json!({"type": "connect", "relay": relay, "attempt": attempt})
        }
        Effect::Send { relay, text } => json!({"type": "send", "relay": relay, "text": text}),
        Effect::Ping { .. } => return None,
        Effect::Close { relay } => json!({"type": "close", "relay": relay}),
        Effect::Connected(url) => json!({"type": "connected", "url": url}),
        Effect::Disconnected(url) => json!({"type": "disconnected", "url": url}),
        Effect::EndOfStoredEvents(url) => json!({"type": "eose", "url": url}),
        Effect::Event { relay, event } => json!({"type": "event", "url": relay, "event": event}),
        Effect::Published { ticket, accepted } => {
            json!({"type": "published", "ticket": ticket, "accepted": accepted})
        }
    })
}
