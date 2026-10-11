//! Relay messages for the page, which keeps the connections itself with the
//! browser's WebSocket. Shum-Core builds what is sent and checks everything
//! that arrives, exactly as native clients do.
use crate::error;
use serde_json::json;
use shum_core::nostr::Event;
use shum_transport_nostr::protocol::{self, Incoming};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = defaultRelays)]
pub fn default_relays() -> Vec<String> {
    protocol::DEFAULT_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Fails unless every address is a secure relay address.
#[wasm_bindgen(js_name = validateRelays)]
pub fn validate_relays(urls: Vec<String>) -> Result<(), JsError> {
    protocol::validate_urls(&urls).map_err(error)
}

/// The first message on a new connection: gift wraps for `inbox` (a Nostr
/// public key in hex). `now` is in seconds since 1970.
#[wasm_bindgen(js_name = relaySubscription)]
pub fn relay_subscription(inbox: &str, now: f64) -> Result<String, JsError> {
    protocol::validate_inbox(inbox).map_err(error)?;
    Ok(protocol::subscription(inbox, now.max(0.0) as u64))
}

/// The message that publishes a signed event given as JSON.
#[wasm_bindgen(js_name = relayPublication)]
pub fn relay_publication(event_json: &str) -> Result<String, JsError> {
    let event: Event = serde_json::from_str(event_json)?;
    protocol::publication(&event).map_err(error)
}

/// Reads one relay message for `inbox`, as JSON:
/// `{"type":"event","event":…}`, `{"type":"ok","id":…,"accepted":…}`,
/// `{"type":"eose"}` or `{"type":"closed"}`. Anything else, including
/// events that fail a check, gives `undefined`.
#[wasm_bindgen(js_name = relayRead)]
pub fn relay_read(text: &str, inbox: &str) -> Option<String> {
    let value = match protocol::read(text, inbox)? {
        Incoming::Event(event) => json!({"type": "event", "event": event}),
        Incoming::Ok { id, accepted } => json!({"type": "ok", "id": id, "accepted": accepted}),
        Incoming::EndOfStoredEvents => json!({"type": "eose"}),
        Incoming::Closed => json!({"type": "closed"}),
    };
    Some(value.to_string())
}
