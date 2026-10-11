//! The Nostr relay messages Shum sends and accepts, without any connection:
//! native clients speak them over tokio sockets ([`crate::RelayPool`]), the
//! browser over its own WebSocket.
use crate::{Error, Result};
use serde_json::{json, Value};
use shum_core::nostr::Event;

pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://nostr.oxtr.dev",
    "wss://soloco.nl",
    "wss://relay.snort.social",
    "wss://nostr.bitcoiner.social",
];
pub const SUBSCRIPTION: &str = "shum-private-v1";
/// Larger relay messages are dropped, by the socket or by [`read`].
pub const MAX_MESSAGE: usize = 256 * 1024;
const MAX_CONTENT: usize = 65536;
/// Stored events older than this are not requested again.
const LOOKBACK: u64 = 3 * 86400;

/// What a relay said, after every check.
#[derive(Debug, PartialEq)]
pub enum Incoming {
    /// A gift wrap for this inbox, with a valid ID and signature.
    Event(Box<Event>),
    /// The relay's answer to a publication: OK(true) or a rejection.
    Ok {
        id: String,
        accepted: bool,
    },
    EndOfStoredEvents,
    /// The relay ended the subscription; reconnect.
    Closed,
}

pub fn validate_urls(urls: &[String]) -> Result<()> {
    if urls.is_empty() || urls.len() > 16 {
        return Err(Error::Configuration);
    }
    for value in urls {
        let parsed = url::Url::parse(value).map_err(|_| Error::Configuration)?;
        let local_plain = parsed.scheme() == "ws"
            && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if (parsed.scheme() != "wss" && !local_plain)
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::Configuration);
        }
    }
    Ok(())
}

pub fn validate_inbox(public_key: &str) -> Result<()> {
    if public_key.len() != 64 || hex::decode(public_key).is_err() {
        return Err(Error::Configuration);
    }
    Ok(())
}

/// The subscription sent after connecting: gift wraps for `public_key` from
/// the last three days. `now` is in seconds since 1970.
pub fn subscription(public_key: &str, now: u64) -> String {
    let since = now.saturating_sub(LOOKBACK);
    json!(["REQ",SUBSCRIPTION,{"kinds":[1059],"#p":[public_key],"since":since,"limit":100}])
        .to_string()
}

/// The message that publishes `event`, which must be signed.
pub fn publication(event: &Event) -> Result<String> {
    if !event.verify() {
        return Err(Error::Publication);
    }
    Ok(json!(["EVENT", event]).to_string())
}

/// Reads one relay message for the inbox `public_key`. Anything else, and
/// events that fail a check, give `None`.
pub fn read(text: &str, public_key: &str) -> Option<Incoming> {
    if text.len() > MAX_MESSAGE {
        return None;
    }
    let value: Value = serde_json::from_str(text).ok()?;
    let ours = value[1].as_str() == Some(SUBSCRIPTION);
    match value[0].as_str()? {
        "EVENT" if ours && value.as_array().is_some_and(|a| a.len() == 3) => {
            let event: Event = serde_json::from_value(value[2].clone()).ok()?;
            let accepted = event.kind == 1059
                && event.tags == vec![vec!["p".to_owned(), public_key.to_owned()]]
                && event.content.len() <= MAX_CONTENT
                && event.verify();
            accepted.then(|| Incoming::Event(Box::new(event)))
        }
        "OK" => Some(Incoming::Ok {
            id: value[1].as_str()?.into(),
            accepted: value[2].as_bool() == Some(true),
        }),
        "EOSE" if ours => Some(Incoming::EndOfStoredEvents),
        "CLOSED" if ours => Some(Incoming::Closed),
        _ => None,
    }
}
