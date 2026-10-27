//! The session machine and the relay connection machine together, for
//! clients that keep their own sockets: the browser and the iPhone. The
//! client feeds in requests, socket events and the time, then carries out
//! [`Output`]s in order. Native desktop clients use [`crate::Session`],
//! which keeps tokio sockets instead.
use crate::{
    machine::{Effect, Host, Machine},
    Failure, Request,
};
use serde_json::{Map, Value};
use shum_core::{card::Card, packet::Packet, queue::PushKind};
use shum_transport_nostr::links::{self, Relays, Ticket};
use std::collections::HashMap;

/// What the client does next.
pub enum Output {
    /// Socket work and relay news, as [`links::Effect`] says.
    Relay(links::Effect),
    /// The answer to a request that waited.
    Reply {
        id: u64,
        result: Result<Value, Failure>,
    },
    /// Ask the push service to wake the recipient, then report through
    /// [`Driver::pushed`].
    Push {
        card: Box<Card>,
        key: shum_core::crypto::Secret32,
        recipient: String,
        event: String,
        kind: PushKind,
    },
    /// Send a packet to a nearby device.
    SendBle { peer: String, packet: Box<Packet> },
    /// Write note `id` to everyone on the Bluetooth mesh.
    Broadcast { id: String, text: String },
}

pub struct Driver<H: Host> {
    pub machine: Machine<H>,
    relays: Relays,
    tickets: HashMap<Ticket, String>,
    now: u64,
    out: Vec<Output>,
}

impl<H: Host> Driver<H> {
    /// Starts the session over `host` with relays at `urls`. `pings` asks
    /// for WebSocket pings, which a browser cannot send. Times are
    /// milliseconds since 1970.
    pub fn new(
        host: H,
        push: bool,
        client: Map<String, Value>,
        urls: &[String],
        pings: bool,
        now: u64,
    ) -> anyhow::Result<Self> {
        let machine = Machine::new(host, push, client)?;
        let relays = Relays::new(urls, machine.inbox(), pings, now)?;
        Ok(Self {
            machine,
            relays,
            tickets: HashMap::new(),
            now,
            out: Vec::new(),
        })
    }

    pub fn snapshot(&mut self) -> Value {
        self.machine.set_relays(self.relays.connected());
        self.machine.snapshot()
    }

    pub fn url(&self, relay: usize) -> Option<&str> {
        self.relays.url(relay)
    }

    /// Handles a request; `None` means the answer comes as [`Output::Reply`].
    pub fn request(
        &mut self,
        id: u64,
        request: Request,
        now: u64,
    ) -> Option<Result<Value, Failure>> {
        self.now = now;
        self.machine.set_relays(self.relays.connected());
        self.machine.request(id, request)
    }

    pub fn opened(&mut self, relay: usize, attempt: u64, now: u64) {
        self.now = now;
        self.relays.opened(relay, attempt, now);
    }

    pub fn received(&mut self, relay: usize, attempt: u64, text: &str, now: u64) {
        self.now = now;
        self.relays.received(relay, attempt, text, now);
    }

    pub fn closed(&mut self, relay: usize, attempt: u64, now: u64) {
        self.now = now;
        self.relays.closed(relay, attempt, now);
    }

    /// Call about once a second.
    pub fn tick(&mut self, now: u64) {
        self.now = now;
        self.relays.tick(now);
        self.machine.set_relays(self.relays.connected());
        self.machine.tick();
    }

    /// The client is back from the background, or a push woke it.
    pub fn wake(&mut self, now: u64) {
        self.now = now;
        self.relays.wake(now);
        self.machine.set_relays(self.relays.connected());
        self.machine.tick();
    }

    /// The push service answered for `event`.
    pub fn pushed(&mut self, event: &str, error: Option<String>) {
        self.machine.pushed(event, error);
    }

    /// What to do now, in order.
    pub fn outputs(&mut self) -> Vec<Output> {
        // The two machines feed each other until both are quiet.
        loop {
            let mut busy = false;
            for effect in self.relays.effects() {
                busy = true;
                match effect {
                    links::Effect::Event { event, .. } => {
                        self.machine.set_relays(self.relays.connected());
                        self.machine.incoming(*event);
                    }
                    links::Effect::Published { ticket, accepted } => {
                        if let Some(operation) = self.tickets.remove(&ticket) {
                            self.machine.published(&operation, accepted);
                        }
                    }
                    other => self.out.push(Output::Relay(other)),
                }
            }
            for effect in self.machine.effects() {
                busy = true;
                match effect {
                    Effect::Publish { operation, event } => {
                        let confirm = operation.is_some();
                        match self.relays.publish(&event, confirm, self.now) {
                            Ok(Some(ticket)) => {
                                if let Some(operation) = operation {
                                    self.tickets.insert(ticket, operation);
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                if let Some(operation) = operation {
                                    self.machine.published(&operation, false);
                                }
                            }
                        }
                    }
                    Effect::Reply { id, result } => self.out.push(Output::Reply { id, result }),
                    Effect::Push {
                        card,
                        key,
                        recipient,
                        event,
                        kind,
                    } => self.out.push(Output::Push {
                        card,
                        key,
                        recipient,
                        event,
                        kind,
                    }),
                    Effect::SendBle { peer, packet } => {
                        self.out.push(Output::SendBle { peer, packet })
                    }
                    Effect::Broadcast { id, text } => self.out.push(Output::Broadcast { id, text }),
                }
            }
            if !busy {
                return std::mem::take(&mut self.out);
            }
        }
    }
}

/// A signed push request (protocol section 08) for a client that sends it
/// itself: `{"type": "push", "event", "path", "headers", "body"}` with the
/// body in base64. `now` is milliseconds since 1970.
pub fn push_request(
    card: &Card,
    key: &shum_core::crypto::Secret32,
    recipient: &str,
    event: &str,
    kind: PushKind,
    now: u64,
) -> anyhow::Result<Value> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use shum_transport_nostr::push;
    let body = push::notification_body(card, recipient, event, kind)?;
    let signed = push::signed_request(
        "POST",
        "/v1/notifications",
        body,
        key,
        (now / 1000) as i64,
        &hex::encode(crate::random::<16>()?),
    )?;
    Ok(serde_json::json!({
        "type": "push",
        "event": event,
        "path": "/v1/notifications",
        "headers": {
            "Content-Type": "application/json",
            "X-Shum-Public-Key": signed.public_key,
            "X-Shum-Timestamp": signed.timestamp,
            "X-Shum-Nonce": signed.nonce,
            "X-Shum-Signature": signed.signature,
        },
        "body": STANDARD.encode(signed.body),
    }))
}

/// Avatar seeds are 64-bit; JavaScript numbers would round them, so clients
/// with JavaScript interfaces get them as text.
pub fn quote_seeds(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "avatarSeed" && item.is_u64() {
                    *item = Value::String(item.to_string());
                } else {
                    quote_seeds(item);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(quote_seeds),
        _ => {}
    }
}
