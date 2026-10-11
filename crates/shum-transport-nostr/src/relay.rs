//! Relay connections over tokio sockets. What to connect, send and close is
//! decided by [`Relays`], the machine every client runs; this module only
//! carries it out and keeps the sockets.
use crate::{
    links::{Effect, Relays, Ticket},
    protocol, Error, Result,
};
use futures_util::{SinkExt, StreamExt};
use shum_core::nostr::Event;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};

/// The machine answers every publication within ten seconds.
const ACK_WAIT: Duration = Duration::from_secs(12);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum RelayUpdate {
    Connected(String),
    Disconnected(String),
    Event { relay: String, event: Box<Event> },
    EndOfStoredEvents(String),
}
struct Publication {
    event: Event,
    reply: Option<oneshot::Sender<bool>>,
}
enum Socket {
    Opened,
    Text(String),
    Closed,
}
enum Outgoing {
    Text(String),
    Ping,
}
struct Lifetime {
    stop: watch::Sender<bool>,
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}
#[derive(Clone)]
pub struct RelayPool {
    publications: mpsc::Sender<Publication>,
    status: watch::Receiver<Vec<String>>,
    _lifetime: Arc<Lifetime>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl RelayPool {
    pub fn validate_urls(urls: &[String]) -> Result<()> {
        protocol::validate_urls(urls)
    }
    pub fn start(urls: &[String], public_key: &str) -> Result<(Self, mpsc::Receiver<RelayUpdate>)> {
        let relays = Relays::new(urls, public_key, true, now())?;
        let (stop, stopped) = watch::channel(false);
        let (status, status_rx) = watch::channel(Vec::new());
        let (updates, incoming) = mpsc::channel(128);
        let (publications, requests) = mpsc::channel(256);
        tokio::spawn(drive(relays, requests, updates, stopped, status));
        Ok((
            Self {
                publications,
                status: status_rx,
                _lifetime: Arc::new(Lifetime { stop }),
            },
            incoming,
        ))
    }
    pub fn connected(&self) -> Vec<String> {
        self.status.borrow().clone()
    }
    /// At least one relay OK(true) is required. This is never a recipient ACK.
    pub async fn publish(&self, event: Event) -> Result<()> {
        if !event.verify() {
            return Err(Error::Publication);
        }
        let (reply, response) = oneshot::channel();
        self.publications
            .try_send(Publication {
                event,
                reply: Some(reply),
            })
            .map_err(|_| Error::Queue)?;
        match timeout(ACK_WAIT, response).await {
            Ok(Ok(true)) => Ok(()),
            _ => Err(Error::Publication),
        }
    }
    /// Contact lookup uses fire-and-forget publication, as Swift does.
    pub fn publish_unconfirmed(&self, event: Event) -> Result<()> {
        if !event.verify() {
            return Err(Error::Publication);
        }
        self.publications
            .try_send(Publication { event, reply: None })
            .map_err(|_| Error::Queue)
    }
}

/// Runs the machine: feeds it publications, socket events and time, and
/// carries out its effects.
async fn drive(
    mut relays: Relays,
    mut publications: mpsc::Receiver<Publication>,
    updates: mpsc::Sender<RelayUpdate>,
    mut stop: watch::Receiver<bool>,
    status: watch::Sender<Vec<String>>,
) {
    let (events, mut sockets) = mpsc::channel::<(usize, u64, Socket)>(256);
    let mut writers: HashMap<usize, mpsc::Sender<Outgoing>> = HashMap::new();
    let mut waiting: HashMap<Ticket, oneshot::Sender<bool>> = HashMap::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            next = publications.recv() => {
                let Some(Publication { event, reply }) = next else { return };
                match relays.publish(&event, reply.is_some(), now()) {
                    Ok(Some(ticket)) => { if let Some(reply) = reply { waiting.insert(ticket, reply); } }
                    Ok(None) => {}
                    Err(_) => { if let Some(reply) = reply { let _ = reply.send(false); } }
                }
            }
            Some((relay, attempt, socket)) = sockets.recv() => match socket {
                Socket::Opened => relays.opened(relay, attempt, now()),
                Socket::Text(text) => relays.received(relay, attempt, &text, now()),
                Socket::Closed => relays.closed(relay, attempt, now()),
            },
            _ = heartbeat.tick() => relays.tick(now()),
        }
        for effect in relays.effects() {
            match effect {
                Effect::Connect { relay, attempt } => {
                    let (writer, outgoing) = mpsc::channel(256);
                    writers.insert(relay, writer);
                    let url = relays.url(relay).unwrap_or_default().to_owned();
                    tokio::spawn(socket(url, relay, attempt, outgoing, events.clone()));
                }
                Effect::Send { relay, text } => {
                    if let Some(writer) = writers.get(&relay) {
                        let _ = writer.try_send(Outgoing::Text(text));
                    }
                }
                Effect::Ping { relay } => {
                    if let Some(writer) = writers.get(&relay) {
                        let _ = writer.try_send(Outgoing::Ping);
                    }
                }
                // Dropping the writer closes the socket.
                Effect::Close { relay } => {
                    writers.remove(&relay);
                }
                Effect::Connected(url) => {
                    let _ = updates.try_send(RelayUpdate::Connected(url));
                }
                Effect::Disconnected(url) => {
                    let _ = updates.try_send(RelayUpdate::Disconnected(url));
                }
                Effect::Event { relay, event } => {
                    let _ = updates.try_send(RelayUpdate::Event { relay, event });
                }
                Effect::EndOfStoredEvents(url) => {
                    let _ = updates.try_send(RelayUpdate::EndOfStoredEvents(url));
                }
                Effect::Published { ticket, accepted } => {
                    if let Some(reply) = waiting.remove(&ticket) {
                        let _ = reply.send(accepted);
                    }
                }
            }
        }
        waiting.retain(|_, reply| !reply.is_closed());
        let connected = relays.connected();
        status.send_if_modified(|list| {
            let changed = *list != connected;
            *list = connected;
            changed
        });
    }
}

/// One WebSocket: reports opening, text messages and closing, and sends
/// what the machine asks for until its writer is dropped.
async fn socket(
    url: String,
    relay: usize,
    attempt: u64,
    mut outgoing: mpsc::Receiver<Outgoing>,
    events: mpsc::Sender<(usize, u64, Socket)>,
) {
    let config = WebSocketConfig::default()
        .max_message_size(Some(protocol::MAX_MESSAGE))
        .max_frame_size(Some(protocol::MAX_MESSAGE));
    let connecting = connect_async_with_config(&url, Some(config), false);
    let connected = tokio::select! {
        result = connecting => Some(result),
        // Nothing is sent before opening; the writer is dropped when the
        // machine gives up on this attempt.
        _ = async { while outgoing.recv().await.is_some() {} } => None,
    };
    if let Some(Ok((mut socket, _))) = connected {
        let _ = events.send((relay, attempt, Socket::Opened)).await;
        loop {
            tokio::select! {
                next = outgoing.recv() => {
                    let message = match next {
                        Some(Outgoing::Text(text)) => Message::Text(text.into()),
                        Some(Outgoing::Ping) => Message::Ping(Vec::new().into()),
                        None => { let _ = timeout(Duration::from_secs(1), socket.close(None)).await; break; }
                    };
                    if !matches!(timeout(SEND_TIMEOUT, socket.send(message)).await, Ok(Ok(()))) { break; }
                }
                message = socket.next() => match message {
                    Some(Ok(Message::Text(text))) => { let _ = events.send((relay, attempt, Socket::Text(text.to_string()))).await; }
                    Some(Ok(Message::Ping(payload))) => {
                        if !matches!(timeout(SEND_TIMEOUT, socket.send(Message::Pong(payload))).await, Ok(Ok(()))) { break; }
                    }
                    // Any other frame, a pong included, shows the relay is alive.
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => { let _ = events.send((relay, attempt, Socket::Text(String::new()))).await; }
                },
            }
        }
    }
    let _ = events.send((relay, attempt, Socket::Closed)).await;
}
