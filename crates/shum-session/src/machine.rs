//! The session of one profile as a state machine, the same in every client:
//! commands, incoming messages, relay and push results and Bluetooth news go
//! in; what to publish, push, send nearby and reply comes out as [`Effect`]s.
//! It never touches sockets, files or clocks of its own runtime: storage is
//! the client's [`Host`], and the client carries out the effects. Native
//! clients run it with tokio ([`crate::Session`]), the browser from
//! WebAssembly.
use crate::{now, phase, random, text, uuid, Failure, Request};
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};
use shum_core::public::PublicBody;
use shum_core::{
    canonical,
    card::Card,
    crypto::Secret32,
    engine::{Context, Engine, Keys},
    invitation::{self, Invitation},
    nostr::{self, WrapEntropy},
    packet::*,
    photo::{Photo, PhotoPart},
    profile::Manifest,
    queue::{Action, Peer, PushKind, Routes},
    rules::Source,
};
use shum_store::{engine as persistence, keys::ProfileKeys};
use std::collections::{HashMap, HashSet};

/// Where a profile is stored, and what only the client can do with it.
pub trait Host {
    fn keys(&self) -> &ProfileKeys;
    /// The stored profile state (protocol section 09).
    fn state(&self) -> &Value;
    /// Stores `next` durably before anything that follows is sent.
    fn commit(&mut self, next: Value) -> Result<()>;
    /// The `profile` entry of snapshots: the local profile's ID and name.
    fn profile(&self) -> Value;
    /// Checks a new name against the client's other local profiles.
    fn check_name(&self, name: &str) -> Result<()> {
        if shum_core::card::valid_name(name) {
            Ok(())
        } else {
            Err(text(
                "Имя: 1–64 байта UTF-8, без пробелов по краям (до 32 русских букв)",
            ))
        }
    }
    /// The profile's name changed; clients that list profiles update it.
    fn renamed(&mut self) -> Result<()> {
        Ok(())
    }
    /// Seals the profile into a backup file (protocol section 13).
    fn backup(&self, _password: &str, _created_at: &str) -> Result<Vec<u8>> {
        Err(text("Резервная копия здесь пока недоступна"))
    }
    /// Stores the JPEG of message `id` apart from the state (protocol
    /// section 04.9), so it is read only when shown.
    fn put_photo(&mut self, _id: &str, _jpeg: &[u8]) -> Result<()> {
        Err(text("Фото здесь пока недоступны"))
    }
    fn photo(&self, _id: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn delete_photo(&mut self, _id: &str) -> Result<()> {
        Ok(())
    }
}

/// By name, then by ID: people may share a name, and a list must not
/// reshuffle them on every snapshot.
fn by_name(a: &Value, b: &Value) -> std::cmp::Ordering {
    let key = |v: &Value| {
        (
            v["card"]["name"].as_str().map(str::to_owned),
            v["id"].as_str().map(str::to_owned),
        )
    };
    key(a).cmp(&key(b))
}

/// Who is still shown in the open chat, by name and then by ID like the
/// other lists, so people with one name do not swap places.
fn shown(people: &HashMap<String, (Card, i64)>) -> Vec<&Card> {
    let now = now();
    let mut cards: Vec<&Card> = people
        .values()
        .filter(|(_, until)| *until > now)
        .map(|(card, _)| card)
        .collect();
    cards.sort_by_cached_key(|c| (c.name.clone(), c.id()));
    cards
}

/// What clients show of a photo: never its key. `state` is ready, loading,
/// or missing once its message expired before every part came.
fn photo_view(photo: &Photo, missing: bool, expires_at: i64) -> Value {
    let state = if !missing {
        "ready"
    } else if expires_at > now() {
        "loading"
    } else {
        "missing"
    };
    json!({"width":photo.width,"height":photo.height,"size":photo.size,"caption":photo.caption,"state":state})
}

/// Parts of a photo that came before its message wait this long, this many.
const EARLY_PART_MS: i64 = 3_600_000;
const EARLY_PARTS: usize = 64;
/// Photos being put together at once.
const PHOTO_BUFFERS: usize = 16;

/// Being in the open chat goes out again this often while it is on screen.
const PUBLIC_PRESENCE_REPEAT_MS: i64 = 15_000;
/// Someone shows as in the open chat this long after their last signal.
const PUBLIC_PRESENCE_SHOWN_MS: i64 = 40_000;
/// Own typing in the open chat goes out again this often while it lasts.
const PUBLIC_TYPING_REPEAT_MS: i64 = 4_000;
/// Someone's typing shows this long after their last signal.
const PUBLIC_TYPING_SHOWN_MS: i64 = 6_000;
/// Open-chat copies sent in one tick at most.
const COPIES_PER_TICK: usize = 10;
/// A refused copy waits this long, doubling up to the maximum.
const COPY_RETRY_MS: i64 = 5_000;
const COPY_RETRY_MAX_MS: i64 = 10 * 60_000;

/// What the client does next.
pub enum Effect {
    /// Publish a signed gift wrap to the relays. With an operation the
    /// client reports the relays' answer through [`Machine::published`].
    Publish {
        operation: Option<String>,
        event: nostr::Event,
    },
    /// Ask the push service to wake the recipient; the client reports the
    /// outcome through [`Machine::pushed`].
    Push {
        card: Box<Card>,
        key: Secret32,
        recipient: String,
        event: String,
        kind: PushKind,
    },
    /// Send a packet to a nearby device over Bluetooth.
    SendBle { peer: String, packet: Box<Packet> },
    /// Send event `id` to everyone on the Bluetooth mesh.
    Broadcast {
        id: String,
        body: shum_core::public::PublicBody,
    },
    /// The answer to a request that waited, by its ID.
    Reply {
        id: u64,
        result: std::result::Result<Value, Failure>,
    },
}

/// News from Bluetooth, as native clients' transport reports it.
pub enum Nearby {
    Peer {
        routing: String,
        card: Box<Card>,
        noise: [u8; 32],
        distance: Option<u32>,
        direct: bool,
    },
    Gone(String),
    Packet {
        routing: String,
        noise: [u8; 32],
        packet: Box<Packet>,
    },
    /// A note in the open chat, from anywhere on the mesh.
    Public {
        event: Box<shum_core::public::PublicEvent>,
        timestamp: i64,
    },
    State {
        role: &'static str,
        state: String,
    },
}

/// What a lookup does with the card it finds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Then {
    Add,
    Invite,
    /// Only shows it, so the person can be checked before adding.
    Show,
}
struct Lookup {
    key: String,
    then: Then,
    expires: i64,
    reply: u64,
}
struct NearbyPeer {
    peer: Peer,
    noise: [u8; 32],
    distance: Option<u32>,
    direct: bool,
}

fn secret() -> Result<Secret32> {
    Ok(Secret32::new(random()?))
}
fn wrap(key: &Secret32, recipient: &str, content: String) -> Result<nostr::Event> {
    let outer = loop {
        let key = secret()?;
        if key.nostr_public().is_ok() {
            break key;
        }
    };
    let time = now() / 1000;
    let offsets = random::<4>()?;
    Ok(nostr::create_private(
        key,
        recipient,
        content,
        time,
        WrapEntropy {
            outer_key: &outer,
            seal_nonce: random()?,
            wrap_nonce: random()?,
            seal_aux: random()?,
            wrap_aux: random()?,
            seal_time: time - 1 - (u16::from_be_bytes([offsets[0], offsets[1]]) % 300) as i64,
            wrap_time: time - 1 - (u16::from_be_bytes([offsets[2], offsets[3]]) % 300) as i64,
        },
    )?)
}

/// A running profile: its engine and everything the session keeps in memory.
pub struct Machine<H: Host> {
    pub host: H,
    pub engine: Engine,
    client: Map<String, Value>,
    nearby: HashMap<String, NearbyPeer>,
    /// Grows whenever someone comes or goes nearby or their distance
    /// changes, which stores nothing, so clients know to show it.
    pub nearby_changes: u64,
    /// Bluetooth status for snapshots; native clients keep it up to date.
    pub bluetooth: Value,
    relays: Vec<String>,
    push: bool,
    /// How long encounters nearby stay listed; each client chooses.
    encounter_retention: i64,
    inflight: HashSet<String>,
    /// Sealed parts of photos this device sends, by message; rebuilt from
    /// the stored JPEG when not here.
    photo_parts: HashMap<String, Vec<PhotoPart>>,
    /// Opened parts of photos coming in, by message, with when the first
    /// came; and parts that came before their message.
    photo_buffers: HashMap<String, (i64, HashMap<usize, Vec<u8>>)>,
    early_parts: Vec<(i64, PhotoPart)>,
    pushed: HashSet<String>,
    lookups: HashMap<String, Lookup>,
    /// When each author's recent open-chat notes arrived, to drop floods.
    public_rate: HashMap<String, Vec<i64>>,
    /// Refused open-chat copies: how many times, and when to try again.
    copy_retry: HashMap<String, (u32, i64)>,
    /// Who is typing in the open chat, by card ID, until when.
    public_typing: HashMap<String, (Card, i64)>,
    /// The last own typing signal in the open chat and when it went.
    public_typing_sent: Option<(bool, i64)>,
    /// Who has the open chat on screen, by card ID, until when.
    public_present: HashMap<String, (Card, i64)>,
    /// The open chat is on screen here; when that last went out.
    public_here: Option<i64>,
    replied: HashMap<String, i64>,
    stopped: bool,
    last_error: Option<String>,
    push_error: Option<String>,
    push_last: Value,
    effects: Vec<Effect>,
}

impl<H: Host> Machine<H> {
    /// `client` is merged into every snapshot, for example the client's
    /// version. `push` says whether the client can send push requests.
    pub fn new(mut host: H, push: bool, client: Map<String, Value>) -> Result<Self> {
        let engine = persistence::restore(host.state(), &host.keys().signing)?;
        host.renamed()?;
        let keys = host.keys();
        if keys.noise.noise_public().as_slice() != engine.inbox.own.noise_key
            || hex::encode(keys.nostr.nostr_public()?) != engine.inbox.own.nostr_key
        {
            return Err(text("Ключи профиля не совпадают с карточкой"));
        }
        Ok(Self {
            host,
            engine,
            client,
            nearby: HashMap::new(),
            nearby_changes: 0,
            bluetooth: json!({"enabled":null,"scan":"starting","advertise":"starting"}),
            relays: Vec::new(),
            push,
            encounter_retention: crate::directory::DEFAULT_RETENTION_MS,
            inflight: HashSet::new(),
            photo_parts: HashMap::new(),
            photo_buffers: HashMap::new(),
            early_parts: Vec::new(),
            pushed: HashSet::new(),
            lookups: HashMap::new(),
            public_rate: HashMap::new(),
            copy_retry: HashMap::new(),
            public_typing: HashMap::new(),
            public_typing_sent: None,
            public_present: HashMap::new(),
            public_here: None,
            replied: HashMap::new(),
            stopped: false,
            last_error: None,
            push_error: None,
            push_last: Value::Null,
            effects: Vec::new(),
        })
    }

    /// What to do now. Every input below adds to it.
    pub fn effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// The person asked to stop the session.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// The Nostr inbox the relays deliver to.
    pub fn inbox(&self) -> &str {
        &self.engine.inbox.own.nostr_key
    }

    /// Relays with a working subscription, for routes and snapshots.
    pub fn set_relays(&mut self, connected: Vec<String>) {
        self.relays = connected;
    }

    /// How long encounters nearby stay listed, in milliseconds; each client
    /// chooses, 24 hours unless it says otherwise.
    pub fn set_encounter_retention(&mut self, milliseconds: i64) {
        if milliseconds > 0 {
            self.encounter_retention = milliseconds;
        }
    }

    /// Bluetooth is off or used by another profile: nobody is nearby.
    pub fn clear_nearby(&mut self) {
        if !self.nearby.is_empty() {
            self.nearby_changes += 1;
        }
        self.nearby.clear();
    }

    fn routes(&self) -> Routes {
        Routes {
            internet: !self.relays.is_empty(),
            peers: self
                .nearby
                .values()
                .filter(|p| !self.engine.inbox.blocked.contains(&p.peer.card.id()))
                .map(|p| p.peer.clone())
                .collect(),
        }
    }

    fn apply(
        &mut self,
        operation: impl FnOnce(&mut Engine, &Context<'_>) -> shum_core::Result<Vec<Action>>,
    ) -> Result<()> {
        self.apply_with_clear(operation, None)
    }

    fn apply_with_clear(
        &mut self,
        operation: impl FnOnce(&mut Engine, &Context<'_>) -> shum_core::Result<Vec<Action>>,
        clear: Option<&str>,
    ) -> Result<()> {
        self.apply_as(uuid()?, clear, operation)
    }

    /// Applies `operation` with `id` as the UUID of what it creates.
    fn apply_as(
        &mut self,
        id: String,
        clear: Option<&str>,
        operation: impl FnOnce(&mut Engine, &Context<'_>) -> shum_core::Result<Vec<Action>>,
    ) -> Result<()> {
        let routes = self.routes();
        let time = now();
        let keys = self.host.keys();
        let context = Context {
            now: time,
            keys: Keys {
                noise: &keys.noise,
                signing: &keys.signing,
                nostr: &keys.nostr,
            },
            routes: &routes,
            uuid: &id,
        };
        let transition = self.engine.prepare(|engine| operation(engine, &context))?;
        // Invitation history and engine state become durable in one encrypted commit,
        // before any network action can be dispatched.
        let mut next = persistence::project(self.host.state(), &transition.state, time)?;
        next["cliInvitationEvents"] =
            crate::timeline::project(self.host.state(), &self.engine, &transition.state, clear);
        self.host.commit(next)?;
        self.engine = transition.state;
        self.dispatch(transition.actions)
    }

    /// The sealed parts of the photo of message `id`, if this device sends
    /// it and has the JPEG.
    fn photo_parts(&mut self, id: &str) -> Option<Vec<PhotoPart>> {
        if let Some(parts) = self.photo_parts.get(id) {
            return Some(parts.clone());
        }
        let photo = self
            .engine
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == id)?
            .plaintext
            .as_ref()?
            .photo
            .clone()?;
        let jpeg = self.host.photo(id).ok()??;
        let key = Secret32::new(photo.key.as_slice().try_into().ok()?);
        let (sealed, parts) =
            Photo::seal(id, &jpeg, photo.width, photo.height, photo.caption, &key).ok()?;
        if sealed != photo {
            return None;
        }
        if self.photo_parts.len() >= 16 {
            self.photo_parts.clear();
        }
        self.photo_parts.insert(id.into(), parts.clone());
        Some(parts)
    }

    /// A message with a photo is followed by its parts on the same way:
    /// over Nostr to its recipient or the profile's own key, and over
    /// Bluetooth only to the recipient itself, never to couriers.
    fn with_photo_parts(&mut self, actions: Vec<Action>) -> Vec<Action> {
        let mut out = Vec::with_capacity(actions.len());
        for action in actions {
            let parts = match &action {
                Action::SendNostr {
                    recipient, packet, ..
                } => packet
                    .envelope
                    .as_ref()
                    .or(packet.own_copy.as_ref().map(|c| &c.envelope))
                    .map(|e| (e.id.clone(), Some(recipient.clone()), None)),
                Action::SendBle { peer, packet } => packet
                    .envelope
                    .as_ref()
                    .filter(|e| {
                        self.nearby.values().any(|p| {
                            p.direct
                                && p.peer.routing == *peer
                                && p.peer.card.id() == e.recipient.id()
                        })
                    })
                    .map(|e| (e.id.clone(), None, Some(peer.clone()))),
                _ => None,
            };
            out.push(action);
            let Some((message, recipient, peer)) = parts else {
                continue;
            };
            let Some(parts) = self.photo_parts(&message) else {
                continue;
            };
            for part in parts {
                let index = part.index;
                let packet = Box::new(Packet {
                    photo_part: Some(part),
                    ..Packet::default()
                });
                if let Some(recipient) = &recipient {
                    out.push(Action::SendNostr {
                        operation: format!("photo-part:{}:{message}:{index}", recipient.id()),
                        recipient: recipient.clone(),
                        packet,
                    });
                } else if let Some(peer) = &peer {
                    out.push(Action::SendBle {
                        peer: peer.clone(),
                        packet,
                    });
                }
            }
        }
        out
    }

    /// The photo a part belongs to, if it is still missing here: of a
    /// received message, or of one copied from another of this profile's
    /// devices.
    fn missing_photo(&self, id: &str) -> Option<Photo> {
        if let Some(m) = self
            .engine
            .inbox
            .messages
            .iter()
            .find(|m| m.envelope.id == id)
        {
            return m.photo_missing.then(|| m.plaintext.photo.clone()).flatten();
        }
        self.engine
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == id && m.photo_missing)?
            .plaintext
            .as_ref()?
            .photo
            .clone()
    }

    /// Opens a part with the key its message carries and stores the photo
    /// once every part is in and the hash matches (protocol section 04.9).
    fn take_photo_part(&mut self, part: PhotoPart) -> Result<()> {
        if part.validate().is_err() {
            return Ok(());
        }
        let time = now();
        let id = part.message_id.clone();
        let Some(photo) = self.missing_photo(&id) else {
            // Its message may still be on the way.
            let known = self
                .engine
                .inbox
                .messages
                .iter()
                .any(|m| m.envelope.id == id)
                || self
                    .engine
                    .outbox
                    .messages
                    .iter()
                    .any(|m| m.envelope.id == id);
            if !known {
                self.early_parts.retain(|(at, _)| time - at < EARLY_PART_MS);
                if self.early_parts.len() < EARLY_PARTS {
                    self.early_parts.push((time, part));
                }
            }
            return Ok(());
        };
        let Ok(bytes) = photo.open(&id, &part) else {
            return Ok(());
        };
        if !self.photo_buffers.contains_key(&id) && self.photo_buffers.len() >= PHOTO_BUFFERS {
            if let Some(oldest) = self
                .photo_buffers
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(id, _)| id.clone())
            {
                self.photo_buffers.remove(&oldest);
            }
        }
        let (_, parts) = self
            .photo_buffers
            .entry(id.clone())
            .or_insert_with(|| (time, HashMap::new()));
        parts.insert(part.index as usize, bytes);
        if parts.len() < photo.count() {
            return Ok(());
        }
        let (_, parts) = self.photo_buffers.remove(&id).expect("buffered");
        let ordered: Option<Vec<_>> = (0..photo.count()).map(|i| parts.get(&i).cloned()).collect();
        // A wrong hash drops every part; they come again.
        let Some(jpeg) = ordered.and_then(|p| photo.join(&p).ok()) else {
            return Ok(());
        };
        self.host.put_photo(&id, &jpeg)?;
        self.apply(|e, c| e.photo_arrived(&id, c))?;
        Ok(())
    }

    /// Parts that came before their message, now that a message came.
    fn retry_early_parts(&mut self) -> Result<()> {
        let time = now();
        let early: Vec<_> = std::mem::take(&mut self.early_parts)
            .into_iter()
            .filter(|(at, _)| time - at < EARLY_PART_MS)
            .collect();
        for (at, part) in early {
            let id = &part.message_id;
            let known = self
                .engine
                .inbox
                .messages
                .iter()
                .any(|m| m.envelope.id == *id)
                || self
                    .engine
                    .outbox
                    .messages
                    .iter()
                    .any(|m| m.envelope.id == *id);
            if known {
                self.take_photo_part(part)?;
            } else {
                self.early_parts.push((at, part));
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, actions: Vec<Action>) -> Result<()> {
        let actions = self.with_photo_parts(actions);
        for action in actions {
            match action {
                Action::SendNostr {
                    operation,
                    recipient,
                    packet,
                } => {
                    if self.inflight.contains(&operation) {
                        continue;
                    }
                    let content = format!(
                        "shum-v1:{}",
                        STANDARD.encode(canonical::encode(packet.as_ref())?)
                    );
                    let event = wrap(&self.host.keys().nostr, &recipient.nostr_key, content)?;
                    self.inflight.insert(operation.clone());
                    self.effects.push(Effect::Publish {
                        operation: Some(operation),
                        event,
                    });
                }
                Action::Push {
                    recipient,
                    event,
                    kind,
                } => {
                    if self.pushed.len() >= 1000 {
                        self.pushed.clear();
                    }
                    if self.push && self.pushed.insert(event.clone()) {
                        self.push_last =
                            json!({"eventId":event,"state":"sending","updatedAt":now()});
                        self.effects.push(Effect::Push {
                            card: Box::new(self.engine.inbox.own.clone()),
                            key: Secret32::new(*self.host.keys().signing.expose()),
                            recipient,
                            event,
                            kind,
                        });
                    }
                }
                Action::SendBle { peer, packet } => {
                    self.effects.push(Effect::SendBle { peer, packet });
                }
            }
        }
        Ok(())
    }

    fn resolve_contact(&self, selector: &str) -> Result<Option<String>> {
        let cards: HashMap<_, _> = self
            .engine
            .inbox
            .contacts
            .iter()
            .chain(self.engine.inbox.requests.iter())
            .map(|(id, card)| (id.clone(), card))
            .chain(
                self.nearby
                    .values()
                    .map(|p| (p.peer.card.id(), &p.peer.card)),
            )
            .collect();
        Ok(crate::contact::resolve(
            selector,
            cards
                .iter()
                .map(|(id, card)| (id.as_str(), card.nostr_key.as_str())),
        )?)
    }

    fn contact(&self, selector: &str) -> Result<String> {
        self.resolve_contact(selector)?.ok_or_else(|| {
            text("Контакт не найден. Добавьте карточку или пригласите по полному сетевому ID.")
        })
    }

    fn invite_contact(&mut self, selector: &str, action: InvitationAction) -> Result<Value> {
        let id = self.contact(selector)?;
        use shum_core::rules::Phase;
        let phase = self.engine.inbox.phase(&id);
        let allowed = match action {
            InvitationAction::Request => phase == Phase::Ready,
            InvitationAction::Accept => {
                matches!(phase, Phase::IncomingPending | Phase::DeclinedLocally)
            }
            InvitationAction::Decline => phase == Phase::IncomingPending,
        };
        if !allowed {
            return Err(self::phase(phase));
        }
        let nearby = self
            .nearby
            .values()
            .find(|p| p.peer.card.id() == id)
            .map(|p| p.peer.card.clone());
        self.apply(|e, c| {
            if !e.inbox.contacts.contains_key(&id) && !e.inbox.requests.contains_key(&id) {
                if let Some(card) = nearby {
                    e.add_contact(card)?;
                }
            }
            e.invitation(&id, action, None, c)
        })?;
        Ok(json!({"status":"ok", "contactID":id}))
    }

    pub fn snapshot(&self) -> Value {
        let own = &self.engine.inbox.own;
        let mut cards: HashMap<_, _> = self
            .engine
            .inbox
            .contacts
            .iter()
            .chain(self.engine.inbox.requests.iter())
            .map(|(id, card)| (id.clone(), card))
            .chain(
                self.nearby
                    .values()
                    .map(|p| (p.peer.card.id(), &p.peer.card)),
            )
            .collect();
        cards.retain(|id, _| !self.engine.inbox.blocked.contains(id));
        let mut contacts:Vec<_>=cards.into_iter().map(|(id,card)|json!({"id":id,"card":card,"phase":self.engine.inbox.phase(&id),"unread":self.engine.inbox.messages.iter().filter(|m|m.envelope.sender.id()==*id&&m.unread).count(),"nearby":self.nearby.values().any(|p|p.direct && p.peer.card.id()==id),"mesh":self.nearby.values().any(|p|p.peer.card.id()==id),"distance":self.nearby.values().find(|p|p.direct && p.peer.card.id()==id).and_then(|p|p.distance),"typing":self.engine.inbox.typing.get(&id).is_some_and(|s|s.active(now())),"addressBook":crate::directory::in_address_book(self.host.state(),&id),"invitationWaiting":self.engine.waiting_invitation(&id).is_some(),"invitationCancellable":self.engine.waiting_invitation(&id).is_some_and(|c|c.retry.nostr_attempts==0),"online":self.engine.inbox.presence.get(&id).is_some_and(|s|s.active(now()))})).collect();
        contacts.sort_by(by_name);
        let mut messages = vec![];
        for m in &self.engine.inbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.sender.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.text,"outgoing":false,"status":if m.read{"read"}else{"delivered"},"reply":m.plaintext.reply,"photo":m.plaintext.photo.as_ref().map(|p|photo_view(p,m.photo_missing,m.envelope.expires_at))}));
        }
        for m in &self.engine.outbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.recipient.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.as_ref().map(|p|p.text.as_str()).unwrap_or(""),"outgoing":true,"status":m.delivery.status,"nostrAccepted":m.delivery.nostr_accepted,"pushScheduled":m.push_sent,"reply":m.plaintext.as_ref().and_then(|p|p.reply.clone()),"photo":m.plaintext.as_ref().and_then(|p|p.photo.as_ref()).map(|p|photo_view(p,m.photo_missing,m.envelope.expires_at))}));
        }
        messages.sort_by_key(|m| {
            (
                m["timestamp"].as_i64().unwrap_or(0),
                m["id"].as_str().unwrap_or("").to_owned(),
            )
        });
        if messages.len() > 2000 {
            messages.drain(..messages.len() - 2000);
        }
        let reactions:Vec<_>=self.engine.inbox.reactions.iter().map(|((message,person),mark)|json!({"messageID":message,"personID":person,"mark":mark})).collect();
        let mut blocked: Vec<_> = self
            .engine
            .inbox
            .blocked_cards
            .iter()
            .map(|(id, card)| json!({ "id": id, "card": card }))
            .collect();
        blocked.sort_by(by_name);
        let mut snapshot = json!({"profile":self.host.profile(),"card":own,"contacts":contacts,"blocked":blocked,"messages":messages,"events":crate::timeline::stored(self.host.state(), &self.engine),"reactions":reactions,"encounters":crate::directory::encounters(self.host.state(),&self.engine.inbox.blocked,now(),self.encounter_retention),"pins":crate::directory::pins(self.host.state()),"publicChat":crate::public::notes(self.host.state(),now()),"publicPresent":shown(&self.public_present),"publicTyping":shown(&self.public_typing),"relays":self.relays,"bluetooth":self.bluetooth,"pushConfigured":self.push,"pushError":self.push_error,"pushLast":self.push_last,"error":self.last_error,"clientCommandVersion":crate::COMMAND_SCHEMA_VERSION});
        if let Some(object) = snapshot.as_object_mut() {
            object.extend(self.client.clone());
        }
        snapshot
    }

    /// Handles a request. Most answer at once; adding or inviting someone by
    /// network ID waits for their profile and answers later with an
    /// [`Effect::Reply`] carrying `id`, which is when this returns `None`.
    pub fn request(
        &mut self,
        id: u64,
        request: Request,
    ) -> Option<std::result::Result<Value, Failure>> {
        if let Request::Add { link } = &request {
            if let Ok(Invitation::Locator(key)) = invitation::parse(link) {
                return self.start_lookup(key, id, Then::Add);
            }
        }
        if let Request::Invite { contact } = &request {
            if matches!(self.resolve_contact(contact), Ok(None))
                && crate::contact::network_id(contact)
            {
                return self.start_lookup(contact.clone(), id, Then::Invite);
            }
        }
        if let Request::Find { contact } = &request {
            let key = match invitation::parse(contact) {
                Ok(Invitation::Card(card)) if card.id() == self.engine.inbox.own.id() => {
                    return Some(Err(Failure::text("Это ваш профиль")));
                }
                Ok(Invitation::Card(card)) => {
                    let id = card.id();
                    return Some(Ok(json!({"card":card, "link":contact, "contactID":id})));
                }
                Ok(Invitation::Locator(key)) => key,
                Err(_) if crate::contact::network_id(contact) => contact.clone(),
                Err(_) => {
                    return Some(Err(Failure::text(
                        "Нужна ссылка Shum или сетевой ID из 64 символов",
                    )))
                }
            };
            return self.start_lookup(key, id, Then::Show);
        }
        let result = match &request {
            Request::Invite { contact } => self.invite_contact(contact, InvitationAction::Request),
            Request::Accept { contact } => self.invite_contact(contact, InvitationAction::Accept),
            Request::Decline { contact } => self.invite_contact(contact, InvitationAction::Decline),
            _ => self.command(request),
        };
        Some(result.map_err(Failure::from_error))
    }

    fn command(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Snapshot => return Ok(self.snapshot()),
            Request::Backup {
                password,
                created_at,
            } => {
                let password = zeroize::Zeroizing::new(password);
                let file = self.host.backup(&password, &created_at)?;
                return Ok(json!({ "file": STANDARD.encode(file) }));
            }
            Request::Add { link } => match invitation::parse(&link)? {
                Invitation::Card(card) => {
                    let id = card.id();
                    if id == self.engine.inbox.own.id() {
                        return Err(text("Это ваш профиль"));
                    }
                    self.apply(|e, _| {
                        e.add_contact(*card)?;
                        Ok(vec![])
                    })?;
                    return Ok(json!({"contactID":id}));
                }
                Invitation::Locator(_) => bail!("Lookup requires asynchronous request"),
            },
            Request::Invite { .. }
            | Request::Accept { .. }
            | Request::Decline { .. }
            | Request::Find { .. } => {
                bail!("internal invitation dispatch")
            }
            Request::CancelInvitation { contact } => {
                let id = self.contact(&contact)?;
                if !self
                    .engine
                    .waiting_invitation(&id)
                    .is_some_and(|c| c.retry.nostr_attempts == 0)
                {
                    return Err(text("Приглашение уже отправлено"));
                }
                self.apply(|e, _| {
                    e.cancel_invitation(&id)?;
                    Ok(vec![])
                })?;
            }
            Request::Send {
                contact,
                text,
                reply,
            } => {
                let id = self.contact(&contact)?;
                if self.engine.inbox.phase(&id) != shum_core::rules::Phase::Accepted {
                    return Err(phase(self.engine.inbox.phase(&id)));
                }
                let ephemeral = secret()?;
                self.apply(|e, c| e.send(&id, &text, reply, &ephemeral, c))?;
            }
            Request::Photo { message } => {
                let jpeg = self
                    .host
                    .photo(&message)?
                    .ok_or_else(|| crate::text("Фото ещё не пришло"))?;
                return Ok(json!({ "photo": STANDARD.encode(jpeg) }));
            }
            Request::SendPhoto {
                contact,
                photo,
                width,
                height,
                text,
                caption,
            } => {
                let id = self.contact(&contact)?;
                if self.engine.inbox.phase(&id) != shum_core::rules::Phase::Accepted {
                    return Err(phase(self.engine.inbox.phase(&id)));
                }
                let jpeg = STANDARD
                    .decode(photo)
                    .map_err(|_| crate::text("Фото не прочитать"))?;
                if jpeg.len() > shum_core::photo::MAX_SIZE {
                    return Err(crate::text("Фото слишком большое"));
                }
                let (key, ephemeral) = (secret()?, secret()?);
                let message = uuid()?;
                // The JPEG is stored before the message exists, so its parts
                // can always follow it.
                self.host.put_photo(&message, &jpeg)?;
                if let Err(error) = self.apply_as(message.clone(), None, |e, c| {
                    e.send_photo(
                        &id,
                        &jpeg,
                        (width, height),
                        &text,
                        caption,
                        &key,
                        &ephemeral,
                        c,
                    )
                }) {
                    let _ = self.host.delete_photo(&message);
                    return Err(error);
                }
                return Ok(json!({ "id": message }));
            }
            Request::Broadcast { text: note, reply } => {
                if shum_core::card::trim(&note).is_empty()
                    || note.len() > shum_core::public::MAX_TEXT
                {
                    return Err(text("Сообщение пустое или слишком длинное"));
                }
                // A quote carries only the start of what it answers.
                let reply = reply.map(|mut r| {
                    r.text = r.text.chars().take(200).collect();
                    r
                });
                let id = self.public_event(PublicBody::Note { text: note, reply })?;
                return Ok(json!({ "id": id }));
            }
            Request::PublicReaction {
                note,
                author,
                reaction,
            } => {
                if !crate::public::contains(self.host.state(), &author, &note) {
                    return Err(text("Сообщение уже недоступно"));
                }
                self.public_event(PublicBody::Reaction {
                    note_id: note,
                    author_id: author,
                    reaction,
                })?;
            }
            Request::PublicTyping { active } => {
                let time = now();
                // As in a chat: on a start or a stop, and again every few
                // seconds while typing goes on.
                let repeat = self.public_typing_sent.is_some_and(|(was, at)| {
                    was == active && (!active || time - at < PUBLIC_TYPING_REPEAT_MS)
                });
                if self.public_typing_sent.is_none() && !active || repeat {
                    return Ok(json!({}));
                }
                self.public_typing_sent = Some((active, time));
                self.effects.push(Effect::Broadcast {
                    id: uuid()?,
                    body: PublicBody::Typing { active },
                });
            }
            Request::PublicPresence { online } => {
                if online != self.public_here.is_some() {
                    self.public_here = online.then(now);
                    self.effects.push(Effect::Broadcast {
                        id: uuid()?,
                        body: PublicBody::Presence { online },
                    });
                }
            }
            Request::PublicRetract { note } => {
                let own = self.engine.inbox.own.id();
                if !crate::public::contains(self.host.state(), &own, &note) {
                    return Err(text("Сообщение уже недоступно"));
                }
                self.public_event(PublicBody::Retract { note_id: note })?;
            }
            Request::Read { contact } => {
                let id = self.contact(&contact)?;
                self.apply(|e, c| e.mark_read(&id, c))?;
            }
            Request::Focus { contact } => {
                let id = contact.as_deref().map(|s| self.contact(s)).transpose()?;
                self.apply(|e, c| {
                    let previous = e.inbox.foreground_contact.clone();
                    let mut actions = Vec::new();
                    if previous != id {
                        if let Some(previous) = previous {
                            actions.extend(e.set_typing(&previous, false, c).unwrap_or_default());
                            actions.extend(e.presence(&previous, false, c).unwrap_or_default());
                        }
                        e.inbox.foreground_contact = id.clone();
                    }
                    if let Some(id) = id {
                        actions.extend(e.mark_read(&id, c)?);
                    }
                    Ok(actions)
                })?;
            }
            Request::Typing { contact, active } => {
                let id = self.contact(&contact)?;
                self.apply(|e, c| e.set_typing(&id, active, c))?;
            }
            Request::Presence { contact, online } => {
                let id = self.contact(&contact)?;
                self.apply(|e, c| e.presence(&id, online, c))?;
            }
            Request::Reaction { message, reaction } => {
                self.apply(|e, c| e.toggle_reaction(&message, reaction, c))?
            }
            Request::Cancel { message } => self.apply(|e, c| e.cancel_sending(&message, c))?,
            Request::Resend { message } => {
                let ephemeral = secret()?;
                self.apply(|e, c| e.resend(&message, &ephemeral, c))?;
            }
            Request::Clear { contact } => {
                let id = self.contact(&contact)?;
                self.apply_with_clear(
                    |e, c| {
                        e.clear_chat(&id, c.now);
                        Ok(vec![])
                    },
                    Some(&id),
                )?;
            }
            Request::Block { contact, blocked } => {
                let id = self.contact(&contact)?;
                self.apply(|e, c| {
                    e.block(&id, blocked, c.now)?;
                    Ok(vec![])
                })?;
            }
            Request::Profile { name, bio, seed } => {
                let own = &self.engine.inbox.own;
                let name = name.unwrap_or_else(|| own.name.clone());
                self.host.check_name(&name)?;
                let bio = bio.unwrap_or_else(|| own.bio.clone());
                let seed = seed.or(own.avatar_seed);
                self.apply(|e, c| {
                    e.update_profile(name, bio, seed, c)?;
                    Ok(e.tick(c.routes, c.now))
                })?;
                self.host.renamed()?;
            }
            Request::ViewEncounters { contact } => {
                let id = contact.map(|c| self.person(&c)).transpose()?;
                self.edit(|state| {
                    crate::directory::view_encounters(state, id.as_deref());
                    true
                })?;
            }
            Request::DeleteEncounters { contact } => {
                let id = contact.map(|c| self.person(&c)).transpose()?;
                self.edit(|state| {
                    crate::directory::delete_encounters(state, id.as_deref());
                    true
                })?;
            }
            Request::Pin { contact, directory } => {
                let id = self.person(&contact)?;
                if directory.is_empty() || directory.len() > 32 || id == self.engine.inbox.own.id()
                {
                    return Err(text("Нельзя закрепить"));
                }
                let mut pinned = false;
                self.edit(|state| {
                    pinned = crate::directory::toggle_pin(state, &directory, &id);
                    true
                })?;
                return Ok(json!({ "pinned": pinned }));
            }
            Request::RemoveContact { contact } => {
                let id = self.contact(&contact)?;
                self.edit(|state| crate::directory::remove_from_contacts(state, &id))?;
            }
            Request::Stop => self.stopped = true,
        }
        Ok(json!({"status":"ok"}))
    }

    /// A person by contact selector, or by the exact Shum ID of someone met
    /// nearby who is not a contact.
    fn person(&self, selector: &str) -> Result<String> {
        if let Some(id) = self.resolve_contact(selector)? {
            return Ok(id);
        }
        let met = self.host.state()["encounters"]
            .as_array()
            .is_some_and(|rows| {
                rows.iter().any(|r| {
                    serde_json::from_value::<Card>(r["card"].clone())
                        .is_ok_and(|c| c.id() == selector)
                })
            });
        if met {
            Ok(selector.into())
        } else {
            Err(text("Контакт не найден"))
        }
    }

    /// Changes profile state that the engine does not model, in one commit.
    /// Applies an own event to the open chat and sends it to the mesh.
    fn public_event(&mut self, body: PublicBody) -> Result<String> {
        let id = uuid()?;
        let own = self.engine.inbox.own.clone();
        let time = now();
        self.edit(|state| crate::public::apply(state, &own, &id, &body, time, true, time))?;
        let event = shum_core::public::PublicEvent::new(id.clone(), body.clone(), own)?;
        self.copy_public(&event, time)?;
        self.effects.push(Effect::Broadcast {
            id: id.clone(),
            body,
        });
        Ok(id)
    }

    /// Queues an open-chat event for this profile's other devices, which
    /// read it from the relays even when they are not nearby.
    fn copy_public(
        &mut self,
        event: &shum_core::public::PublicEvent,
        timestamp: i64,
    ) -> Result<()> {
        let body = shum_core::canonical::encode(&json!({"event": event, "timestamp": timestamp}))?;
        let content = format!("{}{}", crate::public::COPY_PREFIX, STANDARD.encode(body));
        let operation = format!("{}{}", crate::public::COPY_OPERATION, uuid()?);
        self.edit(|state| crate::public::queue_copy(state, &operation, content))?;
        self.send_public_copies();
        Ok(())
    }

    /// Sends the waiting copies once there are relays to take them. A
    /// refused copy waits longer each time, so copies never crowd out the
    /// messages, typing and "in chat" that share the relays.
    fn send_public_copies(&mut self) {
        if self.relays.is_empty() {
            return;
        }
        let own = self.engine.inbox.own.nostr_key.clone();
        let time = now();
        let mut sent = 0;
        let copies = crate::public::copies(self.host.state());
        self.copy_retry
            .retain(|operation, _| copies.iter().any(|(o, _)| o == operation));
        for (operation, content) in copies {
            if sent >= COPIES_PER_TICK {
                break;
            }
            if self.inflight.contains(&operation)
                || self
                    .copy_retry
                    .get(&operation)
                    .is_some_and(|(_, next)| *next > time)
            {
                continue;
            }
            sent += 1;
            match wrap(&self.host.keys().nostr, &own, content) {
                Ok(event) => {
                    self.inflight.insert(operation.clone());
                    self.effects.push(Effect::Publish {
                        operation: Some(operation),
                        event,
                    });
                }
                Err(error) => self.last_error = Some(error.to_string()),
            }
        }
    }

    fn edit(&mut self, change: impl FnOnce(&mut Value) -> bool) -> Result<()> {
        let mut state = self.host.state().clone();
        if change(&mut state) {
            self.host.commit(state)?;
        }
        Ok(())
    }

    fn start_lookup(
        &mut self,
        key: String,
        reply: u64,
        then: Then,
    ) -> Option<std::result::Result<Value, Failure>> {
        if self.lookups.len() >= 8 {
            return Some(Err(Failure::text("Слишком много поисков")));
        }
        if key == self.engine.inbox.own.nostr_key {
            return Some(Err(Failure::text("Это ваш профиль")));
        }
        let prepared = (|| -> Result<(String, nostr::Event)> {
            let id = uuid()?;
            let content = format!(
                "shum-contact-request-v1:{}",
                STANDARD.encode(canonical::encode(&json!({"id":id}))?)
            );
            Ok((id, wrap(&self.host.keys().nostr, &key, content)?))
        })();
        match prepared {
            Ok((id, event)) => {
                self.effects.push(Effect::Publish {
                    operation: None,
                    event,
                });
                self.lookups.insert(
                    id,
                    Lookup {
                        key,
                        then,
                        expires: now() + 20_000,
                        reply,
                    },
                );
                None
            }
            Err(error) => Some(Err(Failure::from_error(error))),
        }
    }

    /// A gift wrap for this inbox arrived from a relay.
    pub fn incoming(&mut self, event: nostr::Event) {
        if let Err(error) = self.receive(event) {
            self.last_error = Some(error.to_string());
        }
    }

    fn receive(&mut self, event: nostr::Event) -> Result<()> {
        if self.host.state()["cliNostrHandled"][&event.id]
            .as_i64()
            .is_some_and(|time| time > now() / 1000 - 4 * 86400)
        {
            return Ok(());
        }
        let opened = nostr::open_private(&event, &self.host.keys().nostr);
        if let Ok(message) = opened {
            if let Some(encoded) = message
                .content
                .strip_prefix("shum-v1:")
                .or_else(|| message.content.strip_prefix("spotchat-v1:"))
            {
                if encoded.len() <= 33000 {
                    if let Ok(bytes) = STANDARD.decode(encoded) {
                        if let Ok(mut packet) = Packet::decode(&bytes) {
                            if let Some(part) = packet.photo_part.take() {
                                self.take_photo_part(part)?;
                            } else {
                                let carries =
                                    packet.envelope.is_some() || packet.own_copy.is_some();
                                self.apply(|e, c| {
                                    e.receive(packet, Source::Nostr(&message.sender), c)
                                })?;
                                if carries {
                                    self.retry_early_parts()?;
                                }
                            }
                        }
                    }
                }
            } else if let Some(encoded) = message.content.strip_prefix(crate::public::COPY_PREFIX) {
                // Only this profile's own devices write copies; they are not copied on.
                if message.sender == self.engine.inbox.own.nostr_key && encoded.len() <= 12000 {
                    if let Some(value) = STANDARD
                        .decode(encoded)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    {
                        let event = shum_core::canonical::encode(&value["event"])
                            .ok()
                            .and_then(|bytes| shum_core::public::PublicEvent::decode(&bytes).ok());
                        if let (Some(event), Some(timestamp)) = (event, value["timestamp"].as_i64())
                        {
                            let own = event.card.id() == self.engine.inbox.own.id();
                            let time = now();
                            self.edit(|state| {
                                crate::public::apply(
                                    state,
                                    &event.card,
                                    &event.id,
                                    &event.body,
                                    timestamp.min(time),
                                    own,
                                    time,
                                )
                            })?;
                        }
                    }
                }
            } else if let Some(encoded) = message.content.strip_prefix("shum-contact-request-v1:") {
                if encoded.len() <= 344 {
                    if let Ok(bytes) = STANDARD.decode(encoded) {
                        if bytes.len() <= 256 {
                            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                                if let Some(id) = value["id"]
                                    .as_str()
                                    .filter(|id| shum_core::packet::uuid(id))
                                {
                                    self.answer_lookup(&message.sender, id)?;
                                }
                            }
                        }
                    }
                }
            } else if let Some(encoded) = message.content.strip_prefix("shum-contact-manifest-v1:")
            {
                if encoded.len() <= 5464 {
                    if let Ok(bytes) = STANDARD.decode(encoded) {
                        if bytes.len() <= 4096 {
                            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                                self.found(&message.sender, &value);
                            }
                        }
                    }
                }
            }
        }
        let time = now() / 1000;
        let mut state = self.host.state().clone();
        if !state["cliNostrHandled"].is_object() {
            state["cliNostrHandled"] = json!({});
        }
        let seen = state["cliNostrHandled"].as_object_mut().expect("object");
        seen.retain(|_, v| v.as_i64().is_some_and(|t| t > time - 4 * 86400));
        if seen.len() >= 31000 {
            let mut entries: Vec<_> = seen
                .iter()
                .map(|(id, t)| (id.clone(), t.as_i64().unwrap_or(0)))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            for (id, _) in entries.into_iter().take(seen.len() - 29999) {
                seen.remove(&id);
            }
        }
        seen.insert(event.id, json!(time));
        self.host.commit(state)
    }

    /// Someone looks this profile up by its network ID: send the card back,
    /// at most once in three seconds per asker.
    fn answer_lookup(&mut self, sender: &str, id: &str) -> Result<()> {
        if self
            .replied
            .get(sender)
            .is_some_and(|last| now() - *last < 3000)
        {
            return Ok(());
        }
        if self.replied.len() >= 1000 {
            self.replied.retain(|_, last| now() - *last < 300000);
        }
        if self.replied.len() >= 1000 {
            return Ok(());
        }
        self.replied.insert(sender.into(), now());
        let card = &self.engine.inbox.own;
        let manifest = Manifest {
            name: card.name.clone(),
            bio: card.bio.clone(),
            avatar_bytes: 0,
            avatar_hash: None,
            avatar_seed: card.avatar_seed,
            avatar_version: card.avatar_version,
        };
        let content = format!(
            "shum-contact-manifest-v1:{}",
            STANDARD.encode(canonical::encode(
                &json!({"id":id,"card":card,"profile":manifest})
            )?)
        );
        let event = wrap(&self.host.keys().nostr, sender, content)?;
        self.effects.push(Effect::Publish {
            operation: None,
            event,
        });
        Ok(())
    }

    /// A profile this one looked up answered with its card.
    fn found(&mut self, sender: &str, value: &Value) {
        let Some(id) = value["id"].as_str() else {
            return;
        };
        if !self
            .lookups
            .get(id)
            .is_some_and(|l| l.key == sender && l.expires > now())
        {
            return;
        }
        let validated = (|| -> Result<Card> {
            let card: Card = serde_json::from_value(value["card"].clone())?;
            let profile: Manifest = serde_json::from_value(value["profile"].clone())?;
            card.validate()?;
            if card.nostr_key != sender
                || !profile.valid()
                || profile.name != card.name
                || profile.bio != card.bio
                || profile.avatar_seed != card.avatar_seed
                || profile.avatar_bytes != 0
                || profile.avatar_hash.is_some()
            {
                return Err(text("Недействительный ответ профиля"));
            }
            Ok(card)
        })();
        let Ok(card) = validated else {
            return;
        };
        let Some(lookup) = self.lookups.remove(id) else {
            return;
        };
        let contact_id = card.id();
        if lookup.then == Then::Show {
            let result = card
                .invitation()
                .map(|link| json!({"card":card, "link":link, "contactID":contact_id}));
            self.effects.push(Effect::Reply {
                id: lookup.reply,
                result: result.map_err(|e| Failure::from_error(e.into())),
            });
            return;
        }
        let result = self.apply(|e, c| {
            e.add_contact(card)?;
            if lookup.then == Then::Invite {
                e.invitation(&contact_id, InvitationAction::Request, None, c)
            } else {
                Ok(vec![])
            }
        });
        self.effects.push(Effect::Reply {
            id: lookup.reply,
            result: result
                .map(|_| json!({"status":"ok", "contactID":contact_id}))
                .map_err(Failure::from_error),
        });
    }

    /// The relays answered a publication with an operation.
    pub fn published(&mut self, operation: &str, accepted: bool) {
        self.inflight.remove(operation);
        if operation.starts_with(crate::public::COPY_OPERATION) {
            if accepted {
                self.copy_retry.remove(operation);
                if let Err(error) = self.edit(|state| crate::public::copied(state, operation)) {
                    self.last_error = Some(error.to_string());
                }
            } else {
                let (attempts, next) = self.copy_retry.entry(operation.into()).or_insert((0, 0));
                *attempts = (*attempts + 1).min(8);
                *next = now() + (COPY_RETRY_MS << (*attempts - 1)).min(COPY_RETRY_MAX_MS);
            }
            return;
        }
        if let Err(error) = self.apply(|e, c| {
            e.outbox.relay_result(operation, accepted, c.now, false);
            Ok(vec![])
        }) {
            self.last_error = Some(error.to_string());
        }
    }

    /// The push service answered for `event`; `error` says why it failed.
    pub fn pushed(&mut self, event: &str, error: Option<String>) {
        // A slow earlier request must not replace the latest event's status.
        if self.push_last["eventId"].as_str() == Some(event) {
            self.push_last = json!({"eventId":event,"state":if error.is_some(){"failed"}else{"accepted"},"error":error,"updatedAt":now()});
            self.push_error = error;
        }
    }

    /// News from Bluetooth.
    pub fn nearby(&mut self, update: Nearby) -> Result<()> {
        match update {
            Nearby::State { role, state } => self.bluetooth[role] = json!(state),
            Nearby::Gone(id) => {
                if self.nearby.remove(&id).is_some() {
                    self.nearby_changes += 1;
                }
            }
            Nearby::Peer {
                routing,
                card,
                noise,
                distance,
                direct,
            } => {
                if !self.engine.inbox.blocked.contains(&card.id()) {
                    if card.id() != self.engine.inbox.own.id() {
                        let met = card.as_ref().clone();
                        let retention = self.encounter_retention;
                        self.edit(|state| {
                            crate::directory::record_encounter(state, &met, now(), retention)
                        })?;
                    }
                    let peer = Peer::authenticated(routing.clone(), *card, &noise)?;
                    let shown = |p: &NearbyPeer| (p.peer.card.id(), p.distance, p.direct);
                    if self.nearby.get(&routing).map(shown)
                        != Some((peer.card.id(), distance, direct))
                    {
                        self.nearby_changes += 1;
                    }
                    self.nearby.insert(
                        routing,
                        NearbyPeer {
                            peer,
                            noise,
                            distance,
                            direct,
                        },
                    );
                }
            }
            Nearby::Packet {
                routing,
                noise,
                packet,
            } => {
                if let Some(part) = packet.photo_part.clone() {
                    if self.nearby.get(&routing).is_some_and(|p| p.noise == noise) {
                        self.take_photo_part(part)?;
                    }
                } else if self.nearby.get(&routing).is_some_and(|p| p.noise == noise)
                    || packet.card.is_some()
                {
                    let carries = packet.envelope.is_some();
                    self.apply(|e, c| {
                        e.receive(
                            *packet,
                            Source::Ble {
                                peer: &routing,
                                session_noise: &noise,
                            },
                            c,
                        )
                    })?;
                    if carries {
                        self.retry_early_parts()?;
                    }
                }
            }
            // Blocked people stay visible: the open chat is not a private one.
            Nearby::Public { event, timestamp } => {
                let author = event.card.id();
                // Anything from someone in the open chat says they are there.
                if author != self.engine.inbox.own.id() {
                    if matches!(event.body, PublicBody::Presence { online: false }) {
                        self.public_present.remove(&author);
                    } else {
                        let until = now() + PUBLIC_PRESENCE_SHOWN_MS;
                        self.public_present
                            .insert(author.clone(), (event.card.clone(), until));
                        // Being there, they see what the chat already holds.
                        let time = now();
                        if crate::public::has_unseen(self.host.state(), &author, time) {
                            self.edit(|state| crate::public::seen_by(state, &author, time))?;
                        }
                    }
                }
                if matches!(event.body, PublicBody::Presence { .. }) {
                    return Ok(());
                }
                if let PublicBody::Typing { active } = event.body {
                    if author != self.engine.inbox.own.id() {
                        if active {
                            let until = now() + PUBLIC_TYPING_SHOWN_MS;
                            self.public_typing.insert(author, (event.card, until));
                        } else {
                            self.public_typing.remove(&author);
                        }
                    }
                    return Ok(());
                }
                if matches!(event.body, PublicBody::Note { .. }) {
                    self.public_typing.remove(&author);
                }
                if matches!(event.body, PublicBody::Note { .. })
                    && crate::public::contains(self.host.state(), &author, &event.id)
                {
                    return Ok(());
                }
                let time = now();
                if self.public_rate.len() > 1000 {
                    self.public_rate.clear();
                }
                let recent = self.public_rate.entry(author.clone()).or_default();
                recent.retain(|t| time - *t < 60_000);
                if recent.len() >= 20 {
                    return Ok(());
                }
                recent.push(time);
                // Another device of this profile wrote it.
                let own = author == self.engine.inbox.own.id();
                let at = timestamp.min(time);
                let mut changed = false;
                self.edit(|state| {
                    changed = crate::public::apply(
                        state,
                        &event.card,
                        &event.id,
                        &event.body,
                        at,
                        own,
                        time,
                    );
                    changed
                })?;
                if changed {
                    self.copy_public(&event, at)?;
                }
            }
        }
        Ok(())
    }

    /// Call about once a second: retries, expiry and waiting lookups.
    pub fn tick(&mut self) {
        if let Err(error) = self.apply(|e, c| Ok(e.tick(c.routes, c.now))) {
            self.last_error = Some(error.to_string());
        }
        self.send_public_copies();
        let time = now();
        self.public_typing.retain(|_, (_, until)| *until > time);
        self.public_present.retain(|_, (_, until)| *until > time);
        if self
            .public_here
            .is_some_and(|at| time - at >= PUBLIC_PRESENCE_REPEAT_MS)
        {
            self.public_here = Some(time);
            match uuid() {
                Ok(id) => self.effects.push(Effect::Broadcast {
                    id,
                    body: PublicBody::Presence { online: true },
                }),
                Err(error) => self.last_error = Some(error.to_string()),
            }
        }
        let expired: Vec<_> = self
            .lookups
            .iter()
            .filter(|(_, l)| l.expires <= now())
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(lookup) = self.lookups.remove(&id) {
                self.effects.push(Effect::Reply {
                    id: lookup.reply,
                    result: Err(Failure::text("Контакт не ответил за 20 секунд. Для добавления офлайн используйте полную карточку или QR.")),
                });
            }
        }
    }
}
