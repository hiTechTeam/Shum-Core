//! A running Shum profile for any client: the engine, encrypted storage,
//! Nostr relays, Bluetooth and push, driven by [`Request`] commands.
//!
//! Clients own presentation: they translate [`Failure`] texts, render
//! snapshots and decide how the process starts and stops. State keys with a
//! `cli` prefix keep their names so existing profiles open unchanged.

#![forbid(unsafe_code)]

pub mod contact;
pub mod service;
pub mod timeline;

use anyhow::{bail, Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shum_core::{
    canonical,
    card::Card,
    crypto::Secret32,
    engine::{Context, Engine, Keys},
    invitation::{self, Invitation},
    nostr::{self, WrapEntropy},
    packet::*,
    profile::Manifest,
    queue::{Action, Routes},
    rules::Source,
};
use shum_store::{engine as persistence, profiles::OpenProfile};
use shum_transport_nostr::{push::PushClient, RelayPool, RelayUpdate};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

/// Version of the [`Request`] API. Clients compare it with a running session.
pub const COMMAND_SCHEMA_VERSION: u64 = 3;

/// Why a request failed, in a form each client can present in its own words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Failure {
    /// Source text for the client's translation catalog, or a technical error.
    #[error("{text}")]
    Text { text: String },
    /// The invitation phase does not allow the action; clients say what to do next.
    #[error("invitation phase {phase}")]
    Phase { phase: String },
}
impl Failure {
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }
    /// Keeps a typed failure and turns any other error into its message.
    pub fn from_error(error: anyhow::Error) -> Self {
        match error.downcast::<Failure>() {
            Ok(failure) => failure,
            Err(error) => Self::text(error.to_string()),
        }
    }
}
fn text(text: &'static str) -> anyhow::Error {
    Failure::text(text).into()
}
fn phase(phase: shum_core::rules::Phase) -> anyhow::Error {
    let value = serde_json::to_value(phase).unwrap_or_default();
    Failure::Phase {
        phase: value.as_str().unwrap_or("").into(),
    }
    .into()
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| text("Системный генератор случайных чисел недоступен"))?;
    Ok(bytes)
}
pub fn uuid() -> Result<String> {
    let mut bytes = random::<16>()?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let h = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Snapshot,
    /// Seal the profile into a backup file (protocol section 13).
    Backup {
        password: String,
        created_at: String,
    },
    Add {
        link: String,
    },
    Invite {
        contact: String,
    },
    Accept {
        contact: String,
    },
    Decline {
        contact: String,
    },
    Send {
        contact: String,
        text: String,
    },
    Read {
        contact: String,
    },
    Focus {
        contact: Option<String>,
    },
    Typing {
        contact: String,
        active: bool,
    },
    Presence {
        contact: String,
        online: bool,
    },
    Reaction {
        message: String,
        reaction: ReactionKind,
    },
    Clear {
        contact: String,
    },
    Cancel {
        message: String,
    },
    Profile {
        name: Option<String>,
        bio: Option<String>,
        seed: Option<u64>,
    },
    Block {
        contact: String,
        blocked: bool,
    },
    Stop,
}
pub struct Command {
    pub request: Request,
    pub reply: Reply,
}
pub type Reply = oneshot::Sender<std::result::Result<Value, Failure>>;
struct Lookup {
    key: String,
    invite: bool,
    expires: i64,
    reply: Reply,
}
struct NearbyPeer {
    peer: shum_core::queue::Peer,
    noise: [u8; 32],
    distance: Option<u32>,
    direct: bool,
}
/// A running profile: engine, storage, relays, Bluetooth and push.
pub struct Session {
    client: serde_json::Map<String, Value>,
    ble: Option<shum_transport_ble::Ble>,
    ble_updates: mpsc::Receiver<shum_transport_ble::Update>,
    nearby: HashMap<String, NearbyPeer>,
    bluetooth: Value,
    pub profile: OpenProfile,
    pub engine: Engine,
    pool: RelayPool,
    updates: mpsc::Receiver<RelayUpdate>,
    jobs: JoinSet<Job>,
    push: Option<PushClient>,
    inflight: HashSet<String>,
    pushed: HashSet<String>,
    lookups: HashMap<String, Lookup>,
    replied: HashMap<String, i64>,
    stopped: bool,
    last_error: Option<String>,
    push_error: Option<String>,
    push_last: Value,
}
enum Job {
    Published(String, bool),
    Pushed(String, Option<String>),
}
impl Session {
    /// `client` is merged into every snapshot, for example the client's version.
    pub fn new(
        mut profile: OpenProfile,
        relays: &[String],
        push: Option<&str>,
        client: serde_json::Map<String, Value>,
    ) -> Result<Self> {
        let engine = persistence::restore(profile.store.state(), &profile.keys.signing)?;
        profile.refresh_name()?;
        if profile.keys.noise.noise_public().as_slice() != engine.inbox.own.noise_key
            || hex::encode(profile.keys.nostr.nostr_public()?) != engine.inbox.own.nostr_key
        {
            return Err(text("Ключи профиля не совпадают с карточкой"));
        }
        let (pool, updates) = RelayPool::start(relays, &engine.inbox.own.nostr_key)?;
        Ok(Self {
            client,
            ble: None,
            ble_updates: mpsc::channel(1).1,
            nearby: HashMap::new(),
            bluetooth: json!({"enabled":null,"scan":"starting","advertise":"starting"}),
            profile,
            engine,
            pool,
            updates,
            jobs: JoinSet::new(),
            push: push.map(PushClient::new).transpose()?,
            inflight: HashSet::new(),
            pushed: HashSet::new(),
            lookups: HashMap::new(),
            replied: HashMap::new(),
            stopped: false,
            last_error: None,
            push_error: None,
            push_last: Value::Null,
        })
    }
    fn routes(&self) -> Routes {
        Routes {
            internet: !self.pool.connected().is_empty(),
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
        let routes = self.routes();
        let id = uuid()?;
        let time = now();
        let keys = &self.profile.keys;
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
        let mut next = persistence::project(self.profile.store.state(), &transition.state, time)?;
        next["cliInvitationEvents"] = crate::timeline::project(
            self.profile.store.state(),
            &self.engine,
            &transition.state,
            clear,
        );
        self.profile.store.commit(next)?;
        self.engine = transition.state;
        self.dispatch(transition.actions)
    }

    fn dispatch(&mut self, actions: Vec<Action>) -> Result<()> {
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
                    let event = wrap(&self.profile.keys.nostr, &recipient.nostr_key, content)?;
                    self.inflight.insert(operation.clone());
                    let pool = self.pool.clone();
                    self.jobs.spawn(async move {
                        Job::Published(operation, pool.publish(event).await.is_ok())
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
                    if let Some(push) = self
                        .push
                        .clone()
                        .filter(|_| self.pushed.insert(event.clone()))
                    {
                        let card = self.engine.inbox.own.clone();
                        let key = Secret32::new(*self.profile.keys.signing.expose());
                        self.push_last =
                            json!({"eventId":event,"state":"sending","updatedAt":now()});
                        self.jobs.spawn(async move {
                            let error = push
                                .notify(&card, &key, &recipient, &event, kind)
                                .await
                                .err()
                                .map(|e| format!("{:#}", anyhow::Error::new(e)));
                            Job::Pushed(event, error)
                        });
                    }
                }
                Action::SendBle { peer, packet } => {
                    if let Some(ble) = &self.ble {
                        if let Err(error) = ble.send(peer, packet) {
                            self.bluetooth["error"] = json!(error.to_string());
                        }
                    }
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
        let mut contacts:Vec<_>=cards.into_iter().map(|(id,card)|json!({"id":id,"card":card,"phase":self.engine.inbox.phase(&id),"unread":self.engine.inbox.messages.iter().filter(|m|m.envelope.sender.id()==*id&&m.unread).count(),"nearby":self.nearby.values().any(|p|p.direct && p.peer.card.id()==id),"distance":self.nearby.values().find(|p|p.direct && p.peer.card.id()==id).and_then(|p|p.distance),"typing":self.engine.inbox.typing.get(&id).is_some_and(|s|s.active(now())),"online":self.engine.inbox.presence.get(&id).is_some_and(|s|s.active(now()))})).collect();
        contacts.sort_by(|a, b| a["card"]["name"].as_str().cmp(&b["card"]["name"].as_str()));
        let mut messages = vec![];
        for m in &self.engine.inbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.sender.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.text,"outgoing":false,"status":if m.read{"read"}else{"delivered"},"reply":m.plaintext.reply}));
        }
        for m in &self.engine.outbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.recipient.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.as_ref().map(|p|p.text.as_str()).unwrap_or(""),"outgoing":true,"status":m.delivery.status,"nostrAccepted":m.delivery.nostr_accepted,"pushScheduled":m.push_sent,"reply":m.plaintext.as_ref().and_then(|p|p.reply.clone())}));
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
        let mut snapshot = json!({"profile":self.profile.profile,"card":own,"contacts":contacts,"messages":messages,"events":crate::timeline::stored(self.profile.store.state(), &self.engine),"reactions":reactions,"relays":self.pool.connected(),"bluetooth":self.bluetooth,"pushConfigured":self.push.is_some(),"pushError":self.push_error,"pushLast":self.push_last,"error":self.last_error,"clientCommandVersion":COMMAND_SCHEMA_VERSION});
        if let Some(object) = snapshot.as_object_mut() {
            object.extend(self.client.clone());
        }
        snapshot
    }
    fn command(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Snapshot => return Ok(self.snapshot()),
            Request::Backup {
                password,
                created_at,
            } => {
                let password = zeroize::Zeroizing::new(password);
                let file = shum_store::backup::export(&self.profile, &password, &created_at)?;
                return Ok(
                    json!({ "file": base64::engine::general_purpose::STANDARD.encode(file) }),
                );
            }
            Request::Add { link } => match invitation::parse(&link)? {
                Invitation::Card(card) => {
                    let id = card.id();
                    self.apply(|e, _| {
                        e.add_contact(*card)?;
                        Ok(vec![])
                    })?;
                    return Ok(json!({"contactID":id}));
                }
                Invitation::Locator(_) => bail!("Lookup requires asynchronous request"),
            },
            Request::Invite { contact }
            | Request::Accept { contact }
            | Request::Decline { contact } => {
                let _ = contact;
                bail!("internal invitation dispatch")
            }
            Request::Send { contact, text } => {
                let id = self.contact(&contact)?;
                if self.engine.inbox.phase(&id) != shum_core::rules::Phase::Accepted {
                    return Err(phase(self.engine.inbox.phase(&id)));
                }
                let ephemeral = secret()?;
                self.apply(|e, c| e.send(&id, &text, None, &ephemeral, c))?;
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
                self.apply(|e, _| {
                    e.block(&id, blocked)?;
                    Ok(vec![])
                })?;
            }
            Request::Profile { name, bio, seed } => {
                let own = &self.engine.inbox.own;
                let name = name.unwrap_or_else(|| own.name.clone());
                self.profile.check_name(&name)?;
                let bio = bio.unwrap_or_else(|| own.bio.clone());
                let seed = seed.or(own.avatar_seed);
                self.apply(|e, c| {
                    e.update_profile(name, bio, seed, None, c)?;
                    Ok(e.tick(c.routes, c.now))
                })?;
                self.profile.refresh_name()?;
            }
            Request::Stop => self.stopped = true,
        }
        Ok(json!({"status":"ok"}))
    }
    fn start_lookup(&mut self, key: String, reply: Reply, invite: bool) {
        if self.lookups.len() >= 8 {
            let _ = reply.send(Err(Failure::text("Слишком много поисков")));
            return;
        }
        if key == self.engine.inbox.own.nostr_key {
            let _ = reply.send(Err(Failure::text("Это ваш профиль")));
            return;
        }
        let prepared = (|| -> Result<String> {
            let id = uuid()?;
            let content = format!(
                "shum-contact-request-v1:{}",
                STANDARD.encode(canonical::encode(&json!({"id":id}))?)
            );
            let event = wrap(&self.profile.keys.nostr, &key, content)?;
            self.pool.publish_unconfirmed(event)?;
            Ok(id)
        })();
        let id = match prepared {
            Ok(id) => id,
            Err(error) => {
                let _ = reply.send(Err(Failure::from_error(error)));
                return;
            }
        };
        self.lookups.insert(
            id,
            Lookup {
                key,
                invite,
                expires: now() + 20_000,
                reply,
            },
        );
    }
    fn incoming(&mut self, event: nostr::Event) -> Result<()> {
        if self.profile.store.state()["cliNostrHandled"][&event.id]
            .as_i64()
            .is_some_and(|time| time > now() / 1000 - 4 * 86400)
        {
            return Ok(());
        }
        let opened = nostr::open_private(&event, &self.profile.keys.nostr);
        if let Ok(message) = opened {
            if let Some(encoded) = message
                .content
                .strip_prefix("shum-v1:")
                .or_else(|| message.content.strip_prefix("spotchat-v1:"))
            {
                if encoded.len() <= 33000 {
                    if let Ok(bytes) = STANDARD.decode(encoded) {
                        if let Ok(packet) = Packet::decode(&bytes) {
                            self.apply(|e, c| {
                                e.receive(packet, Source::Nostr(&message.sender), c)
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
                                    if self
                                        .replied
                                        .get(&message.sender)
                                        .is_none_or(|last| now() - *last >= 3000)
                                    {
                                        if self.replied.len() >= 1000 {
                                            self.replied.retain(|_, last| now() - *last < 300000);
                                        }
                                        if self.replied.len() < 1000 {
                                            self.replied.insert(message.sender.clone(), now());
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
                                            self.pool.publish_unconfirmed(wrap(
                                                &self.profile.keys.nostr,
                                                &message.sender,
                                                content,
                                            )?)?;
                                        }
                                    }
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
                                if let Some(id) = value["id"].as_str() {
                                    if self.lookups.get(id).is_some_and(|l| {
                                        l.key == message.sender && l.expires > now()
                                    }) {
                                        let validated = (|| -> Result<Card> {
                                            let card: Card =
                                                serde_json::from_value(value["card"].clone())?;
                                            let profile: Manifest =
                                                serde_json::from_value(value["profile"].clone())?;
                                            card.validate()?;
                                            if card.nostr_key != message.sender
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
                                        })(
                                        );
                                        if let Ok(card) = validated {
                                            let contact_id = card.id();
                                            if let Some(lookup) = self.lookups.remove(id) {
                                                if !lookup.reply.is_closed() {
                                                    let result = self.apply(|e, c| {
                                                        e.add_contact(card)?;
                                                        if lookup.invite {
                                                            e.invitation(
                                                                &contact_id,
                                                                InvitationAction::Request,
                                                                None,
                                                                c,
                                                            )
                                                        } else {
                                                            Ok(vec![])
                                                        }
                                                    });
                                                    let _ = lookup.reply.send(result
                                                        .map(|_| json!({"status":"ok", "contactID":contact_id}))
                                                        .map_err(Failure::from_error));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let time = now() / 1000;
        self.profile.store.transaction(|state| {
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
            Ok(())
        })?;
        Ok(())
    }
    fn configure_bluetooth(&mut self) -> Result<()> {
        let configured = self.profile.store.state()["cliSettings"]["bluetooth"]
            .as_bool()
            .unwrap_or(true);
        let selected = shum_store::profiles::Profiles::new(self.profile.root())?
            .list()?
            .0;
        let enabled = configured && selected.as_deref() == Some(self.profile.profile.id.as_str());
        self.bluetooth["enabled"] = json!(enabled);
        if !enabled {
            self.ble.take();
            self.nearby.clear();
            self.bluetooth["scan"] = json!(if configured {
                "other_profile"
            } else {
                "disabled"
            });
            self.bluetooth["advertise"] = self.bluetooth["scan"].clone();
            return Ok(());
        }
        let pins = self
            .engine
            .inbox
            .contacts
            .values()
            .chain(self.engine.inbox.blocked_cards.values())
            .cloned()
            .collect();
        if let Some(ble) = &self.ble {
            ble.profile(
                self.engine.inbox.own.clone(),
                pins,
                self.engine.inbox.blocked.clone(),
            )?;
        } else {
            self.bluetooth = json!({"enabled":true,"scan":"starting","advertise":"starting"});
            let (ble, updates) = shum_transport_ble::Ble::start(
                &self.profile.root().join(&self.profile.profile.id),
                self.engine.inbox.own.clone(),
                Secret32::new(*self.profile.keys.noise.expose()),
                Secret32::new(*self.profile.keys.signing.expose()),
                pins,
                self.engine.inbox.blocked.clone(),
            )?;
            self.ble = Some(ble);
            self.ble_updates = updates;
        }
        Ok(())
    }
    fn ble_update(&mut self, update: shum_transport_ble::Update) -> Result<()> {
        use shum_transport_ble::Update;
        match update {
            Update::State { role, state } => self.bluetooth[role] = json!(state),
            Update::Gone(id) => {
                self.nearby.remove(&id);
            }
            Update::Peer {
                routing,
                card,
                noise,
                distance,
                direct,
            } => {
                if !self.engine.inbox.blocked.contains(&card.id()) {
                    let peer =
                        shum_core::queue::Peer::authenticated(routing.clone(), *card, &noise)?;
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
            Update::Packet {
                routing,
                noise,
                packet,
            } => {
                if self.nearby.get(&routing).is_some_and(|p| p.noise == noise)
                    || packet.card.is_some()
                {
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
                }
            }
        }
        Ok(())
    }
    /// Serves commands until `Stop`, the end of `commands`, or `shutdown`.
    pub async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tokio::pin!(shutdown);
        while !self.stopped {
            tokio::select! {
                next=commands.recv()=>{
                    let Some(Command {request,reply})=next else {break;};
                    if let Request::Add {link}=&request {if let Ok(Invitation::Locator(key))=invitation::parse(link){self.start_lookup(key,reply,false);continue;}}
                    if let Request::Invite {contact}=&request {
                        if matches!(self.resolve_contact(contact), Ok(None)) && crate::contact::network_id(contact) {
                            self.start_lookup(contact.clone(),reply,true);continue;
                        }
                    }
                    let result=match &request {
                        Request::Invite {contact}|Request::Accept {contact}|Request::Decline {contact}=> {let action=match &request{Request::Invite {..}=>InvitationAction::Request,Request::Accept {..}=>InvitationAction::Accept,_=>InvitationAction::Decline};self.invite_contact(contact,action)},
                        _=>self.command(request),
                    };
                    let _=reply.send(result.map_err(Failure::from_error));
                }
                update=self.updates.recv()=> {if let Some(RelayUpdate::Event {event,..})=update {if let Err(error)=self.incoming(*event){self.last_error=Some(error.to_string());}}}
                result=self.jobs.join_next(),if !self.jobs.is_empty()=> {match result {
                    Some(Ok(Job::Published(operation,accepted)))=>{self.inflight.remove(&operation);if let Err(error)=self.apply(|e,c|{e.outbox.relay_result(&operation,accepted,c.now,false);Ok(vec![])}){self.last_error=Some(error.to_string());}},
                    // A slow earlier request must not replace the latest event's status.
                    Some(Ok(Job::Pushed(event,error))) if self.push_last["eventId"].as_str() == Some(event.as_str())=>{
                        self.push_last=json!({"eventId":event,"state":if error.is_some(){"failed"}else{"accepted"},"error":error,"updatedAt":now()});
                        self.push_error=error;
                    },
                    _=>{},
                }}
                update=self.ble_updates.recv(),if self.ble.is_some()=>{if let Some(update)=update{if let Err(error)=self.ble_update(update){self.bluetooth["error"]=json!(error.to_string());}}else{self.ble.take();self.nearby.clear();self.bluetooth["error"]=json!("Bluetooth worker stopped");}}
                _=tick.tick()=>{
                    if let Err(error)=self.configure_bluetooth(){self.bluetooth["error"]=json!(error.to_string());}
                    if let Err(error)=self.apply(|e,c|Ok(e.tick(c.routes,c.now))){self.last_error=Some(error.to_string());}
                    let expired:Vec<_>=self.lookups.iter().filter(|(_,l)|l.expires<=now()).map(|(id,_)|id.clone()).collect();for id in expired {if let Some(lookup)=self.lookups.remove(&id){let _=lookup.reply.send(Err(Failure::text("Контакт не ответил за 20 секунд. Для добавления офлайн используйте полную карточку или QR.")));}}
                }
                _=&mut shutdown=>break,
            }
        }
        self.ble.take();
        self.engine.retire();
        self.jobs.abort_all();
        self.profile.store.checkpoint().context("checkpoint")?;
        Ok(())
    }
}
