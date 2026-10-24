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
use shum_core::{
    canonical,
    card::Card,
    crypto::Secret32,
    engine::{Context, Engine, Keys},
    invitation::{self, Invitation},
    nostr::{self, WrapEntropy},
    packet::*,
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
}

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
    State {
        role: &'static str,
        state: String,
    },
}

struct Lookup {
    key: String,
    invite: bool,
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
    pushed: HashSet<String>,
    lookups: HashMap<String, Lookup>,
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
            pushed: HashSet::new(),
            lookups: HashMap::new(),
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
        let routes = self.routes();
        let id = uuid()?;
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
        let mut contacts:Vec<_>=cards.into_iter().map(|(id,card)|json!({"id":id,"card":card,"phase":self.engine.inbox.phase(&id),"unread":self.engine.inbox.messages.iter().filter(|m|m.envelope.sender.id()==*id&&m.unread).count(),"nearby":self.nearby.values().any(|p|p.direct && p.peer.card.id()==id),"distance":self.nearby.values().find(|p|p.direct && p.peer.card.id()==id).and_then(|p|p.distance),"typing":self.engine.inbox.typing.get(&id).is_some_and(|s|s.active(now())),"addressBook":crate::directory::in_address_book(self.host.state(),&id),"online":self.engine.inbox.presence.get(&id).is_some_and(|s|s.active(now()))})).collect();
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
        let mut blocked: Vec<_> = self
            .engine
            .inbox
            .blocked_cards
            .iter()
            .map(|(id, card)| json!({ "id": id, "card": card }))
            .collect();
        blocked.sort_by(|a, b| a["card"]["name"].as_str().cmp(&b["card"]["name"].as_str()));
        let mut snapshot = json!({"profile":self.host.profile(),"card":own,"contacts":contacts,"blocked":blocked,"messages":messages,"events":crate::timeline::stored(self.host.state(), &self.engine),"reactions":reactions,"encounters":crate::directory::encounters(self.host.state(),&self.engine.inbox.blocked,now(),self.encounter_retention),"pins":crate::directory::pins(self.host.state()),"relays":self.relays,"bluetooth":self.bluetooth,"pushConfigured":self.push,"pushError":self.push_error,"pushLast":self.push_last,"error":self.last_error,"clientCommandVersion":crate::COMMAND_SCHEMA_VERSION});
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
                return self.start_lookup(key, id, false);
            }
        }
        if let Request::Invite { contact } = &request {
            if matches!(self.resolve_contact(contact), Ok(None))
                && crate::contact::network_id(contact)
            {
                return self.start_lookup(contact.clone(), id, true);
            }
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
                    self.apply(|e, _| {
                        e.add_contact(*card)?;
                        Ok(vec![])
                    })?;
                    return Ok(json!({"contactID":id}));
                }
                Invitation::Locator(_) => bail!("Lookup requires asynchronous request"),
            },
            Request::Invite { .. } | Request::Accept { .. } | Request::Decline { .. } => {
                bail!("internal invitation dispatch")
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
                self.apply(|e, _| {
                    e.block(&id, blocked)?;
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
                    e.update_profile(name, bio, seed, None, c)?;
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
        invite: bool,
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
                        invite,
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
        let result = self.apply(|e, c| {
            e.add_contact(card)?;
            if lookup.invite {
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

    /// Call about once a second: retries, expiry and waiting lookups.
    pub fn tick(&mut self) {
        if let Err(error) = self.apply(|e, c| Ok(e.tick(c.routes, c.now))) {
            self.last_error = Some(error.to_string());
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
