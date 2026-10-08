use anyhow::{anyhow, bail, Context as _, Result};
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
        .map_err(|_| anyhow!("Системный генератор случайных чисел недоступен"))?;
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
    pub reply: oneshot::Sender<std::result::Result<Value, String>>,
}
type Reply = oneshot::Sender<std::result::Result<Value, String>>;
struct Lookup {
    key: String,
    expires: i64,
    reply: Reply,
}
pub struct Runtime {
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
}
enum Job {
    Published(String, bool),
    Pushed(Option<String>),
}
impl Runtime {
    pub fn new(mut profile: OpenProfile, relays: &[String], push: Option<&str>) -> Result<Self> {
        let engine = persistence::restore(profile.store.state(), &profile.keys.signing)?;
        profile.refresh_name()?;
        if profile.keys.noise.noise_public().as_slice() != engine.inbox.own.noise_key
            || hex::encode(profile.keys.nostr.nostr_public()?) != engine.inbox.own.nostr_key
        {
            bail!("Ключи профиля не совпадают с карточкой");
        }
        let (pool, updates) = RelayPool::start(relays, &engine.inbox.own.nostr_key)?;
        Ok(Self {
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
        })
    }
    fn routes(&self) -> Routes {
        Routes {
            internet: !self.pool.connected().is_empty(),
            peers: vec![],
        }
    }
    fn apply(
        &mut self,
        operation: impl FnOnce(&mut Engine, &Context<'_>) -> shum_core::Result<Vec<Action>>,
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
        let actions = persistence::commit_transition(
            &mut self.profile.store,
            &mut self.engine,
            transition,
            time,
        )?;
        self.dispatch(actions)
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
                        self.jobs.spawn(async move {
                            Job::Pushed(
                                push.notify(&card, &key, &recipient, &event, kind)
                                    .await
                                    .err()
                                    .map(|e| e.to_string()),
                            )
                        });
                    }
                }
                Action::SendBle { .. } => {}
            }
        }
        Ok(())
    }
    fn contact(&self, selector: &str) -> Result<String> {
        let cards: HashMap<_, _> = self
            .engine
            .inbox
            .contacts
            .iter()
            .chain(self.engine.inbox.requests.iter())
            .collect();
        let matches: Vec<_> = cards
            .into_iter()
            .filter(|(id, card)| {
                id.as_str() == selector
                    || card.name == selector
                    || (selector.len() >= 8 && id.starts_with(selector))
            })
            .collect();
        match matches.as_slice() {
            [(id, _)] => Ok((*id).clone()),
            [] => bail!("Контакт не найден: {selector}"),
            _ => bail!("Несколько контактов с этим именем. Укажите Shum ID."),
        }
    }
    pub fn snapshot(&self) -> Value {
        let own = &self.engine.inbox.own;
        let mut cards: HashMap<_, _> = self
            .engine
            .inbox
            .contacts
            .iter()
            .chain(self.engine.inbox.requests.iter())
            .collect();
        cards.retain(|id, _| !self.engine.inbox.blocked.contains(*id));
        let mut contacts:Vec<_>=cards.into_iter().map(|(id,card)|json!({"id":id,"card":card,"phase":self.engine.inbox.phase(id),"unread":self.engine.inbox.messages.iter().filter(|m|m.envelope.sender.id()==*id&&m.unread).count(),"nearby":false,"typing":self.engine.inbox.typing.get(id).is_some_and(|s|s.active(now())),"online":self.engine.inbox.presence.get(id).is_some_and(|s|s.active(now()))})).collect();
        contacts.sort_by(|a, b| a["card"]["name"].as_str().cmp(&b["card"]["name"].as_str()));
        let mut messages = vec![];
        for m in &self.engine.inbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.sender.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.text,"outgoing":false,"status":if m.read{"read"}else{"delivered"},"reply":m.plaintext.reply}));
        }
        for m in &self.engine.outbox.messages {
            messages.push(json!({"id":m.envelope.id,"contactID":m.envelope.recipient.id(),"timestamp":m.envelope.timestamp,"text":m.plaintext.as_ref().map(|p|p.text.as_str()).unwrap_or(""),"outgoing":true,"status":m.delivery.status,"reply":m.plaintext.as_ref().and_then(|p|p.reply.clone())}));
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
        json!({"profile":self.profile.profile,"card":own,"contacts":contacts,"messages":messages,"reactions":reactions,"relays":self.pool.connected(),"bluetooth":"not_implemented","pushConfigured":self.push.is_some(),"pushError":self.push_error,"error":self.last_error,"version":env!("CARGO_PKG_VERSION")})
    }
    fn command(&mut self, request: Request) -> Result<Value> {
        match request {
            Request::Snapshot => return Ok(self.snapshot()),
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
                    bail!("Сначала пригласите собеседника: shum invite <контакт>. После принятия приглашения можно отправлять сообщения");
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
                self.apply(|e, c| {
                    e.clear_chat(&id, c.now);
                    Ok(vec![])
                })?;
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
    fn start_lookup(&mut self, key: String, reply: Reply) -> Result<()> {
        if self.lookups.len() >= 8 {
            let _ = reply.send(Err("Слишком много поисков".into()));
            return Ok(());
        }
        if key == self.engine.inbox.own.nostr_key {
            let _ = reply.send(Err("Это ваш профиль".into()));
            return Ok(());
        }
        let id = uuid()?;
        let content = format!(
            "shum-contact-request-v1:{}",
            STANDARD.encode(canonical::encode(&json!({"id":id}))?)
        );
        let event = wrap(&self.profile.keys.nostr, &key, content)?;
        self.pool.publish_unconfirmed(event)?;
        self.lookups.insert(
            id,
            Lookup {
                key,
                expires: now() + 20_000,
                reply,
            },
        );
        Ok(())
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
                                                bail!("Недействительный ответ профиля");
                                            }
                                            Ok(card)
                                        })(
                                        );
                                        if let Ok(card) = validated {
                                            let contact_id = card.id();
                                            self.apply(|e, _| {
                                                e.add_contact(card)?;
                                                Ok(vec![])
                                            })?;
                                            if let Some(lookup) = self.lookups.remove(id) {
                                                let _ = lookup
                                                    .reply
                                                    .send(Ok(json!({"contactID":contact_id})));
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
    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        while !self.stopped {
            tokio::select! {
                next=commands.recv()=>{
                    let Some(Command {request,reply})=next else {break;};
                    if let Request::Add {link}=&request {if let Ok(Invitation::Locator(key))=invitation::parse(link){if let Err(error)=self.start_lookup(key,reply){self.last_error=Some(error.to_string());}continue;}}
                    let result=match &request {
                        Request::Invite {contact}|Request::Accept {contact}|Request::Decline {contact}=> {let action=match &request{Request::Invite {..}=>InvitationAction::Request,Request::Accept {..}=>InvitationAction::Accept,_=>InvitationAction::Decline};self.contact(contact).and_then(|id|self.apply(|e,c|e.invitation(&id,action,None,c))).map(|_|json!({"status":"ok"}))},
                        _=>self.command(request),
                    };
                    let _=reply.send(result.map_err(|e|e.to_string()));
                }
                update=self.updates.recv()=> {if let Some(RelayUpdate::Event {event,..})=update {if let Err(error)=self.incoming(*event){self.last_error=Some(error.to_string());}}}
                result=self.jobs.join_next(),if !self.jobs.is_empty()=> {match result {
                    Some(Ok(Job::Published(operation,accepted)))=>{self.inflight.remove(&operation);if let Err(error)=self.apply(|e,c|{e.outbox.relay_result(&operation,accepted,c.now,false);Ok(vec![])}){self.last_error=Some(error.to_string());}},
                    Some(Ok(Job::Pushed(error)))=>self.push_error=error,
                    _=>{},
                }}
                _=tick.tick()=>{
                    if let Err(error)=self.apply(|e,c|Ok(e.tick(c.routes,c.now))){self.last_error=Some(error.to_string());}
                    let expired:Vec<_>=self.lookups.iter().filter(|(_,l)|l.expires<=now()).map(|(id,_)|id.clone()).collect();for id in expired {if let Some(lookup)=self.lookups.remove(&id){let _=lookup.reply.send(Err("Контакт не ответил за 20 секунд".into()));}}
                }
                _=shutdown_signal()=>break,
            }
        }
        self.engine.retire();
        self.jobs.abort_all();
        self.profile.store.checkpoint().context("checkpoint")?;
        Ok(())
    }
}
async fn shutdown_signal() {
    // Detached Windows processes do not always have a console control handler.
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
