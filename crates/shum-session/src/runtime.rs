//! The session in native clients: the shared [`Machine`] over SQLite
//! storage, tokio relay connections, Bluetooth and push.
use crate::{
    machine::{Effect, Host, Machine, Nearby},
    Failure, Request,
};
use anyhow::{Context as _, Result};
use serde_json::{json, Value};
use shum_core::crypto::Secret32;
use shum_store::{keys::ProfileKeys, profiles::OpenProfile};
use shum_transport_nostr::{push::PushClient, RelayPool, RelayUpdate};
use std::{collections::HashMap, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

pub struct Command {
    pub request: Request,
    pub reply: Reply,
}
pub type Reply = oneshot::Sender<std::result::Result<Value, Failure>>;

impl Host for OpenProfile {
    fn keys(&self) -> &ProfileKeys {
        &self.keys
    }
    fn state(&self) -> &Value {
        self.store.state()
    }
    fn commit(&mut self, next: Value) -> Result<()> {
        self.store.commit(next)?;
        Ok(())
    }
    fn profile(&self) -> Value {
        serde_json::to_value(&self.profile).unwrap_or_default()
    }
    fn check_name(&self, name: &str) -> Result<()> {
        Ok(OpenProfile::check_name(self, name)?)
    }
    fn renamed(&mut self) -> Result<()> {
        Ok(self.refresh_name()?)
    }
    fn backup(&self, password: &str, created_at: &str) -> Result<Vec<u8>> {
        Ok(shum_store::backup::export(self, password, created_at)?)
    }
}

enum Job {
    Published(String, bool),
    Pushed(String, Option<String>),
}

/// A running profile: the shared session with relays, Bluetooth and push.
pub struct Session {
    machine: Machine<OpenProfile>,
    ble: Option<shum_transport_ble::Ble>,
    ble_updates: mpsc::Receiver<shum_transport_ble::Update>,
    pool: RelayPool,
    updates: mpsc::Receiver<RelayUpdate>,
    jobs: JoinSet<Job>,
    push: Option<PushClient>,
    replies: HashMap<u64, Reply>,
    next_reply: u64,
}

impl Session {
    /// `client` is merged into every snapshot, for example the client's version.
    pub fn new(
        profile: OpenProfile,
        relays: &[String],
        push: Option<&str>,
        client: serde_json::Map<String, Value>,
    ) -> Result<Self> {
        let push = push.map(PushClient::new).transpose()?;
        let machine = Machine::new(profile, push.is_some(), client)?;
        let (pool, updates) = RelayPool::start(relays, machine.inbox())?;
        Ok(Self {
            machine,
            ble: None,
            ble_updates: mpsc::channel(1).1,
            pool,
            updates,
            jobs: JoinSet::new(),
            push,
            replies: HashMap::new(),
            next_reply: 0,
        })
    }

    pub fn snapshot(&self) -> Value {
        self.machine.snapshot()
    }

    /// Carries out what the machine decided.
    fn carry(&mut self) {
        for effect in self.machine.effects() {
            match effect {
                Effect::Publish {
                    operation: Some(operation),
                    event,
                } => {
                    let pool = self.pool.clone();
                    self.jobs.spawn(async move {
                        Job::Published(operation, pool.publish(event).await.is_ok())
                    });
                }
                Effect::Publish {
                    operation: None,
                    event,
                } => {
                    // A lookup that cannot go out ends by its timeout.
                    let _ = self.pool.publish_unconfirmed(event);
                }
                Effect::Push {
                    card,
                    key,
                    recipient,
                    event,
                    kind,
                } => {
                    if let Some(push) = self.push.clone() {
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
                Effect::SendBle { peer, packet } => {
                    if let Some(ble) = &self.ble {
                        if let Err(error) = ble.send(peer, packet) {
                            self.machine.bluetooth["error"] = json!(error.to_string());
                        }
                    }
                }
                Effect::Reply { id, result } => {
                    if let Some(reply) = self.replies.remove(&id) {
                        let _ = reply.send(result);
                    }
                }
            }
        }
    }

    fn configure_bluetooth(&mut self) -> Result<()> {
        let profile = &self.machine.host;
        let configured = profile.store.state()["cliSettings"]["bluetooth"]
            .as_bool()
            .unwrap_or(true);
        let selected = shum_store::profiles::Profiles::new(profile.root())?
            .list()?
            .0;
        let enabled = configured && selected.as_deref() == Some(profile.profile.id.as_str());
        self.machine.bluetooth["enabled"] = json!(enabled);
        if !enabled {
            self.ble.take();
            self.machine.clear_nearby();
            self.machine.bluetooth["scan"] = json!(if configured {
                "other_profile"
            } else {
                "disabled"
            });
            self.machine.bluetooth["advertise"] = self.machine.bluetooth["scan"].clone();
            return Ok(());
        }
        let inbox = &self.machine.engine.inbox;
        let pins = inbox
            .contacts
            .values()
            .chain(inbox.blocked_cards.values())
            .cloned()
            .collect();
        if let Some(ble) = &self.ble {
            ble.profile(inbox.own.clone(), pins, inbox.blocked.clone())?;
        } else {
            self.machine.bluetooth =
                json!({"enabled":true,"scan":"starting","advertise":"starting"});
            let profile = &self.machine.host;
            let (ble, updates) = shum_transport_ble::Ble::start(
                &profile.root().join(&profile.profile.id),
                inbox.own.clone(),
                Secret32::new(*profile.keys.noise.expose()),
                Secret32::new(*profile.keys.signing.expose()),
                pins,
                inbox.blocked.clone(),
            )?;
            self.ble = Some(ble);
            self.ble_updates = updates;
        }
        Ok(())
    }

    fn ble_update(&mut self, update: shum_transport_ble::Update) -> Result<()> {
        use shum_transport_ble::Update;
        self.machine.nearby(match update {
            Update::Peer {
                routing,
                card,
                noise,
                distance,
                direct,
            } => Nearby::Peer {
                routing,
                card,
                noise,
                distance,
                direct,
            },
            Update::Gone(id) => Nearby::Gone(id),
            Update::Packet {
                routing,
                noise,
                packet,
            } => Nearby::Packet {
                routing,
                noise,
                packet,
            },
            Update::State { role, state } => Nearby::State { role, state },
        })
    }

    /// Serves commands until `Stop`, the end of `commands`, or `shutdown`.
    pub async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tokio::pin!(shutdown);
        while !self.machine.stopped() {
            self.machine.set_relays(self.pool.connected());
            tokio::select! {
                next = commands.recv() => {
                    let Some(Command { request, reply }) = next else { break };
                    self.next_reply += 1;
                    let id = self.next_reply;
                    match self.machine.request(id, request) {
                        Some(result) => { let _ = reply.send(result); }
                        None => { self.replies.insert(id, reply); }
                    }
                }
                update = self.updates.recv() => {
                    if let Some(RelayUpdate::Event { event, .. }) = update { self.machine.incoming(*event); }
                }
                result = self.jobs.join_next(), if !self.jobs.is_empty() => match result {
                    Some(Ok(Job::Published(operation, accepted))) => self.machine.published(&operation, accepted),
                    Some(Ok(Job::Pushed(event, error))) => self.machine.pushed(&event, error),
                    _ => {}
                },
                update = self.ble_updates.recv(), if self.ble.is_some() => {
                    if let Some(update) = update {
                        if let Err(error) = self.ble_update(update) { self.machine.bluetooth["error"] = json!(error.to_string()); }
                    } else {
                        self.ble.take();
                        self.machine.clear_nearby();
                        self.machine.bluetooth["error"] = json!("Bluetooth worker stopped");
                    }
                }
                _ = tick.tick() => {
                    if let Err(error) = self.configure_bluetooth() { self.machine.bluetooth["error"] = json!(error.to_string()); }
                    self.machine.tick();
                    // Requests whose callers left no longer wait for an answer.
                    self.replies.retain(|_, reply| !reply.is_closed());
                }
                _ = &mut shutdown => break,
            }
            self.carry();
        }
        self.ble.take();
        self.machine.engine.retire();
        self.jobs.abort_all();
        self.machine.host.store.checkpoint().context("checkpoint")?;
        Ok(())
    }
}
