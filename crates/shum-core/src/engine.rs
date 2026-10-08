//! Protocol state and local operations. Clients persist a prepared transition
//! before installing its state and dispatching its actions.
use crate::{
    card::{self, Card},
    crypto::Secret32,
    packet::*,
    queue::*,
    rules::*,
    Error, Result,
};
use std::collections::{HashMap, HashSet};
pub struct Keys<'a> {
    pub noise: &'a Secret32,
    pub signing: &'a Secret32,
    pub nostr: &'a Secret32,
}
pub struct Context<'a> {
    pub now: i64,
    pub keys: Keys<'a>,
    pub routes: &'a Routes,
    pub uuid: &'a str,
}
#[derive(Clone, Debug)]
pub struct Engine {
    pub inbox: Inbox,
    pub outbox: Outbox,
    limiter: RateLimiter,
    ticks: u32,
    last_typing: HashMap<String, (bool, i64)>,
    last_presence: HashMap<String, i64>,
    presence_timestamp: i64,
    held_reactions: HashMap<String, (String, String, i64)>,
}
pub struct Transition {
    pub state: Engine,
    pub actions: Vec<Action>,
}
impl Engine {
    pub fn new(own: Card) -> Result<Self> {
        own.validate()?;
        Ok(Self {
            inbox: Inbox::new(own),
            outbox: Outbox::default(),
            limiter: RateLimiter::default(),
            ticks: 0,
            last_typing: HashMap::new(),
            last_presence: HashMap::new(),
            presence_timestamp: 0,
            held_reactions: HashMap::new(),
        })
    }
    /// A failed operation leaves the original state intact. Save `state` before
    /// replacing the live Engine or executing `actions`.
    pub fn prepare(
        &self,
        operation: impl FnOnce(&mut Engine) -> Result<Vec<Action>>,
    ) -> Result<Transition> {
        let mut state = self.clone();
        let actions = operation(&mut state)?;
        Ok(Transition { state, actions })
    }
    fn live(&self) -> Result<()> {
        if self.outbox.retired {
            Err(Error::Invalid("retired profile"))
        } else {
            Ok(())
        }
    }
    fn keys(&self, k: &Keys<'_>) -> Result<()> {
        if k.noise.noise_public().as_slice() != self.inbox.own.noise_key
            || k.signing.ed_public().as_slice() != self.inbox.own.signing_key
            || hex::encode(k.nostr.nostr_public()?) != self.inbox.own.nostr_key
        {
            Err(Error::Invalid("own identity keys"))
        } else {
            Ok(())
        }
    }
    fn contact(&self, id: &str, accepted: bool) -> Result<Card> {
        self.live()?;
        if self.inbox.blocked.contains(id) || (accepted && self.inbox.phase(id) != Phase::Accepted)
        {
            return Err(Error::Invalid("contact not authorized"));
        }
        self.inbox
            .contacts
            .get(id)
            .or_else(|| self.inbox.requests.get(id))
            .cloned()
            .ok_or(Error::Invalid("unknown contact"))
    }
    pub fn add_contact(&mut self, card: Card) -> Result<()> {
        self.live()?;
        card.validate()?;
        if card.id() == self.inbox.own.id() || self.inbox.blocked.contains(&card.id()) {
            return Err(Error::Invalid("contact"));
        }
        if let Some(old) = self.inbox.contacts.get(&card.id()) {
            let next = card.preferred(old)?.clone();
            self.inbox.contacts.insert(card.id(), next);
        } else {
            if self.inbox.contacts.len() >= 2000 {
                return Err(Error::Invalid("contact quota"));
            }
            self.inbox.contacts.insert(card.id(), card);
        }
        Ok(())
    }
    pub fn send(
        &mut self,
        id: &str,
        text: &str,
        reply: Option<Reply>,
        ephemeral: &Secret32,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        self.keys(&c.keys)?;
        let peer = self.contact(id, true)?;
        let text = card::trim(text);
        if text.is_empty() || text.len() > 4096 {
            return Err(Error::Invalid("message text"));
        }
        let plaintext = Plaintext {
            protocol_name: "shum.message.v1".into(),
            id: c.uuid.into(),
            conversation_id: conversation_id(&self.inbox.own.id(), id),
            sender_id: self.inbox.own.id(),
            recipient_id: id.into(),
            timestamp: c.now,
            expires_at: c
                .now
                .checked_add(DAY_MS)
                .ok_or(Error::Invalid("time overflow"))?,
            text: text.into(),
            reply,
        };
        let envelope = Envelope::seal(
            self.inbox.own.clone(),
            peer,
            plaintext,
            c.keys.noise,
            c.keys.signing,
            ephemeral,
        )?;
        self.outbox.enqueue(envelope)?;
        Ok(self.tick(c.routes, c.now))
    }
    pub fn invitation(
        &mut self,
        id: &str,
        action: InvitationAction,
        after: Option<i64>,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        self.keys(&c.keys)?;
        let peer = self.contact(id, false)?;
        let phase = self.inbox.phase(id);
        let next = match action {
            InvitationAction::Request if phase == Phase::Ready => Phase::OutgoingPending,
            InvitationAction::Accept
                if [Phase::IncomingPending, Phase::DeclinedLocally].contains(&phase)
                    || (phase == Phase::Accepted && after.is_some()) =>
            {
                Phase::Accepted
            }
            InvitationAction::Decline if phase == Phase::IncomingPending => Phase::DeclinedLocally,
            _ => return Err(Error::Invalid("invitation phase")),
        };
        let previous = self.inbox.invitations.get(id).map_or(0, |v| v.updated_at);
        let timestamp = c
            .now
            .max(
                previous
                    .checked_add(1)
                    .ok_or(Error::Invalid("invitation timestamp"))?,
            )
            .max(
                after
                    .unwrap_or(i64::MIN)
                    .checked_add(1)
                    .ok_or(Error::Invalid("invitation timestamp"))?,
            );
        let control = Control {
            version: 1,
            id: c.uuid.into(),
            sender: self.inbox.own.clone(),
            recipient: peer.clone(),
            timestamp,
            expires_at: timestamp
                .checked_add(30 * DAY_MS)
                .ok_or(Error::Invalid("invitation expiry"))?,
            signature: vec![],
            fields: InvitationFields { action },
        }
        .sign(c.keys.signing)?;
        self.add_contact(peer.clone())?;
        self.inbox.invitations.insert(
            id.into(),
            InvitationState {
                phase: next,
                updated_at: timestamp,
                event_id: control.id.clone(),
            },
        );
        if action == InvitationAction::Request {
            self.inbox.outgoing_requests.insert(id.into());
        } else {
            self.inbox.requests.remove(id);
            self.inbox.outgoing_requests.remove(id);
        }
        self.outbox.enqueue_control(QueuedControl {
            id: control.id.clone(),
            recipient: peer.clone(),
            expires: control.expires_at,
            packet: Packet {
                invitation: Some(control),
                ..Packet::default()
            },
            kind: if action == InvitationAction::Request {
                ControlKind::InvitationRequest
            } else {
                ControlKind::InvitationReply
            },
            retry: Retry::default(),
        });
        let mut actions = self.tick(c.routes, c.now);
        if action != InvitationAction::Decline {
            let packet = Packet {
                card: Some(self.inbox.own.clone()),
                ..Packet::default()
            };
            if c.routes.internet {
                actions.push(Action::SendNostr {
                    operation: format!("legacy-invitation:{}", c.uuid),
                    recipient: Box::new(peer.clone()),
                    packet: Box::new(packet.clone()),
                });
            }
            if action == InvitationAction::Accept {
                for p in &c.routes.peers {
                    if p.card.id() == id {
                        actions.push(Action::SendBle {
                            peer: p.routing.clone(),
                            packet: Box::new(packet.clone()),
                        });
                    }
                }
            }
        }
        Ok(actions)
    }
    pub fn receive(
        &mut self,
        packet: Packet,
        source: Source<'_>,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        if self.outbox.retired {
            return Ok(vec![]);
        }
        // Enforce shape even for callers constructing a Packet directly.
        let packet = Packet::decode(&crate::canonical::encode(&packet)?)?;
        let source_key = match &source {
            Source::Nostr(key) => key.to_string(),
            Source::Ble { peer, .. } => peer.to_string(),
        };
        let blocked = match &source {
            Source::Nostr(key) => self
                .inbox
                .contacts
                .values()
                .chain(self.inbox.blocked_cards.values())
                .any(|v| v.nostr_key == *key && self.inbox.blocked.contains(&v.id())),
            Source::Ble { session_noise, .. } => self
                .inbox
                .blocked
                .contains(&crate::crypto::id(session_noise.as_slice())),
        };
        if blocked
            || packet_parties(&packet)
                .iter()
                .any(|id| self.inbox.blocked.contains(id))
        {
            return Ok(vec![]);
        }
        let class = if packet.typing.is_some() || packet.presence.is_some() {
            Traffic::Ephemeral
        } else if packet.receipt.is_some() {
            Traffic::Receipt
        } else {
            Traffic::Content
        };
        if !self.limiter.allow(&source_key, class, c.now) {
            return Ok(vec![]);
        }
        if let Some(receipt) = &packet.receipt {
            if matches!(&source,Source::Nostr(key) if *key != receipt.sender.nostr_key) {
                return Ok(vec![]);
            }
            let incoming = self
                .inbox
                .messages
                .iter()
                .find(|m| m.envelope.id == receipt.envelope_id)
                .map(|m| &m.envelope);
            // Authentication failures are remote input, not a local transaction failure.
            let _ = self.outbox.apply_receipt(receipt.clone(), incoming, c.now);
            return Ok(vec![]);
        }
        if let Some(e) = &packet.envelope {
            if e.recipient.id() != self.inbox.own.id() {
                if let Source::Ble { session_noise, .. } = &source {
                    if let Some(peer) = c
                        .routes
                        .peers
                        .iter()
                        .find(|p| p.card.noise_key == session_noise.as_slice())
                    {
                        let _ = self.outbox.carry(
                            e.clone(),
                            packet.hop_count.unwrap_or(0),
                            &peer.card,
                            c.now,
                        );
                    }
                }
                return Ok(vec![]);
            }
        }
        let reply_nostr = matches!(source, Source::Nostr(_));
        let reply_peer = match &source {
            Source::Ble { peer, .. } => Some((*peer).to_owned()),
            _ => None,
        };
        let sync = packet.profile_sync.clone();
        let invitation = packet.invitation.clone();
        let retract = packet.retract.clone();
        let effect = match self.inbox.receive(packet, source, c.keys.noise, c.now) {
            Ok(effect) => effect,
            Err(_) => return Ok(vec![]),
        };
        let mut actions = vec![];
        match effect {
            InboundEffect::Accepted(id) | InboundEffect::RepeatReceipt(id) => {
                self.keys(&c.keys)?;
                if let Some(message) = self.inbox.messages.iter().find(|m| m.envelope.id == id) {
                    let receipt = Receipt::create(
                        &message.envelope,
                        self.inbox.own.clone(),
                        c.keys.signing,
                        message.read,
                        c.now,
                    )?;
                    self.outbox
                        .apply_receipt(receipt.clone(), Some(&message.envelope), c.now)?;
                    for peer in &c.routes.peers {
                        if peer.card.id() == message.envelope.sender.id() {
                            actions.push(Action::SendBle {
                                peer: peer.routing.clone(),
                                packet: Box::new(Packet {
                                    receipt: Some(receipt.clone()),
                                    ..Packet::default()
                                }),
                            });
                        }
                    }
                }
            }
            InboundEffect::Invitation(effect) => {
                if let Some(invitation) = invitation {
                    if effect != InvitationEffect::Ignored {
                        self.outbox.controls.retain(|q| {
                            !(q.kind == ControlKind::InvitationRequest
                                && q.recipient.id() == invitation.sender.id())
                        });
                    }
                    if effect == InvitationEffect::ReaffirmAccept {
                        actions.extend(self.invitation(
                            &invitation.sender.id(),
                            InvitationAction::Accept,
                            Some(invitation.timestamp),
                            c,
                        )?);
                        self.inbox.reaffirm_accept.remove(&invitation.sender.id());
                    }
                }
            }
            InboundEffect::Profile {
                reply,
                rebase_above,
            } => {
                if let Some(sync) = sync {
                    if let Some(known) = &sync.known_recipient {
                        self.outbox.acknowledge_profile(&sync.sender, known)?;
                    }
                    if let Some(revision) = rebase_above {
                        self.update_profile(
                            self.inbox.own.name.clone(),
                            self.inbox.own.bio.clone(),
                            self.inbox.own.avatar_seed,
                            Some(revision),
                            c,
                        )?;
                    }
                    if reply {
                        let peer = self.contact(&sync.sender.id(), false)?;
                        let response = ProfileSync {
                            sender: self.inbox.own.clone(),
                            recipient_id: peer.id(),
                            known_recipient: Some(peer.clone()),
                            requests_reply: false,
                            signature: vec![],
                        }
                        .sign(c.keys.signing)?;
                        let packet = Packet {
                            profile_sync: Some(response),
                            ..Packet::default()
                        };
                        if reply_nostr && c.routes.internet {
                            actions.push(Action::SendNostr {
                                operation: format!("profile-reply:{}", peer.id()),
                                recipient: Box::new(peer.clone()),
                                packet: Box::new(packet.clone()),
                            });
                        }
                        for p in &c.routes.peers {
                            if reply_peer.as_deref() == Some(p.routing.as_str())
                                && p.card.id() == peer.id()
                            {
                                actions.push(Action::SendBle {
                                    peer: p.routing.clone(),
                                    packet: Box::new(packet.clone()),
                                });
                            }
                        }
                    }
                }
            }
            InboundEffect::Retracted => {
                if let Some(retract) = retract {
                    self.outbox
                        .receipts
                        .retain(|r| r.receipt.envelope_id != retract.fields.message_id);
                }
            }
            _ => (),
        }
        Ok(actions)
    }
    pub fn mark_read(&mut self, id: &str, c: &Context<'_>) -> Result<Vec<Action>> {
        self.live()?;
        self.keys(&c.keys)?;
        for message in &mut self.inbox.messages {
            if message.envelope.sender.id() == id && message.unread {
                if message.envelope.expires_at > c.now {
                    let r = Receipt::create(
                        &message.envelope,
                        self.inbox.own.clone(),
                        c.keys.signing,
                        true,
                        c.now,
                    )?;
                    self.outbox
                        .apply_receipt(r, Some(&message.envelope), c.now)?;
                }
                message.unread = false;
                message.read = true;
            }
        }
        Ok(self.tick(c.routes, c.now))
    }
    pub fn clear_chat(&mut self, id: &str, now: i64) {
        let own_ids: HashSet<_> = self
            .outbox
            .messages
            .iter()
            .filter(|m| m.envelope.recipient.id() == id)
            .map(|m| m.envelope.id.clone())
            .collect();
        self.inbox
            .reactions
            .retain(|(message, _), _| !own_ids.contains(message));
        self.held_reactions
            .retain(|_, (recipient, _, _)| recipient != id);
        for m in &self.outbox.messages {
            if m.envelope.recipient.id() == id && m.envelope.expires_at > now {
                self.inbox
                    .deleted
                    .insert(m.envelope.id.clone(), m.envelope.expires_at);
            }
        }
        self.inbox.clear_chat(id, now);
        self.outbox.clear_chat(id);
    }
    pub fn block(&mut self, id: &str, blocked: bool) -> Result<()> {
        self.live()?;
        if self.inbox.blocked.contains(id) == blocked {
            return Ok(());
        }
        if blocked {
            let card = self.contact(id, false)?;
            self.inbox.blocked_cards.insert(id.into(), card);
        }
        if blocked {
            if self.inbox.blocked.len() >= 2000 && !self.inbox.blocked.contains(id) {
                return Err(Error::Invalid("blocked quota"));
            }
            self.inbox.blocked.insert(id.into());
            self.held_reactions
                .retain(|_, (recipient, _, _)| recipient != id);
            self.inbox.requests.remove(id);
            self.inbox.typing.remove(id);
            self.inbox.presence.remove(id);
            self.outbox.block(id);
        } else {
            self.inbox.blocked.remove(id);
            self.inbox.blocked_cards.remove(id);
        }
        Ok(())
    }
    pub fn remove_contact(&mut self, id: &str, now: i64) {
        self.clear_chat(id, now);
        self.inbox.contacts.remove(id);
        self.inbox.requests.remove(id);
        self.inbox.invitations.remove(id);
        self.inbox.outgoing_requests.remove(id);
        self.outbox.controls.retain(|q| q.recipient.id() != id);
        self.outbox.profiles.retain(|p| p.recipient.id() != id);
    }
    pub fn update_profile(
        &mut self,
        name: String,
        bio: String,
        seed: Option<u64>,
        above: Option<u64>,
        c: &Context<'_>,
    ) -> Result<()> {
        self.live()?;
        self.keys(&c.keys)?;
        let revision = self
            .inbox
            .own
            .profile_revision
            .unwrap_or(0)
            .max(above.unwrap_or(0))
            .checked_add(1)
            .ok_or(Error::Invalid("profile revision overflow"))?;
        let own = Card::create(
            c.keys.noise,
            c.keys.signing,
            c.keys.nostr,
            name,
            &bio,
            seed,
            revision,
        )?;
        let mut profiles = vec![];
        for peer in self
            .inbox
            .contacts
            .values()
            .filter(|p| !self.inbox.blocked.contains(&p.id()))
        {
            let sync = ProfileSync {
                sender: own.clone(),
                recipient_id: peer.id(),
                known_recipient: Some(peer.clone()),
                requests_reply: true,
                signature: vec![],
            }
            .sign(c.keys.signing)?;
            profiles.push(ProfileDelivery {
                sync,
                recipient: peer.clone(),
                attempts: 0,
                last_attempt: None,
            });
        }
        profiles.sort_by_key(|p| p.recipient.id());
        self.inbox.own = own;
        self.outbox.profiles = profiles;
        Ok(())
    }
    pub fn tick(&mut self, routes: &Routes, now: i64) -> Vec<Action> {
        if self.outbox.retired {
            return vec![];
        }
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(30) {
            self.limiter.prune(now);
        }
        self.inbox.deleted.retain(|_, expiry| *expiry > now);
        let mut actions = self.outbox.tick(&self.inbox.own, routes, now);
        let due: Vec<_> = self
            .held_reactions
            .iter()
            .filter(|(_, (_, _, t))| *t <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            if let Some((recipient, event, _)) = self.held_reactions.remove(&id) {
                if self
                    .inbox
                    .reactions
                    .get(&(id.clone(), self.inbox.own.id()))
                    .is_some_and(|m| m.event_id == event && m.reaction.is_some())
                {
                    actions.push(Action::Push {
                        recipient,
                        event: id,
                        kind: PushKind::Reaction,
                    });
                }
            }
        }
        actions
    }
    pub fn retire(&mut self) {
        self.outbox.retired = true;
        self.held_reactions.clear();
        self.last_typing.clear();
        self.last_presence.clear();
        self.inbox.typing.clear();
        self.inbox.presence.clear();
        self.inbox.foreground_contact = None;
    }
}
fn packet_parties(packet: &Packet) -> HashSet<String> {
    let mut ids = HashSet::new();
    if let Some(c) = &packet.card {
        ids.insert(c.id());
    }
    if let Some(e) = &packet.envelope {
        ids.insert(e.sender.id());
        ids.insert(e.recipient.id());
    }
    if let Some(r) = &packet.receipt {
        ids.insert(r.sender.id());
        ids.insert(r.destination.id());
    }
    macro_rules! parties {
        ($field:ident) => {
            if let Some(c) = &packet.$field {
                ids.insert(c.sender.id());
                ids.insert(c.recipient.id());
            }
        };
    }
    parties!(invitation);
    parties!(typing);
    parties!(presence);
    parties!(retract);
    parties!(reaction);
    if let Some(s) = &packet.profile_sync {
        ids.insert(s.sender.id());
    }
    ids
}

impl Engine {
    fn ephemeral(
        &self,
        peer: Card,
        packet: Packet,
        routes: &Routes,
        operation: String,
        ble: bool,
    ) -> Vec<Action> {
        let mut actions = vec![];
        if ble {
            for p in &routes.peers {
                if p.card.id() == peer.id() {
                    actions.push(Action::SendBle {
                        peer: p.routing.clone(),
                        packet: Box::new(packet.clone()),
                    });
                }
            }
        }
        if routes.internet {
            actions.push(Action::SendNostr {
                operation,
                recipient: Box::new(peer),
                packet: Box::new(packet),
            });
        }
        actions
    }
    pub fn set_typing(&mut self, id: &str, active: bool, c: &Context<'_>) -> Result<Vec<Action>> {
        let peer = self.contact(id, true)?;
        self.keys(&c.keys)?;
        if self.inbox.foreground_contact.as_deref() != Some(id) {
            return Ok(vec![]);
        }
        if self.last_typing.get(id).map_or(!active, |(was, time)| {
            *was == active && (!active || c.now.saturating_sub(*time) < 4000)
        }) {
            return Ok(vec![]);
        }
        let control = Control {
            version: 1,
            id: c.uuid.into(),
            sender: self.inbox.own.clone(),
            recipient: peer.clone(),
            timestamp: c.now,
            expires_at: c
                .now
                .checked_add(8000)
                .ok_or(Error::Invalid("typing expiry"))?,
            signature: vec![],
            fields: TypingFields { is_typing: active },
        }
        .sign(c.keys.signing)?;
        self.last_typing.insert(id.into(), (active, c.now));
        Ok(self.ephemeral(
            peer,
            Packet {
                typing: Some(control),
                ..Packet::default()
            },
            c.routes,
            format!("typing:{}", c.uuid),
            true,
        ))
    }
    pub fn presence(&mut self, id: &str, online: bool, c: &Context<'_>) -> Result<Vec<Action>> {
        let peer = self.contact(id, true)?;
        self.keys(&c.keys)?;
        if !c.routes.internet
            || (online
                && self
                    .last_presence
                    .get(id)
                    .is_some_and(|t| c.now.saturating_sub(*t) < 25000))
        {
            return Ok(vec![]);
        }
        let timestamp = c.now.max(
            self.presence_timestamp
                .checked_add(1)
                .ok_or(Error::Invalid("presence timestamp"))?,
        );
        let control = Control {
            version: 1,
            id: c.uuid.into(),
            sender: self.inbox.own.clone(),
            recipient: peer.clone(),
            timestamp,
            expires_at: timestamp
                .checked_add(40000)
                .ok_or(Error::Invalid("presence expiry"))?,
            signature: vec![],
            fields: PresenceFields { is_online: online },
        }
        .sign(c.keys.signing)?;
        self.presence_timestamp = timestamp;
        if online {
            self.last_presence.insert(id.into(), c.now);
        } else {
            self.last_presence.remove(id);
        }
        Ok(self.ephemeral(
            peer,
            Packet {
                presence: Some(control),
                ..Packet::default()
            },
            c.routes,
            format!("presence:{}", c.uuid),
            false,
        ))
    }
    pub fn toggle_reaction(
        &mut self,
        message_id: &str,
        reaction: ReactionKind,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        self.keys(&c.keys)?;
        self.live()?;
        let outgoing = self
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == message_id);
        let incoming = self
            .inbox
            .messages
            .iter()
            .find(|m| m.envelope.id == message_id);
        let peer = if let Some(m) = outgoing {
            self.contact(&m.envelope.recipient.id(), true)?
        } else if let Some(m) = incoming {
            self.contact(&m.envelope.sender.id(), true)?
        } else {
            return Err(Error::Invalid("unknown message"));
        };
        let is_incoming = incoming.is_some();
        let mark_key = (message_id.into(), self.inbox.own.id());
        let old = self.inbox.reactions.get(&mark_key);
        let next = if old.is_some_and(|v| v.reaction == Some(reaction)) {
            None
        } else {
            Some(reaction)
        };
        let timestamp = c.now.max(
            old.map_or(0, |m| m.timestamp)
                .checked_add(1)
                .ok_or(Error::Invalid("reaction timestamp"))?,
        );
        let control = Control {
            version: 1,
            id: c.uuid.into(),
            sender: self.inbox.own.clone(),
            recipient: peer.clone(),
            timestamp,
            expires_at: timestamp
                .checked_add(DAY_MS)
                .ok_or(Error::Invalid("reaction expiry"))?,
            signature: vec![],
            fields: ReactionFields {
                message_id: message_id.into(),
                reaction: next,
            },
        }
        .sign(c.keys.signing)?;
        self.inbox
            .reactions
            .insert(mark_key, ReactionMark::from_control(&control));
        self.outbox.enqueue_control(QueuedControl {
            id: control.id.clone(),
            recipient: peer.clone(),
            expires: control.expires_at,
            packet: Packet {
                reaction: Some(control),
                ..Packet::default()
            },
            kind: ControlKind::Reaction,
            retry: Retry::default(),
        });
        if next.is_some() && is_incoming {
            self.held_reactions.insert(
                message_id.into(),
                (peer.id(), c.uuid.into(), c.now.saturating_add(5000)),
            );
        } else {
            self.held_reactions.remove(message_id);
        }
        Ok(self.tick(c.routes, c.now))
    }
    pub fn cancel_sending(&mut self, message_id: &str, c: &Context<'_>) -> Result<Vec<Action>> {
        self.live()?;
        self.keys(&c.keys)?;
        let message = self
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == message_id)
            .ok_or(Error::Invalid("unknown outgoing message"))?;
        if !matches!(
            message.delivery.status,
            Delivery::Queued | Delivery::Forwarding
        ) {
            return Err(Error::Invalid("message already finished"));
        }
        let left = message.retry.attempts > 0
            || message.delivery.nostr_accepted
            || message.delivery.last_nostr_attempt.is_some()
            || !message.offered.is_empty();
        if left {
            let control = Control {
                version: 1,
                id: c.uuid.into(),
                sender: self.inbox.own.clone(),
                recipient: message.envelope.recipient.clone(),
                timestamp: c.now,
                expires_at: message.envelope.expires_at,
                signature: vec![],
                fields: RetractFields {
                    message_id: message_id.into(),
                },
            }
            .sign(c.keys.signing)?;
            self.outbox.enqueue_control(QueuedControl {
                id: control.id.clone(),
                recipient: control.recipient.clone(),
                expires: control.expires_at,
                packet: Packet {
                    retract: Some(control),
                    ..Packet::default()
                },
                kind: ControlKind::Retract,
                retry: Retry::default(),
            });
        }
        self.outbox.messages.retain(|m| m.envelope.id != message_id);
        self.inbox.reactions.retain(|(id, _), _| id != message_id);
        self.outbox.controls.retain(|q| {
            q.packet
                .reaction
                .as_ref()
                .is_none_or(|r| r.fields.message_id != message_id)
        });
        self.held_reactions.remove(message_id);
        Ok(self.tick(c.routes, c.now))
    }
}
