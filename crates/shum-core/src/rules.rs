//! Delivery policy with explicit clocks and authenticated transport identity.
use crate::{card::Card, crypto::Secret32, packet::*, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Ready,
    OutgoingPending,
    IncomingPending,
    Accepted,
    DeclinedByPeer,
    DeclinedLocally,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationState {
    pub phase: Phase,
    pub updated_at: i64,
    #[serde(rename = "eventID")]
    pub event_id: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationEffect {
    Ignored,
    Incoming,
    Accepted,
    Declined,
    ReaffirmAccept,
}
impl InvitationState {
    pub fn receive(
        &mut self,
        control: &InvitationControl,
        own_id: &str,
        has_outgoing: bool,
        legacy_source: bool,
    ) -> InvitationEffect {
        if self.event_id == control.id {
            return InvitationEffect::Ignored;
        }
        let legacy = self.phase == Phase::IncomingPending && self.event_id.starts_with("legacy-");
        let effect = match control.fields.action {
            InvitationAction::Request if self.phase == Phase::Accepted => {
                if control.timestamp > self.updated_at {
                    InvitationEffect::ReaffirmAccept
                } else {
                    InvitationEffect::Ignored
                }
            }
            InvitationAction::Request
                if self.phase == Phase::OutgoingPending
                    && own_id < control.sender.id().as_str() =>
            {
                InvitationEffect::Ignored
            }
            InvitationAction::Request
                if [Phase::Ready, Phase::OutgoingPending, Phase::DeclinedByPeer]
                    .contains(&self.phase)
                    || legacy =>
            {
                InvitationEffect::Incoming
            }
            InvitationAction::Accept
                if [
                    Phase::OutgoingPending,
                    Phase::DeclinedByPeer,
                    Phase::Accepted,
                ]
                .contains(&self.phase)
                    || (self.phase == Phase::IncomingPending && has_outgoing)
                    || (legacy && legacy_source) =>
            {
                InvitationEffect::Accepted
            }
            InvitationAction::Decline
                if [Phase::OutgoingPending, Phase::DeclinedByPeer].contains(&self.phase)
                    || (self.phase == Phase::IncomingPending && has_outgoing) =>
            {
                InvitationEffect::Declined
            }
            _ => InvitationEffect::Ignored,
        };
        match effect {
            InvitationEffect::Incoming => self.phase = Phase::IncomingPending,
            InvitationEffect::Accepted | InvitationEffect::ReaffirmAccept => {
                self.phase = Phase::Accepted
            }
            InvitationEffect::Declined => self.phase = Phase::DeclinedByPeer,
            InvitationEffect::Ignored => return effect,
        }
        if effect != InvitationEffect::ReaffirmAccept {
            self.updated_at = control.timestamp;
            self.event_id = control.id.clone();
        }
        effect
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionMark {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<ReactionKind>,
    pub timestamp: i64,
    #[serde(rename = "eventID")]
    pub event_id: String,
}
pub fn newer(timestamp: i64, id: &str, previous_timestamp: i64, previous_id: &str) -> bool {
    (timestamp, id) > (previous_timestamp, previous_id)
}
impl ReactionMark {
    pub fn apply(&mut self, control: &Reaction) -> bool {
        if !newer(
            control.timestamp,
            &control.id,
            self.timestamp,
            &self.event_id,
        ) {
            return false;
        }
        self.reaction = control.fields.reaction;
        self.timestamp = control.timestamp;
        self.event_id = control.id.clone();
        true
    }
    pub fn from_control(c: &Reaction) -> Self {
        Self {
            reaction: c.fields.reaction,
            timestamp: c.timestamp,
            event_id: c.id.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EphemeralSignal {
    pub timestamp: i64,
    pub id: String,
    pub expires: i64,
    pub value: bool,
}
impl EphemeralSignal {
    pub fn apply(&mut self, timestamp: i64, id: &str, expires: i64, value: bool) -> bool {
        if !newer(timestamp, id, self.timestamp, &self.id) {
            return false;
        }
        *self = Self {
            timestamp,
            id: id.into(),
            expires,
            value,
        };
        true
    }
    pub fn active(&self, now: i64) -> bool {
        self.value && self.expires > now
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Delivery {
    Queued,
    Forwarding,
    Delivered,
    Read,
    Expired,
    Cancelled,
}
pub fn nostr_delay_ms(attempts: u32) -> i64 {
    if attempts == 0 {
        0
    } else {
        5_000_i64
            .saturating_mul(1_i64 << attempts.saturating_sub(1).min(4))
            .min(60_000)
    }
}
pub fn ble_delay_ms(attempts: u32) -> i64 {
    10_000 * i64::from(attempts.clamp(1, 6))
}
pub fn profile_delay_ms(attempts: u32) -> i64 {
    (5_000 * (1_i64 << attempts.min(10))).min(3_600_000)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryState {
    pub status: Delivery,
    pub nostr_accepted: bool,
    pub nostr_attempts: u32,
    pub last_nostr_attempt: Option<i64>,
    pub receipt: Option<Receipt>,
}
impl Default for DeliveryState {
    fn default() -> Self {
        Self {
            status: Delivery::Queued,
            nostr_accepted: false,
            nostr_attempts: 0,
            last_nostr_attempt: None,
            receipt: None,
        }
    }
}
impl DeliveryState {
    /// Call inside the state transaction before issuing transport I/O.
    pub fn attempt_nostr(&mut self, now: i64, expires: i64) -> bool {
        if expires <= now {
            if [Delivery::Queued, Delivery::Forwarding].contains(&self.status) {
                self.status = Delivery::Expired;
            }
            return false;
        }
        if self.nostr_accepted
            || ![Delivery::Queued, Delivery::Forwarding].contains(&self.status)
            || self
                .last_nostr_attempt
                .is_some_and(|t| now.saturating_sub(t) < nostr_delay_ms(self.nostr_attempts))
        {
            return false;
        }
        self.nostr_attempts = self.nostr_attempts.saturating_add(1);
        self.last_nostr_attempt = Some(now);
        true
    }
    pub fn relay_result(&mut self, accepted: bool) {
        if accepted {
            self.nostr_accepted = true;
            if self.status == Delivery::Queued {
                self.status = Delivery::Forwarding;
            }
        }
    }
    pub fn apply_receipt(&mut self, receipt: Receipt, envelope: &Envelope, now: i64) -> Result<()> {
        receipt.validate(now)?;
        if receipt.envelope_id != envelope.id
            || receipt.digest != envelope.digest()
            || receipt.sender.id() != envelope.recipient.id()
            || receipt.sender.signing_key != envelope.recipient.signing_key
            || receipt.destination.id() != envelope.sender.id()
        {
            return Err(Error::Invalid("receipt binding"));
        }
        if self.receipt.as_ref().is_some_and(|v| v.read) && !receipt.read {
            return Ok(());
        }
        self.status = if receipt.read {
            Delivery::Read
        } else {
            Delivery::Delivered
        };
        self.receipt = Some(receipt);
        Ok(())
    }
}

pub enum Source<'a> {
    Nostr(&'a str),
    Ble {
        peer: &'a str,
        session_noise: &'a [u8; 32],
    },
}
impl Source<'_> {
    fn binds(&self, card: &Card) -> bool {
        match self {
            Self::Nostr(key) => *key == card.nostr_key,
            Self::Ble { session_noise, .. } => session_noise.as_slice() == card.noise_key,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub envelope: Envelope,
    pub plaintext: Plaintext,
    pub unread: bool,
    pub read: bool,
    pub hop_count: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundEffect {
    Dropped,
    Accepted(String),
    RepeatReceipt(String),
    ContactRequest(String),
    Invitation(InvitationEffect),
    Reaction,
    Typing,
    Presence,
    Retracted,
    Card(Box<Card>),
    Profile {
        reply: bool,
        rebase_above: Option<u64>,
    },
}

/// Persist a clone after a successful operation before emitting any ACK.
/// Keys are passed per operation and are never serialized with public state.
#[derive(Clone, Debug)]
pub struct Inbox {
    pub own: Card,
    pub contacts: HashMap<String, Card>,
    pub blocked: HashSet<String>,
    pub blocked_cards: HashMap<String, Card>,
    pub deleted: HashMap<String, i64>,
    pub messages: Vec<ReceivedMessage>,
    pub invitations: HashMap<String, InvitationState>,
    pub requests: HashMap<String, Card>,
    pub outgoing_requests: HashSet<String>,
    pub reactions: HashMap<(String, String), ReactionMark>,
    pub typing: HashMap<String, EphemeralSignal>,
    pub presence: HashMap<String, EphemeralSignal>,
    pub reaffirm_accept: HashSet<String>,
    pub foreground_contact: Option<String>,
}
impl Inbox {
    pub fn new(own: Card) -> Self {
        Self {
            own,
            contacts: HashMap::new(),
            blocked: HashSet::new(),
            blocked_cards: HashMap::new(),
            deleted: HashMap::new(),
            messages: vec![],
            invitations: HashMap::new(),
            requests: HashMap::new(),
            outgoing_requests: HashSet::new(),
            reactions: HashMap::new(),
            typing: HashMap::new(),
            presence: HashMap::new(),
            reaffirm_accept: HashSet::new(),
            foreground_contact: None,
        }
    }
    pub fn phase(&self, id: &str) -> Phase {
        self.invitations.get(id).map_or_else(
            || {
                if self.requests.contains_key(id) {
                    Phase::IncomingPending
                } else {
                    Phase::Ready
                }
            },
            |v| v.phase,
        )
    }
    fn own_keys(&self, card: &Card) -> bool {
        self.own.noise_key == card.noise_key
            && self.own.signing_key == card.signing_key
            && self.own.nostr_key == card.nostr_key
    }
    fn pinned(&self, card: &Card) -> bool {
        self.contacts.get(&card.id()).is_some_and(|c| {
            c.noise_key == card.noise_key
                && c.signing_key == card.signing_key
                && c.nostr_key == card.nostr_key
        })
    }
    fn merge(&mut self, card: &Card) -> Result<()> {
        if let Some(previous) = self.requests.get(&card.id()) {
            let next = card.preferred(previous)?.clone();
            self.requests.insert(card.id(), next);
        }
        if let Some(previous) = self.contacts.get(&card.id()) {
            let next = card.preferred(previous)?.clone();
            self.contacts.insert(card.id(), next);
        }
        Ok(())
    }
    pub fn clear_chat(&mut self, contact: &str, now: i64) {
        let conversation = conversation_id(&self.own.id(), contact);
        for message in &self.messages {
            if message.envelope.conversation_id == conversation && message.envelope.expires_at > now
            {
                self.deleted
                    .insert(message.envelope.id.clone(), message.envelope.expires_at);
            }
        }
        let ids: HashSet<_> = self
            .messages
            .iter()
            .filter(|m| m.envelope.conversation_id == conversation)
            .map(|m| m.envelope.id.clone())
            .collect();
        self.messages
            .retain(|m| m.envelope.conversation_id != conversation);
        self.reactions.retain(|(id, _), _| !ids.contains(id));
    }
    pub fn receive(
        &mut self,
        packet: Packet,
        source: Source<'_>,
        noise: &Secret32,
        now: i64,
    ) -> Result<InboundEffect> {
        // Source authentication is supplied by the transport, never inferred from JSON.
        if let Source::Ble { session_noise, .. } = &source {
            if self
                .blocked
                .contains(&crate::crypto::id(session_noise.as_slice()))
            {
                return Ok(InboundEffect::Dropped);
            }
        }
        if let Source::Nostr(key) = &source {
            if self
                .contacts
                .values()
                .chain(self.blocked_cards.values())
                .any(|c| c.nostr_key == *key && self.blocked.contains(&c.id()))
            {
                return Ok(InboundEffect::Dropped);
            }
        }
        if let Some(card) = packet.card {
            card.validate()?;
            if self.blocked.contains(&card.id())
                || !source.binds(&card)
                || card.id() == self.own.id()
            {
                return Ok(InboundEffect::Dropped);
            }
            self.merge(&card)?;
            if matches!(source, Source::Nostr(_))
                && !self.contacts.contains_key(&card.id())
                && self.phase(&card.id()) == Phase::Ready
            {
                if self.requests.len() >= 20 {
                    return Err(Error::Invalid("request quota"));
                }
                self.requests.insert(card.id(), card.clone());
                self.invitations.insert(
                    card.id(),
                    InvitationState {
                        phase: Phase::IncomingPending,
                        updated_at: now,
                        event_id: format!("legacy-{}", card.id()),
                    },
                );
            }
            return Ok(InboundEffect::Card(Box::new(card)));
        }
        if let Some(sync) = packet.profile_sync {
            sync.validate()?;
            if sync.recipient_id != self.own.id()
                || self.blocked.contains(&sync.sender.id())
                || !self.pinned(&sync.sender)
                || !source.binds(&sync.sender)
            {
                return Ok(InboundEffect::Dropped);
            }
            let rebase_above = if let Some(peer_own) = &sync.known_recipient {
                if !self.own_keys(peer_own) {
                    return Ok(InboundEffect::Dropped);
                }
                let preferred = peer_own.preferred(&self.own)?;
                if preferred.profile_id()? != self.own.profile_id()? {
                    peer_own.profile_revision
                } else {
                    None
                }
            } else {
                None
            };
            self.merge(&sync.sender)?;
            return Ok(InboundEffect::Profile {
                reply: sync.requests_reply,
                rebase_above,
            });
        }
        if let Some(e) = packet.envelope {
            if self.blocked.contains(&e.sender.id()) || self.blocked.contains(&e.recipient.id()) {
                return Ok(InboundEffect::Dropped);
            }
            e.validate(now)?;
            if !self.own_keys(&e.recipient) {
                return Ok(InboundEffect::Dropped);
            }
            if matches!(&source, Source::Nostr(_)) && !source.binds(&e.sender) {
                return Err(Error::Authentication);
            }
            let hop = match source {
                Source::Nostr(_) => 0,
                Source::Ble { .. } => packet.hop_count.ok_or(Error::Invalid("missing hop"))?,
            };
            if matches!(source, Source::Ble { .. }) && !(1..=e.hop_limit).contains(&hop) {
                return Err(Error::Invalid("message hop"));
            }
            if self.deleted.get(&e.id).is_some_and(|expiry| *expiry > now) {
                return Ok(InboundEffect::Dropped);
            }
            if let Some(old) = self.messages.iter().find(|m| m.envelope.id == e.id) {
                if old.envelope.sender.id() == e.sender.id()
                    && old.envelope.digest() == e.digest()
                    && self.pinned(&e.sender)
                    && self.phase(&e.sender.id()) == Phase::Accepted
                {
                    return Ok(InboundEffect::RepeatReceipt(e.id));
                }
                return Ok(InboundEffect::Dropped);
            }
            let plain = e.open(noise, now)?;
            if self.contacts.contains_key(&e.sender.id()) && !self.pinned(&e.sender) {
                return Ok(InboundEffect::Dropped);
            }
            if !self.pinned(&e.sender) {
                if self.requests.len() >= 20 && !self.requests.contains_key(&e.sender.id()) {
                    return Err(Error::Invalid("request quota"));
                }
                self.requests.insert(e.sender.id(), e.sender.clone());
                self.invitations
                    .entry(e.sender.id())
                    .or_insert_with(|| InvitationState {
                        phase: Phase::IncomingPending,
                        updated_at: now,
                        event_id: format!("legacy-{}", e.sender.id()),
                    });
                return Ok(InboundEffect::ContactRequest(e.sender.id()));
            }
            if self.phase(&e.sender.id()) != Phase::Accepted {
                return Ok(InboundEffect::Dropped);
            }
            self.merge(&e.sender)?;
            let unread = self.foreground_contact.as_deref() != Some(e.sender.id().as_str());
            let id = e.id.clone();
            self.messages.push(ReceivedMessage {
                envelope: e,
                plaintext: plain,
                unread,
                read: !unread,
                hop_count: hop,
            });
            return Ok(InboundEffect::Accepted(id));
        }
        if let Some(c) = packet.invitation {
            c.validate(now)?;
            if !self.own_keys(&c.recipient) || self.blocked.contains(&c.sender.id()) {
                return Ok(InboundEffect::Dropped);
            }
            if !source.binds(&c.sender) {
                return Err(Error::Authentication);
            }
            self.merge(&c.sender)?;
            let id = c.sender.id();
            let own = self.own.id();
            let outgoing = self.outgoing_requests.contains(&id);
            let mut state = self
                .invitations
                .get(&id)
                .cloned()
                .unwrap_or(InvitationState {
                    phase: Phase::Ready,
                    updated_at: 0,
                    event_id: String::new(),
                });
            let effect = state.receive(&c, &own, outgoing, false);
            if effect == InvitationEffect::Incoming {
                if self.requests.len() >= 20 && !self.requests.contains_key(&id) {
                    return Err(Error::Invalid("request quota"));
                }
                self.requests.insert(id.clone(), c.sender.clone());
                self.outgoing_requests.remove(&id);
            } else if [
                InvitationEffect::Accepted,
                InvitationEffect::Declined,
                InvitationEffect::ReaffirmAccept,
            ]
            .contains(&effect)
            {
                self.requests.remove(&id);
                self.outgoing_requests.remove(&id);
                if effect != InvitationEffect::Declined {
                    self.contacts.insert(id.clone(), c.sender.clone());
                }
                if effect == InvitationEffect::ReaffirmAccept {
                    self.reaffirm_accept.insert(id.clone());
                }
            }
            self.invitations.insert(id, state);
            return Ok(InboundEffect::Invitation(effect));
        }
        if let Some(c) = packet.reaction {
            c.validate(now)?;
            if !self.authorized_control(&c.sender, &c.recipient, &source, true) {
                return Ok(InboundEffect::Dropped);
            }
            if let Some(m) = self
                .messages
                .iter()
                .find(|m| m.envelope.id == c.fields.message_id)
            {
                if m.envelope.conversation_id != conversation_id(&self.own.id(), &c.sender.id()) {
                    return Ok(InboundEffect::Dropped);
                }
            }
            self.merge(&c.sender)?;
            let key = (c.fields.message_id.clone(), c.sender.id());
            if let Some(mark) = self.reactions.get_mut(&key) {
                mark.apply(&c);
            } else {
                if !self
                    .reactions
                    .keys()
                    .any(|(id, _)| *id == c.fields.message_id)
                    && self
                        .reactions
                        .keys()
                        .map(|(id, _)| id)
                        .collect::<HashSet<_>>()
                        .len()
                        >= 20_000
                {
                    return Err(Error::Invalid("reaction quota"));
                }
                self.reactions.insert(key, ReactionMark::from_control(&c));
            }
            return Ok(InboundEffect::Reaction);
        }
        if let Some(c) = packet.typing {
            c.validate(now)?;
            if !self.authorized_control(&c.sender, &c.recipient, &source, true) {
                return Ok(InboundEffect::Dropped);
            }
            self.merge(&c.sender)?;
            let id = c.sender.id();
            let changed = apply_signal(
                &mut self.typing,
                &id,
                c.timestamp,
                &c.id,
                c.expires_at,
                c.fields.is_typing,
            );
            if changed && c.fields.is_typing {
                self.presence.insert(
                    id,
                    EphemeralSignal {
                        timestamp: c.timestamp,
                        id: c.id,
                        expires: now.saturating_add(40_000),
                        value: true,
                    },
                );
            }
            return Ok(InboundEffect::Typing);
        }
        if let Some(c) = packet.presence {
            c.validate(now)?;
            if !self.authorized_control(&c.sender, &c.recipient, &source, true) {
                return Ok(InboundEffect::Dropped);
            }
            self.merge(&c.sender)?;
            apply_signal(
                &mut self.presence,
                &c.sender.id(),
                c.timestamp,
                &c.id,
                c.expires_at,
                c.fields.is_online,
            );
            return Ok(InboundEffect::Presence);
        }
        if let Some(c) = packet.retract {
            c.validate(now)?;
            if !self.authorized_control(&c.sender, &c.recipient, &source, false) {
                return Ok(InboundEffect::Dropped);
            }
            if let Some(m) = self
                .messages
                .iter()
                .find(|m| m.envelope.id == c.fields.message_id)
            {
                if m.envelope.sender.id() != c.sender.id() {
                    return Ok(InboundEffect::Dropped);
                }
            }
            self.deleted
                .insert(c.fields.message_id.clone(), c.expires_at);
            self.messages
                .retain(|m| m.envelope.id != c.fields.message_id);
            self.reactions
                .retain(|(id, _), _| *id != c.fields.message_id);
            return Ok(InboundEffect::Retracted);
        }
        Ok(InboundEffect::Dropped)
    }
    fn authorized_control(
        &self,
        sender: &Card,
        recipient: &Card,
        source: &Source<'_>,
        accepted: bool,
    ) -> bool {
        self.own_keys(recipient)
            && !self.blocked.contains(&sender.id())
            && self.pinned(sender)
            && source.binds(sender)
            && (!accepted || self.phase(&sender.id()) == Phase::Accepted)
    }
}
fn apply_signal(
    signals: &mut HashMap<String, EphemeralSignal>,
    sender: &str,
    time: i64,
    id: &str,
    expires: i64,
    value: bool,
) -> bool {
    if let Some(signal) = signals.get_mut(sender) {
        signal.apply(time, id, expires, value)
    } else {
        signals.insert(
            sender.into(),
            EphemeralSignal {
                timestamp: time,
                id: id.into(),
                expires,
                value,
            },
        );
        true
    }
}
