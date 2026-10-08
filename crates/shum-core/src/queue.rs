//! Persistent retry policy. Mutate a tentative clone, persist it, then execute
//! returned actions. Neither this module nor an action performs I/O.
use crate::{
    card::Card,
    packet::{Envelope, Packet, ProfileSync, Receipt},
    rules::{ble_delay_ms, nostr_delay_ms, profile_delay_ms, Delivery, DeliveryState},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
#[derive(Clone, Debug)]
pub struct Peer {
    pub routing: String,
    pub card: Card,
}
impl Peer {
    pub fn authenticated(routing: String, card: Card, session_noise: &[u8; 32]) -> Result<Self> {
        card.validate()?;
        if card.noise_key != session_noise.as_slice() {
            return Err(Error::Authentication);
        }
        Ok(Self { routing, card })
    }
}
#[derive(Clone, Debug, Default)]
pub struct Routes {
    pub internet: bool,
    pub peers: Vec<Peer>,
}
impl Routes {
    fn direct(&self, card: &Card) -> Option<&Peer> {
        self.peers.iter().find(|p| {
            p.card.noise_key == card.noise_key
                && p.card.signing_key == card.signing_key
                && p.card.nostr_key == card.nostr_key
        })
    }
    fn couriers(&self, excluded: &HashSet<String>, sender: &str, recipient: &str) -> Vec<&Peer> {
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .filter(|p| {
                !excluded.contains(&p.card.id())
                    && p.card.id() != sender
                    && p.card.id() != recipient
            })
            .collect();
        peers.sort_by(|a, b| a.routing.cmp(&b.routing));
        peers
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    SendBle {
        peer: String,
        packet: Box<Packet>,
    },
    SendNostr {
        operation: String,
        recipient: Box<Card>,
        packet: Box<Packet>,
    },
    Push {
        recipient: String,
        event: String,
        kind: PushKind,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PushKind {
    Message,
    Invitation,
    Reaction,
}
fn ble(actions: &mut Vec<Action>, peer: &Peer, packet: Packet) {
    actions.push(Action::SendBle {
        peer: peer.routing.clone(),
        packet: Box::new(packet),
    });
}
fn nostr(actions: &mut Vec<Action>, operation: String, recipient: Card, packet: Packet) {
    actions.push(Action::SendNostr {
        operation,
        recipient: Box::new(recipient),
        packet: Box::new(packet),
    });
}
fn due(last: Option<i64>, now: i64, delay: i64) -> bool {
    last.is_none_or(|t| now.saturating_sub(t) >= delay)
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Retry {
    pub attempts: u32,
    pub last_ble: Option<i64>,
    pub nostr_attempts: u32,
    pub last_nostr: Option<i64>,
    pub nostr_accepted: bool,
}
impl Retry {
    fn nostr(&mut self, now: i64) -> bool {
        if self.nostr_accepted || !due(self.last_nostr, now, nostr_delay_ms(self.nostr_attempts)) {
            return false;
        }
        self.nostr_attempts = self.nostr_attempts.saturating_add(1);
        self.last_nostr = Some(now);
        true
    }
    fn ble(&mut self, now: i64, delay: i64) -> bool {
        if !due(self.last_ble, now, delay) {
            return false;
        }
        self.attempts = self.attempts.saturating_add(1);
        self.last_ble = Some(now);
        true
    }
}
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub envelope: Envelope,
    pub delivery: DeliveryState,
    pub retry: Retry,
    pub offered: HashSet<String>,
    pub push_after: Option<i64>,
    pub push_sent: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    InvitationRequest,
    InvitationReply,
    Retract,
    Reaction,
}
#[derive(Clone, Debug)]
pub struct QueuedControl {
    pub id: String,
    pub recipient: Card,
    pub packet: Packet,
    pub expires: i64,
    pub kind: ControlKind,
    pub retry: Retry,
}
#[derive(Clone, Debug)]
pub struct RelayCopy {
    pub envelope: Envelope,
    pub hop: i64,
    pub depositor: String,
    pub offered: HashSet<String>,
    pub last_direct: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct StoredReceipt {
    pub receipt: Receipt,
    pub offered: HashSet<String>,
    pub retry: Retry,
}
#[derive(Clone, Debug)]
pub struct ProfileDelivery {
    pub sync: ProfileSync,
    pub recipient: Card,
    pub attempts: u32,
    pub last_attempt: Option<i64>,
}
#[derive(Clone, Debug, Default)]
pub struct Outbox {
    pub messages: Vec<Outgoing>,
    pub controls: Vec<QueuedControl>,
    pub relay: Vec<RelayCopy>,
    pub receipts: Vec<StoredReceipt>,
    pub profiles: Vec<ProfileDelivery>,
    pub seen_relay: HashMap<String, i64>,
    pub retired: bool,
    pending_push: Vec<Action>,
}
impl Outbox {
    pub fn enqueue(&mut self, envelope: Envelope) -> Result<()> {
        if self.retired
            || self
                .messages
                .iter()
                .filter(|m| matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding))
                .count()
                >= 200
            || self.messages.iter().any(|m| m.envelope.id == envelope.id)
        {
            return Err(Error::Invalid("message queue"));
        }
        self.messages.push(Outgoing {
            envelope,
            delivery: DeliveryState::default(),
            retry: Retry::default(),
            offered: HashSet::new(),
            push_after: None,
            push_sent: false,
        });
        Ok(())
    }
    pub fn enqueue_control(&mut self, control: QueuedControl) {
        if self.retired {
            return;
        }
        self.controls.retain(|c| match control.kind {
            ControlKind::InvitationRequest | ControlKind::InvitationReply => {
                !(matches!(
                    c.kind,
                    ControlKind::InvitationRequest | ControlKind::InvitationReply
                ) && c.recipient.id() == control.recipient.id())
            }
            ControlKind::Reaction => c
                .packet
                .reaction
                .as_ref()
                .zip(control.packet.reaction.as_ref())
                .is_none_or(|(old, new)| old.fields.message_id != new.fields.message_id),
            ControlKind::Retract => c.id != control.id,
        });
        self.controls.push(control);
    }
    pub fn carry(
        &mut self,
        envelope: Envelope,
        hop: i64,
        depositor: &Card,
        now: i64,
    ) -> Result<bool> {
        if self.retired {
            return Ok(false);
        }
        envelope.validate(now)?;
        depositor.validate()?;
        if !(1..envelope.hop_limit).contains(&hop)
            || self.seen_relay.get(&envelope.id).is_some_and(|t| *t > now)
            || self.relay.iter().any(|r| r.envelope.id == envelope.id)
            || self.receipts.iter().any(|r| proof(&r.receipt, &envelope))
        {
            return Ok(false);
        }
        if self.relay.len() >= 64
            || self
                .relay
                .iter()
                .filter(|r| r.depositor == depositor.id())
                .count()
                >= 8
            || self.seen_relay.len() >= 4000
        {
            return Ok(false);
        }
        self.seen_relay
            .insert(envelope.id.clone(), envelope.expires_at);
        self.relay.push(RelayCopy {
            envelope,
            hop,
            depositor: depositor.id(),
            offered: HashSet::new(),
            last_direct: None,
        });
        Ok(true)
    }
    pub fn apply_receipt(
        &mut self,
        receipt: Receipt,
        incoming: Option<&Envelope>,
        now: i64,
    ) -> Result<bool> {
        if self.retired {
            return Ok(false);
        }
        receipt.validate(now)?;
        let old = self
            .receipts
            .iter()
            .find(|r| r.receipt.key() == receipt.key());
        if old.is_some_and(|r| r.receipt.read || !receipt.read) {
            return Ok(false);
        }
        let original = self
            .messages
            .iter()
            .find(|m| m.envelope.id == receipt.envelope_id)
            .map(|m| &m.envelope)
            .or(incoming)
            .or_else(|| {
                self.relay
                    .iter()
                    .find(|r| r.envelope.id == receipt.envelope_id)
                    .map(|r| &r.envelope)
            });
        let valid = original.map_or_else(
            || {
                old.is_some_and(|old| {
                    old.receipt.digest == receipt.digest
                        && old.receipt.sender.signing_key == receipt.sender.signing_key
                        && old.receipt.destination.id() == receipt.destination.id()
                })
            },
            |e| proof(&receipt, e),
        );
        if !valid || (self.receipts.len() >= 2000 && old.is_none()) {
            return Ok(false);
        }
        if let Some(message) = self
            .messages
            .iter_mut()
            .find(|m| m.envelope.id == receipt.envelope_id)
        {
            message
                .delivery
                .apply_receipt(receipt.clone(), &message.envelope, now)?;
            message.push_after = None;
        }
        self.relay.retain(|r| !proof(&receipt, &r.envelope));
        self.receipts.retain(|r| r.receipt.key() != receipt.key());
        self.receipts.push(StoredReceipt {
            receipt,
            offered: HashSet::new(),
            retry: Retry::default(),
        });
        Ok(true)
    }
    /// Callback after a relay OK. Profiles require a signed profile ACK instead.
    pub fn relay_result(&mut self, operation: &str, accepted: bool, now: i64, ble_available: bool) {
        if !accepted || self.retired {
            return;
        }
        if let Some(m) = self
            .messages
            .iter_mut()
            .find(|m| m.envelope.id == operation)
        {
            m.delivery.relay_result(true);
            if !m.push_sent && matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding)
            {
                m.push_after = Some(if ble_available {
                    now.saturating_add(8000)
                } else {
                    now
                });
            }
        }
        if let Some(c) = self.controls.iter_mut().find(|c| c.id == operation) {
            if !c.retry.nostr_accepted
                && matches!(
                    c.kind,
                    ControlKind::InvitationRequest | ControlKind::InvitationReply
                )
            {
                self.pending_push.push(Action::Push {
                    recipient: c.recipient.id(),
                    event: c.id.clone(),
                    kind: PushKind::Invitation,
                });
            }
            c.retry.nostr_accepted = true;
        }
        if let Some(r) = self
            .receipts
            .iter_mut()
            .find(|r| r.receipt.key() == operation)
        {
            r.retry.nostr_accepted = true;
        }
    }
    pub fn acknowledge_profile(&mut self, peer: &Card, known_own: &Card) -> Result<()> {
        peer.validate()?;
        known_own.validate()?;
        self.profiles.retain(|p| {
            p.recipient.id() != peer.id()
                || p.recipient.signing_key != peer.signing_key
                || p.sync.sender.profile_id().ok() != known_own.profile_id().ok()
        });
        Ok(())
    }
    pub fn tick(&mut self, own: &Card, routes: &Routes, now: i64) -> Vec<Action> {
        if self.retired {
            return vec![];
        }
        let mut actions = std::mem::take(&mut self.pending_push);
        self.seen_relay.retain(|_, expires| *expires > now);
        self.relay.retain(|r| r.envelope.expires_at > now);
        self.receipts.retain(|r| r.receipt.expires_at > now);
        self.controls.retain(|c| {
            c.expires > now
                && !c.retry.nostr_accepted
                && (c.kind == ControlKind::InvitationRequest || c.retry.attempts < 6)
        });
        for m in &mut self.messages {
            if m.envelope.expires_at <= now
                && matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding)
            {
                m.delivery.status = Delivery::Expired;
                m.push_after = None;
            }
            if m.push_after.is_some_and(|due| due <= now) {
                m.push_after = None;
                if !m.push_sent
                    && matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding)
                {
                    m.push_sent = true;
                    actions.push(Action::Push {
                        recipient: m.envelope.recipient.id(),
                        event: m.envelope.id.clone(),
                        kind: PushKind::Message,
                    });
                }
            }
        }
        let mut sent = 0;
        for m in &mut self.messages {
            if sent >= 4 {
                break;
            }
            if !matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding) {
                continue;
            }
            let packet = Packet {
                envelope: Some(m.envelope.clone()),
                hop_count: Some(1),
                ..Packet::default()
            };
            let direct = routes.direct(&m.envelope.recipient);
            let next = if direct.is_none() && m.offered.len() < 3 {
                routes
                    .couriers(&m.offered, &own.id(), &m.envelope.recipient.id())
                    .into_iter()
                    .next()
            } else {
                None
            };
            let use_ble = (direct.is_some() || next.is_some())
                && due(m.retry.last_ble, now, ble_delay_ms(m.retry.attempts));
            let use_nostr = routes.internet && m.delivery.attempt_nostr(now, m.envelope.expires_at);
            if !use_ble && !use_nostr {
                continue;
            }
            sent += 1;
            if use_ble {
                m.retry.ble(now, ble_delay_ms(m.retry.attempts));
                m.delivery.status = Delivery::Forwarding;
                if let Some(peer) = direct.or(next) {
                    if direct.is_none() {
                        m.offered.insert(peer.card.id());
                    }
                    ble(&mut actions, peer, packet.clone());
                }
            }
            if use_nostr {
                nostr(
                    &mut actions,
                    m.envelope.id.clone(),
                    m.envelope.recipient.clone(),
                    packet,
                );
            }
        }
        for kind in [
            ControlKind::InvitationRequest,
            ControlKind::Retract,
            ControlKind::Reaction,
        ] {
            // Requests and replies share the invitation pass of four.
            for c in self
                .controls
                .iter_mut()
                .filter(|c| {
                    if kind == ControlKind::InvitationRequest {
                        matches!(
                            c.kind,
                            ControlKind::InvitationRequest | ControlKind::InvitationReply
                        )
                    } else {
                        c.kind == kind
                    }
                })
                .take(if kind == ControlKind::InvitationRequest {
                    4
                } else {
                    8
                })
            {
                if let Some(peer) = routes.direct(&c.recipient) {
                    let delay = if matches!(
                        c.kind,
                        ControlKind::InvitationRequest | ControlKind::InvitationReply
                    ) {
                        invitation_delay_ms(c.retry.attempts)
                    } else {
                        10000
                    };
                    if c.retry.ble(now, delay) {
                        ble(&mut actions, peer, c.packet.clone());
                    }
                }
                if routes.internet && c.retry.nostr(now) {
                    nostr(
                        &mut actions,
                        c.id.clone(),
                        c.recipient.clone(),
                        c.packet.clone(),
                    );
                }
            }
        }
        let mut sent = 0;
        for copy in &mut self.relay {
            if sent >= 8 {
                break;
            }
            if copy.hop >= copy.envelope.hop_limit {
                continue;
            }
            let direct = routes.direct(&copy.envelope.recipient);
            let next = if direct.is_none() && copy.offered.len() < 3 {
                routes
                    .couriers(
                        &copy.offered,
                        &copy.envelope.sender.id(),
                        &copy.envelope.recipient.id(),
                    )
                    .into_iter()
                    .next()
            } else {
                None
            };
            if let Some(peer) = direct
                .filter(|_| due(copy.last_direct, now, 30000))
                .or(next)
            {
                sent += 1;
                if direct.is_some() {
                    copy.last_direct = Some(now);
                } else {
                    copy.offered.insert(peer.card.id());
                }
                ble(
                    &mut actions,
                    peer,
                    Packet {
                        envelope: Some(copy.envelope.clone()),
                        hop_count: Some(copy.hop + 1),
                        ..Packet::default()
                    },
                );
            }
        }
        let mut sent = 0;
        for stored in &mut self.receipts {
            if sent >= 8 {
                break;
            }
            let direct = routes.direct(&stored.receipt.destination);
            let next: Vec<_> = routes
                .peers
                .iter()
                .filter(|p| {
                    !stored.offered.contains(&p.card.id())
                        && direct.is_none_or(|d| d.routing != p.routing)
                })
                .take(8)
                .collect();
            let use_ble =
                due(stored.retry.last_ble, now, 30000) && (direct.is_some() || !next.is_empty());
            let use_nostr = routes.internet
                && stored.receipt.sender.id() == own.id()
                && stored.retry.nostr(now);
            if !use_ble && !use_nostr {
                continue;
            }
            sent += 1;
            let packet = Packet {
                receipt: Some(stored.receipt.clone()),
                ..Packet::default()
            };
            if use_ble {
                stored.retry.ble(now, 30000);
                if let Some(peer) = direct {
                    ble(&mut actions, peer, packet.clone());
                }
                for peer in next {
                    stored.offered.insert(peer.card.id());
                    ble(&mut actions, peer, packet.clone());
                }
            }
            if use_nostr {
                nostr(
                    &mut actions,
                    stored.receipt.key(),
                    stored.receipt.destination.clone(),
                    packet,
                );
            }
        }
        let mut sent = 0;
        for profile in &mut self.profiles {
            if sent >= 4 {
                break;
            }
            let direct = routes.direct(&profile.recipient);
            if profile.attempts >= 20
                || !due(
                    profile.last_attempt,
                    now,
                    profile_delay_ms(profile.attempts),
                )
                || (direct.is_none() && !routes.internet)
            {
                continue;
            }
            sent += 1;
            profile.attempts += 1;
            profile.last_attempt = Some(now);
            let packet = Packet {
                profile_sync: Some(profile.sync.clone()),
                ..Packet::default()
            };
            if let Some(peer) = direct {
                ble(&mut actions, peer, packet.clone());
            }
            if routes.internet {
                nostr(
                    &mut actions,
                    format!("profile:{}", profile.recipient.id()),
                    profile.recipient.clone(),
                    packet,
                );
            }
        }
        actions
    }
    pub fn block(&mut self, id: &str) {
        self.pending_push
            .retain(|p| !matches!(p,Action::Push {recipient,..} if recipient==id));
        for m in &mut self.messages {
            if m.envelope.recipient.id() == id
                && matches!(m.delivery.status, Delivery::Queued | Delivery::Forwarding)
            {
                m.delivery.status = Delivery::Cancelled;
                m.push_after = None;
            }
        }
        self.controls.retain(|c| c.recipient.id() != id);
        self.profiles.retain(|p| p.recipient.id() != id);
        self.relay.retain(|r| {
            r.depositor != id && r.envelope.sender.id() != id && r.envelope.recipient.id() != id
        });
        self.receipts
            .retain(|r| r.receipt.sender.id() != id && r.receipt.destination.id() != id);
    }
    pub fn clear_chat(&mut self, id: &str) {
        self.messages.retain(|m| m.envelope.recipient.id() != id);
        self.controls
            .retain(|c| c.kind != ControlKind::Reaction || c.recipient.id() != id);
        self.receipts
            .retain(|r| r.receipt.sender.id() != id && r.receipt.destination.id() != id);
    }
}
fn proof(receipt: &Receipt, envelope: &Envelope) -> bool {
    receipt.envelope_id == envelope.id
        && receipt.digest == envelope.digest()
        && receipt.sender.id() == envelope.recipient.id()
        && receipt.sender.signing_key == envelope.recipient.signing_key
        && receipt.destination.id() == envelope.sender.id()
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Traffic {
    Ephemeral,
    Receipt,
    Content,
}
#[derive(Clone, Debug, Default)]
pub struct RateLimiter {
    sources: HashMap<(String, Traffic), (i64, u32)>,
}
impl RateLimiter {
    pub fn allow(&mut self, source: &str, class: Traffic, now: i64) -> bool {
        let key = (source.to_owned(), class);
        if !self.sources.contains_key(&key) && self.sources.len() >= 1000 {
            return false;
        }
        let entry = self.sources.entry(key).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60000 {
            *entry = (now, 0);
        }
        if entry.1 >= 80 {
            return false;
        }
        entry.1 += 1;
        true
    }
    pub fn prune(&mut self, now: i64) {
        self.sources
            .retain(|_, (start, _)| now.saturating_sub(*start) < 60000);
    }
}

pub fn invitation_delay_ms(attempts: u32) -> i64 {
    (10000_i64 * (1_i64 << attempts.saturating_sub(1).min(3))).min(60000)
}
