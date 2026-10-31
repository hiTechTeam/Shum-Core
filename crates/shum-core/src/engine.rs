//! Protocol state and local operations. Clients persist a prepared transition
//! before installing its state and dispatching its actions.
use crate::{
    card::{self, Card},
    crypto::Secret32,
    packet::*,
    photo::Photo,
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
    /// What this device last told its other devices about the profile,
    /// and when; and since when it has had something new to tell.
    own_state_sent: Option<(OwnStateView, i64)>,
    own_state_changed: Option<i64>,
}
/// The parts of the profile's state its devices share, compared cheaply.
type OwnStateView = (String, Vec<(String, Phase, i64, String, bool, i64)>);
/// A changed state waits this long for more changes before it goes out.
const OWN_STATE_SETTLE_MS: i64 = 5_000;
/// The state goes out again this often anyway.
const OWN_STATE_REPEAT_MS: i64 = 3_600_000;
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
            own_state_sent: None,
            own_state_changed: None,
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
        if card.id() == self.inbox.own.id() {
            return Err(Error::Invalid("own profile"));
        }
        if self.inbox.blocked.contains(&card.id()) {
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
        self.send_with(id, text, reply, None, ephemeral, c)
    }
    /// Sends a JPEG with `text`: the caption when `caption`, otherwise a
    /// stand-in for clients without photos. `key` is fresh for every photo.
    /// The caller stores the JPEG under `c.uuid` and sends its parts after
    /// the message (protocol section 04.9).
    #[allow(clippy::too_many_arguments)]
    pub fn send_photo(
        &mut self,
        id: &str,
        jpeg: &[u8],
        size: (i64, i64),
        text: &str,
        caption: bool,
        key: &Secret32,
        ephemeral: &Secret32,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        let (photo, _) = Photo::seal(c.uuid, jpeg, size.0, size.1, caption, key)?;
        self.send_with(id, text, None, Some(photo), ephemeral, c)
    }
    fn send_with(
        &mut self,
        id: &str,
        text: &str,
        reply: Option<Reply>,
        photo: Option<Photo>,
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
            photo,
        };
        let envelope = Envelope::seal(
            self.inbox.own.clone(),
            peer,
            plaintext.clone(),
            c.keys.noise,
            c.keys.signing,
            ephemeral,
        )?;
        self.outbox.enqueue(envelope)?;
        self.outbox
            .messages
            .last_mut()
            .expect("enqueued message")
            .plaintext = Some(plaintext);
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
        // This profile's other devices follow it too.
        self.outbox.enqueue_control(QueuedControl {
            id: format!("own-invitation:{}", control.id),
            recipient: self.inbox.own.clone(),
            expires: control.expires_at,
            packet: Packet {
                own_invitation: Some(control.clone()),
                ..Packet::default()
            },
            kind: ControlKind::OwnInvitation,
            retry: Retry::default(),
        });
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
    /// This profile's invitation to `id` while no relay or nearby device has it.
    pub fn waiting_invitation(&self, id: &str) -> Option<&QueuedControl> {
        let event = &self
            .inbox
            .invitations
            .get(id)
            .filter(|v| v.phase == Phase::OutgoingPending)?
            .event_id;
        self.outbox.controls.iter().find(|c| {
            c.id == *event
                && c.kind == ControlKind::InvitationRequest
                && !c.retry.nostr_accepted
                && c.retry.attempts == 0
        })
    }
    /// Takes back an invitation that was never handed to a relay or device.
    pub fn cancel_invitation(&mut self, id: &str) -> Result<()> {
        let event = self
            .waiting_invitation(id)
            .filter(|c| c.retry.nostr_attempts == 0)
            .ok_or(Error::Invalid("invitation already sent"))?
            .id
            .clone();
        let own = format!("own-invitation:{event}");
        // The copy for this profile's other devices waits for relays too.
        if self
            .outbox
            .controls
            .iter()
            .any(|c| c.id == own && c.retry.nostr_attempts > 0)
        {
            return Err(Error::Invalid("invitation already shared"));
        }
        self.outbox
            .controls
            .retain(|c| c.id != event && c.id != own);
        // A request is only made from Ready, so dropping it restores Ready.
        self.inbox.invitations.remove(id);
        self.inbox.outgoing_requests.remove(id);
        Ok(())
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
        // Only this profile's own Nostr key sends these, from its other devices.
        if packet.own_copy.is_some()
            || packet.own_read.is_some()
            || packet.own_reaction.is_some()
            || packet.own_retract.is_some()
            || packet.own_clear.is_some()
            || packet.own_invitation.is_some()
            || packet.own_state.is_some()
        {
            if !matches!(&source, Source::Nostr(key) if *key == self.inbox.own.nostr_key) {
                return Ok(vec![]);
            }
            if let Some(copy) = packet.own_copy {
                // Withdrawn there before the copy reached this device.
                if copy.validate(&self.inbox.own, c.now).is_ok()
                    && !self.inbox.deleted.contains_key(&copy.envelope.id)
                {
                    let recipient = copy.envelope.recipient.clone();
                    if !self.inbox.contacts.contains_key(&recipient.id()) {
                        let _ = self.add_contact(recipient);
                    }
                    self.outbox.mirror(copy);
                    self.settle_sent();
                }
            }
            if let Some(state) = packet
                .own_state
                .filter(|s| s.validate(&self.inbox.own).is_ok())
            {
                self.take_own_state(state);
            }
            if let Some(read) = packet.own_read.filter(|r| r.validate().is_ok()) {
                for message in &mut self.inbox.messages {
                    if read.message_ids.contains(&message.envelope.id) {
                        message.unread = false;
                        message.read = true;
                    }
                }
            }
            if let Some(r) = packet
                .own_reaction
                .filter(|r| validate_own(r, &self.inbox.own, c.now).is_ok())
            {
                let id = &r.fields.message_id;
                let peer = r.recipient.id();
                let known = self
                    .outbox
                    .messages
                    .iter()
                    .any(|m| m.envelope.id == *id && m.envelope.recipient.id() == peer)
                    || self
                        .inbox
                        .messages
                        .iter()
                        .any(|m| m.envelope.id == *id && m.envelope.sender.id() == peer);
                if known {
                    let key = (id.clone(), self.inbox.own.id());
                    if let Some(mark) = self.inbox.reactions.get_mut(&key) {
                        mark.apply(&r);
                    } else {
                        self.inbox
                            .reactions
                            .insert(key, ReactionMark::from_control(&r));
                    }
                }
            }
            if let Some(r) = packet
                .own_retract
                .filter(|r| validate_own(r, &self.inbox.own, c.now).is_ok())
            {
                let id = r.fields.message_id.clone();
                if self
                    .outbox
                    .messages
                    .iter()
                    .find(|m| m.envelope.id == id)
                    .is_none_or(|m| m.envelope.recipient.id() == r.recipient.id())
                {
                    self.inbox.deleted.insert(id.clone(), r.expires_at);
                    self.forget_outgoing(&id);
                }
            }
            if let Some(clear) = packet.own_clear.filter(|v| v.validate().is_ok()) {
                self.clear_until(&clear.contact_id, clear.before, c.now);
            }
            if let Some(i) = packet
                .own_invitation
                .filter(|v| validate_own(v, &self.inbox.own, c.now).is_ok())
            {
                self.apply_own_invitation(i);
            }
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
                actions.extend(self.acknowledge(&id, c)?);
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
            InboundEffect::Profile { reply, adopt } => {
                if let Some(sync) = sync {
                    if let Some(known) = &sync.known_recipient {
                        self.outbox.acknowledge_profile(&sync.sender, known)?;
                    }
                    // Another device of this profile edited it later: take its
                    // version instead of answering with ours, or the two would
                    // keep overriding each other.
                    if let Some(own) = adopt {
                        self.share_profile(*own, c)?;
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
        let mut read = vec![];
        for message in &mut self.inbox.messages {
            if message.envelope.sender.id() == id && message.unread {
                read.push(message.envelope.id.clone());
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
        // This profile's other devices show them read too.
        for (part, ids) in read.chunks(OwnRead::MAX).enumerate() {
            self.outbox.enqueue_control(QueuedControl {
                id: format!("own-read:{}:{part}", c.uuid),
                recipient: self.inbox.own.clone(),
                expires: c.now.saturating_add(DAY_MS),
                packet: Packet {
                    own_read: Some(OwnRead {
                        message_ids: ids.to_vec(),
                    }),
                    ..Packet::default()
                },
                kind: ControlKind::OwnRead,
                retry: Retry::default(),
            });
        }
        Ok(self.tick(c.routes, c.now))
    }
    pub fn clear_chat(&mut self, id: &str, now: i64) {
        let conversation = conversation_id(&self.inbox.own.id(), id);
        let newest = self
            .outbox
            .messages
            .iter()
            .filter(|m| m.envelope.recipient.id() == id)
            .map(|m| m.envelope.timestamp)
            .chain(
                self.inbox
                    .messages
                    .iter()
                    .filter(|m| m.envelope.conversation_id == conversation)
                    .map(|m| m.envelope.timestamp),
            )
            .max()
            .unwrap_or(0);
        let before = now.max(newest);
        self.clear_until(id, before, now);
        // This profile's other devices clear it too.
        self.outbox.enqueue_control(QueuedControl {
            id: format!("own-clear:{id}:{before}"),
            recipient: self.inbox.own.clone(),
            expires: now.saturating_add(DAY_MS),
            packet: Packet {
                own_clear: Some(OwnClear {
                    contact_id: id.into(),
                    before,
                }),
                ..Packet::default()
            },
            kind: ControlKind::OwnClear,
            retry: Retry::default(),
        });
    }
    /// Blocks or unblocks a contact; `at` dates the decision for the
    /// profile's other devices.
    pub fn block(&mut self, id: &str, blocked: bool, at: i64) -> Result<()> {
        self.live()?;
        if self.inbox.blocked.contains(id) == blocked {
            return Ok(());
        }
        self.inbox.block_decisions.insert(id.into(), at);
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
        c: &Context<'_>,
    ) -> Result<()> {
        self.live()?;
        self.keys(&c.keys)?;
        let revision = self
            .inbox
            .own
            .profile_revision
            .unwrap_or(0)
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
        self.share_profile(own, c)
    }
    fn share_profile(&mut self, own: Card, c: &Context<'_>) -> Result<()> {
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
        actions.extend(self.send_own_state(routes, now));
        actions
    }
    fn own_state_view(&self) -> OwnStateView {
        let ids: HashSet<&String> = self
            .inbox
            .invitations
            .iter()
            .filter(|(_, s)| s.phase != Phase::Ready)
            .map(|(id, _)| id)
            .chain(self.inbox.blocked.iter())
            .chain(self.inbox.block_decisions.keys())
            .collect();
        let mut rows: Vec<_> = ids
            .into_iter()
            .map(|id| {
                let (phase, at, event) = self.inbox.invitations.get(id).map_or_else(
                    || (Phase::Ready, 0, "-".to_string()),
                    |s| (s.phase, s.updated_at, s.event_id.clone()),
                );
                let blocked = self.inbox.blocked.contains(id);
                let decided = self.inbox.block_decisions.get(id).copied().unwrap_or(0);
                (id.clone(), phase, at, event, blocked, decided)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let own = &self.inbox.own;
        (format!("{}:{:?}", own.id(), own.profile_revision), rows)
    }
    /// Every page of the profile's state, for its other devices: when this
    /// device starts, shortly after something changes, and every hour.
    fn send_own_state(&mut self, routes: &Routes, now: i64) -> Vec<Action> {
        if !routes.internet {
            return vec![];
        }
        let view = self.own_state_view();
        let due = match &self.own_state_sent {
            None => true,
            Some((sent, at)) => {
                if *sent != view {
                    let since = *self.own_state_changed.get_or_insert(now);
                    now - since >= OWN_STATE_SETTLE_MS
                } else {
                    self.own_state_changed = None;
                    now - at >= OWN_STATE_REPEAT_MS
                }
            }
        };
        if !due {
            return vec![];
        }
        let contacts: Vec<_> = view
            .1
            .iter()
            .filter_map(|(id, phase, at, event, blocked, decided)| {
                let card = self
                    .inbox
                    .contacts
                    .get(id)
                    .or_else(|| self.inbox.requests.get(id))
                    .or_else(|| self.inbox.blocked_cards.get(id))?;
                Some(OwnStateContact {
                    card: card.clone(),
                    phase: *phase,
                    updated_at: *at,
                    event_id: event.clone(),
                    blocked: *blocked,
                    blocked_at: *decided,
                })
            })
            .collect();
        let pages: Vec<_> = contacts.chunks(OwnState::PAGE).collect();
        let count = pages.len().clamp(1, OwnState::MAX_PAGES as usize);
        let own = self.inbox.own.clone();
        let actions = (0..count)
            .map(|page| Action::SendNostr {
                operation: format!("own-state:{page}"),
                recipient: Box::new(own.clone()),
                packet: Box::new(Packet {
                    own_state: Some(OwnState {
                        card: own.clone(),
                        page: page as i64,
                        pages: count as i64,
                        contacts: pages.get(page).map(|p| p.to_vec()).unwrap_or_default(),
                    }),
                    ..Packet::default()
                }),
            })
            .collect();
        self.own_state_sent = Some((view, now));
        self.own_state_changed = None;
        actions
    }
    /// Takes what another device of this profile decided later than this
    /// one: a newer own card, invitation steps and blocks.
    fn take_own_state(&mut self, state: OwnState) {
        if state
            .card
            .preferred(&self.inbox.own)
            .is_ok_and(|p| p.profile_id().ok() != self.inbox.own.profile_id().ok())
        {
            self.inbox.own = state.card;
        }
        for c in state.contacts {
            let id = c.card.id();
            let _ = self.inbox.merge(&c.card);
            if c.phase != Phase::Ready
                && self
                    .inbox
                    .invitations
                    .get(&id)
                    .is_none_or(|s| newer(c.updated_at, &c.event_id, s.updated_at, &s.event_id))
            {
                self.take_step(&c.card, c.phase, c.updated_at, &c.event_id);
            }
            let decided = self.inbox.block_decisions.get(&id).copied().unwrap_or(0);
            if c.blocked_at > decided {
                if !self.inbox.contacts.contains_key(&id)
                    && !self.inbox.requests.contains_key(&id)
                    && !self.inbox.blocked_cards.contains_key(&id)
                {
                    let _ = self.add_contact(c.card.clone());
                }
                if self.block(&id, c.blocked, c.blocked_at).is_ok() {
                    self.inbox.block_decisions.insert(id, c.blocked_at);
                }
            }
        }
    }
    /// Takes an invitation step another device of this profile took, with
    /// the same effects as there, sending nothing.
    fn take_step(&mut self, card: &Card, phase: Phase, at: i64, event: &str) {
        let id = card.id();
        if phase == Phase::IncomingPending {
            if !self.inbox.contacts.contains_key(&id) && !self.inbox.blocked.contains(&id) {
                self.inbox.requests.insert(id.clone(), card.clone());
            }
        } else if self.add_contact(card.clone()).is_err() && !self.inbox.contacts.contains_key(&id)
        {
            return;
        }
        self.inbox.invitations.insert(
            id.clone(),
            InvitationState {
                phase,
                updated_at: at,
                event_id: event.into(),
            },
        );
        match phase {
            Phase::OutgoingPending => {
                self.inbox.outgoing_requests.insert(id);
            }
            Phase::IncomingPending => {
                self.inbox.outgoing_requests.remove(&id);
            }
            _ => {
                self.inbox.requests.remove(&id);
                self.inbox.outgoing_requests.remove(&id);
            }
        }
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
    if let Some(copy) = &packet.own_copy {
        ids.insert(copy.envelope.recipient.id());
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
    parties!(own_reaction);
    parties!(own_retract);
    parties!(own_invitation);
    if let Some(s) = &packet.profile_sync {
        ids.insert(s.sender.id());
    }
    ids
}

impl Engine {
    /// Clears a chat up to `before`; what came later stays.
    fn clear_until(&mut self, id: &str, before: i64, now: i64) {
        let conversation = conversation_id(&self.inbox.own.id(), id);
        let mut cleared = HashSet::new();
        for m in &self.outbox.messages {
            if m.envelope.recipient.id() == id && m.envelope.timestamp <= before {
                cleared.insert(m.envelope.id.clone());
                if m.envelope.expires_at > now {
                    self.inbox
                        .deleted
                        .insert(m.envelope.id.clone(), m.envelope.expires_at);
                }
            }
        }
        cleared.extend(
            self.inbox
                .messages
                .iter()
                .filter(|m| {
                    m.envelope.conversation_id == conversation && m.envelope.timestamp <= before
                })
                .map(|m| m.envelope.id.clone()),
        );
        self.inbox
            .reactions
            .retain(|(message, _), _| !cleared.contains(message));
        self.held_reactions
            .retain(|message, _| !cleared.contains(message));
        self.inbox.clear_until(id, before, now);
        self.outbox.clear_chat(&cleared);
    }
    /// An invitation sent or answered on another of this profile's devices:
    /// this device takes the same step, unless it already took a newer one.
    /// The delivery receipt for received message `id`, unless its photo is
    /// still coming: the sender keeps sending until the photo is here.
    fn acknowledge(&mut self, id: &str, c: &Context<'_>) -> Result<Vec<Action>> {
        self.keys(&c.keys)?;
        let mut actions = vec![];
        let Some(message) = self
            .inbox
            .messages
            .iter()
            .find(|m| m.envelope.id == id && !m.photo_missing)
        else {
            return Ok(actions);
        };
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
        Ok(actions)
    }
    /// The photo of message `id` came together and is stored: a received
    /// one is acknowledged now; a copy from another device just shows it.
    pub fn photo_arrived(&mut self, id: &str, c: &Context<'_>) -> Result<Vec<Action>> {
        if let Some(copy) = self
            .outbox
            .messages
            .iter_mut()
            .find(|m| m.envelope.id == id && m.photo_missing)
        {
            copy.photo_missing = false;
            return Ok(vec![]);
        }
        let Some(message) = self
            .inbox
            .messages
            .iter_mut()
            .find(|m| m.envelope.id == id && m.photo_missing)
        else {
            return Ok(vec![]);
        };
        message.photo_missing = false;
        let mut actions = self.acknowledge(id, c)?;
        actions.extend(self.tick(c.routes, c.now));
        Ok(actions)
    }
    /// A message to someone is sent only once they are accepted, so one
    /// sent after this device's last invitation step with them, here or on
    /// another device of the profile, means they were accepted since. Fixes
    /// answers that never reached this device.
    pub fn settle_sent(&mut self) {
        let mut latest: HashMap<String, (i64, String)> = HashMap::new();
        for m in &self.outbox.messages {
            let e = &m.envelope;
            let id = e.recipient.id();
            if latest.get(&id).is_none_or(|(t, _)| e.timestamp > *t) {
                latest.insert(id, (e.timestamp, e.id.clone()));
            }
        }
        for (id, (at, message)) in latest {
            let stale = self
                .inbox
                .invitations
                .get(&id)
                .is_none_or(|s| s.phase != Phase::Accepted && at > s.updated_at);
            if !stale || self.inbox.blocked.contains(&id) {
                continue;
            }
            let Some(card) = self
                .inbox
                .requests
                .remove(&id)
                .or_else(|| self.inbox.contacts.get(&id).cloned())
            else {
                continue;
            };
            self.inbox.contacts.insert(id.clone(), card);
            self.inbox.outgoing_requests.remove(&id);
            self.inbox.invitations.insert(
                id,
                InvitationState {
                    phase: Phase::Accepted,
                    updated_at: at,
                    event_id: format!("sent-{message}"),
                },
            );
        }
    }
    fn apply_own_invitation(&mut self, c: InvitationControl) {
        let id = c.recipient.id();
        if self
            .inbox
            .invitations
            .get(&id)
            .is_some_and(|s| !newer(c.timestamp, &c.id, s.updated_at, &s.event_id))
            || self.add_contact(c.recipient.clone()).is_err()
        {
            return;
        }
        let phase = match c.fields.action {
            InvitationAction::Request => Phase::OutgoingPending,
            InvitationAction::Accept => Phase::Accepted,
            InvitationAction::Decline => Phase::DeclinedLocally,
        };
        self.inbox.invitations.insert(
            id.clone(),
            InvitationState {
                phase,
                updated_at: c.timestamp,
                event_id: c.id.clone(),
            },
        );
        if c.fields.action == InvitationAction::Request {
            self.inbox.outgoing_requests.insert(id.clone());
        } else {
            self.inbox.requests.remove(&id);
            self.inbox.outgoing_requests.remove(&id);
        }
        // An older step queued here would contradict it.
        self.outbox.controls.retain(|q| {
            q.packet
                .invitation
                .as_ref()
                .is_none_or(|v| v.recipient.id() != id || v.timestamp >= c.timestamp)
        });
    }
    /// Drops a withdrawn outgoing message with its reactions.
    fn forget_outgoing(&mut self, message_id: &str) {
        self.outbox.messages.retain(|m| m.envelope.id != message_id);
        self.inbox.reactions.retain(|(id, _), _| id != message_id);
        self.outbox.controls.retain(|q| {
            [q.packet.reaction.as_ref(), q.packet.own_reaction.as_ref()]
                .into_iter()
                .flatten()
                .all(|r| r.fields.message_id != message_id)
        });
        self.held_reactions.remove(message_id);
    }
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
    /// Whether typing to `id` was last said to be going on.
    pub fn last_typing_active(&self, id: &str) -> bool {
        self.last_typing.get(id).is_some_and(|(active, _)| *active)
    }
    /// Sends typing to `id` once more while it lasts: the first signal can
    /// be lost while a Bluetooth link is still being set up.
    pub fn repeat_typing(&mut self, id: &str, c: &Context<'_>) -> Result<Vec<Action>> {
        if self.inbox.foreground_contact.as_deref() != Some(id)
            || !self.last_typing.get(id).is_some_and(|(active, _)| *active)
        {
            return Ok(vec![]);
        }
        self.last_typing.remove(id);
        self.set_typing(id, true, c)
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
        // This profile's other devices show it too.
        self.outbox.enqueue_control(QueuedControl {
            id: format!("own-reaction:{}", control.id),
            recipient: self.inbox.own.clone(),
            expires: control.expires_at,
            packet: Packet {
                own_reaction: Some(control.clone()),
                ..Packet::default()
            },
            kind: ControlKind::OwnReaction,
            retry: Retry::default(),
        });
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
        self.delete_sent(message_id, true, c)
    }
    /// Deletes a sent message here and on this profile's other devices;
    /// with `everyone`, the contact's copy goes too, delivered or not.
    pub fn delete_sent(
        &mut self,
        message_id: &str,
        everyone: bool,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        self.live()?;
        self.keys(&c.keys)?;
        let message = self
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == message_id)
            .ok_or(Error::Invalid("unknown outgoing message"))?;
        let expires = message.envelope.expires_at;
        // The contact may hold it once it was delivered or went out at all.
        let left = everyone
            && (!matches!(
                message.delivery.status,
                Delivery::Queued | Delivery::Forwarding
            ) || message.retry.attempts > 0
                || message.delivery.nostr_accepted
                || message.delivery.last_nostr_attempt.is_some()
                || !message.offered.is_empty());
        // This profile's other devices hold it too.
        let shared = message.mirror || message.copied || message.copy_offered.is_some();
        if left || shared {
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
            if shared {
                self.outbox.enqueue_control(QueuedControl {
                    id: format!("own-retract:{}", control.id),
                    recipient: self.inbox.own.clone(),
                    expires: control.expires_at,
                    packet: Packet {
                        own_retract: Some(control.clone()),
                        ..Packet::default()
                    },
                    kind: ControlKind::OwnRetract,
                    retry: Retry::default(),
                });
            }
            if left {
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
        }
        // A late own copy must not bring it back.
        self.inbox.deleted.insert(message_id.into(), expires);
        self.forget_outgoing(message_id);
        Ok(self.tick(c.routes, c.now))
    }
    /// Sends an expired message again at the end of the chat and removes the
    /// expired one, so repeated retries never leave duplicates.
    pub fn resend(
        &mut self,
        message_id: &str,
        ephemeral: &Secret32,
        c: &Context<'_>,
    ) -> Result<Vec<Action>> {
        self.live()?;
        let message = self
            .outbox
            .messages
            .iter()
            .find(|m| m.envelope.id == message_id)
            .ok_or(Error::Invalid("unknown outgoing message"))?;
        if message.delivery.status != Delivery::Expired {
            return Err(Error::Invalid("message has not expired"));
        }
        let plaintext = message
            .plaintext
            .clone()
            .ok_or(Error::Invalid("message text is not stored"))?;
        let id = message.envelope.recipient.id();
        let actions = self.send(&id, &plaintext.text, plaintext.reply, ephemeral, c)?;
        self.outbox.messages.retain(|m| m.envelope.id != message_id);
        self.inbox.reactions.retain(|(id, _), _| id != message_id);
        Ok(actions)
    }
}
