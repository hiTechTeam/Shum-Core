use crate::{canonical, card::Card, crypto, noise, Error, Result};
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;

pub const DAY_MS: i64 = 86_400_000;
pub fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, v)| {
            if [8, 13, 18, 23].contains(&i) {
                v == b'-'
            } else {
                v.is_ascii_hexdigit()
            }
        })
}
pub fn conversation_id(first: &str, second: &str) -> String {
    let mut ids = [first, second];
    ids.sort_unstable();
    crypto::id(ids.join(":").as_bytes())
}
fn lifetime(timestamp: i64, expires: i64, now: i64, future: i64, ttl: i64) -> Result<()> {
    if timestamp < 0
        || timestamp > now.saturating_add(future)
        || expires <= now
        || expires <= timestamp
        || expires.checked_sub(timestamp).is_none_or(|d| d > ttl)
    {
        return Err(Error::Invalid("packet lifetime"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub version: i64,
    pub id: String,
    #[serde(rename = "conversationID")]
    pub conversation_id: String,
    pub sender: Card,
    pub recipient: Card,
    pub timestamp: i64,
    pub expires_at: i64,
    pub hop_limit: i64,
    #[serde(with = "canonical::bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
}
impl Envelope {
    pub fn digest(&self) -> String {
        crypto::id(&self.ciphertext)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut v = self.clone();
        v.signature.clear();
        canonical::encode(&v)
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.sender.validate()?;
        self.recipient.validate()?;
        lifetime(self.timestamp, self.expires_at, now, 300_000, DAY_MS)?;
        if self.version != 1
            || !uuid(&self.id)
            || self.sender.id() == self.recipient.id()
            || self.conversation_id != conversation_id(&self.sender.id(), &self.recipient.id())
            || !(1..=4).contains(&self.hop_limit)
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > 12_000
        {
            return Err(Error::Invalid("envelope"));
        }
        if !crypto::verify_ed(
            &self.sender.signing_key,
            &self.signature,
            &self.signing_bytes()?,
        ) {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub fn open(&self, recipient: &crypto::Secret32, now: i64) -> Result<Plaintext> {
        self.validate(now)?;
        if recipient.noise_public().as_slice() != self.recipient.noise_key {
            return Err(Error::Invalid("wrong recipient"));
        }
        let (bytes, sender) = noise::open_courier(recipient, &self.ciphertext)?;
        if sender.as_slice() != self.sender.noise_key {
            return Err(Error::Authentication);
        }
        let plain: Plaintext = serde_json::from_slice(&bytes)?;
        plain.validate(self)?;
        Ok(plain)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    #[serde(rename = "messageID")]
    pub message_id: String,
    #[serde(rename = "senderID")]
    pub sender_id: String,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plaintext {
    pub protocol_name: String,
    pub id: String,
    #[serde(rename = "conversationID")]
    pub conversation_id: String,
    #[serde(rename = "senderID")]
    pub sender_id: String,
    #[serde(rename = "recipientID")]
    pub recipient_id: String,
    pub timestamp: i64,
    pub expires_at: i64,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<Reply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub photo: Option<crate::photo::Photo>,
}
impl Plaintext {
    pub fn validate(&self, e: &Envelope) -> Result<()> {
        if !["shum.message.v1", "spotchat.message.v1"].contains(&self.protocol_name.as_str())
            || self.id != e.id
            || self.conversation_id != e.conversation_id
            || self.sender_id != e.sender.id()
            || self.recipient_id != e.recipient.id()
            || self.timestamp != e.timestamp
            || self.expires_at != e.expires_at
            || self.text.is_empty()
            || self.text.len() > 4096
        {
            return Err(Error::Invalid("plaintext binding"));
        }
        if let Some(r) = &self.reply {
            if r.message_id.is_empty()
                || r.message_id.len() > 255
                || r.text.is_empty()
                || r.text.len() > 4096
                || (r.sender_id != e.sender.id() && r.sender_id != e.recipient.id())
            {
                return Err(Error::Invalid("reply"));
            }
        }
        if let Some(photo) = &self.photo {
            photo.validate()?;
        }
        Ok(())
    }
}

pub trait ControlFields: Clone + Serialize {
    const TTL: i64;
    const FUTURE: i64 = 300_000;
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Control<T> {
    pub version: i64,
    pub id: String,
    pub sender: Card,
    pub recipient: Card,
    pub timestamp: i64,
    pub expires_at: i64,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
    #[serde(flatten)]
    pub fields: T,
}
impl<T: ControlFields> Control<T> {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut v = self.clone();
        v.signature.clear();
        canonical::encode(&v)
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.sender.validate()?;
        self.recipient.validate()?;
        self.fields.validate()?;
        lifetime(self.timestamp, self.expires_at, now, T::FUTURE, T::TTL)?;
        if self.version != 1 || !uuid(&self.id) || self.sender.id() == self.recipient.id() {
            return Err(Error::Invalid("control"));
        }
        if !crypto::verify_ed(
            &self.sender.signing_key,
            &self.signature,
            &self.signing_bytes()?,
        ) {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvitationAction {
    Request,
    Accept,
    Decline,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationFields {
    pub action: InvitationAction,
}
impl ControlFields for InvitationFields {
    const TTL: i64 = 30 * DAY_MS;
}
pub type InvitationControl = Control<InvitationFields>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingFields {
    pub is_typing: bool,
}
impl ControlFields for TypingFields {
    const TTL: i64 = 10_000;
    const FUTURE: i64 = 30_000;
}
pub type Typing = Control<TypingFields>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceFields {
    pub is_online: bool,
}
impl ControlFields for PresenceFields {
    const TTL: i64 = 90_000;
    const FUTURE: i64 = 30_000;
}
pub type Presence = Control<PresenceFields>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetractFields {
    #[serde(rename = "messageID")]
    pub message_id: String,
}
impl ControlFields for RetractFields {
    const TTL: i64 = DAY_MS;
    fn validate(&self) -> Result<()> {
        if uuid(&self.message_id) {
            Ok(())
        } else {
            Err(Error::Invalid("message UUID"))
        }
    }
}
pub type Retract = Control<RetractFields>;
/// A reaction: the name of a sticker from a set that is a reaction too
/// (see `stickers`). The first eight were all of v1; a name no set has
/// does not decode, so a packet carrying it is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReactionKind(&'static str);

#[allow(non_upper_case_globals)]
impl ReactionKind {
    pub const Heart: Self = Self("heart");
    pub const Like: Self = Self("like");
    pub const Dislike: Self = Self("dislike");
    pub const Laugh: Self = Self("laugh");
    pub const Fire: Self = Self("fire");
    pub const Coffin: Self = Self("coffin");
    pub const Hundred: Self = Self("hundred");
    pub const Horror: Self = Self("horror");

    /// Its name in the protocol.
    pub fn name(self) -> &'static str {
        self.0
    }

    /// The reaction with this name, if a set that is a reaction has it.
    pub fn from_name(name: &str) -> Option<Self> {
        crate::stickers::SETS
            .iter()
            .filter(|set| set.reactions)
            .flat_map(|set| set.stickers)
            .find(|sticker| sticker.id == name)
            .map(|sticker| Self(sticker.id))
    }
}

impl Serialize for ReactionKind {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for ReactionKind {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::from_name(&name).ok_or_else(|| serde::de::Error::custom("unknown reaction"))
    }
}

/// A stored reaction this version no longer knows reads as none, so the
/// rest of the state still loads.
pub fn known_reaction<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<ReactionKind>, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    Ok(name.and_then(|name| ReactionKind::from_name(&name)))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionFields {
    #[serde(rename = "messageID")]
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<ReactionKind>,
}
impl ControlFields for ReactionFields {
    const TTL: i64 = DAY_MS;
    fn validate(&self) -> Result<()> {
        if uuid(&self.message_id) {
            Ok(())
        } else {
            Err(Error::Invalid("message UUID"))
        }
    }
}
pub type Reaction = Control<ReactionFields>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    #[serde(rename = "envelopeID")]
    pub envelope_id: String,
    pub digest: String,
    pub sender: Card,
    pub destination: Card,
    pub read: bool,
    pub timestamp: i64,
    pub expires_at: i64,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
}
impl Receipt {
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.envelope_id, self.digest, self.sender.id())
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut v = self.clone();
        v.signature.clear();
        canonical::encode(&v)
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.sender.validate()?;
        self.destination.validate()?;
        if !uuid(&self.envelope_id)
            || self.digest.graphemes(true).count() != 64
            || self.timestamp < 0
            || self.timestamp > now.saturating_add(300_000)
            || self.expires_at <= now
            || self.expires_at > now.saturating_add(86_700_000)
            || !crypto::verify_ed(
                &self.sender.signing_key,
                &self.signature,
                &self.signing_bytes()?,
            )
        {
            return Err(Error::Invalid("receipt"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSync {
    pub sender: Card,
    #[serde(rename = "recipientID")]
    pub recipient_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_recipient: Option<Card>,
    pub requests_reply: bool,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
}
impl ProfileSync {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut v = self.clone();
        v.signature.clear();
        let mut b = b"shum.profile-sync.v1\0".to_vec();
        b.extend(canonical::encode(&v)?);
        Ok(b)
    }
    pub fn validate(&self) -> Result<()> {
        self.sender.validate()?;
        if self.sender.profile_revision.is_none()
            || !crypto::verify_ed(
                &self.sender.signing_key,
                &self.signature,
                &self.signing_bytes()?,
            )
        {
            return Err(Error::Authentication);
        }
        if let Some(c) = &self.known_recipient {
            c.validate()?;
            if c.id() != self.recipient_id {
                return Err(Error::Invalid("known recipient"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationAvatar {
    #[serde(with = "canonical::bytes")]
    pub data: Vec<u8>,
    #[serde(with = "canonical::bytes")]
    pub signature: Vec<u8>,
}
/// Checks a reaction or retract this profile sent from another of its
/// devices: signed by this profile, for one of its contacts.
pub fn validate_own<T: ControlFields>(control: &Control<T>, own: &Card, now: i64) -> Result<()> {
    if control.sender.id() != own.id() || control.sender.signing_key != own.signing_key {
        return Err(Error::Invalid("own control sender"));
    }
    control.validate(now)
}
/// A message this profile sent from another of its devices: the envelope
/// the contact got, and its text, which the envelope hides from everyone but
/// the contact. It travels only to the profile's own Nostr key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnCopy {
    pub envelope: Envelope,
    pub plaintext: Plaintext,
}
impl OwnCopy {
    pub fn validate(&self, own: &Card, now: i64) -> Result<()> {
        // The card may have changed since: the same profile, the same key.
        if self.envelope.sender.id() != own.id()
            || self.envelope.sender.signing_key != own.signing_key
        {
            return Err(Error::Invalid("own copy sender"));
        }
        self.envelope.validate(now)?;
        self.plaintext.validate(&self.envelope)
    }
}
/// Messages this profile read on another of its devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnRead {
    #[serde(rename = "messageIDs")]
    pub message_ids: Vec<String>,
}
impl OwnRead {
    pub const MAX: usize = 200;
    pub fn validate(&self) -> Result<()> {
        if self.message_ids.is_empty()
            || self.message_ids.len() > Self::MAX
            || self.message_ids.iter().any(|id| !uuid(id))
        {
            return Err(Error::Invalid("own read"));
        }
        Ok(())
    }
}
/// One page of this profile's state, from another of its devices (protocol
/// section 04.8.1): its own card, and its steps and blocks with contacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnState {
    pub card: Card,
    pub page: i64,
    pub pages: i64,
    pub contacts: Vec<OwnStateContact>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnStateContact {
    pub card: Card,
    pub phase: crate::rules::Phase,
    pub updated_at: i64,
    #[serde(rename = "eventID")]
    pub event_id: String,
    pub blocked: bool,
    pub blocked_at: i64,
}
impl OwnState {
    pub const PAGE: usize = 20;
    pub const MAX_PAGES: i64 = 100;
    pub fn validate(&self, own: &Card) -> Result<()> {
        self.card.validate()?;
        if self.card.noise_key != own.noise_key
            || self.card.signing_key != own.signing_key
            || self.card.nostr_key != own.nostr_key
            || !(1..=Self::MAX_PAGES).contains(&self.pages)
            || !(0..self.pages).contains(&self.page)
            || self.contacts.len() > Self::PAGE
        {
            return Err(Error::Invalid("own state"));
        }
        for c in &self.contacts {
            c.card.validate()?;
            if c.card.id() == own.id()
                || c.event_id.is_empty()
                || c.event_id.len() > 255
                || c.updated_at < 0
                || c.blocked_at < 0
            {
                return Err(Error::Invalid("own state contact"));
            }
        }
        Ok(())
    }
}
/// A chat this profile cleared on another of its devices: everything in it
/// up to `before`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnClear {
    #[serde(rename = "contactID")]
    pub contact_id: String,
    pub before: i64,
}
impl OwnClear {
    pub fn validate(&self) -> Result<()> {
        if self.contact_id.len() != 64
            || !self
                .contact_id
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || self.before <= 0
        {
            return Err(Error::Invalid("own clear"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Packet {
    pub version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<Card>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<InvitationControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_avatar: Option<InvitationAvatar>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typing: Option<Typing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<Presence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_sync: Option<ProfileSync>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retract: Option<Retract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<Reaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_copy: Option<OwnCopy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_read: Option<OwnRead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_reaction: Option<Reaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_retract: Option<Retract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_clear: Option<OwnClear>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_invitation: Option<InvitationControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_state: Option<OwnState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub photo_part: Option<crate::photo::PhotoPart>,
}
impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 24_000 {
            return Err(Error::Invalid("packet size"));
        }
        let packet: Self = serde_json::from_slice(bytes)?;
        let count = [
            packet.card.is_some(),
            packet.envelope.is_some(),
            packet.receipt.is_some(),
            packet.invitation.is_some(),
            packet.typing.is_some(),
            packet.presence.is_some(),
            packet.profile_sync.is_some(),
            packet.retract.is_some(),
            packet.reaction.is_some(),
            packet.own_copy.is_some(),
            packet.own_read.is_some(),
            packet.own_reaction.is_some(),
            packet.own_retract.is_some(),
            packet.own_clear.is_some(),
            packet.own_invitation.is_some(),
            packet.own_state.is_some(),
            packet.photo_part.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count();
        if packet.version != 1 || count != 1 {
            return Err(Error::Invalid("packet kind count"));
        }
        Ok(packet)
    }
}

impl Envelope {
    /// Caller supplies UUID, time, and fresh ephemeral secret. No I/O or RNG.
    pub fn seal(
        sender: Card,
        recipient: Card,
        plaintext: Plaintext,
        noise_key: &crypto::Secret32,
        signing: &crypto::Secret32,
        ephemeral: &crypto::Secret32,
    ) -> Result<Self> {
        if noise_key.noise_public().as_slice() != sender.noise_key
            || signing.ed_public().as_slice() != sender.signing_key
        {
            return Err(Error::Invalid("sender keys"));
        }
        let mut e = Self {
            version: 1,
            id: plaintext.id.clone(),
            conversation_id: plaintext.conversation_id.clone(),
            sender,
            recipient,
            timestamp: plaintext.timestamp,
            expires_at: plaintext.expires_at,
            hop_limit: 4,
            ciphertext: vec![],
            signature: vec![],
        };
        plaintext.validate(&e)?;
        let recipient_key = e
            .recipient
            .noise_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("recipient Noise key"))?;
        e.ciphertext = noise::seal_courier(
            noise_key,
            recipient_key,
            ephemeral,
            &canonical::encode(&plaintext)?,
        )?;
        e.signature = signing.sign(&e.signing_bytes()?).to_vec();
        e.validate(e.timestamp)?;
        Ok(e)
    }
}
impl<T: ControlFields> Control<T> {
    pub fn sign(mut self, key: &crypto::Secret32) -> Result<Self> {
        if key.ed_public().as_slice() != self.sender.signing_key {
            return Err(Error::Invalid("control signing key"));
        }
        self.signature = key.sign(&self.signing_bytes()?).to_vec();
        self.validate(self.timestamp)?;
        Ok(self)
    }
}
impl Receipt {
    pub fn create(
        envelope: &Envelope,
        own: Card,
        key: &crypto::Secret32,
        read: bool,
        now: i64,
    ) -> Result<Self> {
        if own.noise_key != envelope.recipient.noise_key
            || own.signing_key != envelope.recipient.signing_key
            || own.nostr_key != envelope.recipient.nostr_key
            || key.ed_public().as_slice() != own.signing_key
            || envelope.expires_at <= now
        {
            return Err(Error::Invalid("receipt identity or expiry"));
        }
        let mut value = Self {
            envelope_id: envelope.id.clone(),
            digest: envelope.digest(),
            sender: own,
            destination: envelope.sender.clone(),
            read,
            timestamp: now,
            expires_at: envelope.expires_at,
            signature: vec![],
        };
        value.signature = key.sign(&value.signing_bytes()?).to_vec();
        value.validate(now)?;
        Ok(value)
    }
}
impl ProfileSync {
    pub fn sign(mut self, key: &crypto::Secret32) -> Result<Self> {
        if key.ed_public().as_slice() != self.sender.signing_key {
            return Err(Error::Invalid("profile signing key"));
        }
        self.signature = key.sign(&self.signing_bytes()?).to_vec();
        self.validate()?;
        Ok(self)
    }
}
impl InvitationAvatar {
    pub fn signing_bytes(&self, invitation: &InvitationControl) -> Vec<u8> {
        let mut bytes = b"shum.invitation-avatar.v1\0".to_vec();
        bytes.extend(&invitation.signature);
        bytes.extend(&self.data);
        bytes
    }
    /// Only authenticate the protocol attachment. The client decodes and validates
    /// image dimensions/frame count before displaying it. Current iOS ignores it.
    pub fn authenticate(&self, invitation: &InvitationControl) -> bool {
        invitation.fields.action != InvitationAction::Decline
            && !self.data.is_empty()
            && self.data.len() <= 8192
            && crypto::verify_ed(
                &invitation.sender.signing_key,
                &self.signature,
                &self.signing_bytes(invitation),
            )
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            version: 1,
            card: None,
            envelope: None,
            hop_count: None,
            receipt: None,
            invitation: None,
            invitation_avatar: None,
            typing: None,
            presence: None,
            profile_sync: None,
            retract: None,
            reaction: None,
            own_copy: None,
            own_read: None,
            own_reaction: None,
            own_retract: None,
            own_clear: None,
            own_invitation: None,
            own_state: None,
            photo_part: None,
        }
    }
}
