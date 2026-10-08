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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReactionKind {
    Heart,
    Like,
    Dislike,
    Laugh,
    Fire,
    Coffin,
    Hundred,
    Horror,
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
        }
    }
}
