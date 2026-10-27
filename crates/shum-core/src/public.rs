//! The open chat with everyone nearby: signed Bluetooth broadcasts that the
//! whole mesh relays. Each carries its sender's card, so people several hops
//! away, with no session to the sender, still see who wrote and can trust it.
use crate::{
    canonical,
    card::Card,
    packet::{ReactionKind, Reply},
    wire, Error, Result,
};
use serde::{Deserialize, Serialize};

/// Bluetooth frame type of a public event. Earlier versions skip unknown
/// types but still relay broadcasts, so they carry events they cannot read.
pub const FRAME_KIND: u8 = 0x30;
/// Longest text in bytes; an event with its card stays a few fragments long.
pub const MAX_TEXT: usize = 2000;
/// Longest quoted excerpt in bytes.
const MAX_QUOTE: usize = 500;

/// What happened in the open chat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PublicBody {
    /// A note, maybe quoting an earlier one.
    Note {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply: Option<Reply>,
    },
    /// The sender's one reaction on a note; none takes it back.
    Reaction {
        #[serde(rename = "noteID")]
        note_id: String,
        #[serde(rename = "authorID")]
        author_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reaction: Option<ReactionKind>,
    },
    /// The sender withdraws one of their own notes.
    Retract {
        #[serde(rename = "noteID")]
        note_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEvent {
    pub version: i64,
    pub id: String,
    pub card: Card,
    #[serde(flatten)]
    pub body: PublicBody,
}

fn short_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128
}

impl PublicEvent {
    pub fn new(id: String, body: PublicBody, card: Card) -> Result<Self> {
        let event = Self {
            version: 1,
            id,
            card,
            body,
        };
        event.check()?;
        Ok(event)
    }

    fn check(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Invalid("public event version"));
        }
        if !short_id(&self.id) {
            return Err(Error::Invalid("public event id"));
        }
        let valid = match &self.body {
            PublicBody::Note { text, reply } => {
                !crate::card::trim(text).is_empty()
                    && text.len() <= MAX_TEXT
                    && reply.as_ref().is_none_or(|r| {
                        short_id(&r.message_id)
                            && short_id(&r.sender_id)
                            && r.text.len() <= MAX_QUOTE
                    })
            }
            PublicBody::Reaction {
                note_id, author_id, ..
            } => short_id(note_id) && short_id(author_id),
            PublicBody::Retract { note_id } => short_id(note_id),
        };
        if !valid {
            return Err(Error::Invalid("public event body"));
        }
        self.card.validate()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        canonical::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8000 {
            return Err(Error::Invalid("public event size"));
        }
        let event: Self = serde_json::from_slice(bytes)?;
        event.check()?;
        Ok(event)
    }

    /// The frame came from the card's own device and its owner signed it.
    pub fn verify(&self, frame: &wire::Frame) -> Result<bool> {
        let noise: [u8; 32] = self
            .card
            .noise_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("public event Noise key"))?;
        Ok(frame.kind == FRAME_KIND
            && frame.sender.as_slice() == wire::routing_id(&noise).as_slice()
            && frame.verify(&self.card.signing_key)?)
    }
}
