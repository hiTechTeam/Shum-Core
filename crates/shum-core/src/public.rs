//! The open chat with everyone nearby: a signed Bluetooth broadcast that the
//! whole mesh relays. It carries the sender's card, so people several hops
//! away, with no session to the sender, still see who wrote and can trust it.
use crate::{canonical, card::Card, wire, Error, Result};
use serde::{Deserialize, Serialize};

/// Bluetooth frame type of a public note. Earlier versions skip unknown
/// types but still relay broadcasts, so they carry notes they cannot read.
pub const FRAME_KIND: u8 = 0x30;
/// Longest text in bytes; a note with its card stays a few fragments long.
pub const MAX_TEXT: usize = 2000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicNote {
    pub version: i64,
    pub id: String,
    pub text: String,
    pub card: Card,
}

impl PublicNote {
    pub fn new(id: String, text: String, card: Card) -> Result<Self> {
        let note = Self {
            version: 1,
            id,
            text,
            card,
        };
        note.check()?;
        Ok(note)
    }

    fn check(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Invalid("public note version"));
        }
        if self.id.is_empty() || self.id.len() > 64 {
            return Err(Error::Invalid("public note id"));
        }
        if crate::card::trim(&self.text).is_empty() || self.text.len() > MAX_TEXT {
            return Err(Error::Invalid("public note text"));
        }
        self.card.validate()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        canonical::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8000 {
            return Err(Error::Invalid("public note size"));
        }
        let note: Self = serde_json::from_slice(bytes)?;
        note.check()?;
        Ok(note)
    }

    /// The frame came from the card's own device and its owner signed it.
    pub fn verify(&self, frame: &wire::Frame) -> Result<bool> {
        let noise: [u8; 32] = self
            .card
            .noise_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("public note Noise key"))?;
        Ok(frame.kind == FRAME_KIND
            && frame.sender.as_slice() == wire::routing_id(&noise).as_slice()
            && frame.verify(&self.card.signing_key)?)
    }
}
