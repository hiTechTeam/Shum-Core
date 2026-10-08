//! Initial Swift/Kotlin boundary. Only protocol data and caller-supplied inputs;
//! no raster, storage, clock, RNG, or transport API crosses this boundary.
use crate::{canonical, card::Card, crypto::Secret32, invitation, packet::Packet};
use zeroize::Zeroizing;
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ProtocolError {
    #[error("{message}")]
    Invalid { message: String },
}
impl From<crate::Error> for ProtocolError {
    fn from(e: crate::Error) -> Self {
        Self::Invalid {
            message: e.to_string(),
        }
    }
}
impl From<serde_json::Error> for ProtocolError {
    fn from(e: serde_json::Error) -> Self {
        Self::Invalid {
            message: e.to_string(),
        }
    }
}
#[derive(uniffi::Record)]
pub struct ValidatedCard {
    pub id: String,
    pub name: String,
    pub profile_id: Option<String>,
    pub canonical_json: Vec<u8>,
}
#[uniffi::export]
pub fn validate_card(json: Vec<u8>) -> Result<ValidatedCard, ProtocolError> {
    let c: Card = serde_json::from_slice(&json)?;
    c.validate()?;
    Ok(ValidatedCard {
        id: c.id(),
        name: c.name.clone(),
        profile_id: c.profile_revision.map(|_| c.profile_id()).transpose()?,
        canonical_json: canonical::encode(&c)?,
    })
}
#[uniffi::export]
pub fn parse_invitation(value: String) -> Result<ValidatedCard, ProtocolError> {
    match invitation::parse(&value)? {
        invitation::Invitation::Card(c) => validate_card(canonical::encode(&*c)?),
        invitation::Invitation::Locator(_) => Err(ProtocolError::Invalid {
            message: "locator requires transport lookup".into(),
        }),
    }
}
#[uniffi::export]
pub fn canonical_packet(json: Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
    Ok(canonical::encode(&Packet::decode(&json)?)?)
}
#[uniffi::export]
pub fn open_envelope(
    json: Vec<u8>,
    recipient_secret: Vec<u8>,
    now_ms: i64,
) -> Result<Vec<u8>, ProtocolError> {
    let secret = Zeroizing::new(recipient_secret);
    let key = Secret32::new(
        secret
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::Invalid {
                message: "32-byte Noise key required".into(),
            })?,
    );
    let envelope: crate::packet::Envelope = serde_json::from_slice(&json)?;
    Ok(canonical::encode(&envelope.open(&key, now_ms)?)?)
}
