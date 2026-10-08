//! Exact spec/08 bytes, with fresh authentication for every HTTP retry.
use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use shum_core::{
    canonical,
    card::Card,
    crypto::{sha256, Secret32},
    queue::PushKind,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct SignedRequest {
    pub body: Vec<u8>,
    pub public_key: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub signing_bytes: Vec<u8>,
}
pub fn signed_request(
    method: &str,
    path: &str,
    body: Vec<u8>,
    key: &Secret32,
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest> {
    if body.len() > 16384
        || !matches!(method, "POST" | "DELETE")
        || !matches!(path, "/v1/devices" | "/v1/notifications")
        || !(16..=128).contains(&nonce.len())
        || !nonce.bytes().all(|b| b.is_ascii_graphic())
        || timestamp < 0
    {
        return Err(Error::Configuration);
    }
    let timestamp = timestamp.to_string();
    let signing_bytes = format!(
        "SHUM1\n{method}\n{path}\n{timestamp}\n{nonce}\n{}",
        hex::encode(sha256(&body))
    )
    .into_bytes();
    Ok(SignedRequest {
        body,
        public_key: URL_SAFE_NO_PAD.encode(key.ed_public()),
        timestamp,
        nonce: nonce.into(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&signing_bytes)),
        signing_bytes,
    })
}
pub fn card_dto(card: &Card) -> Result<serde_json::Value> {
    card.validate()?;
    Ok(
        json!({"version":card.version,"noise_key":URL_SAFE_NO_PAD.encode(&card.noise_key),"signing_key":URL_SAFE_NO_PAD.encode(&card.signing_key),"nostr_key":card.nostr_key,"name":card.name,"bio":card.bio,"signature":URL_SAFE_NO_PAD.encode(&card.signature)}),
    )
}
pub fn notification_body(
    card: &Card,
    recipient: &str,
    event: &str,
    kind: PushKind,
) -> Result<Vec<u8>> {
    if recipient.len() != 64
        || !recipient
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !(16..=64).contains(&event.len())
        || !event
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error::Configuration);
    }
    Ok(canonical::encode(
        &json!({"card":card_dto(card)?,"recipient_id":recipient,"event_id":event,"kind":kind}),
    )?)
}
#[derive(Clone)]
pub struct PushClient {
    client: reqwest::Client,
    base: url::Url,
}
impl PushClient {
    pub fn new(base: &str) -> Result<Self> {
        let base = url::Url::parse(base).map_err(|_| Error::Configuration)?;
        let local = base.scheme() == "http"
            && matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if (base.scheme() != "https" && !local)
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(Error::Configuration);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client, base })
    }
    /// Caller owns deduplication/cancellation per Shum event ID.
    pub async fn notify(
        &self,
        card: &Card,
        key: &Secret32,
        recipient: &str,
        event: &str,
        kind: PushKind,
    ) -> Result<()> {
        if card.signing_key != key.ed_public().as_slice() {
            return Err(Error::Configuration);
        }
        let body = notification_body(card, recipient, event, kind)?;
        let mut last_status = None;
        for delay in [0, 2, 5, 15, 30, 60] {
            if delay > 0 {
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Configuration)?
                .as_secs() as i64;
            let mut bytes = [0; 16];
            getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
            let nonce = hex::encode(bytes);
            let signed = signed_request(
                "POST",
                "/v1/notifications",
                body.clone(),
                key,
                timestamp,
                &nonce,
            )?;
            let url = self
                .base
                .join("/v1/notifications")
                .map_err(|_| Error::Configuration)?;
            let response = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header("X-Shum-Public-Key", signed.public_key)
                .header("X-Shum-Timestamp", signed.timestamp)
                .header("X-Shum-Nonce", signed.nonce)
                .header("X-Shum-Signature", signed.signature)
                .body(signed.body)
                .send()
                .await;
            match response {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    last_status = Some(status.as_u16());
                    if status.is_client_error() && status.as_u16() != 429 {
                        return Err(Error::HttpStatus(status.as_u16()));
                    }
                }
                Err(_) => continue,
            }
        }
        Err(last_status.map_or(Error::Publication, Error::HttpStatus))
    }
}
