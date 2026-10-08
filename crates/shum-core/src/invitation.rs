use crate::{card::Card, Error, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use url::Url;

#[derive(Debug, PartialEq, Eq)]
pub enum Invitation {
    Card(Box<Card>),
    Locator(String),
}

pub fn decode_url_base64(text: &str) -> Result<Vec<u8>> {
    let mut standard = text.replace('-', "+").replace('_', "/");
    while !standard.len().is_multiple_of(4) {
        standard.push('=');
    }
    STANDARD
        .decode(standard)
        .map_err(|_| Error::Invalid("base64url"))
}

pub fn parse(text: &str) -> Result<Invitation> {
    if text.len() > 4096 {
        return Err(Error::Invalid("invitation size"));
    }
    let url = Url::parse(text).map_err(|_| Error::Invalid("invitation URL"))?;
    if url.scheme() == "https" && url.path() == "/invite" {
        let fragment = url
            .fragment()
            .ok_or(Error::Invalid("invitation fragment"))?;
        // A direct shum URL cannot recurse into the HTTPS case.
        return parse(&format!("shum://{fragment}"));
    }
    if url.scheme() != "shum" {
        return Err(Error::Invalid("invitation scheme"));
    }
    let host = url.host_str().ok_or(Error::Invalid("invitation host"))?;
    if host == "contact" {
        let value = url
            .query_pairs()
            .find(|(k, _)| k == "data")
            .ok_or(Error::Invalid("invitation query"))?
            .1;
        let bytes = STANDARD
            .decode(value.as_bytes())
            .map_err(|_| Error::Invalid("invitation JSON base64"))?;
        if bytes.len() > 2048 {
            return Err(Error::Invalid("invitation JSON size"));
        }
        let card: Card = serde_json::from_slice(&bytes)?;
        card.validate()?;
        return Ok(Invitation::Card(Box::new(card)));
    }
    let path = url.path().trim_matches('/');
    if host == "c2" {
        if path.len() != 43 {
            return Err(Error::Invalid("locator length"));
        }
        let key = decode_url_base64(path)?;
        if key.len() != 32 {
            return Err(Error::Invalid("locator key"));
        }
        return Ok(Invitation::Locator(hex::encode(key)));
    }
    let expected = match host {
        "c" => 1,
        "c3" => 3,
        "c4" => 4,
        _ => return Err(Error::Invalid("invitation host")),
    };
    if path.is_empty() || path.len() > 2048 {
        return Err(Error::Invalid("invitation length"));
    }
    let bytes = decode_url_base64(path)?;
    if bytes.len() > 1536 {
        return Err(Error::Invalid("invitation binary size"));
    }
    let mut r = Reader(&bytes);
    let format = r.byte()?;
    if format != expected {
        return Err(Error::Invalid("invitation format"));
    }
    let version = i64::from(r.byte()?);
    let noise_key = r.read(32)?.to_vec();
    let signing_key = r.read(32)?.to_vec();
    let nostr_key = hex::encode(r.read(32)?);
    let n = usize::from(r.byte()?);
    let name = r.text(n)?;
    let n = usize::from(u16::from_be_bytes(
        r.read(2)?.try_into().expect("fixed size"),
    ));
    let bio = r.text(n)?;
    let signature = if format == 4 {
        vec![]
    } else {
        r.read(64)?.to_vec()
    };
    let (avatar_seed, avatar_version, profile_revision, avatar_seed_signature, profile_signature) =
        if format != 1 {
            (
                Some(r.integer()?),
                Some(i64::from(r.byte()?)),
                Some(r.integer()?),
                if format == 3 {
                    Some(r.read(64)?.to_vec())
                } else {
                    None
                },
                Some(r.read(64)?.to_vec()),
            )
        } else {
            (None, None, None, None, None)
        };
    if !r.0.is_empty() {
        return Err(Error::Invalid("invitation trailing bytes"));
    }
    let card = Card {
        version,
        noise_key,
        signing_key,
        nostr_key,
        name,
        bio,
        signature,
        avatar_seed,
        avatar_version,
        profile_revision,
        avatar_seed_signature,
        profile_signature,
    };
    card.validate()?;
    Ok(Invitation::Card(Box::new(card)))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn read(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.0.len() {
            return Err(Error::Invalid("truncated invitation"));
        }
        let (data, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(data)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }
    fn integer(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.read(8)?.try_into().expect("fixed size"),
        ))
    }
    fn text(&mut self, count: usize) -> Result<String> {
        String::from_utf8(self.read(count)?.to_vec()).map_err(|_| Error::Invalid("invitation UTF8"))
    }
}

impl Card {
    pub fn invitation(&self) -> Result<String> {
        self.validate()?;
        let modern = self.avatar_seed.is_some()
            && self.avatar_version.is_some()
            && self.profile_revision.is_some()
            && self.profile_signature.is_some();
        let mut data = vec![if modern { 4 } else { 1 }, 1];
        data.extend(&self.noise_key);
        data.extend(&self.signing_key);
        data.extend(hex::decode(&self.nostr_key).map_err(|_| Error::Invalid("nostr hex"))?);
        data.push(self.name.len() as u8);
        data.extend(self.name.as_bytes());
        data.extend((self.bio.len() as u16).to_be_bytes());
        data.extend(self.bio.as_bytes());
        if modern {
            data.extend(self.avatar_seed.expect("modern seed").to_le_bytes());
            data.push(1);
            data.extend(
                self.profile_revision
                    .expect("modern revision")
                    .to_le_bytes(),
            );
            data.extend(self.profile_signature.as_ref().expect("modern signature"));
        } else {
            if self.signature.len() != 64 {
                return Err(Error::Invalid("legacy signature"));
            }
            data.extend(&self.signature);
        }
        Ok(format!(
            "shum://{}/{}",
            if modern { "c4" } else { "c" },
            URL_SAFE_NO_PAD.encode(data)
        ))
    }
}
