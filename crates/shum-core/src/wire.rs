//! Bitchat binary wire format. No adapter, radio, or UI dependencies.
use crate::{canonical, crypto, Error, Result};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const SERVICE_UUID: &str = "F85FC602-7866-4F4C-90AB-4F14E107792B";
pub const CHARACTERISTIC_UUID: &str = "8F85918D-468D-4FBE-825A-CBD890B74D10";
// Shum frames are small; larger Bitchat file transfers are outside this API.
pub const MAX_FRAME: usize = 1_000_000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    pub version: u8,
    #[serde(rename = "type")]
    pub kind: u8,
    pub ttl: u8,
    pub timestamp: u64,
    #[serde(rename = "senderID", with = "canonical::bytes")]
    pub sender: Vec<u8>,
    #[serde(
        rename = "recipientID",
        default,
        skip_serializing_if = "Option::is_none",
        with = "canonical::optional_bytes"
    )]
    pub recipient: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "route_bytes")]
    pub route: Option<Vec<Vec<u8>>>,
    #[serde(with = "canonical::bytes")]
    pub payload: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "canonical::optional_bytes"
    )]
    pub signature: Option<Vec<u8>>,
    #[serde(rename = "isRSR")]
    pub is_rsr: bool,
}
fn id8(input: &[u8]) -> [u8; 8] {
    let mut result = [0; 8];
    let len = input.len().min(8);
    result[..len].copy_from_slice(&input[..len]);
    result
}
pub fn routing_id(noise: &[u8; 32]) -> [u8; 8] {
    crypto::sha256(noise)[..8].try_into().expect("fixed length")
}
fn compress(payload: &[u8]) -> Result<Option<Vec<u8>>> {
    if payload.len() < 100 {
        return Ok(None);
    }
    let mut seen = [false; 256];
    for byte in payload {
        seen[usize::from(*byte)] = true;
    }
    if seen.iter().filter(|v| **v).count() as f64 / payload.len().min(256) as f64 >= 0.9 {
        return Ok(None);
    }
    let mut output = Vec::with_capacity(payload.len() + 128);
    let status = Compress::new(Compression::default(), false)
        .compress_vec(payload, &mut output, FlushCompress::Finish)
        .map_err(|_| Error::Invalid("DEFLATE"))?;
    if status == Status::StreamEnd && output.len() < payload.len() {
        Ok(Some(output))
    } else {
        Ok(None)
    }
}
fn pad(bytes: &mut Vec<u8>) {
    let target = [256, 512, 1024, 2048]
        .into_iter()
        .find(|n| *n >= bytes.len() + 16)
        .unwrap_or(bytes.len());
    let count = target - bytes.len();
    if (1..=255).contains(&count) {
        bytes.resize(target, count as u8);
    }
}
impl Frame {
    pub fn encode(&self, padding: bool) -> Result<Vec<u8>> {
        if ![1, 2].contains(&self.version)
            || self.payload.len() > MAX_FRAME
            || self.signature.as_ref().is_some_and(|v| v.len() != 64)
        {
            return Err(Error::Invalid("binary frame"));
        }
        let route = self
            .route
            .as_ref()
            .filter(|v| self.version == 2 && !v.is_empty());
        if route.is_some_and(|v| v.len() > 255 || v.iter().any(Vec::is_empty)) {
            return Err(Error::Invalid("route"));
        }
        let compressed = compress(&self.payload)?;
        let mut payload = Vec::new();
        if let Some(data) = &compressed {
            if self.version == 1 {
                payload.extend(
                    u16::try_from(self.payload.len())
                        .map_err(|_| Error::Invalid("v1 payload size"))?
                        .to_be_bytes(),
                );
            } else {
                payload.extend((self.payload.len() as u32).to_be_bytes());
            }
            payload.extend(data);
        } else {
            payload.extend(&self.payload);
        }
        let mut out = vec![self.version, self.kind, self.ttl];
        out.extend(self.timestamp.to_be_bytes());
        out.push(
            u8::from(self.recipient.is_some())
                | (u8::from(self.signature.is_some()) << 1)
                | (u8::from(compressed.is_some()) << 2)
                | (u8::from(route.is_some()) << 3)
                | (u8::from(self.is_rsr) << 4),
        );
        if self.version == 1 {
            out.extend(
                u16::try_from(payload.len())
                    .map_err(|_| Error::Invalid("v1 payload size"))?
                    .to_be_bytes(),
            );
        } else {
            out.extend((payload.len() as u32).to_be_bytes());
        }
        out.extend(id8(&self.sender));
        if let Some(recipient) = &self.recipient {
            out.extend(id8(recipient));
        }
        if let Some(route) = route {
            out.push(route.len() as u8);
            for hop in route {
                out.extend(id8(hop));
            }
        }
        out.extend(payload);
        if let Some(signature) = &self.signature {
            out.extend(signature);
        }
        if padding {
            pad(&mut out);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid("frame size"));
        }
        let mut r = Reader(bytes);
        let version = r.byte()?;
        if ![1, 2].contains(&version) {
            return Err(Error::Invalid("frame version"));
        }
        let kind = r.byte()?;
        let ttl = r.byte()?;
        let timestamp = u64::from_be_bytes(r.take(8)?.try_into().expect("fixed length"));
        let flags = r.byte()?;
        let length = r.size(version)?;
        let sender = r.take(8)?.to_vec();
        let recipient = if flags & 1 != 0 {
            Some(r.take(8)?.to_vec())
        } else {
            None
        };
        let route = if version == 2 && flags & 8 != 0 {
            let count = r.byte()?;
            Some(
                (0..count)
                    .map(|_| r.take(8).map(<[u8]>::to_vec))
                    .collect::<Result<_>>()?,
            )
        } else {
            None
        };
        let wire = r.take(length)?;
        let payload = if flags & 4 == 0 {
            wire.to_vec()
        } else {
            let mut cr = Reader(wire);
            let size = cr.size(version)?;
            if size > MAX_FRAME || cr.0.is_empty() || size / cr.0.len() > 50_000 {
                return Err(Error::Invalid("DEFLATE size"));
            }
            let mut decoder = Decompress::new(false);
            let mut result = vec![0; size];
            let status = decoder
                .decompress(cr.0, &mut result, FlushDecompress::Finish)
                .map_err(|_| Error::Invalid("DEFLATE"))?;
            if status != Status::StreamEnd || decoder.total_out() != size as u64 {
                return Err(Error::Invalid("DEFLATE length"));
            }
            result
        };
        let signature = if flags & 2 != 0 {
            Some(r.take(64)?.to_vec())
        } else {
            None
        };
        Ok(Self {
            version,
            kind,
            ttl,
            timestamp,
            sender,
            recipient,
            route,
            payload,
            signature,
            is_rsr: flags & 16 != 0,
        })
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.ttl = 0;
        unsigned.is_rsr = false;
        unsigned.encode(true)
    }
    pub fn verify(&self, key: &[u8]) -> Result<bool> {
        Ok(self.signature.as_ref().is_some_and(|sig| {
            self.signing_bytes()
                .is_ok_and(|b| crypto::verify_ed(key, sig, &b))
        }))
    }
    pub fn broadcast(&self) -> bool {
        self.recipient.as_ref().is_none_or(|v| id8(v) == [255; 8])
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.0.len() {
            return Err(Error::Invalid("truncated frame"));
        }
        let (result, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn size(&mut self, version: u8) -> Result<usize> {
        Ok(if version == 1 {
            u16::from_be_bytes(self.take(2)?.try_into().expect("fixed length")) as usize
        } else {
            u32::from_be_bytes(self.take(4)?.try_into().expect("fixed length")) as usize
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub nickname: String,
    pub noise: [u8; 32],
    pub signing: [u8; 32],
    pub neighbors: Vec<[u8; 8]>,
    pub capabilities: Option<u64>,
    pub geohash: Option<String>,
}
fn tlvs(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut r = Reader(bytes);
    let mut result = vec![];
    while !r.0.is_empty() {
        let kind = r.byte()?;
        let count = r.byte()? as usize;
        result.push((kind, r.take(count)?));
    }
    Ok(result)
}
fn uint_le(bytes: &[u8], canonical: bool) -> Result<u64> {
    if bytes.is_empty()
        || bytes.len() > 8
        || (canonical && bytes.len() > 1 && bytes.last() == Some(&0))
    {
        return Err(Error::Invalid("capabilities"));
    }
    let mut data = [0; 8];
    data[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(data))
}
fn put_tlv(output: &mut Vec<u8>, kind: u8, bytes: &[u8]) -> Result<()> {
    output.push(kind);
    output.push(u8::try_from(bytes.len()).map_err(|_| Error::Invalid("TLV size"))?);
    output.extend(bytes);
    Ok(())
}
fn min_le(value: u64) -> Vec<u8> {
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.len() > 1 && bytes.last() == Some(&0) {
        bytes.pop();
    }
    bytes
}
impl Announcement {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (mut name, mut noise, mut signing) = (None, None, None);
        let (mut neighbors, mut capabilities, mut geohash) = (vec![], None, None);
        for (kind, data) in tlvs(bytes)? {
            match kind {
                1 => {
                    name = Some(
                        std::str::from_utf8(data)
                            .map_err(|_| Error::Invalid("nickname UTF-8"))?
                            .to_owned(),
                    )
                }
                2 => {
                    noise = Some(
                        data.try_into()
                            .map_err(|_| Error::Invalid("announce Noise key"))?,
                    )
                }
                3 => {
                    signing = Some(
                        data.try_into()
                            .map_err(|_| Error::Invalid("announce signing key"))?,
                    )
                }
                4 if data.len().is_multiple_of(8) => {
                    neighbors = data.as_chunks::<8>().0.iter().take(10).copied().collect()
                }
                5 => capabilities = Some(uint_le(data, false)?),
                6 if (1..=12).contains(&data.len()) => {
                    geohash = Some(
                        std::str::from_utf8(data)
                            .map_err(|_| Error::Invalid("geohash UTF-8"))?
                            .to_owned(),
                    )
                }
                _ => (),
            }
        }
        Ok(Self {
            nickname: name.ok_or(Error::Invalid("announce nickname"))?,
            noise: noise.ok_or(Error::Invalid("announce Noise"))?,
            signing: signing.ok_or(Error::Invalid("announce signing"))?,
            neighbors,
            capabilities,
            geohash,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![];
        put_tlv(&mut out, 1, self.nickname.as_bytes())?;
        put_tlv(&mut out, 2, &self.noise)?;
        put_tlv(&mut out, 3, &self.signing)?;
        if !self.neighbors.is_empty() {
            put_tlv(
                &mut out,
                4,
                &self
                    .neighbors
                    .iter()
                    .take(10)
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>(),
            )?;
        }
        if let Some(caps) = self.capabilities {
            put_tlv(&mut out, 5, &min_le(caps))?;
        }
        if let Some(hash) = &self.geohash {
            if !(1..=12).contains(&hash.len()) {
                return Err(Error::Invalid("geohash"));
            }
            put_tlv(&mut out, 6, hash.as_bytes())?;
        }
        Ok(out)
    }
    pub fn verify(&self, frame: &Frame) -> Result<bool> {
        Ok(frame.kind == 1
            && id8(&frame.sender) == routing_id(&self.noise)
            && frame.verify(&self.signing)?)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeerState {
    pub capabilities: Option<u64>,
    pub signing: Option<[u8; 32]>,
}
impl AuthenticatedPeerState {
    /// Decode the body after Noise payload type 0x21.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.first() != Some(&1) {
            return Err(Error::Invalid("peer state version"));
        }
        let mut result = Self {
            capabilities: None,
            signing: None,
        };
        for (kind, data) in tlvs(&bytes[1..])? {
            match kind {
                1 if result.capabilities.is_none() => {
                    result.capabilities = Some(uint_le(data, true)?)
                }
                2 if result.signing.is_none() => {
                    result.signing = Some(
                        data.try_into()
                            .map_err(|_| Error::Invalid("peer state signing key"))?,
                    )
                }
                1 | 2 => return Err(Error::Invalid("duplicate peer state TLV")),
                _ => (),
            }
        }
        Ok(result)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![1];
        if let Some(caps) = self.capabilities {
            put_tlv(&mut out, 1, &min_le(caps))?;
        }
        if let Some(key) = self.signing {
            put_tlv(&mut out, 2, &key)?;
        }
        Ok(out)
    }
}

pub fn fragments(
    frame: &Frame,
    fragment_id: [u8; 8],
    chunk_size: usize,
    padding: bool,
) -> Result<Vec<Frame>> {
    let bytes = frame.encode(padding)?;
    let chunk_size = chunk_size.max(64);
    let total = bytes.len().div_ceil(chunk_size);
    if total > 10_000 {
        return Err(Error::Invalid("fragment count"));
    }
    bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let mut f = frame.clone();
            f.kind = 0x20;
            f.signature = None;
            f.version = if f.route.as_ref().is_some_and(|r| !r.is_empty()) {
                2
            } else {
                1
            };
            f.payload = fragment_id.to_vec();
            f.payload.extend((index as u16).to_be_bytes());
            f.payload.extend((total as u16).to_be_bytes());
            f.payload.push(frame.kind);
            f.payload.extend(chunk);
            Ok(f)
        })
        .collect()
}
struct Assembly {
    started: i64,
    total: u16,
    chunks: HashMap<u16, Vec<u8>>,
}
#[derive(Default)]
pub struct Assemblies {
    streams: HashMap<([u8; 8], [u8; 8]), Assembly>,
}
impl Assemblies {
    pub fn ingest(&mut self, frame: &Frame, now: i64) -> Result<Option<Frame>> {
        self.streams
            .retain(|_, v| now.saturating_sub(v.started) < 30_000);
        if frame.kind != 0x20 || frame.payload.len() < 13 {
            return Err(Error::Invalid("fragment header"));
        }
        let bytes = &frame.payload;
        let key = (
            id8(&frame.sender),
            bytes[..8].try_into().expect("fixed length"),
        );
        let index = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed length"));
        let total = u16::from_be_bytes(bytes[10..12].try_into().expect("fixed length"));
        if total == 0 || total > 10_000 || index >= total {
            return Err(Error::Invalid("fragment index"));
        }
        if !self.streams.contains_key(&key) && self.streams.len() >= 128 {
            if let Some(oldest) = self
                .streams
                .iter()
                .min_by_key(|(_, a)| a.started)
                .map(|(k, _)| *k)
            {
                self.streams.remove(&oldest);
            }
        }
        let assembly = self.streams.entry(key).or_insert_with(|| Assembly {
            started: now,
            total,
            chunks: HashMap::new(),
        });
        assembly.chunks.insert(index, bytes[13..].to_vec());
        if assembly.chunks.values().map(Vec::len).sum::<usize>() > MAX_FRAME {
            self.streams.remove(&key);
            return Err(Error::Invalid("assembly size"));
        }
        if (0..assembly.total).any(|i| !assembly.chunks.contains_key(&i)) {
            return Ok(None);
        }
        let assembly = self.streams.remove(&key).expect("assembly exists");
        let bytes: Vec<_> = (0..assembly.total)
            .flat_map(|i| assembly.chunks[&i].iter().copied())
            .collect();
        Frame::decode(&bytes).map(Some)
    }
}

mod route_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<Vec<Vec<u8>>>, s: S) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|v| v.iter().map(|b| STANDARD.encode(b)).collect::<Vec<_>>())
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<Vec<u8>>>, D::Error> {
        Option::<Vec<String>>::deserialize(d)?
            .map(|v| {
                v.iter()
                    .map(|b| STANDARD.decode(b).map_err(serde::de::Error::custom))
                    .collect()
            })
            .transpose()
    }
}
