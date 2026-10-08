//! Link/session coordination. All wire codecs and cryptography are provided by shum-core.
use anyhow::{ensure, Context, Result};
use shum_core::{
    canonical,
    card::Card,
    crypto::{self, Secret32},
    noise::{HandshakeXX, Role, Session},
    packet::Packet,
    profile::{Kind, Manifest, ProfilePacket},
    wire::{self, Announcement, Assemblies, AuthenticatedPeerState, Frame},
};
use std::collections::{HashMap, HashSet, VecDeque};

pub enum Effect {
    Send {
        link: String,
        frames: Vec<Vec<u8>>,
    },
    Peer {
        routing: String,
        card: Box<Card>,
        noise: [u8; 32],
        distance: Option<u32>,
        direct: bool,
    },
    Gone(String),
    Packet {
        routing: String,
        noise: [u8; 32],
        packet: Box<Packet>,
    },
}
struct Link {
    budget: usize,
    samples: VecDeque<(i64, i16)>,
}
struct Peer {
    announce: Announcement,
    links: HashSet<String>,
    direct: HashSet<String>,
    handshake: Option<(Role, HandshakeXX, i64)>,
    session: Option<Session>,
    card: Option<Card>,
    state_echo: bool,
    first_seen: i64,
    hello: i64,
}
pub struct Mesh {
    own: Card,
    noise: Secret32,
    signing: Secret32,
    id: [u8; 8],
    links: HashMap<String, Link>,
    peers: HashMap<String, Peer>,
    pins: HashMap<String, Card>,
    blocked: HashSet<String>,
    assemblies: Assemblies,
    seen: HashMap<[u8; 32], i64>,
    announce_at: i64,
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}
impl Mesh {
    pub fn new(
        own: Card,
        noise: Secret32,
        signing: Secret32,
        pins: Vec<Card>,
        blocked: HashSet<String>,
    ) -> Result<Self> {
        own.validate()?;
        ensure!(
            own.noise_key == noise.noise_public() && own.signing_key == signing.ed_public(),
            "BLE identity mismatch"
        );
        Ok(Self {
            id: wire::routing_id(&noise.noise_public()),
            own,
            noise,
            signing,
            links: HashMap::new(),
            peers: HashMap::new(),
            pins: pins.into_iter().map(|c| (c.id(), c)).collect(),
            blocked,
            assemblies: Assemblies::default(),
            seen: HashMap::new(),
            announce_at: 0,
        })
    }
    fn frame(&self, kind: u8, payload: Vec<u8>, recipient: Option<Vec<u8>>, now: i64) -> Frame {
        Frame {
            version: 1,
            kind,
            ttl: 7,
            timestamp: now as u64,
            sender: self.id.to_vec(),
            recipient,
            route: None,
            payload,
            signature: None,
            is_rsr: false,
        }
    }
    fn announcement(&self, now: i64) -> Result<Frame> {
        let value = Announcement {
            nickname: self.own.name.clone(),
            noise: self.noise.noise_public(),
            signing: self.signing.ed_public(),
            neighbors: vec![],
            capabilities: Some(0),
            geohash: None,
        };
        let mut frame = self.frame(1, value.encode()?, None, now);
        frame.signature = Some(self.signing.sign(&frame.signing_bytes()?).to_vec());
        Ok(frame)
    }
    fn transmit(&self, link: &str, frame: Frame) -> Result<Effect> {
        let budget = self.links.get(link).context("BLE link disappeared")?.budget;
        let padding = matches!(frame.kind, 0x10 | 0x11);
        let bytes = frame.encode(padding)?;
        let frames = if bytes.len() <= budget {
            vec![bytes]
        } else {
            ensure!(
                budget >= 107,
                "BLE MTU too small for v1 fragments ({budget})"
            );
            wire::fragments(&frame, random()?, budget.saturating_sub(43), padding)?
                .iter()
                .map(|f| f.encode(false))
                .collect::<shum_core::Result<Vec<_>>>()?
        };
        ensure!(
            frames.iter().all(|f| f.len() <= budget),
            "BLE frame exceeds negotiated budget"
        );
        Ok(Effect::Send {
            link: link.into(),
            frames,
        })
    }
    fn to_peer(&self, routing: &str, frame: Frame) -> Result<Effect> {
        let peer = self.peers.get(routing).context("Unknown BLE peer")?;
        let link = peer
            .links
            .iter()
            .filter(|id| self.links.contains_key(*id))
            .min()
            .context("BLE link unavailable")?;
        self.transmit(link, frame)
    }
    pub fn connected(
        &mut self,
        id: String,
        budget: usize,
        rssi: Option<i16>,
        now: i64,
    ) -> Result<Vec<Effect>> {
        ensure!(
            budget >= 107,
            "BLE MTU too small for v1 fragments ({budget})"
        );
        ensure!(
            self.links.len() < 24 || self.links.contains_key(&id),
            "BLE link limit"
        );
        self.links.insert(
            id.clone(),
            Link {
                budget: budget.min(512),
                samples: VecDeque::new(),
            },
        );
        self.rssi(&id, rssi, now);
        Ok(vec![self.transmit(&id, self.announcement(now)?)?])
    }
    pub fn disconnected(&mut self, id: &str) -> Vec<Effect> {
        self.links.remove(id);
        let mut gone = vec![];
        self.peers.retain(|routing, p| {
            p.links.remove(id);
            p.direct.remove(id);
            if p.links.is_empty() {
                gone.push(Effect::Gone(routing.clone()));
                false
            } else {
                true
            }
        });
        gone
    }
    pub fn rssi(&mut self, id: &str, value: Option<i16>, now: i64) {
        if let (Some(link), Some(rssi @ -127..=-1)) = (self.links.get_mut(id), value) {
            link.samples.push_back((now, rssi));
            while link.samples.len() > 30 {
                link.samples.pop_front();
            }
        }
    }
    fn peer_effect(&self, routing: &str, now: i64) -> Option<Effect> {
        let p = self.peers.get(routing)?;
        let session = p.session.as_ref()?;
        let card = p.card.clone()?;
        let mut readings = p
            .direct
            .iter()
            .filter_map(|l| self.links.get(l))
            .flat_map(|l| &l.samples)
            .filter(|(t, _)| now >= *t && now - *t < 30_000)
            .map(|(_, r)| *r)
            .collect::<Vec<_>>();
        readings.sort();
        let distance = readings
            .get(readings.len() / 2)
            .map(|r| 10_f64.powf((-59.0 - f64::from(*r)) / 20.0).round().max(1.0) as u32);
        Some(Effect::Peer {
            routing: routing.into(),
            card: Box::new(card),
            noise: session.remote_static,
            distance,
            direct: !p.direct.is_empty(),
        })
    }
    fn initiate(&mut self, routing: &str, now: i64) -> Result<Effect> {
        let mut h = HandshakeXX::new(
            Role::Initiator,
            Secret32::new(*self.noise.expose()),
            Secret32::new(random()?),
        );
        let payload = h.write(&[])?;
        self.peers
            .get_mut(routing)
            .context("Unknown peer")?
            .handshake = Some((Role::Initiator, h, now));
        self.to_peer(
            routing,
            self.frame(0x10, payload, Some(hex::decode(routing)?), now),
        )
    }
    fn encrypted(&mut self, routing: &str, kind: u8, body: Vec<u8>, now: i64) -> Result<Effect> {
        let mut plain = vec![kind];
        plain.extend(body);
        let p = self.peers.get_mut(routing).context("Unknown peer")?;
        let payload = p
            .session
            .as_mut()
            .context("Noise session not established")?
            .send(&plain)?;
        self.to_peer(
            routing,
            self.frame(0x11, payload, Some(hex::decode(routing)?), now),
        )
    }
    fn state(&mut self, routing: &str, now: i64) -> Result<Effect> {
        let body = AuthenticatedPeerState {
            capabilities: Some(0),
            signing: Some(self.signing.ed_public()),
        }
        .encode()?;
        self.encrypted(routing, 0x21, body, now)
    }
    pub fn send(&mut self, routing: &str, packet: &Packet, now: i64) -> Result<Effect> {
        let body = canonical::encode(packet)?;
        ensure!(body.len() <= 24_000, "Shum BLE packet too large");
        self.encrypted(routing, 0x41, body, now)
    }
    fn hello(&mut self, routing: &str, now: i64) -> Result<Effect> {
        let packet = Packet {
            card: Some(self.own.clone()),
            ..Packet::default()
        };
        self.peers.get_mut(routing).context("Unknown peer")?.hello = now;
        self.send(routing, &packet, now)
    }
    fn finish(&mut self, routing: &str, handshake: HandshakeXX, now: i64) -> Result<Vec<Effect>> {
        let keys = handshake.finish()?;
        let p = self.peers.get_mut(routing).context("Unknown peer")?;
        ensure!(
            keys.remote_static == p.announce.noise
                && hex::encode(wire::routing_id(&keys.remote_static)) == routing,
            "Noise identity mismatch"
        );
        p.session = Some(Session::new(keys));
        p.state_echo = false;
        p.card = None;
        Ok(vec![self.state(routing, now)?, self.hello(routing, now)?])
    }
    pub fn receive(&mut self, link: &str, bytes: &[u8], now: i64) -> Result<Vec<Effect>> {
        ensure!(self.links.contains_key(link), "Unknown link");
        let mut frame = Frame::decode(bytes)?;
        ensure!(
            frame.timestamp.abs_diff(now as u64) <= 120_000 && frame.ttl <= 7,
            "Stale BLE frame"
        );
        if frame.sender == self.id {
            return Ok(vec![]);
        }
        if frame.kind == 0x20 {
            let Some(full) = self.assemblies.ingest(&frame, now)? else {
                return Ok(vec![]);
            };
            frame = full;
        }
        ensure!(
            frame.timestamp.abs_diff(now as u64) <= 120_000 && frame.ttl <= 7,
            "Stale reconstructed frame"
        );
        if frame.kind == 1 {
            ensure!(
                Announcement::decode(&frame.payload)?.verify(&frame)?,
                "Invalid BLE announce signature"
            );
        }
        let routing = hex::encode(&frame.sender);
        let mut normalized = frame.clone();
        normalized.ttl = 0;
        normalized.is_rsr = false;
        let hash = crypto::sha256(&normalized.encode(false)?);
        let duplicate = self.seen.contains_key(&hash);
        // Repeated signed announces still bind a new GATT path or restore a lost
        // peer. All other replays, including encrypted packets, are discarded.
        if duplicate && frame.kind != 1 {
            return Ok(vec![]);
        }
        self.seen.retain(|_, t| now - *t < 120_000);
        if self.seen.len() >= 4096 {
            self.seen.clear();
        }
        self.seen.insert(hash, now);
        let mut effects = vec![];
        // Bitchat mesh TTL is separate from the Shum envelope's courier hopCount.
        if !duplicate
            && frame.ttl > 1
            && (frame.broadcast() || frame.recipient.as_deref() != Some(self.id.as_slice()))
        {
            let mut forwarded = frame.clone();
            forwarded.ttl -= 1;
            for id in self.links.keys().filter(|id| id.as_str() != link) {
                if let Ok(effect) = self.transmit(id, forwarded.clone()) {
                    effects.push(effect);
                }
            }
        }
        if !frame.broadcast() && frame.recipient.as_deref() != Some(self.id.as_slice()) {
            return Ok(effects);
        }
        match frame.kind {
            1 => {
                let announce = Announcement::decode(&frame.payload)?;
                ensure!(announce.verify(&frame)?, "Invalid BLE announce signature");
                let owner = crypto::id(&announce.noise);
                if self.blocked.contains(&owner) {
                    return Ok(effects);
                }
                if let Some(pin) = self.pins.get(&owner) {
                    ensure!(
                        pin.signing_key == announce.signing,
                        "BLE signing key changed"
                    );
                }
                if let Some(peer) = self.peers.get(&routing) {
                    ensure!(
                        peer.announce.noise == announce.noise
                            && peer.announce.signing == announce.signing,
                        "BLE announce identity changed"
                    );
                }
                ensure!(
                    self.peers.len() < 128 || self.peers.contains_key(&routing),
                    "BLE peer limit"
                );
                let p = self.peers.entry(routing.clone()).or_insert_with(|| Peer {
                    announce,
                    links: HashSet::new(),
                    direct: HashSet::new(),
                    handshake: None,
                    session: None,
                    card: None,
                    state_echo: false,
                    first_seen: now,
                    hello: 0,
                });
                p.links.insert(link.into());
                if frame.ttl == 7 {
                    p.direct.insert(link.into());
                }
                if p.session.is_none()
                    && p.handshake.is_none()
                    && self.id.as_slice() < frame.sender.as_slice()
                {
                    effects.push(self.initiate(&routing, now)?);
                }
            }
            0x10 => {
                let p = self
                    .peers
                    .get_mut(&routing)
                    .context("Handshake before signed announce")?;
                if frame.payload.len() == 32 {
                    if p.handshake
                        .as_ref()
                        .is_some_and(|(role, _, _)| *role == Role::Initiator)
                        && self.id.as_slice() < frame.sender.as_slice()
                    {
                        return Ok(effects);
                    }
                    let mut h = HandshakeXX::new(
                        Role::Responder,
                        Secret32::new(*self.noise.expose()),
                        Secret32::new(random()?),
                    );
                    h.read(&frame.payload)?;
                    let payload = h.write(&[])?;
                    p.handshake = Some((Role::Responder, h, now));
                    // Retain an established transport until the replacement proves the same static identity.
                    effects.push(
                        self.to_peer(&routing, self.frame(0x10, payload, Some(frame.sender), now))?,
                    );
                } else {
                    let (role, mut h, _) =
                        p.handshake.take().context("Unexpected handshake frame")?;
                    h.read(&frame.payload)?;
                    if role == Role::Initiator {
                        let payload = h.write(&[])?;
                        effects.push(self.to_peer(
                            &routing,
                            self.frame(0x10, payload, Some(frame.sender), now),
                        )?);
                    }
                    effects.extend(self.finish(&routing, h, now)?);
                }
            }
            0x11 => {
                let p = self
                    .peers
                    .get_mut(&routing)
                    .context("Encrypted packet before announce")?;
                let session = p
                    .session
                    .as_mut()
                    .context("Encrypted packet before Noise")?;
                let noise = session.remote_static;
                let plain = session.receive(&frame.payload)?;
                let (&kind, body) = plain.split_first().context("Empty Noise payload")?;
                match kind {
                    0x21 => {
                        let state = AuthenticatedPeerState::decode(body)?;
                        if let Some(signing) = state.signing {
                            ensure!(
                                signing == p.announce.signing,
                                "Authenticated signing key mismatch"
                            );
                        }
                        if !p.state_echo {
                            p.state_echo = true;
                            effects.push(self.state(&routing, now)?);
                        }
                    }
                    0x41 => {
                        ensure!(body.len() <= 24_000, "Shum BLE body too large");
                        let packet = Packet::decode(body)?;
                        if let Some(card) = &packet.card {
                            card.validate()?;
                            ensure!(
                                card.noise_key == noise && card.signing_key == p.announce.signing,
                                "BLE card identity mismatch"
                            );
                            if let Some(pin) = self.pins.get(&card.id()) {
                                ensure!(
                                    pin.signing_key == card.signing_key
                                        && pin.nostr_key == card.nostr_key,
                                    "BLE pinned card mismatch"
                                );
                            }
                            let mut preferred = card.clone();
                            if let Some(old) = &p.card {
                                preferred = preferred.preferred(old)?.clone();
                            }
                            if let Some(pin) = self.pins.get(&card.id()) {
                                preferred = preferred.preferred(pin)?.clone();
                            }
                            p.card = Some(preferred);
                            if let Some(effect) = self.peer_effect(&routing, now) {
                                effects.push(effect);
                            }
                        }
                        effects.push(Effect::Packet {
                            routing,
                            noise,
                            packet: Box::new(packet),
                        });
                    }
                    0x40 => {
                        let packet = ProfilePacket::decode(body)?;
                        if packet.kind == Kind::Query && !packet.request.is_empty() {
                            let manifest = Manifest {
                                name: self.own.name.clone(),
                                bio: self.own.bio.clone(),
                                avatar_bytes: 0,
                                avatar_hash: None,
                                avatar_seed: self.own.avatar_seed,
                                avatar_version: self.own.avatar_version,
                            };
                            let response = ProfilePacket {
                                version: 1,
                                kind: Kind::Manifest,
                                request: packet.request,
                                manifest: Some(manifest),
                                hash: None,
                                offset: None,
                                data: None,
                            };
                            effects.push(self.encrypted(
                                &routing,
                                0x40,
                                canonical::encode(&response)?,
                                now,
                            )?);
                        }
                    }
                    _ => {}
                }
            }
            3 => {
                if let Some(p) = self.peers.get(&routing) {
                    if frame.verify(&p.announce.signing)? {
                        self.peers.remove(&routing);
                        effects.push(Effect::Gone(routing));
                    }
                }
            }
            _ => {}
        }
        Ok(effects)
    }
    pub fn tick(&mut self, now: i64) -> Result<Vec<Effect>> {
        let mut effects = vec![];
        if now - self.announce_at >= 15_000 {
            self.announce_at = now;
            let frame = self.announcement(now)?;
            for id in self.links.keys() {
                effects.push(self.transmit(id, frame.clone())?);
            }
        }
        let peers = self.peers.keys().cloned().collect::<Vec<_>>();
        for id in peers {
            let p = self.peers.get_mut(&id).unwrap();
            if p.handshake
                .as_ref()
                .is_some_and(|(_, _, at)| now - *at > 10_000)
            {
                p.handshake = None;
                p.first_seen = now;
            }
            if p.session.is_none() && p.handshake.is_none() && now - p.first_seen > 3000 {
                effects.push(self.initiate(&id, now)?);
            } else if p.session.is_some()
                && now - p.hello >= if p.card.is_some() { 30_000 } else { 2000 }
            {
                effects.push(self.hello(&id, now)?);
            }
            if let Some(effect) = self.peer_effect(&id, now) {
                effects.push(effect);
            }
        }
        Ok(effects)
    }
    pub fn update(
        &mut self,
        card: Card,
        pins: Vec<Card>,
        blocked: HashSet<String>,
        now: i64,
    ) -> Result<Vec<Effect>> {
        card.validate()?;
        ensure!(
            card.noise_key == self.own.noise_key && card.signing_key == self.own.signing_key,
            "BLE local identity changed"
        );
        let changed = self.own != card;
        self.own = card;
        self.pins = pins.into_iter().map(|c| (c.id(), c)).collect();
        self.blocked = blocked;
        let mut effects = vec![];
        self.peers.retain(|id, p| {
            if self.blocked.contains(&crypto::id(&p.announce.noise)) {
                effects.push(Effect::Gone(id.clone()));
                false
            } else {
                true
            }
        });
        if changed {
            for id in self
                .peers
                .iter()
                .filter(|(_, p)| p.session.is_some())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
            {
                effects.push(self.hello(&id, now)?);
            }
        }
        Ok(effects)
    }
}
