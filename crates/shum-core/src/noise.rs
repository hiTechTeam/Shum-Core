//! Bitchat Noise primitives. Entropy and static keys are supplied by the caller.
use crate::{
    crypto::{sha256, Secret32},
    Error, Result,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub fn valid_public(public: &[u8; 32]) -> bool {
    if public.iter().all(|v| *v == 0) || public.iter().all(|v| *v == 255) {
        return false;
    }
    let mut one = [0; 32];
    one[0] = 1;
    let mut reverse_one = [0; 32];
    reverse_one[31] = 1;
    let mut da = [255; 32];
    da[0] = 0xda;
    let mut db = da;
    db[0] = 0xdb;
    let extra = [
        hex::decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
            .expect("constant hex"),
        hex::decode("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
            .expect("constant hex"),
    ];
    ![one, reverse_one, da, db].contains(public) && !extra.iter().any(|v| v == public)
}
pub fn dh(secret: &Secret32, public: &[u8; 32]) -> Result<[u8; 32]> {
    if !valid_public(public) {
        return Err(Error::Invalid("Noise public key"));
    }
    let shared = x25519_dalek::StaticSecret::from(*secret.expose())
        .diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(Error::Authentication);
    }
    Ok(shared.to_bytes())
}
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts every key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
pub fn hkdf2(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut prk = hmac(ck, input);
    let first = hmac(&prk, &[1]);
    let mut next = first.to_vec();
    next.push(2);
    let second = hmac(&prk, &next);
    prk.zeroize();
    (first, second)
}
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    key: Option<[u8; 32]>,
    counter: u64,
}
impl SymmetricState {
    pub fn new(name: &[u8], prologue: &[u8]) -> Self {
        let h = if name.len() > 32 {
            sha256(name)
        } else {
            let mut h = [0; 32];
            h[..name.len()].copy_from_slice(name);
            h
        };
        let mut s = Self {
            ck: h,
            h,
            key: None,
            counter: 0,
        };
        s.mix_hash(prologue);
        s
    }
    pub fn hash(&self) -> [u8; 32] {
        self.h
    }
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut bytes = self.h.to_vec();
        bytes.extend(data);
        self.h = sha256(&bytes);
    }
    pub fn mix_key(&mut self, input: &[u8]) {
        let (ck, key) = hkdf2(&self.ck, input);
        self.ck = ck;
        self.key = Some(key);
        self.counter = 0;
    }
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let cipher = if let Some(key) = &self.key {
            let c = ChaCha20Poly1305::new(key.into())
                .encrypt(
                    (&nonce(self.counter)).into(),
                    Payload {
                        msg: plain,
                        aad: &self.h,
                    },
                )
                .map_err(|_| Error::Authentication)?;
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(Error::Invalid("Noise nonce exhausted"))?;
            c
        } else {
            plain.to_vec()
        };
        self.mix_hash(&cipher);
        Ok(cipher)
    }
    pub fn open(&mut self, cipher: &[u8]) -> Result<Vec<u8>> {
        let plain = if let Some(key) = &self.key {
            let p = ChaCha20Poly1305::new(key.into())
                .decrypt(
                    (&nonce(self.counter)).into(),
                    Payload {
                        msg: cipher,
                        aad: &self.h,
                    },
                )
                .map_err(|_| Error::Authentication)?;
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(Error::Invalid("Noise nonce exhausted"))?;
            p
        } else {
            cipher.to_vec()
        };
        self.mix_hash(cipher);
        Ok(plain)
    }
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf2(&self.ck, &[])
    }
}

pub fn seal_courier(
    sender: &Secret32,
    recipient: &[u8; 32],
    ephemeral: &Secret32,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let mut state = SymmetricState::new(b"Noise_X_25519_ChaChaPoly_SHA256", b"bitchat-courier-v1");
    if !valid_public(recipient) {
        return Err(Error::Invalid("courier recipient"));
    }
    state.mix_hash(recipient);
    let mut out = ephemeral.noise_public().to_vec();
    state.mix_hash(&out);
    let mut shared = dh(ephemeral, recipient)?;
    state.mix_key(&shared);
    shared.zeroize();
    out.extend(state.seal(&sender.noise_public())?);
    shared = dh(sender, recipient)?;
    state.mix_key(&shared);
    shared.zeroize();
    out.extend(state.seal(plain)?);
    Ok(out)
}
pub fn open_courier(recipient: &Secret32, cipher: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if cipher.len() < 96 {
        return Err(Error::Invalid("courier length"));
    }
    let mut state = SymmetricState::new(b"Noise_X_25519_ChaChaPoly_SHA256", b"bitchat-courier-v1");
    state.mix_hash(&recipient.noise_public());
    let e: &[u8; 32] = cipher[..32].try_into().expect("length checked");
    state.mix_hash(e);
    let mut shared = dh(recipient, e)?;
    state.mix_key(&shared);
    shared.zeroize();
    let sender: [u8; 32] = state
        .open(&cipher[32..80])?
        .try_into()
        .map_err(|_| Error::Invalid("courier sender length"))?;
    shared = dh(recipient, &sender)?;
    state.mix_key(&shared);
    shared.zeroize();
    Ok((state.open(&cipher[80..])?, sender))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// XX handshake only. Replay tracking is a separate session responsibility.
pub struct HandshakeXX {
    state: SymmetricState,
    role: Role,
    step: u8,
    static_key: Secret32,
    ephemeral: Secret32,
    remote_ephemeral: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
}
pub struct SplitKeys {
    pub send: Secret32,
    pub receive: Secret32,
    pub remote_static: [u8; 32],
    pub handshake_hash: [u8; 32],
}
impl HandshakeXX {
    pub fn new(role: Role, static_key: Secret32, ephemeral: Secret32) -> Self {
        Self {
            state: SymmetricState::new(b"Noise_XX_25519_ChaChaPoly_SHA256", b""),
            role,
            step: 0,
            static_key,
            ephemeral,
            remote_ephemeral: None,
            remote_static: None,
        }
    }
    fn mix_dh(&mut self, ephemeral: bool, remote: [u8; 32]) -> Result<()> {
        let key = if ephemeral {
            &self.ephemeral
        } else {
            &self.static_key
        };
        let mut shared = dh(key, &remote)?;
        self.state.mix_key(&shared);
        shared.zeroize();
        Ok(())
    }
    pub fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match (self.role, self.step) {
            (Role::Initiator, 0) => {
                let e = self.ephemeral.noise_public();
                out.extend(e);
                self.state.mix_hash(&e);
            }
            (Role::Responder, 1) => {
                let re = self.remote_ephemeral.ok_or(Error::Invalid("XX remote e"))?;
                let e = self.ephemeral.noise_public();
                out.extend(e);
                self.state.mix_hash(&e);
                self.mix_dh(true, re)?;
                out.extend(self.state.seal(&self.static_key.noise_public())?);
                self.mix_dh(false, re)?;
            }
            (Role::Initiator, 2) => {
                out.extend(self.state.seal(&self.static_key.noise_public())?);
                self.mix_dh(
                    false,
                    self.remote_ephemeral.ok_or(Error::Invalid("XX remote e"))?,
                )?;
            }
            _ => return Err(Error::Invalid("XX write sequence")),
        }
        out.extend(self.state.seal(payload)?);
        self.step += 1;
        Ok(out)
    }
    pub fn read(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let payload = match (self.role, self.step) {
            (Role::Responder, 0) => {
                if message.len() < 32 {
                    return Err(Error::Invalid("XX message one"));
                }
                let e: [u8; 32] = message[..32].try_into().expect("length checked");
                if !valid_public(&e) {
                    return Err(Error::Invalid("XX e"));
                }
                self.remote_ephemeral = Some(e);
                self.state.mix_hash(&e);
                self.state.open(&message[32..])?
            }
            (Role::Initiator, 1) => {
                if message.len() < 96 {
                    return Err(Error::Invalid("XX message two"));
                }
                let e: [u8; 32] = message[..32].try_into().expect("length checked");
                self.remote_ephemeral = Some(e);
                self.state.mix_hash(&e);
                self.mix_dh(true, e)?;
                let remote: [u8; 32] = self
                    .state
                    .open(&message[32..80])?
                    .try_into()
                    .map_err(|_| Error::Invalid("XX s"))?;
                self.remote_static = Some(remote);
                self.mix_dh(true, remote)?;
                self.state.open(&message[80..])?
            }
            (Role::Responder, 2) => {
                if message.len() < 64 {
                    return Err(Error::Invalid("XX message three"));
                }
                let remote: [u8; 32] = self
                    .state
                    .open(&message[..48])?
                    .try_into()
                    .map_err(|_| Error::Invalid("XX s"))?;
                self.remote_static = Some(remote);
                self.mix_dh(true, remote)?;
                self.state.open(&message[48..])?
            }
            _ => return Err(Error::Invalid("XX read sequence")),
        };
        self.step += 1;
        Ok(payload)
    }
    pub fn finish(self) -> Result<SplitKeys> {
        if self.step != 3 {
            return Err(Error::Invalid("incomplete XX handshake"));
        }
        let (a, b) = self.state.split();
        let (send, receive) = if self.role == Role::Initiator {
            (a, b)
        } else {
            (b, a)
        };
        Ok(SplitKeys {
            send: Secret32::new(send),
            receive: Secret32::new(receive),
            remote_static: self
                .remote_static
                .ok_or(Error::Invalid("missing XX remote static"))?,
            handshake_hash: self.state.hash(),
        })
    }
}

pub fn seal_transport(key: &Secret32, counter: u32, plain: &[u8]) -> Result<Vec<u8>> {
    if counter == u32::MAX {
        return Err(Error::Invalid("transport nonce exhausted"));
    }
    let mut cipher = counter.to_be_bytes().to_vec();
    cipher.extend(
        ChaCha20Poly1305::new(key.expose().into())
            .encrypt((&nonce(u64::from(counter))).into(), plain)
            .map_err(|_| Error::Authentication)?,
    );
    Ok(cipher)
}
/// Primitive only: session must reject replay BEFORE publishing plaintext.
pub fn open_transport(key: &Secret32, cipher: &[u8]) -> Result<(u32, Vec<u8>)> {
    if cipher.len() < 20 {
        return Err(Error::Invalid("transport ciphertext size"));
    }
    let counter = u32::from_be_bytes(cipher[..4].try_into().expect("length checked"));
    let plain = ChaCha20Poly1305::new(key.expose().into())
        .decrypt((&nonce(u64::from(counter))).into(), &cipher[4..])
        .map_err(|_| Error::Authentication)?;
    Ok((counter, plain))
}

/// Authenticated transport with a 1024-counter replay window. Unlike the Swift
/// shift defect recorded in spec/06, advancing the window never forgets a
/// previously accepted counter that is still in range.
pub struct Session {
    send: Secret32,
    receive: Secret32,
    next_send: u32,
    maximum: Option<u32>,
    seen: [u64; 16],
    pub remote_static: [u8; 32],
    pub handshake_hash: [u8; 32],
}
impl Session {
    pub fn new(keys: SplitKeys) -> Self {
        Self {
            send: keys.send,
            receive: keys.receive,
            next_send: 0,
            maximum: None,
            seen: [0; 16],
            remote_static: keys.remote_static,
            handshake_hash: keys.handshake_hash,
        }
    }
    pub fn send(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let result = seal_transport(&self.send, self.next_send, bytes)?;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or(Error::Invalid("Noise counter exhausted"))?;
        Ok(result)
    }
    pub fn receive(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 20 {
            return Err(Error::Invalid("Noise transport length"));
        }
        let counter = u32::from_be_bytes(wire[..4].try_into().expect("fixed length"));
        if let Some(max) = self.maximum {
            if counter <= max {
                let distance = (max - counter) as usize;
                if distance >= 1024 || self.seen[distance / 64] & (1_u64 << (distance % 64)) != 0 {
                    return Err(Error::Invalid("Noise replay"));
                }
            }
        }
        let (_, plain) = open_transport(&self.receive, wire)?;
        match self.maximum {
            None => {
                self.maximum = Some(counter);
                self.seen[0] = 1;
            }
            Some(max) if counter > max => {
                let shift = (counter - max) as usize;
                if shift >= 1024 {
                    self.seen = [0; 16];
                } else {
                    let words = shift / 64;
                    let bits = shift % 64;
                    let mut next = [0; 16];
                    for (i, slot) in next.iter_mut().enumerate().skip(words) {
                        *slot = self.seen[i - words] << bits;
                        if bits > 0 && i > words {
                            *slot |= self.seen[i - words - 1] >> (64 - bits);
                        }
                    }
                    self.seen = next;
                }
                self.maximum = Some(counter);
                self.seen[0] |= 1;
            }
            Some(max) => {
                let distance = (max - counter) as usize;
                self.seen[distance / 64] |= 1_u64 << (distance % 64);
            }
        }
        Ok(plain)
    }
}
