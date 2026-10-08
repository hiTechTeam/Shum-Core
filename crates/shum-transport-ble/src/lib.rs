//! Shum v1 BLE: native GATT I/O around the tested Bitchat/Noise codecs.
#![forbid(unsafe_code)]
#[cfg(target_os = "macos")]
mod macos;
pub mod mesh;
mod radio;
use anyhow::{Context, Result};
use shum_core::{card::Card, crypto::Secret32, packet::Packet};
use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
pub enum Update {
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
    State {
        role: &'static str,
        state: String,
    },
}
enum Command {
    Send(String, Box<Packet>),
    Profile(Box<Card>, Vec<Card>, HashSet<String>),
}
pub struct Ble {
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Ble {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
impl Ble {
    pub fn start(
        directory: &Path,
        card: Card,
        noise: Secret32,
        signing: Secret32,
        pins: Vec<Card>,
        blocked: HashSet<String>,
    ) -> Result<(Self, mpsc::Receiver<Update>)> {
        let mut mesh = mesh::Mesh::new(card, noise, signing, pins, blocked)?;
        let (events, mut incoming) = mpsc::channel(256);
        let radio = radio::Radio::start(directory, events)?;
        let (commands, mut requests) = mpsc::channel(128);
        let (send, updates) = mpsc::channel(256);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                let result = tokio::select! {
                    Some(event)=incoming.recv()=>match event {
                        radio::Event::Connected{link,budget,rssi}=>mesh.connected(link,budget,rssi,now()),
                        radio::Event::Disconnected(link)=>Ok(mesh.disconnected(&link)),
                        radio::Event::Data{link,bytes}=>mesh.receive(&link,&bytes,now()),
                        radio::Event::Rssi(link,rssi)=>{mesh.rssi(&link,Some(rssi),now());Ok(vec![])},
                        radio::Event::State{role,state}=>{let _=send.send(Update::State{role,state}).await;Ok(vec![])},
                    },
                    Some(command)=requests.recv()=>match command {
                        Command::Send(id,packet)=>mesh.send(&id,&packet,now()).map(|e|vec![e]),
                        Command::Profile(card,pins,blocked)=>mesh.update(*card,pins,blocked,now()),
                    },
                    _=tick.tick()=>mesh.tick(now()),
                    _=send.closed()=>break,
                };
                match result {
                    Ok(effects) => {
                        for effect in effects {
                            let update = match effect {
                                mesh::Effect::Send { link, frames } => {
                                    if let Err(error) = radio.send(link, frames) {
                                        let _ = send
                                            .send(Update::State {
                                                role: "link",
                                                state: error.to_string(),
                                            })
                                            .await;
                                    }
                                    continue;
                                }
                                mesh::Effect::Peer {
                                    routing,
                                    card,
                                    noise,
                                    distance,
                                    direct,
                                } => Update::Peer {
                                    routing,
                                    card,
                                    noise,
                                    distance,
                                    direct,
                                },
                                mesh::Effect::Gone(id) => Update::Gone(id),
                                mesh::Effect::Packet {
                                    routing,
                                    noise,
                                    packet,
                                } => Update::Packet {
                                    routing,
                                    noise,
                                    packet,
                                },
                            };
                            if send.send(update).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = send
                            .send(Update::State {
                                role: "packet",
                                state: error.to_string(),
                            })
                            .await;
                    }
                }
            }
        });
        Ok((Self { commands, task }, updates))
    }
    pub fn send(&self, routing: String, packet: Box<Packet>) -> Result<()> {
        self.commands
            .try_send(Command::Send(routing, packet))
            .context("BLE outbound queue full")
    }
    pub fn profile(&self, card: Card, pins: Vec<Card>, blocked: HashSet<String>) -> Result<()> {
        self.commands
            .try_send(Command::Profile(Box::new(card), pins, blocked))
            .context("BLE update queue full")
    }
}
