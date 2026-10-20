//! Relay connections as a state machine, without sockets or clocks: what to
//! connect, send and close, and what that means, for every client. Native
//! clients run it over tokio sockets ([`crate::RelayPool`]), the browser over
//! its own WebSocket. The client feeds in what its sockets did and the time,
//! then carries out the returned [`Effect`]s.
//!
//! One connection per relay. A failed attempt waits twice as long as the
//! previous one, up to a minute; a lost working connection retries after a
//! second. While a relay is offline up to 64 publications wait for it. A
//! publication counts once any relay accepts it.
use crate::{
    protocol::{self, Incoming},
    Error, Result,
};
use shum_core::nostr::Event;
use std::collections::{HashMap, VecDeque};

/// Times are milliseconds since 1970.
const CONNECT_TIMEOUT: u64 = 8_000;
const ACK_TIMEOUT: u64 = 10_000;
const PING_EVERY: u64 = 20_000;
const SILENCE_LIMIT: u64 = 60_000;
const QUEUE: usize = 64;

/// Identifies one publication that waits for a relay's answer.
pub type Ticket = u64;

/// What the client does next. `relay` indexes the URLs given to
/// [`Relays::new`]; `attempt` tells one connection to a relay from the next,
/// and the client reports socket events with it.
#[derive(Debug, PartialEq)]
pub enum Effect {
    Connect {
        relay: usize,
        attempt: u64,
    },
    Send {
        relay: usize,
        text: String,
    },
    /// Only when pings were asked for: a WebSocket ping frame.
    Ping {
        relay: usize,
    },
    Close {
        relay: usize,
    },
    Connected(String),
    Disconnected(String),
    Event {
        relay: String,
        event: Box<Event>,
    },
    EndOfStoredEvents(String),
    /// A relay accepted the publication, or none did in time.
    Published {
        ticket: Ticket,
        accepted: bool,
    },
}

enum State {
    Waiting { until: u64 },
    Connecting { since: u64 },
    Open { last_received: u64, last_ping: u64 },
}
struct Queued {
    text: String,
    id: String,
    ticket: Option<Ticket>,
}
struct Link {
    url: String,
    state: State,
    attempt: u64,
    backoff: u64,
    queue: VecDeque<Queued>,
    /// Event ID → publications waiting for this relay's OK.
    waiting: HashMap<String, Vec<Ticket>>,
}
struct Pending {
    deadline: u64,
    /// Relays that may still accept it.
    outstanding: usize,
}

pub struct Relays {
    inbox: String,
    pings: bool,
    links: Vec<Link>,
    pending: HashMap<Ticket, Pending>,
    next: Ticket,
    effects: Vec<Effect>,
}

impl Relays {
    /// Relays for the inbox `inbox` (a Nostr public key in hex). With
    /// `pings` the machine pings quiet relays and drops silent ones; the
    /// browser cannot send pings and relies on its WebSocket instead.
    /// The first [`Relays::tick`] connects.
    pub fn new(urls: &[String], inbox: &str, pings: bool, now: u64) -> Result<Self> {
        protocol::validate_urls(urls)?;
        protocol::validate_inbox(inbox)?;
        Ok(Self {
            inbox: inbox.into(),
            pings,
            links: urls
                .iter()
                .map(|url| Link {
                    url: url.clone(),
                    state: State::Waiting { until: now },
                    attempt: 0,
                    backoff: 1,
                    queue: VecDeque::new(),
                    waiting: HashMap::new(),
                })
                .collect(),
            pending: HashMap::new(),
            next: 0,
            effects: Vec::new(),
        })
    }

    pub fn url(&self, relay: usize) -> Option<&str> {
        self.links.get(relay).map(|l| l.url.as_str())
    }

    /// Relays with a working subscription, sorted.
    pub fn connected(&self) -> Vec<String> {
        let mut list: Vec<_> = self
            .links
            .iter()
            .filter(|l| matches!(l.state, State::Open { .. }))
            .map(|l| l.url.clone())
            .collect();
        list.sort();
        list
    }

    /// What to do now. Every call below adds to it.
    pub fn effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Publishes a signed event to every relay. With `confirm` it returns a
    /// ticket that a later [`Effect::Published`] answers.
    pub fn publish(&mut self, event: &Event, confirm: bool, now: u64) -> Result<Option<Ticket>> {
        let text = protocol::publication(event)?;
        let ticket = confirm.then(|| {
            self.next += 1;
            self.next
        });
        let mut reached = 0;
        for relay in 0..self.links.len() {
            let link = &mut self.links[relay];
            if matches!(link.state, State::Open { .. }) {
                self.effects.push(Effect::Send {
                    relay,
                    text: text.clone(),
                });
                if let Some(ticket) = ticket {
                    link.waiting
                        .entry(event.id.clone())
                        .or_default()
                        .push(ticket);
                }
            } else if link.queue.len() < QUEUE {
                link.queue.push_back(Queued {
                    text: text.clone(),
                    id: event.id.clone(),
                    ticket,
                });
            } else {
                continue;
            }
            reached += 1;
        }
        if reached == 0 {
            return Err(if confirm {
                Error::Publication
            } else {
                Error::Queue
            });
        }
        if let Some(ticket) = ticket {
            self.pending.insert(
                ticket,
                Pending {
                    deadline: now + ACK_TIMEOUT,
                    outstanding: reached,
                },
            );
        }
        Ok(ticket)
    }

    fn current(&self, relay: usize, attempt: u64) -> bool {
        self.links
            .get(relay)
            .is_some_and(|l| l.attempt == attempt && !matches!(l.state, State::Waiting { .. }))
    }

    /// The socket of `attempt` is open: subscribe and send what waited.
    pub fn opened(&mut self, relay: usize, attempt: u64, now: u64) {
        if !self.current(relay, attempt) {
            return;
        }
        let since = now / 1000;
        let link = &mut self.links[relay];
        if !matches!(link.state, State::Connecting { .. }) {
            return;
        }
        self.effects.push(Effect::Send {
            relay,
            text: protocol::subscription(&self.inbox, since),
        });
        link.state = State::Open {
            last_received: now,
            last_ping: now,
        };
        link.backoff = 1;
        self.effects.push(Effect::Connected(link.url.clone()));
        for queued in std::mem::take(&mut link.queue) {
            if let Some(ticket) = queued.ticket {
                if !self.pending.contains_key(&ticket) {
                    continue;
                }
                link.waiting.entry(queued.id).or_default().push(ticket);
            }
            self.effects.push(Effect::Send {
                relay,
                text: queued.text,
            });
        }
    }

    /// A text message arrived on the socket of `attempt`.
    pub fn received(&mut self, relay: usize, attempt: u64, text: &str, now: u64) {
        if !self.current(relay, attempt) {
            return;
        }
        let link = &mut self.links[relay];
        let State::Open { last_received, .. } = &mut link.state else {
            return;
        };
        *last_received = now;
        match protocol::read(text, &self.inbox) {
            Some(Incoming::Event(event)) => self.effects.push(Effect::Event {
                relay: link.url.clone(),
                event,
            }),
            Some(Incoming::Ok { id, accepted }) => {
                let tickets = link.waiting.remove(&id).unwrap_or_default();
                for ticket in tickets {
                    self.answer(ticket, accepted);
                }
            }
            Some(Incoming::EndOfStoredEvents) => self
                .effects
                .push(Effect::EndOfStoredEvents(link.url.clone())),
            Some(Incoming::Closed) => {
                self.effects.push(Effect::Close { relay });
                self.lost(relay, now);
            }
            None => {}
        }
    }

    /// The socket of `attempt` closed or failed to connect.
    pub fn closed(&mut self, relay: usize, attempt: u64, now: u64) {
        if self.current(relay, attempt) {
            self.lost(relay, now);
        }
    }

    /// The client is back from the background, or a push woke it: relays
    /// waiting to retry connect at once, and open ones are pinged so a
    /// connection that died meanwhile closes now instead of after a minute.
    pub fn wake(&mut self, now: u64) {
        for relay in 0..self.links.len() {
            match &mut self.links[relay].state {
                State::Waiting { until } => *until = now,
                State::Open { last_ping, .. } if self.pings => {
                    *last_ping = now;
                    self.effects.push(Effect::Ping { relay });
                }
                _ => {}
            }
        }
        self.tick(now);
    }

    /// Call about once a second: connects, retries, pings and expires.
    pub fn tick(&mut self, now: u64) {
        for relay in 0..self.links.len() {
            let link = &mut self.links[relay];
            match link.state {
                State::Waiting { until } if now >= until => {
                    link.attempt += 1;
                    link.state = State::Connecting { since: now };
                    self.effects.push(Effect::Connect {
                        relay,
                        attempt: link.attempt,
                    });
                }
                State::Connecting { since } if now.saturating_sub(since) >= CONNECT_TIMEOUT => {
                    self.effects.push(Effect::Close { relay });
                    self.lost(relay, now);
                }
                State::Open {
                    last_received,
                    ref mut last_ping,
                } if self.pings => {
                    if now.saturating_sub(last_received) > SILENCE_LIMIT {
                        self.effects.push(Effect::Close { relay });
                        self.lost(relay, now);
                    } else if now.saturating_sub(*last_ping) >= PING_EVERY {
                        *last_ping = now;
                        self.effects.push(Effect::Ping { relay });
                    }
                }
                _ => {}
            }
        }
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .map(|(ticket, _)| *ticket)
            .collect();
        for ticket in expired {
            self.pending.remove(&ticket);
            self.effects.push(Effect::Published {
                ticket,
                accepted: false,
            });
        }
    }

    fn lost(&mut self, relay: usize, now: u64) {
        let link = &mut self.links[relay];
        let was_open = matches!(link.state, State::Open { .. });
        let pause = if was_open { 1 } else { link.backoff };
        if !was_open {
            link.backoff = (link.backoff * 2).min(60);
        }
        link.state = State::Waiting {
            until: now + pause * 1000,
        };
        let url = link.url.clone();
        let refused: Vec<_> = link.waiting.drain().flat_map(|(_, t)| t).collect();
        self.effects.push(Effect::Disconnected(url));
        for ticket in refused {
            self.answer(ticket, false);
        }
    }

    fn answer(&mut self, ticket: Ticket, accepted: bool) {
        let Some(pending) = self.pending.get_mut(&ticket) else {
            return;
        };
        pending.outstanding = pending.outstanding.saturating_sub(1);
        if accepted || pending.outstanding == 0 {
            self.pending.remove(&ticket);
            self.effects.push(Effect::Published { ticket, accepted });
        }
    }
}
