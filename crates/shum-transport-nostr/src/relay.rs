use crate::{
    protocol::{self, Incoming},
    Error, Result,
};
use futures_util::{SinkExt, StreamExt};
use shum_core::nostr::Event;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};

const ACK_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Debug)]
pub enum RelayUpdate {
    Connected(String),
    Disconnected(String),
    Event { relay: String, event: Box<Event> },
    EndOfStoredEvents(String),
}
struct Publication {
    event: Arc<Event>,
    reply: Option<oneshot::Sender<bool>>,
}
struct Pending {
    reply: oneshot::Sender<bool>,
    deadline: Instant,
}
struct Lifetime {
    stop: watch::Sender<bool>,
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}
#[derive(Clone)]
pub struct RelayPool {
    senders: Arc<Vec<mpsc::Sender<Publication>>>,
    status: watch::Receiver<Vec<String>>,
    _lifetime: Arc<Lifetime>,
}
struct Status {
    url: String,
    status: watch::Sender<Vec<String>>,
}
impl Drop for Status {
    fn drop(&mut self) {
        self.status
            .send_modify(|list| list.retain(|url| *url != self.url));
    }
}

impl RelayPool {
    pub fn validate_urls(urls: &[String]) -> Result<()> {
        protocol::validate_urls(urls)
    }
    pub fn start(urls: &[String], public_key: &str) -> Result<(Self, mpsc::Receiver<RelayUpdate>)> {
        protocol::validate_urls(urls)?;
        protocol::validate_inbox(public_key)?;
        let (stop, _) = watch::channel(false);
        let (status, status_rx) = watch::channel(Vec::new());
        let (updates, incoming) = mpsc::channel(128);
        let mut senders = Vec::new();
        for url in urls {
            let (send, receive) = mpsc::channel(64);
            senders.push(send);
            tokio::spawn(connection(
                url.clone(),
                public_key.into(),
                receive,
                updates.clone(),
                stop.subscribe(),
                status.clone(),
            ));
        }
        Ok((
            Self {
                senders: Arc::new(senders),
                status: status_rx,
                _lifetime: Arc::new(Lifetime { stop }),
            },
            incoming,
        ))
    }
    pub fn connected(&self) -> Vec<String> {
        self.status.borrow().clone()
    }
    /// At least one relay OK(true) is required. This is never a recipient ACK.
    pub async fn publish(&self, event: Event) -> Result<()> {
        if !event.verify() {
            return Err(Error::Publication);
        }
        let event = Arc::new(event);
        let mut pending = JoinSet::new();
        for sender in self.senders.iter() {
            let (reply, response) = oneshot::channel();
            if sender
                .try_send(Publication {
                    event: event.clone(),
                    reply: Some(reply),
                })
                .is_ok()
            {
                pending.spawn(async move {
                    matches!(timeout(ACK_TIMEOUT, response).await, Ok(Ok(true)))
                });
            }
        }
        while let Some(result) = pending.join_next().await {
            if matches!(result, Ok(true)) {
                return Ok(());
            }
        }
        Err(Error::Publication)
    }
    /// Contact lookup uses fire-and-forget publication, as Swift does.
    pub fn publish_unconfirmed(&self, event: Event) -> Result<()> {
        if !event.verify() {
            return Err(Error::Publication);
        }
        let event = Arc::new(event);
        let mut sent = false;
        for sender in self.senders.iter() {
            sent |= sender
                .try_send(Publication {
                    event: event.clone(),
                    reply: None,
                })
                .is_ok();
        }
        if sent {
            Ok(())
        } else {
            Err(Error::Queue)
        }
    }
}
async fn connection(
    url: String,
    public: String,
    mut publications: mpsc::Receiver<Publication>,
    updates: mpsc::Sender<RelayUpdate>,
    mut stop: watch::Receiver<bool>,
    status: watch::Sender<Vec<String>>,
) {
    let mut backoff = 1;
    let mut queued = VecDeque::new();
    loop {
        if *stop.borrow() {
            return;
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(protocol::MAX_MESSAGE))
            .max_frame_size(Some(protocol::MAX_MESSAGE));
        let connecting = timeout(
            Duration::from_secs(8),
            connect_async_with_config(&url, Some(config), false),
        );
        let socket = tokio::select! { result=connecting => result, _=stop.changed() => return };
        let Ok(Ok((mut socket, _))) = socket else {
            let _ = updates.try_send(RelayUpdate::Disconnected(url.clone()));
            tokio::select! { _=tokio::time::sleep(Duration::from_secs(backoff))=>{}, _=stop.changed()=>return }
            backoff = (backoff * 2).min(60);
            continue;
        };
        backoff = 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let request = protocol::subscription(&public, now);
        if !matches!(
            timeout(
                Duration::from_secs(5),
                socket.send(Message::Text(request.into()))
            )
            .await,
            Ok(Ok(()))
        ) {
            continue;
        }
        status.send_modify(|list| {
            if !list.contains(&url) {
                list.push(url.clone());
                list.sort();
            }
        });
        let _connected = Status {
            url: url.clone(),
            status: status.clone(),
        };
        let _ = updates.try_send(RelayUpdate::Connected(url.clone()));
        let mut acknowledgements: HashMap<String, Vec<Pending>> = HashMap::new();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
        let mut last_ping = Instant::now();
        let mut last_received = Instant::now();
        loop {
            let publication = if let Some(value) = queued.pop_front() {
                Some(value)
            } else {
                tokio::select! {
                    _=stop.changed()=> { let _=timeout(Duration::from_secs(1),socket.close(None)).await; return; },
                    next=publications.recv()=> { match next { Some(p)=>Some(p),None=>return } },
                    message=socket.next()=> {
                        let Some(Ok(message))=message else { break; }; last_received=Instant::now();
                        match message {
                            Message::Text(text)=> match protocol::read(&text,&public) {
                                Some(Incoming::Event(event))=> { let _=updates.try_send(RelayUpdate::Event { relay:url.clone(),event }); }
                                Some(Incoming::Ok { id, accepted })=> {
                                    if let Some(waiters)=acknowledgements.remove(&id) { for pending in waiters { let _=pending.reply.send(accepted); } }
                                }
                                Some(Incoming::EndOfStoredEvents)=> { let _=updates.try_send(RelayUpdate::EndOfStoredEvents(url.clone())); }
                                Some(Incoming::Closed)=>break,
                                None=>{}
                            },
                            Message::Ping(payload)=> { if !matches!(timeout(Duration::from_secs(5),socket.send(Message::Pong(payload))).await,Ok(Ok(()))) { break; } },
                            Message::Close(_)=>break,
                            _=>{}
                        }
                        None
                    },
                    _=heartbeat.tick()=> {
                        acknowledgements.retain(|_,waiters| { waiters.retain(|p|p.deadline>Instant::now() && !p.reply.is_closed()); !waiters.is_empty() });
                        if last_received.elapsed()>Duration::from_secs(60) { break; }
                        if last_ping.elapsed()>=Duration::from_secs(20) { if !matches!(timeout(Duration::from_secs(5),socket.send(Message::Ping(Vec::new().into()))).await,Ok(Ok(()))) { break; } last_ping=Instant::now(); }
                        None
                    }
                }
            };
            if let Some(publication) = publication {
                if publication
                    .reply
                    .as_ref()
                    .is_some_and(oneshot::Sender::is_closed)
                {
                    continue;
                }
                let Ok(wire) = protocol::publication(&publication.event) else {
                    continue;
                };
                if !matches!(
                    timeout(
                        Duration::from_secs(5),
                        socket.send(Message::Text(wire.into()))
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    if queued.len() < 64 {
                        queued.push_back(publication);
                    }
                    break;
                }
                if let Some(reply) = publication.reply {
                    acknowledgements
                        .entry(publication.event.id.clone())
                        .or_default()
                        .push(Pending {
                            reply,
                            deadline: Instant::now() + ACK_TIMEOUT,
                        });
                }
            }
        }
        let _ = updates.try_send(RelayUpdate::Disconnected(url.clone()));
        for waiters in acknowledgements.into_values() {
            for pending in waiters {
                let _ = pending.reply.send(false);
            }
        }
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(1))=>{}, _=stop.changed()=>return }
    }
}
