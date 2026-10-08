use anyhow::{Context, Result};
use btleplug::{
    api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType},
    platform::{Manager, Peripheral},
};
use futures_util::StreamExt;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinSet, time::timeout};
use uuid::Uuid;

pub enum Event {
    Connected {
        link: String,
        budget: usize,
        rssi: Option<i16>,
    },
    Data {
        link: String,
        bytes: Vec<u8>,
    },
    Disconnected(String),
    Rssi(String, i16),
    State {
        role: &'static str,
        state: String,
    },
}
type Frames = Vec<Vec<u8>>;
type Writers = Arc<Mutex<HashMap<String, mpsc::Sender<Frames>>>>;
pub struct Radio {
    jobs: JoinSet<()>,
    writers: Writers,
    peripheral: Option<mpsc::Sender<(String, Frames)>>,
}
impl Radio {
    pub fn start(directory: &Path, events: mpsc::Sender<Event>) -> Result<Self> {
        let mut jobs = JoinSet::new();
        let writers: Writers = Arc::default();
        let write = writers.clone();
        let tx = events.clone();
        jobs.spawn(async move {loop {if let Err(error)=central(write.clone(),tx.clone()).await {let _=tx.send(Event::State{role:"scan",state:error.to_string()}).await;}tokio::select!{_=tx.closed()=>break,_=tokio::time::sleep(Duration::from_secs(10))=>{}}}});
        #[cfg(target_os = "macos")]
        let peripheral = Some(super::macos::start(directory, &mut jobs, events)?);
        #[cfg(not(target_os = "macos"))]
        let peripheral = {
            let _ = directory;
            let _ = events.try_send(Event::State {
                role: "advertise",
                state: "Peripheral adapter is not available on this platform yet".into(),
            });
            None
        };
        Ok(Self {
            jobs,
            writers,
            peripheral,
        })
    }
    pub fn send(&self, link: String, frames: Frames) -> Result<()> {
        if link.starts_with("p:") {
            self.peripheral
                .as_ref()
                .context("Peripheral unavailable")?
                .try_send((link, frames))
                .context("BLE peripheral queue full")?;
        } else {
            self.writers
                .lock()
                .expect("writers lock")
                .get(&link)
                .context("BLE link lost")?
                .try_send(frames)
                .context("BLE link queue full")?;
        }
        Ok(())
    }
}
impl Drop for Radio {
    fn drop(&mut self) {
        self.jobs.abort_all();
        self.writers.lock().expect("writers lock").clear();
    }
}
struct Disconnect(Peripheral);
impl Drop for Disconnect {
    fn drop(&mut self) {
        let peer = self.0.clone();
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(2), peer.disconnect()).await;
        });
    }
}
async fn connection(
    peer: Peripheral,
    id: String,
    writers: Writers,
    tx: mpsc::Sender<Event>,
) -> Result<()> {
    let _guard = Disconnect(peer.clone());
    peer.connect_with_timeout(Duration::from_secs(8)).await?;
    let uuid = Uuid::parse_str(shum_core::wire::CHARACTERISTIC_UUID)?;
    let service = Uuid::parse_str(shum_core::wire::SERVICE_UUID)?;
    let mut characteristic = None;
    // An iPhone can be connected while its GATT service is being republished.
    // Retry discovery on that connection before falling back to reconnecting.
    for attempt in 0..3 {
        peer.discover_services_with_timeout(Duration::from_secs(8))
            .await?;
        characteristic = peer
            .characteristics()
            .into_iter()
            .find(|c| c.uuid == uuid && c.service_uuid == service);
        if characteristic.is_some() {
            break;
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    }
    let characteristic = characteristic.context("Shum GATT characteristic missing")?;
    let mut receive = peer.notifications().await?;
    timeout(Duration::from_secs(5), peer.subscribe(&characteristic)).await??;
    let budget = usize::from(peer.mtu()).saturating_sub(3).min(512);
    let rssi = peer.properties().await?.and_then(|p| p.rssi);
    let (send, mut outbound) = mpsc::channel::<Frames>(64);
    writers
        .lock()
        .expect("writers lock")
        .insert(id.clone(), send);
    tx.send(Event::Connected {
        link: id.clone(),
        budget,
        rssi,
    })
    .await?;
    let mut signal = tokio::time::interval(Duration::from_secs(5));
    // The writer and reader run independently so large fragmented sends do not lose inbound ACKs.
    let write_peer = peer.clone();
    let write_char = characteristic.clone();
    let mut writer = tokio::spawn(async move {
        while let Some(frames) = outbound.recv().await {
            for frame in frames {
                timeout(
                    Duration::from_secs(5),
                    write_peer.write(&write_char, &frame, WriteType::WithoutResponse),
                )
                .await??;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    struct Abort<T>(tokio::task::AbortHandle, std::marker::PhantomData<T>);
    impl<T> Drop for Abort<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _writer_guard = Abort::<()>(writer.abort_handle(), std::marker::PhantomData);
    loop {
        tokio::select! {
            value=receive.next()=>match value {Some(value) if value.uuid==uuid=>{tx.send(Event::Data{link:id.clone(),bytes:value.value}).await?;},Some(_)=>{},None=>break},
            result=&mut writer=>{result??;break;},
            _=signal.tick()=>{if !peer.is_connected().await?{break;}
                if let Ok(Ok(rssi))=timeout(Duration::from_secs(1),peer.read_rssi()).await{let _=tx.send(Event::Rssi(id.clone(),rssi)).await;}}
        }
    }
    Ok(())
}
async fn central(writers: Writers, tx: mpsc::Sender<Event>) -> Result<()> {
    let manager = timeout(Duration::from_secs(10), Manager::new()).await??;
    let adapter = timeout(Duration::from_secs(10), manager.adapters())
        .await??
        .into_iter()
        .next()
        .context("Bluetooth adapter not found")?;
    let uuid = Uuid::parse_str(shum_core::wire::SERVICE_UUID)?;
    let mut events = adapter.events().await?;
    let mut links = JoinSet::new();
    let mut active = HashMap::<String, Instant>::new();
    let mut retry_after = HashMap::<String, Instant>::new();
    let mut scan = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _=scan.tick()=>{
                match timeout(Duration::from_secs(3),adapter.start_scan(ScanFilter{services:vec![uuid]})).await {
                    Ok(Ok(()))=>{let _=tx.send(Event::State{role:"scan",state:"scanning".into()}).await;},
                    Ok(Err(error))=>{let _=tx.send(Event::State{role:"scan",state:error.to_string()}).await;},
                    Err(_)=>{let _=tx.send(Event::State{role:"scan",state:"Bluetooth scan timed out".into()}).await;},
                }
                for peer in adapter.peripherals().await? {
                    let id=format!("c:{}",peer.id());
                    if active.contains_key(&id) || links.len()>=6
                        || retry_after.get(&id).is_some_and(|at|*at>Instant::now()) {continue;}
                    let Some(properties)=peer.properties().await? else {continue;};
                    if (!properties.services.contains(&uuid) && !cfg!(target_os="macos")) || properties.rssi.is_some_and(|r|r< -95) {continue;}
                    active.insert(id.clone(),Instant::now());
                    let writers=writers.clone();let events=tx.clone();
                    links.spawn(async move {
                        let result=connection(peer,id.clone(),writers.clone(),events.clone()).await;
                        writers.lock().expect("writers lock").remove(&id);
                        let _=events.send(Event::Disconnected(id.clone())).await;
                        // Connection errors are reported without remote device names or addresses.
                        if let Err(e)=result{let _=events.send(Event::State{role:"link",state:e.to_string()}).await;}
                        id
                    });
                }
            },
            event=events.next()=>{if event.is_none(){anyhow::bail!("Bluetooth event stream closed");}},
            Some(result)=links.join_next(),if !links.is_empty()=>{if let Ok(id)=result{active.remove(&id);retry_after.insert(id,Instant::now()+Duration::from_secs(10));}},
            _=tx.closed()=>{let _=adapter.stop_scan().await;break;},
        }
    }
    Ok(())
}
