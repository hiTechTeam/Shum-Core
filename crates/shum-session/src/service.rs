//! Local service: one process owns a profile and serves its [`Session`] to
//! every client on this device (CLI, desktop app) over authenticated loopback.
//!
//! The owner writes `<root>/<profile>/daemon.json` (mode 0600) with a port and
//! a random token. A client sends the 32-byte token, then one length-prefixed
//! JSON [`Request`], and reads one length-prefixed reply: `{"ok": value}` or
//! `{"error": text, "failure": Failure}`. Starting the owner process is the
//! client's business; this module only serves, calls and stops it.
use crate::{random, Command, Failure, Request, Session};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use shum_store::profiles::Profiles;
use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Semaphore},
    task::JoinSet,
    time::timeout,
};

const LIMIT: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Endpoint {
    port: u16,
    token: String,
    pid: u32,
}

fn text(text: &'static str) -> anyhow::Error {
    Failure::text(text).into()
}

/// Where the owner of profile `id` publishes its address.
pub fn endpoint(root: &Path, id: &str) -> PathBuf {
    root.join(id).join("daemon.json")
}

/// A profile marked locked must not be opened by any process.
pub fn is_locked(root: &Path, id: &str) -> bool {
    root.join(id).join("locked").exists()
}

fn read_endpoint(root: &Path, id: &str) -> Result<Endpoint> {
    let path = endpoint(root, id);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err(text("Недействительный адрес службы"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(text("Адрес службы должен иметь права 0600"));
        }
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > LIMIT {
        return Err(text("Ответ превышает лимит IPC"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > LIMIT {
        return Err(text("Размер IPC превышает лимит"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Sends one request to the process that owns profile `id`. A refused request
/// comes back as a [`Failure`] inside the error.
pub async fn request(root: &Path, id: &str, request: Request) -> Result<Value> {
    let endpoint = read_endpoint(root, id)?;
    let mut stream = timeout(
        Duration::from_secs(2),
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, endpoint.port)),
    )
    .await??;
    let token: Vec<u8> = hex::decode(&endpoint.token)?;
    if token.len() != 32 {
        return Err(text("Недействительный токен службы"));
    }
    timeout(Duration::from_secs(2), stream.write_all(&token)).await??;
    timeout(
        Duration::from_secs(2),
        write_frame(&mut stream, &serde_json::to_vec(&request)?),
    )
    .await??;
    let response: Value =
        serde_json::from_slice(&timeout(Duration::from_secs(25), read_frame(&mut stream)).await??)?;
    if let Ok(failure) = serde_json::from_value::<Failure>(response["failure"].clone()) {
        return Err(failure.into());
    }
    // Services before the structured failure sent only a worded error.
    if let Some(error) = response["error"].as_str() {
        return Err(Failure::text(error).into());
    }
    Ok(response["ok"].clone())
}

/// Asks the owner of profile `id` to stop and waits until it has. An endpoint
/// left by a crashed owner is removed only when the database lock proves no
/// process holds the profile.
pub async fn stop(root: &Path, id: &str) -> Result<()> {
    if !endpoint(root, id).exists() {
        return Ok(());
    }
    if let Err(error) = request(root, id, Request::Stop).await {
        let lock_path = root.join(id).join("messages.sqlite.lock");
        let metadata = fs::symlink_metadata(&lock_path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(text("Недействительная блокировка базы профиля"));
        }
        let Ok(lock) = OpenOptions::new().read(true).write(true).open(lock_path) else {
            return Err(error);
        };
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
            return Err(error);
        }
        fs::remove_file(endpoint(root, id))?;
        return Ok(());
    }
    for _ in 0..50 {
        if !endpoint(root, id).exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(text("Служба не завершилась за 5 секунд"))
}

struct EndpointGuard(PathBuf);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Opens profile `id`, runs its session and serves it until `shutdown`
/// resolves or a client sends [`Request::Stop`]. `client` describes the owner
/// process (version, build) and is merged into every snapshot.
pub async fn serve(
    root: &Path,
    id: &str,
    client: Map<String, Value>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    if is_locked(root, id) {
        return Err(text("Профиль заблокирован"));
    }
    let profiles = Profiles::new(root)?;
    let open = profiles.open(Some(id))?;
    let settings = &open.store.state()["cliSettings"];
    let relays: Vec<String> = if settings["relays"].is_array() {
        serde_json::from_value(settings["relays"].clone())?
    } else {
        shum_transport_nostr::DEFAULT_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let push = settings["pushURL"].as_str().map(str::to_owned);
    let session = Session::new(open, &relays, push.as_deref(), client)?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let token = random::<32>()?;
    let info = Endpoint {
        port: listener.local_addr()?.port(),
        token: hex::encode(token),
        pid: std::process::id(),
    };
    let path = endpoint(root, id);
    let mut temp = tempfile::NamedTempFile::new_in(root.join(id))?;
    temp.write_all(&serde_json::to_vec(&info)?)?;
    temp.as_file().sync_all()?;
    temp.persist(&path)?;
    let _guard = EndpointGuard(path);
    let (commands, receive) = mpsc::channel(128);
    let mut task = tokio::spawn(session.run(receive, shutdown));
    let slots = Arc::new(Semaphore::new(32));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            result = &mut task => {
                let _ = timeout(Duration::from_secs(1), async {
                    while clients.join_next().await.is_some() {}
                })
                .await;
                clients.abort_all();
                return result?;
            }
            result = listener.accept() => {
                let (stream, address) = result?;
                if !address.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let commands = commands.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(Duration::from_secs(30), answer(stream, token, commands)).await;
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

async fn answer(
    mut stream: TcpStream,
    token: [u8; 32],
    commands: mpsc::Sender<Command>,
) -> Result<()> {
    let mut presented = [0; 32];
    stream.read_exact(&mut presented).await?;
    // Constant-time comparison of the presented token.
    if presented
        .iter()
        .zip(token)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        != 0
    {
        bail!("unauthorized");
    }
    let request: Request = serde_json::from_slice(&read_frame(&mut stream).await?)?;
    let (reply, received) = oneshot::channel();
    commands
        .send(Command { request, reply })
        .await
        .map_err(|_| anyhow!("daemon closed"))?;
    let response = match received.await? {
        Ok(value) => json!({ "ok": value }),
        Err(failure) => json!({ "error": failure.to_string(), "failure": failure }),
    };
    write_frame(&mut stream, &serde_json::to_vec(&response)?).await
}

/// The own card and chat count of profile `id` without taking it over: asked
/// from its running owner, or read from its database when nobody owns it.
/// A locked profile, or one that cannot be read right now, gives `None`.
pub async fn preview(root: &Path, id: &str) -> Option<Value> {
    if is_locked(root, id) {
        return None;
    }
    if endpoint(root, id).exists() {
        let snapshot = timeout(
            Duration::from_millis(250),
            request(root, id, Request::Snapshot),
        )
        .await
        .ok()?
        .ok()?;
        let chats = snapshot["contacts"].as_array().map_or(0, Vec::len);
        return Some(json!({ "card": snapshot["card"], "chatCount": chats }));
    }
    let root = root.to_owned();
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || {
        let profiles = Profiles::new(root).ok()?;
        let open = profiles.open(Some(&id)).ok()?;
        let state = open.store.state();
        Some(json!({
            "card": state["ownProfileCard"],
            "chatCount": state["contacts"].as_array().map_or(0, Vec::len),
        }))
    })
    .await
    .ok()?
}
