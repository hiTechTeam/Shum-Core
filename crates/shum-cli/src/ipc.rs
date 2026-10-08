//! Local authenticated IPC. The daemon alone owns a profile database.
use crate::runtime::{Command, Request, Runtime};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shum_store::profiles::{Profile, Profiles};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Semaphore},
    time::timeout,
};

const LIMIT: usize = 16 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Endpoint {
    port: u16,
    token: String,
    pid: u32,
}
pub fn select(profiles: &Profiles, selector: Option<&str>) -> Result<Profile> {
    let (selected, list) = profiles.list()?;
    let name = selector
        .or(selected.as_deref())
        .ok_or_else(|| anyhow!("Профиля пока нет. Выполните shum init."))?;
    list.into_iter()
        .find(|p| !p.deleting && (p.id == name || p.name == name))
        .ok_or_else(|| anyhow!("Профиль не найден: {name}"))
}
fn endpoint(root: &Path, id: &str) -> PathBuf {
    root.join(id).join("daemon.json")
}
fn read_endpoint(root: &Path, id: &str) -> Result<Endpoint> {
    let path = endpoint(root, id);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        bail!("Недействительный адрес службы");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("Адрес службы должен иметь права 0600");
        }
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > LIMIT {
        bail!("Ответ превышает лимит IPC");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > LIMIT {
        bail!("Размер IPC превышает лимит");
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn request(root: &Path, id: &str, request: Request) -> Result<Value> {
    let endpoint = read_endpoint(root, id)?;
    let mut stream = timeout(
        Duration::from_secs(2),
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, endpoint.port)),
    )
    .await??;
    let token: Vec<u8> = hex::decode(&endpoint.token)?;
    if token.len() != 32 {
        bail!("Недействительный токен службы");
    }
    timeout(Duration::from_secs(2), stream.write_all(&token)).await??;
    timeout(
        Duration::from_secs(2),
        write_frame(&mut stream, &serde_json::to_vec(&request)?),
    )
    .await??;
    let response: Value =
        serde_json::from_slice(&timeout(Duration::from_secs(25), read_frame(&mut stream)).await??)?;
    if let Some(error) = response["error"].as_str() {
        bail!("{error}");
    }
    Ok(response["ok"].clone())
}
pub async fn ensure(root: &Path, id: &str) -> Result<()> {
    if request(root, id, Request::Snapshot).await.is_ok() {
        return Ok(());
    }
    if root.join(id).join("locked").exists() {
        bail!("Профиль заблокирован. Выполните shum unlock.");
    }
    let executable = std::env::current_exe()?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let log = options.open(root.join(id).join("daemon.log"))?;
    let mut command = Process::new(executable);
    command
        .arg("--data-dir")
        .arg(root)
        .arg("--profile")
        .arg(id)
        .args(["daemon", "--run"])
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x08000000);
    }
    let mut child = command
        .spawn()
        .context("Не удалось запустить службу Shum")?;
    for _ in 0..100 {
        if request(root, id, Request::Snapshot).await.is_ok() {
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            // Another CLI may have won the exclusive profile lock while starting.
            tokio::time::sleep(Duration::from_millis(200)).await;
            if request(root, id, Request::Snapshot).await.is_ok() {
                return Ok(());
            }
            bail!(
                "Служба завершилась. Диагностика: {}",
                root.join(id).join("daemon.log").display()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("Служба не запустилась за 10 секунд")
}
pub async fn stop(root: &Path, id: &str) -> Result<()> {
    if !endpoint(root, id).exists() {
        return Ok(());
    }
    if let Err(error) = request(root, id, Request::Stop).await {
        // Only an acquired database lock proves that an endpoint is stale.
        let profiles = Profiles::new(root)?;
        let open = profiles.open(Some(id)).map_err(|_| error)?;
        let _ = fs::remove_file(endpoint(root, id));
        drop(open);
        return Ok(());
    }
    for _ in 0..50 {
        if !endpoint(root, id).exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("Служба не завершилась за 5 секунд")
}
struct EndpointGuard(PathBuf);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub async fn serve(root: &Path, id: &str) -> Result<()> {
    if root.join(id).join("locked").exists() {
        bail!("Профиль заблокирован");
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
    let runtime = Runtime::new(open, &relays, push.as_deref())?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let token = crate::runtime::random::<32>()?;
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
    let mut task = tokio::spawn(runtime.run(receive));
    let slots = std::sync::Arc::new(Semaphore::new(32));
    let mut clients = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result=&mut task=>{let _=timeout(Duration::from_secs(1),async {while clients.join_next().await.is_some(){}}).await;clients.abort_all();return result?;},
            result=listener.accept()=>{let (mut stream,address)=result?;if !address.ip().is_loopback(){continue;}let Ok(permit)=slots.clone().try_acquire_owned() else{continue;};let commands=commands.clone();clients.spawn(async move {let _permit=permit;let _=timeout(Duration::from_secs(30),async {
                let mut presented=[0;32];stream.read_exact(&mut presented).await?;if presented.iter().zip(token).fold(0u8,|difference,(a,b)|difference|(*a^b))!=0{bail!("unauthorized");}
                let bytes=read_frame(&mut stream).await?;let request:Request=serde_json::from_slice(&bytes)?;
                let (reply,received)=oneshot::channel();commands.send(Command {request,reply}).await.map_err(|_|anyhow!("daemon closed"))?;
                let response=match received.await?{Ok(value)=>serde_json::json!({"ok":value}),Err(error)=>serde_json::json!({"error":error})};write_frame(&mut stream,&serde_json::to_vec(&response)?).await?;Ok::<(),anyhow::Error>(())
            }).await;});},
            _=clients.join_next(),if !clients.is_empty()=>{}
        }
    }
}
