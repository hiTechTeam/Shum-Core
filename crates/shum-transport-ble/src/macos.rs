use super::radio::Event;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{io::Write, os::unix::fs::PermissionsExt, path::Path};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::mpsc,
    task::JoinSet,
};
const HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shum-ble-peripheral"));
pub fn start(
    directory: &Path,
    jobs: &mut JoinSet<()>,
    events: mpsc::Sender<Event>,
) -> Result<mpsc::Sender<(String, Vec<Vec<u8>>)>> {
    let path = directory.join("ble-peripheral");
    // Atomic replacement preserves an existing running executable's inode.
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(HELPER)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    file.persist(&path)?;
    let mut child = tokio::process::Command::new(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("BLE helper stdin")?;
    let mut output = BufReader::new(child.stdout.take().context("BLE helper stdout")?).lines();
    let (commands, mut pending) = mpsc::channel::<(String, Vec<Vec<u8>>)>(64);
    jobs.spawn(async move {
        let mut writing = false;
        let result=async {
            loop {tokio::select! {
                value=output.next_line()=>{let Some(line)=value? else {break;};if line.len()>2_000_000 {break;}
                    let value:Value=serde_json::from_str(&line)?;let id=value["id"].as_str().unwrap_or("").to_owned();
                    let event=match value["kind"].as_str(){
                        Some("writable")=>{writing=false;continue;},
                        Some("connected")=>Event::Connected{link:id,budget:value["budget"].as_u64().unwrap_or(20) as usize,rssi:None},
                        Some("disconnected")=>Event::Disconnected(id),
                        Some("data")=>Event::Data{link:id,bytes:STANDARD.decode(value["data"].as_str().unwrap_or(""))?},
                        Some("advertising")=>Event::State{role:"advertise",state:"advertising".into()},
                        Some("state")=>Event::State{role:"advertise",state:value["state"].as_str().unwrap_or("unknown").into()},
                        Some("error")=>Event::State{role:"advertise",state:value["error"].as_str().unwrap_or("error").into()},_=>continue,
                    };events.send(event).await?;
                },
                Some((link,frames))=pending.recv(),if !writing=>{writing=true;let encoded=frames.iter().map(|f|STANDARD.encode(f)).collect::<Vec<_>>();let mut line=serde_json::to_vec(&json!({"to":link,"frames":encoded}))?;line.push(b'\n');input.write_all(&line).await?;},
                _=events.closed()=>break,
            }}
            child.kill().await?;Ok::<(),anyhow::Error>(())
        }.await;
        let state=result.err().map(|e|e.to_string()).unwrap_or_else(||"Peripheral stopped".into());
        let _=events.send(Event::State{role:"advertise",state}).await;
    });
    Ok(commands)
}
