use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use shum_core::nostr::Event;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{broadcast, Mutex},
    time::{sleep, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};
const BIN: &str = env!("CARGO_BIN_EXE_shum");
fn command(root: &Path, profile: Option<&str>, args: &[&str]) -> Value {
    let mut command = Command::new(BIN);
    command.arg("--data-dir").arg(root).arg("--json");
    if let Some(profile) = profile {
        command.args(["-p", profile]);
    }
    let result = command.args(args).output().unwrap();
    assert!(
        result.status.success(),
        "{:?}: {} {}",
        args,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn daemon(root: &Path, profile: &str) -> Daemon {
    Daemon(
        Command::new(BIN)
            .arg("--data-dir")
            .arg(root)
            .args(["-p", profile, "daemon", "--run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
async fn snapshot(root: &Path, id: &str) -> Value {
    shum_cli::ipc::request(root, id, shum_cli::runtime::Request::Snapshot)
        .await
        .unwrap()
}
async fn wait(root: &Path, id: &str, predicate: impl Fn(&Value) -> bool) -> Value {
    let mut last = Value::Null;
    let result = timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(value) =
                shum_cli::ipc::request(root, id, shum_cli::runtime::Request::Snapshot).await
            {
                last = value.clone();
                if predicate(&value) {
                    return value;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| {
        panic!(
            "expected state within 15 seconds: relays={} contacts={} messages={} error={}",
            last["relays"], last["contacts"], last["messages"], last["error"]
        )
    })
}
async fn relay() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (events, _) = broadcast::channel::<Event>(128);
    let stored = Arc::new(Mutex::new(Vec::<Event>::new()));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let stored = stored.clone();
            let events = events.clone();
            tokio::spawn(async move {
                let mut socket = accept_async(stream).await.unwrap();
                let mut receive = events.subscribe();
                let mut recipient = String::new();
                loop {
                    tokio::select! {
                     message=socket.next()=>{let Some(Ok(message))=message else{break;};match message {Message::Text(text)=>{let v:Value=serde_json::from_str(&text).unwrap();match v[0].as_str(){Some("REQ")=>{recipient=v[2]["#p"][0].as_str().unwrap().to_owned();let all=stored.lock().await.clone();for event in all.iter().filter(|e|e.tags==vec![vec!["p".to_owned(),recipient.clone()]]){if socket.send(Message::Text(json!(["EVENT","shum-private-v1",event]).to_string().into())).await.is_err(){return;}}let _=socket.send(Message::Text(json!(["EOSE","shum-private-v1"]).to_string().into())).await;},Some("EVENT")=>{let event:Event=serde_json::from_value(v[1].clone()).unwrap();assert!(event.verify());stored.lock().await.push(event.clone());let _=socket.send(Message::Text(json!(["OK",event.id,true,""]).to_string().into())).await;let _=events.send(event);},_=>{}}},Message::Ping(payload)=>{let _=socket.send(Message::Pong(payload)).await;},Message::Close(_)=>break,_=>{}}},
                     event=receive.recv()=>{if let Ok(event)=event{if event.tags==vec![vec!["p".to_owned(),recipient.clone()]]&&socket.send(Message::Text(json!(["EVENT","shum-private-v1",event]).to_string().into())).await.is_err(){break;}}}
                    }
                }
            });
        }
    });
    (url, task)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_cli_invitation_messages_receipts_profile_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    let (relay, server) = relay().await;
    let a = command(
        &root,
        None,
        &[
            "--relay",
            &relay,
            "--push-url",
            "off",
            "init",
            "--name",
            "Alice",
            "--headless",
        ],
    );
    let b = command(
        &root,
        None,
        &[
            "--relay",
            &relay,
            "--push-url",
            "off",
            "init",
            "--name",
            "Bob",
            "--headless",
        ],
    );
    let aid = a["profile"]["id"].as_str().unwrap();
    let bid = b["profile"]["id"].as_str().unwrap();
    let aowner = a["profile"]["ownerId"].as_str().unwrap();
    let bowner = b["profile"]["ownerId"].as_str().unwrap();
    let mut da = daemon(&root, aid);
    let mut db = daemon(&root, bid);
    wait(&root, aid, |s| {
        s["relays"].as_array().is_some_and(|r| !r.is_empty())
    })
    .await;
    wait(&root, bid, |s| {
        s["relays"].as_array().is_some_and(|r| !r.is_empty())
    })
    .await;
    let locator = format!(
        "shum://c2/{}",
        URL_SAFE_NO_PAD.encode(hex::decode(b["card"]["nostrKey"].as_str().unwrap()).unwrap())
    );
    command(&root, Some(aid), &["add", &locator]);
    let qr = qrcode::QrCode::with_error_correction_level(
        a["invitation"].as_str().unwrap(),
        qrcode::EcLevel::M,
    )
    .unwrap();
    let size = qr.width();
    let pixels =
        image::GrayImage::from_fn(((size + 8) * 5) as u32, ((size + 8) * 5) as u32, |x, y| {
            let x = x as usize / 5;
            let y = y as usize / 5;
            image::Luma([
                if x >= 4
                    && y >= 4
                    && x < size + 4
                    && y < size + 4
                    && qr[(x - 4, y - 4)] == qrcode::Color::Dark
                {
                    0
                } else {
                    255
                },
            ])
        });
    let png = dir.path().join("invite.png");
    pixels.save(&png).unwrap();
    command(&root, Some(bid), &["add", "--image", png.to_str().unwrap()]);
    command(&root, Some(aid), &["invite", "Bob"]);
    wait(&root, bid, |s| {
        s["contacts"][0]["phase"] == "incomingPending"
    })
    .await;
    command(&root, Some(bid), &["accept", "Alice"]);
    wait(&root, aid, |s| s["contacts"][0]["phase"] == "accepted").await;
    command(&root, Some(aid), &["send", "Bob", "Привет с CLI 🦀"]);
    let received = wait(&root, bid, |s| {
        s["messages"].as_array().is_some_and(|m| m.len() == 1)
    })
    .await;
    assert_eq!(received["messages"][0]["text"], "Привет с CLI 🦀");
    wait(&root, aid, |s| s["messages"][0]["status"] == "delivered").await;
    command(&root, Some(bid), &["read", "Alice"]);
    wait(&root, aid, |s| s["messages"][0]["status"] == "read").await;
    command(&root, Some(bid), &["send", "Alice", "Ответ"]);
    wait(&root, aid, |s| {
        s["messages"].as_array().is_some_and(|m| m.len() == 2)
    })
    .await;
    let message = received["messages"][0]["id"].as_str().unwrap();
    command(&root, Some(bid), &["react", message, "like"]);
    wait(&root, aid, |s| {
        s["reactions"].as_array().is_some_and(|m| !m.is_empty())
    })
    .await;
    command(&root, Some(bid), &["profile", "name", "Боб"]);
    wait(&root, aid, |s| s["contacts"][0]["card"]["name"] == "Боб").await;
    assert!(command(&root, None, &["profile", "list"])["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == bid && p["name"] == "Боб"));
    command(&root, Some(bid), &["profile", "avatar", "--seed", "42"]);
    wait(&root, aid, |s| s["contacts"][0]["card"]["avatarSeed"] == 42).await;
    shum_cli::ipc::request(
        &root,
        bid,
        shum_cli::runtime::Request::Focus {
            contact: Some(aowner.into()),
        },
    )
    .await
    .unwrap();
    shum_cli::ipc::request(
        &root,
        bid,
        shum_cli::runtime::Request::Typing {
            contact: aowner.into(),
            active: true,
        },
    )
    .await
    .unwrap();
    wait(&root, aid, |s| s["contacts"][0]["typing"] == true).await;
    command(&root, Some(aid), &["daemon", "--stop"]);
    let _ = da.0.wait();
    da = daemon(&root, aid);
    let restored = wait(&root, aid, |s| {
        s["messages"].as_array().is_some_and(|m| m.len() == 2)
    })
    .await;
    assert_eq!(restored["messages"][0]["text"], "Привет с CLI 🦀");
    assert_eq!(restored["contacts"][0]["id"], bowner);
    assert_eq!(restored["messages"][0]["status"], "read");
    // An abrupt recipient crash leaves an endpoint, then the relay stores mail.
    db.0.kill().unwrap();
    db.0.wait().unwrap();
    command(&root, Some(aid), &["send", bowner, "Пока ты офлайн"]);
    wait(&root, aid, |s| s["messages"][2]["status"] == "forwarding").await;
    command(&root, Some(aid), &["daemon", "--stop"]);
    da.0.wait().unwrap();
    da = daemon(&root, aid);
    wait(&root, aid, |s| s["messages"][2]["status"] == "forwarding").await;
    db = daemon(&root, bid);
    wait(&root, bid, |s| {
        s["messages"].as_array().is_some_and(|m| m.len() == 3)
    })
    .await;
    wait(&root, aid, |s| s["messages"][2]["status"] == "delivered").await;
    command(&root, Some(bid), &["daemon", "--stop"]);
    command(&root, Some(aid), &["send", bowner, "Отменить"]);
    let pending = wait(&root, aid, |s| {
        s["messages"].as_array().is_some_and(|m| m.len() == 4)
    })
    .await;
    command(
        &root,
        Some(aid),
        &["cancel", pending["messages"][3]["id"].as_str().unwrap()],
    );
    assert!(snapshot(&root, aid).await["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["id"] != pending["messages"][3]["id"]));
    command(&root, Some(aid), &["clear", bowner, "--confirm"]);
    assert!(snapshot(&root, aid).await["messages"]
        .as_array()
        .unwrap()
        .is_empty());
    command(&root, Some(aid), &["daemon", "--stop"]);
    command(&root, Some(bid), &["daemon", "--stop"]);
    drop(da);
    drop(db);
    // The public command starts its own daemon, without a manual `daemon --run`.
    command(&root, Some(aid), &["status"]);
    command(&root, Some(aid), &["lock"]);
    let locked = Command::new(BIN)
        .arg("--data-dir")
        .arg(&root)
        .args(["--json", "-p", aid, "chats"])
        .output()
        .unwrap();
    assert!(!locked.status.success());
    command(&root, Some(aid), &["unlock"]);
    command(&root, Some(aid), &["daemon", "--stop"]);
    server.abort();
}

fn rejected(root: &Path, profile: &str, args: &[&str]) -> Value {
    let result = Command::new(BIN)
        .arg("--data-dir")
        .arg(root)
        .args(["--json", "-p", profile])
        .args(args)
        .output()
        .unwrap();
    assert!(!result.status.success(), "unexpected success: {args:?}");
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["error"].is_string() || value["success"] == false);
    value
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn command_filters_decline_block_cancel_profile_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    let (url, relay) = relay().await;
    let a = command(
        &root,
        None,
        &[
            "--relay",
            &url,
            "--push-url",
            "off",
            "init",
            "--name",
            "A",
            "--headless",
        ],
    );
    let b = command(
        &root,
        None,
        &[
            "--relay",
            &url,
            "--push-url",
            "off",
            "init",
            "--name",
            "B",
            "--headless",
        ],
    );
    let aid = a["profile"]["id"].as_str().unwrap();
    let bid = b["profile"]["id"].as_str().unwrap();
    let da = daemon(&root, aid);
    let db = daemon(&root, bid);
    wait(&root, aid, |s| !s["relays"].as_array().unwrap().is_empty()).await;
    wait(&root, bid, |s| !s["relays"].as_array().unwrap().is_empty()).await;
    command(
        &root,
        Some(aid),
        &["add", b["invitation"].as_str().unwrap()],
    );
    command(
        &root,
        Some(bid),
        &["add", a["invitation"].as_str().unwrap()],
    );
    assert_eq!(
        command(&root, Some(aid), &["contacts"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(command(&root, Some(aid), &["invite"])["link"]
        .as_str()
        .unwrap()
        .starts_with("shum://c4/"));
    assert!(
        command(&root, Some(aid), &["keys", "verify", "B", "--qr"])["iosFingerprint"].is_string()
    );
    for args in [&["status"][..], &["about"], &["profile"], &["daemon"]] {
        assert!(command(&root, Some(aid), args)["card"].is_object());
    }
    for args in [
        &["chats", "--nearby"][..],
        &["chats", "--unread"],
        &["chats", "--invites"],
    ] {
        assert!(command(&root, Some(aid), args)["contacts"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    for args in [
        &["add"][..],
        &["add", "not-a-link"],
        &["profile", "avatar"],
        &["profile", "avatar", "--photo", "missing.png"],
        &["profile", "name", "B"],
        &["send", "B", "not yet accepted"],
        &["keys", "verify", "Missing"],
        &["clear", "B"],
        &["react", "missing", "invalid"],
    ] {
        rejected(&root, aid, args);
    }
    command(&root, Some(aid), &["profile", "bio", "О себе"]);
    command(&root, Some(aid), &["profile", "avatar", "--random"]);
    assert_eq!(
        command(&root, Some(aid), &["profile"])["card"]["bio"],
        "О себе"
    );
    command(&root, None, &["profile", "use", "A"]);
    assert_eq!(command(&root, None, &["profile", "list"])["selected"], aid);
    command(&root, Some(aid), &["invite", "B"]);
    wait(&root, bid, |s| {
        s["contacts"][0]["phase"] == "incomingPending"
    })
    .await;
    assert_eq!(
        command(&root, Some(bid), &["chats", "--invites"])["contacts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    command(&root, Some(bid), &["decline", "A"]);
    wait(&root, aid, |s| {
        s["contacts"][0]["phase"] == "declinedByPeer"
    })
    .await;
    command(&root, Some(bid), &["block", "A"]);
    assert!(command(&root, Some(bid), &["contacts"])
        .as_array()
        .unwrap()
        .is_empty());
    command(&root, Some(bid), &["block", "A", "--undo"]);
    assert_eq!(
        command(&root, Some(bid), &["contacts"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A local decline cannot immediately initiate a new invitation in v1.
    rejected(&root, bid, &["invite", "A"]);
    command(&root, Some(bid), &["daemon", "--stop"]);
    command(&root, Some(aid), &["daemon", "--stop"]);
    drop(da);
    drop(db);
    rejected(
        &root,
        aid,
        &["profile", "delete", "A", "--confirm", "wrong"],
    );
    command(&root, None, &["profile", "delete", "A", "--confirm", "A"]);
    command(&root, None, &["profile", "delete", "B", "--confirm", "B"]);
    assert!(command(&root, None, &["profile", "list"])["profiles"]
        .as_array()
        .unwrap()
        .is_empty());
    relay.abort();
}
