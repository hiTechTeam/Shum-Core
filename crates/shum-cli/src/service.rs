use anyhow::{bail, Context, Result};
use std::{path::Path, process::Command};
fn run(command: &mut Command) -> Result<()> {
    let result = command.output()?;
    if !result.status.success() {
        bail!(
            "Системная служба: {}",
            crate::terminal::safe(&String::from_utf8_lossy(&result.stderr))
        );
    }
    Ok(())
}
pub fn install(root: &Path, id: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "macos")]
    {
        fn xml(value: &str) -> String {
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        }
        let home = directories::BaseDirs::new()
            .context("Домашний каталог недоступен")?
            .home_dir()
            .to_owned();
        let directory = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&directory)?;
        let label = format!("org.shum.cli.{id}");
        let file = directory.join(format!("{label}.plist"));
        let args = [
            exe.display().to_string(),
            "--data-dir".into(),
            root.display().to_string(),
            "--profile".into(),
            id.into(),
            "daemon".into(),
            "--run".into(),
        ]
        .iter()
        .map(|s| format!("<string>{}</string>", xml(s)))
        .collect::<String>();
        let log = xml(&root.join(id).join("service.log").display().to_string());
        let plist=format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><false/><key>StandardOutPath</key><string>{log}</string><key>StandardErrorPath</key><string>{log}</string></dict></plist>");
        std::fs::write(&file, plist)?;
        let uid = Command::new("id").arg("-u").output()?;
        let uid = std::str::from_utf8(&uid.stdout)?.trim();
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/{label}")])
            .output();
        run(Command::new("launchctl")
            .args(["bootstrap", &format!("gui/{uid}")])
            .arg(file))?;
    }
    #[cfg(target_os = "linux")]
    {
        fn quote(value: &str) -> String {
            format!(
                "\"{}\"",
                value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('%', "%%")
                    .replace('$', "$$")
            )
        }
        let config = directories::BaseDirs::new()
            .context("Нет каталога конфигурации")?
            .config_dir()
            .join("systemd/user");
        std::fs::create_dir_all(&config)?;
        let name = format!("shum-{id}.service");
        let unit=format!("[Unit]\nDescription=Shum profile {id}\nAfter=network-online.target\n[Service]\nType=simple\nExecStart={} --data-dir {} --profile {id} daemon --run\nRestart=on-failure\nRestartSec=10\n[Install]\nWantedBy=default.target\n",quote(&exe.display().to_string()),quote(&root.display().to_string()));
        std::fs::write(config.join(&name), unit)?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("systemctl").args(["--user", "enable", "--now", &name]))?;
    }
    #[cfg(target_os = "windows")]
    {
        let arguments = format!(
            "\"{}\" --data-dir \"{}\" --profile {} daemon --run",
            exe.display(),
            root.display(),
            id
        );
        run(Command::new("schtasks").args([
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/TN",
            &format!("Shum-{id}"),
            "/TR",
            &arguments,
        ]))?;
        run(Command::new("schtasks").args(["/Run", "/TN", &format!("Shum-{id}")]))?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    bail!("Автозапуск на этой системе не поддерживается");
    Ok(())
}
