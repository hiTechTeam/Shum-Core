use crate::display::{Colors, Display, ACCENT, LOGO, LOGO_COLOR, MUTED};
use anyhow::{bail, Result};
use ratatui::style::Color;
use serde_json::Value;
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Copy)]
pub enum Tone {
    Logo,
    Accent,
    Command,
    Warning,
    Error,
    Text,
    Muted,
}
impl Tone {
    fn color(self) -> Color {
        match self {
            Self::Logo => LOGO_COLOR,
            Self::Accent => ACCENT,
            Self::Command => Color::Rgb(83, 214, 255),
            Self::Warning => Color::Rgb(255, 214, 10),
            Self::Error => Color::Rgb(255, 69, 58),
            Self::Text => Color::Rgb(229, 231, 230),
            Self::Muted => MUTED,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Palette {
    colors: Colors,
    enabled: bool,
}
impl Palette {
    pub fn new(colors: Colors, enabled: bool) -> Self {
        Self { colors, enabled }
    }
    pub fn stdout(ascii: bool) -> Self {
        Self::detect(ascii, io::stdout().is_terminal())
    }
    pub fn stderr(ascii: bool) -> Self {
        Self::detect(ascii, io::stderr().is_terminal())
    }
    fn detect(ascii: bool, tty: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self::new(
            Display::detect().colors,
            tty && !ascii && !no_color && std::env::var("TERM").as_deref() != Ok("dumb"),
        )
    }
    pub fn paint(self, tone: Tone, value: impl AsRef<str>) -> String {
        let value = value.as_ref();
        if !self.enabled || value.is_empty() {
            return value.to_owned();
        }
        let sgr = match self.colors.color(tone.color()) {
            Color::Rgb(r, g, b) => format!("38;2;{r};{g};{b}"),
            Color::Indexed(index) => format!("38;5;{index}"),
            _ => unreachable!(),
        };
        // Only foreground colours: leave the shell background and later output intact.
        format!("\x1b[{sgr}m{value}\x1b[0m")
    }
    fn swatches(self) -> String {
        if !self.enabled {
            return String::new();
        }
        [
            Tone::Logo,
            Tone::Accent,
            Tone::Command,
            Tone::Warning,
            Tone::Error,
            Tone::Text,
            Tone::Muted,
        ]
        .into_iter()
        .map(|tone| self.paint(tone, "██"))
        .collect::<Vec<_>>()
        .join(" ")
    }
}
pub fn safe(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
        .collect()
}
pub fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}
pub fn fingerprint(card: &shum_core::card::Card) -> String {
    let id = card.id().to_uppercase();
    format!("{} {} {}", &id[..4], &id[4..8], &id[8..12])
}
pub fn find_contact<'a>(snapshot: &'a Value, selector: &str) -> Result<&'a Value> {
    let matches = snapshot["contacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            c["id"] == selector
                || c["card"]["name"] == selector
                || (selector.len() >= 8 && text(&c["id"]).starts_with(selector))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => bail!("Контакт не найден"),
        _ => bail!("Несколько контактов с этим именем. Укажите Shum ID"),
    }
}
pub fn print_qr(content: &str, ascii: bool) -> Result<()> {
    let code = qr(content, ascii)?;
    if Palette::stdout(ascii).enabled {
        for line in code.lines() {
            println!("\x1b[30;47m{line}\x1b[0m");
        }
    } else {
        print!("{code}");
    }
    Ok(())
}
pub fn trim_width(text: &str, width: usize) -> String {
    let mut output = String::new();
    for c in safe(text).chars() {
        let mut next = output.clone();
        next.push(c);
        if UnicodeWidthStr::width(next.as_str()) > width {
            break;
        }
        output = next;
    }
    output
}
pub fn qr(content: &str, ascii: bool) -> Result<String> {
    let qr = qrcode::QrCode::with_error_correction_level(content, qrcode::EcLevel::M)?;
    let size = qr.width() as isize;
    let dark = |x: isize, y: isize| {
        x >= 0
            && y >= 0
            && x < size
            && y < size
            && qr[(x as usize, y as usize)] == qrcode::Color::Dark
    };
    let mut output = String::new();
    if ascii {
        for y in -4..size + 4 {
            for x in -4..size + 4 {
                output.push_str(if dark(x, y) { "##" } else { "  " });
            }
            output.push('\n');
        }
    } else {
        for y in (-4..size + 4).step_by(2) {
            for x in -4..size + 4 {
                output.push(match (dark(x, y), dark(x, y + 1)) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    _ => ' ',
                });
            }
            output.push('\n');
        }
    }
    Ok(output)
}
pub fn decode_qr(path: &Path) -> Result<String> {
    if std::fs::metadata(path)?.len() > 32 * 1024 * 1024 {
        bail!("Изображение больше 32 MiB");
    }
    let mut reader = image::ImageReader::open(path)?.with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let pixels = reader.decode()?.to_luma8();
    let mut image = rqrr::PreparedImage::prepare(pixels);
    let grids = image.detect_grids();
    let links: std::collections::HashSet<_> = grids
        .iter()
        .filter_map(|g| g.decode().ok().map(|(_, text)| text))
        .filter(|text| shum_core::invitation::parse(text).is_ok())
        .collect();
    match links.len() {
        1 => Ok(links.into_iter().next().unwrap()),
        0 => bail!("QR с приглашением Shum не найден"),
        _ => bail!("На изображении несколько приглашений Shum"),
    }
}
pub fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        bail!("Ввод завершён");
    }
    Ok(value.trim().to_owned())
}
pub fn avatar(seed: u64, ascii: bool) {
    if !Palette::stdout(ascii).enabled {
        return;
    }
    if native_avatar(seed).unwrap_or(false) {
        return;
    }
    let avatar = crate::avatar::render_subject(seed);
    let pixels = avatar.sampled(18);
    let colors = crate::display::Display::detect().colors;
    for y in (0..18).step_by(2) {
        print!("  ");
        for x in 0..18 {
            let top = pixels[y * 18 + x];
            let bottom = pixels[(y + 1) * 18 + x];
            print!("\x1b[0m");
            match (top[3] > 0, bottom[3] > 0) {
                (false, false) => print!(" "),
                // Inverse video keeps the lower half at the shell background.
                (true, false) => print!("{}\x1b[7m▄", colors.sgr(top, false)),
                (false, true) => print!("{}▄", colors.sgr(bottom, false)),
                (true, true) if top == bottom => print!("{} ", colors.sgr(bottom, true)),
                (true, true) => print!("{}{}▄", colors.sgr(bottom, false), colors.sgr(top, true)),
            }
        }
        println!("\x1b[0m");
    }
}
fn native_avatar(seed: u64) -> Result<bool> {
    use ratatui_image::picker::{Picker, ProtocolType};
    let protocol = crate::display::Display::detect().images;
    if protocol == ProtocolType::Halfblocks {
        return Ok(false);
    }
    let mut picker = Picker::halfblocks();
    picker.set_protocol_type(protocol);
    let mut pictures = crate::ui::Pictures::new(picker);
    let mut terminal = ratatui::Terminal::with_options(
        ratatui::backend::CrosstermBackend::new(io::stdout()),
        ratatui::TerminalOptions {
            viewport: ratatui::Viewport::Inline(9),
        },
    )?;
    terminal.draw(|frame| {
        let mut area = frame.area();
        area.width = area.width.min(18);
        pictures.draw(frame, seed, area);
    })?;
    terminal.show_cursor()?;
    println!();
    Ok(true)
}
pub fn profile(snapshot: &Value, ascii: bool) {
    let card = &snapshot["card"];
    if let Some(seed) = card["avatarSeed"].as_u64() {
        avatar(seed, ascii);
    }
    let contacts = snapshot["contacts"].as_array().map_or(0, Vec::len);
    let chats = snapshot["contacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["phase"] == "accepted")
        .count();
    let fingerprint = serde_json::from_value::<shum_core::card::Card>(card.clone())
        .ok()
        .map(|c| fingerprint(&c))
        .unwrap_or_default();
    let palette = Palette::stdout(ascii);
    println!("  {} {}\n  {}\n\n  {} {chats}\n  {} {contacts}\n  {} пиксельный (для всех)\n  {} пока недоступно\n\n  {} {}\n  {} {}",
        palette.paint(Tone::Accent, safe(text(&card["name"]))),
        palette.paint(Tone::Muted, "· текущий"),
        palette.paint(Tone::Muted, safe(text(&card["bio"]))),
        palette.paint(Tone::Muted, "Чаты      "),
        palette.paint(Tone::Muted, "Контакты  "),
        palette.paint(Tone::Muted, "Аватар    "),
        palette.paint(Tone::Muted, "Фото      "),
        palette.paint(Tone::Muted, "Отпечаток "),
        palette.paint(Tone::Command, fingerprint),
        palette.paint(Tone::Muted, "Shum ID   "),
        palette.paint(Tone::Command, safe(text(&snapshot["profile"]["ownerId"]))));
}
pub fn chats(snapshot: &Value, nearby: bool, invites: bool, unread: bool, ascii: bool) {
    print!(
        "{}",
        render_chats(
            snapshot,
            nearby,
            invites,
            unread,
            ascii,
            Palette::stdout(ascii)
        )
    );
}

pub fn render_chats(
    snapshot: &Value,
    nearby: bool,
    invites: bool,
    unread: bool,
    ascii: bool,
    palette: Palette,
) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    let contacts = snapshot["contacts"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let invite = |c: &Value| text(&c["phase"]) == "incomingPending";
    for contact in contacts {
        let is_nearby = contact["nearby"] == true;
        let count = contact["unread"].as_u64().unwrap_or(0);
        if nearby && !is_nearby || invites && !invite(contact) || unread && count == 0 {
            continue;
        }
        let last = snapshot["messages"].as_array().and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|m| m["contactID"] == contact["id"])
        });
        let preview = if invite(contact) {
            "приглашение в чат".into()
        } else if nearby {
            crate::ui::nearby_label(contact)
        } else {
            last.map(|m| trim_width(text(&m["text"]), 33))
                .unwrap_or_else(|| "нет сообщений".into())
        };
        let timestamp = last
            .and_then(|m| m["timestamp"].as_i64())
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|t| {
                let t = t.with_timezone(&chrono::Local);
                if t.date_naive() == chrono::Local::now().date_naive() {
                    t.format("%H:%M").to_string()
                } else {
                    t.format("%d.%m").to_string()
                }
            })
            .unwrap_or_default();
        let marker = if ascii {
            if is_nearby {
                "*"
            } else {
                " "
            }
        } else if is_nearby {
            "●"
        } else {
            "·"
        };
        let name = format!("{:22}", trim_width(text(&contact["card"]["name"]), 22));
        let preview = format!("{preview:33}");
        let preview = if invite(contact) {
            palette.paint(Tone::Warning, preview)
        } else if nearby {
            palette.paint(Tone::Accent, preview)
        } else if count == 0 {
            palette.paint(Tone::Muted, preview)
        } else {
            preview
        };
        writeln!(
            output,
            "  {} {name} {preview} {} {}",
            palette.paint(if is_nearby { Tone::Accent } else { Tone::Muted }, marker),
            palette.paint(Tone::Muted, format!("{timestamp:5}")),
            palette.paint(
                Tone::Accent,
                if count > 0 {
                    count.to_string()
                } else {
                    String::new()
                }
            )
        )
        .unwrap();
    }
    writeln!(
        output,
        "\n  {} {} · {} {} · {} {} · {} {}",
        palette.paint(Tone::Muted, "Все"),
        contacts.len(),
        palette.paint(Tone::Muted, "Рядом"),
        palette.paint(
            Tone::Accent,
            contacts
                .iter()
                .filter(|c| c["nearby"] == true)
                .count()
                .to_string()
        ),
        palette.paint(Tone::Muted, "Приглашения"),
        palette.paint(
            Tone::Warning,
            contacts.iter().filter(|c| invite(c)).count().to_string()
        ),
        palette.paint(Tone::Muted, "Непрочитанные"),
        palette.paint(
            Tone::Accent,
            contacts
                .iter()
                .filter(|c| c["unread"].as_u64().unwrap_or(0) > 0)
                .count()
                .to_string()
        )
    )
    .unwrap();
    writeln!(
        output,
        "  {} {}",
        palette.paint(Tone::Muted, "Фильтр:"),
        palette.paint(Tone::Command, "--nearby  --invites  --unread")
    )
    .unwrap();
    if contacts.iter().any(invite) {
        writeln!(
            output,
            "  {} {}",
            palette.paint(Tone::Muted, "Принять:"),
            palette.paint(Tone::Command, "shum accept <имя>")
        )
        .unwrap();
    }
    output
}

pub fn bluetooth(snapshot: &Value, palette: Palette) -> String {
    let value = &snapshot["bluetooth"];
    let ready = value["scan"] == "scanning" && value["advertise"] == "advertising";
    let tone = if ready {
        Tone::Accent
    } else if value["enabled"] == false {
        Tone::Muted
    } else {
        Tone::Warning
    };
    palette.paint(tone, safe(&crate::ui::bluetooth_status(snapshot)))
}

pub fn push_status(snapshot: &Value) -> String {
    if snapshot["pushConfigured"] != true {
        return "выключен".into();
    }
    match snapshot["pushLast"]["state"].as_str() {
        Some("sending") => "отправляется запрос".into(),
        Some("accepted") => "последний запрос принят сервером".into(),
        _ => match snapshot["pushError"].as_str() {
            Some(error) => format!("ошибка: {}", safe(error)),
            None => "настроен, результат запроса неизвестен".into(),
        },
    }
}

pub fn status(snapshot: &Value, root: &Path, ascii: bool) -> String {
    let p = Palette::stdout(ascii);
    let relays = snapshot["relays"].as_array().map_or(0, Vec::len);
    format!(
        "{} {}\n{} {}\n{} {}\n{}\n{} {}\n{} {}",
        p.paint(Tone::Accent, format!("Shum {}", env!("CARGO_PKG_VERSION"))),
        p.paint(Tone::Muted, "· протокол v1"),
        p.paint(Tone::Muted, "Профиль:"),
        safe(text(&snapshot["card"]["name"])),
        p.paint(Tone::Muted, "Релеи:"),
        p.paint(
            if relays > 0 {
                Tone::Accent
            } else {
                Tone::Warning
            },
            relays.to_string()
        ),
        bluetooth(snapshot, p),
        p.paint(Tone::Muted, "Push API:"),
        p.paint(
            if snapshot["pushError"].is_string() {
                Tone::Warning
            } else {
                Tone::Muted
            },
            push_status(snapshot)
        ),
        p.paint(Tone::Muted, "Данные:"),
        safe(&root.display().to_string())
    )
}

pub fn about(snapshot: &Value, root: &Path, ascii: bool) -> String {
    let (width, height) = if io::stdout().is_terminal() {
        crossterm::terminal::size().unwrap_or((80, 32))
    } else {
        (80, 32)
    };
    let program = std::env::var("TERM_PROGRAM").unwrap_or_else(|_| "терминал".into());
    let program = match program.as_str() {
        "Apple_Terminal" => "Terminal.app",
        "WarpTerminal" => "Warp",
        other => other,
    };
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    };
    let system = format!("{os} · {} · {width}×{height}", safe(program));
    render_about(
        snapshot,
        root,
        &system,
        usize::from(width),
        ascii,
        Palette::stdout(ascii),
    )
}

pub fn render_about(
    snapshot: &Value,
    root: &Path,
    system: &str,
    width: usize,
    ascii: bool,
    p: Palette,
) -> String {
    use std::fmt::Write;
    let relays = snapshot["relays"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let nearby = snapshot["contacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["nearby"] == true)
        .count();
    let side_by_side = !ascii && width >= 72;
    let body_width = width
        .saturating_sub(if side_by_side { 30 } else { 2 })
        .max(20);
    let mut rows = vec![
        format!(
            "{} {}",
            p.paint(Tone::Accent, format!("Shum {}", env!("CARGO_PKG_VERSION"))),
            p.paint(Tone::Muted, "· протокол v1")
        ),
        p.paint(
            Tone::Muted,
            (if ascii { "-" } else { "─" }).repeat(body_width.min(46)),
        ),
    ];
    let mut field = |label: &str, value: &str, tone: Option<Tone>| {
        let mut part = String::new();
        let mut first = true;
        // Wrap before applying ANSI, so escape sequences never affect alignment.
        for c in safe(value).chars().chain(std::iter::once('\0')) {
            let next_width = UnicodeWidthStr::width(part.as_str())
                + unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
            if c == '\0' || next_width > body_width.saturating_sub(11) {
                rows.push(format!(
                    "{} {}",
                    p.paint(
                        Tone::Muted,
                        format!("{:10}", if first { label } else { "" })
                    ),
                    tone.map_or_else(|| part.clone(), |tone| p.paint(tone, &part))
                ));
                first = false;
                part.clear();
            }
            if c != '\0' {
                part.push(c);
            }
        }
    };
    field("Профиль", text(&snapshot["card"]["name"]), None);
    field(
        "Shum ID",
        text(&snapshot["profile"]["ownerId"]),
        Some(Tone::Command),
    );
    field(
        "Релеи",
        &format!("{} подключено", relays.len()),
        Some(if relays.is_empty() {
            Tone::Warning
        } else {
            Tone::Accent
        }),
    );
    let ready = snapshot["bluetooth"]["scan"] == "scanning"
        && snapshot["bluetooth"]["advertise"] == "advertising";
    let bluetooth = crate::ui::bluetooth_status(snapshot);
    field(
        "Bluetooth",
        if ready {
            "вкл · профиль виден рядом"
        } else {
            bluetooth
                .strip_prefix("Bluetooth")
                .unwrap_or(&bluetooth)
                .trim_start_matches([' ', ':', '·'])
        },
        Some(if ready { Tone::Accent } else { Tone::Warning }),
    );
    field("Рядом", &nearby.to_string(), None);
    field("Система", system, None);
    let root_display = std::env::var_os("HOME")
        .and_then(|home| root.strip_prefix(home).ok())
        .map(|relative| format!("~/{}", relative.display()))
        .unwrap_or_else(|| root.display().to_string());
    field("Данные", &root_display, None);
    rows.push(p.swatches());
    let mut output = String::new();
    if !ascii && !side_by_side {
        for line in LOGO {
            let logo = line.replace('.', "  ").replace('#', "██");
            writeln!(output, "  {}", p.paint(Tone::Logo, logo)).unwrap();
        }
    }
    for i in 0..rows.len().max(if side_by_side { LOGO.len() } else { 0 }) {
        let row = rows.get(i).map(String::as_str).unwrap_or("");
        if side_by_side {
            let logo = LOGO
                .get(i)
                .unwrap_or(&"............")
                .replace('.', "  ")
                .replace('#', "██");
            writeln!(output, "  {}    {row}", p.paint(Tone::Logo, logo)).unwrap();
        } else {
            writeln!(output, "  {row}").unwrap();
        }
    }
    writeln!(
        output,
        "\n  Мессенджер без номера телефона.\n  {}",
        p.paint(
            Tone::Muted,
            "Ключи создаются на устройстве и не покидают его."
        )
    )
    .unwrap();
    output
}
