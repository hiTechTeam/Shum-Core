use anyhow::{bail, Result};
use serde_json::Value;
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};
use unicode_width::UnicodeWidthStr;
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
    if !ascii && io::stdout().is_terminal() {
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
    if ascii || !io::stdout().is_terminal() {
        return;
    }
    if native_avatar(seed).unwrap_or(false) {
        return;
    }
    let avatar = crate::avatar::render_subject(seed);
    let pixels = avatar.coarse18();
    let colors = crate::display::Display::detect().colors;
    for y in (0..18).step_by(2) {
        print!("  ");
        for x in 0..18 {
            let top = pixels[y * 18 + x];
            let bottom = pixels[(y + 1) * 18 + x];
            match (top[3] > 0, bottom[3] > 0) {
                (false, false) => print!("\x1b[0m "),
                (true, false) => print!("\x1b[0m{}▀", colors.sgr(top, false)),
                (false, true) => print!("\x1b[0m{}▄", colors.sgr(bottom, false)),
                (true, true) => print!("{}{}▀", colors.sgr(top, false), colors.sgr(bottom, true)),
            }
        }
        println!("\x1b[0m");
    }
}
fn native_avatar(seed: u64) -> Result<bool> {
    use ratatui_image::{
        picker::{Picker, ProtocolType},
        Image, Resize,
    };
    let protocol = crate::display::Display::detect().images;
    if protocol == ProtocolType::Halfblocks {
        return Ok(false);
    }
    let mut picker = Picker::halfblocks();
    picker.set_protocol_type(protocol);
    let pixels = crate::avatar::render_subject(seed)
        .pixels
        .into_iter()
        .flatten()
        .collect();
    let image = image::DynamicImage::ImageRgba8(
        image::RgbaImage::from_raw(36, 36, pixels).expect("avatar size"),
    );
    let image = picker.new_protocol(
        image,
        ratatui::layout::Size::new(18, 9),
        Resize::Scale(Some(image::imageops::FilterType::Nearest)),
    )?;
    let mut terminal = ratatui::Terminal::with_options(
        ratatui::backend::CrosstermBackend::new(io::stdout()),
        ratatui::TerminalOptions {
            viewport: ratatui::Viewport::Inline(9),
        },
    )?;
    terminal.draw(|frame| frame.render_widget(Image::new(&image), frame.area()))?;
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
    println!("  {} · текущий\n  {}\n\n  Чаты       {chats}\n  Контакты   {contacts}\n  Аватар     пиксельный (для всех)\n  Фото       пока недоступно\n\n  Отпечаток  {fingerprint}\n  Shum ID    {}", safe(text(&card["name"])), safe(text(&card["bio"])),text(&snapshot["profile"]["ownerId"]));
}
pub fn chats(snapshot: &Value, nearby: bool, invites: bool, unread: bool, ascii: bool) {
    let contacts = snapshot["contacts"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let invite = |c: &Value| text(&c["phase"]) == "incomingPending";
    for contact in contacts {
        if nearby && !contact["nearby"].as_bool().unwrap_or(false)
            || invites && !invite(contact)
            || unread && contact["unread"].as_u64().unwrap_or(0) == 0
        {
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
        println!(
            "  {} {:22} {:33} {}",
            if ascii { "*" } else { "·" },
            trim_width(text(&contact["card"]["name"]), 22),
            preview,
            contact["unread"]
        );
    }
    println!(
        "\n  Все {} · Рядом {} · Приглашения {} · Непрочитанные {}",
        contacts.len(),
        contacts.iter().filter(|c| c["nearby"] == true).count(),
        contacts.iter().filter(|c| invite(c)).count(),
        contacts
            .iter()
            .filter(|c| c["unread"].as_u64().unwrap_or(0) > 0)
            .count()
    );
}
