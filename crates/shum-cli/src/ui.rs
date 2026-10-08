use crate::{
    ipc,
    runtime::Request,
    terminal::{safe, text, trim_width},
};
use anyhow::{bail, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyModifiers, MouseEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use ratatui_image::{picker::Picker, protocol::StatefulProtocol, Resize, StatefulImage};
use serde_json::Value;
use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

const GREEN: Color = Color::Rgb(48, 209, 88);
const MUTED: Color = Color::Rgb(135, 145, 139);
const LOGO: [&str; 11] = [
    "..########..",
    ".##########.",
    "############",
    "############",
    "############",
    "############",
    ".##########.",
    "..########..",
    "..###.......",
    "..##........",
    "..#.........",
];

#[derive(Default)]
pub struct View {
    pub selected: usize,
    pub opened: Option<String>,
    pub input: String,
    pub status: String,
    pub tab: usize,
    pub scroll: u16,
    pub composing: bool,
    pub qr: Option<String>,
    pub profiles: Option<Vec<shum_store::profiles::Profile>>,
    pub profile_selected: usize,
    form: Option<Form>,
    chat_rows: Vec<(Rect, String)>,
}
impl View {
    pub fn chat(id: &str) -> Self {
        Self {
            opened: Some(id.into()),
            composing: true,
            ..Self::default()
        }
    }
}
enum Form {
    NewProfile,
    DeleteProfile { id: String, name: String },
    ClearChat(String),
}

pub struct Pictures {
    picker: Picker,
    cache: HashMap<(u64, u16, u16), StatefulProtocol>,
}
impl Pictures {
    pub fn new(picker: Picker) -> Self {
        Self {
            picker,
            cache: HashMap::new(),
        }
    }
    fn draw(&mut self, frame: &mut Frame<'_>, seed: u64, area: Rect) {
        if area.is_empty() {
            return;
        }
        if self.picker.protocol_type() == ratatui_image::picker::ProtocolType::Halfblocks {
            // The generic image widget interpolates halfblocks and flattens alpha.
            // Pixel subjects need nearest-neighbour samples and terminal background.
            let pixels = crate::avatar::render_subject(seed).pixels;
            for y in 0..area.height {
                for x in 0..area.width {
                    let sx = (u32::from(x) * 36 / u32::from(area.width)).min(35) as usize;
                    let sy = (u32::from(y) * 36 / u32::from(area.height)).min(35) as usize;
                    let by = ((u32::from(y) * 2 + 1) * 36 / (u32::from(area.height) * 2)).min(35)
                        as usize;
                    let a = pixels[sy * 36 + sx];
                    let b = pixels[by * 36 + sx];
                    let cell = &mut frame.buffer_mut()[(area.x + x, area.y + y)];
                    let rgb = |p: [u8; 4]| Color::Rgb(p[0], p[1], p[2]);
                    match (a[3] > 0, b[3] > 0) {
                        (true, true) => {
                            cell.set_char('▀').set_fg(rgb(a)).set_bg(rgb(b));
                        }
                        (true, false) => {
                            cell.set_char('▀').set_fg(rgb(a));
                        }
                        (false, true) => {
                            cell.set_char('▄').set_fg(rgb(b));
                        }
                        (false, false) => {}
                    }
                }
            }
            return;
        }
        if self.cache.len() > 256 {
            self.cache.clear();
        }
        let state = self
            .cache
            .entry((seed, area.width, area.height))
            .or_insert_with(|| {
                let pixels = crate::avatar::render_subject(seed)
                    .pixels
                    .into_iter()
                    .flatten()
                    .collect();
                let image = image::RgbaImage::from_raw(36, 36, pixels).expect("36x36 avatar");
                self.picker
                    .new_resize_protocol(image::DynamicImage::ImageRgba8(image))
            });
        frame.render_stateful_widget(
            StatefulImage::default()
                .resize(Resize::Scale(Some(image::imageops::FilterType::Nearest))),
            area,
            state,
        );
    }
}
fn contacts(snapshot: &Value, tab: usize) -> Vec<&Value> {
    snapshot["contacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| match tab {
            1 => c["nearby"] == true,
            2 => c["phase"] == "incomingPending",
            3 => c["unread"].as_u64().unwrap_or(0) > 0,
            _ => true,
        })
        .collect()
}
fn find_contact<'a>(snapshot: &'a Value, name: &str) -> Result<&'a Value> {
    let all = snapshot["contacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            text(&c["id"]) == name
                || text(&c["card"]["name"]) == name
                || (name.len() >= 8 && text(&c["id"]).starts_with(name))
        })
        .collect::<Vec<_>>();
    match all.as_slice() {
        [one] => Ok(one),
        [] => bail!("Контакт не найден"),
        _ => bail!("Несколько контактов с этим именем. Укажите Shum ID"),
    }
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}
fn border(title: &str, ascii: bool) -> Block<'_> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if ascii {
            BorderType::Plain
        } else {
            BorderType::Rounded
        })
        .title(title);
    if ascii {
        block.border_set(ratatui::symbols::border::Set {
            top_left: "+",
            top_right: "+",
            bottom_left: "+",
            bottom_right: "+",
            vertical_left: "|",
            vertical_right: "|",
            horizontal_top: "-",
            horizontal_bottom: "-",
        })
    } else {
        block
    }
}
fn stamp(ms: &Value) -> String {
    chrono::DateTime::from_timestamp_millis(ms.as_i64().unwrap_or(0))
        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M").to_string())
        .unwrap_or_default()
}
fn ticks(status: &str, ascii: bool) -> &str {
    match (status, ascii) {
        ("read", false) => "✓✓",
        ("read", true) => "[read]",
        ("delivered", false) => "✓",
        ("delivered", true) => "[delivered]",
        ("forwarding", false) => "↗",
        ("forwarding", true) => "[relay]",
        ("queued", false) => "…",
        ("queued", true) => "[queued]",
        ("expired", _) => "[истекло]",
        ("cancelled", _) => "[отменено]",
        _ => "",
    }
}

pub fn draw(
    frame: &mut Frame<'_>,
    snapshot: &Value,
    view: &mut View,
    pictures: &mut Pictures,
    ascii: bool,
) {
    let area = frame.area();
    if area.width < 35 || area.height < 12 {
        frame.render_widget(
            Paragraph::new("Увеличьте окно терминала (от 35×12). Ctrl+C: выход"),
            area,
        );
        return;
    }
    let accent = if ascii { Color::Reset } else { GREEN };
    let muted = if ascii { Color::Reset } else { MUTED };
    let style = Style::default().fg(accent);
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(2),
    ])
    .split(area);
    let relay = snapshot["relays"].as_array().map_or(0, Vec::len);
    let all = contacts(snapshot, 0);
    let nearby = all.iter().filter(|c| c["nearby"] == true).count();
    frame.render_widget(
        Paragraph::new(format!(
            " ШУМ  {}   релеев {relay}   рядом {nearby}   {}",
            safe(text(&snapshot["card"]["name"])),
            chrono::Local::now().format("%H:%M")
        ))
        .style(style),
        vertical[0],
    );
    let counts = [
        all.len(),
        nearby,
        contacts(snapshot, 2).len(),
        contacts(snapshot, 3).len(),
    ];
    let tabs = ["Все", "Рядом", "Приглашения", "Непрочитанные"]
        .iter()
        .enumerate()
        .map(|(i, label)| {
            Span::styled(
                format!(" {}:{} {} ", i + 1, label, counts[i]),
                if i == view.tab {
                    style
                } else {
                    Style::default().fg(muted)
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Line::from(tabs)), vertical[1]);
    view.chat_rows.clear();
    let listed = contacts(snapshot, view.tab);
    view.selected = view.selected.min(listed.len().saturating_sub(1));
    let full_empty = all.is_empty() && view.opened.is_none();
    let columns = Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(vertical[2]);
    let chat_area = if full_empty || area.width < 60 {
        vertical[2]
    } else {
        columns[1]
    };
    if !full_empty && (area.width >= 60 || view.opened.is_none()) {
        let list_area = if area.width < 60 {
            vertical[2]
        } else {
            columns[0]
        };
        let block = border("Чаты", ascii);
        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);
        let row_height = if ascii { 2 } else { 3 };
        let visible = usize::from(inner.height / row_height).max(1);
        let start = view.selected.saturating_sub(visible - 1);
        for (index, c) in listed.iter().enumerate().skip(start).take(visible) {
            let row = Rect::new(
                inner.x,
                inner.y + (index - start) as u16 * row_height,
                inner.width,
                row_height.min(inner.height),
            );
            let active = index == view.selected;
            let row_style = if active && !ascii {
                Style::default().bg(Color::Rgb(20, 48, 29))
            } else {
                Style::default()
            };
            frame.render_widget(Paragraph::new("").style(row_style), row);
            let inset = if ascii { 2 } else { 7 };
            if !ascii {
                if let Some(seed) = c["card"]["avatarSeed"].as_u64() {
                    pictures.draw(frame, seed, Rect::new(row.x, row.y, 6, row.height));
                }
            }
            let name = format!(
                "{}{}{}",
                if active && ascii { "> " } else { "" },
                safe(text(&c["card"]["name"])),
                if c["unread"].as_u64().unwrap_or(0) > 0 {
                    format!(" ({})", c["unread"])
                } else {
                    String::new()
                }
            );
            let last = snapshot["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .rev()
                .find(|m| m["contactID"] == c["id"]);
            let preview = if c["phase"] == "incomingPending" {
                "Приглашение: Enter".into()
            } else {
                last.map(|m| safe(text(&m["text"]))).unwrap_or_default()
            };
            let text_area = Rect::new(
                row.x + inset,
                row.y,
                row.width.saturating_sub(inset),
                row.height,
            );
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(
                        trim_width(&name, text_area.width as usize),
                        if active { style } else { Style::default() },
                    )),
                    Line::from(Span::styled(
                        trim_width(&preview, text_area.width as usize),
                        Style::default().fg(muted),
                    )),
                ])
                .style(row_style),
                text_area,
            );
            view.chat_rows.push((row, text(&c["id"]).into()));
        }
    }
    if full_empty || (view.opened.is_none() && area.width >= 60) {
        frame.render_widget(border("", ascii), chat_area);
        let compact = ascii || chat_area.height < 19;
        let lines = if compact {
            vec![Line::from("SHUM"), Line::from("")]
        } else {
            LOGO.iter()
                .map(|line| {
                    Line::from(Span::styled(
                        line.replace('#', "██").replace('.', "  "),
                        style,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let mut lines = lines;
        lines.extend([
            Line::from(""),
            Line::from("Пока нет открытого чата"),
            Line::from("i мой QR · a добавить контакт"),
            Line::from("Ctrl+P профили · /help команды"),
        ]);
        frame.render_widget(
            Paragraph::new(lines).alignment(Alignment::Center),
            centered(
                chat_area,
                chat_area.width.saturating_sub(2),
                if compact { 7 } else { 17 },
            ),
        );
    } else if let Some(id) = &view.opened {
        let card = find_contact(snapshot, id).ok();
        let title = card
            .map(|c| safe(text(&c["card"]["name"])))
            .unwrap_or_else(|| "Чат".into());
        let parts = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).split(chat_area);
        let block = border(&title, ascii);
        let inner = block.inner(parts[0]);
        frame.render_widget(block, parts[0]);
        let header_height = if ascii { 2 } else { 4 }.min(inner.height.saturating_sub(1));
        if let Some(card) = card {
            if !ascii {
                if let Some(seed) = card["card"]["avatarSeed"].as_u64() {
                    pictures.draw(
                        frame,
                        seed,
                        Rect::new(inner.x, inner.y, 8.min(inner.width), header_height),
                    );
                }
            }
            let x = if ascii { 0 } else { 9 };
            let phase = if card["typing"] == true {
                "печатает…"
            } else if card["phase"] == "incomingPending" {
                "/accept принять · /decline отклонить"
            } else if card["phase"] != "accepted" {
                "/invite пригласить в чат"
            } else if card["online"] == true {
                "в чате"
            } else {
                "сквозное шифрование"
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(title.clone(), style)),
                    Line::from(Span::styled(phase, Style::default().fg(muted))),
                    Line::from(safe(text(&card["card"]["bio"]))),
                ])
                .wrap(Wrap { trim: false }),
                Rect::new(
                    inner.x + x,
                    inner.y,
                    inner.width.saturating_sub(x),
                    header_height,
                ),
            );
        }
        let history = Rect::new(
            inner.x,
            inner.y + header_height,
            inner.width,
            inner.height.saturating_sub(header_height),
        );
        let mut lines = Vec::new();
        for m in snapshot["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|m| m["contactID"] == *id)
        {
            let own = m["outgoing"] == true;
            if let Some(reply) = m["reply"].as_object() {
                lines.push(Line::from(Span::styled(
                    format!("> {}", safe(text(&reply["text"]))),
                    Style::default().fg(muted),
                )));
            }
            let content = safe(text(&m["text"]));
            let meta = format!(
                " {} {}",
                stamp(&m["timestamp"]),
                if own {
                    ticks(text(&m["status"]), ascii)
                } else {
                    ""
                }
            );
            let line = Line::from(vec![
                Span::raw(content),
                Span::styled(meta, Style::default().fg(if own { accent } else { muted })),
            ]);
            lines.push(if own {
                line.alignment(Alignment::Right)
            } else {
                line
            });
            let marks = snapshot["reactions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["messageID"] == m["id"])
                .filter(|r| r["mark"]["reaction"].is_string())
                .map(|r| text(&r["mark"]["reaction"]).to_owned())
                .collect::<Vec<_>>();
            if !marks.is_empty() {
                lines.push(Line::from(Span::styled(marks.join(" "), style)));
            }
            lines.push(Line::from(""));
        }
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let total = paragraph.line_count(history.width);
        let offset = total
            .saturating_sub(history.height as usize)
            .saturating_sub(view.scroll as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(paragraph.scroll((offset, 0)), history);
        let input = Paragraph::new(view.input.as_str()).block(
            border("Сообщение или /команда", ascii).border_style(if view.composing {
                style
            } else {
                Style::default()
            }),
        );
        let width = parts[1].width.saturating_sub(3) as usize;
        let input_width = unicode_width::UnicodeWidthStr::width(view.input.as_str());
        frame.render_widget(
            input.scroll((
                0,
                input_width.saturating_sub(width).min(u16::MAX as usize) as u16,
            )),
            parts[1],
        );
        if view.composing && view.profiles.is_none() && view.qr.is_none() && view.form.is_none() {
            frame.set_cursor_position((
                parts[1].x + 1 + input_width.min(width) as u16,
                parts[1].y + 1,
            ));
        }
    }
    let status = if view.input.starts_with('/') && view.opened.is_none() {
        &view.input
    } else if view.status.is_empty() {
        text(&snapshot["error"])
    } else {
        &view.status
    };
    frame.render_widget(Paragraph::new(format!("{}\nEnter открыть/отправить · Tab панель · Esc назад · ^P профили · ^N рядом · q выход",safe(status))),vertical[3]);
    if let Some(profiles) = &view.profiles {
        let popup = centered(area, 52, (profiles.len() as u16 * 2 + 7).min(area.height));
        frame.render_widget(Clear, popup);
        let block = border("Профили", ascii).border_style(style);
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let mut lines = profiles
            .iter()
            .enumerate()
            .flat_map(|(i, p)| {
                [
                    Line::from(Span::styled(
                        format!(
                            "{} {}{}",
                            if view.profile_selected == i { ">" } else { " " },
                            safe(&p.name),
                            if p.id == snapshot["profile"]["id"] {
                                "  текущий"
                            } else {
                                ""
                            }
                        ),
                        if view.profile_selected == i {
                            style
                        } else {
                            Style::default()
                        },
                    )),
                    Line::from(""),
                ]
            })
            .collect::<Vec<_>>();
        lines.push(Line::from(Span::styled(
            "n создать · d удалить · Enter выбрать",
            style,
        )));
        lines.push(Line::from("Esc закрыть"));
        frame.render_widget(Paragraph::new(lines), inner);
    }
    if let Some(link) = &view.qr {
        if ascii {
            let popup = centered(area, 76, 8);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(format!(
                    "{link}\n\nQR в режиме ASCII: shum invite --ascii\nEsc закрыть"
                ))
                .wrap(Wrap { trim: false })
                .block(border("Моё приглашение", true)),
                popup,
            );
        } else if let Ok(code) = crate::terminal::qr(link, false) {
            let height = code.lines().count() as u16;
            let width = code.lines().next().map_or(0, |s| s.chars().count()) as u16;
            let popup = centered(area, width + 4, height + 4);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                border("Мой QR · Esc закрыть", ascii).border_style(style),
                popup,
            );
            if popup.width >= width + 2 && popup.height >= height + 2 {
                frame.render_widget(
                    Paragraph::new(code).style(Style::default().fg(Color::Black).bg(Color::White)),
                    centered(popup, width, height),
                );
            } else {
                frame.render_widget(
                    Paragraph::new("Увеличьте окно для QR или выполните shum invite")
                        .wrap(Wrap { trim: false }),
                    border("", ascii).inner(popup),
                );
            }
        }
    }
    if let Some(form) = &view.form {
        let title = match form {
            Form::NewProfile => "Имя нового профиля",
            Form::DeleteProfile { .. } => "Введите имя удаляемого профиля",
            Form::ClearChat(_) => "Очистить чат здесь? Введите да",
        };
        let popup = centered(area, 56, 7);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(format!(
                "{}\n\nEnter подтвердить · Esc отменить",
                safe(&view.input)
            ))
            .block(border(title, ascii).border_style(style)),
            popup,
        );
    }
}

async fn focus(root: &Path, profile: &str, contact: Option<String>) {
    let _ = ipc::request(root, profile, Request::Focus { contact }).await;
}
async fn form_submit(root: &Path, profile: &mut String, view: &mut View) -> Result<bool> {
    match view.form.as_ref().context("Нет формы")? {
        Form::NewProfile => {
            let output = tokio::process::Command::new(std::env::current_exe()?)
                .arg("--data-dir")
                .arg(root)
                .args(["--json", "init", "--name", view.input.trim()])
                .output()
                .await?;
            let value: Value = serde_json::from_slice(&output.stdout)?;
            if !output.status.success() {
                bail!("{}", text(&value["error"]));
            }
            focus(root, profile, None).await;
            *profile = text(&value["profile"]["id"]).into();
            ipc::ensure(root, profile).await?;
            view.opened = None;
        }
        Form::DeleteProfile { id, name } => {
            if view.input != *name {
                bail!("Введите точное имя: {}", safe(name));
            }
            ipc::stop(root, id).await?;
            let profiles = shum_store::profiles::Profiles::new(root)?;
            profiles.delete(id)?;
            if id == profile {
                let (selected, _) = profiles.list()?;
                let Some(next) = selected else {
                    return Ok(true);
                };
                *profile = next;
                ipc::ensure(root, profile).await?;
                view.opened = None;
            }
        }
        Form::ClearChat(contact) => {
            if view.input != "да" {
                bail!("Для очистки введите да");
            }
            ipc::request(
                root,
                profile,
                Request::Clear {
                    contact: contact.clone(),
                },
            )
            .await?;
        }
    }
    view.form = None;
    view.profiles = None;
    view.input.clear();
    Ok(false)
}
pub async fn run(
    root: &Path,
    initial_profile: &str,
    contact: Option<&str>,
    ascii: bool,
) -> Result<()> {
    let mut profile = initial_profile.to_owned();
    ipc::ensure(root, &profile).await?;
    let mut snapshot = ipc::request(root, &profile, Request::Snapshot).await?;
    let mut view = View {
        opened: contact
            .map(|s| find_contact(&snapshot, s).map(|c| text(&c["id"]).to_owned()))
            .transpose()?,
        composing: contact.is_some(),
        ..View::default()
    };
    let mut terminal = ratatui::init();
    let mut pictures = Pictures::new(if ascii {
        Picker::halfblocks()
    } else {
        Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks())
    });
    let mut typing = Instant::now() - Duration::from_secs(10);
    let mut presence = Instant::now() - Duration::from_secs(30);
    let mut typed = false;
    let result = run_loop(
        root,
        &mut profile,
        &mut snapshot,
        &mut view,
        &mut pictures,
        &mut terminal,
        ascii,
        &mut typing,
        &mut presence,
        &mut typed,
    )
    .await;
    let _ = crossterm::execute!(
        std::io::stdout(),
        event::DisableMouseCapture,
        event::DisableBracketedPaste
    );
    ratatui::restore();
    focus(root, &profile, None).await;
    result
}
#[allow(clippy::too_many_arguments)]
async fn run_loop(
    root: &Path,
    profile: &mut String,
    snapshot: &mut Value,
    view: &mut View,
    pictures: &mut Pictures,
    terminal: &mut ratatui::DefaultTerminal,
    ascii: bool,
    typing: &mut Instant,
    presence: &mut Instant,
    typed: &mut bool,
) -> Result<()> {
    crossterm::execute!(
        std::io::stdout(),
        event::EnableMouseCapture,
        event::EnableBracketedPaste
    )?;
    loop {
        terminal.draw(|frame| draw(frame, snapshot, view, pictures, ascii))?;
        if event::poll(Duration::from_millis(150))? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                if key.kind != event::KeyEventKind::Press {
                    continue;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('c') => break,
                        KeyCode::Char('p') => {
                            view.profiles = if view.profiles.is_some() {
                                None
                            } else {
                                Some(shum_store::profiles::Profiles::new(root)?.list()?.1)
                            };
                            continue;
                        }
                        KeyCode::Char('n') => {
                            view.tab = 1;
                            view.composing = false;
                            continue;
                        }
                        _ => {}
                    }
                }
                if view.qr.is_some() {
                    if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        view.qr = None;
                    }
                    continue;
                }
                if view.form.is_some() {
                    match key.code {
                        KeyCode::Esc => {
                            view.form = None;
                            view.input.clear();
                        }
                        KeyCode::Enter => match form_submit(root, profile, view).await {
                            Ok(true) => break,
                            Ok(false) => {}
                            Err(error) => view.status = error.to_string(),
                        },
                        KeyCode::Backspace => {
                            view.input.pop();
                        }
                        KeyCode::Char(c) if !c.is_control() && view.input.len() < 128 => {
                            view.input.push(c)
                        }
                        _ => {}
                    }
                    *snapshot = ipc::request(root, profile, Request::Snapshot).await?;
                    continue;
                }
                if let Some(profiles) = view.profiles.as_ref() {
                    match key.code {
                        KeyCode::Esc => view.profiles = None,
                        KeyCode::Up | KeyCode::Char('k') => {
                            view.profile_selected = view.profile_selected.saturating_sub(1)
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            view.profile_selected =
                                (view.profile_selected + 1).min(profiles.len().saturating_sub(1))
                        }
                        KeyCode::Char('n') => {
                            view.form = Some(Form::NewProfile);
                            view.input.clear();
                        }
                        KeyCode::Char('d') => {
                            if let Some(p) = profiles.get(view.profile_selected) {
                                view.form = Some(Form::DeleteProfile {
                                    id: p.id.clone(),
                                    name: p.name.clone(),
                                });
                                view.input.clear();
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(p) = profiles.get(view.profile_selected) {
                                focus(root, profile, None).await;
                                *profile = p.id.clone();
                                shum_store::profiles::Profiles::new(root)?.select(profile)?;
                                ipc::ensure(root, profile).await?;
                                *snapshot = ipc::request(root, profile, Request::Snapshot).await?;
                                view.opened = None;
                                view.input.clear();
                            }
                            view.profiles = None;
                        }
                        _ => {}
                    }
                    continue;
                }
                let listed = contacts(snapshot, view.tab);
                match key.code {
                    KeyCode::Char('q') if !view.composing && view.input.is_empty() => break,
                    KeyCode::Esc => {
                        view.opened = None;
                        view.composing = false;
                        view.input.clear();
                        view.scroll = 0;
                    }
                    KeyCode::Tab => {
                        if view.opened.is_some() {
                            view.composing = !view.composing;
                        } else {
                            view.tab = (view.tab + 1) % 4;
                            view.selected = 0;
                        }
                    }
                    KeyCode::Char(c @ '1'..='4') if !view.composing && view.input.is_empty() => {
                        view.tab = (c as u8 - b'1') as usize;
                        view.selected = 0;
                    }
                    KeyCode::Up => view.selected = view.selected.saturating_sub(1),
                    KeyCode::Down => {
                        view.selected = (view.selected + 1).min(listed.len().saturating_sub(1))
                    }
                    KeyCode::Char('j') if !view.composing && view.input.is_empty() => {
                        view.selected = (view.selected + 1).min(listed.len().saturating_sub(1))
                    }
                    KeyCode::Char('k') if !view.composing && view.input.is_empty() => {
                        view.selected = view.selected.saturating_sub(1)
                    }
                    KeyCode::PageUp => view.scroll = view.scroll.saturating_add(10),
                    KeyCode::PageDown => view.scroll = view.scroll.saturating_sub(10),
                    KeyCode::Char('a') if !view.composing && view.input.is_empty() => {
                        view.input = "/add ".into()
                    }
                    KeyCode::Char('i') if !view.composing && view.input.is_empty() => {
                        let card: shum_core::card::Card =
                            serde_json::from_value(snapshot["card"].clone())?;
                        let link = card.invitation()?;
                        let qr = crate::terminal::qr(&link, false)?;
                        // c2 is an existing v1 format and fits a small terminal; the daemon answers it.
                        let size = terminal.size()?;
                        view.qr = Some(
                            if qr.lines().count() + 4 <= size.height as usize
                                && qr.lines().next().map_or(0, |s| s.chars().count() + 4)
                                    <= size.width as usize
                            {
                                link
                            } else {
                                use base64::Engine;
                                format!(
                                    "shum://c2/{}",
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .encode(hex::decode(&card.nostr_key)?)
                                )
                            },
                        );
                    }
                    KeyCode::Enter => {
                        if view.input.is_empty() {
                            if let Some(c) = listed.get(view.selected) {
                                view.opened = Some(text(&c["id"]).into());
                                view.composing = true;
                                view.scroll = 0;
                            }
                        } else if view.input == "/clear" {
                            if let Some(id) = &view.opened {
                                view.form = Some(Form::ClearChat(id.clone()));
                                view.input.clear();
                            }
                        } else {
                            match parse_input(&view.input,view.opened.as_deref()){
                            Ok(Some(request))=>match ipc::request(root,profile,request).await{Ok(_)=>{view.status="Сохранено".into();view.input.clear();view.scroll=0;},Err(error)=>view.status=error.to_string()},
                            Ok(None)=>view.status="/add ссылка · /invite · /accept · /decline · /clear · /react ID реакция · /profile имя".into(),Err(error)=>view.status=error.to_string()
                        }
                        }
                    }
                    KeyCode::Backspace => {
                        view.input.pop();
                    }
                    KeyCode::Char(c) if !c.is_control() && view.input.len() < 4096 => {
                        view.input.push(c);
                    }
                    _ => {}
                }
            } else {
                match event {
                    Event::Paste(value) => {
                        let clean = safe(&value);
                        for c in clean.chars() {
                            if view.input.len() + c.len_utf8() > 4096 {
                                break;
                            }
                            view.input.push(c);
                        }
                    }
                    Event::Mouse(mouse) => match mouse.kind {
                        MouseEventKind::ScrollUp => view.scroll = view.scroll.saturating_add(3),
                        MouseEventKind::ScrollDown => view.scroll = view.scroll.saturating_sub(3),
                        MouseEventKind::Down(event::MouseButton::Left) => {
                            if let Some((_, id)) = view
                                .chat_rows
                                .iter()
                                .find(|(r, _)| r.contains((mouse.column, mouse.row).into()))
                            {
                                view.opened = Some(id.clone());
                                view.composing = true;
                                view.scroll = 0;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        focus(root, profile, view.opened.clone()).await;
        if let Some(contact) = &view.opened {
            if presence.elapsed() > Duration::from_secs(25) {
                let _ = ipc::request(
                    root,
                    profile,
                    Request::Presence {
                        contact: contact.clone(),
                        online: true,
                    },
                )
                .await;
                *presence = Instant::now();
            }
            let active = view.composing && !view.input.is_empty() && !view.input.starts_with('/');
            if active != *typed || (active && typing.elapsed() > Duration::from_secs(4)) {
                let _ = ipc::request(
                    root,
                    profile,
                    Request::Typing {
                        contact: contact.clone(),
                        active,
                    },
                )
                .await;
                *typing = Instant::now();
                *typed = active;
            }
        } else {
            *typed = false;
        }
        match ipc::request(root, profile, Request::Snapshot).await {
            Ok(next) => *snapshot = next,
            Err(error) => {
                view.status = error.to_string();
            }
        }
    }
    Ok(())
}
pub fn parse_input(input: &str, contact: Option<&str>) -> Result<Option<Request>> {
    let contact = || contact.map(str::to_owned).context("Сначала выберите чат");
    Ok(Some(match input.split_once(' ').unwrap_or((input, "")) {
        ("/help", _) => return Ok(None),
        ("/add", link) => Request::Add { link: link.into() },
        ("/invite", _) => Request::Invite {
            contact: contact()?,
        },
        ("/accept", _) => Request::Accept {
            contact: contact()?,
        },
        ("/decline", _) => Request::Decline {
            contact: contact()?,
        },
        ("/clear", _) => Request::Clear {
            contact: contact()?,
        },
        ("/profile", name) => Request::Profile {
            name: Some(name.into()),
            bio: None,
            seed: None,
        },
        ("/react", args) => {
            let (message, reaction) = args
                .split_once(' ')
                .context("/react ID like|dislike|laugh|fire|coffin|hundred|horror")?;
            Request::Reaction {
                message: message.into(),
                reaction: serde_json::from_value(Value::String(reaction.into()))?,
            }
        }
        (command, _) if command.starts_with('/') => bail!("Неизвестная команда. /help"),
        _ => Request::Send {
            contact: contact()?,
            text: input.into(),
        },
    }))
}
