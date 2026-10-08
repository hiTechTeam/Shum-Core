use crate::{
    display::{ACCENT as GREEN, LOGO, LOGO_COLOR, MUTED},
    ipc,
    runtime::Request,
    terminal::{safe, text, trim_width},
};
use anyhow::{bail, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use ratatui_image::{
    picker::Picker,
    protocol::{StatefulProtocol, StatefulProtocolType},
    Resize, StatefulImage,
};
use serde_json::Value;
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct View {
    pub selected: usize,
    pub opened: Option<String>,
    pub input: String,
    pub status: String,
    pub tab: usize,
    pub scroll: u16,
    pub composing: bool,
    pub command_mode: bool,
    pub help: bool,
    pub info: Option<(String, String)>,
    pub profile_details: HashMap<String, Value>,
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
    DeleteProfile { id: String, name: String },
    ClearChat(String),
}

pub struct Pictures {
    picker: Picker,
    pub(crate) colors: crate::display::Colors,
    cache: HashMap<(u64, u16, u16), StatefulProtocol>,
    scene: Option<u64>,
    direct: Option<crate::graphics::DirectImages>,
    hide_direct: bool,
    pub(crate) cell_avatars: bool,
}
impl Pictures {
    pub fn new(picker: Picker) -> Self {
        Self::with_display(picker, crate::display::Display::detect())
    }
    pub fn with_display(picker: Picker, display: crate::display::Display) -> Self {
        let direct = display.direct_images
            && picker.protocol_type() != ratatui_image::picker::ProtocolType::Halfblocks
            && !picker.tmux_detected();
        let mut result = Self::with_colors(picker, display.colors);
        result.cell_avatars = display.cell_avatars;
        if direct {
            result.direct = Some(crate::graphics::DirectImages::default());
        }
        result
    }
    pub fn with_colors(picker: Picker, colors: crate::display::Colors) -> Self {
        Self {
            picker,
            colors,
            cache: HashMap::new(),
            scene: None,
            direct: None,
            hide_direct: false,
            cell_avatars: false,
        }
    }
    fn halfblocks(&self) -> bool {
        self.picker.protocol_type() == ratatui_image::picker::ProtocolType::Halfblocks
    }
    pub(crate) fn clear_on_change<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut ratatui::Terminal<B>,
        scene: impl Hash,
    ) -> std::result::Result<(), B::Error> {
        if self.halfblocks() {
            return Ok(());
        }
        let mut hash = DefaultHasher::new();
        scene.hash(&mut hash);
        terminal.size()?.hash(&mut hash);
        let next = hash.finish();
        if self.scene != Some(next) {
            self.clear_graphics(terminal)?;
            // Inline graphics live outside Ratatui's cell diff. ECH erases text,
            // but Warp can retain the old image under a transparent replacement.
            // Clear the terminal and its diff buffer together when images move,
            // change, or become covered by a modal. Ordinary typing stays diffed.
            // Terminal::clear queries stdin for the cursor position. We render
            // fullscreen and position the next frame explicitly, so avoid it.
            terminal.backend_mut().clear()?;
            terminal.swap_buffers();
            terminal.swap_buffers();
            self.scene = Some(next);
        }
        Ok(())
    }
    pub(crate) fn clear_graphics<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut ratatui::Terminal<B>,
    ) -> std::result::Result<(), B::Error> {
        if let Some(direct) = &mut self.direct {
            direct.clear(terminal)?;
        }
        Ok(())
    }
    pub(crate) fn draw(&mut self, frame: &mut Frame<'_>, seed: u64, area: Rect) {
        self.draw_at(frame, seed, area);
    }
    fn thumbnail(&mut self, frame: &mut Frame<'_>, seed: u64, area: Rect) {
        self.draw_at(frame, seed, area);
    }
    fn draw_at(&mut self, frame: &mut Frame<'_>, seed: u64, area: Rect) {
        let area = area.intersection(frame.area());
        if area.is_empty() {
            return;
        }
        if self.halfblocks() {
            if self.cell_avatars {
                if area.width < 24 || area.height < 12 {
                    return;
                }
                let pixels = crate::avatar::render_subject(seed).face_cells();
                let x0 = area.x + (area.width - 24) / 2;
                let y0 = area.y + (area.height - 12) / 2;
                for y in 0..12 {
                    for x in 0..12 {
                        let pixel = pixels[y * 12 + x];
                        if pixel[3] == 0 {
                            continue;
                        }
                        for dx in 0..2 {
                            let cell =
                                &mut frame.buffer_mut()[(x0 + x as u16 * 2 + dx, y0 + y as u16)];
                            let background = match cell.bg {
                                Color::Rgb(r, g, b) => [r, g, b],
                                _ => [10, 13, 11],
                            };
                            let c: [u8; 3] = std::array::from_fn(|i| {
                                ((u32::from(pixel[i]) * u32::from(pixel[3])
                                    + u32::from(background[i]) * (255 - u32::from(pixel[3]))
                                    + 127)
                                    / 255) as u8
                            });
                            cell.set_char(' ').set_bg(Color::Rgb(c[0], c[1], c[2]));
                        }
                    }
                }
                return;
            }
            // Smaller full portraits lose their single-pixel facial details.
            // Compact layouts omit the picture instead of displaying a blob.
            if area.width < 18 || area.height < 9 {
                return;
            }
            let side = area.width.min(area.height.saturating_mul(2)).min(36) / 2 * 2;
            let height = side / 2;
            if height == 0 {
                return;
            }
            let x0 = area.x + (area.width - side) / 2;
            let y0 = area.y + (area.height - height) / 2;
            let pixels = crate::avatar::render_subject(seed).sampled(usize::from(side));
            for y in 0..height {
                for x in 0..side {
                    let a = pixels[usize::from(y * 2 * side + x)];
                    let b = pixels[usize::from((y * 2 + 1) * side + x)];
                    let cell = &mut frame.buffer_mut()[(x0 + x, y0 + y)];
                    if a[3] == 0 && b[3] == 0 {
                        continue;
                    }
                    let background = match cell.bg {
                        Color::Rgb(r, g, b) => [r, g, b],
                        _ => [10, 13, 11],
                    };
                    let composite = |p: [u8; 4]| {
                        let mut channels = [0; 3];
                        for i in 0..3 {
                            channels[i] = ((u32::from(p[i]) * u32::from(p[3])
                                + u32::from(background[i]) * (255 - u32::from(p[3]))
                                + 127)
                                / 255) as u8;
                        }
                        Color::Rgb(channels[0], channels[1], channels[2])
                    };
                    let (top, bottom) = (composite(a), composite(b));
                    // Solid cells need no glyph. For split cells the lower
                    // block avoids the large top bearing of Terminal.app's ▀.
                    if top == bottom {
                        cell.set_char(' ').set_bg(bottom);
                    } else {
                        cell.set_char('▄').set_fg(bottom).set_bg(top);
                    }
                }
            }
            return;
        }
        if self.cache.len() > 256 {
            self.cache.clear();
        }
        if let Some(direct) = &mut self.direct {
            if !self.hide_direct {
                direct.draw(frame, seed, area);
            }
            return;
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
        if let StatefulProtocolType::ITerm2(image) = state.protocol_type() {
            // ratatui-image encodes pixel bounds using an estimated font size.
            // Cell units keep images inside the layout at any terminal zoom/DPI.
            // https://iterm2.com/documentation-images.html
            let cell = &mut frame.buffer_mut()[(area.x, area.y)];
            if let Some((prefix, dimensions)) = cell.symbol().split_once(";width=") {
                if let Some((_, suffix)) = dimensions.split_once(";doNotMoveCursor=") {
                    let bounded = format!(
                        "{prefix};width={};height={};doNotMoveCursor={suffix}",
                        image.size.width.min(area.width),
                        image.size.height.min(area.height),
                    );
                    cell.set_symbol(&bounded);
                }
            }
        }
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
        .border_type(BorderType::Plain)
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
    pictures.hide_direct = view.help
        || view.qr.is_some()
        || view.info.is_some()
        || view.profiles.is_some()
        || view.form.is_some();
    draw_content(frame, snapshot, view, pictures, ascii);
    pictures.hide_direct = false;
    pictures.colors.apply(frame.buffer_mut(), ascii);
}
fn draw_content(
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
    if !ascii {
        frame.render_widget(
            Paragraph::new("").style(Style::default().bg(Color::Rgb(10, 13, 11))),
            area,
        );
    }
    let accent = if ascii { Color::Reset } else { GREEN };
    let muted = if ascii { Color::Reset } else { MUTED };
    let style = Style::default().fg(accent);
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(if view.command_mode { 5 } else { 2 }),
    ])
    .split(area);
    let relay = snapshot["relays"].as_array().map_or(0, Vec::len);
    let all = contacts(snapshot, 0);
    let nearby = all.iter().filter(|c| c["nearby"] == true).count();
    frame.render_widget(
        Paragraph::new(format!(
            " Shum  {}   релеев {relay}   рядом {nearby}   {}",
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
                format!(" {} {} ", label, counts[i]),
                if i == view.tab {
                    if ascii {
                        style
                    } else {
                        style.bg(Color::Rgb(20, 48, 29))
                    }
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
    let full_empty = listed.is_empty() && view.opened.is_none();
    let columns = if pictures.cell_avatars && !ascii && area.width >= 80 {
        Layout::horizontal([
            Constraint::Length((area.width * 36 / 100).max(38)),
            Constraint::Min(1),
        ])
        .split(vertical[2])
    } else {
        Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)])
            .split(vertical[2])
    };
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
        let block = border(
            if view.tab == 1 {
                "Рядом"
            } else {
                "Чаты"
            },
            ascii,
        );
        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);
        let show_avatars = !ascii
            && if pictures.cell_avatars {
                inner.height >= 12 && inner.width >= 36
            } else {
                !pictures.halfblocks() || inner.height >= 9
            };
        let row_height = if !show_avatars {
            2
        } else if pictures.cell_avatars {
            12
        } else if pictures.halfblocks() {
            9
        } else {
            3
        };
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
            let avatar_width = (if pictures.cell_avatars {
                24
            } else if pictures.halfblocks() {
                18
            } else {
                6
            })
            .min(row.width);
            let inset = (if !show_avatars { 2 } else { avatar_width + 1 }).min(row.width);
            if show_avatars {
                if let Some(seed) = c["card"]["avatarSeed"].as_u64() {
                    pictures.thumbnail(
                        frame,
                        seed,
                        Rect::new(row.x, row.y, avatar_width, row.height),
                    );
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
            } else if view.tab == 1 {
                nearby_label(c)
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
            vec![Line::from("Shum"), Line::from("")]
        } else {
            LOGO.iter()
                .map(|line| {
                    Line::from(Span::styled(
                        line.replace('#', "██").replace('.', "  "),
                        Style::default().fg(LOGO_COLOR),
                    ))
                })
                .collect::<Vec<_>>()
        };
        let mut lines = lines;
        lines.extend([
            Line::from(""),
            Line::from(if full_empty && view.tab == 1 {
                "Пока никого рядом"
            } else if full_empty {
                "Пока нет чатов"
            } else {
                "Выберите чат слева"
            }),
            Line::from(Span::styled(
                if full_empty && view.tab == 1 {
                    "Откройте Shum на устройстве рядом"
                } else if full_empty {
                    "Позовите кого-нибудь, и переписка появится здесь"
                } else {
                    "Enter открыть · ↑↓ выбрать"
                },
                Style::default().fg(muted),
            )),
            Line::from(""),
            Line::from("i     показать мой QR-код"),
            Line::from("a     добавить по ссылке или QR"),
            Line::from("^n    кто рядом по Bluetooth"),
            Line::from(""),
            Line::from(Span::styled(
                "или в терминале: shum invite · shum add <ссылка>",
                Style::default().fg(muted),
            )),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .alignment(Alignment::Center),
            centered(
                chat_area,
                chat_area.width.saturating_sub(2),
                if compact { 11 } else { 21 },
            ),
        );
    } else if let Some(id) = &view.opened {
        let card = find_contact(snapshot, id).ok();
        let title = card
            .map(|c| safe(text(&c["card"]["name"])))
            .unwrap_or_else(|| "Чат".into());
        let parts = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).split(chat_area);
        let block = border("", ascii);
        let inner = block.inner(parts[0]);
        frame.render_widget(block, parts[0]);
        let show_avatar = !ascii
            && if pictures.cell_avatars {
                inner.height >= 15 && inner.width >= 36
            } else {
                !pictures.halfblocks() || inner.height >= 12
            };
        let header_height = if !show_avatar {
            2
        } else if pictures.cell_avatars {
            12
        } else if pictures.halfblocks() {
            9
        } else {
            4
        }
        .min(inner.height.saturating_sub(1));
        let avatar_width = header_height * 2;
        if let Some(card) = card {
            if show_avatar {
                if let Some(seed) = card["card"]["avatarSeed"].as_u64() {
                    pictures.draw(
                        frame,
                        seed,
                        Rect::new(
                            inner.x,
                            inner.y,
                            avatar_width.min(inner.width),
                            header_height,
                        ),
                    );
                }
            }
            let x = if show_avatar { avatar_width + 1 } else { 0 };
            let phase = if card["typing"] == true {
                "печатает…"
            } else if card["phase"] == "incomingPending" {
                "/accept принять · /decline отклонить"
            } else if card["phase"] != "accepted" {
                "/invite <ник> пригласить"
            } else if card["online"] == true {
                "в чате"
            } else {
                "сквозное шифрование"
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(title.clone(), style)),
                    Line::from(Span::styled(
                        if card["nearby"] == true {
                            format!("{} · {phase}", nearby_label(card))
                        } else {
                            phase.into()
                        },
                        Style::default().fg(muted),
                    )),
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
        let input = Paragraph::new(if view.command_mode {
            ""
        } else {
            view.input.as_str()
        })
        .block(
            border(
                if view.composing {
                    "Сообщение · Enter отправить · Esc к списку"
                } else {
                    "Сообщение · Tab ввод"
                },
                ascii,
            )
            .border_style(if view.composing {
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
        if view.composing
            && !view.command_mode
            && view.profiles.is_none()
            && view.qr.is_none()
            && view.form.is_none()
        {
            frame.set_cursor_position((
                parts[1].x + 1 + input_width.min(width) as u16,
                parts[1].y + 1,
            ));
        }
    }
    let footer = vertical[3];
    let footer_parts = Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(footer);
    if view.command_mode {
        let width = footer_parts[0].width.saturating_sub(3) as usize;
        let input_width = unicode_width::UnicodeWidthStr::width(view.input.as_str());
        frame.render_widget(
            Paragraph::new(view.input.as_str())
                .scroll((0, input_width.saturating_sub(width) as u16))
                .block(border("Команда · /help список · Esc отменить", ascii).border_style(style)),
            footer_parts[0],
        );
        if view.form.is_none() && view.qr.is_none() && !view.help {
            frame.set_cursor_position((
                footer_parts[0].x + 1 + input_width.min(width) as u16,
                footer_parts[0].y + 1,
            ));
        }
    }
    let nearby_status = bluetooth_status(snapshot);
    let status = if view.status.is_empty() && view.tab == 1 {
        &nearby_status
    } else if view.status.is_empty() {
        snapshot["error"]
            .as_str()
            .or(snapshot["pushError"].as_str())
            .unwrap_or("")
    } else {
        &view.status
    };
    let hint = if view.composing || view.command_mode {
        "Enter отправить · Esc к списку · ^P профили · ^Q выход"
    } else if area.width < 60 {
        "i QR · a добавить · ^P профили · q выход"
    } else if full_empty {
        "i мой QR · a добавить · ^N рядом · ^P профили · / команды · q выход"
    } else {
        "↑↓ чаты · Enter открыть · Tab ввод · / команды · ^P профили · q выход"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(safe(status)),
            Line::from(Span::styled(hint, Style::default().fg(muted))),
        ]),
        footer_parts[1],
    );
    if view.profiles.is_some() || view.help || view.info.is_some() {
        for cell in &mut frame.buffer_mut().content {
            cell.set_fg(if ascii {
                Color::Reset
            } else {
                Color::Rgb(54, 64, 57)
            });
        }
    }
    if let Some(profiles) = &view.profiles {
        let row_height = if !ascii && pictures.halfblocks() {
            6
        } else {
            3
        };
        let stride = row_height + 1;
        let popup = centered(
            area,
            52,
            ((profiles.len() as u16 + 1) * stride + 5).min(area.height),
        );
        frame.render_widget(Clear, popup);
        let block = border(" Профили ", ascii).border_style(style);
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let visible = usize::from(inner.height.saturating_sub(3) / stride).max(1);
        let start = view.profile_selected.saturating_sub(visible - 1);
        for i in start..=(profiles.len()).min(start + visible - 1) {
            let row = Rect::new(
                inner.x + 1,
                inner.y + 1 + (i - start) as u16 * stride,
                inner.width.saturating_sub(2),
                row_height.min(inner.height.saturating_sub(2)),
            );
            let selected = view.profile_selected == i;
            let rowstyle = if selected && !ascii {
                Style::default().bg(Color::Rgb(20, 48, 29))
            } else {
                Style::default()
            };
            frame.render_widget(Paragraph::new("").style(rowstyle), row);
            let label = if let Some(p) = profiles.get(i) {
                let detail = if p.id == snapshot["profile"]["id"] {
                    Some(snapshot)
                } else {
                    view.profile_details.get(&p.id)
                };
                if !ascii {
                    if let Some(seed) = detail.and_then(|d| d["card"]["avatarSeed"].as_u64()) {
                        pictures.thumbnail(
                            frame,
                            seed,
                            Rect::new(row.x, row.y, row_height * 2, row.height),
                        );
                    }
                }
                format!(
                    "{}{}{}",
                    if selected && ascii { "> " } else { "" },
                    safe(&p.name),
                    if p.id == snapshot["profile"]["id"] {
                        "  текущий".into()
                    } else {
                        detail
                            .map(|d| {
                                format!(
                                    "  {} чатов",
                                    d["chatCount"]
                                        .as_u64()
                                        .unwrap_or_else(|| contacts(d, 0).len() as u64)
                                )
                            })
                            .unwrap_or_default()
                    }
                )
            } else {
                "+ Создать новый профиль".into()
            };
            let inset = if ascii { 0 } else { row_height * 2 + 1 };
            frame.render_widget(
                Paragraph::new(label).style(rowstyle.fg(if selected {
                    accent
                } else {
                    Color::Reset
                })),
                Rect::new(row.x + inset, row.y + 1, row.width.saturating_sub(inset), 1),
            );
        }
        frame.render_widget(
            Paragraph::new("Enter выбрать · d удалить · Esc закрыть")
                .style(Style::default().fg(muted)),
            Rect::new(
                inner.x + 1,
                inner.bottom().saturating_sub(1),
                inner.width.saturating_sub(2),
                1,
            ),
        );
    }
    if view.help || view.info.is_some() {
        let (title, body) = view
            .info
            .as_ref()
            .map(|(t, b)| (t.as_str(), b.as_str()))
            .unwrap_or(("Команды в Shum", HELP));
        let popup = centered(area, 76, 26);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: false })
                .block(border(title, ascii).border_style(style)),
            popup,
        );
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
            Form::DeleteProfile { .. } => "Введите имя удаляемого профиля",
            Form::ClearChat(_) => "Очистить чат здесь? Введите да",
        };
        let popup = centered(area, 56, 7);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(format!(
                "{}\n{}\nEnter подтвердить · Esc отменить",
                safe(&view.input),
                safe(&view.status)
            ))
            .block(border(title, ascii).border_style(style)),
            popup,
        );
    }
}

/// Restore the terminal on every return path, including errors in a modal.
pub(crate) struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            event::DisableMouseCapture,
            event::DisableBracketedPaste
        );
        ratatui::restore();
    }
}
pub(crate) fn picture_picker(ascii: bool) -> Picker {
    // Querying stdin here consumed early keystrokes in terminals without replies.
    // Use known graphics protocols; other terminals get transparent halfblocks.
    let mut picker = Picker::halfblocks();
    if !ascii {
        picker.set_protocol_type(crate::display::Display::detect().images);
    }
    picker
}
pub fn is_quit_key(key: KeyEvent) -> bool {
    key.code == KeyCode::F(10)
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q' | 'с' | 'й')))
}
fn shortcut(code: KeyCode) -> KeyCode {
    match code {
        KeyCode::Char(c) => KeyCode::Char(match c {
            'й' => 'q',
            'ш' => 'i',
            'ф' => 'a',
            'о' => 'j',
            'л' => 'k',
            'з' => 'p',
            'т' => 'n',
            'в' => 'd',
            _ => c,
        }),
        _ => code,
    }
}
pub enum Action {
    None,
    Quit,
    Qr,
    Profiles,
    NewProfile,
    Switch(String),
    Delete(String),
    Request(Request),
    Open(String),
    Tab(usize),
    Help,
    Info(String, String),
}
fn open_contact(view: &mut View, id: String) {
    view.opened = Some(id);
    view.composing = true;
    view.command_mode = false;
    view.input.clear();
    view.scroll = 0;
}
/// Navigation never writes into the editor. Text shortcuts are active only outside editors.
pub fn handle_key(view: &mut View, snapshot: &Value, key: KeyEvent) -> Result<Action> {
    if key.kind != event::KeyEventKind::Press {
        return Ok(Action::None);
    }
    if is_quit_key(key) {
        return Ok(Action::Quit);
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return Ok(match shortcut(key.code) {
            KeyCode::Char('p') => Action::Profiles,
            KeyCode::Char('n') => Action::Tab(1),
            _ => Action::None,
        });
    }
    if view.qr.is_some() || view.help || view.info.is_some() {
        if matches!(
            shortcut(key.code),
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')
        ) {
            view.qr = None;
            view.help = false;
            view.info = None;
        }
        return Ok(Action::None);
    }
    if let Some(form) = view.form.as_ref() {
        match key.code {
            KeyCode::Esc => {
                view.form = None;
                view.input.clear();
            }
            KeyCode::Enter => match form {
                Form::DeleteProfile { id, name } => {
                    if view.input != *name {
                        bail!("Введите точное имя: {}", safe(name));
                    }
                    return Ok(Action::Delete(id.clone()));
                }
                Form::ClearChat(id) => {
                    if view.input != "да" {
                        bail!("Для очистки введите да");
                    }
                    return Ok(Action::Request(Request::Clear {
                        contact: id.clone(),
                    }));
                }
            },
            KeyCode::Backspace => {
                view.input.pop();
            }
            KeyCode::Char(c) if !c.is_control() && view.input.len() + c.len_utf8() <= 128 => {
                view.input.push(c)
            }
            _ => {}
        }
        return Ok(Action::None);
    }
    if let Some(profiles) = view.profiles.as_ref() {
        match shortcut(key.code) {
            KeyCode::Esc | KeyCode::Char('q') => view.profiles = None,
            KeyCode::Up | KeyCode::Char('k') => {
                view.profile_selected = view.profile_selected.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                view.profile_selected = (view.profile_selected + 1).min(profiles.len())
            }
            KeyCode::Char('n') => return Ok(Action::NewProfile),
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
                return Ok(profiles
                    .get(view.profile_selected)
                    .map(|p| Action::Switch(p.id.clone()))
                    .unwrap_or(Action::NewProfile))
            }
            _ => {}
        }
        return Ok(Action::None);
    }
    let editing = view.composing || view.command_mode;
    match key.code {
        KeyCode::Esc => {
            if view.command_mode {
                view.command_mode = false;
                view.input.clear();
            } else {
                view.composing = false;
            }
            view.status.clear();
        }
        KeyCode::Tab => {
            if view.command_mode {
                view.command_mode = false;
                view.input.clear();
            } else if view.opened.is_some() {
                view.composing = !view.composing;
            } else {
                view.tab = (view.tab + 1) % 4;
                view.selected = 0;
            }
        }
        KeyCode::PageUp => view.scroll = view.scroll.saturating_add(10),
        KeyCode::PageDown => view.scroll = view.scroll.saturating_sub(10),
        KeyCode::Enter if editing && !view.input.is_empty() => {
            return parse_command(&view.input, view.opened.as_deref(), snapshot);
        }
        KeyCode::Enter => {
            if let Some(c) = contacts(snapshot, view.tab).get(view.selected) {
                open_contact(view, text(&c["id"]).into());
            }
        }
        KeyCode::Backspace if editing => {
            view.input.pop();
        }
        KeyCode::Char(c)
            if editing
                && !c.is_control()
                && !key.modifiers.contains(KeyModifiers::ALT)
                && view.input.len() + c.len_utf8() <= 4096 =>
        {
            view.input.push(c)
        }
        _ if !editing => match shortcut(key.code) {
            KeyCode::Char('q') => return Ok(Action::Quit),
            KeyCode::Char('i') => return Ok(Action::Qr),
            KeyCode::Char('a') => {
                view.input = "/add ".into();
                view.command_mode = true;
            }
            KeyCode::Char('/' | '?') => {
                view.input = "/".into();
                view.command_mode = true;
            }
            KeyCode::Char(c @ '1'..='4') => return Ok(Action::Tab((c as u8 - b'1') as usize)),
            KeyCode::Up | KeyCode::Char('k') => view.selected = view.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                view.selected =
                    (view.selected + 1).min(contacts(snapshot, view.tab).len().saturating_sub(1))
            }
            _ => {}
        },
        _ => {}
    }
    Ok(Action::None)
}
fn parse_command(input: &str, current: Option<&str>, snapshot: &Value) -> Result<Action> {
    if !input.starts_with('/') {
        return Ok(Action::Request(Request::Send {
            contact: current.context("Сначала выберите чат")?.into(),
            text: input.into(),
        }));
    }
    let words = shlex::split(input).context("Незакрытые кавычки")?;
    let args = words.iter().map(String::as_str).collect::<Vec<_>>();
    let contact = |arg: Option<&&str>| -> Result<String> {
        arg.copied()
            .or(current)
            .map(str::to_owned)
            .context("Укажите контакт или откройте чат")
    };
    let req=match args.as_slice() {
        ["/"|"/help"]=>return Ok(Action::Help),
        ["/q"|"/quit"|"/exit"]=>return Ok(Action::Quit),
        ["/invite"]=>return Ok(Action::Qr),
        ["/invite",who]=>Request::Invite{contact:(*who).into()},
        ["/accept",..] if args.len()<=2=>Request::Accept{contact:contact(args.get(1))?},
        ["/decline",..] if args.len()<=2=>Request::Decline{contact:contact(args.get(1))?},
        ["/read",..] if args.len()<=2=>Request::Read{contact:contact(args.get(1))?},
        ["/clear",..] if args.len()<=2=>Request::Clear{contact:contact(args.get(1))?},
        ["/add",link]=>Request::Add{link:(*link).into()},
        ["/add","--image",path]=>Request::Add{link:crate::terminal::decode_qr(Path::new(path))?},
        ["/open",who]=>return Ok(Action::Open(text(&find_contact(snapshot,who)?["id"]).into())),
        ["/send",who,body @ ..] if !body.is_empty()=>Request::Send{contact:(*who).into(),text:body.join(" ")},
        ["/block",who]=>Request::Block{contact:(*who).into(),blocked:true},
        ["/block",who,"--undo"]=>Request::Block{contact:(*who).into(),blocked:false},
        ["/cancel",message]=>Request::Cancel{message:(*message).into()},
        ["/react",message,reaction]=>Request::Reaction{message:(*message).into(),reaction:serde_json::from_value(Value::String((*reaction).into())).context("Реакция: heart like dislike laugh fire coffin hundred horror")?},
        ["/profile","name",name @ ..] if !name.is_empty()=>Request::Profile{name:Some(name.join(" ")),bio:None,seed:None},
        ["/profile","bio",bio @ ..]=>Request::Profile{name:None,bio:Some(bio.join(" ")),seed:None},
        ["/profile","avatar","--random"]=>{let mut bytes=[0;8];getrandom::fill(&mut bytes)?;Request::Profile{name:None,bio:None,seed:Some(u64::from_le_bytes(bytes))}},
        ["/profile","avatar","--seed",seed]=>Request::Profile{name:None,bio:None,seed:Some(seed.parse().context("Семя должно быть целым числом")?)},
        ["/profile"]=>return Ok(Action::Info("Профиль".into(),format!("{}\n{}\n\nShum ID: {}\n\n/profile name <имя>\n/profile bio <текст>\n/profile avatar --random\nCtrl+P: выбрать или создать профиль",safe(text(&snapshot["card"]["name"])),safe(text(&snapshot["card"]["bio"])),text(&snapshot["profile"]["ownerId"])))),
        ["/profile","list"]=>return Ok(Action::Profiles),
        ["/chats"|"/contacts"]=>return Ok(Action::Tab(0)),
        ["/chats","--nearby"]|["/nearby"]=>return Ok(Action::Tab(1)),
        ["/chats","--invites"]=>return Ok(Action::Tab(2)),
        ["/chats","--unread"]=>return Ok(Action::Tab(3)),
        ["/status"|"/about"]=>return Ok(Action::Info("Shum".into(),format!("Версия {} · протокол v1\nПрофиль: {}\nРелеев подключено: {}\n{}\nPush API: {}\n{}",env!("CARGO_PKG_VERSION"),safe(text(&snapshot["card"]["name"])),snapshot["relays"].as_array().map_or(0,Vec::len),bluetooth_status(snapshot),crate::terminal::push_status(snapshot),safe(text(&snapshot["error"]))))),
        ["/keys","verify",who]=>{let c:shum_core::card::Card=serde_json::from_value(find_contact(snapshot,who)?["card"].clone())?;return Ok(Action::Info("Сверка ключей".into(),format!("{}\n\nОтпечаток как в iPhone: {}\n\nShum ID: {}",safe(&c.name),crate::terminal::fingerprint(&c),c.id())));},
        _=>bail!("Команда или аргументы не распознаны. /help: список и примеры"),
    };
    Ok(Action::Request(req))
}
fn invitation(snapshot: &Value, size: ratatui::layout::Size) -> Result<String> {
    let card: shum_core::card::Card = serde_json::from_value(snapshot["card"].clone())?;
    let link = card.invitation()?;
    let qr = crate::terminal::qr(&link, false)?;
    if qr.lines().count() + 4 <= size.height as usize
        && qr.lines().next().map_or(0, |s| s.chars().count() + 4) <= size.width as usize
    {
        return Ok(link);
    }
    use base64::Engine;
    Ok(format!(
        "shum://c2/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hex::decode(&card.nostr_key)?)
    ))
}
struct Pending {
    task: tokio::task::JoinHandle<Result<Option<String>>>,
    input: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Feed(tokio::task::JoinHandle<()>);
impl Drop for Feed {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[derive(Clone, PartialEq, Default)]
struct Activity {
    contact: Option<String>,
    typing: bool,
}
fn feed(
    root: &Path,
    profile: &str,
) -> (
    Feed,
    tokio::sync::watch::Receiver<Option<Value>>,
    tokio::sync::watch::Sender<Activity>,
) {
    let root = root.to_owned();
    let profile = profile.to_owned();
    let (tx, rx) = tokio::sync::watch::channel(None);
    let (activity, mut changes) = tokio::sync::watch::channel(Activity::default());
    let job = tokio::spawn(async move {
        let mut previous = Activity::default();
        let mut heartbeat = Instant::now() - Duration::from_secs(30);
        loop {
            let current = changes.borrow_and_update().clone();
            let update = async {
                if current.contact != previous.contact {
                    let _ = ipc::request(
                        &root,
                        &profile,
                        Request::Focus {
                            contact: current.contact.clone(),
                        },
                    )
                    .await;
                }
                if let Some(id) = &current.contact {
                    if heartbeat.elapsed() > Duration::from_secs(4) || current != previous {
                        let _ = ipc::request(
                            &root,
                            &profile,
                            Request::Typing {
                                contact: id.clone(),
                                active: current.typing,
                            },
                        )
                        .await;
                        let _ = ipc::request(
                            &root,
                            &profile,
                            Request::Presence {
                                contact: id.clone(),
                                online: true,
                            },
                        )
                        .await;
                        heartbeat = Instant::now();
                    }
                }
                let value = ipc::request(&root, &profile, Request::Snapshot).await?;
                Ok::<_, anyhow::Error>(value)
            };
            match tokio::time::timeout(Duration::from_secs(2), update).await {
                Ok(Ok(value)) => {
                    previous = current;
                    let _ = tx.send(Some(value));
                }
                _ => {
                    let _ = tx.send(None);
                }
            }
            tokio::select! {_=tokio::time::sleep(Duration::from_millis(250))=>{},result=changes.changed()=>{if result.is_err(){break;}}}
        }
    });
    (Feed(job), rx, activity)
}
pub async fn run(
    root: &Path,
    initial_profile: &str,
    contact: Option<&str>,
    ascii: bool,
) -> Result<()> {
    let mut profile = initial_profile.to_owned();
    let mut snapshot = ipc::request(root, &profile, Request::Snapshot).await?;
    let mut view = View::default();
    if let Some(contact) = contact {
        open_contact(
            &mut view,
            text(&find_contact(&snapshot, contact)?["id"]).into(),
        );
    }
    loop {
        let mut terminal = ratatui::init();
        let guard = TerminalGuard;
        let mut pictures = Pictures::new(picture_picker(ascii));
        crossterm::execute!(
            std::io::stdout(),
            event::EnableMouseCapture,
            event::EnableBracketedPaste
        )?;
        let result = run_loop(
            root,
            &mut profile,
            &mut snapshot,
            &mut view,
            &mut pictures,
            &mut terminal,
            ascii,
        )
        .await;
        let _ = pictures.clear_graphics(&mut terminal);
        drop(guard);
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            ipc::request(root, &profile, Request::Focus { contact: None }),
        )
        .await;
        if !result? {
            return Ok(());
        }
        let mode = if snapshot["profile"]["keyBackend"] == "file" {
            shum_store::vault::KeyMode::File
        } else {
            shum_store::vault::KeyMode::Auto
        };
        if let Some(created) =
            crate::onboarding::run(root, ascii, mode, crate::onboarding::Settings::default())
                .await?
        {
            profile = created.profile.id;
            ipc::ensure(root, &profile).await?;
            snapshot = ipc::request(root, &profile, Request::Snapshot).await?;
        }
        view = View::default();
    }
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
) -> Result<bool> {
    let (mut worker, mut updates, mut activity) = feed(root, profile);
    let mut pending: Option<Pending> = None;
    let mut previews = tokio::task::JoinSet::new();
    loop {
        while let Some(Ok((id, Some(detail)))) = previews.try_join_next() {
            view.profile_details.insert(id, detail);
        }
        if updates.has_changed().unwrap_or(false) {
            if let Some(value) = updates.borrow_and_update().clone() {
                *snapshot = value;
            } else {
                view.status = "Служба не отвечает. Ctrl+C или F10: выход".into();
            }
        }
        if pending.as_ref().is_some_and(|job| job.task.is_finished()) {
            let mut job = pending.take().unwrap();
            match (&mut job.task).await? {
                Ok(next) => {
                    if let Some(id) = next {
                        if id.is_empty() {
                            return Ok(false);
                        }
                        *profile = id;
                        view.opened = None;
                        view.selected = 0;
                        (worker, updates, activity) = feed(root, profile);
                        *snapshot = Value::Null;
                    }
                    if view.input == job.input {
                        view.input.clear();
                        view.command_mode = false;
                    }
                    view.form = None;
                    view.profiles = None;
                    view.scroll = 0;
                    view.status = "Готово".into();
                }
                Err(error) => view.status = error.to_string(),
            }
        }
        pictures.clear_on_change(
            terminal,
            (
                (
                    profile.as_str(),
                    view.opened.as_deref(),
                    view.tab,
                    view.selected,
                    view.command_mode,
                ),
                (
                    view.help,
                    view.qr.is_some(),
                    view.info.is_some(),
                    view.profiles.is_some(),
                    view.form.is_some(),
                ),
                contacts(snapshot, view.tab)
                    .iter()
                    .map(|c| (text(&c["id"]), c["card"]["avatarSeed"].as_u64()))
                    .collect::<Vec<_>>(),
            ),
        )?;
        terminal.draw(|f| draw(f, snapshot, view, pictures, ascii))?;
        let action = if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => handle_key(view, snapshot, key),
                Event::Paste(value) => {
                    if view.composing || view.command_mode || view.form.is_some() {
                        let limit = if view.form.is_some() { 128 } else { 4096 };
                        for c in safe(&value).chars() {
                            if view.input.len() + c.len_utf8() > limit {
                                break;
                            }
                            view.input.push(c);
                        }
                    }
                    Ok(Action::None)
                }
                Event::Mouse(mouse) => {
                    if view.profiles.is_none()
                        && view.form.is_none()
                        && view.qr.is_none()
                        && !view.help
                        && view.info.is_none()
                    {
                        match mouse.kind {
                            MouseEventKind::ScrollUp => view.scroll = view.scroll.saturating_add(3),
                            MouseEventKind::ScrollDown => {
                                view.scroll = view.scroll.saturating_sub(3)
                            }
                            MouseEventKind::Down(event::MouseButton::Left) => {
                                if let Some((_, id)) = view
                                    .chat_rows
                                    .iter()
                                    .find(|(r, _)| r.contains((mouse.column, mouse.row).into()))
                                {
                                    open_contact(view, id.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(Action::None)
                }
                _ => Ok(Action::None),
            }
        } else {
            Ok(Action::None)
        };
        let action = match action {
            Ok(action) => action,
            Err(error) => {
                view.status = error.to_string();
                Action::None
            }
        };
        match action {
            Action::Quit => return Ok(false),
            Action::NewProfile if pending.is_none() => return Ok(true),
            Action::None | Action::NewProfile => {}
            Action::Qr => match invitation(snapshot, terminal.size()?) {
                Ok(link) => {
                    view.qr = Some(link);
                    if view.command_mode {
                        view.input.clear();
                        view.command_mode = false;
                    }
                }
                Err(error) => view.status = error.to_string(),
            },
            Action::Help => {
                view.help = true;
                view.input.clear();
                view.command_mode = false;
            }
            Action::Info(title, body) => {
                view.info = Some((title, body));
                view.input.clear();
                view.command_mode = false;
            }
            Action::Open(id) => open_contact(view, id),
            Action::Tab(tab) => {
                view.tab = tab;
                view.selected = 0;
                view.composing = false;
                view.command_mode = false;
                view.input.clear();
                if tab == 1 {
                    view.opened = None;
                    view.status.clear();
                }
            }
            Action::Profiles => {
                if view.profiles.is_some() {
                    view.profiles = None;
                } else {
                    let list = shum_store::profiles::Profiles::new(root)?.list()?.1;
                    view.profile_selected = list.iter().position(|p| p.id == *profile).unwrap_or(0);
                    view.profile_details
                        .insert(profile.clone(), snapshot.clone());
                    for p in &list {
                        if p.id != *profile {
                            let root = root.to_owned();
                            let id = p.id.clone();
                            previews.spawn(async move {
                                let detail = profile_preview(&root, &id).await;
                                (id, detail)
                            });
                        }
                    }
                    view.profiles = Some(list);
                }
            }
            Action::Request(Request::Clear { contact })
                if !matches!(view.form, Some(Form::ClearChat(_))) =>
            {
                // Resolve before asking for confirmation, so typos cannot clear a different chat.
                match find_contact(snapshot, &contact) {
                    Ok(c) => {
                        view.form = Some(Form::ClearChat(text(&c["id"]).into()));
                        view.input.clear();
                    }
                    Err(e) => view.status = e.to_string(),
                }
            }
            action => {
                if pending.is_some() {
                    view.status = "Команда выполняется. Можно выйти: Ctrl+C / F10".into();
                    continue;
                }
                let root = root.to_owned();
                let current = profile.clone();
                let task = tokio::spawn(async move {
                    match action {
                        Action::Request(request) => {
                            ipc::request(&root, &current, request).await?;
                            Ok(None)
                        }
                        Action::Switch(id) => {
                            ipc::ensure(&root, &id).await?;
                            let _ = tokio::time::timeout(
                                Duration::from_millis(300),
                                ipc::request(&root, &current, Request::Focus { contact: None }),
                            )
                            .await;
                            shum_store::profiles::Profiles::new(&root)?.select(&id)?;
                            Ok(Some(id))
                        }
                        Action::Delete(id) => {
                            ipc::stop(&root, &id).await?;
                            let profiles = shum_store::profiles::Profiles::new(&root)?;
                            profiles.delete(&id)?;
                            if id == current {
                                let next = profiles.list()?.0.unwrap_or_default();
                                if !next.is_empty() {
                                    ipc::ensure(&root, &next).await?;
                                }
                                Ok(Some(next))
                            } else {
                                Ok(None)
                            }
                        }
                        _ => Ok(None),
                    }
                });
                pending = Some(Pending {
                    task,
                    input: view.input.clone(),
                });
                view.status = "Выполняется… Ctrl+C: выход".into();
            }
        }
        let next = Activity {
            contact: view.opened.clone(),
            typing: view.composing
                && !view.command_mode
                && !view.input.is_empty()
                && !view.input.starts_with('/'),
        };
        activity.send_if_modified(|old| {
            if *old != next {
                *old = next;
                true
            } else {
                false
            }
        });
        let _ = &worker; // Own the task until this terminal session ends.
        tokio::task::yield_now().await;
    }
}

const HELP: &str = "Клавиши работают в английской и русской раскладке.

↑↓ / j k   выбрать чат       Enter открыть / отправить
Esc        из ввода к списку Tab   сменить панель
i          мой QR           a     добавить контакт
Ctrl+P     профили          1–4   фильтр чатов
q          выход из списка  Ctrl+C / Ctrl+Q / F10 из любого окна

/add <ссылка>               /add --image \"/путь/qr.png\"
/invite                    мой QR
/invite <ник>              пригласить в переписку
/accept [ник]              /decline [ник]
/open <ник>                /send <ник> \"текст\"
/read [ник]                /clear [ник] с подтверждением
/react <ID> heart|like|dislike|laugh|fire|coffin|hundred|horror
/cancel <ID>               /block <ник> [--undo]
/profile                   /profile list
/profile name <имя>        /profile bio <текст>
/profile avatar --random   /profile avatar --seed <число>
/keys verify <ник>         /status
/chats [--invites|--unread|--nearby]       /contacts
/quit или /exit            выход

Ник с пробелами заключите в кавычки. Esc закрыть";

/// Read presentation metadata without starting inactive profiles or exposing their messages.
pub async fn profile_preview(root: &Path, id: &str) -> Option<Value> {
    if root.join(id).join("locked").exists() {
        return None;
    }
    if root.join(id).join("daemon.json").exists() {
        return tokio::time::timeout(
            Duration::from_millis(250),
            ipc::request(root, id, Request::Snapshot),
        )
        .await
        .ok()?
        .ok();
    }
    let root = root.to_owned();
    let id = id.to_owned();
    tokio::task::spawn_blocking(move|| {
        let profiles=shum_store::profiles::Profiles::new(root).ok()?;
        let open=profiles.open(Some(&id)).ok()?;
        let state=open.store.state();
        Some(serde_json::json!({"card":state["ownProfileCard"],"chatCount":state["contacts"].as_array().map_or(0,Vec::len)}))
    }).await.ok()?
}

pub fn bluetooth_status(snapshot: &Value) -> String {
    let value = &snapshot["bluetooth"];
    let scan = text(&value["scan"]);
    let advertise = text(&value["advertise"]);
    if value.is_string() {
        return "Перезапустите службу: shum daemon --stop".into();
    }
    if scan == "other_profile" {
        return "Рядом показывается другой выбранный профиль".into();
    }
    if scan == "disabled" || value["enabled"] == false {
        return "Bluetooth отключён · включить: shum --bluetooth status".into();
    }
    if scan == "starting" && advertise == "starting" || scan.is_empty() && advertise.is_empty() {
        return "Bluetooth: запускается поиск устройств рядом…".into();
    }
    if [scan, advertise]
        .iter()
        .any(|s| s.contains("unauthorized") || s.contains("permission") || s.contains("Permission"))
    {
        return match std::env::consts::OS {
            "macos" => "Разрешите Shum: Настройки macOS → Конфиденциальность → Bluetooth",
            "linux" => "Нет доступа к Bluetooth: проверьте BlueZ и правила D-Bus/Polkit",
            _ => "Нет доступа к Bluetooth: проверьте разрешения в настройках системы",
        }
        .into();
    }
    if scan == "poweredOff" || advertise == "poweredOff" {
        return "Bluetooth выключен на компьютере".into();
    }
    if scan.contains("adapter not found") || advertise == "unsupported" {
        return "Bluetooth-адаптер не найден · доступна переписка через релей".into();
    }
    if scan == "scanning" && advertise == "advertising" {
        return "Bluetooth: поиск включён, ваш профиль виден рядом".into();
    }
    format!(
        "Bluetooth · поиск: {} · объявление: {}",
        if scan.is_empty() {
            "запуск"
        } else {
            scan
        },
        if advertise.is_empty() {
            "запуск"
        } else {
            advertise
        }
    )
}

pub fn nearby_label(contact: &Value) -> String {
    match contact["distance"].as_u64() {
        Some(meters) => format!("Рядом · ~{meters} м"),
        None => "Рядом · Bluetooth".into(),
    }
}
