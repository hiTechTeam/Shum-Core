//! First-run presentation and profile creation stay in the client.
use crate::{
    terminal::{safe, text},
    ui::Pictures,
};
use anyhow::{bail, ensure, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};
use serde_json::{json, Value};
use shum_core::card::Card;
use shum_store::{
    profiles::{Profile, Profiles},
    vault::{KeyMode, ProfileKeys},
};
use std::{path::Path, time::Duration};

const GREEN: Color = Color::Rgb(48, 209, 88);
const MUTED: Color = Color::Rgb(135, 145, 139);
const SHIELD: [&str; 13] = [
    "  ############  ",
    " #            # ",
    "#    ######    #",
    "#   #      #   #",
    "#   #  ##  #   #",
    "#   # #### #   #",
    "#    ######    #",
    "#       #      #",
    " #      #     # ",
    "  #     #### #  ",
    "   #    # # #   ",
    "    #   ## #    ",
    "     ######     ",
];
#[derive(Clone)]
pub struct Settings {
    pub bluetooth: bool,
    pub relays: Vec<String>,
    pub push_url: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            bluetooth: true,
            relays: shum_transport_nostr::DEFAULT_RELAYS
                .iter()
                .map(|s| (*s).into())
                .collect(),
            push_url: Some("https://d5d5lr0h6812sbjiiqoa.ccx97b51.apigw.yandexcloud.net".into()),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        shum_transport_nostr::RelayPool::validate_urls(&self.relays)?;
        if let Some(url) = &self.push_url {
            shum_transport_nostr::push::PushClient::new(url)?;
        }
        Ok(())
    }
}
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.trim() == name
            && !name.chars().any(char::is_control),
        "Имя: 1–64 байта UTF-8, без пробелов по краям (до 32 русских букв)"
    );
    Ok(())
}
pub struct Created {
    pub profile: Profile,
    pub card: Card,
}
pub fn create(
    root: &Path,
    name: &str,
    seed: Option<u64>,
    mode: KeyMode,
    settings: &Settings,
    keys: ProfileKeys,
) -> Result<Created> {
    validate_name(name)?;
    settings.validate()?;
    let card = Card::create(
        &keys.noise,
        &keys.signing,
        &keys.nostr,
        name.into(),
        "",
        seed,
        1,
    )?;
    card.validate()?;
    let profiles = Profiles::new(root)?;
    let p = profiles.create_with_keys(name, mode, keys)?;
    let save = (|| -> Result<()> {
        let mut open = profiles.open(Some(&p.id))?;
        open.store.transaction(|s| {
            s["ownProfileCard"] = serde_json::to_value(&card)?;
            s["cliSettings"] = json!({"relays":settings.relays,"pushURL":settings.push_url,"bluetooth":settings.bluetooth});
            Ok(())
        })?;
        drop(open);
        // Read back encrypted storage and verify the signed public card before reporting success.
        let reopened = profiles.open(Some(&p.id))?;
        let stored: Card =
            serde_json::from_value(reopened.store.state()["ownProfileCard"].clone())?;
        stored.validate()?;
        ensure!(
            stored == card && stored.id() == reopened.keys.owner_id(),
            "Не прошла проверка сохранённого профиля"
        );
        drop(reopened);
        profiles.select(&p.id)?;
        Ok(())
    })();
    if let Err(error) = save {
        if let Err(cleanup) = profiles.delete(&p.id) {
            bail!(
                "{error}; не удалось удалить незавершённый профиль {}: {cleanup}",
                p.id
            );
        }
        return Err(error);
    }
    Ok(Created { profile: p, card })
}
#[derive(Clone, Copy, PartialEq)]
pub enum Step {
    Name,
    Avatar,
    Saving,
    Done,
}
pub struct Wizard {
    pub step: Step,
    pub name: String,
    pub seed: u64,
    pub error: String,
    pub file_keys: bool,
}
pub fn draw(frame: &mut Frame<'_>, wizard: &Wizard, pictures: &mut Pictures, ascii: bool) {
    let area = frame.area();
    let color = |c| if ascii { Color::Reset } else { c };
    let muted = Style::default().fg(color(MUTED));
    let green = Style::default().fg(color(GREEN));
    frame.render_widget(
        Paragraph::new("").style(Style::default().bg(color(Color::Rgb(10, 13, 11)))),
        area,
    );
    let x = area.x + 2.min(area.width);
    let width = area.width.saturating_sub(4);
    let row =
        |y: u16, h: u16| Rect::new(x, area.y + y, width, h.min(area.height.saturating_sub(y)));
    if area.width < 35 || area.height < 18 {
        frame.render_widget(
            Paragraph::new("Увеличьте окно до 35×18. Esc отменить"),
            area,
        );
        return;
    }
    frame.render_widget(
        Paragraph::new("ШУМ · Новый профиль").style(green),
        row(1, 1),
    );
    frame.render_widget(
        Paragraph::new("Ключи создаются и сохраняются только на этом устройстве.")
            .style(muted)
            .wrap(Wrap { trim: false }),
        row(3, 2),
    );
    if wizard.step == Step::Name {
        let tall = area.height >= 29 && !ascii;
        if tall {
            frame.render_widget(
                Paragraph::new(
                    SHIELD
                        .iter()
                        .map(|s| Line::from(s.replace('#', "█")))
                        .collect::<Vec<_>>(),
                )
                .style(green),
                Rect::new(x + 2, area.y + 6, 20, 13),
            );
        }
        let y = if tall { 20 } else { 6 };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "✓ Криптографические ключи подготовлены",
                    green,
                )),
                Line::from("  Хранилище будет создано после выбора аватара."),
            ]),
            row(y, 2),
        );
        frame.render_widget(
            Paragraph::new("Как вас зовут? Это имя увидят ваши собеседники.").style(muted),
            row(y + 3, 1),
        );
        let prompt = format!("Имя: {}", safe(&wizard.name));
        frame.render_widget(Paragraph::new(prompt).style(green), row(y + 4, 1));
        frame.set_cursor_position((
            x + 5
                + unicode_width::UnicodeWidthStr::width(wizard.name.as_str())
                    .min(width.saturating_sub(6) as usize) as u16,
            area.y + y + 4,
        ));
    } else {
        frame.render_widget(
            Paragraph::new(format!("Имя: {}", safe(&wizard.name))),
            row(6, 1),
        );
        frame.render_widget(
            Paragraph::new("Аватар · пиксельный, его видят все").style(muted),
            row(8, 1),
        );
        let tall = area.height >= 24;
        let avatar_height = if tall { 9 } else { 3 };
        if !ascii {
            pictures.draw(
                frame,
                wizard.seed,
                Rect::new(x + 2, area.y + 10, if tall { 18 } else { 6 }, avatar_height),
            );
        }
        let dx = if ascii {
            0
        } else if tall {
            24
        } else {
            10
        };
        let options = match wizard.step {
            Step::Avatar => vec![
                Line::from(Span::styled(&wizard.name, green)),
                Line::from(""),
                Line::from("[r] другой вариант"),
                Line::from("[Enter] оставить этот"),
                Line::from("[Esc] изменить имя"),
            ],
            Step::Saving => vec![
                Line::from(Span::styled("Сохраняем профиль…", green)),
                Line::from("Шифруем базу и проверяем ключи."),
            ],
            Step::Done => vec![
                Line::from(Span::styled("✓ Профиль готов", green)),
                Line::from("✓ Ключи и шифрование"),
                Line::from(if wizard.file_keys {
                    "✓ Файл ключей 0600"
                } else {
                    "✓ Системное хранилище ключей"
                }),
                Line::from("✓ Проверка чтения и подписей"),
                Line::from("[Enter] продолжить"),
            ],
            Step::Name => unreachable!(),
        };
        frame.render_widget(
            Paragraph::new(options).wrap(Wrap { trim: false }),
            Rect::new(
                x + dx,
                area.y + 10,
                width.saturating_sub(dx),
                6.min(area.height.saturating_sub(12)),
            ),
        );
        if tall && wizard.step == Step::Avatar {
            frame.render_widget(
                Paragraph::new("Фото-аватары пока недоступны.").style(muted),
                row(21, 1),
            );
        }
    }
    frame.render_widget(
        Paragraph::new(safe(&wizard.error))
            .style(Style::default().fg(color(Color::Yellow)))
            .wrap(Wrap { trim: false }),
        row(area.height.saturating_sub(4), 2),
    );
    frame.render_widget(
        Paragraph::new(if wizard.step == Step::Name {
            "Enter далее · Esc отменить · Ctrl+C выход"
        } else {
            "Ctrl+C выход"
        })
        .style(muted),
        row(area.height - 1, 1),
    );
}
/// No persistent profile exists until the avatar is confirmed. Cancelling drops the prepared keys.
pub async fn run(
    root: &Path,
    ascii: bool,
    mode: KeyMode,
    settings: Settings,
) -> Result<Option<Created>> {
    settings.validate()?;
    let mut keys = Some(ProfileKeys::generate()?);
    let seed = shum_core::crypto::avatar_seed(&keys.as_ref().unwrap().noise.noise_public());
    let mut wizard = Wizard {
        step: Step::Name,
        name: String::new(),
        seed,
        error: String::new(),
        file_keys: matches!(mode.backend()?, shum_store::vault::KeyBackend::File),
    };
    let mut terminal = ratatui::init();
    let _guard = crate::ui::TerminalGuard;
    let mut pictures = Pictures::new(crate::ui::picture_picker(ascii));
    crossterm::execute!(std::io::stdout(), event::EnableBracketedPaste)?;
    let mut created = None;
    let mut saving: Option<tokio::task::JoinHandle<Result<Created>>> = None;
    loop {
        if saving.as_ref().is_some_and(|job| job.is_finished()) {
            match saving.take().unwrap().await? {
                Ok(value) => {
                    created = Some(value);
                    wizard.step = Step::Done;
                }
                Err(error) => {
                    wizard.error = error.to_string();
                    keys = Some(ProfileKeys::generate()?);
                    wizard.step = Step::Name;
                }
            }
        }
        terminal.draw(|f| draw(f, &wizard, &mut pictures, ascii))?;
        if !event::poll(Duration::from_millis(50))? {
            tokio::task::yield_now().await;
            continue;
        }
        let ev = event::read()?;
        // Publication is atomic at the store level; let it finish before leaving this screen.
        if wizard.step == Step::Saving {
            continue;
        }
        match ev {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if crate::ui::is_quit_key(key) {
                    return Ok(created);
                }
                match (wizard.step, key.code) {
                    (Step::Name, KeyCode::Esc) => return Ok(None),
                    (Step::Name, KeyCode::Enter) => {
                        let validation = validate_name(&wizard.name).and_then(|()| {
                            if Profiles::new(root)?
                                .list()?
                                .1
                                .iter()
                                .any(|p| p.name == wizard.name)
                            {
                                bail!("Такое имя уже есть. Выберите другое.");
                            }
                            Ok(())
                        });
                        match validation {
                            Ok(()) => {
                                wizard.step = Step::Avatar;
                                wizard.error.clear();
                            }
                            Err(e) => wizard.error = e.to_string(),
                        }
                    }
                    (Step::Name, KeyCode::Backspace) => {
                        wizard.name.pop();
                    }
                    (Step::Name, KeyCode::Char(c))
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                            && !c.is_control()
                            && wizard.name.len() + c.len_utf8() <= 64 =>
                    {
                        wizard.name.push(c)
                    }
                    (Step::Avatar, KeyCode::Char('r' | 'к')) => {
                        let mut bytes = [0; 8];
                        getrandom::fill(&mut bytes)?;
                        wizard.seed = u64::from_le_bytes(bytes);
                    }
                    (Step::Avatar, KeyCode::Esc) => wizard.step = Step::Name,
                    (Step::Avatar, KeyCode::Enter) => {
                        wizard.step = Step::Saving;
                        let root = root.to_owned();
                        let name = wizard.name.clone();
                        let settings = settings.clone();
                        let seed = wizard.seed;
                        let keys = keys.take().unwrap();
                        saving = Some(tokio::task::spawn_blocking(move || {
                            create(&root, &name, Some(seed), mode, &settings, keys)
                        }));
                    }
                    (Step::Done, KeyCode::Enter | KeyCode::Esc) => return Ok(created),
                    _ => {}
                }
            }
            Event::Paste(value) if wizard.step == Step::Name => {
                for c in safe(&value).chars() {
                    if wizard.name.len() + c.len_utf8() <= 64 {
                        wizard.name.push(c);
                    }
                }
            }
            _ => {}
        }
    }
}
pub fn json(created: &Created) -> Result<Value> {
    Ok(
        json!({"profile":created.profile,"card":created.card,"invitation":created.card.invitation()?}),
    )
}
pub fn completion(created: &Created) -> String {
    format!(
        "Профиль «{}» готов.\nНаберите shum, чтобы открыть чаты, или shum --help.",
        safe(text(&json!(created.profile.name)))
    )
}
