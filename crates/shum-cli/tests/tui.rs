use ratatui::{backend::TestBackend, Terminal};
use ratatui_image::picker::Picker;
use serde_json::{json, Value};
use shum_cli::ui::{draw, Pictures, View};
fn example() -> Value {
    json!({"profile":{"id":"local"},"card":{"name":"Игорь Загоев"},"relays":["wss://test.invalid"],"contacts":[{"id":"anna","card":{"name":"Аня","bio":"Дизайнер, люблю кофе и настолки.","avatarSeed":42},"unread":1,"nearby":false,"phase":"accepted","typing":true},{"id":"igor","card":{"name":"Игорь","avatarSeed":123},"phase":"incomingPending","unread":0}],"messages":[{"id":"m1","contactID":"anna","outgoing":false,"text":"Привет! Ты была на фестивале?","timestamp":1800000000000_i64,"status":"read"},{"id":"m2","contactID":"anna","outgoing":true,"text":"Да, у сцены с синтезаторами","timestamp":1800000100000_i64,"status":"read"}],"reactions":[{"messageID":"m2","mark":{"reaction":"like"}}]})
}
#[test]
fn native_chat_avatars_stay_inside_rows_when_scrolling_and_resizing() {
    use ratatui_image::picker::ProtocolType;
    let mut picker = Picker::halfblocks();
    picker.set_protocol_type(ProtocolType::Iterm2);
    let mut pictures = Pictures::new(picker);
    let mut data = example();
    data["contacts"] = json!((0..20)
        .map(|i| json!({"id":format!("contact{i}"),"card":{"name":format!("Peer{i}"),"avatarSeed":i},"phase":"accepted"}))
        .collect::<Vec<_>>());
    // Reuse the image cache across different layouts and scroll positions.
    for (width, height) in [(100, 32), (40, 16), (35, 12), (9, 12), (100, 32)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        for selected in [0, 1, 19, 0] {
            let mut view = View::default();
            view.selected = selected;
            terminal
                .draw(|frame| {
                    draw(frame, &data, &mut view, &mut pictures, false);
                    let buffer = frame.buffer_mut();
                    let mut previous_bottom = 0;
                    let mut count = 0;
                    for y in 0..height {
                        for x in 0..width {
                            let sequence = buffer[(x, y)].symbol();
                            let Some((_, image)) = sequence.split_once("]1337;File=") else {
                                continue;
                            };
                            let (header, payload) = image.split_once(':').unwrap();
                            let dimension = |name: &str| -> u16 {
                                header
                                    .split(';')
                                    .find_map(|part| part.strip_prefix(name))
                                    .expect("explicit image bounds")
                                    .parse()
                                    .expect("image bounds must use character cells, not pixels")
                            };
                            let image_width = dimension("width=");
                            let image_height = dimension("height=");
                            assert!(image_width > 0 && image_width <= 6);
                            assert!(image_height > 0 && image_height <= 3);
                            assert!(y >= previous_bottom, "avatars overlap vertically");
                            assert!(
                                y + image_height < height - 2,
                                "avatar covers the list border or footer"
                            );
                            assert!(
                                x + image_width < width - 1,
                                "avatar covers the right border"
                            );
                            assert!(payload.starts_with("iVBOR"), "retain the transparent PNG");
                            previous_bottom = y + image_height;
                            count += 1;
                        }
                    }
                    if width < 35 {
                        assert_eq!(count, 0, "small terminals show the resize prompt");
                    } else {
                        assert!(
                            count > 0,
                            "missing avatars at {width}x{height}, selected {selected}"
                        );
                    }
                })
                .unwrap();
        }
    }
}
#[test]
fn nearby_screen_shows_live_radio_state_and_only_nearby_contacts() {
    let mut data = example();
    data["bluetooth"] = json!({"enabled":true,"scan":"scanning","advertise":"advertising"});
    data["contacts"][0]["nearby"] = json!(true);
    data["contacts"][0]["distance"] = json!(3);
    let mut view = View::default();
    view.tab = 1;
    let mut pictures = Pictures::new(Picker::halfblocks());
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    terminal
        .draw(|f| draw(f, &data, &mut view, &mut pictures, false))
        .unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect::<String>();
    assert!(screen.contains("Рядом · ~3 м"));
    assert!(screen.contains("ваш профиль виден рядом"));
    data["contacts"] = json!([]);
    data["bluetooth"]["advertise"] = json!("poweredOff");
    terminal
        .draw(|f| draw(f, &data, &mut view, &mut pictures, false))
        .unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect::<String>();
    assert!(screen.contains("Пока никого рядом"));
    assert!(screen.contains("Bluetooth выключен"));
    assert!(!screen.contains("ваш профиль виден рядом"));
}
#[test]
fn tui_renders_chats_avatars_and_empty_state_in_small_terminals() {
    let mut pictures = Pictures::new(Picker::halfblocks());
    for (width, height) in [(80, 32), (40, 16), (140, 45)] {
        for ascii in [false, true] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut view = View::chat("anna");
            terminal
                .draw(|f| draw(f, &example(), &mut view, &mut pictures, ascii))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let screen = buffer
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("Аня"));
            assert_eq!(
                screen.matches("Аня").count(),
                if width >= 60 { 2 } else { 1 },
                "name belongs in the list and header, not the border"
            );
            assert!(screen.contains("Сообщение"));
            assert!(!screen.contains('\x1b'));
            if width == 80 && !ascii {
                assert!(screen.contains("синтезаторами"));
                assert!(screen.contains("like"));
                if let Ok(path) = std::env::var("SHUM_TEST_SCREEN") {
                    let cells=buffer.content.iter().map(|c|json!({"s":c.symbol(),"fg":format!("{:?}",c.fg),"bg":format!("{:?}",c.bg)})).collect::<Vec<_>>();
                    std::fs::write(
                        path,
                        serde_json::to_vec(&json!({"width":width,"height":height,"cells":cells}))
                            .unwrap(),
                    )
                    .unwrap();
                }
            }
            view.opened = None;
            terminal
                .draw(|f| {
                    draw(
                        f,
                        &json!({"card":{"name":"Игорь"}}),
                        &mut view,
                        &mut pictures,
                        ascii,
                    )
                })
                .unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("QR"));
        }
    }
}

fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}
#[test]
fn keyboard_modes_keep_shortcuts_reachable_without_corrupting_messages() {
    use crossterm::event::{KeyCode as K, KeyModifiers as M};
    use shum_cli::ui::{handle_key, Action};
    let mut view = View::default();
    let data = example();
    for c in ['x', 'ы', 'e', 't'] {
        handle_key(&mut view, &data, key(K::Char(c))).unwrap();
    }
    assert!(
        view.input.is_empty(),
        "navigation must not create invisible input"
    );
    for c in ['i', 'ш'] {
        assert!(matches!(
            handle_key(&mut view, &data, key(K::Char(c))).unwrap(),
            Action::Qr
        ));
    }
    for c in ['q', 'й'] {
        assert!(matches!(
            handle_key(&mut view, &data, key(K::Char(c))).unwrap(),
            Action::Quit
        ));
    }
    handle_key(&mut view, &data, key(K::Enter)).unwrap();
    for c in "qiйшаф123".chars() {
        handle_key(&mut view, &data, key(K::Char(c))).unwrap();
    }
    assert_eq!(view.input, "qiйшаф123");
    handle_key(&mut view, &data, key(K::Esc)).unwrap();
    assert!(matches!(
        handle_key(&mut view, &data, key(K::Char('i'))).unwrap(),
        Action::Qr
    ));
    assert_eq!(view.input, "qiйшаф123", "Esc preserves an unsent draft");
    for modal in [0, 1, 2] {
        view.help = modal == 0;
        view.qr = if modal == 1 {
            Some("test".into())
        } else {
            None
        };
        view.profiles = if modal == 2 { Some(vec![]) } else { None };
        for code in [K::Char('c'), K::Char('q'), K::Char('с'), K::F(10)] {
            assert!(matches!(
                handle_key(
                    &mut view,
                    &data,
                    crossterm::event::KeyEvent::new(code, M::CONTROL)
                )
                .unwrap(),
                Action::Quit
            ));
        }
    }
}
#[test]
fn slash_commands_respect_arguments_and_reject_typos() {
    use crossterm::event::KeyCode;
    use shum_cli::{
        runtime::Request,
        ui::{handle_key, Action},
    };
    let mut view = View::chat("anna");
    let data = example();
    for input in ["/quit", "/exit", "/q"] {
        view.input = input.into();
        assert!(matches!(
            handle_key(&mut view, &data, key(KeyCode::Enter)).unwrap(),
            Action::Quit
        ));
    }
    view.input = "/invite Игорь".into();
    assert!(
        matches!(handle_key(&mut view,&data,key(KeyCode::Enter)).unwrap(),Action::Request(Request::Invite{contact}) if contact=="Игорь")
    );
    view.input = "/send \"Игорь Загоев\" \"Привет, мир!\"".into();
    assert!(
        matches!(handle_key(&mut view,&data,key(KeyCode::Enter)).unwrap(),Action::Request(Request::Send{contact,text}) if contact=="Игорь Загоев" && text=="Привет, мир!")
    );
    for input in [
        "/add",
        "/accept anna extra",
        "/invite a b",
        "/profile avatar --seed nope",
        "/react id none",
        "/typo",
    ] {
        view.input = input.into();
        assert!(
            handle_key(&mut view, &data, key(KeyCode::Enter)).is_err(),
            "{input}"
        );
    }
    view.input = "/profile".into();
    assert!(matches!(
        handle_key(&mut view, &data, key(KeyCode::Enter)).unwrap(),
        Action::Info(..)
    ));
}
#[test]
fn wizard_empty_screen_and_profiles_render_without_clipping_at_supported_sizes() {
    use shum_cli::onboarding::{Step, Wizard};
    let mut pictures = Pictures::new(Picker::halfblocks());
    for (w, h) in [(35, 12), (40, 18), (80, 32), (140, 45)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        for step in [Step::Name, Step::Avatar, Step::Saving, Step::Done] {
            let wizard = Wizard {
                step,
                name: "Игорь Загоев".into(),
                seed: 42,
                error: String::new(),
                file_keys: true,
            };
            terminal
                .draw(|f| shum_cli::onboarding::draw(f, &wizard, &mut pictures, false))
                .unwrap();
            if w == 80 {
                save_screen(
                    &terminal,
                    match step {
                        Step::Name => "init",
                        Step::Avatar => "avatar",
                        Step::Saving => "saving",
                        Step::Done => "done",
                    },
                );
            }
        }
        let empty =
            json!({"profile":{"id":"local"},"card":{"name":"Игорь Загоев","avatarSeed":42}});
        let mut view = View::default();
        terminal
            .draw(|f| draw(f, &empty, &mut view, &mut pictures, false))
            .unwrap();
        if w == 80 {
            save_screen(&terminal, "empty");
        }
        view.profiles = Some(vec![shum_store::profiles::Profile {
            id: "local".into(),
            name: "Игорь Загоев".into(),
            owner_id: "id".into(),
            key_backend: shum_store::vault::KeyBackend::File,
            deleting: false,
        }]);
        terminal
            .draw(|f| draw(f, &empty, &mut view, &mut pictures, false))
            .unwrap();
        if w == 80 {
            save_screen(&terminal, "profiles");
            let s = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(s.contains("Создать новый профиль"));
        }
    }
}
fn save_screen(terminal: &Terminal<TestBackend>, name: &str) {
    if let Ok(dir) = std::env::var("SHUM_TEST_SCREENS") {
        let buffer = terminal.backend().buffer();
        let cells = buffer
            .content
            .iter()
            .map(|c| json!({"s":c.symbol(),"fg":format!("{:?}",c.fg),"bg":format!("{:?}",c.bg)}))
            .collect::<Vec<_>>();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{name}.json")),
            serde_json::to_vec(
                &json!({"width":buffer.area.width,"height":buffer.area.height,"cells":cells}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
