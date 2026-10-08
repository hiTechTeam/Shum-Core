use ratatui::{backend::TestBackend, style::Color, Terminal};
use ratatui_image::picker::{Picker, ProtocolType};
use serde_json::json;
use shum_cli::{
    display::{Colors, Display},
    onboarding::{Step, Wizard},
    ui::{Pictures, View},
};

#[test]
fn warp_direct_placement_contains_the_complete_original_avatar() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let display = Display::for_terminal("WarpTerminal", "xterm-256color", "", false, false);
    let mut picker = Picker::halfblocks();
    picker.set_protocol_type(display.images);
    let mut pictures = Pictures::with_display(picker, display);
    let mut terminal = Terminal::new(TestBackend::new(80, 32)).unwrap();
    let wizard = Wizard {
        step: Step::Avatar,
        name: "Test".into(),
        seed: 42,
        error: String::new(),
        file_keys: true,
    };
    terminal
        .draw(|frame| {
            shum_cli::onboarding::draw(frame, &wizard, &mut pictures, false);
            let data = frame
                .buffer_mut()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(!data.contains("]1337;"));
            assert!(
                !data.contains("U=1"),
                "Warp does not support Unicode image placeholders"
            );
            let (erase, image) = data.split_once("\x1b_Ga=T,").unwrap();
            assert!(erase.contains("\x1b_Ga=d,d=I,"));
            let (header, payload) = image.split_once(';').unwrap();
            assert!(header.contains("c=18,r=9,C=1,q=2"));
            let png = STANDARD
                .decode(payload.split_once("\x1b\\").unwrap().0)
                .unwrap();
            let pixels = image::load_from_memory(&png).unwrap().to_rgba8();
            assert_eq!(pixels.dimensions(), (36, 36));
            assert_eq!(
                pixels.into_raw(),
                shum_cli::avatar::render_subject(42)
                    .pixels
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
            );
        })
        .unwrap();
}

#[test]
fn terminal_capabilities_distinguish_apple_terminal_and_warp() {
    for colorterm in ["", "truecolor"] {
        let apple =
            Display::for_terminal("Apple_Terminal", "xterm-256color", colorterm, false, false);
        assert_eq!(apple.colors, Colors::Indexed);
        assert_eq!(apple.images, ProtocolType::Halfblocks);
    }
    let warp = Display::for_terminal("WarpTerminal", "xterm-256color", "", false, false);
    assert_eq!(warp.colors, Colors::Rgb);
    assert_eq!(warp.images, ProtocolType::Iterm2);
    assert!(warp.direct_images);
    assert_eq!(
        Display::for_terminal("", "xterm-256color", "", false, false).colors,
        Colors::Indexed
    );
    assert_eq!(
        Colors::Rgb.color(Color::Rgb(48, 209, 88)),
        Color::Rgb(48, 209, 88)
    );
    assert_eq!(
        Colors::Indexed.color(Color::Rgb(10, 13, 11)),
        Color::Indexed(232)
    );
}

#[test]
fn apple_terminal_frames_use_indexed_colors_and_readable_defaults() {
    let mut pictures = Pictures::with_colors(Picker::halfblocks(), Colors::Indexed);
    let mut terminal = Terminal::new(TestBackend::new(80, 32)).unwrap();
    let snapshot = json!({"card":{"name":"Test","avatarSeed":42},"contacts":[{"id":"one","phase":"accepted","card":{"name":"Friend","avatarSeed":42}}]});
    let mut view = View::chat("one");
    for modal in [false, true] {
        view.help = modal;
        terminal
            .draw(|f| shum_cli::ui::draw(f, &snapshot, &mut view, &mut pictures, false))
            .unwrap();
        assert!(terminal.backend().buffer().content.iter().all(|c| {
            !matches!(c.fg, Color::Rgb(..) | Color::Reset)
                && !matches!(c.bg, Color::Rgb(..) | Color::Reset)
        }));
    }
    let wizard = Wizard {
        step: Step::Avatar,
        name: "Test".into(),
        seed: 42,
        error: String::new(),
        file_keys: true,
    };
    terminal
        .draw(|f| shum_cli::onboarding::draw(f, &wizard, &mut pictures, false))
        .unwrap();
    let buffer = terminal.backend().buffer();
    assert!(buffer
        .content
        .iter()
        .all(|c| !matches!(c.fg, Color::Rgb(..)) && !matches!(c.bg, Color::Rgb(..))));
    let text = buffer
        .content
        .iter()
        .map(|c| c.symbol())
        .collect::<String>();
    assert!(text.contains("Shum"));
    assert!(!text.contains("ШУМ"));
}

#[test]
fn avatar_preview_preserves_area_samples_and_uses_seamless_cell_backgrounds() {
    for seed in [0, 1, 42, 123, 9001] {
        let mut pictures = Pictures::with_colors(Picker::halfblocks(), Colors::Rgb);
        let mut terminal = Terminal::new(TestBackend::new(80, 32)).unwrap();
        let wizard = Wizard {
            step: Step::Avatar,
            name: "Test".into(),
            seed,
            error: String::new(),
            file_keys: true,
        };
        terminal
            .draw(|f| shum_cli::onboarding::draw(f, &wizard, &mut pictures, false))
            .unwrap();
        let pixels = shum_cli::avatar::render_subject(seed).sampled(18);
        for y in 0..9 {
            for x in 0..18 {
                let cell = &terminal.backend().buffer()[(4 + x as u16, 10 + y as u16)];
                let a = pixels[y * 2 * 18 + x];
                let b = pixels[(y * 2 + 1) * 18 + x];
                let rgb = |p: [u8; 4]| {
                    let c = std::array::from_fn::<_, 3, _>(|i| {
                        ((u32::from(p[i]) * u32::from(p[3])
                            + [10, 13, 11][i] * (255 - u32::from(p[3]))
                            + 127)
                            / 255) as u8
                    });
                    Color::Rgb(c[0], c[1], c[2])
                };
                assert_ne!(cell.symbol(), "▄", "avoid lower-block font seams");
                if rgb(a) == rgb(b) {
                    assert_eq!(cell.symbol(), " ");
                    assert_eq!(cell.bg, rgb(b));
                } else {
                    assert_eq!(cell.symbol(), "▀");
                    assert_eq!(cell.fg, rgb(a));
                    assert_eq!(cell.bg, rgb(b));
                }
            }
        }
    }
}
