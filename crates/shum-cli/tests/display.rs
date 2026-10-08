use ratatui::{backend::TestBackend, style::Color, Terminal};
use ratatui_image::picker::{Picker, ProtocolType};
use serde_json::json;
use shum_cli::{
    display::{Colors, Display},
    onboarding::{Step, Wizard},
    ui::{Pictures, View},
};

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
fn avatar_preview_preserves_every_logical_pixel_and_transparency() {
    // At 18 columns × 9 rows each half cell is exactly one original 2×2 block.
    // Sampling the wrong source corner used to erase single-pixel face details.
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
        let pixels = shum_cli::avatar::render_subject(seed).coarse18();
        for y in 0..9 {
            for x in 0..18 {
                let cell = &terminal.backend().buffer()[(4 + x as u16, 10 + y as u16)];
                let a = pixels[y * 2 * 18 + x];
                let b = pixels[(y * 2 + 1) * 18 + x];
                let rgb = |p: [u8; 4]| Color::Rgb(p[0], p[1], p[2]);
                match (a[3] > 0, b[3] > 0) {
                    (true, true) => {
                        assert_eq!(cell.symbol(), "▀");
                        assert_eq!(cell.fg, rgb(a));
                        assert_eq!(cell.bg, rgb(b));
                    }
                    (true, false) => {
                        assert_eq!(cell.symbol(), "▀");
                        assert_eq!(cell.fg, rgb(a));
                        assert_eq!(cell.bg, Color::Rgb(10, 13, 11));
                    }
                    (false, true) => {
                        assert_eq!(cell.symbol(), "▄");
                        assert_eq!(cell.fg, rgb(b));
                        assert_eq!(cell.bg, Color::Rgb(10, 13, 11));
                    }
                    (false, false) => {
                        assert_eq!(cell.symbol(), " ");
                        assert_eq!(cell.bg, Color::Rgb(10, 13, 11));
                    }
                }
            }
        }
    }
}
