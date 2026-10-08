//! Terminal capabilities and colour conversion belong to client presentation.
use ratatui::{buffer::Buffer, style::Color};
use ratatui_image::picker::ProtocolType;

pub const ACCENT: Color = Color::Rgb(48, 209, 88);
pub const MUTED: Color = Color::Rgb(135, 145, 139);
pub const LOGO_COLOR: Color = Color::Rgb(93, 245, 138);
pub const LOGO: [&str; 11] = [
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Colors {
    Rgb,
    Indexed,
}

#[derive(Clone, Copy)]
pub struct Display {
    pub colors: Colors,
    pub images: ProtocolType,
    pub direct_images: bool,
    pub cell_avatars: bool,
}
impl Display {
    pub fn detect() -> Self {
        Self::for_terminal(
            &std::env::var("TERM_PROGRAM").unwrap_or_default(),
            &std::env::var("TERM").unwrap_or_default(),
            &std::env::var("COLORTERM").unwrap_or_default(),
            std::env::var_os("KITTY_WINDOW_ID").is_some(),
            std::env::var_os("WT_SESSION").is_some(),
        )
    }

    pub fn for_terminal(
        program: &str,
        term: &str,
        colorterm: &str,
        kitty: bool,
        windows: bool,
    ) -> Self {
        let kitty = kitty || term.contains("kitty");
        let images = if program == "Apple_Terminal" {
            ProtocolType::Halfblocks
        } else if kitty {
            ProtocolType::Kitty
        } else if matches!(program, "iTerm.app" | "WezTerm" | "WarpTerminal") {
            ProtocolType::Iterm2
        } else if windows {
            ProtocolType::Sixel
        } else {
            ProtocolType::Halfblocks
        };
        // Terminal.app on macOS 15 does not understand RGB SGR sequences.
        // An inherited COLORTERM=truecolor must not override that known limit.
        let rgb = program != "Apple_Terminal"
            && (kitty
                || windows
                || matches!(
                    program,
                    "iTerm.app" | "WezTerm" | "WarpTerminal" | "ghostty"
                )
                || matches!(colorterm, "truecolor" | "24bit")
                || term.contains("direct"));
        Self {
            colors: if rgb { Colors::Rgb } else { Colors::Indexed },
            images,
            direct_images: program == "WarpTerminal",
            cell_avatars: program == "Apple_Terminal",
        }
    }
}

impl Colors {
    pub fn color(self, color: Color) -> Color {
        match (self, color) {
            (Self::Indexed, Color::Rgb(r, g, b)) => Color::Indexed(indexed(r, g, b)),
            _ => color,
        }
    }
    pub fn apply(self, buffer: &mut Buffer, ascii: bool) {
        for cell in &mut buffer.content {
            if ascii {
                continue;
            }
            // Keep the dark UI readable even when the shell uses a light theme.
            cell.fg = self.color(if cell.fg == Color::Reset {
                Color::Rgb(220, 226, 221)
            } else {
                cell.fg
            });
            cell.bg = self.color(if cell.bg == Color::Reset {
                Color::Rgb(10, 13, 11)
            } else {
                cell.bg
            });
        }
    }
    pub(crate) fn sgr(self, pixel: [u8; 4], background: bool) -> String {
        let channel = if background { 48 } else { 38 };
        match self.color(Color::Rgb(pixel[0], pixel[1], pixel[2])) {
            Color::Indexed(index) => format!("\x1b[{channel};5;{index}m"),
            Color::Rgb(r, g, b) => format!("\x1b[{channel};2;{r};{g};{b}m"),
            _ => unreachable!(),
        }
    }
}

fn indexed(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let component = |v: u8| {
        (0..6)
            .min_by_key(|&i| (i32::from(v) - LEVELS[i]).pow(2))
            .unwrap()
    };
    let (ri, gi, bi) = (component(r), component(g), component(b));
    let distance = |a: i32, c: i32, d: i32| {
        (i32::from(r) - a).pow(2) + (i32::from(g) - c).pow(2) + (i32::from(b) - d).pow(2)
    };
    let gray = ((i32::from(r) + i32::from(g) + i32::from(b)) / 3 - 8 + 5) / 10;
    let gray = gray.clamp(0, 23);
    let level = 8 + gray * 10;
    if distance(level, level, level) < distance(LEVELS[ri], LEVELS[gi], LEVELS[bi]) {
        (232 + gray) as u8
    } else {
        (16 + 36 * ri + 6 * gi + bi) as u8
    }
}
