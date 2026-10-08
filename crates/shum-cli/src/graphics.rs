//! Direct Kitty placements for Warp, which does not support Unicode placeholders.
use base64::{engine::general_purpose::STANDARD, Engine};
use ratatui::{
    backend::Backend,
    buffer::{Cell, CellDiffOption},
    layout::Rect,
    Frame, Terminal,
};
use std::{collections::HashMap, io::Cursor, num::NonZeroU16};

#[derive(Default)]
pub(crate) struct DirectImages {
    ids: HashMap<(u16, u16), u32>,
    pngs: HashMap<u64, String>,
}

impl DirectImages {
    pub fn draw(&mut self, frame: &mut Frame<'_>, seed: u64, area: Rect) {
        let id = *self
            .ids
            .entry((area.x, area.y))
            .or_insert_with(|| getrandom::u32().expect("OS random image identifier").max(1));
        if self.pngs.len() > 256 {
            self.pngs.clear();
        }
        let png = self.pngs.entry(seed).or_insert_with(|| {
            let pixels = crate::avatar::render_subject(seed)
                .pixels
                .into_iter()
                .flatten()
                .collect();
            let image = image::RgbaImage::from_raw(36, 36, pixels).expect("36x36 avatar");
            let mut png = Cursor::new(Vec::new());
            image
                .write_to(&mut png, image::ImageFormat::Png)
                .expect("PNG in memory");
            STANDARD.encode(png.into_inner())
        });
        // Explicitly delete this slot before replacing it. Text erase sequences
        // do not delete graphic placements. q=2 suppresses terminal replies.
        let mut sequence = delete(id);
        // PNGs are small, but respect the protocol's 4096-byte chunk limit.
        let chunks = png.as_bytes().chunks(4096);
        let count = chunks.len();
        for (index, chunk) in chunks.enumerate() {
            let more = u8::from(index + 1 < count);
            if index == 0 {
                sequence.push_str(&format!(
                    "\x1b_Ga=T,f=100,t=d,i={id},p=1,c={},r={},C=1,q=2,m={more};",
                    area.width, area.height
                ));
            } else {
                sequence.push_str(&format!("\x1b_Gm={more};"));
            }
            sequence.push_str(std::str::from_utf8(chunk).expect("base64"));
            sequence.push_str("\x1b\\");
        }
        // Let Ratatui paint every cell's background before placing the PNG.
        // Skipping those cells exposes the shell theme through transparent
        // pixels, producing a rectangle that does not match the panel.
        // The last cell carries the placement so all backgrounds precede it.
        // Paint that cell too, then save/restore the cursor around the image.
        let sequence = format!(" \x1b7\x1b[{};{}H{sequence}\x1b8", area.y + 1, area.x + 1);
        frame.buffer_mut()[(area.right() - 1, area.bottom() - 1)]
            .set_symbol(&sequence)
            .set_diff_option(CellDiffOption::ForcedWidth(NonZeroU16::new(1).unwrap()));
    }

    pub fn clear<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), B::Error> {
        if self.ids.is_empty() {
            return Ok(());
        }
        let sequence = self.ids.values().map(|&id| delete(id)).collect::<String>();
        let mut cell = Cell::default();
        cell.set_symbol(&sequence);
        terminal
            .backend_mut()
            .draw(std::iter::once((0, 0, &cell)))?;
        self.ids.clear();
        Ok(())
    }
}

fn delete(id: u32) -> String {
    format!("\x1b_Ga=d,d=I,i={id},q=2;\x1b\\")
}
