//! Pixel artwork of the eight reactions, matching ShumReactionArt.swift
//! (12 x 12). Clients choose the size; names are the client's words.
use crate::packet::ReactionKind;

/// Reactions in picker order.
pub const KINDS: [ReactionKind; 8] = [
    ReactionKind::Heart,
    ReactionKind::Like,
    ReactionKind::Dislike,
    ReactionKind::Laugh,
    ReactionKind::Fire,
    ReactionKind::Coffin,
    ReactionKind::Hundred,
    ReactionKind::Horror,
];
/// Rows of symbols and the color of each symbol; `.` is transparent.
pub fn art(kind: ReactionKind) -> ([&'static str; 12], &'static [(u8, u32)]) {
    match kind {
        ReactionKind::Heart => (
            [
                "............",
                "..RR....RR..",
                ".RPRR..RRRR.",
                "RPRRRRRRRRRR",
                "RRRRRRRRRRRR",
                "RRRRRRRRRRRR",
                ".RRRRRRRRRR.",
                "..RRRRRRRR..",
                "...RRRRRR...",
                "....RRRR....",
                ".....RR.....",
                "............",
            ],
            &[(b'R', 0xFF4245), (b'P', 0xFF9A9C)],
        ),
        ReactionKind::Like => (
            [
                "............",
                "......YY....",
                ".....YYY....",
                ".....YYY....",
                "....YYY.....",
                "GG.YYYYYYYY.",
                "GG.YYYYYYYYY",
                "GG.YYYYYYYO.",
                "GG.YYYYYYYYY",
                "GG.YYYYYYYO.",
                "GG.YYYYYYY..",
                "............",
            ],
            &[(b'G', 0x30D158), (b'Y', 0xFFC93C), (b'O', 0xE59A1C)],
        ),
        ReactionKind::Dislike => (
            [
                "............",
                "GG.YYYYYYY..",
                "GG.YYYYYYYO.",
                "GG.YYYYYYYYY",
                "GG.YYYYYYYO.",
                "GG.YYYYYYYYY",
                "GG.YYYYYYYY.",
                "....YYY.....",
                ".....YYY....",
                ".....YYY....",
                "......YY....",
                "............",
            ],
            &[(b'G', 0x30D158), (b'Y', 0xFFC93C), (b'O', 0xE59A1C)],
        ),
        ReactionKind::Laugh => (
            [
                "....YYYY....",
                "..YYYYYYYY..",
                ".YYYYYYYYYY.",
                ".YDDYYYYDDY.",
                "BYYYYYYYYYYB",
                "BYYYYYYYYYYB",
                "YYDDDDDDDDYY",
                "YYDWWWWWWDYY",
                ".YDMMMMMMDY.",
                ".YYDDDDDDYY.",
                "..YYYYYYYY..",
                "....YYYY....",
            ],
            &[
                (b'Y', 0xFFC93C),
                (b'D', 0x3B2A12),
                (b'W', 0xFFFFFF),
                (b'M', 0x8C2A1E),
                (b'B', 0x5AC8FA),
            ],
        ),
        ReactionKind::Fire => (
            [
                ".....R......",
                ".....RR.....",
                "....RRR.....",
                "...RRRR..R..",
                "..RRROR.RR..",
                "..RROORRRR..",
                ".RROOOORRRR.",
                ".RROOYOOORR.",
                ".RROYYYOORR.",
                ".RROYYYYORR.",
                "..RROYYORR..",
                "...RRRRRR...",
            ],
            &[(b'R', 0xFF4245), (b'O', 0xFF8A1F), (b'Y', 0xFFD23F)],
        ),
        ReactionKind::Coffin => (
            [
                "....DDDD....",
                "...DWWWWD...",
                "..DWWCCWWD..",
                ".DWWWCCWWWD.",
                ".DWCCCCCCWD.",
                ".DWWWCCWWWD.",
                "..DWWCCWWD..",
                "..DWWCCWWD..",
                "..DWWWWWWD..",
                "...DWWWWD...",
                "...DWWWWD...",
                "....DDDD....",
            ],
            &[(b'D', 0x4A2E14), (b'W', 0x8B5A2B), (b'C', 0xE8C9A0)],
        ),
        ReactionKind::Hundred => (
            [
                "............",
                "..R.RRR.RRR.",
                ".RR.R.R.R.R.",
                "..R.R.R.R.R.",
                "..R.R.R.R.R.",
                "..R.R.R.R.R.",
                "..R.RRR.RRR.",
                "............",
                ".RRRRRRRRRR.",
                "............",
                "..RRRRRRRR..",
                "............",
            ],
            &[(b'R', 0xFF4245)],
        ),
        ReactionKind::Horror => (
            [
                "....LLLL....",
                "..LLLLLLLL..",
                ".LLLLLLLLLL.",
                ".YWKYYYYKWY.",
                "YYWWYYYYWWYY",
                "YYYYYYYYYYYY",
                "YYYYYMMYYYYY",
                "YHYYMMMMYYHY",
                "HHYYMMMMYYHH",
                "HH.YYMMYY.HH",
                "....YYYY....",
                "............",
            ],
            &[
                (b'L', 0x7FB2FF),
                (b'Y', 0xFFC93C),
                (b'W', 0xFFFFFF),
                (b'K', 0x2A1A0A),
                (b'M', 0x3B1010),
                (b'H', 0xE59A1C),
            ],
        ),
    }
}

/// 12 x 12 RGBA pixels, row by row.
pub fn pixels(kind: ReactionKind) -> Vec<[u8; 4]> {
    let (rows, colors) = art(kind);
    rows.iter()
        .flat_map(|row| row.bytes())
        .map(|symbol| {
            colors
                .iter()
                .find(|(s, _)| *s == symbol)
                .map(|(_, rgb)| [(rgb >> 16) as u8, (rgb >> 8) as u8, *rgb as u8, 255])
                .unwrap_or([0; 4])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reaction_is_a_full_12x12_picture() {
        for kind in KINDS {
            let (rows, colors) = art(kind);
            for row in rows {
                assert_eq!(row.len(), 12, "{kind:?}");
                for symbol in row.bytes().filter(|s| *s != b'.') {
                    assert!(colors.iter().any(|(s, _)| *s == symbol), "{kind:?}");
                }
            }
            let pixels = pixels(kind);
            assert_eq!(pixels.len(), 144);
            assert!(pixels.iter().any(|p| p[3] == 255), "{kind:?} is empty");
        }
        assert_eq!(pixels(ReactionKind::Heart)[0], [0; 4], "transparent corner");
    }
}
