//! The reactions: the stickers of every set that is a reaction too, in
//! the sets' order, and their pictures for clients.
use crate::{
    packet::ReactionKind,
    stickers::{Art, Set, Sticker, SETS},
};

/// The sets whose stickers are reactions, in order.
pub fn sections() -> impl Iterator<Item = &'static Set> {
    SETS.iter().filter(|set| set.reactions)
}

/// Every reaction in the order clients offer them.
pub fn order() -> impl Iterator<Item = ReactionKind> {
    sections()
        .flat_map(|set| set.stickers)
        .filter_map(|sticker| ReactionKind::from_name(sticker.id))
}

/// Any sticker by its name, reactions and phrases alike.
pub fn sticker(id: &str) -> Option<&'static Sticker> {
    SETS.iter()
        .flat_map(|set| set.stickers)
        .find(|s| s.id == id)
}

/// A picture as RGBA bytes, row by row.
pub fn rgba(art: &Art) -> Vec<u8> {
    let symbols =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-/:;<=>?@[]^_{|}~";
    art.cells
        .chars()
        .flat_map(|cell| {
            symbols
                .find(cell)
                .and_then(|index| art.colors.get(index))
                .map(|rgb| [(rgb >> 16) as u8, (rgb >> 8) as u8, *rgb as u8, 255])
                .unwrap_or([0; 4])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_picture_is_square_and_drawn() {
        for set in SETS {
            for art in std::iter::once(&set.icon).chain(set.stickers.iter().map(|s| &s.art)) {
                assert!(art.size == 16 || art.size == 32, "{}", set.id);
                assert_eq!(art.cells.chars().count(), art.size * art.size, "{}", set.id);
                let pixels = rgba(art);
                assert_eq!(pixels.len(), art.size * art.size * 4);
                assert!(
                    pixels.chunks(4).any(|p| p[3] == 255),
                    "{} has an empty picture",
                    set.id
                );
                assert!(art.cells.chars().filter(|c| *c != '.').all(|c| {
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-/:;<=>?@[]^_{|}~"
                        .find(c)
                        .is_some_and(|i| i < art.colors.len())
                }), "{}", set.id);
            }
        }
    }

    #[test]
    fn names_are_unique_and_v1_reactions_stay() {
        let mut seen = std::collections::HashSet::new();
        assert!(SETS
            .iter()
            .flat_map(|s| s.stickers)
            .all(|s| seen.insert(s.id)));
        for name in [
            "heart", "like", "dislike", "laugh", "fire", "coffin", "hundred", "horror",
        ] {
            assert!(ReactionKind::from_name(name).is_some(), "{name}");
        }
        assert_eq!(order().count(), 180);
        assert!(
            ReactionKind::from_name("quickShchas").is_none(),
            "phrases are not reactions"
        );
        assert!(sticker("quickShchas").is_some());
    }
}
