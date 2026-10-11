//! The "in chat" mark: a 3x3 pixel grid with four lit cells, the same for a
//! contact on every client (ShumPresencePixels.pattern in the iOS app). The
//! seed is the contact's Shum ID. While the contact types, clients make the
//! grid pulse at random; that animation is their own presentation.

/// Which of the nine cells, row by row, are lit for `seed`.
pub fn pattern(seed: &str) -> [bool; 9] {
    // FNV-1a over the UTF-8 bytes, then a Fisher-Yates shuffle driven by a
    // 64-bit LCG; the first four shuffled cells are lit.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut cells: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    for index in (1..cells.len()).rev() {
        hash = hash
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        cells.swap(index, ((hash >> 33) % (index as u64 + 1)) as usize);
    }
    let mut lit = [false; 9];
    for cell in &cells[..4] {
        lit[*cell] = true;
    }
    lit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_ios_app() {
        // Produced by the Swift code of ShumPresencePixels.pattern(for:).
        let cases: [(&str, [usize; 4]); 6] = [
            ("", [1, 2, 6, 8]),
            ("a", [2, 3, 6, 8]),
            ("Shum", [4, 5, 7, 8]),
            (
                "2366269d48be0f217281ffeeef0bd5f93164a8f74b54ee74bce410eddcbdc00a",
                [0, 1, 2, 6],
            ),
            (
                "538e1b94a561ee0732b025fb168da7e3313aa73c9aca04d983139d4a30daa821",
                [1, 2, 3, 8],
            ),
            ("Руслан", [2, 5, 6, 8]),
        ];
        for (seed, expected) in cases {
            let lit: Vec<usize> = (0..9).filter(|&i| pattern(seed)[i]).collect();
            assert_eq!(lit, expected, "seed {seed:?}");
        }
    }
}
