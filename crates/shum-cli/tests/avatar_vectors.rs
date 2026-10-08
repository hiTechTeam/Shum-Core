use serde_json::Value;
use shum_cli::avatar;
#[test]
fn compact_portraits_keep_the_full_canvas_and_eye_colours() {
    let mut source = avatar::Avatar {
        pixels: vec![[0; 4]; 36 * 36],
    };
    source.pixels[..4 * 36].fill([0, 200, 0, 255]);
    source.pixels[32 * 36..].fill([0, 0, 200, 255]);
    let compact = source.compact_cells(avatar::Kind::Person);
    assert_eq!(compact.len(), 81);
    assert!(compact[..9].iter().all(|p| *p == [0, 200, 0, 255]));
    assert!(compact[8 * 9..].iter().all(|p| *p == [0, 0, 200, 255]));
    assert!(compact[9..8 * 9].iter().all(|p| *p == [0; 4]));

    let fixture: Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/01-avatar-pixels.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let seed = case["seed"].as_str().unwrap().parse().unwrap();
        let source = avatar::render_subject(seed);
        let compact = source.compact_cells(avatar::kind(seed));
        let detail = source.sampled(18);
        assert_eq!(compact[4 * 9 + 3], detail[8 * 18 + 7]);
        assert_eq!(compact[4 * 9 + 5], detail[8 * 18 + 10]);
        assert!(compact[8 * 9..].iter().any(|p| p[3] == 255));
    }
}
#[test]
fn terminal_downsampling_preserves_centered_details_and_transparent_colors() {
    let mut a = avatar::Avatar {
        pixels: vec![[255, 255, 255, 255]; 36 * 36],
    };
    for y in 22..24 {
        for x in 17..19 {
            a.pixels[y * 36 + x] = [0, 0, 0, 255];
        }
    }
    let pixels = a.sampled(18);
    assert_eq!(pixels[11 * 18 + 8], [128, 128, 128, 255]);
    assert_eq!(pixels[11 * 18 + 8], pixels[11 * 18 + 9]);
    for side in [6, 8, 12, 18, 36] {
        let pixels = a.sampled(side);
        for y in 0..side {
            for x in 0..side {
                assert_eq!(pixels[y * side + x], pixels[y * side + side - x - 1]);
            }
        }
    }
    let mut a = avatar::Avatar {
        pixels: vec![[0; 4]; 36 * 36],
    };
    a.pixels[0] = [200, 100, 50, 255];
    a.pixels[1] = [200, 100, 50, 255];
    assert_eq!(a.sampled(18)[0], [200, 100, 50, 128]);
}
#[test]
fn exact_swift_avatar_pixels() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/01-avatar-pixels.json"
    ))
    .unwrap();
    for c in fixture["cases"].as_array().unwrap() {
        let seed = c["seed"].as_str().unwrap().parse().unwrap();
        let avatar = avatar::render(seed);
        assert_eq!(
            format!("{:?}", avatar::kind(seed)).to_lowercase(),
            c["kind"].as_str().unwrap()
        );
        for (i, p) in avatar.pixels.iter().enumerate() {
            assert_eq!(
                hex::encode(p),
                c["rgba36"][i / 36][i % 36].as_str().unwrap(),
                "seed {seed}, x {}, y {}",
                i % 36,
                i / 36
            );
        }
        for (i, p) in avatar.coarse18().iter().enumerate() {
            assert_eq!(
                hex::encode(p),
                c["rgba18_center_sample"][i / 18][i % 18].as_str().unwrap(),
                "coarse seed {seed}"
            );
        }
    }
}
