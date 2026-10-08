use serde_json::Value;
use shum_cli::avatar;
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
