//! Pixel avatar v1, ported from ShumPixelAvatarGenerator.swift. Coordinates are 36x36.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Person,
    Animal,
    Alien,
    Robot,
}
#[derive(Clone, Copy)]
struct Color {
    rgb: [u8; 3],
    alpha: f64,
}
fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color {
        rgb: [r, g, b],
        alpha: 1.0,
    }
}
impl Color {
    fn alpha(self, alpha: f64) -> Self {
        Self { alpha, ..self }
    }
}
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut v = self.0;
        v = (v ^ (v >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        v = (v ^ (v >> 27)).wrapping_mul(0x94D049BB133111EB);
        v ^ (v >> 31)
    }
    fn pick(&mut self, count: usize) -> usize {
        (self.next() % count as u64) as usize
    }
}
pub fn kind(seed: u64) -> Kind {
    match Random(seed ^ 0xA6C8C7D1E3F09245).pick(10) {
        0..=3 => Kind::Person,
        4..=6 => Kind::Animal,
        7..=8 => Kind::Alien,
        _ => Kind::Robot,
    }
}
#[derive(Clone, Debug)]
pub struct Avatar {
    pub pixels: Vec<[u8; 4]>,
}
impl Avatar {
    /// The entire v1 portrait on a 9×9 grid for background-coloured cells.
    /// Keep the source palette instead of blurring neighbouring colours.
    pub fn compact_cells(&self, kind: Kind) -> Vec<[u8; 4]> {
        let mut result = vec![[0; 4]; 9 * 9];
        for y in 0..9 {
            for x in 0..9 {
                let mut colors = std::collections::BTreeMap::new();
                let mut coverage = 0;
                for sy in y * 4..y * 4 + 4 {
                    for sx in x * 4..x * 4 + 4 {
                        let pixel = self.pixels[sy * 36 + sx];
                        if pixel[3] > 0 {
                            *colors.entry(pixel).or_insert(0) += 1;
                            coverage += 1;
                        }
                    }
                }
                if coverage >= 8 {
                    // Colour breaks ties consistently on both sides of a face.
                    result[y * 9 + x] = colors
                        .into_iter()
                        .max_by_key(|&(color, count)| (count, color))
                        .unwrap()
                        .0;
                }
            }
        }
        // Sample the v1 eyes and mouth from their original 2×2 regions so
        // small facial details remain visible. Robots have a higher mouth.
        let mouth_y = if kind == Kind::Robot { 20 } else { 22 };
        for (x, y, sx, sy) in [(3, 4, 14, 16), (5, 4, 20, 16), (4, 5, 17, mouth_y)] {
            let mut sum = [0_u32; 4];
            for dy in 0..2 {
                for dx in 0..2 {
                    let pixel = self.pixels[(sy + dy) * 36 + sx + dx];
                    let alpha = u32::from(pixel[3]);
                    for i in 0..3 {
                        sum[i] += u32::from(pixel[i]) * alpha;
                    }
                    sum[3] += alpha;
                }
            }
            result[y * 9 + x] = std::array::from_fn(|i| {
                if i == 3 {
                    ((sum[3] + 2) / 4) as u8
                } else {
                    (sum[i] + sum[3] / 2).checked_div(sum[3]).unwrap_or(0) as u8
                }
            });
        }
        result
    }

    fn rect(&mut self, x: usize, y: usize, w: usize, h: usize, c: Color) {
        for row in y..(y + h).min(36) {
            for col in x..(x + w).min(36) {
                let p = &mut self.pixels[row * 36 + col];
                for (dst, src) in p[..3].iter_mut().zip(c.rgb) {
                    // Quartz premultiplies the color before quantizing alpha.
                    let source = (f64::from(src) * c.alpha).round() as u16;
                    let alpha = (c.alpha * 255.0).round();
                    let target = (f64::from(*dst) * (255.0 - alpha) / 255.0).round() as u16;
                    *dst = (source + target).min(255) as u8;
                }
                p[3] = 255;
            }
        }
    }
    pub fn coarse18(&self) -> Vec<[u8; 4]> {
        (0..18)
            .flat_map(|y| (0..18).map(move |x| self.pixels[(y * 2 + 1) * 36 + x * 2 + 1]))
            .collect()
    }
    /// Area samples for terminal presentation. A point sample can turn a
    /// centered one-pixel detail into an asymmetric feature or erase it.
    pub fn sampled(&self, side: usize) -> Vec<[u8; 4]> {
        assert!((1..=36).contains(&side));
        let mut result = Vec::with_capacity(side * side);
        for y in 0..side {
            for x in 0..side {
                let (left, top, right, bottom) = (x * 36, y * 36, (x + 1) * 36, (y + 1) * 36);
                let mut alpha = 0_u64;
                let mut rgb = [0_u64; 3];
                for sy in top / side..bottom.div_ceil(side) {
                    for sx in left / side..right.div_ceil(side) {
                        let weight = ((right.min((sx + 1) * side) - left.max(sx * side))
                            * (bottom.min((sy + 1) * side) - top.max(sy * side)))
                            as u64;
                        let p = self.pixels[sy * 36 + sx];
                        let a = u64::from(p[3]) * weight;
                        alpha += a;
                        for i in 0..3 {
                            rgb[i] += u64::from(p[i]) * a;
                        }
                    }
                }
                let mut p = [0; 4];
                for i in 0..3 {
                    p[i] = (rgb[i] + alpha / 2).checked_div(alpha).unwrap_or(0) as u8;
                }
                p[3] = ((alpha + 648) / 1296) as u8;
                result.push(p);
            }
        }
        result
    }
}
pub fn render(seed: u64) -> Avatar {
    render_impl(seed, true)
}
/// Client presentation: the v1 subject without its decorative square.
/// `render` remains the exact, opaque Swift vector renderer.
pub fn render_subject(seed: u64) -> Avatar {
    render_impl(seed, false)
}
fn render_impl(seed: u64, backdrop: bool) -> Avatar {
    let mut random = Random(seed);
    let kind = kind(seed);
    let mut canvas = Avatar {
        pixels: vec![[0; 4]; 36 * 36],
    };
    macro_rules! block {
        ($x:expr,$y:expr,$w:expr,$h:expr,$c:expr) => {
            canvas.rect($x * 2, $y * 2, $w * 2, $h * 2, $c)
        };
    }
    macro_rules! detail {
        ($x:expr,$y:expr,$w:expr,$h:expr,$c:expr) => {
            canvas.rect($x, $y, $w, $h, $c)
        };
    }
    let backgrounds = [
        rgb(84, 111, 94),
        rgb(91, 91, 124),
        rgb(125, 87, 101),
        rgb(92, 103, 122),
        rgb(117, 102, 85),
        rgb(78, 112, 116),
        rgb(124, 96, 122),
        rgb(79, 106, 132),
        rgb(130, 100, 79),
        rgb(87, 116, 105),
        rgb(104, 93, 119),
        rgb(119, 110, 89),
    ];
    let skins = [
        rgb(245, 198, 156),
        rgb(229, 168, 117),
        rgb(199, 132, 86),
        rgb(157, 96, 62),
        rgb(111, 68, 46),
        rgb(239, 184, 150),
        rgb(212, 148, 102),
        rgb(178, 110, 73),
    ];
    let hairs = [
        rgb(34, 30, 32),
        rgb(80, 48, 34),
        rgb(178, 121, 63),
        rgb(218, 174, 95),
        rgb(121, 61, 43),
        rgb(59, 58, 63),
        rgb(53, 42, 54),
        rgb(101, 67, 52),
        rgb(191, 153, 107),
        rgb(42, 52, 59),
    ];
    let shirts = [
        rgb(61, 87, 89),
        rgb(142, 75, 81),
        rgb(80, 89, 134),
        rgb(101, 76, 109),
        rgb(179, 117, 83),
        rgb(68, 100, 75),
        rgb(187, 150, 92),
        rgb(74, 110, 125),
        rgb(156, 88, 118),
        rgb(71, 86, 121),
        rgb(118, 115, 83),
        rgb(150, 103, 81),
    ];
    let background = backgrounds[random.pick(backgrounds.len())];
    let backdrop_detail = backgrounds[random.pick(backgrounds.len())];
    let skin = skins[random.pick(skins.len())];
    let hair = hairs[random.pick(hairs.len())];
    let shirt = shirts[random.pick(shirts.len())];
    let headwear_color = shirts[random.pick(shirts.len())];
    let hairstyle = random.pick(8);
    let fringe = random.pick(4);
    let face_shape = random.pick(3);
    let brow_style = random.pick(3);
    let eye_style = random.pick(3);
    let mouth_style = random.pick(4);
    let eyewear = random.pick(5);
    let facial_hair = random.pick(8);
    let freckles = random.pick(6);
    let neckline = random.pick(4);
    let backdrop_pattern = random.pick(16);
    let headwear = random.pick(10);
    let accessory = random.pick(8);
    let character_variant = random.pick(5);
    let expression = random.pick(4);
    let detail_variant = random.pick(6);
    let fur_colors = [
        rgb(193, 127, 65),
        rgb(128, 101, 82),
        rgb(198, 182, 153),
        rgb(86, 91, 101),
        rgb(222, 153, 83),
        rgb(72, 65, 68),
        rgb(176, 119, 100),
        rgb(233, 205, 163),
    ];
    let alien_colors = [
        rgb(118, 194, 129),
        rgb(139, 159, 217),
        rgb(179, 129, 207),
        rgb(87, 178, 167),
        rgb(214, 150, 178),
        rgb(188, 202, 118),
    ];
    let metal_colors = [
        rgb(137, 164, 173),
        rgb(150, 142, 169),
        rgb(179, 151, 119),
        rgb(119, 155, 151),
        rgb(158, 166, 134),
    ];
    let fur = fur_colors[random.pick(fur_colors.len())];
    let creature = alien_colors[random.pick(alien_colors.len())];
    let metal = metal_colors[random.pick(metal_colors.len())];

    if backdrop {
        block!(0, 0, 18, 18, background);
    }
    let decor = backdrop_detail.alpha(0.38);
    if backdrop && backdrop_pattern & 1 != 0 {
        block!(2, 3, 2, 2, decor);
        block!(14, 12, 2, 2, decor);
    }
    if backdrop && backdrop_pattern & 2 != 0 {
        block!(14, 3, 2, 2, decor);
        block!(2, 12, 2, 2, decor);
    }
    if backdrop && backdrop_pattern & 4 != 0 {
        block!(1, 8, 2, 2, decor);
        block!(15, 8, 2, 2, decor);
    }
    if backdrop && backdrop_pattern & 8 != 0 {
        block!(4, 1, 2, 1, decor);
        block!(12, 1, 2, 1, decor);
    }
    let dark = rgb(40, 37, 41);
    match kind {
        Kind::Animal => {
            let muzzle = rgb(235, 212, 184);
            let inner_ear = rgb(191, 124, 126);
            block!(4, 15, 10, 3, shirt);
            block!(3, 16, 12, 2, shirt);
            block!(7, 12, 4, 4, fur);
            match character_variant {
                0 => {
                    // Cat
                    block!(4, 2, 3, 5, fur);
                    block!(11, 2, 3, 5, fur);
                    block!(5, 3, 1, 2, inner_ear);
                    block!(12, 3, 1, 2, inner_ear);
                }
                1 => {
                    // Dog
                    block!(3, 5, 3, 8, fur);
                    block!(12, 5, 3, 8, fur);
                }
                2 => {
                    // Fox
                    block!(4, 2, 3, 5, fur);
                    block!(11, 2, 3, 5, fur);
                    block!(5, 3, 1, 2, inner_ear);
                    block!(12, 3, 1, 2, inner_ear);
                }
                3 => {
                    // Rabbit
                    block!(5, 1, 2, 7, fur);
                    block!(11, 1, 2, 7, fur);
                    block!(5, 2, 1, 4, inner_ear);
                    block!(12, 2, 1, 4, inner_ear);
                }
                _ => {
                    // Bear
                    block!(4, 3, 3, 4, fur);
                    block!(11, 3, 3, 4, fur);
                    block!(5, 4, 1, 2, inner_ear);
                    block!(12, 4, 1, 2, inner_ear);
                }
            }
            block!(5, 5, 8, 8, fur);
            block!(4, 7, 10, 5, fur);
            if character_variant == 2 {
                block!(5, 10, 3, 2, muzzle);
                block!(10, 10, 3, 2, muzzle);
            }
            block!(7, 8, 1, if expression == 1 { 2 } else { 1 }, dark);
            block!(10, 8, 1, if expression == 1 { 2 } else { 1 }, dark);
            block!(7, 10, 4, 2, muzzle);
            block!(8, 10, 2, 1, dark);
            if expression == 2 {
                block!(8, 12, 2, 1, rgb(153, 78, 88));
            } else {
                detail!(17, 23, 2, 1, dark);
            }
            if character_variant == 0 || character_variant == 2 {
                detail!(8, 20, 5, 1, muzzle);
                detail!(23, 20, 5, 1, muzzle);
            }
            if detail_variant < 3 {
                block!(6, 14, 6, 1, headwear_color);
                block!(8, 15, 2, 1, rgb(222, 197, 113));
            }
            if accessory == 1 {
                block!(8, 13, 2, 1, inner_ear);
            }
            return canvas;
        }
        Kind::Alien => {
            block!(4, 15, 10, 3, shirt);
            block!(3, 16, 12, 2, shirt);
            block!(7, 12, 4, 4, creature);
            match character_variant {
                0 | 1 => {
                    block!(6, 2, 1, 4, creature);
                    block!(11, 2, 1, 4, creature);
                    block!(5, 1, 3, 2, creature);
                    block!(10, 1, 3, 2, creature);
                }
                2 => {
                    block!(4, 2, 2, 5, creature);
                    block!(12, 2, 2, 5, creature);
                }
                3 => {
                    block!(7, 1, 1, 5, creature);
                    block!(10, 1, 1, 5, creature);
                    block!(6, 1, 3, 2, headwear_color);
                    block!(9, 1, 3, 2, headwear_color);
                }
                _ => {
                    block!(4, 4, 2, 4, creature);
                    block!(12, 4, 2, 4, creature);
                }
            }
            block!(5, 5, 8, 8, creature);
            block!(4, 7, 10, 4, creature);
            if character_variant == 4 {
                block!(8, 7, 2, 3, dark);
                detail!(17, 15, 2, 2, rgb(221, 238, 224));
            } else {
                block!(6, 8, 2, 2, dark);
                block!(10, 8, 2, 2, dark);
                detail!(13, 16, 2, 1, rgb(221, 238, 224));
                detail!(21, 16, 2, 1, rgb(221, 238, 224));
                if character_variant == 1 {
                    block!(8, 6, 2, 1, dark);
                }
            }
            match expression {
                0 => {
                    block!(8, 11, 2, 1, dark);
                }
                1 => {
                    block!(7, 11, 4, 1, dark);
                }
                2 => {
                    block!(8, 11, 2, 2, dark);
                    detail!(17, 23, 2, 1, rgb(222, 222, 211));
                }
                _ => {
                    block!(8, 12, 2, 1, rgb(161, 69, 116));
                }
            }
            if detail_variant < 3 {
                block!(5, 7, 1, 1, headwear_color);
                block!(12, 7, 1, 1, headwear_color);
            }
            block!(6, 14, 6, 1, rgb(218, 220, 204));
            return canvas;
        }
        Kind::Robot => {
            let display = rgb(52, 67, 73);
            let lights = [
                rgb(99, 232, 177),
                rgb(251, 201, 101),
                rgb(134, 206, 242),
                rgb(242, 137, 164),
            ];
            let light = lights[detail_variant % lights.len()];
            block!(4, 14, 10, 4, shirt);
            block!(3, 16, 12, 2, shirt);
            block!(8, 2, 2, 3, metal);
            block!(8, 1, 2, 1, light);
            if character_variant > 1 {
                block!(3, 5, 2, 7, metal);
                block!(13, 5, 2, 7, metal);
            }
            block!(5, 4, 8, 9, metal);
            block!(6, 6, 6, 5, display);
            match character_variant {
                0 => {
                    block!(7, 8, 1, 1, light);
                    block!(10, 8, 1, 1, light);
                }
                1 => {
                    block!(6, 8, 2, 1, light);
                    block!(10, 8, 2, 1, light);
                }
                2 => {
                    block!(8, 7, 2, 2, light);
                }
                _ => {
                    block!(7, 8, 4, 1, light);
                }
            }
            block!(
                8,
                10,
                2,
                1,
                if expression == 0 {
                    light
                } else {
                    rgb(216, 224, 219)
                }
            );
            if detail_variant < 3 {
                block!(5, 12, 8, 1, rgb(83, 100, 107));
            }
            block!(7, 15, 4, 1, light);
            return canvas;
        }
        Kind::Person => {}
    }
    block!(4, 15, 10, 3, shirt);
    block!(3, 16, 12, 2, shirt);
    block!(7, 13, 4, 3, skin);

    match hairstyle {
        0 => {
            block!(5, 3, 8, 9, hair);
        }
        1 => {
            block!(4, 3, 10, 11, hair);
            block!(3, 6, 2, 8, hair);
            block!(13, 6, 2, 8, hair);
        }
        2 => {
            block!(4, 4, 10, 8, hair);
            block!(5, 2, 3, 3, hair);
            block!(9, 2, 4, 3, hair);
            block!(3, 5, 2, 4, hair);
            block!(13, 5, 2, 4, hair);
        }
        3 => {
            block!(5, 3, 8, 9, hair);
            block!(4, 5, 2, 6, hair);
            block!(12, 5, 2, 6, hair);
        }
        4 => {
            block!(5, 4, 8, 7, hair);
            block!(4, 5, 2, 5, hair);
        }
        5 => {
            block!(4, 2, 10, 10, hair);
            block!(3, 4, 2, 6, hair);
            block!(13, 4, 2, 6, hair);
        }
        6 => {
            block!(5, 3, 8, 10, hair);
            block!(4, 7, 2, 6, hair);
            block!(12, 7, 2, 6, hair);
        }
        _ => {
            block!(5, 4, 8, 7, hair);
            block!(6, 2, 6, 3, hair);
        }
    }

    block!(6, 5, 6, 7, skin);
    block!(5, 7, 1, 3, skin);
    block!(12, 7, 1, 3, skin);
    match face_shape {
        0 => {
            block!(7, 12, 4, 1, skin);
        }
        1 => {
            block!(6, 12, 6, 1, skin);
        }
        _ => {
            block!(8, 12, 2, 1, skin);
        }
    }
    match fringe {
        0 => {
            block!(5, 4, 8, 1, hair);
        }
        1 => {
            block!(5, 4, 7, 2, hair);
        }
        2 => {
            block!(5, 4, 4, 2, hair);
            block!(10, 4, 3, 1, hair);
        }
        _ => {
            block!(5, 4, 8, 1, hair);
            block!(10, 5, 3, 2, hair);
        }
    }

    match headwear {
        6 => {
            // Beanie
            block!(5, 2, 8, 3, headwear_color);
            block!(4, 4, 10, 2, headwear_color);
            block!(7, 1, 4, 1, headwear_color);
        }
        7 => {
            // Cap
            block!(5, 2, 8, 3, headwear_color);
            block!(4, 5, 10, 1, headwear_color);
            block!(10, 6, 5, 1, headwear_color);
        }
        8 => {
            // Bucket hat
            block!(5, 2, 8, 3, headwear_color);
            block!(3, 5, 12, 1, headwear_color);
            block!(4, 4, 10, 1, headwear_color);
        }
        9 => {
            // Headband
            block!(5, 4, 8, 1, headwear_color);
            block!(4, 5, 2, 1, headwear_color);
        }
        _ => (),
    }

    let eye = rgb(39, 35, 37);
    if brow_style > 0 {
        block!(7, 7, 1, 1, hair);
        block!(10, 7, 1, 1, hair);
        if brow_style == 2 {
            block!(8, 7, 1, 1, hair);
        }
    }
    block!(7, 8, 1, 1, eye);
    block!(10, 8, 1, 1, eye);
    if eye_style == 1 {
        block!(6, 8, 1, 1, eye);
        block!(11, 8, 1, 1, eye);
    } else if eye_style == 2 {
        block!(7, 9, 1, 1, skin);
        block!(10, 9, 1, 1, skin);
    }
    if eyewear == 1 || eyewear == 2 {
        let frame = rgb(67, 54, 51);
        if eyewear == 2 {
            let lens = rgb(70, 95, 105).alpha(0.85);
            detail!(14, 16, 2, 3, lens);
            detail!(20, 16, 2, 3, lens);
        }
        for x in [13, 19] {
            detail!(x, 15, 4, 1, frame);
            detail!(x, 19, 4, 1, frame);
            detail!(x, 16, 1, 3, frame);
            detail!(x + 3, 16, 1, 3, frame);
        }
        detail!(17, 16, 2, 1, frame);
    } else if eyewear == 3 {
        block!(5, 10, 1, 1, rgb(220, 193, 112));
        block!(12, 10, 1, 1, rgb(220, 193, 112));
    } else if eyewear == 4 {
        block!(6, 7, 2, 1, rgb(171, 115, 92));
        block!(10, 7, 2, 1, rgb(171, 115, 92));
    }
    let accessory_color = rgb(226, 193, 111);
    match accessory {
        1 => {
            block!(5, 10, 1, 1, accessory_color);
            block!(12, 10, 1, 1, accessory_color);
        }
        2 => {
            block!(4, 10, 1, 2, accessory_color);
            block!(13, 10, 1, 2, accessory_color);
        }
        3 => {
            block!(4, 5, 2, 1, accessory_color);
        }
        4 => {
            block!(12, 5, 2, 1, accessory_color);
        }
        5 => {
            block!(11, 10, 1, 1, accessory_color);
        }
        6 => {
            block!(4, 8, 1, 3, rgb(208, 210, 204));
            block!(13, 8, 1, 3, rgb(208, 210, 204));
        }
        7 => {
            block!(6, 13, 6, 1, accessory_color);
        }
        _ => (),
    }
    if freckles == 1 || freckles == 2 {
        let freckle = rgb(153, 87, 68);
        block!(6, 10, 1, 1, freckle);
        block!(11, 10, 1, 1, freckle);
        if freckles == 2 {
            block!(7, 10, 1, 1, freckle);
        }
    }
    if facial_hair == 5 || facial_hair == 7 {
        block!(6, 11, 6, 2, hair);
        block!(7, 11, 4, 1, skin);
    }
    if facial_hair == 6 || facial_hair == 7 {
        block!(7, 10, 4, 1, hair);
        block!(8, 10, 2, 1, skin);
    }
    let lip = rgb(151, 75, 74);
    match mouth_style {
        0 => {
            block!(8, 11, 2, 1, lip);
        }
        1 => {
            block!(7, 11, 4, 1, lip);
        }
        2 => {
            block!(8, 11, 2, 1, lip);
            block!(7, 10, 1, 1, lip);
            block!(10, 10, 1, 1, lip);
        }
        _ => {
            block!(8, 11, 2, 1, eye);
        }
    }
    let collar = rgb(226, 226, 217);
    match neckline {
        0 => {
            block!(6, 14, 2, 1, collar);
            block!(10, 14, 2, 1, collar);
        }
        1 => {
            block!(7, 15, 4, 1, collar);
        }
        2 => {
            block!(6, 15, 2, 1, collar);
            block!(10, 15, 2, 1, collar);
        }
        _ => {
            block!(5, 16, 8, 1, collar.alpha(0.35));
        }
    }
    canvas
}
