//! What the page draws with Shum-Core, as native clients do: pixel avatars,
//! reactions and the "in chat" mark.
use crate::error;
use shum_core::packet::ReactionKind;
use wasm_bindgen::prelude::*;

/// The v1 pixel avatar as 36x36 RGBA bytes. Seeds are 64-bit, so they
/// travel as text.
#[wasm_bindgen(js_name = avatarPixels)]
pub fn avatar_pixels(seed: &str) -> Result<Vec<u8>, JsError> {
    let seed: u64 = seed.parse().map_err(error)?;
    Ok(shum_core::avatar::render(seed)
        .pixels
        .into_iter()
        .flatten()
        .collect())
}

/// The 12x12 RGBA picture of a reaction, by its protocol name.
#[wasm_bindgen(js_name = reactionPixels)]
pub fn reaction_pixels(kind: &str) -> Result<Vec<u8>, JsError> {
    let kind: ReactionKind = serde_json::from_value(kind.into())?;
    Ok(shum_core::reaction_art::pixels(kind)
        .into_iter()
        .flatten()
        .collect())
}

/// A sticker's or reaction's picture from Shum's sets as RGBA bytes; its
/// side is the square root of a quarter of the length. Empty for a name no
/// set has.
#[wasm_bindgen(js_name = stickerPixels)]
pub fn sticker_pixels(id: &str) -> Vec<u8> {
    shum_core::pool::sticker(id)
        .map(|sticker| shum_core::pool::rgba(&sticker.art))
        .unwrap_or_default()
}

/// A set's picture for a list of sets, as RGBA bytes.
#[wasm_bindgen(js_name = stickerSetPixels)]
pub fn sticker_set_pixels(set: &str) -> Vec<u8> {
    shum_core::stickers::SETS
        .iter()
        .find(|s| s.id == set)
        .map(|s| shum_core::pool::rgba(&s.icon))
        .unwrap_or_default()
}

/// Shum's sets as JSON, reactions first, as iOS gets them.
#[wasm_bindgen(js_name = stickerSets)]
pub fn sticker_sets() -> String {
    shum_core::pool::sets_json()
}

/// Which cells of the 3x3 "in chat" mark are lit for a contact: nine 0/1.
#[wasm_bindgen(js_name = presencePattern)]
pub fn presence_pattern(seed: &str) -> Vec<u8> {
    shum_core::presence::pattern(seed).map(u8::from).to_vec()
}

/// A new random avatar seed, as text.
#[wasm_bindgen(js_name = newAvatarSeed)]
pub fn new_avatar_seed() -> Result<String, JsError> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(error)?;
    Ok(u64::from_le_bytes(bytes).to_string())
}

/// Fails with the words for the person unless `name` can name a profile.
#[wasm_bindgen(js_name = validateName)]
pub fn validate_name(name: &str) -> Result<(), JsError> {
    if shum_core::card::valid_name(name) {
        Ok(())
    } else {
        Err(JsError::new(
            "Имя: 1–64 байта UTF-8, без пробелов по краям (до 32 русских букв)",
        ))
    }
}
