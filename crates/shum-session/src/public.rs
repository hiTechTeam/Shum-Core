//! The open chat with everyone nearby, kept for a day. Notes live in the
//! state header, not a record bucket, so earlier versions still open the
//! profile; each author's card is kept once for all their notes.
use serde_json::{json, Map, Value};
use shum_core::card::Card;

/// Notes older than this disappear.
pub const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;
/// At most this many notes are kept; the oldest go first.
const MAX_NOTES: usize = 500;

/// Whether this author's note `id` is already here.
pub fn contains(state: &Value, author: &str, id: &str) -> bool {
    state["publicChat"]["notes"]
        .as_array()
        .is_some_and(|notes| notes.iter().any(|n| n["id"] == id && n["author"] == author))
}

/// Adds a note unless it is already here. Returns whether anything changed.
pub fn record(
    state: &mut Value,
    card: &Card,
    id: &str,
    text: &str,
    timestamp: i64,
    outgoing: bool,
    now: i64,
) -> bool {
    let author = card.id();
    if !state["publicChat"].is_object() {
        state["publicChat"] = json!({"notes": [], "authors": {}});
    }
    let chat = &mut state["publicChat"];
    let notes = chat["notes"].as_array().cloned().unwrap_or_default();
    if notes
        .iter()
        .any(|n| n["id"] == id && n["author"] == author.as_str())
    {
        return false;
    }
    let mut notes: Vec<Value> = notes
        .into_iter()
        .filter(|n| now - n["timestamp"].as_i64().unwrap_or(0) < RETENTION_MS)
        .collect();
    notes.push(json!({
        "id": id,
        "author": author,
        "text": text,
        "timestamp": timestamp,
        "outgoing": outgoing,
    }));
    notes.sort_by_key(|n| n["timestamp"].as_i64().unwrap_or(0));
    if notes.len() > MAX_NOTES {
        notes.drain(..notes.len() - MAX_NOTES);
    }
    // Only authors with notes left keep their card.
    let mut authors = Map::new();
    for note in &notes {
        if let Some(id) = note["author"].as_str() {
            let card = if id == author {
                serde_json::to_value(card).unwrap_or_default()
            } else {
                chat["authors"][id].clone()
            };
            authors.insert(id.to_owned(), card);
        }
    }
    chat["notes"] = notes.into();
    chat["authors"] = authors.into();
    true
}

/// The day's notes, oldest first, each with its author's card.
pub fn notes(state: &Value, now: i64) -> Vec<Value> {
    let chat = &state["publicChat"];
    chat["notes"]
        .as_array()
        .map(|notes| {
            notes
                .iter()
                .filter(|n| now - n["timestamp"].as_i64().unwrap_or(0) < RETENTION_MS)
                .map(|n| {
                    let mut note = n.clone();
                    note["card"] = chat["authors"][n["author"].as_str().unwrap_or("")].clone();
                    note
                })
                .collect()
        })
        .unwrap_or_default()
}
