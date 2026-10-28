//! The open chat with everyone nearby, kept for a day. It lives in the state
//! header, not a record bucket, so earlier versions still open the profile.
//! Notes are keyed by their author and ID, since two people may pick the
//! same ID; each person's card is kept once for their notes and reactions.
use serde_json::{json, Map, Value};
use shum_core::{card::Card, public::PublicBody};

/// Notes, reactions and withdrawals older than this disappear.
pub const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;
/// At most this many notes are kept; the oldest go first.
const MAX_NOTES: usize = 500;

fn key(author: &str, id: &str) -> String {
    format!("{author}:{id}")
}

/// Whether this author's note `id` is already here.
pub fn contains(state: &Value, author: &str, id: &str) -> bool {
    state["publicChat"]["notes"]
        .as_array()
        .is_some_and(|notes| notes.iter().any(|n| n["id"] == id && n["author"] == author))
}

/// The person's reaction on a note, if any.
pub fn reaction(state: &Value, author: &str, id: &str, person: &str) -> Option<String> {
    state["publicChat"]["reactions"][key(author, id)][person]
        .as_str()
        .map(str::to_owned)
}

/// Applies an event from `card`. `own` marks this profile's own events.
/// Returns whether anything changed.
pub fn apply(
    state: &mut Value,
    card: &Card,
    id: &str,
    body: &PublicBody,
    timestamp: i64,
    own: bool,
    now: i64,
) -> bool {
    if !state["publicChat"].is_object() {
        state["publicChat"] = json!({});
    }
    let chat = &mut state["publicChat"];
    let sender = card.id();
    let changed = match body {
        PublicBody::Note { text, reply } => {
            if chat["retracted"].get(key(&sender, id)).is_some() {
                return false;
            }
            let notes = chat["notes"].as_array().cloned().unwrap_or_default();
            if notes
                .iter()
                .any(|n| n["id"] == id && n["author"] == sender.as_str())
            {
                return false;
            }
            let mut notes = notes;
            let mut note = json!({
                "id": id,
                "author": sender,
                "text": text,
                "timestamp": timestamp,
                "outgoing": own,
            });
            if let Some(reply) = reply {
                note["reply"] = serde_json::to_value(reply).unwrap_or_default();
            }
            notes.push(note);
            notes.sort_by_key(|n| n["timestamp"].as_i64().unwrap_or(0));
            chat["notes"] = notes.into();
            true
        }
        PublicBody::Reaction {
            note_id,
            author_id,
            reaction,
        } => {
            let target = key(author_id, note_id);
            let exists = chat["notes"].as_array().is_some_and(|notes| {
                notes
                    .iter()
                    .any(|n| n["id"] == note_id.as_str() && n["author"] == author_id.as_str())
            });
            if !exists {
                return false;
            }
            let value = reaction
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .unwrap_or(Value::Null);
            if chat["reactions"][&target][&sender] == value {
                return false;
            }
            if !chat["reactions"].is_object() {
                chat["reactions"] = json!({});
            }
            if !chat["reactions"][&target].is_object() {
                chat["reactions"][&target] = json!({});
            }
            let marks = chat["reactions"][&target].as_object_mut().expect("object");
            if value.is_null() {
                marks.remove(&sender);
            } else {
                marks.insert(sender.clone(), value);
            }
            true
        }
        PublicBody::Retract { note_id } => {
            // Only the author can withdraw: the key holds the sender's own ID.
            let target = key(&sender, note_id);
            if chat["retracted"].get(&target).is_some() {
                return false;
            }
            if let Some(notes) = chat["notes"].as_array_mut() {
                notes.retain(|n| !(n["id"] == note_id.as_str() && n["author"] == sender.as_str()));
            }
            if let Some(reactions) = chat["reactions"].as_object_mut() {
                reactions.remove(&target);
            }
            if !chat["retracted"].is_object() {
                chat["retracted"] = json!({});
            }
            chat["retracted"][&target] = json!(now);
            true
        }
        // Typing is shown, never stored.
        PublicBody::Typing { .. } => false,
    };
    if changed {
        if !chat["authors"].is_object() {
            chat["authors"] = json!({});
        }
        chat["authors"][&sender] = serde_json::to_value(card).unwrap_or_default();
        prune(chat, now);
    }
    changed
}

/// Drops what is older than a day, keeps at most `MAX_NOTES`, and forgets
/// cards and reactions nothing refers to any more.
fn prune(chat: &mut Value, now: i64) {
    let fresh = |t: &Value| now - t.as_i64().unwrap_or(0) < RETENTION_MS;
    let mut notes: Vec<Value> = chat["notes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| fresh(&n["timestamp"]))
        .collect();
    if notes.len() > MAX_NOTES {
        notes.drain(..notes.len() - MAX_NOTES);
    }
    let kept: std::collections::HashSet<String> = notes
        .iter()
        .map(|n| {
            key(
                n["author"].as_str().unwrap_or(""),
                n["id"].as_str().unwrap_or(""),
            )
        })
        .collect();
    let mut reactions = chat["reactions"].as_object().cloned().unwrap_or_default();
    reactions.retain(|target, marks| {
        kept.contains(target) && marks.as_object().is_some_and(|m| !m.is_empty())
    });
    let mut retracted = chat["retracted"].as_object().cloned().unwrap_or_default();
    retracted.retain(|_, t| fresh(t));
    let mut people: std::collections::HashSet<String> = notes
        .iter()
        .filter_map(|n| n["author"].as_str().map(str::to_owned))
        .collect();
    for marks in reactions.values() {
        people.extend(
            marks
                .as_object()
                .into_iter()
                .flatten()
                .map(|(p, _)| p.clone()),
        );
    }
    let mut authors = Map::new();
    for person in people {
        let card = chat["authors"][&person].clone();
        if !card.is_null() {
            authors.insert(person, card);
        }
    }
    chat["notes"] = notes.into();
    chat["reactions"] = reactions.into();
    chat["retracted"] = retracted.into();
    chat["authors"] = authors.into();
}

/// Prefix of the relay message that copies an open-chat event to this
/// profile's other devices. Earlier versions ignore it.
pub const COPY_PREFIX: &str = "shum-public-v1:";
/// Relay operations of those copies start with this.
pub const COPY_OPERATION: &str = "public-copy:";
/// At most this many copies wait for a connection; the oldest go first.
const MAX_COPIES: usize = 500;

/// Queues `content` for this profile's other devices under `operation`.
pub fn queue_copy(state: &mut Value, operation: &str, content: String) -> bool {
    let mut copies = state["publicCopies"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    copies.push(json!({"operation": operation, "content": content}));
    if copies.len() > MAX_COPIES {
        copies.drain(..copies.len() - MAX_COPIES);
    }
    state["publicCopies"] = copies.into();
    true
}

/// Copies still waiting for a relay, as (operation, content).
pub fn copies(state: &Value) -> Vec<(String, String)> {
    state["publicCopies"]
        .as_array()
        .map(|copies| {
            copies
                .iter()
                .filter_map(|c| {
                    Some((
                        c["operation"].as_str()?.to_owned(),
                        c["content"].as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A relay took the copy: it no longer waits.
pub fn copied(state: &mut Value, operation: &str) -> bool {
    let Some(copies) = state["publicCopies"].as_array_mut() else {
        return false;
    };
    let before = copies.len();
    copies.retain(|c| c["operation"] != operation);
    copies.len() != before
}

/// The day's notes, oldest first, each with its author's card, its quote and
/// everyone's reactions with their cards.
pub fn notes(state: &Value, now: i64) -> Vec<Value> {
    let chat = &state["publicChat"];
    chat["notes"]
        .as_array()
        .map(|notes| {
            notes
                .iter()
                .filter(|n| now - n["timestamp"].as_i64().unwrap_or(0) < RETENTION_MS)
                .map(|n| {
                    let author = n["author"].as_str().unwrap_or("");
                    let target = key(author, n["id"].as_str().unwrap_or(""));
                    let mut note = n.clone();
                    note["card"] = chat["authors"][author].clone();
                    note["reactions"] = chat["reactions"][&target]
                        .as_object()
                        .map(|marks| {
                            marks
                                .iter()
                                .map(|(person, reaction)| {
                                    json!({
                                        "personID": person,
                                        "reaction": reaction,
                                        "card": chat["authors"][person],
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                        .into();
                    note
                })
                .collect()
        })
        .unwrap_or_default()
}
