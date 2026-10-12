//! People the profile knows beyond its chats, as the iOS app keeps them in
//! the profile state: encounters with people nearby, pinned entries of each
//! list, and contacts kept out of the address book. Every client reads and
//! changes them the same way. Dates are seconds since 1 January 2001, as the
//! iOS app stores them.
use serde_json::{json, Map, Value};
use shum_core::card::Card;

/// Encounters older than a day leave the list.
pub const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;
/// Seeing someone again within a minute is the same encounter.
const SAME_ENCOUNTER_MS: i64 = 60 * 1000;
const MAX_ENCOUNTERS: usize = 1000;
const EPOCH_2001: f64 = 978_307_200.0;

fn date(ms: i64) -> Value {
    json!(ms as f64 / 1000.0 - EPOCH_2001)
}
fn ms(value: &Value) -> i64 {
    value
        .as_f64()
        .map(|s| ((s + EPOCH_2001) * 1000.0) as i64)
        .unwrap_or(0)
}
fn id_of(row: &Value) -> Option<String> {
    serde_json::from_value::<Card>(row["card"].clone())
        .ok()
        .map(|c| c.id())
}
fn ids(state: &mut Value, key: &str) -> Vec<String> {
    state[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(Into::into))
                .collect()
        })
        .unwrap_or_default()
}
fn set_ids(state: &mut Value, key: &str, ids: Vec<String>) {
    state[key] = json!(ids);
}

/// Records that `card` was seen nearby at `now` (milliseconds since 1970).
/// Returns whether the state changed. A card with other keys under the same
/// Shum ID is refused.
pub fn record_encounter(state: &mut Value, card: &Card, now: i64) -> bool {
    let id = card.id();
    if !state["encounters"].is_array() {
        state["encounters"] = json!([]);
    }
    let card_json = serde_json::to_value(card).unwrap_or_default();
    let encounters = state["encounters"].as_array_mut().expect("array");
    let unviewed;
    if let Some(row) = encounters
        .iter_mut()
        .find(|r| id_of(r).as_deref() == Some(&id))
    {
        let old: Option<Card> = serde_json::from_value(row["card"].clone()).ok();
        if old
            .as_ref()
            .is_some_and(|o| o.signing_key != card.signing_key || o.nostr_key != card.nostr_key)
        {
            return false;
        }
        let previous = ms(&row["lastSeen"]);
        if now - previous < SAME_ENCOUNTER_MS && row["card"] == card_json {
            return false;
        }
        row["card"] = card_json;
        row["lastSeen"] = date(now);
        if now - previous >= SAME_ENCOUNTER_MS {
            row["seenCount"] = json!(row["seenCount"].as_i64().unwrap_or(1) + 1);
        }
        unviewed = now - previous >= RETENTION_MS;
    } else {
        encounters.push(json!({
            "card": card_json,
            "firstSeen": date(now),
            "lastSeen": date(now),
            "seenCount": 1,
        }));
        unviewed = true;
        if encounters.len() > MAX_ENCOUNTERS {
            encounters.sort_by_key(|r| std::cmp::Reverse(ms(&r["lastSeen"])));
            encounters.truncate(MAX_ENCOUNTERS);
        }
    }
    if unviewed {
        let mut list = ids(state, "unviewedEncounterIDs");
        if !list.contains(&id) {
            list.push(id);
        }
        set_ids(state, "unviewedEncounterIDs", list);
    }
    true
}

/// Marks one encounter, or all with `None`, as seen in the list.
pub fn view_encounters(state: &mut Value, id: Option<&str>) {
    let list = match id {
        Some(id) => ids(state, "unviewedEncounterIDs")
            .into_iter()
            .filter(|v| v != id)
            .collect(),
        None => Vec::new(),
    };
    set_ids(state, "unviewedEncounterIDs", list);
}

/// Deletes one encounter, or all with `None`, with its marks and pins.
pub fn delete_encounters(state: &mut Value, id: Option<&str>) {
    let keep = |row: &Value| id.is_some_and(|id| id_of(row).as_deref() != Some(id));
    if let Some(encounters) = state["encounters"].as_array_mut() {
        encounters.retain(keep);
    }
    let unviewed = ids(state, "unviewedEncounterIDs")
        .into_iter()
        .filter(|v| id.is_some_and(|id| v != id))
        .collect();
    set_ids(state, "unviewedEncounterIDs", unviewed);
    if let Some(pins) = state["pinnedDirectoryEntries"].as_object_mut() {
        match id {
            Some(id) => {
                if let Some(list) = pins.get_mut("encounters").and_then(Value::as_array_mut) {
                    list.retain(|v| v.as_str() != Some(id));
                }
            }
            None => {
                pins.remove("encounters");
            }
        }
    }
}

/// Pins `id` at the top of the list `directory`, or unpins it. Returns
/// whether it is pinned now.
pub fn toggle_pin(state: &mut Value, directory: &str, id: &str) -> bool {
    if !state["pinnedDirectoryEntries"].is_object() {
        state["pinnedDirectoryEntries"] = json!({});
    }
    let pins = state["pinnedDirectoryEntries"]
        .as_object_mut()
        .expect("object");
    let mut list: Vec<String> = pins
        .get(directory)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(Into::into))
                .collect()
        })
        .unwrap_or_default();
    let pinned = if list.iter().any(|v| v == id) {
        list.retain(|v| v != id);
        false
    } else {
        list.insert(0, id.into());
        true
    };
    if list.is_empty() {
        pins.remove(directory);
    } else {
        pins.insert(directory.into(), json!(list));
    }
    pinned
}

/// Keeps a contact out of the address book; the chat and keys stay.
pub fn remove_from_contacts(state: &mut Value, id: &str) -> bool {
    let Some(row) = state["contacts"]
        .as_array_mut()
        .and_then(|rows| rows.iter_mut().find(|r| id_of(r).as_deref() == Some(id)))
    else {
        return false;
    };
    if !row["metadata"].is_object() {
        row["metadata"] = json!({});
    }
    row["metadata"]["addressBook"] = json!("false");
    true
}

/// Whether a contact is in the address book.
pub fn in_address_book(state: &Value, id: &str) -> bool {
    state["contacts"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| id_of(r).as_deref() == Some(id)))
        .is_none_or(|row| row["metadata"]["addressBook"].as_str() != Some("false"))
}

/// The encounters of the last day that are not blocked, newest first, for
/// snapshots: `{id, card, firstSeen, lastSeen, seenCount, viewed}` with
/// times in milliseconds since 1970.
pub fn encounters(
    state: &Value,
    blocked: &std::collections::HashSet<String>,
    now: i64,
) -> Vec<Value> {
    let unviewed: Vec<&str> = state["unviewedEncounterIDs"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut list: Vec<Value> = state["encounters"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let id = id_of(row)?;
                    let last = ms(&row["lastSeen"]);
                    (!blocked.contains(&id) && now - last <= RETENTION_MS).then(|| {
                        json!({
                            "id": id,
                            "card": row["card"],
                            "firstSeen": ms(&row["firstSeen"]),
                            "lastSeen": last,
                            "seenCount": row["seenCount"].as_i64().unwrap_or(1),
                            "viewed": !unviewed.contains(&id.as_str()),
                        })
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    list.sort_by_key(|v| std::cmp::Reverse(v["lastSeen"].as_i64().unwrap_or(0)));
    list
}

/// Pinned entries of every list, for snapshots.
pub fn pins(state: &Value) -> Value {
    state["pinnedDirectoryEntries"]
        .as_object()
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(Map::new()))
}
