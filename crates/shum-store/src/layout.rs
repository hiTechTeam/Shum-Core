use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

pub(crate) const ARRAYS: &[(&str, &[&str], bool)] = &[
    ("contacts", &["card", "id"], true),
    ("requests", &["id"], true),
    ("conversations", &["id"], true),
    ("messages", &["envelope", "id"], true),
    ("relay", &["envelope", "id"], true),
    ("receipts", &[], true),
    ("encounters", &["card", "id"], false),
    ("savedProfiles", &["card", "id"], false),
    ("invitationOutbox", &["control", "id"], false),
    ("profileOutbox", &["recipientID"], false),
    ("retractOutbox", &["control", "id"], false),
    ("reactionOutbox", &["control", "id"], false),
    ("legacyMessages", &["id"], false),
];
pub(crate) const DICTS: &[(&str, bool)] = &[
    ("seenRelay", true),
    ("blocked", false),
    ("deletedMessageIDs", false),
    ("invitationStates", false),
    ("reactions", false),
];
pub(crate) type Groups = BTreeMap<String, Vec<(String, Value)>>;

pub fn empty_state(owner: &str) -> Value {
    json!({"version":1,"ownerID":owner,"contacts":[],"requests":[],"conversations":[],"messages":[],"relay":[],"receipts":[],"seenRelay":{},"invitationStates":{},"invitationOutbox":[]})
}
pub(crate) fn validate(state: &Value, owner: &str) -> Result<()> {
    if state["version"].as_u64() != Some(1) || state["ownerID"].as_str() != Some(owner) {
        return Err(Error::Identity);
    }
    Ok(())
}
pub(crate) fn field<'a>(state: &'a Value, bucket: &str) -> &'a Value {
    if bucket == "legacyMessages" {
        &state["legacyHistory"]["messages"]
    } else {
        &state[bucket]
    }
}
pub(crate) fn set_field(state: &mut Value, bucket: &str, value: Value) {
    if bucket == "legacyMessages" {
        state["legacyHistory"]["messages"] = value;
    } else {
        state[bucket] = value;
    }
}
fn string_at<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut v = v;
    for key in path {
        v = &v[*key];
    }
    v.as_str()
        .filter(|s| !s.is_empty())
        .ok_or(Error::Invalid("row identity"))
}
pub(crate) fn row_id(bucket: &str, value: &Value) -> Result<String> {
    fn card_id(card: &Value) -> Result<String> {
        let key = STANDARD
            .decode(string_at(card, &["noiseKey"])?)
            .map_err(|_| Error::Invalid("card Noise key"))?;
        if key.len() != 32 {
            return Err(Error::Invalid("card Noise key length"));
        }
        Ok(shum_core::crypto::id(&key))
    }
    if bucket == "requests" {
        return card_id(value);
    }
    if matches!(bucket, "contacts" | "encounters" | "savedProfiles") {
        return card_id(&value["card"]);
    }
    if bucket == "receipts" {
        let receipt = &value["receipt"];
        return Ok(format!(
            "{}:{}:{}",
            string_at(receipt, &["envelopeID"])?,
            string_at(receipt, &["digest"])?,
            card_id(&receipt["sender"])?
        ));
    }
    let (_, path, _) = ARRAYS
        .iter()
        .find(|(name, _, _)| *name == bucket)
        .ok_or(Error::Invalid("unknown bucket"))?;
    Ok(string_at(value, path)?.to_owned())
}
pub(crate) fn split(state: &Value) -> Result<(Value, Groups)> {
    let mut header_state = state.clone();
    if !state.is_object() {
        return Err(Error::Invalid("state object"));
    }
    let mut groups = Groups::new();
    let mut counts = Map::new();
    for &(bucket, _, required) in ARRAYS {
        let value = field(state, bucket);
        let mut rows = Vec::new();
        if !value.is_null() {
            let array = value.as_array().ok_or(Error::Invalid("array bucket"))?;
            let mut seen = HashSet::new();
            for row in array {
                let id = row_id(bucket, row)?;
                if id.len() > 65535 || !seen.insert(id.clone()) {
                    return Err(Error::Invalid("duplicate or oversized ID"));
                }
                rows.push((id, row.clone()));
            }
            set_field(&mut header_state, bucket, json!([]));
        } else if required {
            return Err(Error::Invalid("required array"));
        }
        counts.insert(bucket.to_owned(), json!(rows.len()));
        groups.insert(bucket.to_owned(), rows);
    }
    for &(bucket, required) in DICTS {
        let value = &state[bucket];
        let mut rows = Vec::new();
        if !value.is_null() {
            for (id, payload) in value
                .as_object()
                .ok_or(Error::Invalid("dictionary bucket"))?
            {
                if id.is_empty() || id.len() > 65535 {
                    return Err(Error::Invalid("dictionary ID"));
                }
                rows.push((id.clone(), payload.clone()));
            }
            header_state[bucket] = json!({});
        } else if required {
            return Err(Error::Invalid("required dictionary"));
        }
        counts.insert(bucket.to_owned(), json!(rows.len()));
        groups.insert(bucket.to_owned(), rows);
    }
    Ok((json!({"state":header_state,"counts":counts}), groups))
}
pub(crate) fn normalize(state: &mut Value, owner: &str) -> Result<()> {
    validate(state, owner)?;
    if state["invitationStates"].is_null() {
        let mut invitations = Map::new();
        for contact in state["contacts"]
            .as_array()
            .ok_or(Error::Invalid("contacts"))?
        {
            let id = row_id("contacts", contact)?;
            let date = contact["addedAt"]
                .as_f64()
                .ok_or(Error::Invalid("contact date"))?;
            let milliseconds = (date + 978_307_200.0) * 1000.0;
            if !milliseconds.is_finite()
                || milliseconds < i64::MIN as f64
                || milliseconds >= i64::MAX as f64
            {
                return Err(Error::Invalid("contact date range"));
            }
            invitations.insert(id.clone(), json!({"phase":"accepted","updatedAt":milliseconds as i64,"eventID":format!("legacy-{id}")}));
        }
        state["invitationStates"] = invitations.into();
    }
    if state["invitationOutbox"].is_null() {
        state["invitationOutbox"] = json!([]);
    }
    state
        .as_object_mut()
        .ok_or(Error::Invalid("state object"))?
        .remove("savedProfiles");
    Ok(())
}
