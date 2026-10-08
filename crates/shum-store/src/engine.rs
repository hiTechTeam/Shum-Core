//! Projection between the pure engine and the existing iOS database schema.
use crate::{Error, Result, Store};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Map, Value};
use shum_core::{
    card::Card,
    crypto::Secret32,
    engine::{Engine, Transition},
    packet::*,
    queue::*,
    rules::*,
};
use std::collections::{HashMap, HashSet};
const EPOCH: f64 = 978_307_200.0;
const PAST: f64 = -63_114_076_800.0;
fn decode<T: DeserializeOwned>(value: &Value) -> Result<T> {
    Ok(serde_json::from_value(value.clone())?)
}
fn rows<'a>(state: &'a Value, name: &str) -> Result<&'a [Value]> {
    if state[name].is_null() {
        return Ok(&[]);
    }
    state[name]
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error::Invalid("stored array"))
}
fn dict<'a>(state: &'a Value, name: &str) -> Result<Option<&'a Map<String, Value>>> {
    if state[name].is_null() {
        Ok(None)
    } else {
        state[name]
            .as_object()
            .map(Some)
            .ok_or(Error::Invalid("stored dictionary"))
    }
}
fn millis(value: &Value) -> Result<Option<i64>> {
    if value.is_null() {
        return Ok(None);
    }
    let date = value.as_f64().ok_or(Error::Invalid("stored Date"))?;
    if date == PAST {
        return Ok(None);
    }
    let ms = (date + EPOCH) * 1000.0;
    if !ms.is_finite() || ms < i64::MIN as f64 || ms >= i64::MAX as f64 {
        return Err(Error::Invalid("stored Date range"));
    }
    Ok(Some(ms.round() as i64))
}
fn date(ms: i64) -> Value {
    json!(ms as f64 / 1000.0 - EPOCH)
}
fn count(v: &Value) -> Result<u32> {
    if v.is_null() {
        Ok(0)
    } else {
        u32::try_from(v.as_u64().ok_or(Error::Invalid("stored attempt count"))?)
            .map_err(|_| Error::Invalid("stored attempt count"))
    }
}
fn flag(v: &Value) -> Result<bool> {
    if v.is_null() {
        Ok(false)
    } else {
        v.as_bool().ok_or(Error::Invalid("stored boolean"))
    }
}
fn strings(v: &Value) -> Result<HashSet<String>> {
    if v.is_null() {
        Ok(HashSet::new())
    } else {
        decode(v)
    }
}
fn retry(v: &Value) -> Result<Retry> {
    Ok(Retry {
        attempts: count(&v["attempts"])?,
        last_ble: millis(&v["lastAttempt"])?,
        nostr_attempts: count(&v["nostrAttempts"])?,
        last_nostr: millis(&v["lastNostrAttempt"])?,
        nostr_accepted: flag(&v["nostrAccepted"])?,
    })
}
fn plain(v: &Value, e: &Envelope) -> Result<Plaintext> {
    Ok(Plaintext {
        protocol_name: "shum.message.v1".into(),
        id: e.id.clone(),
        conversation_id: e.conversation_id.clone(),
        sender_id: e.sender.id(),
        recipient_id: e.recipient.id(),
        timestamp: e.timestamp,
        expires_at: e.expires_at,
        text: v["text"]
            .as_str()
            .ok_or(Error::Invalid("stored text"))?
            .into(),
        reply: if v["reply"].is_null() {
            None
        } else {
            Some(decode(&v["reply"])?)
        },
    })
}
/// Rehydrates historical messages without treating their expired wire TTL as
/// invalid history. Authenticated storage already establishes their origin.
pub fn restore(state: &Value, signing: &Secret32) -> Result<Engine> {
    let own: Card = decode(&state["ownProfileCard"])?;
    if state["ownerID"].as_str() != Some(own.id().as_str())
        || own.signing_key != signing.ed_public().as_slice()
    {
        return Err(Error::Identity);
    }
    let mut engine = Engine::new(own)?;
    for row in rows(state, "contacts")? {
        let card: Card = decode(&row["card"])?;
        card.validate()?;
        engine.inbox.contacts.insert(card.id(), card);
    }
    for row in rows(state, "requests")? {
        let card: Card = decode(row)?;
        card.validate()?;
        engine.inbox.requests.insert(card.id(), card);
    }
    if let Some(blocked) = dict(state, "blocked")? {
        for (id, row) in blocked {
            let card: Card = decode(row)?;
            if card.id() != *id {
                return Err(Error::Invalid("blocked identity"));
            }
            engine.inbox.blocked.insert(id.clone());
            engine.inbox.blocked_cards.insert(id.clone(), card);
        }
    }
    if let Some(invitations) = dict(state, "invitationStates")? {
        for (id, row) in invitations {
            engine.inbox.invitations.insert(id.clone(), decode(row)?);
        }
    }
    if let Some(deleted) = dict(state, "deletedMessageIDs")? {
        for (id, value) in deleted {
            if let Some(ms) = millis(value)? {
                engine.inbox.deleted.insert(id.clone(), ms);
            }
        }
    }
    if let Some(reactions) = dict(state, "reactions")? {
        for (message, people) in reactions {
            for (person, mark) in people
                .as_object()
                .ok_or(Error::Invalid("reaction dictionary"))?
            {
                engine
                    .inbox
                    .reactions
                    .insert((message.clone(), person.clone()), decode(mark)?);
            }
        }
    }
    for row in rows(state, "messages")? {
        let envelope: Envelope = decode(&row["envelope"])?;
        let plaintext = plain(row, &envelope)?;
        let status: Delivery = decode(&row["status"])?;
        if flag(&row["outgoing"])? {
            let r = retry(row)?;
            engine.outbox.messages.push(Outgoing {
                envelope,
                plaintext: Some(plaintext),
                delivery: DeliveryState {
                    status,
                    nostr_accepted: r.nostr_accepted,
                    nostr_attempts: r.nostr_attempts,
                    last_nostr_attempt: r.last_nostr,
                    receipt: None,
                },
                retry: r,
                offered: strings(&row["forwardedTo"])?,
                push_after: None,
                push_sent: flag(&row["cliPushSent"])?,
            });
        } else {
            engine.inbox.messages.push(ReceivedMessage {
                envelope,
                plaintext,
                unread: flag(&row["unread"])?,
                read: status == Delivery::Read,
                hop_count: row["hopCount"].as_i64().unwrap_or(0),
            });
        }
    }
    for row in rows(state, "relay")? {
        engine.outbox.relay.push(RelayCopy {
            envelope: decode(&row["envelope"])?,
            hop: row["hopCount"]
                .as_i64()
                .ok_or(Error::Invalid("relay hop"))?,
            depositor: row["depositor"]
                .as_str()
                .ok_or(Error::Invalid("depositor"))?
                .into(),
            offered: strings(&row["forwardedTo"])?,
            last_direct: millis(&row["lastDirectAttempt"])?,
        });
    }
    if let Some(seen) = dict(state, "seenRelay")? {
        for (id, value) in seen {
            if let Some(ms) = millis(value)? {
                engine.outbox.seen_relay.insert(id.clone(), ms);
            }
        }
    }
    for row in rows(state, "receipts")? {
        engine.outbox.receipts.push(StoredReceipt {
            receipt: decode(&row["receipt"])?,
            offered: strings(&row["sentTo"])?,
            retry: retry(row)?,
        });
    }
    for name in ["invitationOutbox", "retractOutbox", "reactionOutbox"] {
        for row in rows(state, name)? {
            let mut packet = Packet::default();
            let (id, recipient, expires, kind) = match name {
                "invitationOutbox" => {
                    let control: InvitationControl = decode(&row["control"])?;
                    let kind = if control.fields.action == InvitationAction::Request {
                        engine
                            .inbox
                            .outgoing_requests
                            .insert(control.recipient.id());
                        ControlKind::InvitationRequest
                    } else {
                        ControlKind::InvitationReply
                    };
                    let data = (
                        control.id.clone(),
                        control.recipient.clone(),
                        control.expires_at,
                        kind,
                    );
                    packet.invitation = Some(control);
                    if !row["avatar"].is_null() {
                        packet.invitation_avatar = Some(decode(&row["avatar"])?);
                    }
                    data
                }
                "retractOutbox" => {
                    let control: Retract = decode(&row["control"])?;
                    let data = (
                        control.id.clone(),
                        control.recipient.clone(),
                        control.expires_at,
                        ControlKind::Retract,
                    );
                    packet.retract = Some(control);
                    data
                }
                _ => {
                    let control: Reaction = decode(&row["control"])?;
                    let data = (
                        control.id.clone(),
                        control.recipient.clone(),
                        control.expires_at,
                        ControlKind::Reaction,
                    );
                    packet.reaction = Some(control);
                    data
                }
            };
            engine.outbox.controls.push(QueuedControl {
                id,
                recipient,
                packet,
                expires,
                kind,
                retry: retry(row)?,
            });
        }
    }
    for row in rows(state, "profileOutbox")? {
        let id = row["recipientID"]
            .as_str()
            .ok_or(Error::Invalid("profile recipient"))?;
        if let Some(recipient) = engine.inbox.contacts.get(id) {
            if row["profileID"].as_str() != Some(engine.inbox.own.profile_id()?.as_str()) {
                continue;
            }
            let sync = ProfileSync {
                sender: engine.inbox.own.clone(),
                recipient_id: id.into(),
                known_recipient: Some(recipient.clone()),
                requests_reply: true,
                signature: vec![],
            }
            .sign(signing)?;
            engine.outbox.profiles.push(ProfileDelivery {
                sync,
                recipient: recipient.clone(),
                attempts: count(&row["attempts"])?,
                last_attempt: millis(&row["lastAttempt"])?,
            });
        }
    }
    Ok(engine)
}
fn set_optional(row: &mut Value, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        row[key] = value;
    } else if let Some(row) = row.as_object_mut() {
        row.remove(key);
    }
}
fn set_date(row: &mut Value, key: &str, ms: Option<i64>, required: bool) -> Result<()> {
    if millis(&row[key])? == ms && (!row[key].is_null() || !required) {
        return Ok(());
    }
    set_optional(
        row,
        key,
        ms.map(date).or_else(|| required.then(|| json!(PAST))),
    );
    Ok(())
}
fn sorted(set: &HashSet<String>) -> Value {
    let mut v: Vec<_> = set.iter().collect();
    v.sort();
    json!(v)
}
fn put_retry(row: &mut Value, retry: &Retry, attempts: bool) -> Result<()> {
    if attempts {
        row["attempts"] = json!(retry.attempts);
    }
    set_date(row, "lastAttempt", retry.last_ble, true)?;
    row["nostrAccepted"] = json!(retry.nostr_accepted);
    if retry.nostr_attempts != 0 || !row["nostrAttempts"].is_null() {
        row["nostrAttempts"] = json!(retry.nostr_attempts);
    }
    set_date(row, "lastNostrAttempt", retry.last_nostr, false)
}
fn old_rows(state: &Value, bucket: &str) -> Result<HashMap<String, Value>> {
    rows(state, bucket)?
        .iter()
        .map(|row| Ok((crate::layout::row_id(bucket, row)?, row.clone())))
        .collect()
}
fn old_row(rows: &HashMap<String, Value>, id: &str) -> Value {
    rows.get(id).cloned().unwrap_or_else(|| json!({}))
}
fn ordered(mut values: Vec<Value>, previous: &Value, bucket: &str) -> Result<Value> {
    let order: HashMap<_, _> = rows(previous, bucket)?
        .iter()
        .enumerate()
        .map(|(i, row)| Ok((crate::layout::row_id(bucket, row)?, i)))
        .collect::<Result<_>>()?;
    values.sort_by_key(|row| {
        let id = crate::layout::row_id(bucket, row).unwrap_or_default();
        (order.get(&id).copied().unwrap_or(usize::MAX), id)
    });
    Ok(values.into())
}
fn put_model<T: Serialize + DeserializeOwned + PartialEq>(
    row: &mut Value,
    key: &str,
    new: &T,
) -> Result<()> {
    if serde_json::from_value::<T>(row[key].clone()).is_ok_and(|old| old == *new) {
        return Ok(());
    }
    let mut encoded = serde_json::to_value(new)?;
    if let (Some(old), Some(object)) = (row[key].as_object(), encoded.as_object_mut()) {
        // Retain fields unknown to this model while replacing all known fields.
        let known = serde_json::from_value::<T>(row[key].clone())
            .ok()
            .and_then(|v| serde_json::to_value(v).ok());
        for (key, value) in old {
            if known
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|known| !known.contains_key(key))
            {
                object.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
    row[key] = encoded;
    Ok(())
}
pub fn project(previous: &Value, engine: &Engine, now: i64) -> Result<Value> {
    let mut state = previous.clone();
    put_model(&mut state, "ownProfileCard", &engine.inbox.own)?;
    let contacts = old_rows(previous, "contacts")?;
    let mut values = Vec::new();
    for (id, card) in &engine.inbox.contacts {
        let mut row = old_row(&contacts, id);
        put_model(&mut row, "card", card)?;
        if row["addedAt"].is_null() {
            row["addedAt"] = date(now);
        }
        if row["metadata"].is_null() {
            row["metadata"] = json!({});
        }
        values.push(row);
    }
    state["contacts"] = ordered(values, previous, "contacts")?;
    let old_requests = old_rows(previous, "requests")?;
    let mut requests = Vec::new();
    for (id, card) in &engine.inbox.requests {
        let mut wrapper = json!({"value": old_row(&old_requests, id)});
        put_model(&mut wrapper, "value", card)?;
        requests.push(wrapper["value"].take());
    }
    state["requests"] = ordered(requests, previous, "requests")?;
    let mut blocked = Map::new();
    for (id, card) in &engine.inbox.blocked_cards {
        let mut wrapper = json!({"value": previous["blocked"][id].clone()});
        put_model(&mut wrapper, "value", card)?;
        blocked.insert(id.clone(), wrapper["value"].take());
    }
    state["blocked"] = blocked.into();
    let mut invitations = Map::new();
    for (id, invitation) in &engine.inbox.invitations {
        let mut wrapper = json!({"value":previous["invitationStates"][id].clone()});
        put_model(&mut wrapper, "value", invitation)?;
        invitations.insert(id.clone(), wrapper["value"].take());
    }
    state["invitationStates"] = invitations.into();
    let mut deleted = Map::new();
    for (id, ms) in &engine.inbox.deleted {
        deleted.insert(
            id.clone(),
            if millis(&previous["deletedMessageIDs"][id])? == Some(*ms) {
                previous["deletedMessageIDs"][id].clone()
            } else {
                date(*ms)
            },
        );
    }
    state["deletedMessageIDs"] = deleted.into();
    let mut reactions = Map::<String, Value>::new();
    for ((message, person), mark) in &engine.inbox.reactions {
        let mut wrapper = json!({"value":previous["reactions"][message][person].clone()});
        put_model(&mut wrapper, "value", mark)?;
        reactions
            .entry(message.clone())
            .or_insert_with(|| json!({}))[person] = wrapper["value"].take();
    }
    state["reactions"] = reactions.into();
    let messages = old_rows(previous, "messages")?;
    let mut values = Vec::new();
    for message in &engine.inbox.messages {
        let mut row = old_row(&messages, &message.envelope.id);
        put_message(
            &mut row,
            &message.envelope,
            &message.plaintext,
            false,
            if message.read {
                Delivery::Read
            } else {
                Delivery::Delivered
            },
        )?;
        row["unread"] = json!(message.unread);
        row["hopCount"] = json!(message.hop_count);
        if row["attempts"].is_null() {
            put_retry(&mut row, &Retry::default(), true)?;
        }
        values.push(row);
    }
    for message in &engine.outbox.messages {
        let mut row = old_row(&messages, &message.envelope.id);
        let plaintext = message
            .plaintext
            .as_ref()
            .ok_or(Error::Invalid("outgoing plaintext missing"))?;
        put_message(
            &mut row,
            &message.envelope,
            plaintext,
            true,
            message.delivery.status,
        )?;
        put_retry(&mut row, &message.retry, true)?;
        row["nostrAccepted"] = json!(message.delivery.nostr_accepted);
        row["nostrAttempts"] = json!(message.delivery.nostr_attempts);
        set_date(
            &mut row,
            "lastNostrAttempt",
            message.delivery.last_nostr_attempt,
            true,
        )?;
        row["forwardedTo"] = sorted(&message.offered);
        row["cliPushSent"] = json!(message.push_sent);
        if let Some(receipt) = &message.delivery.receipt {
            if row["deliveredAt"].is_null() {
                row["deliveredAt"] = date(receipt.timestamp);
            }
            if receipt.read && row["readAt"].is_null() {
                row["readAt"] = date(receipt.timestamp);
            }
        }
        values.push(row);
    }
    state["messages"] = ordered(values, previous, "messages")?;
    let relay = old_rows(previous, "relay")?;
    let mut values = Vec::new();
    for copy in &engine.outbox.relay {
        let mut row = old_row(&relay, &copy.envelope.id);
        put_model(&mut row, "envelope", &copy.envelope)?;
        row["hopCount"] = json!(copy.hop);
        row["depositor"] = json!(copy.depositor);
        row["forwardedTo"] = sorted(&copy.offered);
        set_date(&mut row, "lastDirectAttempt", copy.last_direct, true)?;
        values.push(row);
    }
    state["relay"] = ordered(values, previous, "relay")?;
    let receipts = old_rows(previous, "receipts")?;
    let mut values = Vec::new();
    for receipt in &engine.outbox.receipts {
        let id = format!(
            "{}:{}:{}",
            receipt.receipt.envelope_id,
            receipt.receipt.digest,
            receipt.receipt.sender.id()
        );
        let mut row = old_row(&receipts, &id);
        put_model(&mut row, "receipt", &receipt.receipt)?;
        put_retry(&mut row, &receipt.retry, false)?;
        row["sentTo"] = sorted(&receipt.offered);
        values.push(row);
    }
    state["receipts"] = ordered(values, previous, "receipts")?;
    state["seenRelay"] = engine
        .outbox
        .seen_relay
        .iter()
        .map(|(id, ms)| (id.clone(), date(*ms)))
        .collect::<Map<_, _>>()
        .into();
    for bucket in ["invitationOutbox", "retractOutbox", "reactionOutbox"] {
        let old = old_rows(previous, bucket)?;
        let mut values = Vec::new();
        for control in &engine.outbox.controls {
            let value = match bucket {
                "invitationOutbox" => control.packet.invitation.as_ref().map(serde_json::to_value),
                "retractOutbox" => control.packet.retract.as_ref().map(serde_json::to_value),
                _ => control.packet.reaction.as_ref().map(serde_json::to_value),
            };
            if let Some(value) = value {
                let mut row = old_row(&old, &control.id);
                row["control"] = value?;
                if bucket == "invitationOutbox" {
                    set_optional(
                        &mut row,
                        "avatar",
                        control
                            .packet
                            .invitation_avatar
                            .as_ref()
                            .map(serde_json::to_value)
                            .transpose()?,
                    );
                }
                put_retry(&mut row, &control.retry, true)?;
                values.push(row);
            }
        }
        state[bucket] = ordered(values, previous, bucket)?;
    }
    let profiles = old_rows(previous, "profileOutbox")?;
    let mut values = Vec::new();
    for delivery in &engine.outbox.profiles {
        let id = delivery.recipient.id();
        let mut row = old_row(&profiles, &id);
        row["recipientID"] = json!(id);
        row["profileID"] = json!(delivery.sync.sender.profile_id()?);
        row["attempts"] = json!(delivery.attempts);
        set_date(&mut row, "lastAttempt", delivery.last_attempt, false)?;
        values.push(row);
    }
    state["profileOutbox"] = ordered(values, previous, "profileOutbox")?;
    let mut conversations = rows(previous, "conversations")?.to_vec();
    let mut ids: HashSet<String> = conversations
        .iter()
        .filter_map(|c| c["id"].as_str().map(str::to_owned))
        .collect();
    for message in state["messages"]
        .as_array()
        .ok_or(Error::Invalid("messages"))?
    {
        let e: Envelope = decode(&message["envelope"])?;
        if ids.insert(e.conversation_id.clone()) {
            let peer = if e.sender.id() == engine.inbox.own.id() {
                e.recipient.id()
            } else {
                e.sender.id()
            };
            conversations.push(
                json!({"id":e.conversation_id,"contactID":peer,"createdAt":date(e.timestamp)}),
            );
        }
    }
    state["conversations"] = conversations.into();
    Ok(state)
}
fn put_message(
    row: &mut Value,
    envelope: &Envelope,
    plain: &Plaintext,
    outgoing: bool,
    status: Delivery,
) -> Result<()> {
    put_model(row, "envelope", envelope)?;
    row["text"] = json!(plain.text);
    row["outgoing"] = json!(outgoing);
    row["status"] = serde_json::to_value(status)?;
    if row["unread"].is_null() {
        row["unread"] = json!(false);
    }
    if row["hopCount"].is_null() {
        row["hopCount"] = json!(0);
    }
    if row["forwardedTo"].is_null() {
        row["forwardedTo"] = json!([]);
    }
    set_optional(
        row,
        "reply",
        plain.reply.as_ref().map(serde_json::to_value).transpose()?,
    );
    Ok(())
}
/// Returns network actions only after the full state is durable.
pub fn commit_transition(
    store: &mut Store,
    live: &mut Engine,
    transition: Transition,
    now: i64,
) -> Result<Vec<Action>> {
    let next = project(store.state(), &transition.state, now)?;
    store.commit(next)?;
    *live = transition.state;
    Ok(transition.actions)
}
