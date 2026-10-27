//! Local invitation timeline, persisted alongside the encrypted engine projection.
use serde_json::{json, Value};
use shum_core::{
    engine::Engine,
    rules::{InvitationState, Phase},
};

fn event(contact: &str, state: &InvitationState, engine: &Engine) -> Option<Value> {
    let local = engine.outbox.controls.iter().any(|q| {
        q.packet
            .invitation
            .as_ref()
            .is_some_and(|c| c.id == state.event_id)
    });
    let kind = match state.phase {
        Phase::Ready => return None,
        Phase::OutgoingPending => "invitationSent",
        Phase::IncomingPending => "invitationReceived",
        Phase::Accepted if local => "invitationAcceptedLocally",
        Phase::Accepted => "invitationAccepted",
        Phase::DeclinedByPeer => "invitationDeclined",
        Phase::DeclinedLocally => "invitationDeclinedLocally",
    };
    Some(
        json!({"id":format!("invitation:{}:{}",contact,state.event_id),
        "contactID":contact,"timestamp":state.updated_at,"kind":kind}),
    )
}

/// For profiles created before the timeline, show the known state without inventing history.
pub fn stored(state: &Value, engine: &Engine) -> Vec<Value> {
    if let Some(events) = state["cliInvitationEvents"].as_array() {
        return events.clone();
    }
    engine
        .inbox
        .invitations
        .iter()
        .filter_map(|(id, invitation)| {
            let mut e = event(id, invitation, engine)?;
            if invitation.phase == Phase::Accepted {
                e["kind"] = json!("chatAvailable");
            }
            Some(e)
        })
        .collect()
}

pub fn project(previous: &Value, before: &Engine, after: &Engine, clear: Option<&str>) -> Value {
    let mut events = stored(previous, before);
    for (id, invitation) in &after.inbox.invitations {
        // Receipt/retry/reaffirmation and replay must not add another timeline row.
        if before.inbox.phase(id) != invitation.phase {
            if let Some(e) = event(id, invitation, after) {
                if !events.iter().any(|old| old["id"] == e["id"]) {
                    events.push(e);
                }
            }
        }
    }
    // A cancelled invitation leaves no row behind.
    for (id, invitation) in &before.inbox.invitations {
        if invitation.phase == Phase::OutgoingPending && !after.inbox.invitations.contains_key(id) {
            let gone = format!("invitation:{id}:{}", invitation.event_id);
            events.retain(|e| e["id"] != gone.as_str());
        }
    }
    if let Some(id) = clear {
        events.retain(|e| e["contactID"] != id);
    }
    events.sort_by_key(|e| {
        (
            e["timestamp"].as_i64().unwrap_or(0),
            e["id"].as_str().unwrap_or("").to_owned(),
        )
    });
    json!(events)
}

pub fn timeline<'a>(snapshot: &'a Value, contact: &str) -> Vec<&'a Value> {
    let mut items: Vec<_> = ["messages", "events"]
        .into_iter()
        .flat_map(|key| snapshot[key].as_array().into_iter().flatten())
        .filter(|v| v["contactID"] == contact)
        .collect();
    items.sort_by_key(|v| {
        (
            v["timestamp"].as_i64().unwrap_or(0),
            v["id"].as_str().unwrap_or(""),
        )
    });
    items
}

/// A contact whose invitation waits for this profile's answer.
pub fn is_invitation(contact: &Value) -> bool {
    matches!(
        contact["phase"].as_str(),
        Some("incomingPending" | "declinedLocally")
    )
}
