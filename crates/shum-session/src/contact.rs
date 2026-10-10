//! Contact addressing uses identifiers; display names never select a recipient.
use crate::Failure;
use std::collections::HashSet;

pub fn validate(selector: &str) -> Result<(), Failure> {
    if !(8..=64).contains(&selector.len())
        || !selector
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Failure::text("Укажите Shum ID (полный или уникальный префикс от 8 символов) либо полный сетевой ID. Имя не является адресом контакта."));
    }
    Ok(())
}

pub fn network_id(selector: &str) -> bool {
    selector.len() == 64 && validate(selector).is_ok()
}

pub fn resolve<'a>(
    selector: &str,
    candidates: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Option<String>, Failure> {
    validate(selector)?;
    let candidates: Vec<_> = candidates.into_iter().collect();
    // An exact Shum ID always wins over prefixes or another card's network ID.
    if candidates.iter().any(|(id, _)| *id == selector) {
        return Ok(Some(selector.into()));
    }
    let matches: HashSet<_> = candidates
        .into_iter()
        .filter(|(id, network)| {
            if selector.len() == 64 {
                *network == selector
            } else {
                id.starts_with(selector)
            }
        })
        .map(|(id, _)| id)
        .collect();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next().map(str::to_owned)),
        _ => Err(Failure::text(
            "ID соответствует нескольким контактам. Укажите полный Shum ID.",
        )),
    }
}
