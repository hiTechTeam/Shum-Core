//! Apple ShumCoding's signed integer JSON subset, implemented explicitly.
use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;

pub fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    append(&value, &mut out)?;
    Ok(out)
}

pub fn string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in value.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if c <= '\u{1f}' => {
                const HEX: &[u8] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(c as usize) >> 4]);
                out.push(HEX[(c as usize) & 15]);
            }
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    out.push(b'"');
}

fn append(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(v) => out.extend_from_slice(if *v { b"true" } else { b"false" }),
        Value::Number(v) => {
            if !v.is_i64() && !v.is_u64() {
                return Err(Error::Invalid("non-integer signed JSON"));
            }
            out.extend_from_slice(v.to_string().as_bytes());
        }
        Value::String(v) => string(v, out),
        Value::Array(values) => {
            out.push(b'[');
            for (i, v) in values.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                append(v, out)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            let mut fields: Vec<_> = values.iter().collect();
            fields.sort_unstable_by_key(|(k, _)| *k);
            out.push(b'{');
            for (i, (k, v)) in fields.into_iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                string(k, out);
                out.push(b':');
                append(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub mod bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

pub mod optional_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_some(&STANDARD.encode(v)),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}
