//! The encrypted record layout of protocol section 09, without any storage:
//! the profile state is split into one sealed record per array item or
//! dictionary entry plus a header, and read back with every check. Native
//! clients keep the records in SQLite ([`crate::Store`]); the browser keeps
//! the same records in IndexedDB. Both persist a [`Plan`] in one durable
//! transaction and only then [`Records::apply`] it.
use crate::{codec, layout, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use shum_core::crypto::Secret32;
use std::collections::{BTreeMap, HashSet};

/// One stored record: what a backend keeps per (bucket, id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub bucket: String,
    /// Keyed index of the item's real ID, so stored IDs reveal nothing.
    pub id: String,
    pub position: i64,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
struct Row {
    record: Record,
    real_id: String,
    value: Value,
}
type Rows = BTreeMap<(String, String), Row>;

/// What a commit writes and deletes. Backends apply it atomically.
pub struct Plan {
    pub write: Vec<Record>,
    /// (bucket, id) of records to delete.
    pub delete: Vec<(String, String)>,
    state: Value,
    rows: Rows,
}

/// The decrypted state of one profile and the records it is stored as.
pub struct Records {
    key: Secret32,
    owner: String,
    state: Value,
    rows: Rows,
}

fn make_row(
    key: &[u8; 32],
    bucket: &str,
    real_id: &str,
    position: i64,
    value: Value,
) -> Result<Row> {
    let index = codec::index_id(key, bucket, real_id);
    let json = zeroize::Zeroizing::new(serde_json::to_vec(&value)?);
    let packed = codec::pack(real_id, &json)?;
    let payload = codec::seal(
        key,
        &codec::random_nonce()?,
        &packed,
        &codec::aad(bucket, &index, position),
    )?;
    Ok(Row {
        record: Record {
            bucket: bucket.into(),
            id: index,
            position,
            payload,
        },
        real_id: real_id.into(),
        value,
    })
}

fn total_size<'a>(mut records: impl Iterator<Item = &'a Record>) -> Result<usize> {
    let total = records.try_fold(0usize, |sum, r| {
        sum.checked_add(r.payload.len())
            .ok_or(Error::Invalid("database size"))
    })?;
    if total > codec::MAX_BYTES {
        return Err(Error::Invalid("database size"));
    }
    Ok(total)
}

impl Records {
    /// A new profile store holding `state`; returns the records to write.
    pub fn create(owner: &str, key: Secret32, state: &Value) -> Result<(Self, Vec<Record>)> {
        layout::validate(state, owner)?;
        let (header, groups) = layout::split(state)?;
        let mut rows = Rows::new();
        let root = make_row(key.expose(), "header", "root", 0, header)?;
        rows.insert(("header".into(), "root".into()), root);
        for (bucket, items) in groups {
            let dictionary = layout::DICTS.iter().any(|(name, _)| *name == bucket);
            for (position, (id, value)) in items.into_iter().enumerate() {
                let position = if dictionary { 0 } else { position as i64 };
                let row = make_row(key.expose(), &bucket, &id, position, value)?;
                rows.insert((bucket.clone(), id), row);
            }
        }
        total_size(rows.values().map(|r| &r.record))?;
        let records = rows.values().map(|r| r.record.clone()).collect();
        Ok((
            Self {
                key,
                owner: owner.into(),
                state: state.clone(),
                rows,
            },
            records,
        ))
    }

    /// Opens stored records: every record must decrypt, belong to its index
    /// and position, and together form a valid state for `owner`.
    pub fn load(
        owner: &str,
        key: Secret32,
        records: impl IntoIterator<Item = Record>,
    ) -> Result<Self> {
        let mut result = Rows::new();
        let mut total = 0usize;
        for record in records {
            if record.bucket.len() > 64 || record.id.len() > 64 {
                return Err(Error::Invalid("record index size"));
            }
            total = total
                .checked_add(record.payload.len())
                .ok_or(Error::Invalid("database size"))?;
            if total > codec::MAX_BYTES {
                return Err(Error::Invalid("database size"));
            }
            let plain = codec::open(
                key.expose(),
                &record.payload,
                &codec::aad(&record.bucket, &record.id, record.position),
            )?;
            let (real_id, json) = codec::unpack(&plain)?;
            if codec::index_id(key.expose(), &record.bucket, real_id) != record.id {
                return Err(Error::Authentication);
            }
            let value: Value = serde_json::from_slice(json)?;
            let token = (record.bucket.clone(), real_id.to_string());
            let row = Row {
                real_id: real_id.into(),
                value,
                record,
            };
            if result.insert(token, row).is_some() {
                return Err(Error::Invalid("duplicate row"));
            }
        }
        let root = result
            .get(&("header".into(), "root".into()))
            .ok_or(Error::Invalid("missing header"))?;
        if root.record.position != 0
            || result
                .values()
                .filter(|r| r.record.bucket == "header")
                .count()
                != 1
        {
            return Err(Error::Invalid("header position or count"));
        }
        let mut state = root.value["state"].clone();
        layout::validate(&state, owner)?;
        let counts = root.value["counts"]
            .as_object()
            .ok_or(Error::Invalid("header counts"))?;
        let mut known: HashSet<&str> = layout::ARRAYS.iter().map(|(name, _, _)| *name).collect();
        known.extend(layout::DICTS.iter().map(|(name, _)| *name));
        if counts.len() != known.len()
            || counts.keys().any(|s| !known.contains(s.as_str()))
            || result
                .values()
                .any(|r| r.record.bucket != "header" && !known.contains(r.record.bucket.as_str()))
        {
            return Err(Error::Invalid("unknown or missing bucket"));
        }
        for bucket in &known {
            if counts[*bucket].as_u64()
                != Some(
                    result
                        .values()
                        .filter(|r| r.record.bucket == *bucket)
                        .count() as u64,
                )
            {
                return Err(Error::Invalid("row count"));
            }
        }
        for &(bucket, _, required) in layout::ARRAYS {
            let mut rows: Vec<_> = result
                .values()
                .filter(|r| r.record.bucket == bucket)
                .collect();
            rows.sort_by_key(|r| r.record.position);
            let mut last = -1;
            for row in &rows {
                if row.record.position <= last || layout::row_id(bucket, &row.value)? != row.real_id
                {
                    return Err(Error::Invalid("array position or ID"));
                }
                last = row.record.position;
            }
            if required || !layout::field(&state, bucket).is_null() {
                layout::set_field(
                    &mut state,
                    bucket,
                    rows.into_iter().map(|r| r.value.clone()).collect(),
                );
            }
        }
        for &(bucket, required) in layout::DICTS {
            let mut dict = Map::new();
            for row in result.values().filter(|r| r.record.bucket == bucket) {
                if row.record.position != 0 {
                    return Err(Error::Invalid("dictionary position"));
                }
                dict.insert(row.real_id.clone(), row.value.clone());
            }
            if required || !state[bucket].is_null() {
                state[bucket] = dict.into();
            }
        }
        Ok(Self {
            key,
            owner: owner.into(),
            state,
            rows: result,
        })
    }

    pub fn state(&self) -> &Value {
        &self.state
    }

    /// Every stored record, for a backend that writes a new profile.
    pub fn all(&self) -> Vec<Record> {
        self.rows.values().map(|r| r.record.clone()).collect()
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[cfg(feature = "native")]
    pub(crate) fn key(&self) -> &Secret32 {
        &self.key
    }

    /// Brings a loaded state up to the current layout, as every open does.
    pub fn normalize(&self) -> Result<Option<Plan>> {
        let mut next = self.state.clone();
        layout::normalize(&mut next, &self.owner)?;
        self.plan(next)
    }

    /// The records to write and delete to store `next`, or `None` when it
    /// equals the current state. Unchanged items keep their sealed bytes.
    pub fn plan(&self, next: Value) -> Result<Option<Plan>> {
        layout::validate(&next, &self.owner)?;
        let (header, groups) = layout::split(&next)?;
        if self.state == next {
            return Ok(None);
        }
        let mut planned = Rows::new();
        for (bucket, values) in groups {
            let dictionary = layout::DICTS.iter().any(|(name, _)| *name == bucket);
            let mut last_existing = -1;
            let mut saw_new = false;
            let mut reorder = false;
            for (id, _) in &values {
                if let Some(old) = self.rows.get(&(bucket.clone(), id.clone())) {
                    if saw_new || old.record.position <= last_existing {
                        reorder = true;
                    }
                    last_existing = old.record.position;
                } else {
                    saw_new = true;
                }
            }
            let mut last = -1i64;
            for (ordinal, (id, value)) in values.into_iter().enumerate() {
                let token = (bucket.clone(), id.clone());
                let old = self.rows.get(&token);
                let position = if dictionary {
                    0
                } else if reorder {
                    i64::try_from(ordinal).map_err(|_| Error::Invalid("ordinal overflow"))?
                } else if let Some(old) = old {
                    old.record.position
                } else {
                    last.checked_add(1)
                        .ok_or(Error::Invalid("position overflow"))?
                };
                last = position;
                let row = if let Some(old) =
                    old.filter(|r| r.record.position == position && r.value == value)
                {
                    old.clone()
                } else {
                    make_row(self.key.expose(), &bucket, &id, position, value)?
                };
                planned.insert(token, row);
            }
        }
        let token = ("header".into(), "root".into());
        let root = if let Some(old) = self.rows.get(&token).filter(|r| r.value == header) {
            old.clone()
        } else {
            make_row(self.key.expose(), "header", "root", 0, header)?
        };
        planned.insert(token, root);
        total_size(planned.values().map(|r| &r.record))?;
        let write = planned
            .iter()
            .filter(|(token, row)| {
                self.rows
                    .get(*token)
                    .is_none_or(|old| old.record.payload != row.record.payload)
            })
            .map(|(_, row)| row.record.clone())
            .collect();
        let delete = self
            .rows
            .iter()
            .filter(|(token, _)| !planned.contains_key(*token))
            .map(|(_, row)| (row.record.bucket.clone(), row.record.id.clone()))
            .collect();
        Ok(Some(Plan {
            write,
            delete,
            state: next,
            rows: planned,
        }))
    }

    /// Takes a plan into memory after its records were durably stored.
    pub fn apply(&mut self, plan: Plan) {
        self.state = plan.state;
        self.rows = plan.rows;
    }
}
