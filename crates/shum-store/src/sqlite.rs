use crate::{codec, layout, Error, Result};
use fs2::FileExt;
use rusqlite::{params, types::ValueRef, Connection, OpenFlags, TransactionBehavior};
use serde_json::{Map, Value};
use shum_core::crypto::Secret32;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
struct Row {
    bucket: String,
    index: String,
    real_id: String,
    position: i64,
    value: Value,
    cipher: Vec<u8>,
}
type Rows = BTreeMap<(String, String), Row>;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommitStats {
    pub transactions: u64,
    pub written_rows: u64,
    pub deleted_rows: u64,
}

/// Holds an exclusive process lock for the profile's entire lifetime.
/// A failed commit leaves `state()` and all cached records unchanged.
pub struct Store {
    connection: Connection,
    key: Secret32,
    owner: String,
    state: Value,
    rows: Rows,
    data_version: i64,
    stats: CommitStats,
    _lock: File,
}
pub(crate) fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}
fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(Error::Invalid("symlink database or lock"))
        }
        Ok(meta) if !meta.is_file() => Err(Error::Invalid("database or lock is not a file")),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn connection(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )?;
    db.busy_timeout(Duration::from_secs(1))?;
    Ok(db)
}
fn configure(db: &Connection) -> Result<()> {
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;")?;
    Ok(())
}
fn version(db: &Connection) -> Result<i64> {
    Ok(db.query_row("PRAGMA data_version", [], |r| r.get(0))?)
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
    let cipher = codec::seal(
        key,
        &codec::random_nonce()?,
        &packed,
        &codec::aad(bucket, &index, position),
    )?;
    Ok(Row {
        bucket: bucket.into(),
        index,
        real_id: real_id.into(),
        position,
        value,
        cipher,
    })
}
fn write_row(db: &Connection, row: &Row) -> Result<()> {
    db.execute("INSERT INTO records(bucket,id,position,payload) VALUES (?1,?2,?3,?4) ON CONFLICT(bucket,id) DO UPDATE SET position=excluded.position,payload=excluded.payload", params![row.bucket, row.index, row.position, row.cipher])?;
    Ok(())
}
fn load(db: &mut Connection, key: &[u8; 32], owner: &str) -> Result<(Value, Rows, i64)> {
    let before_version = version(db)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
    if tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Invalid("SQLite schema version"));
    }
    let mut result = Rows::new();
    let mut total = 0usize;
    {
        let mut query =
            tx.prepare("SELECT bucket,id,position,payload FROM records ORDER BY bucket,position")?;
        let mut cursor = query.query([])?;
        while let Some(record) = cursor.next()? {
            let bucket: String = record.get(0)?;
            let index: String = record.get(1)?;
            let position: i64 = record.get(2)?;
            if bucket.len() > 64 || index.len() > 64 {
                return Err(Error::Invalid("record index size"));
            }
            let ValueRef::Blob(cipher) = record.get_ref(3)? else {
                return Err(Error::Invalid("record payload type"));
            };
            total = total
                .checked_add(cipher.len())
                .ok_or(Error::Invalid("database size"))?;
            if total > codec::MAX_BYTES {
                return Err(Error::Invalid("database size"));
            }
            let plain = codec::open(key, cipher, &codec::aad(&bucket, &index, position))?;
            let (real_id, json) = codec::unpack(&plain)?;
            if codec::index_id(key, &bucket, real_id) != index {
                return Err(Error::Authentication);
            }
            let value: Value = serde_json::from_slice(json)?;
            let row = Row {
                bucket: bucket.clone(),
                index,
                real_id: real_id.into(),
                position,
                value,
                cipher: cipher.to_vec(),
            };
            if result.insert((bucket, real_id.into()), row).is_some() {
                return Err(Error::Invalid("duplicate row"));
            }
        }
    }
    let root = result
        .get(&("header".into(), "root".into()))
        .ok_or(Error::Invalid("missing header"))?;
    if root.position != 0 || result.values().filter(|r| r.bucket == "header").count() != 1 {
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
            .any(|r| r.bucket != "header" && !known.contains(r.bucket.as_str()))
    {
        return Err(Error::Invalid("unknown or missing bucket"));
    }
    for bucket in &known {
        if counts[*bucket].as_u64()
            != Some(result.values().filter(|r| r.bucket == *bucket).count() as u64)
        {
            return Err(Error::Invalid("row count"));
        }
    }
    for &(bucket, _, required) in layout::ARRAYS {
        let mut rows: Vec<_> = result.values().filter(|r| r.bucket == bucket).collect();
        rows.sort_by_key(|r| r.position);
        let mut last = -1;
        for row in &rows {
            if row.position <= last || layout::row_id(bucket, &row.value)? != row.real_id {
                return Err(Error::Invalid("array position or ID"));
            }
            last = row.position;
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
        for row in result.values().filter(|r| r.bucket == bucket) {
            if row.position != 0 {
                return Err(Error::Invalid("dictionary position"));
            }
            dict.insert(row.real_id.clone(), row.value.clone());
        }
        if required || !state[bucket].is_null() {
            state[bucket] = dict.into();
        }
    }
    let data_version = version(&tx)?;
    tx.commit()?;
    if before_version != data_version || version(db)? != data_version {
        return Err(Error::Conflict);
    }
    Ok((state, result, data_version))
}

impl Store {
    pub fn open(path: impl AsRef<Path>, owner: &str, key: Secret32) -> Result<Self> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Resolve the parent so alternative relative paths share the same lock.
        let path = fs::canonicalize(parent)?
            .join(path.file_name().ok_or(Error::Invalid("database path"))?);
        reject_symlink(&path)?;
        for suffix in ["-wal", "-shm", ".lock"] {
            reject_symlink(&sibling(&path, suffix))?;
        }
        let lock = private_options()
            .create(true)
            .truncate(false)
            .open(sibling(&path, ".lock"))?;
        lock.try_lock_exclusive().map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Error::Locked
            } else {
                e.into()
            }
        })?;
        if !path.exists() {
            create_atomic(&path, owner, key.expose(), &layout::empty_state(owner))?;
        } else {
            let mut signature = [0u8; 16];
            let count = File::open(&path)?.read(&mut signature)?;
            if count != 16 || &signature != b"SQLite format 3\0" {
                let mut data = Vec::new();
                File::open(&path)?
                    .take(codec::MAX_BYTES as u64 + 1)
                    .read_to_end(&mut data)?;
                let plain = codec::open(key.expose(), &data, &[])?;
                let mut state: Value = serde_json::from_slice(&plain)?;
                layout::normalize(&mut state, owner)?;
                let recovery = sibling(&path, ".v1-recovery");
                reject_symlink(&recovery)?;
                if !recovery.exists() {
                    let mut file = private_options().create_new(true).open(&recovery)?;
                    file.write_all(&data)?;
                    file.sync_all()?;
                }
                create_atomic(&path, owner, key.expose(), &state)?;
            }
        }
        let mut connection = connection(&path)?;
        let (state, rows, data_version) = load(&mut connection, key.expose(), owner)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            for suffix in ["-wal", "-shm"] {
                let sidecar = sibling(&path, suffix);
                if sidecar.exists() {
                    fs::set_permissions(sidecar, fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        configure(&connection)?;
        let mut store = Self {
            connection,
            key,
            owner: owner.into(),
            state,
            rows,
            data_version,
            stats: CommitStats::default(),
            _lock: lock,
        };
        if version(&store.connection)? != store.data_version {
            return Err(Error::Conflict);
        }
        let mut normalized = store.state.clone();
        layout::normalize(&mut normalized, owner)?;
        store.commit(normalized)?;
        Ok(store)
    }
    pub fn state(&self) -> &Value {
        &self.state
    }
    pub fn stats(&self) -> CommitStats {
        self.stats
    }
    /// Compute a candidate on a clone. Neither memory nor disk changes if it fails.
    pub fn transaction(&mut self, edit: impl FnOnce(&mut Value) -> Result<()>) -> Result<bool> {
        let mut state = self.state.clone();
        edit(&mut state)?;
        self.commit(state)
    }
    pub fn commit(&mut self, next: Value) -> Result<bool> {
        layout::validate(&next, &self.owner)?;
        let (header, groups) = layout::split(&next)?;
        // Even no-op callers must not keep using externally modified state.
        if version(&self.connection)? != self.data_version {
            return Err(Error::Conflict);
        }
        if self.state == next {
            return Ok(false);
        }
        let mut planned = Rows::new();
        for (bucket, values) in groups {
            let dictionary = layout::DICTS.iter().any(|(name, _)| *name == bucket);
            let mut last_existing = -1;
            let mut saw_new = false;
            let mut reorder = false;
            for (id, _) in &values {
                if let Some(old) = self.rows.get(&(bucket.clone(), id.clone())) {
                    if saw_new || old.position <= last_existing {
                        reorder = true;
                    }
                    last_existing = old.position;
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
                    old.position
                } else {
                    last.checked_add(1)
                        .ok_or(Error::Invalid("position overflow"))?
                };
                last = position;
                let row =
                    if let Some(old) = old.filter(|r| r.position == position && r.value == value) {
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
        let total = planned.values().try_fold(0usize, |sum, r| {
            sum.checked_add(r.cipher.len())
                .ok_or(Error::Invalid("database size"))
        })?;
        if total > codec::MAX_BYTES {
            return Err(Error::Invalid("database size"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version(&tx)? != self.data_version {
            return Err(Error::Conflict);
        }
        let mut written = 0;
        let mut deleted = 0;
        for (token, row) in &planned {
            if self
                .rows
                .get(token)
                .is_none_or(|old| old.cipher != row.cipher)
            {
                write_row(&tx, row)?;
                written += 1;
            }
        }
        for (token, row) in &self.rows {
            if !planned.contains_key(token) {
                tx.execute(
                    "DELETE FROM records WHERE bucket=?1 AND id=?2",
                    params![row.bucket, row.index],
                )?;
                deleted += 1;
            }
        }
        tx.commit()?;
        self.state = next;
        self.rows = planned;
        self.stats.transactions += 1;
        self.stats.written_rows += written;
        self.stats.deleted_rows += deleted;
        Ok(true)
    }
    pub fn checkpoint(&self) -> Result<()> {
        let (busy, _, _): (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        if busy != 0 {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub fn portable_snapshot(&self) -> Result<Vec<u8>> {
        if version(&self.connection)? != self.data_version {
            return Err(Error::Conflict);
        }
        let json = zeroize::Zeroizing::new(serde_json::to_vec(&self.state)?);
        codec::seal(self.key.expose(), &codec::random_nonce()?, &json, &[])
    }

    /// Import the optional legacy history once, in the same durable transaction.
    /// The source bytes remain untouched so a failed import can be retried.
    pub fn import_legacy_archive(
        &mut self,
        encrypted: &[u8],
        legacy_key: &Secret32,
    ) -> Result<bool> {
        if !self.state["legacyHistory"].is_null() {
            return Ok(false);
        }
        let plain = codec::open_legacy_archive(legacy_key.expose(), encrypted)?;
        let archive: Value = serde_json::from_slice(&plain)?;
        if !archive.is_object() || !archive["messages"].is_array() {
            return Err(Error::Invalid("legacy archive"));
        }
        self.transaction(|state| {
            state["legacyHistory"] = archive;
            Ok(())
        })
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.checkpoint();
    }
}

fn create_atomic(path: &Path, owner: &str, key: &[u8; 32], state: &Value) -> Result<()> {
    layout::validate(state, owner)?;
    let parent = path.parent().ok_or(Error::Invalid("database parent"))?;
    let temp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut db = connection(temp.path())?;
        configure(&db)?;
        db.execute_batch("CREATE TABLE records(bucket TEXT NOT NULL,id TEXT NOT NULL,position INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(bucket,id)) WITHOUT ROWID; PRAGMA user_version=1;")?;
        let (header, groups) = layout::split(state)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let root = make_row(key, "header", "root", 0, header)?;
        let mut total = root.cipher.len();
        write_row(&tx, &root)?;
        for (bucket, rows) in groups {
            let dictionary = layout::DICTS.iter().any(|(name, _)| *name == bucket);
            for (position, (id, value)) in rows.into_iter().enumerate() {
                let row = make_row(
                    key,
                    &bucket,
                    &id,
                    if dictionary { 0 } else { position as i64 },
                    value,
                )?;
                total = total
                    .checked_add(row.cipher.len())
                    .ok_or(Error::Invalid("database size"))?;
                if total > codec::MAX_BYTES {
                    return Err(Error::Invalid("database size"));
                }
                write_row(&tx, &row)?;
            }
        }
        tx.commit()?;
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    }
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| Error::Io(e.error))?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
