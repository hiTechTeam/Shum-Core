//! Native storage: the encrypted records of [`crate::records`] in SQLite.
use crate::{
    codec, layout,
    records::{Record, Records},
    Error, Result,
};
use fs2::FileExt;
use rusqlite::{
    params, types::ValueRef, Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use serde_json::Value;
use shum_core::crypto::Secret32;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
/// Bucket name for sealing photos, kept apart from the records.
const PHOTOS: &str = "photos";
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
    records: Records,
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
fn write_row(db: &Connection, record: &Record) -> Result<()> {
    db.execute("INSERT INTO records(bucket,id,position,payload) VALUES (?1,?2,?3,?4) ON CONFLICT(bucket,id) DO UPDATE SET position=excluded.position,payload=excluded.payload", params![record.bucket, record.id, record.position, record.payload])?;
    Ok(())
}
fn load(db: &mut Connection, key: Secret32, owner: &str) -> Result<(Records, i64)> {
    let before_version = version(db)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
    if tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1 {
        return Err(Error::Invalid("SQLite schema version"));
    }
    let mut stored = Vec::new();
    let mut total = 0usize;
    {
        let mut query =
            tx.prepare("SELECT bucket,id,position,payload FROM records ORDER BY bucket,position")?;
        let mut cursor = query.query([])?;
        while let Some(row) = cursor.next()? {
            let ValueRef::Blob(payload) = row.get_ref(3)? else {
                return Err(Error::Invalid("record payload type"));
            };
            // Stop reading early; Records checks the same limit again.
            total = total
                .checked_add(payload.len())
                .ok_or(Error::Invalid("database size"))?;
            if total > codec::MAX_BYTES {
                return Err(Error::Invalid("database size"));
            }
            stored.push(Record {
                bucket: row.get(0)?,
                id: row.get(1)?,
                position: row.get(2)?,
                payload: payload.to_vec(),
            });
        }
    }
    let records = Records::load(owner, key, stored)?;
    let data_version = version(&tx)?;
    tx.commit()?;
    if before_version != data_version || version(db)? != data_version {
        return Err(Error::Conflict);
    }
    Ok((records, data_version))
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
        let (records, data_version) = load(&mut connection, key, owner)?;
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
        // Photos live apart from the state, so they are read only when shown;
        // older apps ignore the table.
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY NOT NULL,payload BLOB NOT NULL) WITHOUT ROWID;",
        )?;
        let mut store = Self {
            connection,
            records,
            data_version,
            stats: CommitStats::default(),
            _lock: lock,
        };
        if version(&store.connection)? != store.data_version {
            return Err(Error::Conflict);
        }
        let mut normalized = store.records.state().clone();
        layout::normalize(&mut normalized, owner)?;
        store.commit(normalized)?;
        Ok(store)
    }
    pub fn state(&self) -> &Value {
        self.records.state()
    }
    /// Stores the JPEG of the message `id`, sealed like the records.
    pub fn put_photo(&self, id: &str, jpeg: &[u8]) -> Result<()> {
        let key = self.records.key().expose();
        let index = codec::index_id(key, PHOTOS, id);
        let payload = codec::seal(
            key,
            &codec::random_nonce()?,
            jpeg,
            &codec::aad(PHOTOS, &index, 0),
        )?;
        self.connection.execute(
            "INSERT INTO photos(id,payload) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            params![index, payload],
        )?;
        Ok(())
    }
    /// The JPEG of the message `id`, if this device has it.
    pub fn photo(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let key = self.records.key().expose();
        let index = codec::index_id(key, PHOTOS, id);
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload FROM photos WHERE id=?1",
                params![index],
                |r| r.get(0),
            )
            .optional()?;
        payload
            .map(|p| Ok(codec::open(key, &p, &codec::aad(PHOTOS, &index, 0))?.to_vec()))
            .transpose()
    }
    pub fn delete_photo(&self, id: &str) -> Result<()> {
        let index = codec::index_id(self.records.key().expose(), PHOTOS, id);
        self.connection
            .execute("DELETE FROM photos WHERE id=?1", params![index])?;
        Ok(())
    }
    pub fn stats(&self) -> CommitStats {
        self.stats
    }
    /// Compute a candidate on a clone. Neither memory nor disk changes if it fails.
    pub fn transaction(&mut self, edit: impl FnOnce(&mut Value) -> Result<()>) -> Result<bool> {
        let mut state = self.records.state().clone();
        edit(&mut state)?;
        self.commit(state)
    }
    pub fn commit(&mut self, next: Value) -> Result<bool> {
        layout::validate(&next, self.records.owner())?;
        // Even no-op callers must not keep using externally modified state.
        if version(&self.connection)? != self.data_version {
            return Err(Error::Conflict);
        }
        let Some(plan) = self.records.plan(next)? else {
            return Ok(false);
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if version(&tx)? != self.data_version {
            return Err(Error::Conflict);
        }
        for record in &plan.write {
            write_row(&tx, record)?;
        }
        for (bucket, id) in &plan.delete {
            tx.execute(
                "DELETE FROM records WHERE bucket=?1 AND id=?2",
                params![bucket, id],
            )?;
        }
        tx.commit()?;
        self.stats.transactions += 1;
        self.stats.written_rows += plan.write.len() as u64;
        self.stats.deleted_rows += plan.delete.len() as u64;
        self.records.apply(plan);
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
        let json = zeroize::Zeroizing::new(serde_json::to_vec(self.records.state())?);
        codec::seal(
            self.records.key().expose(),
            &codec::random_nonce()?,
            &json,
            &[],
        )
    }

    /// Import the optional legacy history once, in the same durable transaction.
    /// The source bytes remain untouched so a failed import can be retried.
    pub fn import_legacy_archive(
        &mut self,
        encrypted: &[u8],
        legacy_key: &Secret32,
    ) -> Result<bool> {
        if !self.records.state()["legacyHistory"].is_null() {
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
    let parent = path.parent().ok_or(Error::Invalid("database parent"))?;
    let temp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut db = connection(temp.path())?;
        configure(&db)?;
        db.execute_batch("CREATE TABLE records(bucket TEXT NOT NULL,id TEXT NOT NULL,position INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(bucket,id)) WITHOUT ROWID; PRAGMA user_version=1;")?;
        let (_, records) = Records::create(owner, Secret32::new(*key), state)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for record in &records {
            write_row(&tx, record)?;
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
