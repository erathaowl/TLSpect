use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

use crate::input::parse_pem;

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub pem_bundle: String,
    pub bundle_sha256: String,
    pub trusted: bool,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct Storage {
    pub path: PathBuf,
}

fn db_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

impl Storage {
    pub fn default_path() -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("TLSpect")
            .join("tlspect.sqlite3")
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(db_error)?;
        }
        let storage = Self { path };
        let db = storage.connection()?;
        let version: i32 = db.query_row("PRAGMA user_version", [], |row| row.get(0)).map_err(db_error)?;
        if version > 2 {
            return Err(format!("Unsupported newer database schema version: {version}"));
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('certificate', 'ca')),
                pem_bundle TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                trusted INTEGER NOT NULL DEFAULT 0 CHECK (trusted IN (0, 1)),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (kind, name),
                CHECK (kind = 'ca' OR trusted = 0)
            );
            CREATE TABLE IF NOT EXISTS preferences (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            PRAGMA user_version = 2;"
        ).map_err(db_error)?;
        Ok(storage)
    }

    pub fn open_default() -> Result<Self, String> {
        Self::open(Self::default_path())
    }

    fn connection(&self) -> Result<Connection, String> {
        let db = Connection::open(&self.path).map_err(db_error)?;
        db.busy_timeout(std::time::Duration::from_secs(10)).map_err(db_error)?;
        Ok(db)
    }

    fn entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
        Ok(Entry {
            id: row.get("id")?, kind: row.get("kind")?,
            name: row.get("name")?, pem_bundle: row.get("pem_bundle")?,
            bundle_sha256: row.get("bundle_sha256")?,
            trusted: row.get::<_, i64>("trusted")? != 0,
            enabled: row.get::<_, i64>("enabled")? != 0,
            created_at: row.get("created_at")?, updated_at: row.get("updated_at")?,
        })
    }

    pub fn list(&self) -> Result<Vec<Entry>, String> {
        let db = self.connection()?;
        let mut statement = db.prepare(
            "SELECT * FROM entries ORDER BY kind, name"
        ).map_err(db_error)?;
        let records = statement.query_map([], Self::entry).map_err(db_error)?;
        records.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)
    }

    pub fn get_preference(&self, key: &str, fallback: &str) -> String {
        let Ok(db) = self.connection() else { return fallback.to_owned() };
        let value: rusqlite::Result<String> = db.query_row(
            "SELECT value FROM preferences WHERE key = ?1", [key], |row| row.get(0)
        );
        value.unwrap_or_else(|_| fallback.to_owned())
    }

    pub fn set_preference(&self, key: &str, value: &str) -> Result<(), String> {
        self.connection()?.execute(
            "INSERT INTO preferences(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        ).map_err(db_error)?;
        Ok(())
    }

    pub fn validate(kind: &str, pem: &str, trusted: bool) -> Result<String, String> {
        if !matches!(kind, "certificate" | "ca") {
            return Err("Entry type must be certificate or ca".into());
        }
        let certs = parse_pem(pem)?;
        if trusted {
            if kind != "ca" || certs.iter().any(|cert| !cert.is_ca) {
                return Err("Trusted entries must contain CA:TRUE certificates only".into());
            }
            for cert in &certs {
                let der = cert.cert.to_der().map_err(db_error)?;
                let (_, parsed) = parse_x509_certificate(&der).map_err(db_error)?;
                if let Some(usage) = parsed.key_usage().map_err(db_error)? {
                    if !usage.value.key_cert_sign() {
                        return Err("Trusted CA must permit keyCertSign".into());
                    }
                }
            }
        }
        Ok(certs.into_iter().map(|cert| cert.pem).collect())
    }

    pub fn save(
        &self, kind: &str, name: &str, pem: &str,
        trusted: bool, enabled: bool, replace: bool,
    ) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("A saved item name is required".into());
        }
        let normalized = Self::validate(kind, pem, trusted)?;
        let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
        let timestamp = Utc::now().to_rfc3339();
        let db = self.connection()?;
        if replace {
            db.execute(
                "INSERT INTO entries(kind, name, pem_bundle, bundle_sha256, trusted, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(kind, name) DO UPDATE SET
                    pem_bundle=excluded.pem_bundle,
                    bundle_sha256=excluded.bundle_sha256,
                    trusted=excluded.trusted,
                    enabled=excluded.enabled,
                    updated_at=excluded.updated_at",
                params![kind, name.trim(), normalized, digest, trusted, enabled, timestamp],
            ).map_err(db_error)?;
        } else {
            db.execute(
                "INSERT INTO entries(kind, name, pem_bundle, bundle_sha256, trusted, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![kind, name.trim(), normalized, digest, trusted, enabled, timestamp],
            ).map_err(db_error)?;
        }
        Ok(())
    }

    pub fn rename(&self, id: i64, name: &str) -> Result<(), String> {
        if name.trim().is_empty() { return Err("A saved item name is required".into()); }
        let db = self.connection()?;
        let changed = db.execute(
            "UPDATE entries SET name=?1, updated_at=?2 WHERE id=?3",
            params![name.trim(), Utc::now().to_rfc3339(), id],
        ).map_err(db_error)?;
        if changed == 0 { return Err("The entry no longer exists".into()); }
        Ok(())
    }

    pub fn set_enabled(&self, id: i64, enabled: bool) -> Result<(), String> {
        self.update_flag(id, "enabled", enabled)
    }

    pub fn set_trusted(&self, id: i64, trusted: bool) -> Result<(), String> {
        let entry = self.list()?.into_iter().find(|e| e.id == id)
            .ok_or("The entry no longer exists")?;
        if trusted { Self::validate(&entry.kind, &entry.pem_bundle, true)?; }
        self.update_flag(id, "trusted", trusted)
    }

    fn update_flag(&self, id: i64, column: &str, value: bool) -> Result<(), String> {
        let sql = match column {
            "trusted" => "UPDATE entries SET trusted=?1, updated_at=?2 WHERE id=?3",
            "enabled" => "UPDATE entries SET enabled=?1, updated_at=?2 WHERE id=?3",
            _ => return Err("Unsupported field".into()),
        };
        let count = self.connection()?.execute(
            sql, params![value, Utc::now().to_rfc3339(), id]
        ).map_err(db_error)?;
        if count == 0 { return Err("The entry no longer exists".into()); }
        Ok(())
    }

    pub fn delete(&self, id: i64) -> Result<(), String> {
        let count = self.connection()?.execute("DELETE FROM entries WHERE id=?1", [id])
            .map_err(db_error)?;
        if count == 0 { return Err("The entry no longer exists".into()); }
        Ok(())
    }

    pub fn import_legacy(&self, source: &Path) -> Result<usize, String> {
        if source == self.path { return Err("Select a different database".into()); }
        let old = Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_error)?;
        let mut statement = old.prepare("SELECT * FROM entries").map_err(db_error)?;
        let entries = statement.query_map([], Self::entry).map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?;
        for entry in &entries {
            self.save(
                &entry.kind, &entry.name, &entry.pem_bundle,
                entry.trusted, entry.enabled, true,
            )?;
        }
        Ok(entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_database_starts_empty() {
        let file = std::env::temp_dir().join(format!(
            "tlspect-{}-{}.sqlite3", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let db = Storage::open(&file).expect("SQLite database");
        assert!(db.list().unwrap().is_empty());
        db.set_preference("theme", "dark").unwrap();
        assert_eq!(Storage::open(&file).unwrap().get_preference("theme", "system"), "dark");
        drop(db);
        let _ = std::fs::remove_file(file);
    }
}
