//! SQLite storage: admin accounts, sessions, jobs, a certificate index and
//! the audit log. Private keys are never stored here (they live in Vault).

use std::{path::Path, sync::Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A certificate is due for renewal once less than
/// `min(renew_before_secs, lifetime / 3)` remains. Short-lived certificates
/// (e.g. 6-day) renew at a third of their life instead of constantly.
pub fn renewal_due(not_before: i64, not_after: i64, now: i64, renew_before_secs: i64) -> bool {
    let window = renew_before_secs.min((not_after - not_before) / 3);
    not_after - window <= now
}

const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE admins (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret_enc BLOB NOT NULL,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_login      INTEGER
);
CREATE TABLE recovery_codes (
    admin_id  INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   INTEGER
);
CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    stage      TEXT NOT NULL CHECK (stage IN ('password', 'full')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT
);
CREATE TABLE jobs (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    name          TEXT NOT NULL,
    domains       TEXT NOT NULL,
    requester     TEXT NOT NULL,
    status        TEXT NOT NULL,
    vault_path    TEXT,
    vault_version INTEGER,
    error         TEXT,
    created_at    INTEGER NOT NULL,
    started_at    INTEGER,
    finished_at   INTEGER
);
CREATE INDEX jobs_name ON jobs(name, status);
CREATE INDEX jobs_requester ON jobs(requester, created_at);
CREATE TABLE certificates (
    name          TEXT PRIMARY KEY,
    domains       TEXT NOT NULL,
    vault_path    TEXT NOT NULL,
    vault_version INTEGER NOT NULL,
    not_before    INTEGER NOT NULL,
    not_after     INTEGER NOT NULL,
    serial        TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE TABLE audit (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    actor_kind TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    result     TEXT NOT NULL,
    ip         TEXT,
    detail     TEXT
);
CREATE INDEX audit_ts ON audit(ts);
"#];

#[derive(Clone, Debug)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub totp_secret_enc: Vec<u8>,
    pub totp_last_step: i64,
    pub failed_attempts: i64,
    pub locked_until: i64,
    pub created_at: i64,
    pub last_login: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub admin_id: i64,
    pub csrf: String,
    pub stage: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub domains: Vec<String>,
    pub requester: String,
    pub status: String,
    pub vault_path: Option<String>,
    pub vault_version: Option<i64>,
    pub error: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CertRecord {
    pub name: String,
    pub domains: Vec<String>,
    pub vault_path: String,
    pub vault_version: i64,
    pub not_before: i64,
    pub not_after: i64,
    pub serial: String,
    pub issuer: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub ts: i64,
    pub actor_kind: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub ip: Option<String>,
    pub detail: Option<String>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

fn domains_from(row: &Row, idx: usize) -> rusqlite::Result<Vec<String>> {
    let s: String = row.get(idx)?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

fn admin_from(r: &Row) -> rusqlite::Result<Admin> {
    Ok(Admin {
        id: r.get(0)?,
        username: r.get(1)?,
        password_hash: r.get(2)?,
        totp_secret_enc: r.get(3)?,
        totp_last_step: r.get(4)?,
        failed_attempts: r.get(5)?,
        locked_until: r.get(6)?,
        created_at: r.get(7)?,
        last_login: r.get(8)?,
    })
}

const ADMIN_COLS: &str = "id, username, password_hash, totp_secret_enc, totp_last_step, \
                          failed_attempts, locked_until, created_at, last_login";

fn job_from(r: &Row) -> rusqlite::Result<Job> {
    Ok(Job {
        id: r.get(0)?,
        kind: r.get(1)?,
        name: r.get(2)?,
        domains: domains_from(r, 3)?,
        requester: r.get(4)?,
        status: r.get(5)?,
        vault_path: r.get(6)?,
        vault_version: r.get(7)?,
        error: r.get(8)?,
        created_at: r.get(9)?,
        started_at: r.get(10)?,
        finished_at: r.get(11)?,
    })
}

const JOB_COLS: &str = "id, kind, name, domains, requester, status, vault_path, vault_version, \
                        error, created_at, started_at, finished_at";

fn cert_from(r: &Row) -> rusqlite::Result<CertRecord> {
    Ok(CertRecord {
        name: r.get(0)?,
        domains: domains_from(r, 1)?,
        vault_path: r.get(2)?,
        vault_version: r.get(3)?,
        not_before: r.get(4)?,
        not_after: r.get(5)?,
        serial: r.get(6)?,
        issuer: r.get(7)?,
        updated_at: r.get(8)?,
    })
}

const CERT_COLS: &str =
    "name, domains, vault_path, vault_version, not_before, not_after, serial, issuer, updated_at";

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            conn.execute_batch(sql)
                .with_context(|| format!("migration {}", i + 1))?;
            conn.pragma_update(None, "user_version", i as i64 + 1)?;
        }
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(f(&conn)?)
    }

    // ---- admins ----------------------------------------------------------

    pub fn create_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_enc: &[u8],
    ) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO admins (username, password_hash, totp_secret_enc, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![username, password_hash, totp_enc, now()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn admin_by_username(&self, username: &str) -> Result<Option<Admin>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {ADMIN_COLS} FROM admins WHERE username = ?1"),
                [username],
                admin_from,
            )
            .optional()
        })
    }

    pub fn admin(&self, id: i64) -> Result<Option<Admin>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {ADMIN_COLS} FROM admins WHERE id = ?1"),
                [id],
                admin_from,
            )
            .optional()
        })
    }

    pub fn admins(&self) -> Result<Vec<Admin>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {ADMIN_COLS} FROM admins ORDER BY username"
            ))?;
            st.query_map([], admin_from)?.collect()
        })
    }

    pub fn admin_count(&self) -> Result<i64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0)))
    }

    pub fn delete_admin(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM admins WHERE id = ?1", [id])
                .map(|_| ())
        })
    }

    pub fn set_password(&self, id: i64, hash: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE admins SET password_hash = ?2 WHERE id = ?1",
                params![id, hash],
            )
            .map(|_| ())
        })
    }

    pub fn set_totp(&self, id: i64, totp_enc: &[u8]) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE admins SET totp_secret_enc = ?2, totp_last_step = 0 WHERE id = ?1",
                params![id, totp_enc],
            )
            .map(|_| ())
        })
    }

    /// Count a failed login; lock the account after `max` consecutive failures.
    pub fn record_login_failure(&self, id: i64, max: i64, lock_secs: i64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE admins SET
                    locked_until = CASE WHEN failed_attempts + 1 >= ?2 THEN ?3 ELSE locked_until END,
                    failed_attempts = CASE WHEN failed_attempts + 1 >= ?2 THEN 0 ELSE failed_attempts + 1 END
                 WHERE id = ?1",
                params![id, max, now() + lock_secs],
            )
            .map(|_| ())
        })
    }

    pub fn record_login_success(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE admins SET failed_attempts = 0, locked_until = 0, last_login = ?2 WHERE id = ?1",
                params![id, now()],
            )
            .map(|_| ())
        })
    }

    /// Accept a TOTP step only once (and only moving forward).
    pub fn consume_totp_step(&self, id: i64, step: i64) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE admins SET totp_last_step = ?2 WHERE id = ?1 AND totp_last_step < ?2",
                params![id, step],
            )
            .map(|n| n == 1)
        })
    }

    // ---- recovery codes --------------------------------------------------

    pub fn replace_recovery_codes(&self, admin_id: i64, hashes: &[String]) -> Result<()> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM recovery_codes WHERE admin_id = ?1", [admin_id])?;
        for h in hashes {
            tx.execute(
                "INSERT INTO recovery_codes (admin_id, code_hash) VALUES (?1, ?2)",
                params![admin_id, h],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn use_recovery_code(&self, admin_id: i64, hash: &str) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE recovery_codes SET used_at = ?3
                 WHERE admin_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
                params![admin_id, hash, now()],
            )
            .map(|n| n == 1)
        })
    }

    pub fn unused_recovery_codes(&self, admin_id: i64) -> Result<i64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE admin_id = ?1 AND used_at IS NULL",
                [admin_id],
                |r| r.get(0),
            )
        })
    }

    // ---- sessions --------------------------------------------------------

    pub fn create_session(
        &self,
        id_hash: &str,
        admin_id: i64,
        csrf: &str,
        stage: &str,
        expires_at: i64,
        ip: Option<&str>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions (id_hash, admin_id, csrf, stage, created_at, expires_at, ip)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id_hash, admin_id, csrf, stage, now(), expires_at, ip],
            )
            .map(|_| ())
        })
    }

    pub fn session(&self, id_hash: &str) -> Result<Option<Session>> {
        self.with(|c| {
            c.query_row(
                "SELECT admin_id, csrf, stage, expires_at FROM sessions
                 WHERE id_hash = ?1 AND expires_at > ?2",
                params![id_hash, now()],
                |r| {
                    Ok(Session {
                        admin_id: r.get(0)?,
                        csrf: r.get(1)?,
                        stage: r.get(2)?,
                        expires_at: r.get(3)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn delete_session(&self, id_hash: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE id_hash = ?1", [id_hash])
                .map(|_| ())
        })
    }

    pub fn delete_sessions_for(&self, admin_id: i64) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE admin_id = ?1", [admin_id])
                .map(|_| ())
        })
    }

    pub fn purge_expired_sessions(&self) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now()])
                .map(|_| ())
        })
    }

    // ---- jobs ------------------------------------------------------------

    pub fn create_job(&self, job: &Job) -> Result<()> {
        self.with(|c| {
            c.execute(
                &format!(
                    "INSERT INTO jobs ({JOB_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
                ),
                params![
                    job.id,
                    job.kind,
                    job.name,
                    serde_json::to_string(&job.domains).unwrap_or_default(),
                    job.requester,
                    job.status,
                    job.vault_path,
                    job.vault_version,
                    job.error,
                    job.created_at,
                    job.started_at,
                    job.finished_at
                ],
            )
            .map(|_| ())
        })
    }

    pub fn job(&self, id: &str) -> Result<Option<Job>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1"),
                [id],
                job_from,
            )
            .optional()
        })
    }

    pub fn jobs(&self, limit: i64) -> Result<Vec<Job>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {JOB_COLS} FROM jobs ORDER BY created_at DESC LIMIT ?1"
            ))?;
            st.query_map([limit], job_from)?.collect()
        })
    }

    pub fn jobs_for_name(&self, name: &str, limit: i64) -> Result<Vec<Job>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {JOB_COLS} FROM jobs WHERE name = ?1 ORDER BY created_at DESC LIMIT ?2"
            ))?;
            st.query_map(params![name, limit], job_from)?.collect()
        })
    }

    /// A queued or running job for this certificate name, if any.
    pub fn active_job_for(&self, name: &str) -> Result<Option<Job>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "SELECT {JOB_COLS} FROM jobs WHERE name = ?1 AND status IN ('queued','running')
                     ORDER BY created_at LIMIT 1"
                ),
                [name],
                job_from,
            )
            .optional()
        })
    }

    /// Jobs interrupted by a restart, oldest first.
    pub fn unfinished_jobs(&self) -> Result<Vec<String>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id FROM jobs WHERE status IN ('queued','running') ORDER BY created_at",
            )?;
            st.query_map([], |r| r.get(0))?.collect()
        })
    }

    pub fn job_started(&self, id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET status = 'running', started_at = ?2 WHERE id = ?1",
                params![id, now()],
            )
            .map(|_| ())
        })
    }

    pub fn job_finished(
        &self,
        id: &str,
        status: &str,
        vault_path: Option<&str>,
        vault_version: Option<i64>,
        error: Option<&str>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE jobs SET status = ?2, vault_path = ?3, vault_version = ?4, error = ?5,
                    finished_at = ?6 WHERE id = ?1",
                params![id, status, vault_path, vault_version, error, now()],
            )
            .map(|_| ())
        })
    }

    pub fn requests_since(&self, requester: &str, since: i64) -> Result<i64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM jobs WHERE requester = ?1 AND created_at >= ?2",
                params![requester, since],
                |r| r.get(0),
            )
        })
    }

    // ---- certificates ----------------------------------------------------

    pub fn upsert_certificate(&self, rec: &CertRecord) -> Result<()> {
        self.with(|c| {
            c.execute(
                &format!(
                    "INSERT INTO certificates ({CERT_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                     ON CONFLICT(name) DO UPDATE SET domains = excluded.domains,
                       vault_path = excluded.vault_path, vault_version = excluded.vault_version,
                       not_before = excluded.not_before, not_after = excluded.not_after,
                       serial = excluded.serial, issuer = excluded.issuer,
                       updated_at = excluded.updated_at"
                ),
                params![
                    rec.name,
                    serde_json::to_string(&rec.domains).unwrap_or_default(),
                    rec.vault_path,
                    rec.vault_version,
                    rec.not_before,
                    rec.not_after,
                    rec.serial,
                    rec.issuer,
                    rec.updated_at
                ],
            )
            .map(|_| ())
        })
    }

    pub fn certificate(&self, name: &str) -> Result<Option<CertRecord>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {CERT_COLS} FROM certificates WHERE name = ?1"),
                [name],
                cert_from,
            )
            .optional()
        })
    }

    pub fn certificates(&self) -> Result<Vec<CertRecord>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {CERT_COLS} FROM certificates ORDER BY not_after"
            ))?;
            st.query_map([], cert_from)?.collect()
        })
    }

    /// Certificates due for renewal at `now` (see [`renewal_due`]).
    pub fn certificates_due(&self, now: i64, renew_before_secs: i64) -> Result<Vec<CertRecord>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {CERT_COLS} FROM certificates
                 WHERE not_after - MIN(?2, (not_after - not_before) / 3) <= ?1
                 ORDER BY not_after"
            ))?;
            st.query_map(params![now, renew_before_secs], cert_from)?
                .collect()
        })
    }

    // ---- audit -----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        actor_kind: &str,
        actor: &str,
        action: &str,
        target: &str,
        result: &str,
        ip: Option<&str>,
        detail: Option<&str>,
    ) {
        let r = self.with(|c| {
            c.execute(
                "INSERT INTO audit (ts, actor_kind, actor, action, target, result, ip, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![now(), actor_kind, actor, action, target, result, ip, detail],
            )
        });
        tracing::info!(target: "audit", actor_kind, actor, action, target, result, ip, detail);
        if let Err(e) = r {
            tracing::error!(error = %e, "failed to write audit entry");
        }
    }

    pub fn audit_entries(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT ts, actor_kind, actor, action, target, result, ip, detail
                 FROM audit ORDER BY id DESC LIMIT ?1",
            )?;
            st.query_map([limit], |r| {
                Ok(AuditEntry {
                    ts: r.get(0)?,
                    actor_kind: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    result: r.get(5)?,
                    ip: r.get(6)?,
                    detail: r.get(7)?,
                })
            })?
            .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str, name: &str, status: &str) -> Job {
        Job {
            id: id.into(),
            kind: "issue".into(),
            name: name.into(),
            domains: vec![name.into()],
            requester: "entity:abc".into(),
            status: status.into(),
            vault_path: None,
            vault_version: None,
            error: None,
            created_at: now(),
            started_at: None,
            finished_at: None,
        }
    }

    #[test]
    fn jobs_lifecycle() {
        let db = Db::in_memory().unwrap();
        db.create_job(&job("j1", "a.example.com", "queued"))
            .unwrap();
        assert_eq!(
            db.active_job_for("a.example.com").unwrap().unwrap().id,
            "j1"
        );
        assert_eq!(db.unfinished_jobs().unwrap(), vec!["j1".to_string()]);
        db.job_started("j1").unwrap();
        db.job_finished(
            "j1",
            "succeeded",
            Some("secret/data/certs/a"),
            Some(3),
            None,
        )
        .unwrap();
        let j = db.job("j1").unwrap().unwrap();
        assert_eq!(j.status, "succeeded");
        assert_eq!(j.vault_version, Some(3));
        assert!(db.active_job_for("a.example.com").unwrap().is_none());
        assert_eq!(db.requests_since("entity:abc", 0).unwrap(), 1);
    }

    #[test]
    fn certificates_due() {
        let db = Db::in_memory().unwrap();
        let day = 86_400;
        // 90-day certificate: due 30 days before expiry (the configured window).
        let rec = CertRecord {
            name: "a.example.com".into(),
            domains: vec!["a.example.com".into()],
            vault_path: "secret/data/certs/a.example.com".into(),
            vault_version: 1,
            not_before: 0,
            not_after: 90 * day,
            serial: "01".into(),
            issuer: "CN=test".into(),
            updated_at: 0,
        };
        db.upsert_certificate(&rec).unwrap();
        assert!(db.certificates_due(59 * day, 30 * day).unwrap().is_empty());
        assert_eq!(
            db.certificates_due(60 * day, 30 * day).unwrap(),
            vec![rec.clone()]
        );
        // 6-day certificate: due with 2 days (a third) left, not immediately.
        db.upsert_certificate(&CertRecord {
            vault_version: 2,
            not_after: 6 * day,
            ..rec.clone()
        })
        .unwrap();
        assert!(db.certificates_due(3 * day, 30 * day).unwrap().is_empty());
        assert_eq!(db.certificates_due(4 * day, 30 * day).unwrap().len(), 1);
        assert_eq!(
            db.certificate("a.example.com")
                .unwrap()
                .unwrap()
                .vault_version,
            2
        );
    }

    #[test]
    fn renewal_window() {
        let day = 86_400;
        assert!(!renewal_due(0, 90 * day, 59 * day, 30 * day));
        assert!(renewal_due(0, 90 * day, 60 * day, 30 * day));
        assert!(!renewal_due(0, 45 * day, 29 * day, 30 * day));
        assert!(renewal_due(0, 45 * day, 30 * day, 30 * day));
        assert!(!renewal_due(0, 6 * day, 3 * day, 30 * day));
        assert!(renewal_due(0, 6 * day, 4 * day, 30 * day));
    }

    #[test]
    fn lockout_and_totp_replay() {
        let db = Db::in_memory().unwrap();
        let id = db.create_admin("alice", "hash", b"enc").unwrap();
        for _ in 0..4 {
            db.record_login_failure(id, 5, 900).unwrap();
        }
        assert_eq!(db.admin(id).unwrap().unwrap().locked_until, 0);
        db.record_login_failure(id, 5, 900).unwrap();
        assert!(db.admin(id).unwrap().unwrap().locked_until > now());
        db.record_login_success(id).unwrap();
        assert_eq!(db.admin(id).unwrap().unwrap().locked_until, 0);

        assert!(db.consume_totp_step(id, 100).unwrap());
        assert!(
            !db.consume_totp_step(id, 100).unwrap(),
            "same step must not be reused"
        );
        assert!(!db.consume_totp_step(id, 99).unwrap());
        assert!(db.consume_totp_step(id, 101).unwrap());
    }

    #[test]
    fn recovery_codes_single_use() {
        let db = Db::in_memory().unwrap();
        let id = db.create_admin("bob", "hash", b"enc").unwrap();
        db.replace_recovery_codes(id, &["h1".into(), "h2".into()])
            .unwrap();
        assert!(db.use_recovery_code(id, "h1").unwrap());
        assert!(!db.use_recovery_code(id, "h1").unwrap());
        assert_eq!(db.unused_recovery_codes(id).unwrap(), 1);
    }
}
