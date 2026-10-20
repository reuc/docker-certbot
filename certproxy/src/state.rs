//! Shared application state and the certificate-request logic used by both
//! the API (apps) and the web UI (admins).

use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::mpsc;

use crate::{
    acme::{Acme, storage_name},
    config::Config,
    db::{CertRecord, Db, Job, now, renewal_due},
    vault::VaultClient,
};

pub type Shared = Arc<AppState>;

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub vault: Arc<VaultClient>,
    pub acme: Acme,
    jobs_tx: mpsc::UnboundedSender<String>,
    totp_key: RwLock<Option<[u8; 32]>>,
    /// Set in `TLS_MODE=self` so renewals can hot-reload the UI certificate.
    pub tls_reload: Mutex<Option<RustlsConfig>>,
}

/// Result of asking for a certificate.
#[derive(Debug)]
pub enum RequestOutcome {
    /// A valid certificate with the same names already exists.
    Existing(CertRecord),
    /// A job (new, or already queued/running for this name).
    Queued(Job),
}

impl AppState {
    pub fn new(
        cfg: Config,
        db: Db,
        vault: Arc<VaultClient>,
        acme: Acme,
    ) -> (Shared, mpsc::UnboundedReceiver<String>) {
        let (jobs_tx, rx) = mpsc::unbounded_channel();
        let state = AppState {
            cfg,
            db,
            vault,
            acme,
            jobs_tx,
            totp_key: RwLock::new(None),
            tls_reload: Mutex::new(None),
        };
        (Arc::new(state), rx)
    }

    pub fn enqueue(&self, job_id: &str) {
        let _ = self.jobs_tx.send(job_id.to_string());
    }

    pub fn totp_key(&self) -> Option<[u8; 32]> {
        *self.totp_key.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_totp_key(&self, key: [u8; 32]) {
        *self.totp_key.write().unwrap_or_else(|e| e.into_inner()) = Some(key);
    }

    /// KV path (relative to the mount) where a certificate is stored.
    pub fn kv_cert_path(&self, name: &str) -> String {
        format!("{}/{}", self.cfg.kv_certs_prefix, name)
    }

    /// Full Vault API path, as shown to apps (`secret/data/certs/<name>`).
    pub fn vault_api_path(&self, name: &str) -> String {
        format!("{}/data/{}", self.cfg.kv_mount, self.kv_cert_path(name))
    }

    /// Policy-only path an app token needs `update` on to request `domain`.
    /// Wildcards use the storage name (`*.x.com` -> `wildcard.x.com`) because
    /// `*` is a glob character in Vault policies.
    pub fn marker_path(&self, domain: &str) -> String {
        format!(
            "{}/{}",
            self.cfg.request_marker_prefix,
            storage_name(domain)
        )
    }

    pub fn renew_before_secs(&self) -> i64 {
        self.cfg.renew_before_days * 86_400
    }

    /// Queue issuance for `domains` (validated; first one names the
    /// certificate), unless an equivalent valid certificate or an active job
    /// exists. `force` skips the existing-certificate shortcut.
    pub fn request_certificate(
        &self,
        domains: &[String],
        kind: &str,
        requester: &str,
        force: bool,
    ) -> Result<RequestOutcome> {
        let name = storage_name(&domains[0]);
        if !force
            && let Some(rec) = self.db.certificate(&name)?
            && !renewal_due(
                rec.not_before,
                rec.not_after,
                now(),
                self.renew_before_secs(),
            )
            && same_names(&rec.domains, domains)
        {
            return Ok(RequestOutcome::Existing(rec));
        }
        if let Some(job) = self.db.active_job_for(&name)? {
            return Ok(RequestOutcome::Queued(job));
        }
        let job = Job {
            id: uuid::Uuid::new_v4().to_string(),
            kind: kind.to_string(),
            name,
            domains: domains.to_vec(),
            requester: requester.to_string(),
            status: "queued".into(),
            vault_path: None,
            vault_version: None,
            error: None,
            created_at: now(),
            started_at: None,
            finished_at: None,
        };
        self.db.create_job(&job)?;
        self.enqueue(&job.id);
        Ok(RequestOutcome::Queued(job))
    }
}

fn same_names(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    b.sort();
    a == b
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config::{TlsMode, VaultAuth};
    use std::time::Duration;

    pub fn test_config() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: TlsMode::None,
            data_dir: std::env::temp_dir(),
            vault_addr: "http://127.0.0.1:1".into(),
            vault_namespace: None,
            vault_cacert: None,
            vault_auth: VaultAuth::Token {
                token_file: "/nonexistent".into(),
            },
            kv_mount: "secret".into(),
            kv_certs_prefix: "certs".into(),
            kv_dns_path: "certproxy/dns".into(),
            kv_app_path: "certproxy/app".into(),
            request_marker_prefix: "cert-requests".into(),
            acme_sh: "/bin/false".into(),
            acme_server: "letsencrypt_test".into(),
            acme_email: None,
            acme_dns_provider: "dns_cf".into(),
            acme_key_length: "ec-256".into(),
            acme_dns_sleep: None,
            acme_ca_bundle: None,
            acme_hooks_dir: None,
            acme_timeout: Duration::from_secs(5),
            renew_before_days: 30,
            renew_interval: Duration::from_secs(3600),
            rate_limit_per_hour: 3,
            max_domains_per_request: 5,
            session_hours: 8,
        }
    }

    pub fn test_state() -> (Shared, mpsc::UnboundedReceiver<String>) {
        let cfg = test_config();
        let vault = Arc::new(VaultClient::new(&cfg).unwrap());
        let acme = Acme::new(&cfg);
        AppState::new(cfg, Db::in_memory().unwrap(), vault, acme)
    }

    #[test]
    fn paths() {
        let (s, _rx) = test_state();
        assert_eq!(
            s.vault_api_path("a.example.com"),
            "secret/data/certs/a.example.com"
        );
        assert_eq!(
            s.marker_path("*.example.com"),
            "cert-requests/wildcard.example.com"
        );
    }

    #[test]
    fn request_dedupes_and_reuses() {
        let (s, mut rx) = test_state();
        let d = vec!["a.example.com".to_string()];
        let RequestOutcome::Queued(j1) = s
            .request_certificate(&d, "issue", "entity:x", false)
            .unwrap()
        else {
            panic!("expected a job")
        };
        assert_eq!(rx.try_recv().unwrap(), j1.id);
        // Same name while queued: same job, nothing new enqueued.
        let RequestOutcome::Queued(j2) = s
            .request_certificate(&d, "issue", "entity:y", false)
            .unwrap()
        else {
            panic!("expected a job")
        };
        assert_eq!(j1.id, j2.id);
        assert!(rx.try_recv().is_err());

        s.db.job_finished(&j1.id, "succeeded", None, None, None)
            .unwrap();
        s.db.upsert_certificate(&CertRecord {
            name: "a.example.com".into(),
            domains: d.clone(),
            vault_path: s.vault_api_path("a.example.com"),
            vault_version: 1,
            not_before: now(),
            not_after: now() + 90 * 86_400,
            serial: "01".into(),
            issuer: "CN=test".into(),
            updated_at: now(),
        })
        .unwrap();
        assert!(matches!(
            s.request_certificate(&d, "issue", "entity:x", false)
                .unwrap(),
            RequestOutcome::Existing(_)
        ));
        // Different SAN set or force: new job.
        let more = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        assert!(matches!(
            s.request_certificate(&more, "issue", "entity:x", false)
                .unwrap(),
            RequestOutcome::Queued(_)
        ));
    }
}
