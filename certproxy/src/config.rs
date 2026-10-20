//! Runtime configuration, read from environment variables.
//!
//! Secrets (the Cloudflare token, the TOTP encryption key) are deliberately
//! not configured here: they are read from Vault at runtime.

use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultAuth {
    /// AppRole: role_id and secret_id read from files (Docker Compose secrets).
    AppRole {
        mount: String,
        role_id_file: PathBuf,
        secret_id_file: PathBuf,
    },
    /// Kubernetes: the pod's service-account JWT.
    Kubernetes {
        mount: String,
        role: String,
        jwt_file: PathBuf,
    },
    /// A token read from a file. Intended for development and tests.
    Token { token_file: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// Serve HTTPS with the given PEM certificate chain and key.
    Files { cert: PathBuf, key: PathBuf },
    /// Issue (and renew) a certificate for `hostname` through certproxy itself.
    SelfIssued { hostname: String },
    /// Plain HTTP. Only for tests or behind a TLS-terminating proxy/ingress.
    None,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub tls: TlsMode,
    pub data_dir: PathBuf,

    pub vault_addr: String,
    pub vault_namespace: Option<String>,
    pub vault_cacert: Option<PathBuf>,
    pub vault_auth: VaultAuth,
    pub kv_mount: String,
    pub kv_certs_prefix: String,
    /// KV path whose fields are passed as env vars to the acme.sh DNS hook.
    pub kv_dns_path: String,
    /// KV path holding certproxy's own secrets (`totp_key`).
    pub kv_app_path: String,
    /// KV path where one-time enrollment links for operators are written
    /// (first launch, and `certproxy admin invite`).
    pub kv_bootstrap_path: String,
    /// Base URL used in enrollment links, e.g. `https://certproxy.example.com:8443`.
    pub public_url: Option<String>,
    /// How long an enrollment link stays valid.
    pub invite_ttl: Duration,
    /// Policy-only path prefix used for the per-domain authorization check.
    pub request_marker_prefix: String,

    pub acme_sh: PathBuf,
    pub acme_server: String,
    pub acme_email: Option<String>,
    pub acme_dns_provider: String,
    pub acme_key_length: String,
    pub acme_dns_sleep: Option<u32>,
    pub acme_ca_bundle: Option<PathBuf>,
    /// Optional directory of extra acme.sh DNS hook scripts (`dns_*.sh`),
    /// copied into acme.sh's home before each run.
    pub acme_hooks_dir: Option<PathBuf>,
    pub acme_timeout: Duration,

    pub renew_before_days: i64,
    pub renew_interval: Duration,
    pub rate_limit_per_hour: u32,
    pub max_domains_per_request: usize,
    pub session_hours: i64,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn var_or(name: &str, default: &str) -> String {
    var(name).unwrap_or_else(|| default.to_string())
}

fn parse_or<T: std::str::FromStr>(name: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match var(name) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {name}={v:?}: {e}")),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let data_dir = PathBuf::from(var_or("DATA_DIR", "/data"));

        let tls = match var_or("TLS_MODE", "files").as_str() {
            "files" => TlsMode::Files {
                cert: var("TLS_CERT_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("tls/cert.pem")),
                key: var("TLS_KEY_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("tls/key.pem")),
            },
            "self" => TlsMode::SelfIssued {
                hostname: var("PUBLIC_HOSTNAME")
                    .context("TLS_MODE=self requires PUBLIC_HOSTNAME")?,
            },
            "none" => TlsMode::None,
            other => bail!("invalid TLS_MODE={other:?} (expected files, self or none)"),
        };

        let vault_auth = match var_or("VAULT_AUTH", "approle").as_str() {
            "approle" => VaultAuth::AppRole {
                mount: var_or("VAULT_APPROLE_MOUNT", "approle"),
                role_id_file: PathBuf::from(var_or(
                    "VAULT_ROLE_ID_FILE",
                    "/run/secrets/vault_role_id",
                )),
                secret_id_file: PathBuf::from(var_or(
                    "VAULT_SECRET_ID_FILE",
                    "/run/secrets/vault_secret_id",
                )),
            },
            "kubernetes" => VaultAuth::Kubernetes {
                mount: var_or("VAULT_K8S_MOUNT", "kubernetes"),
                role: var("VAULT_K8S_ROLE")
                    .context("VAULT_AUTH=kubernetes requires VAULT_K8S_ROLE")?,
                jwt_file: PathBuf::from(var_or(
                    "VAULT_K8S_TOKEN_FILE",
                    "/var/run/secrets/kubernetes.io/serviceaccount/token",
                )),
            },
            "token" => VaultAuth::Token {
                token_file: PathBuf::from(var_or("VAULT_TOKEN_FILE", "/run/secrets/vault_token")),
            },
            other => bail!("invalid VAULT_AUTH={other:?} (expected approle, kubernetes or token)"),
        };

        let vault_addr = var_or("VAULT_ADDR", "https://vault.netseclabs.com")
            .trim_end_matches('/')
            .to_string();

        Ok(Config {
            listen: parse_or("LISTEN_ADDR", "0.0.0.0:8443".parse().unwrap())?,
            tls,
            vault_addr,
            vault_namespace: var("VAULT_NAMESPACE"),
            vault_cacert: var("VAULT_CACERT").map(PathBuf::from),
            vault_auth,
            kv_mount: var_or("KV_MOUNT", "secret"),
            kv_certs_prefix: var_or("KV_CERTS_PREFIX", "certs"),
            kv_dns_path: var_or("KV_DNS_PATH", "certproxy/dns"),
            kv_app_path: var_or("KV_APP_PATH", "certproxy/app"),
            kv_bootstrap_path: var_or("KV_BOOTSTRAP_PATH", "certproxy/bootstrap"),
            public_url: var("PUBLIC_URL").map(|u| u.trim_end_matches('/').to_string()),
            invite_ttl: Duration::from_secs(60 * parse_or::<u64>("INVITE_TTL_MINUTES", 30)?),
            request_marker_prefix: var_or("REQUEST_MARKER_PREFIX", "cert-requests"),
            acme_sh: PathBuf::from(var_or("ACME_SH", "/usr/bin/acme.sh")),
            acme_server: var_or("ACME_SERVER", "letsencrypt"),
            acme_email: var("ACME_EMAIL"),
            acme_dns_provider: var_or("ACME_DNS_PROVIDER", "dns_cf"),
            acme_key_length: var_or("ACME_KEY_LENGTH", "ec-256"),
            acme_dns_sleep: var("ACME_DNS_SLEEP")
                .map(|v| v.parse())
                .transpose()
                .context("invalid ACME_DNS_SLEEP")?,
            acme_ca_bundle: var("ACME_CA_BUNDLE").map(PathBuf::from),
            acme_hooks_dir: var("ACME_HOOKS_DIR").map(PathBuf::from),
            acme_timeout: Duration::from_secs(parse_or("ACME_TIMEOUT_SECS", 600)?),
            renew_before_days: parse_or("RENEW_BEFORE_DAYS", 30)?,
            renew_interval: Duration::from_secs(
                3600 * parse_or::<u64>("RENEW_INTERVAL_HOURS", 12)?,
            ),
            rate_limit_per_hour: parse_or("RATE_LIMIT_PER_HOUR", 20)?,
            max_domains_per_request: parse_or("MAX_DOMAINS_PER_REQUEST", 20)?,
            session_hours: parse_or("SESSION_HOURS", 8)?,
            data_dir,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("certproxy.db")
    }

    pub fn acme_home(&self) -> PathBuf {
        self.data_dir.join("acme")
    }

    /// Base URL for links shown to people: `PUBLIC_URL`, else derived from
    /// `PUBLIC_HOSTNAME` in self-issued TLS mode, else `None` (links are then
    /// given as a path to append to certproxy's address).
    pub fn base_url(&self) -> Option<String> {
        if let Some(u) = &self.public_url {
            return Some(u.clone());
        }
        match &self.tls {
            TlsMode::SelfIssued { hostname } => Some(match self.listen.port() {
                443 => format!("https://{hostname}"),
                port => format!("https://{hostname}:{port}"),
            }),
            _ => None,
        }
    }

    /// Cookies get the `Secure` flag unless the UI is served over plain HTTP.
    pub fn secure_cookies(&self) -> bool {
        self.tls != TlsMode::None
    }
}
