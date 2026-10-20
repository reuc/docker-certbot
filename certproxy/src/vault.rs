//! Minimal HashiCorp Vault (or OpenBao) HTTP client.
//!
//! certproxy logs in with its own identity (AppRole, Kubernetes or a token
//! file) to write certificates and read its configuration. App tokens are
//! only ever used for `lookup-self` and `capabilities-self`, and are never
//! stored or logged.

use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;

use crate::config::{Config, VaultAuth};

/// Build a rustls client config trusting the system CA bundle plus an
/// optional extra PEM file (for a private Vault CA, or Pebble in tests).
pub fn tls_client_config(extra_ca: Option<&Path>) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = extra_ca {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            roots.add(cert.context("parsing extra CA certificate")?)?;
        }
    }
    if roots.is_empty() {
        bail!("no trusted CA certificates found");
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("permission denied or invalid token")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("vault: {0}")]
    Other(#[from] anyhow::Error),
}

/// Who an app token belongs to, for authorization bookkeeping and audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Stable identifier: the Vault entity ID, or the display name if the
    /// token has no entity (e.g. a root or orphan token).
    pub id: String,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct KvSecret {
    pub data: Map<String, Value>,
    pub version: u64,
}

struct TokenState {
    token: String,
    /// When to renew or re-login. `None` for non-expiring tokens.
    refresh_at: Option<Instant>,
    renewable: bool,
}

pub struct VaultClient {
    http: reqwest::Client,
    addr: String,
    namespace: Option<String>,
    auth: VaultAuth,
    pub kv_mount: String,
    state: RwLock<Option<TokenState>>,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthInfo,
}

#[derive(Deserialize)]
struct AuthInfo {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

fn read_secret_file(path: &Path) -> Result<String> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let s = s.trim().to_string();
    if s.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(s)
}

/// Parse a `sys/capabilities-self` response. Vault returns one key per
/// requested path, plus `capabilities` (the union) for compatibility.
pub fn parse_capabilities(body: &Value, paths: &[String]) -> HashMap<String, Vec<String>> {
    let caps_at = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let root = body.get("data").unwrap_or(body);
    paths
        .iter()
        .map(|p| {
            let caps = match root.get(p) {
                Some(v) => caps_at(Some(v)),
                // A single-path response may only carry `capabilities`.
                None if paths.len() == 1 => caps_at(root.get("capabilities")),
                None => Vec::new(),
            };
            (p.clone(), caps)
        })
        .collect()
}

/// True if the capability list allows writing to a path.
pub fn allows_update(caps: &[String]) -> bool {
    caps.iter().any(|c| c == "update" || c == "root") && !caps.iter().any(|c| c == "deny")
}

impl VaultClient {
    pub fn new(cfg: &Config) -> Result<Self> {
        let tls = tls_client_config(cfg.vault_cacert.as_deref())?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .user_agent(concat!("certproxy/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(VaultClient {
            http,
            addr: cfg.vault_addr.clone(),
            namespace: cfg.vault_namespace.clone(),
            auth: cfg.vault_auth.clone(),
            kv_mount: cfg.kv_mount.clone(),
            state: RwLock::new(None),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.addr, path.trim_start_matches('/'))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value), VaultError> {
        let mut req = self.http.request(method, self.url(path));
        if let Some(t) = token {
            req = req.header("X-Vault-Token", t);
        }
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("request to {path}: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| anyhow!("reading {path}: {e}"))?;
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        match status {
            s if s.is_success() => Ok((s, value)),
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(VaultError::Forbidden),
            StatusCode::NOT_FOUND => Err(VaultError::NotFound),
            s => {
                let errors = value.get("errors").cloned().unwrap_or(Value::Null);
                Err(VaultError::Other(anyhow!("{path}: HTTP {s}: {errors}")))
            }
        }
    }

    /// Log in with certproxy's own identity.
    pub async fn login(&self) -> Result<()> {
        let (token, lease, renewable) = match &self.auth {
            VaultAuth::Token { token_file } => (read_secret_file(token_file)?, 0, false),
            VaultAuth::AppRole {
                mount,
                role_id_file,
                secret_id_file,
            } => {
                let body = json!({
                    "role_id": read_secret_file(role_id_file)?,
                    "secret_id": read_secret_file(secret_id_file)?,
                });
                self.auth_login(&format!("auth/{mount}/login"), &body)
                    .await?
            }
            VaultAuth::Kubernetes {
                mount,
                role,
                jwt_file,
            } => {
                let body = json!({ "role": role, "jwt": read_secret_file(jwt_file)? });
                self.auth_login(&format!("auth/{mount}/login"), &body)
                    .await?
            }
        };
        let refresh_at = (lease > 0).then(|| Instant::now() + Duration::from_secs(lease * 2 / 3));
        *self.state.write().await = Some(TokenState {
            token,
            refresh_at,
            renewable,
        });
        Ok(())
    }

    async fn auth_login(&self, path: &str, body: &Value) -> Result<(String, u64, bool)> {
        let (_, v) = self
            .send(Method::POST, path, None, Some(body))
            .await
            .map_err(|e| anyhow!("vault login at {path} failed: {e}"))?;
        let auth: AuthResponse = serde_json::from_value(v).context("parsing login response")?;
        Ok((
            auth.auth.client_token,
            auth.auth.lease_duration,
            auth.auth.renewable,
        ))
    }

    /// Keep certproxy's token valid: renew it, or log in again when renewal
    /// is impossible. Runs forever.
    pub async fn maintain_token(self: Arc<Self>) {
        loop {
            let next = {
                let st = self.state.read().await;
                st.as_ref().map(|s| (s.refresh_at, s.renewable))
            };
            match next {
                None => {
                    if let Err(e) = self.login().await {
                        tracing::warn!(error = %e, "vault login failed; retrying in 15s");
                        tokio::time::sleep(Duration::from_secs(15)).await;
                    }
                }
                Some((None, _)) => tokio::time::sleep(Duration::from_secs(300)).await,
                Some((Some(at), renewable)) => {
                    tokio::time::sleep_until(at.into()).await;
                    let renewed = renewable && self.renew_self().await.is_ok();
                    if !renewed && let Err(e) = self.login().await {
                        tracing::warn!(error = %e, "vault re-login failed; retrying in 15s");
                        *self.state.write().await = None;
                        tokio::time::sleep(Duration::from_secs(15)).await;
                    }
                }
            }
        }
    }

    async fn renew_self(&self) -> Result<()> {
        let token = self.token().await?;
        let (_, v) = self
            .send(
                Method::POST,
                "auth/token/renew-self",
                Some(&token),
                Some(&json!({})),
            )
            .await?;
        let auth: AuthResponse = serde_json::from_value(v)?;
        let lease = auth.auth.lease_duration;
        let mut st = self.state.write().await;
        if let Some(s) = st.as_mut() {
            s.refresh_at = (lease > 0).then(|| Instant::now() + Duration::from_secs(lease * 2 / 3));
        }
        Ok(())
    }

    pub async fn token(&self) -> Result<String> {
        self.state
            .read()
            .await
            .as_ref()
            .map(|s| s.token.clone())
            .ok_or_else(|| anyhow!("not logged in to Vault"))
    }

    pub async fn is_logged_in(&self) -> bool {
        self.state.read().await.is_some()
    }

    /// Validate an app token and return its identity.
    pub async fn lookup_self(&self, app_token: &str) -> Result<Identity, VaultError> {
        let (_, v) = self
            .send(Method::GET, "auth/token/lookup-self", Some(app_token), None)
            .await?;
        let data = v
            .get("data")
            .ok_or_else(|| anyhow!("lookup-self: no data"))?;
        let display_name = data
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let id = data
            .get("entity_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| format!("entity:{s}"))
            .unwrap_or_else(|| format!("token:{display_name}"));
        Ok(Identity { id, display_name })
    }

    /// Capabilities of an app token on each path.
    pub async fn capabilities_self(
        &self,
        app_token: &str,
        paths: &[String],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        let body = json!({ "paths": paths });
        let (_, v) = self
            .send(
                Method::POST,
                "sys/capabilities-self",
                Some(app_token),
                Some(&body),
            )
            .await?;
        Ok(parse_capabilities(&v, paths))
    }

    pub async fn kv_get(&self, path: &str) -> Result<Option<KvSecret>, VaultError> {
        let token = self.token().await?;
        let api = format!("{}/data/{}", self.kv_mount, path);
        match self.send(Method::GET, &api, Some(&token), None).await {
            Ok((_, v)) => {
                let data = v
                    .pointer("/data/data")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                let version = v
                    .pointer("/data/metadata/version")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                Ok(Some(KvSecret { data, version }))
            }
            Err(VaultError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write a KV v2 secret and return the new version.
    pub async fn kv_put(&self, path: &str, data: &Value) -> Result<u64, VaultError> {
        let token = self.token().await?;
        let api = format!("{}/data/{}", self.kv_mount, path);
        let (_, v) = self
            .send(
                Method::POST,
                &api,
                Some(&token),
                Some(&json!({ "data": data })),
            )
            .await?;
        Ok(v.pointer("/data/version")
            .and_then(Value::as_u64)
            .unwrap_or(0))
    }

    /// Delete a KV v2 secret and all of its versions (metadata delete).
    pub async fn kv_delete(&self, path: &str) -> Result<(), VaultError> {
        let token = self.token().await?;
        let api = format!("{}/metadata/{}", self.kv_mount, path);
        match self.send(Method::DELETE, &api, Some(&token), None).await {
            Ok(_) | Err(VaultError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Read a KV v2 secret whose fields are all strings.
    pub async fn kv_get_strings(&self, path: &str) -> Result<HashMap<String, String>> {
        let secret = self
            .kv_get(path)
            .await?
            .ok_or_else(|| anyhow!("{}/{path} not found in Vault", self.kv_mount))?;
        Ok(secret
            .data
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect())
    }

    pub async fn healthy(&self) -> bool {
        self.send(Method::GET, "sys/health", None, None)
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_multi_path() {
        let body = json!({
            "cert-requests/a.example.com": ["update", "read"],
            "cert-requests/b.example.com": ["deny"],
            "capabilities": ["update", "read"]
        });
        let paths = vec![
            "cert-requests/a.example.com".to_string(),
            "cert-requests/b.example.com".to_string(),
            "cert-requests/c.example.com".to_string(),
        ];
        let caps = parse_capabilities(&body, &paths);
        assert!(allows_update(&caps[&paths[0]]));
        assert!(!allows_update(&caps[&paths[1]]));
        assert!(caps[&paths[2]].is_empty());
    }

    #[test]
    fn capabilities_single_path_union_only() {
        let body = json!({ "data": { "capabilities": ["create", "update"] } });
        let paths = vec!["cert-requests/a.example.com".to_string()];
        assert!(allows_update(&parse_capabilities(&body, &paths)[&paths[0]]));
    }

    #[test]
    fn deny_wins() {
        assert!(!allows_update(&["update".into(), "deny".into()]));
        assert!(allows_update(&["root".into()]));
        assert!(!allows_update(&["read".into(), "list".into()]));
    }
}
