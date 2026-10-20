//! Background tasks: the issuance worker, the renewal loop, loading
//! certproxy's own secrets from Vault, and session cleanup.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, anyhow};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use crate::{
    acme::storage_name,
    config::TlsMode,
    db::{CertRecord, now, renewal_due},
    security::{self, parse_totp_key},
    state::{RequestOutcome, Shared},
};

/// Issue a certificate with acme.sh and store it in Vault and the local index.
pub async fn issue_and_store(state: &Shared, domains: &[String]) -> Result<CertRecord> {
    let name = storage_name(&domains[0]);
    let dns_env = state
        .vault
        .kv_get_strings(&state.cfg.kv_dns_path)
        .await
        .context("loading DNS provider credentials from Vault")?;
    let issued = state.acme.issue(domains, &dns_env).await?;
    let fmt = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    let data = json!({
        "certificate": issued.cert_pem,
        "private_key": issued.key_pem,
        "chain": issued.chain_pem,
        "fullchain": issued.fullchain_pem,
        "domains": domains,
        "not_before": fmt(issued.info.not_before),
        "not_after": fmt(issued.info.not_after),
        "serial": issued.info.serial,
        "issuer": issued.info.issuer,
        "issued_by": concat!("certproxy/", env!("CARGO_PKG_VERSION")),
    });
    let version = state
        .vault
        .kv_put(&state.kv_cert_path(&name), &data)
        .await
        .map_err(|e| anyhow!("storing certificate in Vault: {e}"))?;
    let rec = CertRecord {
        name: name.clone(),
        domains: domains.to_vec(),
        vault_path: state.vault_api_path(&name),
        vault_version: version as i64,
        not_before: issued.info.not_before.unix_timestamp(),
        not_after: issued.info.not_after.unix_timestamp(),
        serial: issued.info.serial.clone(),
        issuer: issued.info.issuer.clone(),
        updated_at: now(),
    };
    state.db.upsert_certificate(&rec)?;

    if let TlsMode::SelfIssued { hostname } = &state.cfg.tls
        && storage_name(hostname) == name
    {
        write_tls_files(state, &issued.fullchain_pem, &issued.key_pem).await?;
    }
    Ok(rec)
}

fn tls_paths(state: &Shared) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = state.cfg.data_dir.join("tls");
    (dir.join("cert.pem"), dir.join("key.pem"))
}

/// Write the UI certificate (self-issued mode) and hot-reload it if serving.
async fn write_tls_files(state: &Shared, fullchain: &str, key: &str) -> Result<()> {
    let (cert_path, key_path) = tls_paths(state);
    if let Some(dir) = cert_path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    write_private(&key_path, key.as_bytes()).await?;
    tokio::fs::write(&cert_path, fullchain).await?;
    let reload = state.tls_reload.lock().ok().and_then(|g| g.clone());
    if let Some(cfg) = reload {
        cfg.reload_from_pem_file(&cert_path, &key_path).await?;
        tracing::info!("reloaded UI TLS certificate");
    }
    Ok(())
}

async fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.to_path_buf();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(&data)?;
        Ok(())
    })
    .await?
}

/// In `TLS_MODE=self`, make sure a valid UI certificate is on disk before
/// serving: reuse the one in Vault if it is still valid, otherwise issue one.
pub async fn ensure_self_tls(
    state: &Shared,
    hostname: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let paths = tls_paths(state);
    let name = storage_name(hostname);
    if let Some(secret) = state.vault.kv_get(&state.kv_cert_path(&name)).await? {
        let field = |k: &str| {
            secret
                .data
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        if let (Some(full), Some(key)) = (field("fullchain"), field("private_key"))
            && let Ok(info) = crate::acme::parse_cert(&full)
            && !renewal_due(
                info.not_before.unix_timestamp(),
                info.not_after.unix_timestamp(),
                now(),
                state.renew_before_secs(),
            )
        {
            write_tls_files(state, &full, &key).await?;
            return Ok(paths);
        }
    }
    tracing::info!(%hostname, "issuing UI certificate");
    issue_and_store(state, &[hostname.to_string()]).await?;
    Ok(paths)
}

/// Process queued jobs one at a time.
pub async fn run_worker(state: Shared, mut rx: mpsc::UnboundedReceiver<String>) {
    while let Some(id) = rx.recv().await {
        let job = match state.db.job(&id) {
            Ok(Some(j)) if j.status == "queued" || j.status == "running" => j,
            Ok(_) => continue,
            Err(e) => {
                tracing::error!(error = %e, job = %id, "loading job");
                continue;
            }
        };
        let _ = state.db.job_started(&id);
        tracing::info!(job = %id, name = %job.name, kind = %job.kind, "job started");
        match issue_and_store(&state, &job.domains).await {
            Ok(rec) => {
                let _ = state.db.job_finished(
                    &id,
                    "succeeded",
                    Some(&rec.vault_path),
                    Some(rec.vault_version),
                    None,
                );
                state.db.audit(
                    "system",
                    "certproxy",
                    &job.kind,
                    &job.name,
                    "success",
                    None,
                    Some(&format!("vault version {}; job {id}", rec.vault_version)),
                );
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(job = %id, error = %msg, "job failed");
                let _ = state.db.job_finished(&id, "failed", None, None, Some(&msg));
                state.db.audit(
                    "system",
                    "certproxy",
                    &job.kind,
                    &job.name,
                    "failure",
                    None,
                    Some(&id),
                );
            }
        }
    }
}

/// Periodically queue renewals for certificates close to expiry.
pub async fn run_renewals(state: Shared) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        match state.db.certificates_due(now(), state.renew_before_secs()) {
            Ok(due) => {
                for rec in due {
                    match state.request_certificate(&rec.domains, "renew", "system:renewal", true) {
                        Ok(RequestOutcome::Queued(job)) => {
                            tracing::info!(name = %rec.name, job = %job.id, "renewal queued")
                        }
                        Ok(RequestOutcome::Existing(_)) => {}
                        Err(e) => tracing::error!(name = %rec.name, error = %e, "queueing renewal"),
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "listing certificates due for renewal"),
        }
        let _ = state.db.purge_expired_sessions();
        tokio::time::sleep(state.cfg.renew_interval).await;
    }
}

/// Load certproxy's own secrets from Vault, retrying until it works, then
/// run the first-launch bootstrap until the first admin has enrolled.
pub async fn load_app_secrets(state: Shared) {
    loop {
        if state.vault.is_logged_in().await {
            match state.vault.kv_get_strings(&state.cfg.kv_app_path).await {
                Ok(fields) => match fields.get("totp_key").map(|k| parse_totp_key(k)) {
                    Some(Ok(key)) => {
                        state.set_totp_key(key);
                        tracing::info!("loaded certproxy secrets from Vault");
                        break;
                    }
                    Some(Err(e)) => tracing::error!(error = %e, "invalid totp_key in Vault"),
                    None => {
                        tracing::error!(path = %state.cfg.kv_app_path, "totp_key missing in Vault")
                    }
                },
                Err(e) => tracing::warn!(error = %e, "reading certproxy secrets from Vault"),
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    loop {
        match ensure_bootstrap(&state).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => tracing::error!(error = %format!("{e:#}"), "first-launch bootstrap"),
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Write a one-time enrollment link to Vault for an operator to pick up.
///
/// Used on first launch and by `certproxy admin invite`. The link is never
/// printed or logged: only people allowed to read this Vault path (see
/// `deploy/vault/bootstrap-reader-policy.example.hcl`) can use it. certproxy
/// deletes the entry as soon as the enrollment completes.
pub async fn deliver_via_vault(state: &Shared, token: &str, expires_at: i64) -> Result<()> {
    let expires = time::OffsetDateTime::from_unix_timestamp(expires_at)?.format(&Rfc3339)?;
    let note = match state.cfg.base_url() {
        Some(_) => "Open enrollment_url in a browser before expires_at. It works once.".to_string(),
        None => "Append enrollment_url to certproxy's address (set PUBLIC_URL to get a full URL). \
                 It works once, before expires_at."
            .to_string(),
    };
    let data = json!({
        "enrollment_url": state.enroll_link(token),
        "expires_at": expires,
        "note": note,
    });
    state
        .vault
        .kv_put(&state.cfg.kv_bootstrap_path, &data)
        .await
        .map_err(|e| anyhow!("writing enrollment link to Vault: {e}"))?;
    Ok(())
}

/// First launch: while no admin exists, keep exactly one valid bootstrap
/// enrollment link in Vault (replacing it when it expires unused). Returns
/// `true` once an admin exists and bootstrapping is over.
pub async fn ensure_bootstrap(state: &Shared) -> Result<bool> {
    if state.db.admin_count()? > 0 {
        return Ok(true);
    }
    if state.db.open_bootstrap_invite()?.is_some() {
        return Ok(false);
    }
    let (token, expires_at) = security::new_invite(
        &state.db,
        "bootstrap",
        None,
        "vault",
        "system:first-launch",
        state.invite_ttl_secs(),
    )?;
    if let Err(e) = deliver_via_vault(state, &token, expires_at).await {
        state.db.revoke_invites(None, "vault")?;
        return Err(e);
    }
    let path = format!("{}/{}", state.cfg.kv_mount, state.cfg.kv_bootstrap_path);
    state.db.audit(
        "system",
        "certproxy",
        "bootstrap-invite",
        &path,
        "success",
        None,
        None,
    );
    tracing::warn!(
        vault_path = %path,
        expires_at,
        "no admin exists yet: a one-time enrollment link was written to Vault. \
         Read it with `vault kv get -field=enrollment_url {path}` and open it in a browser"
    );
    Ok(false)
}
