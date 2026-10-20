//! certproxy: an ACME (acme.sh) certificate proxy. Apps authorized by Vault
//! policy request certificates; certproxy issues them via DNS-01 and stores
//! them in Vault KV v2. Admins use a local web UI (password + TOTP).
//!
//! # First launch
//!
//! certproxy has no default account and no built-in password. The first admin
//! enrolls through a one-time link that is delivered through Vault, so their
//! password, TOTP seed and recovery codes are only ever shown to them, in
//! their own browser, and never printed, logged or written to disk:
//!
//! 1. Prepare Vault once with `deploy/vault/setup.sh`. It creates certproxy's
//!    policy and AppRole, stores the Cloudflare token (`secret/certproxy/dns`)
//!    and a random key that encrypts TOTP secrets at rest
//!    (`secret/certproxy/app`).
//! 2. Start the container (`docker compose up -d`). Once logged in to Vault,
//!    certproxy sees that no admin exists and writes a single-use enrollment
//!    link, valid for `INVITE_TTL_MINUTES` (30), to `secret/certproxy/bootstrap`
//!    ([`scheduler::ensure_bootstrap`]). The log shows only the Vault path and
//!    the expiry. If the link expires unused, a new one replaces it.
//! 3. An operator allowed to read that path reads the link:
//!    `vault kv get -field=enrollment_url secret/certproxy/bootstrap`
//! 4. The new admin opens it over HTTPS, chooses a username and password, scans
//!    the QR code with an authenticator app, and confirms one code. Only then
//!    is the admin created. Recovery codes are shown once
//!    (see [`security::begin_enrollment`] and [`security::finish_enrollment`]).
//! 5. certproxy consumes the link and deletes the Vault entry. More admins are
//!    invited from the web UI ("Admins"), with the same kind of one-time link.
//!
//! # Securing the container after first launch
//!
//! 1. Check that the bootstrap entry is gone (`vault kv get` on it must fail)
//!    and revoke any token created just to read it.
//! 2. Switch `ACME_SERVER` from `letsencrypt_test` (staging) to `letsencrypt`.
//! 3. Serve the UI over HTTPS (`TLS_MODE=self` or `files`); use `none` only
//!    behind a TLS-terminating proxy.
//! 4. Bind certproxy's AppRole `secret_id` and tokens to the host
//!    (`secret_id_bound_cidrs`, `token_bound_cidrs`) and rotate the `secret_id`
//!    periodically.
//! 5. Limit who can `docker exec` into the container or read the `/data`
//!    volume (ACME account key, admin database), and restrict who can reach the
//!    web UI (firewall or reverse proxy) while keeping the API reachable for
//!    apps.
//! 6. Invite a second admin for break-glass access, keep recovery codes
//!    offline, and review the audit log regularly.
//!
//! If every admin is locked out, `certproxy admin invite <username> --reset`
//! (run inside the container) writes a fresh one-time link to the same Vault
//! path; nothing secret is printed.

mod acme;
mod api;
mod config;
mod db;
mod scheduler;
mod security;
mod state;
mod vault;
mod web;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{
    acme::Acme,
    config::{Config, TlsMode},
    db::Db,
    state::{AppState, Shared},
    vault::VaultClient,
};

#[derive(Parser)]
#[command(name = "certproxy", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the API, web UI and background workers.
    Serve,
    /// Manage web UI administrators.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Write a one-time enrollment link for an admin to Vault (KV_BOOTSTRAP_PATH).
    /// For break-glass recovery; day to day, invite admins from the web UI.
    /// The link itself is never printed.
    Invite {
        username: String,
        /// Re-enroll an existing admin (new password and authenticator).
        #[arg(long)]
        reset: bool,
    },
    /// Delete an admin (never the last one).
    Delete { username: String },
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("installing rustls crypto provider"))?;

    let cfg = Config::from_env()?;
    match cli.command {
        Command::Serve => serve(cfg).await,
        Command::Admin { command } => admin(cfg, command).await,
    }
}

fn build_state(cfg: Config) -> Result<(Shared, tokio::sync::mpsc::UnboundedReceiver<String>)> {
    let db = Db::open(&cfg.db_path())?;
    let vault = Arc::new(VaultClient::new(&cfg)?);
    let acme = Acme::new(&cfg);
    Ok(AppState::new(cfg, db, vault, acme))
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .merge(api::router())
        .merge(web::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web::security_headers,
        ))
        .with_state(state)
}

async fn serve(cfg: Config) -> Result<()> {
    let listen = cfg.listen;
    let (state, rx) = build_state(cfg)?;

    if let Err(e) = state.vault.login().await {
        tracing::warn!(error = %e, "initial Vault login failed; will keep retrying");
    }
    tokio::spawn(state.vault.clone().maintain_token());
    tokio::spawn(scheduler::load_app_secrets(state.clone()));

    // Resume jobs interrupted by a restart, then start the workers.
    for id in state.db.unfinished_jobs()? {
        state.enqueue(&id);
    }
    tokio::spawn(scheduler::run_worker(state.clone(), rx));
    tokio::spawn(scheduler::run_renewals(state.clone()));

    let handle: Handle<SocketAddr> = Handle::new();
    tokio::spawn(shutdown_on_signal(handle.clone()));
    let service = app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();

    match state.cfg.tls.clone() {
        TlsMode::None => {
            tracing::warn!(%listen, "serving plain HTTP (TLS_MODE=none)");
            axum_server::bind(listen)
                .handle(handle)
                .serve(service)
                .await?;
        }
        TlsMode::Files { cert, key } => {
            let tls = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| {
                    format!("loading TLS files {} / {}", cert.display(), key.display())
                })?;
            tracing::info!(%listen, "serving HTTPS");
            axum_server::bind_rustls(listen, tls)
                .handle(handle)
                .serve(service)
                .await?;
        }
        TlsMode::SelfIssued { hostname } => {
            let (cert, key) = loop {
                if state.vault.is_logged_in().await {
                    match scheduler::ensure_self_tls(&state, &hostname).await {
                        Ok(paths) => break paths,
                        Err(e) => {
                            tracing::error!(error = %format!("{e:#}"), "obtaining UI certificate")
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            };
            let tls = RustlsConfig::from_pem_file(&cert, &key).await?;
            *state
                .tls_reload
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))? = Some(tls.clone());
            tracing::info!(%listen, %hostname, "serving HTTPS with self-issued certificate");
            axum_server::bind_rustls(listen, tls)
                .handle(handle)
                .serve(service)
                .await?;
        }
    }
    Ok(())
}

async fn shutdown_on_signal(handle: Handle<SocketAddr>) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    tracing::info!("shutting down");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

async fn admin(cfg: Config, command: AdminCommand) -> Result<()> {
    let (state, _rx) = build_state(cfg)?;
    let db = &state.db;
    match command {
        AdminCommand::Invite { username, reset } => {
            state.vault.login().await.context("logging in to Vault")?;
            let purpose = if reset { "reset" } else { "create" };
            let (token, expires_at) = security::new_invite(
                db,
                purpose,
                Some(&username),
                "vault",
                "cli",
                state.invite_ttl_secs(),
            )?;
            if let Err(e) = scheduler::deliver_via_vault(&state, &token, expires_at).await {
                db.revoke_invites(None, "vault")?;
                return Err(e);
            }
            db.audit(
                "cli",
                "certproxy",
                "admin-invite",
                &username,
                "success",
                None,
                Some(purpose),
            );
            let path = format!("{}/{}", state.cfg.kv_mount, state.cfg.kv_bootstrap_path);
            println!(
                "One-time enrollment link written to Vault. Read it with:\n  \
                 vault kv get -field=enrollment_url {path}"
            );
        }
        AdminCommand::Delete { username } => {
            let a = db
                .admin_by_username(&username)?
                .ok_or_else(|| anyhow!("no such admin"))?;
            if db.admin_count()? <= 1 {
                bail!("refusing to delete the last admin");
            }
            db.delete_admin(a.id)?;
            db.audit(
                "cli",
                "certproxy",
                "admin-delete",
                &username,
                "success",
                None,
                None,
            );
            println!("admin deleted");
        }
    }
    Ok(())
}
