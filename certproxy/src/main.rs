//! certproxy: an ACME (acme.sh) certificate proxy. Apps authorized by Vault
//! policy request certificates; certproxy issues them via DNS-01 and stores
//! them in Vault KV v2. Admins use a local web UI (password + TOTP).

mod acme;
mod api;
mod config;
mod db;
mod scheduler;
mod security;
mod state;
mod vault;
mod web;

use std::{io::IsTerminal, net::SocketAddr, sync::Arc, time::Duration};

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
    /// Create an admin. Reads the password from stdin and prints the TOTP
    /// enrollment URI and recovery codes.
    Create { username: String },
    /// Issue a new TOTP secret and recovery codes (signs out all sessions).
    ResetTotp { username: String },
    /// List admins.
    List,
    /// Delete an admin.
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

fn read_password() -> Result<String> {
    if std::io::stdin().is_terminal() {
        eprint!("Password (min {} characters): ", security::MIN_PASSWORD_LEN);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn print_enrollment(username: &str, e: &security::Enrollment) {
    println!("Admin: {username}");
    println!("TOTP secret (base32): {}", e.secret_base32);
    println!(
        "TOTP URI (add to your authenticator app):\n  {}",
        e.otpauth_url
    );
    println!("Recovery codes (each works once; store them safely):");
    for c in &e.recovery_codes {
        println!("  {c}");
    }
}

async fn admin(cfg: Config, command: AdminCommand) -> Result<()> {
    let (state, _rx) = build_state(cfg)?;
    let needs_key = matches!(
        command,
        AdminCommand::Create { .. } | AdminCommand::ResetTotp { .. }
    );
    let key = if needs_key {
        state.vault.login().await.context("logging in to Vault")?;
        let fields = state.vault.kv_get_strings(&state.cfg.kv_app_path).await?;
        let b64 = fields.get("totp_key").ok_or_else(|| {
            anyhow!(
                "totp_key missing at {}/{}",
                state.cfg.kv_mount,
                state.cfg.kv_app_path
            )
        })?;
        Some(security::parse_totp_key(b64)?)
    } else {
        None
    };
    let db = &state.db;
    match command {
        AdminCommand::Create { username } => {
            let password = read_password()?;
            let e = security::create_admin(db, &key.unwrap(), &username, &password)?;
            db.audit(
                "cli",
                "certproxy",
                "admin-create",
                &username,
                "success",
                None,
                None,
            );
            print_enrollment(&username, &e);
        }
        AdminCommand::ResetTotp { username } => {
            let a = db
                .admin_by_username(&username)?
                .ok_or_else(|| anyhow!("no admin {username:?}"))?;
            let e = security::reset_totp(db, &key.unwrap(), a.id)?;
            db.audit(
                "cli",
                "certproxy",
                "admin-reset-totp",
                &username,
                "success",
                None,
                None,
            );
            print_enrollment(&username, &e);
        }
        AdminCommand::List => {
            for a in db.admins()? {
                println!("{}\tlast_login={:?}", a.username, a.last_login);
            }
        }
        AdminCommand::Delete { username } => {
            let a = db
                .admin_by_username(&username)?
                .ok_or_else(|| anyhow!("no admin {username:?}"))?;
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
