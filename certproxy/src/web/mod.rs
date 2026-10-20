//! Admin web UI: local accounts with password + TOTP.
//!
//! Login is two steps: password, then a TOTP code (or a one-time recovery
//! code). Sessions are random tokens stored hashed; cookies are HttpOnly,
//! SameSite=Strict and Secure (unless TLS_MODE=none). Every state-changing
//! form carries a per-session CSRF token. Private keys are never displayed.

use std::net::SocketAddr;

use askama::Template;
use axum::{
    Form, Router,
    extract::{ConnectInfo, FromRequestParts, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, macros::format_description};

use crate::{
    db::{Admin, now},
    security,
    state::{RequestOutcome, Shared},
};

const MAX_FAILURES: i64 = 5;
const LOCK_SECS: i64 = 15 * 60;
const PASSWORD_STAGE_SECS: i64 = 5 * 60;
const CSS: &str = include_str!("../../static/app.css");

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login_submit))
        .route("/login/totp", get(totp_page).post(totp_submit))
        .route("/logout", post(logout))
        .route("/certs/{name}", get(cert_detail))
        .route("/certs/{name}/renew", post(cert_renew))
        .route("/jobs", get(jobs_page))
        .route("/audit", get(audit_page))
        .route("/admins", get(admins_page).post(admins_create))
        .route("/admins/{id}/reset-totp", post(admins_reset_totp))
        .route("/admins/{id}/delete", post(admins_delete))
        .route("/account", get(account_page))
        .route("/account/password", post(account_password))
        .route(
            "/static/app.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], CSS) }),
        )
}

/// Security headers for every response (UI and API).
pub async fn security_headers(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    if state.cfg.secure_cookies() {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

// ---- helpers ---------------------------------------------------------------

fn cookie_name(state: &Shared) -> &'static str {
    // The __Host- prefix requires Secure, Path=/ and no Domain.
    if state.cfg.secure_cookies() {
        "__Host-certproxy"
    } else {
        "certproxy"
    }
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn set_cookie(state: &Shared, value: &str, max_age: i64) -> (header::HeaderName, String) {
    let secure = if state.cfg.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    (
        header::SET_COOKIE,
        format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
            cookie_name(state)
        ),
    )
}

/// Create a session of the given stage and return the Set-Cookie header.
fn start_session(
    state: &Shared,
    admin_id: i64,
    stage: &str,
    ttl: i64,
    ip: &str,
) -> anyhow::Result<(header::HeaderName, String)> {
    let token = security::random_token();
    state.db.create_session(
        &security::sha256_hex(&token),
        admin_id,
        &security::random_token(),
        stage,
        now() + ttl,
        Some(ip),
    )?;
    Ok(set_cookie(state, &token, ttl))
}

fn fmt_ts(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| {
            t.format(format_description!(
                "[year]-[month]-[day] [hour]:[minute] UTC"
            ))
            .ok()
        })
        .unwrap_or_else(|| "-".into())
}

fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn internal(e: anyhow::Error) -> Response {
    tracing::error!(error = %format!("{e:#}"), "internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// Shown in the page header of signed-in pages.
pub struct Nav {
    pub username: String,
    pub csrf: String,
}

/// A signed-in admin (session stage `full`).
pub struct AdminCtx {
    pub admin: Admin,
    pub csrf: String,
    pub sid_hash: String,
}

impl AdminCtx {
    fn nav(&self) -> Option<Nav> {
        Some(Nav {
            username: self.admin.username.clone(),
            csrf: self.csrf.clone(),
        })
    }

    fn csrf_ok(&self, token: &str) -> bool {
        bool::from(self.csrf.as_bytes().ct_eq(token.as_bytes()))
    }

    fn actor(&self) -> String {
        format!("admin:{}", self.admin.username)
    }
}

fn csrf_denied() -> Response {
    (StatusCode::FORBIDDEN, "invalid CSRF token").into_response()
}

fn session_for(
    state: &Shared,
    headers: &HeaderMap,
    stage: &str,
) -> Option<(crate::db::Session, String)> {
    let token = read_cookie(headers, cookie_name(state))?;
    let hash = security::sha256_hex(&token);
    let s = state.db.session(&hash).ok().flatten()?;
    (s.stage == stage).then_some((s, hash))
}

impl FromRequestParts<Shared> for AdminCtx {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let login = || Redirect::to("/login").into_response();
        let (session, sid_hash) = session_for(state, &parts.headers, "full").ok_or_else(login)?;
        let admin = state
            .db
            .admin(session.admin_id)
            .ok()
            .flatten()
            .ok_or_else(login)?;
        Ok(AdminCtx {
            admin,
            csrf: session.csrf,
            sid_hash,
        })
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

// ---- templates ---------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl {
    nav: Option<Nav>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "totp.html")]
struct TotpTpl {
    nav: Option<Nav>,
    error: Option<String>,
}

pub struct CertRow {
    pub name: String,
    pub domains: String,
    pub not_after: String,
    pub days_left: i64,
    pub version: i64,
    pub vault_path: String,
    pub serial: String,
    pub issuer: String,
}

pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub status: String,
    pub requester: String,
    pub created: String,
    pub error: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTpl {
    nav: Option<Nav>,
    certs: Vec<CertRow>,
    jobs: Vec<JobRow>,
    renew_before_days: i64,
}

#[derive(Template)]
#[template(path = "cert.html")]
struct CertTpl {
    nav: Option<Nav>,
    cert: CertRow,
    jobs: Vec<JobRow>,
}

#[derive(Template)]
#[template(path = "jobs.html")]
struct JobsTpl {
    nav: Option<Nav>,
    jobs: Vec<JobRow>,
}

pub struct AuditRow {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub ip: String,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTpl {
    nav: Option<Nav>,
    entries: Vec<AuditRow>,
}

pub struct AdminRow {
    pub id: i64,
    pub username: String,
    pub last_login: String,
    pub locked: bool,
    pub is_self: bool,
}

#[derive(Template)]
#[template(path = "admins.html")]
struct AdminsTpl {
    nav: Option<Nav>,
    admins: Vec<AdminRow>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "enrollment.html")]
struct EnrollmentTpl {
    nav: Option<Nav>,
    username: String,
    otpauth_url: String,
    secret: String,
    codes: Vec<String>,
    signed_out: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountTpl {
    nav: Option<Nav>,
    error: Option<String>,
    message: Option<String>,
    recovery_left: i64,
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessageTpl {
    nav: Option<Nav>,
    title: String,
    message: String,
}

fn cert_row(r: crate::db::CertRecord) -> CertRow {
    CertRow {
        days_left: (r.not_after - now()).div_euclid(86_400),
        not_after: fmt_ts(r.not_after),
        domains: r.domains.join(", "),
        name: r.name,
        version: r.vault_version,
        vault_path: r.vault_path,
        serial: r.serial,
        issuer: r.issuer,
    }
}

fn job_row(j: crate::db::Job) -> JobRow {
    JobRow {
        created: fmt_ts(j.created_at),
        error: j.error.unwrap_or_default(),
        id: j.id,
        kind: j.kind,
        name: j.name,
        status: j.status,
        requester: j.requester,
    }
}

// ---- login -----------------------------------------------------------------

async fn login_page(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if session_for(&state, &headers, "full").is_some() {
        return Redirect::to("/").into_response();
    }
    render(&LoginTpl {
        nav: None,
        error: None,
    })
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = peer.ip().to_string();
    if state.totp_key().is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            render(&LoginTpl {
                nav: None,
                error: Some("Not ready: waiting for Vault.".into()),
            }),
        )
            .into_response();
    }
    let username = form.username.trim().to_ascii_lowercase();
    let admin = match state.db.admin_by_username(&username) {
        Ok(a) => a,
        Err(e) => return internal(e),
    };
    let hash = admin
        .as_ref()
        .map(|a| a.password_hash.clone())
        .unwrap_or_else(|| security::dummy_hash().into());
    let password = form.password;
    let ok = tokio::task::spawn_blocking(move || security::verify_password(&password, &hash))
        .await
        .unwrap_or(false);

    match admin {
        Some(a) if ok && a.locked_until <= now() => {
            match start_session(&state, a.id, "password", PASSWORD_STAGE_SECS, &ip) {
                Ok(cookie) => {
                    state.db.audit(
                        "admin",
                        &username,
                        "login-password",
                        &username,
                        "success",
                        Some(&ip),
                        None,
                    );
                    ([cookie], Redirect::to("/login/totp")).into_response()
                }
                Err(e) => internal(e),
            }
        }
        other => {
            if let Some(a) = &other
                && a.locked_until <= now()
            {
                let _ = state.db.record_login_failure(a.id, MAX_FAILURES, LOCK_SECS);
            }
            let result = if other.as_ref().is_some_and(|a| a.locked_until > now()) {
                "locked"
            } else {
                "failure"
            };
            state.db.audit(
                "admin",
                &username,
                "login-password",
                &username,
                result,
                Some(&ip),
                None,
            );
            (
                StatusCode::UNAUTHORIZED,
                render(&LoginTpl {
                    nav: None,
                    error: Some(
                        "Invalid credentials, or the account is temporarily locked.".into(),
                    ),
                }),
            )
                .into_response()
        }
    }
}

async fn totp_page(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if session_for(&state, &headers, "password").is_none() {
        return Redirect::to("/login").into_response();
    }
    render(&TotpTpl {
        nav: None,
        error: None,
    })
}

#[derive(Deserialize)]
struct TotpForm {
    code: String,
}

async fn totp_submit(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TotpForm>,
) -> Response {
    let ip = peer.ip().to_string();
    let Some((session, sid_hash)) = session_for(&state, &headers, "password") else {
        return Redirect::to("/login").into_response();
    };
    let (Some(key), Ok(Some(admin))) = (state.totp_key(), state.db.admin(session.admin_id)) else {
        return Redirect::to("/login").into_response();
    };
    if admin.locked_until > now() {
        let _ = state.db.delete_session(&sid_hash);
        return Redirect::to("/login").into_response();
    }

    let code = form.code.trim();
    let is_recovery = code.chars().any(|c| c.is_ascii_alphabetic());
    let ok = if is_recovery {
        let hash = security::sha256_hex(&security::normalize_recovery_code(code));
        state.db.use_recovery_code(admin.id, &hash).unwrap_or(false)
    } else {
        security::verify_totp(&state.db, &key, admin.id, code).unwrap_or(false)
    };
    let action = if is_recovery {
        "login-recovery-code"
    } else {
        "login-totp"
    };

    if ok {
        let _ = state.db.delete_session(&sid_hash);
        let _ = state.db.record_login_success(admin.id);
        match start_session(
            &state,
            admin.id,
            "full",
            state.cfg.session_hours * 3600,
            &ip,
        ) {
            Ok(cookie) => {
                state.db.audit(
                    "admin",
                    &admin.username,
                    action,
                    &admin.username,
                    "success",
                    Some(&ip),
                    None,
                );
                ([cookie], Redirect::to("/")).into_response()
            }
            Err(e) => internal(e),
        }
    } else {
        let _ = state
            .db
            .record_login_failure(admin.id, MAX_FAILURES, LOCK_SECS);
        state.db.audit(
            "admin",
            &admin.username,
            action,
            &admin.username,
            "failure",
            Some(&ip),
            None,
        );
        if state
            .db
            .admin(admin.id)
            .ok()
            .flatten()
            .is_some_and(|a| a.locked_until > now())
        {
            let _ = state.db.delete_session(&sid_hash);
            return Redirect::to("/login").into_response();
        }
        (
            StatusCode::UNAUTHORIZED,
            render(&TotpTpl {
                nav: None,
                error: Some("Invalid code.".into()),
            }),
        )
            .into_response()
    }
}

async fn logout(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let _ = state.db.delete_session(&ctx.sid_hash);
    let ip = peer.ip().to_string();
    state.db.audit(
        "admin",
        &ctx.admin.username,
        "logout",
        &ctx.admin.username,
        "success",
        Some(&ip),
        None,
    );
    ([set_cookie(&state, "", 0)], Redirect::to("/login")).into_response()
}

// ---- pages -------------------------------------------------------------------

async fn dashboard(State(state): State<Shared>, ctx: AdminCtx) -> Response {
    let (certs, jobs) = match (state.db.certificates(), state.db.jobs(10)) {
        (Ok(c), Ok(j)) => (c, j),
        (Err(e), _) | (_, Err(e)) => return internal(e),
    };
    render(&DashboardTpl {
        nav: ctx.nav(),
        certs: certs.into_iter().map(cert_row).collect(),
        jobs: jobs.into_iter().map(job_row).collect(),
        renew_before_days: state.cfg.renew_before_days,
    })
}

fn not_found(nav: Option<Nav>) -> Response {
    (
        StatusCode::NOT_FOUND,
        render(&MessageTpl {
            nav,
            title: "Not found".into(),
            message: "No such certificate.".into(),
        }),
    )
        .into_response()
}

async fn cert_detail(
    State(state): State<Shared>,
    ctx: AdminCtx,
    Path(name): Path<String>,
) -> Response {
    match state.db.certificate(&name) {
        Ok(Some(rec)) => {
            let jobs = state.db.jobs_for_name(&name, 20).unwrap_or_default();
            render(&CertTpl {
                nav: ctx.nav(),
                cert: cert_row(rec),
                jobs: jobs.into_iter().map(job_row).collect(),
            })
        }
        Ok(None) => not_found(ctx.nav()),
        Err(e) => internal(e),
    }
}

async fn cert_renew(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let rec = match state.db.certificate(&name) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(ctx.nav()),
        Err(e) => return internal(e),
    };
    let ip = peer.ip().to_string();
    match state.request_certificate(&rec.domains, "renew", &ctx.actor(), true) {
        Ok(RequestOutcome::Queued(job)) => {
            state.db.audit(
                "admin",
                &ctx.admin.username,
                "renew",
                &name,
                "queued",
                Some(&ip),
                Some(&job.id),
            );
            Redirect::to("/jobs").into_response()
        }
        Ok(RequestOutcome::Existing(_)) => Redirect::to("/jobs").into_response(),
        Err(e) => internal(e),
    }
}

async fn jobs_page(State(state): State<Shared>, ctx: AdminCtx) -> Response {
    match state.db.jobs(100) {
        Ok(jobs) => render(&JobsTpl {
            nav: ctx.nav(),
            jobs: jobs.into_iter().map(job_row).collect(),
        }),
        Err(e) => internal(e),
    }
}

async fn audit_page(State(state): State<Shared>, ctx: AdminCtx) -> Response {
    match state.db.audit_entries(200) {
        Ok(entries) => render(&AuditTpl {
            nav: ctx.nav(),
            entries: entries
                .into_iter()
                .map(|e| AuditRow {
                    ts: fmt_ts(e.ts),
                    actor: format!("{}:{}", e.actor_kind, e.actor),
                    action: e.action,
                    target: e.target,
                    result: e.result,
                    ip: e.ip.unwrap_or_default(),
                    detail: e.detail.unwrap_or_default(),
                })
                .collect(),
        }),
        Err(e) => internal(e),
    }
}

fn admins_tpl(state: &Shared, ctx: &AdminCtx, error: Option<String>) -> Response {
    match state.db.admins() {
        Ok(admins) => render(&AdminsTpl {
            nav: ctx.nav(),
            admins: admins
                .into_iter()
                .map(|a| AdminRow {
                    is_self: a.id == ctx.admin.id,
                    locked: a.locked_until > now(),
                    last_login: a.last_login.map(fmt_ts).unwrap_or_else(|| "never".into()),
                    id: a.id,
                    username: a.username,
                })
                .collect(),
            error,
        }),
        Err(e) => internal(e),
    }
}

async fn admins_page(State(state): State<Shared>, ctx: AdminCtx) -> Response {
    admins_tpl(&state, &ctx, None)
}

#[derive(Deserialize)]
struct CreateAdminForm {
    csrf: String,
    username: String,
    password: String,
}

async fn admins_create(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Form(form): Form<CreateAdminForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let Some(key) = state.totp_key() else {
        return admins_tpl(&state, &ctx, Some("Not ready: waiting for Vault.".into()));
    };
    let username = form.username.trim().to_ascii_lowercase();
    let ip = peer.ip().to_string();
    match security::create_admin(&state.db, &key, &username, &form.password) {
        Ok(e) => {
            state.db.audit(
                "admin",
                &ctx.admin.username,
                "admin-create",
                &username,
                "success",
                Some(&ip),
                None,
            );
            render(&EnrollmentTpl {
                nav: ctx.nav(),
                username,
                otpauth_url: e.otpauth_url,
                secret: e.secret_base32,
                codes: e.recovery_codes,
                signed_out: false,
            })
        }
        Err(e) => admins_tpl(&state, &ctx, Some(e.to_string())),
    }
}

async fn admins_reset_totp(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let Some(key) = state.totp_key() else {
        return admins_tpl(&state, &ctx, Some("Not ready: waiting for Vault.".into()));
    };
    let target = match state.db.admin(id) {
        Ok(Some(a)) => a,
        Ok(None) => return admins_tpl(&state, &ctx, Some("No such admin.".into())),
        Err(e) => return internal(e),
    };
    let ip = peer.ip().to_string();
    match security::reset_totp(&state.db, &key, id) {
        Ok(e) => {
            state.db.audit(
                "admin",
                &ctx.admin.username,
                "admin-reset-totp",
                &target.username,
                "success",
                Some(&ip),
                None,
            );
            let signed_out = id == ctx.admin.id;
            render(&EnrollmentTpl {
                nav: if signed_out { None } else { ctx.nav() },
                username: target.username,
                otpauth_url: e.otpauth_url,
                secret: e.secret_base32,
                codes: e.recovery_codes,
                signed_out,
            })
        }
        Err(e) => internal(e),
    }
}

async fn admins_delete(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    if id == ctx.admin.id {
        return admins_tpl(
            &state,
            &ctx,
            Some("You can't delete your own account.".into()),
        );
    }
    let target = match state.db.admin(id) {
        Ok(Some(a)) => a,
        Ok(None) => return admins_tpl(&state, &ctx, Some("No such admin.".into())),
        Err(e) => return internal(e),
    };
    if let Err(e) = state.db.delete_admin(id) {
        return internal(e);
    }
    let ip = peer.ip().to_string();
    state.db.audit(
        "admin",
        &ctx.admin.username,
        "admin-delete",
        &target.username,
        "success",
        Some(&ip),
        None,
    );
    Redirect::to("/admins").into_response()
}

fn account_tpl(
    state: &Shared,
    ctx: &AdminCtx,
    error: Option<String>,
    message: Option<String>,
) -> Response {
    render(&AccountTpl {
        nav: ctx.nav(),
        error,
        message,
        recovery_left: state.db.unused_recovery_codes(ctx.admin.id).unwrap_or(0),
    })
}

async fn account_page(State(state): State<Shared>, ctx: AdminCtx) -> Response {
    account_tpl(&state, &ctx, None, None)
}

#[derive(Deserialize)]
struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    confirm: String,
}

async fn account_password(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Form(form): Form<PasswordForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let hash = ctx.admin.password_hash.clone();
    let current = form.current.clone();
    let ok = tokio::task::spawn_blocking(move || security::verify_password(&current, &hash))
        .await
        .unwrap_or(false);
    let ip = peer.ip().to_string();
    if !ok {
        state.db.audit(
            "admin",
            &ctx.admin.username,
            "password-change",
            &ctx.admin.username,
            "failure",
            Some(&ip),
            None,
        );
        return account_tpl(
            &state,
            &ctx,
            Some("Current password is wrong.".into()),
            None,
        );
    }
    if form.new != form.confirm {
        return account_tpl(
            &state,
            &ctx,
            Some("New passwords don't match.".into()),
            None,
        );
    }
    if let Err(e) = security::check_password_policy(&form.new) {
        return account_tpl(&state, &ctx, Some(e.to_string()), None);
    }
    let new = form.new;
    let hashed = match tokio::task::spawn_blocking(move || security::hash_password(&new)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e.into()),
    };
    if let Err(e) = state.db.set_password(ctx.admin.id, &hashed) {
        return internal(e);
    }
    state.db.audit(
        "admin",
        &ctx.admin.username,
        "password-change",
        &ctx.admin.username,
        "success",
        Some(&ip),
        None,
    );
    account_tpl(&state, &ctx, None, Some("Password changed.".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; certproxy=tok; b=2".parse().unwrap());
        assert_eq!(read_cookie(&h, "certproxy").as_deref(), Some("tok"));
        assert_eq!(read_cookie(&h, "missing"), None);
    }

    mod http {
        use std::net::SocketAddr;

        use axum::{
            body::Body,
            extract::connect_info::MockConnectInfo,
            http::{Request, StatusCode, header},
        };
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use crate::{security, state::tests::test_state};

        const PASSWORD: &str = "a long enough password";

        fn app(state: crate::state::Shared) -> axum::Router {
            crate::app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
        }

        async fn send(
            app: &axum::Router,
            method: &str,
            uri: &str,
            cookie: Option<&str>,
            form: Option<&str>,
        ) -> (StatusCode, Option<String>, Option<String>, String) {
            let mut req = Request::builder().method(method).uri(uri);
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            let body = match form {
                Some(f) => {
                    req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                    Body::from(f.to_string())
                }
                None => Body::empty(),
            };
            let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
            let status = resp.status();
            let header_str = |name| {
                resp.headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let location = header_str(header::LOCATION);
            let cookie =
                header_str(header::SET_COOKIE).map(|c| c.split(';').next().unwrap().to_string());
            let body = String::from_utf8(
                resp.into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap();
            (status, location, cookie, body)
        }

        fn setup() -> (crate::state::Shared, axum::Router, security::Enrollment) {
            let (state, _rx) = test_state();
            let key = security::random_bytes::<32>();
            state.set_totp_key(key);
            let e = security::create_admin(&state.db, &key, "alice", PASSWORD).unwrap();
            let app = app(state.clone());
            (state, app, e)
        }

        fn code_for(e: &security::Enrollment) -> String {
            let secret = totp_rs::Secret::try_from_base32(&e.secret_base32).unwrap();
            security::totp_for(secret.as_bytes().to_vec(), "alice")
                .unwrap()
                .generate_current()
                .to_string()
        }

        fn csrf_from(body: &str) -> String {
            let marker = "name=\"csrf\" value=\"";
            let start = body.find(marker).expect("csrf field") + marker.len();
            body[start..start + body[start..].find('"').unwrap()].to_string()
        }

        #[tokio::test]
        async fn password_then_totp_login() {
            let (_state, app, e) = setup();

            let (st, loc, _, _) = send(&app, "GET", "/", None, None).await;
            assert_eq!(
                (st, loc.as_deref()),
                (StatusCode::SEE_OTHER, Some("/login"))
            );

            let form = format!("username=alice&password={}", PASSWORD.replace(' ', "+"));
            let (st, loc, pw_cookie, _) = send(&app, "POST", "/login", None, Some(&form)).await;
            assert_eq!(
                (st, loc.as_deref()),
                (StatusCode::SEE_OTHER, Some("/login/totp"))
            );
            let pw_cookie = pw_cookie.expect("password-stage cookie");

            // A password-stage session is not enough for the UI.
            let (st, loc, _, _) = send(&app, "GET", "/", Some(&pw_cookie), None).await;
            assert_eq!(
                (st, loc.as_deref()),
                (StatusCode::SEE_OTHER, Some("/login"))
            );

            let (st, _, _, _) = send(
                &app,
                "POST",
                "/login/totp",
                Some(&pw_cookie),
                Some("code=000000"),
            )
            .await;
            assert!(st == StatusCode::UNAUTHORIZED || code_for(&e) == "000000");

            let form = format!("code={}", code_for(&e));
            let (st, loc, full_cookie, _) =
                send(&app, "POST", "/login/totp", Some(&pw_cookie), Some(&form)).await;
            assert_eq!((st, loc.as_deref()), (StatusCode::SEE_OTHER, Some("/")));
            let full_cookie = full_cookie.expect("session cookie");

            let (st, _, _, body) = send(&app, "GET", "/", Some(&full_cookie), None).await;
            assert_eq!(st, StatusCode::OK);
            assert!(body.contains("<h1>Certificates</h1>"));

            // State-changing requests need the session's CSRF token.
            let (st, _, _, _) = send(
                &app,
                "POST",
                "/logout",
                Some(&full_cookie),
                Some("csrf=wrong"),
            )
            .await;
            assert_eq!(st, StatusCode::FORBIDDEN);
            let form = format!("csrf={}", csrf_from(&body));
            let (st, loc, _, _) =
                send(&app, "POST", "/logout", Some(&full_cookie), Some(&form)).await;
            assert_eq!(
                (st, loc.as_deref()),
                (StatusCode::SEE_OTHER, Some("/login"))
            );
            let (st, _, _, _) = send(&app, "GET", "/", Some(&full_cookie), None).await;
            assert_eq!(
                st,
                StatusCode::SEE_OTHER,
                "session must be gone after logout"
            );
        }

        #[tokio::test]
        async fn recovery_code_login_and_lockout() {
            let (state, app, e) = setup();
            let form = format!("username=alice&password={}", PASSWORD.replace(' ', "+"));
            let (_, _, pw_cookie, _) = send(&app, "POST", "/login", None, Some(&form)).await;
            let rc = format!("code={}", e.recovery_codes[0]);
            let (st, loc, _, _) =
                send(&app, "POST", "/login/totp", pw_cookie.as_deref(), Some(&rc)).await;
            assert_eq!((st, loc.as_deref()), (StatusCode::SEE_OTHER, Some("/")));

            for _ in 0..5 {
                let (st, _, _, _) = send(
                    &app,
                    "POST",
                    "/login",
                    None,
                    Some("username=alice&password=wrong"),
                )
                .await;
                assert_eq!(st, StatusCode::UNAUTHORIZED);
            }
            let (st, _, cookie, _) = send(&app, "POST", "/login", None, Some(&form)).await;
            assert_eq!(
                st,
                StatusCode::UNAUTHORIZED,
                "correct password must fail while locked"
            );
            assert!(cookie.is_none());
            let audit = state.db.audit_entries(50).unwrap();
            assert!(audit.iter().any(|a| a.result == "locked"));
            assert!(
                audit
                    .iter()
                    .any(|a| a.action == "login-recovery-code" && a.result == "success")
            );
        }

        #[tokio::test]
        async fn unknown_user_and_headers() {
            let (_state, app, _) = setup();
            let (st, _, cookie, body) = send(
                &app,
                "POST",
                "/login",
                None,
                Some("username=nobody&password=whatever"),
            )
            .await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
            assert!(cookie.is_none());
            assert!(body.contains("Invalid credentials"));

            let req = Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let h = resp.headers();
            assert!(
                h[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("frame-ancestors 'none'")
            );
            assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(h[header::CACHE_CONTROL], "no-store");
        }

        #[tokio::test]
        async fn api_rejects_before_vault() {
            let (_state, app, _) = setup();
            let call = |token: Option<&str>, body: &str| {
                let mut req = Request::builder()
                    .method("POST")
                    .uri("/api/v1/certificates")
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(t) = token {
                    req = req.header("x-vault-token", t);
                }
                app.clone()
                    .oneshot(req.body(Body::from(body.to_string())).unwrap())
            };
            let resp = call(None, r#"{"domains":["a.example.com"]}"#)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let resp = call(Some("t"), r#"{"domains":["--issue"]}"#).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let resp = call(Some("t"), r#"{"domains":[]}"#).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }
}
