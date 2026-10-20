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
        .route("/admins/{id}/reenroll", post(admins_reenroll))
        .route("/admins/{id}/delete", post(admins_delete))
        .route("/enroll/{token}", get(enroll_page).post(enroll_submit))
        .route("/enroll/{token}/confirm", post(enroll_confirm))
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

/// Shown once to the admin who created an invite, so they can pass the
/// link on (out of band) to the person it is for.
#[derive(Template)]
#[template(path = "invite.html")]
struct InviteTpl {
    nav: Option<Nav>,
    username: String,
    purpose: String,
    link: String,
    expires: String,
}

#[derive(Template)]
#[template(path = "enroll.html")]
struct EnrollTpl {
    nav: Option<Nav>,
    token: String,
    /// Fixed username (named invites); `None` lets the person choose one.
    username: Option<String>,
    reset: bool,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "enroll_totp.html")]
struct EnrollTotpTpl {
    nav: Option<Nav>,
    token: String,
    username: String,
    qr_svg: String,
    secret: String,
    otpauth_url: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "enroll_done.html")]
struct EnrollDoneTpl {
    nav: Option<Nav>,
    username: String,
    codes: Vec<String>,
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
struct InviteForm {
    csrf: String,
    username: String,
}

/// Create a one-time enrollment link for a new or existing admin and show it
/// to the inviting admin. The inviter never sees the other person's password,
/// TOTP seed or recovery codes: those exist only in the invitee's browser.
async fn issue_invite(
    state: &Shared,
    ctx: &AdminCtx,
    ip: &str,
    purpose: &str,
    username: &str,
) -> Response {
    let action = if purpose == "reset" {
        "admin-reenroll-invite"
    } else {
        "admin-invite"
    };
    match security::new_invite(
        &state.db,
        purpose,
        Some(username),
        "ui",
        &ctx.actor(),
        state.invite_ttl_secs(),
    ) {
        Ok((token, expires_at)) => {
            state.db.audit(
                "admin",
                &ctx.admin.username,
                action,
                username,
                "success",
                Some(ip),
                None,
            );
            render(&InviteTpl {
                nav: ctx.nav(),
                username: username.to_string(),
                purpose: purpose.to_string(),
                link: state.enroll_link(&token),
                expires: fmt_ts(expires_at),
            })
        }
        Err(e) => admins_tpl(state, ctx, Some(e.to_string())),
    }
}

async fn admins_create(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Form(form): Form<InviteForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    let username = form.username.trim().to_ascii_lowercase();
    issue_invite(&state, &ctx, &peer.ip().to_string(), "create", &username).await
}

/// Re-enrollment link for an existing admin (lost authenticator or forgotten
/// password). Their current credentials keep working until it is completed,
/// which then replaces them and signs out all of that admin's sessions.
async fn admins_reenroll(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ctx: AdminCtx,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !ctx.csrf_ok(&form.csrf) {
        return csrf_denied();
    }
    match state.db.admin(id) {
        Ok(Some(a)) => {
            issue_invite(&state, &ctx, &peer.ip().to_string(), "reset", &a.username).await
        }
        Ok(None) => admins_tpl(&state, &ctx, Some("No such admin.".into())),
        Err(e) => internal(e),
    }
}

// ---- enrollment (public, authorized by the one-time token) ------------------

fn invite_gone() -> Response {
    (
        StatusCode::GONE,
        render(&MessageTpl {
            nav: None,
            title: "Link not valid".into(),
            message: "This enrollment link has expired, was already used, or had too many \
                      wrong codes. Ask an admin for a new one (on first launch, certproxy \
                      writes a new link to Vault automatically)."
                .into(),
        }),
    )
        .into_response()
}

fn enroll_error(e: security::EnrollError, retry: impl FnOnce(String) -> Response) -> Response {
    match e {
        security::EnrollError::Invalid => invite_gone(),
        security::EnrollError::User(msg) => retry(msg),
        security::EnrollError::Internal(e) => internal(e),
    }
}

/// Step 1: choose a username (first launch only) and a password.
async fn enroll_page(State(state): State<Shared>, Path(token): Path<String>) -> Response {
    match security::invite_for(&state.db, &token) {
        Ok(Some(inv)) => render(&EnrollTpl {
            nav: None,
            token,
            reset: inv.purpose == "reset",
            username: inv.username,
            error: None,
        }),
        Ok(None) => invite_gone(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct EnrollForm {
    #[serde(default)]
    username: String,
    password: String,
    confirm: String,
}

/// Step 2: show the new TOTP secret (QR code and base32) to the person
/// enrolling, and ask for a code to prove their authenticator is set up.
async fn enroll_submit(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Form(form): Form<EnrollForm>,
) -> Response {
    let Some(key) = state.totp_key() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Not ready: waiting for Vault.",
        )
            .into_response();
    };
    let retry = |msg: String| {
        let inv = security::invite_for(&state.db, &token).ok().flatten();
        let (username, reset) = inv
            .map(|i| (i.username, i.purpose == "reset"))
            .unwrap_or((None, false));
        (
            StatusCode::BAD_REQUEST,
            render(&EnrollTpl {
                nav: None,
                token: token.clone(),
                username,
                reset,
                error: Some(msg),
            }),
        )
            .into_response()
    };
    if form.password != form.confirm {
        return retry("Passwords don't match.".into());
    }
    let (t, u, pw) = (token.clone(), form.username.clone(), form.password.clone());
    let st = state.clone();
    let result =
        tokio::task::spawn_blocking(move || security::begin_enrollment(&st.db, &key, &t, &u, &pw))
            .await
            .unwrap_or_else(|e| Err(security::EnrollError::Internal(e.into())));
    match result {
        Ok(p) => {
            let ip = peer.ip().to_string();
            state.db.audit(
                "enroll",
                &p.username,
                "enroll-start",
                &p.username,
                "success",
                Some(&ip),
                None,
            );
            render(&EnrollTotpTpl {
                nav: None,
                token,
                username: p.username,
                qr_svg: p.qr_svg,
                secret: p.secret_base32,
                otpauth_url: p.otpauth_url,
                error: None,
            })
        }
        Err(e) => enroll_error(e, retry),
    }
}

#[derive(Deserialize)]
struct ConfirmForm {
    code: String,
}

/// Step 3: check the code, create (or re-enroll) the admin, show the recovery
/// codes once, and delete the Vault copy of the link if there was one.
async fn enroll_confirm(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Some(key) = state.totp_key() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Not ready: waiting for Vault.",
        )
            .into_response();
    };
    let ip = peer.ip().to_string();
    match security::finish_enrollment(&state.db, &key, &token, &form.code) {
        Ok(security::Confirmation::Done {
            username,
            purpose,
            delivery,
            recovery_codes,
        }) => {
            if delivery == "vault"
                && let Err(e) = state.vault.kv_delete(&state.cfg.kv_bootstrap_path).await
            {
                tracing::error!(error = %e, "deleting the used enrollment link from Vault");
            }
            let action = if purpose == "reset" {
                "enroll-reset-complete"
            } else {
                "enroll-complete"
            };
            state.db.audit(
                "enroll",
                &username,
                action,
                &username,
                "success",
                Some(&ip),
                None,
            );
            render(&EnrollDoneTpl {
                nav: None,
                username,
                codes: recovery_codes,
            })
        }
        Ok(security::Confirmation::WrongCode { attempts_left }) => {
            let pending = security::pending_enrollment(&state.db, &key, &token);
            let who = pending
                .as_ref()
                .map(|p| p.username.clone())
                .unwrap_or_default();
            state.db.audit(
                "enroll",
                &who,
                "enroll-confirm",
                &who,
                "failure",
                Some(&ip),
                None,
            );
            match pending {
                Ok(p) => (
                    StatusCode::UNAUTHORIZED,
                    render(&EnrollTotpTpl {
                        nav: None,
                        token,
                        username: p.username,
                        qr_svg: p.qr_svg,
                        secret: p.secret_base32,
                        otpauth_url: p.otpauth_url,
                        error: Some(format!("Wrong code. {attempts_left} attempt(s) left.")),
                    }),
                )
                    .into_response(),
                Err(e) => enroll_error(e, |m| (StatusCode::BAD_REQUEST, m).into_response()),
            }
        }
        Err(e) => enroll_error(e, |m| (StatusCode::BAD_REQUEST, m).into_response()),
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

        /// Generated once per test run; never a hard-coded credential.
        fn password() -> &'static str {
            static PW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            PW.get_or_init(security::random_token)
        }

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

        /// What the enrolling person saw: their TOTP seed and recovery codes.
        struct Enrolled {
            secret: String,
            codes: Vec<String>,
        }

        fn between<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
            let i = s
                .find(start)
                .unwrap_or_else(|| panic!("{start:?} not in page"))
                + start.len();
            &s[i..i + s[i..].find(end).unwrap()]
        }

        /// TOTP code `steps_ahead` time steps from now (the server accepts
        /// one step of skew; each step can be used only once).
        fn code_for(secret: &str, steps_ahead: u64) -> String {
            let secret = totp_rs::Secret::try_from_base32(secret).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            security::totp_for(secret.as_bytes().to_vec(), "x")
                .unwrap()
                .generate(now + 30 * steps_ahead)
                .to_string()
        }

        /// Walk through /enroll/{token} like a browser would.
        async fn enroll(
            app: &axum::Router,
            token: &str,
            username: &str,
            password: &str,
        ) -> Enrolled {
            let url = format!("/enroll/{token}");
            let (st, _, _, _) = send(app, "GET", &url, None, None).await;
            assert_eq!(st, StatusCode::OK, "enrollment page");
            let form = format!("username={username}&password={password}&confirm={password}");
            let (st, _, _, body) = send(app, "POST", &url, None, Some(&form)).await;
            assert_eq!(st, StatusCode::OK, "{body}");
            assert!(body.contains("<svg"), "QR code shown");
            let secret =
                between(&body, "Secret (base32): <code class=\"wrap\">", "</code>").to_string();
            let form = format!("code={}", code_for(&secret, 0));
            let (st, _, _, body) =
                send(app, "POST", &format!("{url}/confirm"), None, Some(&form)).await;
            assert_eq!(st, StatusCode::OK, "{body}");
            let codes = body
                .split("<li><code>")
                .skip(1)
                .map(|p| p[..p.find("</code>").unwrap()].to_string())
                .collect::<Vec<_>>();
            assert_eq!(codes.len(), security::RECOVERY_CODES);
            Enrolled { secret, codes }
        }

        /// Password + TOTP login; returns the session cookie.
        async fn login(app: &axum::Router, username: &str, password: &str, secret: &str) -> String {
            let form = format!("username={username}&password={password}");
            let (st, _, pw_cookie, _) = send(app, "POST", "/login", None, Some(&form)).await;
            assert_eq!(st, StatusCode::SEE_OTHER);
            // Enrollment consumed the current step, so use the next one.
            let form = format!("code={}", code_for(secret, 1));
            let (st, loc, cookie, _) = send(
                app,
                "POST",
                "/login/totp",
                pw_cookie.as_deref(),
                Some(&form),
            )
            .await;
            assert_eq!((st, loc.as_deref()), (StatusCode::SEE_OTHER, Some("/")));
            cookie.expect("session cookie")
        }

        /// First-launch state: an admin "alice" enrolled through a bootstrap link.
        async fn setup() -> (crate::state::Shared, axum::Router, Enrolled, String) {
            let (state, _rx) = test_state();
            state.set_totp_key(security::random_bytes::<32>());
            let app = app(state.clone());
            let (token, _) =
                security::new_invite(&state.db, "bootstrap", None, "ui", "test", 600).unwrap();
            let e = enroll(&app, &token, "alice", password()).await;
            (state, app, e, token)
        }

        fn csrf_from(body: &str) -> String {
            let marker = "name=\"csrf\" value=\"";
            let start = body.find(marker).expect("csrf field") + marker.len();
            body[start..start + body[start..].find('"').unwrap()].to_string()
        }

        #[tokio::test]
        async fn password_then_totp_login() {
            let (_state, app, e, _) = setup().await;

            let (st, loc, _, _) = send(&app, "GET", "/", None, None).await;
            assert_eq!(
                (st, loc.as_deref()),
                (StatusCode::SEE_OTHER, Some("/login"))
            );

            let form = format!("username=alice&password={}", password());
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
            assert!(st == StatusCode::UNAUTHORIZED || code_for(&e.secret, 1) == "000000");

            let form = format!("code={}", code_for(&e.secret, 1));
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
            let (state, app, e, _) = setup().await;
            let form = format!("username=alice&password={}", password());
            let (_, _, pw_cookie, _) = send(&app, "POST", "/login", None, Some(&form)).await;
            let rc = format!("code={}", e.codes[0]);
            let (st, loc, _, _) =
                send(&app, "POST", "/login/totp", pw_cookie.as_deref(), Some(&rc)).await;
            assert_eq!((st, loc.as_deref()), (StatusCode::SEE_OTHER, Some("/")));

            for _ in 0..5 {
                let wrong = format!("username=alice&password={}", security::random_token());
                let (st, _, _, _) = send(&app, "POST", "/login", None, Some(&wrong)).await;
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
            let (_state, app, _, _) = setup().await;
            let form = format!("username=nobody&password={}", security::random_token());
            let (st, _, cookie, body) = send(&app, "POST", "/login", None, Some(&form)).await;
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
            let (_state, app, _, _) = setup().await;
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

        #[tokio::test]
        async fn enrollment_links_are_single_use_and_lock_after_wrong_codes() {
            let (state, app, _, used) = setup().await;
            let (st, _, _, _) = send(&app, "GET", &format!("/enroll/{used}"), None, None).await;
            assert_eq!(st, StatusCode::GONE, "used link");
            let (st, _, _, _) = send(&app, "GET", "/enroll/not-a-token", None, None).await;
            assert_eq!(st, StatusCode::GONE, "unknown link");

            let (token, _) =
                security::new_invite(&state.db, "create", Some("bob"), "ui", "test", 600).unwrap();
            let url = format!("/enroll/{token}");
            let pw = security::random_token();
            let (st, _, _, _) = send(
                &app,
                "POST",
                &url,
                None,
                Some(&format!("password={pw}&confirm=x{pw}")),
            )
            .await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "passwords must match");
            let (st, _, _, body) = send(
                &app,
                "POST",
                &url,
                None,
                Some(&format!("password={pw}&confirm={pw}")),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
            assert!(
                body.contains("<strong>bob</strong>"),
                "username fixed by invite"
            );
            for _ in 0..crate::db::INVITE_MAX_FAILURES {
                let (st, _, _, _) = send(
                    &app,
                    "POST",
                    &format!("{url}/confirm"),
                    None,
                    Some("code=1"),
                )
                .await;
                assert!(st == StatusCode::UNAUTHORIZED || st == StatusCode::GONE);
            }
            let (st, _, _, _) = send(&app, "GET", &url, None, None).await;
            assert_eq!(st, StatusCode::GONE, "locked after too many wrong codes");
            assert!(state.db.admin_by_username("bob").unwrap().is_none());
        }

        #[tokio::test]
        async fn invites_and_reenrollment_from_the_ui() {
            let (state, app, e, _) = setup().await;
            let cookie = login(&app, "alice", password(), &e.secret).await;
            let (_, _, _, page) = send(&app, "GET", "/admins", Some(&cookie), None).await;
            let csrf = csrf_from(&page);

            // Invite bob: the inviter sees only a link.
            let (st, _, _, body) = send(
                &app,
                "POST",
                "/admins",
                Some(&cookie),
                Some("csrf=wrong&username=bob"),
            )
            .await;
            assert_eq!(st, StatusCode::FORBIDDEN);
            let form = format!("csrf={csrf}&username=bob");
            let (st, _, _, body2) = send(&app, "POST", "/admins", Some(&cookie), Some(&form)).await;
            assert_eq!(st, StatusCode::OK, "{body}");
            let token = between(&body2, "/enroll/", "</code>").to_string();
            assert!(
                !body2.contains("otpauth://"),
                "inviter never sees a TOTP seed"
            );
            let bob_pw = security::random_token();
            enroll(&app, &token, "ignored", &bob_pw).await;
            assert!(state.db.admin_by_username("bob").unwrap().is_some());

            // Re-enroll alice: her session ends once she completes it.
            let alice = state.db.admin_by_username("alice").unwrap().unwrap();
            let form = format!("csrf={csrf}");
            let (st, _, _, body) = send(
                &app,
                "POST",
                &format!("/admins/{}/reenroll", alice.id),
                Some(&cookie),
                Some(&form),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
            let token = between(&body, "/enroll/", "</code>").to_string();
            let (st, _, _, _) = send(&app, "GET", "/", Some(&cookie), None).await;
            assert_eq!(
                st,
                StatusCode::OK,
                "still signed in until re-enrollment completes"
            );
            let new_pw = security::random_token();
            let e2 = enroll(&app, &token, "ignored", &new_pw).await;
            let (st, _, _, _) = send(&app, "GET", "/", Some(&cookie), None).await;
            assert_eq!(
                st,
                StatusCode::SEE_OTHER,
                "re-enrollment signs out old sessions"
            );
            login(&app, "alice", &new_pw, &e2.secret).await;
            let audit = state.db.audit_entries(100).unwrap();
            assert!(audit.iter().any(|a| a.action == "enroll-reset-complete"));
            assert!(
                audit
                    .iter()
                    .all(|a| !a.detail.clone().unwrap_or_default().contains(&token))
            );
        }
    }
}
