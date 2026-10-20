//! App-facing JSON API.
//!
//! Apps authenticate with their own Vault token (`X-Vault-Token`, or
//! `Authorization: Bearer`). A request for a domain is allowed only if that
//! token has `update` on `<REQUEST_MARKER_PREFIX>/<domain>` in Vault. The API
//! never returns private keys: apps read the certificate from Vault.

use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    acme::{storage_name, validate_domain},
    db::{CertRecord, Job, now},
    state::{RequestOutcome, Shared},
    vault::{Identity, VaultError, allows_update},
};

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/v1/certificates", post(request_certificate))
        .route("/api/v1/certificates/{domain}", get(get_certificate))
        .route("/api/v1/jobs/{id}", get(get_job))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
}

#[derive(Debug)]
pub struct ApiError(StatusCode, serde_json::Value);

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError(status, json!({ "error": msg.into() }))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "internal error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

fn rfc3339(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[derive(Serialize)]
struct CertView {
    name: String,
    domains: Vec<String>,
    /// Full Vault API path, e.g. `secret/data/certs/app.example.com`.
    vault_path: String,
    vault_version: i64,
    not_before: String,
    not_after: String,
    serial: String,
    issuer: String,
}

impl From<CertRecord> for CertView {
    fn from(r: CertRecord) -> Self {
        CertView {
            name: r.name,
            domains: r.domains,
            vault_path: r.vault_path,
            vault_version: r.vault_version,
            not_before: rfc3339(r.not_before),
            not_after: rfc3339(r.not_after),
            serial: r.serial,
            issuer: r.issuer,
        }
    }
}

#[derive(Serialize)]
struct JobView {
    id: String,
    kind: String,
    name: String,
    domains: Vec<String>,
    status: String,
    vault_path: Option<String>,
    vault_version: Option<i64>,
    error: Option<String>,
    created_at: String,
    finished_at: Option<String>,
}

impl From<Job> for JobView {
    fn from(j: Job) -> Self {
        JobView {
            id: j.id,
            kind: j.kind,
            name: j.name,
            domains: j.domains,
            status: j.status,
            vault_path: j.vault_path,
            vault_version: j.vault_version,
            error: j.error,
            created_at: rfc3339(j.created_at),
            finished_at: j.finished_at.map(rfc3339),
        }
    }
}

fn app_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let from_vault = headers.get("x-vault-token").and_then(|v| v.to_str().ok());
    let from_bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    from_vault
        .or(from_bearer)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing X-Vault-Token header"))
}

async fn identify(state: &Shared, token: &str) -> Result<Identity, ApiError> {
    state.vault.lookup_self(token).await.map_err(|e| match e {
        VaultError::Forbidden => ApiError::new(StatusCode::UNAUTHORIZED, "invalid Vault token"),
        other => {
            tracing::error!(error = %other, "vault lookup-self failed");
            ApiError::new(StatusCode::BAD_GATEWAY, "Vault unavailable")
        }
    })
}

/// Authenticate the token and require `update` on every domain's marker path.
async fn authorize(
    state: &Shared,
    headers: &HeaderMap,
    domains: &[String],
    action: &str,
    ip: &str,
) -> Result<Identity, ApiError> {
    let token = app_token(headers)?;
    let identity = identify(state, &token).await?;
    let paths: Vec<String> = domains.iter().map(|d| state.marker_path(d)).collect();
    let caps = state
        .vault
        .capabilities_self(&token, &paths)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "vault capabilities-self failed");
            ApiError::new(StatusCode::BAD_GATEWAY, "Vault unavailable")
        })?;
    let denied: Vec<&String> = domains
        .iter()
        .zip(&paths)
        .filter(|(_, p)| !caps.get(*p).is_some_and(|c| allows_update(c)))
        .map(|(d, _)| d)
        .collect();
    if !denied.is_empty() {
        let target = domains.join(",");
        let detail = format!(
            "denied: {}",
            denied
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        state.db.audit(
            "app",
            &identity.display_name,
            action,
            &target,
            "denied",
            Some(ip),
            Some(&detail),
        );
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            json!({ "error": "not authorized for these domains", "denied": denied }),
        ));
    }
    Ok(identity)
}

/// Validate, normalize and de-duplicate requested domains (order kept).
pub fn normalize_domains(input: &[String], max: usize) -> Result<Vec<String>, ApiError> {
    if input.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "domains must not be empty",
        ));
    }
    if input.len() > max {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("at most {max} domains per request"),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for d in input {
        let d = validate_domain(d).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        if !out.contains(&d) {
            out.push(d);
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct CertRequest {
    domains: Vec<String>,
}

async fn request_certificate(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CertRequest>,
) -> Result<Response, ApiError> {
    let ip = peer.ip().to_string();
    let domains = normalize_domains(&req.domains, state.cfg.max_domains_per_request)?;
    let identity = authorize(&state, &headers, &domains, "request", &ip).await?;
    let target = domains.join(",");

    let recent = state.db.requests_since(&identity.id, now() - 3600)?;
    if recent >= state.cfg.rate_limit_per_hour as i64 {
        state.db.audit(
            "app",
            &identity.display_name,
            "request",
            &target,
            "rate-limited",
            Some(&ip),
            None,
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded; try again later",
        ));
    }

    match state.request_certificate(&domains, "issue", &identity.id, false)? {
        RequestOutcome::Existing(rec) => {
            state.db.audit(
                "app",
                &identity.display_name,
                "request",
                &target,
                "existing",
                Some(&ip),
                None,
            );
            Ok((
                StatusCode::OK,
                Json(json!({ "status": "exists", "certificate": CertView::from(rec) })),
            )
                .into_response())
        }
        RequestOutcome::Queued(job) => {
            state.db.audit(
                "app",
                &identity.display_name,
                "request",
                &target,
                "queued",
                Some(&ip),
                Some(&job.id),
            );
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({ "status": job.status, "job_id": job.id, "job": JobView::from(job) })),
            )
                .into_response())
        }
    }
}

async fn get_job(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<JobView>, ApiError> {
    let token = app_token(&headers)?;
    let identity = identify(&state, &token).await?;
    match state.db.job(&id)? {
        // Apps only see their own jobs; everything else looks like a 404.
        Some(job) if job.requester == identity.id => Ok(Json(job.into())),
        _ => Err(ApiError::new(StatusCode::NOT_FOUND, "no such job")),
    }
}

async fn get_certificate(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<CertView>, ApiError> {
    let domains = normalize_domains(&[domain], 1)?;
    authorize(
        &state,
        &headers,
        &domains,
        "metadata",
        &peer.ip().to_string(),
    )
    .await?;
    state
        .db
        .certificate(&storage_name(&domains[0]))?
        .map(|r| Json(r.into()))
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no certificate for this domain"))
}

async fn readyz(State(state): State<Shared>) -> (StatusCode, Json<serde_json::Value>) {
    let vault = state.vault.is_logged_in().await;
    let secrets = state.totp_key().is_some();
    let status = if vault && secrets {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({ "vault_logged_in": vault, "secrets_loaded": secrets })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domains() {
        let d = normalize_domains(
            &[
                "A.example.com".into(),
                "a.example.com".into(),
                "*.Example.com".into(),
            ],
            5,
        )
        .unwrap();
        assert_eq!(d, vec!["a.example.com", "*.example.com"]);
        assert_eq!(
            normalize_domains(&[], 5).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            normalize_domains(&["--issue".into()], 5).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        let many: Vec<String> = (0..6).map(|i| format!("h{i}.example.com")).collect();
        assert_eq!(
            normalize_domains(&many, 5).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn token_extraction() {
        let mut h = HeaderMap::new();
        assert_eq!(app_token(&h).unwrap_err().0, StatusCode::UNAUTHORIZED);
        h.insert("authorization", "Bearer abc".parse().unwrap());
        assert_eq!(app_token(&h).unwrap(), "abc");
        h.insert("x-vault-token", "xyz".parse().unwrap());
        assert_eq!(app_token(&h).unwrap(), "xyz");
    }
}
