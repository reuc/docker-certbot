//! Password hashing, TOTP, recovery codes, token generation and encryption
//! of TOTP secrets at rest. Shared by the web UI and the `admin` CLI.

use std::sync::OnceLock;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow, bail};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use sha2::{Digest, Sha256};
use totp_rs::{Builder, Totp};

use crate::db::Db;

pub const MIN_PASSWORD_LEN: usize = 12;
pub const RECOVERY_CODES: usize = 10;
const TOTP_ISSUER: &str = "certproxy";

pub fn random_bytes<const N: usize>() -> [u8; N] {
    rand::rng().random()
}

/// URL-safe random token with 256 bits of entropy.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("hashing password: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A real hash (of a random, discarded password) to verify against when the
/// username doesn't exist, so unknown and known usernames take the same time.
pub fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password(&random_token()).unwrap_or_default())
}

pub fn check_password_policy(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(())
}

pub fn validate_username(username: &str) -> Result<()> {
    let ok = !username.is_empty()
        && username.len() <= 64
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if !ok {
        bail!("username must be 1-64 characters of a-z, 0-9, '.', '_' or '-'");
    }
    Ok(())
}

/// Encrypt with AES-256-GCM; output is nonce (12 bytes) || ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("{e}"))?;
    let nonce_bytes = random_bytes::<12>();
    let ct = cipher
        .encrypt(&Nonce::from(nonce_bytes), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok([nonce_bytes.as_slice(), &ct].concat())
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        bail!("ciphertext too short");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("{e}"))?;
    let nonce: [u8; 12] = data[..12].try_into()?;
    cipher
        .decrypt(&Nonce::from(nonce), &data[12..])
        .map_err(|_| anyhow!("decryption failed (wrong key?)"))
}

/// Decode the base64 `totp_key` stored in Vault.
pub fn parse_totp_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("totp_key is not valid base64: {e}"))?;
    raw.try_into()
        .map_err(|_| anyhow!("totp_key must decode to exactly 32 bytes"))
}

pub fn totp_for(secret: Vec<u8>, username: &str) -> Result<Totp> {
    Builder::new()
        .with_secret(secret)
        .with_account_name(username)
        .with_issuer(Some(TOTP_ISSUER))
        .build()
        .map_err(|e| anyhow!("building TOTP: {e}"))
}

/// Normalize a recovery code as typed (case, spaces, dashes) before hashing.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn generate_recovery_codes() -> Vec<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    (0..RECOVERY_CODES)
        .map(|_| {
            let raw: String = (0..12)
                .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
                .collect();
            format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..])
        })
        .collect()
}

/// Create a one-time enrollment link token.
///
/// * `bootstrap`: first launch; the new admin chooses their username.
/// * `create`: a named new admin, invited by an existing admin.
/// * `reset`: an existing admin re-enrolls (new password and TOTP), e.g.
///   after losing their authenticator. Their sessions end when it completes.
///
/// Only the token's SHA-256 is stored. Earlier open invites for the same
/// username (or, for Vault delivery, the previous Vault-delivered link, since
/// Vault holds one at a time) are revoked. Returns `(token, expires_at)`.
pub fn new_invite(
    db: &Db,
    purpose: &str,
    username: Option<&str>,
    delivery: &str,
    created_by: &str,
    ttl_secs: i64,
) -> Result<(String, i64)> {
    let admin_id = match (purpose, username) {
        ("bootstrap", None) => None,
        ("create", Some(u)) => {
            validate_username(u)?;
            if db.admin_by_username(u)?.is_some() {
                bail!("admin {u:?} already exists");
            }
            None
        }
        ("reset", Some(u)) => Some(
            db.admin_by_username(u)?
                .ok_or_else(|| anyhow!("no admin {u:?}"))?
                .id,
        ),
        _ => bail!("invalid invite"),
    };
    if let Some(u) = username {
        db.revoke_invites(Some(u), delivery)?;
    }
    if delivery == "vault" {
        db.revoke_invites(None, "vault")?;
    }
    let token = random_token();
    let expires_at = crate::db::now() + ttl_secs;
    db.create_invite(
        &sha256_hex(&token),
        purpose,
        delivery,
        username,
        admin_id,
        created_by,
        expires_at,
    )?;
    Ok((token, expires_at))
}

/// Why an enrollment step was refused.
#[derive(Debug)]
pub enum EnrollError {
    /// Unknown, used, expired or locked token.
    Invalid,
    /// A problem the person can fix (shown to them).
    User(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for EnrollError {
    fn from(e: anyhow::Error) -> Self {
        EnrollError::Internal(e)
    }
}

/// What the enrolling person needs to add certproxy to their authenticator.
/// Shown only to them, in their browser, during enrollment.
pub struct PendingEnrollment {
    pub username: String,
    pub otpauth_url: String,
    pub secret_base32: String,
    pub qr_svg: String,
}

fn pending_view(key: &[u8; 32], username: &str, totp_enc: &[u8]) -> Result<PendingEnrollment> {
    let totp = totp_for(decrypt(key, totp_enc)?, username)?;
    let otpauth_url = totp.to_url().map_err(|e| anyhow!("{e}"))?;
    Ok(PendingEnrollment {
        username: username.to_string(),
        qr_svg: qr_svg(&otpauth_url)?,
        secret_base32: totp.secret().to_base32(),
        otpauth_url,
    })
}

/// Look up a valid invite by its token.
pub fn invite_for(db: &Db, token: &str) -> Result<Option<crate::db::Invite>> {
    db.valid_invite(&sha256_hex(token))
}

/// Step 1: the person chose a username (bootstrap only) and password. Store
/// them with a fresh TOTP secret on the invite (nothing is an admin yet) and
/// return what to show for authenticator setup.
pub fn begin_enrollment(
    db: &Db,
    key: &[u8; 32],
    token: &str,
    username_input: &str,
    password: &str,
) -> Result<PendingEnrollment, EnrollError> {
    let invite = invite_for(db, token)?.ok_or(EnrollError::Invalid)?;
    let username = match &invite.username {
        Some(u) => u.clone(),
        None => {
            let u = username_input.trim().to_ascii_lowercase();
            validate_username(&u).map_err(|e| EnrollError::User(e.to_string()))?;
            u
        }
    };
    if invite.purpose != "reset" && db.admin_by_username(&username)?.is_some() {
        return Err(EnrollError::User(format!(
            "admin {username:?} already exists"
        )));
    }
    check_password_policy(password).map_err(|e| EnrollError::User(e.to_string()))?;
    let password_hash = hash_password(password)?;
    let totp_enc = encrypt(key, &random_bytes::<20>())?;
    db.set_invite_pending(&invite.token_hash, &username, &password_hash, &totp_enc)?;
    Ok(pending_view(key, &username, &totp_enc)?)
}

/// Re-show the authenticator setup for an invite in step 2 (after a wrong code).
pub fn pending_enrollment(
    db: &Db,
    key: &[u8; 32],
    token: &str,
) -> Result<PendingEnrollment, EnrollError> {
    let invite = invite_for(db, token)?.ok_or(EnrollError::Invalid)?;
    match (&invite.pending_username, &invite.pending_totp_enc) {
        (Some(u), Some(enc)) => Ok(pending_view(key, u, enc)?),
        _ => Err(EnrollError::Invalid),
    }
}

/// Result of confirming the authenticator code.
pub enum Confirmation {
    /// Enrollment finished: the admin exists and these recovery codes (shown
    /// once) were issued. `delivery` tells the caller whether to delete the
    /// Vault copy of the link.
    Done {
        username: String,
        purpose: String,
        delivery: String,
        recovery_codes: Vec<String>,
    },
    /// Wrong code; this many attempts are left before the invite is void.
    WrongCode { attempts_left: i64 },
}

/// Step 2: check a code from the person's authenticator, then create (or
/// reset) the admin in one transaction.
pub fn finish_enrollment(
    db: &Db,
    key: &[u8; 32],
    token: &str,
    code: &str,
) -> Result<Confirmation, EnrollError> {
    let invite = invite_for(db, token)?.ok_or(EnrollError::Invalid)?;
    let (Some(username), Some(enc)) = (
        invite.pending_username.clone(),
        invite.pending_totp_enc.clone(),
    ) else {
        return Err(EnrollError::Invalid);
    };
    let totp = totp_for(decrypt(key, &enc)?, &username)?;
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    let Some(step) = totp.check_current(&code) else {
        let attempts_left = db.invite_failure(&invite.token_hash)?;
        return Ok(Confirmation::WrongCode { attempts_left });
    };
    let recovery_codes = generate_recovery_codes();
    let hashes: Vec<String> = recovery_codes
        .iter()
        .map(|c| sha256_hex(&normalize_recovery_code(c)))
        .collect();
    db.complete_enrollment(&invite, &hashes, step as i64)?;
    Ok(Confirmation::Done {
        username,
        purpose: invite.purpose,
        delivery: invite.delivery,
        recovery_codes,
    })
}

/// Render an otpauth URI as an inline SVG QR code (no image dependencies,
/// no data: URLs, so the strict Content-Security-Policy stays as it is).
pub fn qr_svg(data: &str) -> Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| anyhow!("QR code: {e}"))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .build();
    // Drop the XML declaration so the SVG can be embedded in HTML.
    Ok(svg
        .find("<svg")
        .map(|i| svg[i..].to_string())
        .unwrap_or(svg))
}

/// Check a 6-digit TOTP code for an admin, accepting each time step once.
pub fn verify_totp(db: &Db, key: &[u8; 32], admin_id: i64, code: &str) -> Result<bool> {
    let admin = db
        .admin(admin_id)?
        .ok_or_else(|| anyhow!("no such admin"))?;
    let secret = decrypt(key, &admin.totp_secret_enc)?;
    let totp = totp_for(secret, &admin.username)?;
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    match totp.check_current(&code) {
        Some(step) => db.consume_totp_step(admin.id, step as i64),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No literal passwords, keys or seeds: every secret here is generated.

    #[test]
    fn password_roundtrip() {
        let password = random_token();
        let h = hash_password(&password).unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&password, &h));
        assert!(!verify_password(&random_token(), &h));
        assert!(
            !verify_password(&password, &random_token()),
            "garbage is not a valid hash"
        );
        assert!(check_password_policy(&password[..MIN_PASSWORD_LEN - 1]).is_err());
        assert!(check_password_policy(&password).is_ok());
    }

    #[test]
    fn encryption_roundtrip() {
        let key = random_bytes::<32>();
        let plaintext = random_bytes::<24>();
        let ct = encrypt(&key, &plaintext).unwrap();
        assert_eq!(decrypt(&key, &ct).unwrap(), plaintext);
        assert!(decrypt(&random_bytes::<32>(), &ct).is_err());
    }

    #[test]
    fn usernames() {
        assert!(validate_username("ops.admin-1").is_ok());
        for bad in ["", "Admin", "a b", "a:b", &"a".repeat(65)] {
            assert!(validate_username(bad).is_err(), "{bad:?}");
        }
    }

    fn code_for(p: &PendingEnrollment) -> String {
        let secret = totp_rs::Secret::try_from_base32(&p.secret_base32).unwrap();
        totp_for(secret.as_bytes().to_vec(), &p.username)
            .unwrap()
            .generate_current()
            .to_string()
    }

    #[test]
    fn bootstrap_enrollment() {
        let db = Db::in_memory().unwrap();
        let key = random_bytes::<32>();
        let password = random_token();
        let (token, _) = new_invite(&db, "bootstrap", None, "vault", "system", 600).unwrap();

        assert!(matches!(
            begin_enrollment(&db, &key, &token, "Bad Name", &password),
            Err(EnrollError::User(_))
        ));
        assert!(matches!(
            begin_enrollment(&db, &key, &token, "alice", &password[..5]),
            Err(EnrollError::User(_))
        ));
        let p = begin_enrollment(&db, &key, &token, "Alice", &password).unwrap();
        assert_eq!(p.username, "alice");
        assert!(p.otpauth_url.starts_with("otpauth://totp/certproxy:alice?"));
        assert!(p.qr_svg.starts_with("<svg"));
        assert_eq!(
            pending_enrollment(&db, &key, &token).unwrap().secret_base32,
            p.secret_base32
        );

        let Confirmation::WrongCode { attempts_left } =
            finish_enrollment(&db, &key, &token, "not a code").unwrap()
        else {
            panic!("expected wrong code")
        };
        assert_eq!(attempts_left, crate::db::INVITE_MAX_FAILURES - 1);

        let code = code_for(&p);
        let Confirmation::Done {
            username,
            delivery,
            recovery_codes,
            ..
        } = finish_enrollment(&db, &key, &token, &code).unwrap()
        else {
            panic!("expected success")
        };
        assert_eq!((username.as_str(), delivery.as_str()), ("alice", "vault"));
        assert_eq!(recovery_codes.len(), RECOVERY_CODES);

        let admin = db.admin_by_username("alice").unwrap().unwrap();
        assert!(verify_password(&password, &admin.password_hash));
        assert!(
            !verify_totp(&db, &key, admin.id, &code).unwrap(),
            "confirmation code can't be replayed"
        );
        assert!(matches!(
            begin_enrollment(&db, &key, &token, "bob", &password),
            Err(EnrollError::Invalid)
        ));
        let typed = recovery_codes[0].to_lowercase().replace('-', " ");
        assert!(
            db.use_recovery_code(admin.id, &sha256_hex(&normalize_recovery_code(&typed)))
                .unwrap()
        );
    }

    #[test]
    fn invites_for_named_admins() {
        let db = Db::in_memory().unwrap();
        let key = random_bytes::<32>();
        assert!(new_invite(&db, "reset", Some("nobody"), "ui", "t", 600).is_err());
        assert!(new_invite(&db, "create", Some("Not Valid"), "ui", "t", 600).is_err());

        let (t1, _) = new_invite(&db, "create", Some("bob"), "ui", "t", 600).unwrap();
        let (t2, _) = new_invite(&db, "create", Some("bob"), "ui", "t", 600).unwrap();
        assert!(
            invite_for(&db, &t1).unwrap().is_none(),
            "a new invite revokes the old one"
        );
        // The username is fixed by the invite, whatever is typed.
        let p = begin_enrollment(&db, &key, &t2, "mallory", &random_token()).unwrap();
        assert_eq!(p.username, "bob");
        let code = code_for(&p);
        assert!(matches!(
            finish_enrollment(&db, &key, &t2, &code).unwrap(),
            Confirmation::Done { .. }
        ));
        assert!(
            new_invite(&db, "create", Some("bob"), "ui", "t", 600).is_err(),
            "already exists"
        );

        // Expired invites are rejected.
        let (t3, _) = new_invite(&db, "reset", Some("bob"), "ui", "t", -1).unwrap();
        assert!(invite_for(&db, &t3).unwrap().is_none());
    }

    #[test]
    fn qr_code_is_inline_svg() {
        let svg = qr_svg(&format!(
            "otpauth://totp/certproxy:a?secret={}",
            random_token()
        ))
        .unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
    }

    #[test]
    fn totp_key_parsing() {
        let key = random_bytes::<32>();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(parse_totp_key(&b64).unwrap(), key);
        let short = base64::engine::general_purpose::STANDARD.encode(random_bytes::<16>());
        assert!(parse_totp_key(&short).is_err());
    }
}
