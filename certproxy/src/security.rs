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

/// What a new or re-enrolled admin needs to set up their authenticator.
pub struct Enrollment {
    pub otpauth_url: String,
    pub secret_base32: String,
    pub recovery_codes: Vec<String>,
}

/// New TOTP secret (encrypted), its enrollment details, and recovery-code hashes.
fn new_totp_secret(key: &[u8; 32], username: &str) -> Result<(Vec<u8>, Enrollment, Vec<String>)> {
    let secret = random_bytes::<20>().to_vec();
    let totp = totp_for(secret.clone(), username)?;
    let codes = generate_recovery_codes();
    let hashes = codes
        .iter()
        .map(|c| sha256_hex(&normalize_recovery_code(c)))
        .collect();
    let enrollment = Enrollment {
        otpauth_url: totp.to_url().map_err(|e| anyhow!("{e}"))?,
        secret_base32: totp.secret().to_base32(),
        recovery_codes: codes,
    };
    Ok((encrypt(key, &secret)?, enrollment, hashes))
}

pub fn create_admin(db: &Db, key: &[u8; 32], username: &str, password: &str) -> Result<Enrollment> {
    validate_username(username)?;
    check_password_policy(password)?;
    if db.admin_by_username(username)?.is_some() {
        bail!("admin {username:?} already exists");
    }
    let (enc, enrollment, hashes) = new_totp_secret(key, username)?;
    let id = db.create_admin(username, &hash_password(password)?, &enc)?;
    db.replace_recovery_codes(id, &hashes)?;
    Ok(enrollment)
}

pub fn reset_totp(db: &Db, key: &[u8; 32], admin_id: i64) -> Result<Enrollment> {
    let admin = db
        .admin(admin_id)?
        .ok_or_else(|| anyhow!("no such admin"))?;
    let (enc, enrollment, hashes) = new_totp_secret(key, &admin.username)?;
    db.set_totp(admin.id, &enc)?;
    db.replace_recovery_codes(admin.id, &hashes)?;
    db.delete_sessions_for(admin.id)?;
    Ok(enrollment)
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

    #[test]
    fn password_roundtrip() {
        let password = random_token();
        let h = hash_password(&password).unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&password, &h));
        assert!(!verify_password(&random_token(), &h));
        assert!(!verify_password(&password, "not-a-hash"));
        assert!(check_password_policy(&password[..MIN_PASSWORD_LEN - 1]).is_err());
        assert!(check_password_policy(&password).is_ok());
    }

    #[test]
    fn encryption_roundtrip() {
        let key = random_bytes::<32>();
        let ct = encrypt(&key, b"secret").unwrap();
        assert_eq!(decrypt(&key, &ct).unwrap(), b"secret");
        assert!(decrypt(&random_bytes::<32>(), &ct).is_err());
    }

    #[test]
    fn usernames() {
        assert!(validate_username("ops.admin-1").is_ok());
        for bad in ["", "Admin", "a b", "a:b", &"a".repeat(65)] {
            assert!(validate_username(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn admin_enrollment_and_totp() {
        let db = Db::in_memory().unwrap();
        let key = random_bytes::<32>();
        let password = random_token();
        let e = create_admin(&db, &key, "alice", &password).unwrap();
        assert!(e.otpauth_url.starts_with("otpauth://totp/certproxy:alice?"));
        assert_eq!(e.recovery_codes.len(), RECOVERY_CODES);
        assert!(create_admin(&db, &key, "alice", &password).is_err());

        let admin = db.admin_by_username("alice").unwrap().unwrap();
        let secret = totp_rs::Secret::try_from_base32(&e.secret_base32).unwrap();
        let totp = totp_for(secret.as_bytes().to_vec(), "alice").unwrap();
        let code = totp.generate_current().to_string();
        assert!(verify_totp(&db, &key, admin.id, &code).unwrap());
        assert!(
            !verify_totp(&db, &key, admin.id, &code).unwrap(),
            "replay must fail"
        );
        assert!(!verify_totp(&db, &key, admin.id, "000000").unwrap() || code == "000000");

        let typed = e.recovery_codes[0].to_lowercase().replace('-', " ");
        assert!(
            db.use_recovery_code(admin.id, &sha256_hex(&normalize_recovery_code(&typed)))
                .unwrap()
        );
    }

    #[test]
    fn totp_key_parsing() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(parse_totp_key(&b64).unwrap(), [7u8; 32]);
        assert!(parse_totp_key("c2hvcnQ=").is_err());
    }
}
