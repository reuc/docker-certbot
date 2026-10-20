//! acme.sh wrapper, domain validation and certificate parsing.
//!
//! Every issuance (including renewals) starts from a clean domain directory
//! and therefore generates a new private key. After the certificate has been
//! read, the domain directory is deleted and acme.sh's saved credentials are
//! scrubbed, so `/data` only keeps the ACME account key and settings.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use time::OffsetDateTime;
use tokio::process::Command;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

use crate::config::Config;

/// Validate and normalize a requested domain name.
///
/// Accepts lowercase-able DNS names with an optional `*.` wildcard prefix.
/// Rejects anything that could be mistaken for an acme.sh option, IP
/// addresses, single-label names and trailing dots.
pub fn validate_domain(input: &str) -> Result<String, String> {
    let d = input.trim().to_ascii_lowercase();
    let bare = d.strip_prefix("*.").unwrap_or(&d);
    if d.is_empty() || d.len() > 253 {
        return Err(format!("{input:?}: invalid length"));
    }
    let labels: Vec<&str> = bare.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("{input:?}: must have at least two labels"));
    }
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(format!("{input:?}: invalid label {label:?}"));
        }
    }
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("{input:?}: IP addresses are not allowed"));
    }
    Ok(d)
}

/// Name used for the Vault path and acme.sh directory: `*.x.com` -> `wildcard.x.com`.
pub fn storage_name(domain: &str) -> String {
    match domain.strip_prefix("*.") {
        Some(rest) => format!("wildcard.{rest}"),
        None => domain.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub serial: String,
    pub sans: Vec<String>,
    pub issuer: String,
}

/// Parse the first certificate of a PEM bundle.
pub fn parse_cert(pem: &str) -> Result<CertInfo> {
    let (_, pem) = parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("invalid PEM: {e}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow!("invalid certificate: {e}"))?;
    let sans = cert
        .subject_alternative_name()
        .map_err(|e| anyhow!("invalid SAN extension: {e}"))?
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(s) => Some(s.to_ascii_lowercase()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertInfo {
        not_before: cert.validity().not_before.to_datetime(),
        not_after: cert.validity().not_after.to_datetime(),
        serial: cert.raw_serial_as_string(),
        sans,
        issuer: cert.issuer().to_string(),
    })
}

#[derive(Clone)]
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: String,
    pub fullchain_pem: String,
    pub info: CertInfo,
}

impl std::fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCert")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct Acme {
    acme_sh: PathBuf,
    home: PathBuf,
    server: String,
    email: Option<String>,
    dns_provider: String,
    key_length: String,
    dns_sleep: Option<u32>,
    ca_bundle: Option<PathBuf>,
    hooks_dir: Option<PathBuf>,
    timeout: Duration,
}

/// Replace secret values in acme.sh output before it is logged or stored.
fn redact(text: &str, secrets: &HashMap<String, String>) -> String {
    secrets
        .values()
        .filter(|v| v.len() >= 4)
        .fold(text.to_string(), |acc, v| {
            acc.replace(v.as_str(), "[REDACTED]")
        })
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// Remove `SAVED_*` lines (stored DNS credentials) from an acme.sh conf file.
pub fn scrub_saved_credentials(conf: &Path) -> Result<()> {
    let Ok(text) = std::fs::read_to_string(conf) else {
        return Ok(());
    };
    let kept: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("SAVED_"))
        .map(|l| format!("{l}\n"))
        .collect();
    if kept != text {
        std::fs::write(conf, kept).with_context(|| format!("scrubbing {}", conf.display()))?;
    }
    Ok(())
}

impl Acme {
    pub fn new(cfg: &Config) -> Self {
        Acme {
            acme_sh: cfg.acme_sh.clone(),
            home: cfg.acme_home(),
            server: cfg.acme_server.clone(),
            email: cfg.acme_email.clone(),
            dns_provider: cfg.acme_dns_provider.clone(),
            key_length: cfg.acme_key_length.clone(),
            dns_sleep: cfg.acme_dns_sleep,
            ca_bundle: cfg.acme_ca_bundle.clone(),
            hooks_dir: cfg.acme_hooks_dir.clone(),
            timeout: cfg.acme_timeout,
        }
    }

    fn domain_dir(&self, main: &str) -> PathBuf {
        if self.key_length.starts_with("ec-") {
            self.home.join(format!("{main}_ecc"))
        } else {
            self.home.join(main)
        }
    }

    /// acme.sh arguments for issuing `domains` (validated, first = main name).
    pub fn issue_args(&self, domains: &[String]) -> Vec<String> {
        let home = self.home.display().to_string();
        let mut args: Vec<String> = [
            "--issue",
            "--home",
            &home,
            "--config-home",
            &home,
            "--server",
            &self.server,
            "--keylength",
            &self.key_length,
            "--dns",
            &self.dns_provider,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for d in domains {
            args.push("-d".into());
            args.push(d.clone());
        }
        if let Some(s) = self.dns_sleep {
            args.push("--dnssleep".into());
            args.push(s.to_string());
        }
        if let Some(ca) = &self.ca_bundle {
            args.push("--ca-bundle".into());
            args.push(ca.display().to_string());
        }
        if let Some(email) = &self.email {
            args.push("--accountemail".into());
            args.push(email.clone());
        }
        args
    }

    /// Issue a certificate for `domains` with a fresh key.
    pub async fn issue(
        &self,
        domains: &[String],
        dns_env: &HashMap<String, String>,
    ) -> Result<IssuedCert> {
        let main = domains.first().ok_or_else(|| anyhow!("no domains"))?;
        for d in domains {
            validate_domain(d).map_err(|e| anyhow!(e))?;
        }
        tokio::fs::create_dir_all(&self.home).await?;
        self.install_hooks().await?;
        let dir = self.domain_dir(main);
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let child = Command::new(&self.acme_sh)
            .args(self.issue_args(domains))
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.home)
            .env("LANG", "C.UTF-8")
            .envs(dns_env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", self.acme_sh.display()))?;

        let result = tokio::time::timeout(self.timeout, child.wait_with_output()).await;
        let outcome = async {
            let output = result
                .map_err(|_| anyhow!("acme.sh timed out after {:?}", self.timeout))?
                .context("waiting for acme.sh")?;
            if !output.status.success() {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                bail!(
                    "acme.sh exited with {}:\n{}",
                    output.status,
                    tail(&redact(&text, dns_env), 25)
                );
            }
            self.read_issued(&dir, main, domains).await
        }
        .await;

        // Never keep keys or DNS credentials on disk, whatever happened.
        let _ = tokio::fs::remove_dir_all(&dir).await;
        scrub_saved_credentials(&self.home.join("account.conf"))?;
        outcome
    }

    /// Copy `dns_*.sh` scripts from ACME_HOOKS_DIR into acme.sh's home, where
    /// acme.sh looks for DNS hooks it doesn't ship.
    async fn install_hooks(&self) -> Result<()> {
        let Some(dir) = &self.hooks_dir else {
            return Ok(());
        };
        let mut entries = tokio::fs::read_dir(dir)
            .await
            .with_context(|| format!("reading ACME_HOOKS_DIR {}", dir.display()))?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("dns_") && name.ends_with(".sh") {
                tokio::fs::copy(entry.path(), self.home.join(name.as_ref())).await?;
            }
        }
        Ok(())
    }

    async fn read_issued(&self, dir: &Path, main: &str, domains: &[String]) -> Result<IssuedCert> {
        let read = |name: String| {
            let path = dir.join(name);
            async move {
                tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))
            }
        };
        let cert_pem = read(format!("{main}.cer")).await?;
        let key_pem = read(format!("{main}.key")).await?;
        let chain_pem = read("ca.cer".to_string()).await?;
        let fullchain_pem = read("fullchain.cer".to_string()).await?;
        let info = parse_cert(&cert_pem)?;
        for d in domains {
            if !info.sans.contains(d) {
                bail!(
                    "issued certificate does not cover {d} (SANs: {:?})",
                    info.sans
                );
            }
        }
        Ok(IssuedCert {
            cert_pem,
            key_pem,
            chain_pem,
            fullchain_pem,
            info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation() {
        assert_eq!(
            validate_domain("App.Example.COM").unwrap(),
            "app.example.com"
        );
        assert_eq!(validate_domain("*.example.com").unwrap(), "*.example.com");
        assert_eq!(
            validate_domain("xn--bcher-kva.example").unwrap(),
            "xn--bcher-kva.example"
        );
        for bad in [
            "",
            "localhost",
            "-d.example.com",
            "--issue",
            "a..example.com",
            "example.com.",
            "*.*.example.com",
            "a.*.example.com",
            "ex ample.com",
            "a_b.example.com",
            "bad-.example.com",
            "10.0.0.1",
            "a.example.com;rm",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(validate_domain(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn storage_names() {
        assert_eq!(storage_name("*.example.com"), "wildcard.example.com");
        assert_eq!(storage_name("a.example.com"), "a.example.com");
    }

    #[test]
    fn parses_certificate() {
        let ck = rcgen::generate_simple_self_signed(vec![
            "a.example.com".to_string(),
            "*.example.com".to_string(),
        ])
        .unwrap();
        let info = parse_cert(&ck.cert.pem()).unwrap();
        assert_eq!(info.sans, vec!["a.example.com", "*.example.com"]);
        assert!(info.not_after > info.not_before);
        assert!(!info.serial.is_empty());
    }

    #[test]
    fn redacts_secrets_and_tails() {
        let env = HashMap::from([("CF_Token".to_string(), "s3cr3t-token".to_string())]);
        let out = redact("using s3cr3t-token here", &env);
        assert_eq!(out, "using [REDACTED] here");
        assert_eq!(tail("1\n2\n3\n4", 2), "3\n4");
    }

    #[test]
    fn scrubs_saved_lines() {
        let dir = std::env::temp_dir().join(format!("certproxy-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("account.conf");
        std::fs::write(
            &conf,
            "ACCOUNT_EMAIL='a@b.c'\nSAVED_CF_Token='x'\n  SAVED_CF_Account_ID='y'\n",
        )
        .unwrap();
        scrub_saved_credentials(&conf).unwrap();
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "ACCOUNT_EMAIL='a@b.c'\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn builds_issue_args() {
        let acme = Acme {
            acme_sh: "/usr/bin/acme.sh".into(),
            home: "/data/acme".into(),
            server: "letsencrypt".into(),
            email: Some("ops@example.com".into()),
            dns_provider: "dns_cf".into(),
            key_length: "ec-256".into(),
            dns_sleep: Some(1),
            ca_bundle: None,
            hooks_dir: None,
            timeout: Duration::from_secs(1),
        };
        let args = acme.issue_args(&["a.example.com".into(), "*.example.com".into()]);
        let joined = args.join(" ");
        assert!(joined.starts_with("--issue --home /data/acme --config-home /data/acme"));
        assert!(joined.contains("--dns dns_cf -d a.example.com -d *.example.com --dnssleep 1"));
        assert!(joined.ends_with("--accountemail ops@example.com"));
        assert_eq!(
            acme.domain_dir("a.example.com"),
            PathBuf::from("/data/acme/a.example.com_ecc")
        );
    }
}
