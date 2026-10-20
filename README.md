# wolfi-polyglot

[![build-and-scan](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml/badge.svg)](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml)

Hardened container images built on [Wolfi](https://github.com/wolfi-dev):

- **Toolchain images** (`wolfi-polyglot`), in a shell variant and a distroless variant. See [Variants](#variants).
- **Certbot image** (`wolfi-certbot`): Certbot with every official DNS plugin, distroless. See [Certbot image](#certbot-image).
- **certproxy** (`wolfi-certproxy`): a certificate proxy for apps. Apps authorized by Vault policy request certificates, certproxy issues them with acme.sh (Cloudflare DNS-01) and stores them in Vault, and admins use a web UI with password + TOTP. See [certproxy](#certproxy).

Each toolchain image contains:

- **Python 3.14.x**, with pip and the dev headers
- **Go**, the latest version in Wolfi
- **Rust**, with rustc and cargo
- **A C toolchain** (gcc, binutils, glibc-dev, pkgconf), for cgo and native extensions

The Makefile builds all the images, smoke-tests them, and runs a **CVE gate** with [grype](https://github.com/anchore/grype). The gate fails unless both of these hold:

| Severity | Allowed |
|----------|---------|
| Critical | 0       |
| High     | < 2     |
| Medium   | < 5     |
| Low      | < 10    |

## Variants

| Image tag | Dockerfile | Shell | apk | User |
|-----------|------------|-------|-----|------|
| `wolfi-polyglot:<date>` | `Dockerfile` | busybox `/bin/sh` | no | `nonroot` (65532) |
| `wolfi-polyglot:<date>-distroless` | `Dockerfile.distroless` | none | no | `nonroot` (65532) |

Use the **shell** variant for CI jobs, interactive work, and anything that runs `make` or shell scripts.
Use the **distroless** variant when you call the tools directly and want the smallest attack surface. It has no `make`, because `make` needs a shell.

## Certbot image

`Dockerfile.certbot` builds `wolfi-certbot:<date>`, which contains [Certbot](https://certbot.eff.org/) and **all 13 official DNS plugins**: cloudflare, digitalocean, dnsimple, dnsmadeeasy, gehirn, google, linode, luadns, nsone, ovh, rfc2136, route53 and sakuracloud. Certbot's built-in `standalone`, `webroot` and `manual` plugins are included too.

| | |
|---|---|
| Base | Wolfi `python-3.14` in a `FROM scratch` image |
| Certbot | the version pinned in `certbot/requirements.in` (currently 5.8.0) |
| Shell / apk / pip | none |
| User | `nonroot` (65532) |
| Entrypoint | `/opt/certbot/bin/certbot` |

**How Certbot is installed.** Wolfi doesn't package Certbot, so it comes from PyPI. It's installed into a virtualenv at `/opt/certbot` from `certbot/requirements.txt`, a lock file that pins every package (Certbot, the plugins and all their dependencies) to an exact version with SHA-256 hashes. The build uses `pip install --require-hashes --only-binary=:all:`, so it fails if any download doesn't match its hash and never compiles anything. pip is only in the builder stage. The final image can't install packages.

### Using it

Mount volumes for Certbot's directories. They must be writable by UID 65532:

```bash
docker volume create letsencrypt
docker volume create letsencrypt-lib

# DNS-01 with Cloudflare (the credentials file must be readable by UID 65532)
docker run --rm \
  -v letsencrypt:/etc/letsencrypt -v letsencrypt-lib:/var/lib/letsencrypt \
  -v "$PWD/cloudflare.ini":/run/secrets/cloudflare.ini:ro \
  wolfi-certbot:<tag> certonly --non-interactive --agree-tos -m you@example.com \
  --dns-cloudflare --dns-cloudflare-credentials /run/secrets/cloudflare.ini \
  -d example.com -d '*.example.com'

# DNS-01 with Route 53 (standard AWS environment variables or a mounted ~/.aws)
docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  -v letsencrypt:/etc/letsencrypt -v letsencrypt-lib:/var/lib/letsencrypt \
  wolfi-certbot:<tag> certonly --non-interactive --agree-tos -m you@example.com \
  --dns-route53 -d example.com

# HTTP-01 standalone
docker run --rm -p 80:80 \
  -v letsencrypt:/etc/letsencrypt -v letsencrypt-lib:/var/lib/letsencrypt \
  wolfi-certbot:<tag> certonly --standalone --non-interactive --agree-tos -m you@example.com -d example.com

# Renew everything that's due
docker run --rm -v letsencrypt:/etc/letsencrypt -v letsencrypt-lib:/var/lib/letsencrypt \
  wolfi-certbot:<tag> renew --non-interactive
```

A fresh named volume copies the image's directory, including its UID 65532 ownership, so the commands above work as written. With a bind mount from the host, `chown 65532:65532` the host directory first. Add `-v letsencrypt-logs:/var/log/letsencrypt` if you want to keep the logs.

### Limitations

- **No hook commands.** Certbot runs `--pre-hook`, `--post-hook`, `--deploy-hook` and `--manual-auth-hook` through `/bin/sh`, and this image has no shell. Do follow-up work (such as reloading a web server) from outside the container after `certonly` or `renew` succeeds.
- **No installer plugins.** The nginx and apache plugins are left out. They only work when the web server runs in the same container.
- **Binding port 80 as non-root.** Docker lets containers bind ports below 1024 without root, so `--standalone` on port 80 works with `-p 80:80`. With `--network host`, that doesn't apply: use `--http-01-port 8080` and forward port 80 to it.

### Updating Certbot and its dependencies

The daily CI rebuild refreshes Wolfi's packages (including Python itself), but **not** the PyPI packages, which stay at the versions in the lock file. To pick up new Certbot releases or fixes in dependencies:

1. Change the version in `certbot/requirements.in` if you want a new Certbot release. All 14 Certbot packages there must share one version.
2. Run `make certbot-lock` (needs [uv](https://docs.astral.sh/uv/)). This re-resolves every dependency to its latest compatible version and rewrites `certbot/requirements.txt` with new hashes.
3. Commit both files and open a PR. CI builds, tests and scans the result on both architectures.

grype reads every PyPI package in the virtualenv, so the CVE gate covers them. It can't see libraries bundled inside binary wheels, though. For example, the `cryptography` wheel includes its own OpenSSL, so a CVE in that OpenSSL is fixed by upgrading `cryptography` through the lock file, not by rebuilding.

## certproxy

`certproxy` lets apps get TLS certificates without each holding DNS credentials or an ACME account. It's a small Rust service (`certproxy/`) built into `wolfi-certproxy:<date>` by `Dockerfile.certproxy`.

### What's in certproxy

- **The API for apps:**
  - An app sends its own Vault token with a list of domains.
  - certproxy asks Vault whether that token has `update` on `cert-requests/<domain>` for every domain, so you grant access with ordinary Vault policies.
  - It issues the certificate with acme.sh over Cloudflare DNS-01 and writes certificate, key and chain to `secret/data/certs/<name>`.
  - The app reads the certificate from Vault. The API never returns private keys.
- **Renewal:** a background loop renews certificates automatically, with a new key each time.
- **The web UI** uses local accounts: password, then a TOTP code or a one-time recovery code. Admins see certificates, jobs and the audit log, and can renew certificates, manage admins and change passwords. Five failed attempts lock an account for 15 minutes. The first admin enrolls through a one-time link that certproxy writes to Vault, and every later admin through a one-time link from the UI, so nobody else ever sees their password, TOTP seed or recovery codes.
- **The image** runs as UID 65532 with no package manager. It keeps busybox because acme.sh is a shell script, so it can't be distroless like the Certbot image.
- **Secrets stay in Vault.** The Cloudflare token and the key that encrypts TOTP secrets are read from Vault at runtime. After each run, certproxy deletes the certificate's key from disk and strips the credentials acme.sh saves.
- **Deployment and tests:** a Docker Compose deployment, Vault policies with a setup script, a smoke test and an end-to-end test. New Makefile targets, and two CI changes: certproxy added on amd64 and arm64, plus a `certproxy checks` job.

### Testing done without Docker

- rustfmt and clippy are clean, and all 28 unit and HTTP tests pass.
- The binary was run against a real Vault 2.2.0 dev server, Pebble 2.10.1 (Let's Encrypt's test CA) and acme.sh 3.1.6, the version Wolfi ships. All 15 checks passed on 8 consecutive runs. They cover:
  - token and permission errors
  - issuance, and that only the right app can read the certificate
  - that nothing secret is left on disk
  - TOTP login
  - renewal from the UI with a new key
  - the audit log
- That testing caught a real bug. A fixed 30-day renewal window would reissue Let's Encrypt's 6-day certificates every 12 hours. Renewal is now due at 30 days or a third of the certificate's lifetime, whichever is shorter.

### Additions beyond the original request

- **`codeql.yml`:** `rust` was added to its languages so code scanning covers the new code.
- **`ACME_HOOKS_DIR`:** a new setting that lets you add custom acme.sh DNS hook scripts. The end-to-end test needed it.
- **Domains:** wildcards are stored and authorized as `wildcard.example.com`, because `*` is a glob character in Vault policies.

### Before you use it

- `setup.sh` writes the AppRole credential files. Run it as root, or `chown 65532:65532` those files afterwards; it tells you when.
- Start with `ACME_SERVER=letsencrypt_test` (Let's Encrypt staging), then switch to `letsencrypt`.
- Run one replica only when you move to Kubernetes, because the job queue, database and ACME account can't be shared.
- There's no default account or password. On first launch, read the one-time enrollment link from Vault (`vault kv get -field=enrollment_url secret/certproxy/bootstrap`) and enroll in the browser; see [First launch](#first-launch).
- After first launch, work through [Securing it after first launch](#securing-it-after-first-launch).

### How it works

```
 app ──(1) Vault login──────────────────────────► Vault (vault.netseclabs.com)
  │                                                  ▲   ▲
  ├──(2) POST /api/v1/certificates ──► certproxy ────┘   │ (3) checks the app's token,
  │       X-Vault-Token: <app token>      │              │     stores the cert (KV v2)
  │                                       └─ acme.sh ──► Let's Encrypt (DNS-01 via Cloudflare)
  └──(4) read secret/data/certs/<name> ─────────────────┘
```

1. The app logs in to Vault with its own identity (AppRole, Kubernetes, JWT…).
2. It asks certproxy for a certificate, sending its Vault token.
3. certproxy checks the token with Vault. The app may request a domain only if its token has **`update` on `cert-requests/<domain>`**. That path is policy-only (no mount needed), so access is managed entirely with Vault policies. certproxy then issues the certificate with acme.sh and writes it to **`secret/data/certs/<name>`**.
4. The app reads the certificate and key **directly from Vault** with its own policy. certproxy's API never returns private keys.

Certificates renew automatically when less than `RENEW_BEFORE_DAYS` (30) or a third of their lifetime remains, whichever is shorter, and each renewal writes a new KV version with a **new key**. Wildcards are supported (`*.example.com` is stored, and authorized, as `wildcard.example.com`).

### Vault setup

```bash
export VAULT_ADDR=https://vault.netseclabs.com VAULT_TOKEN=<admin token>
CF_TOKEN=<Cloudflare API token with Zone:DNS:Edit> ./deploy/vault/setup.sh
```

This creates the `certproxy` policy (`deploy/vault/certproxy-policy.hcl`, which also covers the one-time enrollment link at `secret/certproxy/bootstrap`) and AppRole role, stores the Cloudflare token at `secret/certproxy/dns` and a TOTP encryption key at `secret/certproxy/app`, and writes the AppRole credentials to `deploy/compose/secrets/`. Run it as root, or `sudo chown 65532:65532` the two files afterwards as it tells you: the container runs as UID 65532.

Grant each app a policy like `deploy/vault/app-policy.example.hcl`:

```hcl
path "cert-requests/app.example.com"    { capabilities = ["update"] }  # may request
path "secret/data/certs/app.example.com" { capabilities = ["read"] }    # may read the result
```

### Requesting a certificate (app side)

```bash
TOKEN=$(vault write -field=token auth/approle/login role_id=... secret_id=...)
curl -sS -H "X-Vault-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domains":["app.example.com","www.app.example.com"]}' \
  https://certproxy.netseclabs.com/api/v1/certificates
# 202 {"status":"queued","job_id":"..."}  or  200 {"status":"exists","certificate":{...}}

curl -sS -H "X-Vault-Token: $TOKEN" https://certproxy.netseclabs.com/api/v1/jobs/<job_id>
# {"status":"succeeded","vault_path":"secret/data/certs/app.example.com","vault_version":1,...}

vault kv get -field=fullchain   secret/certs/app.example.com > fullchain.pem
vault kv get -field=private_key secret/certs/app.example.com > key.pem
```

| Endpoint | |
|---|---|
| `POST /api/v1/certificates` | `{"domains": [...]}`. Returns 202 with a job, or 200 if a valid certificate with the same names exists. 401 for a bad token, 403 (listing the denied domains) without permission, 429 over `RATE_LIMIT_PER_HOUR`. |
| `GET /api/v1/jobs/{id}` | Job status; apps only see their own jobs. |
| `GET /api/v1/certificates/{domain}` | Metadata (expiry, serial, Vault path and version). Never the key. |
| `GET /healthz`, `GET /readyz` | Liveness, and readiness (logged in to Vault, secrets loaded). |

The KV secret has the fields `certificate`, `private_key`, `chain`, `fullchain`, `domains`, `not_before`, `not_after`, `serial` and `issuer`.

### Web UI

Admins sign in at `https://<host>:8443/` with a **username and password, then a TOTP code** from an authenticator app (or a one-time recovery code). The UI shows certificates and expiry, jobs, and the audit log. Admins can renew a certificate, invite other admins, send re-enrollment links, and change their password. It never shows private keys.

#### First launch

certproxy has no default account and no built-in password. Every admin, including the first, enrolls through a **one-time link** (single use, 30 minutes by default):

1. Start certproxy. Once it's logged in to Vault and finds no admin, it writes the link to **`secret/certproxy/bootstrap`** in Vault. The log shows only that path and the expiry, never the link. If the link expires unused, certproxy writes a new one.
2. An operator with read access to that path (for example with `deploy/vault/bootstrap-reader-policy.example.hcl`) gets the link:
   ```bash
   vault kv get -field=enrollment_url secret/certproxy/bootstrap
   ```
3. The new admin opens it over HTTPS, chooses a username and password, scans the QR code with an authenticator app, and confirms one 6-digit code. The admin account is only created after that code is confirmed, so a mis-scanned authenticator can't lock them out.
4. Ten recovery codes are shown **once**, so store them offline. certproxy marks the link used and **deletes it from Vault**.

The password, TOTP seed and recovery codes are only ever shown to the person enrolling, in their browser. They're never printed, logged or written to disk; the TOTP seed is stored encrypted. Set `PUBLIC_URL` (or `PUBLIC_HOSTNAME` with `TLS_MODE=self`) so the link is a complete URL.

More admins: on **Admins → Invite an admin**, enter a username to get a one-time link to pass on. The inviter never sees the new admin's password or seed. **Re-enrollment link** does the same for an existing admin who lost their authenticator or password; their old credentials keep working until they finish, then all their sessions are signed out. If every admin is locked out, run this inside the container:

```bash
docker compose exec certproxy certproxy admin invite <username> --reset
```

It writes a new link to the same Vault path and prints only where to find it.

#### Securing it after first launch

1. **Check the link is gone.** `vault kv get secret/certproxy/bootstrap` should fail. Revoke any token you created just to read it.
2. **Switch ACME to production:** change `ACME_SERVER` from `letsencrypt_test` to `letsencrypt`.
3. **Keep HTTPS on:** `TLS_MODE=self` or `files`. Use `none` only behind a TLS-terminating proxy.
4. **Lock the AppRole to the host:** bind certproxy's `secret_id` and tokens to it (`secret_id_bound_cidrs`, `token_bound_cidrs`) and rotate the `secret_id` periodically. The commands are in the comments at the top of `deploy/vault/setup.sh`.
5. **Limit access to the container:**
   - Limit who can `docker exec` into it or read the `certproxy-data` volume, which holds the ACME account key and the admin database.
   - Restrict who can reach the web UI with a firewall or reverse proxy, but keep `/api/` reachable for apps.
6. **Plan for lockouts:** invite a second admin for break-glass access, keep recovery codes offline, and review the audit log regularly.

Passwords are hashed with Argon2id and must be at least 12 characters. TOTP secrets are encrypted with AES-256-GCM using the key from Vault, and each code is accepted only once. Five failed attempts lock an account for 15 minutes. Sessions use random tokens (stored hashed) in `HttpOnly`, `SameSite=Strict`, `Secure` cookies, and every form carries a CSRF token. A strict Content-Security-Policy is applied and the UI uses no JavaScript.

### Running it

```bash
cd deploy/compose
cp .env.example .env        # VAULT_ADDR, ACME_SERVER, PUBLIC_HOSTNAME, ...
docker compose up -d
```

The Compose service runs read-only, with all capabilities dropped and `no-new-privileges`. With `TLS_MODE=self` (the default in `.env.example`), certproxy issues and renews the UI's own certificate for `PUBLIC_HOSTNAME`. Use `TLS_MODE=files` for your own certificate, or `TLS_MODE=none` only behind a TLS-terminating proxy. **Start with `ACME_SERVER=letsencrypt_test`** (Let's Encrypt staging) and switch to `letsencrypt` once it works.

| Variable | Default | |
|---|---|---|
| `VAULT_ADDR` | `https://vault.netseclabs.com` | Vault URL (`VAULT_NAMESPACE`, `VAULT_CACERT` optional) |
| `VAULT_AUTH` | `approle` | `approle` (`VAULT_ROLE_ID_FILE`, `VAULT_SECRET_ID_FILE`), `kubernetes` (`VAULT_K8S_ROLE`), or `token` (`VAULT_TOKEN_FILE`, dev only) |
| `KV_MOUNT` / `KV_CERTS_PREFIX` | `secret` / `certs` | Where certificates are stored |
| `REQUEST_MARKER_PREFIX` | `cert-requests` | Policy path checked for authorization |
| `ACME_SERVER` | `letsencrypt` | acme.sh server name or directory URL |
| `ACME_EMAIL` | | ACME account email |
| `ACME_DNS_PROVIDER` | `dns_cf` | acme.sh DNS hook. Its credentials are read from `secret/certproxy/dns` and passed as env vars, so any acme.sh provider works. |
| `ACME_HOOKS_DIR` | | Optional directory of extra `dns_*.sh` hook scripts |
| `TLS_MODE` | `files` | `self` (with `PUBLIC_HOSTNAME`), `files` (`TLS_CERT_FILE`, `TLS_KEY_FILE`) or `none` |
| `RENEW_BEFORE_DAYS` | `30` | Renewal window (capped at a third of the lifetime) |
| `RATE_LIMIT_PER_HOUR` | `20` | Requests per app identity per hour |
| `SESSION_HOURS` | `8` | Admin session lifetime |
| `PUBLIC_URL` | | Base URL in enrollment links (default `https://PUBLIC_HOSTNAME:<port>` with `TLS_MODE=self`) |
| `INVITE_TTL_MINUTES` | `30` | How long an enrollment link stays valid |
| `KV_BOOTSTRAP_PATH` | `certproxy/bootstrap` | Vault KV path where first-launch and CLI enrollment links are written |
| `LOG_FORMAT` | | `json` for JSON logs |

### Security notes

- **Secrets stay in Vault.** The Cloudflare token and the TOTP key never go into env files or the image. acme.sh runs with a clean environment that only gets the DNS credentials. After every run certproxy deletes the domain's key directory and strips acme.sh's `SAVED_*` credential lines, so **`/data` holds only the ACME account key, the SQLite database and (in `self` mode) the UI certificate.**
- **App tokens are never stored or logged.** They're only used for `lookup-self` and `capabilities-self`.
- **Everything is audited.** Every request (allowed, denied, rate-limited) and every admin action goes to the audit log, with identity and source IP, and to the container log.
- **Why this image has a shell.** acme.sh is a shell script, so the image includes busybox. It still has no package manager, no setuid binaries and runs as UID 65532.
- **CVE coverage.** The binary is built with `cargo auditable`, so grype scans the Rust crates inside it as well as the Wolfi packages.

### Kubernetes

The service is ready to move. Configuration is all env vars, state lives only in `/data` (use a PVC), `VAULT_AUTH=kubernetes` uses the pod's service-account token, and `/healthz` and `/readyz` work as probes. Run **one replica**, because the job queue, SQLite and the ACME account are single-writer. Manifests will come in a later change.

### Testing

`make test-certproxy-unit` runs rustfmt, clippy and the unit tests in Docker. `make e2e-certproxy` runs the image against a **Vault dev server and Pebble** (Let's Encrypt's test CA) with a no-op DNS hook. It checks:

- authorization: a bad token gets 401, missing permission or partial permission gets 403
- issuance, and that the app can read the certificate and matching key from Vault while other apps can't
- certificate reuse, and that the API returns no key material
- that no keys or credentials are left on disk
- first launch: the enrollment link appears in Vault, browser enrollment (password, QR code, confirmation code, recovery codes), then the link is deleted and no longer works
- password + TOTP login and the dashboard
- `admin invite` writes a new link to Vault without printing it, and no link ever appears in certproxy's logs
- a renewal from the UI, which must produce a new key
- the audit log

### Publishing to Docker Hub

`.github/workflows/publish-certproxy.yml` publishes **`docker.io/<DOCKER_USER>/wolfi-certproxy`** for `linux/amd64` and `linux/arm64` from the `CertBot` branch.

**When it runs:**
- on every push to `CertBot` that touches certproxy, its Dockerfile, tests, the Makefile or the workflow
- daily at 07:23 UTC, so new Wolfi security fixes are published without a code change
- on demand (**Actions → publish-certproxy → Run workflow**)
- on pull requests into `CertBot` that change the workflow, as a **dry run**: the gates run, but nothing is logged in or pushed

**Gates:** each architecture is built natively, then must pass the architecture check, the smoke test and the grype CVE gate (0 Critical, fewer than 2 High, 5 Medium and 10 Low). amd64 also runs the end-to-end test against Vault and Pebble. Only the **exact image that passed** is pushed. If either architecture fails, nothing is published.

**What gets pushed:**

| Item | Where | Signed / attested |
|---|---|---|
| amd64 image | `:sha-<commit>-amd64` | SBOM attestation (SPDX) + cosign signature |
| arm64 image | `:sha-<commit>-arm64` | SBOM attestation (SPDX) + cosign signature |
| multi-arch index | `:latest`, `:YYYYMMDD`, `:sha-<commit>`, `:<version>` (e.g. `:0.1.0`) | SLSA build provenance + cosign signature |

All tags except the date are **rebuilt and moved by the daily run**: `sha-<commit>` names the source commit, not a single build. In production, **pin by digest**. The digest is shown in each run's summary.

**Setup (Settings → Secrets and variables → Actions):**
- **`DOCKER_USER`:** your Docker Hub username or organization. As a *variable* it shows in run summaries; as a *secret* it's masked.
- **`DOCKER_TOKEN`:** a Docker Hub **personal access token** with *Read & Write* scope. Don't use your account password.
- Docker Hub creates the `wolfi-certproxy` repository on the first push. Check its visibility (public or private) afterwards.

**Why it's also on `main`:** GitHub only runs scheduled workflows, and only shows "Run workflow", from the default branch. So the same file is also on `main`. Those runs check out and build `CertBot`; no certproxy code lives on `main`.

**Verify an image before deploying it:**

```bash
IMAGE=docker.io/<DOCKER_USER>/wolfi-certproxy@sha256:<digest>
cosign verify "$IMAGE" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/reuc/docker-wolfi/\.github/workflows/publish-certproxy\.yml@'
gh attestation verify "oci://$IMAGE" -R reuc/docker-wolfi
```

## Requirements

- Docker with BuildKit (Docker 23+ has it on by default)
- [grype](https://github.com/anchore/grype#installation) and `jq`, for the CVE gate
- [syft](https://github.com/anchore/syft#installation), optional, for SBOMs
- [uv](https://docs.astral.sh/uv/), optional, only for `make certbot-lock`
- Network access to `cgr.dev` and `packages.wolfi.dev`

## Quick start

```bash
make            # build, smoke-test and CVE-gate both variants
make help       # list all targets
```

`make` exits non-zero if a build, a smoke test or the CVE gate fails, so you can use it as a CI step directly.

## Make targets

| Target | What it does |
|--------|--------------|
| `all` (default) | `build` + `test` + `scan` |
| `build` | Builds all images |
| `build-shell` / `build-distroless` / `build-certbot` / `build-certproxy` | Builds one image |
| `test` | Smoke-tests all images |
| `test-shell` / `test-distroless` / `test-certbot` / `test-certproxy` | Smoke-tests one image |
| `test-certproxy-unit` | certproxy: rustfmt, clippy and unit tests (in Docker) |
| `e2e-certproxy` | certproxy end-to-end test against Vault dev + Pebble |
| `scan` | Runs the CVE gate on all images |
| `scan-shell` / `scan-distroless` / `scan-certbot` / `scan-certproxy` | Runs the CVE gate on one image |
| `certbot-lock` | Regenerates `certbot/requirements.txt` from `certbot/requirements.in` (needs uv) |
| `sbom` | Writes SPDX JSON SBOMs to `reports/` |
| `clean` | Removes the built images and `reports/` |

## Configuration

Override any variable on the command line, for example `make build TAG=v1 PLATFORM=linux/arm64`.

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAGE` | `wolfi-polyglot` | Toolchain image repository name |
| `CERTBOT_IMAGE_NAME` | `wolfi-certbot` | Certbot image repository name |
| `CERTPROXY_IMAGE_NAME` | `wolfi-certproxy` | certproxy image repository name |
| `TAG` | today's date (`YYYYMMDD`) | Tag for the shell variant and the Certbot image; the distroless variant adds `-distroless` |
| `PLATFORM` | `linux/amd64` | Target platform (`linux/arm64` also works) |
| `BASE_IMAGE` | `cgr.dev/chainguard/wolfi-base:latest` | Builder base image. Pin it by digest for reproducible builds. |
| `PYTHON_VERSION` | `3.14` | Python minor version for all images. The build fails if the installed Python doesn't match. |
| `GO_PACKAGE` | `go` | Wolfi Go package. Set e.g. `go-1.25` to pin a minor version. |
| `RUST_PACKAGE` | `rust` | Wolfi Rust package |
| `EXTRA_PACKAGES` | *(empty)* | More Wolfi packages to install, separated by spaces |
| `APK_CACHE_BUST` | today's date | Changing it forces packages to be fetched again |
| `NO_CACHE` | *(empty)* | Set to `1` to build with `--no-cache` |
| `MAX_CRITICAL` / `MAX_HIGH` / `MAX_MEDIUM` / `MAX_LOW` | `0` / `1` / `4` / `9` | CVE gate limits (the most allowed of each) |
| `REPORT_DIR` | `reports` | Where scan reports and SBOMs are written |
| `GRYPE` / `SYFT` / `JQ` / `UV` | `grype` / `syft` / `jq` / `uv` | Tool paths |

### Examples

```bash
# Reproducible build with a pinned base image
make BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:<digest>

# Add git and ssh (these add CVE surface)
make EXTRA_PACKAGES="git openssh-client"

# Pin the Go minor version and build for arm64
make GO_PACKAGE=go-1.25 PLATFORM=linux/arm64

# Stricter gate: no Highs allowed
make scan MAX_HIGH=0

# Force a fresh build to pick up newly published CVE fixes
make NO_CACHE=1
```

## Using the images

### Shell variant

```bash
# Interactive shell with the current directory mounted
docker run --rm -it -v "$PWD":/work -w /work wolfi-polyglot:<tag>

# Run a build
docker run --rm -v "$PWD":/work -w /work wolfi-polyglot:<tag> \
  sh -c 'go build ./... && cargo build --release && python3 -m pytest'
```

### Distroless variant

There is no shell, so call the tools directly:

```bash
docker run --rm wolfi-polyglot:<tag>-distroless go version
docker run --rm -v "$PWD":/work -w /work wolfi-polyglot:<tag>-distroless go build ./...
docker run --rm -v "$PWD":/work -w /work wolfi-polyglot:<tag>-distroless cargo build --release
docker run --rm -v "$PWD":/work -w /work wolfi-polyglot:<tag>-distroless python3 script.py
```

### As a base image

```dockerfile
FROM wolfi-polyglot:<tag> AS build
WORKDIR /home/nonroot/src
COPY --chown=65532:65532 . .
RUN go build -o /home/nonroot/app ./cmd/app
```

### Notes

- **Bind mounts must be writable by UID 65532** for any build that writes output. Either fix permissions on the host or add `--user "$(id -u):$(id -g)"`. If you override the user, also set `-e HOME=/tmp`, because `/home/nonroot` is only writable by 65532.
- **pip:** the system site-packages are owned by root. Use a virtualenv (`python3 -m venv .venv`) or `pip install --user`.
- **Go** never downloads other toolchain versions (`GOTOOLCHAIN=local`). It builds with `-trimpath` by default. Modules are fetched through `proxy.golang.org`, so git isn't needed unless you use private or direct-VCS modules.
- **Caches** go under `$HOME` (`/home/nonroot`): `GOPATH`, `GOCACHE` and `CARGO_HOME`. To keep them between runs, mount a volume there.

### Running locked down

The smoke tests use these flags, and they work for normal use too:

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=2g \
  --tmpfs /home/nonroot:rw,exec,nosuid,size=2g,uid=65532,gid=65532 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  wolfi-polyglot:<tag> go version
```

## How it's hardened

1. **Only the listed packages get in.** A throwaway `wolfi-base` stage installs them into an empty root folder with `apk add --root … --initdb --no-scripts`. That folder is copied into `FROM scratch`, so nothing else from the builder lands in the final image.
2. **No package manager.** `apk-tools` is never installed in the final image, and the apk signing keys and caches are removed.
3. **No shell** in the distroless variant. The build fails if any dependency pulls in `sh`, `bash`, `busybox` or `apk`, and names the package responsible.
4. **Compiler hardening still works without a shell.** Wolfi's `gcc` package routes `gcc`, `cc`, `g++` and related commands through `/usr/local/bin/gcc-wrapper`, which adds the [OpenSSF compiler-hardening](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) spec file. Upstream that wrapper is a `/bin/sh` script, so the distroless build replaces it with a compiled C program that does the same thing. The build fails if any compiler command in `/usr/local/bin` is still a script.
5. **Non-root by default.** Both images run as UID/GID 65532.
6. **No setuid or setgid binaries.** These bits are removed from every file.
7. **The scanners still see everything.** The installed-package list (`/lib/apk/db/installed`) is kept on purpose, so grype, trivy and syft can identify every package. Removing it would hide CVEs, not fix them.
8. **Minimal build context.** `.dockerignore` excludes everything except `certbot/requirements.txt` and certproxy's sources, so no other local files can leak into an image.

## CVE gate

`make scan` does the following for each variant:

1. Updates the grype vulnerability database.
2. Scans the image with `--by-cve`, which turns GHSA IDs into CVE IDs where possible. It prints a table and writes `reports/<variant>-grype.json`.
3. Counts **unique vulnerability IDs** per severity. A CVE that affects several packages counts once.
4. Fails if any count is above its limit.

Example output:

```
CVE gate for wolfi-polyglot:20261018:
  Critical    0 (max 0)
  High        1 (max 1)
  Medium      2 (max 4)
  Low         3 (max 9)
  PASS
```

Grype uses the Wolfi security database, so it already ignores CVEs that Wolfi has marked as fixed or not affecting the package.

### When the gate fails

1. **Rebuild with fresh packages.** Wolfi usually publishes fixes within days: `make NO_CACHE=1`.
2. **Find what's affected** in `reports/<variant>-grype.json`. This lists vulnerability ID, package, installed version and fixed version:
   ```bash
   jq -r '.matches[] | [.vulnerability.severity, .vulnerability.id, .artifact.name, .artifact.version, (.vulnerability.fix.versions|join(","))] | @tsv' \
     reports/shell-grype.json | sort -u
   ```
3. **Remove packages you don't need**, especially anything added with `EXTRA_PACKAGES`.
4. **Pin an older minor version** if the newest one has a regression (`GO_PACKAGE=go-1.xx`).
5. **For a reviewed false positive**, add a [grype ignore rule](https://github.com/anchore/grype#specifying-matches-to-ignore) in `.grype.yaml` with a justification. Don't loosen the limits to make a build pass.

## Continuous integration

`.github/workflows/build-and-scan.yml` builds, smoke-tests and CVE-gates **every image on every architecture**, eight jobs in all:

| | `amd64` (runner `ubuntu-24.04`) | `arm64` (runner `ubuntu-24.04-arm`) |
|---|---|---|
| `shell` | ✓ | ✓ |
| `distroless` | ✓ | ✓ |
| `certbot` | ✓ | ✓ |
| `certproxy` | ✓ | ✓ |

Each job builds natively on its own architecture's runner, with no QEMU emulation. It runs `make build-<variant>`, checks that the image's architecture matches the job, then runs `make test-<variant>` and `make scan-<variant>`, with `PLATFORM=linux/<arch>`.

The workflow runs:

- on every pull request
- on every push to `main`
- daily at 06:17 UTC, so new CVEs and new Wolfi fixes show up without a code change
- on demand (**Actions → build-and-scan → Run workflow**)

Builds always use `NO_CACHE=1` so they pick up the latest Wolfi packages. A job fails if the build, the architecture check, the smoke test or the CVE gate fails. Each job writes a table of CVE counts and findings to the run summary and uploads `reports/` as an artifact named `grype-<variant>-<arch>`, kept for 30 days.

The workflow only builds and scans. It doesn't publish images.

To make the gate block merges, add **`build-and-scan (all)`** as a required status check in the branch protection rule for `main`. That one check passes only when all eight jobs pass, plus the `certproxy checks` job (rustfmt, clippy, unit tests and the end-to-end test), which runs on pull requests and pushes but not on the daily schedule.

## Smoke tests

`tests/smoke.py` tests the toolchain images and `tests/smoke_certbot.py` tests the Certbot image.

`tests/smoke.py` is piped into the container's Python through stdin, so it works without a shell. It checks:

- the process runs as UID 65532
- Python is 3.14.x, and `ssl`, `sqlite3`, `ctypes`, `venv`, `zlib`, `lzma` and `bz2` import
- `pip` works
- `gcc` reads the OpenSSF hardening spec file
- `/bin/sh` exists in the shell variant and is absent in the distroless variant, and `apk` is absent in both
- C (via both `cc` and `gcc`), Go, cgo and Rust (via `cargo new` and `cargo build --offline`) each compile a program, and the program runs and prints the expected output

The tests run with `--network=none`, a read-only root filesystem and all capabilities dropped.

`tests/smoke_certbot.py` runs the same way, with Certbot's virtualenv Python and Certbot's three default directories mounted as writable tmpfs. It checks:

- the process runs as UID 65532, and Python is 3.14.x
- there's no shell, no apk, and no pip in the virtualenv
- the installed Certbot version matches `certbot/requirements.in`
- all 13 DNS plugins plus `manual`, `standalone` and `webroot` are registered and import
- Certbot's default directories are writable, and `certbot --version` and `certbot plugins` succeed
- the CA bundle that `REQUESTS_CA_BUNDLE` points to exists

## Files

```
.
├── .github/workflows/
│   ├── build-and-scan.yml # CI: build, test, CVE gate
│   ├── codeql.yml         # CodeQL (actions, python, rust)
│   └── publish-certproxy.yml # publish certproxy to Docker Hub
├── Dockerfile             # shell variant
├── Dockerfile.distroless  # no-shell variant
├── Dockerfile.certbot     # Certbot + all DNS plugins (distroless)
├── Dockerfile.certproxy   # certproxy (Rust build, acme.sh runtime)
├── certproxy/             # certproxy source (Cargo.toml, Cargo.lock, src/, templates/, static/)
├── deploy/compose/        # Docker Compose deployment for certproxy
├── deploy/vault/          # Vault policies and setup script for certproxy
├── certbot/
│   ├── requirements.in    # Certbot + plugin versions (edit this)
│   └── requirements.txt   # hash-locked lock file (make certbot-lock)
├── Makefile               # build / test / scan / sbom / certbot-lock
├── tests/smoke.py         # toolchain smoke test
├── tests/smoke_certbot.py # Certbot smoke test
├── tests/smoke_certproxy.sh # certproxy smoke test
├── tests/e2e/             # certproxy end-to-end test (Vault dev + Pebble)
├── .dockerignore          # build context: only the Certbot lock file and certproxy sources
└── README.md
```
