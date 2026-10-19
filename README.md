# wolfi-polyglot

[![build-and-scan](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml/badge.svg)](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml)

Hardened container images built on [Wolfi](https://github.com/wolfi-dev):

- **Toolchain images** (`wolfi-polyglot`), in a shell variant and a distroless variant. See [Variants](#variants).
- **Certbot image** (`wolfi-certbot`): Certbot with every official DNS plugin, distroless. See [Certbot image](#certbot-image).

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
| `build-shell` / `build-distroless` / `build-certbot` | Builds one image |
| `test` | Smoke-tests all images |
| `test-shell` / `test-distroless` / `test-certbot` | Smoke-tests one image |
| `scan` | Runs the CVE gate on all images |
| `scan-shell` / `scan-distroless` / `scan-certbot` | Runs the CVE gate on one image |
| `certbot-lock` | Regenerates `certbot/requirements.txt` from `certbot/requirements.in` (needs uv) |
| `sbom` | Writes SPDX JSON SBOMs to `reports/` |
| `clean` | Removes the built images and `reports/` |

## Configuration

Override any variable on the command line, for example `make build TAG=v1 PLATFORM=linux/arm64`.

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAGE` | `wolfi-polyglot` | Toolchain image repository name |
| `CERTBOT_IMAGE_NAME` | `wolfi-certbot` | Certbot image repository name |
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
8. **Minimal build context.** `.dockerignore` excludes everything except `certbot/requirements.txt`, so no other local files can leak into an image.

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

`.github/workflows/build-and-scan.yml` builds, smoke-tests and CVE-gates **every image on every architecture**, six jobs in all:

| | `amd64` (runner `ubuntu-24.04`) | `arm64` (runner `ubuntu-24.04-arm`) |
|---|---|---|
| `shell` | ✓ | ✓ |
| `distroless` | ✓ | ✓ |
| `certbot` | ✓ | ✓ |

Each job builds natively on its own architecture's runner, with no QEMU emulation. It runs `make build-<variant>`, checks that the image's architecture matches the job, then runs `make test-<variant>` and `make scan-<variant>`, with `PLATFORM=linux/<arch>`.

The workflow runs:

- on every pull request
- on every push to `main`
- daily at 06:17 UTC, so new CVEs and new Wolfi fixes show up without a code change
- on demand (**Actions → build-and-scan → Run workflow**)

Builds always use `NO_CACHE=1` so they pick up the latest Wolfi packages. A job fails if the build, the architecture check, the smoke test or the CVE gate fails. Each job writes a table of CVE counts and findings to the run summary and uploads `reports/` as an artifact named `grype-<variant>-<arch>`, kept for 30 days.

The workflow only builds and scans. It doesn't publish images.

To make the gate block merges, add **`build-and-scan (all)`** as a required status check in the branch protection rule for `main`. That one check passes only when all six jobs pass.

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
│   └── build-and-scan.yml # CI: build, test, CVE gate
├── Dockerfile             # shell variant
├── Dockerfile.distroless  # no-shell variant
├── Dockerfile.certbot     # Certbot + all DNS plugins (distroless)
├── certbot/
│   ├── requirements.in    # Certbot + plugin versions (edit this)
│   └── requirements.txt   # hash-locked lock file (make certbot-lock)
├── Makefile               # build / test / scan / sbom / certbot-lock
├── tests/smoke.py         # toolchain smoke test
├── tests/smoke_certbot.py # Certbot smoke test
├── .dockerignore          # build context: only the Certbot lock file
└── README.md
```
