# wolfi-polyglot

[![build-and-scan](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml/badge.svg)](https://github.com/reuc/docker-wolfi/actions/workflows/build-and-scan.yml)

Hardened container images built on [Wolfi](https://github.com/wolfi-dev). Each image contains:

- **Python 3.14.x**, with pip and the dev headers
- **Go**, the latest version in Wolfi
- **Rust**, with rustc and cargo
- **A C toolchain** (gcc, binutils, glibc-dev, pkgconf), for cgo and native extensions

The Makefile builds the images, smoke-tests them, and runs a **CVE gate** with [grype](https://github.com/anchore/grype). The gate fails unless both of these hold:

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

## Requirements

- Docker with BuildKit (Docker 23+ has it on by default)
- [grype](https://github.com/anchore/grype#installation) and `jq`, for the CVE gate
- [syft](https://github.com/anchore/syft#installation), optional, for SBOMs
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
| `build` | Builds both variants |
| `build-shell` / `build-distroless` | Builds one variant |
| `test` | Smoke-tests both variants |
| `test-shell` / `test-distroless` | Smoke-tests one variant |
| `scan` | Runs the CVE gate on both variants |
| `scan-shell` / `scan-distroless` | Runs the CVE gate on one variant |
| `sbom` | Writes SPDX JSON SBOMs to `reports/` |
| `clean` | Removes the built images and `reports/` |

## Configuration

Override any variable on the command line, for example `make build TAG=v1 PLATFORM=linux/arm64`.

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAGE` | `wolfi-polyglot` | Image repository name |
| `TAG` | today's date (`YYYYMMDD`) | Tag for the shell variant; the distroless variant adds `-distroless` |
| `PLATFORM` | `linux/amd64` | Target platform (`linux/arm64` also works) |
| `BASE_IMAGE` | `cgr.dev/chainguard/wolfi-base:latest` | Builder base image. Pin it by digest for reproducible builds. |
| `PYTHON_VERSION` | `3.14` | Python minor version. The build fails if the installed Python doesn't match. |
| `GO_PACKAGE` | `go` | Wolfi Go package. Set e.g. `go-1.25` to pin a minor version. |
| `RUST_PACKAGE` | `rust` | Wolfi Rust package |
| `EXTRA_PACKAGES` | *(empty)* | More Wolfi packages to install, separated by spaces |
| `APK_CACHE_BUST` | today's date | Changing it forces packages to be fetched again |
| `NO_CACHE` | *(empty)* | Set to `1` to build with `--no-cache` |
| `MAX_CRITICAL` / `MAX_HIGH` / `MAX_MEDIUM` / `MAX_LOW` | `0` / `1` / `4` / `9` | CVE gate limits (the most allowed of each) |
| `REPORT_DIR` | `reports` | Where scan reports and SBOMs are written |
| `GRYPE` / `SYFT` / `JQ` | `grype` / `syft` / `jq` | Tool paths |

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
4. **Non-root by default.** Both images run as UID/GID 65532.
5. **No setuid or setgid binaries.** These bits are removed from every file.
6. **The scanners still see everything.** The installed-package list (`/lib/apk/db/installed`) is kept on purpose, so grype, trivy and syft can identify every package. Removing it would hide CVEs, not fix them.
7. **Empty build context.** `.dockerignore` excludes everything, so no local files can leak into the image.

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

`.github/workflows/build-and-scan.yml` builds, smoke-tests and CVE-gates **every variant on every architecture**, four jobs in all:

| | `amd64` (runner `ubuntu-24.04`) | `arm64` (runner `ubuntu-24.04-arm`) |
|---|---|---|
| `shell` | ✓ | ✓ |
| `distroless` | ✓ | ✓ |

Each job builds natively on its own architecture's runner, with no QEMU emulation. It runs `make build-<variant>`, checks that the image's architecture matches the job, then runs `make test-<variant>` and `make scan-<variant>`, with `PLATFORM=linux/<arch>`.

The workflow runs:

- on every pull request
- on every push to `main`
- daily at 06:17 UTC, so new CVEs and new Wolfi fixes show up without a code change
- on demand (**Actions → build-and-scan → Run workflow**)

Builds always use `NO_CACHE=1` so they pick up the latest Wolfi packages. A job fails if the build, the architecture check, the smoke test or the CVE gate fails. Each job writes a table of CVE counts and findings to the run summary and uploads `reports/` as an artifact named `grype-<variant>-<arch>`, kept for 30 days.

The workflow only builds and scans. It doesn't publish images.

To make the gate block merges, add **`build-and-scan (all)`** as a required status check in the branch protection rule for `main`. That one check passes only when all four jobs pass.

## Smoke tests

`tests/smoke.py` is piped into the container's Python through stdin, so it works without a shell. It checks:

- the process runs as UID 65532
- Python is 3.14.x, and `ssl`, `sqlite3`, `ctypes`, `venv`, `zlib`, `lzma` and `bz2` import
- `pip` works
- `/bin/sh` exists in the shell variant and is absent in the distroless variant, and `apk` is absent in both
- Go, cgo and Rust (via `cargo new` and `cargo build --offline`) each compile a program, and the program runs and prints the expected output

The tests run with `--network=none`, a read-only root filesystem and all capabilities dropped.

## Files

```
.
├── .github/workflows/
│   └── build-and-scan.yml # CI: build, test, CVE gate
├── Dockerfile             # shell variant
├── Dockerfile.distroless  # no-shell variant
├── Makefile               # build / test / scan / sbom
├── tests/smoke.py         # in-container smoke test
├── .dockerignore          # empty build context
└── README.md
```
