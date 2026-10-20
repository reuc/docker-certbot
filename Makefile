# Hardened Wolfi images:
#   - toolchain (Python 3.14.x, Go, Rust): shell and distroless variants
#   - certbot (Certbot + all official DNS plugins): distroless
#   - certproxy (acme.sh proxy + Vault storage + admin UI, Rust)
#
#   make            build + smoke-test + CVE-gate all images
#   make help       list targets
#
# Requires: docker (BuildKit), grype, jq. Optional: syft (for `make sbom`),
# uv (for `make certbot-lock`).

SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all

# ---- Image settings -------------------------------------------------------
IMAGE          ?= wolfi-polyglot
CERTBOT_IMAGE_NAME ?= wolfi-certbot
CERTPROXY_IMAGE_NAME ?= wolfi-certproxy
TAG            ?= $(shell date -u +%Y%m%d)
PLATFORM       ?= linux/amd64
# Pin by digest for reproducible builds, e.g.
#   make BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:...
BASE_IMAGE     ?= cgr.dev/chainguard/wolfi-base:latest
PYTHON_VERSION ?= 3.14
GO_PACKAGE     ?= go
RUST_PACKAGE   ?= rust
EXTRA_PACKAGES ?=
# Defaults to today so packages are re-resolved at least once a day.
APK_CACHE_BUST ?= $(shell date -u +%Y%m%d)
NO_CACHE       ?=

SHELL_IMAGE      := $(IMAGE):$(TAG)
DISTROLESS_IMAGE := $(IMAGE):$(TAG)-distroless
CERTBOT_IMAGE    := $(CERTBOT_IMAGE_NAME):$(TAG)
CERTPROXY_IMAGE  := $(CERTPROXY_IMAGE_NAME):$(TAG)

# Certbot version as pinned in certbot/requirements.in.
CERTBOT_VERSION := $(shell sed -n 's/^certbot==//p' certbot/requirements.in)
# certproxy version as set in certproxy/Cargo.toml.
CERTPROXY_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' certproxy/Cargo.toml | head -1)
UV              ?= uv

# ---- CVE limits (the gate fails when a count is ABOVE the max) -------------
# Policy: 0 Critical, <2 High, <5 Medium, <10 Low
MAX_CRITICAL ?= 0
MAX_HIGH     ?= 1
MAX_MEDIUM   ?= 4
MAX_LOW      ?= 9

GRYPE      ?= grype
SYFT       ?= syft
JQ         ?= jq
REPORT_DIR ?= reports

COMMON_BUILD_ARGS = \
	--build-arg BASE_IMAGE=$(BASE_IMAGE) \
	--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
	--build-arg APK_CACHE_BUST=$(APK_CACHE_BUST) \
	--label org.opencontainers.image.created=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
	--label org.opencontainers.image.base.name=$(BASE_IMAGE)

BUILD_ARGS = $(COMMON_BUILD_ARGS) \
	--build-arg GO_PACKAGE=$(GO_PACKAGE) \
	--build-arg RUST_PACKAGE=$(RUST_PACKAGE) \
	--build-arg "EXTRA_PACKAGES=$(EXTRA_PACKAGES)" \
	--label org.opencontainers.image.title=$(IMAGE)

CERTBOT_BUILD_ARGS = $(COMMON_BUILD_ARGS) \
	--label org.opencontainers.image.title=$(CERTBOT_IMAGE_NAME) \
	--label org.opencontainers.image.version=$(CERTBOT_VERSION)

CERTPROXY_BUILD_ARGS = \
	--build-arg BASE_IMAGE=$(BASE_IMAGE) \
	--build-arg APK_CACHE_BUST=$(APK_CACHE_BUST) \
	--label org.opencontainers.image.created=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
	--label org.opencontainers.image.base.name=$(BASE_IMAGE) \
	--label org.opencontainers.image.title=$(CERTPROXY_IMAGE_NAME) \
	--label org.opencontainers.image.version=$(CERTPROXY_VERSION)

# Run the smoke test as locked down as possible.
RUN_HARDENED = docker run --rm -i \
	--platform $(PLATFORM) \
	--read-only \
	--tmpfs /tmp:rw,exec,nosuid,size=2g \
	--tmpfs /home/nonroot:rw,exec,nosuid,size=2g,uid=65532,gid=65532 \
	--cap-drop=ALL \
	--security-opt=no-new-privileges \
	--network=none

# Certbot's default directories, mounted writable the way volumes would be.
CERTBOT_DIRS = \
	--tmpfs /etc/letsencrypt:rw,noexec,nosuid,uid=65532,gid=65532,mode=0750 \
	--tmpfs /var/lib/letsencrypt:rw,noexec,nosuid,uid=65532,gid=65532,mode=0750 \
	--tmpfs /var/log/letsencrypt:rw,noexec,nosuid,uid=65532,gid=65532,mode=0750

.PHONY: all help build build-shell build-distroless build-certbot build-certproxy \
        test test-shell test-distroless test-certbot test-certproxy \
        test-certproxy-unit e2e-certproxy \
        scan scan-shell scan-distroless scan-certbot scan-certproxy \
        certbot-lock sbom check-tools clean \
        image-ref-shell image-ref-distroless image-ref-certbot image-ref-certproxy

all: build test scan ## Build, smoke-test and CVE-gate all images

help: ## Show this help
	@grep -E '^[a-zA-Z_%-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# Print an image reference, e.g. `make -s image-ref-certbot` (used by CI).
image-ref-shell:      ; @echo $(SHELL_IMAGE)
image-ref-distroless: ; @echo $(DISTROLESS_IMAGE)
image-ref-certbot:    ; @echo $(CERTBOT_IMAGE)
image-ref-certproxy:  ; @echo $(CERTPROXY_IMAGE)

# ---- Build ----------------------------------------------------------------
build: build-shell build-distroless build-certbot build-certproxy ## Build all images

build-shell: ## Build non-root toolchain image with busybox shell (no apk)
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(BUILD_ARGS) \
		-f Dockerfile -t $(SHELL_IMAGE) .

build-distroless: ## Build non-root toolchain image with no shell and no apk
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(BUILD_ARGS) \
		-f Dockerfile.distroless -t $(DISTROLESS_IMAGE) .

build-certbot: ## Build non-root Certbot image (all DNS plugins, no shell, no apk)
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(CERTBOT_BUILD_ARGS) \
		-f Dockerfile.certbot -t $(CERTBOT_IMAGE) .

build-certproxy: ## Build the certproxy image (acme.sh proxy, admin UI; non-root, no apk)
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(CERTPROXY_BUILD_ARGS) \
		-f Dockerfile.certproxy -t $(CERTPROXY_IMAGE) .

certbot-lock: ## Regenerate certbot/requirements.txt (hash-locked) from requirements.in
	$(UV) pip compile certbot/requirements.in \
		--python-version $(PYTHON_VERSION) --python-platform linux \
		--generate-hashes --no-header --quiet \
		-o certbot/requirements.txt

# ---- Smoke tests ----------------------------------------------------------
test: test-shell test-distroless test-certbot test-certproxy ## Smoke-test all images

test-shell: ## Smoke-test the shell variant
	$(RUN_HARDENED) -e EXPECT_SHELL=1 $(SHELL_IMAGE) python3 - < tests/smoke.py

test-distroless: ## Smoke-test the distroless variant
	$(RUN_HARDENED) -e EXPECT_SHELL=0 $(DISTROLESS_IMAGE) python3 - < tests/smoke.py

test-certbot: ## Smoke-test the Certbot image
	$(RUN_HARDENED) $(CERTBOT_DIRS) -e EXPECT_CERTBOT_VERSION=$(CERTBOT_VERSION) \
		--entrypoint /opt/certbot/bin/python $(CERTBOT_IMAGE) - < tests/smoke_certbot.py

test-certproxy: ## Smoke-test the certproxy image
	$(RUN_HARDENED) --tmpfs /data:rw,noexec,nosuid,uid=65532,gid=65532,mode=0700 \
		--entrypoint /bin/sh $(CERTPROXY_IMAGE) -s < tests/smoke_certproxy.sh

test-certproxy-unit: ## certproxy: cargo fmt --check, clippy -D warnings, unit tests (in Docker)
	DOCKER_BUILDKIT=1 docker build --pull --platform $(PLATFORM) $(CERTPROXY_BUILD_ARGS) \
		--target test -f Dockerfile.certproxy .

e2e-certproxy: ## certproxy end-to-end test against a Vault dev server and Pebble
	CERTPROXY_IMAGE=$(CERTPROXY_IMAGE) tests/e2e/run.sh

# ---- CVE gate -------------------------------------------------------------
# $(1) = image ref, $(2) = report name
# Counts unique vulnerability IDs per severity (--by-cve folds GHSA ids into CVE ids).
define cve_gate
	@mkdir -p $(REPORT_DIR)
	$(GRYPE) docker:$(1) --by-cve -o table -o json=$(REPORT_DIR)/$(2)-grype.json
	@f=$(REPORT_DIR)/$(2)-grype.json; \
	count() { $(JQ) --arg s "$$1" '[.matches[] | select(.vulnerability.severity == $$s) | .vulnerability.id] | unique | length' "$$f"; }; \
	c=$$(count Critical); h=$$(count High); m=$$(count Medium); l=$$(count Low); \
	echo ""; \
	echo "CVE gate for $(1):"; \
	printf '  %-9s %3s (max %s)\n' Critical "$$c" $(MAX_CRITICAL) High "$$h" $(MAX_HIGH) Medium "$$m" $(MAX_MEDIUM) Low "$$l" $(MAX_LOW); \
	fail=0; \
	[ "$$c" -le $(MAX_CRITICAL) ] || { echo "  FAIL: Critical $$c > $(MAX_CRITICAL)"; fail=1; }; \
	[ "$$h" -le $(MAX_HIGH) ]     || { echo "  FAIL: High $$h > $(MAX_HIGH)"; fail=1; }; \
	[ "$$m" -le $(MAX_MEDIUM) ]   || { echo "  FAIL: Medium $$m > $(MAX_MEDIUM)"; fail=1; }; \
	[ "$$l" -le $(MAX_LOW) ]      || { echo "  FAIL: Low $$l > $(MAX_LOW)"; fail=1; }; \
	if [ $$fail -eq 0 ]; then echo "  PASS"; fi; \
	exit $$fail
endef

scan: check-tools scan-shell scan-distroless scan-certbot scan-certproxy ## CVE-gate all images with grype

scan-shell: ## CVE-gate the shell variant
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(SHELL_IMAGE),shell)

scan-distroless: ## CVE-gate the distroless variant
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(DISTROLESS_IMAGE),distroless)

scan-certbot: ## CVE-gate the Certbot image
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(CERTBOT_IMAGE),certbot)

scan-certproxy: ## CVE-gate the certproxy image
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(CERTPROXY_IMAGE),certproxy)

sbom: ## Write SPDX SBOMs for all images (needs syft)
	@mkdir -p $(REPORT_DIR)
	$(SYFT) docker:$(SHELL_IMAGE)      -o spdx-json=$(REPORT_DIR)/shell-sbom.spdx.json
	$(SYFT) docker:$(DISTROLESS_IMAGE) -o spdx-json=$(REPORT_DIR)/distroless-sbom.spdx.json
	$(SYFT) docker:$(CERTBOT_IMAGE)    -o spdx-json=$(REPORT_DIR)/certbot-sbom.spdx.json
	$(SYFT) docker:$(CERTPROXY_IMAGE)  -o spdx-json=$(REPORT_DIR)/certproxy-sbom.spdx.json

check-tools:
	@for t in docker $(GRYPE) $(JQ); do \
		command -v $$t >/dev/null || { echo "missing required tool: $$t"; exit 1; }; \
	done

clean: ## Remove built images and reports
	-docker rmi $(SHELL_IMAGE) $(DISTROLESS_IMAGE) $(CERTBOT_IMAGE) $(CERTPROXY_IMAGE) 2>/dev/null
	rm -rf $(REPORT_DIR)
