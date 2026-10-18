# Hardened Wolfi toolchain images (Python 3.14.x, Go, Rust).
#
#   make            build + smoke-test + CVE-gate both variants
#   make help       list targets
#
# Requires: docker (BuildKit), grype, jq. Optional: syft (for `make sbom`).

SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all

# ---- Image settings -------------------------------------------------------
IMAGE          ?= wolfi-polyglot
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

BUILD_ARGS = \
	--build-arg BASE_IMAGE=$(BASE_IMAGE) \
	--build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
	--build-arg GO_PACKAGE=$(GO_PACKAGE) \
	--build-arg RUST_PACKAGE=$(RUST_PACKAGE) \
	--build-arg "EXTRA_PACKAGES=$(EXTRA_PACKAGES)" \
	--build-arg APK_CACHE_BUST=$(APK_CACHE_BUST) \
	--label org.opencontainers.image.title=$(IMAGE) \
	--label org.opencontainers.image.created=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
	--label org.opencontainers.image.base.name=$(BASE_IMAGE)

# Run the smoke test as locked down as possible.
RUN_HARDENED = docker run --rm -i \
	--platform $(PLATFORM) \
	--read-only \
	--tmpfs /tmp:rw,exec,nosuid,size=2g \
	--tmpfs /home/nonroot:rw,exec,nosuid,size=2g,uid=65532,gid=65532 \
	--cap-drop=ALL \
	--security-opt=no-new-privileges \
	--network=none

.PHONY: all help build build-shell build-distroless test test-shell test-distroless \
        scan scan-shell scan-distroless sbom check-tools clean

all: build test scan ## Build, smoke-test and CVE-gate both images

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---- Build ----------------------------------------------------------------
build: build-shell build-distroless ## Build both variants

build-shell: ## Build non-root image with busybox shell (no apk)
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(BUILD_ARGS) \
		-f Dockerfile -t $(SHELL_IMAGE) .

build-distroless: ## Build non-root image with no shell and no apk
	DOCKER_BUILDKIT=1 docker build --pull $(if $(NO_CACHE),--no-cache) \
		--platform $(PLATFORM) $(BUILD_ARGS) \
		-f Dockerfile.distroless -t $(DISTROLESS_IMAGE) .

# ---- Smoke tests ----------------------------------------------------------
test: test-shell test-distroless ## Smoke-test both variants

test-shell: ## Smoke-test the shell variant
	$(RUN_HARDENED) -e EXPECT_SHELL=1 $(SHELL_IMAGE) python3 - < tests/smoke.py

test-distroless: ## Smoke-test the distroless variant
	$(RUN_HARDENED) -e EXPECT_SHELL=0 $(DISTROLESS_IMAGE) python3 - < tests/smoke.py

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

scan: check-tools scan-shell scan-distroless ## CVE-gate both variants with grype

scan-shell: ## CVE-gate the shell variant
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(SHELL_IMAGE),shell)

scan-distroless: ## CVE-gate the distroless variant
	@$(GRYPE) db update >/dev/null
	$(call cve_gate,$(DISTROLESS_IMAGE),distroless)

sbom: ## Write SPDX SBOMs for both variants (needs syft)
	@mkdir -p $(REPORT_DIR)
	$(SYFT) docker:$(SHELL_IMAGE)      -o spdx-json=$(REPORT_DIR)/shell-sbom.spdx.json
	$(SYFT) docker:$(DISTROLESS_IMAGE) -o spdx-json=$(REPORT_DIR)/distroless-sbom.spdx.json

check-tools:
	@for t in docker $(GRYPE) $(JQ); do \
		command -v $$t >/dev/null || { echo "missing required tool: $$t"; exit 1; }; \
	done

clean: ## Remove built images and reports
	-docker rmi $(SHELL_IMAGE) $(DISTROLESS_IMAGE) 2>/dev/null
	rm -rf $(REPORT_DIR)
