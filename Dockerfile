# syntax=docker/dockerfile:1
#
# Hardened Wolfi toolchain image: Python 3.14.x, Go, Rust.
# Variant: non-root, busybox shell kept, NO package manager.
#
# The rootfs is assembled with `apk --root` in a throwaway builder stage and
# copied into `scratch`, so only the packages listed below (and their deps)
# end up in the final image. apk-tools is never installed in the final image.

ARG BASE_IMAGE=cgr.dev/chainguard/wolfi-base:latest

FROM ${BASE_IMAGE} AS builder

ARG PYTHON_VERSION=3.14
ARG GO_PACKAGE=go
ARG RUST_PACKAGE=rust
ARG EXTRA_PACKAGES=""
# Change this value (the Makefile passes today's date) to force a fresh package
# resolution so newly published CVE fixes are picked up.
ARG APK_CACHE_BUST=0

RUN set -eux; \
    echo "cache-bust: ${APK_CACHE_BUST}"; \
    mkdir -p /rootfs; \
    apk add --no-cache --no-scripts --initdb --root /rootfs \
        --keys-dir /etc/apk/keys \
        --repositories-file /etc/apk/repositories \
        wolfi-baselayout \
        ca-certificates-bundle \
        glibc \
        glibc-locale-posix \
        tzdata \
        busybox \
        "python-${PYTHON_VERSION}" \
        "python-${PYTHON_VERSION}-dev" \
        "py${PYTHON_VERSION}-pip" \
        "${GO_PACKAGE}" \
        "${RUST_PACKAGE}" \
        gcc \
        glibc-dev \
        binutils \
        make \
        pkgconf \
        ${EXTRA_PACKAGES}; \
    # --no-scripts skips busybox's applet-link trigger, so create the links here.
    chroot /rootfs /bin/busybox --install -s; \
    # Ensure unversioned python entry points exist.
    for l in python3 python; do \
        [ -e "/rootfs/usr/bin/$l" ] || ln -s "python${PYTHON_VERSION}" "/rootfs/usr/bin/$l"; \
    done; \
    # Fail the build if the Python we got is not the requested minor version.
    chroot /rootfs /usr/bin/python3 --version | grep -Eq "^Python ${PYTHON_VERSION}\.[0-9]+$"; \
    # Non-root user (UID/GID 65532, the Chainguard/distroless convention).
    grep -q '^nonroot:' /rootfs/etc/passwd || \
        echo 'nonroot:x:65532:65532:nonroot:/home/nonroot:/bin/sh' >> /rootfs/etc/passwd; \
    grep -q '^nonroot:' /rootfs/etc/group || \
        echo 'nonroot:x:65532:' >> /rootfs/etc/group; \
    mkdir -p /rootfs/home/nonroot /rootfs/tmp; \
    chown -R 65532:65532 /rootfs/home/nonroot; \
    chmod 0750 /rootfs/home/nonroot; \
    chmod 1777 /rootfs/tmp; \
    # Hardening: strip setuid/setgid bits; drop apk caches and signing keys.
    # /lib/apk/db is deliberately KEPT so scanners (grype/trivy/syft) can see
    # every installed package. Deleting it would hide CVEs, not fix them.
    find /rootfs -xdev -type f -perm /6000 -exec chmod a-s {} +; \
    rm -rf /rootfs/var/cache/apk/* /rootfs/etc/apk/keys /rootfs/root/.cache

FROM scratch

COPY --from=builder /rootfs/ /

ENV PATH=/home/nonroot/.cargo/bin:/home/nonroot/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    HOME=/home/nonroot \
    LANG=C.UTF-8 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    GOTOOLCHAIN=local \
    GOPATH=/home/nonroot/go \
    GOCACHE=/home/nonroot/.cache/go-build \
    GOFLAGS=-trimpath \
    CARGO_HOME=/home/nonroot/.cargo

USER 65532:65532
WORKDIR /home/nonroot

CMD ["/bin/sh"]
