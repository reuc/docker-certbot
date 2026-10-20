#!/usr/bin/env bash
# Run the certproxy end-to-end test with Docker Compose.
#   CERTPROXY_IMAGE=wolfi-certproxy:<tag> tests/e2e/run.sh
set -euo pipefail
: "${CERTPROXY_IMAGE:?set CERTPROXY_IMAGE}"
HERE=$(cd "$(dirname "$0")" && pwd)
export CERTPROXY_IMAGE
E2E_CREDS=$(mktemp -d)
export E2E_CREDS
dc() { docker compose -f "$HERE/compose.yaml" "$@"; }

finish() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "---- certproxy logs ----"
    dc logs --no-color --tail 100 certproxy || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$E2E_CREDS"
  exit "$rc"
}
trap finish EXIT

dc up -d vault pebble
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:8200/v1/sys/health >/dev/null && break
  sleep 1
done

VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root "$HERE/setup-vault.sh" "$E2E_CREDS"
dc cp pebble:/test/certs/pebble.minica.pem "$E2E_CREDS/pebble-ca.pem"
# The container runs as UID 65532; test-only credentials can be world-readable.
chmod 0755 "$E2E_CREDS" && chmod 0644 "$E2E_CREDS"/*

dc up -d certproxy

VAULT_ADDR=http://127.0.0.1:8200 \
CERTPROXY_URL=http://127.0.0.1:8080 \
CREDS_DIR="$E2E_CREDS" \
ADMIN_CMD="docker compose -f $HERE/compose.yaml exec -T certproxy certproxy admin" \
  "$HERE/test.sh"
