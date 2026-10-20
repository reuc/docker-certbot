#!/usr/bin/env bash
# One-time Vault setup for certproxy. Needs an admin token with permission to
# manage auth methods, policies and the KV mount.
#
#   export VAULT_ADDR=https://vault.netseclabs.com VAULT_TOKEN=...
#   CF_TOKEN=... ./deploy/vault/setup.sh [output-dir]
#
# Creates the "certproxy" policy and AppRole role, stores the Cloudflare API
# token and a fresh TOTP encryption key in KV, and writes the role_id and a
# secret_id for Docker Compose to the output dir (default: deploy/compose/secrets).
set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR}" "${VAULT_TOKEN:?set VAULT_TOKEN}" "${CF_TOKEN:?set CF_TOKEN (Cloudflare API token with Zone:DNS:Edit)}"
KV_MOUNT=${KV_MOUNT:-secret}
ROLE=${ROLE:-certproxy}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/../compose/secrets}

api() { # method path [json]
  curl -fsS -X "$1" -H "X-Vault-Token: $VAULT_TOKEN" ${VAULT_NAMESPACE:+-H "X-Vault-Namespace: $VAULT_NAMESPACE"} \
    ${3:+-H "Content-Type: application/json" -d "$3"} "$VAULT_ADDR/v1/$2"
}

# AppRole auth (ignore "already in use").
api POST sys/auth/approle '{"type":"approle"}' >/dev/null 2>&1 || true

# KV v2 at $KV_MOUNT (ignore if it already exists).
api POST "sys/mounts/$KV_MOUNT" '{"type":"kv","options":{"version":"2"}}' >/dev/null 2>&1 || true

policy=$(sed "s#secret/#$KV_MOUNT/#g" "$HERE/certproxy-policy.hcl")
api PUT "sys/policies/acl/$ROLE" "$(jq -n --arg p "$policy" '{policy: $p}')" >/dev/null

api POST "auth/approle/role/$ROLE" \
  "$(jq -n --arg p "$ROLE" '{token_policies: [$p], token_ttl: "1h", token_max_ttl: "24h", secret_id_ttl: "0"}')" >/dev/null

api POST "$KV_MOUNT/data/certproxy/dns" "$(jq -n --arg t "$CF_TOKEN" '{data: {CF_Token: $t}}')" >/dev/null

# Keep an existing TOTP key: replacing it would lock out every admin.
if ! api GET "$KV_MOUNT/data/certproxy/app" >/dev/null 2>&1; then
  key=$(head -c 32 /dev/urandom | base64)
  api POST "$KV_MOUNT/data/certproxy/app" "$(jq -n --arg k "$key" '{data: {totp_key: $k}}')" >/dev/null
fi

mkdir -p "$OUT"
umask 077
api GET "auth/approle/role/$ROLE/role-id" | jq -r .data.role_id >"$OUT/vault_role_id"
api POST "auth/approle/role/$ROLE/secret-id" '{}' | jq -r .data.secret_id >"$OUT/vault_secret_id"
echo "Wrote $OUT/vault_role_id and $OUT/vault_secret_id"

# Compose mounts these files as-is; the container runs as UID 65532.
if [ "$(id -u)" = 0 ]; then
  chown 65532:65532 "$OUT/vault_role_id" "$OUT/vault_secret_id"
else
  echo "Now run: sudo chown 65532:65532 $OUT/vault_role_id $OUT/vault_secret_id"
fi
