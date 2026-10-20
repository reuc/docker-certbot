#!/usr/bin/env bash
# Configure a Vault dev server for the end-to-end test:
#   - certproxy's policy, AppRole role and KV secrets (via deploy/vault/setup.sh)
#   - app1: may request app1.e2e.test + www.app1.e2e.test and read its cert
#   - app2: authenticated, but no request permission
# Writes role/secret IDs into $1.
set -euo pipefail
: "${VAULT_ADDR:?}" "${VAULT_TOKEN:?}"
OUT=${1:?output dir}
HERE=$(cd "$(dirname "$0")" && pwd)

CF_TOKEN=e2e-fake-cloudflare-token "$HERE/../../deploy/vault/setup.sh" "$OUT"

api() {
  curl -fsS -X "$1" -H "X-Vault-Token: $VAULT_TOKEN" ${3:+-H "Content-Type: application/json" -d "$3"} "$VAULT_ADDR/v1/$2"
}

app1='path "cert-requests/app1.e2e.test" { capabilities = ["update"] }
path "cert-requests/www.app1.e2e.test" { capabilities = ["update"] }
path "secret/data/certs/app1.e2e.test" { capabilities = ["read"] }'
app2='path "secret/data/certs/app2.e2e.test" { capabilities = ["read"] }'

for app in app1 app2; do
  pol=${!app}
  api PUT "sys/policies/acl/$app" "$(jq -n --arg p "$pol" '{policy: $p}')" >/dev/null
  api POST "auth/approle/role/$app" "$(jq -n --arg p "$app" '{token_policies: [$p], token_ttl: "10m"}')" >/dev/null
  api GET "auth/approle/role/$app/role-id" | jq -r .data.role_id >"$OUT/${app}_role_id"
  api POST "auth/approle/role/$app/secret-id" '{}' | jq -r .data.secret_id >"$OUT/${app}_secret_id"
done
echo "vault configured"
