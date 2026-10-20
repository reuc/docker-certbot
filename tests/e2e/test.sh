#!/usr/bin/env bash
# End-to-end assertions against a running certproxy, Vault and ACME CA.
#
# Env:
#   VAULT_ADDR      Vault URL reachable from here
#   CERTPROXY_URL   certproxy URL reachable from here (plain HTTP in tests)
#   CREDS_DIR       dir with app1/app2 role_id/secret_id files (setup-vault.sh)
#   ADMIN_CMD       command that runs `certproxy admin` (args appended)
#   DATA_DIR        optional: certproxy's data dir, to check nothing secret is left
set -euo pipefail
: "${VAULT_ADDR:?}" "${CERTPROXY_URL:?}" "${CREDS_DIR:?}" "${ADMIN_CMD:?}"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

login() { # app -> token
  curl -fsS -X POST "$VAULT_ADDR/v1/auth/approle/login" \
    -d "$(jq -n --arg r "$(cat "$CREDS_DIR/$1_role_id")" --arg s "$(cat "$CREDS_DIR/$1_secret_id")" '{role_id: $r, secret_id: $s}')" |
    jq -r .auth.client_token
}

api() { # token method path [json] -> writes body to $WORK/body, prints status
  curl -sS -o "$WORK/body" -w '%{http_code}' -X "$2" -H "X-Vault-Token: $1" \
    ${4:+-H "Content-Type: application/json" -d "$4"} "$CERTPROXY_URL$3"
}

wait_job() { # token job_id -> final job JSON on stdout
  for _ in $(seq 1 90); do
    api "$1" GET "/api/v1/jobs/$2" >/dev/null
    case "$(jq -r .status "$WORK/body")" in
      succeeded) cat "$WORK/body"; return 0 ;;
      failed) jq -r .error "$WORK/body" >&2; return 1 ;;
    esac
    sleep 2
  done
  echo "timed out waiting for job $2" >&2
  return 1
}

totp() { # base32 secret -> current code
  python3 - "$1" <<'PY'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]
k = base64.b32decode(s + "=" * (-len(s) % 8))
h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
PY
}

# ---- readiness ---------------------------------------------------------------
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$CERTPROXY_URL/readyz")" = 200 ] && break
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$CERTPROXY_URL/readyz")" = 200 ] || fail "certproxy not ready"
pass "certproxy ready"

APP1=$(login app1)
APP2=$(login app2)
REQ='{"domains":["app1.e2e.test","www.app1.e2e.test"]}'

# ---- authorization -----------------------------------------------------------
[ "$(api invalid-token POST /api/v1/certificates "$REQ")" = 401 ] || fail "invalid token not rejected"
pass "invalid Vault token -> 401"

[ "$(api "$APP2" POST /api/v1/certificates "$REQ")" = 403 ] || fail "app2 not rejected"
[ "$(jq -r '.denied | length' "$WORK/body")" = 2 ] || fail "403 should list both denied domains"
pass "app without request permission -> 403"

[ "$(api "$APP1" POST /api/v1/certificates '{"domains":["app1.e2e.test","other.e2e.test"]}')" = 403 ] || fail "partial permission not rejected"
pass "request including an unauthorized domain -> 403"

# ---- issuance ----------------------------------------------------------------
[ "$(api "$APP1" POST /api/v1/certificates "$REQ")" = 202 ] || fail "request not accepted: $(cat "$WORK/body")"
JOB=$(jq -r .job_id "$WORK/body")
wait_job "$APP1" "$JOB" >"$WORK/job.json" || fail "job $JOB failed"
[ "$(jq -r .vault_path "$WORK/job.json")" = secret/data/certs/app1.e2e.test ] || fail "unexpected vault path"
pass "certificate issued (job $JOB)"

[ "$(api "$APP2" GET "/api/v1/jobs/$JOB")" = 404 ] || fail "app2 can see app1's job"
pass "jobs are private to the requesting identity"

# The app reads the certificate straight from Vault with its own token.
curl -fsS -H "X-Vault-Token: $APP1" "$VAULT_ADDR/v1/secret/data/certs/app1.e2e.test" >"$WORK/secret.json" ||
  fail "app1 cannot read its certificate from Vault"
jq -r .data.data.certificate "$WORK/secret.json" >"$WORK/cert.pem"
jq -r .data.data.private_key "$WORK/secret.json" >"$WORK/key.pem"
openssl x509 -in "$WORK/cert.pem" -noout -ext subjectAltName | grep -q 'DNS:www.app1.e2e.test' || fail "SAN missing"
[ "$(openssl x509 -in "$WORK/cert.pem" -noout -pubkey | openssl sha256)" = \
  "$(openssl pkey -in "$WORK/key.pem" -pubout | openssl sha256)" ] || fail "key does not match certificate"
pass "certificate and matching key readable from Vault by app1"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $APP2" "$VAULT_ADDR/v1/secret/data/certs/app1.e2e.test")
[ "$code" = 403 ] || fail "app2 can read app1's certificate (HTTP $code)"
pass "other apps cannot read the certificate"

[ "$(api "$APP1" POST /api/v1/certificates "$REQ")" = 200 ] || fail "repeat request should return existing cert: $(cat "$WORK/body")"
[ "$(jq -r .status "$WORK/body")" = exists ] || fail "expected status=exists"
pass "repeat request reuses the valid certificate"

[ "$(api "$APP1" GET /api/v1/certificates/app1.e2e.test)" = 200 ] || fail "metadata lookup failed"
jq -e 'has("private_key") | not' "$WORK/body" >/dev/null || fail "API must not return keys"
pass "metadata API works and returns no key material"

if [ -n "${DATA_DIR:-}" ]; then
  ! grep -rqs 'SAVED_' "$DATA_DIR/acme" || fail "acme.sh saved credentials left in $DATA_DIR/acme"
  ! grep -rqs 'e2e-fake-cloudflare-token' "$DATA_DIR" || fail "DNS token found on disk"
  [ ! -e "$DATA_DIR/acme/app1.e2e.test_ecc" ] || fail "domain key directory left on disk"
  pass "no certificate keys or DNS credentials left in the data dir"
fi

# ---- admin UI ----------------------------------------------------------------
PW="e2e-$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
printf '%s\n' "$PW" | $ADMIN_CMD create e2e-admin >"$WORK/enroll.txt" || fail "admin create failed"
SECRET=$(sed -n 's/^TOTP secret (base32): //p' "$WORK/enroll.txt")
[ -n "$SECRET" ] || fail "no TOTP secret printed"
pass "admin created via CLI"

JAR="$WORK/cookies"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" --data-urlencode username=e2e-admin --data-urlencode "password=$PW" "$CERTPROXY_URL/login")
[ "$code" = 303 ] || fail "password step failed (HTTP $code)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" --data-urlencode "code=$(totp "$SECRET")" "$CERTPROXY_URL/login/totp")
[ "$code" = 303 ] || fail "TOTP step failed (HTTP $code)"
curl -fsS -b "$JAR" "$CERTPROXY_URL/" >"$WORK/dash.html"
grep -q 'app1.e2e.test' "$WORK/dash.html" || fail "dashboard does not list the certificate"
pass "admin login with password + TOTP; dashboard lists the certificate"

curl -fsS -b "$JAR" "$CERTPROXY_URL/certs/app1.e2e.test" >"$WORK/cert.html"
CSRF=$(grep -o 'name="csrf" value="[^"]*"' "$WORK/cert.html" | head -1 | sed 's/.*value="//; s/"$//')
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" --data-urlencode "csrf=$CSRF" "$CERTPROXY_URL/certs/app1.e2e.test/renew")
[ "$code" = 303 ] || fail "renew failed (HTTP $code)"
for _ in $(seq 1 90); do
  v=$(curl -fsS -H "X-Vault-Token: $APP1" "$VAULT_ADDR/v1/secret/data/certs/app1.e2e.test" | jq -r .data.metadata.version)
  [ "$v" -ge 2 ] && break
  sleep 2
done
[ "$v" -ge 2 ] || fail "renewal did not write a new Vault version"
NEWKEY=$(curl -fsS -H "X-Vault-Token: $APP1" "$VAULT_ADDR/v1/secret/data/certs/app1.e2e.test" | jq -r .data.data.private_key | openssl sha256)
[ "$NEWKEY" != "$(openssl sha256 <"$WORK/key.pem")" ] || fail "renewal reused the old key"
pass "renew from the UI wrote Vault version $v with a new key"

curl -fsS -b "$JAR" "$CERTPROXY_URL/audit" | grep -q 'login-totp' || fail "audit log missing login"
pass "audit log records admin activity"

echo "All end-to-end checks passed."
