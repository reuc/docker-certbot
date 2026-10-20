#!/bin/sh
# Smoke test for the certproxy image, run inside the container:
#   docker run ... --entrypoint /bin/sh IMAGE -s < tests/smoke_certproxy.sh
# Needs a writable /data (tmpfs) and loopback networking only.
set -u
failures=0
check() { # name, then a command
  name=$1; shift
  if "$@" >/tmp/out 2>&1; then echo "[PASS] $name"; else echo "[FAIL] $name: $(head -c 300 /tmp/out)"; failures=$((failures + 1)); fi
}

check "non-root uid 65532" test "$(id -u)" = 65532
check "no apk" sh -c '! command -v apk'
check "certproxy --version" certproxy --version
check "acme.sh --version" acme.sh --version
check "acme.sh Cloudflare hook present" test -f /usr/share/acme.sh/dnsapi/dns_cf.sh
check "openssl available" openssl version
check "curl available" curl --version
check "/data writable" sh -c 'touch /data/.w && rm /data/.w'
check "no setuid binaries" sh -c '[ -z "$(find / -xdev -perm -4000 -type f 2>/dev/null)" ]'

# Start the server without Vault: it must stay up, answer /healthz and
# report not-ready on /readyz.
TLS_MODE=none LISTEN_ADDR=127.0.0.1:8080 VAULT_ADDR=http://127.0.0.1:1 VAULT_AUTH=token \
  VAULT_TOKEN_FILE=/nonexistent certproxy serve >/tmp/serve.log 2>&1 &
pid=$!
i=0
until wget -q -O /tmp/health http://127.0.0.1:8080/healthz 2>/dev/null || [ $i -ge 20 ]; do sleep 0.5; i=$((i + 1)); done
check "/healthz responds" grep -q ok /tmp/health
check "/readyz is 503 without Vault" sh -c '! wget -q -O- http://127.0.0.1:8080/readyz'
check "login page renders" sh -c 'wget -q -O- http://127.0.0.1:8080/login | grep -q "Sign in"'
check "security headers set" sh -c 'wget -S -q -O /dev/null http://127.0.0.1:8080/healthz 2>&1 | grep -qi "content-security-policy"'
kill $pid 2>/dev/null

echo
if [ $failures -gt 0 ]; then echo "$failures check(s) failed"; cat /tmp/serve.log | tail -20; exit 1; fi
echo "All certproxy smoke checks passed."
