"""Smoke test for the Certbot image (piped via stdin to the venv's Python).

Checks the user, the absence of a shell/apk/pip, the Certbot version, that
every official DNS plugin is installed and loads, and that Certbot runs with
its default directories. Set EXPECT_CERTBOT_VERSION to the pinned version.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
from importlib.metadata import entry_points, version

DNS_PLUGINS = [
    "cloudflare", "digitalocean", "dnsimple", "dnsmadeeasy", "gehirn",
    "google", "linode", "luadns", "nsone", "ovh", "rfc2136", "route53",
    "sakuracloud",
]
BUILTIN_PLUGINS = ["manual", "standalone", "webroot"]
DEFAULT_DIRS = ["/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt"]

failures = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{(': ' + detail) if detail else ''}")
    if not ok:
        failures.append(name)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


check("non-root uid 65532", os.getuid() == 65532, str(os.getuid()))
check("python 3.14.x", sys.version_info[:2] == (3, 14), sys.version.split()[0])
check("no shell", not os.path.lexists("/bin/sh"))
check("no apk", shutil.which("apk") is None)
check("no pip in venv", importlib.util.find_spec("pip") is None)
check("CA bundle present", os.path.isfile(os.environ.get("REQUESTS_CA_BUNDLE", "")),
      os.environ.get("REQUESTS_CA_BUNDLE", "unset"))

want = os.environ.get("EXPECT_CERTBOT_VERSION")
got = version("certbot")
check("certbot version", want is None or got == want, f"{got} (expected {want})")

registered = {e.name: e for e in entry_points(group="certbot.plugins")}
for name in [f"dns-{p}" for p in DNS_PLUGINS] + BUILTIN_PLUGINS:
    ep = registered.get(name)
    if ep is None:
        check(f"plugin {name}", False, "not registered")
        continue
    try:
        ep.load()
        check(f"plugin {name}", True)
    except Exception as e:  # noqa: BLE001
        check(f"plugin {name}", False, repr(e))

for d in DEFAULT_DIRS:
    check(f"writable {d}", os.access(d, os.W_OK))

rc, out = run(["certbot", "--version"])
check("certbot --version", rc == 0 and got in out, out)

rc, out = run(["certbot", "plugins", "--text"])
listed = {line[2:].strip() for line in out.splitlines() if line.startswith("* ")}
missing = sorted(f"dns-{p}" for p in DNS_PLUGINS if f"dns-{p}" not in listed)
check("certbot plugins", rc == 0 and not missing,
      f"missing {missing}" if missing else f"{len(listed)} listed")

print()
if failures:
    print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("All Certbot smoke checks passed.")
