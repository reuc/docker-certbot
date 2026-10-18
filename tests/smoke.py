"""Smoke test run inside the image (piped via stdin, so it needs no shell).

Checks the user, the Python version, and that Go, cgo, and Rust can compile and
run real programs. Set EXPECT_SHELL=1 or 0 to check whether /bin/sh exists.
"""

import os
import shutil
import subprocess
import sys
import tempfile

failures = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{(': ' + detail) if detail else ''}")
    if not ok:
        failures.append(name)


def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


check("non-root uid 65532", os.getuid() == 65532, str(os.getuid()))
check("python 3.14.x", sys.version_info[:2] == (3, 14), sys.version.split()[0])

for mod in ("ssl", "sqlite3", "ctypes", "venv", "zlib", "lzma", "bz2"):
    try:
        __import__(mod)
        check(f"import {mod}", True)
    except Exception as e:  # noqa: BLE001
        check(f"import {mod}", False, repr(e))

rc, out = run([sys.executable, "-m", "pip", "--version"])
check("pip", rc == 0, out)

expect_shell = os.environ.get("EXPECT_SHELL")
if expect_shell is not None:
    has_shell = os.path.lexists("/bin/sh")
    check("shell presence", has_shell == (expect_shell == "1"), f"/bin/sh exists={has_shell}")
check("no apk", shutil.which("apk") is None)

with tempfile.TemporaryDirectory() as d:
    # C via both compiler entry points (Wolfi routes these through gcc-wrapper)
    with open(os.path.join(d, "hello.c"), "w") as f:
        f.write('#include <stdio.h>\nint main(void){ puts("c-ok"); return 0; }\n')
    for compiler in ("cc", "gcc"):
        exe = os.path.join(d, f"hello-{compiler}")
        rc, out = run([compiler, "-o", exe, "hello.c"], cwd=d)
        check(f"{compiler} build", rc == 0, out)
        if rc == 0:
            rc, out = run([exe])
            check(f"{compiler} run", out == "c-ok", out)

    # The OpenSSF hardening spec must still be applied.
    rc, out = run(["gcc", "-v"])
    check("gcc uses hardening spec", "openssf.spec" in out or "gcc_spec_file" in out,
          next((l for l in out.splitlines() if "Reading specs" in l), "no 'Reading specs' line"))

    # Go (pure)
    with open(os.path.join(d, "main.go"), "w") as f:
        f.write('package main\nimport "fmt"\nfunc main(){ fmt.Println("go-ok") }\n')
    rc, out = run(["go", "build", "-o", "hello-go", "main.go"], cwd=d)
    check("go build", rc == 0, out)
    if rc == 0:
        rc, out = run([os.path.join(d, "hello-go")])
        check("go run", out == "go-ok", out)

    # Go with cgo (exercises gcc + glibc-dev)
    cgo = os.path.join(d, "cgo")
    os.mkdir(cgo)
    with open(os.path.join(cgo, "main.go"), "w") as f:
        f.write(
            'package main\n/*\n#include <stdlib.h>\nint add(int a,int b){return a+b;}\n*/\n'
            'import "C"\nimport "fmt"\nfunc main(){ fmt.Println(int(C.add(2,3))) }\n'
        )
    rc, out = run(["go", "build", "-o", "hello-cgo", "main.go"], cwd=cgo)
    check("cgo build", rc == 0, out)
    if rc == 0:
        rc, out = run([os.path.join(cgo, "hello-cgo")])
        check("cgo run", out == "5", out)

    # Rust via cargo (offline, no dependencies)
    rc, out = run(["cargo", "new", "--vcs", "none", "--quiet", "hello-rs"], cwd=d)
    check("cargo new", rc == 0, out)
    if rc == 0:
        proj = os.path.join(d, "hello-rs")
        rc, out = run(["cargo", "build", "--release", "--offline", "--quiet"], cwd=proj)
        check("cargo build", rc == 0, out)
        if rc == 0:
            rc, out = run([os.path.join(proj, "target", "release", "hello-rs")])
            check("rust run", out == "Hello, world!", out)

print()
if failures:
    print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("All smoke checks passed.")
