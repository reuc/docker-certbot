#!/usr/bin/env bash
# Run a command; if it fails, turn its [FAIL] lines and the last 60 lines of
# output into GitHub annotations, so failures are visible on the PR (and via
# the checks API) without downloading the job log.
#
#   .github/scripts/run-annotated.sh "<title>" <command> [args...]
set -uo pipefail
title=$1
shift
log=$(mktemp)
"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then
  grep -E '^\[FAIL\]' "$log" | while IFS= read -r line; do
    echo "::error title=${title}::${line}"
  done
  tail_out=$(tail -n 60 "$log" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | sed ':a;N;$!ba;s/\n/%0A/g')
  echo "::error title=${title} (last 60 lines)::${tail_out}"
fi
rm -f "$log"
exit "$rc"
