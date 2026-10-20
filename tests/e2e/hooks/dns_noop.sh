#!/usr/bin/env sh
# No-op acme.sh DNS hook for the end-to-end test: Pebble runs with
# PEBBLE_VA_ALWAYS_VALID=1, so no TXT record is needed.
dns_noop_add() { return 0; }
dns_noop_rm() { return 0; }
