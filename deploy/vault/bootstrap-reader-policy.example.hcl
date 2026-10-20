# Example policy for the operator(s) allowed to pick up certproxy's one-time
# enrollment link on first launch (or after `certproxy admin invite`):
#
#   vault kv get -field=enrollment_url secret/certproxy/bootstrap
#
# Grant it only to the people who should be able to become the first admin,
# and revoke tokens created just for this once enrollment is done. The link
# is single-use and expires (INVITE_TTL_MINUTES, default 30); certproxy
# deletes the entry when it's used.
path "secret/data/certproxy/bootstrap" {
  capabilities = ["read"]
}
