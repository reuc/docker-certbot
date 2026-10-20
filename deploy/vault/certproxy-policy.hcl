# Policy for certproxy's own Vault identity (AppRole or Kubernetes role).
# Paths assume KV v2 mounted at "secret/" (KV_MOUNT) with the defaults
# KV_CERTS_PREFIX=certs, KV_DNS_PATH=certproxy/dns, KV_APP_PATH=certproxy/app.

# Write issued certificates (and read them back for the UI certificate).
path "secret/data/certs/*" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/certs/*" {
  capabilities = ["read", "list"]
}

# certproxy's configuration: DNS provider credentials and its own secrets.
path "secret/data/certproxy/dns" {
  capabilities = ["read"]
}
path "secret/data/certproxy/app" {
  capabilities = ["read"]
}

# One-time enrollment links for operators (first launch, and
# `certproxy admin invite`). certproxy writes the link here and deletes the
# whole entry (all versions) once it has been used.
path "secret/data/certproxy/bootstrap" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/certproxy/bootstrap" {
  capabilities = ["delete"]
}
