# Example policy for an app that may obtain a certificate for
# app.example.com and www.app.example.com.
#
# "cert-requests/..." is not a real mount: certproxy only asks Vault whether
# the app's token has "update" there (sys/capabilities-self). Wildcard names
# use "wildcard." in place of "*." (e.g. cert-requests/wildcard.example.com).

# Allowed to ask certproxy for these names.
path "cert-requests/app.example.com" {
  capabilities = ["update"]
}
path "cert-requests/www.app.example.com" {
  capabilities = ["update"]
}

# Allowed to read the issued certificate (stored under the first name).
path "secret/data/certs/app.example.com" {
  capabilities = ["read"]
}
