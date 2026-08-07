terraform {
  required_version = ">= 1.9"

  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.80"
    }
  }
}

# Credentials come from the same place the `scw` CLI reads them (~/.config/scw/config.yaml, or the
# SCW_* environment). Nothing here holds a key, and none may ever be added: a kubeconfig or an API
# secret in this repo is a committed credential.
provider "scaleway" {
  zone = var.zone
}
