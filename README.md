# 1Password administration provider

`opadmin` manages 1Password vaults and group access through the official Go SDK. It authenticates with `OP_SERVICE_ACCOUNT_TOKEN` and does not require the 1Password CLI.

The provider creates vaults, updates their titles and descriptions, and imports vaults by ID. Group access resources manage the permissions for one group and one vault. The provisioning service account needs permission to create vaults. Use separate deployment service accounts with access to the vault for their service and environment.

## Configure a vault

Install the provider through a filesystem mirror until a registry listing becomes available. Set `OP_SERVICE_ACCOUNT_TOKEN` in the environment before running OpenTofu. Keep the token out of configuration and outputs.

```hcl
terraform {
  required_providers {
    opadmin = {
      source = "registry.opentofu.org/pleme-io/opadmin"
    }
  }
}

provider "opadmin" {}

resource "opadmin_vault" "tack_qa" {
  title       = "tack-qa"
  description = "Tack QA deployment credentials."

  lifecycle {
    prevent_destroy = true
  }
}
```

## Develop

Development requires Go at the version specified by the module, OpenTofu on `PATH`, and GoReleaser v2 for packaging. The tests supply a fake SDK client and do not contact a live 1Password account.

```sh
go test ./...
go vet ./...
go build ./...
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign
```

Snapshots create local archives without publishing them. Follow [Publish a release](docs/release.md) to configure signing and publish versioned packages.
