# Publish a release

Configure a GPG signing key before pushing a release tag. Each release contains ZIP archives for Linux and macOS on amd64 and arm64, a protocol 6 manifest, SHA-256 checksums, and a detached signature for those checksums.

1. Add the signing key to the repository secret `GPG_PRIVATE_KEY` and its passphrase to `GPG_PASSPHRASE`.
2. Publish the public signing key through a trusted channel for consumers to verify release checksums.
3. Run the provider tests and a local snapshot build as documented in [Develop](../README.md#develop).
4. Create and push a semantic version tag such as `v0.1.0`. The release workflow tests the provider, builds the packages, signs the checksums, and publishes a GitHub release.

Pushing a release tag publishes downloadable binaries. A GitHub release does not register the provider in the OpenTofu registry. Follow the [OpenTofu provider submission requirements](https://github.com/opentofu/registry/blob/main/README.md) separately. The repository must use the registry's required `terraform-provider-opadmin` name before a standard submission.

## Install through a filesystem mirror

Verify the checksum signature with the trusted public signing key before installing an archive. The version and platform in these commands must match the selected release.

1. Verify the signature over the downloaded checksum file.

   ```sh
   gpg --verify terraform-provider-opadmin_0.1.0_SHA256SUMS.sig terraform-provider-opadmin_0.1.0_SHA256SUMS
   ```

2. Compare the selected archive's SHA-256 hash with its entry in the verified checksum file.

   ```sh
   shasum -a 256 terraform-provider-opadmin_0.1.0_darwin_arm64.zip
   ```

3. Extract the archive into a filesystem mirror directory for its source, version, and platform.

   ```sh
   mkdir -p ./provider-mirror/registry.opentofu.org/pleme-io/opadmin/0.1.0/darwin_arm64
   unzip terraform-provider-opadmin_0.1.0_darwin_arm64.zip -d ./provider-mirror/registry.opentofu.org/pleme-io/opadmin/0.1.0/darwin_arm64
   ```

4. Configure OpenTofu to use that mirror in its CLI configuration. Replace the example path with the absolute mirror path.

   ```hcl
   provider_installation {
     filesystem_mirror {
       path    = "/absolute/path/to/provider-mirror"
       include = ["registry.opentofu.org/pleme-io/opadmin"]
     }
     direct {
       exclude = ["registry.opentofu.org/pleme-io/opadmin"]
     }
   }
   ```

5. Run `tofu init` in the configuration that requires the provider.
