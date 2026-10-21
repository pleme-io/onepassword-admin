{
  description = "terraform-provider-opadmin — 1Password vaults and group vault access, beside the 1Password/onepassword provider";

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";
    substrate.url = "github:pleme-io/substrate";
  };

  outputs =
    { self, nixpkgs, substrate, ... }:
    (import "${substrate}/lib/build/go/tool-release-flake.nix" { inherit nixpkgs; })
      {
        toolName = "terraform-provider-opadmin";
        version = "0.1.0";
        src = self;
        vendorHash = "sha256-I/Tn7BH+xJ3Lh8k9VKSvDrPfOLbe2c9RSdz0Lf0CyTg=";
        versionLdflags = { "main.version" = "0.1.0"; };
        repo = "pleme-io/onepassword-admin";
      };
}
