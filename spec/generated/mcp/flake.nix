{
  description = "tameshi_mcp -- Deterministic integrity attestation and compliance verification for infrastructure.

Tameshi unifies two complementary services:

- **sekiban** -- Kubernetes integrity gating via deterministic BLAKE3 signature
  verification across infrastructure layers (Nix, OCI, Helm, Tofu, etc.).
- **kensa** -- Compliance engine that runs NIST/OSCAL assessments and drives a
  multi-stage product certification pipeline.

Together they provide a cryptographically verifiable chain from source code
through build, image, chart, deployment, and compliance -- producing a single
certification hash that attests the entire stack.
";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    crate2nix,
    flake-utils,
    substrate,
    devenv,
  }:
    (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils devenv;
    }) {
      toolName = "tameshi_mcp";
      src = self;
      repo = "pleme-io/tameshi_mcp";
      crateOverrides = {
        rmcp = attrs: {
          CARGO_CRATE_NAME = "rmcp";
        };
      };
    }
    // {
      homeManagerModules.default = import ./module {
        hmHelpers = import "${substrate}/lib/hm-service-helpers.nix" { lib = nixpkgs.lib; };
      };
    };
}
