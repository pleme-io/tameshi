{
  description = "Tameshi (試し) - Deterministic integrity attestation library for infrastructure layers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crate2nix = {
      url = "github:nix-community/crate2nix";
      flake = false;
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, substrate, crate2nix, fenix, devenv, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];

      forEachSystem = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          rustLibrary = import "${substrate}/lib/rust-library.nix" {
            inherit system nixpkgs crate2nix devenv;
            nixLib = substrate;
          };
          result = rustLibrary {
            name = "tameshi";
            src = ./.;
          };

          verifyApps = {
            # Layer 1: proptest (38 properties x 10k cases)
            verify-proptest = {
              type = "app";
              program = toString (pkgs.writeShellScript "verify-proptest" ''
                set -euo pipefail
                echo "=== Layer 1: Proptest (38 properties x 10,000 cases) ==="
                cargo test --test proptest_properties -- --test-threads=1
              '');
            };

            # Layer 1 nightly: proptest with 100k cases
            verify-proptest-nightly = {
              type = "app";
              program = toString (pkgs.writeShellScript "verify-proptest-nightly" ''
                set -euo pipefail
                echo "=== Layer 1 (nightly): Proptest (38 properties x 100,000 cases) ==="
                PROPTEST_CASES=100000 cargo test --test proptest_properties -- --test-threads=1
              '');
            };

            # Layer 2: Kani bounded model checking (16 harnesses)
            verify-kani = {
              type = "app";
              program = toString (pkgs.writeShellScript "verify-kani" ''
                set -euo pipefail
                echo "=== Layer 2: Kani Bounded Model Checking (44 harnesses) ==="
                cargo kani --manifest-path proofs/kani/Cargo.toml --output-format terse
              '');
            };

            # Layer 3: F* formal proofs (8 modules)
            verify-fstar = {
              type = "app";
              program = toString (pkgs.writeShellScript "verify-fstar" ''
                set -euo pipefail
                echo "=== Layer 3: F* Formal Proofs (10 modules) ==="
                cd fstar
                fstar.exe --include . \
                  Tameshi.Hash.fst \
                  Tameshi.Merkle.fst \
                  Tameshi.Artifact.fst \
                  Tameshi.Chain.fst \
                  Tameshi.Signing.fst \
                  Tameshi.Reduction.fst \
                  Tameshi.DomainSeparation.fst \
                  Tameshi.NonInterference.fst \
                  Tameshi.Refinement.fst \
                  Tameshi.FragmentedSovereignty.fst
              '');
            };

            # Run all verification layers
            verify-all = {
              type = "app";
              program = toString (pkgs.writeShellScript "verify-all" ''
                set -euo pipefail
                echo "=== Tameshi Three-Layer Formal Verification ==="
                echo ""

                echo "--- Layer 1: Proptest (38 properties x 10,000 cases) ---"
                cargo test --test proptest_properties -- --test-threads=1
                echo ""

                echo "--- Layer 2: Kani Bounded Model Checking (44 harnesses) ---"
                if command -v cargo-kani &>/dev/null; then
                  cargo kani --manifest-path proofs/kani/Cargo.toml --output-format terse
                else
                  echo "SKIP: cargo-kani not installed (cargo install --locked kani-verifier && cargo kani setup)"
                fi
                echo ""

                echo "--- Layer 3: F* Formal Proofs (10 modules) ---"
                if command -v fstar.exe &>/dev/null; then
                  cd fstar
                  fstar.exe --include . \
                    Tameshi.Hash.fst \
                    Tameshi.Merkle.fst \
                    Tameshi.Artifact.fst \
                    Tameshi.Chain.fst \
                    Tameshi.Signing.fst \
                    Tameshi.Reduction.fst \
                    Tameshi.DomainSeparation.fst
                  cd ..
                else
                  echo "SKIP: fstar.exe not installed (opam install fstar)"
                fi
                echo ""

                echo "=== Verification complete ==="
              '');
            };
          };
        in f result verifyApps
      );
    in {
      packages = forEachSystem (r: _: r.packages);
      devShells = forEachSystem (r: _: r.devShells);
      apps = forEachSystem (r: va: r.apps // va);
    };
}
