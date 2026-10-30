{
  description = "Tameshi (試し) - Deterministic integrity attestation library for infrastructure layers";

  # substrate.rust.library dispatches over Cargo.gen.lock (the slim gen delta,
  # reconstructed to the full BuildSpec in pure Nix) — no crate2nix, no Cargo.nix.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { self, substrate, ... }:
    let
      base = substrate.rust.library { src = ./.; };
      receipt = import ./nix/receipt.nix;
      forSystem = system: receipt {
        pkgs = substrate.inputs.nixpkgs.legacyPackages.${system};
        tameshi = self.packages.${system}.tameshi;
      };
    in
    base // {
      lib = {
        wrapTest =
          { system ? builtins.currentSystem or (throw "tameshi.lib.wrapTest: pass `system`; pure evaluation has no current system")
          , ...
          }@args:
          (forSystem system).wrapTest (removeAttrs args [ "system" ]);
      };
      overlays = base.overlays // {
        default = final: prev:
          let built = (base.overlays.default final prev).tameshi;
          in { tameshi = built // { inherit ((receipt { pkgs = final; tameshi = built; })) wrapTest; }; };
      };
      checks = builtins.mapAttrs (system: checks: checks // (forSystem system).checks) base.checks;
    };
}
