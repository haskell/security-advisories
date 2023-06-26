{
  description = "hsec-tools";


  nixConfig = {
    extra-substituters = "https://cache.nixos.org https://hydra.nixos.org https://nix-community.cachix.org";
    extra-trusted-public-keys = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= hydra.nixos.org-1:CNHJZBh9K4tP3EKF6FkkgeVYsS3ohTl+oS0Qa8bezVs= nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs=";
    # extra-experimental-features = "nix-command flakes";
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          jailbreakUnbreak = pkg:
            pkgs.haskell.lib.doJailbreak (pkgs.haskell.lib.dontCheck (pkgs.haskell.lib.unmarkBroken pkg));

          haskellPackages = pkgs.haskell.packages.ghc925.override
            {
              overrides = hself: hsuper: {
                Cabal-syntax = hsuper.Cabal-syntax_3_8_1_0;
              };
            };
        in
        rec
        {
          packages.hsec-tools =
            haskellPackages.callCabal2nix "hsec-tools" ./. {
              # Dependency overrides go here
            };

          defaultPackage = packages.hsec-tools;

          devShell =
            pkgs.mkShell {
              buildInputs = with haskellPackages; [
                haskell-language-server
                ghcid
                cabal-install
              ];
              inputsFrom = [
                self.defaultPackage.${system}.env
              ];
            };
        });
}
