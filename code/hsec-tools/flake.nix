{
  description = "hsec-tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ ];
        pkgs =
          import nixpkgs { inherit system overlays; config.allowBroken = true; };
        project = returnShellEnv:
          pkgs.haskellPackages.developPackage {
            inherit returnShellEnv;
            name = "hsec-tools";
            root = ./.;
            withHoogle = false;
            overrides = self: super: with pkgs.haskell.lib; {
              Cabal-syntax = super.Cabal-syntax_3_8_1_0;
            };
            modifier = drv:
              pkgs.haskell.lib.addBuildTools drv (with pkgs.haskellPackages;
              [
                cabal-fmt
                cabal-install
                ghcid
                haskell-language-server
                pkgs.nixpkgs-fmt
              ]);
          };
      in
      {
        # Used by `nix build` & `nix run` (prod exe)
        defaultPackage = project false;

        # Used by `nix develop` (dev shell)
        devShell = project true;
      });
}
