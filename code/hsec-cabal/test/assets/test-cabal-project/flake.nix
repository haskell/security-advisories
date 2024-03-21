{
  nixConfig.allow-import-from-derivation = true;
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
  };
  outputs = inputs:
    inputs.parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      imports = [
        inputs.haskell-flake.flakeModule
      ];

      perSystem =
        {
          haskellProjects.default = {
            defaults.devShell.tools = ps: { inherit (ps) cabal-install; };
            packages = {
              toml-reader.source = "0.1.0.0";
              megaparsec.source = "9.2.0";
            };
            settings = { };
          };
        };
    };
}
