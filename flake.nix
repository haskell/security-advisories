{
  nixConfig.allow-import-from-derivation = true;
  description = "hsec-flake";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";

    toml-parser.url = "https://hackage.haskell.org/package/toml-parser-2.0.0.0/toml-parser-2.0.0.0.tar.gz";
    toml-parser.flake = false;
  };
  outputs = inputs:
    inputs.parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      imports = [
        inputs.haskell-flake.flakeModule
        inputs.pre-commit-hooks.flakeModule
      ];

      perSystem =
        { config
        , pkgs
        , ...
        }: {
          pre-commit = {
            check.enable = true;
            settings.hooks = {
              cabal-fmt.enable = true;
              hlint.enable = true;

              nixpkgs-fmt.enable = true;
              statix.enable = true;
              deadnix.enable = true;
            };
          };
          haskellProjects.default = {
            packages = {
              Cabal-syntax.source = "3.10.2.0";
              toml-parser.source = inputs.toml-parser;
            };
            settings = {
              cabal-audit.justStaticExecutables = true;
              hsec-sync.check = false;
              hsec-sync.justStaticExecutables = true;
            };
            projectRoot = ./code;
            devShell.mkShellArgs.shellHook = config.pre-commit.installationScript;
          };

          packages.default = config.packages.hsec-tools;

          packages.hsec-tools-image =
            let
              gitconfig =
                pkgs.writeTextFile {
                  name = ".gitconfig";
                  text = ''
                    [safe]
                      directory = *
                  '';
                  destination = "/.gitconfig"; # should match 'config.WorkDir'
                };
            in
            pkgs.dockerTools.buildImage {
              name = "haskell/hsec-tools";
              tag = "latest";

              copyToRoot = pkgs.buildEnv {
                name = "image-root";
                paths = [
                  config.packages.hsec-tools
                  pkgs.gitMinimal.out
                  gitconfig
                ];
                pathsToLink = [ "/bin" "/" ];
              };
              runAsRoot = "rm -Rf /share";
              config = {
                Cmd = [ "/bin/hsec-tools" ];
                Env = [
                  "LOCALE_ARCHIVE=${pkgs.glibcLocalesUtf8}/lib/locale/locale-archive"
                  "LC_TIME=en_US.UTF-8"
                  "LANG=en_US.UTF-8"
                  "LANGUAGE=en"
                  "LC_ALL=en_US.UTF-8"
                  "GIT_DISCOVERY_ACROSS_FILESYSTEM=1"
                ];
                Volumes = {
                  "/repo" = { };
                };
                WorkDir = "/";
              };
            };
        };
    };
}
