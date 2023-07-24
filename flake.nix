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
            root = ./code/hsec-tools;
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
      {

        packages.hsec-tools = pkgs.haskell.lib.justStaticExecutables (project false);
        packages.hsec-tools-image =
          pkgs.dockerTools.buildImage {
            name = "haskell/hsec-tools";
            tag = "latest";

            copyToRoot = pkgs.buildEnv {
              name = "image-root";
              paths = [
                self.packages.${system}.hsec-tools
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
                "/advisories" = { };
              };
              WorkDir = "/";
            };
          };
        # Used by `nix build` & `nix run` (prod exe)
        defaultPackage = self.packages.${system}.hsec-tools;

        # Used by `nix develop` (dev shell)
        devShell = project true;
      });
}
