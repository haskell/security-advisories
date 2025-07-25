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
        jailbreakUnbreak = pkg:
          pkgs.haskell.lib.doJailbreak (pkgs.haskell.lib.dontCheck (pkgs.haskell.lib.unmarkBroken pkg));

        purl = pkgs.haskellPackages.callCabal2nix "purl" ./code/purl { };
        cvss = pkgs.haskellPackages.callCabal2nix "cvss" ./code/cvss { };
        osv = pkgs.haskellPackages.callCabal2nix "osv" ./code/osv { inherit cvss purl; };
        hsec-core = pkgs.haskellPackages.callCabal2nix "hsec-core" ./code/hsec-core {
          inherit cvss osv;
        };
        hsec-tools = returnShellEnv:
          pkgs.haskellPackages.developPackage {
            inherit returnShellEnv;
            name = "hsec-tools";
            root = ./code/hsec-tools;
            withHoogle = false;
            overrides = self: super: {
              inherit cvss hsec-core osv;
            };

            modifier = drv:
              if returnShellEnv
              then
                pkgs.haskell.lib.addBuildTools drv
                  (with pkgs.haskellPackages;
                  [
                    cabal-fmt
                    cabal-install
                    ghcid
                    haskell-language-server
                    pkgs.nixpkgs-fmt
                  ])
              else drv;
          };
        hsec-sync =
          pkgs.haskell.lib.dontCheck
            (pkgs.haskellPackages.callCabal2nix
              "hsec-sync"
              ./code/hsec-sync
              { inherit hsec-core; });

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
        packages.cvss = cvss;
        packages.osv = osv;
        packages.purl = purl;
        packages.hsec-core = hsec-core;
        packages.hsec-tools = pkgs.haskell.lib.justStaticExecutables (hsec-tools false);
        packages.hsec-sync = hsec-sync;
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
                "/repo" = { };
              };
              WorkDir = "/";
            };
          };
        # Used by `nix build` & `nix run` (prod exe)
        defaultPackage = self.packages.${system}.hsec-tools;

        # Used by `nix develop` (dev shell)
        devShell = hsec-tools true;
      });
}
