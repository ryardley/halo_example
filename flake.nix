{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustVersion = pkgs.rust-bin.stable.latest.default;
      in
        with pkgs; {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              rustVersion
              rust-analyzer
              cmake
              expat
              freetype
              cairo
              pkg-config
            ];

            shellHook = ''
              echo "Development environment loaded!"
            '';
          };
        }
    );
}
