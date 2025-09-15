{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [
    pkgs.gcc
    pkgs.python3
    pkgs.python3Packages.pip
    pkgs.rustc
    pkgs.cargo
    pkgs.libiconv # Required for some Rust dependencies on macOS
  ];
}
