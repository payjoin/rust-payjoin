{
  description = "payjoin-mailroom nixos flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # These inputs should be chosen based on the latest stable release version you can find.
    # The latest payjoin-mailroom tag here https://github.com/payjoin/rust-payjoin/tags.
    rust-payjoin.url = "github:payjoin/rust-payjoin";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-payjoin,
      ...
    }:
    {
      nixosConfigurations.payjoin-mailroom = nixpkgs.lib.nixosSystem {
        modules = [
          ./configuration.nix
          rust-payjoin.nixosModule.payjoin-mailroom

          (
            { config, pkgs, ... }:
            {
              services.payjoin-mailroom = {
                enable = true;
                settings = {
                  # Add any settings you feel are necessary for your setup. To find our recommendations take a look at our example ./config.example.toml
                };
              };
            }
          )
        ];
      };
    };
}
